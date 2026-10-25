//! 文件系统访问校验器
//!
//! ## 判定顺序（2026-09-27 授权策略增强 · 票 02/03 起）
//!
//! 0. **硬拒绝记录**（`plugin_auth_records` 中 `effect='deny'` 命中目标）：直接拒绝，
//!    不弹窗、不看任何放行层——用户显式撤销/拒绝过的目标优先于一切放行路径
//!    （spec §6.1 第 1 步）；
//! 1. **第一方集成目录预授权**（[`FIRST_PARTY_TRUSTED_DIRS`]）：只对具名第一方插件、
//!    只在其归属清单点名的目录段内免弹窗——不是「白名单插件任意路径放行」，
//!    也不是「路径里出现 `.claude/` 就放行」。**它排在策略之前**：档位管不着这批
//!    内置免询问项（spec §7 裁定「优先级高于策略档位」，否则该表存在的唯一理由
//!    就被「总是询问」架空了）；
//! 2. **策略档位**（[`super::strategy::StrategyStep`]，判定时实时读取）：
//!    「总是询问」在此**跳过**下面两条 allow 记录（含旧记录回退）直接进询问；
//!    「默认」继续往下；「始终允许」免询问直接放行，并以 `source='always_allow'`
//!    落账（票 04；spec §4.1 第 2 档的口径是「不问，但必须留痕」——免询问也要在
//!    管理界面可见，否则最高风险档上会出现不可见空洞）；
//! 3. **授权记录命中**（同表 `effect='allow'`）：目标命中且**操作集覆盖**本次操作才放行；
//! 4. **旧版扁平前缀回退**（`plugin_storage.fs_granted_paths`，**只读**）：存量用户的
//!    既有目录授权继续生效（视作读写都授权）。
//! 5. **弹窗授权**（前面都未命中；无头上下文没有弹窗通道 → 保守拒绝）。
//!    应答三态见 [`FsDecision`]：「总是询问」档不提供「记住」（该档不读记录，
//!    落一条永远不会被读到的记录只会造成两处口径）。
//!
//! ## resolve 规则（spec §5.2）
//!
//! 只有「记录 + 旧记录」两级**都有确定性结论**时才可能免弹窗，规则是：
//!
//! 1. 取 `effect='allow'` 且 target 是本次规范化路径**祖先或自身**的全部记录；
//! 2. 集合非空 ⇒ **完全由新表说了算**：任一行覆盖本次操作 → 放行；否则不放行，
//!    且**不再回退旧记录**（用户显式管理过的子树，旧记录对它是作废的）；
//! 3. 集合为空 ⇒ 回退旧记录：命中任一前缀 → 放行（视作 read + write，与旧版逐字一致）。
//!
//! **操作维度**（[`FsOps`]）：授权记录带生效操作集，读与写不再互相隐含。授权「读」
//! 某目录后，插件写该目录会**再问一次**（spec §12.1 C5）；旧记录没有操作维度，
//! 按读写都授权处理，存量用户零感知。
//!
//! 每条判定都在日志里点明**命中的是哪一层**（`layer = ...`），排障时不必靠猜：
//! 免弹窗来源不唯一（清单 / 策略自动放行 / 记录 / 旧记录 / 用户刚同意），
//! 无层号日志就无法回答「为什么这次没弹框」。
//!
//! ## 为什么第一层不再是「全局路径白名单」
//!
//! 旧实现按 `.claude/` **子串**匹配，对**所有**带 `fs:read` 的插件生效：任意位置的
//! 同名目录段（`/tmp/attacker-controlled/.claude/x`）都免弹窗，等于把「访问未授权
//! 目录按需弹窗」的兜底架空；而它的真实消费者只有两个第一方插件（agent-hub 分发
//! 技能到 `~/.claude/skills`、bedcode 写项目集成目录）。改造后：
//! 第三方 `fs:read` 插件读 `~/.claude/**` 必须过弹窗（红测断言），第一方按归属清单免弹窗。
//!
//! ## 不在本校验器里的事
//!
//! 任务单元（core-task 池线程）**不得触发弹窗**——判据由调用侧走 [`FsAuthChecker::is_granted`]，
//! 未授权直接 fail-visible 拒绝（见宿主侧 task 域实现）。

use crate::security::auth_policy::{
    AuthPolicyStore, AuthRecordSource, AuthResource, AuthStrategy, GrantOutcome, AUTH_EFFECT_ALLOW,
    AUTH_EFFECT_DENY,
};
use crate::security::strategy::{self, StrategyStep, Tier};
use crate::storage::PluginStorage;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;
use tokio::sync::{oneshot, Mutex};

/// 弹窗授权请求的等待上限（无应答即拒——AGENTS §8 fail-safe 默认）
///
/// 生产值固定 30s；测试可经 [`FsAuthChecker::with_prompt_timeout`] 调小，
/// 否则「超时不落账」这条契约要等 30 秒才验得到。
const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// 命中的授权层（日志与拒绝文案用它说明判据来源）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsGrantLayer {
    /// 第一方集成目录预授权（按插件 id 归属）
    FirstPartyDir,
    /// 「始终允许」档的免询问放行（票 04；记录已按 `source='always_allow'` 落账）
    AlwaysAllow,
    /// 授权记录命中（`plugin_auth_records` 的 allow 且操作集覆盖本次操作）
    RecordGrant,
    /// 旧版扁平前缀回退（`fs_granted_paths`，只读；视作读写都授权）
    LegacyGrant,
}

impl FsGrantLayer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstPartyDir => "first-party-dir",
            Self::AlwaysAllow => "always-allow",
            Self::RecordGrant => "record-grant",
            Self::LegacyGrant => "legacy-grant",
        }
    }
}

/// 第一方免弹窗目录的形态
///
/// **纯净性收口票 08（P0-2）**：本类型是判定语义（机制）留在本 crate；
/// **产品清单不在本 crate**——`FIRST_PARTY_TRUSTED_DIRS` 常量已删除，清单由
/// 宿主 lib 装配时经 `FsAuthChecker::new` 注入（`Vec<(&'static str, Vec<TrustedDir>)>`），
/// 空表 = 无免弹窗项（无头 / 测试 / 未装配宿主语义逐字不变）。
#[derive(Debug, Clone, Copy)]
pub enum TrustedDir {
    /// 家目录下的相对前缀（`~/.agents/skills` 这类宿主已知位置）
    Home(&'static str),
    /// 任意项目根下的同名**目录段**（agent CLI 的项目级配置目录约定：
    /// `<project>/.claude` / `.codex` / `.pi` / `.opencode`）。
    /// 按路径段全等匹配，因此 `.claudex/` 与 `/x.claude` 都不命中——旧实现用
    /// `contains(".claude/")` 子串，相邻名字也能命中。
    ProjectSegment(&'static str),
}

/// 第一方免弹窗项的**只读投影**（授权管理界面的读模型用，spec §9.3 / 票 08）
///
/// 判定语义只有本模块一处真源（[`first_party_dir_matches_with_home`]）；这里仅把
/// 清单翻译成可展示形状，使这批「内置免询问」在授权管理界面可见——不导出就等于
/// 用户看不见的特权（spec §7「必须配套」）。
///
/// 展示文案不在此处拼：`kind` + `value` 交前端按 locale 组合（AGENTS §6 用户可见
/// 文案一律走 i18n，宿主 Rust 不产出面向用户的中文串）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirstPartyDirEntry {
    /// 归属应用（该特权只对它成立）
    pub plugin_id: &'static str,
    /// 匹配形态：`home`（家目录下前缀）/ `project-segment`（任意项目下的目录段）
    pub kind: &'static str,
    /// 清单里的原始值：`~/.agents` 的 `".agents"`、项目段 `".claude"`
    pub value: &'static str,
}

/// 文件操作类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    Read,
    Write,
}

impl FsOp {
    /// 库值 / wire 值（`plugin_auth_records.ops` 元素、弹窗 payload 的 operation）
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl std::fmt::Display for FsOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 文件操作**集**（授权记录的操作集 / 一次请求所需的能力集）
///
/// 授权与判定都按集合比较，而不是单值：一次「目录授权」可以同时要读与写
/// （插件自报数据目录、系统选择器结果），进度只按集合覆盖关系判断——
/// 「所需能力 ⊆ 已授权操作集」才放行。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsOps(u8);

impl FsOps {
    pub const READ: Self = Self(0b01);
    pub const WRITE: Self = Self(0b10);
    /// 读 + 写（旧记录回退、选择器结果、插件自报数据目录的口径）
    pub const READ_WRITE: Self = Self(0b11);

    /// 单操作集合
    pub const fn single(op: FsOp) -> Self {
        match op {
            FsOp::Read => Self::READ,
            FsOp::Write => Self::WRITE,
        }
    }

    /// 是否包含某个操作
    pub const fn contains(self, op: FsOp) -> bool {
        self.0 & Self::single(op).0 != 0
    }

    /// 是否覆盖所需能力集（`needed ⊆ self`）
    pub const fn covers(self, needed: Self) -> bool {
        needed.0 & !self.0 == 0
    }

    /// 与另一集合合并（落账时同一目标的操作集取并集）
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// 落库形态（`plugin_auth_records.ops` 的 JSON 数组元素，顺序固定 read → write）
    pub fn to_wire(self) -> Vec<String> {
        let mut out = Vec::new();
        if self.contains(FsOp::Read) {
            out.push(FsOp::Read.as_str().to_string());
        }
        if self.contains(FsOp::Write) {
            out.push(FsOp::Write.as_str().to_string());
        }
        out
    }

    /// 从库值解析（未知元素忽略；空结果 = 没有生效操作）
    pub fn from_wire(ops: &[String]) -> Self {
        let mut set = Self::default();
        for op in ops {
            match op.as_str() {
                "read" => set = set.union(Self::READ),
                "write" => set = set.union(Self::WRITE),
                // 未知操作不进集合：宁可判定为「未覆盖」（→ 继续询问），
                // 也不能把不认识的字符串当成某个已授权能力
                _ => {}
            }
        }
        set
    }

    /// 日志 / 弹窗 payload 用的展示值：`read` / `write` / `read+write`
    pub fn as_wire_str(self) -> &'static str {
        match self.0 {
            0b01 => "read",
            0b10 => "write",
            _ => "read+write",
        }
    }
}

/// 「记住授权」时的落账粒度（`respond(remember = true)` 持久化什么）
///
/// 两种来源的用户心智不同，落账粒度也就不同：
/// - [`Exact`](Self::Exact)：插件**直接请求访问**某个路径（`check` /
///   `check_batch` / WASI 预打开）——用户是对那个路径点头，粒度就等于它；
/// - [`Directory`](Self::Directory)：**系统文件选择器**的结果（`host-platform`
///   的 `pick-*`）——用户表达的是「这个目录里的东西可以用」；若只落账到单个文件，
///   同目录下换个文件再选就会重新弹框（一次选 N 个文件 → N 次弹窗）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantScope {
    /// 精确：目录 → 目录本身；文件 → 文件本身（`save_granted_path` 的既有规则）
    Exact,
    /// 目录：目录 → 自身；文件 → 所在父目录
    Directory,
}

impl GrantScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Directory => "directory",
        }
    }
}

/// 弹窗请求的来源（弹窗文案用它说清「谁在要这个目录」）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOrigin {
    /// 插件直接请求文件访问（既有全部调用方）
    Fs,
    /// 用户刚在**系统文件选择器**里选中这些路径（`host-platform.pick-*`）
    Picker,
}

impl AuthOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Picker => "picker",
        }
    }
}

/// 授权询问的应答决定（票 03 固定四态，wire 值即命令参数）
///
/// 「允许本次 / 拒绝 / 以后都拒绝」三个按钮 + 「默认」档的「记住」勾选，组合起来
/// 正好落在这四个决定上。写成枚举而不是两个布尔：`allowed + remember` 的双布尔
/// 形态表达不了「以后都拒绝」，而给布尔再加一个只会让组合里出现非法态
/// （拒绝 + 记住 与 拒绝 + 不记住 的差别只有宿主知道）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsDecision {
    /// 允许本次：一次性放行，**不落账**
    AllowOnce,
    /// 允许并记住（「默认」档的「记住」勾选）→ 落 allow 记录（操作集 = 本次请求）
    AllowRemember,
    /// 拒绝：不落账（下次访问会重新询问）
    Deny,
    /// 以后都拒绝 → 落 `effect='deny'` 记录（该目标与其子树后续被直接拒绝）
    DenyAlways,
}

impl FsDecision {
    /// wire 值（`plugin_fs_auth_respond` 的 `decision` 参数）
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow_once",
            Self::AllowRemember => "allow_remember",
            Self::Deny => "deny",
            Self::DenyAlways => "deny_always",
        }
    }

    /// 解析 wire 值；未知值返回 `None`（调用方显性报错，**不兜底成放行**）
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "allow_once" => Some(Self::AllowOnce),
            "allow_remember" => Some(Self::AllowRemember),
            "deny" => Some(Self::Deny),
            "deny_always" => Some(Self::DenyAlways),
            _ => None,
        }
    }

    /// 本次是否放行（落账细节在 [`FsAuthChecker::respond`]，与放行方向无关）
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::AllowOnce | Self::AllowRemember)
    }
}

/// 弹窗事件投递口（生产 = `AppHandle.emit`；同模块测试 = 捕获闭包）
///
/// 抽成注入点而不是在测试里硬塞 `AppHandle`：tao 事件循环不允许在测试线程建
/// `AppHandle`，而「弹窗按弹出时档位渲染 / 应答落账 / 超时不落账」这些契约必须
/// 在**真实判定链**上验证（只测纯函数的变异教训见 spec §12.2）。
/// `None` = 无头上下文 ⇒ 询问层不可用 ⇒ 拒绝。
pub type PromptEmitter = Arc<dyn Fn(&str, serde_json::Value) -> Result<(), String> + Send + Sync>;

/// 待处理的授权请求
struct PendingRequest {
    /// 请求 ID（UUID）
    request_id: String,
    /// 请求授权的插件 ID
    plugin_id: String,
    /// 请求授权的文件路径（单路径请求为单元素；批量请求含全部未授权路径）
    paths: Vec<String>,
    /// 本次请求的操作集（「记住」时按它落账到授权记录）
    ops: FsOps,
    /// 「记住」时的落账粒度
    grant_scope: GrantScope,
    /// 请求来源（弹窗文案）
    origin: AuthOrigin,
    /// **弹出时**的策略档位（决定弹窗给不给「记住」、应答怎么落账）
    ///
    /// 在弹窗弹出时固定下来（spec §8.1）：等待应答期间用户改了档位，这个弹窗
    /// 仍按旧口径走完——半途改口径会让「用户看到的按钮」与「实际落账」不一致。
    strategy: AuthStrategy,
    /// 回复通道
    reply_tx: oneshot::Sender<bool>,
}

impl PendingRequest {
    /// 本弹窗是否提供「记住」（= 该弹窗弹出时的档位是否会读授权记录）
    ///
    /// 「总是询问」档跳过记录 ⇒ 落账写了也没人读 ⇒ 弹窗不提供「记住」
    /// （spec §6.3），应答侧据此把越界的 `allow_remember` 降级为一次性放行。
    fn offers_remember(&self) -> bool {
        StrategyStep::of(self.strategy).reads_allow_records()
    }
}

/// 免弹窗判定的完整结论（`check` / `check_batch` / `is_granted` 三条入口的单点）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoDialogDecision {
    /// 硬拒绝记录命中：直接拒绝，**不弹窗**（用户已说过「不要再放行」）
    Denied,
    /// 命中某个放行层
    Allowed(FsGrantLayer),
    /// 未命中：需要弹窗（无弹窗通道的上下文按拒绝处理）
    ///
    /// 带上弹出时的档位：询问层要按它决定给不给「记住」、应答怎么落账。
    Ask(AuthStrategy),
}

/// 记录层信号（一次读库算出，避免判定链里两次查表）
#[derive(Debug, Clone, Copy, Default)]
struct RecordSignals {
    /// 命中了 effect='deny' 的记录
    deny_hit: bool,
    /// 命中的 allow 记录的操作集并集；`None` = 没有任何 allow 记录命中
    allow_ops: Option<FsOps>,
}

/// 文件系统访问校验器
pub struct FsAuthChecker {
    /// 插件存储（**只读**旧版扁平授权前缀；新授权一律进授权记录表）
    storage: Arc<PluginStorage>,
    /// 授权策略与授权记录真源（判定实时读取，不缓存——spec §8.1）
    auth_records: AuthPolicyStore,
    /// 待处理的弹窗授权请求
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    /// 弹窗事件投递口（`None` = 无头上下文：询问层不可用，未覆盖目标直接拒绝）
    emit: Option<PromptEmitter>,
    /// 弹窗等待上限（生产 [`PROMPT_TIMEOUT`]；测试可调小以验证超时语义）
    prompt_timeout: Duration,
    /// 第一方免弹窗归属清单（**宿主注入**，票 08/P0-2：产品数据出厂 lib，
    /// 判定逻辑留本 crate）。空表 = 无免弹窗项——无头 / 测试 / 未装配宿主
    /// 语义逐字不变（无豁免表 = 无免弹窗项）。
    first_party_dirs: Vec<(&'static str, Vec<TrustedDir>)>,
}

impl FsAuthChecker {
    /// 创建文件访问校验器
    ///
    /// `app_handle` 为 None 时（无头/测试上下文）弹窗授权层不可用，直接拒绝。
    /// 授权记录真源由插件存储持有的同一数据库句柄构造（不额外传参，避免 20+ 处
    /// 构造点全部改签名）。
    ///
    /// `first_party_dirs`：第一方免弹窗归属清单（[`TrustedDir`] 形态），由**宿主
    /// lib 装配时注入**（`src-tauri/src/first_party_dirs.rs`）；传空表 = 无免弹窗项。
    pub fn new(
        storage: Arc<PluginStorage>,
        app_handle: Option<Arc<tauri::AppHandle>>,
        first_party_dirs: Vec<(&'static str, Vec<TrustedDir>)>,
    ) -> Self {
        let emit = app_handle.map(|handle| {
            let handle = handle.clone();
            Arc::new(move |event: &str, payload: serde_json::Value| {
                handle.emit(event, payload).map_err(|e| e.to_string())
            }) as PromptEmitter
        });
        Self::assemble(storage, emit, first_party_dirs)
    }

    fn assemble(
        storage: Arc<PluginStorage>,
        emit: Option<PromptEmitter>,
        first_party_dirs: Vec<(&'static str, Vec<TrustedDir>)>,
    ) -> Self {
        let auth_records = AuthPolicyStore::new(storage.db());
        Self {
            storage,
            auth_records,
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            emit,
            prompt_timeout: PROMPT_TIMEOUT,
            first_party_dirs,
        }
    }

    /// **测试专用**：以显式事件投递口装配（捕获弹窗 payload、触发超时路径）
    #[cfg(test)]
    pub(crate) fn with_emitter(
        storage: Arc<PluginStorage>,
        emit: Option<PromptEmitter>,
        first_party_dirs: Vec<(&'static str, Vec<TrustedDir>)>,
    ) -> Self {
        Self::assemble(storage, emit, first_party_dirs)
    }

    /// **测试专用**：调小弹窗等待上限（「超时按拒绝且不落任何记录」契约的验证口）
    ///
    /// `#[cfg(test)]`：生产不允许放宽 / 收紧这个上限——它是 fail-safe 的时限，
    /// 不是可配置项（可配置就等于允许把「无应答即拒」拖成无限期等待）。
    #[cfg(test)]
    pub(crate) fn with_prompt_timeout(mut self, timeout: Duration) -> Self {
        self.prompt_timeout = timeout;
        self
    }

    /// 注入 core-monitor 句柄（授权记录容量丢弃计数；两阶段初始化）
    ///
    /// 与 `SecurityFramework::set_monitor` / `MessageBus::set_monitor` 同一形态：
    /// core-monitor 生于 `WasmRuntime`，晚于校验器构造。计数落在授权真源的落账点
    /// （`AuthPolicyStore::grant`），这里只做转交。
    pub fn set_monitor(&self, monitor: Arc<crate::monitor::MetricsRegistry>) {
        self.auth_records.set_monitor(monitor);
    }

    /// 校验文件访问权限
    ///
    /// 判定顺序：硬拒绝记录 → 免弹窗层（第一方 / 记录 / 旧记录）→ 弹窗。
    /// 返回 true 表示允许访问，false 表示拒绝。
    pub async fn check(&self, plugin_id: &str, path: &str, operation: FsOp) -> bool {
        let canonical = match Self::canonicalize_path(path) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    path = %path,
                    "fs_auth: path canonicalization failed"
                );
                return false;
            }
        };

        match self
            .decide_without_dialog(plugin_id, &canonical, FsOps::single(operation))
            .await
        {
            NoDialogDecision::Denied => {
                tracing::info!(
                    plugin_id = %plugin_id,
                    path = %path,
                    operation = operation.as_str(),
                    "fs_auth: denied by explicit deny record"
                );
                false
            }
            // 免弹窗放行是每次文件读写的默认路径（第一方目录 / 授权记录 / 旧记录），
            // 逐次打日志即风暴：agent-hub 一次用量全盘扫描就是「一个文件一行」，
            // 实测单分钟刷 1121 行。放行本身由 core-monitor 的授权决策计数承担，
            // 真正需要留痕的拒绝 / 弹窗 / 规范化失败路径在各自分支单独记录。
            NoDialogDecision::Allowed(_) => true,
            // 最后一层：弹窗授权（前面都未命中才走到这里）
            NoDialogDecision::Ask(strategy) => {
                self.request_user_auth(plugin_id, path, FsOps::single(operation), strategy)
                    .await
            }
        }
    }

    /// 免弹窗判定单点（顺序 = 模块文档的判定顺序）
    ///
    /// 三条入口（`check` / `check_batch` / `is_granted`）必须拿到**逐字相同**的结论，
    /// 否则「无弹窗面」（WASI 预打开 / 任务单元）与「弹窗面」会给出两套答案
    /// （同一目录一边可写一边被拒）。`needed` 是本次要用的能力集：记录必须覆盖它。
    async fn decide_without_dialog(
        &self,
        plugin_id: &str,
        canonical: &Path,
        needed: FsOps,
    ) -> NoDialogDecision {
        let signals = self.record_signals(plugin_id, canonical).await;
        // 0. 硬拒绝记录优先于一切放行路径（含第一方免询问目录与策略档位）：
        //    「总是询问」跳过的**只是** allow 记录，用户已说过的「以后都拒绝」
        //    仍在这里拦住——否则同一条硬拒绝会每次访问都重新弹窗
        if signals.deny_hit {
            return NoDialogDecision::Denied;
        }
        // 1. 第一方集成目录（清单归属，spec §7；撤销它只能靠 deny 记录）。
        //    排在策略之前：档位管不着这批内置免询问项（spec §7 裁定），
        //    否则「弹窗把一次技能同步拆成 N 次点击」的老问题会回来
        if self.first_party_dir_matches(plugin_id, canonical) {
            return NoDialogDecision::Allowed(FsGrantLayer::FirstPartyDir);
        }
        // 2. 策略档位（判定时实时读取，不缓存、不做激活期快照——spec §8.1）
        let step = match strategy::evaluate(&self.auth_records, plugin_id, AuthResource::Fs).await {
            Ok(step) => step,
            Err(e) => {
                // 读不出来按「询问」处理（fail-safe 方向）：策略读失败时记录大概率
                // 也读不出来，放行方向才是危险的；档位按默认档兜底，与
                // `AuthStrategy::parse` 的未知值口径一致
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "fs_auth: 策略档位读取失败，本次判定按询问处理"
                );
                return NoDialogDecision::Ask(AuthStrategy::Default);
            }
        };
        match step.tier() {
            // 「总是询问」：跳过全部 allow 记录（含旧记录回退），直接进询问
            Tier::Ask => {
                tracing::debug!(
                    plugin_id = %plugin_id,
                    path = %canonical.display(),
                    step = step.as_str(),
                    "fs_auth: 总是询问档，跳过授权记录"
                );
                return NoDialogDecision::Ask(AuthStrategy::AlwaysAsk);
            }
            // 「始终允许」（票 04）：免询问放行 + 以 `source='always_allow'` 落账。
            // 它**不读**已有 allow 记录（spec §4.1 第 2 档），因此记录覆盖与否都在
            // 这里直接放行；落账让「免询问自动放行」在管理界面可见（spec §9.4）。
            // 硬闸门（deny 记录 / 路径规范化 / manifest 声明 / 配额）全在本步之前或
            // 之外，档位管不着（spec §4.2、票 04 的红测断言）
            Tier::AutoAllow => {
                // 审计义务随档位携带（S-11）：类型上防止「match 后什么都不做」——
                // 删除落账会让本断言（debug 测试构建）与行为测试同时转红
                debug_assert!(
                    step.must_land_auto_allow(),
                    "AutoAllow 档位字段丢失审计义务（S-11）"
                );
                self.land_auto_allow(plugin_id, canonical, needed).await;
                return NoDialogDecision::Allowed(FsGrantLayer::AlwaysAllow);
            }
            Tier::ConsultRecords => {}
        }
        match signals.allow_ops {
            // 3. 授权记录命中且操作集覆盖本次能力 → 放行
            Some(ops) if ops.covers(needed) => NoDialogDecision::Allowed(FsGrantLayer::RecordGrant),
            // 3'. 授权记录命中但操作集不含本次所需 → 该子树由用户显式管理过，
            //     旧记录对它**作废**（spec §5.2 第 2 步的短路条件），进询问
            Some(_) => NoDialogDecision::Ask(AuthStrategy::Default),
            // 4. 没有任何 allow 记录命中 → 回退旧版扁平前缀（视作读写都授权）
            None => {
                if self.legacy_prefix_matches(plugin_id, canonical).await {
                    NoDialogDecision::Allowed(FsGrantLayer::LegacyGrant)
                } else {
                    NoDialogDecision::Ask(AuthStrategy::Default)
                }
            }
        }
    }

    /// 读一次授权记录，算出 deny 命中与 allow 操作集并集
    ///
    /// 前缀匹配用 `Path::strip_prefix`（组件边界）：`.wasmnest` 不会吃掉 `.wasmnest-other`。
    /// 真源读失败**不降级放行**：按「未命中」处理并显性记错（拍成放行会把安全闸门变成
    /// 「数据库一坏就全放行」）。
    async fn record_signals(&self, plugin_id: &str, canonical: &Path) -> RecordSignals {
        let rows = match self
            .auth_records
            .records_for_match(plugin_id, AuthResource::Fs)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "fs_auth: 授权记录读取失败，本次判定按未命中处理"
                );
                return RecordSignals::default();
            }
        };

        let mut signals = RecordSignals::default();
        for row in &rows {
            let Some(record_path) = Self::canonicalize_path(&row.target) else {
                continue;
            };
            if canonical.strip_prefix(&record_path).is_err() {
                continue;
            }
            if row.effect == AUTH_EFFECT_DENY {
                signals.deny_hit = true;
            } else if row.effect == AUTH_EFFECT_ALLOW {
                let ops = FsOps::from_wire(&row.ops);
                signals.allow_ops = Some(signals.allow_ops.unwrap_or_default().union(ops));
            }
        }
        signals
    }

    /// 第一方集成目录判定（见 [`first_party_dir_matches_with_home`]）
    fn first_party_dir_matches(&self, plugin_id: &str, canonical: &Path) -> bool {
        first_party_dir_matches_with_home(
            &self.first_party_dirs,
            plugin_id,
            canonical,
            dirs::home_dir().as_deref(),
        )
    }

    /// 第一方免弹窗项的**只读投影**（授权管理界面的读模型；数据源 = 宿主注入表）
    ///
    /// 判定语义只有本模块一处真源（[`first_party_dir_matches_with_home`]）；这里仅把
    /// 清单翻译成可展示形状，使这批「内置免询问」在授权管理界面可见——不导出就等于
    /// 用户看不见的特权（spec §7「必须配套」）。空表（未装配）→ 空投影。
    pub fn first_party_trusted_dirs(&self) -> Vec<FirstPartyDirEntry> {
        self.first_party_dirs
            .iter()
            .flat_map(|(plugin_id, dirs)| {
                dirs.iter().map(move |dir| match dir {
                    TrustedDir::Home(rel) => FirstPartyDirEntry {
                        plugin_id,
                        kind: "home",
                        value: rel,
                    },
                    TrustedDir::ProjectSegment(seg) => FirstPartyDirEntry {
                        plugin_id,
                        kind: "project-segment",
                        value: seg,
                    },
                })
            })
            .collect()
    }

    /// 测试访问器：授权记录真源（用例要驱动撤销 / 断言落账行；生产只经判定链读写）
    #[cfg(test)]
    pub(crate) fn auth_records(&self) -> &AuthPolicyStore {
        &self.auth_records
    }

    /// 处理用户授权回复（由前端 Tauri command 调用；决定三态见 [`FsDecision`]）
    ///
    /// - `allow_once`：一次性放行，**不落账**；
    /// - `allow_remember`：放行 + 按本次请求的操作集落 allow 记录（仅当该弹窗
    ///   弹出时的档位会读记录，见 [`PendingRequest::offers_remember`]）；
    /// - `deny`：拒绝，不落账（下次访问重新询问）；
    /// - `deny_always`：拒绝 + 落 `effect='deny'` 记录（该目标与其子树后续被直接拒绝）。
    ///
    /// 超时走的是另一条路（[`PROMPT_TIMEOUT`]）：按拒绝且**不落任何记录**——
    /// 超时不是用户的表态，不能替用户记下「以后都拒绝」。
    pub async fn respond(&self, request_id: &str, decision: FsDecision) {
        // 先把请求从队列里取出来（持锁只做定位），再在锁外落账：
        // 落账要 await 数据库，持锁 await 会把整个弹窗队列堵住
        let request = {
            let mut pending = self.pending_requests.lock().await;
            pending
                .iter()
                .position(|r| r.request_id == request_id)
                .map(|idx| pending.remove(idx))
        };
        let Some(request) = request else {
            tracing::warn!(request_id = %request_id, "fs_auth: respond for unknown request");
            return;
        };

        // 「记住」只在弹出时档位会读记录的前提下才落账。等待应答期间档位可能已被
        // 改成「总是询问」，但那不影响**这个**弹窗的口径（spec §8.1：已等待应答的
        // 弹窗按弹出时的旧策略走完）。越界的 `allow_remember`（该弹窗根本没给
        // 「记住」按钮）降级为一次性放行并留痕：放行方向与用户意图一致，只是不落
        // 一条此后没人读的记录。
        let remember = decision == FsDecision::AllowRemember && request.offers_remember();
        if decision == FsDecision::AllowRemember && !request.offers_remember() {
            tracing::warn!(
                plugin_id = %request.plugin_id,
                request_id = %request_id,
                strategy = request.strategy.as_str(),
                "fs_auth: 该弹窗未提供「记住」，本次允许按一次性放行处理"
            );
        }
        if remember {
            self.land_allow_records(&request).await;
        }
        if decision == FsDecision::DenyAlways {
            self.land_deny_records(&request).await;
        }
        let _ = request.reply_tx.send(decision.is_allow());
    }

    /// 「始终允许」档的免询问放行留痕（spec §4.1 第 2 档：不问，但必须落账）
    ///
    /// 目标粒度 = 本次请求的路径本身（与插件直请路径的「记住」同一套
    /// [`GrantScope::Exact`] 规则）：记录是**前缀**，逐个目标访问按目标累积。
    /// 上溯到父目录落账等于替用户扩大授权范围（家里直子目录一落就是整个家目录），
    /// 正是这个档位最该避免的一侧偏差。
    ///
    /// 落账失败 / 容量上限（[`GrantOutcome::DroppedByCap`]）都**不影响放行方向**：
    /// 档位的语义是「不问」，留痕是它的义务，但留不下痕时拒绝访问是更坏的结果
    /// （用户明确配了这个档位；且 spec §4.2 的硬闸门在更靠前的位置已经拦过一遍）。
    async fn land_auto_allow(&self, plugin_id: &str, canonical: &Path, ops: FsOps) {
        let target = canonical.to_string_lossy().to_string();
        match self
            .auth_records
            .grant(
                plugin_id,
                AuthResource::Fs,
                &target,
                &ops.to_wire(),
                AuthRecordSource::AlwaysAllow,
            )
            .await
        {
            Ok(GrantOutcome::Stored) => {
                tracing::debug!(
                    plugin_id = %plugin_id,
                    path = %target,
                    ops = ops.as_wire_str(),
                    "fs_auth: 始终允许档，免询问放行并落账"
                );
            }
            // 计数与 warn 都在落账点（`AuthPolicyStore::grant`）出，这里不重复
            Ok(GrantOutcome::DroppedByCap) => {}
            Err(e) => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    path = %target,
                    error = %e,
                    "fs_auth: 始终允许档的落账失败（放行方向不变）"
                );
            }
        }
    }

    /// 随包服务型插件的**免询问放行**（issue #6 D4）
    ///
    /// 判据不在这里：调用方（`PluginHost::preauthorize_plugin`）先按「来源非
    /// `UserInstalled` **且** manifest 角色驱动（L1/L2）」裁定，本方法只做
    /// 「落账 + 不弹窗」这一件事。
    ///
    /// 落账来源 = [`AuthRecordSource::Service`]：与用户确认的 `User`、策略档的
    /// `AlwaysAllow` 区分开，安全面板才能解释「这条授权来自随包服务，不是用户点的」。
    /// 落账粒度 = 路径本身（与插件直请路径的 `GrantScope::Exact` 同口径）：服务声明
    /// 什么就放行什么；上溯父目录等于替用户扩大授权面。
    ///
    /// 失败（库错 / 容量上限）**不阻断激活**：记录缺位的后果是后续访问重新走询问层
    /// （安全方向不变，只是回到未豁免前的噪声），比「服务起不来」可接受。
    ///
    /// @returns 成功落账的路径条数（日志 / 测试用）
    pub async fn grant_service_paths(
        &self,
        plugin_id: &str,
        paths: &[String],
        ops: FsOps,
    ) -> usize {
        let mut stored = 0usize;
        for path in paths {
            let Some(target) = Self::grant_target(path, GrantScope::Exact) else {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    path = %path,
                    "fs_auth: 服务型免询问放行的目标规范化失败，跳过落账"
                );
                continue;
            };
            match self
                .auth_records
                .grant(
                    plugin_id,
                    AuthResource::Fs,
                    &target,
                    &ops.to_wire(),
                    AuthRecordSource::Service,
                )
                .await
            {
                Ok(GrantOutcome::Stored) => stored += 1,
                Ok(GrantOutcome::DroppedByCap) => {}
                Err(e) => tracing::warn!(
                    plugin_id = %plugin_id,
                    path = %target,
                    error = %e,
                    "fs_auth: 服务型免询问放行落账失败（后续访问会重新询问）"
                ),
            }
        }
        tracing::info!(
            plugin_id = %plugin_id,
            stored,
            requested = paths.len(),
            ops = ops.as_wire_str(),
            "fs_auth: 随包服务型插件免询问放行"
        );
        stored
    }

    /// 落账 allow 记录（用户勾「记住」后点头的路径，操作集 = 本次请求）
    async fn land_allow_records(&self, request: &PendingRequest) {
        for path in &request.paths {
            let Some(target) = Self::grant_target(path, request.grant_scope) else {
                tracing::warn!(
                    plugin_id = %request.plugin_id,
                    path = %path,
                    "fs_auth: 授权目标规范化失败，跳过落账"
                );
                continue;
            };
            if let Err(e) = self
                .auth_records
                .grant(
                    &request.plugin_id,
                    AuthResource::Fs,
                    &target,
                    &request.ops.to_wire(),
                    AuthRecordSource::User,
                )
                .await
            {
                tracing::warn!(
                    plugin_id = %request.plugin_id,
                    error = %e,
                    "fs_auth: 授权记录落账失败"
                );
            }
        }
        tracing::info!(
            plugin_id = %request.plugin_id,
            origin = request.origin.as_str(),
            grant_scope = request.grant_scope.as_str(),
            ops = request.ops.as_wire_str(),
            granted_count = request.paths.len(),
            "fs_auth: user allowed and remembered the grant"
        );
    }

    /// 落账 deny 记录（「以后都拒绝」：该目标与其子树此后被第 0 层直接拦下）
    ///
    /// 粒度与 allow 走同一套规则（`grant_scope`），否则「取消授权」与「以后都拒绝」
    /// 在同一目录上会覆盖不同的子树；来源固定 `user_deny`（界面按它标「用户拒绝」）。
    async fn land_deny_records(&self, request: &PendingRequest) {
        for path in &request.paths {
            let Some(target) = Self::grant_target(path, request.grant_scope) else {
                tracing::warn!(
                    plugin_id = %request.plugin_id,
                    path = %path,
                    "fs_auth: 拒绝目标规范化失败，跳过落账"
                );
                continue;
            };
            if let Err(e) = self
                .auth_records
                .deny(
                    &request.plugin_id,
                    AuthResource::Fs,
                    &target,
                    AuthRecordSource::UserDeny,
                )
                .await
            {
                tracing::warn!(
                    plugin_id = %request.plugin_id,
                    error = %e,
                    "fs_auth: 拒绝记录落账失败"
                );
            }
        }
        tracing::info!(
            plugin_id = %request.plugin_id,
            origin = request.origin.as_str(),
            grant_scope = request.grant_scope.as_str(),
            denied_count = request.paths.len(),
            "fs_auth: user denied forever, deny records written"
        );
    }

    /// 「记住」时落账到授权记录的目标（规范化 + 粒度规则）
    ///
    /// - [`GrantScope::Exact`]：目录 → 目录本身；文件 → 文件本身；
    /// - [`GrantScope::Directory`]：目录 → 自身；文件 → 所在父目录（选择器语义，
    ///   见 [`directory_scope_target`]）。
    ///
    /// 记录里存**规范化路径**（spec §5.1），判定侧同一规范化，避免 `\\?\` 前缀 /
    /// 符号链接造成「明明授权了却仍弹窗」。规范化失败（路径不存在且无父目录，极少）
    /// 返回 `None`，调用方跳过落账而不是存一个永远匹配不上的目标。
    fn grant_target(path: &str, scope: GrantScope) -> Option<String> {
        let canonical = Self::canonicalize_path(path)?;
        let canonical = canonical.to_string_lossy().to_string();
        Some(match scope {
            GrantScope::Exact => canonical,
            GrantScope::Directory => directory_scope_target(&canonical),
        })
    }

    /// 批量请求目录授权（`check_batch`：落账粒度 = 精确，来源 = 插件直请）
    ///
    /// 已授权路径直接放行；未授权路径合并为**一次**弹窗询问，
    /// 全部同意才返回 `true`（任一拒绝或超时即 `false`）。
    /// 供插件 activate 时集中申请数据目录访问权、以及 `host-fs.request-auth`
    /// 预申请路径——两处口径都是「这些路径要能读写」（与旧版无操作维度时一致）。
    pub async fn check_batch(&self, plugin_id: &str, paths: &[String], ops: FsOps) -> bool {
        self.check_batch_scoped(plugin_id, paths, ops, GrantScope::Exact, AuthOrigin::Fs)
            .await
    }

    /// 系统文件选择器结果的授权校验（`host-platform.pick-*` 专用入口）
    ///
    /// 契约（见 WIT `host-platform.pick-files` 注释）：
    /// - 命中已授权目录记录 / 第一方归属目录的路径**静默放行**（不弹框）；
    /// - 只就**未授权部分**弹一次框，落账粒度按所在目录（`GrantScope::Directory`），
    ///   使同目录后续选择免弹；
    /// - 拒绝 / 超时 / 无弹窗通道（无头上下文）→ `false`，调用方据此 `Err`，
    ///   **不得**回传路径（fail-visible：不允许把「被拒」降级成「用户没选」）。
    ///
    /// 操作集 [`FsOps::READ_WRITE`]：用户在选择器里点头的是「这个目录可以用」，
    /// 与旧版无操作维度时的语义逐字一致（真实读 / 写仍各过 `fs:read` / `fs:write`
    /// 权限门——选择器不隐含权限位）。
    pub async fn authorize_picked(&self, plugin_id: &str, paths: &[String]) -> bool {
        self.check_batch_scoped(
            plugin_id,
            paths,
            FsOps::READ_WRITE,
            GrantScope::Directory,
            AuthOrigin::Picker,
        )
        .await
    }

    /// 批量校验本体（`check_batch` 与 `authorize_picked` 共用）
    async fn check_batch_scoped(
        &self,
        plugin_id: &str,
        paths: &[String],
        ops: FsOps,
        grant_scope: GrantScope,
        origin: AuthOrigin,
    ) -> bool {
        let mut ungranted: Vec<String> = Vec::new();
        // 整批共用一次弹窗，档位取**首个未授权路径**判定时的档位（同一批内档位
        // 理论上一致；取首个而不是最后一个，是为了让「用户看到的弹窗」对应
        // 最早触发它的那次判定）
        let mut ask_strategy: Option<AuthStrategy> = None;

        for path in paths {
            let canonical = match Self::canonicalize_path(path) {
                Some(c) => c,
                None => {
                    tracing::warn!(plugin_id = %plugin_id, path = %path, "fs_auth: path canonicalization failed");
                    return false;
                }
            };

            match self.decide_without_dialog(plugin_id, &canonical, ops).await {
                // 硬拒绝：整批失败且**不为它弹窗**（征求同意不该发生在已拒绝的目标上）
                NoDialogDecision::Denied => {
                    tracing::info!(
                        plugin_id = %plugin_id,
                        path = %path,
                        ops = ops.as_wire_str(),
                        "fs_auth: batch denied by explicit deny record"
                    );
                    return false;
                }
                NoDialogDecision::Allowed(_) => continue,
                NoDialogDecision::Ask(strategy) => {
                    ask_strategy.get_or_insert(strategy);
                    ungranted.push(path.clone());
                }
            }
        }

        if ungranted.is_empty() {
            return true;
        }

        self.request_user_auth_batch(
            plugin_id,
            &ungranted,
            ops,
            grant_scope,
            origin,
            ask_strategy.unwrap_or(AuthStrategy::Default),
        )
        .await
    }

    /// 查询路径是否已授权（含所需操作集），**不弹窗**
    ///
    /// 两个无弹窗消费者共用它，语义都是「没有授权就是没有」：
    /// - WASI 预打开目录校验（**仅 worker 类别可达**，ADR 0034——非 worker 声明
    ///   preopen 已被加载期闸门拒绝）：只为已授权目录建 preopen，防止插件借自身
    ///   storage 配置（config 可由插件写）指向任意路径绕过授权弹窗；
    /// - 任务单元（core-task 池线程）：未授权即 fail-visible 拒绝，绝不从池线程弹窗
    ///   （弹窗会占用池槽位最长 30s，且用户在错误的时机看到错误的问题）。
    ///
    /// `needed` = 该消费者要放行的能力集：预打开按声明档位（只读 → 读；读写 → 读+写），
    /// 任务单元按单元种类。**带操作集是必须的**：否则「授权读」就等于「读写都行」，
    /// 无弹窗面会把弹窗面刚做的操作拆分原地架空。
    pub async fn is_granted(&self, plugin_id: &str, path: &str, needed: FsOps) -> bool {
        let Some(canonical) = Self::canonicalize_path(path) else {
            return false;
        };
        matches!(
            self.decide_without_dialog(plugin_id, &canonical, needed)
                .await,
            NoDialogDecision::Allowed(_)
        )
    }

    /// 弹窗请求用户授权（批量：一次弹窗展示全部未授权路径）
    ///
    /// `grant_scope` / `origin` 只影响「记住」的落账粒度与弹窗文案，**不影响
    /// 放行判据**——放行只看免弹窗判定（`decide_without_dialog`）。`ops` 同时决定
    /// 弹窗文案（读取 / 写入 / 读写）与「记住」落账的操作集。
    /// `strategy` 是**弹出时**的档位：写进待应答请求（应答按它落账）并发给前端
    /// （前端据此决定给不给「记住」按钮），pop 之后不再重读（spec §8.1）。
    async fn request_user_auth_batch(
        &self,
        plugin_id: &str,
        paths: &[String],
        ops: FsOps,
        grant_scope: GrantScope,
        origin: AuthOrigin,
        strategy: AuthStrategy,
    ) -> bool {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (reply_tx, reply_rx) = oneshot::channel();

        {
            let mut pending = self.pending_requests.lock().await;
            pending.push(PendingRequest {
                request_id: request_id.clone(),
                plugin_id: plugin_id.to_string(),
                paths: paths.to_vec(),
                ops,
                grant_scope,
                origin,
                strategy,
                reply_tx,
            });
        }

        // 发送弹窗事件到前端（paths 数组 + path 兼容字段 = 首个路径）
        let payload = serde_json::json!({
            "requestId": request_id,
            "pluginId": plugin_id,
            "paths": paths,
            "path": paths.first().cloned().unwrap_or_default(),
            "operation": ops.as_wire_str(),
            "grantScope": grant_scope.as_str(),
            "origin": origin.as_str(),
            "strategy": strategy.as_str(),
        });

        // 无头上下文（测试）没有投递口，无法弹窗：移除已入队请求，保守拒绝
        let Some(emit) = self.emit.as_ref() else {
            let mut pending = self.pending_requests.lock().await;
            pending.retain(|r| r.request_id != request_id);
            tracing::warn!(
                plugin_id = %plugin_id,
                "fs_auth: headless context (no prompt emitter), denying auth request"
            );
            return false;
        };

        if let Err(e) = emit("plugin:fs-auth-request", payload) {
            // 事件未送达前端：请求永远不会被响应，移除已入队条目避免 pending 泄漏
            let mut pending = self.pending_requests.lock().await;
            pending.retain(|r| r.request_id != request_id);
            tracing::error!(error = %e, "fs_auth: failed to emit auth request event");
            return false;
        }

        // 等待用户回复（超时 30 秒自动拒绝）
        match tokio::time::timeout(self.prompt_timeout, reply_rx).await {
            Ok(Ok(allowed)) => {
                tracing::info!(
                    plugin_id = %plugin_id,
                    paths = ?paths,
                    allowed = allowed,
                    "fs_auth: user responded (batch)"
                );
                allowed
            }
            _ => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    paths = ?paths,
                    "fs_auth: batch auth request timed out or cancelled"
                );
                let mut pending = self.pending_requests.lock().await;
                pending.retain(|r| r.request_id != request_id);
                false
            }
        }
    }

    /// 旧版扁平授权前缀回退（`plugin_storage.fs_granted_paths`，**只读**）
    ///
    /// 存量用户的既有目录授权继续生效：命中任一前缀即放行，**视作读写都授权**
    /// （旧记录没有操作维度，spec §5.2 第 3 步）。新授权一律进授权记录表，
    /// 本表不再被写入（写入方法只剩测试用的 [`Self::seed_legacy_granted_path`]）。
    ///
    /// 只在新表**没有任何 allow 记录命中**时才被走到（见 `decide_without_dialog`）：
    /// 用户显式管理过的子树，旧记录对它作废。
    async fn legacy_prefix_matches(&self, plugin_id: &str, canonical: &Path) -> bool {
        let storage_key = "fs_granted_paths".to_string();
        let granted = match self.storage.get(plugin_id, &storage_key).await {
            Ok(Some(serde_json::Value::Array(arr))) => arr,
            _ => return false,
        };

        for prefix_val in &granted {
            if let Some(prefix_str) = prefix_val.as_str() {
                // 与检查路径同一规范化（含 \?\ 剥离），保证两端格式一致
                if let Some(prefix_path) = Self::canonicalize_path(prefix_str) {
                    // Path::strip_prefix 按组件剥离：成功即表示 canonical 位于授权前缀之下，
                    // 组件边界天然防止 `.wasmnest` 误匹配 `.wasmnest-other` 这类相邻目录
                    if canonical.strip_prefix(&prefix_path).is_ok() {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// 弹窗请求用户授权（单路径：操作集就是本次操作；`strategy` 语义同批量入口）
    async fn request_user_auth(
        &self,
        plugin_id: &str,
        path: &str,
        ops: FsOps,
        strategy: AuthStrategy,
    ) -> bool {
        let request_id = uuid::Uuid::new_v4().to_string();

        let (reply_tx, reply_rx) = oneshot::channel();

        {
            let mut pending = self.pending_requests.lock().await;
            pending.push(PendingRequest {
                request_id: request_id.clone(),
                plugin_id: plugin_id.to_string(),
                paths: vec![path.to_string()],
                ops,
                grant_scope: GrantScope::Exact,
                origin: AuthOrigin::Fs,
                strategy,
                reply_tx,
            });
        }

        // 发送弹窗事件到前端
        let payload = serde_json::json!({
            "requestId": request_id,
            "pluginId": plugin_id,
            "path": path,
            "operation": ops.as_wire_str(),
            "grantScope": GrantScope::Exact.as_str(),
            "origin": AuthOrigin::Fs.as_str(),
            "strategy": strategy.as_str(),
        });

        // 无头上下文（测试）没有投递口，无法弹窗：移除已入队请求，保守拒绝
        let Some(emit) = self.emit.as_ref() else {
            let mut pending = self.pending_requests.lock().await;
            pending.retain(|r| r.request_id != request_id);
            tracing::warn!(
                plugin_id = %plugin_id,
                path = %path,
                "fs_auth: headless context (no prompt emitter), denying auth request"
            );
            return false;
        };

        if let Err(e) = emit("plugin:fs-auth-request", payload) {
            // 事件未送达前端：请求永远不会被响应，移除已入队条目避免 pending 泄漏
            let mut pending = self.pending_requests.lock().await;
            pending.retain(|r| r.request_id != request_id);
            tracing::error!(error = %e, "fs_auth: failed to emit auth request event");
            return false;
        }

        // 等待用户回复（超时 30 秒自动拒绝）
        match tokio::time::timeout(self.prompt_timeout, reply_rx).await {
            Ok(Ok(allowed)) => {
                tracing::info!(
                    plugin_id = %plugin_id,
                    path = %path,
                    allowed = allowed,
                    "fs_auth: user responded"
                );
                allowed
            }
            _ => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    path = %path,
                    "fs_auth: auth request timed out or cancelled"
                );
                // 超时后移除 pending request
                let mut pending = self.pending_requests.lock().await;
                pending.retain(|r| r.request_id != request_id);
                false
            }
        }
    }

    /// **测试专用**：预置一条旧版扁平授权前缀（`plugin_storage.fs_granted_paths`）
    ///
    /// 旧表自票 02 起退化为只读回退：生产路径（`respond` 落账）只写授权记录表，
    /// 本方法是**唯一**写入口——闭环用例（session_e2e / task_e2e /
    /// wasi_e2e 预打开）与 legacy 回退用例都靠它构造存量用户状态。
    /// 粒度规则与旧实现逐字一致（目录 → 自身；已存在文件 → 自身；不存在路径 → 父目录）。
    ///
    /// **常编译 pub（wasm-core 纯净性收口票 05b）**：原 `#[cfg(test)]`（wasm-core
    /// 内部测试可见）；lib 集成测试（session_e2e，独立测试二进制）看不到 cfg(test)
    /// 项，提为常编译 pub 供 `wasmnest_wasm_core::…` 消费。
    pub async fn seed_legacy_granted_path(
        &self,
        plugin_id: &str,
        path: &str,
    ) -> anyhow::Result<()> {
        let storage_key = "fs_granted_paths".to_string();

        let mut granted: Vec<serde_json::Value> =
            match self.storage.get(plugin_id, &storage_key).await {
                Ok(Some(serde_json::Value::Array(arr))) => arr,
                _ => Vec::new(),
            };

        // 授权粒度精确化：目录 → 目录本身；已存在文件 → 文件本身；不存在路径
        // （将写入/创建）→ 父目录。不再无条件提取父目录——预授权 home 直子目录
        // （~/.codex、~/.pi、~/.npmrc 等）时父目录为 home 根，一次授权覆盖整个
        // home，架空"访问未授权目录按需弹窗"的兜底（实测 fs_granted_paths 落
        // home 根，任何访问均前缀命中"已授权"、永不弹窗）
        let prefix = if path.is_empty() {
            String::new()
        } else {
            let p = Path::new(path);
            if p.is_dir() {
                p.to_string_lossy().to_string()
            } else if p.exists() {
                p.to_string_lossy().to_string()
            } else {
                p.parent()
                    .map(|pp| pp.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.to_string())
            }
        };

        if !prefix.is_empty() && !granted.iter().any(|v| v.as_str() == Some(prefix.as_str())) {
            granted.push(serde_json::Value::String(prefix));
        }

        self.storage
            .set(plugin_id, &storage_key, serde_json::Value::Array(granted))
            .await?;

        Ok(())
    }

    /// 规范化路径（解析 ..、符号链接等）
    ///
    /// Windows 上 `canonicalize` 返回 `\\?\C:\...` verbatim 格式，而 fallback
    /// 分支（父目录尚不存在）只能返回普通路径——两者格式不一致会导致与已授权
    /// 前缀的匹配失败（首次写入新子目录文件时误弹窗）。此处统一剥掉 `\\?\` 前缀。
    fn canonicalize_path(path: &str) -> Option<PathBuf> {
        let p = Path::new(path);
        // 文件可能不存在（如即将写入的文件），使用父目录 canonicalize
        let result = if p.exists() {
            p.canonicalize().ok()
        } else if let Some(parent) = p.parent() {
            // 父目录可能存在
            if parent.exists() {
                let canon_parent = parent.canonicalize().ok()?;
                let file_name = p.file_name()?;
                Some(canon_parent.join(file_name))
            } else {
                // 父目录也不存在：直接使用路径（后续 fs_write 会创建）。
                // 规范化分隔符——canonicalize 在 Windows 上统一为 `\`，
                // 否则与已授权前缀的匹配会因 `/` 与 `\` 混用而失败
                let raw = p.to_string_lossy();
                #[cfg(windows)]
                let normalized = PathBuf::from(raw.replace('/', "\\"));
                #[cfg(not(windows))]
                let normalized = PathBuf::from(raw.into_owned());
                Some(normalized)
            }
        } else {
            Some(p.to_path_buf())
        };
        result.map(|pb| strip_verbatim_prefix(&pb))
    }
}

/// 「目录粒度」授权的落账目标：选到目录 → 目录本身；选到文件 → 所在父目录
///
/// 与 [`FsAuthChecker::grant_target`] 里 `GrantScope::Exact` 的粒度规则不同：那里对
/// **文件**落账到文件本身（插件直请路径时用户点的就是那个文件）；选择器场景用户点头
/// 的是「这个目录」，故取父目录。取不到父目录（盘符根 / 相对路径）时退回原路径——
/// 宁可判据保守，也不要凭空授权一个更大的前缀。
pub(crate) fn directory_scope_target(path: &str) -> String {
    let p = Path::new(path);
    if p.is_dir() {
        return path.to_string();
    }
    p.parent()
        .map(|pp| pp.to_string_lossy().to_string())
        .filter(|parent| !parent.is_empty())
        .unwrap_or_else(|| path.to_string())
}

/// 剥掉 Windows canonicalize 的 `\\?\` verbatim 前缀，统一路径格式
#[cfg(windows)]
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

#[cfg(not(windows))]
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// 第一方集成目录判定的可注入 home 变体（测试用临时目录构造伪 HOME，
/// 与 `component.rs::resolve_preopen_dirs_with_home` 同一形态）
///
/// `home = None` 时 `Home` 形态**不放开**（只剩段名形态可用）：取不到家目录就把
/// `~/.agents` 这类清单退化成「任意位置的 `.agents` 段」是反向的降级。
///
/// **票 08（P0-2）**：清单改为参数注入（[`FsAuthChecker::new`] 第 3 参），
/// 判定逻辑（机制）留本 crate 不变；空表 = 恒不命中。
fn first_party_dir_matches_with_home(
    table: &[(&'static str, Vec<TrustedDir>)],
    plugin_id: &str,
    canonical: &Path,
    home: Option<&Path>,
) -> bool {
    let Some((_, dirs)) = table.iter().find(|(id, _)| *id == plugin_id) else {
        return false;
    };
    dirs.iter().any(|d| match d {
        TrustedDir::Home(rel) => match home {
            // 组件边界匹配（strip_prefix）：`~/.agents` 不覆盖 `~/.agentsx`
            Some(h) => canonical.strip_prefix(h.join(rel)).is_ok(),
            None => false,
        },
        TrustedDir::ProjectSegment(seg) => path_has_named_segment(canonical, seg),
    })
}

/// 路径的**自身或任一祖先目录段**是否恰为 `seg`（段名全等，不是子串）
///
/// 命中 `<project>/.claude`（目录本身）与 `<project>/.claude/settings.json`、
/// `<project>/.claude/hooks/x.py`（后代），不命中 `<project>/.claudex/…`
/// 与 `<project>/x.claude/…`——旧实现用 `contains(".claude/")` 子串，相邻命名一并放过。
fn path_has_named_segment(canonical: &Path, seg: &str) -> bool {
    canonical
        .ancestors()
        .any(|a| a.file_name().is_some_and(|name| name == seg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::storage::PluginStorage;
    use std::sync::Arc;

    /// 校验器共用的内存库（生产初始化跑一遍：迁移被破坏时本模块用例随之变红）
    fn checker_storage() -> Arc<PluginStorage> {
        let db = Database::new(&std::path::Path::new(":memory:")).unwrap();
        db.init_schema().unwrap();
        // Mutex 为 tokio::sync::Mutex（super::* 引入），与 PluginStorage 签名一致
        Arc::new(PluginStorage::new(Arc::new(std::sync::Mutex::new(db))))
    }

    /// 内存数据库 + 无投递口（None）的校验器：无法弹窗，未授权路径应保守拒绝
    ///
    /// 默认空豁免表（票 08/P0-2：豁免表宿主注入，测试默认无豁免）——普通用例
    /// 语义与旧「无清单条目插件」一致；first-party 专项用例改用
    /// [`first_party_checker`]（注入测试表）。
    async fn headless_checker() -> FsAuthChecker {
        FsAuthChecker::new(checker_storage(), None, Vec::new())
    }

    /// first-party 专项用例的校验器：注入**测试特制**豁免表（中性 plugin_id，
    /// 不携带产品 wire——purity 票 08：wasm-core 连测试也不得持产品清单；
    /// 目录形态与 lib 真源清单一致，验证的是判定机制而非产品绑定）
    async fn first_party_checker() -> FsAuthChecker {
        FsAuthChecker::new(checker_storage(), None, test_first_party_table())
    }

    /// 测试特制豁免表（目录形态 = lib `first_party_dirs.rs` 真源清单的镜像；
    /// 插件 id 中性化——判定逻辑与插件名无关）
    fn test_first_party_table() -> Vec<(&'static str, Vec<TrustedDir>)> {
        vec![
            (
                "test.agent-hub",
                vec![
                    TrustedDir::Home(".agents"),
                    TrustedDir::Home(".claude/skills"),
                    TrustedDir::Home(".pi/agent/skills"),
                    TrustedDir::Home(".wasmnest/agent-hub/runs"),
                ],
            ),
            (
                "test.bedcode",
                vec![
                    TrustedDir::ProjectSegment(".claude"),
                    TrustedDir::ProjectSegment(".codex"),
                    TrustedDir::ProjectSegment(".pi"),
                    TrustedDir::ProjectSegment(".opencode"),
                ],
            ),
        ]
    }

    /// 捕获的弹窗事件（`(event, payload)`）
    ///
    /// 闭包是同步 `Fn`（投递口不允许 await），故用 std Mutex：临界区只有 push，
    /// 不跨 await 持锁。
    type EmittedLog = Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>;

    /// 可弹窗的校验器（注入投递口）＋捕获事件，超时可调小
    ///
    /// 用**真实弹窗链路**替代「手工塞 pending」：档位 → 弹窗 payload → 应答 / 超时
    /// 的契约必须在同一条链上验（spec §12.2 的教训：只测纯函数会让落账粒度一类的
    /// 变异全绿）。
    async fn promptable_checker(timeout: Duration) -> (FsAuthChecker, EmittedLog) {
        let log: EmittedLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = log.clone();
        let emit: PromptEmitter = Arc::new(move |event: &str, payload: serde_json::Value| {
            captured
                .lock()
                .expect("emit log poisoned")
                .push((event.to_string(), payload));
            Ok(())
        });
        (
            FsAuthChecker::with_emitter(checker_storage(), Some(emit), Vec::new())
                .with_prompt_timeout(timeout),
            log,
        )
    }

    /// 等弹窗 payload 出现（真实链路：判定 → emit → 待应答）
    async fn wait_for_prompt(log: &EmittedLog) -> serde_json::Value {
        for _ in 0..400 {
            if let Some(payload) = log
                .lock()
                .expect("emit log poisoned")
                .last()
                .map(|(_, p)| p.clone())
            {
                return payload;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("no fs-auth prompt was emitted");
    }

    /// canonical 后的临时目录根：`matched_layer` 收的是生产形态（已 canonicalize）路径，
    /// 拿未规范化的 `temp_dir()` 比对会因符号链接（macOS `/var` → `/private/var`）
    /// 让前缀与段名判定错位，测出与实现无关的红
    fn canonical_temp_dir() -> PathBuf {
        std::fs::canonicalize(std::env::temp_dir()).expect("temp dir must be canonicalizable")
    }

    /// 票 07 红测本体：**第三方** `fs:read` 插件读任意位置的 `.claude/` 不再免弹窗
    ///
    /// 旧实现按 `.claude/` 子串放行所有插件，`/tmp/x/.claude/settings.json` 这种
    /// 攻击者可控位置也免弹窗——「访问未授权目录按需弹窗」的兜底被架空。
    /// 无头上下文没有弹窗通道 → 未授权即拒；这正是判据：改造前这里返回 true。
    #[tokio::test]
    async fn third_party_cannot_silently_read_claude_dir() {
        let checker = headless_checker().await;
        let path = std::env::temp_dir()
            .join(".claude")
            .join("settings.json")
            .to_string_lossy()
            .to_string();
        assert!(
            !checker
                .check_batch("com.wasmnest.test", &[path.clone()], FsOps::READ)
                .await,
            "第三方插件不得静默读 .claude 目录段: {path}"
        );
        assert!(
            !checker.check("com.wasmnest.test", &path, FsOp::Read).await,
            "单路径入口同判据（check 与 check_batch 不能两套答案）"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "拒绝路径不得残留 pending"
        );
    }

    /// 第一方按归属清单免弹窗：bedcode 写项目集成目录（段名形态）
    #[tokio::test]
    async fn first_party_project_integration_dirs_stay_silent() {
        let checker = first_party_checker().await;
        for seg in [".claude", ".codex", ".pi", ".opencode"] {
            let path = std::env::temp_dir()
                .join("some-project")
                .join(seg)
                .join("settings.json")
                .to_string_lossy()
                .to_string();
            assert!(
                checker
                    .check_batch("test.bedcode", &[path.clone()], FsOps::WRITE)
                    .await,
                "会话启动前写项目集成目录是本插件的产品面，不得弹窗: {path}"
            );
        }
    }

    /// 收紧的另一半：第一方插件**清单外**的路径不再任意放行
    ///
    /// 旧「插件白名单 = 任意路径免弹窗」把 bedcode / file-transfer 变成
    /// 全盘可读可写；改造后它们与第三方一样只覆盖到具名目录，其余走弹窗 + 记住。
    #[tokio::test]
    async fn first_party_outside_declared_dirs_requires_grant() {
        let checker = first_party_checker().await;
        let outside = std::env::temp_dir()
            .join("home-not-declared")
            .join("secrets.env")
            .to_string_lossy()
            .to_string();
        for plugin in ["test.bedcode", "test.agent-hub"] {
            assert!(
                !checker
                    .check_batch(plugin, &[outside.clone()], FsOps::READ)
                    .await,
                "{plugin} 读清单外路径必须走授权，不得免弹窗"
            );
        }
        // file-transfer 的白名单条目已删：它一个 fs 原语都不调（走 peer-net），
        // 留着特权只剩风险没有收益
        assert!(
            !checker
                .check_batch("com.wasmnest.file-transfer", &[outside], FsOps::READ)
                .await,
            "file-transfer 不再享有 fs 特权（零消费者）"
        );
    }

    #[tokio::test]
    async fn check_batch_ungranted_headless_denied_and_pending_cleaned() {
        let checker = headless_checker().await;
        // 未授权路径 + 无头上下文：保守拒绝，且不残留 pending 条目（泄漏回归）
        let path = std::env::temp_dir().to_string_lossy().to_string();
        assert!(
            !checker
                .check_batch("com.wasmnest.test", &[path], FsOps::READ)
                .await
        );
        assert!(checker.pending_requests.lock().await.is_empty());
    }

    /// 命中层的归属必须说得出来（日志「为什么这次没弹框」全靠它）
    ///
    /// 票 02 起旧记录与新记录分成两层：`legacy-grant` 与 `record-grant` 必须报得开，
    /// 否则「为什么这次没弹框」在迁移期无法回答（是旧记录在兜底还是新记录命中）。
    #[tokio::test]
    async fn matched_layer_names_the_reason_for_no_dialog() {
        let checker = first_party_checker().await;
        let base = canonical_temp_dir();
        let dir = base.join("fs-auth-layer");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.txt");

        // 未授权：无层可报（结论 = 进询问，且带上弹出时档位 = 默认档）
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Ask(AuthStrategy::Default),
            "未授权路径不得凭空报出一层"
        );

        // 旧版扁平前缀（只读回退）→ legacy-grant
        checker
            .seed_legacy_granted_path("com.wasmnest.test", &file.to_string_lossy())
            .await
            .unwrap();
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::LegacyGrant)
        );

        // 授权记录（走真实 respond 落账）→ record-grant
        let second = dir.join("g.txt");
        let request_id = "req-layer-record";
        seed_pending(
            &checker,
            request_id,
            "com.wasmnest.test",
            vec![second.to_string_lossy().to_string()],
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
            AuthStrategy::Default,
        )
        .await;
        checker.respond(request_id, FsDecision::AllowRemember).await;
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &second, FsOps::READ)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::RecordGrant)
        );

        // 第一方目录 → first-party-dir（与上面两层分得开）
        let claude = base.join("proj").join(".claude").join("settings.json");
        assert_eq!(
            checker
                .decide_without_dialog("test.bedcode", &claude, FsOps::WRITE)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::FirstPartyDir)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 清单判据表（可注入 home 的纯函数面，逐形态锁边界）
    #[test]
    fn first_party_dir_rules_match_segments_and_home_prefixes() {
        let home = std::path::Path::new("/home/u");
        let p = |s: &str| std::path::PathBuf::from(s);
        // 判定逻辑与插件名无关：注入测试表（中性 id，形态与 lib 真源清单一致）
        let table = test_first_party_table();

        // Home 形态：家目录下按组件前缀命中，相邻命名与「别处的同名目录」都不命中
        assert!(first_party_dir_matches_with_home(
            &table,
            "test.agent-hub",
            &p("/home/u/.agents/skills/x/SKILL.md"),
            Some(home)
        ));
        assert!(first_party_dir_matches_with_home(
            &table,
            "test.agent-hub",
            &p("/home/u/.claude/skills/a.md"),
            Some(home)
        ));
        assert!(
            !first_party_dir_matches_with_home(
                &table,
                "test.agent-hub",
                &p("/home/u/.claude/settings.json"),
                Some(home)
            ),
            "test.agent-hub 只拿到 skills 子树，不是整个 ~/.claude"
        );
        // 自身数据根下的输出目录（判据 ②）：runs 子树任一层放行，
        // 但仅限 runs/——统计库（同数据根下非 runs）不走豁免
        assert!(first_party_dir_matches_with_home(
            &table,
            "test.agent-hub",
            &p("/home/u/.wasmnest/agent-hub/runs/skills-scan-3.log"),
            Some(home)
        ));
        assert!(first_party_dir_matches_with_home(
            &table,
            "test.agent-hub",
            &p("/home/u/.wasmnest/agent-hub/runs/a/b/c.log"),
            Some(home)
        ));
        assert!(
            !first_party_dir_matches_with_home(
                &table,
                "test.agent-hub",
                &p("/home/u/.wasmnest/agent-hub/stats.db"),
                Some(home)
            ),
            "豁免只到 runs/ 子目录，同一数据根下的其他文件不放开"
        );
        assert!(!first_party_dir_matches_with_home(
            &table,
            "test.agent-hub",
            &p("/home/u/.wasmnest/agent-hubx/runs/x.log"),
            Some(home)
        ));
        assert!(!first_party_dir_matches_with_home(
            &table,
            "test.agent-hub",
            &p("/home/other/.agents/x"),
            Some(home)
        ));
        assert!(
            !first_party_dir_matches_with_home(
                &table,
                "test.agent-hub",
                &p("/home/u/.agentsx/y"),
                Some(home)
            ),
            "组件边界：前缀不得吃掉相邻目录名"
        );
        // 取不到 home → Home 形态不放开（绝不退化成「任意位置的 .agents 段」）
        assert!(!first_party_dir_matches_with_home(
            &table,
            "test.agent-hub",
            &p("/home/u/.agents/skills/x"),
            None
        ));

        // ProjectSegment 形态：段名全等，非子串
        assert!(first_party_dir_matches_with_home(
            &table,
            "test.bedcode",
            &p("/srv/proj/.claude/hooks/x.py"),
            None
        ));
        assert!(
            first_party_dir_matches_with_home(
                &table,
                "test.bedcode",
                &p("/srv/proj/.claude"),
                None
            ),
            "集成目录本身（read_dir / 建目录）也要覆盖"
        );
        assert!(
            !first_party_dir_matches_with_home(
                &table,
                "test.bedcode",
                &p("/srv/proj/.claudex/a"),
                None
            ),
            "子串不得放过相邻段名"
        );
        assert!(!first_party_dir_matches_with_home(
            &table,
            "test.bedcode",
            &p("/srv/proj/x.claude/a"),
            None
        ));
        // 收紧的本体：会话项目根本身**不在**清单里（今天它免弹窗 = 全盘可读）
        assert!(
            !first_party_dir_matches_with_home(
                &table,
                "test.bedcode",
                &p("/srv/proj/src/main.rs"),
                None
            ),
            "项目根文件浏览须走弹窗 + 记住，不再有任意路径特权"
        );

        // 未列入清单的插件：一律不放开
        for id in [
            "com.wasmnest.test",
            "com.wasmnest.ai-chatbox",
            "com.example.third",
        ] {
            assert!(
                !first_party_dir_matches_with_home(
                    &table,
                    id,
                    &p("/home/u/.claude/settings.json"),
                    Some(home)
                ),
                "{id} 不在第一方清单里"
            );
        }
    }

    /// 投影完备性：注入表里每一条都被导出，且顺序一致（机制面）
    ///
    /// 少一条 = 授权管理界面看不见一项免询问特权（spec §7 的不可见特权正是要避免的）；
    /// 顺序一致 = 界面渲染顺序与审计面（清单本身）可逐行对照。
    /// 产品清单的 well-formed 审计（条目非空 / id 不重复 / 只放第一方 / 已知消费者
    /// 不变）随清单出厂迁移 lib（`src-tauri/src/first_party_dirs.rs` 模块测试）。
    #[test]
    fn first_party_projection_covers_every_listed_dir() {
        let table = test_first_party_table();
        let listed: Vec<(&str, &str)> = table
            .iter()
            .flat_map(|(id, dirs)| {
                dirs.iter().map(move |d| {
                    (
                        *id,
                        match d {
                            TrustedDir::Home(rel) => *rel,
                            TrustedDir::ProjectSegment(seg) => *seg,
                        },
                    )
                })
            })
            .collect();
        let projected: Vec<(&str, &str)> = FsAuthChecker::new(checker_storage(), None, table)
            .first_party_trusted_dirs()
            .iter()
            .map(|entry| (entry.plugin_id, entry.value))
            .collect();
        assert_eq!(
            projected, listed,
            "投影必须与清单逐条对齐（少一条即界面上少一项可见特权）"
        );
    }

    #[tokio::test]
    async fn check_batch_empty_paths_returns_true() {
        let checker = headless_checker().await;
        assert!(
            checker
                .check_batch("com.wasmnest.test", &[], FsOps::READ)
                .await
        );
        assert!(checker.pending_requests.lock().await.is_empty());
    }

    /// canonicalize_path：父目录也不存在（首次写入新子目录文件）时应规范化分隔符
    #[test]
    fn canonicalize_path_normalizes_separators() {
        let fake = format!(
            "{}/sub-not-exist/deep-not-exist/file.jsonl",
            std::env::temp_dir().to_string_lossy()
        );
        let canon = FsAuthChecker::canonicalize_path(&fake).expect("fallback must succeed");
        // 平台感知断言：Windows 规范化分隔符为 `\`，其余平台保持原样
        // （canonicalize_path 的 fallback 在 cfg(windows) 下 replace 分隔符，
        //  非 Windows 直接原样返回——见函数注释）
        #[cfg(not(windows))]
        assert_eq!(canon.to_string_lossy().as_ref(), fake);
        #[cfg(windows)]
        assert_eq!(
            canon.to_string_lossy().as_ref(),
            fake.replace('/', "\\"),
            "fallback path must use backslash on Windows"
        );
    }

    /// 已授权前缀：边界匹配 + 尚不存在的子路径（混合分隔符）也应放行
    #[tokio::test]
    async fn granted_path_prefix_respects_separator_boundary() {
        let checker = headless_checker().await;
        let base = std::env::temp_dir();
        let granted_dir = base.join("fs-auth-granted");
        std::fs::create_dir_all(&granted_dir).unwrap();
        let granted = granted_dir.to_string_lossy().to_string();

        // 保存授权前缀（父目录形式）
        checker
            .seed_legacy_granted_path("com.wasmnest.test", &format!("{}/data.jsonl", granted))
            .await
            .unwrap();

        // 前缀内、尚不存在的子目录 + 混合分隔符 → 放行（回归首次写新目录场景）
        let inside = format!("{}/conversations/new.jsonl", granted);
        assert!(
            checker
                .check_batch("com.wasmnest.test", &[inside], FsOps::WRITE)
                .await
        );

        // 相邻目录（前缀后紧跟非分隔符）不放行
        let adjacent = format!("{}2/file.jsonl", granted);
        assert!(
            !checker
                .check_batch("com.wasmnest.test", &[adjacent], FsOps::WRITE)
                .await
        );

        std::fs::remove_dir_all(&granted_dir).unwrap();
    }

    // ==================== 系统选择器授权（`host-platform.pick-*` 的结果门）====================

    /// 在临时目录下建一个夹具目录，返回其 canonical 路径
    fn fixture_dir(tag: &str) -> PathBuf {
        let dir = canonical_temp_dir().join(tag);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    /// C-104 契约本体：选中文件**落在已授权目录下** → 静默放行，不弹授权框
    ///
    /// 无头上下文没有弹窗通道：若实现仍去弹窗，这里会因无 AppHandle 被拒——
    /// 断言为 true 本身就证明了「没有多问一次」。
    #[tokio::test]
    async fn picked_file_under_granted_dir_is_silent() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-pick-granted");
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").expect("write fixture");
        let file = file.to_string_lossy().to_string();

        // 前置：未授权时同一条路径必须被拒（否则本测试恒真）
        assert!(
            !checker
                .authorize_picked("com.wasmnest.test", &[file.clone()])
                .await,
            "未授权的选择结果在无弹窗通道下必须拒绝"
        );

        checker
            .seed_legacy_granted_path("com.wasmnest.test", &dir.to_string_lossy())
            .await
            .unwrap();
        assert!(
            checker.authorize_picked("com.wasmnest.test", &[file]).await,
            "已授权目录下的选择不得再弹框"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "静默放行不得残留 pending"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C-106 落账粒度：选到**文件** → 目录级授权（父目录），同目录兄弟文件随之免弹
    ///
    /// 这是「一次选 N 个文件不弹 N 次框」的落点：若落账到文件本身，
    /// 同目录换文件就会重新弹框。
    #[tokio::test]
    async fn picker_grant_scope_is_directory_so_siblings_are_covered() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-pick-scope");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, b"x").expect("write a");
        std::fs::write(&b, b"y").expect("write b");

        assert_eq!(
            directory_scope_target(&a.to_string_lossy()),
            dir.to_string_lossy().to_string(),
            "选到文件 → 落账到所在目录"
        );
        assert_eq!(
            directory_scope_target(&dir.to_string_lossy()),
            dir.to_string_lossy().to_string(),
            "选到目录 → 落账到该目录本身（不得上溯到父目录）"
        );

        // 落账到目录（旧记录口径：目录前缀即覆盖整棵子树）后，兄弟文件必须免弹
        let granted = directory_scope_target(&a.to_string_lossy());
        checker
            .seed_legacy_granted_path("com.wasmnest.test", &granted)
            .await
            .unwrap();
        assert!(
            checker
                .is_granted("com.wasmnest.test", &b.to_string_lossy(), FsOps::READ_WRITE)
                .await
        );
        assert!(
            checker
                .authorize_picked("com.wasmnest.test", &[b.to_string_lossy().to_string()])
                .await,
            "同目录另一个文件应被目录级授权覆盖"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 反例：相邻目录不因「同一个父目录」而放行（组件边界）
    #[tokio::test]
    async fn picker_grant_does_not_leak_to_adjacent_dir() {
        let checker = headless_checker().await;
        let base = canonical_temp_dir();
        let granted = fixture_dir("fs-auth-pick-adj-granted");
        let sibling = fixture_dir("fs-auth-pick-adj-other");
        let file = sibling.join("secret.txt");
        std::fs::write(&file, b"s").expect("write fixture");

        checker
            .seed_legacy_granted_path(
                "com.wasmnest.test",
                &directory_scope_target(&granted.to_string_lossy()),
            )
            .await
            .unwrap();
        assert!(
            !checker
                .authorize_picked("com.wasmnest.test", &[file.to_string_lossy().to_string()])
                .await,
            "相邻目录（{}）不在授权范围内",
            sibling.display()
        );
        let _ = base;
        std::fs::remove_dir_all(&granted).ok();
        std::fs::remove_dir_all(&sibling).ok();
    }

    /// C-107 用户取消（空选择）→ 直接放行，且**不产生**授权请求
    #[tokio::test]
    async fn empty_pick_is_cancelled_not_denied() {
        let checker = headless_checker().await;
        assert!(checker.authorize_picked("com.wasmnest.test", &[]).await);
        assert!(checker.pending_requests.lock().await.is_empty());
    }

    /// 混合批：已授权目录下的文件静默放行，未授权部分才走弹窗（且无通道 → 整批拒）
    #[tokio::test]
    async fn mixed_batch_only_ungranted_part_needs_dialog() {
        let checker = headless_checker().await;
        let granted = fixture_dir("fs-auth-pick-mix-granted");
        let other = fixture_dir("fs-auth-pick-mix-other");
        let inside = granted.join("in.txt");
        let outside = other.join("out.txt");
        std::fs::write(&inside, b"1").expect("write in");
        std::fs::write(&outside, b"2").expect("write out");

        checker
            .seed_legacy_granted_path("com.wasmnest.test", &granted.to_string_lossy())
            .await
            .unwrap();
        let batch = vec![
            inside.to_string_lossy().to_string(),
            outside.to_string_lossy().to_string(),
        ];
        assert!(
            !checker.authorize_picked("com.wasmnest.test", &batch).await,
            "含未授权路径的批次不能因为部分已授权而整批放行"
        );

        // 去掉未授权项后，同一批的其余部分静默放行
        assert!(
            checker
                .authorize_picked("com.wasmnest.test", &[inside.to_string_lossy().to_string()])
                .await
        );
        std::fs::remove_dir_all(&granted).ok();
        std::fs::remove_dir_all(&other).ok();
    }

    /// 落账去重：同一目录重复授权不得堆出重复条目（否则列表无界增长）
    #[tokio::test]
    async fn saving_same_grant_twice_does_not_duplicate() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-pick-dedupe");
        let path = dir.to_string_lossy().to_string();
        checker
            .seed_legacy_granted_path("com.wasmnest.test", &path)
            .await
            .unwrap();
        checker
            .seed_legacy_granted_path("com.wasmnest.test", &path)
            .await
            .unwrap();
        let stored = checker
            .storage
            .get("com.wasmnest.test", "fs_granted_paths")
            .await
            .expect("storage read");
        let entries = match stored {
            Some(serde_json::Value::Array(arr)) => arr.len(),
            _ => 0,
        };
        assert_eq!(entries, 1, "重复授权不得堆叠条目");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C-106 落账链本体（驱动真实 `respond` 路径）：`GrantScope::Directory` 的请求
    /// 在「允许 + 记住」后，授权必须落在**目录**上——同目录兄弟文件随之免弹
    ///
    /// 本条是目录粒度的**唯一**行为锁：只断言 `directory_scope_target` 纯函数的话，
    /// 把 `respond` 里的 `GrantScope::Directory => path.clone()` 改回「文件本身」
    /// 仍会全绿（上一轮变异自检实测如此）——落账发生在 `respond` 内部，必须从这里断言。
    #[tokio::test]
    async fn respond_with_directory_scope_grants_the_whole_directory() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-pick-respond-dir");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, b"x").expect("write a");
        std::fs::write(&b, b"y").expect("write b");

        // 手工入队一个待响应请求（无头上下文弹不出也入不了队，故直接构造 pending
        // —— 测的正是 `respond` 里的落账分支）
        let request_id = "req-directory-scope";
        seed_pending(
            &checker,
            request_id,
            "com.wasmnest.test",
            vec![a.to_string_lossy().to_string()],
            FsOps::READ_WRITE,
            GrantScope::Directory,
            AuthOrigin::Picker,
            AuthStrategy::Default,
        )
        .await;

        checker.respond(request_id, FsDecision::AllowRemember).await;

        assert!(
            checker
                .is_granted("com.wasmnest.test", &b.to_string_lossy(), FsOps::READ_WRITE)
                .await,
            "目录粒度授权必须覆盖同目录的其它文件（用户点头的是这个目录）"
        );
        // 选择器落账的操作集是读写：读能力包含在「读写」里（集合覆盖而非相等）
        assert!(
            checker
                .is_granted("com.wasmnest.test", &b.to_string_lossy(), FsOps::READ)
                .await,
            "「读写」授权必须覆盖单独的读请求"
        );
        assert!(checker.pending_requests.lock().await.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 反例（同一条链的另一侧）：`GrantScope::Exact` 的请求只授权**那个文件**，
    /// 同目录兄弟文件仍需重新授权——两个粒度必须真的不同
    #[tokio::test]
    async fn respond_with_exact_scope_grants_only_that_path() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-pick-respond-exact");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, b"x").expect("write a");
        std::fs::write(&b, b"y").expect("write b");

        let request_id = "req-exact-scope";
        seed_pending(
            &checker,
            request_id,
            "com.wasmnest.test",
            vec![a.to_string_lossy().to_string()],
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
            AuthStrategy::Default,
        )
        .await;

        checker.respond(request_id, FsDecision::AllowRemember).await;

        assert!(
            checker
                .is_granted("com.wasmnest.test", &a.to_string_lossy(), FsOps::READ)
                .await
        );
        assert!(
            !checker
                .is_granted("com.wasmnest.test", &b.to_string_lossy(), FsOps::READ)
                .await,
            "精确粒度不得顺手授权同目录的其它文件"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 反例：拒绝 / 不勾「记住」都不得留下任何授权（否则下次静默放行）
    #[tokio::test]
    async fn respond_deny_or_no_remember_leaves_no_grant() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-pick-respond-deny");
        let a = dir.join("a.txt");
        std::fs::write(&a, b"x").expect("write a");
        let a = a.to_string_lossy().to_string();

        for (id, decision) in [
            ("req-deny", FsDecision::Deny),
            ("req-no-remember", FsDecision::AllowOnce),
        ] {
            seed_pending(
                &checker,
                id,
                "com.wasmnest.test",
                vec![a.clone()],
                FsOps::READ_WRITE,
                GrantScope::Directory,
                AuthOrigin::Picker,
                AuthStrategy::Default,
            )
            .await;
            checker.respond(id, decision).await;
            assert!(
                !checker
                    .is_granted("com.wasmnest.test", &a, FsOps::READ_WRITE)
                    .await,
                "{id}（decision={}）不得落授权",
                decision.as_str()
            );
        }
        assert!(checker.pending_requests.lock().await.is_empty());
        // 一次性放行（remember=false）同样**不写旧表**：旧表自票 02 起只读
        assert!(
            checker
                .storage
                .get("com.wasmnest.test", "fs_granted_paths")
                .await
                .expect("storage read")
                .is_none(),
            "票 02 后 fs_granted_paths 不得再被写入"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ==================== is_granted（WASI 预打开校验，无弹窗） ====================

    /// `is_granted` 的免弹窗集合 == `matched_layer` 的集合（票 07 后不再等于「任意路径」）
    ///
    /// 它是 WASI 预打开与任务单元的唯一判据：这里放开一分，那两条无弹窗通道就放开一分。
    #[tokio::test]
    async fn is_granted_covers_first_party_dirs_and_persisted_grants_only() {
        let checker = first_party_checker().await;
        // 第三方 + 任意位置的 .claude 段 → 不放开（旧实现在这里返回 true）
        let third_party = std::env::temp_dir()
            .join(".claude")
            .to_string_lossy()
            .to_string();
        assert!(
            !checker
                .is_granted("com.wasmnest.test", &third_party, FsOps::READ)
                .await,
            "第三方插件不得经 is_granted 静默拿到 .claude 目录"
        );
        // 第一方清单内 → 放开（且不经弹窗）
        assert!(
            checker
                .is_granted(
                    "test.bedcode",
                    &std::env::temp_dir()
                        .join("proj/.claude/settings.json")
                        .to_string_lossy(),
                    FsOps::WRITE
                )
                .await
        );
        // 第一方清单外 → 不放开（旧「插件白名单 = 任意路径」已退役）
        assert!(
            !checker
                .is_granted(
                    "test.bedcode",
                    &std::env::temp_dir().to_string_lossy(),
                    FsOps::READ
                )
                .await,
            "白名单插件的全盘特权已退役"
        );
        // 旧记录授权 → 放开（读写都算，spec §5.2 第 3 步），且只对获授权的插件放开
        let dir = canonical_temp_dir().join("fs-auth-isgranted");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_string_lossy().to_string();
        assert!(
            !checker
                .is_granted("com.wasmnest.test", &path, FsOps::READ)
                .await
        );
        checker
            .seed_legacy_granted_path("com.wasmnest.test", &path)
            .await
            .unwrap();
        assert!(
            checker
                .is_granted("com.wasmnest.test", &path, FsOps::READ)
                .await
        );
        assert!(
            checker
                .is_granted("com.wasmnest.test", &path, FsOps::READ_WRITE)
                .await,
            "旧记录视作读写都授权（存量用户零感知）"
        );
        assert!(
            !checker
                .is_granted("com.wasmnest.other", &path, FsOps::READ)
                .await
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ==================== 票 02：授权记录按操作拆分（读 / 写）====================

    /// 手工入队一个待应答请求（`strategy` = 该弹窗**弹出时**的档位）
    ///
    /// 绝大多数用例请走 [`promptable_checker`] 的真实弹窗链路；本入口留给
    /// 「弹窗已弹出、档位随后被改」这类必须构造特定 pending 状态的场景。
    #[allow(clippy::too_many_arguments)]
    async fn seed_pending(
        checker: &FsAuthChecker,
        request_id: &str,
        plugin_id: &str,
        paths: Vec<String>,
        ops: FsOps,
        scope: GrantScope,
        origin: AuthOrigin,
        strategy: AuthStrategy,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        checker.pending_requests.lock().await.push(PendingRequest {
            request_id: request_id.to_string(),
            plugin_id: plugin_id.to_string(),
            paths,
            ops,
            grant_scope: scope,
            origin,
            strategy,
            reply_tx: tx,
        });
        rx
    }

    /// 走真实 `respond` 落账（等价于用户在弹出的授权框里点「允许 + 记住」）
    async fn grant_via_respond(
        checker: &FsAuthChecker,
        request_id: &str,
        plugin_id: &str,
        path: &str,
        ops: FsOps,
        scope: GrantScope,
        origin: AuthOrigin,
    ) {
        seed_pending(
            checker,
            request_id,
            plugin_id,
            vec![path.to_string()],
            ops,
            scope,
            origin,
            AuthStrategy::Default,
        )
        .await;
        checker.respond(request_id, FsDecision::AllowRemember).await;
    }

    /// C5 正例：授权**读**某目录后，对该目录的**写**要再问一次
    ///
    /// 无头上下文没有弹窗通道，「再问一次」在这里的表现是 `check(write) == false`
    /// 且免弹窗判定未命中任何层（→ 走到弹窗层）。变异判据：把记录匹配的操作集检查
    /// 去掉（读授权即覆盖写），本条转红。
    #[tokio::test]
    async fn read_grant_asks_again_for_write() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ops-read-only");
        let file = dir.join("data.jsonl");
        let file_s = file.to_string_lossy().to_string();

        grant_via_respond(
            &checker,
            "req-read",
            "com.wasmnest.test",
            &file_s,
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
        )
        .await;

        // 读：命中记录层 → 静默放行（无头上下文能返回 true 只可能是免弹窗层命中）
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await,
            "授权读之后读必须静默放行"
        );
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::RecordGrant)
        );
        // 写：记录不含写 → 免弹窗层未命中 → 弹窗（无头 → 拒）
        assert!(
            !checker
                .check("com.wasmnest.test", &file_s, FsOp::Write)
                .await,
            "授权读之后写必须再问一次，不得静默放行"
        );
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::WRITE)
                .await,
            NoDialogDecision::Ask(AuthStrategy::Default),
            "记录命中但操作集不含写：不得报出任何放行层"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "拒绝路径不得残留 pending"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C5 续：先授权读、再授权写 → 同一目标一行记录、操作集取并集，读写都不再问
    #[tokio::test]
    async fn write_grant_merges_into_read_record() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ops-merge");
        let file = dir.join("data.jsonl");
        let file_s = file.to_string_lossy().to_string();

        grant_via_respond(
            &checker,
            "req-read",
            "com.wasmnest.test",
            &file_s,
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
        )
        .await;
        grant_via_respond(
            &checker,
            "req-write",
            "com.wasmnest.test",
            &file_s,
            FsOps::WRITE,
            GrantScope::Exact,
            AuthOrigin::Fs,
        )
        .await;

        let rows = checker
            .auth_records()
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .expect("read records");
        assert_eq!(rows.len(), 1, "同一目标只留一行记录（操作集并集）");
        assert_eq!(rows[0].ops, vec!["read".to_string(), "write".to_string()]);

        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await
        );
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Write)
                .await,
            "读写都授权过之后写不再问"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C5 反例（短路条件）：子树在记录里被显式管理过、但不含本次操作 ⇒ **不回退旧记录**
    ///
    /// 变异判据（票 02 指定的变异自检）：把 `decide_without_dialog` 的
    /// `Some(_) => Ask` 反转成「继续回退旧记录」——旧记录是读写都授权的，
    /// 于是这里的写会被旧记录放行，本条转红。
    #[tokio::test]
    async fn record_without_op_short_circuits_legacy_fallback() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ops-shortcircuit");
        let file = dir.join("data.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();
        let dir_s = dir.to_string_lossy().to_string();

        // 旧记录：同一目录（视作读写都授权）——存量用户的常见状态
        checker
            .seed_legacy_granted_path("com.wasmnest.test", &dir_s)
            .await
            .unwrap();
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Write)
                .await,
            "前置：只有旧记录时写是可放行的（否则本用例恒真）"
        );

        // 新记录：同一目录只授了读 → 该子树从此由新表说了算
        grant_via_respond(
            &checker,
            "req-read",
            "com.wasmnest.test",
            &dir_s,
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
        )
        .await;

        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await,
            "记录覆盖读 → 读静默放行"
        );
        assert!(
            !checker
                .check("com.wasmnest.test", &file_s, FsOp::Write)
                .await,
            "记录命中且不含写时不得回退旧记录（旧记录对该子树作废）"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 存量零感知：**只有**旧记录的目录，读写都照常放行（不回退成「先问一次」）
    #[tokio::test]
    async fn legacy_only_grant_covers_read_and_write() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ops-legacy");
        let file = dir.join("legacy.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        checker
            .seed_legacy_granted_path("com.wasmnest.test", &dir.to_string_lossy())
            .await
            .unwrap();

        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await
        );
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Write)
                .await,
            "旧记录没有操作维度 → 视作读写都授权"
        );
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ_WRITE)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::LegacyGrant)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 选择器入口的落账口径是**读写**：用户点头的是「这个目录可以用」
    ///
    /// 走真实 `authorize_picked` 落账链（`respond` + `GrantScope::Directory`），
    /// 之后对该目录的写不再弹窗——与旧版无操作维度时逐字一致。
    #[tokio::test]
    async fn picker_grant_records_read_write_ops() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ops-picker");
        let a = dir.join("a.txt");
        std::fs::write(&a, b"x").expect("write fixture");

        grant_via_respond(
            &checker,
            "req-pick",
            "com.wasmnest.test",
            &a.to_string_lossy(),
            FsOps::READ_WRITE,
            GrantScope::Directory,
            AuthOrigin::Picker,
        )
        .await;

        let rows = checker
            .auth_records()
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .expect("read records");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].target,
            std::fs::canonicalize(&dir)
                .unwrap()
                .to_string_lossy()
                .to_string(),
            "记录目标 = 规范化后的目录（文件选择器按所在目录落账）"
        );
        assert_eq!(rows[0].ops, vec!["read".to_string(), "write".to_string()]);

        let sibling = dir.join("b.txt");
        std::fs::write(&sibling, b"y").expect("write fixture");
        assert!(
            checker
                .check("com.wasmnest.test", &sibling.to_string_lossy(), FsOp::Write)
                .await,
            "选择器授权之后同目录的写不再弹窗"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 撤销（spec §8.4）：删 allow + 落 deny ⇒ 该目标与其子树**直接拒绝**，
    /// 且 deny 优先于第一方免询问目录（spec §6.1 第 1 步）
    #[tokio::test]
    async fn revoke_records_deny_that_wins_over_first_party_dir() {
        let checker = first_party_checker().await;
        let base = canonical_temp_dir();
        let project = base.join("fs-auth-revoke-proj");
        let claude = project.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let target = claude.join("settings.json");
        let target_s = target.to_string_lossy().to_string();
        // 第一方清单覆盖的目录：撤销前免弹窗（否则本用例恒真）
        assert!(
            checker
                .check("test.bedcode", &target_s, FsOp::Write)
                .await,
            "前置：第一方集成目录本来免弹窗"
        );

        checker
            .auth_records()
            .deny(
                "test.bedcode",
                AuthResource::Fs,
                &claude.to_string_lossy(),
                AuthRecordSource::UserDeny,
            )
            .await
            .expect("revoke");

        assert!(
            !checker
                .check("test.bedcode", &target_s, FsOp::Write)
                .await,
            "硬拒绝记录必须优先于第一方免询问目录（撤销后访问被直接拒绝）"
        );
        assert!(
            !checker
                .check("test.bedcode", &target_s, FsOp::Read)
                .await,
            "deny 是整目标硬拒绝：读同样被拒"
        );
        let sibling = claude.join("hooks/x.py");
        assert!(
            !checker
                .check(
                    "test.bedcode",
                    &sibling.to_string_lossy(),
                    FsOp::Read
                )
                .await,
            "deny 覆盖子树"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "deny 命中不得为它弹窗"
        );
        std::fs::remove_dir_all(&project).ok();
    }

    /// 票 08：撤销的**两种出口**都要通——落 deny ⇒ 第一方免询问失效；移除该 deny
    /// ⇒ 第一方免询问恢复（spec §8.4 要求的「两种意图都有出口」）
    ///
    /// 变异判据：`remove_deny` 若顺手删了同目标的 allow 行、或只删一半，本条的后半段
    /// 转红（恢复后仍被拒 = 用户失去「反悔」的出口）。
    #[tokio::test]
    async fn removing_the_revoke_record_restores_the_first_party_exemption() {
        let checker = first_party_checker().await;
        let project = canonical_temp_dir().join("fs-auth-revoke-restore");
        let claude = project.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let target = claude.join("settings.json");
        std::fs::write(&target, b"{}").unwrap();
        let target_s = target.to_string_lossy().to_string();
        let dir_s = claude.to_string_lossy().to_string();

        // 撤销：走与界面完全相同的写面（`revoke` = 删 allow + 落 deny）
        assert!(
            checker
                .check("test.bedcode", &target_s, FsOp::Read)
                .await,
            "前置：第一方集成目录本来免弹窗"
        );
        checker
            .auth_records()
            .revoke("test.bedcode", AuthResource::Fs, &dir_s)
            .await
            .expect("revoke");
        assert!(
            !checker
                .check("test.bedcode", &target_s, FsOp::Read)
                .await,
            "撤销后该目录被硬拒绝"
        );

        // 另一出口：移除撤销记录 → 回到「第一方免询问」层（而非落到弹窗）
        let removed = checker
            .auth_records()
            .remove_deny("test.bedcode", AuthResource::Fs, &dir_s)
            .await
            .expect("remove deny");
        assert_eq!(
            removed, 1,
            "移除出口必须真删一行（0 = 界面上按钮点了没反应）"
        );
        assert_eq!(
            checker
                .decide_without_dialog("test.bedcode", &target, FsOps::READ)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::FirstPartyDir),
            "移除撤销记录后第一方免询问必须恢复（档位 / 记录层都不是它）"
        );
        assert!(
            checker
                .check("test.bedcode", &target_s, FsOp::Read)
                .await
        );
        std::fs::remove_dir_all(&project).ok();
    }

    /// 批量入口按**本次请求的操作集**判定（不是固定读、也不是读授权即读写）
    ///
    /// 变异判据：`check_batch` 若把操作集写死成读（或忽略参数），`READ_WRITE` 那一档
    /// 会被只读记录放行，本条转红。
    #[tokio::test]
    async fn batch_entry_uses_request_ops() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ops-batch");
        let file = dir.join("data.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        grant_via_respond(
            &checker,
            "req-read",
            "com.wasmnest.test",
            &dir.to_string_lossy(),
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
        )
        .await;

        assert!(
            checker
                .check_batch(
                    "com.wasmnest.test",
                    std::slice::from_ref(&file_s),
                    FsOps::READ
                )
                .await,
            "记录覆盖读 → 读批次静默放行"
        );
        assert!(
            !checker
                .check_batch(
                    "com.wasmnest.test",
                    std::slice::from_ref(&file_s),
                    FsOps::WRITE
                )
                .await,
            "只授读的目录不得放行写批次"
        );
        assert!(
            !checker
                .check_batch(
                    "com.wasmnest.test",
                    std::slice::from_ref(&file_s),
                    FsOps::READ_WRITE
                )
                .await,
            "读写批次要求记录同时覆盖两种能力（覆盖关系不是「有交集即放行」）"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 批量入口（`check_batch`）与单路径入口共用操作集判据：批里任一路径被 deny
    /// 命中 → 整批失败且不弹窗
    #[tokio::test]
    async fn batch_denied_by_deny_record_without_dialog() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ops-batch-deny");
        let file = dir.join("x.txt");
        std::fs::write(&file, b"x").expect("write fixture");

        checker
            .auth_records()
            .deny(
                "com.wasmnest.test",
                AuthResource::Fs,
                &dir.to_string_lossy(),
                AuthRecordSource::UserDeny,
            )
            .await
            .expect("revoke");

        assert!(
            !checker
                .check_batch(
                    "com.wasmnest.test",
                    &[file.to_string_lossy().to_string()],
                    FsOps::READ_WRITE
                )
                .await,
            "被硬拒绝的路径不得靠批量入口放行"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "硬拒绝路径不参与弹窗"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ==================== 票 03：「总是询问」档 + 询问三态 ====================

    /// 设文件侧档位（走真源写入面，与设置页控件同一条路）
    async fn set_fs_strategy(checker: &FsAuthChecker, plugin_id: &str, strategy: AuthStrategy) {
        checker
            .auth_records()
            .set_strategy(plugin_id, AuthResource::Fs, strategy)
            .await
            .expect("set fs strategy");
    }

    /// C2 正例 + C12：「总是询问」下已授权目录**仍询问**（跳过 allow 记录），改回默认档即时恢复
    ///
    /// 变异判据（票 03 指定）：把 `StrategyStep::Ask` 分支改回继续读记录 ——
    /// 本条的「仍要问」两处断言（`decide_without_dialog` / `check`）转红。
    #[tokio::test]
    async fn always_ask_skips_new_table_records_and_asks_again() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ask-records");
        let file = dir.join("data.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        grant_via_respond(
            &checker,
            "req-ask-read",
            "com.wasmnest.test",
            &file_s,
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
        )
        .await;
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await,
            "前置：默认档下记录命中即静默放行（否则本用例恒真）"
        );

        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Ask(AuthStrategy::AlwaysAsk),
            "总是询问档必须跳过 allow 记录（记录命中也不再免弹窗）"
        );
        assert!(
            !checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await,
            "已授权目录在总是询问档下仍要问（无头上下文 → 拒）"
        );
        assert!(
            !checker
                .is_granted("com.wasmnest.test", &file_s, FsOps::READ)
                .await,
            "无弹窗面（WASI 预打开 / 任务单元）同判据：跳过记录 = 不再是 granted"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "无弹窗通道的拒绝不得残留 pending"
        );

        // 实时读取（spec §8.1）：改回默认档，同一个目录立刻恢复「记录命中即静默」
        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::Default).await;
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await,
            "改回默认档后记录重新生效——档位判定时实时读取，不做激活期快照"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 「总是询问」跳过的是**全部** allow 记录：旧版扁平前缀回退同样不例外
    #[tokio::test]
    async fn always_ask_skips_legacy_fallback_too() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ask-legacy");
        let file = dir.join("legacy.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        checker
            .seed_legacy_granted_path("com.wasmnest.test", &dir.to_string_lossy())
            .await
            .unwrap();
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Write)
                .await,
            "前置：只有旧记录时写可放行"
        );

        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ_WRITE)
                .await,
            NoDialogDecision::Ask(AuthStrategy::AlwaysAsk),
            "旧记录也是 allow 记录的一种形态，总是询问档不得读它"
        );
        assert!(
            !checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C2 反例（spec §6.1 第 1 步）：「总是询问」下已有 deny 记录**不再询问**
    ///
    /// 跳过的只是 allow 记录——用户明确说过的「以后都拒绝」在更靠前的第 0 层就拦下，
    /// 否则同一条硬拒绝会每次访问重新弹窗，等于把 deny 记录作废。
    /// 变异判据（票 03 指定）：把 deny 判定移到策略层之后（或让 `Ask` 直通询问），
    /// 本条「不弹窗」的断言转红。
    #[tokio::test]
    async fn always_ask_still_honours_deny_records_without_dialog() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-ask-deny");
        let file = dir.join("secret.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        checker
            .auth_records()
            .deny(
                "com.wasmnest.test",
                AuthResource::Fs,
                &dir.to_string_lossy(),
                AuthRecordSource::UserDeny,
            )
            .await
            .expect("seed deny");
        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;

        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Denied,
            "deny 记录优先于策略档位：总是询问档下仍是硬拒绝"
        );
        assert!(
            !checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await
        );
        assert!(
            !checker
                .check_batch(
                    "com.wasmnest.test",
                    std::slice::from_ref(&file_s),
                    FsOps::READ
                )
                .await,
            "批量入口同判据（三条入口不得给出两套答案）"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "硬拒绝不为它弹窗（否则用户每次访问都被问一个已经拒绝过的目标）"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// spec §7：第一方免询问项**不受档位影响**（档位管不着这批内置特权）
    ///
    /// 「总是询问」若把第一方层也失效，agent-hub 同步一次技能就要用户点 N 次——
    /// 那张表存在的唯一理由（免掉 N 次点击）就被架空了。撤销它只能靠 deny 记录
    /// （见上一条：deny 优先于第一方层）。
    #[tokio::test]
    async fn always_ask_does_not_reopen_first_party_dirs() {
        let checker = first_party_checker().await;
        let project = canonical_temp_dir().join("fs-auth-ask-firstparty");
        let target = project.join(".claude").join("settings.json");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"{}").unwrap();

        set_fs_strategy(&checker, "test.bedcode", AuthStrategy::AlwaysAsk).await;
        assert_eq!(
            checker
                .decide_without_dialog("test.bedcode", &target, FsOps::WRITE)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::FirstPartyDir),
            "第一方集成目录在总是询问档下仍免弹窗"
        );
        assert!(
            checker
                .check(
                    "test.bedcode",
                    &target.to_string_lossy(),
                    FsOp::Write
                )
                .await
        );
        std::fs::remove_dir_all(&project).ok();
    }

    // ==================== 票 04：「始终允许」档（免询问放行 + 留痕） ====================

    /// 某应用在文件侧的记录行（读模型投影，含来源与操作集）
    async fn fs_records(
        checker: &FsAuthChecker,
        plugin_id: &str,
    ) -> Vec<crate::security::auth_policy::AuthRecord> {
        checker
            .auth_records()
            .overview(plugin_id, "T", Vec::new())
            .await
            .expect("overview")
            .records
    }

    /// C3 正例：「始终允许」下未覆盖的新目标免询问放行，并以 `source='always_allow'` 落账
    ///
    /// 变异判据（票 04 指定）：把档位映射的 `AlwaysAllow` 改成 `Ask` / `ConsultRecords`
    /// （=「始终允许」改回询问）——无头上下文没有弹窗通道，本条的放行断言与层断言一起转红。
    #[tokio::test]
    async fn always_allow_allows_new_target_and_lands_always_allow_record() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-always-allow");
        let file = dir.join("new.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        // 前置：默认档下同一路径在无头上下文被拒（否则本用例恒真）
        assert!(
            !checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await,
            "前置：默认档未覆盖目标必须走询问（无头 → 拒）"
        );

        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAllow).await;
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Allowed(FsGrantLayer::AlwaysAllow),
            "始终允许档必须报出 always-allow 层（排障要能回答「为什么这次没弹框」）"
        );
        // 无头上下文没有弹窗通道：返回 true 只可能是免弹窗层命中
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await,
            "始终允许档不得再弹窗（不问）"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "免询问放行不得残留 pending"
        );

        // 留痕（spec §4.3：免询问也必须落账，否则界面出现不可见空洞）
        let rows = fs_records(&checker, "com.wasmnest.test").await;
        assert_eq!(
            rows.len(),
            1,
            "免询问放行必须以 always_allow 来源落一条记录: {rows:?}"
        );
        assert_eq!(
            rows[0].target, file_s,
            "落账目标是本次请求的路径本身（上溯父目录等于替用户扩大授权）"
        );
        assert_eq!(rows[0].ops, vec!["read".to_string()], "操作集 = 本次请求");
        assert_eq!(
            rows[0].source, "always_allow",
            "来源标记是界面「未经确认」判据"
        );
        assert_eq!(rows[0].effect, "allow");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 留痕按目标去重、操作集取并集：同一目标读写各来一次 → 一行 `read+write`
    ///
    /// 变异判据：把落账目标改成父目录 ⇒ 首条断言的目标相等转红；把 `ops` 固定成读写 ⇒
    /// 只有读时的 `["read"]` 断言转红（与上一条互为镜像）。
    #[tokio::test]
    async fn always_allow_dedupes_per_target_and_merges_ops() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-always-allow-dedupe");
        let file = dir.join("data.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAllow).await;
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await
        );
        assert!(
            checker
                .check("com.wasmnest.test", &file_s, FsOp::Write)
                .await,
            "写目标是另一个未覆盖判定，同样免询问放行"
        );

        let rows = fs_records(&checker, "com.wasmnest.test").await;
        assert_eq!(rows.len(), 1, "同一目标至多一行（目标去重，不记次数）");
        assert_eq!(rows[0].ops, vec!["read".to_string(), "write".to_string()]);

        // 另一个目标另起一行（逐个目标累积 = 该档位的固有语义）
        let sibling = dir.join("other.jsonl");
        std::fs::write(&sibling, b"y").expect("write fixture");
        assert!(
            checker
                .check("com.wasmnest.test", &sibling.to_string_lossy(), FsOp::Read)
                .await
        );
        assert_eq!(
            fs_records(&checker, "com.wasmnest.test").await.len(),
            2,
            "碰过的目标逐个累积进记录（记录是路径前缀，不是整盘授权）"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C1/C8：硬闸门不受档位影响——deny 记录优先于「始终允许」，且不产生任何 allow 留痕
    ///
    /// 变异判据：把策略层提到 deny 判定之前 ⇒ 本条「拒绝」断言转红（会变成免询问放行）。
    #[tokio::test]
    async fn always_allow_still_honours_deny_records() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-always-allow-deny");
        let file = dir.join("secret.jsonl");
        std::fs::write(&file, b"x").expect("write fixture");
        let file_s = file.to_string_lossy().to_string();

        checker
            .auth_records()
            .deny(
                "com.wasmnest.test",
                AuthResource::Fs,
                &dir.to_string_lossy(),
                AuthRecordSource::UserDeny,
            )
            .await
            .expect("seed deny");
        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAllow).await;

        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Denied,
            "用户说过的「以后都拒绝」优先于免询问放行"
        );
        assert!(
            !checker
                .check("com.wasmnest.test", &file_s, FsOp::Read)
                .await
        );
        assert!(
            fs_records(&checker, "com.wasmnest.test")
                .await
                .iter()
                .all(|r| r.effect == "deny"),
            "被硬拒绝的目标不得留下 always_allow 记录"
        );
        assert!(checker.pending_requests.lock().await.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C8 续：路径规范化失败是硬闸门——即使 `always_allow` 也拒，且不落账
    ///
    /// `<已存在文件>/..` 的 `file_name()` 为 `None` ⇒ `canonicalize_path` 返回 None，
    /// 判定链在进入策略层**之前**就被拦下。变异判据：把规范化失败降级成「用原始路径
    /// 继续判定」⇒ 本条的拒绝断言转红（免询问放行把未知路径放进去）。
    #[tokio::test]
    async fn always_allow_does_not_bypass_path_canonicalization_hard_gate() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-always-allow-hardgate");
        let file = dir.join("plain.txt");
        std::fs::write(&file, b"x").expect("write fixture");
        let broken = format!("{}/..", file.to_string_lossy());

        assert!(
            FsAuthChecker::canonicalize_path(&broken).is_none(),
            "前置：该形态必须规范化失败（否则本用例测的不是硬闸门）"
        );

        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAllow).await;
        assert!(
            !checker
                .check("com.wasmnest.test", &broken, FsOp::Read)
                .await,
            "路径规范化失败即拒：任何档位都放行不了（spec §4.2）"
        );
        assert!(
            !checker
                .is_granted("com.wasmnest.test", &broken, FsOps::READ)
                .await,
            "无弹窗面同判据"
        );
        assert!(
            !checker
                .check_batch(
                    "com.wasmnest.test",
                    std::slice::from_ref(&broken),
                    FsOps::READ
                )
                .await,
            "批量入口同判据"
        );
        assert!(
            fs_records(&checker, "com.wasmnest.test").await.is_empty(),
            "规范化失败的目标不得落账（否则记录里会出现永远匹配不上的脏目标）"
        );
        assert!(checker.pending_requests.lock().await.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 弹窗 payload 带**弹出时**的档位（前端据此决定给不给「记住」）
    ///
    /// 走真实弹窗链路：判定 → emit → 应答。「允许本次」一次性放行不落账。
    #[tokio::test]
    async fn prompt_payload_carries_the_frozen_strategy() {
        let (checker, log) = promptable_checker(Duration::from_secs(30)).await;
        let dir = fixture_dir("fs-auth-prompt-strategy");
        let file = dir.join("data.jsonl");
        std::fs::write(&file, b"x").unwrap();
        let file_s = file.to_string_lossy().to_string();

        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;
        let (allowed, ()) = tokio::join!(
            checker.check("com.wasmnest.test", &file_s, FsOp::Read),
            async {
                let prompt = wait_for_prompt(&log).await;
                assert_eq!(
                    prompt["strategy"], "always_ask",
                    "弹窗必须自报弹出时的档位（前端据此渲染决定集）"
                );
                assert_eq!(prompt["operation"], "read");
                let request_id = prompt["requestId"].as_str().expect("requestId").to_string();
                checker.respond(&request_id, FsDecision::AllowOnce).await;
            }
        );
        assert!(allowed, "「允许本次」必须放行");
        assert!(
            checker
                .auth_records()
                .records_for_match("com.wasmnest.test", AuthResource::Fs)
                .await
                .unwrap()
                .is_empty(),
            "一次性放行不落账（记住才是落账动作）"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "应答后 pending 必须清空"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// spec §8.1：已等待应答的弹窗按**弹出时**的旧策略走完，不半途改口径
    ///
    /// 两个方向都锁：
    /// ① 弹出时默认档 → 等待期间档位被改成「总是询问」，这个弹窗的「记住」仍落账
    ///    （用户看到的按钮就是那个口径）；
    /// ② 弹出时总是询问 → 等待期间改回默认档，越界的 `allow_remember` 仍按一次性
    ///    放行处理（该弹窗根本没给「记住」按钮，落一条此后没人读的记录只会造成两处口径）。
    #[tokio::test]
    async fn pending_prompt_keeps_the_strategy_it_was_raised_with() {
        // ① 弹出时默认档 → 记住照落
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-prompt-frozen-default");
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let file_s = file.to_string_lossy().to_string();

        let _rx = seed_pending(
            &checker,
            "req-frozen-default",
            "com.wasmnest.test",
            vec![file_s],
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
            AuthStrategy::Default,
        )
        .await;
        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;
        checker
            .respond("req-frozen-default", FsDecision::AllowRemember)
            .await;
        assert_eq!(
            checker
                .auth_records()
                .records_for_match("com.wasmnest.test", AuthResource::Fs)
                .await
                .unwrap()
                .len(),
            1,
            "弹出时是默认档：等待期间改档不得抹掉这个弹窗的「记住」语义"
        );

        // ② 弹出时总是询问 → 越界的 allow_remember 降级为一次性放行（不落账）
        let checker = headless_checker().await;
        let dir2 = fixture_dir("fs-auth-prompt-frozen-ask");
        let file2 = dir2.join("b.txt");
        std::fs::write(&file2, b"x").unwrap();

        let rx = seed_pending(
            &checker,
            "req-frozen-ask",
            "com.wasmnest.test",
            vec![file2.to_string_lossy().to_string()],
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
            AuthStrategy::AlwaysAsk,
        )
        .await;
        set_fs_strategy(&checker, "com.wasmnest.test", AuthStrategy::Default).await;
        checker
            .respond("req-frozen-ask", FsDecision::AllowRemember)
            .await;
        assert!(
            rx.await.expect("reply"),
            "降级方向仍是放行（用户点的是允许）"
        );
        assert!(
            checker
                .auth_records()
                .records_for_match("com.wasmnest.test", AuthResource::Fs)
                .await
                .unwrap()
                .is_empty(),
            "该弹窗没提供「记住」：不得落一条此后不会被读到的记录"
        );
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&dir2).ok();
    }

    /// 正例：「以后都拒绝」落 deny 记录（spec §8.4），该目标与其子树此后被直接拒绝
    ///
    /// 变异判据：把 `respond` 里的 `DenyAlways` 分支改成不落账（或落成 allow），
    /// 本条转红。
    #[tokio::test]
    async fn deny_always_lands_a_deny_record_covering_the_subtree() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-deny-always");
        let inside = dir.join("secret.txt");
        std::fs::write(&inside, b"x").unwrap();

        let rx = seed_pending(
            &checker,
            "req-deny-always",
            "com.wasmnest.test",
            vec![dir.to_string_lossy().to_string()],
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
            AuthStrategy::Default,
        )
        .await;
        checker
            .respond("req-deny-always", FsDecision::DenyAlways)
            .await;

        assert!(!rx.await.expect("reply"), "「以后都拒绝」当次也是拒绝");
        let rows = checker
            .auth_records()
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "同一目标只落一行 deny");
        assert_eq!(rows[0].effect, AUTH_EFFECT_DENY);
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &inside, FsOps::READ)
                .await,
            NoDialogDecision::Denied,
            "deny 记录覆盖子树（后续访问不再弹窗）"
        );
        assert!(checker.pending_requests.lock().await.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 反例：「拒绝」（不带「以后」）不落任何记录 —— 下次访问重新询问
    #[tokio::test]
    async fn plain_deny_leaves_no_record_and_asks_again() {
        let checker = headless_checker().await;
        let dir = fixture_dir("fs-auth-deny-once");
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").unwrap();

        let rx = seed_pending(
            &checker,
            "req-deny-once",
            "com.wasmnest.test",
            vec![file.to_string_lossy().to_string()],
            FsOps::READ,
            GrantScope::Exact,
            AuthOrigin::Fs,
            AuthStrategy::Default,
        )
        .await;
        checker.respond("req-deny-once", FsDecision::Deny).await;

        assert!(!rx.await.expect("reply"));
        assert!(
            checker
                .auth_records()
                .records_for_match("com.wasmnest.test", AuthResource::Fs)
                .await
                .unwrap()
                .is_empty(),
            "一次性拒绝不落账"
        );
        assert_eq!(
            checker
                .decide_without_dialog("com.wasmnest.test", &file, FsOps::READ)
                .await,
            NoDialogDecision::Ask(AuthStrategy::Default),
            "下次访问仍进询问（拒绝 ≠ 以后都拒绝）"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// C10 边界：无应答超时 → 按拒绝且**不落任何记录**（超时不是用户的表态）
    ///
    /// 超时上限在测试里调小（生产固定 30s），但这**不是**把契约放宽：等 30 秒
    /// 验不了这条契约，而「超时也落账」会把系统的沉默记成用户的拒绝决定。
    #[tokio::test]
    async fn prompt_timeout_denies_without_recording() {
        let (checker, log) = promptable_checker(Duration::from_millis(80)).await;
        let dir = fixture_dir("fs-auth-timeout");
        let file = dir.join("data.jsonl");
        std::fs::write(&file, b"x").unwrap();

        assert!(
            !checker
                .check("com.wasmnest.test", &file.to_string_lossy(), FsOp::Read)
                .await,
            "无应答超时按拒绝"
        );
        assert!(
            !log.lock().expect("emit log poisoned").is_empty(),
            "前置：确实弹过窗（否则「超时」恒真）"
        );
        assert!(
            checker.pending_requests.lock().await.is_empty(),
            "超时必须清掉 pending（否则泄漏到下一次判定）"
        );
        assert!(
            checker
                .auth_records()
                .records_for_match("com.wasmnest.test", AuthResource::Fs)
                .await
                .unwrap()
                .is_empty(),
            "超时不落任何记录"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

// ==================== FsAuthGate 端口实现（票 02 B5 起常编译） ====================
//
// crate 内机制面（approval / 域测试夹具）经端口 trait 消费授权判定；宿主
// 切换后宿主 FsAuthChecker（白名单 / 弹窗真源）另行实现同一 trait 注入。
// **票 02 B5 起常编译**（`bare-host` / `common-host` 两个形态 feature 已于
// 2026-10-13 单形态收口退休，本 impl 的常编译语义不变）：统一 `WasmHostContext`
// 的 `fs_auth` 槽收敛为
// `Arc<dyn FsAuthGate>`（超集，见 `host_api/context.rs` 字段注释），桌面形态把
// 具体 `FsAuthChecker` 注入为 trait 对象——本 impl 不常编译则桌面 lib 编译红。
// 移动宿主在 `移动宿主` 侧实现同一 trait（其 SAF URI / 白名单管理语义
// 与桌面实现不同，B5 裁决保持注入式超集，不迁移）。

#[async_trait::async_trait]
impl crate::host_api::ports::FsAuthGate for FsAuthChecker {
    async fn check(
        &self,
        plugin_id: &str,
        path: &str,
        op: crate::host_api::ports::FsAuthOp,
    ) -> bool {
        let mapped = match op {
            crate::host_api::ports::FsAuthOp::Read => FsOp::Read,
            crate::host_api::ports::FsAuthOp::Write => FsOp::Write,
        };
        self.check(plugin_id, path, mapped).await
    }

    async fn check_batch(
        &self,
        plugin_id: &str,
        paths: &[String],
        op: crate::host_api::ports::FsAuthOp,
    ) -> bool {
        let mapped = match op {
            crate::host_api::ports::FsAuthOp::Read => FsOps::single(FsOp::Read),
            crate::host_api::ports::FsAuthOp::Write => FsOps::single(FsOp::Write),
        };
        self.check_batch(plugin_id, paths, mapped).await
    }
}
