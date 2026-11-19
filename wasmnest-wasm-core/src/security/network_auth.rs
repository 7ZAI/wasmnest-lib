//! 网络出站（`host-http.fetch`）的授权判定与询问（授权策略增强）
//!
//! 与文件侧的 [`super::fs_auth`] 同构：判定链 + 弹窗应答通道，但**目标形态**不同
//! （网络是归一化 origin，文件是规范路径前缀），所以本模块自带归一化与匹配。
//!
//! ## 判定管线（网络侧）
//!
//! ```text
//! 0. manifest 声明门（network:http）        —— 硬闸门，在 host-http 端口权限门上一层
//!    （端口 adapter 已迁宿主 `src-tauri/src/plugin/http.rs`）
//! 1. 硬拒绝记录（deny 命中）               —— 硬闸门，优先于一切放行路径
//! 2. 策略层（三档，共用 super::strategy）    —— 三档全部接线
//! 3. 授权记录命中（origin + path 前缀段边界）—— 仅「默认」档读记录
//! 4. 询问用户（新事件 + 新命令，三态决定）
//! ```
//!
//! 档位语义与文件侧**逐字同源**（共用 [`super::strategy`] 的档位映射与顺序）：
//! 「总是询问」跳过全部 allow 记录（deny 记录仍在第 1 步拦住）、「始终允许」
//! 免询问放行并以 `source='always_allow'` 留痕。两处各写一遍必然漂移，而漂移的
//! 形态是安全语义级的（两档语义不同的变异正是要防的形态）。
//!
//! 硬闸门的位置与本模块**正交**：SSRF 防护（`redirect_decision`：公网 → 私网/回环/
//! 链路本地重定向阻断，锁在 `wasmnest-server-http` 自己的用例里）留在请求执行期，授权层
//! 放行不改变它——「记录命中」从来不是「越过网络栈的安全裁决」。
//!
//! ## 为什么询问走「新事件 + 新命令」而不是复用 fs 那套双布尔
//!
//! fs 侧是 `allowed: bool` + `remember: bool`（路径逐条记忆，粒度在路径上）；
//! 网络侧的询问粒度**就是 origin**，用户点头的语义是「这个地址可以访问」，不存在
//! 「只这一次、别记」的中间档——若把 `allow_once` 实现成不落账，默认档下每次访问
//! 同一 origin 都会重新弹窗（agent-hub 一次刷新几十个请求 → 策略在实践中等于不可用），
//! 且与「default 档：新命中经用户确认后落 allow」的既定语义直接冲突。故固定三态
//! （既定枚举）：`allow_once` / `deny` / `deny_always`——「允许」按 origin
//! 落 allow 记录（`source='user'`），「以后都拒绝」落 deny 记录。
//!
//! **「总是询问」档是这套语义的唯一例外**：该档不读 allow 记录，落一条
//! 没人会读的记录等于在管理界面里谎称「用户已授权」。因此该档下「允许」只放行本批、
//! **不落账**（与 fs 侧同档不提供「记住」按钮同源，见 [`NetworkAuthChecker::prompt`]）。
//! 「以后都拒绝」仍落 deny 记录——deny 在第 1 步生效，任何档位都尊重用户说过的拒绝。
//!
//! ## 无询问面（任务单元）
//!
//! 任务单元跑在 core-task 池线程上，**绝不弹窗**（与 fs 任务单元同款约束：弹窗会占住
//! 池槽位最长 30s，且用户在错误的时机看到问题）。[`NetworkAuthChecker::is_granted`]
//! 只认记录、未记录即拒绝，由调用方 fail-visible 报错。
//!
//! ## 归属
//!
//! 安全闸门：只回答「这个出站地址要不要问用户 / 有没有问过」，不含任何业务语义
//! （不判断地址属于哪个服务、不解释重定向链上的业务含义）。

use crate::db::Database;
use crate::security::auth_policy::{
    AuthPolicyStore, AuthRecordMatch, AuthRecordSource, AuthResource, GrantOutcome,
    AUTH_EFFECT_ALLOW, AUTH_EFFECT_DENY,
};
use crate::security::strategy::{self, StrategyStep, Tier};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::Emitter;
use tokio::sync::{oneshot, Mutex};
// db 锁统一为 std Mutex（单形态收口，与 storage.rs / auth_policy.rs 同款裁决：
// 同步锁 + 短临界区，guard 非 Send 编译器强制无跨 await 持锁）；
// prompts 锁恒 tokio（本模块内部请求队列状态，双端一致，不在 db 锁收敛范围）
use std::sync::Mutex as DbMutex;

/// 出站询问的等待上限（与 fs 侧一致）
///
/// **超时按拒绝**（fail-safe 默认「无应答即拒」）：不落任何记录。
const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// 同 origin 询问的合并窗口（固定常量）
///
/// 作用是让「同一波请求」只打扰用户一次：① 弹窗在途时并入同一询问；② 用户答完后
/// 窗口内到达的请求（agent-hub 一次刷新里排在后面的那些）复用同一决定。
/// 显式常量而非隐式去抖：窗口**不因新请求重置**（滑动窗口会让持续访问永远见不到
/// 询问，等于把「总是询问」档架空），过期后第一次请求即重新询问。
const PROMPT_MERGE_WINDOW: Duration = Duration::from_secs(2);

/// 弹窗事件名（前端 `NetworkAuthDialog` 监听；与 fs 的 `plugin:fs-auth-request` 分开，
/// 因为两者的应答决定形状不同——见文件头「为什么走新事件 + 新命令」）
pub const NETWORK_AUTH_REQUEST_EVENT: &str = "plugin:network-auth-request";

/// 批量授权弹窗事件名（前端 `NetworkAuthBatchDialog` 监听）
///
/// 与单 origin 事件分开：载荷是 origin 列表，应答是三态批量决定；改造单 origin
/// 事件会让现有弹窗、测试与兼容字段同时承担两种形状。
pub const NETWORK_AUTH_BATCH_REQUEST_EVENT: &str = "plugin:network-auth-batch-request";

/// 弹窗事件投递口（生产 = `AppHandle.emit`；同模块测试 = 捕获闭包）
///
/// 抽成注入点而不是在测试里硬塞 AppHandle：tao 事件循环不允许在测试线程建
/// `AppHandle`，而「同 origin 只弹一次」「应答后落账」这些契约必须在**真实判定链**上
/// 验证（只测纯函数的变异教训：契约必须在真实判定链上验）。生产语义与 fs 侧一致：`None` = 无头
/// 上下文 ⇒ 询问层不可用 ⇒ 拒绝。
type PromptEmitter = Arc<dyn Fn(&str, serde_json::Value) -> Result<(), String> + Send + Sync>;

/// 归一化后的出站目标
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTarget {
    /// 落库 / 展示 / 报错用的 origin：`scheme://host:port`
    ///
    /// 默认端口**显式化**（https→443 / http→80）：否则 `https://api.x.com` 与
    /// `https://api.x.com:443` 会算成两个目标，同一站点问两次、记两条。
    pub origin: String,
    /// 归一化请求 path（必以 `/` 开头，根路径为 `/`；去尾斜杠）
    pub path: String,
}

/// 归一化出站 URL
///
/// **query / fragment / userinfo 绝不进入结果**（凭据红线：token 不得落库、
/// 不得进错误串、不得进日志）——只取 scheme / host / port / path 四段，URL 里的
/// `?token=…`、`#…`、`user:pass@` 天然被排除在外。
/// 无法解析（无 scheme / 无 host / 无端口可定）返回 `None`，由调用方 fail-visible
/// 报错——不猜、不降级放行。
pub fn normalize_target(url: &str) -> Option<NormalizedTarget> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let origin = origin_of(&parsed)?;
    Some(NormalizedTarget {
        origin,
        path: normalize_path(parsed.path()),
    })
}

/// path 归一化：去尾斜杠（`/v1/` ≡ `/v1`），空 → `/`
fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// 从已解析 URL 取归一化 origin（`scheme://host:port`）
fn origin_of(url: &reqwest::Url) -> Option<String> {
    let scheme = url.scheme().to_ascii_lowercase();
    // host_str 不含 userinfo；IPv6 字面量自带方括号（`[::1]`），拼接即合法 origin
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some(format!("{scheme}://{host}:{port}"))
}

/// 一条记录是否覆盖目标（origin 相同 + 可选 path 前缀按**段边界**比较）
///
/// 段边界是硬要求：`/v1` 的前缀记录不得命中 `/v1abc`（子串比较会把
/// `https://h:443/v1beta` 一并放行，而用户点头的是「只放行 `/v1`」）。
/// 畸形行（带 path 尾巴却标 `prefix_match=0`）按**不覆盖**处理（fail-closed）：
/// 宁可少放行一次让用户重新点头，也不把一条说不清的记录当整站授权。
/// origin 比较忽略大小写（手改过的 `HTTPS://…` 行不得因大小写逃过 deny 记录）。
pub fn record_covers(record: &AuthRecordMatch, target: &NormalizedTarget) -> bool {
    let Ok(stored) = reqwest::Url::parse(&record.target) else {
        return false;
    };
    let Some(stored_origin) = origin_of(&stored) else {
        return false;
    };
    if !stored_origin.eq_ignore_ascii_case(&target.origin) {
        return false;
    }
    let stored_path = normalize_path(stored.path());
    if !record.prefix_match {
        return stored_path == "/";
    }
    target.path == stored_path
        || target
            .path
            .strip_prefix(&stored_path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// 出站询问的应答决定（固定三态，wire 值即命令参数）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkDecision {
    /// 允许本次询问覆盖的那批请求，并按 origin 落 allow 记录
    AllowOnce,
    /// 拒绝本次，不落账（下一次访问同一 origin 会重新询问）
    Deny,
    /// 拒绝本次并落 deny 记录（以后都拒绝）
    DenyAlways,
}

impl NetworkDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow_once",
            Self::Deny => "deny",
            Self::DenyAlways => "deny_always",
        }
    }

    /// 解析 wire 值；**未知值返回 `None`**（调用方显性报错）
    ///
    /// 不得给未知值兜底成「允许」：命令参数来自前端，兜底放行等于把应答通道变成一个
    /// 可猜测的绕过口（fail-visible）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "allow_once" => Some(Self::AllowOnce),
            "deny" => Some(Self::Deny),
            "deny_always" => Some(Self::DenyAlways),
            _ => None,
        }
    }
}

/// 批量授权的应答决定（wire 值即命令参数）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkBatchDecision {
    /// 允许本次批量覆盖的全部未决 origin，并按 origin 落 allow 记录
    Allow,
    /// 拒绝本次，不落账（下次批量或单 origin 访问仍会询问）
    Deny,
    /// 拒绝本次并逐 origin 落 deny 记录（以后都拒绝）
    DenyAlways,
}

impl NetworkBatchDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::DenyAlways => "deny_always",
        }
    }

    /// 解析 wire 值；未知值返回 `None`（调用方显性报错，不兜底放行）
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "deny_always" => Some(Self::DenyAlways),
            _ => None,
        }
    }
}

/// 批量授权的整体结果
///
/// 逐项结果与入参 URL **等长且同序**；`AlwaysAsk` / `Unavailable` / `StoreFailed` /
/// `Internal` 是整批失败，不伪造任何逐项成功。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchAuth {
    /// 批量判定完成（全部或部分命中记录 / 一次询问落定）
    Verdicts {
        /// 与入参 URL 等长且同序
        verdicts: Vec<OutboundVerdict>,
        /// 因授权记录容量上限未能落账的 allow 条数（放行方向不变）
        dropped_records: usize,
    },
    /// 当前策略为「总是询问」，批量提前询问与该档语义冲突
    AlwaysAsk,
    /// 无弹窗通道（无头 / 事件投递失败）
    Unavailable(String),
    /// 授权记录读取失败，无法判定
    StoreFailed(String),
    /// 其他宿主内部错误（含 URL 不可归一化）
    Internal(String),
}

/// 出站判定结果（供调用方决定放行 / 报错，附带**命中的判据层**用于日志）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundVerdict {
    /// 放行
    Allow {
        origin: String,
        /// 命中的判据层：`record`（授权记录）/ `always-allow`（始终允许档免询问）/
        /// `user`（用户刚点头）
        layer: &'static str,
    },
    /// 拒绝
    Deny {
        origin: String,
        /// `deny-record`（硬拒绝记录）/ `user-denied` / `user-denied-always`
        reason: &'static str,
    },
}

impl OutboundVerdict {
    /// 是否放行（调用方只读这一个；层与原因留给日志与错误文案）
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// 归一化 origin（错误文案与日志用；**不含 path / query**——token 不外泄）
    pub fn origin(&self) -> &str {
        match self {
            Self::Allow { origin, .. } | Self::Deny { origin, .. } => origin,
        }
    }

    /// 拒绝原因（`deny-record` / `user-denied` / `user-denied-always` / `no-record`）
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Allow { layer, .. } => layer,
            Self::Deny { reason, .. } => reason,
        }
    }
}

/// 同 origin 询问的键（属主 + origin：不同应用访问同一站点各问各的）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PromptKey {
    plugin_id: String,
    origin: String,
}

/// 批量询问的应答内容（落账在应答通道完成后随决定一起回传）
struct BatchReply {
    decision: NetworkBatchDecision,
    /// 批量允许时因容量上限未落账的条数
    dropped_records: usize,
}

/// 在途批量询问（一个询问挂 N 个未决 origin，一次应答整批落定）
struct BatchPrompt {
    plugin_id: String,
    /// 去重后的未决 origin（保持首次出现顺序，即弹窗展示顺序）
    origins: Vec<String>,
    waiters: Vec<oneshot::Sender<BatchReply>>,
}

/// 在途（或刚落定）的同 origin 询问
struct OriginPrompt {
    request_id: String,
    /// 在途等待者：一个询问可同时放行同 origin 的一批在途请求
    waiters: Vec<oneshot::Sender<NetworkDecision>>,
    /// 已作出的决定 + 决定时刻（合并窗口的起点）
    decision: Option<(NetworkDecision, Instant)>,
    /// 弹出时档位**是否读授权记录** ⇒ 应答「允许」要不要落 allow 记录
    ///
    /// 在**弹出时**固定：等待应答期间用户改了档位，这个弹窗仍按旧口径
    /// 走完——落不落账跟着弹出时的档位走，与 fs 侧 `PendingRequest::offers_remember`
    /// 同一原则（用户看到的按钮与实际落账必须一致）。
    lands_allow_record: bool,
}

/// 策略求值结果 = 判定步 + 询问落账口径
///
/// **两个字段必须分开**：`StrategyStep::Ask` 有两种来由——「总是询问」档主动跳过
/// 记录（不落账），与「档位读取失败按 fail-safe 退化成询问」（落账，否则用户点了
/// 允许却留不下任何痕迹）。合成一个字段就只能二选一地错。
struct StrategyVerdict {
    step: StrategyStep,
    /// 询问应答「允许」是否落 allow 记录
    lands_allow_record: bool,
}

/// 网络出站授权校验器
pub struct NetworkAuthChecker {
    store: AuthPolicyStore,
    /// 弹窗事件投递口（`None` = 无头上下文，询问层不可用即拒绝）
    emit: Option<PromptEmitter>,
    /// 在途 / 刚落定的询问（键 = 属主 + origin）
    prompts: Arc<Mutex<HashMap<PromptKey, OriginPrompt>>>,
    /// 在途批量询问（键 = request_id；一次批量入口只发一次询问）
    batch_prompts: Arc<Mutex<HashMap<String, BatchPrompt>>>,
    /// 询问等待上限（生产 30s；同模块测试调小，免用例挂 30 秒）
    prompt_timeout: Duration,
    /// 同 origin 合并窗口（生产 2s；同模块测试调小）
    merge_window: Duration,
}

impl NetworkAuthChecker {
    /// 创建校验器（与 [`super::fs_auth::FsAuthChecker::new`] 同一形态）
    ///
    /// `app_handle` 为 `None`（无头 / 测试上下文）时询问层不可用，直接拒绝。
    pub fn new(db: Arc<DbMutex<Database>>, app_handle: Option<Arc<tauri::AppHandle>>) -> Self {
        let emit = app_handle.map(|handle| {
            let handle = handle.clone();
            Arc::new(move |event: &str, payload: serde_json::Value| {
                handle.emit(event, payload).map_err(|e| e.to_string())
            }) as PromptEmitter
        });
        Self::assemble(db, emit)
    }

    /// 以显式事件投递口装配（测试注入点；`None` 语义同「无头上下文」）
    pub fn with_emitter(db: Arc<DbMutex<Database>>, emit: Option<PromptEmitter>) -> Self {
        Self::assemble(db, emit)
    }

    fn assemble(db: Arc<DbMutex<Database>>, emit: Option<PromptEmitter>) -> Self {
        Self {
            store: AuthPolicyStore::new(db),
            emit,
            prompts: Arc::new(Mutex::new(HashMap::new())),
            batch_prompts: Arc::new(Mutex::new(HashMap::new())),
            prompt_timeout: PROMPT_TIMEOUT,
            merge_window: PROMPT_MERGE_WINDOW,
        }
    }

    /// 注入 core-monitor 句柄（授权记录容量丢弃计数）
    ///
    /// 与 `fs_auth::FsAuthChecker::set_monitor` 同一形态（两阶段注入：monitor 生于
    /// `WasmRuntime`，晚于宿主上下文构建）。不注入时容量丢弃**静默发生**——网络侧
    /// 「始终允许」档下记录按 origin 累积，触顶后没有计数就等于无人知晓的留痕空洞。
    pub fn set_monitor(&self, monitor: Arc<crate::monitor::MetricsRegistry>) {
        self.store.set_monitor(monitor);
    }

    /// 弹窗面判定：可询问用户
    ///
    /// `Err` 是 fail-visible 的两类情况：URL 不可归一化、库读失败——都不降级放行
    /// （硬闸门：规范化失败即拒）。
    ///
    /// `Err` 是 fail-visible 的两类情况：URL 不可归一化、库读失败——都不降级放行
    pub async fn authorize_outbound(
        &self,
        plugin_id: &str,
        url: &str,
    ) -> crate::Result<OutboundVerdict> {
        let Some(target) = normalize_target(url) else {
            // 错误串**不含**原始 url：query 里的 token 不进日志 / 错误信封
            return Err(crate::AppError::Internal(
                "网络出站授权：URL 不可归一化（缺 scheme / host / 端口），已拒绝".to_string(),
            ));
        };

        let records = self
            .store
            .records_for_match(plugin_id, AuthResource::Network)
            .await?;

        // 第 1 步：硬拒绝记录优先于一切放行路径
        if records
            .iter()
            .any(|row| row.effect == AUTH_EFFECT_DENY && record_covers(row, &target))
        {
            tracing::info!(
                plugin_id = %plugin_id,
                origin = %target.origin,
                "host-http: 出站被硬拒绝记录拦截（不询问）"
            );
            return Ok(OutboundVerdict::Deny {
                origin: target.origin,
                reason: "deny-record",
            });
        }

        // 第 2 步：策略层（三档；判定时实时读取，不缓存）
        let strategy = self.read_strategy(plugin_id).await;
        match strategy.step.tier() {
            // 「始终允许」：免询问放行 + 以 `source='always_allow'` 留痕。
            // 记录粒度 = 本次归一化 origin（询问粒度就是 origin，落更细的 path
            // 等于替用户收紧/放大到另一套粒度上；整站记录与「允许本 origin」同形）
            Tier::AutoAllow => {
                // 落账是档位的义务（S-11）：档位标志把义务钉在类型上，
                // 删除落账会让此处断言（debug 测试构建）与行为测试同时转红
                debug_assert!(
                    strategy.step.must_land_auto_allow(),
                    "AutoAllow 档位字段丢失审计义务（S-11）"
                );
                self.land_auto_allow(plugin_id, &target).await;
                return Ok(OutboundVerdict::Allow {
                    origin: target.origin,
                    layer: "always-allow",
                });
            }
            // 「总是询问」：跳过全部 allow 记录（含 path 前缀记录）直接进询问
            Tier::Ask => {
                tracing::debug!(
                    plugin_id = %plugin_id,
                    origin = %target.origin,
                    "host-http: 总是询问档，跳过授权记录"
                );
            }
            Tier::ConsultRecords => {}
        }

        // 第 3 步：授权记录命中（**仅默认档读记录**——「总是询问」在此之前已跳过）
        if strategy.step.reads_allow_records()
            && records
                .iter()
                .any(|row| row.effect == AUTH_EFFECT_ALLOW && record_covers(row, &target))
        {
            tracing::debug!(
                plugin_id = %plugin_id,
                origin = %target.origin,
                "host-http: 出站命中授权记录，免询问放行"
            );
            return Ok(OutboundVerdict::Allow {
                origin: target.origin,
                layer: "record",
            });
        }

        // 第 4 步：询问用户（未记录目标 = 未授权）
        match self
            .prompt(plugin_id, &target, strategy.lands_allow_record)
            .await
        {
            NetworkDecision::AllowOnce => {
                tracing::info!(
                    plugin_id = %plugin_id,
                    origin = %target.origin,
                    "host-http: 用户允许该 origin，本次放行（记录由应答通道落账）"
                );
                Ok(OutboundVerdict::Allow {
                    origin: target.origin,
                    layer: "user",
                })
            }
            NetworkDecision::Deny => Ok(OutboundVerdict::Deny {
                origin: target.origin,
                reason: "user-denied",
            }),
            NetworkDecision::DenyAlways => Ok(OutboundVerdict::Deny {
                origin: target.origin,
                reason: "user-denied-always",
            }),
        }
    }

    /// 批量出站授权提前询问（只询问、不发请求）
    ///
    /// 与单 origin 判定链同源：硬拒绝记录优先，其次是策略档与 allow 记录；未决
    /// origin 去重后进入一次询问，应答按 origin 逐条落账。与单 origin 的差异：
    /// - 「总是询问」档整体返回 [`BatchAuth::AlwaysAsk`]（批量提前询问与该档的
    ///   「每次都问」语义冲突）；
    /// - 无弹窗通道返回 [`BatchAuth::Unavailable`]（不静默降级成逐项拒绝）；
    /// - 同 origin 的多个 URL 只占一行询问，逐项结果仍按入参顺序回填。
    ///
    /// 返回的逐项裁决与 `urls` **等长且同序**；批量入口本身不发放越过 `fetch`
    /// 判定链的通行证，实际出站仍逐次经过完整判定。
    pub async fn authorize_batch(&self, plugin_id: &str, urls: &[String]) -> BatchAuth {
        let started = Instant::now();
        let mut targets = Vec::with_capacity(urls.len());
        for url in urls {
            let Some(target) = normalize_target(url) else {
                return BatchAuth::Internal(
                    "网络批量授权：URL 不可归一化（缺 scheme / host / 端口），已拒绝".to_string(),
                );
            };
            targets.push(target);
        }
        if targets.is_empty() {
            return BatchAuth::Verdicts {
                verdicts: Vec::new(),
                dropped_records: 0,
            };
        }

        let records = match self
            .store
            .records_for_match(plugin_id, AuthResource::Network)
            .await
        {
            Ok(records) => records,
            Err(e) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "network_auth: 批量授权读取授权记录失败"
                );
                return BatchAuth::StoreFailed(e.to_string());
            }
        };

        let strategy = self.read_strategy(plugin_id).await;
        let tier = strategy.step.tier();
        if matches!(tier, Tier::Ask) {
            tracing::info!(
                plugin_id = %plugin_id,
                count = targets.len(),
                "network_auth: 总是询问档不支持批量提前询问"
            );
            return BatchAuth::AlwaysAsk;
        }

        let mut verdicts: Vec<Option<OutboundVerdict>> = vec![None; targets.len()];
        let mut pending_origins: Vec<String> = Vec::new();
        let mut pending_seen: HashSet<String> = HashSet::new();
        let mut dropped_records = 0usize;

        for (index, target) in targets.iter().enumerate() {
            // 第 1 步：硬拒绝记录优先于一切放行路径（与单 origin 同判据）
            if records
                .iter()
                .any(|row| row.effect == AUTH_EFFECT_DENY && record_covers(row, target))
            {
                verdicts[index] = Some(OutboundVerdict::Deny {
                    origin: target.origin.clone(),
                    reason: "deny-record",
                });
                continue;
            }

            match tier {
                // 第 2 步：「始终允许」免询问放行 + 留痕（不询问）
                Tier::AutoAllow => {
                    match self
                        .store
                        .grant(
                            plugin_id,
                            AuthResource::Network,
                            &target.origin,
                            &[],
                            AuthRecordSource::AlwaysAllow,
                        )
                        .await
                    {
                        Ok(GrantOutcome::Stored) => {}
                        Ok(GrantOutcome::DroppedByCap) => dropped_records += 1,
                        Err(e) => {
                            tracing::warn!(
                                plugin_id = %plugin_id,
                                origin = %target.origin,
                                error = %e,
                                "network_auth: 始终允许档的批量落账失败（放行方向不变）"
                            );
                        }
                    }
                    verdicts[index] = Some(OutboundVerdict::Allow {
                        origin: target.origin.clone(),
                        layer: "always-allow",
                    });
                }
                // 第 3 步：默认档读 allow 记录；未命中进入批量询问（同 origin 只占一行）
                Tier::ConsultRecords => {
                    if strategy.step.reads_allow_records()
                        && records.iter().any(|row| {
                            row.effect == AUTH_EFFECT_ALLOW && record_covers(row, target)
                        })
                    {
                        verdicts[index] = Some(OutboundVerdict::Allow {
                            origin: target.origin.clone(),
                            layer: "record",
                        });
                    } else if pending_seen.insert(target.origin.clone()) {
                        pending_origins.push(target.origin.clone());
                    }
                }
                Tier::Ask => unreachable!("总是询问档已在批量询问前返回"),
            }
        }

        if !pending_origins.is_empty() {
            let reply = match self.batch_prompt(plugin_id, &pending_origins).await {
                Ok(reply) => reply,
                Err(reason) => return BatchAuth::Unavailable(reason),
            };
            for (index, target) in targets.iter().enumerate() {
                if verdicts[index].is_some() {
                    continue;
                }
                verdicts[index] = Some(match reply.decision {
                    NetworkBatchDecision::Allow => OutboundVerdict::Allow {
                        origin: target.origin.clone(),
                        layer: "user",
                    },
                    NetworkBatchDecision::Deny => OutboundVerdict::Deny {
                        origin: target.origin.clone(),
                        reason: "user-denied",
                    },
                    NetworkBatchDecision::DenyAlways => OutboundVerdict::Deny {
                        origin: target.origin.clone(),
                        reason: "user-denied-always",
                    },
                });
            }
            if reply.decision == NetworkBatchDecision::Allow {
                dropped_records = reply.dropped_records;
            }
        }

        let verdicts: Vec<OutboundVerdict> = verdicts
            .into_iter()
            .map(|verdict| verdict.expect("批量目标在询问结束后必须有裁决"))
            .collect();
        let allowed = verdicts
            .iter()
            .filter(|verdict| verdict.is_allowed())
            .count();
        let denied = verdicts.len() - allowed;
        tracing::info!(
            plugin_id = %plugin_id,
            requested = verdicts.len(),
            pending = pending_origins.len(),
            allowed,
            denied,
            dropped_records,
            elapsed_micros = started.elapsed().as_micros() as u64,
            "network_auth: 批量出站授权完成"
        );
        BatchAuth::Verdicts {
            verdicts,
            dropped_records,
        }
    }

    /// 处理批量询问应答（由前端 Tauri 命令调用；仅宿主面凭证可代答）
    ///
    /// 落账只在这里发生一次：`allow` 逐 origin 落 `user` allow 记录，
    /// `deny_always` 逐 origin 落 `user_deny` deny 记录，`deny` 不落账。
    /// 落账的容量丢弃数随决定回传给等待中的批量入口。
    /// 返回 `false` = 未知 / 已作答 / 已超时的 request_id，调用方显性报错。
    pub async fn respond_batch(&self, request_id: &str, decision: NetworkBatchDecision) -> bool {
        let prompt = {
            let mut prompts = self.batch_prompts.lock().await;
            prompts.remove(request_id)
        };
        let Some(prompt) = prompt else {
            tracing::warn!(
                request_id = %request_id,
                "network_auth: 批量应答指向未知或已失效的询问（已忽略）"
            );
            return false;
        };

        let mut dropped_records = 0usize;
        match decision {
            NetworkBatchDecision::Allow => {
                for origin in &prompt.origins {
                    match self
                        .store
                        .grant(
                            &prompt.plugin_id,
                            AuthResource::Network,
                            origin,
                            &[],
                            AuthRecordSource::User,
                        )
                        .await
                    {
                        Ok(GrantOutcome::Stored) => {}
                        Ok(GrantOutcome::DroppedByCap) => dropped_records += 1,
                        Err(e) => {
                            tracing::warn!(
                                plugin_id = %prompt.plugin_id,
                                origin = %origin,
                                error = %e,
                                "network_auth: 批量允许记录落账失败（本次已放行）"
                            );
                        }
                    }
                }
            }
            NetworkBatchDecision::Deny => {}
            NetworkBatchDecision::DenyAlways => {
                for origin in &prompt.origins {
                    if let Err(e) = self
                        .store
                        .deny(
                            &prompt.plugin_id,
                            AuthResource::Network,
                            origin,
                            AuthRecordSource::UserDeny,
                        )
                        .await
                    {
                        tracing::warn!(
                            plugin_id = %prompt.plugin_id,
                            origin = %origin,
                            error = %e,
                            "network_auth: 批量拒绝记录落账失败（本次已拒绝）"
                        );
                    }
                }
            }
        }

        for waiter in prompt.waiters {
            let _ = waiter.send(BatchReply {
                decision,
                dropped_records,
            });
        }
        tracing::info!(
            plugin_id = %prompt.plugin_id,
            request_id = %request_id,
            decision = decision.as_str(),
            origins = prompt.origins.len(),
            dropped_records,
            "network_auth: 批量出站授权应答已落定"
        );
        true
    }

    /// 发起一次批量询问并等待应答（超时 / 通道关闭按本次拒绝）
    ///
    /// 无事件通道（无头上下文）或事件投递失败返回 `Err`，由批量入口整体映射为
    /// 「不可用」；不伪造逐项结果，也不落账。
    async fn batch_prompt(
        &self,
        plugin_id: &str,
        origins: &[String],
    ) -> Result<BatchReply, String> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let batch_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        {
            let mut prompts = self.batch_prompts.lock().await;
            prompts.insert(
                request_id.clone(),
                BatchPrompt {
                    plugin_id: plugin_id.to_string(),
                    origins: origins.to_vec(),
                    waiters: vec![tx],
                },
            );
        }

        let Some(emit) = self.emit.as_ref() else {
            self.batch_prompts.lock().await.remove(&request_id);
            tracing::warn!(
                plugin_id = %plugin_id,
                origins = origins.len(),
                "network_auth: 无事件通道（无头上下文），批量出站授权不可用"
            );
            return Err("no prompt channel (headless context)".to_string());
        };

        let payload = serde_json::json!({
            "requestId": request_id,
            "batchId": batch_id,
            "pluginId": plugin_id,
            "origins": origins,
            "remembers": true,
        });
        if let Err(e) = emit(NETWORK_AUTH_BATCH_REQUEST_EVENT, payload) {
            self.batch_prompts.lock().await.remove(&request_id);
            tracing::error!(
                plugin_id = %plugin_id,
                error = %e,
                "network_auth: 批量弹窗事件投递失败，批量授权不可用"
            );
            return Err(format!("batch prompt event delivery failed: {e}"));
        }
        tracing::info!(
            plugin_id = %plugin_id,
            batch_id = %batch_id,
            request_id = %request_id,
            origins = origins.len(),
            "network_auth: 发起批量出站授权询问"
        );

        match tokio::time::timeout(self.prompt_timeout, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Ok(BatchReply {
                decision: NetworkBatchDecision::Deny,
                dropped_records: 0,
            }),
            Err(_) => {
                self.batch_prompts.lock().await.remove(&request_id);
                tracing::warn!(
                    plugin_id = %plugin_id,
                    request_id = %request_id,
                    origins = origins.len(),
                    "network_auth: 批量出站授权询问超时（按本次拒绝，不落账）"
                );
                Ok(BatchReply {
                    decision: NetworkBatchDecision::Deny,
                    dropped_records: 0,
                })
            }
        }
    }

    /// 无询问面判定（任务单元 / 池线程）：只认记录，未记录即拒绝
    ///
    /// 与 [`Self::authorize_outbound`] 的第 1、2、3 步判据**逐字同源**（deny 优先 +
    /// 档位 + 记录命中 + 始终允许档的留痕），差别只在第 4 步：这里没有弹窗，直接拒绝。
    /// **两处判据必须同源**，否则「任务单元里能过、命令面里被拒」这类双答案永远
    /// 无法解释——而双答案正是显性接线策略守卫的理由（早期代码只有默认档）。
    pub async fn is_granted(&self, plugin_id: &str, url: &str) -> bool {
        self.authorize_outbound_quiet(plugin_id, url)
            .await
            .is_ok_and(|verdict| verdict.is_allowed())
    }

    /// [`Self::is_granted`] 的结构化版本（带 origin / 原因，供错误文案用）
    pub async fn authorize_outbound_quiet(
        &self,
        plugin_id: &str,
        url: &str,
    ) -> crate::Result<OutboundVerdict> {
        let Some(target) = normalize_target(url) else {
            return Err(crate::AppError::Internal(
                "网络出站授权：URL 不可归一化（缺 scheme / host / 端口），已拒绝".to_string(),
            ));
        };
        let records = self
            .store
            .records_for_match(plugin_id, AuthResource::Network)
            .await?;
        if records
            .iter()
            .any(|row| row.effect == AUTH_EFFECT_DENY && record_covers(row, &target))
        {
            return Ok(OutboundVerdict::Deny {
                origin: target.origin,
                reason: "deny-record",
            });
        }
        // 策略层：与弹窗面同一个 `read_strategy`（档位语义不分面）
        let strategy = self.read_strategy(plugin_id).await;
        if matches!(strategy.step.tier(), Tier::AutoAllow) {
            // 留痕与弹窗面同点：档位语义是「不问」，留痕是它的义务（S-11）
            debug_assert!(
                strategy.step.must_land_auto_allow(),
                "AutoAllow 档位字段丢失审计义务（S-11）"
            );
            self.land_auto_allow(plugin_id, &target).await;
            return Ok(OutboundVerdict::Allow {
                origin: target.origin,
                layer: "always-allow",
            });
        }
        if strategy.step.reads_allow_records()
            && records
                .iter()
                .any(|row| row.effect == AUTH_EFFECT_ALLOW && record_covers(row, &target))
        {
            return Ok(OutboundVerdict::Allow {
                origin: target.origin,
                layer: "record",
            });
        }
        // 无记录且无弹窗通道：拒绝（与「用户还没来得及答」同结果）。
        // 「总是询问」档也落在这里：它每批都要弹窗，池线程不弹窗 = 拒绝。
        Ok(OutboundVerdict::Deny {
            origin: target.origin,
            reason: "no-record",
        })
    }

    /// 策略层求值（**判定时实时读取**，不缓存、不做激活期快照）
    ///
    /// 共用 [`strategy::evaluate`]：档位→动作的映射与「先判档位还是先读记录」的顺序
    /// 只有一处真源（网络侧若自己拼一次 `match`，与文件侧的差异从代码上看两边都自洽）。
    ///
    /// 读失败按 fail-safe 退化成「询问 + 落账」（与 fs 侧 `decide_without_dialog` 同源）：
    /// 放行方向才是危险的一侧，策略读不出来时最该做的是问用户，而不是当更宽松的档走。
    async fn read_strategy(&self, plugin_id: &str) -> StrategyVerdict {
        match strategy::evaluate(&self.store, plugin_id, AuthResource::Network).await {
            Ok(step) => StrategyVerdict {
                lands_allow_record: step.reads_allow_records(),
                step,
            },
            Err(e) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "network_auth: 策略档位读取失败，本次判定按询问处理"
                );
                StrategyVerdict {
                    step: StrategyStep::ask(),
                    lands_allow_record: true,
                }
            }
        }
    }

    /// 「始终允许」档的免询问放行留痕（不问，但必须落账）
    ///
    /// 落账粒度 = 本次归一化 origin（`prefix_match=0`，整站）：询问粒度本就是 origin，
    /// 落更细的 path 会在界面上出现「用户授权的明明是 `/v1`、库里却是整站」这类
    /// 形状不一致；而落更粗（合并整站）正是这个粒度本身，不存在放大。
    ///
    /// 落账失败 / 容量上限（[`GrantOutcome::DroppedByCap`]）**不影响放行方向**：档位
    /// 语义是「不问」，留不下痕时拒绝访问是更坏的结果（用户明确配了这个档位）。
    async fn land_auto_allow(&self, plugin_id: &str, target: &NormalizedTarget) {
        match self
            .store
            .grant(
                plugin_id,
                AuthResource::Network,
                &target.origin,
                &[],
                AuthRecordSource::AlwaysAllow,
            )
            .await
        {
            Ok(GrantOutcome::Stored) => {
                tracing::debug!(
                    plugin_id = %plugin_id,
                    origin = %target.origin,
                    "network_auth: 始终允许档，免询问放行并落账"
                );
            }
            // 计数与 warn 都在落账点（`AuthPolicyStore::grant`）出，这里不重复
            Ok(GrantOutcome::DroppedByCap) => {}
            Err(e) => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    origin = %target.origin,
                    error = %e,
                    "network_auth: 始终允许档的落账失败（放行方向不变）"
                );
            }
        }
    }

    /// 处理用户应答（由前端 Tauri 命令调用；仅宿主面凭证可代答）
    ///
    /// **落账只在这里发生一次**（而不是每个等待者各落一次）：合并批次里的 N 个请求共用
    /// 一次询问、一次落账。`allow_once` 落 allow（`source='user'`），
    /// `deny_always` 落 deny（`source='user_deny'`），`deny` 不落账。
    /// 「总是询问」档下 `allow_once` **不落账**：该档不读记录，落一条
    /// 永远不会被命中的 allow 记录只会让管理界面显示一条假的「用户已授权」。
    /// 返回 `false` = 未知 / 已作答的 request_id（重复应答、超时后迟到）：只记 warn。
    pub async fn respond(&self, request_id: &str, decision: NetworkDecision) -> bool {
        let key = {
            let mut prompts = self.prompts.lock().await;
            let key = prompts
                .iter()
                .find(|(_, prompt)| prompt.request_id == request_id)
                .map(|(key, _)| key.clone());
            // 键刚由 iter 命中，取不到说明并发下已被移除（超时清理）：按未知处理
            let Some(key) = key else {
                drop(prompts);
                tracing::warn!(
                    request_id = %request_id,
                    "network_auth: 应答指向未知或已失效的询问（已忽略）"
                );
                return false;
            };
            let Some(entry) = prompts.get_mut(&key) else {
                return false;
            };
            // 已作答的询问不接受二次决定：否则迟到点击会改写已放行批次的语义
            if entry.decision.is_some() {
                drop(prompts);
                tracing::warn!(
                    request_id = %request_id,
                    "network_auth: 询问已作答，重复应答已忽略"
                );
                return false;
            }
            entry.decision = Some((decision, Instant::now()));
            let waiters = std::mem::take(&mut entry.waiters);
            // 落账口径随**弹出时**的档位一起取走：用户点「允许」时改档，
            // 已在途的这个弹窗仍按旧口径走完
            let lands_allow_record = entry.lands_allow_record;
            (key, waiters, lands_allow_record)
        };
        let (key, waiters, lands_allow_record) = key;

        for waiter in waiters {
            // 等待者可能已超时退出（oneshot 发送失败）：忽略即可，不是错误
            let _ = waiter.send(decision);
        }

        // 落账（只此一处）
        match decision {
            NetworkDecision::AllowOnce if !lands_allow_record => {
                // 「总是询问」档：只放行本批，不落账（该档不读记录，落了也没人读，
                // 且会在管理界面显示成「用户已授权」——与实际行为不符）
                tracing::debug!(
                    plugin_id = %key.plugin_id,
                    origin = %key.origin,
                    "network_auth: 总是询问档下允许本次，不落账"
                );
            }
            NetworkDecision::AllowOnce => {
                if let Err(e) = self
                    .store
                    .grant(
                        &key.plugin_id,
                        AuthResource::Network,
                        &key.origin,
                        &[],
                        AuthRecordSource::User,
                    )
                    .await
                {
                    // 放行不受落账失败影响（用户已经点头），但必须留痕：否则记录缺失
                    // 表现为「刚同意过又问一次」，无从解释
                    tracing::warn!(
                        plugin_id = %key.plugin_id,
                        origin = %key.origin,
                        error = %e,
                        "network_auth: 允许记录落账失败（本次已放行）"
                    );
                }
            }
            NetworkDecision::DenyAlways => {
                if let Err(e) = self
                    .store
                    .deny(
                        &key.plugin_id,
                        AuthResource::Network,
                        &key.origin,
                        AuthRecordSource::UserDeny,
                    )
                    .await
                {
                    tracing::warn!(
                        plugin_id = %key.plugin_id,
                        origin = %key.origin,
                        error = %e,
                        "network_auth: 拒绝记录落账失败（本次已拒绝）"
                    );
                }
            }
            NetworkDecision::Deny => {}
        }
        true
    }

    /// 询问用户（合并同 origin 的并发 / 紧邻请求）
    ///
    /// `lands_allow_record` = 弹出时档位是否读授权记录：「总是询问」档传
    /// 假 ⇒ 应答「允许」只放行本批、不落账（那条记录没人会读，落了等于在管理界面
    /// 谎称「用户已授权」）。合并窗口在**所有档位**下都生效——否则
    /// 「总是询问」在 agent-hub 一次几十个请求的刷新里会变成几十次弹窗。
    async fn prompt(
        &self,
        plugin_id: &str,
        target: &NormalizedTarget,
        lands_allow_record: bool,
    ) -> NetworkDecision {
        let key = PromptKey {
            plugin_id: plugin_id.to_string(),
            origin: target.origin.clone(),
        };

        // 槽位决策：复用窗口内既有决定 / 并入在途询问 / 新建询问。
        // 全部在锁内完成——锁只做 map 操作与 sender 投递，绝不跨 await
        enum Slot {
            Reuse(NetworkDecision),
            Join(oneshot::Receiver<NetworkDecision>),
            Fresh {
                request_id: String,
                reply: oneshot::Receiver<NetworkDecision>,
            },
        }

        let slot = {
            let mut prompts = self.prompts.lock().await;
            // 顺带回收过期条目：没有后台清理任务，靠下一次询问触发（防止 map 无界增长）
            let now = Instant::now();
            prompts.retain(|_, prompt| match prompt.decision {
                Some((_, decided_at)) => now.duration_since(decided_at) <= self.merge_window,
                // 未作答的条目不回收：用户可能还在看弹窗，删掉会把它永远悬着
                None => true,
            });

            match prompts.get_mut(&key) {
                Some(entry) => match entry.decision {
                    Some((decision, _)) => Slot::Reuse(decision),
                    None => {
                        let (tx, rx) = oneshot::channel();
                        entry.waiters.push(tx);
                        Slot::Join(rx)
                    }
                },
                None => {
                    let (tx, rx) = oneshot::channel();
                    let request_id = uuid::Uuid::new_v4().to_string();
                    prompts.insert(
                        key.clone(),
                        OriginPrompt {
                            request_id: request_id.clone(),
                            waiters: vec![tx],
                            decision: None,
                            lands_allow_record,
                        },
                    );
                    Slot::Fresh {
                        request_id,
                        reply: rx,
                    }
                }
            }
        };

        match slot {
            Slot::Reuse(decision) => {
                tracing::debug!(
                    plugin_id = %plugin_id,
                    origin = %target.origin,
                    decision = decision.as_str(),
                    "host-http: 复用合并窗口内的同 origin 决定"
                );
                decision
            }
            Slot::Join(reply) => self.await_reply(&key, reply, None).await,
            Slot::Fresh { request_id, reply } => {
                // 无头上下文（测试）没有事件通道，无法弹窗：整批按拒绝，条目不留
                let Some(emit) = self.emit.as_ref() else {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        origin = %target.origin,
                        "network_auth: 无事件通道（无头上下文），出站按拒绝"
                    );
                    self.abort_prompt(&key, &request_id).await;
                    return NetworkDecision::Deny;
                };
                let payload = serde_json::json!({
                    "requestId": request_id,
                    "pluginId": plugin_id,
                    "origin": target.origin,
                    // 「允许」会不会落成授权记录（= 弹出时档位是否读记录）。
                    // 前端据此换文案：说「以后不再询问」而在「总是询问」档下实际不记，
                    // 就是在骗用户（弹窗解释与实际行为必须同源）
                    "remembers": lands_allow_record,
                });
                if let Err(e) = emit(NETWORK_AUTH_REQUEST_EVENT, payload) {
                    // 事件未送达前端：请求永远不会被应答，整批按拒绝（不留悬空条目）
                    tracing::error!(
                        plugin_id = %plugin_id,
                        origin = %target.origin,
                        error = %e,
                        "network_auth: 弹窗事件投递失败，出站按拒绝"
                    );
                    self.abort_prompt(&key, &request_id).await;
                    return NetworkDecision::Deny;
                }
                self.await_reply(&key, reply, Some(&request_id)).await
            }
        }
    }

    /// 等待应答（超时按拒绝）
    ///
    /// `leader_request_id` = `Some` 时本调用是询问的创建者：超时后负责把条目清掉。
    /// 这不只是防内存涨——**不清理就会留下一个仍可被应答的悬空询问**：用户在超时后
    /// 才点「允许」，`respond` 会找到它并落一条 allow 记录，而那次请求早已按拒绝收场
    /// （记录与事实不符，UI 上还会出现「我明明拒绝了怎么又授权了」）。并入者
    /// （`None`）无权清理：条目属创建者的在途询问。
    async fn await_reply(
        &self,
        key: &PromptKey,
        reply: oneshot::Receiver<NetworkDecision>,
        leader_request_id: Option<&str>,
    ) -> NetworkDecision {
        match tokio::time::timeout(self.prompt_timeout, reply).await {
            Ok(Ok(decision)) => decision,
            // 通道被丢弃（问询方已超时退出）：不重试，按拒绝
            Ok(Err(_)) => NetworkDecision::Deny,
            Err(_) => {
                tracing::warn!(
                    plugin_id = %key.plugin_id,
                    origin = %key.origin,
                    merged = leader_request_id.is_none(),
                    "network_auth: 出站授权询问超时（按拒绝，不落账）"
                );
                if let Some(request_id) = leader_request_id {
                    self.drop_prompt_if_current(key, request_id).await;
                }
                NetworkDecision::Deny
            }
        }
    }

    /// 丢弃本询问（仅当条目仍属该 request_id；已被新询问替换则不动）
    async fn drop_prompt_if_current(&self, key: &PromptKey, request_id: &str) {
        let mut prompts = self.prompts.lock().await;
        let owned_by_request = prompts
            .get(key)
            .is_some_and(|entry| entry.request_id == request_id);
        if owned_by_request {
            prompts.remove(key);
        }
    }

    /// 弹窗不可用（无事件通道 / 投递失败）：把该询问下所有等待者按拒绝并清条目
    async fn abort_prompt(&self, key: &PromptKey, request_id: &str) {
        let mut prompts = self.prompts.lock().await;
        let Some(entry) = prompts.get_mut(key) else {
            return;
        };
        if entry.request_id != request_id {
            // 已被新的询问替换（不属本次），不动
            return;
        }
        let waiters = std::mem::take(&mut entry.waiters);
        prompts.remove(key);
        for waiter in waiters {
            let _ = waiter.send(NetworkDecision::Deny);
        }
    }
}

// ==================== Tests ====================

// 用例按功能拆至 `network_auth/tests/`（本内联模块的子模块路径由 rustc
// 自动解析到该目录；模块树 `wasm_core::security::network_auth::tests::<文件>` 与内联形态等价，私有项可见性不受影响）。
#[cfg(test)]
mod tests {
    use super::*;
    mod batch;
    mod decision_chain;
    mod general;
    mod no_prompt_task;
    mod policy_tiers;
    mod policy_tiers_2;
    mod prompt_channel;
    mod prompt_channel_2;
    mod record_match;
    mod scaffold;
}
