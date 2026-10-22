//! 能力模块自动注册表：收集 → 排序 → 白名单双向校验 → linker 装配
//!
//! ## 为什么「自动」还要「锁」
//!
//! `inventory` 的固有风险是**能力集随链接到的 crate 漂移**：某个 crate 被误删依赖，
//! 它提供的 interface 就静默从插件 import 集里消失，而 guest 侧毫无察觉——插件
//! 编译期照常 import，运行期才在实例化时炸。
//!
//! 治理手段是**白名单锁**（不是弃用自动发现）：宿主维护一个树内白名单常量，与收集
//! 结果**双向**比对——
//!
//! - 收集到但白名单没有 ⇒ 红（新增能力强制过 review，不会悄悄进产品）
//! - 白名单有但没收集到 ⇒ 红（依赖被删/没链上时立刻定位，不等到插件实例化）
//!
//! 「强制引用行」（`use wasmnest_cap_x as _;`）与白名单常量**放在同一处**，两者不漂移。
//!
//! ## 装配顺序
//!
//! 按模块名**字典序**装配（而非注册顺序）：linker 的 interface 命名空间彼此独立，
//! 顺序本无语义；固定顺序只为让重复注册的报错信息可复现。

use wasmtime::component::Linker;

use crate::module::HostModuleDesc;
use crate::state::WasmPluginState;
use crate::{HostKitError, Result};

// ==================== 描述符零产品名词判据（ADR 0035 D4） ====================

/// 描述符禁用词表：模块名 / 接口路径 / 权限位中不得出现的产品名词词段
///
/// 判据规则（词段相等，非子串包含）见 [`ModuleRegistry::product_noun_violations`]。
/// 这些词代表产品语义（会话 / 终端 / 配对 / 设备 / 传输 / 文件 / 对话 / AI / Agent /
/// PTY 实例 / MCP）；一旦进入描述符，注册表就从「通用注册表与寻址」退化成业务容器
/// （AGENTS §5.1 B1/B5）。
///
/// **端独有扩展的例外不在这里**：豁免由各扫描点显式登记（例：移动 `mobile-terminal-stream`
/// 是 ADR 0047 / ADR 0052 D4 保留的窄转发端扩展，命中 `terminal` 属端事实），
/// 本表只定义「什么算命中」。
pub const PRODUCT_NOUN_DENYLIST: &[&str] = &[
    "session",
    "terminal",
    "pairing",
    "device",
    "transfer",
    "file",
    "chat",
    "ai",
    "agent",
    "pty-instance",
    "mcp",
];

/// 单条描述符命中记录（模块名 + 命中词 + 判定用的归一化文本）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorNounViolation {
    /// 模块名（[`HostModuleDesc::name`]）
    pub module: &'static str,
    /// 命中的禁用词（[`PRODUCT_NOUN_DENYLIST`] 中一项）
    pub noun: &'static str,
    /// 判定用的归一化文本（模块名 + 接口路径 + 权限位 + ABI 下界）
    pub haystack: String,
}

/// 词段命中判定：按非字母数字切段，`-` / `_` 视作**段内连接符**（不切）
///
/// 于是 `host-session` 切成 `host` + `session`（命中）、`database:main` 里的 `ai`
/// 只是 `main` 的内部子串（不命中）。契约例见本文件 `mod tests`。
fn descriptor_haystack_has_noun(haystack: &str, noun: &str) -> bool {
    // 先把 `_` 归一化成 `-`（两种连接符在本仓库都出现：接口路径用 `-`，模块名 /
    // 权限位用 `_`），再切词；`-` 保留为段内连接符。
    let normalized = haystack.replace('_', "-");
    let prefix = format!("{noun}-");
    let suffix = format!("-{noun}");
    let infix = format!("-{noun}-");
    normalized
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .filter(|word| !word.is_empty())
        .any(|word| {
            word == noun
                || word.starts_with(&prefix)
                || word.ends_with(&suffix)
                || word.contains(&infix)
        })
}

/// 宿主能力模块注册表
/// 能力模块注册表（机制内核 crate）
///
/// 手工 `Debug`（不 derive）：字段是 `&dyn HostModule`，而 `HostModule` 不要求
/// `Debug`（能力 crate 没必要为此实现它）⇒ 改按模块名与描述符输出。存在的理由：
/// 能力模块的**错误**路径用 `expect_err` 断言需要成功类型可格式化，而注册表本身
/// 在生产代码里不走任何 Debug 输出。
pub struct ModuleRegistry {
    modules: Vec<&'static dyn crate::module::HostModule>,
}

impl std::fmt::Debug for ModuleRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.modules.iter().map(|m| m.desc().name))
            .finish()
    }
}

impl ModuleRegistry {
    /// 收集全局已自报的能力模块（未过滤、未校验）
    pub fn collected() -> Self {
        let mut modules: Vec<&'static dyn crate::module::HostModule> =
            inventory::iter::<crate::module::ModuleEntry>
                .into_iter()
                .map(|entry| entry.module)
                .collect();
        modules.sort_by_key(|m| m.desc().name);
        Self { modules }
    }

    /// 从**显式模块集**构造注册表（不经 `inventory` 收集）
    ///
    /// 存在的理由：`collected()` 只能拿到当前二进制里 `submit!` 过的模块，构造不出
    /// 「真实现 + 兜底/兼容桩」的精确对峙组合——而 [`Self::install_all`] 的两遍装配
    /// 语义（兜底让位）必须能被单独钉住：跨端同进程 rig 虽是这套语义的目标场景，
    /// 但其测试是 `#[ignore]` 的（CI 不跑），没有这里的单测，让位逻辑就只有
    /// 「真实互连时炸一次」这一个发现渠道。
    ///
    /// 排序口径与 `collected()` 一致（按模块名字典序：装配顺序稳定 ⇒ 重复注册的
    /// 报错可复现）。
    pub fn from_modules(modules: Vec<&'static dyn crate::module::HostModule>) -> Self {
        let mut modules = modules;
        modules.sort_by_key(|m| m.desc().name);
        Self { modules }
    }

    /// 已装配模块的描述符（装配顺序 = 字典序）
    pub fn descs(&self) -> Vec<HostModuleDesc> {
        self.modules.iter().map(|m| m.desc()).collect()
    }

    /// 已装配模块数
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// 是否一个模块都没有（宿主刚起来、能力 crate 全没链上的诊断用）
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// 白名单双向校验：收集结果必须与白名单**完全相等**
    ///
    /// 差异即 [`HostKitError::WhitelistMismatch`]——**显性失败**，不静默忽略：
    /// 「多出来的」意味着有 crate 被加进来却没过 review；「少了的」意味着依赖丢失。
    pub fn verify_whitelist(&self, whitelist: &[&str]) -> Result<()> {
        let mut listed: Vec<&str> = self.modules.iter().map(|m| m.desc().name).collect();
        listed.sort_unstable();
        let mut expected: Vec<&str> = whitelist.to_vec();
        expected.sort_unstable();

        if listed == expected {
            return Ok(());
        }
        let unlisted: Vec<String> = listed
            .iter()
            .filter(|n| !expected.contains(n))
            .map(|n| (*n).to_string())
            .collect();
        let missing: Vec<String> = expected
            .iter()
            .filter(|n| !listed.contains(n))
            .map(|n| (*n).to_string())
            .collect();
        Err(HostKitError::WhitelistMismatch { unlisted, missing })
    }

    /// 描述符产品名词命中（空 = 通过；AGENTS §5.1 B1/B5 红线）
    ///
    /// **为什么在机制侧**：描述符是 [`crate::module::HostModuleDesc`] 的自报面，而
    /// `inventory` 收集按**测试二进制**隔离——某端宿主 adapter 自报的模块只有该端
    /// 的测试二进制能收集到。判据与词表因此以本方法为单一真源，各扫描点
    /// （wasm-core / 两端宿主）对自己的 `ModuleRegistry::collected()` 全量跑一次。
    ///
    /// **只返回原始命中、不做豁免**：端独有扩展可以合法携带端事实词汇（例：移动
    /// `mobile-terminal-stream`，ADR 0047 / ADR 0052 D4 保留的窄转发端扩展），
    /// 豁免由各扫描点把期望命中集显式登记后比对（防「静默放过」）。
    ///
    /// 匹配粒度 = **词段相等**，不是子串包含：`database:main` 里的 `ai` 是 `main`
    /// 的内部子串，不命中（票 08 实测修正，子串判据曾把纯机制权限位判成产品名词）。
    pub fn product_noun_violations(&self) -> Vec<DescriptorNounViolation> {
        let mut violations = Vec::new();
        for desc in self.descs() {
            let haystack = format!(
                "{} {:?} {:?} {}",
                desc.name, desc.interfaces, desc.permissions, desc.abi_min
            )
            .to_lowercase();
            for noun in PRODUCT_NOUN_DENYLIST {
                if descriptor_haystack_has_noun(&haystack, noun) {
                    violations.push(DescriptorNounViolation {
                        module: desc.name,
                        noun,
                        haystack: haystack.clone(),
                    });
                }
            }
        }
        violations
    }

    /// 逐模块装配进插件 linker（顺序 = 字典序；**兜底/兼容桩模块最后**）
    ///
    /// 任一模块装配失败即整体失败并点名该模块（fail-visible：不允许「装了一半」的
    /// linker 流到实例化，那会让 guest 在更晚、更难定位的地方炸）。
    ///
    /// **两遍装配**：先装正式实现（`fallback() == false`），再装 [`HostModule::fallback`]
    /// 自报的兜底/兼容桩，且**跳过接口已被正式实现占用的桩**。为什么必须这样：跨端同
    /// 进程装配（`cross-end-tests`：桌面 lib 与移动 lib 同时链入）时，移动侧的桌面兼容桩
    /// （`mobile-desktop-compat`：只为 import 闭合的 fail-visible 桩）会与桌面真实现
    /// 同名 interface 撞车；桩的语义本来就是「没有真实现时才填位」，跳过是正解。
    /// 单端装配下接口无竞争，两遍装配与单遍行为一致（桩照装）。
    pub fn install_all(&self, linker: &mut Linker<WasmPluginState>) -> Result<()> {
        let mut claimed: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        // 第一遍：正式实现
        for module in self.modules.iter().filter(|m| !m.fallback()) {
            let desc = module.desc();
            module
                .register(linker)
                .map_err(|source| HostKitError::Register {
                    module: desc.name,
                    source,
                })?;
            claimed.extend(desc.interfaces.iter().copied());
        }
        // 第二遍：兜底/兼容桩（接口已被正式实现占用即跳过；无竞争则照装）
        for module in self.modules.iter().filter(|m| m.fallback()) {
            let desc = module.desc();
            let contested: Vec<&&'static str> = desc
                .interfaces
                .iter()
                .filter(|i| claimed.contains(**i))
                .collect();
            if !contested.is_empty() {
                tracing::debug!(
                    module = desc.name,
                    interfaces = ?contested,
                    "host-kit: fallback module skipped (interfaces already provided by real implementations)"
                );
                continue;
            }
            module
                .register(linker)
                .map_err(|source| HostKitError::Register {
                    module: desc.name,
                    source,
                })?;
            claimed.extend(desc.interfaces.iter().copied());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! 词段判据自身的契约例（判据本身也是被锁对象）
    //!
    //! 没有这组用例，匹配规则被改宽（回到子串）时**零红灯**——那时 `database:main`
    //! 会重新把纯机制权限位判成产品名词，修法往往是「把 sqlite 从词表里摘掉」，
    //! 正是本判据要防的那种降级。

    use super::descriptor_haystack_has_noun;

    /// 正例：复合名词命中（连接符是段内的一部分）
    #[test]
    fn descriptor_noun_matcher_keeps_compounds_and_drops_substrings() {
        assert!(descriptor_haystack_has_noun(
            "wasmnest:plugin@0.0.1/host-session",
            "session"
        ));
        assert!(descriptor_haystack_has_noun("pty-instance", "pty-instance"));
        assert!(descriptor_haystack_has_noun(
            "host_pty_instance",
            "pty-instance"
        ));
        assert!(descriptor_haystack_has_noun("ai-chatbox", "ai"));
        assert!(descriptor_haystack_has_noun(
            "wasmnest:plugin@0.0.1/host-session",
            "plugin"
        ));
        // 正例：分号 / 斜杠权限位与接口路径的词段照样命中
        assert!(descriptor_haystack_has_noun("[\"database:main\"]", "main"));
        assert!(descriptor_haystack_has_noun(
            "[\"host-session\"]",
            "session"
        ));
        // 反例：单词**内部**的子串不算命中（`database:main` 当年因这条误判）
        assert!(!descriptor_haystack_has_noun(
            "[\"database:main\", \"storage\"]",
            "ai"
        ));
        assert!(!descriptor_haystack_has_noun("sqlite", "ai"));
        assert!(!descriptor_haystack_has_noun("[\"network:mdns\"]", "file"));
        // 正例：连字符是段边界 ⇒ `m-ai-n` 里的 `ai` 是**整段**，必须命中
        assert!(descriptor_haystack_has_noun("m-ai-n", "ai"));
        // 反例：名词**粘在**别的字符里（没有段边界）不算命中
        assert!(!descriptor_haystack_has_noun("mail", "ai"));
        assert!(!descriptor_haystack_has_noun("[\"m.ain\"]", "ai"));
        assert!(!descriptor_haystack_has_noun(
            "[\"ptyinstance\"]",
            "pty-instance"
        ));
    }
}
