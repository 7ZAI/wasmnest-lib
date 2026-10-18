//! 能力域生命周期钩子注册表：让内核在「插件装载 / 停用回收」两个时点回调能力域
//!
//! ## 解决的问题
//!
//! 内核（wasm-core）原本**直接调用**能力域的回收入口
//! （`wasmnest_pty_engine::plugin_binding::register_quota` / `purge_for_plugin`），
//! 于是内核必须 path 依赖每一个能力域 crate：新增能力域要改内核、不含该域的宿主
//! （移动端 / 无头探针）也无法复用内核。这与 ADR 0035 已消灭的「装配与实现绑死」
//! 是同一个病灶，只是出现在生命周期面上。
//!
//! 处置与 [`crate::module`] 同范式：能力域用 `inventory::submit!` 自报钩子，内核
//! 遍历回调表 ⇒ **内核源码里不再出现任何能力域 crate 名**（票 02 批次 01）。
//!
//! ## 语义红线（AGENTS §5.1 B6）
//!
//! 钩子参数只许机制语义：`plugin_id` 与 **manifest 原文**。配额与声明项的解析权在
//! 能力域自己——内核一旦解释 manifest 字段（如「pty 配额多少」）就变成解释产品
//! 事件，命中 B6。故 [`DomainHooks::on_manifest_load`] 传的是 JSON 原文而非
//! 结构化配额。
//!
//! ## 与 [`crate::module`] 的分工
//!
//! - [`crate::module::HostModule`]：`linker` 装配（面向 guest import）
//! - 本模块：生命周期回调（面向宿主装载 / 回收）
//!
//! 两者由同一个能力域自报、共用同一个白名单键（[`DomainHooks::name`] 与
//! [`crate::HostModuleDesc::name`] 同源），故宿主白名单校验对两面同时生效。

/// 能力域生命周期钩子（每项可选：能力域只报自己关心的时点）
#[derive(Debug, Clone, Copy)]
pub struct DomainHooks {
    /// 能力域名（与 [`crate::HostModuleDesc::name`] 同源，宿主白名单键）
    pub name: &'static str,
    /// 装载期回调：`(plugin_id, manifest_json)`——manifest 原文交给能力域自解析
    ///
    /// **为什么传原文而不是结构化配额**：解析 manifest 字段等于替能力域解释它的
    /// 声明语义（B6），且字段一变内核就要跟着改。原文下发后，字段演进只需动能力域。
    ///
    /// **返回 `Result<(), String>`（票 02 批次 03 起）**：能力域可**拒绝**该 manifest
    /// ——`Err(reason)` = 「本域不接受此插件装载」，内核据此不装载并把 `reason` 原样
    /// 落 `error!`。域内声明越界（如 `ptyQuota` 超出上限）必须走这条返回值，而不是域内
    /// 记日志后静默降级：降级后插件会按自己声明的并发数规划业务、实际却少得多，属
    /// fail-visible 反例（与 `PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN` 的「不夹取」同口径）。
    pub on_manifest_load: Option<fn(&str, &str) -> Result<(), String>>,
    /// 停用期回调：`(plugin_id)`——回收该插件在能力域内的全部资源
    ///
    /// 无返回值：回收是尽力而为的清理（句柄已失效时重复回收必须幂等），失败一律
    /// 由能力域自行记 `warn!`，不上抛、不阻断停用流程。
    pub on_plugin_purge: Option<fn(&str)>,
}

/// inventory 提交类型（能力域用 `submit!` 自报；收集点必须在本 crate，孤儿规则）
///
/// 与 [`crate::ModuleEntry`] 同款约束：`inventory::collect!` 展开为「为本类型实现
/// `inventory::Collect`」，该 trait 要求本地类型 ⇒ 收集点只能在 kit。
pub struct DomainHooksEntry {
    /// 静态单例（能力域用 `&'static` 常量提交）
    pub hooks: &'static DomainHooks,
}

inventory::collect!(DomainHooksEntry);

/// 能力域侧提交宏：把一组生命周期钩子自报进全局注册表
///
/// 用法（能力域 crate 内）：
/// ```ignore
/// static HOOKS: wasmnest_host_kit::DomainHooks = wasmnest_host_kit::DomainHooks {
///     name: MODULE_NAME,
///     on_manifest_load: Some(on_manifest_load),
///     on_plugin_purge: Some(purge_for_plugin),
/// };
/// wasmnest_host_kit::submit_hooks!(HOOKS);
/// ```
#[macro_export]
macro_rules! submit_hooks {
    ($hooks:expr) => {
        ::inventory::submit! {
            $crate::DomainHooksEntry { hooks: &$hooks }
        }
    };
}

/// 生命周期钩子注册表（收集 → 排序 → 白名单校验 → 遍历回调）
///
/// 排序与 [`crate::registry::ModuleRegistry`] 同口径（按名**字典序**）：回调彼此
/// 独立、顺序本无语义，固定顺序只为让日志与报错可复现。
pub struct DomainHooksRegistry {
    hooks: Vec<&'static DomainHooks>,
}

impl std::fmt::Debug for DomainHooksRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.hooks.iter().map(|h| h.name))
            .finish()
    }
}

impl DomainHooksRegistry {
    /// 收集全局已自报的生命周期钩子（未过滤、未校验）
    pub fn collected() -> Self {
        let mut hooks: Vec<&'static DomainHooks> = inventory::iter::<DomainHooksEntry>
            .into_iter()
            .map(|entry| entry.hooks)
            .collect();
        hooks.sort_by_key(|h| h.name);
        Self { hooks }
    }

    /// 已收集钩子的能力域名（字典序）
    pub fn names(&self) -> Vec<&'static str> {
        self.hooks.iter().map(|h| h.name).collect()
    }

    /// 已收集钩子数
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// 是否一个钩子都没收集到（宿主刚起来 / 能力 crate 全没链上的诊断用）
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// 白名单双向校验：收集结果必须与白名单**完全相等**
    ///
    /// 与 [`crate::registry::ModuleRegistry::verify_whitelist`] 同款判据（多出 = 未经
    /// review 进来的能力；少了 = 依赖被删 / 没链上）。差异即显性失败，不静默忽略。
    pub fn verify_whitelist(&self, whitelist: &[&str]) -> crate::Result<()> {
        let mut listed: Vec<&str> = self.hooks.iter().map(|h| h.name).collect();
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
        Err(crate::HostKitError::WhitelistMismatch { unlisted, missing })
    }

    /// 装载期：遍历全部钩子下发 manifest 原文（跳过未实现的时点）
    ///
    /// 内核侧唯一入口——**调用方不得再点名任何能力域 crate**。
    ///
    /// 任一钩子返回 `Err` 即**短路**并原样上抛（遍历顺序 = 能力域名典序，确定性）：
    /// 该 manifest 已被拒绝 ⇒ 再让后续域登记等于为「不会装载的插件」留状态。调用方
    /// （装载漏斗）必须把 `Err` 变成「不装载」，**不得**吞掉后继续（fail-visible）。
    pub fn on_manifest_load(&self, plugin_id: &str, manifest_json: &str) -> Result<(), String> {
        for hooks in &self.hooks {
            if let Some(callback) = hooks.on_manifest_load {
                callback(plugin_id, manifest_json)?;
            }
        }
        Ok(())
    }

    /// 停用期：遍历全部钩子回收该插件资源（跳过未实现的时点）
    pub fn on_plugin_purge(&self, plugin_id: &str) {
        for hooks in &self.hooks {
            if let Some(callback) = hooks.on_plugin_purge {
                callback(plugin_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! 注册表自身行为的单测（自报与收集需要 inventory 静态，故在本 crate 内起一个
    //! 探针钩子；`tests/` 目录受治理锁约束 ⇒ 一律写在 `src/` 并 `#[cfg(test)] mod` 引入）

    use super::{DomainHooks, DomainHooksRegistry};

    static PROBE: DomainHooks = DomainHooks {
        name: "kit-lifecycle-probe",
        on_manifest_load: None,
        on_plugin_purge: None,
    };

    crate::submit_hooks!(PROBE);

    /// 拒绝探针：证明「域可拒绝装载」这条契约路径真被遍历到并原样上抛
    static REJECT_PROBE: DomainHooks = DomainHooks {
        name: "kit-lifecycle-reject-probe",
        on_manifest_load: Some(reject_manifest),
        on_plugin_purge: None,
    };

    crate::submit_hooks!(REJECT_PROBE);

    fn reject_manifest(plugin_id: &str, _manifest_json: &str) -> Result<(), String> {
        Err(format!("kit-lifecycle-reject-probe 拒绝 {plugin_id} 的 manifest 声明"))
    }

    /// 自报的探针必须被收集到（强制引用在本文件内成立 ⇒ inventory 静态被执行）
    #[test]
    fn submitted_probe_is_collected() {
        let registry = DomainHooksRegistry::collected();
        assert!(
            registry.names().contains(&"kit-lifecycle-probe"),
            "自报的探针应被收集到，实际：{:?}",
            registry.names()
        );
    }

    /// 白名单相等时通过
    #[test]
    fn whitelist_matches_returns_ok() {
        let registry = DomainHooksRegistry::collected();
        registry
            .verify_whitelist(&["kit-lifecycle-probe", "kit-lifecycle-reject-probe"])
            .expect("白名单与收集结果一致时应通过");
    }

    /// 白名单多出一项 ⇒ missing 方向点名（依赖没链上的典型症状）
    #[test]
    fn whitelist_missing_is_reported() {
        let registry = DomainHooksRegistry::collected();
        let err = registry
            .verify_whitelist(&[
                "kit-lifecycle-probe",
                "kit-lifecycle-reject-probe",
                "not-linked-domain",
            ])
            .expect_err("白名单多出未收集项应失败");
        let msg = err.to_string();
        assert!(msg.contains("not-linked-domain"), "错误须点名缺失域：{msg}");
    }

    /// 回调遍历：未实现 `on_plugin_purge`（None）的钩子被跳过且不 panic
    #[test]
    fn callbacks_skip_unimplemented_hooks() {
        let registry = DomainHooksRegistry::collected();
        // 两个探针的 purge 钩子都是 None ⇒ 遍历应静默跳过
        registry.on_plugin_purge("plugin-a");
    }

    /// 拒绝语义：任一钩子返回 `Err` ⇒ 短路并把该域的原因原样上抛
    ///
    /// 这是「域可拒绝装载」的唯一出口——吞掉它等于让越界声明静默生效
    /// （fail-visible 反例，口径见 `DomainHooks::on_manifest_load`）。
    #[test]
    fn manifest_load_rejection_is_propagated() {
        let registry = DomainHooksRegistry::collected();
        let err = registry
            .on_manifest_load("plugin-a", "{}")
            .expect_err("拒绝探针必须让装载期回调失败");
        assert!(
            err.contains("kit-lifecycle-reject-probe") && err.contains("plugin-a"),
            "错误须点名拒绝域与被拒插件：{err}"
        );
    }
}
