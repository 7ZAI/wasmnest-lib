//! 插件互调 api 注册表（ADR-0017 层 1 门禁）
//!
//! 插件激活时登记 manifest `api` 声明的全限定 api 名（如
//! `com.wasmnest.scheduler.add`），停用时注销。`bus_publish` 对
//! `wasmnest.api.*` 请求 topic 做目标校验：api 名必须命中注册表，
//! 否则拒绝 —— 「注册即声明，未声明不可调」由宿主强制。
//!
//! 注册表同时是「api → 声明属主」的解析入口（[`ApiRegistry::owner_of`]）：
//! 互调回复道据此校验回复 `sender`（票 05），与门禁判定读同一张表，
//! 不存在「门禁放行但属主解析不一致」的漂移。**属主解析统一走
//! [`ApiRegistry::gate`]**（单读锁内同时返回存在性与属主），避免
//! contains→owner_of 两次独立加锁间被 register/unregister 插缝。
//!
//! 注册表只存「目标 api 是否存在」（层 1），不校验调用方身份、不做
//! 版本化（ADR-0017 已决）；激活态插件的 api 才在表中，因此「已注册」
//! 等价于「目标插件已激活」。
//!
//! **登记 fail-closed**：api 已被**其它**插件声明时拒绝（[`Self::register`]
//! 返回 Err）——后激活插件不得抢占他人声明的 api 名（抢占后其回复会
//! 被回复道校验当作原属主接受，正是票 05 要挡的劫持形态）。

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

/// 插件互调 api 注册表：api 全限定名 → 声明它的插件 ID
pub struct ApiRegistry {
    apis: RwLock<HashMap<String, String>>,
}

impl Default for ApiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiRegistry {
    pub fn new() -> Self {
        Self {
            apis: RwLock::new(HashMap::new()),
        }
    }

    /// 登记插件声明的 api 清单（激活时调用；重复登记幂等）
    ///
    /// **fail-closed**：api 已被**其它**插件声明 → 返回 Err（拒绝登记，骂名
    /// 由激活路径显性升级为激活失败）；同一插件重复登记幂等（激活→停用→再激活
    /// 依赖幂等）。先全量校验后一次性写入——清单中任一 api 冲突即整体拒绝，
    /// 不留「前半已写入、后半失败」的半途状态。
    ///
    /// 同步锁：临界区仅 map 操作（无 await），wasm host 调用栈内
    /// （bus_publish 门禁）与异步激活路径均可用
    pub fn register(&self, plugin_id: &str, apis: &[String]) -> crate::Result<()> {
        let mut map = self.apis.write().unwrap_or_else(recover_poison);
        for api in apis {
            if let Some(existing) = map.get(api) {
                if existing != plugin_id {
                    return Err(crate::AppError::Plugin(format!(
                        "api '{api}' is already declared by plugin '{existing}'"
                    )));
                }
            }
        }
        for api in apis {
            map.insert(api.clone(), plugin_id.to_string());
        }
        Ok(())
    }

    /// 注销插件的全部 api（停用时调用；未登记过则幂等无操作）
    pub fn unregister(&self, plugin_id: &str) {
        let mut map = self.apis.write().unwrap_or_else(recover_poison);
        map.retain(|_, owner| owner != plugin_id);
    }

    /// 目标 api 是否已被某激活插件声明（门禁判定）
    pub fn contains(&self, api: &str) -> bool {
        let map = self.apis.read().unwrap_or_else(recover_poison);
        map.contains_key(api)
    }

    /// 声明该 api 的插件 ID（票 05 回复道 sender 校验依据）
    ///
    /// 与 [`Self::contains`] 同表同语义：未登记（未声明 / 已停用注销）→ `None`。
    pub fn owner_of(&self, api: &str) -> Option<String> {
        let map = self.apis.read().unwrap_or_else(recover_poison);
        map.get(api).cloned()
    }

    /// 单读锁内返回「api 是否存在 + 声明属主」——门禁与属主解析不跨锁漂移
    ///
    /// `None` = 未登记（门禁拒绝）或原属主已注销。调用方一次取回判定与属主，
    /// 替代「[`Self::contains`] → [`Self::owner_of`]」两次独立加锁（两次加锁间
    /// register/unregister 可插缝 → 门禁放行但属主解析不一致）。
    pub fn gate(&self, api: &str) -> Option<String> {
        let map = self.apis.read().unwrap_or_else(recover_poison);
        map.get(api).cloned()
    }

    /// 已登记的 api 清单（诊断/测试用）
    pub fn list_apis(&self) -> Vec<String> {
        let map = self.apis.read().unwrap_or_else(recover_poison);
        map.keys().cloned().collect()
    }

    /// 登记项数（诊断/测试用）
    pub fn len(&self) -> usize {
        let map = self.apis.read().unwrap_or_else(recover_poison);
        map.len()
    }

    /// 注册表是否为空（clippy 配对建议）
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 锁中毒恢复：返回内部值前记录事件（防破坏的注册表被静默当有效用）
///
/// 仅发生在写锁临界区内 panic（register/unregister 的用户数据不变量破坏）；
/// 记录后其余调用至少能观察到一次 warn 日志，而非毫无痕迹地继续。
/// 真正的 poison 场景罕见且无更好的恢复选项（fail-closed 传播 poison 会
/// 让所有后续登记/解析在插件仍激活的情况下全部失败——更糟）。
fn recover_poison<T>(e: PoisonError<T>) -> T {
    tracing::warn!(error = %e, "ApiRegistry lock poisoned, recovering");
    e.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 登记后可命中；未登记的 api 不命中（门禁核心判定）
    #[test]
    fn contains_after_register() {
        let reg = ApiRegistry::new();
        assert!(!reg.contains("com.wasmnest.scheduler.add"));
        reg.register(
            "com.wasmnest.scheduler",
            &["com.wasmnest.scheduler.add".to_string()],
        )
        .unwrap();
        assert!(reg.contains("com.wasmnest.scheduler.add"));
        assert!(!reg.contains("com.wasmnest.scheduler.none"));
    }

    /// 停用注销后目标不可调（「未激活插件目标调用被拒」验收）
    #[test]
    fn unregister_removes_plugin_apis() {
        let reg = ApiRegistry::new();
        reg.register(
            "com.wasmnest.scheduler",
            &[
                "com.wasmnest.scheduler.add".to_string(),
                "com.wasmnest.scheduler.list".to_string(),
            ],
        )
        .unwrap();
        reg.register(
            "com.wasmnest.other",
            &["com.wasmnest.other.ping".to_string()],
        )
        .unwrap();
        reg.unregister("com.wasmnest.scheduler");
        assert!(!reg.contains("com.wasmnest.scheduler.add"));
        // 其他插件的 api 不受影响
        assert!(reg.contains("com.wasmnest.other.ping"));
        assert_eq!(reg.len(), 1);
    }

    /// 重复登记幂等；**他插件抢占同名 api 被拒（fail-closed，S-01）**
    ///
    /// 变异判据：把 register 改回「后登记覆盖」⇒ 本测试转红（劫持者
    /// 回复会被回复道校验当原属主接受，正是要挡的形态）。
    #[test]
    fn register_idempotent_and_rejects_cross_plugin_conflict() {
        let reg = ApiRegistry::new();
        reg.register("p1", &["a.x".to_string()]).unwrap();
        reg.register("p1", &["a.x".to_string()]).unwrap();
        assert_eq!(reg.len(), 1);

        // 另一插件声明同名 api：必须拒绝，且错误点名两侧，原登记不受影响
        let err = reg
            .register("p2", &["a.x".to_string()])
            .expect_err("跨插件冲突必须被拒");
        assert!(
            format!("{err}").contains("a.x") && format!("{err}").contains("p1"),
            "错误须点名冲突 api 与原属主: {err}"
        );
        assert!(reg.contains("a.x"));
        assert_eq!(
            reg.owner_of("a.x").as_deref(),
            Some("p1"),
            "原属主登记不得被覆盖"
        );

        reg.unregister("p1");
        assert!(!reg.contains("a.x"));
        // p1 注销后 p2 才可声明（无冲突 → 正常登记）
        reg.register("p2", &["a.x".to_string()]).unwrap();
        assert_eq!(reg.owner_of("a.x").as_deref(), Some("p2"));
    }

    /// 门禁 + 属主解析单锁合一（S-05）：`gate` 与 `owner_of` 同表同语义，
    /// 未命中返回 None（门禁拒绝与属主取不到不会漂移）
    #[test]
    fn gate_combines_existence_and_owner_in_one_read() {
        let reg = ApiRegistry::new();
        assert_eq!(reg.gate("a.x"), None, "未登记：门禁拒绝且无属主");
        reg.register("p1", &["a.x".to_string()]).unwrap();
        assert_eq!(reg.gate("a.x").as_deref(), Some("p1"));
        reg.unregister("p1");
        assert_eq!(reg.gate("a.x"), None, "注销后两者同时失效");
        // 与 owner_of / contains 完全同源
        assert_eq!(reg.gate("a.x"), reg.owner_of("a.x"));
        assert_eq!(reg.gate("a.x").is_some(), reg.contains("a.x"));
    }

    /// 空清单登记 / 未登记插件注销：幂等无操作
    #[test]
    fn empty_register_and_unknown_unregister_noop() {
        let reg = ApiRegistry::new();
        reg.register("p1", &[]).unwrap();
        reg.unregister("ghost");
        assert_eq!(reg.len(), 0);
    }

    /// `owner_of` 与 `contains` 同表同语义：命中返回声明方，未命中返回 None
    /// （票 05 回复道 sender 校验依据——门禁放行与属主解析不得漂移）
    #[test]
    fn owner_of_matches_contains_semantics() {
        let reg = ApiRegistry::new();
        reg.register(
            "com.wasmnest.bedcode",
            &["com.wasmnest.bedcode.pair".to_string()],
        )
        .unwrap();
        assert_eq!(
            reg.owner_of("com.wasmnest.bedcode.pair").as_deref(),
            Some("com.wasmnest.bedcode")
        );
        assert_eq!(reg.owner_of("com.wasmnest.bedcode.nope"), None);
        // 注销后两者同时失效
        reg.unregister("com.wasmnest.bedcode");
        assert_eq!(reg.owner_of("com.wasmnest.bedcode.pair"), None);
        assert!(!reg.contains("com.wasmnest.bedcode.pair"));
    }

    /// 同名 api 被**拒绝**抢占：属主解析保持首个声明方（S-01 fail-closed）
    #[test]
    fn owner_of_keeps_first_declarer_when_conflict_rejected() {
        let reg = ApiRegistry::new();
        reg.register("p1", &["shared.api".to_string()]).unwrap();
        assert!(
            reg.register("p2", &["shared.api".to_string()]).is_err(),
            "冲突登记必须失败"
        );
        assert_eq!(
            reg.owner_of("shared.api").as_deref(),
            Some("p1"),
            "属主必须是首个声明方"
        );
    }
}
