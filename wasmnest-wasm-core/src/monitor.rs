//! 监控模块（core-monitor）
//!
//! 内核运行时指标埋点与观测：
//! - 每插件 Store 线性内存当前值/峰值（记账挂在 ResourceLimiter 增长回调）
//! - 导出调用聚合：次数 / 燃料消耗总量 / 耗时分布（直方图桶）
//! - 插件生命周期事件计数（实例化/激活成功/激活失败/停用/trap/降级）+ 最近发生时间
//! - 快照导出：一次调用拿全量 JSON（前端诊断页、CLI、未来 sink 扩展的统一数据源）
//!
//! 红线：热路径埋点为纯原子操作，零日志（日志级别语义见 AGENTS.md §8）；
//! 指标标签只用 `plugin_id` 等结构化维度，禁止拼消息字符串。
//!
//! 可扩展性：所有写入收敛于 [`MetricsRegistry::plugin`] 返回的 [`PluginMetrics`]
//! 句柄，未来新增指标只需在 [`PluginMetrics`] 加字段；系统维度段经
//! [`MetricsRegistry::register_source`] 注册 [`MetricsSource`] 自供给（如 host-task
//! 的 `task` 段），monitor 不内联依赖兄弟模块；sink 扩展点（文件/远程上报）以
//! 消费 [`MetricsRegistry::snapshot`] 的方式接入，不改埋点侧。

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ==================== 迁往机制内核的类型（转发） ====================
//
// `wasmnest-host-kit` 持有本模块的**值对象层**（单插件原子计数器 + 生命周期/授权
// 维度枚举 + 计时器 + 快照形状），本模块只留**注册表与诊断面**（`MetricsRegistry` /
// `MetricsSource` / JSON 拼装）。拆的理由：值对象是 `WasmPluginState` 的字段类型，
// 机制内核不依赖宿主，就必须能命名它们（能力域脱绑，见 2026-10-07 拆分系）。
//
// 可见性以 `pub use` 原样转发，既有 `monitor::PluginMetrics` 等引用路径逐字不变。
pub use wasmnest_host_kit::metrics::{
    AuthzDecisionKind, CallTimer, LifecycleEvent, PluginMetrics, PluginMetricsSnapshot, TrapKind,
};

// ==================== 快照出口端口（WIT `host-metrics` 的宿主侧句柄） ====================

/// 指标快照源（宿主装配面注入；内核不反向依赖宿主持有方式）
///
/// 由 `WasmRuntime` 在装配期把 [`MetricsRegistry`] 写进 `WasmHostContext` 的槽位，
/// WIT `host-metrics.snapshot` 只经本 trait 取字符串——内核绑定层不认识「谁持有
/// 注册表」，移动 / 桌面 / 无头三种装配同一条路径。
///
/// 未装配时返回 `Err`（fail-visible）：不返回 `{}` 冒充「没有插件」，
/// 否则监控应用会把断链显示成「一切正常」。
pub trait MetricsSnapshotSource: Send + Sync {
    /// 全量快照 JSON（形状同 [`MetricsRegistry::snapshot`]）
    fn snapshot_json(&self) -> Result<String, String>;
}

impl MetricsSnapshotSource for MetricsRegistry {
    fn snapshot_json(&self) -> Result<String, String> {
        serde_json::to_string(&self.snapshot())
            .map_err(|e| format!("metrics snapshot serialization failed: {e}"))
    }
}

// ==================== 系统维度快照源（注册制） ====================

/// 系统维度指标快照源（去环：Observer + Registry 模式）
///
/// monitor 不主动 import 兄弟模块——各维度数据属主（如 host-task 的 `task` 段）
/// 实现本 trait，并在 runtime 初始化时经 [`MetricsRegistry::register_source`]
/// 自注册；全量快照通过 trait 对象回调合并输出。注册名即快照输出段名，
/// 重复注册覆盖不叠加（注册点幂等）。
pub trait MetricsSource: Send + Sync {
    /// 本维度快照（JSON；键名 camelCase，沿既有 JSON 惯例由属主自定）
    fn snapshot(&self) -> serde_json::Value;
}

// ==================== 指标注册表 ====================

/// 指标注册表（内核级共享，线程安全）
///
/// 经 [`crate::manager::runtime::WasmRuntime::monitor`] 获取；
/// 所有埋点方（limiter / 导出调用 / 生命周期）先取插件句柄再记账
pub struct MetricsRegistry {
    /// plugin_id → 指标集
    plugins: RwLock<HashMap<String, Arc<PluginMetrics>>>,
    /// 系统维度快照源（键 = 快照输出段名，如 `task`；注册制注入，见 [`MetricsSource`]）
    sources: RwLock<HashMap<String, Arc<dyn MetricsSource>>>,
    /// 插件元数据（name / kind / state 等只读展示字段；宿主在装载 / 状态变更时写入）。
    /// 与指标分开：指标是热路径原子计数，元数据是低频结构化事实，不参与记账。
    plugin_meta: RwLock<HashMap<String, serde_json::Value>>,
}

/// 锁中毒恢复：记录事件后继续（指标是对外观测面，锁中毒不应让整个监控面
/// 永久 panic；R-17——恢复的代价是可能丢一笔计数，比全入口崩溃可接受）
fn recovered<T>(e: std::sync::PoisonError<T>, what: &'static str) -> T {
    tracing::warn!(what, "MetricsRegistry lock poisoned, recovering");
    e.into_inner()
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            sources: RwLock::new(HashMap::new()),
            plugin_meta: RwLock::new(HashMap::new()),
        }
    }

    /// 注册系统维度快照源（幂等：同名重复注册覆盖不叠加）
    ///
    /// `plugins` 是快照的**保留段名**（插件维度指标），用户源不得占用——
    /// 否则注册名 `"plugins"` 的源会静默覆盖/碰撞插件维度段（R-18）。
    /// 保留名注册被拒绝（error 日志 + 跳过注册）：快照里该段缺失本身就是
    /// fail-visible 信号。
    pub fn register_source(&self, name: &str, source: Box<dyn MetricsSource>) {
        if name == "plugins" {
            tracing::error!(
                name = %name,
                "MetricsRegistry: 快照段名 'plugins' 是插件维度保留段，拒绝注册（R-18）"
            );
            return;
        }
        self.sources
            .write()
            .unwrap_or_else(|e| recovered(e, "sources"))
            .insert(name.to_string(), Arc::from(source));
    }

    /// 获取（或创建）插件指标句柄
    pub fn plugin(&self, plugin_id: &str) -> Arc<PluginMetrics> {
        // 快路径：读锁命中
        if let Some(m) = self
            .plugins
            .read()
            .unwrap_or_else(|e| recovered(e, "plugins"))
            .get(plugin_id)
        {
            return m.clone();
        }
        let mut map = self
            .plugins
            .write()
            .unwrap_or_else(|e| recovered(e, "plugins"));
        map.entry(plugin_id.to_string())
            .or_insert_with(|| Arc::new(PluginMetrics::default()))
            .clone()
    }

    /// 移除插件指标句柄（卸载路径调用）
    ///
    /// 注册表必须与「已加载插件集合」一致：卸载后残留的旧计数会以状态未知的
    /// 幽灵卡形式出现在监控快照里，直到宿主重启。重装 / 停机重载**不**走这里
    /// ——它们的累计计数应延续，只有卸载意味着插件生命周期真正结束。
    ///
    /// 返回是否命中；已取出的 `Arc<PluginMetrics>` 句柄仍可记账，但不再进入快照。
    pub fn remove(&self, plugin_id: &str) -> bool {
        let removed = self
            .plugins
            .write()
            .unwrap_or_else(|e| recovered(e, "plugins"))
            .remove(plugin_id)
            .is_some();
        self.plugin_meta
            .write()
            .unwrap_or_else(|e| recovered(e, "plugin_meta"))
            .remove(plugin_id);
        removed
    }

    /// 写入 / 覆盖插件元数据（name / kind / state 等只读展示字段）。
    ///
    /// 宿主在装载、激活状态变更时调用；不属于指标热路径。快照中以
    /// `plugin_meta.<plugin_id>` 输出，移动端 monitor 用它做服务 / 应用分类，
    /// 避免为分类新增 WIT 原语或要求目标插件参与。
    pub fn set_plugin_meta(&self, plugin_id: &str, meta: serde_json::Value) {
        self.plugin_meta
            .write()
            .unwrap_or_else(|e| recovered(e, "plugin_meta"))
            .insert(plugin_id.to_string(), meta);
    }

    /// 全量快照（JSON）：`{ "plugins": { "<plugin_id>": { ... } }, <source_name>: { ... }, ... }`
    ///
    /// `plugins` 段为插件维度指标；其余段来自已注册的 [`MetricsSource`]。
    /// host-task 的 `task` 段由 `manager::task` 经 [`Self::register_source`] 注册，
    /// 内容见 [`crate::manager::task::task_metrics_snapshot`]：任务提交/拒绝
    /// 计数、单元完成累计、并发高水位、回调丢弃计数——各段均纯原子
    /// 记账、快照导出是唯一消费口。未注册段在快照中缺失而非 panic（确定性降级，
    /// fail-visible；生产路径 runtime 初始化即注册，无此窗口）。
    ///
    /// **用户回调不持锁**（R-07）：`MetricsSource::snapshot()` 是任意实现（可能回捣
    /// 注册表取插件句柄 → 写锁请求）；在短锁内先收集源列表、释放两把读锁后再逐个
    /// 调用，杜绝「快照持读锁 → 源回调请求写锁 → 自锁/饥饿」。
    pub fn snapshot(&self) -> serde_json::Value {
        let plugins: serde_json::Map<String, serde_json::Value> = {
            let map = self
                .plugins
                .read()
                .unwrap_or_else(|e| recovered(e, "plugins"));
            map.iter()
                .map(|(id, m)| {
                    (
                        id.clone(),
                        serde_json::to_value(m.snapshot()).unwrap_or(serde_json::Value::Null),
                    )
                })
                .collect()
        };
        let mut out = serde_json::Map::new();
        out.insert("plugins".to_string(), serde_json::Value::Object(plugins));
        // 插件元数据段（可选；没有写入时保持旧快照形状，旧消费方零迁移）
        let meta: serde_json::Map<String, serde_json::Value> = {
            let map = self
                .plugin_meta
                .read()
                .unwrap_or_else(|e| recovered(e, "plugin_meta"));
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        if !meta.is_empty() {
            out.insert("plugin_meta".to_string(), serde_json::Value::Object(meta));
        }
        // 短锁收集源（Arc 克隆），锁外调用用户回调
        let sources: Vec<(String, Arc<dyn MetricsSource>)> = {
            let s = self
                .sources
                .read()
                .unwrap_or_else(|e| recovered(e, "sources"));
            s.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (name, source) in sources {
            out.insert(name, source.snapshot());
        }
        serde_json::Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_get_or_create_is_idempotent_per_plugin() {
        let reg = MetricsRegistry::new();
        let a1 = reg.plugin("com.wasmnest.a");
        let a2 = reg.plugin("com.wasmnest.a");
        let b = reg.plugin("com.wasmnest.b");
        assert!(Arc::ptr_eq(&a1, &a2), "同插件必须返回同一句柄");
        assert!(!Arc::ptr_eq(&a1, &b));
    }

    /// 卸载清理：移除后快照不再包含该插件，其他插件不受影响；重装从零开始
    #[test]
    fn remove_plugin_drops_only_its_snapshot_entry() {
        let reg = MetricsRegistry::new();
        reg.plugin("com.wasmnest.a")
            .record_lifecycle(LifecycleEvent::Instantiate);
        reg.plugin("com.wasmnest.b")
            .record_lifecycle(LifecycleEvent::Instantiate);

        assert!(reg.remove("com.wasmnest.a"));
        let snap = reg.snapshot();
        assert!(
            snap["plugins"].get("com.wasmnest.a").is_none(),
            "卸载后旧指标不得继续出现在快照里: {snap}"
        );
        assert_eq!(
            snap["plugins"]["com.wasmnest.b"]["lifecycle"]["instantiate"],
            1
        );

        assert!(!reg.remove("com.wasmnest.a"), "重复移除是无害 no-op");
        assert_eq!(
            reg.plugin("com.wasmnest.a").snapshot().lifecycle["instantiate"],
            0,
            "重装同 id 必须从零计数，不继承卸载前指标"
        );
    }

    #[test]
    fn plugin_meta_is_exposed_and_cleared_on_remove() {
        let reg = MetricsRegistry::new();
        reg.plugin("com.wasmnest.monitor");
        reg.set_plugin_meta(
            "com.wasmnest.monitor",
            serde_json::json!({ "name": "Monitor", "kind": "internal-business" }),
        );
        let snap = reg.snapshot();
        assert_eq!(
            snap["plugin_meta"]["com.wasmnest.monitor"]["kind"],
            "internal-business"
        );

        reg.remove("com.wasmnest.monitor");
        let snap = reg.snapshot();
        assert!(
            snap.get("plugin_meta").is_none(),
            "卸载后元数据不得以幽灵条目残留: {snap}"
        );
    }

    #[test]
    fn memory_growth_tracks_current_and_peak() {
        let m = PluginMetrics::default();
        m.record_memory_growth(1024);
        m.record_memory_growth(4096);
        m.record_memory_growth(2048); // 回落不动峰值
        let snap = m.snapshot();
        assert_eq!(snap.memory_current_bytes, 2048);
        assert_eq!(snap.memory_peak_bytes, 4096);
    }

    #[test]
    fn call_aggregation_counts_fuel_and_duration() {
        let m = Arc::new(PluginMetrics::default());
        for _ in 0..3 {
            let _t = m.start_call();
            m.record_fuel_consumed(100);
        } // 3 次调用在此落账（drop 计时）
        m.record_fuel_consumed(50);
        let snap = m.snapshot();
        assert_eq!(snap.calls_total, 3);
        assert_eq!(snap.fuel_consumed_total, 350);
        assert_eq!(
            snap.call_duration_buckets.iter().sum::<u64>(),
            3,
            "直方图桶计数必须等于调用数"
        );
    }

    #[test]
    fn duration_histogram_bucket_boundaries() {
        let m = PluginMetrics::default();
        m.record_call_duration(500); // < 1ms → 桶 0
        m.record_call_duration(1_000); // ≥ 1ms → 桶 1
        m.record_call_duration(20_000_000); // ≥ 10s → 最后桶
        let snap = m.snapshot();
        assert_eq!(snap.call_duration_buckets[0], 1);
        assert_eq!(snap.call_duration_buckets[1], 1);
        assert_eq!(snap.call_duration_buckets[5], 1);
        assert_eq!(snap.call_duration_us_max, 20_000_000);
    }

    /// 授权决策计数：三类决策分别落到 authz.allow / deny / require_approval，
    /// 累加正确且互不串位（core-security 管线的唯一埋点入口）
    #[test]
    fn authz_decisions_counted_by_kind() {
        let m = PluginMetrics::default();
        m.record_authz_decision(AuthzDecisionKind::Allow);
        m.record_authz_decision(AuthzDecisionKind::Allow);
        m.record_authz_decision(AuthzDecisionKind::Deny);
        m.record_authz_decision(AuthzDecisionKind::RequireApproval);
        m.record_authz_decision(AuthzDecisionKind::RequireApproval);
        m.record_authz_decision(AuthzDecisionKind::RequireApproval);
        let snap = m.snapshot();
        assert_eq!(snap.authz["allow"], 2);
        assert_eq!(
            snap.authz["deny"], 1,
            "deny 不得记入 allow/require_approval 桶"
        );
        assert_eq!(snap.authz["require_approval"], 3);
    }

    /// 授权记录容量丢弃计数与决策计数互不串台
    ///
    /// 变异判据：把 `record_authz_record_dropped` 记到 `authz` 段的某个槽位，
    /// 本条的 allow 计数或 dropped 计数必有一侧转红。
    #[test]
    fn authz_record_drops_counted_separately_from_decisions() {
        let m = PluginMetrics::default();
        m.record_authz_decision(AuthzDecisionKind::Allow);
        m.record_authz_record_dropped();
        m.record_authz_record_dropped();
        let snap = m.snapshot();
        assert_eq!(snap.authz["records_dropped"], 2, "丢弃必须有自己的桶");
        assert_eq!(snap.authz["allow"], 1, "丢弃不得计入放行决策");
        assert_eq!(snap.authz["deny"], 0);
        assert_eq!(snap.authz["require_approval"], 0);
    }

    /// 总线计数：队列满丢弃与格式不匹配拒绝分别累计，互不影响
    /// （背压/格式过滤的监控落点）
    #[test]
    fn bus_dropped_and_format_rejected_counted_separately() {
        let m = PluginMetrics::default();
        m.record_bus_dropped();
        m.record_bus_dropped();
        m.record_bus_format_rejected();
        let snap = m.snapshot();
        assert_eq!(snap.bus["dropped"], 2);
        assert_eq!(snap.bus["format_rejected"], 1, "格式拒绝不得计入 dropped");
    }

    #[test]
    fn lifecycle_counts_and_last_timestamp() {
        let m = PluginMetrics::default();
        m.record_lifecycle(LifecycleEvent::Instantiate);
        m.record_lifecycle(LifecycleEvent::ActivateOk);
        m.record_lifecycle(LifecycleEvent::Trap);
        m.record_lifecycle(LifecycleEvent::Trap);
        let snap = m.snapshot();
        assert_eq!(snap.lifecycle["instantiate"], 1);
        assert_eq!(snap.lifecycle["activate_ok"], 1);
        assert_eq!(snap.lifecycle["trap"], 2);
        assert_eq!(snap.lifecycle["deactivate"], 0);
        assert!(
            snap.lifecycle_last_unix.contains_key("trap"),
            "发生过的事件须有最近时间戳"
        );
        assert!(
            !snap.lifecycle_last_unix.contains_key("deactivate"),
            "未发生的事件不出现时间戳"
        );
    }

    #[test]
    fn snapshot_shape_is_stable_json_with_plugin_dimension() {
        let reg = MetricsRegistry::new();
        reg.plugin("com.wasmnest.a")
            .record_lifecycle(LifecycleEvent::Instantiate);
        let snap = reg.snapshot();
        let plugin = &snap["plugins"]["com.wasmnest.a"];
        assert!(plugin.is_object(), "快照必须按 plugin_id 维度组织: {snap}");
        for key in [
            "memory_current_bytes",
            "memory_peak_bytes",
            "calls_total",
            "calls_in_flight",
            "fuel_consumed_total",
            "call_duration_us_total",
            "call_duration_us_max",
            "call_duration_buckets",
            "lifecycle",
            "lifecycle_last_unix",
            "trap_reasons",
            "memory_grow_denied_total",
            "table_grow_denied_total",
            "activation_us_total",
            "activation_us_max",
            "quota",
            "authz",
            "bus",
        ] {
            assert!(plugin.get(key).is_some(), "快照缺字段 {key}");
        }
        assert_eq!(plugin["lifecycle"]["instantiate"], 1);
    }

    /// 全量快照顶层结构逐字节对照（行为零变化锁）：
    /// `{"plugins":…,"task":…}` 两段与字段形状与旧内联实现一致
    /// （serde_json Map 无 preserve_order，键字母序 plugins < task）。
    /// task 段枚举字段沿用 host-task 既有 camelCase 键名。
    #[test]
    fn snapshot_byte_shape_matches_legacy_plugins_plus_task_layout() {
        struct FixedTask;
        impl MetricsSource for FixedTask {
            fn snapshot(&self) -> serde_json::Value {
                serde_json::json!({
                    "jobsSubmittedTotal": 0,
                    "jobsRejectedTotal": 0,
                    "unitsCompletedTotal": 0,
                    "concurrentUnitsPeak": 0,
                    "eventsDroppedTotal": 0,
                })
            }
        }
        let reg = MetricsRegistry::new();
        reg.register_source("task", Box::new(FixedTask));
        assert_eq!(
            reg.snapshot().to_string(),
            r#"{"plugins":{},"task":{"concurrentUnitsPeak":0,"eventsDroppedTotal":0,"jobsRejectedTotal":0,"jobsSubmittedTotal":0,"unitsCompletedTotal":0}}"#
        );
    }

    /// 系统维度快照源并入全量快照：plugins 段与 task 段并存互不影响
    #[test]
    fn snapshot_merges_registered_system_sources() {
        struct FakeTask;
        impl MetricsSource for FakeTask {
            fn snapshot(&self) -> serde_json::Value {
                serde_json::json!({"jobsSubmittedTotal": 7})
            }
        }
        let reg = MetricsRegistry::new();
        reg.plugin("com.wasmnest.a")
            .record_lifecycle(LifecycleEvent::Instantiate);
        reg.register_source("task", Box::new(FakeTask));
        let snap = reg.snapshot();
        assert_eq!(
            snap["plugins"]["com.wasmnest.a"]["lifecycle"]["instantiate"],
            1
        );
        assert_eq!(snap["task"]["jobsSubmittedTotal"], 7);
    }

    /// 注册点幂等：同名重复注册覆盖不叠加（重注册后快照只反映新源）
    #[test]
    fn register_source_overwrites_on_duplicate_name() {
        struct SourceV1;
        impl MetricsSource for SourceV1 {
            fn snapshot(&self) -> serde_json::Value {
                serde_json::json!({"v": 1})
            }
        }
        struct SourceV2;
        impl MetricsSource for SourceV2 {
            fn snapshot(&self) -> serde_json::Value {
                serde_json::json!({"v": 2})
            }
        }
        let reg = MetricsRegistry::new();
        reg.register_source("task", Box::new(SourceV1));
        reg.register_source("task", Box::new(SourceV2));
        assert_eq!(reg.snapshot()["task"]["v"], 2, "重复注册必须覆盖，不得叠加");
    }

    /// 未注册段确定性降级：快照不 panic、该段缺失（fail-visible）。
    /// 生产路径 runtime 初始化即注册 task 源，无此窗口；仅裸 registry
    /// 单测路径可观测。
    #[test]
    fn unregistered_source_segment_absent_without_panic() {
        let reg = MetricsRegistry::new();
        let snap = reg.snapshot();
        assert!(snap.get("plugins").is_some());
        assert!(snap.get("task").is_none(), "未注册段缺失而非 panic");
    }

    /// R-18：`plugins` 是快照保留段名，用户源不得占用——保留名注册被拒绝，
    /// 插件维度段不被静默覆盖/碰撞。变异判据：register_source 放行保留名 ⇒ 转红。
    #[test]
    fn reserved_plugins_segment_name_rejected_for_user_sources() {
        struct Sneaky;
        impl MetricsSource for Sneaky {
            fn snapshot(&self) -> serde_json::Value {
                serde_json::json!({ "hijacked": true })
            }
        }
        let reg = MetricsRegistry::new();
        reg.register_source("plugins", Box::new(Sneaky));
        let snap = reg.snapshot();
        assert!(
            !snap["plugins"].get("hijacked").is_some(),
            "保留段不得被用户源劫持: {snap}"
        );
        // 正常段名仍可注册
        reg.register_source("custom", Box::new(Sneaky));
        assert!(reg.snapshot()["custom"]["hijacked"].as_bool().is_some());
    }

    /// R-07：用户 `MetricsSource::snapshot()` 回捣注册表（取插件句柄 → 写锁）
    /// 不得死锁——快照先释放两把读锁再调用户回调。
    #[test]
    fn user_source_reentry_into_registry_does_not_deadlock() {
        struct Reentrant {
            reg: std::sync::Arc<MetricsRegistry>,
        }
        impl MetricsSource for Reentrant {
            fn snapshot(&self) -> serde_json::Value {
                // 回捣：取插件句柄并记账（需要写锁路径）——持读锁期间调用即死锁
                self.reg
                    .plugin("com.wasmnest.reentrant")
                    .record_memory_growth(8);
                serde_json::json!({ "ok": true })
            }
        }
        let reg = std::sync::Arc::new(MetricsRegistry::new());
        reg.register_source("reentrant", Box::new(Reentrant { reg: reg.clone() }));
        // 快照正常返回（修复前：持读锁调源回调 → 回调请求写锁 → 自锁）
        let snap = reg.snapshot();
        assert_eq!(snap["reentrant"]["ok"], serde_json::json!(true));
        // 回调的记账确实落盘（回调发生在 plugins 段构建之后，故第二次快照才可见）
        assert_eq!(
            reg.plugin("com.wasmnest.reentrant")
                .snapshot()
                .memory_current_bytes,
            8
        );
        assert_eq!(
            reg.snapshot()["plugins"]["com.wasmnest.reentrant"]["memory_current_bytes"],
            8,
            "回捣记账应进入插件维度段"
        );
    }

    /// R-16：current 与 peak 同序观察自洽——回落分配后读到的 current 不大于 peak
    #[test]
    fn memory_current_never_exceeds_peak_in_snapshot() {
        let m = PluginMetrics::default();
        m.record_memory_growth(4096);
        m.record_memory_growth(1024); // 回落
        let snap = m.snapshot();
        assert!(snap.memory_current_bytes <= snap.memory_peak_bytes);
        assert_eq!(snap.memory_peak_bytes, 4096);
    }
}
