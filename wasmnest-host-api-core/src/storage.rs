//! `host-storage` 实现层（插件键值存储，3 条原语，按 `plugin_id` 隔离）
//!
//! 自桌面 `packages/wasmnest-wasm-core/src/host_api/storage.rs` 上移（票 18 批次 1），
//! 机制语义逐字保留：**权限门 → 系统空间纵深守卫 → 能力路由（转发命中短路宿主原语）
//! → 宿主键值原语**。各端 adapter 把本端宿主服务接到 [`StoragePorts`] 上：
//!
//! - 桌面：`SqlitePorts` adapter（`host_api/storage.rs`，权限判定走 PermissionManager）；
//! - 移动：`WasmPluginState` adapter（`manager/runtime/host_impl/storage.rs`，权限判定
//!   走 `granted_permissions` 集，异步存储经 `block_in_place` 驱动）。
//!
//! ## 真源说明
//!
//! [`SYSTEM_PLUGIN_ID`] 真源随实现层上移到本模块（原双端各持一份，票 18 起单点）；
//! 双端 `storage.rs` 经再导出保既有路径（`crate::storage::SYSTEM_PLUGIN_ID` 照旧可用，
//! 激活状态写入方不感知迁移）。
//!
//! ## 错误文本纪律
//!
//! guest 可见的错误文本**逐字保留**（trap 文本是既有行为面）：权限拒绝文案经
//! [`PermissionGate::deny_error`] 由各端传入（桌面 `"permission denied"` / 移动
//! `"permission denied: storage"`——历史双份，强行统一属行为变更，走独立裁决）；
//! 键值原语失败统一包 `storage error: {e}`；系统空间守卫与转发路径的文案是机制
//! 语义，双端同文。

use serde_json::Value;

/// 系统级 `plugin_id`：非插件私有的全局数据命名空间
///
/// 插件键值存储按 `plugin_id` 分区，系统空间（宿主激活状态、审批记录等真源所在）
/// 与插件空间天然隔离；插件面原语对它 fail-closed（[`ensure_not_system_space`]，
/// R-02 纵深防御）。
pub const SYSTEM_PLUGIN_ID: &str = "__system__";

/// 权限门入参（批次 2 起提升为独立 `gate` 模块，storage / bus 两域共用）
pub use crate::gate::PermissionGate;

/// 宿主服务端口（实现层只认端口，不认任何一端的宿主类型）
///
/// dyn 兼容：域函数收 `&dyn StoragePorts`，实现方 = 各端 adapter；实现应当轻——
/// 每条原语调用都要经它。
pub trait StoragePorts: Send + Sync {
    /// 权限判定。返回 `false` 时**实现方**必须已按 AGENTS §8 落拒绝 warn（结构化
    /// 字段 `plugin_id` / `permission` / `api`），本层不重复落日志；无权限管理器的
    /// 上下文（无头 / 测试）必须返回 `false`（fail-safe）。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 键值读（`plugin_storage` 表，按 `plugin_id` 隔离），值取 serde_json 规范形
    fn kv_get(&self, plugin_id: &str, key: &str) -> Result<Option<Value>, String>;

    /// 键值写（upsert）
    fn kv_set(&self, plugin_id: &str, key: &str, value: Value) -> Result<(), String>;

    /// 键值删（幂等）
    fn kv_delete(&self, plugin_id: &str, key: &str) -> Result<(), String>;

    // ==================== 能力路由（桌面 core-plugin-manager 独有） ====================

    /// `host-storage.get` 转给系统组件提供者；无提供者返回 `None`（= 走宿主原语，
    /// `None` 不是错误）。移动端无能力路由，走默认实现。
    fn forward_kv_get(&self, _plugin_id: &str, _key: &str) -> Option<Result<Option<String>, String>> {
        None
    }

    /// `host-storage.set` 转发（语义同 [`StoragePorts::forward_kv_get`]）
    fn forward_kv_set(&self, _plugin_id: &str, _key: &str, _value: &str) -> Option<Result<(), String>> {
        None
    }

    /// `host-storage.delete` 转发（语义同 [`StoragePorts::forward_kv_get`]）
    fn forward_kv_delete(&self, _plugin_id: &str, _key: &str) -> Option<Result<(), String>> {
        None
    }
}

/// 插件面存储原语的系统空间守卫（R-02 纵深防御）
///
/// 插件实例的 `plugin_id` 由运行时从已认证身份派生，guest 无法伪造；但若真出现
/// `__system__`（实施者 bug / 未来某条宽松入径），必须 fail-closed——系统空间是
/// 宿主激活状态 / 审批记录等的真源，任何插件写它就是越权。
fn ensure_not_system_space(plugin_id: &str) -> Result<(), String> {
    if plugin_id == SYSTEM_PLUGIN_ID {
        return Err("storage: plugin may not access system storage space".to_string());
    }
    Ok(())
}

/// 获取值（权限门 → 系统空间守卫 → 能力路由 → 键值原语）
pub fn storage_get(
    ports: &dyn StoragePorts,
    plugin_id: &str,
    key: &str,
    gate: &PermissionGate<'_>,
) -> Result<Option<Value>, String> {
    if !ports.check_permission(plugin_id, gate.permission, gate.api) {
        return Err(gate.deny_error.to_string());
    }
    ensure_not_system_space(plugin_id)?;
    // 能力路由：系统组件提供者命中时转发（组件间不共享内存，WIT 边界序列化）；
    // 非 JSON 存量串降级为字符串值（既有语义，桌面 FakePorts 用例钉住）
    if let Some(result) = ports.forward_kv_get(plugin_id, key) {
        return result.map(|opt| opt.map(|s| serde_json::from_str(&s).unwrap_or(Value::String(s))));
    }
    ports.kv_get(plugin_id, key).map_err(|e| format!("storage error: {}", e))
}

/// 设置值（权限门 → 系统空间守卫 → 能力路由 → 键值原语）
pub fn storage_set(
    ports: &dyn StoragePorts,
    plugin_id: &str,
    key: &str,
    value: Value,
    gate: &PermissionGate<'_>,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, gate.permission, gate.api) {
        return Err(gate.deny_error.to_string());
    }
    ensure_not_system_space(plugin_id)?;
    if let Some(result) = ports.forward_kv_set(plugin_id, key, &value.to_string()) {
        return result;
    }
    ports.kv_set(plugin_id, key, value).map_err(|e| format!("storage error: {}", e))
}

/// 删除值（权限门 → 系统空间守卫 → 能力路由 → 键值原语）
pub fn storage_delete(
    ports: &dyn StoragePorts,
    plugin_id: &str,
    key: &str,
    gate: &PermissionGate<'_>,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, gate.permission, gate.api) {
        return Err(gate.deny_error.to_string());
    }
    ensure_not_system_space(plugin_id)?;
    if let Some(result) = ports.forward_kv_delete(plugin_id, key) {
        return result;
    }
    ports.kv_delete(plugin_id, key).map_err(|e| format!("storage error: {}", e))
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    /// 假端口：内存 kv + 按插件授权集 + 可选转发空间（形状对齐桌面
    /// `sqlite_scaffold::FakePorts`，但不依赖任何一端类型）
    struct MockPorts {
        granted: Mutex<HashMap<String, HashSet<String>>>,
        kv: Mutex<HashMap<(String, String), Value>>,
        /// 转发空间（系统组件侧）；仅 `forward_owners` 中的属主走转发
        forward: Mutex<HashMap<(String, String), String>>,
        forward_owners: Mutex<HashSet<String>>,
        /// 键值原语强制失败（错误包装用例）
        kv_fail: bool,
        /// gate 入参记录（permission, api）——词汇经参数传入的直接证据
        gate_calls: Mutex<Vec<(String, String)>>,
    }

    impl MockPorts {
        fn new() -> Self {
            Self {
                granted: Mutex::new(HashMap::new()),
                kv: Mutex::new(HashMap::new()),
                forward: Mutex::new(HashMap::new()),
                forward_owners: Mutex::new(HashSet::new()),
                kv_fail: false,
                gate_calls: Mutex::new(Vec::new()),
            }
        }

        fn grant(&self, plugin_id: &str, permission: &str) {
            self.granted
                .lock()
                .unwrap()
                .entry(plugin_id.to_string())
                .or_default()
                .insert(permission.to_string());
        }

        fn enable_forward(&self, plugin_id: &str) {
            self.forward_owners.lock().unwrap().insert(plugin_id.to_string());
        }
    }

    impl StoragePorts for MockPorts {
        fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool {
            self.gate_calls.lock().unwrap().push((permission.to_string(), api.to_string()));
            self.granted
                .lock()
                .unwrap()
                .get(plugin_id)
                .is_some_and(|perms| perms.contains(permission))
        }

        fn kv_get(&self, plugin_id: &str, key: &str) -> Result<Option<Value>, String> {
            if self.kv_fail {
                return Err("mock kv failure".to_string());
            }
            Ok(self
                .kv
                .lock()
                .unwrap()
                .get(&(plugin_id.to_string(), key.to_string()))
                .cloned())
        }

        fn kv_set(&self, plugin_id: &str, key: &str, value: Value) -> Result<(), String> {
            if self.kv_fail {
                return Err("mock kv failure".to_string());
            }
            self.kv
                .lock()
                .unwrap()
                .insert((plugin_id.to_string(), key.to_string()), value);
            Ok(())
        }

        fn kv_delete(&self, plugin_id: &str, key: &str) -> Result<(), String> {
            if self.kv_fail {
                return Err("mock kv failure".to_string());
            }
            self.kv.lock().unwrap().remove(&(plugin_id.to_string(), key.to_string()));
            Ok(())
        }

        fn forward_kv_get(&self, plugin_id: &str, key: &str) -> Option<Result<Option<String>, String>> {
            if !self.forward_owners.lock().unwrap().contains(plugin_id) {
                return None;
            }
            Some(Ok(self
                .forward
                .lock()
                .unwrap()
                .get(&(plugin_id.to_string(), key.to_string()))
                .cloned()))
        }

        fn forward_kv_set(&self, plugin_id: &str, key: &str, value: &str) -> Option<Result<(), String>> {
            if !self.forward_owners.lock().unwrap().contains(plugin_id) {
                return None;
            }
            self.forward
                .lock()
                .unwrap()
                .insert((plugin_id.to_string(), key.to_string()), value.to_string());
            Some(Ok(()))
        }

        fn forward_kv_delete(&self, plugin_id: &str, key: &str) -> Option<Result<(), String>> {
            if !self.forward_owners.lock().unwrap().contains(plugin_id) {
                return None;
            }
            self.forward.lock().unwrap().remove(&(plugin_id.to_string(), key.to_string()));
            Some(Ok(()))
        }
    }

    const PLUGIN: &str = "test-plugin";
    const PERM: &str = "storage";

    fn gate(api: &'static str) -> PermissionGate<'static> {
        PermissionGate { permission: PERM, api, deny_error: "permission denied" }
    }

    /// 未授权插件：三条原语都在权限门处被拒，deny_error 逐字透传；
    /// 且权限词汇 / 原语名确实作为参数到达端口（gate_calls 记录）
    #[test]
    fn permission_gate_blocks_ungranted_and_passes_vocabulary() {
        let ports = MockPorts::new();
        assert_eq!(storage_get(&ports, PLUGIN, "k", &gate("host_storage_get")).unwrap_err(), "permission denied");
        assert_eq!(
            storage_set(&ports, PLUGIN, "k", serde_json::json!(1), &gate("host_storage_set")).unwrap_err(),
            "permission denied"
        );
        assert_eq!(
            storage_delete(&ports, PLUGIN, "k", &gate("host_storage_delete")).unwrap_err(),
            "permission denied"
        );
        let calls = ports.gate_calls.lock().unwrap();
        assert_eq!(
            *calls,
            vec![
                (PERM.to_string(), "host_storage_get".to_string()),
                (PERM.to_string(), "host_storage_set".to_string()),
                (PERM.to_string(), "host_storage_delete".to_string()),
            ]
        );
    }

    /// 授权后 set/get/delete 往返 + 插件间隔离 + 缺失 key 返回 None + 删除幂等
    #[test]
    fn roundtrip_isolation_and_idempotent_delete() {
        let ports = MockPorts::new();
        ports.grant(PLUGIN, PERM);
        let value = serde_json::json!({ "count": 3, "tags": ["a", "b"] });

        storage_set(&ports, PLUGIN, "cfg", value.clone(), &gate("host_storage_set")).expect("set ok");
        assert_eq!(
            storage_get(&ports, PLUGIN, "cfg", &gate("host_storage_get")).expect("get ok").expect("value"),
            value
        );
        // 插件间隔离：另一插件先授权再读，读不到（按 plugin_id 分区）
        ports.grant("other-plugin", PERM);
        assert!(storage_get(&ports, "other-plugin", "cfg", &gate("host_storage_get")).expect("get ok").is_none());
        // 未设置的 key 返回 None
        assert!(storage_get(&ports, PLUGIN, "missing", &gate("host_storage_get")).expect("get ok").is_none());

        storage_delete(&ports, PLUGIN, "cfg", &gate("host_storage_delete")).expect("delete ok");
        assert!(storage_get(&ports, PLUGIN, "cfg", &gate("host_storage_get")).expect("get ok").is_none());
        storage_delete(&ports, PLUGIN, "cfg", &gate("host_storage_delete")).expect("delete again ok");
    }

    /// R-02 纵深防御：系统空间对插件面原语不可达——即便权限已授予
    #[test]
    fn system_space_rejected_even_when_granted() {
        let ports = MockPorts::new();
        ports.grant(PLUGIN, PERM);
        ports.grant(SYSTEM_PLUGIN_ID, PERM);

        let err = storage_get(&ports, SYSTEM_PLUGIN_ID, "activation_state", &gate("host_storage_get"))
            .expect_err("系统空间读取必须被拒");
        assert!(err.contains("system storage space"), "实际: {err}");
        assert!(
            storage_set(&ports, SYSTEM_PLUGIN_ID, "k", serde_json::json!(1), &gate("host_storage_set")).is_err(),
            "系统空间写入必须被拒"
        );
        assert!(
            storage_delete(&ports, SYSTEM_PLUGIN_ID, "activation_state", &gate("host_storage_delete")).is_err(),
            "系统空间删除必须被拒"
        );
        // 正常插件空间不受影响
        assert!(storage_get(&ports, PLUGIN, "k", &gate("host_storage_get")).expect("get ok").is_none());
    }

    /// 能力路由：转发命中短路宿主原语（两空间互不可见）；未登记转发的属主走原语
    #[test]
    fn forward_routing_short_circuits_host_primitives() {
        let ports = MockPorts::new();
        ports.grant(PLUGIN, PERM);
        ports.enable_forward(PLUGIN);

        storage_set(&ports, PLUGIN, "cfg", serde_json::json!({ "count": 3 }), &gate("host_storage_set"))
            .expect("set 经转发应成功");
        assert_eq!(ports.kv.lock().unwrap().len(), 0, "转发命中时不得同时写宿主原语空间");
        assert_eq!(
            storage_get(&ports, PLUGIN, "cfg", &gate("host_storage_get")).expect("get ok"),
            Some(serde_json::json!({ "count": 3 })),
            "值必须从系统组件侧取回"
        );

        // 未登记转发的属主：走宿主原语，读不到系统组件侧的值
        ports.grant("other-plugin", PERM);
        assert!(storage_get(&ports, "other-plugin", "cfg", &gate("host_storage_get")).expect("get ok").is_none());
        storage_set(&ports, "other-plugin", "k", serde_json::json!(1), &gate("host_storage_set")).expect("set ok");
        assert!(
            !ports.forward.lock().unwrap().contains_key(&("other-plugin".to_string(), "k".to_string())),
            "宿主原语写入不得落到系统组件侧空间"
        );
        assert_eq!(
            ports.kv.lock().unwrap().get(&("other-plugin".to_string(), "k".to_string())),
            Some(&serde_json::json!(1))
        );

        // 删除走转发：系统组件侧清空
        storage_delete(&ports, PLUGIN, "cfg", &gate("host_storage_delete")).expect("delete ok");
        assert!(storage_get(&ports, PLUGIN, "cfg", &gate("host_storage_get")).expect("get ok").is_none());
    }

    /// 非 JSON 存量串：转发路径降级为字符串值（既有 unwrap_or 语义）
    #[test]
    fn forward_non_json_string_degrades_to_string_value() {
        let ports = MockPorts::new();
        ports.grant(PLUGIN, PERM);
        ports.enable_forward(PLUGIN);
        ports.forward
            .lock()
            .unwrap()
            .insert((PLUGIN.to_string(), "raw".to_string()), "not-json".to_string());
        assert_eq!(
            storage_get(&ports, PLUGIN, "raw", &gate("host_storage_get")).expect("get ok"),
            Some(Value::String("not-json".to_string()))
        );
    }

    /// 键值原语失败统一包装为 `storage error: {e}`；转发路径的错误原样透传
    #[test]
    fn kv_error_wrapped_and_forward_error_passthrough() {
        let ports = MockPorts::new();
        ports.grant(PLUGIN, PERM);
        let mut ports = ports;
        ports.kv_fail = true;
        assert_eq!(
            storage_get(&ports, PLUGIN, "k", &gate("host_storage_get")).unwrap_err(),
            "storage error: mock kv failure"
        );

        let ports = MockPorts::new();
        ports.grant(PLUGIN, PERM);
        ports.enable_forward(PLUGIN);
        // 转发命中的 Err 不经 "storage error:" 包装（桌面既有语义：result 直接返回）
        ports.forward_owners.lock().unwrap().insert(PLUGIN.to_string());
        // 借 forward_kv_get 的返回面注入 Err：占位 owner 未在 forward 空间登记 key
        // 时返回 Ok(None)，故这里改为手工构造一个恒 Err 的最小端口
        struct FailingForward;
        impl StoragePorts for FailingForward {
            fn check_permission(&self, _: &str, _: &str, _: &str) -> bool {
                true
            }
            fn kv_get(&self, _: &str, _: &str) -> Result<Option<Value>, String> {
                unreachable!("转发命中时不应触达宿主原语")
            }
            fn kv_set(&self, _: &str, _: &str, _: Value) -> Result<(), String> {
                unreachable!()
            }
            fn kv_delete(&self, _: &str, _: &str) -> Result<(), String> {
                unreachable!()
            }
            fn forward_kv_get(&self, _: &str, _: &str) -> Option<Result<Option<String>, String>> {
                Some(Err("forward boom".to_string()))
            }
        }
        assert_eq!(
            storage_get(&FailingForward, PLUGIN, "k", &gate("host_storage_get")).unwrap_err(),
            "forward boom"
        );
    }
}
