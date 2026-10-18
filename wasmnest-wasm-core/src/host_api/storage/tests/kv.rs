//! `host-storage` 能力域的 3 条原语：权限门 / 系统空间纵深守卫 / 键值往返与属主隔离
//!
//! 迁移自宿主 `wasm_core::host_api/storage.rs` 的同名用例（票 08），断言逐字保留：
//! 未授权一律拒（含 set / delete）、授权后 get/set/delete 往返、跨插件隔离、
//! 未设置 key 返回 `None`、删不存在 key 幂等、以及 R-02 纵深（`__system__` 系统空间
//! 对插件面原语一律不可达）。

use crate::host_api::sqlite_scaffold::*;
use crate::host_api::storage::{storage_delete, storage_get, storage_set, SYSTEM_PLUGIN_ID};
use crate::permission::PERMISSION_STORAGE;

const PLUGIN: &str = "test-plugin";

/// 未授权插件（从未 grant）：storage 三个操作均被权限门禁拒绝
#[test]
fn storage_ops_permission_denied() {
    let fake = FakePorts::new();
    let ports = as_ports(&fake);
    assert_eq!(storage_get(ports, PLUGIN, "k").unwrap_err(), "permission denied");
    assert_eq!(
        storage_set(ports, PLUGIN, "k", serde_json::json!(1)).unwrap_err(),
        "permission denied"
    );
    assert_eq!(storage_delete(ports, PLUGIN, "k").unwrap_err(), "permission denied");
}

/// 授权后 set/get/delete 往返 + 插件间隔离 + 缺失 key 返回 None
#[tokio::test]
async fn storage_set_get_delete_roundtrip() {
    let fake = FakePorts::new();
    let ports = as_ports(&fake);
    fake.grant(PLUGIN, &[PERMISSION_STORAGE]);
    let value = serde_json::json!({ "count": 3, "tags": ["a", "b"] });

    storage_set(ports, PLUGIN, "cfg", value.clone()).expect("set ok");
    assert_eq!(
        storage_get(ports, PLUGIN, "cfg").expect("get ok").expect("value"),
        value
    );
    // 插件间隔离：另一个插件读不到（key 按 plugin_id 分区）——
    // 需先授权该插件，否则在权限门禁处就被拒绝，无法触达存储层语义
    fake.grant("other-plugin", &[PERMISSION_STORAGE]);
    assert!(storage_get(ports, "other-plugin", "cfg").expect("get ok").is_none());
    // 未设置的 key 返回 None
    assert!(storage_get(ports, PLUGIN, "missing").expect("get ok").is_none());

    storage_delete(ports, PLUGIN, "cfg").expect("delete ok");
    assert!(storage_get(ports, PLUGIN, "cfg").expect("get ok").is_none());
    // 删除不存在的 key 幂等
    storage_delete(ports, PLUGIN, "cfg").expect("delete again ok");
}

/// R-02 纵深防御：系统空间（`__system__`）对插件面原语不可达——即便权限
/// 已授予，读/写/删系统空间一律拒绝（激活状态、审批记录等宿主真源不可触碰）
#[test]
fn system_space_rejected_on_plugin_primitives() {
    let fake = FakePorts::new();
    let ports = as_ports(&fake);
    // 正常插件 + 模拟“系统 id 被误授权限”（buggy 路径）：权限门过了
    // 也必须在纵深守卫处被拒
    fake.grant(PLUGIN, &[PERMISSION_STORAGE]);
    fake.grant(SYSTEM_PLUGIN_ID, &[PERMISSION_STORAGE]);

    let err = storage_get(ports, SYSTEM_PLUGIN_ID, "activation_state").expect_err("系统空间读取必须被拒");
    assert!(err.contains("system storage space"), "实际: {err}");
    assert!(
        storage_set(ports, SYSTEM_PLUGIN_ID, "k", serde_json::json!(1)).is_err(),
        "系统空间写入必须被拒"
    );
    assert!(
        storage_delete(ports, SYSTEM_PLUGIN_ID, "activation_state").is_err(),
        "系统空间删除必须被拒"
    );
    // 正常插件空间不受影响
    assert!(storage_get(ports, PLUGIN, "k").expect("get ok").is_none());
}

/// 能力路由（core-plugin-manager）：该能力由**系统组件**提供时，三条原语按**调用方**
/// 命名空间转发到它的同形导出，**不碰宿主原语**；未命中提供者才走宿主原语
///
/// 两个断言面各钉一侧：
/// ① 转发命中 → 宿主原语空间**为空**（转发确实短路了原语，不是两条都写）；
/// ② 未登记转发的属主 → 读不到前者的值（转发空间与原语空间互相不可见，
///    否则「两条路径共用一份存储」会让这条用例恒绿）。
#[test]
fn capability_routing_short_circuits_host_primitives() {
    let fake = FakePorts::new();
    let ports = as_ports(&fake);
    fake.grant(PLUGIN, &[PERMISSION_STORAGE]);
    fake.forward_kv_for(PLUGIN);

    storage_set(ports, PLUGIN, "cfg", serde_json::json!({ "count": 3 })).expect("set 经转发应成功");
    assert_eq!(
        storage_get(ports, PLUGIN, "cfg").expect("get ok"),
        Some(serde_json::json!({ "count": 3 })),
        "转发命中时值必须从系统组件侧取回"
    );
    assert_eq!(
        fake.forwarded_value(PLUGIN, "cfg"),
        Some(serde_json::json!({ "count": 3 })),
        "值必须落在系统组件侧空间"
    );
    assert_eq!(fake.host_value(PLUGIN, "cfg"), None, "转发命中时不得同时写宿主原语空间");

    // 未登记转发的属主：走宿主原语，读不到系统组件侧的值
    fake.grant("other-plugin", &[PERMISSION_STORAGE]);
    assert!(
        storage_get(ports, "other-plugin", "cfg").expect("get ok").is_none(),
        "转发空间按调用方命名空间隔离，他属主不得读到"
    );
    storage_set(ports, "other-plugin", "cfg", serde_json::json!(1)).expect("set 走原语应成功");
    assert_eq!(fake.host_value("other-plugin", "cfg"), Some(serde_json::json!(1)));
    assert_eq!(
        fake.forwarded_value("other-plugin", "cfg"),
        None,
        "宿主原语写入不得落到系统组件侧空间"
    );

    // 删除同理走转发：系统组件侧清空、宿主原语空间始终未被创建
    storage_delete(ports, PLUGIN, "cfg").expect("delete 经转发应成功");
    assert!(storage_get(ports, PLUGIN, "cfg").expect("get ok").is_none());
    assert_eq!(fake.host_value(PLUGIN, "cfg"), None);
}
