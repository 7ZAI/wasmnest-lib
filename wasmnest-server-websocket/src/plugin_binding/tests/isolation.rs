//! 隔离契约（票据 06：跨插件 + 事件面）

use super::scaffold::*;
use super::*;

/// 状态事件按属主私有 topic 投递：事件只落属主命名空间（spec §2.3）
///
/// 本用例锁「能力域只经属主 topic 投递」；「非属主订阅不到」由总线命名空间门禁
/// 负责（见 `host_api/bus.rs` 的跨命名空间订阅拒绝用例）。
#[tokio::test]
async fn status_events_are_owner_scoped() {
    let owner = test_plugin("topic-owner");
    let other = test_plugin("topic-other");
    let owner_topic = owned_topic(&owner, WS_CLOSE);
    let other_topic = owned_topic(&other, WS_CLOSE);
    assert_ne!(owner_topic, other_topic, "两个属主的命名空间必须不同");

    let fake = FakePorts::with(&[]);
    let ports: Arc<dyn WsPorts> = fake.clone();
    publish_ws(&ports, &owner_topic, serde_json::json!({ "handle": "wsc-1" }));

    let published = fake.published();
    assert_eq!(published.len(), 1, "恰好一次投递（事件不重放）");
    assert_eq!(published[0].0, owner_topic, "事件只落属主私有 topic");
    assert_eq!(published[0].1["handle"], "wsc-1");
    assert!(
        !published.iter().any(|(topic, _)| topic == &other_topic),
        "他人命名空间收不到该事件"
    );
}

/// 跨插件隔离（全函数负向，票据 06 清单）：他人句柄 / 端点 / 对端客户端标识
/// 上的全部函数一律拒绝，且**零副作用**（句柄不消费、端点不注销、连接不断开）
#[tokio::test]
async fn cross_plugin_isolation_covers_all_handle_functions() {
    let owner = test_plugin("iso-owner");
    let intruder = test_plugin("iso-intruder");
    let owner_ports: Arc<dyn WsPorts> =
        FakePorts::with(&[(&owner, PERMISSION_WS_CLIENT), (&owner, PERMISSION_WS_SERVER)]);
    let intruder_ports: Arc<dyn WsPorts> =
        FakePorts::with(&[(&intruder, PERMISSION_WS_CLIENT), (&intruder, PERMISSION_WS_SERVER)]);

    let handle = format!("wsc-{}", uuid::Uuid::new_v4());
    fake_client(&owner_ports, &owner, &handle, "ws://127.0.0.1:1/");
    let endpoint = register_endpoint(&owner_ports, &owner, "iso");
    let peer_client = "127.0.0.1:1";

    // 客户端域（4 个带句柄的函数）
    let client_results = [
        ws_send_text(&intruder_ports, &intruder, &handle, "hi").map(|_| ()),
        ws_send_binary(&intruder_ports, &intruder, &handle, b"hi").map(|_| ()),
        ws_close(&intruder_ports, &intruder, &handle, "{}").map(|_| ()),
        ws_is_connected(&intruder_ports, &intruder, &handle).map(|_| ()),
    ];
    for result in client_results {
        assert_eq!(result.unwrap_err(), NOT_OWNER, "客户端域跨属主必须拒绝");
    }
    // 服务端域（8 个带端点/对端标识的函数）
    let server_results = [
        ws_send_text_to_client(&intruder_ports, &intruder, &endpoint, peer_client, "hi").map(|_| ()),
        ws_send_binary_to_client(&intruder_ports, &intruder, &endpoint, peer_client, b"hi").map(|_| ()),
        ws_broadcast_text(&intruder_ports, &intruder, &endpoint, "hi").map(|_| ()),
        ws_broadcast_binary(&intruder_ports, &intruder, &endpoint, b"hi").map(|_| ()),
        ws_close_client(&intruder_ports, &intruder, &endpoint, peer_client, "{}").map(|_| ()),
        ws_unregister_endpoint(&intruder_ports, &intruder, &endpoint).map(|_| ()),
        ws_list_clients(&intruder_ports, &intruder, &endpoint).map(|_| ()),
        ws_connection_context(&intruder_ports, &intruder, &endpoint, peer_client).map(|_| ()),
    ];
    for result in server_results {
        assert_eq!(result.unwrap_err(), NOT_ENDPOINT_OWNER, "服务端域跨属主必须拒绝");
    }
    // 无「他人句柄」入参的三个函数按契约只作用于调用方自身：
    // connect 受本人连接数上限约束、register-endpoint 挂在本人命名空间、
    // list-endpoints 只列本人端点 —— 冲突与上限已由其它用例覆盖，此处断言
    // 「他人的东西不出现在本人视图里」= 零可见
    assert_eq!(
        ws_list_endpoints(&intruder_ports, &intruder).unwrap(),
        "[]",
        "他人端点零可见"
    );
    assert_eq!(
        crate::endpoint::list_by_owner(&intruder).len(),
        0,
        "他人端点表条目零可见"
    );

    // 零副作用：拒绝不得消费句柄 / 注销端点 / 断开连接
    assert!(crate::endpoint::get(&endpoint).is_some(), "端点未被注销");
    assert!(
        ws_is_connected(&owner_ports, &owner, &handle).unwrap(),
        "本人连接未被关闭"
    );
    assert_eq!(ws_list_clients(&owner_ports, &owner, &endpoint).unwrap(), "[]");
    assert_eq!(ws_list_endpoints(&owner_ports, &owner).unwrap().contains("iso"), true);

    drop_client(&handle);
    drop_endpoint(&endpoint);
}
