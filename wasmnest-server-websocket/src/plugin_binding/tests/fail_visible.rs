//! 句柄寻址 / 属主仲裁 / fail-visible

use super::scaffold::*;
use super::*;

#[tokio::test]
async fn send_and_query_unknown_handle_are_errors_not_panics() {
    let plugin = test_plugin("unknown");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_CLIENT)]);

    assert!(ws_send_text(&ports, &plugin, "wsc-missing", "hi").is_err());
    assert!(ws_send_binary(&ports, &plugin, "wsc-missing", b"hi").is_err());
    // 未知句柄：close 幂等 false；is-connected false
    assert!(!ws_close(&ports, &plugin, "wsc-missing", "{}").unwrap());
    assert!(!ws_is_connected(&ports, &plugin, "wsc-missing").unwrap());
}

#[tokio::test]
async fn cross_plugin_handle_access_rejected_without_consuming() {
    let owner = test_plugin("owner");
    let intruder = test_plugin("intruder");
    let owner_ports: Arc<dyn WsPorts> =
        FakePorts::with(&[(&owner, PERMISSION_WS_CLIENT), (&intruder, PERMISSION_WS_CLIENT)]);
    let intruder_ports = owner_ports.clone();
    let handle = format!("wsc-{}", uuid::Uuid::new_v4());
    fake_client(&owner_ports, &owner, &handle, "ws://127.0.0.1:1/");

    assert_eq!(
        ws_send_text(&intruder_ports, &intruder, &handle, "hi").unwrap_err(),
        NOT_OWNER
    );
    assert_eq!(
        ws_is_connected(&intruder_ports, &intruder, &handle).unwrap_err(),
        NOT_OWNER
    );
    assert_eq!(
        ws_close(&intruder_ports, &intruder, &handle, "{}").unwrap_err(),
        NOT_OWNER
    );
    // 拒绝不得消费句柄
    assert!(ws_is_connected(&owner_ports, &owner, &handle).unwrap());
    // 属主本人可用
    assert!(ws_send_text(&owner_ports, &owner, &handle, "hi").is_ok());

    drop_client(&handle);
}

#[tokio::test]
async fn send_queue_full_is_fail_visible() {
    let plugin = test_plugin("queuefull");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_CLIENT)]);
    let handle = format!("wsc-{}", uuid::Uuid::new_v4());
    let (tx, rx) = mpsc::channel(1);
    CLIENTS.lock().unwrap().insert(
        handle.to_string(),
        ClientEntry {
            owner: plugin.clone(),
            url: "ws://127.0.0.1:1/".to_string(),
            tx,
            state: Arc::new(AtomicU8::new(STATE_OPEN)),
            reader: spawn_with_error_boundary("ws_test_reader", async {}),
            writer: spawn_with_error_boundary("ws_test_writer", async {}),
        },
    );
    assert!(ws_send_text(&ports, &plugin, &handle, "first").is_ok());
    assert_eq!(
        ws_send_text(&ports, &plugin, &handle, "second").unwrap_err(),
        "ws send queue full"
    );
    drop(rx);
    assert_eq!(
        ws_send_text(&ports, &plugin, &handle, "closed").unwrap_err(),
        "ws connection is closed"
    );
    drop_client(&handle);
}

#[tokio::test]
async fn close_config_defaults_to_1000_and_reports_hit() {
    let plugin = test_plugin("close");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_CLIENT)]);
    let handle = format!("wsc-{}", uuid::Uuid::new_v4());
    fake_client(&ports, &plugin, &handle, "ws://127.0.0.1:1/");

    // 缺省 code = 1000（spec §4.4 close 语义）
    assert!(ws_close(&ports, &plugin, &handle, "{}").unwrap());
    // 句柄已摘除 → 幂等 false
    assert!(!ws_close(&ports, &plugin, &handle, "{}").unwrap());
    assert!(!ws_is_connected(&ports, &plugin, &handle).unwrap());
    // 显式 code/reason 解析成功路径
    let handle2 = format!("wsc-{}", uuid::Uuid::new_v4());
    fake_client(&ports, &plugin, &handle2, "ws://127.0.0.1:1/");
    assert!(ws_close(&ports, &plugin, &handle2, r#"{"code":4004,"reason":"kicked"}"#).unwrap());
    drop_client(&handle2);
    // 非法 close-json 拒绝
    let handle3 = format!("wsc-{}", uuid::Uuid::new_v4());
    fake_client(&ports, &plugin, &handle3, "ws://127.0.0.1:1/");
    assert!(ws_close(&ports, &plugin, &handle3, "not json").is_err());
    assert!(
        ws_is_connected(&ports, &plugin, &handle3).unwrap(),
        "解析失败不得摘除句柄"
    );
    drop_client(&handle3);
}
