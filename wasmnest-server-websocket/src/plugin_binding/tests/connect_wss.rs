//! connect 语义边界（失败零事件、wss 拒绝、连接数上限）

use super::scaffold::*;
use super::*;

#[tokio::test]
async fn connect_rejects_non_ws_scheme_and_bad_config() {
    let plugin = test_plugin("scheme");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_CLIENT)]);

    // D7：wss:// 显式拒绝（不启用 TLS），且错误文案指明未支持
    let err = ws_connect(&ports, &plugin, r#"{"url":"wss://example.com/socket"}"#).expect_err("wss rejected");
    assert!(err.contains("only ws://"), "wss 拒绝文案应指明仅支持 ws://：{err}");

    // 空 url / 非法 JSON / 非法 header 名：都在握手前失败
    assert!(ws_connect(&ports, &plugin, r#"{"url":"  "}"#).is_err());
    assert!(ws_connect(&ports, &plugin, "not json").is_err());
    assert!(ws_connect(
        &ports,
        &plugin,
        r#"{"url":"ws://127.0.0.1:1/","headers":{"bad header":"x"}}"#
    )
    .is_err());

    // 失败路径不产生连接（表内无本人条目）→ 也无任何事件副作用
    let table = CLIENTS.lock().unwrap();
    assert!(!table.values().any(|e| e.owner == plugin));
}

#[tokio::test]
async fn connect_enforces_per_plugin_limit() {
    let plugin = test_plugin("limit");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_CLIENT)]);
    // 预置到上限
    for i in 0..PLUGIN_WS_MAX_CONNS_PER_PLUGIN {
        fake_client(&ports, &plugin, &format!("wsc-{plugin}-{i}"), "ws://127.0.0.1:1/");
    }
    let err = ws_connect(&ports, &plugin, r#"{"url":"ws://127.0.0.1:1/"}"#).expect_err("limit");
    assert!(err.contains("connection limit reached"), "got: {err}");
    for i in 0..PLUGIN_WS_MAX_CONNS_PER_PLUGIN {
        drop_client(&format!("wsc-{plugin}-{i}"));
    }
}
