//! 权限门（客户端域 / 服务端域分域）

use super::scaffold::*;
use super::*;

#[tokio::test]
async fn connect_denied_without_ws_client_permission() {
    let plugin = test_plugin("perm-client");
    // 未授权：客户端域一律拒绝
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[]);
    let err = ws_connect(&ports, &plugin, r#"{"url":"ws://127.0.0.1:1/"}"#).expect_err("denied");
    assert_eq!(err, denied_client());

    // 只有服务端域权限也不得放行客户端域（分域隔离，spec D6）
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);
    let err = ws_connect(&ports, &plugin, r#"{"url":"ws://127.0.0.1:1/"}"#).expect_err("denied");
    assert_eq!(err, denied_client());
}

#[tokio::test]
async fn server_domain_denied_without_ws_server_permission() {
    let plugin = test_plugin("perm-server");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[]);
    let err = ws_register_endpoint(&ports, &plugin, r#"{"path":"chat"}"#).expect_err("denied");
    assert_eq!(err, denied_server());

    // 只有客户端域权限也不得放行服务端域
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_CLIENT)]);
    let err = ws_register_endpoint(&ports, &plugin, r#"{"path":"chat"}"#).expect_err("denied");
    assert_eq!(err, denied_server());
}
