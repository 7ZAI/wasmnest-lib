//! connection-context（脱敏上下文，v28 票 02）用例组（自 scaffold.rs 拆出，
//! 2026-10-04 OCR K-07：scaffold 只放跨组共享助手，真测试单独成组）
//!
//! `ws_connection_context` 查询「某端点下某客户端」的连接上下文：属主可查完整
//! 脱敏上下文，跨属主 / 跨端点 / 未知客户端一律显性拒绝（fail-visible，
//! 不返回「成功但无数据」）。

use super::scaffold::*;
use super::*;

/// 权限门：无 `ws:server` —— connection-context 拒绝
#[actix_rt::test]
pub(super) async fn connection_context_denied_without_ws_server_permission() {
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[]);
    let plugin = test_plugin("ctx-perm");
    let err = ws_connection_context(&ports, &plugin, "wse-x", "127.0.0.1:1").expect_err("denied");
    assert_eq!(err, denied_server());
}

/// 属主可查已认证客户端：完整脱敏上下文（含 authContext 三字段）
#[actix_rt::test]
pub(super) async fn connection_context_authenticated_owner_query() {
    let plugin = test_plugin("ctx-auth");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(plugin.as_str(), PERMISSION_WS_SERVER)]);
    let endpoint = register_endpoint(&ports, &plugin, "ctx");
    let client = register_endpoint_client(
        "ctx-auth-c1",
        &plugin,
        &endpoint,
        true,
        Some("device-9"),
        Some("Phone"),
        Some("fp-9"),
    )
    .await;

    let json = ws_connection_context(&ports, &plugin, &endpoint, &client).expect("owner query");
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["clientId"], client);
    assert_eq!(value["addr"], client, "addr 即注册表键（= 对端地址串）");
    assert_eq!(value["endpointId"], endpoint);
    assert_eq!(value["owner"], plugin);
    assert_eq!(value["authenticated"], true);
    assert!(value["connectedAt"].is_number(), "connectedAt 为 epoch 毫秒");
    assert_eq!(value["authContext"]["subject"], "device-9");
    assert_eq!(value["authContext"]["deviceName"], "Phone");
    assert_eq!(value["authContext"]["fingerprint"], "fp-9");
    // 凭据红线：token / 密钥 / 公钥绝不出现
    let flat = json.to_string();
    for forbidden in ["token", "secret", "publicKey", "private", "jwt"] {
        assert!(
            !flat.to_lowercase().contains(forbidden),
            "上下文不得泄漏凭据字段: {forbidden}"
        );
    }

    drop_registry_client(&client).await;
    drop_endpoint(&endpoint);
}

/// `auth: none` / 未认证连接：authenticated=false 且 authContext 省略（不伪造身份）
#[actix_rt::test]
pub(super) async fn connection_context_unauthenticated_omits_auth_context() {
    let plugin = test_plugin("ctx-none");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(plugin.as_str(), PERMISSION_WS_SERVER)]);
    let endpoint = register_endpoint(&ports, &plugin, "open");
    let client = register_endpoint_client("ctx-none-c1", &plugin, &endpoint, false, None, None, None).await;

    let json = ws_connection_context(&ports, &plugin, &endpoint, &client).expect("owner query");
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["authenticated"], false);
    assert!(value.get("authContext").is_none(), "未认证不得出现 authContext");

    drop_registry_client(&client).await;
    drop_endpoint(&endpoint);
}

/// 跨属主 / 跨端点 / 未知客户端：显性拒绝，不返回「成功但无数据」
#[actix_rt::test]
pub(super) async fn connection_context_rejects_cross_owner_and_unknown() {
    let owner = test_plugin("ctx-owner");
    let intruder = test_plugin("ctx-intruder");
    let owner_ports: Arc<dyn WsPorts> = FakePorts::with(&[(&owner, PERMISSION_WS_SERVER)]);
    let intruder_ports: Arc<dyn WsPorts> = FakePorts::with(&[(&intruder, PERMISSION_WS_SERVER)]);
    let endpoint = register_endpoint(&owner_ports, &owner, "mine");
    let client = register_endpoint_client("ctx-own-c1", &owner, &endpoint, true, Some("d"), Some("N"), Some("f")).await;

    // 跨属主：他人查询本人端点里的客户端 → 属主仲裁拒绝
    let err =
        ws_connection_context(&intruder_ports, &intruder, &endpoint, &client).expect_err("cross-owner must reject");
    assert_eq!(err, NOT_ENDPOINT_OWNER);
    // 跨端点：未注册的端点句柄 → 显性报错（不返回「成功但无数据」）
    let err =
        ws_connection_context(&owner_ports, &owner, "wse-ghost", &client).expect_err("unknown endpoint must reject");
    assert!(err.contains("not found"), "未知端点必须点名，got: {err}");
    // 未知客户端：端点存在且属主合法，但客户端不在端点名下 → fail-visible
    let err =
        ws_connection_context(&owner_ports, &owner, &endpoint, "127.0.0.1:9").expect_err("unknown client must reject");
    assert!(err.contains("not found in endpoint"), "got: {err}");
    // 客户端不属于该端点：属于**另一个端点**的客户端，用本端点查询 → 同错
    // （2026-10-04 OCR K-08：旧实现在此处只做了一次「本人端点的本人客户端」
    // 正例查询来充当「负例」，跨端点客户端的拒绝意图从未被真正断言——注释
    // 说的「不属于该端点 → 同错」没有对应的负例执行。此处补上真负例，再
    // 用正例收尾防「恒拒绝」假绿。）
    let other_endpoint = register_endpoint(&owner_ports, &owner, "other");
    let other_client = register_endpoint_client(
        "ctx-own-c2",
        &owner,
        &other_endpoint,
        true,
        Some("d2"),
        Some("N2"),
        Some("f2"),
    )
    .await;
    let err = ws_connection_context(&owner_ports, &owner, &endpoint, &other_client)
        .expect_err("other-endpoint client must reject");
    assert!(err.contains("not found in endpoint"), "got: {err}");
    // 本人端点的本人客户端仍是正例（负例断言之后回归，防「一刀切全拒」）
    let json = ws_connection_context(&owner_ports, &owner, &endpoint, &client).expect("owner query must work");
    assert!(json.contains("\"authenticated\":true"));
    // 拒绝路径零副作用：连接仍在线（未被断开）
    assert_eq!(
        ws_list_clients(&owner_ports, &owner, &endpoint).unwrap().len() > 0,
        true
    );

    drop_registry_client(&other_client).await;
    drop_endpoint(&other_endpoint);

    drop_registry_client(&client).await;
    drop_endpoint(&endpoint);
}
