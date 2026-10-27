//! 入站（服务端域）用例组：权限门 / 注册闭环与属主仲裁 / 非法形状零副作用 / 回收只碰本人

use super::scaffold::*;
use super::*;
use crate::registry;

/// 服务端域权限门：未声明 network:http 的插件 register/unregister 一律拒绝
#[test]
fn register_endpoint_requires_network_http_permission() {
    let ports = denying_permission();
    let err = http_register_endpoint(&as_ports(&ports), "p1", r#"{"path":"configs"}"#)
        .expect_err("unpermissioned register must be rejected");
    assert!(
        err.contains("permission denied") && err.contains("network:http"),
        "error should state permission reason, got: {err}"
    );
    let err = http_unregister_endpoint(&as_ports(&ports), "p1", "http-x")
        .expect_err("unpermissioned unregister must be rejected");
    assert!(err.contains("permission denied"), "got: {err}");
}

/// 服务端域注册闭环：授权后 register 成功返回句柄，注销属主命中、他人拒绝
#[test]
fn register_endpoint_roundtrip_with_owner_arbitration() {
    let ports = granting();
    let plugin = test_plugin(&uuid::Uuid::new_v4().to_string());
    let other = test_plugin(&format!("other-{}", uuid::Uuid::new_v4()));

    // 缺省档 = jwt（HTTP 面未声明即最严），内部路径注册成功
    let id = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"configs"}"#).expect("register");
    assert!(id.starts_with("http-"), "句柄前缀: {id}");
    let internal = format!("/api/plugin/{plugin}/configs");
    let entry = registry::find_by_internal(&internal).expect("registered");
    assert_eq!(entry.owner, plugin);
    assert_eq!(entry.auth, EndpointAuth::Jwt, "未声明 auth 落最严档");

    // 显式 none + host 别名 + 模板
    let id2 = http_register_endpoint(
        &as_ports(&ports),
        &plugin,
        &format!(
            r#"{{"path":"sessions/stop","host":"/api/sessions-{0}/{{id}}/stop","methods":["POST"],"auth":"none"}}"#,
            uuid::Uuid::new_v4().simple()
        ),
    )
    .expect("register alias");
    assert!(registry::is_owner(&id2, &plugin));

    // 注销：属主命中；他人句柄 → Err 且不消费
    assert!(http_unregister_endpoint(&as_ports(&ports), &other, &id).is_err());
    assert!(registry::is_owner(&id, &plugin), "他人注销不得消费句柄");
    assert!(http_unregister_endpoint(&as_ports(&ports), &plugin, &id).unwrap());
    assert!(
        !http_unregister_endpoint(&as_ports(&ports), &plugin, &id).unwrap(),
        "重复注销幂等 false"
    );
    assert!(registry::find_by_internal(&internal).is_none());

    purge_for_plugin(&plugin);
    purge_for_plugin(&other);
}

/// 非法 config：畸形 JSON / 空 path / 非法 auth 档位 → Err（fail-visible，零副作用）
#[test]
fn register_endpoint_rejects_bad_config() {
    let ports = granting();
    let plugin = test_plugin(&format!("bad-{}", uuid::Uuid::new_v4()));

    assert!(http_register_endpoint(&as_ports(&ports), &plugin, "not json").is_err());
    assert!(http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":""}"#).is_err());
    let err = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"x","auth":"local-only"}"#)
        .expect_err("unknown auth tier must be rejected");
    assert!(
        err.contains("local-only") && err.contains("jwt"),
        "文案须点明非法取值与合法档位: {err}"
    );
    assert_eq!(registry::count_by_owner(&plugin), 0, "失败零副作用");
}

/// 入站方向零改动：未记录任何网络授权时，`register-endpoint` 仍照旧注册成功
/// （出站策略只管出站方向）
#[test]
fn inbound_registration_is_untouched_by_outbound_policy() {
    let ports = granting(); // 出站一律 `no-record` 拒绝
    let plugin = test_plugin(&format!("inbound-{}", uuid::Uuid::new_v4()));

    let id = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"probe"}"#).expect("inbound must not ask");
    assert!(id.starts_with("http-"));
    purge_for_plugin(&plugin);
}

/// 停用回收只碰本人：另一插件的端点在册者不受影响（停用路径不设权限门）
#[test]
fn purge_for_plugin_touches_only_owner_endpoints() {
    let ports = granting();
    let owner = test_plugin(&format!("owner-{}", uuid::Uuid::new_v4()));
    let bystander = test_plugin(&format!("bystander-{}", uuid::Uuid::new_v4()));

    let owner_id = http_register_endpoint(&as_ports(&ports), &owner, r#"{"path":"a"}"#).expect("register");
    http_register_endpoint(&as_ports(&ports), &bystander, r#"{"path":"b"}"#).expect("register");

    assert_eq!(purge_for_plugin(&owner), 1, "回收数 = 该属主端点数");
    assert!(!registry::is_owner(&owner_id, &owner), "属主端点已摘除");
    assert_eq!(registry::count_by_owner(&bystander), 1, "他人端点不得被动到");

    purge_for_plugin(&bystander);
}
