//! 入站（服务端域）用例组：权限门 / 注册闭环与属主仲裁 / 非法形状零副作用 / 回收只碰本人

use super::scaffold::*;
use super::*;
use crate::registry;
use wasmnest_server_core::link_crypto::EncryptionPolicy;

/// 触碰链路加密全局快照的用例必须串行（本 crate 内只有本组会改它）
static LINK_CRYPTO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

// ==================== 按端点链路加密策略（spec §1 / §2） ====================

/// 未声明 `encryption` → 端点记录 `None`（跟随宿主下限），注册照旧成功
#[test]
fn register_endpoint_without_encryption_follows_host_floor() {
    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ports = granting();
    let plugin = test_plugin(&format!("enc-none-{}", uuid::Uuid::new_v4()));
    let id = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"status"}"#).expect("register");
    let entry = registry::get(&id).expect("registered");
    assert_eq!(entry.encryption, None, "未声明 = 跟随下限（不写死 preferred）");
    purge_for_plugin(&plugin);
}

/// 声明的策略落在端点记录上；取值严格白名单（拼错不允许静默当明文）
#[test]
fn register_endpoint_parses_encryption_strictly() {
    use wasmnest_server_core::link_crypto::{self, LinkCryptoConfig};

    // 下限是进程级快照：本用例假设 floor=off，必须与改路径的用例串行
    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = link_crypto::current_config();
    link_crypto::update_config(LinkCryptoConfig::default());

    let ports = granting();
    let plugin = test_plugin(&format!("enc-parse-{}", uuid::Uuid::new_v4()));

    let id = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"monitor","encryption":"off"}"#)
        .expect("off 在默认下限（off）下允许");
    assert_eq!(registry::get(&id).unwrap().encryption, Some(EncryptionPolicy::Off));

    for bad in ["required-all", "REQUIRED", "plain"] {
        let err = http_register_endpoint(
            &as_ports(&ports),
            &plugin,
            &format!(r#"{{"path":"bad-{bad}","encryption":"{bad}"}}"#),
        )
        .expect_err("未知策略必须拒绝");
        assert!(
            err.contains(bad) && err.contains("required") && err.contains("preferred") && err.contains("off"),
            "文案须点名非法取值与合法取值: {err}"
        );
    }
    // 未知字段同样拒绝：旧解析器静默忽略新字段 = 「以为加密了、实际明文」
    let err = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"typo","encrypton":"required"}"#)
        .expect_err("未知字段必须拒绝");
    assert!(err.contains("encrypton"), "文案须点名未知字段: {err}");

    assert_eq!(registry::count_by_owner(&plugin), 1, "失败不得留下端点");
    purge_for_plugin(&plugin);
    link_crypto::update_config(original);
}

/// 宿主下限更严时 `off` 声明注册失败且零副作用（floor=required）
#[test]
fn register_endpoint_rejects_off_when_floor_is_required() {
    use wasmnest_server_core::link_crypto::{self, LinkCryptoConfig};

    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = link_crypto::current_config();
    link_crypto::update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Required));

    let ports = granting();
    let plugin = test_plugin(&format!("enc-floor-{}", uuid::Uuid::new_v4()));
    let err = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"plain","encryption":"off"}"#)
        .expect_err("floor=required 时 off 必须拒绝");
    assert!(
        err.contains("off") && err.contains("required") && err.contains(&plugin),
        "文案须点名策略 / 下限 / 属主: {err}"
    );
    assert_eq!(registry::count_by_owner(&plugin), 0, "拒绝不得留下端点");
    assert!(
        crate::registry::find_by_internal(&format!("/api/plugin/{plugin}/plain")).is_none(),
        "拒绝不得留下内部路径"
    );

    // preferred 声明允许（生效仍取更严的 required）
    let id = http_register_endpoint(&as_ports(&ports), &plugin, r#"{"path":"ok","encryption":"preferred"}"#)
        .expect("preferred 是向上/持平声明");
    assert_eq!(
        link_crypto::effective_endpoint_policy(&plugin, &id, wasmnest_server_core::filter::TrafficChannel::Http),
        EncryptionPolicy::Required
    );

    purge_for_plugin(&plugin);
    link_crypto::update_config(original);
}
