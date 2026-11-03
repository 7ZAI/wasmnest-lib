//! 服务端域（票 05：注册 / 查询 / 属主仲裁 / 回收）

use super::scaffold::*;
use super::*;
use wasmnest_server_base::constants::PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN;

#[tokio::test]
async fn register_endpoint_validates_shape_and_auth() {
    let plugin = test_plugin("ep-shape");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);

    // path 校验先行（契约形状尽早暴露拼装错误）
    assert!(ws_register_endpoint(&ports, &plugin, r#"{"path":""}"#)
        .unwrap_err()
        .contains("must not be empty"));
    assert!(ws_register_endpoint(&ports, &plugin, r#"{"path":"a/b"}"#)
        .unwrap_err()
        .contains("must not contain"));
    assert!(ws_register_endpoint(&ports, &plugin, r#"{"path":".."}"#)
        .unwrap_err()
        .contains("must not contain"));
    let too_long = "x".repeat(PLUGIN_WS_ENDPOINT_PATH_MAX_LEN + 1);
    assert!(
        ws_register_endpoint(&ports, &plugin, &format!(r#"{{"path":"{too_long}"}}"#))
            .unwrap_err()
            .contains("too long")
    );
    // 非法 JSON / 未定义 auth 取值 → 报错（认证策略绝不静默降级为 none）
    assert!(ws_register_endpoint(&ports, &plugin, "not json").is_err());
    assert!(
        ws_register_endpoint(&ports, &plugin, r#"{"path":"chat","auth":"token"}"#)
            .unwrap_err()
            .contains("unknown auth")
    );
    assert_eq!(crate::endpoint::count_by_owner(&plugin), 0, "校验失败零副作用");

    // 两种合法策略都能注册（缺省 = none）
    let open = register_endpoint(&ports, &plugin, "open");
    let guarded = ws_register_endpoint(&ports, &plugin, r#"{"path":"guarded","auth":"jwt"}"#).expect("jwt endpoint");
    assert_eq!(
        crate::endpoint::get(&open).unwrap().auth,
        EndpointAuth::None,
        "缺省 auth = none"
    );
    assert_eq!(crate::endpoint::get(&guarded).unwrap().auth, EndpointAuth::Jwt);

    drop_endpoint(&open);
    drop_endpoint(&guarded);
}

#[tokio::test]
async fn register_endpoint_returns_handle_and_lists_it() {
    let plugin = test_plugin("ep-roundtrip");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);

    let endpoint = register_endpoint(&ports, &plugin, "chat");
    assert!(endpoint.starts_with("wse-"), "句柄前缀 wse-，got: {endpoint}");

    // 完整挂载路径由插件侧推导（宿主注入属主命名空间段，spec D5）
    let entry = crate::endpoint::get(&endpoint).expect("endpoint exists");
    assert_eq!(entry.owner, plugin);
    assert_eq!(entry.mount_path, format!("/ws/plugin/{plugin}/chat"));

    // list-endpoints：`[{ endpointId, path, clientCount }]`
    let listed: Vec<serde_json::Value> = serde_json::from_str(&ws_list_endpoints(&ports, &plugin).unwrap()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["endpointId"], endpoint);
    assert_eq!(listed[0]["path"], "chat");
    assert_eq!(listed[0]["clientCount"], 0);

    // 注销：命中 true → 清单清空 → 幂等 false
    assert!(ws_unregister_endpoint(&ports, &plugin, &endpoint).unwrap());
    assert_eq!(ws_list_endpoints(&ports, &plugin).unwrap(), "[]");
    assert!(!ws_unregister_endpoint(&ports, &plugin, &endpoint).unwrap());
}

#[tokio::test]
async fn register_endpoint_conflict_and_limit_are_side_effect_free() {
    let plugin = test_plugin("ep-limit");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);
    let limit = PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN;

    let mut ids = vec![register_endpoint(&ports, &plugin, "chat")];
    // 同插件同后缀 → 冲突拒绝（端点表按完整挂载路径判定）
    assert!(ws_register_endpoint(&ports, &plugin, r#"{"path":"chat"}"#)
        .unwrap_err()
        .contains("already registered"));
    // 同插件不同后缀可用
    ids.push(register_endpoint(&ports, &plugin, "lobby"));

    let mut i = ids.len();
    while crate::endpoint::count_by_owner(&plugin) < limit {
        ids.push(register_endpoint(&ports, &plugin, &format!("p{i}")));
        i += 1;
    }
    // 超限 → Err 且无副作用
    assert!(ws_register_endpoint(&ports, &plugin, &format!(r#"{{"path":"p{i}"}}"#))
        .unwrap_err()
        .contains("endpoint limit reached"));
    assert_eq!(
        crate::endpoint::count_by_owner(&plugin),
        limit,
        "超限拒绝不得留下副作用"
    );

    for id in ids {
        drop_endpoint(&id);
    }
}

#[tokio::test]
async fn server_domain_cross_owner_access_is_rejected() {
    let owner = test_plugin("ep-owner");
    let intruder = test_plugin("ep-intruder");
    let owner_ports: Arc<dyn WsPorts> = FakePorts::with(&[(&owner, PERMISSION_WS_SERVER)]);
    let intruder_ports: Arc<dyn WsPorts> = FakePorts::with(&[(&intruder, PERMISSION_WS_SERVER)]);
    let endpoint = register_endpoint(&owner_ports, &owner, "chat");

    // 属主仲裁：他人端点上的一切操作一律拒绝（跨插件不可互操作）
    let results = [
        ws_send_text_to_client(&intruder_ports, &intruder, &endpoint, "c-1", "hi").map(|_| ()),
        ws_send_binary_to_client(&intruder_ports, &intruder, &endpoint, "c-1", b"hi").map(|_| ()),
        ws_broadcast_text(&intruder_ports, &intruder, &endpoint, "hi").map(|_| ()),
        ws_broadcast_binary(&intruder_ports, &intruder, &endpoint, b"hi").map(|_| ()),
        ws_close_client(&intruder_ports, &intruder, &endpoint, "c-1", "{}").map(|_| ()),
        ws_list_clients(&intruder_ports, &intruder, &endpoint).map(|_| ()),
    ];
    for result in results {
        assert_eq!(result.unwrap_err(), NOT_ENDPOINT_OWNER, "跨属主必须拒绝");
    }
    // 注销同样仲裁，且拒绝不得摘除端点
    assert_eq!(
        ws_unregister_endpoint(&intruder_ports, &intruder, &endpoint).unwrap_err(),
        NOT_ENDPOINT_OWNER
    );
    assert!(crate::endpoint::get(&endpoint).is_some(), "拒绝不得消费端点");
    // 属主本人可用（无在线客户端 → 清单空数组，计数 0）
    assert_eq!(ws_list_clients(&owner_ports, &owner, &endpoint).unwrap(), "[]");
    assert_eq!(ws_broadcast_text(&owner_ports, &owner, &endpoint, "hi").unwrap(), 0);

    drop_endpoint(&endpoint);
}

#[tokio::test]
async fn server_domain_unknown_endpoint_is_idempotent() {
    let plugin = test_plugin("ep-unknown");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);

    // 未注册端点：单发 / 广播 / 清单 → Err（fail-visible，不静默成功）
    assert!(ws_send_text_to_client(&ports, &plugin, "wse-none", "c-1", "hi")
        .unwrap_err()
        .contains("not found"));
    assert!(ws_send_binary_to_client(&ports, &plugin, "wse-none", "c-1", b"hi")
        .unwrap_err()
        .contains("not found"));
    assert!(ws_broadcast_text(&ports, &plugin, "wse-none", "hi")
        .unwrap_err()
        .contains("not found"));
    assert!(ws_list_clients(&ports, &plugin, "wse-none")
        .unwrap_err()
        .contains("not found"));
    // 注销是幂等查询：未知端点 → false（不 panic）
    assert!(!ws_unregister_endpoint(&ports, &plugin, "wse-none").unwrap());

    // 端点存在但客户端不在其名下 → 踢出 Ok(false)（寻址错配不消费端点）
    let endpoint = register_endpoint(&ports, &plugin, "chat");
    assert!(!ws_close_client(&ports, &plugin, &endpoint, "c-missing", "{}").unwrap());
    // 非法 close-json → Err（不静默用缺省码）
    assert!(ws_close_client(&ports, &plugin, &endpoint, "c-missing", "not json").is_err());
    assert_eq!(ws_broadcast_binary(&ports, &plugin, &endpoint, b"hi").unwrap(), 0);

    drop_endpoint(&endpoint);
}

#[tokio::test]
async fn purge_for_plugin_removes_only_owner_endpoints() {
    let victim = test_plugin("ep-purge");
    let bystander = test_plugin("ep-purge-bystander");
    let victim_ports: Arc<dyn WsPorts> = FakePorts::with(&[(&victim, PERMISSION_WS_SERVER)]);
    let bystander_ports: Arc<dyn WsPorts> = FakePorts::with(&[(&bystander, PERMISSION_WS_SERVER)]);
    let victim_endpoint = register_endpoint(&victim_ports, &victim, "chat");
    let bystander_endpoint = register_endpoint(&bystander_ports, &bystander, "chat");

    purge_for_plugin(&victim, &victim_ports);

    assert!(crate::endpoint::get(&victim_endpoint).is_none(), "本人端点随停用回收");
    assert!(crate::endpoint::get(&bystander_endpoint).is_some(), "他人端点不受影响");
    // 幂等：再次回收无命中
    assert_eq!(purge_for_plugin(&victim, &victim_ports), 0);

    drop_endpoint(&bystander_endpoint);
}

// ==================== 按端点链路加密策略（spec §1 / §2） ====================

/// 触碰链路加密全局快照的用例必须串行
static LINK_CRYPTO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 未声明 `encryption` → 端点记录 `None`（跟随宿主下限）；声明值落在记录上；
/// 未知取值 / 未知字段一律注册失败且零副作用
#[tokio::test]
async fn register_endpoint_parses_encryption_strictly() {
    use wasmnest_server_core::link_crypto::{self, LinkCryptoConfig};

    // 下限是进程级快照：本用例假设 floor=off，必须与改路径的用例串行
    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = link_crypto::current_config();
    link_crypto::update_config(LinkCryptoConfig::default());

    let plugin = test_plugin("ep-enc");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);

    let follow = register_endpoint(&ports, &plugin, "follow");
    assert_eq!(
        crate::endpoint::get(&follow).unwrap().encryption,
        None,
        "未声明 = 跟随宿主下限"
    );

    let plain = ws_register_endpoint(&ports, &plugin, r#"{"path":"plain","encryption":"off"}"#)
        .expect("默认下限（off）下 off 声明允许");
    assert_eq!(
        crate::endpoint::get(&plain).unwrap().encryption,
        Some(wasmnest_server_core::link_crypto::EncryptionPolicy::Off)
    );

    for bad in ["required-all", "REQUIRED", "plain"] {
        let err = ws_register_endpoint(
            &ports,
            &plugin,
            &format!(r#"{{"path":"bad-{bad}","encryption":"{bad}"}}"#),
        )
        .expect_err("未知策略必须拒绝");
        assert!(
            err.contains(bad) && err.contains("required") && err.contains("preferred") && err.contains("off"),
            "文案须点名非法取值与合法取值: {err}"
        );
    }
    let err = ws_register_endpoint(&ports, &plugin, r#"{"path":"typo","encrypton":"required"}"#)
        .expect_err("未知字段必须拒绝");
    assert!(err.contains("encrypton"), "文案须点名未知字段: {err}");
    assert!(crate::endpoint::find_by_mount(&crate::endpoint::mount_path(&plugin, "typo")).is_none());

    // 清理（全局端点表跨用例共享）
    for entry in crate::endpoint::list_by_owner(&plugin) {
        crate::endpoint::remove(&entry.endpoint_id);
    }
    link_crypto::update_config(original);
}

/// 宿主下限更严时 `off` 声明注册失败且零副作用（floor=required）
#[tokio::test]
async fn register_endpoint_rejects_off_when_floor_is_required() {
    use wasmnest_server_core::link_crypto::{self, EncryptionPolicy, LinkCryptoConfig};

    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = link_crypto::current_config();
    link_crypto::update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Required));

    let plugin = test_plugin("ep-floor");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);
    let err = ws_register_endpoint(&ports, &plugin, r#"{"path":"plain","encryption":"off"}"#)
        .expect_err("floor=required 时 off 必须拒绝");
    assert!(
        err.contains("off") && err.contains("required") && err.contains(&plugin),
        "文案须点名策略 / 下限 / 属主: {err}"
    );
    assert_eq!(crate::endpoint::count_by_owner(&plugin), 0, "拒绝不得留下端点");

    // preferred 声明允许，生效值取更严的 required
    let id = ws_register_endpoint(&ports, &plugin, r#"{"path":"ok","encryption":"preferred"}"#)
        .expect("preferred 是向上/持平声明");
    assert_eq!(
        link_crypto::effective_endpoint_policy(&plugin, &id, wasmnest_server_core::filter::TrafficChannel::WsPlugin),
        EncryptionPolicy::Required
    );

    for entry in crate::endpoint::list_by_owner(&plugin) {
        crate::endpoint::remove(&entry.endpoint_id);
    }
    link_crypto::update_config(original);
}

/// 宿主下限运行期调严 → WS 协议升级前即拒绝（生效策略判据，spec §5 Phase 2）
///
/// 回归：routes 曾直接读端点声明值（`entry.encryption == Some(Required)`），
/// 下限调严后「声明 off 的存量端点」会先完成升级、再被帧过滤器断开——
/// 与「不建立一条随后必被断开的连接」的判据相悖。判据必须是
/// `strictest(floor, declared)`，且错误文案点名生效策略 / 声明值 / 端点。
#[tokio::test]
async fn ws_upgrade_rejects_required_effective_policy_from_floor() {
    use actix_web::{test, App};
    use wasmnest_server_core::link_crypto::{self, EncryptionPolicy, LinkCryptoConfig};

    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = link_crypto::current_config();
    let plugin = test_plugin("ep-floor-gate");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);

    // 下限 off 时声明 off 合法；随后宿主设置页把下限调严（运行期动作）
    link_crypto::update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Off));
    let endpoint = ws_register_endpoint(&ports, &plugin, r#"{"path":"gated","encryption":"off"}"#)
        .expect("floor=off 时 off 声明允许");
    link_crypto::update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Required));

    let app = test::init_service(App::new().configure(crate::routes::configure_routes)).await;
    let req = test::TestRequest::get()
        .uri(&crate::endpoint::mount_path(&plugin, "gated"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    let body = test::read_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("effective policy 'required'"),
        "错误须点名生效策略（下限调严）: {text}"
    );
    assert!(text.contains("declared 'off'"), "错误须点名端点声明值: {text}");
    assert!(text.contains(&endpoint), "错误须点名端点句柄: {text}");

    drop_endpoint(&endpoint);
    link_crypto::update_config(original);
}
