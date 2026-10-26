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
