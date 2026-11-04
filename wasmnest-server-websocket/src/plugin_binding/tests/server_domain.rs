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

// ==================== 链路加密契约（按应用策略，端点不声明） ====================

/// 触碰链路加密全局策略表的用例必须串行
static LINK_CRYPTO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 链路身份就绪（`required` 策略要求本进程可加密）
fn ready_identity() {
    let dir = tempfile::tempdir().unwrap();
    wasmnest_server_core::link_crypto::init_identity(dir.path()).unwrap();
}

/// 旧的端点级 `encryption` 字段必须显性拒绝，不得被静默忽略
#[tokio::test]
async fn register_endpoint_rejects_legacy_encryption_field() {
    let plugin = test_plugin("ep-legacy-enc");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);

    let err = ws_register_endpoint(&ports, &plugin, r#"{"path":"legacy","encryption":"required"}"#)
        .expect_err("端点级 encryption 字段已退役，必须显性拒绝");
    assert!(err.contains("encryption"), "文案须点名未知字段: {err}");
    assert!(
        crate::endpoint::find_by_mount(&crate::endpoint::mount_path(&plugin, "legacy")).is_none(),
        "拒绝不得留下端点"
    );
}

/// WS 会话握手已实现：`required` 应用注册 WS 端点不再被注册期拦截
///
/// 升级期协商能拒无提案客户端（见 `ws_upgrade_rejects_required_app_policy`），
/// 因此注册阶段不得再制造死端点以外的第二道拒绝。
#[tokio::test]
async fn register_endpoint_allows_required_app_policy() {
    use wasmnest_server_core::link_crypto::{self, EncryptionPolicy};

    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ready_identity();
    let plugin = test_plugin("ep-policy-required");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);
    link_crypto::set_app_policy(&plugin, EncryptionPolicy::Required).expect("required 策略");

    let endpoint = ws_register_endpoint(&ports, &plugin, r#"{"path":"gated"}"#)
        .expect("required 应用可以注册 WS 端点（升级期协商负责门禁）");
    assert_eq!(crate::endpoint::count_by_owner(&plugin), 1);

    drop_endpoint(&endpoint);
    link_crypto::remove_app_policy(&plugin);
}

/// 应用策略 required → 无提案的 WS 升级在协议升级前即拒绝
/// （不建立一条随后必被帧过滤器断开的连接）
#[tokio::test]
async fn ws_upgrade_rejects_required_app_policy() {
    use actix_web::{test, App};
    use wasmnest_server_core::link_crypto::{self, EncryptionPolicy};

    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ready_identity();

    let plugin = test_plugin("ep-policy-gate");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);
    let endpoint = ws_register_endpoint(&ports, &plugin, r#"{"path":"gated"}"#).expect("register");
    link_crypto::set_app_policy(&plugin, EncryptionPolicy::Required).expect("required 策略");

    let app = test::init_service(App::new().configure(crate::routes::configure_routes)).await;
    let req = test::TestRequest::get()
        .uri(&crate::endpoint::mount_path(&plugin, "gated"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    let body = test::read_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("app policy 'required'"), "错误须点名应用策略: {text}");
    assert!(text.contains("X-WasmNest-Crypto"), "错误须点名协商头: {text}");
    assert!(text.contains(&endpoint), "错误须点名端点句柄: {text}");
    assert!(text.contains(&plugin), "错误须点名属主: {text}");

    drop_endpoint(&endpoint);
    link_crypto::remove_app_policy(&plugin);
}

/// 带了协商头但形状非法 → 显性 400（不得按「未提案」静默处理）
#[tokio::test]
async fn ws_upgrade_rejects_malformed_offer() {
    use actix_web::{test, App};

    let plugin = test_plugin("ep-policy-malformed");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[(&plugin, PERMISSION_WS_SERVER)]);
    let endpoint = ws_register_endpoint(&ports, &plugin, r#"{"path":"bad-offer"}"#).expect("register");

    let app = test::init_service(App::new().configure(crate::routes::configure_routes)).await;
    let req = test::TestRequest::get()
        .uri(&crate::endpoint::mount_path(&plugin, "bad-offer"))
        .insert_header(("X-WasmNest-Crypto", "v2 QUJD"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    let text = String::from_utf8_lossy(&test::read_body(resp).await).to_string();
    assert!(
        text.contains("invalid 'X-WasmNest-Crypto'"),
        "错误须点名非法协商头: {text}"
    );

    drop_endpoint(&endpoint);
}

// ==================== 升级期协商：真链路（101 头 + 帧加解密） ====================

/// 取本机非环回地址（UDP connect 只做路由选择，不发包）
fn primary_non_loopback_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback()).then_some(ip)
}

/// required + 合法提案：101 带策略/会话密钥头，注册的会话密码能解入站帧、加出站帧
///
/// 真链路只钉「升级响应头 + 密码注册 + 过滤器字节面」三件事：
/// - 101 的 policy 头恒有、session key 仅接受提案时下发；
/// - 服务端按对端 addr 注册密码（与过滤器查询键同源）；
/// - 客户端 `ClientWsCrypto` 与服务端过滤器能在 `ws-plugin` 通道上互通
///   （入站解出明文 / 出站被加密后客户端能解开）。
///
/// 帧投递到插件的路径依赖宿主运行时端口（无头上下文不派生投递任务），
/// 由 channel/plugin 的既有用例覆盖，这里不重复。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_upgrade_negotiates_session_and_roundtrips_frames() {
    use actix_web::{App, HttpServer};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::MaybeTlsStream;
    use wasmnest_server_core::filter::{Direction, FilterContext, TrafficChannel, TrafficFilterChain};
    use wasmnest_server_core::link_crypto::{self, ClientWsCrypto, EncryptionPolicy};

    let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ready_identity();
    let (_, kd_public_b64) = link_crypto::identity_parts().expect("identity parts");

    let plugin = test_plugin("ep-policy-negotiated");
    let endpoint = crate::endpoint::register(
        &plugin,
        "gated",
        crate::endpoint::EndpointAuth::None,
        None,
        None,
        Arc::new(TestBus) as Arc<dyn wasmnest_server_base::ports::BusPort>,
    )
    .expect("register endpoint");
    link_crypto::set_app_policy(&plugin, EncryptionPolicy::Required).expect("required 策略");

    // 必须从**非环回**地址连接：环回与 HTTP 面同口径豁免（不要求协商），
    // 否则本例会在 policy 门禁前就走本地明文分支。
    let Some(bind_ip) = primary_non_loopback_ip() else {
        eprintln!("skipping: no non-loopback interface available");
        drop_endpoint(&endpoint.endpoint_id);
        link_crypto::remove_app_policy(&plugin);
        return;
    };

    // 真 HTTP 服务器（actix System 独占线程；结束时 stop 并回收线程）
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let server_thread = std::thread::spawn(move || {
        let system = actix_web::rt::System::new();
        system.block_on(async move {
            let server = HttpServer::new(|| App::new().configure(crate::routes::configure_routes))
                .workers(1)
                .bind((bind_ip, 0))
                .expect("bind test server");
            let addr = server.addrs()[0];
            let server = server.run();
            ready_tx.send((addr, server.handle())).expect("send server addr");
            if let Err(error) = server.await {
                eprintln!("test ws server stopped with error: {error}");
            }
        });
    });
    let (addr, server_handle) = ready_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("test ws server ready");

    // 客户端升级：带临时公钥提案
    let (m_priv, m_pub) = link_crypto::generate_ephemeral();
    let m_ek_b64 = link_crypto::b64_encode(&m_pub);
    let mut request = format!("ws://{addr}{}", crate::endpoint::mount_path(&plugin, "gated"))
        .into_client_request()
        .expect("client request");
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::HeaderName::from_static("x-wasmnest-crypto"),
        tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!("v1 {m_ek_b64}")).expect("offer header"),
    );
    let (mut ws, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("upgrade must be accepted");

    assert_eq!(
        response
            .headers()
            .get("x-wasmnest-crypto-policy")
            .and_then(|v| v.to_str().ok()),
        Some("required"),
        "101 必须回策略头"
    );
    let s_ek_b64 = response
        .headers()
        .get("x-wasmnest-crypto")
        .and_then(|v| v.to_str().ok())
        .and_then(link_crypto::parse_negotiation)
        .expect("101 must carry the server session key");

    // 服务端按「客户端源地址」注册了密码（过滤器查询键 = 同一 addr）
    let peer = match ws.get_ref() {
        MaybeTlsStream::Plain(stream) => stream.local_addr().expect("client local addr").to_string(),
        _ => panic!("plain ws expected"),
    };
    assert!(
        link_crypto::ws_has_ciphers(&peer),
        "升级接受提案后必须为对端地址注册会话密码"
    );

    let kd_public: [u8; 32] = link_crypto::b64_decode(&kd_public_b64)
        .expect("pin b64")
        .try_into()
        .expect("pin length");
    let mut crypto = ClientWsCrypto::derive(&m_priv, &m_ek_b64, s_ek_b64, &kd_public).expect("client derive");

    // 入站：客户端密封 → 过滤器解出明文（插件看到的是明文，不是信封）
    //
    // 不真的把帧发给服务器 actor：帧投递依赖宿主运行时端口（无头上下文不派生），
    // 且 actor 解密会推进服务端接收序号，使下面的字节面断言产生时序耦合。
    // 这里直接驱动同一个全局过滤器，确定性验证「注册的密码 ↔ 客户端派生」互通。
    let chain = TrafficFilterChain::global();
    let mut inbound = FilterContext {
        channel: TrafficChannel::WsPlugin,
        direction: Direction::Inbound,
        peer: &peer,
        route: "text",
        owner: &plugin,
        endpoint: &endpoint.endpoint_id,
        negotiation: "",
        data: crypto
            .seal_text(link_crypto::WS_PLUGIN_CHANNEL, "hello-sealed")
            .expect("seal frame again")
            .into_bytes(),
        outbound_headers: Vec::new(),
    };
    chain.run_inbound(&mut inbound).expect("inbound must decrypt");
    assert_eq!(inbound.data, b"hello-sealed");

    // 出站：过滤器加密 → 客户端用同一会话解开（序号从 0 起）
    let mut outbound = FilterContext {
        channel: TrafficChannel::WsPlugin,
        direction: Direction::Outbound,
        peer: &peer,
        route: "text",
        owner: &plugin,
        endpoint: &endpoint.endpoint_id,
        negotiation: "",
        data: b"reply-plain".to_vec(),
        outbound_headers: Vec::new(),
    };
    chain.run_outbound(&mut outbound).expect("outbound must encrypt");
    let opened = crypto
        .open_text(
            link_crypto::WS_PLUGIN_CHANNEL,
            std::str::from_utf8(&outbound.data).expect("envelope is utf-8 json"),
        )
        .expect("client must decrypt outbound");
    assert_eq!(opened, "reply-plain");

    let _ = ws.close(None).await;
    server_handle.stop(true).await;
    let _ = server_thread.join();
    drop_endpoint(&endpoint.endpoint_id);
    link_crypto::remove_app_policy(&plugin);
}
