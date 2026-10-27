//! packages/wasmnest-server-http/src/gateway.rs 的跨分组测试脚手架（用例文件经 `use super::scaffold::*` 引用）

use super::*;

use crate::middleware::auth_gateway::auth_gateway;

/// 注册一条测试别名（全局注册表跨用例共享：路径带用例唯一段）
pub(super) fn register_test_alias(owner: &str, path: &str, host: &str, methods: &[&str], auth: EndpointAuth) {
    let methods: Vec<String> = methods.iter().map(|s| s.to_string()).collect();
    registry::register(owner, path, Some(host), &methods, auth).expect("register test alias");
}

pub(super) fn purge(owner: &str) {
    registry::purge_for_plugin(owner);
}

/// 请求体提取：无载荷 → Null；合法 JSON → 原样；畸形 JSON → 显式失败
#[actix_web::test]
pub(super) async fn body_extraction_distinguishes_empty_from_malformed() {
    let (http_req, mut payload) = actix_web::test::TestRequest::get()
        .uri("/api/configs")
        .to_srv_request()
        .into_parts();
    assert_eq!(body_value(&http_req, &mut payload).await.unwrap(), Value::Null);

    let (http_req, mut payload) = actix_web::test::TestRequest::post()
        .uri("/api/file-tree")
        .insert_header(("content-type", "application/json"))
        .set_json(serde_json::json!({ "session_id": "s-1" }))
        .to_srv_request()
        .into_parts();
    assert_eq!(
        body_value(&http_req, &mut payload).await.unwrap(),
        serde_json::json!({ "session_id": "s-1" })
    );

    let (http_req, mut payload) = actix_web::test::TestRequest::post()
        .uri("/api/file-tree")
        .insert_header(("content-type", "application/json"))
        .set_payload(b"{not json".to_vec())
        .to_srv_request()
        .into_parts();
    let err = body_value(&http_req, &mut payload).await.unwrap_err();
    assert!(err.contains("Invalid JSON body"), "畸形 body 必须显式失败, got: {err}");
}

// ==================== 中间件行为（真实 actix 栈） ====================
/// 组装「认证闸门（外）→ 业务网关（内）→ 哨兵宿主 handler」的最小 `/api` scope
///
/// 两个中间件都取生产实现（`auth_gateway` / `business_gateway`），所以这里验的是真实
/// 链路顺序，不是测试自己搭的近似物。哨兵 handler 复刻宿主自持端点的回包形状。
pub(super) fn test_scope() -> impl actix_web::dev::HttpServiceFactory + 'static {
    use actix_web::middleware::from_fn;
    web::scope("/api")
        .wrap(from_fn(business_gateway))
        .wrap(from_fn(auth_gateway))
        .route("/configs", web::get().to(host_sentinel))
        .route("/git/branches", web::get().to(host_sentinel))
}

/// `Scope::wrap` 的注册顺序语义（app.rs 挂载顺序的依据，第三方 API 的承重假设）
#[actix_web::test]
pub(super) async fn scope_wrap_registration_puts_jwt_outermost() {
    use actix_web::body::MessageBody;
    use actix_web::middleware::{from_fn, Next};
    use std::sync::{Arc, Mutex};

    async fn probe<B>(
        name: &'static str,
        trace: Arc<Mutex<Vec<&'static str>>>,
        req: ServiceRequest,
        next: Next<B>,
    ) -> Result<ServiceResponse, Error>
    where
        B: MessageBody + 'static,
    {
        trace.lock().unwrap().push(name);
        next.call(req).await.map(|res| res.map_into_boxed_body())
    }

    let trace = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let t_gateway = trace.clone();
    let t_jwt = trace.clone();
    let app = actix_web::test::init_service(
        actix_web::App::new().service(
            web::scope("/api")
                .wrap(from_fn(move |req, next| probe("gateway", t_gateway.clone(), req, next)))
                .wrap(from_fn(move |req, next| probe("jwt", t_jwt.clone(), req, next)))
                .route("/x", web::get().to(|| async { HttpResponse::Ok().finish() })),
        ),
    )
    .await;
    actix_web::test::call_service(&app, actix_web::test::TestRequest::get().uri("/api/x").to_request()).await;
    assert_eq!(
        *trace.lock().unwrap(),
        vec!["jwt", "gateway"],
        "最后注册的中间件必须先执行，否则 app.rs 的「先验签后网关」失效"
    );
}

pub(super) async fn host_sentinel() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok_with_data(serde_json::json!({ "configs": [] })))
}

/// 只挂网关（不挂认证中间件）的测试 scope
///
/// v33 起宿主**没有签发面**（`utils/auth/jwt.rs` 已退役），无头单测里拿不到
/// 「能通过认证中间件的凭证」。要单独测网关的转发判定就不能连中间件一起挂——
/// 否则被测的是中间件（它会一律 401），不是网关。
pub(super) fn gateway_only_scope() -> impl actix_web::dev::HttpServiceFactory + 'static {
    use actix_web::middleware::from_fn;
    web::scope("/api")
        .wrap(from_fn(business_gateway))
        .route("/configs", web::get().to(host_sentinel))
}

/// 未验签请求绝不进网关转发：`/api/configs` 无 token → 401（今天的形状）
#[actix_web::test]
pub(super) async fn unverified_requests_never_reach_gateway() {
    let app = actix_web::test::init_service(actix_web::App::new().service(test_scope())).await;
    let resp = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get().uri("/api/configs").to_request(),
    )
    .await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    let body: Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["code"], CODE_PLUGIN_AUTH_FAILED as u64);
}

/// 未登记路径 / 方法不符：网关不介入，状态码与「同一 scope 不挂网关」完全一致
///
/// 用对照组而不是写死 405：`Scope` 挂了中间件之后，actix 对「路径在、方法不在」的
/// 应答并不是教科书上的 405（今天宿主面就是这一格行为）。对照组把标准钉在「与不挂
/// 网关时相同」，比钉一个记错的数字更诚实。
#[actix_web::test]
pub(super) async fn unregistered_and_wrong_method_requests_are_not_touched() {
    use std::str::FromStr;

    let gateway_only = actix_web::test::init_service(
        actix_web::App::new().service(
            web::scope("/api")
                .wrap(actix_web::middleware::from_fn(business_gateway))
                .route("/configs", web::get().to(host_sentinel))
                .route("/git/branches", web::get().to(host_sentinel)),
        ),
    )
    .await;
    let baseline = actix_web::test::init_service(
        actix_web::App::new().service(
            web::scope("/api")
                .route("/configs", web::get().to(host_sentinel))
                .route("/git/branches", web::get().to(host_sentinel)),
        ),
    )
    .await;

    for (method, uri) in [
        ("POST", "/api/configs"),
        ("GET", "/api/not-a-business-endpoint"),
        ("PUT", "/api/git/branches?session_id=s-1"),
        ("DELETE", "/api/git/checkout"),
    ] {
        let mk = || {
            actix_web::test::TestRequest::default()
                .method(actix_web::http::Method::from_str(method).unwrap())
                .uri(uri)
                .to_request()
        };
        let with = actix_web::test::call_service(&gateway_only, mk()).await;
        let without = actix_web::test::call_service(&baseline, mk()).await;
        assert_eq!(
            with.status(),
            without.status(),
            "{method} {uri}：挂上网关后的状态码必须与不挂时一致（网关不得介入）"
        );
    }
}

/// 已登记别名 + 无 AppContext（无头/测试：插件面不可判定）→ 原样放行（哨兵应答）
///
/// 只挂网关：本用例的被测对象是**网关的转发判定**（插件面不可判定时原样放行），
/// 认证中间件不在链路里——无头上下文里没有认证中心，整条链上任何凭证都过不了
/// 认证（fail-closed），把它一起挂上就变成在测中间件了。
#[actix_web::test]
pub(super) async fn registered_alias_falls_through_when_plugin_surface_unavailable() {
    let owner = "test-gw-fallthrough";
    register_test_alias(owner, "configs", "/api/configs", &["GET"], EndpointAuth::Jwt);
    let app = actix_web::test::init_service(actix_web::App::new().service(gateway_only_scope())).await;
    let resp = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get().uri("/api/configs").to_request(),
    )
    .await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let body: Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(
        body,
        serde_json::json!({ "code": 0, "message": "ok", "data": { "configs": [] } }),
        "无 AppContext 时不得把请求交给不存在的插件（原样放行）"
    );
    purge(owner);
}

/// 「插件未激活」响应形状：HTTP 200 + `{code:1007,message}`，与既有未激活响应同口径
#[actix_web::test]
pub(super) async fn plugin_required_response_keeps_existing_error_shape() {
    let entry = registry::register(
        "test-gw-shape",
        "configs",
        Some("/api/configs-shape"),
        &["GET".to_string()],
        EndpointAuth::Jwt,
    )
    .expect("register");
    let resp = plugin_unavailable_response(&entry);
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let ct = resp
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        ct.starts_with("application/json"),
        "错误响应必须是 JSON 信封, got: {ct}"
    );
    let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "code": CODE_PLUGIN_AUTH_FAILED,
            "message": "Plugin test-gw-shape is not activated",
        })
    );
    purge("test-gw-shape");
}

/// 票 08：「要验签而未验签」的响应形状是 401 + 1007 + 点名对外路径
#[actix_web::test]
pub(super) async fn auth_required_response_says_authentication_not_activation() {
    let resp = unauthorized_response("/api/configs");
    assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], CODE_PLUGIN_AUTH_FAILED as u64);
    assert_eq!(
        json["message"],
        serde_json::json!("Authentication required for /api/configs"),
        "文案按对外别名路径说，不暴露插件端点段"
    );
    assert!(
        !json["message"].as_str().unwrap_or_default().contains("not activated"),
        "不得把未登录报成插件未激活"
    );
}

/// 降级分支不消费 payload：网关若在判定阶段读 body，宿主 handler 就会拿到空载荷并
/// 400——那是最隐蔽的「实现搬走、行为变味」形态，故单列一条。
#[actix_web::test]
pub(super) async fn fallback_branch_leaves_the_payload_intact() {
    async fn echo(body: web::Json<Value>) -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({ "echo": body.0 }))
    }
    let owner = "test-gw-payload";
    register_test_alias(owner, "file-tree", "/api/file-tree", &["POST"], EndpointAuth::Jwt);
    let app = actix_web::test::init_service(
        actix_web::App::new().service(
            web::scope("/api")
                .wrap(actix_web::middleware::from_fn(business_gateway))
                .route("/file-tree", web::post().to(echo)),
        ),
    )
    .await;
    let resp = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/api/file-tree")
            .insert_header(("content-type", "application/json"))
            .set_json(serde_json::json!({ "session_id": "s-9", "depth": 3 }))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let body: Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["echo"]["session_id"], "s-9");
    assert_eq!(body["echo"]["depth"], 3);
    purge(owner);
}

pub(super) fn assert_shape<T: serde::Serialize>(value: ApiResponse<T>, expected: Value) {
    assert_eq!(
        serde_json::to_value(&value).expect("DTO 必须可序列化"),
        expected,
        "响应形状漂移：移动端会看到不同字节"
    );
}
