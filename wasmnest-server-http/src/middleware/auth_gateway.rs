//! HTTP 网关中间件 — 认证
//!
//! 挂载在 /api scope 上，统一拦截认证：
//! - /api/health 等宿主自持公开端点 — 放行
//! - /api/plugin/* — 有凭证就问认证中心；无凭证一律**放行到 handler**，
//!   由 handler 按**端点声明的档位**决定要不要真的到达插件（票 08）：manifest
//!   `contributes.httpEndpoints` 未声明 `auth` 即最严档 `jwt`（无凭证 → 401），
//!   免凭证必须逐条显式声明 `auth: "none"`（环回 hook 脚本无法持有凭证，正是这一格）。
//!   本中间件不做端点级判定，因为它还不知道属主插件是谁（旧前缀兜底在 handler 里解）。
//! - 其余 /api/* — 必须通过认证中心裁决
//!
//! 信任边界：服务监听 BIND_ADDRESS（0.0.0.0）。票 08 前「局域网内任意设备可无凭证
//! 调用已激活插件的 HTTP 端点（含写操作）」；现在这一面由插件的逐端点声明承担——
//! 未显式声明 `auth: "none"` 的端点要求验签，且插件拿得到宿主判定的调用方身份
//! （`caller` = device / localhost / anonymous）用于自行收紧。
//!
//! **验签执行点 = 认证中心**（v33 / ADR 0033）：宿主不再持有任何设备 JWT 密码学
//! （`utils/auth/jwt.rs` 已退役），本中间件**只问中心一次**——中心内部先验签再
//! 逐条做策略，成功时交回连接身份注入 request extensions，handler 经
//! [`get_authenticated_identity`] 提取。裁决 **fail-closed**（ADR 0031 v32）：
//! 无中心在册 / 中心调用失败 / 中心拒绝 → 一律拒绝（`deny_kind` 分
//! no_center / unavailable / policy）。唯一例外是端口注册表未注入（无头 /
//! 单测上下文）时整段跳过——生产运行期由宿主 bootstrap 注入，恒在，这不构成部署降级路径。

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{Error, HttpMessage, HttpResponse};
use serde_json::json;

use wasmnest_server_base::identity::AuthenticatedIdentity;

/// 从 request extensions 提取认证中心交回的连接身份
///
/// 供 handler 使用：中间件裁决通过后身份已注入
pub fn get_authenticated_identity(req: &actix_web::HttpRequest) -> Option<AuthenticatedIdentity> {
    req.extensions().get::<AuthenticatedIdentity>().cloned()
}

/// 从 Authorization header 取 Bearer 凭证（纯解析，不做任何判定）
///
/// 只认逐字 `Bearer ` 前缀（大小写敏感）：宽松接受 `bearer` / `Token` 会让凭证
/// 提取这一层变成「猜 scheme」，而 scheme 是线协议的一部分（移动端只发 Bearer）。
fn bearer_credential(req: &actix_web::dev::ServiceRequest) -> Option<&str> {
    let auth_header = req.headers().get("Authorization")?.to_str().ok()?;
    auth_header.strip_prefix("Bearer ")
}

/// 从 Authorization header 取凭证并问认证中心裁决一次
///
/// 名字里的「认证」指**问中心**而不是本地验签：v33（ADR 0033）后宿主没有验签面，
/// 本函数只做「提取 Bearer 凭证 → 交给中心」两件事（凭证形状对宿主不透明）。
/// 返回 `Some(identity)` = 中心放行（身份注入 extensions）；`None` = 无凭证 /
/// 中心拒绝（原因已由 [`enforce_connection_policy`] 打点，结构化字段 `deny_kind`）。
pub fn authenticate_with_center(req: &actix_web::dev::ServiceRequest) -> Option<AuthenticatedIdentity> {
    authenticate(bearer_credential(req)?)
}

/// 问认证中心裁决一次（无中心 / 调用失败 / 拒绝 / 身份不可用 → `None`）
///
/// 验签 + 策略都在中心内部（ADR 0033），故这里是**唯一**的认证入口，不再有
/// 「先本地验签、再问策略」两步。仅当端口注册表未注入（无头 / 单测）才放行——生产
/// 运行期不存在「查不到中心就放行」的分支。
fn authenticate(token: &str) -> Option<AuthenticatedIdentity> {
    // 宿主壳注入的 AuthCenter 端口：无端口（无头/单测）即无中心可问 → None
    // （生产运行期不存在此路径，与既有「无端口注册表 → 跳过」分支同语义）
    let Some(ports) = wasmnest_server_base::ports::get() else {
        return None;
    };
    match ports.auth_center.enforce_connection_policy(token) {
        Ok(identity) => Some(identity),
        Err(reason) => {
            tracing::warn!(%reason, "HTTP /api request denied by auth center");
            None
        }
    }
}

/// 判断请求路径是否属于宿主自持公开端点（无需认证）
///
/// 只含**宿主自有**公开面：`/api/health`（健康检查）与 `/health`（历史别名）。
/// 插件注册的公开别名（`auth: "none"`）**不走本函数**——公开判定统一走动态
/// 注册表档位（ABI v29 路由下沉，见 [`auth_gateway`] 的注册表查询），精确匹配非前缀。
pub fn is_public_path(path: &str) -> bool {
    path == "/api/health" || path == "/health"
}

/// 判断请求路径是否属于插件端点
///
/// 插件端点**有凭证就问中心**（身份注入后由 handler 按端点档位判定）；无凭证的
/// 请求放行到 handler——端点级认证在 `plugin_controller::plugin_http_endpoint`，
/// 不在这里（本层还解析不出属主插件，旧前缀兜要按接管方的声明判）。
pub fn is_plugin_path(path: &str) -> bool {
    path.starts_with("/api/plugin/")
}

/// HTTP 网关中间件（`/api` scope）：认证通过注入身份，否则按路径规则放行 / 401
///
/// 从 `crate::routes`（本 crate 路由装配）里提出来成为具名中间件，目的是让「协议网关挂在认证之后」
/// 这一顺序约束可被真实 actix 栈测到（见本 crate `gateway.rs` 的中间件用例），而不是靠注释
/// 约定。认证判定本身**下沉到认证中心**（ADR 0033），本层只做「问中心 + 注入 / 放行」。
pub(crate) async fn auth_gateway<B>(req: ServiceRequest, next: Next<B>) -> Result<ServiceResponse, Error>
where
    B: MessageBody + 'static,
{
    let path = req.path().to_string();
    let method = req.method().as_str().to_string();

    // 宿主自持公开端点（/api/health）直接放行
    if is_public_path(&path) {
        return next.call(req).await.map(|res| res.map_into_boxed_body());
    }

    // 插件注册别名（ABI v29 动态路由）：公开判定走注册表档位——`auth: "none"` 即公开
    // （免验签放行到网关转发，精确/模板匹配非前缀），`jwt` 档与未登记路径一律要求验签。
    // 与网关的档位判定同表同源：这里放行的只是「免凭证可达」的公开档，网关仍会做
    // 属主激活与转发判定（双保险）。
    if let Some(host_match) = crate::registry::find_by_host(&path, &method) {
        if host_match.entry.auth == crate::wire::EndpointAuth::None {
            return next.call(req).await.map(|res| res.map_into_boxed_body());
        }
    }

    // 认证通过 → 注入连接身份并放行
    if let Some(identity) = authenticate_with_center(&req) {
        req.extensions_mut().insert(identity);
        return next.call(req).await.map(|res| res.map_into_boxed_body());
    }

    // 插件端点：无 JWT 时放行到 handler（票 08）——真正的「这个端点要不要凭证」由
    // handler 按属主插件登记的档位判定，环回 hook 才能免 JWT 命中显式登记
    // `auth: "none"` 的那几条
    if is_plugin_path(&path) {
        return next.call(req).await.map(|res| res.map_into_boxed_body());
    }

    // 其余受保护路由：认证未过 → 返回 401
    let (req, _payload) = req.into_parts();
    let response = HttpResponse::Unauthorized().json(json!({
        "code": 1007,
        "message": "Authentication required"
    }));
    Ok(ServiceResponse::new(req, response))
}

// ==================== Tests ====================

// 用例按功能拆至 `auth_gateway/tests/`（本内联模块的子模块路径由 rustc
// 自动解析到该目录；模块树 `middleware::auth_gateway::tests::<文件>` 与内联形态等价，私有项可见性不受影响）。
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::web;
    // 跨分组共享的测试脚手架（子模块经 `use super::*` 可见）

    /// ABI v29：公开判定走注册表档位——插件登记 `auth: "none"` 的别名免验签放行
    /// （真实中间件栈：注册公开别名 → 无 token 请求通过 auth_gateway 到哨兵）
    #[actix_web::test]
    async fn registered_none_tier_alias_passes_without_token() {
        use actix_web::middleware::from_fn;

        async fn sentinel() -> HttpResponse {
            HttpResponse::Ok().json(json!({ "ok": true }))
        }

        let owner = "test-jwt-public";
        let methods: Vec<String> = vec!["POST".to_string()];
        crate::registry::register(
            owner,
            "pairing",
            Some("/api/auth/pairing"),
            &methods,
            crate::wire::EndpointAuth::None,
        )
        .expect("register public alias");

        let app = actix_web::test::init_service(
            actix_web::App::new().service(
                web::scope("/api")
                    .wrap(from_fn(auth_gateway))
                    .route("/auth/pairing", web::post().to(sentinel)),
            ),
        )
        .await;
        let resp = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/api/auth/pairing")
                .to_request(),
        )
        .await;
        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::OK,
            "注册为 none 档的公开别名必须免验签放行"
        );

        crate::registry::purge_for_plugin(owner);
    }
    /// ABI v29：`jwt` 档别名 / 未登记路径无 token → 401（受保护默认，不静默放行）
    #[actix_web::test]
    async fn jwt_tier_alias_without_token_is_401() {
        use actix_web::middleware::from_fn;

        async fn sentinel() -> HttpResponse {
            HttpResponse::Ok().json(json!({ "ok": true }))
        }

        let owner = "test-jwt-guarded";
        let methods: Vec<String> = vec!["GET".to_string()];
        // 宿主路径取**本用例专属**的 `/api/jwt-guarded-alias`（原为 `/api/configs`）：
        // HTTP 端点注册表是**进程级全局**，host path + method 唯一。两个用例登记同一
        // 路径时后到者拿到「already registered by plugin 'X'」而 panic，与线程调度
        // 有关（同一对用例谁先谁后随机）——表现为全量 `cargo test` 偶发单红，而单跑
        // 与单线程都绿。新增登记用例时**必须取专属路径**。
        crate::registry::register(
            owner,
            "jwt-guarded-alias",
            Some("/api/jwt-guarded-alias"),
            &methods,
            crate::wire::EndpointAuth::Jwt,
        )
        .expect("register jwt alias");

        let app = actix_web::test::init_service(
            actix_web::App::new().service(
                web::scope("/api")
                    .wrap(from_fn(auth_gateway))
                    .route("/jwt-guarded-alias", web::get().to(sentinel)),
            ),
        )
        .await;
        let resp = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/api/jwt-guarded-alias")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);

        crate::registry::purge_for_plugin(owner);
    }
    // ==================== ADR 0033：认证问中心（中间件单测） ====================
    //
    // v33 起宿主**没有签发面也没有验签面**（`utils/auth/jwt.rs` 已退役），故本层
    // 单测不再造 token。可单测的部分收成两半：
    // ① 凭证**提取**（纯解析，Bearer scheme / 缺头 / 非 Bearer）；
    // ② 无运行时上下文（无头 / 单测）时**一律拒**（fail-closed 的可观测形态之一）。
    // 「合法凭证放行」那一半在 in-crate 闭环用例里用**真实中心产物**断言
    // （`wasm_core/manager/host/tests/system_component_test.rs`）——那里才有中心。
    /// 构造带 Authorization: Bearer 头的 ServiceRequest
    fn srv_req_with_bearer(token: &str) -> actix_web::dev::ServiceRequest {
        use actix_web::test;
        test::TestRequest::get()
            .uri("/api/sessions")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_srv_request()
    }
    mod adr_0033;
    mod host_public_paths_are_only;
}
