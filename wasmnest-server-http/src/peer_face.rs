//! 对等面门禁（内网穿透 T03）
//!
//! 配对窗口只放行配对引导端点：配对态连接即便来自 loopback，也不得触达业务
//! 路径。闸门挂在 app 级 face 链外层，`/ws` 与静态端点同样受管。
//! 配对连接注册表与 `peerNodeId` 由宿主经 `PeerFaceResolver` 注入（T05 接线），
//! 本模块只消费 [`RequestFace`]，不读请求头。

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{Error, HttpMessage, HttpResponse};
use wasmnest_server_base::face::RequestFace;

use crate::dtos::{ApiResponse, CODE_PLUGIN_AUTH_FAILED};

/// 配对引导端点前缀（设计 §4.1：bedcode 的 `/api/auth/*`）
pub const PAIRING_PATH_PREFIX: &str = "/api/auth/";

/// 配对窗口路径白名单（纯函数，供双端与测试锁复用）
///
/// 前缀内的路径穿越必须以拒绝处理：放行 `/api/auth/../plugin/...` 等于放行
/// 全部业务端点。
pub fn pairing_path_allowed(path: &str) -> bool {
    if !path.starts_with(PAIRING_PATH_PREFIX) {
        return false;
    }
    !path.contains("..") && !path.to_ascii_lowercase().contains("%2e%2e")
}

/// 配对态连接的路径闸门：白名单外 403，普通面零介入
pub async fn peer_face_guard<B>(req: ServiceRequest, next: Next<B>) -> Result<ServiceResponse, Error>
where
    B: MessageBody + 'static,
{
    let face = req.extensions().get::<RequestFace>().cloned().unwrap_or_default();
    if face.is_pairing() && !pairing_path_allowed(req.path()) {
        let path = req.path().to_string();
        let (http_req, _payload) = req.into_parts();
        tracing::warn!(path = %path, "pairing window rejected non-pairing endpoint");
        let response = HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            CODE_PLUGIN_AUTH_FAILED,
            &format!("pairing window rejects '{path}': only {PAIRING_PATH_PREFIX}* is allowed"),
        ));
        return Ok(ServiceResponse::new(http_req, response));
    }
    next.call(req).await.map(|res| res.map_into_boxed_body())
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use actix_service::Service;
    use actix_web::middleware::from_fn;
    use actix_web::{web, App};

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    /// 配对窗口只放行配对端点；路径穿越不得借前缀逃逸
    #[test]
    fn pairing_path_allows_only_auth_endpoints() {
        assert!(pairing_path_allowed("/api/auth/pairing"));
        assert!(pairing_path_allowed("/api/auth/qr-connect?x=1"));
        assert!(!pairing_path_allowed("/api/auth"), "前缀本身不含端点段");
        assert!(!pairing_path_allowed("/api/plugin/bedcode/task-status"));
        assert!(!pairing_path_allowed("/api/auth/../plugin/bedcode/task-status"));
        assert!(!pairing_path_allowed("/api/auth/%2e%2e/plugin/bedcode/task-status"));
        assert!(!pairing_path_allowed("/api/health"));
        assert!(!pairing_path_allowed("/ws/plugin/bedcode/terminal"));
    }

    /// 安全锁：配对态 loopback 请求访问业务端点必须 403，不得落到 handler
    #[actix_web::test]
    async fn pairing_window_rejects_business_endpoint_on_peer_face() {
        let face = RequestFace::peer_face(None, true);
        let app = actix_web::test::init_service(
            App::new()
                .wrap(from_fn(peer_face_guard))
                .wrap_fn(move |req, srv| {
                    req.extensions_mut().insert(face.clone());
                    srv.call(req)
                })
                .route("/api/auth/pairing", web::get().to(ok))
                .route("/api/plugin/bedcode/task-status", web::get().to(ok)),
        )
        .await;

        let denied = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/api/plugin/bedcode/task-status")
                .peer_addr("127.0.0.1:54321".parse().unwrap())
                .to_request(),
        )
        .await;
        assert_eq!(denied.status(), actix_web::http::StatusCode::FORBIDDEN);
        let body = actix_web::test::read_body(denied).await;
        assert!(
            String::from_utf8_lossy(&body).contains("/api/auth/"),
            "拒绝原因要点名放行范围: {}",
            String::from_utf8_lossy(&body)
        );

        let allowed = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/api/auth/pairing")
                .peer_addr("127.0.0.1:54321".parse().unwrap())
                .to_request(),
        )
        .await;
        assert!(allowed.status().is_success(), "配对端点必须可达");
    }

    /// 反例：普通面（无面标记）与已匹配 peer 面都不受配对白名单约束
    #[actix_web::test]
    async fn normal_faces_are_not_restricted_by_pairing_window() {
        for face in [
            RequestFace::local(),
            RequestFace::peer_face(Some("node-1".into()), false),
        ] {
            let app = actix_web::test::init_service(
                App::new()
                    .wrap(from_fn(peer_face_guard))
                    .wrap_fn(move |req, srv| {
                        req.extensions_mut().insert(face.clone());
                        srv.call(req)
                    })
                    .route("/api/plugin/bedcode/task-status", web::get().to(ok)),
            )
            .await;
            let res = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri("/api/plugin/bedcode/task-status")
                    .peer_addr("127.0.0.1:54321".parse().unwrap())
                    .to_request(),
            )
            .await;
            assert!(res.status().is_success(), "非配对态不得被窗口闸门误伤");
        }
    }
}
