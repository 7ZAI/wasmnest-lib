//! Actix Web 服务器组合装配（server-lib-split 票 03：D3 组合 API trait 化）
//!
//! HTTP 与 WS 共用一个端口、一个 `HttpServer`，组合物必然同时认识两面。
//! 拆 lib 后本 crate 无法再 import 两个传输面 crate（I1/I3），
//! 组合改经 [`TransportFace`] 依赖倒置：http / ws 各自实现一个 face（定义在
//! 各自 lib），宿主壳装配 faces 传入 [`serve`]。
//!
//! 面级中间件（如 http 的 `TrafficFilter`）经 [`TransportFace::wrap`] 注入——
//! actix 的 `App::wrap` 链是类型泛型的（每个 middleware 产生新的 opaque
//! endpoint 类型），无法按 `Vec` 循环；解法是单个 `wrap_fn`（共享 fn item，
//! 类型统一）内做 **boxed service 链式组合**（`BoxService`）：最内层是
//! `Next`，每个 face 的 `wrap` 把下一层服务包进自己的中间件服务。

use actix_cors::Cors;
use actix_service::boxed::BoxService;
use actix_service::Service;
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::KeepAlive;
use actix_web::middleware::Next;
use actix_web::{web, App, Error, HttpServer};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use wasmnest_server_base::config::NetworkConfig;
use wasmnest_server_base::constants::{BIND_ADDRESS, CORS_MAX_AGE_SECS};

/// 传输面组合契约（libp2p SwarmBuilder 式）：一个 face = 一个传输面的
/// 路由装配 + 可选 app 级中间件（boxed service 链式注入）。
pub trait TransportFace: Send + Sync {
    /// 路由装配（http/ws 各自 `configure_routes` 的实现）
    fn configure(&self, cfg: &mut web::ServiceConfig);

    /// 把本面的 app 级中间件包在 `next` 外层（默认透传；http 面挂
    /// `TrafficFilter` 等价物——挂在最内层，CORS/日志层拒绝的请求不进入
    /// 缓冲逻辑）。链为空时零开销透传由面实现自行短路。
    fn wrap(
        &self,
        next: BoxService<ServiceRequest, ServiceResponse<BoxBody>, Error>,
    ) -> BoxService<ServiceRequest, ServiceResponse<BoxBody>, Error> {
        next
    }
}

/// 响应体归一适配：`ServiceResponse<B>` → `ServiceResponse<BoxBody>`
/// （`BoxService` 链要求统一 body 类型，actix 的 `map_into_boxed_body` 等价物）
struct MapBoxedBody<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for MapBoxedBody<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        Box::pin(async move { Ok(fut.await?.map_into_boxed_body()) })
    }
}

/// 单点 `wrap_fn` 内执行全部 face 中间件（fn item，类型统一）：
/// 最内层 `Next` 装箱（响应体归一 `BoxBody`）→ 每个 face 的 `wrap`
/// 从外到内包一层 → 调用链。泛型 `B`：与所在 wrap 链的当前 body 类型解耦，
/// 各层无需显式指定 body。
async fn apply_face_wraps<B>(
    req: ServiceRequest,
    srv: Next<B>,
    faces: Arc<Vec<Arc<dyn TransportFace>>>,
) -> Result<ServiceResponse<BoxBody>, Error>
where
    B: MessageBody + 'static,
{
    let mut chain: BoxService<ServiceRequest, ServiceResponse<BoxBody>, Error> =
        actix_service::boxed::service(MapBoxedBody { service: srv });
    // 从外到内：最后一个 face 的 wrap 最内层（靠近路由）
    for face in faces.iter().rev() {
        chain = face.wrap(chain);
    }
    chain.call(req).await
}

/// 构建路由配置 — 组合物：只做两侧装配，不承载任何端点
///
/// HTTP 侧（公开端点 + `/api` scope）与 WS 侧（三条握手路由）各自落在
/// 面 lib 的 `routes.rs`；本函数按注入的 faces 顺序装配。
pub fn configure_routes(cfg: &mut web::ServiceConfig, faces: &[Arc<dyn TransportFace>]) {
    for face in faces {
        face.configure(cfg);
    }
}

/// 启动 Actix Web 服务器（HTTP + WebSocket 统一端口，faces 注入装配）
///
/// 返回 `ServerHandle` 用于优雅停机
/// 调用方通过 oneshot channel 获取 handle，然后继续 await server 保持运行
pub async fn serve(
    port: u16,
    config: &NetworkConfig,
    faces: Vec<Arc<dyn TransportFace>>,
) -> std::io::Result<(
    actix_web::dev::ServerHandle,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    tracing::info!("Starting Actix Web server (HTTP + WS) on port {}", port);

    let keep_alive = if config.keep_alive_secs == 0 {
        KeepAlive::Disabled
    } else {
        KeepAlive::Timeout(Duration::from_secs(config.keep_alive_secs))
    };

    let faces_for_metrics: Arc<Vec<Arc<dyn TransportFace>>> = faces.into();

    let mut server_builder = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(CORS_MAX_AGE_SECS);

        let faces = Arc::clone(&faces_for_metrics);
        App::new()
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            // 指标层（外层）：计数后透传
            .wrap_fn(|req, srv| {
                crate::metrics::MetricsCollector::global().inc_http_request();
                srv.call(req)
            })
            // face 层（最内层）：boxed service 链式组合各面中间件
            // （用 `middleware::from_fn` 而非 `App::wrap_fn`——后者回调签名是
            // `&T::Service`，from_fn 才是 `Next<B>` 的 Next 中间件形态）
            .wrap(actix_web::middleware::from_fn(move |req, srv| {
                apply_face_wraps(req, srv, faces.clone())
            }))
            .configure(|cfg| {
                for face in faces_for_metrics.iter() {
                    face.configure(cfg);
                }
            })
    })
    .bind(format!("{}:{}", BIND_ADDRESS, port))?
    .keep_alive(keep_alive)
    .client_request_timeout(Duration::from_secs(config.client_request_timeout_secs))
    .client_disconnect_timeout(Duration::from_secs(config.client_disconnect_timeout_secs))
    .max_connections(config.max_connections)
    .backlog(config.backlog)
    .tcp_nodelay(config.tcp_nodelay)
    .shutdown_timeout(config.shutdown_timeout_secs);

    if config.workers > 0 {
        server_builder = server_builder.workers(config.workers);
    }

    let server = server_builder.run();

    // 在 await 之前获取 handle，用于后续优雅停机
    let handle = server.handle();

    Ok((handle, server))
}
