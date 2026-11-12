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
use actix_web::{web, App, Error, HttpMessage, HttpServer};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use wasmnest_server_base::config::NetworkConfig;
use wasmnest_server_base::constants::{BIND_ADDRESS, CORS_MAX_AGE_SECS, LOCALHOST_IP};
use wasmnest_server_base::face::{PeerFaceResolver, RequestFace};

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

/// 启动普通面 Actix Web 服务器（HTTP + WebSocket 统一端口，faces 注入装配）
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
    let (_, handle, server) = serve_on(
        BindTarget::Addr(format!("{}:{}", BIND_ADDRESS, port)),
        config,
        faces,
        RequestFace::local(),
        None,
    )
    .await?;
    Ok((handle, server))
}

/// 启动对等 HTTP/WS 面（内网穿透 T03）：**只绑 127.0.0.1**，路由表与中间件
/// 与普通面完全共用，仅注入 [`RequestFace`] 面标记。
///
/// `resolver` 是宿主按连接四元组给出「已验证 nodeId / 配对态」的接线点
/// （T05 配对连接注册表）；为 `None` 时退化为无 nodeId 的 peer 面，
/// **不会**因为读不到上下文就把请求升级为本机身份。
/// 生命周期由宿主 `tunnel:serve` 规则驱动（T06），本函数只管装配。
pub async fn serve_peer_face(
    port: u16,
    config: &NetworkConfig,
    faces: Vec<Arc<dyn TransportFace>>,
    resolver: Option<PeerFaceResolver>,
) -> std::io::Result<(
    actix_web::dev::ServerHandle,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    let (_, handle, server) = serve_on(
        BindTarget::Addr(format!("{}:{}", LOCALHOST_IP, port)),
        config,
        faces,
        RequestFace::peer_face(None, false),
        resolver,
    )
    .await?;
    Ok((handle, server))
}

/// 启动对等面并**返回实际监听地址**（T06：宿主先 bind `127.0.0.1:0`，端口由系统
/// 分配后再交给隧道策略做管理端口黑名单与 `kind=http` 后端目标）。
///
/// listener 必须由调用方绑定并置为非阻塞（`std::net::TcpListener`；actix
/// `HttpServer::listen` 的契约）。
pub async fn serve_peer_face_on(
    listener: std::net::TcpListener,
    config: &NetworkConfig,
    faces: Vec<Arc<dyn TransportFace>>,
    resolver: Option<PeerFaceResolver>,
) -> std::io::Result<(
    std::net::SocketAddr,
    actix_web::dev::ServerHandle,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    let (addrs, handle, server) = serve_on(
        BindTarget::Listener(listener),
        config,
        faces,
        RequestFace::peer_face(None, false),
        resolver,
    )
    .await?;
    let addr = addrs
        .first()
        .copied()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "peer face bound without address"))?;
    Ok((addr, handle, server))
}

/// 绑定目标：普通面按地址 bind；对等面由宿主先占 `127.0.0.1:0` 再移交 listener
enum BindTarget {
    Addr(String),
    Listener(std::net::TcpListener),
}

/// 对等面绑定自证：只允许 loopback（端口 0 允许，由 system 分配）
fn validate_peer_face_bind(bind: &BindTarget) -> std::io::Result<()> {
    let addr = match bind {
        BindTarget::Listener(listener) => listener.local_addr()?,
        BindTarget::Addr(addr) => addr.parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("对等面绑定地址必须为 <loopback>:<port>：{addr}"),
            )
        })?,
    };
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("对等面只能绑回环地址，拒绝 {addr}"),
        ));
    }
    Ok(())
}

async fn serve_on(
    bind: BindTarget,
    config: &NetworkConfig,
    faces: Vec<Arc<dyn TransportFace>>,
    face: RequestFace,
    resolver: Option<PeerFaceResolver>,
) -> std::io::Result<(
    Vec<std::net::SocketAddr>,
    actix_web::dev::ServerHandle,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    let bind_label = match &bind {
        BindTarget::Addr(addr) => addr.clone(),
        BindTarget::Listener(listener) => listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<listener>".to_string()),
    };
    // 对等面只能绑回环（不变量 1 / T03）：listener 由调用方传入，机制层必须
    // 自证，不能只靠调用方自觉（误用非回环 listener 会把 peer 面暴露到 LAN）。
    if face.is_peer() {
        validate_peer_face_bind(&bind)?;
    }
    tracing::info!(
        "Starting Actix Web server (HTTP + WS) on {} (peer face: {})",
        bind_label,
        face.is_peer()
    );

    let keep_alive = if config.keep_alive_secs == 0 {
        KeepAlive::Disabled
    } else {
        KeepAlive::Timeout(Duration::from_secs(config.keep_alive_secs))
    };

    let faces_shared: Arc<Vec<Arc<dyn TransportFace>>> = faces.into();
    let face_for_inject = face.clone();
    let resolver_for_inject = resolver.clone();

    let server_builder = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(CORS_MAX_AGE_SECS);

        let face = face_for_inject.clone();
        let resolver = resolver_for_inject.clone();
        let faces = Arc::clone(&faces_shared);
        App::new()
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            // 指标层（外层）：计数后透传
            .wrap_fn(|req, srv| {
                crate::metrics::MetricsCollector::global().inc_http_request();
                srv.call(req)
            })
            // 面标记注入（外层）：listener 决定信任面，客户端头不可伪造。
            // 注入在 face 中间件链之前，TrafficFilter / 网关 / WS 握手都能读到。
            .wrap_fn(move |req, srv| {
                let resolved = match (&resolver, req.peer_addr()) {
                    (Some(resolve), Some(addr)) => resolve(&addr),
                    _ => face.clone(),
                };
                req.extensions_mut().insert(resolved);
                srv.call(req)
            })
            // face 层（最内层）：boxed service 链式组合各面中间件
            // （用 `middleware::from_fn` 而非 `App::wrap_fn`——后者回调签名是
            // `&T::Service`，from_fn 才是 `Next<B>` 的 Next 中间件形态）
            .wrap(actix_web::middleware::from_fn(move |req, srv| {
                apply_face_wraps(req, srv, faces.clone())
            }))
            .configure(|cfg| {
                for face in faces_shared.iter() {
                    face.configure(cfg);
                }
            })
    });
    let server_builder = match bind {
        BindTarget::Addr(addr) => server_builder.bind(addr)?,
        BindTarget::Listener(listener) => server_builder.listen(listener)?,
    };
    let mut server_builder = server_builder
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

    // 绑定端口由系统分配时（listener 形态），实际地址只能从 HttpServer 取
    let addrs = server_builder.addrs();
    let server = server_builder.run();

    // 在 await 之前获取 handle，用于后续优雅停机
    let handle = server.handle();

    Ok((addrs, handle, server))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 不变量 1 / T03：对等面 listener 必须自证 loopback——调用方误传非回环
    /// listener 时机制层拒绝，而不是把 peer 面暴露到 LAN。
    #[tokio::test]
    async fn peer_face_rejects_non_loopback_listener() {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let err = match serve_peer_face_on(listener, &NetworkConfig::default(), Vec::new(), None).await {
            Ok(_) => panic!("非回环 listener 必须被拒绝"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    }

    /// `Addr` 形态同样拒绝非回环绑定（`serve_peer_face` 之外的自定义调用面）
    #[tokio::test]
    async fn peer_face_rejects_non_loopback_addr_bind() {
        let err = match serve_on(
            BindTarget::Addr("0.0.0.0:0".to_string()),
            &NetworkConfig::default(),
            Vec::new(),
            RequestFace::peer_face(None, false),
            None,
        )
        .await
        {
            Ok(_) => panic!("非回环绑定必须被拒绝"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    }
}
