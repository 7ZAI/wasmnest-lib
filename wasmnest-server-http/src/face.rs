//! HTTP 面的组合装配实现（server-lib-split 票 03 的 `TransportFace` 契约，票 04 随面下沉）
//!
//! 票 03 时 face 适配器住在宿主组合根 `server/composition.rs` 里（http 面当时还是宿主
//! 模块）；本票把实现收进本 crate，宿主壳此后只做「把 faces 交给 `core::app::serve`」，
//! 不再认识面内类型（`TrafficFilter` 等）。

use actix_service::boxed::BoxService;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse, Transform};
use actix_web::{web, Error};
use wasmnest_server_core::TransportFace;
use futures_util::FutureExt;

use crate::middleware::http_filter::TrafficFilter;

/// face 中间件链的装箱服务类型（与 [`TransportFace::wrap`] 契约一致）
type FaceService = BoxService<ServiceRequest, ServiceResponse<BoxBody>, Error>;

/// HTTP 面：路由装配 + `TrafficFilter` 中间件
///
/// `TrafficFilter` 挂在 face 层（= 拆分前的最内层位置）：CORS/日志层拒绝的请求
/// 不进入缓冲逻辑，链为空时零介入。
pub struct HttpTransportFace;

impl TransportFace for HttpTransportFace {
    fn configure(&self, cfg: &mut web::ServiceConfig) {
        crate::configure_routes(cfg);
    }

    fn wrap(&self, next: FaceService) -> FaceService {
        // new_transform 的 Future 是 `std::future::Ready`、InitError 是 `()`：
        // 中间件装配期即完成且不可能失败，故同步取回后装箱接进 face 链
        let service = TrafficFilter
            .new_transform(next)
            .now_or_never()
            .and_then(|result| result.ok())
            .expect("TrafficFilter 中间件装配失败（new_transform 契约为 Ready + InitError=()）");
        actix_service::boxed::service(service)
    }
}
