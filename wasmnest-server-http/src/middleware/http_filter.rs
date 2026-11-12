//! HTTP Traffic Filter Middleware
//!
//! 把 HTTP 请求体（入站）与响应体（出站）送入 [`TrafficFilterChain`] 责任链，
//! 以标准 actix Transform/Service 形式实现，由组合根 `server/composition.rs` 的
//! http face `wrap` 在最内层接入。
//!
//! 快速路径：链为空 / WS 升级握手 / HEAD → 不缓冲直接透传。
//!
//! 启用过滤器时，请求体与响应体会整体读入内存做转换——本服务当前均为
//! JSON 报文端点、无流式响应，整体缓冲可接受；未来新增大流量端点
//! （文件流下载等）时应由过滤器按 route 自行放行或扩展分块机制。

use std::rc::Rc;
use std::task::{Context, Poll};

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorInternalServerError,
    http::header::CONTENT_LENGTH,
    web,
    web::Bytes,
    FromRequest, HttpMessage, HttpResponse, Result,
};
use tracing::{Instrument, Level};

use crate::dtos::common_dto::{ApiResponse, CODE_INVALID_REQUEST};
use wasmnest_server_base::face::RequestFace;
use wasmnest_server_core::filter::{Direction, FilterContext, TrafficChannel, TrafficFilterChain};
use wasmnest_server_core::link_crypto::{EncryptionPolicy, LinkEncryptionFilter};

// ==================== Transform（构造层） ====================

/// 流量过滤器中间件（HTTP 接入点）
///
/// 用法：`App::new().wrap(TrafficFilter)`。挂在最内层：CORS/日志层拒绝的
/// 请求不进入缓冲逻辑。
#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficFilter;

impl<S, B> Transform<S, ServiceRequest> for TrafficFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    type Transform = TrafficFilterService<S>;
    type InitError = ();
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(TrafficFilterService {
            service: Rc::new(service),
        }))
    }
}

// ==================== Service（执行层） ====================

pub struct TrafficFilterService<S> {
    /// Rc 包装：call() 需把下游服务移入 'static async 块（actix service 非 Send）
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for TrafficFilterService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    type Future = futures_util::future::LocalBoxFuture<'static, Result<Self::Response>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // 快速路径在进入 async 块前判断，避免无谓的任务装箱开销：
        // WS 升级请求的帧级过滤在 WS 层做；HEAD 响应无 body；空链零介入
        let skip_filtering = req.path().starts_with("/ws") || req.method() == actix_web::http::Method::HEAD;
        let peer = req
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let chain = TrafficFilterChain::global();

        // 链路加密协商头（issue 02）：原样透传给过滤器，解析归 link_crypto。
        // 提到快速路径之前——下面那条 fail-visible 裁决要先看它。
        let negotiation = req
            .headers()
            .get(wasmnest_server_core::link_crypto::NEGOTIATION_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // ==================== fail-visible：协商头在，本端却不参与 ====================
        // 背景：spec §6 决策模型第 3 条「响应绑定」要求——请求一旦带协商头，对端就必须
        // 按信号参与（解密 + 用 k_resp 回加密），不取决于本端子开关当前值；而同一份
        // spec 的实现语义段又写「主开关关闭 ⇒ 过滤器不注册」，§7 兼容矩阵更把
        // 「任一侧默认关」直接等同于明文。三处互相矛盾，实现落在「不注册」这一支。
        //
        // 后果（跨端实测）：移动端开启加密、桌面端未开启时，过滤器不在链上 ⇒ 协商头
        // **根本没人读** ⇒ 密文原样透给插件 ⇒ 插件把密文当 JSON 解析，回出
        // `{"code":1002,"message":"configId required"}` 之类**误导性业务码**。
        //
        // 本分支按「静默错误必须显性化」（AGENTS §8）处理：显性 4xx + 点名开关，
        // 而不是继续往下游丢密文。GET 同样拒——否则「GET 静默明文通、POST 神秘报
        // 业务错」的不一致更难排查。
        //
        // 成本：未参与时每个非 HEAD/WS 请求多一次 header 查找（表已解析完的一次
        // 哈希查）。换来的是不再出现「200 + 误导性业务码」。
        if !skip_filtering && !negotiation.is_empty() && !chain.contains(wasmnest_server_core::link_crypto::FILTER_NAME)
        {
            // 拒绝码 = `encryption-required`：对端**发起过**协商，是本端没参与
            // （旧服务端 / 没开加密的端）。与「对端压根没协商」（unsupported）分开。
            let message = wasmnest_server_core::link_crypto::coded_reason(
                wasmnest_server_core::link_crypto::CODE_ENCRYPTION_REQUIRED,
                "encrypted request rejected: link-crypto is not active on this server \
(no app has enabled link encryption). Enable link encryption in the target app's settings, \
or turn off encryption on the client.",
            );
            return Box::pin(async move {
                tracing::warn!(
                    path = %req.path(),
                    method = %req.method(),
                    "HTTP inbound rejected: encryption negotiated but server not participating"
                );
                let (http_req, _payload) = req.into_parts();
                Ok(reject_with_crypto_code(
                    http_req,
                    message,
                    Some(wasmnest_server_core::link_crypto::CODE_ENCRYPTION_REQUIRED),
                ))
            });
        }

        // ==================== HEAD + required 端点：不得绕过协商要求 ====================
        // HEAD 响应无 body 可加密，整体跳过过滤链是既有快速路径；但端点策略不能
        // 因此被旁路（否则「GET 拒绝、HEAD 放行」就是一条明文探测通道）。这里只
        // 取策略裁决（本地豁免 / 白名单逻辑复用过滤器同一实现），不驱动责任链。
        if req.method() == actix_web::http::Method::HEAD {
            let (owner, endpoint) = resolve_route_identity(req.path(), "HEAD");
            // 内网穿透 T04：面标记由 listener 注入，HEAD 快速路径同样要按面裁决
            let face = req.extensions().get::<RequestFace>().cloned().unwrap_or_default();
            let probe = FilterContext {
                channel: TrafficChannel::Http,
                direction: Direction::Inbound,
                peer: &peer,
                route: req.path(),
                owner: &owner,
                endpoint: &endpoint,
                negotiation: &negotiation,
                data: Vec::new(),
                outbound_headers: Vec::new(),
                face: face.clone(),
            };
            if LinkEncryptionFilter::policy_of(&probe) == Some(EncryptionPolicy::Required)
                && negotiation.trim().is_empty()
            {
                // HEAD 与 GET 同判据、同拒绝码：HEAD 是明文探测通道，也是旧客户端
                // 唯一可能「看起来成功」的路径，不能在这里放宽成无码拒绝。
                let message = wasmnest_server_core::link_crypto::coded_reason(
                    wasmnest_server_core::link_crypto::CODE_ENCRYPTION_UNSUPPORTED,
                    format!(
                        "link encryption required but this request carries no negotiation header: \
                         endpoint '{endpoint}' of plugin '{owner}' (channel 'http', policy 'required')"
                    ),
                );
                return Box::pin(async move {
                    tracing::warn!(
                        path = %req.path(),
                        "HTTP HEAD rejected: required endpoint without link encryption negotiation"
                    );
                    let (http_req, _payload) = req.into_parts();
                    Ok(reject_with_crypto_code(
                        http_req,
                        message,
                        Some(wasmnest_server_core::link_crypto::CODE_ENCRYPTION_UNSUPPORTED),
                    ))
                });
            }
        }

        if skip_filtering || chain.is_empty() {
            let fut = self.service.call(req);
            return Box::pin(async move { Ok(fut.await?.map_into_boxed_body()) });
        }

        let path = req.path().to_string();
        // 端点身份只从注册表取（spec §3）：不解析 URL 猜属主，也不接受对端自报
        let (owner, endpoint) = resolve_route_identity(req.path(), req.method().as_str());
        let service = self.service.clone();

        // 链路追踪（05 调用链）：请求级 span 在同步上下文创建，`instrument` 包裹异步体
        let method = req.method().clone();
        let request_id = new_request_id(&peer);
        let span = tracing::info_span!(
            "http_request",
            request_id = %request_id,
            method = %method,
            path = %path,
        );

        Box::pin(async move {
            run_traffic_filter(req, service, peer, path, negotiation, owner, endpoint)
                .instrument(span)
                .await
        })
    }
}

/// 由已注册路由反查端点身份（属主插件 id / 端点句柄）
///
/// 两条查法都只读宿主注册表：内部路径 `/api/plugin/<owner>/<path>` 精确反查，
/// 其次对外别名（含 `{name}` 模板段）按（路径, 方法）匹配。未注册路径返回空
/// 身份——那是宿主自有面（健康检查 / 配对引导 / 404），按通道下限裁决。
fn resolve_route_identity(path: &str, method: &str) -> (String, String) {
    if let Some(entry) = crate::registry::find_by_internal(path) {
        return (entry.owner, entry.endpoint_id);
    }
    if let Some(host_match) = crate::registry::find_by_host(path, method) {
        return (host_match.entry.owner, host_match.entry.endpoint_id);
    }
    (String::new(), String::new())
}

/// 400 拒绝响应 + 链路加密拒绝码头（`code = None` = 普通拒绝，不下码）
///
/// 码是**机器可读**的 fail-visible 出口（内网穿透 T07）：客户端据此把「对端不会
/// 协商」（`encryption-unsupported`）与「协商建不起来」（`encryption-required`）
/// 映射成两条不同的用户出路，不必从自由文本里猜。正文同样带 `<code>: ` 前缀，
/// 头与正文同源（`link_crypto::coded_reason`），不会出现「头一个码、正文另一套词」。
///
/// 与 `run_traffic_filter` 内部的过滤器 Reject 分支**同一个错误信封**（400 +
/// `CODE_INVALID_REQUEST`），使客户端侧两种「拒绝」形状一致、便于按 code 归类。
/// 消息**点名能力状态与两端各自的修法**（应用设置里的链路加密），否则用户只会
/// 看到一句无处置建议的 400。
fn reject_with_crypto_code(
    http_req: actix_web::HttpRequest,
    message: String,
    code: Option<&'static str>,
) -> ServiceResponse {
    let mut builder = HttpResponse::BadRequest();
    if let Some(code) = code {
        builder.insert_header((wasmnest_server_core::link_crypto::ERROR_HEADER, code));
    }
    let response = builder.json(ApiResponse::<()>::error(CODE_INVALID_REQUEST, &message));
    ServiceResponse::new(http_req, response)
}

/// 完整过滤流程：入站请求体 → 下游 → 出站响应体
///
/// 单一出口统一记录请求完成事件（01 全路径日志）：请求结束按结果记
/// `status` + `duration_ms` 结构化字段，级别按结果语义（成功 **trace** 不刷屏 /
/// 4xx warn / 5xx+异常 error），成功分支另带 `requests_in_window` 秒级聚合计数
/// （见 [`super::http_stats`]）；`request_id`/`method`/`path` 由外层 span 字段继承。
async fn run_traffic_filter<S, B>(
    req: ServiceRequest,
    service: Rc<S>,
    peer: String,
    path: String,
    negotiation: String,
    owner: String,
    endpoint: String,
) -> Result<ServiceResponse>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody + 'static,
{
    // 内网穿透 T04：面标记随 FilterContext 进入链加密判据；缺省 = 普通面，
    // 既有环回豁免行为不回归。
    let face = req.extensions().get::<RequestFace>().cloned().unwrap_or_default();
    let started = std::time::Instant::now();

    // 主体流程包进 async 块：错误经 `?` 上抛到单一出口（不再散落 return），
    // 保证拒绝/下游错误/成功所有路径都有一次完成事件
    let outcome: Result<ServiceResponse> = async {
        let chain = TrafficFilterChain::global();

        // ==================== 入站：请求体 ====================
        let (http_req, mut payload) = req.into_parts();
        let body = <web::Bytes as FromRequest>::from_request(&http_req, &mut payload).await?;

        let mut ctx = FilterContext {
            channel: TrafficChannel::Http,
            direction: Direction::Inbound,
            peer: &peer,
            route: &path,
            owner: &owner,
            endpoint: &endpoint,
            negotiation: &negotiation,
            data: body.to_vec(),
            outbound_headers: Vec::new(),
            face: face.clone(),
        };
        if let Err(rej) = chain.run_inbound(&mut ctx) {
            tracing::warn!(peer = %peer, route = %path, %rej, "HTTP inbound request rejected by traffic filter");
            // 链路加密的拒绝自带稳定码（`<code>: ` 前缀，见 link_crypto）→ 回给
            // 对端的 400 带上码，客户端不必从自由文本猜分类；其他过滤器的拒绝
            // 不带码，维持原有「Traffic filter rejected request」文案。
            let response = reject_with_crypto_code(
                http_req,
                format!("Traffic filter rejected request: {rej}"),
                wasmnest_server_core::link_crypto::reason_code(&rej.reason),
            );
            return Ok(response);
        }

        let service_req = ServiceRequest::from_parts(http_req, Payload::from(Bytes::from(ctx.data)));

        // ==================== 下游处理 ====================
        let res = service.call(service_req).await?.map_into_boxed_body();

        // ==================== 出站：响应体 ====================
        let (res_req, http_res) = res.into_parts();
        let (res_head, res_body) = http_res.into_parts();
        let res_bytes = to_bytes_owned(res_body).await?;

        let mut out_ctx = FilterContext {
            channel: TrafficChannel::Http,
            direction: Direction::Outbound,
            peer: &peer,
            route: &path,
            owner: &owner,
            endpoint: &endpoint,
            negotiation: &negotiation,
            data: res_bytes,
            outbound_headers: Vec::new(),
            face: face.clone(),
        };
        if let Err(rej) = chain.run_outbound(&mut out_ctx) {
            tracing::warn!(peer = %peer, route = %path, %rej, "HTTP outbound response rejected by traffic filter");
            let mut response = HttpResponse::InternalServerError();
            if let Some(code) = wasmnest_server_core::link_crypto::reason_code(&rej.reason) {
                response.insert_header((wasmnest_server_core::link_crypto::ERROR_HEADER, code));
            }
            let response = response.json(ApiResponse::<()>::error(
                CODE_INVALID_REQUEST,
                &format!("Traffic filter rejected response: {rej}"),
            ));
            return Ok(ServiceResponse::new(res_req, response));
        }

        // 重建响应：替换体后 Content-Length 已失配，剔除原值由 builder 按新体重算；
        // 其余头（含 CORS / Set-Cookie / Content-Type）原样保留，并入过滤器
        // 注入的出站附加头（如链路加密响应标记 `X-WasmNest-Crypto: v1`，spec §4）
        let mut builder = HttpResponse::build(res_head.status());
        for (name, value) in res_head.headers() {
            if name == CONTENT_LENGTH {
                continue;
            }
            builder.insert_header((name.clone(), value.clone()));
        }
        for (name, value) in out_ctx.outbound_headers {
            let name = actix_web::http::header::HeaderName::try_from(name);
            let value = actix_web::http::header::HeaderValue::try_from(value);
            if let (Ok(name), Ok(value)) = (name, value) {
                builder.insert_header((name, value));
            } else {
                // 标记头是承重件：丢失会让客户端把无标记的加密信封当明文 API 载荷
                // 解析（JSON.parse 成功但 code === undefined），比崩溃更难排查
                tracing::warn!(
                    route = %path,
                    peer = %peer,
                    "dropped filter outbound header (invalid name/value)"
                );
            }
        }
        let rebuilt = builder.body(Bytes::from(out_ctx.data));

        Ok::<ServiceResponse, actix_web::Error>(ServiceResponse::new(res_req, rebuilt))
    }
    .await;

    // 秒级聚合计数：只累加「有过滤链在跑」的请求（快速路径 / 空链在上方已提前返回，
    // 不计入），每个请求固定一次原子写，与是否有日志输出无关
    let status = match &outcome {
        Ok(res) => Some(res.status().as_u16()),
        Err(_) => None,
    };
    let requests_in_window = super::http_stats::record(status);

    // 完成事件（01）：span 已带 request_id/method/path，事件只补 status/duration_ms/error；
    // 成功分支的级别由 `completion_level` 统一裁决（TRACE，见其注释）
    let duration_ms = started.elapsed().as_millis() as u64;
    match &outcome {
        Ok(res) => emit_completion(res.status().as_u16(), duration_ms, requests_in_window),
        // 下游/读体的异常路径：不吞错误，error 字段带失败文本（request_id 仍由 span 继承）
        Err(e) => tracing::error!(error = %e, duration_ms, "HTTP request failed"),
    }
    outcome
}

// ==================== 成功完成事件的秒级聚合 ====================
//
// 为什么需要：请求完成日志的成功分支从 `debug` 降到 `trace` 后（见上方完成事件处
// 注释），「成功请求是否还在流动」不能随之完全失明——排查「客户端说调不通、宿主
// 这边什么都没有」时，第一个要回答的就是「到底有没有请求进来」。实现住在
// [`super::http_stats`]：进程级原子计数、每秒滚动一个窗口、不产生任何日志输出，
// 唯一出口是本文件完成事件的 `requests_in_window` 字段。

/// 完成事件 → 级别选择（纯函数，日志级别口径的单一事实源）
///
/// 成功（2xx/3xx）走 `TRACE`：逐请求留痕属于数据面日志，放 `DEBUG` 会在应用轮询 /
/// 事件推送下把控制台与 runtime 文件层刷满（2026-11-04 桌面端日志风暴）。成功与否的
/// 可见性由 [`super::http_stats`] 的秒级聚合计数承担；需要逐条追踪某次请求时开
/// `RUST_LOG=wasmnest_server_http::middleware::http_filter=trace`（EnvFilter 语法，
/// 无需改代码）。4xx 仍 `WARN`、5xx 仍 `ERROR`——那些是异常，逐条留痕是义务。
fn completion_level(status: u16) -> Level {
    if (200..400).contains(&status) {
        Level::TRACE
    } else if (400..500).contains(&status) {
        Level::WARN
    } else {
        Level::ERROR
    }
}

/// 按状态码发出完成事件（4xx / 5xx 的唯一日志出口）
fn emit_completion(status: u16, duration_ms: u64, requests_in_window: u64) {
    match completion_level(status) {
        Level::TRACE => tracing::trace!(status, duration_ms, requests_in_window, "HTTP request completed"),
        Level::WARN => tracing::warn!(status, duration_ms, "HTTP request completed with client error"),
        _ => tracing::error!(status, duration_ms, "HTTP request completed with server error"),
    }
}

/// 缓冲完整响应体（BoxBody）为内存字节
async fn to_bytes_owned(body: BoxBody) -> Result<Vec<u8>> {
    let bytes = actix_web::body::to_bytes(body)
        .await
        .map_err(ErrorInternalServerError)?;
    Ok(bytes.to_vec())
}

/// 生成请求级关联 ID（05 调用链）：peer 归一化 + 进程内单调序号（hex）
///
/// 序号而非时间戳：`subsec_nanos` 在纳秒级并发下会重复（同一纳秒内的多个请求得到
/// 同一 id，关联反而失效），且取系统时钟比一次原子加一贵。序号从 1 起单调递增、
/// 进程内唯一，日志中可直接按字典序/数值序判断请求先后。
fn new_request_id(peer: &str) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let peer_slug = peer.replace([':', '.'], "-");
    format!("req-{peer_slug}-{seq:x}")
}

/// 级别口径锁：成功 = TRACE（防止「200 + 耗时」按请求刷屏回归），4xx = WARN，
/// 5xx = ERROR
#[cfg(test)]
#[test]
fn completion_level_maps_success_to_trace() {
    for status in [200u16, 201, 204, 302, 304] {
        assert_eq!(
            completion_level(status),
            Level::TRACE,
            "成功响应必须落 TRACE，否则高 QPS 应用会刷满控制台与 runtime 日志"
        );
    }
    assert_eq!(completion_level(400), Level::WARN);
    assert_eq!(completion_level(404), Level::WARN);
    assert_eq!(completion_level(500), Level::ERROR);
    assert_eq!(completion_level(503), Level::ERROR);
}

#[cfg(test)]
#[test]
fn request_id_is_stable_format_and_unique_enough() {
    let r1 = new_request_id("192.168.1.5:54321");
    let r2 = new_request_id("192.168.1.5:54321");
    // 格式：req-<peer 归一化>-<hex 序号>
    assert!(r1.starts_with("req-192-168-1-5-54321-"), "got: {r1}");
    // 单调序号：同 peer 连续调用必然不同
    assert_ne!(r1, r2);
    // 未知 peer 也能生成（不 panic）
    assert!(new_request_id("unknown").starts_with("req-unknown-"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use wasmnest_server_core::filter::{TrafficFilter, Verdict};

    /// 全局链是进程级单例，串行化触碰它的集成测试
    static GLOBAL_CHAIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 转换型过滤器：入站请求体转大写（模拟解密），出站响应体追加标记（模拟加密）
    struct TransformFilter;

    impl TrafficFilter for TransformFilter {
        fn name(&self) -> &str {
            "test-transform"
        }
        fn on_inbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
            ctx.data = ctx.data.to_ascii_uppercase();
            Verdict::Continue
        }
        fn on_outbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
            let mut body = String::from_utf8_lossy(&ctx.data).into_owned();
            body.push_str("|ENCRYPTED");
            ctx.data = body.into_bytes();
            Verdict::Continue
        }
    }

    /// 拒绝型过滤器：入站一律拒绝
    struct RejectAllFilter;

    impl TrafficFilter for RejectAllFilter {
        fn name(&self) -> &str {
            "reject-all"
        }
        fn on_inbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
            Verdict::Reject("blocked by test".to_string())
        }
    }

    /// 同名 `link-crypto` 的空转过滤器（只验「在链上时不得被协商裁决拒」）
    struct LinkCryptoNamedNoop;

    impl TrafficFilter for LinkCryptoNamedNoop {
        fn name(&self) -> &str {
            wasmnest_server_core::link_crypto::FILTER_NAME
        }
        fn on_inbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
            Verdict::Continue
        }
        fn on_outbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
            Verdict::Continue
        }
    }

    /// 协商头在、本端不参与 → 显性 4xx（fail-visible 裁决）
    ///
    /// 背景：spec §6 决策模型第 3 条「响应绑定」要求「请求一旦带协商头，对端就按信号
    /// 参与，不取决于本端子开关当前值」；同一份 spec 的实现语义段又写「主开关关闭 ⇒
    /// 过滤器不注册」，§7 兼容矩阵更把「任一侧默认关」等同于明文——三处互相矛盾。
    /// 实现落在「不注册」这一支，后果是密文原样透给插件，插件把密文当 JSON 解析，
    /// 回出 `1002 configId required` 这类**误导性业务码**（跨端实测）。本分支按
    /// AGENTS §8「静默错误必须显性化」收口。
    #[actix_web::test]
    async fn negotiated_request_is_rejected_when_link_crypto_not_registered() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        // 链上有**别的**过滤器也不算数——判据是按名找 link-crypto 是否在链上
        chain.register(std::sync::Arc::new(RejectAllFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/echo")
            .insert_header((
                wasmnest_server_core::link_crypto::NEGOTIATION_HEADER,
                "v1 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ))
            .set_payload("hello")
            .to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body = test::read_body(res).await;
        let text = String::from_utf8_lossy(&body);
        // 消息必须点名能力状态与修法，否则用户只看到一句无处置建议的 400
        assert!(text.contains("link encryption"), "拒绝消息应点名链路加密设置: {text}");
        assert!(
            !text.contains("blocked by test"),
            "本端不参与时的拒绝必须来自协商裁决，不得落到链上其他过滤器: {text}"
        );
        chain.clear();
    }

    /// 对照：链上**有** link-crypto 时，带协商头的请求不得被这条裁决拒
    /// （否则能力开启反被自己的守卫挡住）
    #[actix_web::test]
    async fn negotiated_request_passes_when_link_crypto_registered() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(LinkCryptoNamedNoop));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/echo")
            .insert_header((wasmnest_server_core::link_crypto::NEGOTIATION_HEADER, "v1 AAAA"))
            .set_payload("hello")
            .to_request();
        let res = test::call_service(&app, req).await;
        assert!(
            res.status().is_success(),
            "link-crypto 在链上时不得被协商裁决拒: status={}",
            res.status()
        );
        chain.clear();
    }

    /// 内网穿透 T07 端到端锁：旧客户端（不协商）在 `required` 端点上的 400 必须
    /// 带 `X-WasmNest-Crypto-Error: encryption-unsupported`，且**不落到 handler**
    ///
    /// 与 server-core 的过滤器单测互补：那条锁「裁决与码」，这条锁「码真的走到了
    /// HTTP 响应头」——客户端（移动宿主 / 桌面应用）按头分类，不从自由文本里猜。
    #[actix_web::test]
    async fn required_endpoint_without_negotiation_answers_unsupported_code() {
        use crate::wire::EndpointAuth;
        use wasmnest_server_core::link_crypto::{
            self as crypto, CODE_ENCRYPTION_REQUIRED, CODE_ENCRYPTION_UNSUPPORTED, ERROR_HEADER,
        };

        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crypto::init_identity(dir.path()).unwrap();

        let owner = "com.example.t07-legacy-http";
        let path = "/api/plugin/com.example.t07-legacy-http/sessions";
        crate::registry::register(owner, "/sessions", None, &[], EndpointAuth::Jwt).expect("测试端点注册失败");
        crypto::set_app_policy(owner, EncryptionPolicy::Required).unwrap();

        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(LinkEncryptionFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/api/plugin/{owner}/{rest:.*}", web::post().to(echo_handler)),
        )
        .await;

        // ① 无协商头 = 旧客户端 → encryption-unsupported
        let res = test::call_service(
            &app,
            test::TestRequest::post().uri(path).set_payload("hello").to_request(),
        )
        .await;
        assert_eq!(res.status(), actix_web::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            res.headers().get(ERROR_HEADER).and_then(|v| v.to_str().ok()),
            Some(CODE_ENCRYPTION_UNSUPPORTED),
            "无协商头的拒绝码必须是 encryption-unsupported"
        );
        let body = test::read_body(res).await;
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("received"), "拒绝不得落到 handler（无明文回退）: {text}");
        assert!(text.contains("upgrade the peer"), "必须给升级提示: {text}");
        assert!(text.contains(CODE_ENCRYPTION_UNSUPPORTED), "正文与响应头同源: {text}");

        // ② 协商已发起但载荷损坏 → encryption-required（两类不得混码）
        let (_, public) = crypto::generate_ephemeral();
        let negotiation = format!("v1 {}", crypto::b64_encode(&public));
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(path)
                .insert_header((crypto::NEGOTIATION_HEADER, negotiation))
                .set_payload("not-an-envelope")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), actix_web::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            res.headers().get(ERROR_HEADER).and_then(|v| v.to_str().ok()),
            Some(CODE_ENCRYPTION_REQUIRED),
            "坏协商必须归 encryption-required"
        );

        chain.clear();
        crate::registry::purge_for_plugin(owner);
        crypto::remove_app_policy(owner);
    }

    /// 默认态回归：桌面端不开加密（过滤器不在链）时，**无协商头的明文请求照常通过**
    /// ——opt-in 基线，本次 fail-visible 不得改变它
    #[actix_web::test]
    async fn plain_request_passes_when_link_crypto_not_registered() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        TrafficFilterChain::global().clear();

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();
        let res = test::call_service(&app, req).await;
        assert!(
            res.status().is_success(),
            "默认态（不加密）明文请求必须照常通过，不得被协商裁决误伤: status={}",
            res.status()
        );
    }

    /// 拒绝型过滤器：出站一律拒绝（模拟加密链路裁决失败）
    struct RejectOutboundFilter;

    impl TrafficFilter for RejectOutboundFilter {
        fn name(&self) -> &str {
            "reject-outbound"
        }
        fn on_inbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
            Verdict::Continue
        }
        fn on_outbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
            Verdict::Reject("outbound cipher negotiation failed".to_string())
        }
    }

    async fn echo_handler(body: web::Bytes) -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({ "received": String::from_utf8_lossy(&body) }))
    }

    #[actix_web::test]
    async fn request_and_response_bodies_pass_through_chain() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(TransformFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();
        let res = test::call_service(&app, req).await;
        assert!(res.status().is_success());

        // 出站过滤器已改写响应体
        let body = test::read_body(res).await;
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("ENCRYPTED"), "响应体应经过出站过滤: {text}");
        assert!(text.contains("HELLO"), "handler 应收到入站过滤后的大写请求体: {text}");

        chain.clear();
    }

    /// 测试用中间件：模拟对等面 listener 在 extensions 注入 `RequestFace`
    struct InsertPeerFace;

    impl<S, B> actix_web::dev::Transform<S, ServiceRequest> for InsertPeerFace
    where
        S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = actix_web::Error;
        type InitError = ();
        type Transform = InsertPeerFaceMiddleware<S>;
        type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

        fn new_transform(&self, service: S) -> Self::Future {
            std::future::ready(Ok(InsertPeerFaceMiddleware { service }))
        }
    }

    struct InsertPeerFaceMiddleware<S> {
        service: S,
    }

    impl<S, B> actix_web::dev::Service<ServiceRequest> for InsertPeerFaceMiddleware<S>
    where
        S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = actix_web::Error;
        type Future = S::Future;

        fn poll_ready(&self, ctx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
            self.service.poll_ready(ctx)
        }

        fn call(&self, req: ServiceRequest) -> Self::Future {
            req.extensions_mut()
                .insert(RequestFace::peer_face(Some("peer-node-test".to_string()), false));
            self.service.call(req)
        }
    }

    /// 探针过滤器：记录每次过滤上下文里的面标记
    struct FaceProbe(std::sync::Arc<std::sync::Mutex<Vec<RequestFace>>>);

    impl TrafficFilter for FaceProbe {
        fn name(&self) -> &str {
            "face-probe"
        }
        fn on_inbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
            self.0.lock().unwrap().push(ctx.face.clone());
            Verdict::Continue
        }
        fn on_outbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
            self.0.lock().unwrap().push(ctx.face.clone());
            Verdict::Continue
        }
    }

    /// 不变量 15 服务级锁：listener 注入的 `RequestFace` 必须原样进入
    /// `FilterContext.face`（链加密豁免判据的唯一来源），入站 / 出站一致。
    #[actix_web::test]
    async fn listener_face_marker_reaches_filter_context() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(FaceProbe(std::sync::Arc::clone(&captured))));

        // `.wrap(TrafficFilter).wrap(InsertPeerFace)`：后者在外层，先注入再过滤
        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .wrap(InsertPeerFace)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("x").to_request();
        let res = test::call_service(&app, req).await;
        assert!(res.status().is_success());

        let faces = captured.lock().unwrap();
        assert_eq!(faces.len(), 2, "入站与出站各进一次过滤链");
        for face in faces.iter() {
            assert!(face.is_peer(), "面标记必须随请求进入过滤上下文");
            assert_eq!(face.peer_node_id.as_deref(), Some("peer-node-test"));
            assert!(!face.is_pairing());
        }
        drop(faces);
        chain.clear();
    }

    #[actix_web::test]
    async fn inbound_rejection_returns_400_without_reaching_handler() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(RejectAllFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body = test::read_body(res).await;
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("reject-all") && text.contains("blocked by test"),
            "错误响应应携带拒绝详情: {text}"
        );

        chain.clear();
    }

    #[actix_web::test]
    async fn empty_chain_passthrough_keeps_response_intact() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        TrafficFilterChain::global().clear();

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();
        let res = test::call_service(&app, req).await;
        assert!(res.status().is_success());

        let body = test::read_body(res).await;
        assert!(!String::from_utf8_lossy(&body).contains("ENCRYPTED"));
    }

    /// 出站拒绝分支（票据 12 盲区）：run_outbound 返回 Err → 500 响应，
    /// 且不泄露下游 handler 的实际 body（加密链路静默降级防护）
    #[actix_web::test]
    async fn outbound_rejection_returns_500_and_hides_handler_body() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(RejectOutboundFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        let body = test::read_body(res).await;
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("reject") && text.contains("outbound cipher negotiation failed"),
            "500 响应应携带拒绝详情: {text}"
        );
        // 下游 handler 的真实 body（received 字段）不得泄露
        assert!(
            !text.contains("received") && !text.contains("HELLO"),
            "拒绝响应不得泄露下游 handler 内容: {text}"
        );

        chain.clear();
    }

    /// /ws 前缀快速路径（票据 12 盲区）：不缓冲、不走过滤器链，直通下游
    #[actix_web::test]
    async fn ws_prefix_fast_path_skips_filtering() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(RejectAllFilter));

        let app = test::init_service(App::new().wrap(TrafficFilter).route(
            "/ws/terminal",
            web::get().to(|| async { HttpResponse::Ok().body("ws-upgrade-stub") }),
        ))
        .await;
        let req = test::TestRequest::get().uri("/ws/terminal").to_request();
        let res = test::call_service(&app, req).await;
        // 即使链上挂着 RejectAllFilter，/ws 快速路径也应直通下游（不触发 400）
        assert!(res.status().is_success(), "/ws 快速路径应跳过过滤: {}", res.status());
        let body = test::read_body(res).await;
        assert_eq!(String::from_utf8_lossy(&body), "ws-upgrade-stub");

        chain.clear();
    }

    /// HEAD 方法快速路径（票据 12）：不缓冲无 body 响应
    #[actix_web::test]
    async fn head_method_skips_filtering() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(RejectAllFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::head().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;
        let req = test::TestRequest::with_uri("/echo")
            .method(actix_web::http::Method::HEAD)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert!(res.status().is_success(), "HEAD 快速路径应跳过过滤: {}", res.status());

        chain.clear();
    }

    // ==================== 01 完成事件日志 ====================

    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    /// 最小 thread-local 执行器（futures-util 的 executor 特性未启用）：测试中在
    /// `with_default` 同步闭包内驱动一次请求；局部未来无真实 IO，Pending 即让出。
    #[allow(dead_code)] // 仅 cfg(test) 下被测试引用；clippy lib 目标按未引用误报（同 TransformFilter 等既有项）
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut pinned = std::pin::pin!(fut);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(v) => return v,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// 内存收集 fmt 输出（with_default 线程本地：请求未来在测试线程内联轮询，
    /// 事件可直接捕获，无需全局 subscriber）
    #[allow(dead_code)] // 仅 cfg(test) 下被测试引用（见 block_on 注释）
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[allow(dead_code)] // 仅 cfg(test) 下被测试引用（见 block_on 注释）
    struct CaptureWriterMaker(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriterMaker {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriter(self.0.clone())
        }
    }

    /// 在捕获订阅器下执行一次请求（请求类型与 call_service 一致，泛型透传）
    ///
    /// `max_level`：捕获订阅器的级别上限。成功完成事件已降为 `trace`（数据面日志），
    /// 默认 `DEBUG` 捕获会**看不到**它——需要验证成功路径的用例显式传 `TRACE`；
    /// 4xx/5xx 用例传 `DEBUG` 即可（warn/error 恒可见）。
    #[allow(dead_code)] // 仅 cfg(test) 下被测试引用（见 block_on 注释）
    fn run_request_captured<S, R, B, E>(app: &S, buf: &Arc<Mutex<Vec<u8>>>, max_level: tracing::Level, req: R)
    where
        S: actix_web::dev::Service<R, Response = actix_web::dev::ServiceResponse<B>, Error = E>,
        E: std::fmt::Debug,
    {
        use tracing_subscriber::filter::LevelFilter;
        use tracing_subscriber::layer::Layer as _;
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(CaptureWriterMaker(buf.clone()))
            .with_ansi(false)
            .with_target(false)
            .with_filter(LevelFilter::from_level(max_level));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let _ = block_on(test::call_service(app, req));
        });
    }

    /// 01 验收：成功请求在 http_request span 内发完成事件，携带
    /// status/duration_ms/requests_in_window 字段，且 request_id 由 span 继承
    ///
    /// **级别锁**：成功完成必须是 `TRACE`——曾有实现把它放在 `debug`，配合 dev
    /// 控制台 `debug` 兜底与 dev 强制 `file_level=debug`，应用轮询即把控制台与
    /// runtime 日志刷成「200 + 耗时」风暴。此断言是这条降噪结论的回归锁。
    #[actix_web::test]
    async fn completed_request_logs_status_and_duration() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(TransformFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();

        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        run_request_captured(&app, &buf, tracing::Level::TRACE, req);
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();

        // 完成事件：trace 级（数据面降噪）+ status + duration_ms + 秒级聚合计数
        assert!(
            out.contains("TRACE") && out.contains("HTTP request completed"),
            "success completion must be TRACE (debug 会造成请求日志风暴): {out}"
        );
        assert!(out.contains("status=200"), "completion should carry status: {out}");
        assert!(
            out.contains("duration_ms="),
            "completion should carry duration_ms: {out}"
        );
        assert!(
            out.contains("requests_in_window="),
            "completion should carry window aggregate: {out}"
        );
        // span 继承：文本行带 http_request span（含 request_id）
        assert!(
            out.contains("http_request") && out.contains("request_id="),
            "completion should inherit request_id from span: {out}"
        );

        chain.clear();
    }

    /// 降噪回归锁：默认日志级别（debug）下**不得**出现成功完成事件——
    /// 这才是「日志风暴」消失的直接判据（dev 控制台兜底 debug、runtime 层 dev 强制 debug）
    #[actix_web::test]
    async fn successful_completion_is_silent_at_debug_level() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(TransformFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();

        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        run_request_captured(&app, &buf, tracing::Level::DEBUG, req);
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();

        assert!(
            !out.contains("HTTP request completed"),
            "debug 级不得输出成功完成事件（否则高 QPS 应用会刷满日志）: {out}"
        );

        chain.clear();
    }

    /// 01 验收：下游返回 5xx 时完成事件为 error 级
    #[actix_web::test]
    async fn completed_request_error_status_logs_error() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(TransformFilter));

        async fn boom() -> HttpResponse {
            HttpResponse::InternalServerError().finish()
        }
        let app = test::init_service(App::new().wrap(TrafficFilter).route("/boom", web::get().to(boom))).await;
        let req = test::TestRequest::get().uri("/boom").to_request();

        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        run_request_captured(&app, &buf, tracing::Level::DEBUG, req);
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();

        assert!(
            out.contains("ERROR") && out.contains("HTTP request completed with server error"),
            "5xx completion should be error level: {out}"
        );
        assert!(out.contains("status=500"), "completion should carry 500: {out}");

        chain.clear();
    }

    /// 01 回归：拒绝路径既有 warn（带 rej 详情）保留，且完成事件为 4xx warn
    #[actix_web::test]
    async fn rejected_request_keeps_warn_and_logs_completion() {
        let _guard = GLOBAL_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let chain = TrafficFilterChain::global();
        chain.clear();
        chain.register(std::sync::Arc::new(RejectAllFilter));

        let app = test::init_service(
            App::new()
                .wrap(TrafficFilter)
                .route("/echo", web::post().to(echo_handler)),
        )
        .await;
        let req = test::TestRequest::post().uri("/echo").set_payload("hello").to_request();

        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        run_request_captured(&app, &buf, tracing::Level::DEBUG, req);
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();

        // 既有拒绝 warn 保留（rej 详情）
        assert!(
            out.contains("HTTP inbound request rejected by traffic filter") && out.contains("blocked by test"),
            "rejection warn should be kept: {out}"
        );
        // 完成事件：400 → warn 级 + status 字段
        assert!(
            out.contains("WARN") && out.contains("HTTP request completed with client error"),
            "4xx completion should be warn: {out}"
        );
        assert!(out.contains("status=400"), "completion should carry 400: {out}");

        chain.clear();
    }
}
