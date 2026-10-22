//! 监听循环、首连确认闸门与拨号：ticket 02 的传输行为核心。
//!
//! ## 为什么自管 TcpListener + accept 循环而不引入 actix-web（Decision 3）
//!
//! 闸门语义要求在「TLS 握手完成后、上层协议分发前」拦截，actix-web 高层监听
//! 不暴露此缝；本票亦无 HTTP 面，引入 actix 只扩编译面（Android 目标尤其敏感）
//! 而零测试收益。后续 HTTP 服务票在本模块定义的 [`ConnectionHandler`] 缝上挂
//! 低层驱动（`actix_http::HttpService` 可驱动既有 IO 流）或并行 actix-server，
//! 监听/TLS/闸门层零返工——此衔接意图即 ADR 0027「数据面栈复用方向」的落点。
//!
//! ## 事件通道形态
//!
//! 首连确认经 `tokio::sync::mpsc::Sender<TrustEvent>` 推给宿主、应答走帧内
//! `oneshot` 回执：免 async-trait 依赖；有界发送天然背压（宿主不消费则新连接
//! 按拒绝结算）；事件枚举可追加新变体演进。符合 Event-Driven 架构决策。
//!
//! ## 关停语义（Graceful Shutdown）
//!
//! `shutdown` 经 `watch` 广播：accept 循环停止收新连接；在途闸门任务收到信号
//! 后**按拒绝结算**（写 Denied 帧 + 释放 pending 槽位）而非悬挂；随后对剩余
//! 任务给予短暂宽限再强制中止（业务 handler 的长连接由对端关闭或宽限到期收束）。

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::Error as RustlsError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::server::TlsStream as ServerTlsStream;
// 统一流枚举：Connection 需要同形承载 client/server 两侧移交的连接
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream as UnifiedTlsStream};

use crate::base::cert::node_id_from_cert;
use crate::base::error::{PeerNetError, Result};
use crate::base::frame::{
    TrustStatus, TrustStatusFrame, read_frame, write_frame,
};
use crate::base::identity::{NodeId, NodeIdentity};
use crate::base::node::StaticPeerRecord;
use crate::base::tls::{BINDING_MISMATCH_PREFIX, parse_binding_mismatch};

// ==================== 常量 ====================

/// 首连确认超时：留足用户读弹窗时间；超时按拒绝处理并关闭连接（拨号方可重试）
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);

/// 并发 pending 确认上限：防同网恶意节点堆 pending 耗尽内存的资源保护
///
/// 超限新连接立即按拒绝结算；同一 node_id 已有 pending 时重复拨入也直接拒绝，
/// 避免弹窗风暴（Decision 6）。
pub const MAX_PENDING_CONFIRMATIONS: usize = 8;

/// TCP accept 出错后的退避间隔：避免持续错误时热循环空转
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// 关停时给在途任务的宽限期：闸门任务在信号后即时结算，宽限只留给业务 handler
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

// ==================== 事件 ====================

/// 推送给宿主的信任事件
#[derive(Debug)]
pub enum TrustEvent {
    /// 新节点首次拨入，等待宿主确认
    ///
    /// 宿主经 `reply` 回执 `true`=接受（双方落库并连通）/ `false`=拒绝；
    /// 弃置回执（drop Sender）等同拒绝。
    ConfirmRequested {
        /// 请求确认的对端节点 ID
        node_id: NodeId,
        /// 应答回执通道
        reply: oneshot::Sender<bool>,
    },
}

// ==================== 连接与 handler 缝 ====================

/// 一条已完成 mTLS 握手且通过信任放行的连接
///
/// 身份已在 TLS 层证毕（证书指纹钉扎 + CertificateVerify 私钥持有证明），
/// 上层无需也无法再做身份协商；`AsyncRead`/`AsyncWrite` 直接透传内层流，
/// 供后续 HTTP/WS 服务票原样挂载（ADR 0027 衔接缝）。
///
/// 内部用 tokio-rustls 的统一 `TlsStream` 枚举承载：拨号侧（client 变体）与
/// 接听侧（server 变体）移交的连接对上层形态一致。
#[derive(Debug)]
pub struct Connection {
    io: UnifiedTlsStream<TcpStream>,
    peer_node_id: NodeId,
}

impl Connection {
    pub(crate) fn new(
        io: impl Into<UnifiedTlsStream<TcpStream>>,
        peer_node_id: NodeId,
    ) -> Self {
        Self {
            io: io.into(),
            peer_node_id,
        }
    }

    /// 对端已认证节点 ID（客户端证书 SPKI 公钥指纹）
    pub fn peer_node_id(&self) -> &NodeId {
        &self.peer_node_id
    }

    /// 对端 TCP 地址（供日志/UI 展示）
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.get_ref().0.peer_addr()
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// handler 返回的 future：由 transport 在该连接的独立任务中驱动至完成
pub type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// 信任放行后的上层协议处理缝（后续 HTTP 服务票的挂载点）
///
/// 实现方拿到 [`Connection`] 即持有完全认证的传输流；返回的 future 结束或被
/// 关停中止都意味着连接生命周期终止。同步 trait 方法 + 显式 boxed future：
/// 免 async-trait 依赖且保持对象安全（`Arc<dyn ConnectionHandler>`）。
pub trait ConnectionHandler: Send + Sync + 'static {
    /// 处理一条信任放行的已认证连接
    fn handle(&self, conn: Connection) -> HandlerFuture;
}

// ==================== 运行期共享上下文 ====================

/// accept 循环与各连接任务共享的运行期状态（内部互斥，禁止 unsafe impl）
pub(crate) struct NodeRuntime {
    trust: Arc<crate::base::trust_store::TrustStore>,
    events: mpsc::Sender<TrustEvent>,
    handler: Arc<dyn ConnectionHandler>,
    /// 当前处于确认闸门的节点 ID 集合（去重 + 上限判定）
    pending: Mutex<HashSet<NodeId>>,
}

impl NodeRuntime {
    pub(crate) fn new(
        trust: Arc<crate::base::trust_store::TrustStore>,
        events: mpsc::Sender<TrustEvent>,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Self {
        Self {
            trust,
            events,
            handler,
            pending: Mutex::new(HashSet::new()),
        }
    }

    /// 尝试为该节点占用一个 pending 槽位；重复拨入或超上限均拒绝（Decision 6）
    fn try_enter_pending(&self, node_id: &NodeId) -> bool {
        let mut guard = self.pending.lock().expect("pending table lock poisoned");
        if guard.contains(node_id) || guard.len() >= MAX_PENDING_CONFIRMATIONS {
            return false;
        }
        guard.insert(node_id.clone());
        true
    }

    /// 释放 pending 槽位（无论结论是接受还是拒绝都必须调用）
    fn settle_pending(&self, node_id: &NodeId) {
        self.pending
            .lock()
            .expect("pending table lock poisoned")
            .remove(node_id);
    }

    fn trust(&self) -> &Arc<crate::base::trust_store::TrustStore> {
        &self.trust
    }
}

// ==================== 监听循环 ====================

/// accept 循环主体：TCP accept → TLS 握手 → 信任分流 → handler 移交
///
/// 由 [`crate::base::node::PeerNetNode::start`] 系列方法在 tokio 任务中启动；正常
/// 只因 shutdown 信号退出，退出前排空所有在途连接任务（见模块文档关停语义）。
pub(crate) async fn run_accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    runtime: Arc<NodeRuntime>,
    mut shutdown: watch::Receiver<bool>,
) {
    let local_addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    tracing::info!(addr = %local_addr, "peer-net listening");

    let mut conn_tasks: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;

            _ = wait_for_shutdown(&mut shutdown) => {
                tracing::info!(addr = %local_addr, "peer-net accept loop stopping");
                break;
            }

            accepted = listener.accept() => match accepted {
                Ok((tcp, peer_addr)) => {
                    let acceptor = acceptor.clone();
                    let runtime = Arc::clone(&runtime);
                    let mut conn_shutdown = shutdown.clone();
                    conn_tasks.spawn(async move {
                        enable_keepalive(&tcp);
                        if let Err(e) =
                            serve_inbound(tcp, peer_addr, acceptor, runtime, &mut conn_shutdown).await
                        {
                            tracing::warn!(peer = %peer_addr, "inbound connection ended with error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(addr = %local_addr, "TCP accept failed: {e}");
                    // 错误退避必须保持对关停信号的响应
                    tokio::select! {
                        biased;
                        _ = wait_for_shutdown(&mut shutdown) => break,
                        _ = tokio::time::sleep(ACCEPT_BACKOFF) => {}
                    }
                }
            },
        }
    }

    // ---- 关停排空：先等闸门类任务按拒绝结算自然退出，宽限后强制中止 ----
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    loop {
        tokio::select! {
            biased;
            finished = conn_tasks.join_next() => match finished {
                Some(result) => log_join_result("inbound connection", result),
                None => break,
            },
            _ = tokio::time::sleep_until(deadline) => {
                let aborted = conn_tasks.len();
                conn_tasks.abort_all();
                if aborted > 0 {
                    tracing::warn!(
                        count = aborted,
                        "aborted remaining connections after shutdown grace period"
                    );
                }
                // abort 之后继续排空直至全部收束
                while let Some(result) = conn_tasks.join_next().await {
                    log_join_result("inbound connection", result);
                }
                break;
            }
        }
    }
}

/// 单条入站连接的全生命周期：握手 → 身份提取 → 信任分流 → 闸门 → handler
async fn serve_inbound(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    runtime: Arc<NodeRuntime>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    // TLS 握手：mandatory client auth + 形状校验 verifier 在此生效；
    // 非 WasmNest 客户端在此直接失败（ADR 0027 协议私有）
    let mut tls = tokio::select! {
        biased;
        _ = wait_for_shutdown(shutdown) => return Ok(()),
        handshook = acceptor.accept(tcp) => handshook
            .map_err(|e| map_handshake_error(peer_addr, e))?,
    };

    let certs = tls
        .get_ref()
        .1
        .peer_certificates()
        .ok_or(PeerNetError::PeerCertMissing { peer_addr })?;
    let end_entity = certs.first().ok_or(PeerNetError::PeerCertMissing { peer_addr })?;
    let peer_id = node_id_from_cert(end_entity.as_ref()).map_err(|e| PeerNetError::TlsHandshake {
        peer_addr,
        detail: format!("client certificate unusable: {e}"),
    })?;

    if runtime.trust().contains(&peer_id) {
        // 信任直通快路径：仍无条件发 Accepted 帧——双向信任态不对称（A 信 B 但
        // B 可能已撤销 A），统一「必发一帧」消除谁该等帧的歧义（Decision 3）
        write_frame(&mut tls, &TrustStatusFrame::accepted(&peer_id))
            .await
            .map_err(|e| control_frame_error(peer_addr, e))?;
        tracing::info!(
            node_id = %peer_id,
            short = %peer_id.short_fingerprint(),
            peer = %peer_addr,
            "trusted peer connected"
        );
        return deliver_to_handler(runtime, tls, peer_id, peer_addr).await;
    }

    // ---- 首连确认闸门 ----
    if !runtime.try_enter_pending(&peer_id) {
        // 同 ID 已有 pending（弹窗风暴防护）或超并发上限（资源保护）：直接拒绝
        tracing::warn!(
            node_id = %peer_id,
            peer = %peer_addr,
            "connection rejected: confirmation already pending or cap reached"
        );
        write_best_effort_denied(&mut tls, &peer_id, peer_addr).await;
        return Ok(());
    }

    // —— 已进入 pending 表：以下任何出口都必须先 settle ——
    let verdict: bool = 'gate: {
        if let Err(e) =
            write_frame(&mut tls, &TrustStatusFrame::pending_confirmation(&peer_id)).await
        {
            tracing::warn!(node_id = %peer_id, peer = %peer_addr, "write pending frame failed: {e}");
            break 'gate false;
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        if let Err(e) = runtime.events.try_send(TrustEvent::ConfirmRequested {
            node_id: peer_id.clone(),
            reply: reply_tx,
        }) {
            // 事件通道满或宿主已停消费：按拒绝结算（背压语义，模块文档）
            tracing::warn!(node_id = %peer_id, "confirm event undeliverable, denying: {e}");
            break 'gate false;
        }
        tracing::info!(
            node_id = %peer_id,
            short = %peer_id.short_fingerprint(),
            peer = %peer_addr,
            "first-connect confirmation requested"
        );

        let decision = tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => false,
            waited = tokio::time::timeout(CONFIRM_TIMEOUT, reply_rx) => match waited {
                Ok(Ok(accepted)) => accepted,
                // 宿主弃置回执视为拒绝（oneshot 文档约定）
                Ok(Err(_recv_closed)) => false,
                Err(_elapsed) => {
                    let timeout = PeerNetError::ConfirmTimeout { node_id: peer_id.clone() };
                    tracing::warn!("{timeout}; treating as denial");
                    false
                }
            },
        };
        break 'gate decision;
    };
    runtime.settle_pending(&peer_id);

    if verdict {
        // 双向落库的接听侧半边；持久化失败不影响本次放行（远端已确认，连接本身
        // 有效），仅影响重启后免确认——如实记日志交运维感知
        if let Err(e) = runtime.trust().add(&peer_id) {
            tracing::error!(node_id = %peer_id, "persist newly trusted peer failed: {e}");
        }
        if let Err(e) = write_frame(&mut tls, &TrustStatusFrame::accepted(&peer_id)).await {
            return Err(control_frame_error(peer_addr, e));
        }
        tracing::info!(node_id = %peer_id, short = %peer_id.short_fingerprint(), "first-connect confirmed, trusting peer");
        return deliver_to_handler(runtime, tls, peer_id, peer_addr).await;
    }

    write_best_effort_denied(&mut tls, &peer_id, peer_addr).await;
    tracing::info!(node_id = %peer_id, short = %peer_id.short_fingerprint(), "first-connect denied or timed out");
    Ok(())
}

/// 把放行的连接移交给宿主 handler 并驱动至完成（连接所有权移交）
async fn deliver_to_handler(
    runtime: Arc<NodeRuntime>,
    tls: ServerTlsStream<TcpStream>,
    peer_id: NodeId,
    peer_addr: SocketAddr,
) -> Result<()> {
    let conn = Connection::new(tls, peer_id);
    let fut = runtime.handler.handle(conn);
    fut.await;
    tracing::debug!(peer = %peer_addr, "handler finished for connection");
    Ok(())
}

// ==================== 拨号 ====================

/// 拨号对端：TCP 连接 → 客户端 mTLS 握手（身份钉扎在此生效）→ 读状态帧分流
///
/// - 对端发 `Accepted` → 本地可信表落库（双向落库的发起侧半边），返回连接；
/// - `Denied` → [`PeerNetError::DialDeniedByPeer`]（用户拒绝/超时/资源拒绝），
///   可重试；
/// - 中间态 `PendingConfirmation` → 继续等待终态帧（宿主思考时间可达
///   [`CONFIRM_TIMEOUT`]）；
/// - 证书指纹与期望不符 → [`PeerNetError::TlsBindingMismatch`]（AC#3 断言点）。
/// LAN 活性探测：拨号/接听即设 TCP keepalive
///
/// 对端静默死亡（WiFi 骤断/休眠等无 FIN 场景）时探测失败让挂起的读写以
/// 错误返回——宿主侧会话活性泵与入站 handler 据此感知中断并发断开事件。
/// 时间窗取「30s 静默 + 10s×3 探测」（interval/retries 仅 Unix 可显式设置，
/// Windows 用系统默认约 1-2s、收敛更快但两端不一致），LAN 规模下断网约
/// 1 分钟内收敛。
fn enable_keepalive(tcp: &TcpStream) {
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    #[cfg(unix)]
    let ka = ka.with_interval(Duration::from_secs(10)).with_retries(3);
    // keepalive 设置失败不阻断建连（fail-open），但必须留痕：首帧超时移除后
    // 连接活性强依赖此探测，静默失败会让对端静默死亡时挂起无兜底
    if let Err(e) = socket2::SockRef::from(tcp).set_tcp_keepalive(&ka) {
        tracing::warn!(error = %e, "set TCP keepalive failed; dead-peer detection degraded");
    }
}

pub(crate) async fn dial(
    identity: &NodeIdentity,
    own_cert_der: &[u8],
    trust: &Arc<crate::base::trust_store::TrustStore>,
    record: &StaticPeerRecord,
) -> Result<Connection> {
    let tcp = TcpStream::connect(record.addr)
        .await
        .map_err(|e| PeerNetError::DialConnect {
            addr: record.addr,
            source: e,
        })?;
    enable_keepalive(&tcp);

    let config = crate::base::tls::client_config(&record.node_id, identity, own_cert_der)?;
    let connector = TlsConnector::from(Arc::new(config));
    // 自定义 verifier 忽略 server_name（身份由证书指纹钉扎）；IP 直连无 DNS，
    // 用 IpAddress 形态满足类型要求即可
    let server_name = ServerName::from(record.addr.ip());

    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| map_handshake_error(record.addr, e))?;

    loop {
        let frame =
            read_frame(&mut tls)
                .await
                .map_err(|e| control_frame_error(record.addr, e))?;
        let subject = NodeId::parse(&frame.node_id).map_err(|_| PeerNetError::ControlFrame {
            peer_addr: record.addr,
            detail: format!("status frame carries invalid node id: {}", frame.node_id),
        })?;
        // 状态帧的 node_id 指拨入方（本节）自身：对端在陈述「关于你」的信任状态。
        // 不符说明对端状态机错乱或未来多路复用时误投递，防御性拒绝
        if subject != *identity.node_id() {
            return Err(PeerNetError::UnknownPeer { node_id: subject });
        }

        match frame.status {
            TrustStatus::Accepted => {
                // 发起侧半边落库；持久化失败仅影响重启后免确认，连接仍有效
                if let Err(e) = trust.add(&record.node_id) {
                    tracing::error!(node_id = %record.node_id, "persist trusted peer after accepted dial failed: {e}");
                }
                tracing::info!(
                    node_id = %record.node_id,
                    short = %record.node_id.short_fingerprint(),
                    peer = %record.addr,
                    "dial accepted by peer"
                );
                return Ok(Connection::new(tls, record.node_id.clone()));
            }
            TrustStatus::Denied => {
                tracing::info!(
                    node_id = %record.node_id,
                    peer = %record.addr,
                    "dial denied by peer"
                );
                return Err(PeerNetError::DialDeniedByPeer {
                    node_id: record.node_id.clone(),
                });
            }
            TrustStatus::PendingConfirmation => {
                tracing::debug!(
                    node_id = %record.node_id,
                    peer = %record.addr,
                    "peer confirmation gate open, waiting for verdict"
                );
                continue;
            }
        }
    }
}

// ==================== 内部辅助 ====================

/// 等待关停信号（值为真）。用 borrow_and_update 标记版本，避免错过信号
async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow_and_update() {
            return;
        }
    }
}

/// 尽力写入 Denied 帧：写失败只记日志——连接即将关闭，无恢复动作可做
async fn write_best_effort_denied(
    tls: &mut ServerTlsStream<TcpStream>,
    peer_id: &NodeId,
    peer_addr: SocketAddr,
) {
    if let Err(e) = write_frame(tls, &TrustStatusFrame::denied(peer_id)).await {
        tracing::warn!(node_id = %peer_id, peer = %peer_addr, "write denied frame failed: {e}");
    }
}

/// 控制帧 IO 错误归一到 ControlFrame 变体
fn control_frame_error(peer_addr: SocketAddr, e: std::io::Error) -> PeerNetError {
    PeerNetError::ControlFrame {
        peer_addr,
        detail: e.to_string(),
    }
}

/// 把 tokio-rustls 的握手错误归一到具体错误种类
///
/// tokio-rustls 以 `io::Error` 包装 rustls 错误（inner 为 `rustls::Error`）：
/// 下钻还原类型信息，把「指纹不符」从一般握手失败中分拣出来（AC#3 需要
/// 错误种类级断言）。
fn map_handshake_error(peer_addr: SocketAddr, e: std::io::Error) -> PeerNetError {
    let io_display = e.to_string();
    let inner = e.into_inner().and_then(|b| b.downcast::<RustlsError>().ok().map(|b| *b));
    match inner {
        Some(RustlsError::General(msg)) if msg.starts_with(BINDING_MISMATCH_PREFIX) => {
            let (expected, actual) = parse_binding_mismatch(&msg)
                .unwrap_or_else(|| (String::new(), String::new()));
            PeerNetError::TlsBindingMismatch { expected, actual }
        }
        Some(other) => PeerNetError::TlsHandshake {
            peer_addr,
            detail: other.to_string(),
        },
        None => PeerNetError::TlsHandshake {
            peer_addr,
            detail: io_display,
        },
    }
}

/// 记录任务 join 结果（JoinError 分级日志：取消属预期，panic 属异常）
fn log_join_result(label: &'static str, result: std::result::Result<(), JoinError>) {
    match result {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => tracing::debug!("{label} task cancelled during shutdown"),
        Err(e) => tracing::error!("{label} task panicked: {e}"),
    }
}

// ==================== 运行句柄 ====================

/// 节点运行句柄：accept 循环存活期的控制面
///
/// 由 [`crate::base::node::PeerNetNode`] 的 start 系列方法产出；drop 句柄**不会**停
/// 节点（任务已移交运行时），显式关停必须调用 [`RunningNode::shutdown`]。
pub struct RunningNode {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    accept_task: Option<JoinHandle<()>>,
}

impl RunningNode {
    /// 实际监听地址（自绑路径下可能与配置的 `bind_addr` 端口 0 展开值不同）
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 优雅关停：停收新连接 → 在途闸门按拒绝结算 → 排空/中止在途连接 → join
    ///
    /// 已放行的业务 handler 连接有 [`SHUTDOWN_GRACE`] 宽限，超时强制中止——
    /// 长连接的收尾属宿主协议层职责（Graceful Shutdown 架构决策）。
    pub async fn shutdown(mut self) {
        // 先广播：accept 循环退出接收；闸门任务按拒绝结算并写 Denied 帧
        if self.shutdown_tx.send(true).is_err() {
            // 全部接收端已消失 = 循环早已结束；无需再等
            tracing::debug!("shutdown signal skipped: accept loop receivers already gone");
        }
        if let Some(task) = self.accept_task.take() {
            match task.await {
                Ok(()) => tracing::info!("peer-net node shut down cleanly"),
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("peer-net accept loop already cancelled")
                }
                Err(e) => log_join_result("peer-net accept loop", Err(e)),
            }
        }
    }
}

/// 启动监听装配线：listener 准备 → TLS 配置 → 共享上下文 → spawn accept 循环
///
/// 必须在 tokio 运行时上下文中调用（spawn 依赖 Handle::current）：生产侧为
/// tauri 异步环境，测试侧为 `#[tokio::test]`。
pub(crate) fn spawn_running_node(
    listener: std::net::TcpListener,
    identity: &NodeIdentity,
    own_cert_der: &[u8],
    trust: Arc<crate::base::trust_store::TrustStore>,
    events: mpsc::Sender<TrustEvent>,
    handler: Arc<dyn ConnectionHandler>,
) -> Result<RunningNode> {
    let local_addr =
        listener
            .local_addr()
            .map_err(|source| PeerNetError::ListenerPrepare { source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| PeerNetError::ListenerPrepare { source })?;
    let listener =
        TcpListener::from_std(listener).map_err(|source| PeerNetError::ListenerPrepare {
            source,
        })?;

    let server_config = Arc::new(crate::base::tls::server_config(identity, own_cert_der)?);
    let acceptor = TlsAcceptor::from(server_config);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = Arc::new(NodeRuntime::new(trust, events, handler));

    let accept_task = tokio::spawn(run_accept_loop(listener, acceptor, runtime, shutdown_rx));
    Ok(RunningNode {
        local_addr,
        shutdown_tx,
        accept_task: Some(accept_task),
    })
}
