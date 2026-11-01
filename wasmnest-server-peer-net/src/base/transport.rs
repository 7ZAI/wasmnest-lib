//! libp2p 传输适配层：连接/流、信任状态握手、准入桥与节点的启动/关停。
//!
//! ## P1 换轨口径
//!
//! 旧实现自管 `TcpListener` + rustls mTLS + 自签证书；P1 起连接、加密、身份
//! 与多路复用全部交给 `wasmnest-p2p-engine`（TCP + noise + yamux + ping）。
//! 本模块只保留 peer-net 的线协议语义：
//!
//! - `/wasmnest/trust-status/1`：拨号方先发 [`TrustHelloFrame`] 声明期望对端，
//!   接听方校验后才请求准入，再把 Pending / Accepted / Denied 写回；
//! - `/wasmnest/transfer/1`、`/wasmnest/shared-dir/1`、`/wasmnest/session/1`：
//!   业务流，帧编解码（`frame.rs` / `transfer/message.rs` / `shared.rs`）
//!   **逐字复用**——它们只依赖 `AsyncRead`/`AsyncWrite`，本模块用 tokio-util
//!   compat 把 libp2p 子流转成 tokio IO。
//!
//! ## 准入闸门
//!
//! 引擎以 `admit_on_connect = false` 启动：入站连接只登记 `Pending`，不产生
//! 确认回调。信任状态流先读 Hello 并校验期望身份，再显式
//! [`wasmnest_p2p_engine::engine::RunningNode::request_admission`]——伪造身份
//! 记录在接听侧不会弹确认窗（对齐旧 TLS 钉扎语义）。业务流由引擎按
//! `Admitted` 过滤，闸门放行前零业务协议流量。
//!
//! ## 关停语义
//!
//! [`RunningNode::shutdown`] 停引擎（swarm 析构关闭全部连接与流），再中止本层
//! 派生出的协议接收循环；在途 handler 因流关闭自然收束。

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

use wasmnest_p2p_engine::admission::AdmissionConfig;
use wasmnest_p2p_engine::engine::{socket_addr_to_multiaddr, P2pEngine, P2pNodeConfig, RunningNode as P2pRunningNode};
use wasmnest_p2p_engine::error::P2pError;
use wasmnest_p2p_engine::identity_bridge::{NodeId as P2pNodeId, NodeKey};
use wasmnest_p2p_engine::links::LinkAdmission;
use wasmnest_p2p_engine::ports::{
    DialFailed, P2pEventSink, P2pPorts, PeerAdmissionPort, PeerConnected, PeerDenied, PeerDisconnected,
};
use wasmnest_p2p_engine::stream_proto;
use wasmnest_p2p_engine::{InboundStream, IncomingStreams, P2pStream, PeerId as P2pPeerId};

use crate::base::error::{PeerNetError, Result};
use crate::base::frame::{
    read_frame, read_hello, write_frame, write_hello, TrustHelloFrame, TrustStatus, TrustStatusFrame,
};
use crate::base::identity::{NodeId, NodeIdentity};
use crate::base::node::StaticPeerRecord;
use crate::base::trust_store::TrustStore;

/// 首连确认超时：留足用户读弹窗时间；超时按拒绝处理（引擎闸门结算）
pub use wasmnest_p2p_engine::admission::DEFAULT_CONFIRM_TIMEOUT as CONFIRM_TIMEOUT;

/// 并发 pending 确认上限：防同网恶意节点堆 pending 耗尽内存的资源保护
pub use wasmnest_p2p_engine::admission::DEFAULT_MAX_PENDING as MAX_PENDING_CONFIRMATIONS;

/// 等拨号方 Hello 的窗口：超时即关闭信任状态流（不触发确认回调）
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

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

/// 一条已通过身份校验与信任放行的会话流
///
/// 底层是 libp2p 具名子流：noise 已完成双向身份认证，PeerId → node_id 互验在
/// 引擎侧完成；本类型只把 futures IO 适配成 tokio IO，供既有帧编解码原样消费。
pub struct Connection {
    io: Compat<P2pStream>,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peer_node_id", &self.peer_node_id)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl Connection {
    pub(crate) fn new(stream: P2pStream, peer_node_id: NodeId, peer_addr: SocketAddr) -> Self {
        Self {
            io: stream.compat(),
            peer_node_id,
            peer_addr,
        }
    }

    /// 对端已认证节点 ID（PeerId 公钥 → SHA-256 指纹，引擎侧已完成互验）
    pub fn peer_node_id(&self) -> &NodeId {
        &self.peer_node_id
    }

    /// 对端地址（供日志/UI 展示）
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// handler 返回的 future：由 transport 在该连接的独立任务中驱动至完成
pub type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// 信任放行后的上层协议处理缝
///
/// 实现方拿到 [`Connection`] 即持有完全认证的传输流；返回的 future 结束或
/// 连接关闭都意味着会话生命周期终止。同步 trait 方法 + 显式 boxed future：
/// 免 async-trait 依赖且保持对象安全（`Arc<dyn ConnectionHandler>`）。
pub trait ConnectionHandler: Send + Sync + 'static {
    /// 处理一条信任放行的已认证连接
    fn handle(&self, conn: Connection) -> HandlerFuture;
}

// ==================== 信任准入桥 ====================

/// 引擎准入端口 → 宿主首连确认事件
struct TrustAdmissionPort {
    trust: Arc<TrustStore>,
    events: mpsc::Sender<TrustEvent>,
}

#[async_trait::async_trait]
impl PeerAdmissionPort for TrustAdmissionPort {
    async fn confirm_inbound(&self, node_id: &P2pNodeId, _peer_id: &P2pPeerId) -> bool {
        let Ok(node_id) = NodeId::parse(node_id.as_str()) else {
            tracing::warn!(raw = %node_id, "inbound admission carries invalid node id");
            return false;
        };
        if self.trust.contains(&node_id) {
            return true;
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        if let Err(e) = self.events.try_send(TrustEvent::ConfirmRequested {
            node_id: node_id.clone(),
            reply: reply_tx,
        }) {
            // 事件通道满或宿主已停消费：按拒绝结算（背压语义）
            tracing::warn!(node_id = %node_id, "confirm event undeliverable, denying: {e}");
            return false;
        }
        match reply_rx.await {
            Ok(true) => {
                // 接听侧半边落库；持久化失败不影响本次放行，仅影响重启后免确认
                if let Err(e) = self.trust.add(&node_id) {
                    tracing::error!(node_id = %node_id, "persist newly trusted peer failed: {e}");
                }
                true
            }
            // 宿主弃置回执视为拒绝（oneshot 文档约定）
            _ => false,
        }
    }
}

/// 引擎连接态事件出口：本层不消费（连接态由 `InboundConnectionBridge` 与
/// 宿主出站会话表维护），只留诊断日志。
struct LogEventSink;

impl P2pEventSink for LogEventSink {
    fn listening_changed(&self, addrs: Vec<SocketAddr>) {
        tracing::debug!(?addrs, "p2p listening addresses changed");
    }
    fn peer_connected(&self, ev: PeerConnected) {
        tracing::debug!(
            node_id = %ev.node_id,
            outbound = ev.outbound,
            addr = %ev.remote_addr,
            "p2p peer connected"
        );
    }
    fn peer_disconnected(&self, ev: PeerDisconnected) {
        tracing::debug!(
            node_id = %ev.node_id,
            by_local = ev.by_local,
            "p2p peer disconnected"
        );
    }
    fn peer_denied(&self, ev: PeerDenied) {
        tracing::warn!(
            node_id = ?ev.node_id,
            cause = ?ev.cause,
            "p2p inbound peer denied"
        );
    }
    fn dial_failed(&self, ev: DialFailed) {
        tracing::debug!(
            addr = %ev.addr,
            cause = %ev.cause,
            "p2p dial failed"
        );
    }
}

// ==================== 拨号 ====================

/// 拨号对端：引擎连接/校验 → Hello 信任握手 → 开指定业务流
///
/// - 对端身份与记录不符 → [`PeerNetError::IdentityMismatch`]（引擎握手后校验）；
/// - 对端 `Denied` → [`PeerNetError::DialDeniedByPeer`]（用户拒绝/超时/资源拒绝）；
/// - 中间态 `PendingConfirmation` → 继续等终态帧（窗口见 [`CONFIRM_TIMEOUT`]）。
pub(crate) async fn dial(
    p2p: &P2pRunningNode,
    identity: &NodeIdentity,
    trust: &Arc<TrustStore>,
    record: &StaticPeerRecord,
    protocol: &'static str,
) -> Result<Connection> {
    let expected = P2pNodeId::parse(record.node_id.as_str()).map_err(|e| PeerNetError::Transport {
        detail: format!("invalid node id: {e}"),
    })?;
    p2p.dial(socket_addr_to_multiaddr(record.addr), expected.clone())
        .await
        .map_err(map_p2p_error)?;

    // 信任状态流：Hello 声明期望对端，接听方校验后才请求准入
    let trust_stream = p2p
        .open_stream(&expected, stream_proto::TRUST_STATUS)
        .await
        .map_err(map_p2p_error)?;
    let mut trust_io = trust_stream.compat();
    write_hello(&mut trust_io, &TrustHelloFrame::new(&record.node_id))
        .await
        .map_err(|e| control_frame_error(record.addr, e))?;

    loop {
        let frame = read_frame(&mut trust_io)
            .await
            .map_err(|e| control_frame_error(record.addr, e))?;
        let subject = NodeId::parse(&frame.node_id).map_err(|_| PeerNetError::ControlFrame {
            peer_addr: record.addr,
            detail: format!("status frame carries invalid node id: {}", frame.node_id),
        })?;
        // 状态帧的 node_id 指拨入方（本节）自身：不符说明对端状态机错乱
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
                    protocol,
                    "dial accepted by peer"
                );
                break;
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

    let stream = p2p.open_stream(&expected, protocol).await.map_err(map_p2p_error)?;
    Ok(Connection::new(stream, record.node_id.clone(), record.addr))
}

// ==================== 入站协议接收 ====================

/// 业务协议接收循环：引擎已按 `Admitted` 过滤，本层只转成 [`Connection`] 并
/// 交给宿主 handler（每条流一个任务，互不阻塞）。
async fn accept_business_streams(
    mut streams: IncomingStreams,
    handler: Arc<dyn ConnectionHandler>,
    protocol: &'static str,
) {
    while let Some(inbound) = streams.next().await {
        let Ok(node_id) = NodeId::parse(inbound.node_id.as_str()) else {
            tracing::warn!(protocol, raw = %inbound.node_id, "inbound stream carries invalid node id");
            continue;
        };
        let conn = Connection::new(inbound.stream, node_id, inbound.remote_addr);
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            handler.handle(conn).await;
        });
    }
    tracing::debug!(protocol, "inbound business stream acceptor ended");
}

/// 信任状态流接收循环：每流独立任务（Hello 等待不阻塞其他连接）
async fn accept_trust_streams(
    mut streams: IncomingStreams,
    p2p: P2pRunningNode,
    own_node_id: NodeId,
    trust: Arc<TrustStore>,
) {
    while let Some(inbound) = streams.next().await {
        let p2p = p2p.clone();
        let own_node_id = own_node_id.clone();
        let trust = Arc::clone(&trust);
        tokio::spawn(async move {
            if let Err(detail) = serve_trust_stream(inbound, p2p, own_node_id, trust).await {
                tracing::debug!("trust-status stream ended: {detail}");
            }
        });
    }
    tracing::debug!("trust-status stream acceptor ended");
}

/// 单条信任状态流：Hello 校验 → 显式准入 → 写 Pending / 终态帧
///
/// 连接复用下信任可能已被撤销：链路上旧 `Admitted` 快照不能直接复用，必须先
/// 按可信表重置准入再重走闸门（否则撤销后重连会被静默放行）。
async fn serve_trust_stream(
    inbound: InboundStream,
    p2p: P2pRunningNode,
    own_node_id: NodeId,
    trust: Arc<TrustStore>,
) -> std::result::Result<(), String> {
    let peer_id = inbound.peer_id;
    let peer_addr = inbound.remote_addr;
    let peer_node_id = NodeId::parse(inbound.node_id.as_str()).map_err(|e| e.to_string())?;
    let p2p_peer_node_id = P2pNodeId::parse(inbound.node_id.as_str()).map_err(|e| e.to_string())?;
    let mut io = inbound.stream.compat();

    // 先校验拨号方期望的对端身份：不符即关闭，不触发确认回调
    let hello = tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut io))
        .await
        .map_err(|_| format!("hello timeout ({peer_addr})"))?
        .map_err(|e| format!("hello read failed ({peer_addr}): {e}"))?;
    if hello.expected_node_id != own_node_id.as_str() {
        tracing::warn!(
            peer = %peer_addr,
            expected = %hello.expected_node_id,
            own = %own_node_id,
            "dialer expected another node; rejecting without confirmation callback"
        );
        let _ = p2p.disconnect(p2p_peer_node_id).await;
        return Ok(());
    }

    let link = p2p
        .peer_link(&p2p_peer_node_id)
        .ok_or("link vanished before admission")?;
    let trusted = trust.contains(&peer_node_id);
    let already_admitted = link.admission == LinkAdmission::Admitted;
    if !trusted || !already_admitted {
        p2p.reset_admission(&peer_id)
            .await
            .map_err(|e| format!("reset admission failed: {e}"))?;
    }

    let Some(mut watch) = p2p.admission_watch(&peer_id) else {
        return Ok(());
    };
    if let Err(e) = p2p.request_admission(&peer_id).await {
        // 已拒绝 / 链路消失：按 watch 当前值写终态（Denied 仍要写回拨号方）
        tracing::debug!(peer = %peer_addr, error = %e, "request admission returned error");
    }

    let mut state = *watch.borrow();
    loop {
        let frame = match state {
            LinkAdmission::Pending => TrustStatusFrame::pending_confirmation(&peer_node_id),
            LinkAdmission::Admitted => TrustStatusFrame::accepted(&peer_node_id),
            LinkAdmission::Denied => TrustStatusFrame::denied(&peer_node_id),
        };
        write_frame(&mut io, &frame)
            .await
            .map_err(|e| format!("write status failed ({peer_addr}): {e}"))?;
        if state != LinkAdmission::Pending {
            break;
        }
        if watch.changed().await.is_err() {
            return Ok(());
        }
        state = *watch.borrow();
    }
    Ok(())
}

// ==================== 内部辅助 ====================

/// 控制帧 IO 错误归一到 ControlFrame 变体
fn control_frame_error(peer_addr: SocketAddr, e: std::io::Error) -> PeerNetError {
    PeerNetError::ControlFrame {
        peer_addr,
        detail: e.to_string(),
    }
}

/// 引擎错误 → peer-net 错误（消费方按 `DialDeniedByPeer` / `IdentityMismatch`
/// 分支，其余归入 Transport 明细）
fn map_p2p_error(e: P2pError) -> PeerNetError {
    match e {
        P2pError::NodeIdMismatch { expected, actual } => PeerNetError::IdentityMismatch { expected, actual },
        P2pError::NotRunning => PeerNetError::NodeNotStarted,
        P2pError::DialTimeout => PeerNetError::Transport {
            detail: "dial timeout".to_string(),
        },
        P2pError::Dial(detail)
        | P2pError::Build(detail)
        | P2pError::Listen(detail)
        | P2pError::InvalidSeed(detail)
        | P2pError::InvalidNodeId(detail)
        | P2pError::UnsupportedPeerIdentity(detail)
        | P2pError::ProtocolRegistered(detail) => PeerNetError::Transport { detail },
        P2pError::NotConnected(detail) => PeerNetError::Transport {
            detail: format!("peer not connected: {detail}"),
        },
        P2pError::NotAdmitted(detail) => PeerNetError::Transport {
            detail: format!("peer not admitted: {detail}"),
        },
        P2pError::Stream { protocol, detail } => PeerNetError::Transport {
            detail: format!("open stream {protocol}: {detail}"),
        },
        P2pError::StreamTimeout(protocol) => PeerNetError::Transport {
            detail: format!("open stream timeout: {protocol}"),
        },
    }
}

// ==================== 运行句柄 ====================

/// 节点运行句柄：引擎 swarm + 本层协议接收循环
///
/// 由 [`crate::base::node::PeerNetNode`] 的 start 系列方法产出；显式关停必须
/// 调用 [`RunningNode::shutdown`]（drop 句柄不会停节点）。
pub struct RunningNode {
    p2p: P2pRunningNode,
    local_addr: SocketAddr,
    accept_tasks: Vec<JoinHandle<()>>,
}

impl RunningNode {
    /// 实际监听地址（端口 0 已展开）
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 引擎节点句柄（`PeerNetNode::dial` 与诊断用）
    pub(crate) fn p2p(&self) -> &P2pRunningNode {
        &self.p2p
    }

    /// 优雅关停：停引擎（关闭全部连接/流）→ 中止本层接收循环
    pub async fn shutdown(self) {
        let RunningNode { p2p, accept_tasks, .. } = self;
        p2p.shutdown().await;
        for task in accept_tasks {
            task.abort();
        }
        tracing::info!("peer-net node shut down cleanly (libp2p)");
    }
}

/// 启动引擎与入站协议接收循环
///
/// 必须在 tokio 运行时上下文中调用（spawn 依赖 Handle::current）：生产侧为
/// tauri 异步环境，测试侧为 `#[tokio::test]`。
pub(crate) fn spawn_running_node(
    listen_addr: SocketAddr,
    identity: &NodeIdentity,
    trust: Arc<TrustStore>,
    events: mpsc::Sender<TrustEvent>,
    handler: Arc<dyn ConnectionHandler>,
) -> Result<RunningNode> {
    // libp2p 的 listen_on 异步展开端口：先占位取端口再释放（与旧 listener 占位
    // 同一防竞态思路）。旧调用方可能仍持有 listener 副本（try_clone 后只把克隆
    // 交进来）——此时已选端口仍占用，回退系统分配端口，实际地址以
    // `RunningNode::local_addr` 为准（调用方须据此寻址）。
    let port = match std::net::TcpListener::bind(listen_addr) {
        Ok(placeholder) => {
            let port = placeholder
                .local_addr()
                .map_err(|source| PeerNetError::ListenerPrepare { source })?
                .port();
            drop(placeholder);
            port
        }
        Err(source) if source.kind() == std::io::ErrorKind::AddrInUse => {
            let fallback =
                std::net::TcpListener::bind((listen_addr.ip(), 0)).map_err(|source| PeerNetError::ListenBind {
                    addr: listen_addr,
                    source,
                })?;
            let port = fallback
                .local_addr()
                .map_err(|source| PeerNetError::ListenerPrepare { source })?
                .port();
            drop(fallback);
            tracing::warn!(
                requested = %listen_addr,
                actual_port = port,
                "peer-net listen port still occupied (caller kept a listener clone); using ephemeral port"
            );
            port
        }
        Err(source) => {
            return Err(PeerNetError::ListenBind {
                addr: listen_addr,
                source,
            })
        }
    };
    let resolved_addr = SocketAddr::new(listen_addr.ip(), port);

    let key = NodeKey::from_seed_bytes(&identity.seed_bytes()).map_err(|e| PeerNetError::Transport {
        detail: format!("node identity seed rejected: {e}"),
    })?;
    let config = P2pNodeConfig {
        listen_addr: resolved_addr.ip(),
        listen_port: resolved_addr.port(),
        admission: AdmissionConfig {
            confirm_timeout: CONFIRM_TIMEOUT,
            max_pending: MAX_PENDING_CONFIRMATIONS,
        },
        admit_on_connect: false,
    };
    let ports = P2pPorts {
        admission: Arc::new(TrustAdmissionPort {
            trust: Arc::clone(&trust),
            events,
        }),
        events: Arc::new(LogEventSink),
    };
    let protocols = [
        stream_proto::TRUST_STATUS,
        stream_proto::TRANSFER,
        stream_proto::SHARED_DIR,
        stream_proto::SESSION,
    ];
    let (p2p, mut incoming) = P2pEngine::start_with_protocols(key, config, ports, &protocols).map_err(map_p2p_error)?;

    let own_node_id = identity.node_id().clone();
    let mut accept_tasks = Vec::new();
    if let Some(trust_streams) = incoming.remove(stream_proto::TRUST_STATUS) {
        accept_tasks.push(tokio::spawn(accept_trust_streams(
            trust_streams,
            p2p.clone(),
            own_node_id,
            trust,
        )));
    } else {
        tracing::error!("trust-status protocol acceptor missing after engine start");
    }
    for protocol in [stream_proto::TRANSFER, stream_proto::SHARED_DIR, stream_proto::SESSION] {
        if let Some(streams) = incoming.remove(protocol) {
            accept_tasks.push(tokio::spawn(accept_business_streams(
                streams,
                Arc::clone(&handler),
                protocol,
            )));
        } else {
            tracing::error!(protocol, "business protocol acceptor missing after engine start");
        }
    }

    tracing::info!(addr = %resolved_addr, "peer-net listening (libp2p)");
    Ok(RunningNode {
        p2p,
        local_addr: resolved_addr,
        accept_tasks,
    })
}
