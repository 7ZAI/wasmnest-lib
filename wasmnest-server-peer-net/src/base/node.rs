//! 节点公共 API 缝：配置形状与发现注入入口 + 运行时能力 + mDNS 发现缓存挂载。
//!
//! ## 配置形状（决策 D5）
//!
//! [`PeerNetNodeConfig`] 的 `bind_addr` / `static_peers` 是发现注入与监听配置的
//! 稳定缝。P1 传输栈换轨后 `bind_addr` 仍表达「本端监听地址」；底层由
//! `wasmnest-p2p-engine` 的 swarm 绑定（port 0 由系统展开）。`static_peers`
//! 即「向节点注入一条已发现记录」的种子通路——mDNS 守护回调与测试喂入走同一
//! 入口。
//!
//! ## 可信存储的注入路径
//!
//! 节点缺省持有内存态空可信表；需要持久化（生产/AC#5 测试）经
//! [`PeerNetNode::with_trust_store`] 注入 [`TrustStore::load_or_create`] 产物——
//! 宿主对身份与可信列表用同一目录，与 identity 的「crate 管 IO、宿主只给目录」
//! 模式一致。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::base::discovery::DiscoveryCache;
use crate::base::error::{PeerNetError, Result};
use crate::base::identity::{NodeId, NodeIdentity};
use crate::base::transport::{spawn_running_node, Connection, ConnectionHandler, RunningNode, TrustEvent};
use crate::base::trust_store::TrustStore;
use wasmnest_p2p_engine::engine::RunningNode as P2pRunningNode;
use wasmnest_p2p_engine::stream_proto;

// ==================== 发现记录 ====================

/// 一条静态对端记录：「已知某 node_id 在某地址」的最小发现形态
///
/// mDNS 发现结果与测试注入统一收敛到本结构；`node_id` 与 `addr` 并存使后续
/// 可信连接可直接做身份绑定校验（引擎握手后按 PeerId 重算 node_id 比对）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPeerRecord {
    /// 对端节点 ID（公钥指纹）
    pub node_id: NodeId,
    /// 对端监听地址
    pub addr: SocketAddr,
}

// ==================== 节点配置 ====================

/// 节点配置（形状由 ticket 01 定死，见 D5）
#[derive(Debug, Clone)]
pub struct PeerNetNodeConfig {
    /// 本节点监听地址
    ///
    /// 测试可先 `TcpListener::bind("127.0.0.1:0")` 占位分配回环端口，再把端口
    /// 经 [`PeerNetNode::start_with_listener`] 交给节点（句柄本身在绑定前释放）；
    /// 生产侧 [`PeerNetNode::start`] 直接按本地址绑定。
    pub bind_addr: SocketAddr,
    /// 节点身份（宿主经 [`NodeIdentity::load_or_create`] 注入）
    pub identity: NodeIdentity,
    /// 静态对端列表（发现注入的种子通路）
    pub static_peers: Vec<StaticPeerRecord>,
}

// ==================== 节点 ====================

/// 对等网络节点：持有身份 + 监听/拨号/可信连接运行时
///
/// 构造（[`PeerNetNode::new`]）保持纯同步无网络操作；监听拨号经 [`start`]
/// / [`dial`] 显式启动，须在 tokio 运行时上下文中调用。
///
/// [`start`]: PeerNetNode::start
/// [`dial`]: PeerNetNode::dial
#[derive(Clone)]
pub struct PeerNetNode {
    config: PeerNetNodeConfig,
    /// 本节可信列表句柄：准入端口查询、宿主撤销（AC#4/#5）、dial 落库共用
    trust_store: Arc<TrustStore>,
    /// 发现结果在线缓存：mDNS 守护回调与测试喂入的同一通路入口
    discovery: Option<Arc<DiscoveryCache>>,
    /// 引擎运行句柄（start 后填充；Clone 共享——同一节点多次 dial 复用连接）
    runtime: Arc<Mutex<Option<P2pRunningNode>>>,
}

impl std::fmt::Debug for PeerNetNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerNetNode")
            .field("config", &self.config)
            .field(
                "started",
                &self.runtime.lock().expect("peer runtime lock poisoned").is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl PeerNetNode {
    /// 构造节点（纯同步、无网络操作）
    ///
    /// 可信表缺省为内存态空表；需要持久化时链式调用
    /// [`Self::with_trust_store`] 注入文件版。
    pub fn new(config: PeerNetNodeConfig) -> Result<Self> {
        Ok(Self {
            config,
            trust_store: Arc::new(TrustStore::in_memory()),
            discovery: None,
            runtime: Arc::new(Mutex::new(None)),
        })
    }

    /// 注入持久化可信存储（builder 风格，返回消费后的自身）
    pub fn with_trust_store(mut self, store: Arc<TrustStore>) -> Self {
        self.trust_store = store;
        self
    }

    /// 注入发现结果在线缓存（builder 风格，镜像 [`Self::with_trust_store`] 先例）
    ///
    /// 挂载后 [`crate::base::discovery::spawn_peer_mdns_daemon`] 的事件循环（消费宿主编
    /// 造的中枢浏览订阅）与测试的手工喂入共用该缓存实例（「同一通路」，D1）。
    pub fn with_discovery(mut self, cache: Arc<DiscoveryCache>) -> Self {
        self.discovery = Some(cache);
        self
    }

    /// 已挂载的发现缓存句柄（未挂载返回 `None`；守护启动前校验用）
    pub fn discovery(&self) -> Option<Arc<DiscoveryCache>> {
        self.discovery.as_ref().map(Arc::clone)
    }

    /// 启动监听：按 `bind_addr` 起 libp2p 节点并派生协议接收循环
    ///
    /// 必须在 tokio 运行时上下文中调用。`events` 为首连确认事件通道，
    /// `handler` 接收信任放行后的已认证业务流。
    pub fn start(&self, events: mpsc::Sender<TrustEvent>, handler: Arc<dyn ConnectionHandler>) -> Result<RunningNode> {
        self.start_on(self.config.bind_addr, events, handler)
    }

    /// 以既有 listener 的地址启动监听（端口预留的旧调用缝）
    ///
    /// libp2p 无法接管外部 `TcpListener` 句柄：这里读出地址后释放占位句柄，
    /// 再由引擎绑定同一端口（端口 0 由系统重新分配）。生产侧优先用
    /// [`Self::start`]。
    pub fn start_with_listener(
        &self,
        listener: std::net::TcpListener,
        events: mpsc::Sender<TrustEvent>,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<RunningNode> {
        let addr = listener
            .local_addr()
            .map_err(|source| PeerNetError::ListenerPrepare { source })?;
        drop(listener);
        self.start_on(addr, events, handler)
    }

    fn start_on(
        &self,
        listen_addr: SocketAddr,
        events: mpsc::Sender<TrustEvent>,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<RunningNode> {
        let running = spawn_running_node(
            listen_addr,
            &self.config.identity,
            Arc::clone(&self.trust_store),
            events,
            handler,
        )?;
        *self.runtime.lock().expect("peer runtime lock poisoned") = Some(running.p2p().clone());
        Ok(running)
    }

    /// 拨号对端并完成身份校验与信任状态协商（默认开 SESSION 流）
    ///
    /// 数据面按用途用 [`Self::dial_with`] 开 TRANSFER / SHARED_DIR 具名流。
    pub async fn dial(&self, record: &StaticPeerRecord) -> Result<Connection> {
        self.dial_with(record, stream_proto::SESSION).await
    }

    /// 拨号并打开指定业务流（协议名取 `wasmnest_p2p_engine::stream_proto`）
    pub async fn dial_with(&self, record: &StaticPeerRecord, protocol: &'static str) -> Result<Connection> {
        let p2p = self
            .runtime
            .lock()
            .expect("peer runtime lock poisoned")
            .clone()
            .ok_or(PeerNetError::NodeNotStarted)?;
        crate::base::transport::dial(&p2p, &self.config.identity, &self.trust_store, record, protocol).await
    }

    /// 共享可信存储句柄（测试断言 / 宿主撤销入口）
    pub fn trust(&self) -> Arc<TrustStore> {
        Arc::clone(&self.trust_store)
    }

    /// 本节点 ID（公钥指纹）
    pub fn node_id(&self) -> &NodeId {
        self.config.identity.node_id()
    }

    /// 本节点身份
    pub fn identity(&self) -> &NodeIdentity {
        &self.config.identity
    }

    /// 声明的监听地址
    pub fn bind_addr(&self) -> SocketAddr {
        self.config.bind_addr
    }

    /// 已注入的静态对端记录
    pub fn static_peers(&self) -> &[StaticPeerRecord] {
        &self.config.static_peers
    }
}
