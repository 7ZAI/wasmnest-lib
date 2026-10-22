//! 节点公共 API 缝：配置形状与发现注入入口 + ticket 02 运行时能力 + ticket 03
//! mDNS 发现缓存挂载。
//!
//! ## 配置形状冻结（决策 D5）
//!
//! [`PeerNetNodeConfig`] 的 `bind_addr` / `static_peers` 是发现注入与监听配置的
//! 稳定缝，ticket 01 定死、ticket 02 挂上真实 TCP 栈后未改动。`static_peers`
//! 即「向节点注入一条已发现记录」的种子通路——mDNS 守护回调与测试喂入走同一
//! 入口，ticket 03 起发现结果经 [`PeerNetNode::with_discovery`] 挂载的在线缓存
//! 流动（`discovery` 模块），静态列表只是其最简形态。
//!
//! ## 可信存储的注入路径
//!
//! 配置形状冻结意味着数据目录不经配置传入：节点缺省持有内存态空可信表；
//! 需要持久化（生产/AC#5 测试）经 [`PeerNetNode::with_trust_store`] 注入
//! [`TrustStore::load_or_create`] 产物——宿主对身份与可信列表用同一目录，
//! 与 identity 的「crate 管 IO、宿主只给目录」模式一致。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::base::cert::{CertDer, generate_self_signed_cert};
use crate::base::discovery::DiscoveryCache;
use crate::base::error::Result;
use crate::base::identity::{NodeId, NodeIdentity};
use crate::base::transport::{
    Connection, ConnectionHandler, RunningNode, TrustEvent, spawn_running_node,
};
use crate::base::trust_store::TrustStore;

// ==================== 发现记录 ====================

/// 一条静态对端记录：「已知某 node_id 在某地址」的最小发现形态
///
/// ticket 02 起，mDNS 发现结果与测试注入统一收敛到本结构；`node_id` 与
/// `addr` 并存使后续可信连接可直接做证书绑定校验（先比对 ID 再握手）。
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
    /// 测试经 `TcpListener::bind("127.0.0.1:0")` 占位分配回环端口后把句柄
    /// 移交给 [`PeerNetNode::start_with_listener`]，避免端口竞态；生产侧
    /// [`PeerNetNode::start`] 直接按本地址绑定。
    pub bind_addr: SocketAddr,
    /// 节点身份（宿主经 [`NodeIdentity::load_or_create`] 注入）
    pub identity: NodeIdentity,
    /// 静态对端列表（发现注入的种子通路）
    pub static_peers: Vec<StaticPeerRecord>,
}

// ==================== 节点 ====================

/// 对等网络节点：持有身份与自签证书 + 监听/拨号/可信连接运行时
///
/// 构造（[`PeerNetNode::new`]）保持纯同步无网络操作；监听拨号经 [`start`]
/// / [`dial`] 显式启动，须在 tokio 运行时上下文中调用。
///
/// [`start`]: PeerNetNode::start
/// [`dial`]: PeerNetNode::dial
#[derive(Debug, Clone)]
pub struct PeerNetNode {
    config: PeerNetNodeConfig,
    certificate: CertDer,
    /// 本节可信列表句柄：accept 循环查询、宿主撤销（AC#4/#5）、dial 落库共用
    trust_store: Arc<TrustStore>,
    /// 发现结果在线缓存：mDNS 守护回调与测试喂入的同一通路入口（ticket 03，D1）
    discovery: Option<Arc<DiscoveryCache>>,
}

impl PeerNetNode {
    /// 构造节点：生成本节自签证书并存于节点上
    ///
    /// 不发起任何网络操作——纯同步构造使 harness 无需异步运行时即可断言
    /// 身份与证书性质。可信表缺省为内存态空表；需要持久化时链式调用
    /// [`Self::with_trust_store`] 注入文件版。
    pub fn new(config: PeerNetNodeConfig) -> Result<Self> {
        let certificate = generate_self_signed_cert(&config.identity)?;
        Ok(Self {
            config,
            certificate,
            trust_store: Arc::new(TrustStore::in_memory()),
            discovery: None,
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

    /// 启动监听：自绑 `bind_addr` 并进入 accept 循环
    ///
    /// 必须在 tokio 运行时上下文中调用。`events` 为首连确认事件通道，
    /// `handler` 接收信任放行后的已认证连接。
    pub fn start(
        &self,
        events: mpsc::Sender<TrustEvent>,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<RunningNode> {
        let listener =
            std::net::TcpListener::bind(self.config.bind_addr).map_err(|source| {
                crate::base::error::PeerNetError::ListenBind {
                    addr: self.config.bind_addr,
                    source,
                }
            })?;
        self.start_with_listener(listener, events, handler)
    }

    /// 以既有 listener 启动监听（端口预留 + 所有权移交，Decision 4）
    ///
    /// 测试先 `TcpListener::bind("127.0.0.1:0")` 占位防竞态，再把占位句柄移交
    /// 给节点；生产侧用 [`Self::start`] 即可。
    pub fn start_with_listener(
        &self,
        listener: std::net::TcpListener,
        events: mpsc::Sender<TrustEvent>,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<RunningNode> {
        spawn_running_node(
            listener,
            &self.config.identity,
            &self.certificate,
            Arc::clone(&self.trust_store),
            events,
            handler,
        )
    }

    /// 拨号对端并完成 mTLS 身份钉扎握手与信任状态协商（见 transport::dial）
    pub async fn dial(&self, record: &StaticPeerRecord) -> Result<Connection> {
        crate::base::transport::dial(
            &self.config.identity,
            &self.certificate,
            &self.trust_store,
            record,
        )
        .await
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

    /// 本节点自签证书（DER 编码）
    ///
    /// ticket 02 的 TLS 握手直接复用：服务端/客户端配置共用同一密钥材料，
    /// mTLS 双向互验；对端校验走 tls.rs 的钉扎 verifier。
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
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
