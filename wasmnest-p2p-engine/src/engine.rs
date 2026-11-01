//! swarm 引擎：节点生命周期（监听 / 拨号 / 事件泵 / 关停）、具名流协议与连接状态机。
//!
//! ## 形态
//!
//! [`P2pEngine::start`] 装配一个 swarm（TCP + noise + yamux + ping + 具名流行为）
//! 并派生**事件泵任务**：泵独占 swarm，`select` 四路输入——swarm 事件 / 引擎命令
//! （[`EngineCmd`]，[`RunningNode`] 句柄发来）/ 准入结算（[`crate::admission`]）/
//! 拒绝回收定时器。句柄侧全部操作经命令通道进泵，无共享可变状态（监听地址、
//! 链路登记、准入 watch 是只读共享快照）。
//!
//! ## 连接状态机（P1 传输栈换轨的语义）
//!
//! | 事件 | 出站（本端拨） | 入站（对端拨入） |
//! | --- | --- | --- |
//! | 连接建立 | 从 PeerId 重算 node_id 并与期望校验：不一致 → 断开 + `dial_failed` | 同左重算：派生不出（非 ed25519）→ 断开 + `peer_denied(UnsupportedIdentity)` |
//! | 建立后校验过 | 登记链路 `Admitted` + `peer_connected(outbound=true)` | 登记链路 `Pending`，走准入闸门 |
//! | 闸门结算 | — | 放行 → `Admitted` + `peer_connected(outbound=false)`；拒绝 → `Denied` + `peer_denied(cause)`，连接留给信任状态流写 Denied |
//! | 连接全关 | `peer_disconnected` | 同左（未结算先断：撤 pending 记账，不发事件；拒绝态不发断开） |
//!
//! **闸门放行前零业务协议流量**：P1 起只有
//! `/wasmnest/trust-status/1` 在 `Pending` 态可被对端开流（用于把确认中/拒绝
//! 写回拨号方）；其余业务流由 [`crate::links::IncomingStreams`] 统一按
//! `Admitted` 过滤。拒绝后连接最多保留 [`DENY_GRACE`]，供信任状态流写出终态帧，
//! 随后由回收定时器断开。
//!
//! 保活语义：空闲连接超时设一天 + ping（默认 15s 间隔 / 20s 超时）探死——对端
//! 静默死亡（WiFi 骤断无 FIN）在 ping 超时窗口内以连接关闭浮现，对齐现役栈
//! socket2 keepalive 的意图；连接常驻（会话不因空闲被拆）。
//!
//! ## 拨号归属的边界（刻意，已文档化）
//!
//! libp2p 的拨号失败事件不携带所拨地址：**单路在飞时精确归属失败**；多路在飞时
//! 失败事件无法逐路对应，由 [`RunningNode::dial`] 的超时窗口兜底结算。文件传输
//! 场景一次拨一个目标，不触此边界。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, StreamProtocol, Swarm, SwarmEvent};
use libp2p::{noise, ping, tcp, yamux, Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;

use crate::admission::{AdmissionGate, AdmissionSettled, GateRequest};
use crate::error::P2pError;
use crate::identity_bridge::{node_id_from_peer_id, verify_peer_identity, NodeId, NodeKey};
use crate::links::{IncomingStreams, LinkAdmission, LinkRegistry, LinkRegistryInner, PeerLink};
use crate::ports::{
    DenyCause, DialFailed, P2pEventSink, P2pPorts, PeerConnected, PeerDenied, PeerDisconnected,
};

/// 拨号完成的超时窗口（握手 + node_id 校验；多路在飞时失败归属的兜底结算）
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// 开流协商超时（对端须已注册该协议；超时即失败，不无限挂起）
pub const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// 空闲连接超时：远大于 ping 间隔——连接常驻，探死交给 ping
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// 拒绝态连接宽限期：留给信任状态流写出 Denied 再断开
const DENY_GRACE: Duration = Duration::from_secs(3);

/// 拒绝态回收扫描周期
const DENY_REAPER_INTERVAL: Duration = Duration::from_millis(500);

/// 节点行为面：ping 保活 + 具名流协议协商
#[derive(NetworkBehaviour)]
pub(crate) struct NodeBehaviour {
    ping: ping::Behaviour,
    stream: libp2p_stream::Behaviour,
}

// ==================== 节点配置 ====================

/// 节点配置
#[derive(Debug, Clone)]
pub struct P2pNodeConfig {
    /// 监听绑定的本端地址（默认 `0.0.0.0` 全网卡；测试用 `127.0.0.1`）
    pub listen_addr: IpAddr,
    /// 监听端口（默认 0 = 系统分配；现役栈的固定端口由调用方传入）
    pub listen_port: u16,
    /// 准入闸门配置（超时 / pending 上限）
    pub admission: crate::admission::AdmissionConfig,
    /// 入站连接建立即自动进入准入闸门
    ///
    /// P0/P1 默认 `true`（连接即确认，事件面最简）。peer-net 换轨后置
    /// `false`：先由信任状态流读取拨号方的「期望 node_id」并校验，再显式
    /// [`RunningNode::request_admission`]——伪造身份记录不会触发确认弹窗。
    pub admit_on_connect: bool,
}

impl Default for P2pNodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: IpAddr::from([0, 0, 0, 0]),
            listen_port: 0,
            admission: crate::admission::AdmissionConfig::default(),
            admit_on_connect: true,
        }
    }
}

// ==================== 命令与句柄 ====================

/// 引擎命令（句柄 → 泵）
enum EngineCmd {
    /// 拨号：完成 = 握手 + node_id 校验通过（reply 才回 Ok）
    Dial {
        addr: Multiaddr,
        expected: NodeId,
        reply: oneshot::Sender<Result<(), P2pError>>,
    },
    /// 取消在飞拨号（dial 超时后清账，防止迟到连接误命中）
    CancelDial { addr: Multiaddr, expected: NodeId },
    /// 按 node_id 断开（reply = 是否命中在连对端）
    Disconnect {
        node_id: NodeId,
        reply: oneshot::Sender<bool>,
    },
    /// 显式请求入站准入（信任状态流校验拨号方期望身份后调用）
    ///
    /// reply 只表示「已受理 / 已终态 / 链路不存在」，终态经
    /// [`RunningNode::admission_watch`] 发出。
    RequestAdmission {
        peer_id: PeerId,
        reply: oneshot::Sender<Result<(), P2pError>>,
    },
    /// 重置链路准入为 Pending（信任被撤销后重握手，或拒绝后重试）
    ResetAdmission {
        peer_id: PeerId,
        reply: oneshot::Sender<Result<(), P2pError>>,
    },
    /// 关停（泵退出前回执）
    Shutdown { reply: oneshot::Sender<()> },
}

struct RunningNodeInner {
    node_id: NodeId,
    peer_id: PeerId,
    cmd: mpsc::Sender<EngineCmd>,
    listen_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    links: LinkRegistry,
    /// libp2p-stream 控制句柄（开流 / 注册协议都需要 &mut，故串行化）
    control: Arc<Mutex<libp2p_stream::Control>>,
    /// 拨号串行闸：同一时刻只让一个 dial 走完「检查链路 → 发命令 → 等校验」，
    /// 并发拨同一对端时后到者直接命中已建立的链路。
    dial_gate: Arc<Mutex<()>>,
    /// 泵任务（shutdown 取走；克隆句柄共享同一 Option）
    pump: Mutex<Option<JoinHandle<()>>>,
}

/// 运行中的节点句柄（可克隆：命令通道 + 只读快照；shutdown 幂等）
#[derive(Clone)]
pub struct RunningNode {
    inner: Arc<RunningNodeInner>,
}

impl RunningNode {
    /// 本节点 node_id
    pub fn node_id(&self) -> &NodeId {
        &self.inner.node_id
    }

    /// 本节点 PeerId
    pub fn peer_id(&self) -> PeerId {
        self.inner.peer_id
    }

    /// 当前监听地址快照（NewListenAddr / ExpiredListenAddr 维护）
    pub fn listen_addresses(&self) -> Vec<SocketAddr> {
        self.inner
            .listen_addrs
            .read()
            .expect("监听地址快照中毒")
            .clone()
    }

    /// 等待首个监听地址就绪（port 0 / 事件泵尚未跑到 NewListenAddr 时使用）
    pub async fn wait_listen_addr(&self, timeout: Duration) -> Option<SocketAddr> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(addr) = self.listen_addresses().first().copied() {
                return Some(addr);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 拨号对端并等握手 + node_id 校验完成
    ///
    /// - 已存在 `Admitted` 链路且拨号地址一致：直接返回 Ok（复用连接，多路流按协议开）；
    /// - 已存在出站链路但**拨号地址变了**（对端重启换端口 / IP）：断开旧链路后重拨；
    /// - 存在同址 `Pending` / `Denied` 链路：返回 [`P2pError::NotAdmitted`]；
    /// - 否则发起拨号。返回时机 = 校验通过或失败 / 超时（连接已被引擎断开）。
    pub async fn dial(&self, addr: Multiaddr, expected_node_id: NodeId) -> Result<(), P2pError> {
        let _gate = self.inner.dial_gate.lock().await;
        let dial_addr = multiaddr_to_socket_addr(&addr);
        let mut must_redial = false;
        {
            let links = self.inner.links.read().expect("链路登记表中毒");
            if let Some(link) = links.get_by_node(&expected_node_id) {
                // 出站链路才代表「我们知道对端的监听地址」；入站链路是对方拨来的
                // 连接，源端口不是监听端口，不能拿来判断地址变化。
                must_redial =
                    link.outbound && dial_addr.is_some_and(|want| want != link.remote_addr);
                if !must_redial {
                    return match link.admission {
                        LinkAdmission::Admitted => Ok(()),
                        LinkAdmission::Pending | LinkAdmission::Denied => {
                            Err(P2pError::NotAdmitted(expected_node_id.to_string()))
                        }
                    };
                }
            }
        }
        if must_redial {
            // 对端换址重启：先断旧链路并等登记摘除，否则新 ConnectionEstablished
            // 会命中旧 ConnState（按 PeerId 键控）被当成重复连接累加。
            tracing::info!(
                node_id = %expected_node_id,
                ?dial_addr,
                "peer address changed; dropping stale link before redial"
            );
            let _ = self.disconnect(expected_node_id.clone()).await;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if self.peer_link(&expected_node_id).is_none() {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(P2pError::Dial(
                        "stale link did not close after address change".to_string(),
                    ));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        let (tx, rx) = oneshot::channel();
        self.inner
            .cmd
            .send(EngineCmd::Dial {
                addr: addr.clone(),
                expected: expected_node_id.clone(),
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        match tokio::time::timeout(DIAL_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_recv)) => Err(P2pError::NotRunning),
            Err(_elapsed) => {
                // 拨号窗口已关：清掉在飞登记，避免迟到连接误命中
                let _ = self
                    .inner
                    .cmd
                    .send(EngineCmd::CancelDial {
                        addr,
                        expected: expected_node_id,
                    })
                    .await;
                Err(P2pError::DialTimeout)
            }
        }
    }

    /// 按 node_id 断开在连对端（返回是否命中）
    pub async fn disconnect(&self, node_id: NodeId) -> Result<bool, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .cmd
            .send(EngineCmd::Disconnect { node_id, reply: tx })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        rx.await.map_err(|_| P2pError::NotRunning)
    }

    /// 向已准入对端开一条具名流（`protocol` 取 [`crate::stream_proto`] 常量）
    ///
    /// 只对 `Admitted` 链路开流：pending / denied 一律拒绝，防止业务协议在
    /// 闸门放行前流通。开流失败 / 超时均显性返回。
    pub async fn open_stream(
        &self,
        node_id: &NodeId,
        protocol: &'static str,
    ) -> Result<libp2p::swarm::Stream, P2pError> {
        let peer_id = {
            let links = self.inner.links.read().expect("链路登记表中毒");
            let Some(link) = links.get_by_node(node_id) else {
                return Err(P2pError::NotConnected(node_id.to_string()));
            };
            if link.admission != LinkAdmission::Admitted {
                return Err(P2pError::NotAdmitted(node_id.to_string()));
            }
            link.peer_id
        };
        let mut control = self.inner.control.lock().await;
        match tokio::time::timeout(
            STREAM_OPEN_TIMEOUT,
            control.open_stream(peer_id, StreamProtocol::new(protocol)),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(P2pError::Stream {
                protocol: protocol.to_string(),
                detail: e.to_string(),
            }),
            Err(_) => Err(P2pError::StreamTimeout(protocol.to_string())),
        }
    }

    /// 注册并接收某个协议名的入站流
    ///
    /// `require_admitted = true`（业务协议）只放行已准入对端；信任状态协议传
    /// `false`——这是闸门放行前唯一允许流通的协议。同一协议名只能注册一次，
    /// 重复注册返回 [`P2pError::ProtocolRegistered`]。
    pub async fn accept_streams(
        &self,
        protocol: &'static str,
        require_admitted: bool,
    ) -> Result<IncomingStreams, P2pError> {
        let mut control = self.inner.control.lock().await;
        let incoming = control
            .accept(StreamProtocol::new(protocol))
            .map_err(|_| P2pError::ProtocolRegistered(protocol.to_string()))?;
        Ok(IncomingStreams::new(
            incoming,
            Arc::clone(&self.inner.links),
            require_admitted,
        ))
    }

    /// 显式请求入站准入（`admit_on_connect = false` 时由信任状态流调用）
    ///
    /// 返回 `Ok(())` 表示闸门已受理（终态看 [`Self::admission_watch`]）或对端
    /// 已放行；已拒绝 / 链路不存在显性报错。重复调用幂等。
    pub async fn request_admission(&self, peer_id: &PeerId) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .cmd
            .send(EngineCmd::RequestAdmission {
                peer_id: *peer_id,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        rx.await.map_err(|_| P2pError::NotRunning)?
    }

    /// 把链路准入重置为 Pending（信任撤销 / 拒绝后重试时由信任状态流调用）
    ///
    /// 连接复用下，对端「撤销信任」不会断开既有链路；重握手前必须先重置，
    /// 否则链路上的旧 `Admitted` 快照会绕过确认闸门。重置会撤销在飞闸门记账
    /// 并通知 watch 订阅者。
    pub async fn reset_admission(&self, peer_id: &PeerId) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .cmd
            .send(EngineCmd::ResetAdmission {
                peer_id: *peer_id,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        rx.await.map_err(|_| P2pError::NotRunning)?
    }

    /// 订阅某条链路的准入状态变化（信任状态流据此在 pending 时挂起等终态）
    pub fn admission_watch(&self, peer_id: &PeerId) -> Option<watch::Receiver<LinkAdmission>> {
        self.inner
            .links
            .read()
            .expect("链路登记表中毒")
            .watch(peer_id)
    }

    /// 按 node_id 取链路快照
    pub fn peer_link(&self, node_id: &NodeId) -> Option<PeerLink> {
        self.inner
            .links
            .read()
            .expect("链路登记表中毒")
            .get_by_node(node_id)
    }

    /// 全部链路快照（诊断/测试）
    pub fn peers(&self) -> Vec<PeerLink> {
        self.inner.links.read().expect("链路登记表中毒").snapshot()
    }

    /// 关停节点（幂等：重复调用无副作用）
    ///
    /// 泵退出即 swarm 析构（在途连接与流全部关闭）；**不逐连接发
    /// `peer_disconnected`**——关停是节点级语义，逐连接风暴无消费价值（现役栈同口径）。
    pub async fn shutdown(&self) {
        let mut guard = self.inner.pump.lock().await;
        if guard.is_none() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        if self
            .inner
            .cmd
            .send(EngineCmd::Shutdown { reply: tx })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
        if let Some(pump) = guard.take() {
            let _ = pump.await;
        }
    }
}

/// 引擎入口（无状态：装配 + 派生泵）
pub struct P2pEngine;

impl P2pEngine {
    /// 启动节点（无预注册协议；测试 / 不需要入站流的宿主用）
    pub fn start(
        key: NodeKey,
        config: P2pNodeConfig,
        ports: P2pPorts,
    ) -> Result<RunningNode, P2pError> {
        Ok(Self::start_with_protocols(key, config, ports, &[])?.0)
    }

    /// 启动节点并**在开始监听前**预注册一组入站流协议
    ///
    /// 预注册消除「监听已开、协议未登记」窗口：对端在窗口内开流会协商失败。
    /// 返回各协议的接收器；信任状态协议自动按 `require_admitted = false`
    /// 注册（闸门放行前唯一可用协议），其余协议按 `true` 注册。
    pub fn start_with_protocols(
        key: NodeKey,
        config: P2pNodeConfig,
        ports: P2pPorts,
        protocols: &[&'static str],
    ) -> Result<(RunningNode, HashMap<&'static str, IncomingStreams>), P2pError> {
        let node_id = key.node_id().clone();
        let peer_id = key.peer_id();

        let stream_behaviour = libp2p_stream::Behaviour::new();
        let mut control = stream_behaviour.new_control();
        let links: LinkRegistry = Arc::new(RwLock::new(LinkRegistryInner::default()));
        let mut incoming = HashMap::new();
        for protocol in protocols {
            let streams = control
                .accept(StreamProtocol::new(protocol))
                .map_err(|_| P2pError::ProtocolRegistered(protocol.to_string()))?;
            incoming.insert(
                *protocol,
                IncomingStreams::new(
                    streams,
                    Arc::clone(&links),
                    *protocol != crate::stream_proto::TRUST_STATUS,
                ),
            );
        }

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key.into_keypair())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| P2pError::Build(format!("TCP/noise/yamux 传输栈装配失败：{e}")))?
            .with_behaviour(|_key| NodeBehaviour {
                ping: ping::Behaviour::new(ping::Config::new()),
                stream: stream_behaviour,
            })
            .map_err(|e| P2pError::Build(format!("行为面装配失败：{e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
            .build();

        let listen_ma = listen_multiaddr(config.listen_addr, config.listen_port);
        swarm
            .listen_on(listen_ma)
            .map_err(|e| P2pError::Listen(e.to_string()))?;

        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (settle_tx, settle_rx) = mpsc::channel(64);
        let listen_addrs: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));

        let pump = tokio::spawn(run_pump(
            swarm,
            cmd_rx,
            settle_rx,
            settle_tx,
            AdmissionGate::new(config.admission),
            ports,
            Arc::clone(&listen_addrs),
            Arc::clone(&links),
            config.admit_on_connect,
        ));

        let handle = RunningNode {
            inner: Arc::new(RunningNodeInner {
                node_id,
                peer_id,
                cmd: cmd_tx,
                listen_addrs,
                links,
                control: Arc::new(Mutex::new(control)),
                dial_gate: Arc::new(Mutex::new(())),
                pump: Mutex::new(Some(pump)),
            }),
        };
        Ok((handle, incoming))
    }
}

// ==================== 事件泵 ====================

/// 泵内的对端连接记录
struct ConnState {
    node_id: NodeId,
    /// true = 出站（建立即已按期望校验）；false = 入站（admitted 前**不可用**）
    outbound: bool,
    /// 是否已放行（出站恒 true——校验即准入）
    admitted: bool,
    /// 是否已拒绝（拒绝态保留连接供信任状态流写 Denied）
    denied: bool,
    /// 是否已发起过准入请求（自动 / 显式二选一，防重复进入闸门）
    admission_requested: bool,
    /// 拒绝结算时刻（回收定时器判据）
    denied_at: Option<Instant>,
    /// 本端是否主动关（关停 / 断开 / 拒绝结算），disconnected 事件携带
    by_local: bool,
    /// 对端地址（出站 = 所拨地址；入站 = 对端来源地址）
    remote_addr: SocketAddr,
    /// 同 PeerId 的存活连接数
    connections: usize,
}

/// 拨号在飞登记（按所拨 multiaddr 键控：established 事件回带同一地址）
struct PendingDial {
    expected: NodeId,
    reply: oneshot::Sender<Result<(), P2pError>>,
}

#[allow(clippy::too_many_arguments)]
async fn run_pump(
    mut swarm: Swarm<NodeBehaviour>,
    mut cmd_rx: mpsc::Receiver<EngineCmd>,
    mut settle_rx: mpsc::Receiver<AdmissionSettled>,
    settle_tx: mpsc::Sender<AdmissionSettled>,
    gate: AdmissionGate,
    ports: P2pPorts,
    listen_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    links: LinkRegistry,
    admit_on_connect: bool,
) {
    let mut conns: HashMap<PeerId, ConnState> = HashMap::new();
    let mut pending_dials: HashMap<Multiaddr, PendingDial> = HashMap::new();
    let mut reaper = tokio::time::interval(DENY_REAPER_INTERVAL);
    reaper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                None => break, // 句柄侧全部丢弃 = 无持有者，泵随最后一个句柄退出
                Some(EngineCmd::Shutdown { reply }) => {
                    let _ = reply.send(());
                    break; // swarm 随泵任务结束析构，在途连接全关
                }
                Some(EngineCmd::CancelDial { addr, expected }) => {
                    if pending_dials.get(&addr).is_some_and(|p| p.expected == expected) {
                        pending_dials.remove(&addr);
                    }
                }
                Some(EngineCmd::Dial { addr, expected, reply }) => {
                    if let Err(e) = swarm.dial(addr.clone()) {
                        let _ = reply.send(Err(P2pError::Dial(e.to_string())));
                        ports.events.dial_failed(DialFailed {
                            addr: socket_addr_or_zero(&addr),
                            expected_node_id: Some(expected),
                            cause: e.to_string(),
                        });
                    } else {
                        pending_dials.insert(addr, PendingDial { expected, reply });
                    }
                }
                Some(EngineCmd::Disconnect { node_id, reply }) => {
                    let hit = conns.iter().find(|(_, st)| st.node_id == node_id).map(|(pid, _)| *pid);
                    match hit {
                        Some(pid) => {
                            if let Some(st) = conns.get_mut(&pid) {
                                st.by_local = true;
                            }
                            let _ = swarm.disconnect_peer_id(pid); // 失败 = 已在关，ConnectionClosed 随后到
                            let _ = reply.send(true);
                        }
                        None => {
                            let _ = reply.send(false);
                        }
                    }
                }
                Some(EngineCmd::RequestAdmission { peer_id, reply }) => {
                    match conns.get(&peer_id) {
                        None => {
                            let _ = reply.send(Err(P2pError::NotConnected(peer_id.to_string())));
                        }
                        Some(st) if st.outbound || st.admitted => {
                            let _ = reply.send(Ok(()));
                        }
                        Some(st) if st.denied => {
                            let _ = reply.send(Err(P2pError::NotAdmitted(st.node_id.to_string())));
                        }
                        Some(st) if st.admission_requested => {
                            // 自动模式已在闸门中 / 已受理过一次：幂等返回，终态看 watch
                            let _ = reply.send(Ok(()));
                        }
                        Some(st) => {
                            let node_id = st.node_id.clone();
                            match gate.request(
                                node_id.clone(),
                                peer_id,
                                Arc::clone(&ports.admission),
                                settle_tx.clone(),
                            ) {
                                GateRequest::InProgress => {
                                    if let Some(st) = conns.get_mut(&peer_id) {
                                        st.admission_requested = true;
                                    }
                                    let _ = reply.send(Ok(()));
                                }
                                GateRequest::Denied(cause) => {
                                    if let Some(st) = conns.get_mut(&peer_id) {
                                        st.denied = true;
                                        st.admission_requested = true;
                                        st.denied_at = Some(Instant::now());
                                    }
                                    links
                                        .write()
                                        .expect("链路登记表中毒")
                                        .settle(&peer_id, LinkAdmission::Denied);
                                    ports.events.peer_denied(PeerDenied {
                                        node_id: Some(node_id),
                                        peer_id: Some(peer_id),
                                        cause,
                                    });
                                    let _ =
                                        reply.send(Err(P2pError::NotAdmitted(peer_id.to_string())));
                                }
                            }
                        }
                    }
                }
                Some(EngineCmd::ResetAdmission { peer_id, reply }) => {
                    match conns.get_mut(&peer_id) {
                        None => {
                            let _ = reply.send(Err(P2pError::NotConnected(peer_id.to_string())));
                        }
                        Some(st) => {
                            if st.admission_requested {
                                gate.withdraw(&st.node_id);
                            }
                            st.admitted = false;
                            st.denied = false;
                            st.admission_requested = false;
                            st.denied_at = None;
                            links
                                .write()
                                .expect("链路登记表中毒")
                                .settle(&peer_id, LinkAdmission::Pending);
                            let _ = reply.send(Ok(()));
                        }
                    }
                }
            },

            settled = settle_rx.recv() => {
                if let Some(AdmissionSettled { node_id, peer_id, admitted, cause }) = settled {
                    match conns.get_mut(&peer_id) {
                        // 连接仍在且未结算过：按结局处置
                        Some(st) if !st.outbound && !st.admitted && !st.denied => {
                            if admitted {
                                st.admitted = true;
                                links.write().expect("链路登记表中毒").settle(&peer_id, LinkAdmission::Admitted);
                                let ev = PeerConnected {
                                    node_id: st.node_id.clone(),
                                    peer_id,
                                    outbound: false,
                                    remote_addr: st.remote_addr,
                                };
                                ports.events.peer_connected(ev);
                            } else {
                                // 保留连接：信任状态流还要把 Denied 帧写回拨号方；
                                // 回收定时器在 DENY_GRACE 后断开
                                st.denied = true;
                                st.denied_at = Some(Instant::now());
                                links.write().expect("链路登记表中毒").settle(&peer_id, LinkAdmission::Denied);
                                ports.events.peer_denied(PeerDenied {
                                    node_id: Some(node_id),
                                    peer_id: Some(peer_id),
                                    cause,
                                });
                            }
                        }
                        // 连接已不在（闸门未结算先断）/ 已结算过：结算迟到，丢弃即可
                        _ => {}
                    }
                }
            }

            _ = reaper.tick() => {
                let now = Instant::now();
                let expired: Vec<PeerId> = conns
                    .iter()
                    .filter(|(_, st)| {
                        st.denied
                            && st
                                .denied_at
                                .is_some_and(|at| now.duration_since(at) >= DENY_GRACE)
                    })
                    .map(|(pid, _)| *pid)
                    .collect();
                for pid in expired {
                    if let Some(st) = conns.get_mut(&pid) {
                        st.by_local = true;
                    }
                    let _ = swarm.disconnect_peer_id(pid);
                }
            }

            ev = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm,
                    &mut conns,
                    &mut pending_dials,
                    &gate,
                    &settle_tx,
                    &ports,
                    &listen_addrs,
                    &links,
                    admit_on_connect,
                    ev,
                );
            }
        }
    }
    // 泵退出前清掉在飞句柄等待者（避免 dial 等满超时）
    for (_, pending) in pending_dials.drain() {
        let _ = pending.reply.send(Err(P2pError::NotRunning));
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    swarm: &mut Swarm<NodeBehaviour>,
    conns: &mut HashMap<PeerId, ConnState>,
    pending_dials: &mut HashMap<Multiaddr, PendingDial>,
    gate: &AdmissionGate,
    settle_tx: &mpsc::Sender<AdmissionSettled>,
    ports: &P2pPorts,
    listen_addrs: &Arc<RwLock<Vec<SocketAddr>>>,
    links: &LinkRegistry,
    admit_on_connect: bool,
    ev: SwarmEvent<NodeBehaviourEvent>,
) {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } => {
            if let Some(sa) = multiaddr_to_socket_addr(&address) {
                let mut snap = listen_addrs.write().expect("监听地址快照中毒");
                if !snap.contains(&sa) {
                    snap.push(sa);
                    snap.sort();
                }
                ports.events.listening_changed(snap.clone());
            }
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            if let Some(sa) = multiaddr_to_socket_addr(&address) {
                let mut snap = listen_addrs.write().expect("监听地址快照中毒");
                snap.retain(|a| *a != sa);
                ports.events.listening_changed(snap.clone());
            }
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => match endpoint {
            ConnectedPoint::Dialer { address, .. } => {
                let actual = match node_id_from_peer_id(&peer_id) {
                    Ok(id) => id,
                    Err(e) => {
                        // 出站握手后身份不支持：断开 + 归属失败（若有在飞登记）
                        let _ = swarm.disconnect_peer_id(peer_id);
                        fail_pending_dial(pending_dials, &address, &ports.events, e.to_string());
                        return;
                    }
                };
                let remote_addr = socket_addr_or_zero(&address);

                // 同 PeerId 已有连接：只累加计数；出站方向把 pending 入站链路提升
                if let Some(st) = conns.get_mut(&peer_id) {
                    st.connections += 1;
                    st.outbound = true;
                    st.admitted = true;
                    st.denied = false;
                    st.denied_at = None;
                    st.remote_addr = remote_addr;
                    links.write().expect("链路登记表中毒").insert(PeerLink {
                        node_id: actual.clone(),
                        peer_id,
                        remote_addr,
                        outbound: true,
                        admission: LinkAdmission::Admitted,
                        connections: 1,
                    });
                    if let Some((_, pending)) = take_pending_dial(pending_dials, &address, &actual)
                    {
                        let _ = pending.reply.send(Ok(()));
                    }
                    return;
                }

                let Some((_, PendingDial { expected, reply })) =
                    take_pending_dial(pending_dials, &address, &actual)
                else {
                    // 无在飞登记的出站连接（当前引擎只经 dial 出站，防御分支）
                    tracing::warn!(%peer_id, node_id = %actual, "出站连接无在飞登记，按已校验放行");
                    insert_link_with_peer(
                        conns,
                        links,
                        peer_id,
                        ConnState {
                            node_id: actual.clone(),
                            outbound: true,
                            admitted: true,
                            denied: false,
                            admission_requested: false,
                            denied_at: None,
                            by_local: false,
                            remote_addr,
                            connections: 1,
                        },
                    );
                    ports.events.peer_connected(PeerConnected {
                        node_id: actual,
                        peer_id,
                        outbound: true,
                        remote_addr,
                    });
                    return;
                };
                match verify_peer_identity(&peer_id, &expected) {
                    Ok(_) => {
                        insert_link_with_peer(
                            conns,
                            links,
                            peer_id,
                            ConnState {
                                node_id: actual.clone(),
                                outbound: true,
                                admitted: true,
                                denied: false,
                                admission_requested: false,
                                denied_at: None,
                                by_local: false,
                                remote_addr,
                                connections: 1,
                            },
                        );
                        let _ = reply.send(Ok(()));
                        ports.events.peer_connected(PeerConnected {
                            node_id: actual,
                            peer_id,
                            outbound: true,
                            remote_addr,
                        });
                    }
                    Err(e) => {
                        let _ = swarm.disconnect_peer_id(peer_id);
                        let _ = reply.send(Err(P2pError::NodeIdMismatch {
                            expected: expected.to_string(),
                            actual: actual.to_string(),
                        }));
                        ports.events.dial_failed(DialFailed {
                            addr: remote_addr,
                            expected_node_id: Some(expected),
                            cause: e.to_string(),
                        });
                    }
                }
            }
            ConnectedPoint::Listener { send_back_addr, .. } => {
                let node_id = match node_id_from_peer_id(&peer_id) {
                    Ok(id) => id,
                    Err(e) => {
                        let _ = swarm.disconnect_peer_id(peer_id);
                        ports.events.peer_denied(PeerDenied {
                            node_id: None,
                            peer_id: Some(peer_id),
                            cause: DenyCause::UnsupportedIdentity,
                        });
                        tracing::warn!(%peer_id, error = %e, "入站对端身份不支持，已断开");
                        return;
                    }
                };
                let remote_addr = socket_addr_or_zero(&send_back_addr);

                // 同 PeerId 已有连接：只累加计数；已准入则不再走闸门
                if let Some(st) = conns.get_mut(&peer_id) {
                    st.connections += 1;
                    if st.remote_addr.port() == 0 {
                        st.remote_addr = remote_addr;
                    }
                    links.write().expect("链路登记表中毒").insert(PeerLink {
                        node_id: node_id.clone(),
                        peer_id,
                        remote_addr,
                        outbound: false,
                        admission: if st.admitted {
                            LinkAdmission::Admitted
                        } else if st.denied {
                            LinkAdmission::Denied
                        } else {
                            LinkAdmission::Pending
                        },
                        connections: 1,
                    });
                    return;
                }

                insert_link_with_peer(
                    conns,
                    links,
                    peer_id,
                    ConnState {
                        node_id: node_id.clone(),
                        outbound: false,
                        admitted: false,
                        denied: false,
                        admission_requested: false,
                        denied_at: None,
                        by_local: false,
                        remote_addr,
                        connections: 1,
                    },
                );
                // 自动闸门（P0 语义）与显式闸门（信任状态流校验后请求）二选一：
                // 显式模式下链路保持 Pending，业务流由 IncomingStreams 过滤。
                if admit_on_connect {
                    match gate.request(
                        node_id,
                        peer_id,
                        Arc::clone(&ports.admission),
                        settle_tx.clone(),
                    ) {
                        GateRequest::InProgress => {
                            if let Some(st) = conns.get_mut(&peer_id) {
                                st.admission_requested = true;
                            }
                        }
                        GateRequest::Denied(cause) => {
                            // 立时拒绝（重复 pending / 超上限）同样保留连接写 Denied，
                            // 由回收定时器断开
                            if let Some(st) = conns.get_mut(&peer_id) {
                                st.denied = true;
                                st.admission_requested = true;
                                st.denied_at = Some(Instant::now());
                            }
                            links
                                .write()
                                .expect("链路登记表中毒")
                                .settle(&peer_id, LinkAdmission::Denied);
                            let denied_node_id = conns.get(&peer_id).map(|st| st.node_id.clone());
                            ports.events.peer_denied(PeerDenied {
                                node_id: denied_node_id,
                                peer_id: Some(peer_id),
                                cause,
                            });
                        }
                    }
                }
            }
        },
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            let last = if let Some(st) = conns.get_mut(&peer_id) {
                if num_established == 0 {
                    true
                } else {
                    st.connections = st.connections.saturating_sub(1);
                    false
                }
            } else {
                num_established == 0
            };
            if last {
                let _ = links
                    .write()
                    .expect("链路登记表中毒")
                    .remove_connection(&peer_id);
                if let Some(st) = conns.remove(&peer_id) {
                    if !st.outbound && !st.admitted && !st.denied {
                        // 闸门未结算先断：撤记账防滞留（结算迟到时泵侧丢弃）
                        gate.withdraw(&st.node_id);
                    } else if st.admitted {
                        ports.events.peer_disconnected(PeerDisconnected {
                            node_id: st.node_id,
                            peer_id,
                            by_local: st.by_local,
                        });
                    }
                } else {
                    // 防御：连接在登记前就关闭（身份不支持等），确保登记面不残留
                    let _ = links.write().expect("链路登记表中毒").remove(&peer_id);
                }
            } else {
                let _ = links
                    .write()
                    .expect("链路登记表中毒")
                    .remove_connection(&peer_id);
            }
        }
        SwarmEvent::OutgoingConnectionError { error, .. } => {
            // 多路在飞时失败事件不携地址无法归属：只在单路时精确结算，多路由拨号超时兜底
            if pending_dials.len() == 1 {
                let (addr, entry) = pending_dials.drain().next().expect("len==1 必有元素");
                let _ = entry.reply.send(Err(P2pError::Dial(error.to_string())));
                ports.events.dial_failed(DialFailed {
                    addr: socket_addr_or_zero(&addr),
                    expected_node_id: Some(entry.expected),
                    cause: error.to_string(),
                });
            } else {
                tracing::debug!(%error, pending = pending_dials.len(), "出站连接失败（多路在飞不归属，由拨号超时兜底）");
            }
        }
        SwarmEvent::Behaviour(NodeBehaviourEvent::Ping(ping::Event {
            result: Err(e),
            peer,
            ..
        })) => {
            // ping 探死：连接随后由 swarm 关闭，ConnectionClosed 兜底发事件
            tracing::debug!(peer = %peer, error = %e, "ping 失败（对端疑似静默死亡）");
        }
        SwarmEvent::Behaviour(NodeBehaviourEvent::Ping(ping::Event {
            result: Ok(rtt),
            peer,
            ..
        })) => {
            tracing::trace!(peer = %peer, ?rtt, "ping");
        }
        SwarmEvent::IncomingConnection { .. }
        | SwarmEvent::IncomingConnectionError { .. }
        | SwarmEvent::ListenerClosed { .. }
        | SwarmEvent::ListenerError { .. }
        | SwarmEvent::Dialing { .. }
        | SwarmEvent::NewExternalAddrCandidate { .. }
        | SwarmEvent::ExternalAddrConfirmed { .. }
        | SwarmEvent::ExternalAddrExpired { .. } => {}
        // SwarmEvent 是 non_exhaustive：升级 libp2p 引入的新事件一律按「引擎不
        // 消费」忽略——上面具名分组已覆盖当前全部语义面，新面是否要接由升级
        // 批次的对齐判据（环回测试 + P1 线协议用例）决定
        _ => {}
    }
}

/// 带显式 PeerId 的链路登记（泵内唯一入口）
fn insert_link_with_peer(
    conns: &mut HashMap<PeerId, ConnState>,
    links: &LinkRegistry,
    peer_id: PeerId,
    state: ConnState,
) {
    let info = PeerLink {
        node_id: state.node_id.clone(),
        peer_id,
        remote_addr: state.remote_addr,
        outbound: state.outbound,
        admission: if state.admitted {
            LinkAdmission::Admitted
        } else if state.denied {
            LinkAdmission::Denied
        } else {
            LinkAdmission::Pending
        },
        connections: 1,
    };
    links.write().expect("链路登记表中毒").insert(info);
    conns.insert(peer_id, state);
}

/// 取在飞拨号登记：先按地址，再按期望 node_id（libp2p 地址可能规范化）
fn take_pending_dial(
    pending_dials: &mut HashMap<Multiaddr, PendingDial>,
    addr: &Multiaddr,
    actual_node_id: &NodeId,
) -> Option<(Multiaddr, PendingDial)> {
    let key = if pending_dials.contains_key(addr) {
        Some(addr.clone())
    } else {
        pending_dials
            .iter()
            .find(|(_, pending)| pending.expected == *actual_node_id)
            .map(|(key, _)| key.clone())
    }?;
    pending_dials.remove_entry(&key)
}

/// 把在飞拨号登记结算为失败（回执 + 事件；无登记则只发事件——保留兜底语义）
fn fail_pending_dial(
    pending_dials: &mut HashMap<Multiaddr, PendingDial>,
    addr: &Multiaddr,
    events: &Arc<dyn P2pEventSink>,
    cause: String,
) {
    let entry = pending_dials.remove(addr);
    let expected = entry.as_ref().map(|e| e.expected.clone());
    if let Some(entry) = entry {
        let _ = entry.reply.send(Err(P2pError::Dial(cause.clone())));
    }
    events.dial_failed(DialFailed {
        addr: socket_addr_or_zero(addr),
        expected_node_id: expected,
        cause,
    });
}

// ==================== 地址工具 ====================

/// 监听 multiaddr 组装（`/ip4|ip6/<addr>/tcp/<port>`）
fn listen_multiaddr(ip: IpAddr, port: u16) -> Multiaddr {
    let ma = Multiaddr::empty();
    let ma = match ip {
        IpAddr::V4(v4) => ma.with(Protocol::Ip4(v4)),
        IpAddr::V6(v6) => ma.with(Protocol::Ip6(v6)),
    };
    ma.with(Protocol::Tcp(port))
}

/// 拨号地址 → multiaddr（peer-net 组装 StaticPeerRecord 时使用）
pub fn socket_addr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    listen_multiaddr(addr.ip(), addr.port())
}

/// multiaddr → SocketAddr（取首个 IP 组件 + TCP 端口；其余形态 None）
pub(crate) fn multiaddr_to_socket_addr(ma: &Multiaddr) -> Option<SocketAddr> {
    let mut ip = None;
    let mut port = None;
    for p in ma.iter() {
        match p {
            Protocol::Ip4(v) => ip = Some(IpAddr::V4(v)),
            Protocol::Ip6(v) => ip = Some(IpAddr::V6(v)),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?))
}

/// SocketAddr 形态兜底：本引擎生成/回带的地址恒为 ip+tcp，转换失败说明形态
/// 异常——事件里给全零地址并在调用点留痕，不静默丢事件
fn socket_addr_or_zero(ma: &Multiaddr) -> SocketAddr {
    multiaddr_to_socket_addr(ma).unwrap_or_else(|| {
        tracing::warn!(%ma, "multiaddr 非预期形态（无 ip/tcp），事件地址落全零");
        SocketAddr::from(([0, 0, 0, 0], 0))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PeerAdmissionPort;
    use crate::stream_proto::{TRANSFER, TRUST_STATUS};
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use std::time::Duration;
    use tokio::sync::Mutex as AsyncMutex;

    // ==================== 测试装配 ====================

    /// 事件收集桩：全部事件转字符串推入通道（断言按词匹配）
    #[derive(Clone)]
    struct CollectSink {
        tx: mpsc::UnboundedSender<String>,
    }

    fn describe_listening(addrs: &[SocketAddr]) -> String {
        format!("listening {:?}", addrs)
    }

    impl P2pEventSink for CollectSink {
        fn listening_changed(&self, addrs: Vec<SocketAddr>) {
            let _ = self.tx.send(describe_listening(&addrs));
        }
        fn peer_connected(&self, ev: PeerConnected) {
            let _ = self.tx.send(format!(
                "connected node={} outbound={} addr={}",
                ev.node_id, ev.outbound, ev.remote_addr
            ));
        }
        fn peer_disconnected(&self, ev: PeerDisconnected) {
            let _ = self.tx.send(format!(
                "disconnected node={} local={}",
                ev.node_id, ev.by_local
            ));
        }
        fn peer_denied(&self, ev: PeerDenied) {
            let _ = self.tx.send(format!(
                "denied node={:?} cause={:?}",
                ev.node_id.map(|n| n.to_string()),
                ev.cause
            ));
        }
        fn dial_failed(&self, ev: DialFailed) {
            let _ = self.tx.send(format!("dial_failed cause={}", ev.cause));
        }
    }

    struct AutoAdmit;
    #[async_trait::async_trait]
    impl PeerAdmissionPort for AutoAdmit {
        async fn confirm_inbound(&self, _node_id: &NodeId, _peer_id: &PeerId) -> bool {
            true
        }
    }

    struct AlwaysDeny;
    #[async_trait::async_trait]
    impl PeerAdmissionPort for AlwaysDeny {
        async fn confirm_inbound(&self, _node_id: &NodeId, _peer_id: &PeerId) -> bool {
            false
        }
    }

    /// 永不应答端口（超时结算测试用）
    struct NeverAnswer;
    #[async_trait::async_trait]
    impl PeerAdmissionPort for NeverAnswer {
        async fn confirm_inbound(&self, _node_id: &NodeId, _peer_id: &PeerId) -> bool {
            std::future::pending().await
        }
    }

    fn ports_with(
        admit: Arc<dyn PeerAdmissionPort>,
    ) -> (P2pPorts, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            P2pPorts {
                admission: admit,
                events: Arc::new(CollectSink { tx }),
            },
            rx,
        )
    }

    fn localhost_config() -> P2pNodeConfig {
        P2pNodeConfig {
            listen_addr: IpAddr::from([127, 0, 0, 1]),
            listen_port: 0,
            admission: crate::admission::AdmissionConfig::default(),
            admit_on_connect: true,
        }
    }

    async fn wait_listen(node: &RunningNode) -> SocketAddr {
        for _ in 0..100 {
            if let Some(sa) = node.listen_addresses().first() {
                return *sa;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("监听地址 2s 内未出现");
    }

    /// 等待对端链路登记（拨号方 dial 返回早于被拨方处理入站事件）
    async fn wait_peer_link(node: &RunningNode, node_id: &NodeId) -> PeerLink {
        for _ in 0..100 {
            if let Some(link) = node.peer_link(node_id) {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("2s 内未见对端链路 {} 登记", node_id);
    }

    /// 轮询事件通道直到出现含 `needle` 的事件（5s 超时；已读事件按序保留语义：
    /// 简化为丢弃非目标事件——各测试只断言自己关心的事件）
    async fn await_event(rx: &AsyncMutex<mpsc::UnboundedReceiver<String>>, needle: &str) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                panic!("5s 内未见事件含 {needle:?}");
            }
            let ev = {
                let mut guard = rx.try_lock().expect("事件通道锁竞争");
                match guard.recv().await {
                    Some(ev) => ev,
                    None => panic!("事件通道关闭"),
                }
            };
            if ev.contains(needle) {
                return ev;
            }
        }
    }

    // ==================== 用例 ====================

    #[tokio::test]
    async fn 环回_拨号_双向事件_与_身份互验() {
        let (b_ports, b_rx) = ports_with(Arc::new(AutoAdmit));
        let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();

        // A 拨 B：dial 完成 = 握手 + node_id 校验通过
        let b_node_id = b.node_id().clone();
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b_node_id.clone(),
        )
        .await
        .expect("环回拨号应成功");

        let a_rx = AsyncMutex::new(a_rx);
        let ev = await_event(&a_rx, "connected").await;
        assert!(
            ev.contains(&b_node_id.to_string()),
            "A 侧 connected 应点名 B 的 node_id：{ev}"
        );
        assert!(ev.contains("outbound=true"), "A 侧应为出站：{ev}");

        let b_rx = AsyncMutex::new(b_rx);
        let ev = await_event(&b_rx, "connected").await;
        assert!(
            ev.contains(&a.node_id().to_string()),
            "B 侧 connected 应点名 A 的 node_id：{ev}"
        );
        assert!(
            ev.contains("outbound=false"),
            "B 侧应为入站（已过准入）：{ev}"
        );

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 期望_node_id_不符_断开且显性报错() {
        let (b_ports, _b_rx) = ports_with(Arc::new(AutoAdmit));
        let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();

        // 期望一个不存在的 node_id：握手完成后校验必失败
        let bogus = NodeKey::generate().node_id().clone();
        let err = a
            .dial(
                listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
                bogus,
            )
            .await
            .expect_err("身份不符应显性报错");
        assert!(
            matches!(err, P2pError::NodeIdMismatch { .. }),
            "应为 NodeIdMismatch：{err:?}"
        );

        let a_rx = AsyncMutex::new(a_rx);
        assert!(await_event(&a_rx, "dial_failed")
            .await
            .contains("node_id 不匹配"));

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 准入拒绝_端口说不_上报成因并回收连接() {
        let (b_ports, b_rx) = ports_with(Arc::new(AlwaysDeny));
        let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();

        // A 侧校验只关乎 B 的身份，dial 本身成功；B 随后拒绝并保留连接写 Denied
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("A 侧拨号校验通过");

        let b_rx = AsyncMutex::new(b_rx);
        let ev = await_event(&b_rx, "denied").await;
        assert!(ev.contains("PortDenied"), "拒绝成因应为端口拒绝：{ev}");

        // 拒绝态链路已登记 Denied（宽限期内仍在），业务流不可用
        let denied = wait_peer_link(&b, a.node_id()).await;
        assert_eq!(denied.admission, LinkAdmission::Denied);

        let a_rx = AsyncMutex::new(a_rx);
        await_event(&a_rx, "disconnected").await;

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 准入超时_按拒绝结算() {
        let (b_ports, b_rx) = ports_with(Arc::new(NeverAnswer));
        let config = P2pNodeConfig {
            admission: crate::admission::AdmissionConfig {
                confirm_timeout: Duration::from_millis(150),
                max_pending: 8,
            },
            ..localhost_config()
        };
        let b = P2pEngine::start(NodeKey::generate(), config, b_ports).unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("A 侧拨号校验通过");

        let b_rx = AsyncMutex::new(b_rx);
        let ev = await_event(&b_rx, "denied").await;
        assert!(ev.contains("Timeout"), "拒绝成因应为超时：{ev}");

        let a_rx = AsyncMutex::new(a_rx);
        await_event(&a_rx, "disconnected").await;

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 断开命令_命中在连对端() {
        let (b_ports, _b_rx) = ports_with(Arc::new(AutoAdmit));
        let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("拨号成功");

        let a_rx = AsyncMutex::new(a_rx);
        await_event(&a_rx, "connected").await;

        assert!(a
            .disconnect(b.node_id().clone())
            .await
            .expect("断开命令应可达"));
        assert!(!a
            .disconnect(b.node_id().clone())
            .await
            .expect("重复断开应未命中"));
        let ev = await_event(&a_rx, "disconnected").await;
        assert!(ev.contains("local=true"), "本端主动断开：{ev}");

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 关停幂等_克隆句柄共享同一泵() {
        let (ports, _rx) = ports_with(Arc::new(AutoAdmit));
        let node = P2pEngine::start(NodeKey::generate(), localhost_config(), ports).unwrap();
        let clone = node.clone();
        node.shutdown().await;
        // 第二次 shutdown（另一个克隆）应直接返回，不 panic / 不挂起
        clone.shutdown().await;
        // 关停后命令面失效：拨号返回 NotRunning
        let err = clone
            .dial(
                listen_multiaddr(IpAddr::from([127, 0, 0, 1]), 1),
                NodeKey::generate().node_id().clone(),
            )
            .await
            .expect_err("关停后拨号应失败");
        assert!(
            matches!(err, P2pError::NotRunning),
            "应为 NotRunning：{err:?}"
        );
    }

    /// 多地址工具判据
    #[test]
    fn multiaddr_与_socketaddr_互转() {
        let ma = listen_multiaddr(IpAddr::from([127, 0, 0, 1]), 47613);
        assert_eq!(
            multiaddr_to_socket_addr(&ma),
            Some(SocketAddr::from(([127, 0, 0, 1], 47613)))
        );
        // 非 ip/tcp 形态 → None（fail-visible：调用方决定兜底）
        let dns_like: Multiaddr = "/dns4/example.com/tcp/80".parse().unwrap();
        assert_eq!(multiaddr_to_socket_addr(&dns_like), None);
    }

    // ==================== 具名流 P1 用例 ====================

    #[tokio::test]
    async fn 已准入业务流_可往返读写() {
        let (b_ports, _b_rx) = ports_with(Arc::new(AutoAdmit));
        let (b, mut streams) = P2pEngine::start_with_protocols(
            NodeKey::generate(),
            localhost_config(),
            b_ports,
            &[TRANSFER],
        )
        .unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, _a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("拨号成功");

        let mut incoming = streams.remove(TRANSFER).expect("业务协议接收器");
        let a_node_id = a.node_id().clone();
        let server = tokio::spawn(async move {
            let mut inbound = incoming.next().await.expect("应收到业务流");
            assert_eq!(inbound.node_id, a_node_id, "入站流应来自拨号方 A");
            let mut buf = [0u8; 5];
            inbound.stream.read_exact(&mut buf).await.expect("读请求");
            assert_eq!(&buf, b"ping!");
            inbound.stream.write_all(b"pong!").await.expect("写响应");
            inbound.stream.flush().await.expect("flush");
        });

        let mut stream = a
            .open_stream(&b.node_id().clone(), TRANSFER)
            .await
            .expect("已准入链路开流");
        stream.write_all(b"ping!").await.expect("写请求");
        stream.flush().await.expect("flush");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.expect("读响应");
        assert_eq!(&buf, b"pong!");

        server.await.expect("server task");
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 信任状态流_在_pending_可被接收() {
        // B 永不回答准入 → 链路保持 Pending；信任状态协议仍须可开流（写 Pending）
        let (b_ports, _b_rx) = ports_with(Arc::new(NeverAnswer));
        let (b, mut streams) = P2pEngine::start_with_protocols(
            NodeKey::generate(),
            localhost_config(),
            b_ports,
            &[TRUST_STATUS],
        )
        .unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, _a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("拨号成功");

        let b_link = wait_peer_link(&b, a.node_id()).await;
        assert_eq!(b_link.admission, LinkAdmission::Pending);

        let mut incoming = streams.remove(TRUST_STATUS).expect("信任状态协议接收器");
        let server = tokio::spawn(async move {
            let mut inbound = incoming.next().await.expect("pending 态信任状态流应可收");
            inbound
                .stream
                .write_all(b"pending")
                .await
                .expect("写 Pending");
            inbound.stream.flush().await.expect("flush");
        });

        let mut stream = a
            .open_stream(&b.node_id().clone(), TRUST_STATUS)
            .await
            .expect("已准入出站链路可开信任状态流");
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.expect("读 Pending");
        assert_eq!(&buf, b"pending");

        server.await.expect("server task");
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 显式准入_请求前保持_pending_请求后放行() {
        // peer-net 换轨路径：连接建立不自动进闸门，信任状态流校验 Hello 后
        // 才 request_admission；在此之前业务流一律被丢弃。
        let config = P2pNodeConfig {
            admit_on_connect: false,
            ..localhost_config()
        };
        let (b_ports, _b_rx) = ports_with(Arc::new(AutoAdmit));
        let (b, mut streams) =
            P2pEngine::start_with_protocols(NodeKey::generate(), config, b_ports, &[TRANSFER])
                .unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, _a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("拨号成功");

        let b_link = wait_peer_link(&b, a.node_id()).await;
        assert_eq!(b_link.admission, LinkAdmission::Pending);
        let mut watch = b.admission_watch(&b_link.peer_id).expect("准入 watch");

        let mut incoming = streams.remove(TRANSFER).expect("业务协议接收器");
        let _pre = a
            .open_stream(&b.node_id().clone(), TRANSFER)
            .await
            .expect("A 侧出站链路已准入");
        let got = tokio::time::timeout(Duration::from_millis(300), incoming.next()).await;
        assert!(got.is_err(), "未请求准入前业务流不应被接收");

        b.request_admission(&b_link.peer_id)
            .await
            .expect("显式准入请求应受理");
        tokio::time::timeout(Duration::from_secs(2), watch.changed())
            .await
            .expect("准入 2s 内应结算")
            .expect("watch 应存活");
        assert_eq!(*watch.borrow(), LinkAdmission::Admitted);

        let _post = a
            .open_stream(&b.node_id().clone(), TRANSFER)
            .await
            .expect("放行后开流");
        let inbound = tokio::time::timeout(Duration::from_secs(2), incoming.next())
            .await
            .expect("放行后 2s 内应收到业务流")
            .expect("业务流接收器不应结束");
        assert_eq!(inbound.node_id, a.node_id().clone());

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 未准入业务流_入站侧被丢弃() {
        // B 保持 Pending（NeverAnswer）；A 侧出站链路已准入，可尝试开业务流；
        // B 的 IncomingStreams(require_admitted=true) 必须丢弃该流。
        let (b_ports, _b_rx) = ports_with(Arc::new(NeverAnswer));
        let (b, mut streams) = P2pEngine::start_with_protocols(
            NodeKey::generate(),
            localhost_config(),
            b_ports,
            &[TRANSFER],
        )
        .unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, _a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("拨号成功");

        let b_link = wait_peer_link(&b, a.node_id()).await;
        assert_eq!(b_link.admission, LinkAdmission::Pending);

        let mut incoming = streams.remove(TRANSFER).expect("业务协议接收器");
        let _stream = a
            .open_stream(&b.node_id().clone(), TRANSFER)
            .await
            .expect("A 侧出站链路已准入");

        // B 侧应持续拿不到该流（被准入过滤丢弃）
        let got = tokio::time::timeout(Duration::from_millis(500), incoming.next()).await;
        assert!(got.is_err(), "未准入业务流不应被接收");

        a.shutdown().await;
        b.shutdown().await;
    }
}
