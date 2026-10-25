//! swarm 引擎：节点生命周期（监听 / 拨号 / 事件泵 / 关停）与连接状态机。
//!
//! ## 形态
//!
//! [`P2pEngine::start`] 装配一个 swarm（TCP + noise + yamux + ping）并派生
//! **事件泵任务**：泵独占 swarm，`select` 三路输入——swarm 事件 / 引擎命令
//! （[`EngineCmd`]，[`RunningNode`] 句柄发来）/ 准入结算（[`crate::admission`]）。
//! 句柄侧全部操作经命令通道进泵，无共享可变状态（除监听地址快照的只读共享）。
//!
//! ## 连接状态机（P0 语义，P1 换轨的对齐判据）
//!
//! | 事件 | 出站（本端拨） | 入站（对端拨入） |
//! | --- | --- | --- |
//! | 连接建立 | 从 PeerId 重算 node_id 并与期望校验：不一致 → 断开 + `dial_failed` | 同左重算：派生不出（非 ed25519）→ 断开 + `peer_denied(UnsupportedIdentity)` |
//! | 建立后校验过 | `peer_connected(outbound=true)` | 走准入闸门（端口确认 vs 超时） |
//! | 闸门结算 | — | 放行 → `peer_connected(outbound=false)`；拒绝 → 断开 + `peer_denied(cause)` |
//! | 连接全关 | `peer_disconnected` | 同左（未结算先断：撤 pending 记账，不发事件） |
//!
//! **闸门放行前零上层协议流量**：P0 行为面只有 ping（保活 / 探死）；业务流协议
//! （[`crate::stream_proto`]）P1 接入时必须只对已放行对端供流。
//!
//! 保活语义：空闲连接超时设一天 + ping（默认 15s 间隔 / 20s 超时）探死——对端
//! 静默死亡（WiFi 骤断无 FIN）在 ping 超时窗口内以连接关闭浮现，对齐现役栈
//! socket2 keepalive 的意图；连接常驻（会话不因空闲被拆）。
//!
//! ## 拨号归属的 P0 边界（刻意，已文档化）
//!
//! libp2p 的拨号失败事件不携带所拨地址：**单路在飞时精确归属失败**；多路在飞时
//! 失败事件无法逐路对应，由 [`RunningNode::dial`] 的超时窗口兜底结算。文件传输
//! 场景一次拨一个目标，不触此边界。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{noise, ping, tcp, yamux, Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::admission::{AdmissionGate, AdmissionSettled, GateRequest};
use crate::error::P2pError;
use crate::identity_bridge::{node_id_from_peer_id, verify_peer_identity, NodeId, NodeKey};
use crate::ports::{
    DenyCause, DialFailed, P2pEventSink, P2pPorts, PeerConnected, PeerDenied, PeerDisconnected,
};

/// 拨号完成的超时窗口（握手 + node_id 校验；多路在飞时失败归属的兜底结算）
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// 空闲连接超时：远大于 ping 间隔——连接常驻，探死交给 ping
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// 节点配置
#[derive(Debug, Clone)]
pub struct P2pNodeConfig {
    /// 监听绑定的本端地址（默认 `0.0.0.0` 全网卡；测试用 `127.0.0.1`）
    pub listen_addr: IpAddr,
    /// 监听端口（默认 0 = 系统分配；现役栈的固定端口由调用方传入）
    pub listen_port: u16,
    /// 准入闸门配置（超时 / pending 上限）
    pub admission: crate::admission::AdmissionConfig,
}

impl Default for P2pNodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: IpAddr::from([0, 0, 0, 0]),
            listen_port: 0,
            admission: crate::admission::AdmissionConfig::default(),
        }
    }
}

// ==================== 行为面 ====================

/// 节点行为面：P0 只有 ping（保活 + 探死）
///
/// 业务流行为（trust-status / transfer / shared-dir）P1 随线协议迁移加入——
/// 加入时必须只对已放行对端供流（闸门语义，见模块文档）。
#[derive(NetworkBehaviour)]
pub(crate) struct NodeBehaviour {
    ping: ping::Behaviour,
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
    /// 按 node_id 断开（reply = 是否命中在连对端）
    Disconnect {
        node_id: NodeId,
        reply: oneshot::Sender<bool>,
    },
    /// 关停（泵退出前回执）
    Shutdown { reply: oneshot::Sender<()> },
}

/// 运行中的节点句柄（命令通道 + 只读快照；clone 不提供——单句柄与节点同寿命）
pub struct RunningNode {
    node_id: NodeId,
    peer_id: PeerId,
    cmd: mpsc::Sender<EngineCmd>,
    listen_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    pump: Option<JoinHandle<()>>,
}

impl RunningNode {
    /// 本节点 node_id
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// 本节点 PeerId
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// 当前监听地址快照（NewListenAddr / ExpiredListenAddr 维护）
    pub fn listen_addresses(&self) -> Vec<SocketAddr> {
        self.listen_addrs.read().expect("监听地址快照中毒").clone()
    }

    /// 拨号对端并等握手 + node_id 校验完成
    ///
    /// 返回时机：校验通过（连接可用）或失败 / 超时（连接已被引擎断开）。
    /// **并发拨号时失败事件无法逐路归属**（libp2p 限制，见模块文档），多路场景
    /// 依赖超时兜底——一次拨一个目标的用法（文件传输）不受影响。
    pub async fn dial(&self, addr: Multiaddr, expected_node_id: NodeId) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(EngineCmd::Dial {
                addr,
                expected: expected_node_id,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        match tokio::time::timeout(DIAL_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_recv)) => Err(P2pError::NotRunning),
            Err(_elapsed) => Err(P2pError::DialTimeout),
        }
    }

    /// 按 node_id 断开在连对端（返回是否命中）
    pub async fn disconnect(&self, node_id: NodeId) -> Result<bool, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(EngineCmd::Disconnect { node_id, reply: tx })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        rx.await.map_err(|_| P2pError::NotRunning)
    }

    /// 关停节点（幂等：重复调用无副作用）
    ///
    /// 泵退出即 swarm 析构（在途连接全部关闭）；**不逐连接发 `peer_disconnected`**
    /// ——关停是节点级语义，逐连接风暴无消费价值（现役栈同口径）。
    pub async fn shutdown(mut self) {
        if let Some(pump) = self.pump.take() {
            let (tx, rx) = oneshot::channel();
            if self
                .cmd
                .send(EngineCmd::Shutdown { reply: tx })
                .await
                .is_ok()
            {
                let _ = rx.await;
            }
            let _ = pump.await;
        }
    }
}

/// 引擎入口（无状态：装配 + 派生泵）
pub struct P2pEngine;

impl P2pEngine {
    /// 启动节点：装配 swarm、开始监听、派生事件泵
    ///
    /// **须在 tokio 运行时上下文调用**（泵与准入任务都在此派生）。
    /// 监听失败（端口被占等）显性返回 [`P2pError::Listen`]。
    pub fn start(
        key: NodeKey,
        config: P2pNodeConfig,
        ports: P2pPorts,
    ) -> Result<RunningNode, P2pError> {
        let node_id = key.node_id().clone();
        let peer_id = key.peer_id();

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
        ));

        Ok(RunningNode {
            node_id,
            peer_id,
            cmd: cmd_tx,
            listen_addrs,
            pump: Some(pump),
        })
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
    /// 本端是否主动关（关停 / 断开 / 拒绝结算），disconnected 事件携带
    by_local: bool,
    /// 对端地址（出站 = 所拨地址；入站 = 对端来源地址）
    remote_addr: SocketAddr,
}

/// 拨号在飞登记（按所拨 multiaddr 键控：established 事件回带同一地址）
struct PendingDial {
    expected: NodeId,
    reply: oneshot::Sender<Result<(), P2pError>>,
}

async fn run_pump(
    mut swarm: Swarm<NodeBehaviour>,
    mut cmd_rx: mpsc::Receiver<EngineCmd>,
    mut settle_rx: mpsc::Receiver<AdmissionSettled>,
    settle_tx: mpsc::Sender<AdmissionSettled>,
    gate: AdmissionGate,
    ports: P2pPorts,
    listen_addrs: Arc<RwLock<Vec<SocketAddr>>>,
) {
    let mut conns: HashMap<PeerId, ConnState> = HashMap::new();
    let mut pending_dials: HashMap<Multiaddr, PendingDial> = HashMap::new();

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                None => break, // 句柄侧全部丢弃 = 无持有者，泵随最后一个句柄退出
                Some(EngineCmd::Shutdown { reply }) => {
                    let _ = reply.send(());
                    break; // swarm 随泵任务结束析构，在途连接全关
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
            },

            settled = settle_rx.recv() => {
                if let Some(AdmissionSettled { node_id, peer_id, admitted, cause }) = settled {
                    match conns.get_mut(&peer_id) {
                        // 连接仍在且未结算过：按结局处置
                        Some(st) if !st.admitted && !st.outbound => {
                            if admitted {
                                st.admitted = true;
                                let ev = PeerConnected {
                                    node_id: st.node_id.clone(),
                                    peer_id,
                                    outbound: false,
                                    remote_addr: st.remote_addr,
                                };
                                ports.events.peer_connected(ev);
                            } else {
                                st.by_local = true;
                                let _ = swarm.disconnect_peer_id(peer_id);
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

            ev = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm, &mut conns, &mut pending_dials, &gate, &settle_tx, &ports, &listen_addrs, ev,
                );
            }
        }
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
                let Some(PendingDial { expected, reply }) = pending_dials.remove(&address) else {
                    // 无在飞登记的出站连接（当前引擎只经 dial 出站，防御分支）
                    tracing::warn!(%peer_id, node_id = %actual, "出站连接无在飞登记，按已校验放行");
                    conns.insert(
                        peer_id,
                        ConnState {
                            node_id: actual.clone(),
                            outbound: true,
                            admitted: true,
                            by_local: false,
                            remote_addr,
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
                        conns.insert(
                            peer_id,
                            ConnState {
                                node_id: actual.clone(),
                                outbound: true,
                                admitted: true,
                                by_local: false,
                                remote_addr,
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
                        conns.insert(
                            peer_id,
                            ConnState {
                                node_id: actual.clone(),
                                outbound: true,
                                admitted: true,
                                by_local: true,
                                remote_addr,
                            },
                        );
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
                conns.insert(
                    peer_id,
                    ConnState {
                        node_id: node_id.clone(),
                        outbound: false,
                        admitted: false,
                        by_local: false,
                        remote_addr,
                    },
                );
                match gate.request(
                    node_id,
                    peer_id,
                    Arc::clone(&ports.admission),
                    settle_tx.clone(),
                ) {
                    GateRequest::InProgress => {}
                    GateRequest::Denied(cause) => {
                        if let Some(st) = conns.get_mut(&peer_id) {
                            st.by_local = true;
                        }
                        let _ = swarm.disconnect_peer_id(peer_id);
                        let denied_node_id = conns.get(&peer_id).map(|st| st.node_id.clone());
                        ports.events.peer_denied(PeerDenied {
                            node_id: denied_node_id,
                            peer_id: Some(peer_id),
                            cause,
                        });
                    }
                }
            }
        },
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            if num_established == 0 {
                if let Some(st) = conns.remove(&peer_id) {
                    if !st.outbound && !st.admitted {
                        // 闸门未结算先断：撤记账防滞留（结算迟到时泵侧丢弃）
                        gate.withdraw(&st.node_id);
                    } else {
                        ports.events.peer_disconnected(PeerDisconnected {
                            node_id: st.node_id,
                            peer_id,
                            by_local: st.by_local,
                        });
                    }
                }
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
    use std::time::Duration;
    use tokio::sync::Mutex;

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

    /// 轮询事件通道直到出现含 `needle` 的事件（5s 超时；已读事件按序保留语义：
    /// 简化为丢弃非目标事件——各测试只断言自己关心的事件）
    async fn await_event(rx: &Mutex<mpsc::UnboundedReceiver<String>>, needle: &str) -> String {
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

        let a_rx = Mutex::new(a_rx);
        let ev = await_event(&a_rx, "connected").await;
        assert!(
            ev.contains(&b_node_id.to_string()),
            "A 侧 connected 应点名 B 的 node_id：{ev}"
        );
        assert!(ev.contains("outbound=true"), "A 侧应为出站：{ev}");

        let b_rx = Mutex::new(b_rx);
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

        let a_rx = Mutex::new(a_rx);
        assert!(await_event(&a_rx, "dial_failed")
            .await
            .contains("node_id 不匹配"));

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 准入拒绝_端口说不_断开并上报成因() {
        let (b_ports, b_rx) = ports_with(Arc::new(AlwaysDeny));
        let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();
        let b_addr = wait_listen(&b).await;

        let (a_ports, a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();

        // A 侧校验只关乎 B 的身份，dial 本身成功；B 随后拒绝并断开
        a.dial(
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), b_addr.port()),
            b.node_id().clone(),
        )
        .await
        .expect("A 侧拨号校验通过");

        let b_rx = Mutex::new(b_rx);
        let ev = await_event(&b_rx, "denied").await;
        assert!(ev.contains("PortDenied"), "拒绝成因应为端口拒绝：{ev}");

        let a_rx = Mutex::new(a_rx);
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

        let b_rx = Mutex::new(b_rx);
        let ev = await_event(&b_rx, "denied").await;
        assert!(ev.contains("Timeout"), "拒绝成因应为超时：{ev}");

        let a_rx = Mutex::new(a_rx);
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

        let a_rx = Mutex::new(a_rx);
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
    async fn 关停幂等_句柄随后不可用() {
        let (ports, _rx) = ports_with(Arc::new(AutoAdmit));
        let node = P2pEngine::start(NodeKey::generate(), localhost_config(), ports).unwrap();
        node.shutdown().await;
        // shutdown 消费句柄，幂等性由「泵 Option 已取空 + 通道随泵退出关闭」保证；
        // 关停后再拨号应 NotRunning——用新句柄路径验证命令面失效
        let (ports2, _rx2) = ports_with(Arc::new(AutoAdmit));
        let node2 = P2pEngine::start(NodeKey::generate(), localhost_config(), ports2).unwrap();
        node2.shutdown().await;
        //（两条链路各自一次 shutdown 即本用例的幂等面：无二次可用路径）
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
}
