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
#[cfg(feature = "relay")]
use crate::ports::RelayStatusChanged;
use crate::ports::{
    DenyCause, DialFailed, P2pEventSink, P2pPorts, PeerConnected, PeerDenied, PeerDisconnected,
    TransportChanged,
};
use crate::relay::{relayed_dial_target, RelayStatus, Transport};
#[cfg(feature = "relay")]
use crate::relay::{retry_delay, RelayEndpoint, RelayState, RESERVATION_TIMEOUT};
#[cfg(feature = "relay")]
use libp2p::core::transport::ListenerId;

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

/// 多地址拨号结果：命中的候选地址与传输形态
#[derive(Debug, Clone)]
pub struct DialOutcome {
    /// 成功的候选地址（relayed 地址含 `/p2p-circuit`）
    pub addr: Multiaddr,
    /// 由地址判定的传输形态（宿主据此点亮「内网直连 / 外网中继」）
    pub transport: Transport,
}

/// 节点行为面：ping 保活 + 具名流协议协商（默认构建）
#[cfg(not(feature = "relay"))]
#[derive(NetworkBehaviour)]
pub(crate) struct NodeBehaviour {
    ping: ping::Behaviour,
    stream: libp2p_stream::Behaviour,
}

/// 节点行为面（`relay` feature）：额外挂 Circuit Relay v2 客户端
///
/// 为什么用两份定义而不是 `#[cfg]` 字段：`#[derive(NetworkBehaviour)]` 生成的
/// 事件枚举是行为面的公开投影，字段级 cfg 在不同宏版本行为不一致；两份定义让
/// 「开关 = 换一份装配」显性化，事件匹配处同样 cfg 分支，不存在半开状态。
#[cfg(feature = "relay")]
#[derive(NetworkBehaviour)]
pub(crate) struct NodeBehaviour {
    ping: ping::Behaviour,
    stream: libp2p_stream::Behaviour,
    relay_client: libp2p::relay::client::Behaviour,
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
        /// 经 relay 拨号时的 relay PeerId（其控制连接不登记为业务对端）
        infra_peer: Option<PeerId>,
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
    /// 建立 relay 预留（按给定端点顺序尝试；feature 关闭时显性失败）
    RelayReserve {
        addrs: Vec<Multiaddr>,
        reply: oneshot::Sender<Result<Multiaddr, P2pError>>,
    },
    /// 释放 relay 预留（幂等；返回是否命中在管预留）
    RelayRelease { reply: oneshot::Sender<bool> },
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
    /// relay 控制面状态快照（泵写、句柄读；`status()` 的数据面）
    relay_status: Arc<RwLock<RelayStatus>>,
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
        self.dial_with_timeout(addr, expected_node_id, DIAL_TIMEOUT)
            .await
    }

    /// [`Self::dial`] 的显式超时版本
    ///
    /// 多地址拨号（[`Self::dial_addrs`]）按候选给短窗口（LAN 2~3s，见设计 §4.9）；
    /// 超时结算与清理语义与 [`Self::dial`] 完全一致（清在飞登记，防迟到连接误命中）。
    pub async fn dial_with_timeout(
        &self,
        addr: Multiaddr,
        expected_node_id: NodeId,
        timeout: Duration,
    ) -> Result<(), P2pError> {
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
                infra_peer: crate::relay::relay_peer_of_dial_addr(&addr),
                addr: addr.clone(),
                expected: expected_node_id.clone(),
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        match tokio::time::timeout(timeout, rx).await {
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

    /// 多地址拨号：按调用方给定顺序逐个尝试，首个成功即返回
    ///
    /// 设计 §4.9 的拨号策略落在调用方（先 LAN、明确不在内网才 relay），引擎只保证
    /// **顺序 + 逐候选短超时 + 失败成因逐条可见**：
    ///
    /// - 顺序 = 入参顺序（不排序、不去重、不自动把 relay 提前）；
    /// - 每个候选按 `per_addr_timeout` 结算（LAN 建议 2~3s；relay 候选可给长一些）；
    /// - 某候选失败继续下一个；全部失败返回 [`P2pError::DialAllFailed`]（含逐候选成因）；
    /// - 经 relay 的候选先做形状校验（必须 `.../p2p-circuit/p2p/<target>`，且 target
    ///   与期望 node_id 一致），形状非法直接报错——不把「注定失败」的地址塞给 swarm。
    pub async fn dial_addrs(
        &self,
        addrs: &[Multiaddr],
        expected_node_id: NodeId,
        per_addr_timeout: Duration,
    ) -> Result<DialOutcome, P2pError> {
        if addrs.is_empty() {
            return Err(P2pError::Dial("候选地址为空".to_string()));
        }
        // 先整体校验经 relay 的候选形状：身份不匹配是配置错误，不该靠逐个拨号试出来
        for addr in addrs {
            if let Some(target) = relayed_dial_target(addr)? {
                verify_peer_identity(&target, &expected_node_id)?;
            }
        }
        let mut failures = Vec::new();
        for addr in addrs {
            match self
                .dial_with_timeout(addr.clone(), expected_node_id.clone(), per_addr_timeout)
                .await
            {
                Ok(()) => {
                    return Ok(DialOutcome {
                        transport: Transport::from_multiaddr(addr),
                        addr: addr.clone(),
                    });
                }
                Err(err) => {
                    tracing::debug!(%addr, error = %err, "候选地址拨号失败，尝试下一个");
                    failures.push(format!("{addr} => {err}"));
                }
            }
        }
        Err(P2pError::DialAllFailed {
            attempts: addrs.len(),
            detail: failures.join("；"),
        })
    }

    /// 建立 relay 预留（Circuit Relay v2 client）：`relay_addrs` 按顺序尝试
    ///
    /// - 地址必须已钉住 relay PeerId（见 [`crate::relay::RelayEndpoint::parse`]）；域名地址先用
    ///   [`crate::relay::resolve_relay_addr`] 解析成 IP；
    /// - 成功后返回实际预留的 relay 端点（含 `/p2p/<relay>`，不含 `/p2p-circuit`）；
    /// - 失败 / relay 重启 → 引擎按指数退避（1s → 60s 封顶）自动重连，状态经
    ///   [`P2pEventSink::relay_status_changed`] 与 [`Self::relay_status`] 可见；
    /// - 幂等：重复调用会以新列表替换旧配置（旧预留先释放）；
    /// - **reference counting 在宿主隧道管理器**（T06）：引擎只提供建立/释放原语。
    pub async fn reserve_relay(&self, relay_addrs: Vec<Multiaddr>) -> Result<Multiaddr, P2pError> {
        if relay_addrs.is_empty() {
            return Err(P2pError::Relay("relay 地址列表为空".to_string()));
        }
        let (tx, rx) = oneshot::channel();
        self.inner
            .cmd
            .send(EngineCmd::RelayReserve {
                addrs: relay_addrs,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        rx.await.map_err(|_| P2pError::NotRunning)?
    }

    /// 释放 relay 预留（幂等；返回是否命中在管预留）
    pub async fn release_relay(&self) -> Result<bool, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .cmd
            .send(EngineCmd::RelayRelease { reply: tx })
            .await
            .map_err(|_| P2pError::NotRunning)?;
        rx.await.map_err(|_| P2pError::NotRunning)
    }

    /// relay 控制面状态快照（未启用时 `state = Idle`）
    pub fn relay_status(&self) -> RelayStatus {
        self.inner
            .relay_status
            .read()
            .expect("relay 状态快照中毒")
            .clone()
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

        let base_builder = libp2p::SwarmBuilder::with_existing_identity(key.into_keypair())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| P2pError::Build(format!("TCP/noise/yamux 传输栈装配失败：{e}")))?;

        // relay 客户端 = 行为面 + 一条组合传输（`OrTransport`：circuit 地址走 relay，
        // 其余走 TCP）。`with_relay_client` 由 libp2p 装配这两半，避免手写升级栈。
        #[cfg(feature = "relay")]
        let mut swarm = base_builder
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| P2pError::Build(format!("relay 客户端传输装配失败：{e}")))?
            .with_behaviour(|_key, relay_client| NodeBehaviour {
                ping: ping::Behaviour::new(ping::Config::new()),
                stream: stream_behaviour,
                relay_client,
            })
            .map_err(|e| P2pError::Build(format!("行为面装配失败：{e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
            .build();

        #[cfg(not(feature = "relay"))]
        let mut swarm = base_builder
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
        let relay_status: Arc<RwLock<RelayStatus>> = Arc::new(RwLock::new(RelayStatus::default()));

        let pump = tokio::spawn(run_pump(
            swarm,
            cmd_rx,
            settle_rx,
            settle_tx,
            AdmissionGate::new(config.admission),
            ports,
            Arc::clone(&listen_addrs),
            Arc::clone(&links),
            Arc::clone(&relay_status),
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
                relay_status,
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
    /// 传输形态（lan-direct / wan-relay）
    transport: Transport,
}

/// 拨号在飞登记（按所拨 multiaddr 键控：established 事件回带同一地址）
struct PendingDial {
    expected: NodeId,
    reply: oneshot::Sender<Result<(), P2pError>>,
}

// ==================== relay 预留运行时（feature = relay） ====================

/// relay 预留运行时：端点轮换、请求硬超时、指数退避、状态发布
///
/// 一个节点同时只维护**一个**预留（设计 §4.8：reservation 由宿主隧道管理器单一
/// 引用计数所有；引擎不并行为多个 relay 建预留）。多端点语义是「按顺序 failover」，
/// 不是「全建」——避免同一节点在多 relay 上散落孤儿预留。
#[cfg(feature = "relay")]
#[derive(Default)]
struct RelayRuntime {
    /// 已启用的端点（按调用方顺序轮换）
    endpoints: Vec<RelayEndpoint>,
    /// 当前尝试的端点下标
    current: usize,
    /// 连续失败次数（退避指数）
    attempt: u32,
    /// 当前 circuit 监听（预留句柄）
    listener: Option<ListenerId>,
    /// 对外状态
    state: RelayState,
    /// 首次预留的回执（首个失败即结算为 Err；后台继续退避重试）
    pending_reply: Option<oneshot::Sender<Result<Multiaddr, P2pError>>>,
    /// 本次预留请求起始时刻（硬超时判据）
    waiting_since: Option<Instant>,
    /// 下次重试时刻
    next_retry: Option<Instant>,
    /// 最近一次失败原因（人读）
    last_error: String,
}

#[cfg(feature = "relay")]
impl RelayRuntime {
    /// 当前端点基础地址（不含 `/p2p-circuit`）
    fn addr(&self) -> Option<Multiaddr> {
        self.endpoints.get(self.current).map(|e| e.base().clone())
    }

    /// 发布状态快照 + 推事件（唯一写入口，保证两者一致）
    fn publish(&self, events: &Arc<dyn P2pEventSink>, status: &Arc<RwLock<RelayStatus>>) {
        let snapshot = RelayStatus {
            state: self.state,
            relay_addr: self.addr(),
            detail: self.last_error.clone(),
        };
        *status.write().expect("relay 状态快照中毒") = snapshot.clone();
        events.relay_status_changed(RelayStatusChanged {
            state: snapshot.state,
            relay_addr: snapshot.relay_addr,
            detail: snapshot.detail,
        });
    }

    /// 校验端点列表（形状 / PeerId 钉住）；纯地址面，失败不改变运行时状态
    fn parse_endpoints(addrs: &[Multiaddr]) -> Result<Vec<RelayEndpoint>, P2pError> {
        addrs
            .iter()
            .map(|addr| RelayEndpoint::parse(addr, None))
            .collect()
    }

    /// 启用/替换 relay 端点配置（重复调用 = 先释放旧预留再按新列表建）
    ///
    /// 入参已过 [`Self::parse_endpoints`] 校验，这里只做接管与首轮尝试。
    fn enable(
        &mut self,
        endpoints: Vec<RelayEndpoint>,
        reply: oneshot::Sender<Result<Multiaddr, P2pError>>,
        swarm: &mut Swarm<NodeBehaviour>,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) {
        let _ = self.release(swarm, events, status);
        self.endpoints = endpoints;
        self.current = 0;
        self.attempt = 0;
        self.state = RelayState::Connecting;
        self.last_error.clear();
        self.pending_reply = Some(reply);
        self.waiting_since = None;
        self.next_retry = None;
        self.start_attempt(swarm, events, status);
    }

    /// 对当前端点发起预留（circuit 监听）；失败即轮换到下一个端点并排退避
    fn start_attempt(
        &mut self,
        swarm: &mut Swarm<NodeBehaviour>,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) {
        let Some(endpoint) = self.endpoints.get(self.current).cloned() else {
            self.fail(swarm, "没有可用的 relay 端点".to_string(), events, status);
            return;
        };
        let addr = endpoint.reservation_addr();
        match swarm.listen_on(addr.clone()) {
            Ok(listener) => {
                self.listener = Some(listener);
                self.state = RelayState::Connecting;
                self.waiting_since = Some(Instant::now());
                self.next_retry = None;
                self.last_error.clear();
                tracing::info!(
                    relay = %endpoint.peer_id(),
                    %addr,
                    "relay 预留请求已发出（等待 ReservationReqAccepted）"
                );
                self.publish(events, status);
            }
            Err(e) => {
                self.fail(
                    swarm,
                    format!("circuit 监听失败（{addr}）：{e}"),
                    events,
                    status,
                );
            }
        }
    }

    /// 结算一次失败：撤监听、轮换端点、排指数退避
    fn fail(
        &mut self,
        swarm: &mut Swarm<NodeBehaviour>,
        cause: String,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) {
        if let Some(listener) = self.listener.take() {
            let _ = swarm.remove_listener(listener);
        }
        self.waiting_since = None;
        let delay = retry_delay(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        if !self.endpoints.is_empty() {
            self.current = (self.current + 1) % self.endpoints.len();
        }
        self.next_retry = Some(Instant::now() + delay);
        self.state = RelayState::Lost;
        self.last_error = format!("{cause}（{delay:?} 后重试）");
        tracing::warn!(%cause, retry_in = ?delay, "relay 预留失败，进入退避重试");
        // 首次调用方拿到显性失败；后台重试继续（状态经 relay_status 可见）
        if let Some(reply) = self.pending_reply.take() {
            let _ = reply.send(Err(P2pError::Relay(cause)));
        }
        self.publish(events, status);
    }

    /// 预留被 relay 接受（`ReservationReqAccepted`；renewal 也走这里）
    fn on_accepted(
        &mut self,
        relay_peer: PeerId,
        renewal: bool,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) {
        let Some(endpoint) = self.endpoints.get(self.current).cloned() else {
            return;
        };
        if endpoint.peer_id() != relay_peer {
            // 钉住校验：地址里声明的 relay 与实际接受预留的 relay 必须是同一身份
            tracing::warn!(
                expected = %endpoint.peer_id(),
                actual = %relay_peer,
                "relay 预留被非预期 PeerId 接受，忽略（钉住校验）"
            );
            return;
        }
        self.state = RelayState::Reserved;
        self.attempt = 0;
        self.waiting_since = None;
        self.next_retry = None;
        self.last_error.clear();
        tracing::info!(
            relay = %relay_peer,
            renewal,
            addr = %endpoint.base(),
            "relay 预留已建立"
        );
        if let Some(reply) = self.pending_reply.take() {
            let _ = reply.send(Ok(endpoint.base().clone()));
        }
        self.publish(events, status);
    }

    /// 释放预留（幂等）；返回是否命中在管预留或非 Idle 状态
    fn release(
        &mut self,
        swarm: &mut Swarm<NodeBehaviour>,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) -> bool {
        let had_listener = self.listener.take().is_some_and(|listener| {
            let _ = swarm.remove_listener(listener);
            true
        });
        let was_active = had_listener || self.state != RelayState::Idle;
        if let Some(reply) = self.pending_reply.take() {
            let _ = reply.send(Err(P2pError::Relay("预留已取消".to_string())));
        }
        self.endpoints.clear();
        self.current = 0;
        self.attempt = 0;
        self.state = RelayState::Idle;
        self.waiting_since = None;
        self.next_retry = None;
        self.last_error.clear();
        if was_active {
            tracing::info!("relay 预留已释放");
            self.publish(events, status);
        }
        was_active
    }

    /// 定时驱动：请求硬超时 / 退避到点重试
    fn tick(
        &mut self,
        swarm: &mut Swarm<NodeBehaviour>,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) {
        match self.state {
            RelayState::Connecting => {
                if self
                    .waiting_since
                    .is_some_and(|since| since.elapsed() >= RESERVATION_TIMEOUT)
                {
                    let cause = format!("relay 预留请求超时（{}s）", RESERVATION_TIMEOUT.as_secs());
                    self.fail(swarm, cause, events, status);
                }
            }
            RelayState::Lost => {
                if self.next_retry.is_some_and(|at| Instant::now() >= at) {
                    self.state = RelayState::Connecting;
                    self.start_attempt(swarm, events, status);
                }
            }
            RelayState::Idle | RelayState::Reserved => {}
        }
    }

    /// 消费 relay 相关的 swarm 事件（其余事件由主处理器兜底）
    fn on_swarm_event(
        &mut self,
        ev: &SwarmEvent<NodeBehaviourEvent>,
        swarm: &mut Swarm<NodeBehaviour>,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) {
        match ev {
            SwarmEvent::Behaviour(NodeBehaviourEvent::RelayClient(
                libp2p::relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    ..
                },
            )) => {
                self.on_accepted(*relay_peer_id, *renewal, events, status);
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } if Some(*listener_id) == self.listener => {
                let cause = format!("relay circuit 监听关闭：{reason:?}");
                self.on_lost(cause, swarm, events, status);
            }
            SwarmEvent::ListenerError { listener_id, error }
                if Some(*listener_id) == self.listener =>
            {
                let cause = format!("relay circuit 监听出错：{error}");
                self.on_lost(cause, swarm, events, status);
            }
            // relay 连接断开时，relay client 把已确认的 circuit 地址标记为过期
            // （`ToSwarm::ExternalAddrExpired`）——这是「预留丢失」的权威信号。
            SwarmEvent::ExternalAddrExpired { address, .. }
                if Transport::from_multiaddr(address) == Transport::WanRelay
                    && self.state == RelayState::Reserved =>
            {
                let cause = format!("relay circuit 地址过期（{address}）");
                self.on_lost(cause, swarm, events, status);
            }
            _ => {}
        }
    }

    /// 预留丢失（listener 被关 / listener 出错）：进入退避
    fn on_lost(
        &mut self,
        cause: String,
        swarm: &mut Swarm<NodeBehaviour>,
        events: &Arc<dyn P2pEventSink>,
        status: &Arc<RwLock<RelayStatus>>,
    ) {
        if self.state == RelayState::Idle {
            return;
        }
        self.fail(swarm, cause, events, status);
    }
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
    // relay feature 关闭时该快照没有写入方（始终 Idle），参数保留以稳定装配面
    #[allow(unused_variables)] relay_status: Arc<RwLock<RelayStatus>>,
    admit_on_connect: bool,
) {
    let mut conns: HashMap<PeerId, ConnState> = HashMap::new();
    let mut pending_dials: HashMap<Multiaddr, PendingDial> = HashMap::new();
    // relay 是基础设施，不是业务对端：经 relay 拨号时其控制连接不登记链路、
    // 不发 peer_connected（宿主设备列表不应出现 relay）。
    let mut infra_peers: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
    #[cfg(feature = "relay")]
    let mut relay = RelayRuntime::default();
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
                Some(EngineCmd::RelayReserve { addrs, reply }) => {
                    #[cfg(feature = "relay")]
                    {
                        match RelayRuntime::parse_endpoints(&addrs) {
                            Ok(endpoints) => {
                                infra_peers.extend(endpoints.iter().map(|e| e.peer_id()));
                                relay.enable(
                                    endpoints,
                                    reply,
                                    &mut swarm,
                                    &ports.events,
                                    &relay_status,
                                );
                            }
                            Err(err) => {
                                // 地址面错误（形状 / 钉住）不进入退避，直接回给调用方
                                tracing::warn!(error = %err, "relay 端点配置被拒绝");
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                    #[cfg(not(feature = "relay"))]
                    {
                        let _ = addrs;
                        let _ = reply.send(Err(P2pError::RelayDisabled));
                    }
                }
                Some(EngineCmd::RelayRelease { reply }) => {
                    #[cfg(feature = "relay")]
                    {
                        let hit = relay.release(&mut swarm, &ports.events, &relay_status);
                        let _ = reply.send(hit);
                    }
                    #[cfg(not(feature = "relay"))]
                    {
                        let _ = reply.send(false);
                    }
                }
                Some(EngineCmd::Dial { addr, expected, infra_peer, reply }) => {
                    if let Some(peer) = infra_peer {
                        infra_peers.insert(peer);
                    }
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
                // relay 退避重试 / 预留硬超时共用同一条 500ms 心跳
                #[cfg(feature = "relay")]
                relay.tick(&mut swarm, &ports.events, &relay_status);
            }

            ev = swarm.select_next_some() => {
                #[cfg(feature = "relay")]
                relay.on_swarm_event(&ev, &mut swarm, &ports.events, &relay_status);
                handle_swarm_event(
                    &mut swarm,
                    &mut conns,
                    &mut pending_dials,
                    &gate,
                    &settle_tx,
                    &ports,
                    &listen_addrs,
                    &links,
                    &infra_peers,
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
    // 基础设施 PeerId（relay）：其控制连接不登记为业务对端
    infra_peers: &std::collections::HashSet<PeerId>,
    admit_on_connect: bool,
    ev: SwarmEvent<NodeBehaviourEvent>,
) {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } => {
            // circuit 地址不是本机 socket 监听面（IP/TCP 属于 relay），relay 状态
            // 由 RelayRuntime 按 ReservationReqAccepted 维护——不混进 listen_addresses。
            if Transport::from_multiaddr(&address) == Transport::WanRelay {
                return;
            }
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
            if Transport::from_multiaddr(&address) == Transport::WanRelay {
                return;
            }
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
                // relay 控制连接是基础设施连接：不登记链路、不发 peer_connected，
                // 否则宿主设备列表会把 relay 当业务对端（设计 §4.1「relay 不是信任点」）。
                if infra_peers.contains(&peer_id) {
                    tracing::debug!(%peer_id, "relay 控制连接已建立（不登记为业务对端）");
                    return;
                }
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
                let transport = Transport::from_multiaddr(&address);
                ports.events.transport_changed(TransportChanged {
                    node_id: actual.clone(),
                    transport,
                    address: address.clone(),
                });

                // 同 PeerId 已有连接：只累加计数；出站方向把 pending 入站链路提升
                if let Some(st) = conns.get_mut(&peer_id) {
                    st.connections += 1;
                    st.outbound = true;
                    st.admitted = true;
                    st.denied = false;
                    st.denied_at = None;
                    st.remote_addr = remote_addr;
                    st.transport = transport;
                    links.write().expect("链路登记表中毒").insert(PeerLink {
                        node_id: actual.clone(),
                        peer_id,
                        remote_addr,
                        outbound: true,
                        admission: LinkAdmission::Admitted,
                        connections: 1,
                        transport,
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
                            transport,
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
                                transport,
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
                let transport = Transport::from_multiaddr(&send_back_addr);
                ports.events.transport_changed(TransportChanged {
                    node_id: node_id.clone(),
                    transport,
                    address: send_back_addr.clone(),
                });

                // 同 PeerId 已有连接：只累加计数；已准入则不再走闸门
                if let Some(st) = conns.get_mut(&peer_id) {
                    st.connections += 1;
                    if st.remote_addr.port() == 0 {
                        st.remote_addr = remote_addr;
                    }
                    st.transport = transport;
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
                        transport,
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
                        transport,
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
        transport: state.transport,
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
///
/// 公开给上层 peer-net：多地址拨号成功后要把命中地址回填到 `Connection` 的
/// 展示/日志字段（relay 地址取的是中继端点，不是对端监听地址）。
pub fn multiaddr_to_socket_addr(ma: &Multiaddr) -> Option<SocketAddr> {
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
        fn transport_changed(&self, ev: TransportChanged) {
            let _ = self.tx.send(format!(
                "transport node={} kind={} addr={}",
                ev.node_id,
                ev.transport.as_str(),
                ev.address
            ));
        }
        fn relay_status_changed(&self, ev: crate::ports::RelayStatusChanged) {
            let _ = self.tx.send(format!("relay state={}", ev.state.as_str()));
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

    // ==================== 多地址拨号（T02） ====================

    /// 取一个「刚释放」的本地端口作为死地址（连接立即 ECONNREFUSED，不占测试窗口）
    fn free_local_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("取空闲端口");
        listener.local_addr().expect("本地地址").port()
    }

    #[tokio::test]
    async fn 多地址拨号_按入参顺序回退_并上报传输形态() {
        let (a_ports, _a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        let a_addr = wait_listen(&a).await;

        let (b_ports, b_rx) = ports_with(Arc::new(AutoAdmit));
        let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();

        let dead = listen_multiaddr(IpAddr::from([127, 0, 0, 1]), free_local_port());
        let live = listen_multiaddr(IpAddr::from([127, 0, 0, 1]), a_addr.port());

        let outcome = b
            .dial_addrs(
                &[dead, live],
                a.node_id().clone(),
                Duration::from_millis(800),
            )
            .await
            .expect("首个候选失败后应回退到第二个");
        assert_eq!(outcome.transport, Transport::LanDirect);
        assert_eq!(
            outcome.addr,
            listen_multiaddr(IpAddr::from([127, 0, 0, 1]), a_addr.port())
        );

        let b_rx = AsyncMutex::new(b_rx);
        // 注意 needle 不能用裸 "transport"：dial_failed 的成因文案里也含该词
        let ev = await_event(&b_rx, "kind=lan-direct").await;
        assert!(
            ev.contains("kind=lan-direct"),
            "直连应上报 lan-direct：{ev}"
        );

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn 多地址拨号_候选全失败_逐条成因显性返回() {
        let (a_ports, _a_rx) = ports_with(Arc::new(AutoAdmit));
        let a = P2pEngine::start(NodeKey::generate(), localhost_config(), a_ports).unwrap();
        let dead1 = listen_multiaddr(IpAddr::from([127, 0, 0, 1]), free_local_port());
        let dead2 = listen_multiaddr(IpAddr::from([127, 0, 0, 1]), free_local_port());

        let (b_ports, _b_rx) = ports_with(Arc::new(AutoAdmit));
        let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();
        let err = b
            .dial_addrs(
                &[dead1, dead2],
                a.node_id().clone(),
                Duration::from_millis(500),
            )
            .await
            .expect_err("全部候选不可达应显性失败");
        match err {
            P2pError::DialAllFailed { attempts, detail } => {
                assert_eq!(attempts, 2);
                assert!(detail.contains("=>"), "应逐条给成因：{detail}");
            }
            other => panic!("应为 DialAllFailed：{other:?}"),
        }

        a.shutdown().await;
        b.shutdown().await;
    }

    #[cfg(not(feature = "relay"))]
    #[tokio::test]
    async fn relay_feature_未启用时_预留显性失败() {
        let (ports, _rx) = ports_with(Arc::new(AutoAdmit));
        let node = P2pEngine::start(NodeKey::generate(), localhost_config(), ports).unwrap();
        let endpoint: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", PeerId::random())
            .parse()
            .unwrap();
        let err = node
            .reserve_relay(vec![endpoint])
            .await
            .expect_err("未编译 relay feature 必须显性失败");
        assert!(
            matches!(err, P2pError::RelayDisabled),
            "应为 RelayDisabled：{err:?}"
        );
        assert_eq!(node.relay_status().state, crate::relay::RelayState::Idle);
        node.shutdown().await;
    }

    // ==================== relay 端到端（T01/T02，feature = relay） ====================

    #[cfg(feature = "relay")]
    mod relay_flow {
        use super::*;
        use crate::relay::{RelayEndpoint, RelayState};
        use crate::stream_proto::SESSION;
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
        use futures_util::StreamExt;
        use libp2p::identity::Keypair;
        use libp2p::relay;
        use libp2p::SwarmBuilder;
        use tokio::sync::oneshot;

        /// 测试用 relay v2 服务端（固定身份/端口可重启，验证预留自动恢复）
        struct RelayServer {
            addr: Multiaddr,
            peer_id: PeerId,
            stop: Option<oneshot::Sender<()>>,
            task: Option<tokio::task::JoinHandle<()>>,
        }

        impl RelayServer {
            async fn start(key: Keypair, port: u16) -> Self {
                let peer_id = key.public().to_peer_id();
                // 默认 128KiB / 2min 会把 1MiB 与 100MiB 用例掐断（T01 吞吐验收）
                let config = relay::Config {
                    max_circuit_bytes: 256 * 1024 * 1024,
                    max_circuit_duration: Duration::from_secs(600),
                    reservation_duration: Duration::from_secs(600),
                    ..Default::default()
                };
                let mut swarm = SwarmBuilder::with_existing_identity(key)
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        noise::Config::new,
                        yamux::Config::default,
                    )
                    .expect("relay TCP 传输")
                    .with_behaviour(|_| {
                        let mut behaviour = relay::Behaviour::new(peer_id, config);
                        // 默认 Status::Disable 不对外通告 HOP 协议（客户端会得到
                        // Reservation(Unsupported)）；测试 relay 固定开启，等价于
                        // T13 部署里的显式启用。
                        behaviour.set_status(Some(relay::Status::Enable));
                        behaviour
                    })
                    .expect("relay 服务端行为")
                    .build();
                swarm
                    .listen_on(
                        format!("/ip4/127.0.0.1/tcp/{port}")
                            .parse()
                            .expect("relay 监听地址"),
                    )
                    .expect("relay 监听");
                let addr = loop {
                    if let SwarmEvent::NewListenAddr { address, .. } =
                        swarm.select_next_some().await
                    {
                        break address;
                    }
                };
                // reservation 响应必须携带 relay 的对外地址（否则客户端收到
                // `NoAddressesInReservation`）——测试里把监听地址声明为 external。
                swarm.add_external_address(addr.clone());
                let (stop, mut rx) = oneshot::channel();
                let task = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = &mut rx => break,
                            _ = swarm.select_next_some() => {}
                        }
                    }
                });
                Self {
                    addr,
                    peer_id,
                    stop: Some(stop),
                    task: Some(task),
                }
            }

            fn endpoint(&self) -> Multiaddr {
                self.addr.clone().with(Protocol::P2p(self.peer_id))
            }

            async fn shutdown(mut self) {
                if let Some(stop) = self.stop.take() {
                    let _ = stop.send(());
                }
                if let Some(task) = self.task.take() {
                    let _ = task.await;
                }
            }
        }

        async fn wait_relay_state(node: &RunningNode, want: RelayState, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if node.relay_status().state == want {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            false
        }

        /// T01 核心用例：A 预留 → B 经 relay 拨 A → `/wasmnest/session/1` 往返 1MiB
        #[tokio::test]
        async fn 经_relay_预留_拨号_并往返_1mib_具名流() {
            let relay = RelayServer::start(Keypair::generate_ed25519(), 0).await;
            let relay_addr = relay.endpoint();

            // A：被访问方（预留 + 接收 SESSION 流）
            let (a_ports, a_rx) = ports_with(Arc::new(AutoAdmit));
            let (a, mut streams) = P2pEngine::start_with_protocols(
                NodeKey::generate(),
                localhost_config(),
                a_ports,
                &[SESSION],
            )
            .unwrap();
            let reserved = a
                .reserve_relay(vec![relay_addr.clone()])
                .await
                .expect("relay 预留应被接受");
            assert_eq!(reserved, relay_addr, "预留成功应回带钉住的 relay 端点");
            assert_eq!(a.relay_status().state, RelayState::Reserved);

            // B：拨号方（不预留；经 relay 拨 A）
            let (b_ports, b_rx) = ports_with(Arc::new(AutoAdmit));
            let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();

            let relay_ep = RelayEndpoint::parse(&relay_addr, None).expect("relay 端点");
            let dial_addr = relay_ep.dial_addr(a.peer_id());
            let outcome = b
                .dial_addrs(&[dial_addr], a.node_id().clone(), Duration::from_secs(20))
                .await
                .expect("经 relay 拨号应成功");
            assert_eq!(
                outcome.transport,
                Transport::WanRelay,
                "含 /p2p-circuit 的地址应判为 wan-relay"
            );

            // 1MiB 往返：payload 用非零变化字节，能发现截断/乱序
            let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
            let expect = payload.clone();
            let mut incoming = streams.remove(SESSION).expect("SESSION 接收器");
            let server = tokio::spawn(async move {
                let mut inbound = incoming.next().await.expect("relay 上应收到业务流");
                let mut buf = vec![0u8; expect.len()];
                inbound.stream.read_exact(&mut buf).await.expect("读 1MiB");
                assert_eq!(buf, expect, "relay 上的 1MiB 载荷应逐字一致");
                inbound.stream.write_all(&buf).await.expect("回写 1MiB");
                inbound.stream.flush().await.expect("flush");
            });

            let mut stream = b
                .open_stream(&a.node_id().clone(), SESSION)
                .await
                .expect("经 relay 开流");
            stream.write_all(&payload).await.expect("写 1MiB");
            stream.flush().await.expect("flush");
            let mut buf = vec![0u8; payload.len()];
            stream.read_exact(&mut buf).await.expect("读回 1MiB");
            assert_eq!(buf, payload, "往返载荷应逐字一致");

            server.await.expect("server task");

            // 事件面：A 侧 relay-reserved；B 侧 wan-relay
            let a_rx = AsyncMutex::new(a_rx);
            let ev = await_event(&a_rx, "relay state=relay-reserved").await;
            assert!(ev.contains("relay-reserved"), "{ev}");
            let b_rx = AsyncMutex::new(b_rx);
            let ev = await_event(&b_rx, "transport").await;
            assert!(
                ev.contains("kind=wan-relay"),
                "relay 拨号应上报 wan-relay：{ev}"
            );

            a.shutdown().await;
            b.shutdown().await;
            relay.shutdown().await;
        }

        #[tokio::test]
        async fn relay_预留_释放幂等_状态回到_idle() {
            let relay = RelayServer::start(Keypair::generate_ed25519(), 0).await;
            let (ports, _rx) = ports_with(Arc::new(AutoAdmit));
            let a = P2pEngine::start(NodeKey::generate(), localhost_config(), ports).unwrap();
            a.reserve_relay(vec![relay.endpoint()]).await.expect("预留");
            assert!(a.release_relay().await.expect("释放命中"));
            assert_eq!(a.relay_status().state, RelayState::Idle);
            assert!(!a.release_relay().await.expect("重复释放不命中"));
            a.shutdown().await;
            relay.shutdown().await;
        }

        #[tokio::test]
        async fn relay_端点地址非法_显性拒绝_不进退避() {
            let (ports, _rx) = ports_with(Arc::new(AutoAdmit));
            let a = P2pEngine::start(NodeKey::generate(), localhost_config(), ports).unwrap();
            let missing_peer: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
            let err = a
                .reserve_relay(vec![missing_peer])
                .await
                .expect_err("缺 /p2p/<relay> 应拒绝");
            assert!(
                matches!(err, P2pError::Relay(_)),
                "应为 Relay 错误：{err:?}"
            );
            assert_eq!(a.relay_status().state, RelayState::Idle);
            a.shutdown().await;
        }

        /// T01 PoC 指标（手动跑）：
        /// `cargo test --features relay relay_poc_metrics -- --ignored --nocapture`
        ///
        /// 记录：预留建立耗时 / 环回 relay RTT / 1MiB 与 100MiB 吞吐。
        /// **这是 loopback 数据**，只能作实现正确性与数量级参考；真机跨网数据
        /// 必须按 T10 在「手机蜂窝 ↔ 家庭宽带」上另测（本机无法代替）。
        #[tokio::test]
        #[ignore = "PoC 指标测量，手动运行（--ignored --nocapture）"]
        async fn relay_poc_metrics() {
            let relay = RelayServer::start(Keypair::generate_ed25519(), 0).await;
            let relay_addr = relay.endpoint();

            let (a_ports, _a_rx) = ports_with(Arc::new(AutoAdmit));
            let (a, mut streams) = P2pEngine::start_with_protocols(
                NodeKey::generate(),
                localhost_config(),
                a_ports,
                &[SESSION],
            )
            .unwrap();
            let t0 = Instant::now();
            a.reserve_relay(vec![relay_addr.clone()])
                .await
                .expect("relay 预留");
            println!("[poc] reservation_ms={}", t0.elapsed().as_millis());

            let (b_ports, _b_rx) = ports_with(Arc::new(AutoAdmit));
            let b = P2pEngine::start(NodeKey::generate(), localhost_config(), b_ports).unwrap();
            let relay_ep = RelayEndpoint::parse(&relay_addr, None).unwrap();
            let t_dial = Instant::now();
            b.dial_addrs(
                &[relay_ep.dial_addr(a.peer_id())],
                a.node_id().clone(),
                Duration::from_secs(20),
            )
            .await
            .expect("relay 拨号");
            println!("[poc] dial_via_relay_ms={}", t_dial.elapsed().as_millis());

            let mut incoming = streams.remove(SESSION).expect("SESSION 接收器");
            let echo = tokio::spawn(async move {
                while let Some(mut inbound) = incoming.next().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        loop {
                            match inbound.stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if inbound.stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                    let _ = inbound.stream.flush().await;
                                }
                            }
                        }
                    });
                }
            });

            // RTT：1KiB 往返 10 次取均值。**读写必须并发**：单流 echo 下
            // 「写完再读」会被 Yamux 流控卡死在接收窗口（大载荷死锁）。
            let stream = b.open_stream(&a.node_id().clone(), SESSION).await.unwrap();
            let (mut reader, mut writer) = stream.split();
            let mut rtt_total = Duration::ZERO;
            for _ in 0..10 {
                let t = Instant::now();
                writer.write_all(&[7u8; 1024]).await.unwrap();
                writer.flush().await.unwrap();
                let mut buf = [0u8; 1024];
                reader.read_exact(&mut buf).await.unwrap();
                rtt_total += t.elapsed();
            }
            println!(
                "[poc] rtt_1kib_avg_ms={:.2}",
                rtt_total.as_secs_f64() * 1000.0 / 10.0
            );

            for mib in [1usize, 100] {
                let payload = vec![0xA5u8; mib * 1024 * 1024];
                let mut received = vec![0u8; payload.len()];
                let t = Instant::now();
                let write = async {
                    writer.write_all(&payload).await.unwrap();
                    writer.flush().await.unwrap();
                };
                let read = async {
                    reader.read_exact(&mut received).await.unwrap();
                };
                tokio::join!(write, read);
                let secs = t.elapsed().as_secs_f64();
                assert_eq!(received, payload, "{mib}MiB 往返应逐字一致");
                println!(
                    "[poc] echo_{mib}mib_secs={secs:.3} throughput_mib_s={:.1}",
                    (mib as f64) / secs
                );
            }

            echo.abort();
            a.shutdown().await;
            b.shutdown().await;
            relay.shutdown().await;
        }

        /// T02：relay 重启（同身份同端口）后，引擎退避重试应自动恢复预留
        #[tokio::test]
        async fn relay_重启后自动恢复预留() {
            let key = Keypair::generate_ed25519();
            let port = free_local_port();
            let relay = RelayServer::start(key.clone(), port).await;
            let endpoint = relay.endpoint();

            let (ports, _rx) = ports_with(Arc::new(AutoAdmit));
            let a = P2pEngine::start(NodeKey::generate(), localhost_config(), ports).unwrap();
            a.reserve_relay(vec![endpoint]).await.expect("首次预留");
            assert_eq!(a.relay_status().state, RelayState::Reserved);

            // relay 下线：relay client 把 circuit 地址标记过期 → 引擎应转 Lost 并重试
            relay.shutdown().await;
            assert!(
                wait_relay_state(&a, RelayState::Lost, Duration::from_secs(10)).await,
                "relay 下线后应进入 Lost（当前 {:?}）",
                a.relay_status().state
            );

            // 同身份同端口回来：退避重试应重建预留
            let relay2 = RelayServer::start(key, port).await;
            assert!(
                wait_relay_state(&a, RelayState::Reserved, Duration::from_secs(30)).await,
                "relay 恢复后应自动重建预留（当前 {:?} / {}）",
                a.relay_status().state,
                a.relay_status().detail
            );

            a.shutdown().await;
            relay2.shutdown().await;
        }
    }
}
