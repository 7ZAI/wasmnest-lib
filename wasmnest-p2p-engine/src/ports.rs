//! 宿主端口面：引擎实际消费的两个端口 + 事件出口词汇。
//!
//! 对齐 `wasmnest-discovery-engine` / `wasmnest-server-peer-net` 的窄端口先例：
//! 能力 crate 只声明**自己真正要用的**宿主能力，宿主按需实现并按端装配——
//! 本 crate 零内部依赖（不引 server-base 的端口 trait），端口词汇自持。
//!
//! | 端口 | 用途 | 宿主侧实现（P1 起） |
//! | --- | --- | --- |
//! | [`PeerAdmissionPort`] | 入站首连确认（可挂起等弹窗） | 信任列表查证 + UI 确认（拒绝/超时/放行） |
//! | [`P2pEventSink`] | 连接态事件出口（前端桥 / 日志） | 对接既有连接态前端事件与 `peer:*` 词汇 |

use std::net::SocketAddr;

use async_trait::async_trait;
use libp2p::PeerId;

use crate::identity_bridge::NodeId;

/// 入站准入端口：首连确认闸门的决策方
///
/// 引擎在**入站连接建立且身份验证通过后**调用本端口；端口实现查信任列表，
/// 已信 → 立即 `true`；未信 → 弹窗等用户应答（挂起本 future）。
/// 返回 `false` = 拒绝（双方不记信任）；超时由引擎侧结算（见 [`crate::admission`]），
/// 端口实现无需自管超时。信任条目的落库由宿主侧自理（引擎不持信任状态）。
#[async_trait]
pub trait PeerAdmissionPort: Send + Sync + 'static {
    /// `peer_id` 是 swarm 层标识（诊断用），**决策必须只依赖 `node_id`**
    /// （指纹即身份；PeerId 是同一公钥的另一派生，非独立身份源）。
    async fn confirm_inbound(&self, node_id: &NodeId, peer_id: &PeerId) -> bool;
}

/// 连接已可用（出站 = node_id 校验通过；入站 = 准入放行）
#[derive(Debug, Clone)]
pub struct PeerConnected {
    /// 对端 node_id（已验证）
    pub node_id: NodeId,
    /// 对端 PeerId
    pub peer_id: PeerId,
    /// true = 本端主动拨号（已按期望 node_id 校验）；false = 对端拨入（已过准入）
    pub outbound: bool,
    /// 对端地址（拨号 = 拨的地址；拨入 = 对端来源地址）
    pub remote_addr: SocketAddr,
}

/// 连接完全关闭（该对端已无在建连接）
#[derive(Debug, Clone)]
pub struct PeerDisconnected {
    /// 对端 node_id
    pub node_id: NodeId,
    /// 对端 PeerId
    pub peer_id: PeerId,
    /// 关闭时是否为本端主动（关停 / 断开命令 / 拒绝结算）
    pub by_local: bool,
}

/// 入站对端被拒绝（未进入可用态，连接已被引擎断开）
#[derive(Debug, Clone)]
pub struct PeerDenied {
    /// 对端 node_id（身份不支持时为 None——派生不出来才拒的）
    pub node_id: Option<NodeId>,
    /// 对端 PeerId
    pub peer_id: Option<PeerId>,
    /// 拒绝成因
    pub cause: DenyCause,
}

/// 拒绝成因（与 [`crate::admission::GateRequest::Denied`] 的 cause 同词汇）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyCause {
    /// 端口应答拒绝（宿主/用户明确说不）
    PortDenied,
    /// 确认超时（窗口见 [`crate::admission::AdmissionConfig`]）
    Timeout,
    /// 同一 node_id 已有在等的确认（弹窗风暴防护）
    DuplicatePending,
    /// pending 确认数达上限（资源保护）
    CapacityExceeded,
    /// 对端身份不支持（非 ed25519 / 哈希型 PeerId，node_id 派生不出来）
    UnsupportedIdentity,
}

/// 出站拨号失败（握手失败 / 校验不过 / 超时）
#[derive(Debug, Clone)]
pub struct DialFailed {
    /// 拨的地址
    pub addr: SocketAddr,
    /// 期望的 node_id（如有）
    pub expected_node_id: Option<NodeId>,
    /// 失败成因（人读文案）
    pub cause: String,
}

/// 引擎事件出口：连接态事件全部经此推送（同步、不回压——宿主实现自行缓冲/丢弃策略）
pub trait P2pEventSink: Send + Sync + 'static {
    /// 监听地址集合变化（快照全量）
    fn listening_changed(&self, addrs: Vec<SocketAddr>);
    /// 连接可用（见 [`PeerConnected`] 的两种触发时机）
    fn peer_connected(&self, ev: PeerConnected);
    /// 连接完全关闭
    fn peer_disconnected(&self, ev: PeerDisconnected);
    /// 入站拒绝（只会有入站方向）
    fn peer_denied(&self, ev: PeerDenied);
    /// 拨号失败（只会有出站方向）
    fn dial_failed(&self, ev: DialFailed);
}

/// 引擎端口聚合（字段即装配面）
pub struct P2pPorts {
    /// 入站准入决策方
    pub admission: std::sync::Arc<dyn PeerAdmissionPort>,
    /// 连接态事件出口
    pub events: std::sync::Arc<dyn P2pEventSink>,
}
