//! 链路登记与具名流接入：P1 传输栈换轨后的「连接 → 流」公共面。
//!
//! ## 职责
//!
//! - [`PeerLink`]：一条已建立连接的对端快照（node_id / PeerId / 地址 / 方向 /
//!   准入状态 / 连接计数）。引擎事件泵是唯一写者；流消费方只读。
//! - [`LinkAdmission`]：入站准入的对外状态（Pending / Admitted / Denied）。
//!   信任状态流据此决定发 Pending 还是终态帧；业务流只接受 Admitted。
//! - [`IncomingStreams`]：按协议名登记的入站流接收器。业务协议默认只放行
//!   Admitted 对端；信任状态协议允许 Pending（闸门放行前唯一允许的协议）。
//!
//! ## 为什么把筛选放在引擎内
//!
//! 「闸门放行前零上层协议流量」是 P0 起就钉死的不变量。若把筛选留给消费方，
//! 每个消费方都要重复实现准入检查，漏一处就是把未信任对端放进业务协议。
//! 本模块让协议注册时声明 `require_admitted`，由引擎统一拦截。
//!
//! ## 连接计数
//!
//! libp2p 允许同一 PeerId 同时存在多条连接（双方同时拨号、或应用重拨）。
//! 登记按 `connections` 计数：只有最后一条连接关闭才摘除链路、发断开事件；
//! 中途建立的新连接只累加，不重复发 `peer_connected`（事件幂等由引擎保证）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use libp2p::swarm::Stream;
use libp2p::PeerId;
use tokio::sync::watch;

use crate::identity_bridge::NodeId;
use crate::relay::Transport;

/// 入站准入状态（对外只读词汇）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAdmission {
    /// 已进入首连确认闸门，等待端口应答或超时
    Pending,
    /// 放行：业务流可用
    Admitted,
    /// 拒绝：业务流一律拒绝，等待对端关闭或宽限回收
    Denied,
}

/// 一条链路的只读快照
#[derive(Debug, Clone)]
pub struct PeerLink {
    /// 对端 node_id（已验证）
    pub node_id: NodeId,
    /// 对端 PeerId
    pub peer_id: PeerId,
    /// 对端地址（出站 = 拨号地址；入站 = 对端来源地址）
    pub remote_addr: SocketAddr,
    /// true = 本端主动拨号
    pub outbound: bool,
    /// 当前准入状态
    pub admission: LinkAdmission,
    /// 同 PeerId 的存活连接数（≥1）
    pub connections: usize,
    /// 传输形态：LAN 直连 / 经 relay（宿主据此显示「内网直连 / 外网中继」）
    pub transport: Transport,
}

/// 入站流：已按协议名筛选，消费方可直接交给线协议处理
#[derive(Debug)]
pub struct InboundStream {
    /// 对端 node_id（已验证）
    pub node_id: NodeId,
    /// 对端 PeerId
    pub peer_id: PeerId,
    /// 对端地址
    pub remote_addr: SocketAddr,
    /// libp2p 子流（futures AsyncRead/AsyncWrite；消费方按需转 tokio）
    pub stream: Stream,
}

// ==================== 登记表 ====================

struct LinkEntry {
    info: PeerLink,
    admission_tx: watch::Sender<LinkAdmission>,
}

/// 链路登记表（引擎泵写、流消费方读）
pub(crate) type LinkRegistry = Arc<RwLock<LinkRegistryInner>>;

/// 登记表内部状态
#[derive(Default)]
pub(crate) struct LinkRegistryInner {
    links: HashMap<PeerId, LinkEntry>,
    by_node: HashMap<NodeId, PeerId>,
}

impl LinkRegistryInner {
    /// 取链路快照
    pub(crate) fn get(&self, peer_id: &PeerId) -> Option<PeerLink> {
        self.links.get(peer_id).map(|entry| entry.info.clone())
    }

    /// 按 node_id 取链路快照
    pub(crate) fn get_by_node(&self, node_id: &NodeId) -> Option<PeerLink> {
        self.by_node
            .get(node_id)
            .and_then(|peer_id| self.links.get(peer_id))
            .map(|entry| entry.info.clone())
    }

    /// 订阅某条链路的准入状态变化；链路不存在返回 None
    pub(crate) fn watch(&self, peer_id: &PeerId) -> Option<watch::Receiver<LinkAdmission>> {
        self.links
            .get(peer_id)
            .map(|entry| entry.admission_tx.subscribe())
    }

    /// 登记或累加一条连接；返回 true = 新链路（首次连接）
    ///
    /// 已存在的链路只累加计数并刷新地址；若新连接携带 Admitted（出站校验通过），
    /// 会把仍在 pending 的入站链路提升为 Admitted——方向混合时以「已可用」为准。
    pub(crate) fn insert(&mut self, info: PeerLink) -> bool {
        if let Some(entry) = self.links.get_mut(&info.peer_id) {
            entry.info.connections += 1;
            entry.info.outbound |= info.outbound;
            if info.remote_addr.port() != 0 {
                entry.info.remote_addr = info.remote_addr;
            }
            // 同对端可能同时有 LAN / relay 连接：快照按「最后一条连接」的形态呈现
            // （宿主状态栏只显示当前活跃路径，不做混合态展示）
            entry.info.transport = info.transport;
            if info.admission == LinkAdmission::Admitted
                && entry.info.admission != LinkAdmission::Admitted
            {
                entry.info.admission = LinkAdmission::Admitted;
                let _ = entry.admission_tx.send(LinkAdmission::Admitted);
            }
            return false;
        }
        let (admission_tx, _) = watch::channel(info.admission);
        self.by_node.insert(info.node_id.clone(), info.peer_id);
        self.links
            .insert(info.peer_id, LinkEntry { info, admission_tx });
        true
    }

    /// 结算准入状态（仅更新已存在链路；链路已断则丢弃）
    pub(crate) fn settle(&mut self, peer_id: &PeerId, state: LinkAdmission) {
        if let Some(entry) = self.links.get_mut(peer_id) {
            if entry.info.admission != state {
                entry.info.admission = state;
                let _ = entry.admission_tx.send(state);
            }
        }
    }

    /// 连接关闭：递减计数，最后一条才摘除；返回摘除后的快照
    pub(crate) fn remove_connection(&mut self, peer_id: &PeerId) -> Option<PeerLink> {
        let entry = self.links.get_mut(peer_id)?;
        if entry.info.connections > 1 {
            entry.info.connections -= 1;
            return None;
        }
        let entry = self.links.remove(peer_id)?;
        if self
            .by_node
            .get(&entry.info.node_id)
            .is_some_and(|mapped| *mapped == *peer_id)
        {
            self.by_node.remove(&entry.info.node_id);
        }
        Some(entry.info)
    }

    /// 强制摘除链路（身份不支持等拒绝路径用；不关心计数）
    pub(crate) fn remove(&mut self, peer_id: &PeerId) -> Option<PeerLink> {
        let entry = self.links.remove(peer_id)?;
        if self
            .by_node
            .get(&entry.info.node_id)
            .is_some_and(|mapped| *mapped == *peer_id)
        {
            self.by_node.remove(&entry.info.node_id);
        }
        Some(entry.info)
    }

    /// 全部链路快照（诊断/测试）
    pub(crate) fn snapshot(&self) -> Vec<PeerLink> {
        let mut links: Vec<_> = self
            .links
            .values()
            .map(|entry| entry.info.clone())
            .collect();
        links.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        links
    }
}

// ==================== 入站流接收器 ====================

/// 按协议名登记的入站流接收器
///
/// 生命周期与协议登记绑定：drop 即注销该协议（libp2p-stream 语义），
/// 对端后续开流协商失败。
pub struct IncomingStreams {
    inner: libp2p_stream::IncomingStreams,
    links: LinkRegistry,
    require_admitted: bool,
}

impl IncomingStreams {
    pub(crate) fn new(
        inner: libp2p_stream::IncomingStreams,
        links: LinkRegistry,
        require_admitted: bool,
    ) -> Self {
        Self {
            inner,
            links,
            require_admitted,
        }
    }

    /// 取下一条符合准入条件的入站流（无流时挂起）
    ///
    /// 未达准入条件的流被丢弃（关闭）；链路已摘除的流（连接已关）同样丢弃。
    pub async fn next(&mut self) -> Option<InboundStream> {
        loop {
            let (peer_id, stream) = self.inner.next().await?;
            // 流事件与 ConnectionEstablished 事件分属两个任务：给引擎泵一个
            // 极短窗口先登记链路（同机毫秒级；链路确已摘除则 1s 后丢弃）
            let Some(link) = self.wait_link(peer_id).await else {
                tracing::debug!(%peer_id, "入站流来自已摘除链路，丢弃");
                continue;
            };
            if self.require_admitted && link.admission != LinkAdmission::Admitted {
                tracing::debug!(
                    %peer_id,
                    node_id = %link.node_id,
                    admission = ?link.admission,
                    "入站业务流未达准入，丢弃"
                );
                continue;
            }
            return Some(InboundStream {
                node_id: link.node_id,
                peer_id,
                remote_addr: link.remote_addr,
                stream,
            });
        }
    }

    /// 等链路登记（最多 1s；流可能先于 ConnectionEstablished 被泵消费）
    async fn wait_link(&self, peer_id: PeerId) -> Option<PeerLink> {
        for _ in 0..100 {
            if let Some(link) = self.links.read().expect("链路登记表中毒").get(&peer_id) {
                return Some(link);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }

    /// 当前筛选模式（true = 只放行 Admitted）
    pub fn requires_admission(&self) -> bool {
        self.require_admitted
    }
}

/// 把入站流接收器装箱为可跨任务持有的 future 驱动（供期望 `Pin<Box<...>>` 的
/// 宿主装配；本 crate 自身不依赖 pin-project）。
pub type IncomingStreamsBoxed = Pin<Box<IncomingStreams>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn node(n: u8) -> NodeId {
        NodeId::parse(&hex::encode([n; 32])).unwrap()
    }

    fn link(n: u8, admission: LinkAdmission) -> PeerLink {
        PeerLink {
            node_id: node(n),
            peer_id: PeerId::random(),
            remote_addr: SocketAddr::from(([127, 0, 0, 1], 4000 + n as u16)),
            outbound: false,
            admission,
            connections: 1,
            transport: Transport::LanDirect,
        }
    }

    #[test]
    fn 登记_按_node_id_反查_与连接计数() {
        let mut inner = LinkRegistryInner::default();
        let a = link(1, LinkAdmission::Pending);
        let pid = a.peer_id;
        assert!(inner.insert(a.clone()));
        assert_eq!(
            inner.get_by_node(&a.node_id).map(|link| link.peer_id),
            Some(pid)
        );
        assert_eq!(inner.get(&pid).unwrap().connections, 1);

        // 同 PeerId 第二条连接：只累加，不重复登记
        let mut again = a.clone();
        again.connections = 1;
        assert!(!inner.insert(again));
        assert_eq!(inner.get(&pid).unwrap().connections, 2);
        assert!(inner.remove_connection(&pid).is_none());
        assert_eq!(inner.get(&pid).unwrap().connections, 1);
        assert!(inner.remove_connection(&pid).is_some());
        assert!(inner.get_by_node(&a.node_id).is_none());
    }

    #[test]
    fn 准入状态_订阅_结算_可见() {
        let mut inner = LinkRegistryInner::default();
        let a = link(2, LinkAdmission::Pending);
        let pid = a.peer_id;
        inner.insert(a);
        let rx = inner.watch(&pid).expect("watch");
        assert_eq!(*rx.borrow(), LinkAdmission::Pending);
        inner.settle(&pid, LinkAdmission::Admitted);
        assert_eq!(*rx.borrow(), LinkAdmission::Admitted);
        inner.settle(&pid, LinkAdmission::Denied);
        assert_eq!(*rx.borrow(), LinkAdmission::Denied);
    }

    #[test]
    fn 出站已准入_提升_pending_入站链路() {
        let mut inner = LinkRegistryInner::default();
        let a = link(3, LinkAdmission::Pending);
        let pid = a.peer_id;
        inner.insert(a.clone());
        let mut outbound = a;
        outbound.outbound = true;
        outbound.admission = LinkAdmission::Admitted;
        inner.insert(outbound);
        let snapshot = inner.get(&pid).unwrap();
        assert!(snapshot.outbound);
        assert_eq!(snapshot.admission, LinkAdmission::Admitted);
    }
}
