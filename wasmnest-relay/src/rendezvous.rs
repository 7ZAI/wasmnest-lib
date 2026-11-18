//! 中继侧设备会合表（`/wasmnest/relay-control/1` 的 `announce` / `query` 落点）。
//!
//! ## 为什么中继要记这个
//!
//! Circuit Relay v2 只解决「怎么把字节送到对端」，不解决「对端是谁、现在在不在」。
//! mDNS 只能在同一个二层网络里发现设备；两台设备跨 NAT 时，即使都连上了同一个
//! 中继，也互相不知道对方的 PeerId —— 除非用户手工交换连接串。会合表补的就是
//! 这一段：设备连上中继后登记一次（认证身份由 Noise 握手给出，不信任载荷自报），
//! 其它设备查询同一房间即可拿到「可拨的 PeerId + 展示名」，再由宿主拼出
//! `<relay>/p2p-circuit/p2p/<peer>` 直接拨号。
//!
//! ## 房间边界
//!
//! 房间键由客户端给出（当前 = 固定 `nest`，即「同一台中继 = 同一个私有网络」）。
//! 中继只把它当不透明字符串，不做语义解释。**房间不是授权点**：真正的访问控制
//! 仍是目标宿主的信任表 + 首连确认；本表只负责发现，发现到不等于能访问。
//!
//! 多租户中继若需要隔离，应升级为「每房间一个共享密钥」的派生键（客户端只发
//! 哈希），而不是在未认证的房间里互相信任。当前实现按自建/私有中继口径设计，
//! 房间键与准入模式（open / allowlist）共同构成可见性边界。
//!
//! ## 过期与容量
//!
//! - 记录 TTL = [`ENTRY_TTL`]；客户端按 [`ANNOUNCE_INTERVAL`] 节奏续期。
//! - 每个房间最多 [`MAX_PEERS_PER_ROOM`] 条；满了之后新设备挤掉最久未续期的
//!   一条（确定性、不随机踢人）。
//! - 断线不即时删除：控制流是短连接，中继无法可靠区分「正常关闭」与「网络断开」，
//!   由 TTL 兜底，避免抖动导致设备在列表里闪进闪出。

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use libp2p::PeerId;

/// 记录存活时间：客户端每 [`ANNOUNCE_INTERVAL`] 续期一次，允许丢两次心跳
pub const ENTRY_TTL: Duration = Duration::from_secs(90);
/// 建议续期间隔（写入协议文档；客户端可更频繁，但不能超过 TTL）
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
/// 单房间设备上限（防御性上限；私有网络远达不到）
pub const MAX_PEERS_PER_ROOM: usize = 64;
/// 房间总数上限（防御「不断换房间号」的内存增长；超出时淘汰最久无活动的房间）
pub const MAX_ROOMS: usize = 256;
/// 房间键长度上限
pub const MAX_ROOM_LEN: usize = 64;

/// 一条会合记录（对外只读投影）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousPeer {
    /// 对端 libp2p PeerId（base58；拼 circuit 地址用）
    pub peer_id: PeerId,
    /// 对端自报的 64 位 hex 节点 ID（宿主握手时仍会复核）
    pub node_id: String,
    /// 展示名（可为空）
    pub name: String,
    /// 最近一次登记时刻（Unix 毫秒；给界面展示「刚刚在线」）
    pub last_seen_ms: u64,
}

impl RendezvousPeer {
    /// 转换为线协议形状（`peer_id` 用 base58）
    pub fn to_wire(&self) -> crate::wire::RendezvousPeer {
        crate::wire::RendezvousPeer {
            peer_id: self.peer_id.to_base58(),
            node_id: self.node_id.clone(),
            name: self.name.clone(),
            last_seen_ms: self.last_seen_ms,
        }
    }
}

/// 会合表（进程内，随中继生命周期存续）
#[derive(Default)]
pub struct Rendezvous {
    rooms: Mutex<HashMap<String, HashMap<PeerId, Entry>>>,
}

#[derive(Debug, Clone)]
struct Entry {
    node_id: String,
    name: String,
    seen: Instant,
    last_seen_ms: u64,
}

impl Rendezvous {
    /// 新建空表
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记 / 续期一台设备，返回房间内**除自己以外**的当前设备。
    ///
    /// 校验失败不写表（调用方把错误回给客户端）。
    pub fn announce(
        &self,
        room: &str,
        peer: PeerId,
        node_id: &str,
        name: &str,
    ) -> Result<Vec<RendezvousPeer>, RendezvousError> {
        validate_room(room)?;
        validate_node_id(node_id)?;
        let name = sanitize_name(name);

        let now = Instant::now();
        let mut rooms = self.rooms.lock().expect("rendezvous lock poisoned");
        // 新房间先做全局清理 / 容量检查，避免无限房间号把进程内存拖大
        if !rooms.contains_key(room) {
            rooms.retain(|_, entries| {
                prune(entries, now);
                !entries.is_empty()
            });
            if rooms.len() >= MAX_ROOMS {
                if let Some(oldest) = rooms
                    .iter()
                    .filter_map(|(key, entries)| {
                        entries
                            .values()
                            .map(|e| e.seen)
                            .max()
                            .map(|seen| (key.clone(), seen))
                    })
                    .min_by_key(|(_, seen)| *seen)
                    .map(|(key, _)| key)
                {
                    rooms.remove(&oldest);
                }
            }
        }
        let entries = rooms.entry(room.to_string()).or_default();
        prune(entries, now);

        if !entries.contains_key(&peer) && entries.len() >= MAX_PEERS_PER_ROOM {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.seen)
                .map(|(peer, _)| *peer)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            peer,
            Entry {
                node_id: node_id.to_string(),
                name,
                seen: now,
                last_seen_ms: unix_millis(),
            },
        );

        Ok(entries
            .iter()
            .filter(|(id, _)| **id != peer)
            .map(|(id, entry)| RendezvousPeer {
                peer_id: *id,
                node_id: entry.node_id.clone(),
                name: entry.name.clone(),
                last_seen_ms: entry.last_seen_ms,
            })
            .collect())
    }

    /// 查询房间内所有未过期设备（不写表）。
    pub fn query(&self, room: &str) -> Result<Vec<RendezvousPeer>, RendezvousError> {
        validate_room(room)?;
        let now = Instant::now();
        let mut rooms = self.rooms.lock().expect("rendezvous lock poisoned");
        let Some(entries) = rooms.get_mut(room) else {
            return Ok(Vec::new());
        };
        prune(entries, now);
        Ok(entries
            .iter()
            .map(|(id, entry)| RendezvousPeer {
                peer_id: *id,
                node_id: entry.node_id.clone(),
                name: entry.name.clone(),
                last_seen_ms: entry.last_seen_ms,
            })
            .collect())
    }

    /// 测试 / 诊断：房间内当前条数
    #[cfg(test)]
    fn len(&self, room: &str) -> usize {
        self.rooms
            .lock()
            .expect("rendezvous lock poisoned")
            .get(room)
            .map(HashMap::len)
            .unwrap_or(0)
    }
}

fn prune(entries: &mut HashMap<PeerId, Entry>, now: Instant) {
    entries.retain(|_, entry| now.duration_since(entry.seen) < ENTRY_TTL);
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// 房间键校验：1..=64 个 `[A-Za-z0-9_-]`（不让 JSON / 日志里出现奇怪控制字符）
pub fn validate_room(room: &str) -> Result<(), RendezvousError> {
    if room.is_empty() {
        return Err(RendezvousError::InvalidRoom);
    }
    if room.len() > MAX_ROOM_LEN {
        return Err(RendezvousError::InvalidRoom);
    }
    if !room
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(RendezvousError::InvalidRoom);
    }
    Ok(())
}

/// 节点 ID 校验：64 位小写 hex（与能力仓 `NodeId` 同判据）
pub fn validate_node_id(node_id: &str) -> Result<(), RendezvousError> {
    if node_id.len() == 64
        && node_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(RendezvousError::InvalidNodeId)
    }
}

/// 展示名清洗：去控制字符、裁剪首尾空白、最多 64 个字符（不是字节）
pub fn sanitize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(64)
        .collect()
}

/// 会合表错误（词汇稳定，客户端按词分支）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousError {
    /// 房间键非法
    InvalidRoom,
    /// 节点 ID 非法
    InvalidNodeId,
}

impl RendezvousError {
    /// 线协议错误词
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRoom => "invalid-room",
            Self::InvalidNodeId => "invalid-node-id",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn node_id(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    #[test]
    fn announce_返回除自己以外的设备() {
        let table = Rendezvous::new();
        let a = peer();
        let b = peer();
        let first = table
            .announce("nest", a, &node_id(1), "desktop")
            .expect("announce");
        assert!(first.is_empty(), "首位登记者看不到别人");
        let second = table
            .announce("nest", b, &node_id(2), "phone")
            .expect("announce");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].peer_id, a);
        assert_eq!(second[0].node_id, node_id(1));
        assert_eq!(second[0].name, "desktop");
        assert_eq!(table.len("nest"), 2);
    }

    #[test]
    fn 重复登记是续期而不是新增() {
        let table = Rendezvous::new();
        let a = peer();
        table.announce("nest", a, &node_id(1), "a").expect("first");
        table
            .announce("nest", a, &node_id(1), "renamed")
            .expect("second");
        assert_eq!(table.len("nest"), 1);
        let peers = table.query("nest").expect("query");
        assert_eq!(peers[0].name, "renamed");
    }

    #[test]
    fn 查询空房间返回空表() {
        let table = Rendezvous::new();
        assert!(table.query("missing").expect("query").is_empty());
    }

    #[test]
    fn 非法房间与节点_id_显性拒绝且不写表() {
        let table = Rendezvous::new();
        let a = peer();
        assert_eq!(
            table.announce("", a, &node_id(1), "a"),
            Err(RendezvousError::InvalidRoom)
        );
        assert_eq!(
            table.announce("nest", a, "short", "a"),
            Err(RendezvousError::InvalidNodeId)
        );
        assert_eq!(
            table.announce("bad room", a, &node_id(1), "a"),
            Err(RendezvousError::InvalidRoom)
        );
        assert_eq!(table.len("nest"), 0);
        assert_eq!(table.len("bad room"), 0);
    }

    #[test]
    fn 超容量时淘汰最久未续期的一条() {
        let table = Rendezvous::new();
        let members: Vec<PeerId> = (0..MAX_PEERS_PER_ROOM).map(|_| peer()).collect();
        for (idx, id) in members.iter().enumerate() {
            table
                .announce("nest", *id, &node_id(idx as u8), "n")
                .expect("announce");
        }
        let newcomer = peer();
        table
            .announce("nest", newcomer, &node_id(250), "new")
            .expect("announce");
        assert_eq!(table.len("nest"), MAX_PEERS_PER_ROOM);
        assert!(
            !table
                .query("nest")
                .expect("query")
                .iter()
                .any(|p| p.peer_id == members[0]),
            "最旧的一条应被挤掉"
        );
        assert!(
            table
                .query("nest")
                .expect("query")
                .iter()
                .any(|p| p.peer_id == newcomer),
            "新设备必须在表里"
        );
    }

    #[test]
    fn 房间数超限时淘汰最久无活动的房间() {
        let table = Rendezvous::new();
        for idx in 0..MAX_ROOMS {
            table
                .announce(&format!("room-{idx}"), peer(), &node_id(idx as u8), "n")
                .expect("announce");
        }
        assert_eq!(table.rooms.lock().expect("lock").len(), MAX_ROOMS);
        let newcomer = peer();
        table
            .announce("fresh-room", newcomer, &node_id(250), "new")
            .expect("announce");
        let rooms = table.rooms.lock().expect("lock");
        assert_eq!(rooms.len(), MAX_ROOMS, "房间总数上限必须保持");
        assert!(rooms.contains_key("fresh-room"), "新房间必须占位");
        assert!(!rooms.contains_key("room-0"), "最旧房间应被淘汰");
    }

    #[test]
    fn 名称清洗控制字符并截断() {
        assert_eq!(sanitize_name("  a\u{0}b\n  "), "ab");
        assert_eq!(sanitize_name(&"x".repeat(100)).chars().count(), 64);
    }

    #[test]
    fn 记录过期后查询不可见() {
        let table = Rendezvous::new();
        let a = peer();
        table
            .announce("nest", a, &node_id(1), "a")
            .expect("announce");
        {
            let mut rooms = table.rooms.lock().expect("lock");
            let entry = rooms
                .get_mut("nest")
                .and_then(|room| room.get_mut(&a))
                .expect("entry");
            entry.seen = Instant::now() - ENTRY_TTL - Duration::from_secs(1);
        }
        assert!(table.query("nest").expect("query").is_empty());
    }
}
