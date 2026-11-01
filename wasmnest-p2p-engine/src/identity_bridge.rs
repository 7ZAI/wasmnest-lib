//! 节点身份桥：同一把 ed25519 密钥派生两套标识，node_id ↔ PeerId 互验。
//!
//! ## 为什么零迁移（本模块的设计基石）
//!
//! 现役 peer-net 的 [`NodeIdentity`]：node_id = `hex(SHA-256(raw ed25519 公钥 32B))`，
//! 信任列表按 node_id 键控、mDNS TXT 里广播的也是 node_id。libp2p 的 PeerId 则是
//! 公钥的 multihash（ed25519 = identity multihash(protobuf 编码公钥)）——**两者都是
//! 同一公钥的纯函数**：把同一把密钥喂给 [`NodeKey`]，node_id 与 PeerId 同时确定。
//! 于是「对端 PeerId → 解出公钥 → 重算 SHA-256 → 得 node_id」即可完成互验，
//! 信任列表零迁移，指纹即身份的红线平移为「PeerId 公钥即节点公钥」。
//!
//! ## 与 peer-net 的对齐判据（跨 crate 线上不变量）
//!
//! 本 crate 零内部依赖（边界锁钉死），不能 import peer-net 的实现，因此对齐靠
//! 双侧各持判据：本模块 [`node_id_from_raw_public_key`] 的输入字节 = peer-net
//! `base/identity.rs` 的 `public_key_raw`（ed25519 验证键 `to_bytes()` 的 32 字节
//! 原始形式，非 DER/SPKI），输出 = 小写 64 字符 hex。[`tests`] 里的固定种子
//! 金向量同时钉 node_id 与 PeerId 的跨版本稳定性（libp2p 若改变密钥编码即红）。
//!
//! ## 非 ed25519 对端：显性拒绝
//!
//! node_id 派生语义只对 ed25519 成立（RSA/ECDSA 的 PeerId 是哈希形式，公钥不可
//! 从 PeerId 还原）。遇到哈希型或非 ed25519 身份时 [`node_id_from_peer_id`]
//! 返回 [`P2pError::UnsupportedPeerIdentity`]，由引擎断开连接并上报——
//! 不做静默降级（fail-visible 红线）。
//!
//! [`NodeIdentity`]: crate::engine
//! [`P2pError::UnsupportedPeerIdentity`]: crate::error::P2pError::UnsupportedPeerIdentity

use libp2p::identity::{self, Keypair};
use libp2p::{multihash, PeerId};
use sha2::{Digest, Sha256};

use crate::error::P2pError;

/// identity multihash 的类型码（ed25519 PeerId = identity(protobuf 公钥)）
const MULTIHASH_IDENTITY_CODE: u64 = 0x00;

// ==================== NodeId ====================

/// 节点 ID：`hex(SHA-256(raw ed25519 公钥 32B))`，小写全长 64 字符
///
/// 与 peer-net 的同名概念是**同一个线上标识**（字符串形式逐字一致）；P1 接入时
/// peer-net 侧做字符串级换装（其 newtype 不出域，本 newtype 亦然）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(String);

impl NodeId {
    /// 由 raw ed25519 公钥（32 字节）派生节点 ID——对齐判据的落点
    pub fn from_raw_public_key(raw: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(raw)))
    }

    /// 解析并校验：长度 64 且全为小写 hex（与 peer-net `is_valid_node_id` 同判据）
    pub fn parse(value: &str) -> Result<Self, P2pError> {
        if value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value.to_string()))
        } else {
            Err(P2pError::InvalidNodeId(value.to_string()))
        }
    }

    /// 字符串形式（小写 hex 64 字符）
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ==================== NodeKey ====================

/// 节点身份密钥：seed → libp2p 密钥对 + 两套派生标识（node_id / PeerId）
///
/// 持久化（落盘 JSON）属调用方（P1 起 = peer-net 的 PathsPort 数据目录，
/// 与现役 `node_identity.json` 同一存储），本类型只收 32 字节种子——
/// 引擎不碰文件系统。
#[derive(Clone)]
pub struct NodeKey {
    keypair: Keypair,
    node_id: NodeId,
}

impl NodeKey {
    /// 由 32 字节 ed25519 种子构建（现役身份文件里存的即此形态）
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self, P2pError> {
        if seed.len() != 32 {
            return Err(P2pError::InvalidSeed(format!(
                "种子须 32 字节，实得 {}",
                seed.len()
            )));
        }
        let mut buf = seed.to_vec();
        let keypair = identity::Keypair::ed25519_from_bytes(&mut buf)
            .map_err(|e| P2pError::InvalidSeed(e.to_string()))?;
        Self::from_keypair(keypair)
    }

    /// 随机生成（OsRng；测试与全新节点用。重装即新身份的决策属调用方）
    pub fn generate() -> Self {
        Self::from_keypair(identity::Keypair::generate_ed25519()).expect("ed25519 生成不会失败")
    }

    fn from_keypair(keypair: Keypair) -> Result<Self, P2pError> {
        let node_id = node_id_from_public_key(&keypair.public())?;
        Ok(Self { keypair, node_id })
    }

    /// 本节点 node_id（应用/信任层标识）
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// 本节点 PeerId（swarm 层标识）
    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.keypair.public())
    }

    /// 取出密钥对（装配 swarm 用）
    pub fn into_keypair(self) -> Keypair {
        self.keypair
    }
}

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密钥材料不进 Debug 输出（安全红线：凭据只记派生标识，不落明文）
        f.debug_struct("NodeKey")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

// ==================== 互验 ====================

/// 从公钥直接派生 node_id（只接受 ed25519——node_id 派生语义的前提）
pub fn node_id_from_public_key(public_key: &identity::PublicKey) -> Result<NodeId, P2pError> {
    // libp2p-identity 0.3 起 PublicKey 是类型擦除 struct：按 try_into 判型
    match public_key.clone().try_into_ed25519() {
        Ok(key) => Ok(NodeId::from_raw_public_key(&key.to_bytes())),
        Err(_) => Err(P2pError::UnsupportedPeerIdentity(
            "密钥类型非 ed25519，无法派生 node_id".to_string(),
        )),
    }
}

/// 从 PeerId 还原 node_id：ed25519 的 PeerId = identity multihash(protobuf 公钥)
pub fn node_id_from_peer_id(peer_id: &PeerId) -> Result<NodeId, P2pError> {
    let bytes = peer_id.to_bytes();
    let mh = multihash::Multihash::<64>::from_bytes(&bytes)
        .map_err(|e| P2pError::UnsupportedPeerIdentity(format!("PeerId 非法 multihash：{e}")))?;
    if mh.code() != MULTIHASH_IDENTITY_CODE {
        return Err(P2pError::UnsupportedPeerIdentity(
            "PeerId 为哈希型（RSA 等大密钥），公钥不可还原".to_string(),
        ));
    }
    let public_key = identity::PublicKey::try_decode_protobuf(mh.digest())
        .map_err(|e| P2pError::UnsupportedPeerIdentity(format!("PeerId 内嵌公钥解码失败：{e}")))?;
    node_id_from_public_key(&public_key)
}

/// 校验对端身份：PeerId 派生的 node_id 必须与期望逐字一致（指纹即身份）
///
/// 不一致时返回 [`P2pError::NodeIdMismatch`]，调用方（引擎）立即断开并上报。
pub fn verify_peer_identity(peer_id: &PeerId, expected: &NodeId) -> Result<NodeId, P2pError> {
    let actual = node_id_from_peer_id(peer_id)?;
    if actual == *expected {
        Ok(actual)
    } else {
        Err(P2pError::NodeIdMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 金向量种子（任意固定 32 字节；向量值在首次定版时从实现打印钉入）
    const GOLDEN_SEED: [u8; 32] = [
        0x0b, 0x21, 0x4f, 0x18, 0x9d, 0x61, 0xc3, 0x8d, 0x2f, 0x77, 0xa5, 0x3e, 0xc0, 0x93, 0x24,
        0x68, 0x51, 0x7e, 0xd0, 0xb4, 0xa6, 0x18, 0x39, 0x40, 0x43, 0x1f, 0x6a, 0x0c, 0x75, 0xf2,
        0x55, 0x1a,
    ];

    #[test]
    fn node_id_派生与_peer_id_互验自洽() {
        let key = NodeKey::from_seed_bytes(&GOLDEN_SEED).unwrap();
        // 双标识都是同一公钥的纯函数：互验必须自洽（零迁移设计的判据）
        let derived = node_id_from_peer_id(&key.peer_id()).unwrap();
        assert_eq!(derived, *key.node_id());
        assert!(verify_peer_identity(&key.peer_id(), key.node_id()).is_ok());
    }

    #[test]
    fn node_id_等于_raw_公钥的_sha256_hex() {
        // 对齐判据：直接用 sha2 对 raw 32B 公钥手算，与桥接派生逐字比对
        let key = NodeKey::from_seed_bytes(&GOLDEN_SEED).unwrap();
        let ed = key
            .clone()
            .into_keypair()
            .try_into_ed25519()
            .expect("种子必须派生 ed25519 密钥")
            .public();
        let raw = ed.to_bytes();
        assert_eq!(key.node_id().as_str(), hex::encode(Sha256::digest(raw)));
    }

    #[test]
    fn 金向量_钉跨版本稳定性() {
        // 定版快照：libp2p / 派生实现若变动（密钥编码 / 哈希输入 / hex 形态）即红
        let key = NodeKey::from_seed_bytes(&GOLDEN_SEED).unwrap();
        assert_eq!(
            key.node_id().as_str(),
            "3cd2298858dcd85afc278723bfbec7420c31fc0c66e9d6878cd40aed44615ac0"
        );
        assert_eq!(
            key.peer_id().to_string(),
            "12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA"
        );
    }

    #[test]
    fn node_id_解析校验() {
        let key = NodeKey::generate();
        let parsed = NodeId::parse(key.node_id().as_str()).unwrap();
        assert_eq!(parsed, *key.node_id());
        // 大写 / 短串 / 非法字符全拒（与 peer-net 判据一致：64 位小写 hex）
        let upper = key.node_id().as_str().to_uppercase();
        assert!(NodeId::parse(&upper).is_err());
        assert!(NodeId::parse(&key.node_id().as_str()[..63]).is_err());
        assert!(NodeId::parse(&"g".repeat(64)).is_err());
        assert!(NodeId::parse("").is_err());
    }

    #[test]
    fn 种子长度校验() {
        assert!(NodeKey::from_seed_bytes(&[0u8; 31]).is_err());
        assert!(NodeKey::from_seed_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn 同种子同标识_异种子异标识() {
        let a1 = NodeKey::from_seed_bytes(&GOLDEN_SEED).unwrap();
        let a2 = NodeKey::from_seed_bytes(&GOLDEN_SEED).unwrap();
        assert_eq!(a1.node_id(), a2.node_id());
        assert_eq!(a1.peer_id(), a2.peer_id());
        let b = NodeKey::generate();
        assert_ne!(a1.node_id(), b.node_id());
        assert_ne!(a1.peer_id(), b.peer_id());
    }

    #[test]
    fn 密钥不进_debug_输出() {
        let key = NodeKey::from_seed_bytes(&GOLDEN_SEED).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains(key.node_id().as_str()));
        assert!(!debug.contains("Secret"));
    }
}
