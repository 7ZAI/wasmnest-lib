//! # wasmnest-peer-net — 对等网络共享基础设施
//!
//! 桌面端与移动端共享的对等网络底座（设计依据见本文件末尾的 ADR 0027 / 0028；
//! 原 issue tracker `.scratch/peer-network/issues/01`（节点身份）、`/02`（TLS 直连）
//! 所在目录已不在仓库中，裁决已固化进 ADR 0027 / 0028）：
//!
//! - **节点身份**（[`identity`]）：Ed25519 长效密钥，首启纯随机生成、持久化于宿主
//!   注入的数据目录；重装即新身份（决策 D2），与设备身份（DeviceIdentity）彻底分离；
//! - **自签证书**（[`cert`]）：由节点身份种子构造 rcgen 密钥产出的自签 TLS 证书，
//!   证书公钥即节点公钥，「证书绑定校验」是可信连接的根基；
//! - **TLS 直连**（ticket 02 已锁定 tokio-rustls(ring) / TLS 1.3 单版本）：
//!   自定义 verifier 落地「指纹即身份」的两层分工——拨号侧按期望 NodeId 钉扎
//!   比对（不符即 TLS 层拒绝，AC#3），接听侧仅做 SPKI 形状校验；「是否可信」
//!   由握手后的应用层闸门查 trust store 决定。两个 verifier 的
//!   `verify_tls13_signature` 均做真实 Ed25519 签名验证（RFC 8446 §4.4.3），
//!   证明对端持有对应私钥——伪造身份在密码学上不可行（ADR 0028）。
//! - **信任与首连闸门**：[`trust_store`] 持久化可信节点列表；未信任方拨入停在
//!   应用层确认闸门，宿主经 [`TrustEvent::ConfirmRequested`] 回调接受/拒绝，
//!   接受则双向落库连通、后续重连静默（AC#1/#2），撤销后重走确认（AC#4/#5）。
//! - **上层缝**（[`transport::ConnectionHandler`]）：信任放行后的已认证连接移交
//!   点，后续 HTTP 服务票在此挂载低层驱动（ADR 0027 衔接决策）。
//! - **mDNS 节点发现**（[`discovery`]，ticket 03）：对等网络专用服务类型
//!   `_wasmnest-peer._tcp.local.` 广播+浏览并存，TXT 携带设备名/协议版本/能力
//!   位图；发现结果进带 TTL 的在线缓存，「在线」即记录可见、与连接无关。
//!   守护回调与测试喂入共用 [`DiscoveryCache::observe`] 同一通路（注入缝）；
//!   浏览面消费宿主注入的类型中枢订阅（[`PeerMdnsBrowse`]，同类型 browse 唯一性
//!   归中枢，ADR 0054），本 crate 不自行 browse / stop_browse；
//!   与终端链路旧 `_wasmnest._tcp` 完全独立互不感知。
//!
//! 设计依据：`docs/adr/0027-peer-network-transport-stack.md`（传输栈方向）、
//! `docs/adr/0028-peer-trust-model.md`（信任模型）。
//!
//! ## 指纹算法（既定约定）
//!
//! - `node_id = hex(SHA-256(raw ed25519 公钥 32B))`，小写全长 64 字符；
//!   选原始公钥哈希而非 DER SPKI 哈希，因为两侧计算路径都最短：
//!   生成侧持有原始公钥，校验侧从 SPKI BIT STRING 直接取 32 字节原始钥再哈希；
//! - 短指纹 = 前 8 字符（UI 展示用，见 [`NodeId::short_fingerprint`]）。

pub mod cert;
pub mod discovery;
pub mod error;
pub mod frame;
pub mod identity;
pub mod node;
pub mod shared;
pub mod transfer;
pub mod transport;
pub mod trust_store;

mod tls;

pub use cert::{CertDer, generate_self_signed_cert, verify_cert_matches_node_id};
pub use discovery::{
    CAP_FILE_TRANSFER, DISCOVERY_PROTOCOL_VERSION, DiscoveryCache,
    DiscoveryConfig, DiscoveryDaemon, DiscoveredPeerRecord, PEER_DISCOVERY_TTL,
    PeerMdnsBrowse, SERVICE_TYPE, SWEEP_INTERVAL, disable_virtual_interfaces,
    spawn_peer_mdns_daemon,
};
pub use error::{PeerNetError, Result};
pub use frame::{TrustStatus, TrustStatusFrame};
pub use identity::{NodeId, NodeIdentity};
pub use node::{PeerNetNode, PeerNetNodeConfig, StaticPeerRecord};
pub use shared::{
    BUILTIN_DOWNLOADS_ID, BrowseListing, SharedRootMeta, browse_shared_dir, list_shared_roots,
    pull_shared_file, resolve_rel_path, saf_not_found, sort_entries, SeqReader, SharedDirEntry,
    SharedDirHandler, SharedDirRoot, SharedSafAccess, SharedDirStore,
};
pub use transfer::{
    CancelOrigin, CancelToken, FileLanding, FileMeta, IncomingFrame, OutgoingFile, PauseCmd,
    PauseSlot, ReceivePolicy, RejectReason, TerminalState, TransferConfig, TransferEvent,
    TransferFrame, TransferReceiveHandler, send_batch,
};
pub use transfer::batch::DirEntry;
pub use transport::{
    CONFIRM_TIMEOUT, Connection, ConnectionHandler, HandlerFuture, MAX_PENDING_CONFIRMATIONS,
    RunningNode, TrustEvent,
};
pub use trust_store::{TrustStore, TrustedPeerEntry};
