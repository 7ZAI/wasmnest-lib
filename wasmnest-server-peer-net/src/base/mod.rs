//! 对等网络底座机制（`wasmnest-peer-net` 拆分并入，2026-10-22 peer-net-dissolve）
//!
//! 原 `wasmnest-peer-net` crate 的机制面整体迁入本模块：Ed25519 节点身份 /
//! 自签证书 / TLS 直连 / 信任闸门 / mDNS 服务注册 / 传输会话引擎原语 /
//! 共享目录线协议。设计依据沿原 crate：ADR 0027 / 0028（传输栈方向与信任模型）。
//!
//! ## 拆分口径（spec §4.1，产品语义不下沉、机制全部保留）
//!
//! - **机制**（本模块）：身份 / 证书 / TLS / 信任 / 帧 / 节点 / 连接 / mDNS 注册 /
//!   传输线协议与断点续传 / 取消暂停 / 浏览拉取线协议与路径安全 / SAF 注入缝；
//! - **业务语义不留在底座**：接收策略值经 WIT `set-receive-policy` 由插件写入
//!   （本模块只执行）；共享目录暴露面条目经 WIT `set-shared-roots` 由插件全量
//!   推送（原 `BUILTIN_DOWNLOADS_ID` 内置免授权条目已删，双写冗余）；
//!   `disable_virtual_interfaces` 已归位 `wasmnest-discovery-engine`（mDNS 机制）。
//!
//! ## 可见性
//!
//! 本模块对 crate 外经 `wasmnest_server_peer_net` 顶层 re-export 暴露
//! （`crate::base::` 的符号名与旧 `wasmnest_peer_net::` 逐字一致，消费方仅改前缀）；
//! `tls` 为 `pub(crate)`（传输模块消费，不对 crate 外暴露）。

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

pub(crate) mod tls;

pub use cert::{generate_self_signed_cert, verify_cert_matches_node_id, CertDer};
pub use discovery::{
    spawn_peer_mdns_daemon, DiscoveredPeerRecord, DiscoveryCache, DiscoveryConfig, DiscoveryDaemon, PeerMdnsBrowse,
    CAP_FILE_TRANSFER, DISCOVERY_PROTOCOL_VERSION, PEER_DISCOVERY_TTL, SERVICE_TYPE, SWEEP_INTERVAL,
};
pub use error::{PeerNetError, Result};
pub use frame::{TrustStatus, TrustStatusFrame};
pub use identity::{NodeId, NodeIdentity};
pub use node::{PeerNetNode, PeerNetNodeConfig, StaticPeerRecord};
pub use shared::{
    browse_shared_dir, list_shared_roots, pull_shared_file, resolve_rel_path, saf_not_found, sort_entries,
    BrowseListing, SeqReader, SharedDirEntry, SharedDirHandler, SharedDirRoot, SharedDirStore, SharedRootMeta,
    SharedSafAccess,
};
pub use transfer::batch::DirEntry;
pub use transfer::{
    send_batch, CancelOrigin, CancelToken, FileLanding, FileMeta, IncomingFrame, OutgoingFile, PauseCmd, PauseSlot,
    ReceivePolicy, RejectReason, TerminalState, TransferConfig, TransferEvent, TransferFrame, TransferReceiveHandler,
};
pub use transport::{
    Connection, ConnectionHandler, HandlerFuture, RunningNode, TrustEvent, CONFIRM_TIMEOUT, MAX_PENDING_CONFIRMATIONS,
};
pub use trust_store::{TrustStore, TrustedPeerEntry};
