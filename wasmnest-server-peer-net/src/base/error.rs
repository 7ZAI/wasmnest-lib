//! 统一错误类型：crate 内所有可失败操作收敛到 [`PeerNetError`]。
//!
//! 与宿主的 `AppError` 刻意解耦（共享 crate 不能反向依赖宿主）：宿主需要映射时
//! 自行 `map_err`；本票宿主侧只打日志，不做映射。

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::base::identity::NodeId;

/// crate 内统一 Result 别名
pub type Result<T> = std::result::Result<T, PeerNetError>;

/// 对等网络基础设施错误集合
///
/// 每个变体的文案说明「什么操作在哪失败」；带 `#[source]` 的变体保留底层错误链。
#[derive(Debug, thiserror::Error)]
pub enum PeerNetError {
    /// 创建节点身份数据目录失败（`load_or_create` 前置步骤）
    #[error("create peer-net data dir failed: {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 读取身份文件失败（IO 层）
    #[error("read node identity file failed: {path}: {source}")]
    IdentityRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 身份文件不是合法 JSON——文件损坏，快速失败而非静默重建（决策 D3）
    #[error("parse node identity file as JSON failed (file corrupted): {path}: {source}")]
    IdentityParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// 身份文件内容不自洽或字段非法（seed 解码失败 / node_id 不匹配等）
    #[error("node identity file corrupted or inconsistent: {path}: {detail}")]
    IdentityCorrupted { path: PathBuf, detail: String },

    /// 序列化身份到 JSON 失败
    #[error("serialize node identity to JSON failed: {source}")]
    #[allow(dead_code)]
    IdentitySerialize {
        #[source]
        source: serde_json::Error,
    },

    /// 写入临时文件失败（原子写第一步）
    #[error("write node identity temp file failed: {path}: {source}")]
    IdentityWriteTemp {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 临时文件替换正式文件失败（原子写第二步）
    #[error("atomic rename of node identity file failed: {from} -> {to}: {source}")]
    IdentityRename {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 设置身份文件权限失败（仅 unix）
    #[error("restrict permissions on node identity file failed: {path}: {source}")]
    #[allow(dead_code)]
    IdentityPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// node_id 字符串格式非法（期望 64 位小写 hex）
    #[error("invalid node id (expected 64 lowercase hex chars): {value}")]
    InvalidNodeId { value: String },

    /// 从身份种子构造证书签名密钥对失败（PKCS#8 包装/解析层）
    #[error("build certificate key pair from identity seed failed (node_id={node_id}): {source}")]
    KeyPairFromSeed {
        node_id: String,
        #[source]
        source: rcgen::Error,
    },

    /// rcgen 自签证书生成失败
    #[error("generate self-signed certificate failed (node_id={node_id}): {source}")]
    CertGenerate {
        node_id: String,
        #[source]
        source: rcgen::Error,
    },

    /// X.509 证书 DER / SPKI 解析失败
    ///
    /// `detail` 承载底层解析器（nom/x509-parser）的错误描述文本：
    /// 该错误经 nom 的 Err 包装，无法以标准 `#[source]` 形式保留。
    #[error("parse x509 certificate DER failed: {detail}")]
    CertParse { detail: String },

    // ==================== 监听 / 拨号 / TLS（ticket 02）====================

    /// 绑定本节点 TCP 监听端口失败
    #[error("bind peer-net TCP listener failed: {addr}: {source}")]
    ListenBind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// 准备移交的 TCP listener 失败（读本地地址 / 设非阻塞 / std→tokio 转换）
    #[error("prepare TCP listener for peer-net node failed: {source}")]
    ListenerPrepare {
        #[source]
        source: std::io::Error,
    },

    /// 拨号对端时 TCP 连接失败
    #[error("dial peer failed on TCP connect: {addr}: {source}")]
    DialConnect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// 构建 rustls TLS 配置失败（协议版本/key/cert 装载层，非单连接握手）
    #[error("build rustls TLS configuration failed: {detail}")]
    TlsConfig { detail: String },

    /// 与对端的 TLS 握手失败
    ///
    /// `detail` 承载 rustls/io 层错误描述文本：错误经 tokio-rustls 的 `io::Error`
    /// 包装后类型信息不统一，无法以标准 `#[source]` 形式保留。
    #[error("TLS handshake with peer failed ({peer_addr}): {detail}")]
    TlsHandshake { peer_addr: SocketAddr, detail: String },

    /// 对端证书指纹与期望节点 ID 不符——拨号侧 TLS 层身份钉扎拒绝（AC#3 的错误种类）
    #[error("TLS certificate binding mismatch: expected node_id={expected}, actual={actual}")]
    TlsBindingMismatch {
        expected: String,
        actual: String,
    },

    /// mTLS 握手完成但对端未出示证书（mandatory client auth 被绕过的防御分支）
    #[error("mTLS peer presented no certificate (peer_addr={peer_addr})")]
    PeerCertMissing {
        peer_addr: SocketAddr,
    },

    /// 首连信任状态控制帧读写失败（长度前缀/JSON/IO 层）
    #[error("trust status control frame I/O failed ({peer_addr}): {detail}")]
    ControlFrame { peer_addr: SocketAddr, detail: String },

    /// 拨号被对端确认闸门拒绝（宿主拒绝或确认超时）
    #[error("dial denied by peer (node_id={node_id})")]
    DialDeniedByPeer { node_id: NodeId },

    /// 状态帧所指节点与本次连接的已认证身份不符（协议一致性防御分支）
    #[error("control frame refers to unexpected peer node (node_id={node_id})")]
    UnknownPeer { node_id: NodeId },

    /// 接听侧等待宿主首连确认应答超时，按拒绝处理（Decision 6）
    #[error("first-connect confirmation timed out (node_id={node_id})")]
    ConfirmTimeout { node_id: NodeId },

    // ==================== 可信节点存储 ====================

    /// 读取可信节点列表文件失败（IO 层）
    #[error("read trusted nodes file failed: {path}: {source}")]
    TrustStoreRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 可信节点列表文件不是合法 JSON——文件损坏，快速失败而非静默重建
    #[error("parse trusted nodes file as JSON failed (file corrupted): {path}: {source}")]
    TrustStoreParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// 可信节点列表文件内容不自洽或字段非法
    #[error("trusted nodes file corrupted or inconsistent: {path}: {detail}")]
    TrustStoreCorrupted { path: PathBuf, detail: String },

    /// 序列化可信节点列表到 JSON 失败
    #[error("serialize trusted nodes to JSON failed: {source}")]
    TrustStoreSerialize {
        #[source]
        source: serde_json::Error,
    },

    /// 写入可信节点列表临时文件失败（原子写第一步）
    #[error("write trusted nodes temp file failed: {path}: {source}")]
    TrustStoreWriteTemp {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 临时文件替换正式文件失败（原子写第二步）
    #[error("atomic rename of trusted nodes file failed: {from} -> {to}: {source}")]
    TrustStoreRename {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 设置可信节点列表文件权限失败（仅 unix）
    #[error("restrict permissions on trusted nodes file failed: {path}: {source}")]
    #[allow(dead_code)]
    TrustStorePermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // ==================== 传输会话（issue 05）====================

    /// 传输会话 IO/编解码失败（读写帧、文件落盘层）
    ///
    /// `role` 标注失败发生在哪一端角色（sender/receiver），detail 说明具体操作。
    #[error("transfer session failed ({role}): {detail}")]
    TransferSession { role: &'static str, detail: String },

    /// 对端违反传输协议（帧序错乱、数据块越界、版本不识别等）
    #[error("transfer protocol violation ({role}): {detail}")]
    TransferProtocol { role: &'static str, detail: String },

    // ==================== 共享目录（issue 07）====================

    /// 读取共享目录注册表文件失败（IO 层）
    #[error("read shared dirs file failed: {path}: {source}")]
    SharedDirsRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 共享目录注册表文件不是合法 JSON——文件损坏，快速失败而非静默清空
    /// （静默重建等于「重启即停止暴露」，暴露面语义回退不可接受）
    #[error("parse shared dirs file as JSON failed (file corrupted): {path}: {source}")]
    SharedDirsParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// 序列化共享目录注册表到 JSON 失败
    #[error("serialize shared dirs to JSON failed: {source}")]
    SharedDirsSerialize {
        #[source]
        source: serde_json::Error,
    },

    /// 写入共享目录注册表临时文件失败（原子写第一步）
    #[error("write shared dirs temp file failed: {path}: {source}")]
    SharedDirsWriteTemp {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 临时文件替换正式文件失败（原子写第二步）
    #[error("atomic rename of shared dirs file failed: {from} -> {to}: {source}")]
    SharedDirsRename {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // ==================== mDNS 发现（ticket 03）====================

    /// 启动发现守护时节点未挂载在线缓存（宿主编排错误，非运行态故障）
    #[error("start discovery daemon requires a DiscoveryCache attached via PeerNetNode::with_discovery")]
    DiscoveryNotAttached,

    /// 创建 mDNS 守护进程失败（ServiceDaemon::new）
    #[error("create mDNS service daemon failed: {source}")]
    MdnsDaemon {
        #[source]
        source: mdns_sd::Error,
    },

    /// 构造本节点 mDNS 服务信息失败（TXT 载荷/服务名本地校验层）
    #[error("build mDNS service info for announcement failed: {source}")]
    MdnsServiceInfo {
        #[source]
        source: mdns_sd::Error,
    },

    /// 注册自身广播失败（register_service）
    #[error("register peer-net mDNS service failed: {source}")]
    MdnsRegister {
        #[source]
        source: mdns_sd::Error,
    },

    /// 优雅关停时注销自身广播失败（unregister）
    #[error("unregister peer-net mDNS service failed: {source}")]
    MdnsUnregister {
        #[source]
        source: mdns_sd::Error,
    },

    /// 优雅关停时关闭 mDNS 守护线程失败（shutdown）
    #[error("shutdown mDNS service daemon failed: {source}")]
    MdnsShutdown {
        #[source]
        source: mdns_sd::Error,
    },
}
