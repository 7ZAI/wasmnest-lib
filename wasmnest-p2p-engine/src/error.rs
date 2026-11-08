//! 引擎错误：fail-visible——每个变体点名成因，不静默降级。

/// 引擎操作错误
#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    /// swarm 构建失败（传输升级 / 行为装配）——配置期错误，重试无意义
    #[error("swarm 构建失败：{0}")]
    Build(String),
    /// 监听地址绑定失败（端口被占等）——调用方应换端口或排查占用
    #[error("监听失败：{0}")]
    Listen(String),
    /// 拨号失败（地址不可达 / 握手失败等）
    #[error("拨号失败：{0}")]
    Dial(String),
    /// 拨号超时：超时窗口内未完成握手与 node_id 校验（窗口见 engine 模块常量）
    #[error("拨号超时：窗口内未完成握手与 node_id 校验")]
    DialTimeout,
    /// 对端 node_id 与期望不符（指纹即身份红线：立即断开并显性报错）
    #[error("对端 node_id 不匹配：期望 {expected}，实得 {actual}")]
    NodeIdMismatch {
        /// 拨号时调用方声明的期望 node_id
        expected: String,
        /// 从对端 PeerId 公钥重算出的实际 node_id
        actual: String,
    },
    /// 对端身份密钥类型不支持——本引擎只接受 ed25519（node_id 派生的前提）
    #[error("对端身份不支持：{0}（只接受 ed25519 身份密钥）")]
    UnsupportedPeerIdentity(String),
    /// node_id 字符串非法（须 64 位小写 hex——SHA-256 输出的 hex 形）
    #[error("node_id 非法（须 64 位小写 hex）：{0}")]
    InvalidNodeId(String),
    /// 身份种子非法（长度非 32 字节等）
    #[error("身份种子非法：{0}")]
    InvalidSeed(String),
    /// 引擎已关停（节点已 shutdown，句柄不再可用）
    #[error("引擎已关停")]
    NotRunning,
    /// 目标 node_id 当前没有存活链路（未拨号或已断开）
    #[error("对端未连接：{0}（先 dial 或确认链路存活）")]
    NotConnected(String),
    /// 对端链路未达准入（pending / denied）——业务流不可用
    #[error("对端未准入：{0}（等待首连确认或已拒绝）")]
    NotAdmitted(String),
    /// 流协议已注册过（同一协议名只能有一份接收器）
    #[error("流协议已注册：{0}（drop 旧 IncomingStreams 再重新注册）")]
    ProtocolRegistered(String),
    /// 开流失败（协议协商失败 / 连接已断）
    #[error("开流失败（{protocol}）：{detail}")]
    Stream {
        /// 协议名
        protocol: String,
        /// 失败明细
        detail: String,
    },
    /// 开流超时（对端未接受该协议）
    #[error("开流超时（{0}）：窗口内未完成协议协商")]
    StreamTimeout(String),
    /// relay 地址 / 预留操作失败（成因点名，含地址形状与失败原因）
    #[error("relay 操作失败：{0}")]
    Relay(String),
    /// relay 端点 PeerId 与钉住值不一致（安全红线：拒绝同址不同身份替换）
    #[error("relay 身份不匹配：期望 {expected}，实得 {actual}（拒绝同 IP 不同 PeerId 替换）")]
    RelayPeerMismatch {
        /// 调用方钉住的 relay PeerId
        expected: String,
        /// 地址里实际携带的 PeerId
        actual: String,
    },
    /// 本构建未启用 `relay` feature（宿主需显式开启；不做静默降级）
    #[error("relay 未启用：本构建未编译 relay feature（宿主显式开启后重试）")]
    RelayDisabled,
    /// 多地址拨号全部候选失败（逐个成因汇总，便于定位 LAN/relay 哪条路不通）
    #[error("全部候选地址拨号失败（{attempts} 个）：{detail}")]
    DialAllFailed {
        /// 尝试过的候选数
        attempts: usize,
        /// 逐候选失败成因（`addr => cause`，分号分隔）
        detail: String,
    },
}
