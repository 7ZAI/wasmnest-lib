//! 服务器端口层的总线消息 wire 契约（自持副本）
//!
//! ## 为什么自持（能力域脱绑 P5，2026-10-08）
//!
//! 本 crate 是 server 各面的**叶子地基**（能力域与宿主壳经它取端口 traits）。
//! [`crate::ports::BusMessageHandler`] 的载荷形状原先直连桌面 SDK
//! （`wasmnest-plugin-api` 的 `BusMessage`），使地基 crate 携带桌面 SDK 依赖，
//! 全部下游（能力域 / 传输面）都被迫传递性见到 SDK。P5 常量下沉后改为
//! **本 crate 自持副本**：地基与各能力域默认形态零桌面 SDK 依赖，
//! 任何宿主可直接引用。
//!
//! 桌面 SDK 原定义**不删除**（另有消费方：wasm-core 总线内部流转、WIT guest 面），
//! 副本与原版逐字一致由平台仓漂移锁钉死（三仓拆分 L2/E2b 票 08 迁出本 crate：
//! `cross-end-tests/tests/wire_drift_locks.rs`）：任一侧漂移即红。
//! 双类型在 `wasm-core` 的 `WasmHandlerAdapter` 桥接点做值转换（形状一致由本锁保证）。
//!
//! 注意：本模块定义块与桌面 SDK **逐字一致**（漂移锁按行级比对），
//! 本地说明一律写在本模块文档里，不要改动定义块内注释。

/// 消息总线消息
///
/// 插件间通信的统一消息封装，通过 Topic 消息总线传递
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BusMessage {
    /// 消息主题（格式：domain:action，如 task:status-changed）
    pub topic: String,
    /// 发送者插件 ID
    pub sender: String,
    /// 消息负载（任意 JSON）——二进制消息此字段恒为 Null
    pub payload: serde_json::Value,
    /// 二进制负载（v11，仅 `publish-binary` 消息）：零 JSON 编解码，
    /// 可传非 UTF-8 字节与大载荷（MB 级）；JSON 消息此字段为 None。
    /// 消费方以 `payload_binary.is_some()` 区分载荷格式
    #[serde(default)]
    pub payload_binary: Option<Vec<u8>>,
    /// 时间戳（毫秒 Unix）
    pub timestamp: u64,
}
