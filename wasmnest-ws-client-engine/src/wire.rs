//! WS 出站连接能力域的 wire 契约词汇（自持副本）
//!
//! ## 为什么自持（引擎抽根，2026-10-09）
//!
//! 能力域默认形态 = 纯引擎机制 + 端口抽象（零 WIT 依赖），任何宿主可直接引用。本域
//! 原先在移动端 fork crate 里直连移动 SDK（`wasmnest_plugin_api_mobile`）的 wire 词汇，
//! 抽根后改为**本域自持副本**：
//!
//! - 状态事件名（`ws:open` / `ws:error` / `ws:close` / `ws:reconnect-scheduled`）与
//!   属主私有 topic 拼法（`<plugin-id>:ws:<event>`，即 `<owner>:<event>`）；
//! - 入站帧信封的 kind 常量与头长（`kind(1) + handle 长度 u16 BE(2)`）；
//! - 权限字面量 `ws:client`（拒绝文案 `permission denied: ws:client` 的组成部分）。
//!
//! 都是纯 wire 契约（事件名 / 命名空间形状 / 字节布局），不携带宿主机制——移进本 crate
//! 不改变任何依赖方向。**插件的消费面**（`parse_ws_frame` / `WsIncomingFrame` / `HostWs`
//! trait / topic 助手）仍住在移动 SDK `host/ws.rs`，本 crate 与它逐字一致由
//! 平台仓漂移锁钉死（三仓拆分 L2/E2b 票 08 迁出本 crate：
//! `cross-end-tests/tests/wire_drift_locks.rs`）：任一侧漂移即红。
//!
//! 注意：下方**事件名常量块**与 **topic 助手块**的注释与移动 SDK **逐字一致**
//! （漂移锁按文本块比对），本地说明一律写在本模块文档与块之间，不要改动块内注释。

// ==================== 状态事件 topic（属主私有命名空间，勿手拼） ====================

// 以下常量块至 topic 助手块与移动 SDK `host/ws.rs` 逐字一致（漂移锁提取
// 「/// 连接建立（客户端域）」至「/// 生成属主私有状态事件 topic」之间的文本块比对，
// 不要改动块内任何字符——含注释）。

/// 连接建立（客户端域）
pub const WS_OPEN: &str = "ws:open";
/// 连接错误（客户端域）
pub const WS_ERROR: &str = "ws:error";
/// 连接关闭（客户端域）
pub const WS_CLOSE: &str = "ws:close";
/// 重连退避排期（客户端域，ABI v15：config 声明 `auto-reconnect` 时宿主在
/// 每轮退避前发布）payload `{ handle, retryInMs }`（handle 为旧句柄）
pub const WS_RECONNECT_SCHEDULED: &str = "ws:reconnect-scheduled";

/// 生成属主私有状态事件 topic：`<plugin-id>:ws:<event>`
///
/// `plugin_id` 必须传本插件 ID。`event` 用本模块的 `WS_*` 常量——手拼易错，
/// 而拼错的后果是「订阅了却永远收不到」（漏订阅不报错，只静默丢事件）。
pub fn ws_event_topic(event: &str, plugin_id: &str) -> String {
    format!("{plugin_id}:{event}")
}

/// 二进制帧 topic 后缀（属主私有；经 `host-bus` 的 `subscribe-binary` 订阅）
pub const WS_MESSAGE: &str = "ws:message";

/// 生成属主私有帧 topic：`<plugin-id>:ws:message`
pub fn ws_message_topic(plugin_id: &str) -> String {
    ws_event_topic(WS_MESSAGE, plugin_id)
}

// ==================== 帧信封（宿主 → 插件的入站帧） ====================

/// 帧类型：文本
pub const WS_FRAME_KIND_TEXT: u8 = 1;
/// 帧类型：二进制
pub const WS_FRAME_KIND_BINARY: u8 = 2;

/// 帧信封头部长度：`kind(1) + handle 长度 u16 BE(2)`
pub const WS_FRAME_HEADER_LEN: usize = 3;

// 以上三个常量与移动 SDK `host/ws.rs` 同形（漂移锁行级比对；SDK 侧另有
// `parse_ws_frame` / `WsIncomingFrame` 解析面——那是插件消费面，不随引擎抽根）。

// ==================== 权限字面量 ====================

/// 出站连接权限位（fail-closed：未在 manifest 声明即拒）
///
/// 拒绝文案 `permission denied: ws:client` 由本 crate 的 [`crate::engine`] 统一生成；
/// 值本身与移动 SDK `permission.rs::PERMISSION_WS_CLIENT` 逐字一致（漂移锁钉死）。
pub const PERMISSION_WS_CLIENT: &str = "ws:client";
