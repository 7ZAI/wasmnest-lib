//! host-websocket 能力域 —— WS 基础能力服务（ABI v14）
//!
//! spec：`.scratch/2026-09-18-ws-base-service/spec.md`；票据 04（客户端域闭环）；
//! wasm-core-lib-split 票 04（自宿主 `src-tauri/src/plugin/ws.rs` 整体迁入本 crate）。
//!
//! **零业务代码红线（D1）**：本模块只做引擎原语——连接生命周期、帧收发、句柄
//! 登记、属主仲裁、按属主回收、事件定向投递；不拼装、不解读任何业务字段
//! （消息格式 / 房间 / 协议 / 重连策略一律由插件构造编排）。
//!
//! - **客户端域（出站）**：`LazyLock` 全局连接表（每条带 `owner`），复用
//!   `tokio-tungstenite 0.24`。`connect` 同步阻塞至握手完成（ABI v14 D4），
//!   成功返回句柄并发布 `<owner>::ws:open`，失败只回 Err 不发事件；
//!   **不自动重连**（编排归插件）；**不启用 TLS**（`wss://` 显式拒绝，D7）；
//! - **服务端域（入站）**：插件在宿主 WS 服务器上挂载端点（`/ws/plugin/<owner>/<path>`，
//!   spec D5）。端点表见 [`crate::endpoint`]，连接侧通道见 [`crate::channel::plugin`]——
//!   宿主只做引擎级动作（命名空间注入、认证策略执行、帧转发、按属主回收），
//!   **业务语义完全归插件**；
//! - **事件**：状态事件走消息总线属主私有 topic（票 05 命名空间）
//!   （`<owner>::ws:open|error|close`、`<owner>::ws:client-connect|client-disconnect`，
//!   标识在 payload；非属主订阅被总线门禁拒绝）；消息帧经可选导出 `events-ws` 回调，未导出则丢弃 +
//!   首次 `warn!` + 计数（宿主不缓存，spec §2.2）；
//! - **回收**：插件停用 → [`purge_for_plugin`] 关闭并摘除其全部出站连接与入站端点
//!   （只碰本人）。
//!
//! ## 分层
//!
//! ```text
//!   本文件        机制 + 客户端 WIT 接线（5 条客户端原语的 Host 实现 + 能力模块自报；
//!                 服务端 10 条原语保留为引擎 API，Host impl 在桌面宿主 plugin/ws.rs）
//!   ports.rs      边界：宿主能力端口（权限门 / 事件发布 / 总线端口 / 帧投递 / 异步桥）
//! ```
//!
//! 宿主侧只剩一个 adapter（`src-tauri/src/plugin/ws.rs`）与一次开机装配调用。
//!
//! **脱绑（能力域脱绑 P3）**：本文件混住机制面与 WIT 绑定层。机制面（连接表 /
//! 端点原语 / 帧投递 / 回收 / 装配入口）默认编译，任何宿主可用；WIT 绑定层
//! （`bindgen!` / `HostModule` / `inventory::submit!` / `impl Host`）以
//! `#[cfg(feature = "common-host")]` 门控——桌面宿主开 feature 后行为逐字不变
//! （ABI / WIT / 权限位 / 事件形状 / inventory 注册零变化），无 feature 的宿主
//! （移动端 / 无头）拿纯引擎。wire 词汇（权限位 / 事件名 / topic 构造 /
//! `EndpointAuth`）改自持副本（[`crate::wire`] + 漂移锁），本 crate 零桌面 SDK
//! 直接依赖。

// 绑定层专属依赖（`HostModule` 装配 + wasmtime `Linker`）：只随 `common-host`
// feature 进编译图——无 feature 的宿主（移动端 / 无头）拿纯引擎，不装配 WIT 绑定层。
use crate::wire::{owned_topic, PERMISSION_WS_CLIENT, PERMISSION_WS_SERVER, WS_CLOSE, WS_ERROR, WS_OPEN};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
#[cfg(feature = "common-host")]
use wasmnest_host_kit::{HostModule, HostModuleDesc, ModuleEntry, WasmPluginState};
use wasmnest_server_base::constants::{
    PLUGIN_WS_CONNECT_TIMEOUT_SECS, PLUGIN_WS_ENDPOINT_PATH_MAX_LEN, PLUGIN_WS_MAX_CONNS_PER_PLUGIN,
    PLUGIN_WS_MAX_MESSAGE_BYTES, PLUGIN_WS_SEND_QUEUE_CAPACITY,
};
use wasmnest_server_base::error_boundary::spawn_with_error_boundary;
#[cfg(feature = "common-host")]
use wasmtime::component::{bindgen, Linker};

use crate::endpoint::EndpointAuth;
use crate::plugin_binding::ports::{block_on, FrameDispatch, WsFrameTarget, WsPorts};
use crate::registry::WsSessionRegistry;

/// 宿主能力端口（边界层；见 [`ports`] 模块文档）
pub mod ports;

/// 连接状态：握手完成且未关闭
const STATE_OPEN: u8 = 1;
/// 连接已关闭（对端 Close / 传输错误 / 宿主回收）
const STATE_CLOSED: u8 = 0;

/// 非属主操作的统一拒绝文案（属主仲裁，spec §2.3）
const NOT_OWNER: &str = "not owner of ws handle";

/// 非属主端点的统一拒绝文案（服务端域属主仲裁）
const NOT_ENDPOINT_OWNER: &str = "not owner of ws endpoint";

fn denied_client() -> String {
    "permission denied: ws:client".to_string()
}

fn denied_server() -> String {
    "permission denied: ws:server".to_string()
}

// ==================== 连接表 ====================

/// 出站帧（插件 → 对端）：经有界队列交写任务，队列满即 fail-visible 拒绝
enum OutboundFrame {
    Text(String),
    Binary(Vec<u8>),
    Close { code: u16, reason: String },
}

/// 单条出站连接
struct ClientEntry {
    /// 属主插件（停用时按属主回收；跨插件调用一律拒绝）
    owner: String,
    /// 连接 URL（审计/排障可见；不含凭据，域内不做业务解读）
    #[allow(dead_code)]
    url: String,
    /// 有界发送队列（`try_send` 立即判定，满 → `ws send queue full`）
    tx: mpsc::Sender<OutboundFrame>,
    /// 连接状态（`is-connected` 事实源）
    state: Arc<AtomicU8>,
    /// 读任务（帧回灌 + 关闭事件上报）
    ///
    /// 端口不在表内：读任务在 `connect` 时就克隆了一份自己持有（它要活到连接关闭
    /// 之后，不依赖表条目）。本字段供测试用例 abort（清理），域内不消费。
    #[allow(dead_code)]
    reader: tokio::task::JoinHandle<()>,
    /// 写任务（发送队列 → 对端）
    writer: tokio::task::JoinHandle<()>,
}

/// 全局连接表（句柄 → 连接；句柄带 owner，回收只碰本人）
static CLIENTS: LazyLock<Mutex<HashMap<String, ClientEntry>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// 未导出 `events-ws` 的插件被丢弃的消息帧计数（core-monitor 之外的本地可见性）
static WS_FRAMES_DROPPED: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// 已就「未导出 events-ws」告警过的插件（首次 warn，后续 debug，防刷屏）
static WS_DROP_WARNED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

// ==================== 配置 ====================

/// `connect` 的 config-json 契约（纯引擎参数，camelCase）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectConfig {
    url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(default)]
    connect_timeout_secs: Option<u64>,
    #[serde(default)]
    max_message_bytes: Option<usize>,
}

/// `close` / `close-client` 的 close-json 契约（code 缺省由调用域决定）
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseConfig {
    #[serde(default)]
    code: Option<u16>,
    #[serde(default)]
    reason: Option<String>,
}

/// 插件端点注册 config-json 契约（服务端域；本票只做形状校验的预留定义）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndpointConfig {
    path: String,
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    max_message_bytes: Option<usize>,
    #[serde(default)]
    max_clients: Option<usize>,
}

// ==================== 客户端域原语 ====================

/// 建立出站 WS 连接（同步阻塞至握手完成，spec D4）
///
/// 成功 → 返回句柄 `wsc-<uuid>` 并发布 `<owner>::ws:open`；
/// 失败 → 错误上抛且**不发布任何事件**（无句柄可寻址）
pub fn ws_connect(ports: &Arc<dyn WsPorts>, plugin_id: &str, config_json: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_CLIENT, "host_websocket_connect") {
        return Err(denied_client());
    }
    let config: ConnectConfig =
        serde_json::from_str(config_json).map_err(|e| format!("ws connect: invalid config: {e}"))?;
    let url = config.url.trim().to_string();
    if url.is_empty() {
        return Err("ws connect: url must not be empty".to_string());
    }
    // D7：本期仅 ws://——tokio-tungstenite 0.24 未启用任何 TLS feature，
    // 接受 wss:// 会以「握手失败」掩盖真实原因，故在此显式拒绝并提示
    if !url.starts_with("ws://") {
        return Err(format!(
            "ws connect: url scheme not supported ({}); only ws:// is available in this version (wss:// is not implemented yet)",
            url
        ));
    }
    // 连接数上限（spec §4.4）：超限直接 Err，不产生任何副作用
    //
    // 首检是廉价快路；**插入时锁内复查**（H-07）兜住握手窗口的并发——
    // 表锁读数→放锁→阻塞握手→再插入 的窗口里，同插件并行 ws_connect 可
    // 全部通过首检；复查把并发超限挡在插入前（超额连接直接关，不占配额槽）。
    let owned = {
        let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        table.values().filter(|e| e.owner == plugin_id).count()
    };
    if owned >= PLUGIN_WS_MAX_CONNS_PER_PLUGIN {
        return Err(format!(
            "ws connect: connection limit reached ({PLUGIN_WS_MAX_CONNS_PER_PLUGIN})"
        ));
    }

    // 请求构造：url + 插件自定 headers / subprotocols（宿主不解读任何业务头）
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| format!("ws connect: invalid url: {e}"))?;
    for (name, value) in &config.headers {
        let header = tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| format!("ws connect: invalid header name '{name}': {e}"))?;
        let value = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(value)
            .map_err(|e| format!("ws connect: invalid header value for '{name}': {e}"))?;
        request.headers_mut().insert(header, value);
    }
    if !config.protocols.is_empty() {
        let joined = config.protocols.join(", ");
        let value = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&joined)
            .map_err(|e| format!("ws connect: invalid protocols: {e}"))?;
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
            value,
        );
    }

    // 超时上限截断为常量（spec §4.4「上限截断为常量」）
    let timeout_secs = config
        .connect_timeout_secs
        .unwrap_or(PLUGIN_WS_CONNECT_TIMEOUT_SECS)
        .clamp(1, PLUGIN_WS_CONNECT_TIMEOUT_SECS);
    let limit = max_message_bytes()
        .min(config.max_message_bytes.unwrap_or(usize::MAX))
        .max(1);
    let ws_config = WebSocketConfig {
        max_message_size: Some(limit),
        max_frame_size: Some(limit),
        ..WebSocketConfig::default()
    };

    // 同步阻塞至握手完成（与 host-http 非流式模式同一 block_on 桥）
    let (stream, response) = block_on(ports, async move {
        tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false),
        )
        .await
    })
    .map_err(|_| format!("ws connect: handshake timed out after {timeout_secs}s"))?
    .map_err(|e| format!("ws connect: handshake failed: {e}"))?;

    // 子协议回执（协商结果回传插件；缺失则省略字段）
    let protocol = response
        .headers()
        .get(tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let handle = format!("wsc-{}", uuid::Uuid::new_v4());
    let owner = plugin_id.to_string();
    let state = Arc::new(AtomicU8::new(STATE_OPEN));
    let (tx, rx) = mpsc::channel(PLUGIN_WS_SEND_QUEUE_CAPACITY);
    let (write, read) = stream.split();
    let writer = spawn_with_error_boundary("ws_client_writer", run_writer(write, rx));
    let reader = spawn_with_error_boundary(
        "ws_client_reader",
        run_reader(
            read,
            handle.clone(),
            owner.clone(),
            Arc::clone(&state),
            Arc::clone(ports),
        ),
    );

    let entry = ClientEntry {
        owner: owner.clone(),
        url: url.clone(),
        tx,
        state,
        reader,
        writer,
    };
    {
        let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        // 插入前锁内复查上限（H-07）：握手窗口里并发连接可能都通过了首检，
        // 超额者在此拒绝并关闭（writer 中止 + entry 随作用域 drop → rx 关闭）
        let owned_now = table.values().filter(|e| e.owner == owner).count();
        if owned_now >= PLUGIN_WS_MAX_CONNS_PER_PLUGIN {
            drop(table);
            tracing::warn!(
                plugin_id = %owner,
                "ws connect: connection limit reached at insert (concurrent connects), closing excess connection"
            );
            entry.writer.abort();
            return Err(format!(
                "ws connect: connection limit reached ({PLUGIN_WS_MAX_CONNS_PER_PLUGIN})"
            ));
        }
        table.insert(handle.clone(), entry);
    }

    // 成功才发 open 事件（失败路径零事件，D4）；发布先于返回值到达插件
    let mut payload = serde_json::json!({ "handle": handle, "url": url });
    if let Some(protocol) = protocol {
        payload["protocol"] = serde_json::Value::String(protocol);
    }
    publish_ws(ports, &owned_topic(&owner, WS_OPEN), payload);
    tracing::info!(plugin_id = %owner, handle = %handle, "ws client connection opened");
    Ok(handle)
}

/// 发送文本帧（UTF-8）
pub fn ws_send_text(ports: &Arc<dyn WsPorts>, plugin_id: &str, handle: &str, text: &str) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_CLIENT, "host_websocket_send_text") {
        return Err(denied_client());
    }
    enqueue(plugin_id, handle, OutboundFrame::Text(text.to_string()))
}

/// 发送二进制帧
pub fn ws_send_binary(ports: &Arc<dyn WsPorts>, plugin_id: &str, handle: &str, payload: &[u8]) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_CLIENT, "host_websocket_send_binary") {
        return Err(denied_client());
    }
    enqueue(plugin_id, handle, OutboundFrame::Binary(payload.to_vec()))
}

/// 主动关闭连接：返回是否命中（幂等：未知句柄 false）
///
/// 关闭命令入队后由写任务发出 Close 帧并结束；对端回 Close → 读任务上报
/// `<owner>::ws:close`（`wasClean` 按对端回帧 code 判定，spec D11）
pub fn ws_close(ports: &Arc<dyn WsPorts>, plugin_id: &str, handle: &str, close_json: &str) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_CLIENT, "host_websocket_close") {
        return Err(denied_client());
    }
    let close: CloseConfig =
        serde_json::from_str(close_json).map_err(|e| format!("ws close: invalid close-json: {e}"))?;
    let code = close.code.unwrap_or(1000);
    let reason = close.reason.unwrap_or_default();

    let entry = {
        let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = table.remove(handle) else {
            return Ok(false);
        };
        if entry.owner != plugin_id {
            table.insert(handle.to_string(), entry);
            return Err(NOT_OWNER.to_string());
        }
        entry
    };
    match entry.tx.try_send(OutboundFrame::Close { code, reason }) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // 写任务已退出（对端先断）：句柄已摘除，语义等同关闭完成
            tracing::debug!(plugin_id = %plugin_id, handle = %handle, "ws close: writer already finished");
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            // 发送队列满（H-01）：Close 帧无法入队——静默丢弃会让连接永不关闭
            //（writer 卡在积压帧的 send 上）。强制中止写任务：写半段立即释放，
            // 对端收到 EOF；读任务继续读到对端关闭并上报 close（wasClean=false）
            tracing::warn!(
                plugin_id = %plugin_id,
                handle = %handle,
                "ws close: send queue full, aborting writer to force close"
            );
            entry.writer.abort();
        }
    }
    Ok(true)
}

/// 查询连接是否处于 open 态（握手完成且未关闭）；仅属主可查
pub fn ws_is_connected(ports: &Arc<dyn WsPorts>, plugin_id: &str, handle: &str) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_CLIENT, "host_websocket_is_connected") {
        return Err(denied_client());
    }
    let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    match table.get(handle) {
        Some(entry) if entry.owner == plugin_id => Ok(entry.state.load(Ordering::SeqCst) == STATE_OPEN),
        Some(_) => Err(NOT_OWNER.to_string()),
        None => Ok(false),
    }
}

/// 入队出站帧（fail-visible：队列满 / 连接已关闭立即返回明确错误，D10）
///
/// 入队前检查连接状态（H-06）：peer 已关闭（state→CLOSED）后仍返回 Ok 会让
/// 插件以为帧已排队（实际无法投递，还占着队列与配额槽）；CLOSED 连接在此直接
/// 拒绝。
fn enqueue(plugin_id: &str, handle: &str, frame: OutboundFrame) -> Result<(), String> {
    let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(entry) = table.get(handle) else {
        return Err(format!("ws connection not found: {handle}"));
    };
    if entry.owner != plugin_id {
        return Err(NOT_OWNER.to_string());
    }
    if entry.state.load(Ordering::SeqCst) != STATE_OPEN {
        return Err(format!("ws connection is closed: {handle}"));
    }
    match entry.tx.try_send(frame) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err("ws send queue full".to_string()),
        Err(mpsc::error::TrySendError::Closed(_)) => Err("ws connection is closed".to_string()),
    }
}

// ==================== 服务端域原语（插件入站端点，spec §2.4 / 票据 05） ====================
//
// 宿主只做引擎级动作：路径命名空间注入、认证策略执行、帧转发、按属主回收。
// 业务语义（消息格式 / 房间 / 协议 / 重连策略）完全归插件（D1）。

/// 端点域属主仲裁：未注册 / 非属主 → `Err`（跨插件不可互操作）
fn owned_endpoint(endpoint_id: &str, plugin_id: &str) -> Result<crate::endpoint::EndpointEntry, String> {
    match crate::endpoint::get(endpoint_id) {
        Some(entry) if entry.owner == plugin_id => Ok(entry),
        Some(_) => Err(NOT_ENDPOINT_OWNER.to_string()),
        None => Err(format!("ws endpoint not found: {endpoint_id}")),
    }
}

/// 注册插件端点（`/ws/plugin/<plugin-id>/<path>`，命名空间段由宿主注入，D5）
///
/// 校验顺序：权限门 → 形状校验（空 / 含 `/` / 含 `.` / 超长）→ 认证策略解析
/// → 端点数上限与同插件冲突（失败零副作用）。返回端点句柄 `wse-<uuid>`；
/// 完整挂载路径 = [`wasmnest_server_websocket::endpoint::mount_path`]（插件侧可推导）。
pub fn ws_register_endpoint(ports: &Arc<dyn WsPorts>, plugin_id: &str, config_json: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_register_endpoint") {
        return Err(denied_server());
    }
    let config: EndpointConfig =
        serde_json::from_str(config_json).map_err(|e| format!("ws register-endpoint: invalid config: {e}"))?;
    let path = config.path.trim();
    if path.is_empty() {
        return Err("ws register-endpoint: path must not be empty".to_string());
    }
    if path.contains('/') || path.contains('.') {
        return Err("ws register-endpoint: path must not contain '/' or '.'".to_string());
    }
    if path.chars().count() > PLUGIN_WS_ENDPOINT_PATH_MAX_LEN {
        return Err(format!(
            "ws register-endpoint: path too long (max {})",
            PLUGIN_WS_ENDPOINT_PATH_MAX_LEN
        ));
    }
    // 缺省档 = none（WS 历史行为）；未定义取值报错，绝不静默降级为较宽档位
    let auth = EndpointAuth::parse_with(config.auth.as_deref(), EndpointAuth::None)
        .map_err(|e| format!("ws register-endpoint: {e}"))?;

    let entry = crate::endpoint::register(
        plugin_id,
        path,
        auth,
        config.max_clients,
        config.max_message_bytes,
        ports.bus_port(),
    )?;
    Ok(entry.endpoint_id)
}

/// 向端点指定客户端发文本帧
///
/// 客户端不在该端点名下 → `Err`（错配寻址 fail-visible，不静默丢弃）；
/// 出站帧由接收连接的通道过滤链处理（`TrafficChannel::WsPlugin`）
pub fn ws_send_text_to_client(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    endpoint_id: &str,
    client_id: &str,
    text: &str,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_send_text_to_client") {
        return Err(denied_server());
    }
    owned_endpoint(endpoint_id, plugin_id)?;
    let endpoint = endpoint_id.to_string();
    let client = client_id.to_string();
    let text = text.to_string();
    block_on(ports, async move {
        WsSessionRegistry::global()
            .send_to_endpoint_client(&endpoint, &client, text)
            .await
    })
}

/// 向端点指定客户端发二进制帧
pub fn ws_send_binary_to_client(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    endpoint_id: &str,
    client_id: &str,
    payload: &[u8],
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_send_binary_to_client") {
        return Err(denied_server());
    }
    owned_endpoint(endpoint_id, plugin_id)?;
    let endpoint = endpoint_id.to_string();
    let client = client_id.to_string();
    let payload = payload.to_vec();
    block_on(ports, async move {
        WsSessionRegistry::global()
            .send_binary_to_endpoint_client(&endpoint, &client, payload)
            .await
    })
}

/// 向端点全部客户端广播文本帧 → 成功入队客户端数
///
/// 部分失败不回滚（失败明细记 debug，成功数供调用方判定，spec D10）
pub fn ws_broadcast_text(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    endpoint_id: &str,
    text: &str,
) -> Result<u32, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_broadcast_text") {
        return Err(denied_server());
    }
    owned_endpoint(endpoint_id, plugin_id)?;
    let endpoint = endpoint_id.to_string();
    let text = text.to_string();
    let sent = block_on(ports, async move {
        WsSessionRegistry::global().broadcast_to_endpoint(&endpoint, text).await
    });
    Ok(sent as u32)
}

/// 向端点全部客户端广播二进制帧 → 成功入队客户端数
pub fn ws_broadcast_binary(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    endpoint_id: &str,
    payload: &[u8],
) -> Result<u32, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_broadcast_binary") {
        return Err(denied_server());
    }
    owned_endpoint(endpoint_id, plugin_id)?;
    let endpoint = endpoint_id.to_string();
    let payload = payload.to_vec();
    let sent = block_on(ports, async move {
        WsSessionRegistry::global()
            .broadcast_binary_to_endpoint(&endpoint, payload)
            .await
    });
    Ok(sent as u32)
}

/// 踢出端点指定客户端（close-json：`{ code?, reason? }`，缺省 4004）
///
/// 返回是否命中（客户端不在该端点名下 → `false`，幂等不 panic）；
/// 对端随后收到 `client-disconnect` 事件（宿主主动断开，`wasClean = false`）
pub fn ws_close_client(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    endpoint_id: &str,
    client_id: &str,
    close_json: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_close_client") {
        return Err(denied_server());
    }
    owned_endpoint(endpoint_id, plugin_id)?;
    let close: CloseConfig =
        serde_json::from_str(close_json).map_err(|e| format!("ws close-client: invalid close-json: {e}"))?;
    // 踢出缺省 4004（spec §4.5 关闭理由语义）
    let code = close.code.unwrap_or(4004);
    let reason = close.reason.unwrap_or_else(|| "kicked by plugin".to_string());
    let endpoint = endpoint_id.to_string();
    let client = client_id.to_string();
    Ok(block_on(ports, async move {
        WsSessionRegistry::global()
            .disconnect_endpoint_client(&endpoint, &client, code, &reason)
            .await
    }))
}

/// 关闭端点并回收句柄（含下线全部客户端，close code 4005）
///
/// 返回是否存在该端点（未知句柄 → `Ok(false)`；他人端点 → `Err` 属主仲裁）。
/// 先摘端点再下线客户端：摘除后台的握手立即 404，不再有新客户端接入
pub fn ws_unregister_endpoint(ports: &Arc<dyn WsPorts>, plugin_id: &str, endpoint_id: &str) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_unregister_endpoint") {
        return Err(denied_server());
    }
    let Some(entry) = crate::endpoint::get(endpoint_id) else {
        return Ok(false);
    };
    if entry.owner != plugin_id {
        return Err(NOT_ENDPOINT_OWNER.to_string());
    }
    crate::endpoint::remove(endpoint_id);
    let endpoint = entry.endpoint_id.clone();
    let closed = block_on(ports, async move {
        WsSessionRegistry::global()
            .disconnect_by_endpoint(&endpoint, 4005, "endpoint unregistered")
            .await
    });
    tracing::info!(
        plugin_id = %plugin_id,
        endpoint_id = %endpoint_id,
        clients = closed,
        "plugin ws endpoint unregistered"
    );
    Ok(true)
}

/// 端点在线的客户端清单 → JSON 数组
///
/// `[{ clientId, addr, authenticated, connectedAt }]`（camelCase）——丢弃
/// `client-connect` 事件后的自愈入口（spec D3）；仅属主可查
pub fn ws_list_clients(ports: &Arc<dyn WsPorts>, plugin_id: &str, endpoint_id: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_list_clients") {
        return Err(denied_server());
    }
    owned_endpoint(endpoint_id, plugin_id)?;
    let endpoint = endpoint_id.to_string();
    let clients = block_on(ports, async move {
        WsSessionRegistry::global().list_by_endpoint(&endpoint).await
    });
    let list: Vec<serde_json::Value> = clients
        .into_iter()
        .map(|client| {
            serde_json::json!({
                "clientId": client.client_id,
                "addr": client.addr,
                "authenticated": client.authenticated,
                "connectedAt": client.connected_at,
            })
        })
        .collect();
    serde_json::to_string(&list).map_err(|e| format!("ws list-clients: serialization failed: {e}"))
}

/// 本插件已注册端点清单 → JSON 数组
///
/// `[{ endpointId, path, clientCount }]`（camelCase，按挂载路径升序稳定输出）
pub fn ws_list_endpoints(ports: &Arc<dyn WsPorts>, plugin_id: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_list_endpoints") {
        return Err(denied_server());
    }
    let entries = crate::endpoint::list_by_owner(plugin_id);
    let mut list: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
    for entry in entries {
        let endpoint = entry.endpoint_id.clone();
        let client_count = block_on(ports, async move {
            WsSessionRegistry::global().endpoint_client_count(&endpoint).await
        });
        list.push(serde_json::json!({
            "endpointId": entry.endpoint_id,
            "path": entry.path,
            "clientCount": client_count,
        }));
    }
    serde_json::to_string(&list).map_err(|e| format!("ws list-endpoints: serialization failed: {e}"))
}

/// 查询端点指定客户端的**已脱敏**连接/认证上下文（websocket 业务下沉专项票 02）
///
/// 只返回连接/认证**事实**（spec §3.1）：`clientId` / `endpointId` / `owner` /
/// `addr` / `authenticated` / `connectedAt` / `authContext?{subject, deviceName,
/// fingerprint}`。约束：
/// - 仅**端点属主**可调（权限 `ws:server` + 属主仲裁，跨插件查询显式拒绝）；
/// - 客户端不存在/不在该端点名下 → `Err`（fail-visible，不返回「成功但无数据」）；
/// - **永不返回 JWT、token、公钥、私钥或配对记录**（凭据红线，AGENTS §8——
///   本函数只组装注册表内已脱敏字段，不触碰任何凭据存储）；
/// - `auth: "none"` 连接 `authenticated=false`，`authContext` 省略（不伪造身份）。
pub fn ws_connection_context(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    endpoint_id: &str,
    client_id: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_WS_SERVER, "host_websocket_connection_context") {
        return Err(denied_server());
    }
    let entry = owned_endpoint(endpoint_id, plugin_id)?;
    let owner = entry.owner.clone();
    let endpoint = entry.endpoint_id.clone();
    let client = client_id.to_string();
    let endpoint_ctx = endpoint.clone();
    // 先验端点域寻址（跨端点错配 → 显性 Err），再取脱敏条目
    let summary = block_on(ports, async move {
        if !WsSessionRegistry::global()
            .is_endpoint_client(&endpoint_ctx, &client)
            .await
        {
            return None;
        }
        WsSessionRegistry::global().get_client(&client).await
    });
    let Some(c) = summary else {
        return Err(format!("client {client_id} not found in endpoint {endpoint_id}"));
    };
    let mut value = serde_json::json!({
        "clientId": c.client_id,
        "endpointId": endpoint,
        "owner": owner,
        "addr": c.addr,
        "authenticated": c.authenticated,
        "connectedAt": c.connected_at,
    });
    if c.authenticated {
        let mut auth = serde_json::Map::new();
        if let Some(subject) = c.subject {
            auth.insert("subject".to_string(), serde_json::Value::String(subject));
        }
        if let Some(device_name) = c.device_name {
            auth.insert("deviceName".to_string(), serde_json::Value::String(device_name));
        }
        if let Some(fingerprint) = c.fingerprint {
            auth.insert("fingerprint".to_string(), serde_json::Value::String(fingerprint));
        }
        value["authContext"] = serde_json::Value::Object(auth);
    }
    serde_json::to_string(&value).map_err(|e| format!("ws connection-context: serialization failed: {e}"))
}

// ==================== 回收 ====================

/// 回收指定插件的全部 WS 资源（插件停用/卸载时由 PluginHost 调用）
///
/// 两侧一并回收，且**只碰本人**（`owner` 比对）：
/// - 客户端域（出站连接）：close 4005 并摘除句柄；
/// - 服务端域（入站端点）：先摘端点（后续握手立即 404），再下线其全部在线
///   客户端（close 4005，spec §4.5 属主停用语义）。
///
/// 返回被回收的连接数（出站 + 入站在线客户端）
pub fn purge_for_plugin(plugin_id: &str, ports: &Arc<dyn WsPorts>) -> usize {
    let handles: Vec<String> = {
        let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        table
            .iter()
            .filter(|(_, entry)| entry.owner == plugin_id)
            .map(|(handle, _)| handle.clone())
            .collect()
    };
    let mut purged = 0;
    for handle in handles {
        if purge_one(plugin_id, &handle) {
            purged += 1;
        }
    }

    // 服务端域：端点表回收 + 其在线客户端 4005 下线
    let endpoints = crate::endpoint::purge_for_plugin(plugin_id);
    for entry in endpoints {
        let endpoint = entry.endpoint_id.clone();
        let closed = block_on(ports, async move {
            WsSessionRegistry::global()
                .disconnect_by_endpoint(&endpoint, 4005, "plugin deactivated")
                .await
        });
        purged += closed;
    }

    // 降级计数/告警标记随属主回收，避免插件重载后残留旧计数
    WS_FRAMES_DROPPED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(plugin_id);
    WS_DROP_WARNED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(plugin_id);
    if purged > 0 {
        tracing::info!(plugin_id = %plugin_id, connections = purged, "ws plugin resources purged");
    }
    purged
}

/// 摘除并关闭单条连接（属主校验；返回是否命中）
fn purge_one(owner: &str, handle: &str) -> bool {
    let entry = {
        let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = table.remove(handle) else {
            return false;
        };
        if entry.owner != owner {
            table.insert(handle.to_string(), entry);
            return false;
        }
        entry
    };
    // 属主停用回收：close code 4005（spec §4.5），wasClean=false
    match entry.tx.try_send(OutboundFrame::Close {
        code: 4005,
        reason: "plugin deactivated".to_string(),
    }) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!(handle = %handle, "ws purge: writer already finished");
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            // 队列满（H-01）：Close 帧无法入队，强制中止写任务以释放连接
            //（对端收到 EOF，读任务随后上报 close，wasClean=false）
            tracing::warn!(handle = %handle, "ws purge: send queue full, aborting writer");
            entry.writer.abort();
        }
    }
    true
}

// ==================== 读写任务 ====================

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsWrite = futures_util::stream::SplitSink<WsStream, Message>;
type WsRead = futures_util::stream::SplitStream<WsStream>;

/// 写任务：有界发送队列 → 对端；收到 Close 帧后发送并结束
async fn run_writer(mut write: WsWrite, mut rx: mpsc::Receiver<OutboundFrame>) {
    while let Some(frame) = rx.recv().await {
        let (message, is_close) = match frame {
            OutboundFrame::Text(text) => (Message::Text(text), false),
            OutboundFrame::Binary(payload) => (Message::Binary(payload), false),
            OutboundFrame::Close { code, reason } => (
                Message::Close(Some(CloseFrame {
                    code: CloseCode::from(code),
                    reason: reason.into(),
                })),
                true,
            ),
        };
        if let Err(e) = write.send(message).await {
            tracing::debug!(error = %e, "ws client write failed, closing");
            break;
        }
        if is_close {
            break;
        }
    }
    if let Err(e) = write.close().await {
        tracing::debug!(error = %e, "ws client close handshake failed");
    }
}

/// 读任务：帧回灌插件（可选导出）+ 关闭事件上报（恰好一次）
///
/// `<owner>::ws:close` 的 `wasClean` 仅当**对端主动发送 Close 帧**且 code ∈
/// {1000, 1001} 时为 true（spec D11）；异常断开 / 传输错误 → 省略 code + false。
/// 同一连接内帧按到达序投递（保序，spec §2.2 D2）
async fn run_reader(mut read: WsRead, handle: String, owner: String, state: Arc<AtomicU8>, ports: Arc<dyn WsPorts>) {
    // 关闭事件恰好一次（对端 Close 与后续收尾共用同一守卫）
    let close_reported = Arc::new(AtomicBool::new(false));
    let mut close_frame: Option<(Option<u16>, String, bool)> = None;

    while let Some(incoming) = read.next().await {
        match incoming {
            Ok(Message::Text(text)) => deliver_frame(&ports, &owner, &handle, "text", text.into_bytes()).await,
            Ok(Message::Binary(payload)) => deliver_frame(&ports, &owner, &handle, "binary", payload).await,
            Ok(Message::Close(frame)) => {
                let (code, reason) = match frame {
                    Some(f) => (Some(u16::from(f.code)), f.reason.to_string()),
                    None => (None, String::new()),
                };
                // 1006（异常关闭）等不可发送码不会出现在对端 Close 帧里；
                // 无 code 的对端 Close 视为异常断开
                close_frame = Some((code, reason.clone(), close_was_clean(code)));
                report_close(
                    &ports,
                    &owner,
                    &handle,
                    code,
                    &reason,
                    close_was_clean(code),
                    &close_reported,
                );
                break;
            }
            // 心跳与原始帧由 tungstenite 协议层处理，业务层不外泄
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
            Err(e) => {
                publish_ws(
                    &ports,
                    &owned_topic(&owner, WS_ERROR),
                    serde_json::json!({ "handle": handle, "message": e.to_string() }),
                );
                break;
            }
        }
    }

    // 先置关闭态再上报：上报后 `is-connected` 立即为 false（spec D3 同款时序）
    state.store(STATE_CLOSED, Ordering::SeqCst);
    if let Some((code, reason, clean)) = close_frame {
        // 已在 Close 分支上报过（守卫防御性再调一次，不会重复投递）
        report_close(&ports, &owner, &handle, code, &reason, clean, &close_reported);
    } else {
        // 未收到对端 Close（TCP 断 / 传输错误 / 宿主主动关）→ code 省略 + wasClean=false
        report_close(&ports, &owner, &handle, None, "", false, &close_reported);
    }
    // 摘除已关闭连接的条目（H-06）：CLOSED 条目继续占表位会让连接配额槽泄漏、
    // 后续 send 在入队检查（enqueue state 检查）前已过 owner 校验但投递无意义。
    // 摘除 drop tx → 写任务 rx 关闭 → writer 收尾 write.close()。
    // 属主校验避免误摘（handle 为 UUID 无复用，防御性保留）。
    {
        let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        if table.get(&handle).is_some_and(|e| e.owner == owner) {
            table.remove(&handle);
        }
    }
    tracing::debug!(plugin_id = %owner, handle = %handle, "ws client reader exited");
}

/// close code → `wasClean`（spec D11）：仅对端主动 Close 且 code ∈ {1000,1001} 为 true
fn close_was_clean(code: Option<u16>) -> bool {
    matches!(code, Some(1000) | Some(1001))
}

/// 上报 `<owner>::ws:close`（守卫保证每连接恰好一次）
fn report_close(
    ports: &Arc<dyn WsPorts>,
    owner: &str,
    handle: &str,
    code: Option<u16>,
    reason: &str,
    was_clean: bool,
    reported: &AtomicBool,
) {
    if reported.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut payload = serde_json::json!({ "handle": handle, "wasClean": was_clean });
    if let Some(code) = code {
        payload["code"] = serde_json::Value::Number(code.into());
    }
    if !reason.is_empty() {
        payload["reason"] = serde_json::Value::String(reason.to_string());
    }
    publish_ws(ports, &owned_topic(owner, WS_CLOSE), payload);
    tracing::info!(plugin_id = %owner, handle = %handle, was_clean, "ws client connection closed");
}

// ==================== 帧投递与事件 ====================

/// 客户端域帧投递：经宿主端口定向投给属主插件实例
async fn deliver_frame(ports: &Arc<dyn WsPorts>, plugin_id: &str, handle: &str, kind: &str, payload: Vec<u8>) {
    dispatch_frame(ports, plugin_id, WsFrameTarget::Client(handle), kind, payload).await;
}

/// 服务端域帧投递（插件端点入站帧；标识为 `endpoint_id/client_id`）
///
/// 与客户端域同源同语义（同一降级路径）：由端点通道的单条投递任务串行调用，
/// 因此**同一连接内的帧按到达序投递**（保序，spec §2.2 D2）
pub async fn deliver_endpoint_frame(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    endpoint_id: &str,
    client_id: &str,
    kind: &str,
    payload: Vec<u8>,
) {
    dispatch_frame(
        ports,
        plugin_id,
        WsFrameTarget::EndpointClient { endpoint_id, client_id },
        kind,
        payload,
    )
    .await;
}

/// 共同投递语义（客户端域 / 服务端域唯一降级路径）
///
/// 宿主投递器未注入（无头/测试的中间态）→ 仅记 debug，不计数也不 panic；
/// 插件未导出 `events-ws` → 降级（丢弃 + 首次 warn + 计数，宿主不缓存）
async fn dispatch_frame(
    ports: &Arc<dyn WsPorts>,
    plugin_id: &str,
    target: WsFrameTarget<'_>,
    kind: &str,
    payload: Vec<u8>,
) {
    let label = target.label();
    match ports.dispatch_frame(plugin_id, target, kind, payload) {
        FrameDispatch::Delivered => {}
        FrameDispatch::NotExported => record_dropped_frame(plugin_id, &label),
        FrameDispatch::Unavailable => {
            tracing::debug!(
                plugin_id = %plugin_id,
                target = %label,
                "ws frame dispatch skipped: message bus dispatcher not set"
            );
        }
        FrameDispatch::Failed(e) => {
            // trap 等投递失败由宿主统一记录并触发重载，此处只补上下文
            tracing::error!(
                plugin_id = %plugin_id,
                target = %label,
                error = %e,
                "ws frame dispatch failed"
            );
        }
    }
}

/// 未导出 `events-ws`：丢弃 + 首次 `warn!` + 计数（宿主不缓存，spec §2.2）
fn record_dropped_frame(plugin_id: &str, handle: &str) {
    let total = {
        let mut counters = WS_FRAMES_DROPPED.lock().unwrap_or_else(|e| e.into_inner());
        let counter = counters.entry(plugin_id.to_string()).or_insert(0);
        *counter += 1;
        *counter
    };
    let first = {
        let mut warned = WS_DROP_WARNED.lock().unwrap_or_else(|e| e.into_inner());
        warned.insert(plugin_id.to_string())
    };
    // 结构化字段按 AGENTS §8：plugin_id 为字段而非消息拼接
    if first {
        tracing::warn!(
            plugin_id = %plugin_id,
            handle = %handle,
            dropped_total = total,
            "ws frame dropped: plugin exports no events-ws (frames are not buffered); subscribe state events via host-bus and query snapshots for self-healing"
        );
    }
    // 后续每帧**不打日志**：这是按帧触发的丢弃路径，高频流下逐帧 debug 即风暴
    // （与 bus 投递 / fs 放行同一类）。累计量在上面的首次 warn 里带出，
    // 精确计数经 `dropped_frame_count` 读（本模块测试与排障用）。
}

/// 该插件的消息帧丢弃计数（对外诊断面；core-monitor / 排障 / 测试取用）
pub fn dropped_frame_count(plugin_id: &str) -> u64 {
    WS_FRAMES_DROPPED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(plugin_id)
        .copied()
        .unwrap_or(0)
}

/// 发布状态事件到插件消息总线（发送者 = `"host"`；订阅侧按精确 topic 分发）
///
/// 经连接持有的端口实例发送（非全局单例）：与 `deliver_frame` 同源，
/// 宿主测试可用自建端口实现直接断言属主私有 topic（`<owner>::ws:*`）
fn publish_ws(ports: &Arc<dyn WsPorts>, topic: &str, payload: serde_json::Value) {
    ports.publish(topic, payload);
}

/// 帧/消息字节上限：与移动端终端链路同一事实源；配置不可读时回退常量
///
/// 形状 `ws_frame_limit().max(1).min(PLUGIN_WS_MAX_MESSAGE_BYTES)`（H-04）：
/// 网络配置上限（可被运维调大）**不得突破** 1 MiB 平台硬上限——旧式
/// `PLUGIN_WS_MAX_MESSAGE_BYTES.min(1)` 把常量钳成 1，整式坍缩为
/// `ws_frame_limit().max(1)`，硬上限形同虚设（若 frame_limit 为 0 还退化成
/// 1 字节全拒）。与 endpoint.rs 的 hard-cap 模式对齐。
fn max_message_bytes() -> usize {
    crate::routes::ws_frame_limit().clamp(1, PLUGIN_WS_MAX_MESSAGE_BYTES)
}

// ==================== 能力模块装配（wasm-core-lib-split 票 04） ====================
//
// 宿主侧对应物：`src-tauri/src/plugin/ws.rs`（adapter + 开机装配）与
// `component.rs` 的 `HOST_MODULES` 白名单 + 强制引用行。

/// 能力模块名（宿主白名单键 = 装载期日志与错误文案里的模块名）
///
/// **常编译 pub**（票 02 批次 03）：adapter 迁宿主后白名单条目
/// （`expect_host_module!`）与装载期一致性核对改在宿主侧引用本常量。
pub const MODULE_NAME: &str = "websocket";

/// 本域提供的 WIT 接口（必须与拼装 package 逐字一致；改错即 guest import 失配）
///
/// ADR 0052 D2/D4：客户端域 `host-websocket`（双端交集）契约真源在
/// `wasmnest-ws-client-engine/wit/ws.wit`，本 crate 的 `common-host` 绑定暂留客户端实现
/// （Q4 裁决；双轨收敛另行立项）；服务端域 `host-websocket-server`（桌面扩展）的
/// WIT 声明与 `impl Host` 已归桌面宿主（本模块不再注册/声明它）。
pub const MODULE_INTERFACES: &[&str] = &["wasmnest:plugin@0.0.2/host-websocket"];

/// 本域的权限位（必须与 WIT / SDK 权限表逐字一致）
///
/// 服务端域 `ws:server` 随 `impl Host` 一同归桌面宿主模块（`ws-server`）声明。
pub const MODULE_PERMISSIONS: &[&str] = &["ws:client"];

/// 能力模块描述符（只描述机制，禁带产品名词——AGENTS §5.1 B1/B5）
#[cfg(feature = "common-host")]
const DESC: HostModuleDesc = HostModuleDesc {
    name: MODULE_NAME,
    interfaces: MODULE_INTERFACES,
    permissions: MODULE_PERMISSIONS,
    abi_min: 14,
};

/// WS 能力域模块（`host-websocket` 客户端域 5 条）
#[cfg(feature = "common-host")]
pub struct WebsocketModule;

#[cfg(feature = "common-host")]
impl HostModule for WebsocketModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        wasmnest::plugin::host_websocket::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
    }
}

/// getter：让 guest 侧 import 取到可变的状态引用（与宿主既有接线同款）
#[cfg(feature = "common-host")]
type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

/// 静态单例（供 `submit_module!` 取址）
#[cfg(feature = "common-host")]
static MODULE: WebsocketModule = WebsocketModule;

// 能力模块自报（linker-section 静态）
//
// **依赖前提**：宿主必须有一行 `use wasmnest_server_websocket as _;` 强制引用
// （见 `wasm_core::manager::runtime::component`），否则本 rlib 不进最终二进制、
// 静态不执行 ⇒ 注册丢失，且 guest 会在实例化期报「无该 import」。无
// `common-host` feature 的宿主（移动端 / 无头）**不应**注册——它没有插件宿主
// 机制，桌面侧强制引用行同步 `#[cfg(feature = "common-host")]`。
#[cfg(feature = "common-host")]
inventory::submit! {
    ModuleEntry { module: &MODULE }
}

/// 能力域名（宿主上下文里的键；[`wasmnest_host_kit::ports::HostPorts::domain_ports`]）
///
/// 纯字符串常量（无 WIT 依赖），默认可用：宿主 adapter 在 `common-host` 装配路径
/// 引用它。
pub const DOMAIN: &str = "websocket";

/// 停用期回调：回收本插件的全部 WS 资源（出站连接 + 服务端端点 + 在线客户端）
///
/// 适配器：域内 [`purge_for_plugin`] 返回回收计数（关停面要用），而钩子契约是
/// `fn(&str)`——计数对「单个插件停用」没有消费者，此处就地记 debug 日志吸收。
///
/// **端口取自进程级装配**（宿主 adapter 开机期装入；未装配即 panic —— fail-visible，
/// 与 guest 首次调本域原语同口径）。
#[cfg(feature = "common-host")]
fn on_plugin_purge(plugin_id: &str) {
    let reclaimed = purge_for_plugin(plugin_id, &ports::ports());
    tracing::debug!(
        plugin_id = %plugin_id,
        count = reclaimed,
        "host-websocket: 停用回收完成"
    );
}

/// 生命周期钩子自报（票 02 批次 01 机制，批次 03 本域接入）
///
/// 接入后内核 `manager/host/activation.rs` 不再直调本域回收入口——这是内核摘掉本域
/// adapter 的前提之一（另一处是 `bus.rs` 的帧投递窄端口，见票面「ws / http 实测」节）。
#[cfg(feature = "common-host")]
pub static HOOKS: wasmnest_host_kit::DomainHooks = wasmnest_host_kit::DomainHooks {
    name: MODULE_NAME,
    on_manifest_load: None,
    on_plugin_purge: Some(on_plugin_purge),
};

#[cfg(feature = "common-host")]
wasmnest_host_kit::submit_hooks!(HOOKS);

/// 装配端口的便捷入口（宿主开机期调用）
///
/// 纯 Rust（不依赖 `WasmPluginState`），默认可用：任何宿主持有端口实现即可装配。
pub fn install<P: WsPorts + 'static>(ports: P) {
    ports::install_ports(Arc::new(ports));
}

/// [`ports::install_ports`] 的再导出（宿主 adapter 需要直接装**已构造好的**端口对象：
/// 同一份要同时登记进程级与实例级，不能经 `install` 新建）
pub use ports::install_ports;

/// 取本插件实例该用的端口：**实例级优先**，未装配则回落到进程级装配
///
/// 为什么要两级（见 `wasmnest_host_kit::ports` 模块文档）：进程级只有一格，而一个
/// 进程可以有多份宿主上下文（无头测试每个用例一份）；实例级让端口与**本实例的**
/// 权限管理器 / 消息总线绑定，能力域代码不感知上下文数量。
///
/// 宿主注入的是 `Arc<dyn Any>` 包着的 `Arc<dyn WsPorts>`（能力域的端口类型只有
/// 能力域自己认识，kit 与宿主都不能把它裸存进表），故这里向下转型后**克隆内层
/// Arc**（同形对象，多个实例共享一份 adapter，无副作用）。
///
/// 依赖 `WasmPluginState`（host-kit 类型），随 `common-host` feature 编译。
#[cfg(feature = "common-host")]
pub fn ports_for(state: &WasmPluginState) -> Arc<dyn WsPorts> {
    match state
        .host
        .domain_ports(DOMAIN)
        .and_then(wasmnest_host_kit::ports::downcast_domain_ports::<Arc<dyn WsPorts>>)
    {
        Some(ports) => Arc::clone(&ports),
        None => ports::ports(),
    }
}

#[cfg(feature = "common-host")]
bindgen!({
    // provider 侧绑定：spec D8「能力 crate 不自带 generate!」的前提在本 crate
    // 不成立——宿主自己的 `wasmnest` 模块是 **guest 视角**（import 是调用函数，
    // 不是 `Host` trait + `add_to_linker`）。能力 crate 要自己装配就必须生成
    // provider 侧。
    //
    // ⚠️ 由此产生的**硬约束**：本 crate 与宿主各自生成的
    // `wasmnest::plugin::host_websocket::Host` 是**同名但不同类型**的 trait。宿主必须
    // 同时删掉自己的 ws `Host` impl 与 `add_to_linker` 行，否则同一个 interface
    // 被注册两次 → 装配期 `defined twice`。
    // 票 05 / ADR 0052 D2：契约面脱端——客户端域契约真源住能力域 crate
    // `wasmnest-ws-client-engine/wit/ws.wit`（world cap-ws 只 import `host-websocket`），
    // 本 crate 的 provider 侧 bindgen 直接指向它（桌面客户端实现暂留本 crate 的
    // common-host 绑定，Q4 裁决；本 crate 原有 `wit/ws.wit` 已删，不再持第二份副本）。
    // 服务端域 `host-websocket-server` 的声明在桌面 wit-src、impl 在桌面宿主。
    path: "../wasmnest-ws-client-engine/wit/ws.wit",
    world: "cap-ws",
    // 与宿主同款：全部导出绑定生成 async 变体（wasmtime async store 要求）。
    // cap-ws 无 export 成员，此配置无生效对象（实测编译绿，票 05 实施记录）
    exports: { default: async },
});

// ==================== 宿主绑定层（Host trait 实现） ====================
//
// 每个接口方法 = 一条 WIT 原语。权限门在本文件内的域函数里（随实现同迁，
// 经端口问宿主结果），此层只做「取端口 → 转调 → 按 WIT `result` 形状返回」。

#[cfg(feature = "common-host")]
impl wasmnest::plugin::host_websocket::Host for WasmPluginState {
    // ==================== 客户端域（出站） ====================

    fn connect(&mut self, config_json: String) -> Result<String, String> {
        ws_connect(&ports_for(self), &self.plugin_id, &config_json)
    }

    fn send_text(&mut self, handle: String, text: String) -> Result<(), String> {
        ws_send_text(&ports_for(self), &self.plugin_id, &handle, &text)
    }

    fn send_binary(&mut self, handle: String, payload: Vec<u8>) -> Result<(), String> {
        ws_send_binary(&ports_for(self), &self.plugin_id, &handle, &payload)
    }

    fn close(&mut self, handle: String, close_json: String) -> Result<bool, String> {
        ws_close(&ports_for(self), &self.plugin_id, &handle, &close_json)
    }

    fn is_connected(&mut self, handle: String) -> Result<bool, String> {
        ws_is_connected(&ports_for(self), &self.plugin_id, &handle)
    }
}

/// v36/v37 / ADR 0052 D4：`host-websocket-server`（桌面扩展服务端域）的 `impl Host`
/// 已迁桌面宿主 `src-tauri/src/plugin/ws.rs`（路径 B 模块 `ws-server`）——
/// 本模块不再生成/实现该 trait；引擎 API（`ws_*` 域函数）仍住本 crate，
/// 被服务器自身（`conn` / `websocket_manager` / 路由）与宿主 e2e 消费。

#[cfg(test)]
mod tests;
