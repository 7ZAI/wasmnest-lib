//! WS 出站连接引擎：`host-websocket` **客户端子集**的机制主体
//!
//! 本模块是 `wasmnest-ws-client-engine` 的全部机制面（零宿主依赖）：句柄表（属主化）、
//! reader/writer 双任务、连接级心跳（Ping + 静默判死）、退避重连、帧信封、close code
//! 语义、停用回收。宿主只剩薄适配器：装配 [`crate::ports::WsClientPorts`] 并把 5 条
//! 原语转成自己的 WIT/ABI 命令面。
//!
//! ## 纯引擎纪律（AGENTS §5.1）
//!
//! **本模块不解释字节**：url / headers / subprotocols 与帧内容都是纯透传。产品语义
//! （订阅协议 / ack-resync / 重订阅编排）归各 wasm 应用；本 crate 不含任何产品名词。
//!
//! ## 三条安全 / 生命周期约束
//!
//! 1. **权限门 fail-closed**：[`WsClientPorts::check_permission`] 返回 `false` 即一律拒
//!    （出站是 SSRF 面，插件可代宿主访问任意 `ws://` 地址）；
//! 2. **属主仲裁**：句柄只对属主可见可操作，他人句柄一律 `Err`（不返回 `false`，
//!    避免「不是我的」与「不存在」两种语义被插件混用）；
//! 3. **停用可回收**：[`purge_for_plugin`] 下线该插件全部连接与重连会话，句柄表不留残条。
//!
//! ## 为什么 `connect` 是 async 而原语是同步
//!
//! WIT `host fn` 是同步上下文，宿主适配器用 `block_on_async` 驱动本引擎的 async
//! `connect`；而**引擎自己从不假设自己处于某个 runtime 上下文**——reader / writer /
//! 重连任务一律经 [`WsClientPorts::spawn`] 派生到宿主运行时上。这是能力域抽根的关键
//! 前提：wasmtime fiber 内裸 `tokio::spawn` 会 panic。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;
use tokio_tungstenite::tungstenite::protocol::{
    frame::coding::CloseCode, CloseFrame, Message, WebSocketConfig,
};

use crate::ports::{WsClientPorts, WsTask};
use crate::wire::{
    ws_event_topic, ws_message_topic, WS_CLOSE, WS_ERROR, WS_FRAME_HEADER_LEN,
    WS_FRAME_KIND_BINARY, WS_FRAME_KIND_TEXT, WS_OPEN, WS_RECONNECT_SCHEDULED,
};

/// 握手请求类型别名（tungstenite 全路径太长，签名里用别名）
type HandshakeRequest = tokio_tungstenite::tungstenite::handshake::client::Request;

/// 握手产出的流类型（tokio-tungstenite 客户端非 TLS 形态；读写任务用其 split 两半）
type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
/// 写半（run_writer 参数；由 `WsStream::split` 产出）
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
/// 读半（run_reader 参数；由 `WsStream::split` 产出）
type WsSource = futures_util::stream::SplitStream<WsStream>;

// ==================== 常量（引擎参数，插件不可调） ====================

/// 连接状态：open（握手完成且未关闭）
const STATE_OPEN: u8 = 1;
/// 连接状态：已关闭
const STATE_CLOSED: u8 = 2;

/// 单插件并发连接数上限（超限时 [`connect`] 直接 `Err`，无任何副作用）
const MAX_CONNS_PER_PLUGIN: usize = 8;
/// 单连接发送队列容量（满则 `send_*` 报 `ws send queue full`，不阻塞实例）
const SEND_QUEUE_CAPACITY: usize = 64;
/// 握手超时上限（秒）。**上限即默认值**：插件传更大的值被截断到此处——host fn 是
/// 同步上下文，握手期阻塞整个插件实例，不允许长挂
const CONNECT_TIMEOUT_SECS: u64 = 5;
/// 单帧字节缺省上限（插件可经 `max-message-bytes` 调小）
const MAX_MESSAGE_BYTES_DEFAULT: usize = 8 * 1024 * 1024;
/// 单帧字节硬顶（插件不能把宿主内存上限当自己的帧上限用）
const MAX_MESSAGE_BYTES_CAP: usize = 16 * 1024 * 1024;

/// 心跳缺省周期（秒）与静默判死倍数（30s Ping / 90s 判死；「心跳归引擎」对齐桌面
/// server 骨架级心跳 conn.rs）
const HEARTBEAT_PING_SECS_DEFAULT: u64 = 30;
/// 心跳静默判死倍数：静默阈值 = 周期 × 3（静默 shell 不产生出站帧，判活只能
/// 靠入站活动，阈值必须宽到能容下「终端长时间无人操作」而不误杀）
const HEARTBEAT_SILENCE_MULTIPLIER: u64 = 3;
/// 静默判死检查周期（毫秒）——只查时间戳，不发帧，代价可忽略
const HEARTBEAT_PROBE_TICK_MS: u64 = 5_000;

/// 自动重连退避钳制：边界常量真源在宿主全局退避（经
/// [`WsClientPorts::reconnect_bounds`] 投影）——下限是自愈风暴的教训沉淀，
/// 不允许 config 绕过。常量在运行期从端口取，本 crate 不持常量副本（杜绝双真源漂移）。
/// 非属主操作的统一拒绝文案（属主仲裁）
const NOT_OWNER: &str = "not owner of ws handle";

/// 权限门拒绝文案（fail-closed；`ws:client` 字面量取自 [`crate::wire`] 自持副本）
pub(crate) fn denied() -> String {
    format!("permission denied: {}", crate::wire::PERMISSION_WS_CLIENT)
}

// ==================== 数据模型 ====================

/// `auto-reconnect` 的 config 契约（`{ baseMs, maxMs }`；无限重试，取消 =
/// 插件对句柄 `close` 或宿主停用回收——「N 次后交还用户」的裁决由插件协议层做，
/// 不在传输面）
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AutoReconnectConfig {
    base_ms: u64,
    max_ms: u64,
}

/// [`connect`] 的 config-json 契约（纯引擎参数，camelCase）
///
/// 可选字段（缺省行为不变）：`jwt-auth`（宿主代发首消息认证帧，token 不落插件）、
/// `heartbeat-secs`（连接级心跳，0 = 禁用）、`auto-reconnect`（断线自动重连 +
/// reconnect-scheduled 事件）
#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default)]
    jwt_auth: Option<bool>,
    #[serde(default)]
    heartbeat_secs: Option<u64>,
    #[serde(default)]
    auto_reconnect: Option<AutoReconnectConfig>,
}

/// 连接级心跳参数（config 解析产物；writer 发 Ping、reader 判静默共用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeartbeatParams {
    /// Ping 周期（秒）；0 = 禁用
    ping_secs: u64,
    /// 静默判死阈值（秒）= 周期 × 3
    timeout_secs: u64,
}

impl HeartbeatParams {
    fn from_config(secs: Option<u64>) -> Self {
        match secs {
            Some(0) => Self {
                ping_secs: 0,
                timeout_secs: 0,
            },
            other => {
                let ping = other.unwrap_or(HEARTBEAT_PING_SECS_DEFAULT).max(1);
                Self {
                    ping_secs: ping,
                    timeout_secs: ping * HEARTBEAT_SILENCE_MULTIPLIER,
                }
            }
        }
    }
}

/// 一次「带自动重连的连接生命周期」会话
///
/// 断线后本域按宿主退避策略（[`crate::ports::ReconnectPolicy`]，真源 = 宿主全局退避单一事实源：
/// 指数退避 + 抖动 + 下限钳制）按原 config 重建连接，成功后以**新句柄**发
/// `ws:open`（插件按新句柄重新订阅；订阅协议 / 重订阅编排归插件，TCP 重建归传输面）。
struct ReconnectSession {
    /// 属主插件 id（重连不重查权限门：连接是 activate 期授权的延续；
    /// 停用走 purge 强制取消）
    owner: String,
    /// 原 connect config（重连按原参数重建）
    config: ConnectConfig,
    /// 宿主端口（jwt-auth 帧 token / 重连策略 / 退避边界 / 事件与任务派生——
    /// 重连任务脱离插件实例状态后仍需访问宿主）
    ports: Arc<dyn WsClientPorts>,
    /// 重连成功后的当前句柄（reconnect-scheduled / 诊断事件用）
    last_handle: Mutex<String>,
    /// 取消标志：插件 `close` 命中（显式关闭 = 取消重连）或停用 purge
    cancelled: AtomicBool,
}

/// `close` 的 close-json 契约
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseConfig {
    #[serde(default)]
    code: Option<u16>,
    #[serde(default)]
    reason: Option<String>,
}

/// 出站帧（插件 → 对端）
enum OutboundFrame {
    Text(String),
    Binary(Vec<u8>),
    Close { code: u16, reason: String },
}

/// 一条出站连接（句柄表条目；句柄带 owner，回收只碰本人）
struct ClientEntry {
    /// 属主插件 id
    owner: String,
    /// 连接目标 url（诊断用；引擎不解释）
    #[allow(dead_code)]
    url: String,
    /// 发送队列（满即拒，绝不阻塞宿主）
    tx: mpsc::Sender<OutboundFrame>,
    /// 连接状态（`is_connected` 事实源；reader 退出即置 CLOSED）
    state: Arc<AtomicU8>,
    /// 写任务（发送队列 → 对端）
    writer: Arc<dyn WsTask>,
    /// 读任务（帧回灌 + 关闭事件上报）
    #[allow(dead_code)]
    reader: Arc<dyn WsTask>,
    /// 自动重连会话（config 声明 `auto-reconnect` 时存在；显式 close 即取消）
    reconnect: Option<Arc<ReconnectSession>>,
}

/// 全局连接表（句柄 → 连接）
static CLIENTS: LazyLock<Mutex<HashMap<String, ClientEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 重连会话表（旧句柄 → 会话）：连接断开后条目从 `CLIENTS` 摘除，
/// 重连任务以此表为取消寻址面——插件对旧句柄 `close`（未命中连接表时）
/// 命中此表即取消重连；重连成功换键到新句柄
static RECONNECTING: LazyLock<Mutex<HashMap<String, Arc<ReconnectSession>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ==================== 客户端域原语 ====================

/// 建立出站 WS 连接（握手 + 双任务 + 句柄登记 + open 事件）
///
/// 成功 → 返回句柄 `wsc-<uuid>` 并发布 `<owner>:ws:open`；
/// 失败 → 错误上抛且**不发布任何事件**（无句柄可寻址）。
///
/// config 增强面：`jwt-auth`（宿主代发首消息认证帧，token 不落插件——C4）；
/// `heartbeat-secs`（连接级心跳）；`auto-reconnect`（断线自动重连，取消 =
/// 对句柄 `close` 或停用回收）。
///
/// 权限门 fail-closed：[`WsClientPorts::check_permission`] 为假即在握手前拒绝。
/// **同步上下文驱动是宿主的事**（`block_on_async` / panic 边界都在适配器侧）——本
/// 函数只承诺「在自己的 future 里跑到握手完成」。
pub async fn connect(
    ports: &Arc<dyn WsClientPorts>,
    plugin_id: &str,
    config_json: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id) {
        return Err(denied());
    }
    let config: ConnectConfig = serde_json::from_str(config_json)
        .map_err(|e| format!("ws connect: invalid config: {e}"))?;
    validate_config(&config)?;

    let owner = plugin_id.to_string();
    // 连接数上限：首检是廉价快路，插入时锁内复查兜住握手窗口的并发
    let owned = {
        let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        table.values().filter(|e| e.owner == owner).count()
    };
    if owned >= MAX_CONNS_PER_PLUGIN {
        return Err(format!(
            "ws connect: connection limit reached ({MAX_CONNS_PER_PLUGIN})"
        ));
    }

    // jwt-auth：宿主当前无 token → 握手前显性失败（fail-visible；带 token 的
    // auth 帧是连接可用前提，握手后再失败只会留下「连上了但立刻死」的噪声）
    if config.jwt_auth == Some(true) && ports.global_token().is_empty() {
        return Err(
            "ws connect: jwt-auth requested but host has no auth token (device not authenticated yet)"
                .to_string(),
        );
    }

    let reconnect = config.auto_reconnect.as_ref().map(|_| {
        Arc::new(ReconnectSession {
            owner: owner.clone(),
            config: config.clone(),
            ports: Arc::clone(ports),
            last_handle: Mutex::new(String::new()),
            cancelled: AtomicBool::new(false),
        })
    });

    let handle = spawn_connection(
        Arc::clone(ports),
        owner.clone(),
        config.clone(),
        reconnect.clone(),
    )
    .await?;

    if let Some(rs) = reconnect {
        *rs.last_handle.lock().unwrap_or_else(|p| p.into_inner()) = handle.clone();
        RECONNECTING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handle.clone(), rs);
    }
    Ok(handle)
}

/// config 校验（权限门之后、握手之前；重连复用同一判据）
fn validate_config(config: &ConnectConfig) -> Result<(), String> {
    let url = config.url.trim();
    if url.is_empty() {
        return Err("ws connect: url must not be empty".to_string());
    }
    // 仅 ws://：不启 TLS 属**显式立项边界**而非缺陷（wss:// 需带 CA / 自签证书
    // 配置）。显式拒绝而非让握手失败掩盖真实原因。
    if !url.starts_with("ws://") {
        return Err(format!(
            "ws connect: url scheme not supported ({url}); only ws:// is available on mobile \
             (wss:// needs CA/custom-cert configuration, not implemented yet)"
        ));
    }
    Ok(())
}

/// 建连执行体（握手 → 读写任务 → 条目登记 → open 事件）
///
/// 首次 [`connect`] 与自动重连任务共用；**不含权限门与连接数首检**（重连是
/// activate 期授权连接的延续，停用经 purge 强制取消，不会绕过授权）。
/// 成功返回新句柄并发布 `<owner>:ws:open`；失败零事件（重连任务自行推进退避）。
///
/// **返回 boxed future**：本函数与 [`run_reader`] / [`run_reconnect`] 构成
/// 「建连 → reader → 重连 → 建连」的 async 递归环，三者都是 `async fn` 时 rustc 的
/// 不透明 future 类型推导会自指（E0391 opaque type cycle）。把**递归那条边**装箱
/// 打破环，其余调用点仍按具名 future `.await`。
fn spawn_connection(
    ports: Arc<dyn WsClientPorts>,
    owner: String,
    config: ConnectConfig,
    reconnect: Option<Arc<ReconnectSession>>,
) -> BoxedConnect {
    Box::pin(async move {
        let ports = &ports;
        let owner = owner.as_str();
        let config = &config;
        let reconnect = reconnect.as_ref();
        let url = config.url.trim().to_string();
        let request = build_request(&url, config)?;
        let timeout_secs = config
            .connect_timeout_secs
            .unwrap_or(CONNECT_TIMEOUT_SECS)
            .clamp(1, CONNECT_TIMEOUT_SECS);
        let limit = MAX_MESSAGE_BYTES_DEFAULT
            .min(config.max_message_bytes.unwrap_or(usize::MAX))
            .clamp(1, MAX_MESSAGE_BYTES_CAP);
        let ws_config = WebSocketConfig {
            max_message_size: Some(limit),
            max_frame_size: Some(limit),
            ..WebSocketConfig::default()
        };

        // 握手：等完成或超时。调用方（宿主适配器）负责 panic 边界与同步驱动
        let (stream, response) = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false),
        )
        .await
        .map_err(|_| format!("ws connect: handshake timed out after {timeout_secs}s"))?
        .map_err(|e| format!("ws connect: handshake failed: {e}"))?;

        // 子协议协商结果回传插件（缺失则省略字段，不伪造）
        let protocol = response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let handle = format!("wsc-{}", uuid::Uuid::new_v4());
        let open_state = Arc::new(AtomicU8::new(STATE_OPEN));
        let (tx, rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let (write, read) = stream.split();
        let heartbeat = HeartbeatParams::from_config(config.heartbeat_secs);

        // jwt-auth：宿主代发首消息认证帧（C4：token 从宿主认证状态取，不落插件；
        // auth 帧形状 = 两端宿主传输面契约）。在 writer spawn **前**入队——队列空
        // （句柄尚未返回给插件），auth 帧必然先于任何业务帧发出；token 空则整条连接
        // 显性失败（重连窗口 token 被清时由重连任务按退避重试，主连接重新认证成功后
        // 自然恢复）
        if config.jwt_auth == Some(true) {
            let token = ports.global_token();
            if token.is_empty() {
                return Err(
                    "ws connect: host auth token cleared before auth frame (wait for re-auth)"
                        .to_string(),
                );
            }
            let auth = format!(r#"{{"type":"auth","token":"{}"}}"#, token);
            let _ = tx.try_send(OutboundFrame::Text(auth));
            tracing::info!(plugin_id = %owner, token_len = token.len(), "ws connect: host-injected jwt auth frame (token length only, never plaintext)");
        }

        // 任务一律经端口派生到宿主运行时（host fn 可能在无 runtime 上下文的线程上
        // 执行：spawn_blocking / 纯 std 线程，裸 tokio::spawn 会 panic）
        let writer = ports.spawn(
            "ws_client_writer",
            Box::pin(run_writer(write, rx, heartbeat)),
        );
        let reader = ports.spawn(
            "ws_client_reader",
            Box::pin(run_reader(
                read,
                handle.clone(),
                owner.to_string(),
                Arc::clone(&open_state),
                Arc::clone(ports),
                heartbeat,
            )),
        );

        {
            let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
            // 插入前锁内复查上限：握手窗口里并发 connect 可能都通过了首检
            //（重连路径同判——退避成功后表位已腾出，正常不触发）
            let owned_now = table.values().filter(|e| e.owner == owner).count();
            if owned_now >= MAX_CONNS_PER_PLUGIN {
                drop(table);
                tracing::warn!(
                    plugin_id = %owner,
                    "ws connect: connection limit reached at insert (concurrent connects), closing excess"
                );
                writer.cancel();
                reader.cancel();
                return Err(format!(
                    "ws connect: connection limit reached ({MAX_CONNS_PER_PLUGIN})"
                ));
            }
            table.insert(
                handle.clone(),
                ClientEntry {
                    owner: owner.to_string(),
                    url: url.clone(),
                    tx,
                    state: open_state,
                    writer,
                    reader,
                    reconnect: reconnect.cloned(),
                },
            );
        }

        // 成功才发 open 事件（失败路径零事件）；重连成功时携带 `reconnectedFrom`
        // 旧句柄——句柄与会话的映射只在插件侧，靠它把新句柄接回等待中的订阅
        let mut payload = serde_json::json!({ "handle": handle, "url": url });
        if let Some(session) = reconnect {
            let last = session
                .last_handle
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if !last.is_empty() {
                payload["reconnectedFrom"] = serde_json::Value::String(last);
            }
        }
        if let Some(protocol) = protocol {
            payload["protocol"] = serde_json::Value::String(protocol);
        }
        ports.publish(&ws_event_topic(WS_OPEN, owner), payload);
        tracing::info!(plugin_id = %owner, handle = %handle, "ws client connection opened");
        Ok(handle)
    })
}

/// 建连执行体的返回类型（boxed future：打破 async 递归环，见 [`spawn_connection`]）
type BoxedConnect = Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;

/// 发送文本帧（UTF-8）
pub fn send_text(
    ports: &Arc<dyn WsClientPorts>,
    plugin_id: &str,
    handle: &str,
    text: &str,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id) {
        return Err(denied());
    }
    enqueue(plugin_id, handle, OutboundFrame::Text(text.to_string()))
}

/// 发送二进制帧
pub fn send_binary(
    ports: &Arc<dyn WsClientPorts>,
    plugin_id: &str,
    handle: &str,
    payload: Vec<u8>,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id) {
        return Err(denied());
    }
    enqueue(plugin_id, handle, OutboundFrame::Binary(payload))
}

/// 主动关闭连接：返回是否命中（幂等：未知句柄 false）
///
/// 关闭命令入队后由写任务发 Close 帧并收尾；对端回 Close → 读任务上报
/// `<owner>:ws:close`（`wasClean` 按对端回帧 code 判定）。
/// 命中的是**正在退避重连的旧句柄**时，取消重连并返回 `true`。
pub fn close(
    ports: &Arc<dyn WsClientPorts>,
    plugin_id: &str,
    handle: &str,
    close_json: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id) {
        return Err(denied());
    }
    let close: CloseConfig = serde_json::from_str(close_json)
        .map_err(|e| format!("ws close: invalid close-json: {e}"))?;
    let code = close.code.unwrap_or(1000);
    let reason = close.reason.unwrap_or_default();

    let tx = {
        let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = table.get(handle) else {
            // 连接表未命中：可能是正在退避重连的旧句柄——命中即取消重连
            //（显式关闭 = 「不再重连」的插件语义，也是重连会话的取消寻址面）
            let mut reconnecting = RECONNECTING.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = reconnecting.get(handle) {
                if session.owner != plugin_id {
                    return Err(NOT_OWNER.to_string());
                }
                session.cancelled.store(true, Ordering::SeqCst);
                reconnecting.remove(handle);
                tracing::debug!(
                    plugin_id = %plugin_id,
                    handle = %handle,
                    "ws close: cancelled auto-reconnect session"
                );
                return Ok(true);
            }
            return Ok(false);
        };
        if entry.owner != plugin_id {
            return Err(NOT_OWNER.to_string());
        }
        // 显式关闭同时取消自动重连：对端回 Close → reader 判 clean 不重连，
        // 此处置位是双保险（Close 往返丢失时 reader 走异常路径也不会复活连接）
        if let Some(session) = entry.reconnect.as_ref() {
            session.cancelled.store(true, Ordering::SeqCst);
            RECONNECTING
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(handle);
        }
        entry.tx.clone()
    };
    match tx.try_send(OutboundFrame::Close { code, reason }) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // 写任务已退出（对端先断）：语义等同关闭完成
            tracing::debug!(
                plugin_id = %plugin_id,
                handle = %handle,
                "ws close: writer already finished"
            );
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            // 队列满 → Close 帧无法入队；静默丢弃会让连接永不关闭（writer 卡在积压帧
            // 的 send 上）。只中止写任务：写半段立即释放，对端收到 EOF；读任务继续
            // 读到对端关闭并上报 ws:close（wasClean=false）——条目由读任务退出时摘除
            tracing::warn!(
                plugin_id = %plugin_id,
                handle = %handle,
                "ws close: send queue full, aborting writer to force close"
            );
            abort_writer(handle, plugin_id);
        }
    }
    Ok(true)
}

/// 查询连接是否 open；仅属主可查（句柄不存在 ⇒ false）
pub fn is_connected(
    ports: &Arc<dyn WsClientPorts>,
    plugin_id: &str,
    handle: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id) {
        return Err(denied());
    }
    let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    match table.get(handle) {
        Some(entry) if entry.owner == plugin_id => {
            Ok(entry.state.load(Ordering::SeqCst) == STATE_OPEN)
        }
        Some(_) => Err(NOT_OWNER.to_string()),
        None => Ok(false),
    }
}

/// 入队出站帧（fail-visible：队列满 / 已关闭立即报错，绝不阻塞宿主线程）
fn enqueue(owner: &str, handle: &str, frame: OutboundFrame) -> Result<(), String> {
    let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(entry) = table.get(handle) else {
        return Err(format!("ws connection not found: {handle}"));
    };
    if entry.owner != owner {
        return Err(NOT_OWNER.to_string());
    }
    if entry.state.load(Ordering::SeqCst) != STATE_OPEN {
        return Err(format!("ws connection is closed: {handle}"));
    }
    match entry.tx.try_send(frame) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err("ws send queue full".to_string()),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            Err(format!("ws connection is closed: {handle}"))
        }
    }
}

/// 仅中止某连接的写任务（队列满强关用；读任务继续上报 close 并摘除条目）
fn abort_writer(handle: &str, owner: &str) -> bool {
    let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    match table.get(handle) {
        Some(entry) if entry.owner == owner => {
            entry.writer.cancel();
            true
        }
        _ => false,
    }
}

/// 中止某连接的读写任务并摘除条目（停用回收共用）
fn abort_and_remove(handle: &str, owner: &str) -> bool {
    let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(entry) = table.get(handle) else {
        return false;
    };
    if entry.owner != owner {
        return false;
    }
    entry.writer.cancel();
    entry.reader.cancel();
    table.remove(handle);
    true
}

/// 停用回收：下线该插件全部连接（只碰本人句柄）+ 取消全部重连会话
///
/// 返回被回收的**连接**数（重连会话只取消不计数——它没有活连接可下线）。
/// 停用后重连成功 = 无授权连接复活，故 `cancelled` 是重连任务每轮 sleep 后的退出闸。
pub fn purge_for_plugin(plugin_id: &str) -> usize {
    let handles: Vec<String> = {
        let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        table
            .iter()
            .filter(|(_, e)| e.owner == plugin_id)
            .map(|(h, _)| h.clone())
            .collect()
    };
    let purged = handles
        .iter()
        .filter(|h| abort_and_remove(h, plugin_id))
        .count();
    let cancelled_reconnects = {
        let mut reconnecting = RECONNECTING.lock().unwrap_or_else(|e| e.into_inner());
        let keys: Vec<String> = reconnecting
            .iter()
            .filter(|(_, s)| s.owner == plugin_id)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &keys {
            if let Some(session) = reconnecting.get(k) {
                session.cancelled.store(true, Ordering::SeqCst);
            }
            reconnecting.remove(k);
        }
        keys.len()
    };
    if purged > 0 || cancelled_reconnects > 0 {
        tracing::info!(
            plugin_id = %plugin_id,
            purged,
            cancelled_reconnects,
            "ws client connections purged on plugin deactivate"
        );
    }
    purged
}

// ==================== 请求构造 ====================

/// 请求构造：url + 插件自定 headers / subprotocols（引擎不解读任何业务头）
fn build_request(url: &str, config: &ConnectConfig) -> Result<HandshakeRequest, String> {
    let mut request = url
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
        request.headers_mut().insert(SEC_WEBSOCKET_PROTOCOL, value);
    }
    Ok(request)
}

// ==================== 读写任务 ====================

/// 写任务：出站队列 → 对端；Close 帧发完即收尾。
///
/// config 声明心跳（`heartbeatSecs` 非 0）时周期发标准 Ping 帧
/// （RFC 6455，对端协议层自动回 Pong）——TCP 半开时 `send` 只写本地缓冲
/// 不会报错，判活靠 reader 侧静默检查（见 `run_reader`）。
async fn run_writer(
    mut write: WsSink,
    mut rx: mpsc::Receiver<OutboundFrame>,
    heartbeat: HeartbeatParams,
) {
    use futures_util::SinkExt;
    let mut ping_tick = (heartbeat.ping_secs > 0).then(|| {
        let mut i = tokio::time::interval(std::time::Duration::from_secs(heartbeat.ping_secs));
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    });
    // 跳过 interval 立即触发的那一拍（首轮 Ping 等 1 个完整周期）
    if let Some(t) = ping_tick.as_mut() {
        t.tick().await;
    }
    loop {
        tokio::select! {
            frame = rx.recv() => {
                let Some(frame) = frame else { break; };
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
            _ = async {
                match ping_tick.as_mut() {
                    Some(t) => {
                        t.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                if write.send(Message::Ping(Vec::new())).await.is_err() {
                    tracing::debug!("ws client ping send failed, closing");
                    break;
                }
            }
        }
    }
    if let Err(e) = write.close().await {
        tracing::debug!(error = %e, "ws client close handshake failed");
    }
}

/// 读任务：帧回灌属主二进制 topic + 关闭事件上报（每连接恰好一次）+
/// 心跳静默判死 + 自动重连触发
///
/// 入站帧保序：单任务顺序投递，总线侧为 FIFO 有界队列。
/// 心跳：任意入站帧（业务/控制/Ping/Pong）刷新活性时间戳——静默 shell
/// 不产生 Pong，只认 Pong 会把「终端空闲」误判成「连接已死」；超过
/// `timeout_secs` 无任何入站 → 判死，主动走异常断开路径（close 1006）。
async fn run_reader(
    mut read: WsSource,
    handle: String,
    owner: String,
    state: Arc<AtomicU8>,
    ports: Arc<dyn WsClientPorts>,
    heartbeat: HeartbeatParams,
) {
    use futures_util::StreamExt;
    let close_reported = Arc::new(AtomicBool::new(false));
    let mut close_frame: Option<(Option<u16>, String, bool)> = None;
    let last_activity_ms = Arc::new(AtomicU64::new(now_millis()));
    let mut probe_tick = (heartbeat.ping_secs > 0).then(|| {
        let mut i =
            tokio::time::interval(std::time::Duration::from_millis(HEARTBEAT_PROBE_TICK_MS));
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    });
    if let Some(t) = probe_tick.as_mut() {
        t.tick().await; // 跳过立即触发的那一拍
    }

    loop {
        let incoming = tokio::select! {
            biased;
            _ = async {
                match probe_tick.as_mut() {
                    // 半开探测：TCP 半开时 writer 的 send 照样成功（只写本地缓冲），
                    // 必须靠「多久没有任何入站活动」判死，而不是靠 send 报错
                    Some(t) => {
                        t.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                let last = last_activity_ms.load(Ordering::SeqCst);
                if now_millis().saturating_sub(last) > heartbeat.timeout_secs * 1000 {
                    tracing::warn!(
                        plugin_id = %owner,
                        handle = %handle,
                        timeout_secs = heartbeat.timeout_secs,
                        "ws client silent beyond heartbeat timeout (half-open suspected), closing"
                    );
                    // 判死 = 宿主侧异常断开：code 1006 不会出现在真实 Close 帧
                    //（RFC 6455 保留），此处作诊断标记；wasClean=false
                    close_frame = Some((Some(1006), "heartbeat timeout".to_string(), false));
                    break;
                }
                continue;
            }
            r = read.next() => r,
        };
        let Some(incoming) = incoming else {
            break;
        };
        match incoming {
            Ok(Message::Text(text)) => {
                last_activity_ms.store(now_millis(), Ordering::SeqCst);
                publish_frame(&ports, &owner, WS_FRAME_KIND_TEXT, &handle, text.as_bytes());
            }
            Ok(Message::Binary(payload)) => {
                last_activity_ms.store(now_millis(), Ordering::SeqCst);
                publish_frame(&ports, &owner, WS_FRAME_KIND_BINARY, &handle, &payload);
            }
            Ok(Message::Close(frame)) => {
                let (code, reason) = match frame {
                    Some(f) => (Some(u16::from(f.code)), f.reason.to_string()),
                    None => (None, String::new()),
                };
                // 无 code 的对端 Close 视为异常断开（1006 之类不会出现在 Close 帧里）
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
            // Ping/Pong/Frame 由 tungstenite 协议层处理，业务层不外泄；
            // 但都是入站活动（静默判活的事实源）
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {
                last_activity_ms.store(now_millis(), Ordering::SeqCst);
            }
            Err(e) => {
                ports.publish(
                    &ws_event_topic(WS_ERROR, &owner),
                    serde_json::json!({ "handle": handle, "message": e.to_string() }),
                );
                break;
            }
        }
    }

    // 先置关闭态再上报：上报后 is_connected 立即为 false
    state.store(STATE_CLOSED, Ordering::SeqCst);
    let clean = close_frame.as_ref().map(|(_, _, c)| *c);
    match close_frame {
        Some((code, reason, clean)) => {
            report_close(
                &ports,
                &owner,
                &handle,
                code,
                &reason,
                clean,
                &close_reported,
            );
        }
        None => {
            // 未收到对端 Close（TCP 断 / 传输错误 / 宿主主动关）→ code 省略 + wasClean=false
            report_close(&ports, &owner, &handle, None, "", false, &close_reported);
        }
    }
    // 摘除已关闭条目并中止写任务：CLOSED 条目继续占表位会让连接配额槽泄漏；
    // 写任务挂在队列 recv 上，对端已死时永远等不到唤醒（任务泄漏），reader
    // 退出即收。cancel 打断的最多是发往已死连接的帧（无投递价值）
    let removed = {
        let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        if table.get(&handle).is_some_and(|e| e.owner == owner) {
            table.remove(&handle)
        } else {
            None
        }
    };
    if let Some(entry) = &removed {
        entry.writer.cancel();
    }
    tracing::debug!(plugin_id = %owner, handle = %handle, "ws client reader exited");

    // 自动重连：仅异常断开触发——对端主动 Close(1000/1001) 是协议层的正常关闭
    // （终端场景 = 插件收到 session_stopped 后主动 close，已在 close 时置 cancelled，
    // 双保险），不重连
    if !clean.unwrap_or(false) {
        if let Some(session) = removed.and_then(|e| e.reconnect) {
            if !session.cancelled.load(Ordering::SeqCst) {
                let ports_for_task = Arc::clone(&session.ports);
                ports_for_task.spawn("ws_client_reconnect", Box::pin(run_reconnect(session)));
            }
        }
    }
}

/// 自动重连任务：按宿主退避策略（[`crate::ports::ReconnectPolicy`]，全局退避单一事实源——
/// 指数退避 + 抖动 + 下限钳制；无限重试，取消 = 插件 close 命中 / 停用 purge 置
/// cancelled）重建连接。每轮排期发布 `<owner>:ws:reconnect-scheduled`
/// `{ handle, retryInMs }`（旧句柄寻址），成功后 `spawn_connection` 发布 `ws:open`
/// （新句柄）并把重连表换键到新句柄
async fn run_reconnect(session: Arc<ReconnectSession>) {
    // 退避边界运行期经端口投影（真源 = 宿主全局退避常量，禁 config 绕过）
    let (bounds_min, bounds_max) = session.ports.reconnect_bounds();
    let (base_ms, max_ms) = match session.config.auto_reconnect.as_ref() {
        Some(a) => (
            a.base_ms.max(bounds_min),
            a.max_ms.min(bounds_max).max(bounds_min),
        ),
        None => return,
    };
    // 策略对象经端口取（真源 = 宿主全局退避单一事实源）
    let policy = session.ports.reconnect_policy(0, base_ms, max_ms);
    loop {
        if session.cancelled.load(Ordering::SeqCst) {
            return;
        }
        // 策略推进一轮（无限重试下恒 Some；防御性保留放弃分支）
        if policy.start().await.is_none() {
            tracing::warn!(plugin_id = %session.owner, "ws reconnect policy gave up");
            return;
        }
        let delay = policy.get_delay().await;
        let last_handle = session
            .last_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        session.ports.publish(
            &ws_event_topic(WS_RECONNECT_SCHEDULED, &session.owner),
            serde_json::json!({
                "handle": last_handle,
                "retryInMs": u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            }),
        );
        tracing::debug!(
            plugin_id = %session.owner,
            retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "ws client reconnect scheduled"
        );
        tokio::time::sleep(delay).await;
        if session.cancelled.load(Ordering::SeqCst) {
            return;
        }
        match spawn_connection(
            Arc::clone(&session.ports),
            session.owner.clone(),
            session.config.clone(),
            Some(Arc::clone(&session)),
        )
        .await
        {
            Ok(new_handle) => {
                *session
                    .last_handle
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = new_handle.clone();
                {
                    let mut table = RECONNECTING.lock().unwrap_or_else(|e| e.into_inner());
                    table.remove(&last_handle);
                    table.insert(new_handle, Arc::clone(&session));
                }
                policy.on_success().await;
                return;
            }
            Err(e) => {
                tracing::debug!(plugin_id = %session.owner, error = %e, "ws reconnect attempt failed, next backoff round");
            }
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// close code → `wasClean`：仅对端主动 Close 且 code ∈ {1000, 1001} 为 true
fn close_was_clean(code: Option<u16>) -> bool {
    matches!(code, Some(1000) | Some(1001))
}

/// 上报 `<owner>:ws:close`（守卫保证每连接恰好一次）
fn report_close(
    ports: &Arc<dyn WsClientPorts>,
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
    ports.publish(&ws_event_topic(WS_CLOSE, owner), payload);
    tracing::info!(plugin_id = %owner, handle = %handle, was_clean, "ws client connection closed");
}

// ==================== 帧投递 ====================

/// 入站帧：属主私有二进制 topic（帧信封 = kind + handle + 原始字节）
///
/// 未订阅该二进制 topic 时宿主总线侧记 debug 并丢弃（宿主不缓存、不补发）——故
/// WIT 与 SDK 文档都要求 activate 期完成 `subscribe-binary`。
fn publish_frame(
    ports: &Arc<dyn WsClientPorts>,
    owner: &str,
    kind: u8,
    handle: &str,
    payload: &[u8],
) {
    ports.publish_binary(
        &ws_message_topic(owner),
        frame_envelope(kind, handle, payload),
    );
}

/// 帧信封字节（与插件 SDK `parse_ws_frame` 配对，形状变更须两端同批）
fn frame_envelope(kind: u8, handle: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WS_FRAME_HEADER_LEN + handle.len() + payload.len());
    out.push(kind);
    out.extend_from_slice(&(handle.len() as u16).to_be_bytes());
    out.extend_from_slice(handle.as_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests;
