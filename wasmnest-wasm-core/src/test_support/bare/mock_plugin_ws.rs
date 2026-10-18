//! 假插件端点夹具（专项票 01 P0：基线与假插件端点夹具；spec §3.2/§3.3）
//!
//! 本地 WS server，模拟桌面插件 `com.wasmnest.terminal-session` 的两个 WS 端点：
//! `session-control`（常驻事件通道）与 `terminal`（终端流）。在不依赖真实桌面的
//! 前提下复现两端点的帧协议，供移动端 Rust 单测（crate 内 `#[path]` 引入）与
//! `src-tauri/tests/` 集成测试复用（票 03 事件通道 / 票 05 终端流 / 票 07 闭环）。
//!
//! ## 帧形状锚点（对齐桌面 wire，勿凭 spec 印象改字段名——字段名漂移即测试红）
//!
//! 桌面协议事实来源：应用仓桌面 bedcode 的 `rust/src/ws_control.rs`
//! 与 `ws_terminal.rs`。JSON 值比较按 `serde_json::Value` 语义（键序无关），
//! 但键名必须逐字一致：
//!
//! - 认证首帧（两端点）：`{"type":"auth","token":"<jwt>"}`；宿主安全边界，
//!   坏 token / 未认证 → close 4001（survey §握手证据）。
//! - 事件帧（session-control，7 类业务事件）：`{"type":"event","event":"<name>","payload":{...}}`
//!   顶层仅 `type`/`event`/`payload` 三键；事件名与载荷键为 snake_case（spec §3.1 表）。
//! - 终端文本帧（客户端→插件）：`subscribe`（`sessionId`/`mode`，mode 缺省 live）、
//!   `unsubscribe`、`ack`（`offset`）、`resync`（`offset`）、`input`（`data`，UTF-8 文本）、`poll`。
//!   注意 `sessionId` 为 camelCase（桌面 `TerminalFrame` serde 形状锁，两端协议事实）。
//! - 终端文本帧（插件→客户端）：`subscribed`（`sessionId`/`mode`）、`unsubscribed`、
//!   `ring_resync`（`offset`）、`session_stopped`（`sessionId`/`reason`/`exitCode`?）、
//!   `error`（`message`）。
//! - 终端二进制：客户端→插件 = 原始输入字节（可含控制字符）；插件→客户端 = 输出裸字节
//!   **无帧头、无 per-frame offset**（旧 TB v3 的 16B 头 / `from_offset` / `history_end`
//!   已退役，夹具任何帧不得出现这些键——自检用例锁死）。
//!
//! ## 职责边界
//!
//! 只做协议壳与可编程应答，不实现任何业务语义（无会话状态机）：
//! 收到什么帧就记录什么帧（`received_text` / `received_binary`），测试用
//! `send_text` / `send_binary` / `send_event` 按需注入服务端帧；连接数可观测；
//! 启停释放端口。夹具自身单测见 `tests/mock_plugin_ws_fixture.rs`。

// 多消费者共享：不同测试只用到子集方法，整文件豁免 dead_code
// （与 tests/common/mod.rs 的既有规则一致）
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message as WsMsg};
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};

// ==================== 常量（端点 / 帧形状锚点） ====================

/// 桌面插件 ID（契约恒定，移动端 URL 常量独一出处见 system/constants/connection.rs 跟进）
pub const PLUGIN_ID: &str = "com.wasmnest.terminal-session";

/// `session-control` 端点（常驻事件通道；spec §3.2）
pub const ENDPOINT_SESSION_CONTROL: &str = "session-control";

/// `terminal` 端点（终端流；spec §3.3）
pub const ENDPOINT_TERMINAL: &str = "terminal";

/// 插件端点 URL 基础路径（与桌面宿主路由 `/ws/plugin/{plugin-id}/{path}` 一致）
pub const WS_BASE_PATH: &str = "/ws/plugin/com.wasmnest.terminal-session";

/// 认证首帧 type（spec §3.2/§3.3 握手；送审时首帧必须为此形状）
pub const TYPE_AUTH: &str = "auth";

/// 事件帧 type（session-control 广播帧壳，spec §3.2）
pub const TYPE_EVENT: &str = "event";

// ---- 终端文本帧 type（客户端 → 插件；桌面 ws_terminal.rs 词表） ----
pub const TERM_SUBSCRIBE: &str = "subscribe";
pub const TERM_UNSUBSCRIBE: &str = "unsubscribe";
pub const TERM_ACK: &str = "ack";
pub const TERM_RESYNC: &str = "resync";
pub const TERM_INPUT: &str = "input";
pub const TERM_POLL: &str = "poll";

// ---- 终端文本帧 type（插件 → 客户端；桌面 ws_terminal.rs 词表） ----
pub const TERM_SUBSCRIBED: &str = "subscribed";
pub const TERM_UNSUBSCRIBED: &str = "unsubscribed";
pub const TERM_RING_RESYNC: &str = "ring_resync";
pub const TERM_SESSION_STOPPED: &str = "session_stopped";
pub const TERM_ERROR: &str = "error";

/// 7 类业务事件名（spec §3.1 表，逐字不可漂移；载荷键 snake_case 自足）
pub const EVENT_SESSION_CREATED: &str = "session:created";
pub const EVENT_SESSION_STOPPED: &str = "session:stopped";
pub const EVENT_SESSION_REMOVED: &str = "session:removed";
pub const EVENT_TASK_STATUS_CHANGED: &str = "task:status-changed";
pub const EVENT_SESSION_MODE_CHANGED: &str = "session:mode-changed";
pub const EVENT_TASK_QUEUE_CHANGED: &str = "task:queue-changed";
pub const EVENT_TASK_SCHEDULED_CHANGED: &str = "task:scheduled-changed";

/// 全部业务事件名（校验「7 类」完备性用；次序与 spec §3.1 表一致）
pub const ALL_BUSINESS_EVENTS: [&str; 7] = [
    EVENT_SESSION_CREATED,
    EVENT_SESSION_STOPPED,
    EVENT_SESSION_REMOVED,
    EVENT_TASK_STATUS_CHANGED,
    EVENT_SESSION_MODE_CHANGED,
    EVENT_TASK_QUEUE_CHANGED,
    EVENT_TASK_SCHEDULED_CHANGED,
];

/// 认证失败关闭码（对齐桌面宿主：坏 token / 未认证 → close 4001，survey §握手证据）
pub const AUTH_REJECT_CLOSE_CODE: u16 = 4001;

/// 未知端点关闭码（夹具行为：握手成功后立即 close，模拟路由 404 语义）
pub const UNKNOWN_ENDPOINT_CLOSE_CODE: u16 = 1008;

// ==================== 帧构造（键名唯一出处：改动即测试红） ====================

/// 认证首帧 `{"type":"auth","token":"<jwt>"}`
pub fn auth_frame(token: &str) -> serde_json::Value {
    serde_json::json!({ "type": TYPE_AUTH, "token": token })
}

/// 事件帧 `{"type":"event","event":"<name>","payload":{...}}`（顶层仅三键）
pub fn event_frame(event: &str, payload: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "type": TYPE_EVENT, "event": event, "payload": payload })
}

/// 终端订阅帧 `{"type":"subscribe","sessionId":"...","mode":"live"|"poll"}`
/// （`mode` 为 `None` 时省略键——桌面缺省 live，两端协议事实）
pub fn subscribe_frame(session_id: &str, mode: Option<&str>) -> serde_json::Value {
    match mode {
        Some(m) => serde_json::json!({ "type": TERM_SUBSCRIBE, "sessionId": session_id, "mode": m }),
        None => serde_json::json!({ "type": TERM_SUBSCRIBE, "sessionId": session_id }),
    }
}

/// 终端退订帧 `{"type":"unsubscribe"}`
pub fn unsubscribe_frame() -> serde_json::Value {
    serde_json::json!({ "type": TERM_UNSUBSCRIBE })
}

/// 终端流控 ack 帧 `{"type":"ack","offset":N}`（本地已渲染字节数）
pub fn ack_frame(offset: u64) -> serde_json::Value {
    serde_json::json!({ "type": TERM_ACK, "offset": offset })
}

/// 终端重锚帧 `{"type":"resync","offset":N}`（客户端已清屏，从 N 继续）
pub fn resync_frame(offset: u64) -> serde_json::Value {
    serde_json::json!({ "type": TERM_RESYNC, "offset": offset })
}

/// 终端文本输入帧 `{"type":"input","data":"<UTF-8 文本>"}`（无控制字符）
pub fn terminal_input_frame(data: &str) -> serde_json::Value {
    serde_json::json!({ "type": TERM_INPUT, "data": data })
}

/// 终端主动拉取帧 `{"type":"poll"}`（批量态客户端驱动）
pub fn poll_frame() -> serde_json::Value {
    serde_json::json!({ "type": TERM_POLL })
}

/// 订阅回包帧 `{"type":"subscribed","sessionId":"...","mode":"..."}`
pub fn subscribed_frame(session_id: &str, mode: &str) -> serde_json::Value {
    serde_json::json!({ "type": TERM_SUBSCRIBED, "sessionId": session_id, "mode": mode })
}

/// 退订回包帧 `{"type":"unsubscribed"}`
pub fn unsubscribed_frame() -> serde_json::Value {
    serde_json::json!({ "type": TERM_UNSUBSCRIBED })
}

/// 环淘汰重锚帧 `{"type":"ring_resync","offset":N}`（N 之前数据不可恢复）
pub fn ring_resync_frame(offset: u64) -> serde_json::Value {
    serde_json::json!({ "type": TERM_RING_RESYNC, "offset": offset })
}

/// 停止帧 `{"type":"session_stopped","sessionId":"...","reason":"...","exitCode":N?}`
/// （`exit_code` 为 `None` 时省略键——桌面仅在 pty exit 码可用时携带）
pub fn session_stopped_frame(session_id: &str, reason: &str, exit_code: Option<i32>) -> serde_json::Value {
    let mut frame = serde_json::json!({
        "type": TERM_SESSION_STOPPED,
        "sessionId": session_id,
        "reason": reason,
    });
    if let Some(code) = exit_code {
        frame["exitCode"] = serde_json::json!(code);
    }
    frame
}

/// 错误帧 `{"type":"error","message":"..."}`
pub fn terminal_error_frame(message: &str) -> serde_json::Value {
    serde_json::json!({ "type": TERM_ERROR, "message": message })
}

// ==================== 认证策略 ====================

/// 端点认证门策略（session-control / terminal 两端点一致；缺省放行任意 token）
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthPolicy {
    /// 校验首帧为合法 auth 帧（token 任意）
    RequireAnyToken,
    /// 校验首帧 auth 且 token 精确匹配；不匹配 → close 4001
    RequireToken(String),
    /// 拒绝一切认证：合法 auth 首帧到达后 close 4001（可断言仍收到该帧）
    RejectAll,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        AuthPolicy::RequireAnyToken
    }
}

// ==================== 服务器 ====================

type SharedSink = Arc<AsyncMutex<futures_util::stream::SplitSink<WebSocketStream<TcpStream>, WsMsg>>>;

/// 本地假插件 WS server（127.0.0.1:0 随机端口；单监听按路径路由双端点）
///
/// 生命周期：`start()` 启动 → 各端点可配认证策略、可注入服务端帧、可观测连接数；
/// `shutdown().await` 幂等停机并**确定释放监听端口**（accept 任务 await 完成后 listener
/// 已 drop）；`Drop` 兜底 abort 全部任务（测试中途 panic 不泄漏端口/进程）。
pub struct MockPluginWsServer {
    pub addr: std::net::SocketAddr,
    state: Arc<ServerState>,
    /// accept 循环任务（shutdown 时 abort + await 确保 listener 已关闭；Option 供
    /// async fn 内取出——本类型实现 Drop，字段不可直接 move（E0509））
    task: Option<JoinHandle<()>>,
}

struct ServerState {
    session_control: Arc<EndpointState>,
    terminal: Arc<EndpointState>,
    /// 全部连接处理任务（Drop / shutdown 时 abort）；Arc 使 accept 循环可克隆持柄
    conn_tasks: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
}

/// 单端点共享状态（同路径多客户端共用；计数跨连接累计/递减）
struct EndpointState {
    auth_policy: std::sync::Mutex<AuthPolicy>,
    /// 收到的全部可解析文本帧（按到达序，跨连接累计；非 JSON 文本不在此，见 received_raw_text）
    received_text: AsyncMutex<Vec<serde_json::Value>>,
    /// 收到的全部文本帧原文（含非 JSON 畸形帧，按到达序）——畸形帧留痕断言用
    received_raw_text: AsyncMutex<Vec<String>>,
    /// 收到的全部二进制帧（客户端→插件原始输入字节，按到达序）
    received_binary: AsyncMutex<Vec<Vec<u8>>>,
    /// 当前已连接客户端数（握手完成即计数；断开递减）
    connected: AtomicUsize,
    /// 累计握手成功次数（断线重连场景断言「新连接已建立」用）
    total_accepted: AtomicU64,
    /// 活动连接的共享发送端（send_* 广播用；连接摘除时 retain 剔除）
    sinks: AsyncMutex<Vec<SharedSink>>,
}

impl MockPluginWsServer {
    /// 启动服务器（127.0.0.1:0 随机端口；不依赖外部网络）
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(ServerState {
            session_control: Arc::new(EndpointState::new()),
            terminal: Arc::new(EndpointState::new()),
            conn_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        let sc = state.session_control.clone();
        let term = state.terminal.clone();
        let conn_tasks = state.conn_tasks.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    break;
                };
                let sc = sc.clone();
                let term = term.clone();
                let conn_tasks = conn_tasks.clone();
                let handle = tokio::spawn(async move {
                    let Ok((ws, path)) = accept(stream).await else {
                        return;
                    };
                    // 按请求路径路由到端点；未知路径握手后立即 close（模拟路由 404 语义）
                    let ep = if path == endpoint_path(ENDPOINT_SESSION_CONTROL) {
                        sc
                    } else if path == endpoint_path(ENDPOINT_TERMINAL) {
                        term
                    } else {
                        let (mut tx, _rx) = ws.split();
                        let _ = tx
                            .send(WsMsg::Close(Some(close_frame(
                                UNKNOWN_ENDPOINT_CLOSE_CODE,
                                "unknown endpoint",
                            ))))
                            .await;
                        return;
                    };
                    handle_connection(ep, ws).await;
                });
                conn_tasks.lock().unwrap().push(handle);
            }
        });
        Self {
            addr,
            state,
            task: Some(task),
        }
    }

    /// 监听地址（ip:port）
    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// 端点访问 URL（`ws://127.0.0.1:<port>/ws/plugin/.../{endpoint}`）
    pub fn url(&self, endpoint: &str) -> String {
        format!(
            "ws://{}:{}{}",
            self.addr.ip(),
            self.addr.port(),
            endpoint_path(endpoint)
        )
    }

    /// 配置端点认证门策略（仅影响之后建连的认证判定；已有连接不受影响）
    pub fn set_auth_policy(&self, endpoint: &str, policy: AuthPolicy) {
        *self.endpoint(endpoint).auth_policy.lock().unwrap() = policy;
    }

    /// 当前已连接客户端数（握手完成计数；auth 前后均算「已连接」）
    pub fn connected(&self, endpoint: &str) -> usize {
        self.endpoint(endpoint).connected.load(Ordering::SeqCst)
    }

    /// 累计握手成功次数（断线重连断言用：重建后应递增）
    pub fn total_accepted(&self, endpoint: &str) -> u64 {
        self.endpoint(endpoint).total_accepted.load(Ordering::SeqCst)
    }

    /// 收到的全部可解析文本帧（按到达序，跨连接累计）
    pub async fn received_text(&self, endpoint: &str) -> Vec<serde_json::Value> {
        self.endpoint(endpoint).received_text.lock().await.clone()
    }

    /// 收到的全部文本帧原文（含非 JSON 畸形帧）
    pub async fn received_raw_text(&self, endpoint: &str) -> Vec<String> {
        self.endpoint(endpoint).received_raw_text.lock().await.clone()
    }

    /// 收到的全部二进制帧（原始输入字节）
    pub async fn received_binary(&self, endpoint: &str) -> Vec<Vec<u8>> {
        self.endpoint(endpoint).received_binary.lock().await.clone()
    }

    /// 轮询等待收到满足谓词的可解析文本帧（超时 panic；防测试卡死）
    pub async fn wait_for_text(
        &self,
        endpoint: &str,
        mut pred: impl FnMut(&serde_json::Value) -> bool,
        timeout: Duration,
    ) -> Vec<serde_json::Value> {
        let ep = self.endpoint(endpoint);
        let deadline = Instant::now() + timeout;
        loop {
            {
                let guard = ep.received_text.lock().await;
                let matched: Vec<_> = guard.iter().filter(|v| pred(v)).cloned().collect();
                if !matched.is_empty() {
                    return matched;
                }
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for text frame on {endpoint}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 轮询等待收到满足谓词的二进制帧（超时 panic）
    pub async fn wait_for_binary(
        &self,
        endpoint: &str,
        mut pred: impl FnMut(&Vec<u8>) -> bool,
        timeout: Duration,
    ) -> Vec<Vec<u8>> {
        let ep = self.endpoint(endpoint);
        let deadline = Instant::now() + timeout;
        loop {
            {
                let guard = ep.received_binary.lock().await;
                let matched: Vec<_> = guard.iter().filter(|b| pred(b)).cloned().collect();
                if !matched.is_empty() {
                    return matched;
                }
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for binary frame on {endpoint}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 广播一条 JSON 文本帧给该端点全部客户端（事件 / 终端控制帧注入入口）
    pub async fn send_text(&self, endpoint: &str, frame: &serde_json::Value) {
        self.broadcast_text(endpoint, &frame.to_string()).await;
    }

    /// 广播任意文本（畸形帧注入用；模拟服务端发坏帧，客户端应丢弃+留痕不断连）
    pub async fn send_raw_text(&self, endpoint: &str, text: &str) {
        self.broadcast_text(endpoint, text).await;
    }

    /// 广播一条二进制帧（裸字节输出，逐条按序送达；分片=连续调用 send_binary）
    pub async fn send_binary(&self, endpoint: &str, bytes: &[u8]) {
        let ep = self.endpoint(endpoint);
        let guard = ep.sinks.lock().await;
        for sink in guard.iter() {
            let mut s = sink.lock().await;
            let _ = s.send(WsMsg::Binary(bytes.to_vec().into())).await;
        }
    }

    /// 广播一条业务事件帧（session-control 专用；`{"type":"event",...}` 帧壳）
    pub async fn send_event(&self, event: &str, payload: serde_json::Value) {
        let frame = event_frame(event, payload);
        self.send_text(ENDPOINT_SESSION_CONTROL, &frame).await;
    }

    /// 停机：abort accept 循环并 await（listener 确定性关闭、端口释放），
    /// 再 abort 全部连接任务。幂等；消费 self（Drop 不再兜底）。
    pub async fn shutdown(mut self) {
        // async fn 中 Drop 类型的字段不可 move（E0509）：经 mem::swap 取出后置 None
        let mut task = None;
        std::mem::swap(&mut task, &mut self.task);
        let task = task.expect("accept task handle");
        task.abort();
        let _ = task.await; // JoinError::Cancelled：accept 任务确已终止 → listener 已 drop
        let tasks = std::mem::take(&mut *self.state.conn_tasks.lock().unwrap());
        for t in tasks {
            t.abort();
        }
    }

    fn endpoint(&self, name: &str) -> &EndpointState {
        match name {
            ENDPOINT_SESSION_CONTROL => &self.state.session_control,
            ENDPOINT_TERMINAL => &self.state.terminal,
            other => panic!("mock plugin ws: unknown endpoint {other:?}"),
        }
    }

    async fn broadcast_text(&self, endpoint: &str, text: &str) {
        let ep = self.endpoint(endpoint);
        let guard = ep.sinks.lock().await;
        for sink in guard.iter() {
            let mut s = sink.lock().await;
            // 个别连接已关闭时 send 失败 → 忽略（退出连接任务自己会摘除）
            let _ = s.send(WsMsg::Text(text.to_string().into())).await;
        }
    }
}

impl Drop for MockPluginWsServer {
    fn drop(&mut self) {
        // 兜底：测试中途 panic / 未显式 shutdown 时终止全部任务，防端口与 worker 泄漏
        if let Some(t) = self.task.take() {
            t.abort();
        }
        let tasks = std::mem::take(&mut *self.state.conn_tasks.lock().unwrap());
        for t in tasks {
            t.abort();
        }
    }
}

impl EndpointState {
    fn new() -> Self {
        Self {
            auth_policy: std::sync::Mutex::new(AuthPolicy::default()),
            received_text: AsyncMutex::new(Vec::new()),
            received_raw_text: AsyncMutex::new(Vec::new()),
            received_binary: AsyncMutex::new(Vec::new()),
            connected: AtomicUsize::new(0),
            total_accepted: AtomicU64::new(0),
            sinks: AsyncMutex::new(Vec::new()),
        }
    }
}

// ==================== 内部：握手与连接处理 ====================

/// 完成 WS 握手并捕获请求路径（accept_hdr_async 回调是 FnOnce：经 Mutex 槽传回路径）
async fn accept(stream: TcpStream) -> Result<(WebSocketStream<TcpStream>, String), ()> {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    let path_slot: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let slot = path_slot.clone();
    let ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
        *slot.lock().unwrap() = Some(req.uri().path().to_string());
        Ok(resp)
    })
    .await
    .map_err(|_| ())?;
    let path = path_slot.lock().unwrap().take().unwrap_or_default();
    Ok((ws, path))
}

/// 处理单条连接：认证门 → 帧记录 → 断开摘除。
///
/// 认证语义（对齐桌面宿主）：首帧必须为合法 auth 帧；未认证二进制帧 / 非 auth
/// 首帧 / 策略拒绝 → close 4001。帧**先记录后判定**：被拒绝的 auth 帧仍可在
/// `received_text` 中断言到（「校验首帧」可测）。
async fn handle_connection(ep: Arc<EndpointState>, ws: WebSocketStream<TcpStream>) {
    ep.connected.fetch_add(1, Ordering::SeqCst);
    ep.total_accepted.fetch_add(1, Ordering::SeqCst);
    let (tx, mut rx) = ws.split();
    let sink: SharedSink = Arc::new(AsyncMutex::new(tx));
    ep.sinks.lock().await.push(sink.clone());

    let mut authenticated = false;
    while let Some(msg) = rx.next().await {
        match msg {
            Ok(WsMsg::Text(text)) => {
                ep.received_raw_text.lock().await.push(text.to_string());
                let parsed = serde_json::from_str::<serde_json::Value>(&text).ok();
                if let Some(v) = &parsed {
                    ep.received_text.lock().await.push(v.clone());
                }
                if !authenticated {
                    // 首帧认证门：非合法 auth / 策略拒绝 → 关闭（close 4001）
                    if !accept_auth_if_first(&ep, &sink, parsed.as_ref()).await {
                        break;
                    }
                    // 认证通过后本连接不再过门（后续帧按业务协议记录/转发）
                    authenticated = true;
                }
            }
            Ok(WsMsg::Binary(bytes)) => {
                if !authenticated {
                    // 认证前收到的帧：关闭（防御畸形客户端，对齐宿主安全边界）
                    let _ = sink
                        .lock()
                        .await
                        .send(WsMsg::Close(Some(close_frame(
                            AUTH_REJECT_CLOSE_CODE,
                            "binary before auth",
                        ))))
                        .await;
                    break;
                }
                ep.received_binary.lock().await.push(bytes.to_vec());
            }
            Ok(WsMsg::Ping(payload)) => {
                let _ = sink.lock().await.send(WsMsg::Pong(payload)).await;
            }
            Ok(WsMsg::Close(_)) | Err(_) => break,
            // Binary 之外的其它帧（Pong/Frame）：不处理，保持连接存活
            _ => {}
        }
    }

    ep.connected.fetch_sub(1, Ordering::SeqCst);
    ep.sinks.lock().await.retain(|s| !Arc::ptr_eq(s, &sink));
}

/// 首帧认证门：帧为合法 auth 且通过策略 → `true`（已认证）；否则 close 4001 → `false`
async fn accept_auth_if_first(ep: &EndpointState, sink: &SharedSink, frame: Option<&serde_json::Value>) -> bool {
    let Some(frame) = frame else {
        // 首帧非 JSON：协议违规
        let _ = sink
            .lock()
            .await
            .send(WsMsg::Close(Some(close_frame(
                AUTH_REJECT_CLOSE_CODE,
                "first frame must be auth",
            ))))
            .await;
        return false;
    };
    let is_auth = frame.get("type").and_then(|v| v.as_str()) == Some(TYPE_AUTH) && frame.get("token").is_some();
    if !is_auth {
        let _ = sink
            .lock()
            .await
            .send(WsMsg::Close(Some(close_frame(
                AUTH_REJECT_CLOSE_CODE,
                "first frame must be auth",
            ))))
            .await;
        return false;
    }
    let policy = ep.auth_policy.lock().unwrap().clone();
    let accepted = match policy {
        AuthPolicy::RequireAnyToken => true,
        AuthPolicy::RequireToken(expected) => frame.get("token").and_then(|v| v.as_str()) == Some(expected.as_str()),
        AuthPolicy::RejectAll => false,
    };
    if !accepted {
        let _ = sink
            .lock()
            .await
            .send(WsMsg::Close(Some(close_frame(AUTH_REJECT_CLOSE_CODE, "auth rejected"))))
            .await;
        return false;
    }
    true
}

fn close_frame(code: u16, reason: &str) -> CloseFrame<'static> {
    CloseFrame {
        code: CloseCode::from(code),
        reason: reason.to_string().into(),
    }
}

// ==================== 其它 ====================

/// 端点完整路径（`/ws/plugin/com.wasmnest.terminal-session/{endpoint}`；URL 唯一构造点）
pub fn endpoint_path(endpoint: &str) -> String {
    format!("{WS_BASE_PATH}/{endpoint}")
}
