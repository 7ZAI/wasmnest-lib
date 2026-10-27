//! WS 连接骨架（通用连接级状态机，零业务语义）
//!
//! 骨架把「连接生命周期」与「通道协议」分离：
//!
//! - **连接级（本文件）**：握手完成后的心跳（5s ping / 45s 无活动超时）、首消息
//!   认证策略（[`AuthMode`]）与认证超时（10s）、帧级流量过滤链（inbound / outbound）、
//!   会话注册（`WsSessionRegistry`）与离线判定、优雅关闭（链路加密失败 4003）；
//! - **通道级（[`ChannelHandler`]）**：收帧解析、关闭回调、认证通过回调、认证策略声明。
//!
//! 终态（websocket 业务下沉票 08）唯一通道实现是插件端点
//! （`crate::channel::plugin`，`/ws/plugin/{plugin_id}/{path}`）；旧终端/
//! 事件通道（`/ws/terminal/session/{id}`、`/ws/event`）已随业务硬切删除。往宿主 WS
//! 服务器挂新通道 = 新增一个实现 + 路由构造点，不再改本文件（spec §3.2 A1）。

use actix::prelude::*;
use actix_web_actors::ws;
use actix_web_actors::ws::{Message as WsMessage, ProtocolError};
use std::any::Any;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::registry::{WsRegistration, WsSessionRegistry};
use wasmnest_server_base::constants::{HEARTBEAT_INTERVAL_SECS, REMOTE_CLIENT_TIMEOUT_SECS, WS_AUTH_TIMEOUT_SECS};
use wasmnest_server_core::filter::{Direction, FilterContext, TrafficChannel, TrafficFilterChain};
use wasmnest_server_core::link_crypto;

/// 心跳间隔
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);

/// 骨架 actor 上下文（通道处理器经此持有 `Addr<WsConnBase>` 与写帧能力）
pub type ConnCtx = ws::WebsocketContext<WsConnBase>;

// ==================== 通道处理器 ====================

/// 通道认证策略（骨架参数，非硬编码）
///
/// 阶段 B 的插件端点 `auth:"none"` 依赖此声明避免回头改骨架（spec §3.2 A1 / §4.3）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// 首消息认证必需：连接建立后 `WS_AUTH_TIMEOUT_SECS` 内未认证 → 服务端关闭
    Required,
    /// 无需认证：跳过首消息认证状态机与认证超时（`PLUGIN_WS_AUTH_TIMEOUT_SECS` 不适用）
    None,
}

/// WS 通道处理器：由「通道」实现协议语义，骨架只负责连接生命周期
///
/// 骨架保证的调用契约：
/// - `on_started` 在心跳 / 认证超时 / 注册表登记均已就绪后调用一次；
/// - `on_text` / `on_binary` 的入参**已过入站过滤链**（被拒帧不会到达）；
/// - `on_auth_ok` 在 `authenticated` 由 false 翻转为 true 的**该次收帧处理之后**调用
///   （`AuthMode::None` 时骨架在 `on_started` 之后立即调用一次，语义 = 连接可用）；
/// - `on_close` 在骨架停止前调用**恰好一次**（对端 Close 帧、异常断开、服务端主动
///   关闭均收敛到此），供通道回收自有任务与上报断开事件。
pub trait ChannelHandler: Send {
    /// 认证策略声明
    fn auth_mode(&self) -> AuthMode;

    /// 认证超时的关闭码（`AuthMode::Required` 且窗口内未认证时使用）
    ///
    /// `None`（默认）= 不发 Close 帧、直接断开——终端 / 事件通道既有行为逐字
    /// 保持（阶段 A 行为零变化）；插件端点 `auth:"jwt"` 声明 `Some(4001)`
    /// （spec D8：认证超时 / 失败统一 4001）
    fn auth_timeout_close_code(&self) -> Option<u16> {
        None
    }

    /// 连接建立回调（骨架侧登记与超时守卫已就绪）
    fn on_started(&mut self, _conn: &mut WsConnBase, _ctx: &mut ConnCtx) {}

    /// 收到文本帧（已过入站过滤链）
    fn on_text(&mut self, conn: &mut WsConnBase, text: String, ctx: &mut ConnCtx);

    /// 收到二进制帧（已过入站过滤链）
    fn on_binary(&mut self, conn: &mut WsConnBase, data: Vec<u8>, ctx: &mut ConnCtx);

    /// 认证通过回调（或 `AuthMode::None` 下的连接可用回调）
    fn on_auth_ok(&mut self, _conn: &mut WsConnBase, _ctx: &mut ConnCtx) {}

    /// 连接关闭回调（骨架停止前回调，恰好一次）：通道回收自有任务 / 上报断开
    fn on_close(&mut self, _conn: &mut WsConnBase) {}

    /// 通道私有消息（骨架不解释内容，原样转交；实现方自行 downcast）
    fn on_channel_msg(&mut self, _conn: &mut WsConnBase, _msg: Box<dyn Any + Send>, _ctx: &mut ConnCtx) {}
}

// ==================== Actor 消息 ====================

/// 外部推送消息（用于广播/定向发送，由 WsSessionRegistry 调用）
#[derive(Message)]
#[rtype(result = "()")]
pub struct SendTextMessage {
    pub text: String,
}

/// 外部推送二进制帧（插件端点向指定客户端下发二进制；与文本同走过滤链）
#[derive(Message)]
#[rtype(result = "()")]
pub struct SendBinaryMessage {
    pub data: Vec<u8>,
}

/// 终止本连接（订阅者链路回收，如僵尸订阅者）：停止 actor 并关闭 socket
#[derive(Message)]
#[rtype(result = "()")]
pub struct TerminateConnection;

/// 服务端主动关闭本连接（踢出 / 端点注销 / 属主回收），可指定 close code 与原因
///
/// 关闭理由语义（spec §4.5）：宿主踢出缺省 4004、端点注销 / 属主停用 4005
#[derive(Message)]
#[rtype(result = "()")]
pub struct CloseConnection {
    pub code: u16,
    pub reason: String,
}

/// 通道私有 actor 消息载体
///
/// 骨架不解释内容（保持零业务语义），原样转交当前通道处理器的 `on_channel_msg`；
/// 实现方按需 downcast 到自己的消息类型。
#[derive(Message)]
#[rtype(result = "()")]
pub struct ChannelMessage(pub Box<dyn Any + Send>);

/// 连接终止原因（骨架记录，通道在 `on_close` 中读取以上报断开事件）
///
/// 语义区分 `peer_initiated`：对端 Close 帧 vs 宿主主动关闭（踢出 / 端点注销 /
/// 属主停用 / 服务器停机）。`wasClean` 判定（spec D11 规则）只对前者成立
#[derive(Debug, Clone)]
pub(crate) struct CloseOutcome {
    /// 关闭码（对端 Close 未带码时为 `None`）
    pub code: Option<u16>,
    /// 关闭原因文本（对端未提供时为空串）
    pub reason: String,
    /// `true` = 对端主动发 Close 帧；`false` = 宿主主动关闭
    pub peer_initiated: bool,
}

// ==================== 连接骨架 ====================

/// 连接级认证/身份状态（引擎事实，零业务派生字段）
///
/// 终态（websocket 业务下沉票 08）只保留连接事实：对端地址 + JWT 验签后的主体身份
/// （sub / deviceName / fingerprint，连接上下文的脱敏来源）。旧 `subscribed_sessions`
/// 多路订阅与产品会话关联已随会话/终端通道删除（订阅语义归插件）。
#[derive(Debug, Clone)]
pub(crate) struct WsSession {
    /// 客户端地址
    pub addr: SocketAddr,
    /// 设备 ID（JWT 认证后设置）
    pub device_id: Option<String>,
    /// 设备名称（JWT claims 透传，连接上下文脱敏字段）
    pub device_name: Option<String>,
    /// 设备指纹（JWT claims 透传，连接上下文脱敏字段）
    pub fingerprint: Option<String>,
    /// 是否已认证
    pub authenticated: bool,
}

impl WsSession {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            device_id: None,
            device_name: None,
            fingerprint: None,
            authenticated: false,
        }
    }
}

/// 连接构造参数（路由侧声明属主 / 端点标识）
pub struct ConnSpec {
    /// 连接地址（对端）
    pub addr: SocketAddr,
    /// 属主插件 id（端点注册表域寻址与按属主回收）
    pub owner: Option<String>,
    /// 端点标识（端点域寻址：列表 / 单发 / 广播 / 批量断开）
    pub endpoint_id: Option<String>,
}

impl ConnSpec {
    /// 最小构造：仅地址，属主 / 端点标识留空
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            owner: None,
            endpoint_id: None,
        }
    }
}

/// WS 连接骨架 actor
///
/// 一个实例 = 一条 WS 连接。通道协议由 `handler` 决定，连接级状态由本结构持有。
pub struct WsConnBase {
    /// 连接级认证/身份状态（认证态 / 设备身份）
    pub(crate) session: WsSession,
    /// 最近一次收到 Pong / Ping 的时刻（心跳超时判定）
    hb: Instant,
    /// 属主插件 id（插件端点通道）；注册表按此字段做属主回收与跨属主隔离
    pub(crate) owner: Option<String>,
    /// 端点标识（插件端点通道）；注册表按此字段做端点域寻址
    /// （列表 / 单发 / 广播 / 批量断开）
    pub(crate) endpoint_id: Option<String>,
    /// 连接终止原因（对端 Close 帧或宿主主动关闭时置位；异常断开保持 `None`）
    ///
    /// 在 `stopping()` 之前写入，供通道在 `on_close` 中读取以上报断开事件
    /// （插件端点 `ws:client-disconnect` 的 code / reason / wasClean 来源）
    close_outcome: Option<CloseOutcome>,
    /// 通道处理器（构造时注入，连接存续期恒定存在）
    handler: Option<Box<dyn ChannelHandler>>,
    register_on_start: bool,
}

impl WsConnBase {
    /// 以通道处理器构造连接骨架
    ///
    /// `owner` / `endpoint_id` 供注册表做属主隔离与端点域寻址
    pub fn new(spec: ConnSpec, handler: Box<dyn ChannelHandler>) -> Self {
        Self {
            session: WsSession::new(spec.addr),
            hb: Instant::now(),
            owner: spec.owner,
            endpoint_id: spec.endpoint_id,
            close_outcome: None,
            handler: Some(handler),
            register_on_start: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn disable_registry_for_test(&mut self) {
        self.register_on_start = false;
    }

    /// 连接终止原因（`on_close` 中读取；`None` = 异常断开，无 Close 交换）
    pub(crate) fn close_outcome(&self) -> Option<&CloseOutcome> {
        self.close_outcome.as_ref()
    }

    /// 心跳检测
    ///
    /// 本地环回通道（桌面 WebView）保持 10s 超时；远程通道（移动端）放宽到
    /// 45s——移动端在输出风暴/高负载/弱网下 Pong 回复可能延迟，收紧的超时
    /// 会造成断连-重连-再订阅的循环（每次循环都触发前端断连提示）
    fn start_heartbeat(&self, ctx: &mut ConnCtx) {
        let timeout = Duration::from_secs(REMOTE_CLIENT_TIMEOUT_SECS);
        ctx.run_interval(HEARTBEAT_INTERVAL, move |act, ctx| {
            if Instant::now().duration_since(act.hb) > timeout {
                tracing::warn!(client = %act.session.addr, "WebSocket heartbeat timeout");
                ctx.close(None);
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }

    // ==================== 通道处理器分派 ====================
    //
    // 处理器随骨架同生共死（构造即注入），此处 take/replace 只为满足借用规则
    // （处理器需要 `&mut WsConnBase` 才能写帧 / 读会话状态）

    /// 临时取出处理器执行，执行后放回（处理器闭包内可安全借用 `&mut self`）
    ///
    /// 处理器随骨架构造注入、连接存续期恒定存在；槽位为空只可能发生在处理器
    /// panic 中止 actor 之后，此处 fail-visible 记 error（不静默丢帧）
    fn with_handler<R>(&mut self, f: impl FnOnce(&mut dyn ChannelHandler, &mut Self) -> R) -> Option<R> {
        let Some(mut handler) = self.handler.take() else {
            tracing::error!(
                addr = %self.session.addr,
                "channel handler missing (actor aborted by panic), frame dropped"
            );
            return None;
        };
        let result = f(handler.as_mut(), self);
        self.handler = Some(handler);
        Some(result)
    }

    /// 当前通道的认证策略（无处理器时退化为「认证必需」，保守默认）
    fn handler_auth_mode(&self) -> AuthMode {
        self.handler
            .as_ref()
            .map(|h| h.auth_mode())
            .unwrap_or(AuthMode::Required)
    }

    /// 当前通道声明的认证超时关闭码（无处理器 → `None`，保持既有断开行为）
    fn handler_auth_timeout_close_code(&self) -> Option<u16> {
        self.handler.as_ref().and_then(|h| h.auth_timeout_close_code())
    }

    /// 连接建立回调
    fn dispatch_on_started(&mut self, ctx: &mut ConnCtx) {
        self.with_handler(|h, conn| h.on_started(conn, ctx));
    }

    /// 文本帧派发（已过入站过滤链）
    fn dispatch_on_text(&mut self, text: String, ctx: &mut ConnCtx) {
        self.with_handler(|h, conn| h.on_text(conn, text, ctx));
    }

    /// 二进制帧派发（已过入站过滤链）
    fn dispatch_on_binary(&mut self, data: Vec<u8>, ctx: &mut ConnCtx) {
        self.with_handler(|h, conn| h.on_binary(conn, data, ctx));
    }

    /// 认证通过（或无需认证下的连接可用）回调
    fn dispatch_on_auth_ok(&mut self, ctx: &mut ConnCtx) {
        self.with_handler(|h, conn| h.on_auth_ok(conn, ctx));
    }

    /// 连接关闭回调
    fn dispatch_on_close(&mut self) {
        self.with_handler(|h, conn| {
            h.on_close(conn);
        });
    }

    /// 通道私有消息派发
    fn dispatch_channel_msg(&mut self, msg: Box<dyn Any + Send>, ctx: &mut ConnCtx) {
        self.with_handler(|h, conn| h.on_channel_msg(conn, msg, ctx));
    }

    // ==================== Traffic Filter Hooks（流量过滤责任链接线） ====================

    /// 本连接对应的流量通道类型
    ///
    /// 终态（票 08）只有插件端点一类连接，恒为 `WsPlugin`；方法保留为
    /// 过滤链通道标签的事实来源（`TrafficChannel` 仍是传输面分类词汇，
    /// 链路加密配置按通道取档）
    fn traffic_channel(&self) -> TrafficChannel {
        TrafficChannel::WsPlugin
    }

    /// 链路加密失败收尾：Close(4003) 并停止 actor（spec：WS 解密失败不丢帧，
    /// TBv2 序列流丢帧会破坏 ack 环与渲染序，必须断连重建）
    fn close_link_crypto_failure(&self, reason: String, ctx: &mut ConnCtx) {
        tracing::warn!(addr = %self.session.addr, %reason, "link crypto failure, closing 4003");
        ctx.close(Some(ws::CloseReason {
            code: ws::CloseCode::Other(4003),
            description: Some(reason),
        }));
        ctx.stop();
    }

    /// 入站帧过滤：None = 被拒（已关连接），调用方应立即返回
    fn filter_inbound_data(&self, data: Vec<u8>, kind: &'static str, ctx: &mut ConnCtx) -> Option<Vec<u8>> {
        let chain = TrafficFilterChain::global();
        if chain.is_empty() {
            return Some(data);
        }
        let peer = self.session.addr.to_string();
        let mut fctx = FilterContext {
            channel: self.traffic_channel(),
            direction: Direction::Inbound,
            peer: &peer,
            route: kind,
            negotiation: "",
            data,
            outbound_headers: Vec::new(),
        };
        match chain.run_inbound(&mut fctx) {
            Ok(()) => Some(fctx.data),
            Err(rej) => {
                tracing::warn!(
                    addr = %peer,
                    channel = self.traffic_channel().as_str(),
                    frame = kind,
                    %rej,
                    "WS inbound frame rejected by traffic filter"
                );
                self.close_link_crypto_failure(rej.to_string(), ctx);
                None
            }
        }
    }

    /// 入站文本帧过滤（JSON 控制帧 / 业务消息）
    fn filter_inbound_text(&self, text: String, ctx: &mut ConnCtx) -> Option<String> {
        self.filter_inbound_data(text.into_bytes(), "text", ctx)
            .map(|data| String::from_utf8_lossy(&data).into_owned())
    }

    /// 出站文本帧：经过滤链后写出（含 metrics 计数）；被拒 → 丢弃 + warn。
    /// 全部业务文本帧的唯一写出口，广播/推送经 Handler<SendTextMessage> 汇入
    pub(crate) fn send_text_filtered(&self, text: String, ctx: &mut ConnCtx) {
        let chain = TrafficFilterChain::global();
        if chain.is_empty() {
            wasmnest_server_core::metrics::MetricsCollector::global().inc_ws_sent();
            ctx.text(text);
            return;
        }
        let peer = self.session.addr.to_string();
        let mut fctx = FilterContext {
            channel: self.traffic_channel(),
            direction: Direction::Outbound,
            peer: &peer,
            route: "text",
            negotiation: "",
            data: text.into_bytes(),
            outbound_headers: Vec::new(),
        };
        match chain.run_outbound(&mut fctx) {
            Ok(()) => {
                wasmnest_server_core::metrics::MetricsCollector::global().inc_ws_sent();
                ctx.text(String::from_utf8_lossy(&fctx.data).into_owned());
            }
            Err(rej) => {
                tracing::warn!(
                    addr = %peer,
                    channel = self.traffic_channel().as_str(),
                    %rej,
                    "WS outbound text frame rejected by traffic filter"
                );
                self.close_link_crypto_failure(rej.to_string(), ctx);
            }
        }
    }

    /// 出站二进制帧：经过滤链后写出（含 metrics 计数）；被拒 → 丢弃 + warn。
    /// 承载 TB v3 终端输出流（spec §5.3），加密过滤器的主战场
    pub(crate) fn send_binary_filtered(&self, data: Vec<u8>, ctx: &mut ConnCtx) {
        let chain = TrafficFilterChain::global();
        if chain.is_empty() {
            wasmnest_server_core::metrics::MetricsCollector::global().inc_ws_sent();
            ctx.binary(data);
            return;
        }
        let peer = self.session.addr.to_string();
        let mut fctx = FilterContext {
            channel: self.traffic_channel(),
            direction: Direction::Outbound,
            peer: &peer,
            route: "binary",
            negotiation: "",
            data,
            outbound_headers: Vec::new(),
        };
        match chain.run_outbound(&mut fctx) {
            Ok(()) => {
                wasmnest_server_core::metrics::MetricsCollector::global().inc_ws_sent();
                ctx.binary(fctx.data);
            }
            Err(rej) => {
                tracing::warn!(
                    addr = %peer,
                    channel = self.traffic_channel().as_str(),
                    %rej,
                    "WS outbound binary frame rejected by traffic filter"
                );
                self.close_link_crypto_failure(rej.to_string(), ctx);
            }
        }
    }
}

impl Actor for WsConnBase {
    type Context = ConnCtx;

    fn started(&mut self, ctx: &mut Self::Context) {
        if !self.register_on_start {
            return;
        }
        ctx.set_mailbox_capacity(wasmnest_server_base::constants::PLUGIN_WS_SEND_QUEUE_CAPACITY);
        tracing::info!(client = %self.session.addr, "WS connected");
        self.start_heartbeat(ctx);

        let auth_mode = self.handler_auth_mode();
        if auth_mode == AuthMode::Required {
            let auth_timeout = Duration::from_secs(WS_AUTH_TIMEOUT_SECS);
            let close_code = self.handler_auth_timeout_close_code();
            ctx.run_later(auth_timeout, move |act, ctx| {
                if !act.session.authenticated {
                    tracing::warn!(
                        addr = %act.session.addr,
                        "WS auth timeout: no first-message auth within {}s",
                        WS_AUTH_TIMEOUT_SECS
                    );
                    if let Some(code) = close_code {
                        ctx.close(Some(ws::CloseReason {
                            code: ws::CloseCode::Other(code),
                            description: Some("authentication timeout".to_string()),
                        }));
                    }
                    ctx.stop();
                }
            });
        }

        let client_id = self.session.addr.to_string();
        let registration = WsSessionRegistry::global().register_now(WsRegistration {
            client_id,
            socket_addr: self.session.addr,
            actor_addr: ctx.address(),
            owner: self.owner.clone(),
            endpoint_id: self.endpoint_id.clone(),
        });
        if let Err(error) = registration {
            tracing::error!(client_id = %self.session.addr, error = %error, "WS connection registration failed");
            ctx.close(Some(ws::CloseReason {
                code: ws::CloseCode::Other(1011),
                description: Some("connection registration failed".to_string()),
            }));
            ctx.stop();
            return;
        }

        self.dispatch_on_started(ctx);

        if auth_mode == AuthMode::None {
            self.dispatch_on_auth_ok(ctx);
        }
    }

    fn stopping(&mut self, _ctx: &mut Self::Context) -> Running {
        if !self.register_on_start {
            return Running::Stop;
        }
        tracing::info!(client = %self.session.addr, "WS disconnected");

        // 通道侧清理（插件端点：断开事件上报等）
        self.dispatch_on_close();

        // 注销 WsSessionRegistry + 断连清理。
        // 票 07：设备离线判定 / 认证记录 close / device 事件全部归插件
        // （`<owner>::ws:client-disconnect` → 插件自驱 touch/close + emit），
        // 宿主不再代做；本块只剩引擎事实清理（注册表摘除 + 链路加密密码表）。
        let client_id = self.session.addr.to_string();
        actix::spawn(async move {
            let registry = WsSessionRegistry::global();
            registry.unregister(&client_id).await;

            // 断连清理：链路加密密码表（issue 04）——必须在连接标识失效前移除
            link_crypto::ws_remove_ciphers(&client_id);
        });

        Running::Stop
    }
}

/// 处理 WebSocket 消息
impl StreamHandler<Result<WsMessage, ProtocolError>> for WsConnBase {
    fn handle(&mut self, msg: Result<WsMessage, ProtocolError>, ctx: &mut Self::Context) {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                tracing::error!(error = %e, "WS protocol error, closing connection");
                ctx.close(None);
                ctx.stop();
                return;
            }
        };

        match msg {
            WsMessage::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            WsMessage::Pong(_) => {
                self.hb = Instant::now();
            }
            WsMessage::Text(text) => {
                wasmnest_server_core::metrics::MetricsCollector::global().inc_ws_received();
                // 入站先过流量过滤链（解密/审计）；被拒即链路加密失败 → 已 Close 4003
                let Some(text) = self.filter_inbound_text(text.to_string(), ctx) else {
                    return;
                };
                let was_authenticated = self.session.authenticated;
                self.dispatch_on_text(text, ctx);
                if !was_authenticated && self.session.authenticated {
                    self.dispatch_on_auth_ok(ctx);
                }
            }
            WsMessage::Binary(data) => {
                wasmnest_server_core::metrics::MetricsCollector::global().inc_ws_received();
                // 入站先过流量过滤链，被拒即链路加密失败 → 已 Close 4003（不丢帧续跑）
                let Some(data) = self.filter_inbound_data(data.to_vec(), "binary", ctx) else {
                    return;
                };
                let was_authenticated = self.session.authenticated;
                self.dispatch_on_binary(data, ctx);
                if !was_authenticated && self.session.authenticated {
                    self.dispatch_on_auth_ok(ctx);
                }
            }
            WsMessage::Close(reason) => {
                // 记录对端主动关闭（通道在 on_close 中据此判定 wasClean，spec D11）
                self.close_outcome = Some(CloseOutcome {
                    code: reason.as_ref().map(|r| u16::from(r.code)),
                    reason: reason.as_ref().and_then(|r| r.description.clone()).unwrap_or_default(),
                    peer_initiated: true,
                });
                ctx.close(reason);
                ctx.stop();
            }
            _ => {}
        }
    }
}

// ==================== Actor Message Handlers（连接级） ====================

/// 处理外部推送消息（广播/定向发送）
impl Handler<SendTextMessage> for WsConnBase {
    type Result = ();

    fn handle(&mut self, msg: SendTextMessage, ctx: &mut Self::Context) {
        self.send_text_filtered(msg.text, ctx);
    }
}

/// 二进制外部推送（插件端点）：与文本同走出站过滤链（`TrafficChannel::WsPlugin`）
impl Handler<SendBinaryMessage> for WsConnBase {
    type Result = ();

    fn handle(&mut self, msg: SendBinaryMessage, ctx: &mut Self::Context) {
        self.send_binary_filtered(msg.data, ctx);
    }
}

/// 订阅者链路终止（僵尸回收等）：关闭连接并停止 actor。
/// 该动作只影响这一条订阅链路，源产出与其他订阅者不受影响
impl Handler<TerminateConnection> for WsConnBase {
    type Result = ();

    fn handle(&mut self, _msg: TerminateConnection, ctx: &mut Self::Context) {
        ctx.close(None);
        ctx.stop();
    }
}

/// 服务端主动关闭连接（踢出 / 端点注销 / 属主回收）
impl Handler<CloseConnection> for WsConnBase {
    type Result = ();

    fn handle(&mut self, msg: CloseConnection, ctx: &mut Self::Context) {
        tracing::debug!(
            client = %self.session.addr,
            close_code = msg.code,
            reason = %msg.reason,
            "server closing websocket connection"
        );
        // 记录宿主主动关闭（踢出 4004 / 端点注销 / 属主停用 4005 / 停机 1001）：
        // 通道在 on_close 中据此上报断开事件（wasClean 恒 false，spec §4.5）
        self.close_outcome = Some(CloseOutcome {
            code: Some(msg.code),
            reason: msg.reason.clone(),
            peer_initiated: false,
        });
        ctx.close(Some(ws::CloseReason {
            code: ws::CloseCode::Other(msg.code),
            description: Some(msg.reason),
        }));
        ctx.stop();
    }
}

/// 通道私有消息：原样转交给通道处理器
impl Handler<ChannelMessage> for WsConnBase {
    type Result = ();

    fn handle(&mut self, msg: ChannelMessage, ctx: &mut Self::Context) {
        self.dispatch_channel_msg(msg.0, ctx);
    }
}
