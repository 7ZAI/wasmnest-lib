//! 插件端点通道处理器（`/ws/plugin/{plugin_id}/{path}`，spec §2.4 / 票据 05）
//!
//! 通道语义：插件在宿主 WS 服务器上挂载的入站端点。宿主只做引擎级事情——
//! 认证策略执行、帧转发给属主插件、接入/断开事件上报；**业务语义完全归插件**
//! （消息格式、房间、协议、重连策略宿主一概不解读，spec D1）。
//!
//! ## 认证策略（spec D8）
//!
//! - `auth:"none"`（缺省）：跳过首消息认证状态机（[`AuthMode::None`]）——连上即可
//!   收发，认证由插件自管；
//! - `auth:"jwt"`：骨架保证 [`AuthMode::Required`]（窗口内未认证 → close 4001），
//!   本通道校验首消息 `{"type":"auth","token":"<jwt>"}`（**不引入 `message.rs`
//!   类型**）。未认证期间的一切业务帧**丢弃 + warn，不缓存**（spec §4.3）。
//!
//! ## 帧与事件
//!
//! - 入站文本 / 二进制帧经骨架过滤链后转投属主插件（`events-ws` 可选导出），
//!   同连接内保序（单条投递任务串行消费）；
//! - 接入事件 `<owner>::ws:client-connect` 在连接**可用**时发布一次（`auth:"none"`
//!   为连接建立、`auth:"jwt"` 为认证通过），先于该连接的首个业务帧；
//!   断开事件 `<owner>::ws:client-disconnect` 在骨架停止前发布一次
//!   （且仅当接入事件已发布——认证失败/超时不留「无接入的断开」噪音）。
//!
//! 连接生命周期（心跳 / 认证超时 / 帧级过滤链 / 注册表）全部由骨架
//! [`crate::conn`] 承担，本文件只实现通道协议。

use actix::prelude::*;
use actix_web_actors::ws::{CloseCode, CloseReason};
use crate::wire::{owned_topic, WS_CLIENT_CONNECT, WS_CLIENT_DISCONNECT};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::super::conn::{AuthMode, ChannelHandler, ConnCtx, WsConnBase};
use super::super::endpoint::{EndpointAuth, EndpointEntry};
use crate::registry::WsSessionRegistry;
use wasmnest_server_base::constants::PLUGIN_WS_SEND_QUEUE_CAPACITY;
use wasmnest_server_base::ports::BusPort;
// 认证中心裁决返回的身份类型见 `wasmnest_server_base::identity`（AuthCenter 端口的
// 返回类型，本文件不需具名引用）

/// 插件端点认证失败 / 超时的关闭码（spec D8；4000 段为应用自定义码）
const CLOSE_AUTH_FAILED: u16 = 4001;
const CLOSE_BACKPRESSURE: u16 = 1013;

/// 插件端点首消息认证帧（D8：宿主自有的极小契约，不引入 `message.rs` 类型）
///
/// `frame_type` 字段仅测试读取（`auth_mode_follows_endpoint`），生产路径按
/// 帧内容判别走 `token`；保留字段以承载 wire 上的 `type` 键（契约面）
#[derive(Debug, serde::Deserialize)]
struct AuthFrame {
    #[serde(rename = "type")]
    #[allow(dead_code)] // wire 契约字段：反序列化必需，测试断言用
    frame_type: String,
    token: String,
}

/// 待投递帧（通道 → 投递任务）
struct FrameJob {
    kind: &'static str,
    payload: Vec<u8>,
}

enum FrameEnqueueError {
    Full,
    Closed,
}

/// 插件端点通道处理器
///
/// 只持有本连接自有状态（接入/断开上报守卫、帧投递队列）；连接级状态
/// （认证态、地址、关闭原因）在骨架中，经 `&mut WsConnBase` 访问。
pub struct PluginChannel {
    /// 属主插件 id（事件 topic 的属主段 + 帧投递目标）
    owner: String,
    /// 端点句柄（事件 payload 标识）
    endpoint_id: String,
    /// 对端连接 id（= 注册表会话键 = 对端地址字符串，与 `list-clients` 同源）
    client_id: String,
    /// 首消息认证策略
    auth: EndpointAuth,
    /// 端点事件总线 + 帧投递端口（端点上登记，连接侧不依赖宿主运行时上下文
    /// 全局单例；宿主壳注入实现，无头/单测可用假实现）
    bus: Arc<dyn BusPort>,
    /// 接入事件已发布（守卫保证每连接恰好一次）
    connected_announced: bool,
    /// 断开事件已发布（守卫保证每连接恰好一次）
    disconnect_reported: bool,
    /// 帧投递队列发送端（投递任务串行消费 → 同连接保序）
    frames: mpsc::Sender<FrameJob>,
    /// 帧投递队列接收端（`on_started` 时移交给投递任务）
    frames_rx: Option<mpsc::Receiver<FrameJob>>,
}

impl PluginChannel {
    /// 以已注册端点构造通道（`addr` 为对端地址，即会话注册键）
    pub fn new(entry: &EndpointEntry, addr: std::net::SocketAddr) -> Self {
        let (frames, frames_rx) = mpsc::channel(PLUGIN_WS_SEND_QUEUE_CAPACITY);
        Self {
            owner: entry.owner.clone(),
            endpoint_id: entry.endpoint_id.clone(),
            client_id: addr.to_string(),
            auth: entry.auth,
            bus: Arc::clone(&entry.bus),
            connected_announced: false,
            disconnect_reported: false,
            frames,
            frames_rx: Some(frames_rx),
        }
    }

    fn enqueue_frame(&self, kind: &'static str, payload: Vec<u8>) -> Result<(), FrameEnqueueError> {
        match self.frames.try_send(FrameJob { kind, payload }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(FrameEnqueueError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(FrameEnqueueError::Closed),
        }
    }

    fn reject_frame_queue(&mut self, ctx: &mut ConnCtx) {
        tracing::warn!(
            plugin_id = %self.owner,
            endpoint_id = %self.endpoint_id,
            client_id = %self.client_id,
            "plugin endpoint frame queue unavailable, closing 1013"
        );
        ctx.close(Some(CloseReason {
            code: CloseCode::Other(CLOSE_BACKPRESSURE),
            description: Some("endpoint frame queue unavailable".to_string()),
        }));
        ctx.stop();
    }

    /// 未认证期的帧处理（`auth:"jwt"` 专属）
    ///
    /// 首消息必须是认证帧；其余帧丢弃 + warn（不缓存，spec §4.3）。
    /// 认证失败 → close 4001 并断开（不做重试协商，重连编排归插件）。
    fn handle_unauthenticated_frame(&mut self, conn: &mut WsConnBase, text: String, ctx: &mut ConnCtx) {
        let addr = conn.session.addr;
        let value = match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(
                    plugin_id = %self.owner,
                    endpoint_id = %self.endpoint_id,
                    peer = %addr,
                    "plugin endpoint frame dropped: not authenticated (expecting first-message auth frame)"
                );
                return;
            }
        };
        if value.get("type").and_then(serde_json::Value::as_str) != Some("auth") {
            tracing::warn!(
                plugin_id = %self.owner,
                endpoint_id = %self.endpoint_id,
                peer = %addr,
                "plugin endpoint frame dropped: not authenticated (expecting first-message auth frame)"
            );
            return;
        }
        let frame = match serde_json::from_value::<AuthFrame>(value) {
            Ok(frame) => frame,
            Err(_) => {
                self.reject_auth(conn, "malformed authentication frame", ctx);
                return;
            }
        };

        if frame.token.trim().is_empty() {
            self.reject_auth(conn, "no token provided", ctx);
            return;
        }

        match authenticate_endpoint_connection(conn, &frame.token) {
            Ok(subject) => {
                // 注册表认证态同步（异步态：list-clients 的 authenticated 字段来源）。
                // 不经 `authenticate_jwt`：插件端点的第三方客户端**不参与配对设备
                // 在线语义**（不快照 last_seen、不向前端发 DEVICE_CONNECTED）
                let client_id = self.client_id.clone();
                let device_name = conn.session.device_name.clone();
                let fingerprint = conn.session.fingerprint.clone();
                if !WsSessionRegistry::global().set_authenticated_now(
                    &client_id,
                    Some(subject),
                    device_name,
                    fingerprint,
                ) {
                    self.reject_auth(conn, "connection registration unavailable", ctx);
                    return;
                }
                tracing::info!(
                    plugin_id = %self.owner,
                    endpoint_id = %self.endpoint_id,
                    peer = %addr,
                    "plugin endpoint client authenticated"
                );
            }
            Err((_code, message)) => self.reject_auth(conn, &message, ctx),
        }
    }

    /// 认证失败收尾：close(4001) + 停止 actor
    fn reject_auth(&mut self, conn: &mut WsConnBase, message: &str, ctx: &mut ConnCtx) {
        tracing::warn!(
            plugin_id = %self.owner,
            endpoint_id = %self.endpoint_id,
            peer = %conn.session.addr,
            reason = %message,
            "plugin endpoint auth failed, closing 4001"
        );
        ctx.close(Some(CloseReason {
            code: CloseCode::Other(CLOSE_AUTH_FAILED),
            description: Some(message.to_string()),
        }));
        ctx.stop();
    }

    /// 发布接入事件（恰好一次）
    fn announce_connect(&mut self, conn: &WsConnBase) {
        if self.connected_announced {
            return;
        }
        self.connected_announced = true;
        let addr = conn.session.addr.to_string();
        self.bus.publish(
            &owned_topic(&self.owner, WS_CLIENT_CONNECT),
            "host",
            serde_json::json!({
                "endpointId": self.endpoint_id,
                "clientId": addr,
                "addr": addr,
                "authenticated": conn.session.authenticated,
            }),
        );
        tracing::info!(
            plugin_id = %self.owner,
            endpoint_id = %self.endpoint_id,
            client_id = %self.client_id,
            "plugin endpoint client connected"
        );
    }
}

/// 插件端点认证（只置会话认证态，不触达配对设备在线语义）
///
/// **验签与策略都由认证中心做**（v33 / ADR 0033）：宿主不再持有任何设备 JWT
/// 密码学（`utils/auth/jwt.rs` 已退役），这里只问中心一次
/// （`enforce_connection_policy`，与 HTTP 中间件 `auth_gateway::authenticate_with_center`
/// **同一条路径、同一个判据**），成功后把中心交回的连接身份写进连接会话。
///
/// fail-closed（ADR 0031）：无中心 / 调用失败 / 中心拒绝 → 拒绝连接（随后 close
/// 4001），`deny_kind` 三态在中心桥接面分类；仅当端口注册表未注入（无头 / 单测）跳过。
fn authenticate_endpoint_connection(conn: &mut WsConnBase, token: &str) -> Result<String, (String, String)> {
    // 宿主壳注入的 AuthCenter 端口：无端口（无头 / 单测上下文）即无中心可问
    // （生产运行期不存在此路径），语义同既有「无端口注册表 → 跳过」分支
    let Some(ports) = wasmnest_server_base::ports::get() else {
        return Err((
            "AUTH_FAILED".to_string(),
            "auth center unavailable: no runtime context".to_string(),
        ));
    };
    let identity = ports
        .auth_center
        .enforce_connection_policy(token)
        .map_err(|reason| ("AUTH_FAILED".to_string(), reason))?;

    conn.session.authenticated = true;
    conn.session.device_id = Some(identity.device_id.clone());
    conn.session.device_name = identity.device_name.clone();
    conn.session.fingerprint = identity.fingerprint.clone();
    Ok(identity.device_id)
}

/// 帧投递任务：串行消费队列并投给属主插件（同连接内保序，spec §2.2 D2）
///
/// 通道随连接销毁时发送端被 drop → 队列排空后任务自然结束。
async fn run_endpoint_delivery(
    mut rx: mpsc::Receiver<FrameJob>,
    bus: Arc<dyn BusPort>,
    owner: String,
    endpoint_id: String,
    client_id: String,
) {
    while let Some(job) = rx.recv().await {
        bus.deliver_endpoint_frame(&owner, &endpoint_id, &client_id, job.kind, job.payload)
            .await;
    }
}

impl ChannelHandler for PluginChannel {
    /// 认证策略由端点注册时声明（spec D8）
    fn auth_mode(&self) -> AuthMode {
        match self.auth {
            EndpointAuth::None => AuthMode::None,
            EndpointAuth::Jwt => AuthMode::Required,
        }
    }

    /// 认证超时统一 close 4001（`auth:"none"` 无认证窗口，不适用）
    fn auth_timeout_close_code(&self) -> Option<u16> {
        match self.auth {
            EndpointAuth::None => None,
            EndpointAuth::Jwt => Some(CLOSE_AUTH_FAILED),
        }
    }

    fn on_started(&mut self, _conn: &mut WsConnBase, _ctx: &mut ConnCtx) {
        // 启动帧投递任务（队列在工作线程上串行消费；不阻塞 actor）
        //
        // **必须派生到 ambient runtime**（不能用 `actix::spawn`）：投递是同步桥
        // （`block_on_async`），会阻塞所在线程直到客人回调返回；若落在 arbiter 线程上，
        // 客人回调内的宿主 WS 原语（`send-text-to-client` / `broadcast-*` / `close-client`）
        // 需要 await arbiter 上的连接 actor —— arbiter 被投递自己占住，双方互等即自锁
        // （插件端点回显的必经路径）。派生到 ambient 后 arbiter 保持空闲，actor 正常推进。
        if let Some(rx) = self.frames_rx.take() {
            let bus = Arc::clone(&self.bus);
            let owner = self.owner.clone();
            let endpoint_id = self.endpoint_id.clone();
            let client_id = self.client_id.clone();
            let ambient = wasmnest_server_base::ports::get().map(|p| p.runtime.ambient_handle());
            if let Some(ambient) = ambient {
                wasmnest_server_base::error_boundary::spawn_with_error_boundary_on(
                    &ambient,
                    "ws_endpoint_delivery",
                    run_endpoint_delivery(rx, bus, owner, endpoint_id, client_id),
                );
            }
        }
    }

    /// 连接可用（`auth:"none"` 建立即可用 / `auth:"jwt"` 认证通过）→ 接入事件一次
    ///
    /// 骨架保证本回调先于该连接的首个业务帧投递（认证帧除外）
    fn on_auth_ok(&mut self, conn: &mut WsConnBase, _ctx: &mut ConnCtx) {
        self.announce_connect(conn);
    }

    fn on_text(&mut self, conn: &mut WsConnBase, text: String, ctx: &mut ConnCtx) {
        if self.auth == EndpointAuth::Jwt && !conn.session.authenticated {
            self.handle_unauthenticated_frame(conn, text, ctx);
            return;
        }
        if self.enqueue_frame("text", text.into_bytes()).is_err() {
            self.reject_frame_queue(ctx);
        }
    }

    fn on_binary(&mut self, conn: &mut WsConnBase, data: Vec<u8>, ctx: &mut ConnCtx) {
        if self.auth == EndpointAuth::Jwt && !conn.session.authenticated {
            // 二进制帧不能承载认证帧（认证帧是 JSON 文本）→ 一律丢弃 + warn
            tracing::warn!(
                plugin_id = %self.owner,
                endpoint_id = %self.endpoint_id,
                peer = %conn.session.addr,
                bytes = data.len(),
                "plugin endpoint binary frame dropped: not authenticated"
            );
            let _ = ctx;
            return;
        }
        if self.enqueue_frame("binary", data).is_err() {
            self.reject_frame_queue(ctx);
        }
    }

    /// 断开上报（骨架停止前回调，恰好一次）
    ///
    /// 仅在接入事件已发布时上报（认证失败 / 超时连接从未「接入」）；
    /// 关闭码与 `wasClean` 取自骨架记录的连接终止原因（spec §4.5 / D11）：
    /// 对端 Close 且 code ∈ {1000,1001} → clean；宿主主动断开（踢出 4004 /
    /// 端点注销 · 属主停用 4005 / 停机 1001）→ 恒 false。
    fn on_close(&mut self, conn: &mut WsConnBase) {
        if !self.connected_announced || self.disconnect_reported {
            return;
        }
        self.disconnect_reported = true;

        let (code, reason, was_clean) = match conn.close_outcome() {
            Some(outcome) if outcome.peer_initiated => (
                outcome.code,
                outcome.reason.clone(),
                matches!(outcome.code, Some(1000) | Some(1001)),
            ),
            Some(outcome) => (outcome.code, outcome.reason.clone(), false),
            // 异常断开（传输错误 / 心跳超时 / 订阅链路终止）：无 Close 交换
            None => (None, String::new(), false),
        };

        let mut payload = serde_json::json!({
            "endpointId": self.endpoint_id,
            "clientId": self.client_id,
            "wasClean": was_clean,
        });
        if let Some(code) = code {
            payload["code"] = serde_json::Value::Number(code.into());
        }
        if !reason.is_empty() {
            payload["reason"] = serde_json::Value::String(reason);
        }
        self.bus
            .publish(&owned_topic(&self.owner, WS_CLIENT_DISCONNECT), "host", payload);
        tracing::info!(
            plugin_id = %self.owner,
            endpoint_id = %self.endpoint_id,
            client_id = %self.client_id,
            was_clean,
            "plugin endpoint client disconnected"
        );
    }
}

// ==================== Tests ====================

// 用例按功能拆至 `plugin/tests/`（本内联模块的子模块路径由 rustc
// 自动解析到该目录；模块树 `channel::plugin::tests::<文件>` 与内联形态等价，私有项可见性不受影响）。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{register, EndpointAuth};
    use std::net::SocketAddr;
    use std::sync::Arc;
    // 跨分组共享的测试脚手架（子模块经 `use super::*` 可见）

    fn test_endpoint(seed: &str, auth: EndpointAuth) -> EndpointEntry {
        let owner = format!("test-plugin-channel-{seed}");
        register(&owner, "echo", auth, None, None, Arc::new(TestBus)).expect("register endpoint")
    }
    /// 测试假总线（通道只存句柄；无头/单测上下文不投递）
    struct TestBus;
    #[async_trait::async_trait]
    impl wasmnest_server_base::ports::BusPort for TestBus {
        fn publish(&self, _topic: &str, _sender: &str, _payload: serde_json::Value) {}
        fn publish_binary(&self, _topic: &str, _sender: &str, _payload: Vec<u8>) {}
        async fn subscribe_static(
            &self,
            _subscriber: &str,
            _topic: &str,
            _handler: Box<dyn wasmnest_server_base::ports::BusMessageHandler>,
        ) {
        }
        async fn deliver_endpoint_frame(
            &self,
            _owner: &str,
            _endpoint_id: &str,
            _client_id: &str,
            _kind: &str,
            _payload: Vec<u8>,
        ) {
        }
    }
    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }
    mod auth_mode_follows_endpoint;
}
