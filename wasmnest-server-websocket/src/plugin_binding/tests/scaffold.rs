//! `plugin_binding` 的跨分组测试脚手架（用例文件经 `use super::scaffold::*` 引用）
//!
//! **为什么自带假端口**：本域的端口实现属宿主（`宿主 adapter（src-tauri/src/plugin/ws.rs）的 HostWsPorts`），
//! crate 内不能引用宿主 bin crate ⇒ 单测必须在 crate 内造一份假实现。
//! 假端口同时是「机制自持」的可测性证据：权限门、事件寻址、帧投递三态的断言
//! 全在本域内闭环，不经宿主上下文。

use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use wasmnest_server_base::ports::{BusMessageHandler, BusPort};

use super::*;
use crate::plugin_binding::ports::{BoxedBlocked, FrameDispatch, WsFrameTarget, WsPorts};

/// 唯一插件 id（静态表按 id 隔离，并行用例互不干扰）
pub(super) fn test_plugin(seed: &str) -> String {
    format!("test-ws-{seed}")
}

// ==================== 假端口 ====================

/// 假端口（不触宿主、不起总线）：权限授予集 + 事件捕获 + 帧投递结果编排
pub(super) struct FakePorts {
    /// 已授权的 `(plugin_id, permission)` 对
    granted: HashSet<(String, String)>,
    /// 捕获到的事件投递（topic, payload）
    published: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    /// 帧投递结果（编排降级路径的三态）
    dispatch_result: std::sync::Mutex<FrameDispatch>,
}

impl FakePorts {
    /// 按「(插件, 权限)」清单造端口（空清单 = 一律拒绝）
    pub(super) fn with(grants: &[(&str, &str)]) -> Arc<FakePorts> {
        Arc::new(FakePorts {
            granted: grants
                .iter()
                .map(|(plugin, permission)| (plugin.to_string(), permission.to_string()))
                .collect(),
            published: std::sync::Mutex::new(Vec::new()),
            dispatch_result: std::sync::Mutex::new(FrameDispatch::Delivered),
        })
    }

    /// 捕获到的事件（按到达序）
    pub(super) fn published(&self) -> Vec<(String, serde_json::Value)> {
        self.published.lock().expect("published sink poisoned").clone()
    }

    /// 编排帧投递结果（`NotExported` = 未导出 `events-ws` 的降级路径）
    pub(super) fn set_dispatch_result(&self, result: FrameDispatch) {
        *self.dispatch_result.lock().expect("dispatch result poisoned") = result;
    }
}

impl WsPorts for FakePorts {
    fn check_permission(&self, plugin_id: &str, permission: &str, _api: &str) -> bool {
        self.granted
            .iter()
            .any(|(p, perm)| p == plugin_id && perm == permission)
    }

    fn publish(&self, topic: &str, payload: serde_json::Value) {
        self.published
            .lock()
            .expect("published sink poisoned")
            .push((topic.to_string(), payload));
    }

    fn bus_port(&self) -> Arc<dyn BusPort> {
        Arc::new(TestBus)
    }

    fn dispatch_frame(
        &self,
        _plugin_id: &str,
        _target: WsFrameTarget<'_>,
        _kind: &str,
        _payload: Vec<u8>,
    ) -> FrameDispatch {
        self.dispatch_result.lock().expect("dispatch result poisoned").clone()
    }

    /// 同步↔异步桥（测试替身）：新线程 + 独立 multi-thread runtime 驱动。
    ///
    /// 与宿主 `runtime_util::block_on_async` 的 current_thread 分支同策略
    /// （本域的用例跑在 `#[tokio::test]` / `#[actix_rt::test]` 的 current_thread
    /// 运行时里，同线程 `block_on` 必死锁）。
    fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .expect("test bridge runtime")
                        .block_on(fut)
                })
                .join()
                .expect("test bridge driver thread must not panic")
        })
    }
}

/// 端点登记要挂的总线端口（测试替身：帧投递是空实现——回灌路径不在本组用例）
pub(super) struct TestBus;

#[async_trait]
impl BusPort for TestBus {
    fn publish(&self, _topic: &str, _sender: &str, _payload: serde_json::Value) {}

    fn publish_binary(&self, _topic: &str, _sender: &str, _payload: Vec<u8>) {}

    async fn subscribe_static(&self, _subscriber: &str, _topic: &str, _handler: Box<dyn BusMessageHandler>) {}

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

/// 空通道处理器（与 conn / registry 测试同款：仅满足骨架构造约束，不被驱动）
pub(super) struct StubWsChannel;

impl crate::conn::ChannelHandler for StubWsChannel {
    fn auth_mode(&self) -> crate::conn::AuthMode {
        crate::conn::AuthMode::None
    }

    fn on_text(&mut self, _conn: &mut crate::conn::WsConnBase, _text: String, _ctx: &mut crate::conn::ConnCtx) {}

    fn on_binary(&mut self, _conn: &mut crate::conn::WsConnBase, _data: Vec<u8>, _ctx: &mut crate::conn::ConnCtx) {}
}

// ==================== 客户端域脚手架 ====================

/// 伪造一条出站连接条目（不真连网络）：写任务持有永不消费的队列
/// `ports` 暂未使用——作为插件的宿主端口句柄备用（签名保持会话构造的完整性）
pub(super) fn fake_client(_ports: &Arc<dyn WsPorts>, owner: &str, handle: &str, url: &str) {
    let (tx, rx) = mpsc::channel(PLUGIN_WS_SEND_QUEUE_CAPACITY);
    // 队列接收端挂起任务持有，保证 try_send 非 Closed 语义
    let writer = spawn_with_error_boundary("ws_test_writer", async move {
        let mut rx = rx;
        while rx.recv().await.is_some() {}
    });
    let reader = spawn_with_error_boundary("ws_test_reader", async {});
    CLIENTS.lock().unwrap().insert(
        handle.to_string(),
        ClientEntry {
            owner: owner.to_string(),
            url: url.to_string(),
            tx,
            state: Arc::new(AtomicU8::new(STATE_OPEN)),
            reader,
            writer,
        },
    );
}

/// 摘除并清理测试条目（避免污染其他用例的计数）
pub(super) fn drop_client(handle: &str) {
    if let Some(entry) = CLIENTS.lock().unwrap().remove(handle) {
        entry.reader.abort();
        entry.writer.abort();
    }
}

// ==================== 服务端域脚手架 ====================

/// 注册端点并返回句柄（形状合法时的成功路径 = 句柄 `wse-<uuid>`）
pub(super) fn register_endpoint(ports: &Arc<dyn WsPorts>, plugin: &str, path: &str) -> String {
    ws_register_endpoint(ports, plugin, &format!(r#"{{"path":"{path}"}}"#)).expect("register endpoint")
}

/// 摘除端点（全局表跨用例共享，用例结束必须清理）
pub(super) fn drop_endpoint(endpoint_id: &str) {
    crate::endpoint::remove(endpoint_id);
}

/// 在**全局**注册表登记一条插件端点连接（伪 WS 握手取得 Addr；独立 seed
/// 互不干扰，可并行）——注册表键 = 派生 socket addr 串（镜像生产：client_id
/// 即对端地址串），返回该 client_id 供查询/清理；`authenticated` 时同步
/// subject/deviceName/fingerprint
#[allow(clippy::too_many_arguments)]
pub(super) async fn register_endpoint_client(
    seed: &str,
    owner: &str,
    endpoint_id: &str,
    authenticated: bool,
    subject: Option<&str>,
    device_name: Option<&str>,
    fingerprint: Option<&str>,
) -> String {
    use crate::conn::{ConnSpec, WsConnBase};
    use crate::registry::WsRegistration;

    let port = 30000u16 + (seed.bytes().fold(0usize, |acc, b| acc.wrapping_add(b as usize)) % 10000) as u16;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let client_id = addr.to_string();
    let actor_ctx_addr = addr;
    let req = actix_web::test::TestRequest::default()
        .insert_header(("Connection", "Upgrade"))
        .insert_header(("Upgrade", "websocket"))
        .insert_header(("Sec-WebSocket-Version", "13"))
        .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .to_http_request();
    let payload: actix_web::dev::Payload = actix_web::dev::Payload::None;
    let actor = WsConnBase::new(
        ConnSpec {
            owner: Some(owner.to_string()),
            endpoint_id: Some(endpoint_id.to_string()),
            ..ConnSpec::new(actor_ctx_addr)
        },
        Box::new(StubWsChannel),
    );
    let (actor_addr, _resp) = actix_web_actors::ws::WsResponseBuilder::new(actor, &req, payload)
        .start_with_addr()
        .expect("fake ws handshake must succeed");
    WsSessionRegistry::global()
        .register(WsRegistration {
            client_id: client_id.clone(),
            socket_addr: addr,
            actor_addr,
            owner: Some(owner.to_string()),
            endpoint_id: Some(endpoint_id.to_string()),
        })
        .await;
    if authenticated {
        WsSessionRegistry::global()
            .set_authenticated(
                &client_id,
                subject.map(str::to_string),
                device_name.map(str::to_string),
                fingerprint.map(str::to_string),
            )
            .await;
    }
    client_id
}

/// 摘除全局注册表测试条目（用例结束清理）
pub(super) async fn drop_registry_client(client_id: &str) {
    WsSessionRegistry::global().unregister(client_id).await;
}
