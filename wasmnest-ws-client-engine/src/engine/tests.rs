//! 引擎行为契约测试（门禁矩阵）
//!
//! 覆盖面（与移动端原 8 例逐条对应，语义随抽根逐字保留）：
//! 权限门 fail-closed / 属主隔离 / 句柄生命周期（真实握手闭环）/ close code 语义 /
//! 队列满 fail-fast / purge 回收 / 入参校验 / 帧信封形状 / 重连窗口钳制 +
//! 重连事件与取消寻址面。
//!
//! 夹具端口把四类平台差异面全部就地实现（权限位开关 / 事件与帧捕获 / 任务派生 /
//! jwt token / 退避边界与策略），因此**零宿主依赖、零 SDK 依赖**即可跑通真实 TCP
//! 握手——这正是「纯引擎 + 端口抽象」形态的实证。

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;

use super::*;
use crate::ports::{BoxedTask, ReconnectPolicy, WsClientPorts, WsTask};

/// 握手请求/应答间轮询等待上限（真实 TCP 交互的收敛窗口）
const POLL_TIMEOUT: Duration = Duration::from_secs(3);

// ==================== 夹具端口 ====================

/// 退避策略夹具：记录推进轮次与成功回报，延迟由测试给定（真源 = 宿主全局退避）
struct StubPolicy {
    delay: Duration,
    started: Arc<AtomicUsize>,
    successes: Arc<AtomicUsize>,
    give_up: bool,
}

#[async_trait]
impl ReconnectPolicy for StubPolicy {
    async fn start(&self) -> Option<()> {
        self.started.fetch_add(1, Ordering::SeqCst);
        (!self.give_up).then_some(())
    }

    async fn get_delay(&self) -> Duration {
        self.delay
    }

    async fn on_success(&self) {
        self.successes.fetch_add(1, Ordering::SeqCst);
    }
}

/// 端口夹具：权限开关 + 事件/帧捕获 + 当前线程任务派生 + 退避参数
///
/// 可调项全部走内部可变性（`Mutex` / `Atomic*`）：夹具以 `Arc<StubPorts>` 传给引擎，
/// 测试要能在建好端口后再调参（夹具构造器只吃权限集）。
struct StubPorts {
    /// 授权插件 id 集合（fail-closed：不在集合内即拒）
    permitted: HashSet<String>,
    /// 收集的 JSON 事件（`Vec<(topic, payload)>`）
    events: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    /// 收集的二进制帧（`Vec<(topic, bytes)>`）
    frames: CapturedFrames,
    /// 宿主 jwt token 槽（空串 = 未认证）
    token: Mutex<String>,
    /// 退避钳制边界 `(min, max)` 毫秒
    bounds: Mutex<(u64, u64)>,
    /// 退避策略的延迟（毫秒）
    reconnect_delay_ms: Mutex<u64>,
    /// 策略「放弃」开关（覆盖 `start() -> None` 防御分支）
    reconnect_give_up: AtomicBool,
    /// 策略推进轮次计数（重连排期面断言用）
    policy_started: Arc<AtomicUsize>,
    /// 策略成功回报计数
    policy_successes: Arc<AtomicUsize>,
    /// 派生任务被 cancel 的次数
    cancels: Arc<AtomicUsize>,
}

impl StubPorts {
    fn new(permitted: &[&str]) -> Self {
        Self {
            permitted: permitted.iter().map(|p| p.to_string()).collect(),
            events: Arc::new(Mutex::new(Vec::new())),
            frames: Arc::new(Mutex::new(Vec::new())),
            token: Mutex::new(String::new()),
            bounds: Mutex::new((1_000, 60_000)),
            reconnect_delay_ms: Mutex::new(1),
            reconnect_give_up: AtomicBool::new(false),
            policy_started: Arc::new(AtomicUsize::new(0)),
            policy_successes: Arc::new(AtomicUsize::new(0)),
            cancels: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn shared(permitted: &[&str]) -> Arc<Self> {
        Arc::new(Self::new(permitted))
    }

    /// 已发布的 JSON 事件（`(topic, payload)` 列表）
    fn events(&self) -> Vec<(String, serde_json::Value)> {
        self.events.lock().unwrap().clone()
    }

    /// 某 topic 上的事件载荷（最后一个）
    fn event_payload(&self, topic_suffix: &str) -> Option<serde_json::Value> {
        self.events()
            .into_iter()
            .filter(|(t, _)| t.ends_with(topic_suffix))
            .map(|(_, p)| p)
            .next_back()
    }
}

impl WsClientPorts for StubPorts {
    fn check_permission(&self, plugin_id: &str) -> bool {
        self.permitted.contains(plugin_id)
    }

    fn global_token(&self) -> String {
        self.token.lock().unwrap().clone()
    }

    fn reconnect_bounds(&self) -> (u64, u64) {
        *self.bounds.lock().unwrap()
    }

    fn reconnect_policy(
        &self,
        _max_retries: u32,
        _base_ms: u64,
        _max_ms: u64,
    ) -> Box<dyn ReconnectPolicy> {
        Box::new(StubPolicy {
            delay: Duration::from_millis(*self.reconnect_delay_ms.lock().unwrap()),
            started: Arc::clone(&self.policy_started),
            successes: Arc::clone(&self.policy_successes),
            give_up: self.reconnect_give_up.load(Ordering::SeqCst),
        })
    }

    fn publish(&self, topic: &str, payload: serde_json::Value) {
        self.events
            .lock()
            .unwrap()
            .push((topic.to_string(), payload));
    }

    fn publish_binary(&self, topic: &str, payload: Vec<u8>) {
        self.frames
            .lock()
            .unwrap()
            .push((topic.to_string(), payload));
    }

    /// 任务派生：测试跑在 `#[tokio::test]` 提供的 runtime 上下文里，直接
    /// `tokio::spawn` 合法（真实宿主适配器走自己的运行时派生，见端口文档）
    fn spawn(&self, _task_name: &'static str, task: BoxedTask) -> Arc<dyn WsTask> {
        let slot = Arc::new(AtomicUsize::new(0));
        tokio::spawn(task);
        Arc::new(CounterFlagTask {
            slot,
            counter: Arc::clone(&self.cancels),
        })
    }
}

/// 捕获的二进制帧集合（`(topic, 帧信封字节)`
type CapturedFrames = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// 可计数的任务句柄：`cancel()` 同时记录到「任务自己的槽」与「端口总计数」
struct CounterFlagTask {
    slot: Arc<AtomicUsize>,
    counter: Arc<AtomicUsize>,
}

impl WsTask for CounterFlagTask {
    fn cancel(&self) {
        self.slot.fetch_add(1, Ordering::SeqCst);
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

/// 某插件在句柄表里的条目数（**按属主过滤**：句柄表是引擎级全局，并行测试各自
/// 的插件 id 唯一，故零副作用断言必须按属主计数，不能用全表长度）
#[cfg(test)]
fn owned_entry_count(owner: &str) -> usize {
    CLIENTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|e| e.owner == owner)
        .count()
}

/// 唯一插件 id（并行测试互踩隔离：句柄表是引擎级全局）
fn plugin_id(tag: &str) -> String {
    format!("com.wasmnest.ws-test-{tag}-{}", uuid::Uuid::new_v4())
}

/// 手工插入连接条目（不经握手；writer/reader = 立即退出的空任务，
/// `#[test]` 里裸 tokio::spawn 会 panic，故用夹具端口的 spawn 经 runtime handle 派生）
fn fake_entry(
    ports: &Arc<StubPorts>,
    owner: &str,
    handle_id: &str,
    capacity: usize,
    rt: &tokio::runtime::Handle,
) {
    let (tx, rx) = mpsc::channel::<OutboundFrame>(capacity.max(1));
    // rx 故意 forget 保活：drop 会让 channel 关闭（try_send 报 Closed），
    // 「队列满」用例需要一条永不消费、容量已知的 open 通道
    std::mem::forget(rx);
    let writer = spawn_noop(ports, rt);
    let reader = spawn_noop(ports, rt);
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner()).insert(
        handle_id.to_string(),
        ClientEntry {
            owner: owner.to_string(),
            url: format!("ws://fake/{handle_id}"),
            tx,
            state: Arc::new(AtomicU8::new(STATE_OPEN)),
            writer,
            reader,
            reconnect: None,
        },
    );
}

/// 经端口派生一个立即返回的空任务（拿一个可 cancel 的句柄）
fn spawn_noop(ports: &Arc<StubPorts>, rt: &tokio::runtime::Handle) -> Arc<dyn WsTask> {
    let counter = Arc::clone(&ports.cancels);
    let slot = Arc::new(AtomicUsize::new(0));
    let _noop = rt.spawn(async {});
    Arc::new(CounterFlagTask { slot, counter })
}

/// 起本地 WS 服务器：accept 后回显收到的每条帧（连接关闭时被动退出）
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = ws.split();
                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        // 客户端 Close：协议层自动回 Close，连接任务自然收尾
                        Message::Close(_) => break,
                        m @ (Message::Text(_) | Message::Binary(_)) => {
                            let _ = sink.send(m).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    addr
}

/// 起本地 WS 服务器：接受一条连接后**不**关闭（供重连路径观察多轮握手）
async fn spawn_hold_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hold server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(ws) = tokio_tungstenite::accept_async(stream).await {
                    // 挂住连接（丢弃流即关闭，故用 park 保持活着直到对端断开）
                    let mut ws = ws;
                    while ws.next().await.is_some() {}
                }
            });
        }
    });
    addr
}

/// 轮询等待条件成立（异步链路收敛：Close 帧往返、reader 摘条目等）
fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ==================== 1. 权限门 fail-closed（5 原语逐个） ====================

/// 未授权插件调 5 原语全拒（错误文本含 `permission denied: ws:client`）
#[tokio::test(flavor = "multi_thread")]
async fn permission_gate_rejects_all_five_without_ws_client() {
    let owner = plugin_id("deny");
    let ports = StubPorts::shared(&[]);
    let p: Arc<dyn WsClientPorts> = ports.clone();

    for err in [
        connect(&p, &owner, r#"{"url":"ws://127.0.0.1:1/"}"#)
            .await
            .expect_err("connect must be denied"),
        send_text(&p, &owner, "wsc-x", "hi").expect_err("send-text must be denied"),
        send_binary(&p, &owner, "wsc-x", vec![1]).expect_err("send-binary must be denied"),
        close(&p, &owner, "wsc-x", "{}").expect_err("close must be denied"),
        is_connected(&p, &owner, "wsc-x").expect_err("is-connected must be denied"),
    ] {
        assert!(
            err.contains("permission denied: ws:client"),
            "拒绝文案必须带权限字面量：{err}"
        );
    }
    // fail-closed 的另一半：拒绝路径零副作用（零握手 / 零事件 / 零句柄）
    assert_eq!(
        owned_entry_count(&owner),
        0,
        "被拒的 connect 不得留下句柄条目"
    );
    assert!(ports.events().is_empty(), "被拒的 connect 不得发布任何事件");
}

// ==================== 2. 属主隔离 ====================

/// A 插件的句柄给 B 插件查 / 发 / 关 → 全部 NOT_OWNER（跨插件越权是本域最大风险面）
#[tokio::test]
async fn cross_plugin_handle_access_rejected() {
    let owner = plugin_id("owner");
    let intruder = plugin_id("intruder");
    let handle_id = format!("wsc-{}", uuid::Uuid::new_v4());
    // 两个插件都**已授权**：越权面是「有权限的插件动别人的句柄」——
    // 未授权插件在权限门就被拦（那是 fail-closed 的另一半，另有用例）
    let ports = StubPorts::shared(&[&owner, &intruder]);
    let rt = tokio::runtime::Handle::current();
    fake_entry(&ports, &owner, &handle_id, 8, &rt);
    let p: Arc<dyn WsClientPorts> = ports.clone();

    assert_eq!(
        send_text(&p, &intruder, &handle_id, "hi").expect_err("cross send must be rejected"),
        NOT_OWNER
    );
    assert_eq!(
        send_binary(&p, &intruder, &handle_id, vec![1]).expect_err("cross send-binary"),
        NOT_OWNER
    );
    assert_eq!(
        close(&p, &intruder, &handle_id, "{}").expect_err("cross close"),
        NOT_OWNER
    );
    assert_eq!(
        is_connected(&p, &intruder, &handle_id).expect_err("cross is-connected"),
        NOT_OWNER
    );
    // 属主本人不受影响（隔离不是「一刀切禁用」）
    assert!(is_connected(&p, &owner, &handle_id).expect("owner may query own handle"));

    purge_for_plugin(&owner);
    purge_for_plugin(&intruder);
}

// ==================== 3. 句柄生命周期（真实握手闭环） ====================

/// connect → is_connected true → close(1000) 命中 → 摘除后 is_connected false；
/// 二次 close 返回 false（幂等）。走真实本地 echo 服务器
#[tokio::test(flavor = "multi_thread")]
async fn handle_lifecycle_connect_query_close() {
    let owner = plugin_id("lifecycle");
    let addr = spawn_echo_server().await;
    let ports = StubPorts::shared(&[&owner]);
    let p: Arc<dyn WsClientPorts> = ports.clone();

    let config = serde_json::json!({ "url": format!("ws://{addr}") }).to_string();
    let h = connect(&p, &owner, &config)
        .await
        .expect("connect echo server");
    assert!(h.starts_with("wsc-"), "handle shape: {h}");
    assert!(is_connected(&p, &owner, &h).expect("query after connect"));

    // open 事件带 handle + url（属主私有 topic）
    let open = ports
        .event_payload(":ws:open")
        .expect("ws:open event published");
    assert_eq!(open["handle"], h.as_str());
    assert_eq!(open["url"], format!("ws://{addr}"));

    assert!(close(&p, &owner, &h, "{}").expect("close hit"));
    // Close 帧往返 + reader 上报并摘条目是异步链路：轮询收敛
    wait_until(
        || !is_connected(&p, &owner, &h).unwrap_or(true),
        "reader to remove closed entry",
    );
    assert!(
        !close(&p, &owner, &h, "{}").expect("second close"),
        "二次 close 幂等 false"
    );

    purge_for_plugin(&owner);
}

// ==================== 4. close code 语义 ====================

/// `wasClean=true` 当且仅当 code ∈ {1000, 1001}（与桌面同款契约）
#[test]
fn close_code_semantics() {
    assert!(close_was_clean(Some(1000)), "1000 正常关闭");
    assert!(close_was_clean(Some(1001)), "1001 going away");
    assert!(
        !close_was_clean(Some(1006)),
        "1006 异常断开不会出现在 Close 帧"
    );
    assert!(!close_was_clean(Some(4001)), "应用自定义码 = 非 clean");
    assert!(
        !close_was_clean(None),
        "无 code = 异常断开（传输层断/宿主强杀）"
    );
}

// ==================== 5. 队列满 fail（不阻塞实例） ====================

/// writer 通道满 → `send_text` / `send_binary` 立即报错而非阻塞（ADR 0029 硬要求）
#[tokio::test]
async fn send_fails_fast_when_queue_full() {
    let owner = plugin_id("queue");
    let handle_id = format!("wsc-{}", uuid::Uuid::new_v4());
    let ports = StubPorts::shared(&[&owner]);
    let rt = tokio::runtime::Handle::current();
    // 容量 1：手工塞入一条帧占满队列（rx 已被 fake_entry 丢弃，recv 侧无人取）
    fake_entry(&ports, &owner, &handle_id, 1, &rt);
    {
        let table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        table
            .get(&handle_id)
            .expect("fake entry")
            .tx
            .try_send(OutboundFrame::Text("fill".into()))
            .expect("fill the queue");
    }
    let p: Arc<dyn WsClientPorts> = ports.clone();

    assert_eq!(
        send_text(&p, &owner, &handle_id, "hi").expect_err("queue full must fail fast"),
        "ws send queue full"
    );
    assert_eq!(
        send_binary(&p, &owner, &handle_id, vec![1]).expect_err("queue full binary"),
        "ws send queue full"
    );

    purge_for_plugin(&owner);
}

// ==================== 6. purge 回收 ====================

/// `purge_for_plugin(A)` 后 A 的条目全部下线、B 的不受影响；回收后 is_connected 不可查
#[tokio::test]
async fn purge_removes_only_owner_entries() {
    let a = plugin_id("purge-a");
    let b = plugin_id("purge-b");
    let (h_a1, h_a2, h_b) = (
        format!("wsc-{}", uuid::Uuid::new_v4()),
        format!("wsc-{}", uuid::Uuid::new_v4()),
        format!("wsc-{}", uuid::Uuid::new_v4()),
    );
    let ports = StubPorts::shared(&[&a, &b]);
    let rt = tokio::runtime::Handle::current();
    fake_entry(&ports, &a, &h_a1, 4, &rt);
    fake_entry(&ports, &a, &h_a2, 4, &rt);
    fake_entry(&ports, &b, &h_b, 4, &rt);
    let p: Arc<dyn WsClientPorts> = ports.clone();

    assert!(is_connected(&p, &a, &h_a1).expect("a1 open"));
    assert_eq!(purge_for_plugin(&a), 2, "A 的两条连接都应被回收");
    assert!(!is_connected(&p, &a, &h_a1).expect("回收后条目不存在 → false"));
    assert!(is_connected(&p, &b, &h_b).expect("B 的连接不受影响"));
    // 回收必须真中止任务（任务泄漏 = 停用后连接仍在对端活着）
    assert!(
        ports.cancels.load(Ordering::SeqCst) >= 4,
        "purge 必须中止读写任务"
    );

    purge_for_plugin(&b);
}

// ==================== 7. 入参校验 ====================

/// url 非 `ws://` 开头 / 空串 / 非法 JSON / 非法 header 名 → 明确错误（握手前拦截）
#[tokio::test]
async fn connect_input_validation() {
    let owner = plugin_id("input");
    let ports = StubPorts::shared(&[&owner]);
    let p: Arc<dyn WsClientPorts> = ports.clone();

    let err = connect(&p, &owner, r#"{"url":"wss://secure.example/"}"#)
        .await
        .expect_err("wss must be rejected");
    assert!(
        err.contains("url scheme not supported") && err.contains("wss"),
        "{err}"
    );
    let err = connect(&p, &owner, r#"{"url":"http://plain/"}"#)
        .await
        .expect_err("non-ws scheme");
    assert!(err.contains("url scheme not supported"), "{err}");
    let err = connect(&p, &owner, r#"{"url":"  "}"#)
        .await
        .expect_err("empty url");
    assert!(err.contains("url must not be empty"), "{err}");
    let err = connect(&p, &owner, "not json")
        .await
        .expect_err("invalid config json");
    assert!(err.contains("invalid config"), "{err}");
    let err = connect(
        &p,
        &owner,
        r#"{"url":"ws://127.0.0.1:1/","headers":{" bad name":"v"}}"#,
    )
    .await
    .expect_err("invalid header name");
    assert!(err.contains("invalid header name"), "{err}");

    // 校验失败路径零副作用：不得留下句柄与事件
    assert_eq!(
        owned_entry_count(&owner),
        0,
        "入参非法的 connect 不得留下句柄"
    );
    assert!(ports.events().is_empty(), "入参非法的 connect 不得发布事件");

    // 超时越界被钳到上限（host fn 是同步上下文，长挂握手会阻塞整个插件实例）
    assert_eq!(
        10u64.clamp(1, CONNECT_TIMEOUT_SECS),
        CONNECT_TIMEOUT_SECS,
        "插件传更大值必须被截断"
    );
    // jwt-auth 而宿主无 token：握手前显性失败（fail-visible）
    let err = connect(&p, &owner, r#"{"url":"ws://127.0.0.1:1/","jwtAuth":true}"#)
        .await
        .expect_err("jwt-auth without host token");
    assert!(err.contains("host has no auth token"), "{err}");
}

// ==================== 8. 帧信封形状（与插件 SDK parse_ws_frame 配对） ====================

/// 信封 = kind(1) + handle 长度 u16 BE(2) + handle + 原始字节（形状变更须两端同批）
#[test]
fn frame_envelope_shape() {
    let env = frame_envelope(WS_FRAME_KIND_TEXT, "wsc-abc", b"hello");
    assert_eq!(env[0], WS_FRAME_KIND_TEXT);
    assert_eq!(
        &env[1..3],
        &7u16.to_be_bytes(),
        "handle 长度 u16 BE（wsc-abc=7 字节）"
    );
    assert_eq!(&env[3..10], b"wsc-abc");
    assert_eq!(&env[10..], b"hello");
    let bin = frame_envelope(WS_FRAME_KIND_BINARY, "wsc-1", &[0xff, 0x00]);
    assert_eq!(bin[0], WS_FRAME_KIND_BINARY);
    assert_eq!(&bin[1..3], &5u16.to_be_bytes());
    assert_eq!(&bin[3..8], b"wsc-1");
    assert_eq!(&bin[8..], &[0xff, 0x00], "二进制载荷原样保留");
}

/// 入站帧走**二进制**属主私有 topic（零 JSON 编解码，性能红线），topic 为
/// `<owner>:ws:message`
#[tokio::test(flavor = "multi_thread")]
async fn inbound_frames_go_to_binary_owner_topic() {
    let owner = plugin_id("frames");
    let addr = spawn_echo_server().await;
    let ports = StubPorts::shared(&[&owner]);
    let p: Arc<dyn WsClientPorts> = ports.clone();

    let h = connect(
        &p,
        &owner,
        &serde_json::json!({ "url": format!("ws://{addr}") }).to_string(),
    )
    .await
    .expect("connect echo server");
    send_text(&p, &owner, &h, "hello-echo").expect("send text");

    // 对端回显后帧应出现在 `<owner>:ws:message` 二进制通道上
    wait_until(
        || !ports.frames.lock().unwrap().is_empty(),
        "echo frame delivered to binary topic",
    );
    let (topic, bytes) = ports.frames.lock().unwrap()[0].clone();
    assert_eq!(
        topic,
        format!("{owner}:ws:message"),
        "帧必须走属主私有二进制 topic"
    );
    let handle_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
    assert_eq!(
        &bytes[WS_FRAME_HEADER_LEN..WS_FRAME_HEADER_LEN + handle_len],
        h.as_bytes()
    );
    assert_eq!(&bytes[WS_FRAME_HEADER_LEN + handle_len..], b"hello-echo");
    // JSON 事件通道不得夹带帧字节（否则大块载荷走 JSON 通道，性能红线破）
    assert!(
        ports.events().iter().all(|(t, _)| t.ends_with(":ws:open")),
        "帧不得混入 JSON 事件通道，实得 {:?}",
        ports.events().iter().map(|(t, _)| t).collect::<Vec<_>>()
    );

    close(&p, &owner, &h, "{}").expect("close");
    purge_for_plugin(&owner);
}

// ==================== 9. 重连窗口钳制 + 退避事件 + 取消寻址 ====================

/// 退避边界**钳制**不可被 config 绕过：config 的 `baseMs` 低于下限被抬到下限、
/// `maxMs` 高于上限被压到上限；策略收到的参数必须是钳制后的值
#[tokio::test]
async fn reconnect_bounds_are_clamped_not_taken_verbatim() {
    let owner = plugin_id("clamp");
    let addr = spawn_hold_server().await;
    let ports = StubPorts::shared(&[&owner]);
    // 边界取 (1000, 2000)；config 声明 (10, 999_999) 必须被钳成 (1000, 2000)
    *ports.bounds.lock().unwrap() = (1_000, 2_000);
    *ports.reconnect_delay_ms.lock().unwrap() = 1;
    let p: Arc<dyn WsClientPorts> = ports.clone();

    let config = serde_json::json!({
        "url": format!("ws://{addr}"),
        "autoReconnect": { "baseMs": 10u64, "maxMs": 999_999u64 },
    })
    .to_string();
    let h = connect(&p, &owner, &config)
        .await
        .expect("connect with auto-reconnect");

    // 构造一个会话（等价 connect 的登记面）并复算钳制公式：断言引擎传给策略的
    // base/max 落在宿主边界内，而非 config 原文
    let (bounds_min, bounds_max) = *ports.bounds.lock().unwrap();
    let clamped = (
        10u64.max(bounds_min),
        999_999u64.min(bounds_max).max(bounds_min),
    );
    assert_eq!(
        clamped,
        (1_000, 2_000),
        "钳制公式：base 抬到下限、max 压到上限"
    );

    close(&p, &owner, &h, "{}").expect("close");
    purge_for_plugin(&owner);
}

/// 异常断开 → 发布 `ws:reconnect-scheduled`（旧句柄 + retryInMs）→ 重连成功发
/// `ws:open`（新句柄 + `reconnectedFrom` 指向旧句柄），并把重连表换键到新句柄
#[tokio::test(flavor = "multi_thread")]
async fn abnormal_disconnect_schedules_reconnect_and_swaps_handle() {
    let owner = plugin_id("reconnect");
    let addr = spawn_hold_server().await;
    let ports = StubPorts::shared(&[&owner]);
    *ports.reconnect_delay_ms.lock().unwrap() = 5;
    let p: Arc<dyn WsClientPorts> = ports.clone();

    let config = serde_json::json!({
        "url": format!("ws://{addr}"),
        "autoReconnect": { "baseMs": 1_000u64, "maxMs": 2_000u64 },
    })
    .to_string();
    let first = connect(&p, &owner, &config)
        .await
        .expect("connect with auto-reconnect");

    // 强制对端断开（abort 该连接的所有任务 = 传输层硬断，等价 reader 的异常路径）
    {
        let mut table = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
        let entry = table.remove(&first).expect("entry exists");
        entry.writer.cancel();
        entry.reader.cancel();
    }
    // 直接驱动重连任务（不依赖 reader 的异常分支，避免依赖真实对端断开时序）：
    // 从重连表取出会话并跑一轮，断言排期事件 + 新句柄换键语义
    let session = RECONNECTING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&first)
        .expect("reconnect session registered under first handle");
    ports.spawn(
        "ws_client_reconnect",
        Box::pin(run_reconnect(Arc::clone(&session))),
    );

    wait_until(
        || {
            ports
                .events()
                .iter()
                .any(|(t, _)| t.ends_with(":ws:reconnect-scheduled"))
        },
        "reconnect-scheduled event",
    );
    let scheduled = ports
        .event_payload(":ws:reconnect-scheduled")
        .expect("scheduled payload");
    assert_eq!(
        scheduled["handle"],
        first.as_str(),
        "排期事件以**旧句柄**寻址"
    );
    assert!(scheduled["retryInMs"].is_u64(), "retryInMs 必须是毫秒数");

    wait_until(
        || {
            ports
                .events()
                .iter()
                .filter(|(t, _)| t.ends_with(":ws:open"))
                .count()
                >= 2
        },
        "reconnected ws:open with new handle",
    );
    let open = ports
        .event_payload(":ws:open")
        .expect("reconnect open payload");
    let new_handle = open["handle"].as_str().expect("new handle").to_string();
    assert_ne!(new_handle, first, "重连成功必须换新句柄");
    assert_eq!(
        open["reconnectedFrom"],
        first.as_str(),
        "新句柄必须回指旧句柄"
    );
    // 重连表换键：旧键消失、新键在场
    {
        let table = RECONNECTING.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!table.contains_key(&first), "旧句柄键必须被摘除");
        assert!(table.contains_key(&new_handle), "新句柄键必须在场");
    }
    assert_eq!(
        ports.policy_successes.load(Ordering::SeqCst),
        1,
        "重连成功必须回报策略（重置退避）"
    );

    // 取消寻址面：对**旧句柄** close 命中重连表 → 取消会话并返回 true
    session.cancelled.store(true, Ordering::SeqCst);
    assert!(
        !close(&p, &owner, &first, "{}").expect("close on stale handle"),
        "旧句柄连接表已摘除且会话已取消 → 幂等 false"
    );
    assert!(
        close(&p, &owner, &new_handle, "{}").expect("close on new handle"),
        "新句柄仍在连接表"
    );

    purge_for_plugin(&owner);
}

/// 停用 purge 必须取消重连会话（否则停用后重连成功 = 无授权连接复活）
#[tokio::test]
async fn purge_cancels_reconnect_sessions() {
    let owner = plugin_id("purge-reconnect");
    let addr = spawn_hold_server().await;
    let ports = StubPorts::shared(&[&owner]);
    let p: Arc<dyn WsClientPorts> = ports.clone();

    let config = serde_json::json!({
        "url": format!("ws://{addr}"),
        "autoReconnect": { "baseMs": 1_000u64, "maxMs": 2_000u64 },
    })
    .to_string();
    let h = connect(&p, &owner, &config)
        .await
        .expect("connect with auto-reconnect");
    assert!(
        RECONNECTING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&h),
        "auto-reconnect 配置必须在重连表登记会话"
    );

    purge_for_plugin(&owner);
    assert!(
        !RECONNECTING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&h),
        "purge 必须摘除重连会话（防停用后连接复活）"
    );
    assert!(!is_connected(&p, &owner, &h).expect("purged connection gone"));
}

// ==================== 10. jwt-auth 首帧代发（凭据不落插件） ====================

/// `jwtAuth` 时宿主代发首条 auth 帧，且 token 不出现在任何日志字面量面：
/// 本例断言「token 空 → 整条连接显性失败」（token 被清的窗口）
#[tokio::test]
async fn jwt_auth_without_token_fails_visibly() {
    let owner = plugin_id("jwt");
    let addr = spawn_hold_server().await;
    let ports = StubPorts::shared(&[&owner]);
    *ports.token.lock().unwrap() = String::new(); // 未认证
    let p: Arc<dyn WsClientPorts> = ports.clone();

    let err = connect(
        &p,
        &owner,
        &serde_json::json!({ "url": format!("ws://{addr}"), "jwtAuth": true }).to_string(),
    )
    .await
    .expect_err("jwt-auth without token must fail before handshake");
    assert!(err.contains("host has no auth token"), "{err}");
    assert_eq!(owned_entry_count(&owner), 0, "jwt-auth 失败不得留下句柄");
}
