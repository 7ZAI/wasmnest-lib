//! 插件互调回复道编排（ADR-0017）——`host-api-call` 的**机制面**
//!
//! **WIT impl 已迁宿主**（票 02 批次 05，`src-tauri/src/plugin/api_call.rs` 路径 B
//! 薄转发：无权限门，互调门禁在注册表）。本文件**留内核**的判据与 peer/ws/http
//! 「内核仍消费引擎面」同源：内核 `intercall`（通用互调客户端）、`auth_center`
//! 桥接（注册表真源留内核裁决）与 `WasmHostContext::call_plugin_api_host` 消费
//! 同一条回复道编排——编排是「通信」引擎原语（零产品语义），不是域 adapter。
//!
//! 语义：发布 JSON-RPC 请求到 `wasmnest.api.<api>` topic（经 [`super::bus`]
//! 的门禁校验），然后阻塞等待回复。回复 topic 为
//! `wasmnest.api.reply.<caller-plugin-id>.<request-id>`（spec §9.3），
//! 其中 caller-id 取调用方插件 ID（host function 的 Caller state），
//! request-id 取请求载荷中的字符串 `id` 字段（SDK 生成，JSON-RPC 约定）。
//!
//! ## 回复道安全（审计票 05，P1-4）
//!
//! 回复道是 caller 的收件箱，但**刻意不走 `<caller>::…` 私有命名空间**：
//! 响应者是别的插件，必须能发布进 caller 的回复道，开了「非属主可发布他人
//! 命名空间」的例外面，命名空间的收件箱语义就废了。两个缺口分别单独堵：
//!
//! - **窃听**：`wasmnest.api.reply.*` 对 WASM 订阅面一律拒绝（`super::bus` 的
//!   订阅门禁）—— 回复订阅本就由宿主在此静态注册。此前任意插件可订阅他人
//!   回复道，而 correlation id 是可猜的单调计数器（SDK `req-1`、`req-2`…）。
//! - **抢答**：[`ReplyHandler`] 校验 `msg.sender` == 该 api 的声明属主
//!   （`ApiRegistry::owner_of`）。`sender` 由宿主按 Caller state 落章，
//!   guest 无法自报，故非属主投递被丢弃 + `warn`，调用方按超时收敛。
//!
//! ## 为什么回复订阅是宿主侧静态订阅
//!
//! WASM guest 是同步执行模型：调用方阻塞等待期间，宿主无法把回复投递到
//! 调用方插件的 `on_message` —— 投递路径（宿主 `call_guest` 的 mutex 模型）
//! 需要锁住调用方实例，而该锁正被阻塞中的调用持有，必然自锁死锁。因此宿主在
//! 回复 topic 上注册静态订阅（Rust callback 投递，不经过调用方 wasm 实例），
//! 经 oneshot 通道唤醒等待者。消息形状（JSON-RPC）与 correlation id 生命周期
//! 归 SDK 管理，本原语只是「发布请求、等待回复」的通用管道。

use super::bus;
use crate::bus::{BusMessageHandler, MessageBus};
#[cfg(test)]
use crate::host_api::context::WasmHostContext;
use crate::runtime_util::block_on_async;
use wasmnest_plugin_api::host::bus::API_TOPIC_PREFIX;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

/// 宿主侧互调调用方身份（票 11 命令面桥接）：宿主不是插件，reply topic 路由
/// `wasmnest.api.reply.<caller>.<request-id>` 需要稳定身份；互调门禁（层 1）
/// 只校验目标 api 声明、不校验调用方，宿主身份同样受注册表约束（未激活 → 拒绝）。
pub const HOST_API_CALLER_ID: &str = "wasmnest-host";

/// 回复订阅处理器：收到回复即投递到 oneshot 通道（仅取第一条）
///
/// Sender 包在 `Arc<Mutex<Option<_>>>` 中：`take()` 保证只消费一条回复
/// （迟到的重复回复直接丢弃），Mutex 提供 `Sync`（oneshot::Sender 非 Sync，
/// 而 BusMessageHandler 要求 Send + Sync）
///
/// **回复身份校验（票 05 / P1-4）**：只接受 `sender == expected_sender`（api 的
/// 声明属主）的回复。`sender` 由宿主按调用方 Caller state 落章，guest 无法自报，
/// 因此第三方插件向该回复道伪投递（抢答）会被丢弃 + `warn`，调用方按超时收敛。
/// 此前回复道零校验，而 SDK 的 correlation id 是进程内单调计数器（`req-1`…），
/// 串号可猜，等于任何已激活插件都能劫持他人的互调结果。
struct ReplyHandler {
    tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    /// 期望的回复来源（目标 api 的声明属主插件 ID）
    expected_sender: String,
    /// 回复 topic（仅日志定位用）
    reply_topic: String,
}

impl BusMessageHandler for ReplyHandler {
    fn on_message(&self, msg: &crate::bus::BusMessage) -> anyhow::Result<()> {
        if msg.sender != self.expected_sender {
            tracing::warn!(
                expected = %self.expected_sender,
                got = %msg.sender,
                topic = %self.reply_topic,
                "api_call: reply from a plugin other than the declared api owner rejected (reply lane, audit ticket 05)"
            );
            return Ok(());
        }
        let mut tx = self
            .tx
            .try_lock()
            .map_err(|_| anyhow::anyhow!("api_call: reply handler lock poisoned"))?;
        if let Some(tx) = tx.take() {
            let _ = tx.send(msg.payload.to_string());
        }
        Ok(())
    }
}

/// 插件互调调用：发布请求（经门禁）+ 阻塞等待回复（宿主侧订阅 + 超时）
///
/// 返回回复 JSON 字符串（`{ jsonrpc, id, result | error }`），并校验回复
/// `id` 与请求一致（防错配回复串台）与 `sender` 属主一致（防抢答）。
/// 超时/门禁拒绝返回 Err。
///
/// **pub（票 02 批次 05）**：WIT impl 迁宿主后，宿主薄转发层以调用方
/// `plugin_id` 为 caller 经本公开面复用同一条编排（`call_plugin_api_host`
/// 的宿主身份快捷入口保留不动——两者是同一编排的两个 caller）。
pub fn api_call(
    bus: &dyn crate::host_api::context::BusScope,
    reg: &dyn crate::host_api::context::ApiRegistryScope,
    sec: &dyn crate::host_api::context::SecurityScope,
    caller_id: &str,
    request_topic: &str,
    payload_json: &str,
    timeout_ms: u64,
) -> Result<String, String> {
    // 1. 解析请求载荷并提取 correlation id（回复 topic 路由依据）
    let payload: Value =
        serde_json::from_str(payload_json).map_err(|e| format!("api_call: invalid JSON payload: {}", e))?;
    let request_id = payload
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "api_call: request payload must contain a non-empty string 'id'".to_string())?;

    // 2. 解析目标 api 的声明属主——回复只接受来自它的投递。门禁本身仍由
    //    bus_publish 兜（此处多读一次注册表，同一张表不漂移）；未声明目标在
    //    注册回复订阅**之前**就返回，避免旧顺序下的订阅与消费任务泄漏。
    let expected_sender = match super::bus::api_gate_target_owner(reg, request_topic) {
        Some(owner) => owner,
        None => {
            return Err(format!(
                "api_call: api '{}' is not declared by any activated plugin (gate)",
                request_topic.strip_prefix(API_TOPIC_PREFIX).unwrap_or(request_topic)
            ));
        }
    };

    let reply_topic = format!("wasmnest.api.reply.{}.{}", caller_id, request_id);
    let (tx, rx) = oneshot::channel::<String>();
    let handler = ReplyHandler {
        tx: Arc::new(Mutex::new(Some(tx))),
        expected_sender,
        reply_topic: reply_topic.clone(),
    };

    // 3. 注册静态回复订阅（先订阅后发布：oneshot 缓冲保证时序安全）
    let sub_bus = bus.message_bus().clone();
    let sub_topic = reply_topic.clone();
    let sub_result = block_on_async(async move {
        sub_bus.subscribe_static(caller_id, &sub_topic, Box::new(handler)).await;
        Ok::<(), String>(())
    });
    sub_result.map_err(|e| format!("api_call: subscribe failed: {}", e))?;

    // 4. 发布请求（bus_publish 内含 JSON 校验 + 命名空间/ wasmnest.api.* 门禁校验，
    //    未声明目标在此被拒，错误直接透传给调用方；失败须回收刚注册的回复订阅）
    //
    //    **必须在 ambient 多线程上下文内执行**（2026-09-23 P1-b 补）：同步互调若
    //    在 actix current_thread worker 上直接发布，`MessageBus::publish` 的
    //    `tokio::spawn`（请求消费任务 / 后续回复投递）会落入该 current_thread
    //    runtime——其唯一调度线程正被本互调同步阻塞 → 消费任务永不执行 → 超时。
    //    与其它 async fire-and-forget 调用同根因（如连接触摸通知），此处改为发布也
    //    经 `block_on_async` 搬到 ambient 多线程上下文：spawn 落在 ambient 线程池，
    //    回复自由投递。
    let publish_result =
        block_on_async(async move { bus::bus_publish(bus, sec, caller_id, request_topic, payload_json) });
    if let Err(e) = publish_result {
        cleanup_reply_subscription(bus.message_bus(), caller_id, &reply_topic);
        return Err(e);
    }

    // 5. 等待回复（超时）
    let wait_result =
        block_on_async(async move { tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), rx).await });
    let reply_json = match wait_result {
        Ok(Ok(reply)) => reply,
        Ok(Err(_)) => {
            return Err(format!(
                "api_call: reply channel dropped before response on '{}'",
                reply_topic
            ));
        }
        Err(_) => {
            // 超时路径同样清理订阅（见下方清理），保持回复 topic 无残留
            cleanup_reply_subscription(bus.message_bus(), caller_id, &reply_topic);
            return Err(format!(
                "api_call: timeout after {}ms waiting for reply on '{}'",
                timeout_ms, reply_topic
            ));
        }
    };

    // 6. 校验回复 id 与请求一致（防迟到的旧回复/错配回复串台）
    let reply: Value = serde_json::from_str(&reply_json).map_err(|e| format!("api_call: invalid reply JSON: {}", e))?;
    let reply_id = reply.get("id").and_then(|v| v.as_str());
    if reply_id != Some(request_id) {
        cleanup_reply_subscription(bus.message_bus(), caller_id, &reply_topic);
        return Err(format!(
            "api_call: reply id mismatch (expected '{}', got {:?}) on '{}'",
            request_id, reply_id, reply_topic
        ));
    }

    // 7. 清理回复订阅（幂等）
    cleanup_reply_subscription(bus.message_bus(), caller_id, &reply_topic);
    Ok(reply_json)
}

/// 移除回复 topic 上的订阅（幂等；超时/错误路径共用）
fn cleanup_reply_subscription(bus: &Arc<MessageBus>, caller_id: &str, reply_topic: &str) {
    let bus = bus.clone();
    let caller = caller_id.to_string();
    let topic = reply_topic.to_string();
    if let Err(e) = block_on_async(async move {
        bus.unsubscribe(&caller, &topic).await;
        Ok::<(), String>(())
    }) {
        tracing::warn!(
            error = %e,
            topic = %reply_topic,
            "api_call: reply subscription cleanup failed"
        );
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_api::tests::build_host_ctx;
    use std::time::Duration;

    /// 静态响应者：收到请求 topic 消息后，向回复 topic 回一条 JSON-RPC 回复。
    /// 通过 channel 把收到的请求转发给测试体（断言请求内容）。
    struct Responder {
        request_tx: tokio::sync::mpsc::UnboundedSender<String>,
        /// 回复 id 覆盖（None = 原样回传；Some = 故意错配）
        reply_id_override: Option<String>,
        /// 是否回复（None = 静默不回复，模拟无响应目标）
        respond: bool,
        /// 与测试体共用的消息总线（回复发布走同一 bus）
        bus: Arc<MessageBus>,
    }

    impl BusMessageHandler for Responder {
        fn on_message(&self, msg: &crate::bus::BusMessage) -> anyhow::Result<()> {
            let _ = self.request_tx.send(msg.payload.to_string());
            if !self.respond {
                return Ok(());
            }
            let req: Value = serde_json::from_str(&msg.payload.to_string()).unwrap();
            let id = self
                .reply_id_override
                .clone()
                .unwrap_or_else(|| req["id"].as_str().unwrap().to_string());
            let reply = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "echo": req["params"][0] },
            });
            // 回复 topic：wasmnest.api.reply.<caller>.<request-id>；sender 用目标插件 ID
            // （真实流程中回复由目标插件发布 —— 总线跳过「发送者自己」，若以 caller
            // 身份发布会命中回复订阅者的插件 ID 而错失投递）
            let reply_topic = format!("wasmnest.api.reply.{}.{}", msg.sender, req["id"].as_str().unwrap());
            self.bus.publish(&reply_topic, "com.wasmnest.sdk-test", reply);
            Ok(())
        }
    }

    /// 注册请求 topic 的静态响应者，返回收到的请求通道
    fn setup_responder(
        ctx: &Arc<WasmHostContext>,
        request_topic: &str,
        respond: bool,
        reply_id_override: Option<String>,
    ) -> tokio::sync::mpsc::UnboundedReceiver<String> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let responder = Responder {
            request_tx: tx,
            reply_id_override,
            respond,
            bus: ctx.message_bus.clone(),
        };
        let ctx2 = ctx.clone();
        let topic = request_topic.to_string();
        block_on_async(async move {
            ctx2.message_bus
                .subscribe_static("responder", &topic, Box::new(responder))
                .await;
            Ok::<(), String>(())
        })
        .expect("subscribe responder");
        rx
    }

    /// 完整往返：请求发布（门禁放行）→ 响应者回复 → 等待解析 → id 校验
    #[test]
    fn api_call_roundtrip_success() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ctx.api_registry()
                .register("com.wasmnest.sdk-test", &["com.wasmnest.sdk-test.echo".to_string()])
                .expect("夹具登记 echo api 失败：往返用例的前置条件未成立");
            let mut rx = setup_responder(&ctx, "wasmnest.api.com.wasmnest.sdk-test.echo", true, None);

            let reply = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.sdk-test.echo",
                r#"{"jsonrpc":"2.0","id":"req-1","method":"echo","params":["hi"]}"#,
                2000,
            )
            .expect("roundtrip must succeed");

            let reply: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(reply["id"], "req-1");
            assert_eq!(reply["result"]["echo"], "hi");

            // 请求确实触达目标（响应者收到的载荷原样）
            let req = rx.recv().await.expect("responder must receive request");
            assert!(req.contains("\"method\":\"echo\""));
        });
    }

    /// 未声明 api：请求被门禁拒绝，错误透传给调用方（无等待）
    #[test]
    fn api_call_rejects_undeclared_api() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let err = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.scheduler.remove",
                r#"{"jsonrpc":"2.0","id":"req-1","method":"remove","params":[]}"#,
                2000,
            )
            .unwrap_err();
            assert!(err.contains("not declared"), "got: {}", err);
        });
    }

    /// 无响应目标：超时（调用方按超时错误处理，spec 验收）
    #[test]
    fn api_call_timeout_when_no_reply() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ctx.api_registry()
                .register("com.wasmnest.sdk-test", &["com.wasmnest.sdk-test.silent".to_string()])
                .expect("夹具登记 silent api 失败：超时用例测的就��没回复");
            // 目标订阅了但静默不回复
            setup_responder(&ctx, "wasmnest.api.com.wasmnest.sdk-test.silent", false, None);

            let started = std::time::Instant::now();
            let err = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.sdk-test.silent",
                r#"{"jsonrpc":"2.0","id":"req-1","method":"silent","params":[]}"#,
                500,
            )
            .unwrap_err();
            assert!(err.contains("timeout"), "got: {}", err);
            assert!(
                started.elapsed() >= Duration::from_millis(400),
                "must wait at least the timeout"
            );
        });
    }

    /// 回复 id 错配：拒绝（防迟到旧回复/错配回复串台）
    #[test]
    fn api_call_rejects_id_mismatch() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ctx.api_registry()
                .register("com.wasmnest.sdk-test", &["com.wasmnest.sdk-test.echo".to_string()])
                .expect("夹具登记 echo api 失败：id 错配用例的前置条件未成立");
            setup_responder(
                &ctx,
                "wasmnest.api.com.wasmnest.sdk-test.echo",
                true,
                Some("wrong-id".to_string()),
            );

            let err = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.sdk-test.echo",
                r#"{"jsonrpc":"2.0","id":"req-1","method":"echo","params":["hi"]}"#,
                2000,
            )
            .unwrap_err();
            assert!(err.contains("id mismatch"), "got: {}", err);
        });
    }

    /// 请求载荷缺 id：立即报错（SDK 契约，宿主不做猜测）
    #[test]
    fn api_call_requires_string_id() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let err = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.sdk-test.echo",
                r#"{"jsonrpc":"2.0","method":"echo"}"#,
                2000,
            )
            .unwrap_err();
            assert!(err.contains("'id'"), "got: {}", err);
        });
    }

    /// 伪响应者：收到请求后向 caller 的回复道投一条**非声明属主**发出的回复（抢答）
    struct Spoofer {
        /// 伪造的 sender（总线按宿主落章的插件 ID 填，这里模拟另一已激活插件）
        fake_sender: String,
        bus: Arc<MessageBus>,
    }

    impl BusMessageHandler for Spoofer {
        fn on_message(&self, msg: &crate::bus::BusMessage) -> anyhow::Result<()> {
            let req: Value = serde_json::from_str(&msg.payload.to_string()).unwrap();
            let reply = serde_json::json!({
                "jsonrpc": "2.0",
                "id": req["id"].as_str().unwrap(),
                "result": { "spoofed": true },
            });
            let reply_topic = format!("wasmnest.api.reply.{}.{}", msg.sender, req["id"].as_str().unwrap());
            self.bus.publish(&reply_topic, &self.fake_sender, reply);
            Ok(())
        }
    }

    /// 非声明属主抢答回复道：调用方必须拒收（表现为超时），伪造载荷不得上浮
    #[test]
    fn api_call_rejects_reply_from_non_owner() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // 目标 api 已声明但真目标缺席：只有第三方插件在请求道上抢答
            ctx.api_registry()
                .register("com.wasmnest.sdk-test", &["com.wasmnest.sdk-test.echo".to_string()])
                .expect("夹具登记 echo api 失败：真目标缺席用例的前置条件未成立");
            ctx.message_bus
                .subscribe_static(
                    "com.wasmnest.evil",
                    "wasmnest.api.com.wasmnest.sdk-test.echo",
                    Box::new(Spoofer {
                        fake_sender: "com.wasmnest.evil".to_string(),
                        bus: ctx.message_bus.clone(),
                    }),
                )
                .await;

            let err = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.sdk-test.echo",
                r#"{"jsonrpc":"2.0","id":"req-1","method":"echo","params":["hi"]}"#,
                500,
            )
            .unwrap_err();
            assert!(err.contains("timeout"), "抢答须被拒→调用方按超时收敛, got: {}", err);
            assert!(!err.contains("spoofed"), "伪造载荷不得出现在调用方错误里: got: {}", err);
        });
    }

    /// 声明属主正常回复：sender 校验放行（正向对照，防把回复道锁死）
    #[test]
    fn api_call_accepts_reply_from_declared_owner() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ctx.api_registry()
                .register("com.wasmnest.sdk-test", &["com.wasmnest.sdk-test.echo".to_string()])
                .expect("夹具登记 echo api 失败：属主回复用例的前置条件未成立");
            let mut rx = setup_responder(&ctx, "wasmnest.api.com.wasmnest.sdk-test.echo", true, None);

            let reply = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.sdk-test.echo",
                r#"{"jsonrpc":"2.0","id":"req-9","method":"echo","params":["ok"]}"#,
                2000,
            )
            .expect("declared owner reply must be accepted");
            let reply: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(reply["id"], "req-9");
            assert_eq!(reply["result"]["echo"], "ok");
            rx.recv().await.expect("responder must receive request");
        });
    }

    /// 门禁拒绝路径不得泄漏回复订阅（旧顺序：先订阅后过门 → 未声明 api 时订阅与
    /// 其消费任务永久残留）
    #[test]
    fn api_call_gate_rejection_leaves_no_reply_subscription() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let err = api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.ghost.echo",
                r#"{"jsonrpc":"2.0","id":"req-1","method":"echo","params":[]}"#,
                500,
            )
            .unwrap_err();
            assert!(err.contains("not declared"), "got: {}", err);
            assert_eq!(
                ctx.message_bus
                    .subscriber_count("wasmnest.api.reply.com.wasmnest.caller.req-1")
                    .await,
                0,
                "门禁拒绝后回复道不得残留订阅"
            );
        });
    }

    /// 成功路径收敛后同样无残留（cleanup 幂等性对照）
    #[test]
    fn api_call_success_cleans_reply_subscription() {
        let ctx = build_host_ctx();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ctx.api_registry()
                .register("com.wasmnest.sdk-test", &["com.wasmnest.sdk-test.echo".to_string()])
                .expect("夹具登记 echo api 失败：订阅清理用例的前置条件未成立");
            setup_responder(&ctx, "wasmnest.api.com.wasmnest.sdk-test.echo", true, None);

            api_call(
                ctx.as_ref(),
                ctx.as_ref(),
                ctx.as_ref(),
                "com.wasmnest.caller",
                "wasmnest.api.com.wasmnest.sdk-test.echo",
                r#"{"jsonrpc":"2.0","id":"req-42","method":"echo","params":["hi"]}"#,
                2000,
            )
            .expect("roundtrip ok");

            assert_eq!(
                ctx.message_bus
                    .subscriber_count("wasmnest.api.reply.com.wasmnest.caller.req-42")
                    .await,
                0,
                "回复消费后须注销订阅"
            );
        });
    }
}
