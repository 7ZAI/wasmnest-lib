//! host-pty 能力域的域行为用例（随域机制从 `wasm-core::host_api` 迁入本 crate）
//!
//! ## 为什么这些用例住在能力域而不是宿主
//!
//! 它们断言的是**域的契约**：权限三态经端口、属主隔离、配额/环容量仲裁、退出事件的
//! 发布形状、限频通知的合并语义、真实 PTY 产出到环的落位。域的注册表与环是本 crate
//! 的实现，**只有住在本 crate 的用例才看得到**（`ring_of` / `wait_until` 直接读
//! `watermarks()` / `chunk_count()`——这两处正是「源侧零等待」「多 push 合并」两类
//! 契约的唯一可观测面）。
//!
//! ## 夹具：迷你宿主（[`TestCtx`]）
//!
//! 宿主侧的等价物是 `src-tauri/src/plugin/pty.rs` 的 `HostPtyPorts`（真 PermissionManager +
//! 真 MessageBus + 真 AppConfig）。本 crate 不能依赖宿主（那会造环），故夹具逐项对应：
//!
//! | 端口方法 | 宿主实现 | 本夹具 |
//! | --- | --- | --- |
//! | `check_permission` | `PermissionManager::check` + 拒绝 warn | [`TestCtx::grant`] 登记的权限位 |
//! | `publish` | `MessageBus::publish`（命名空间门禁 + 有界队列 + 投递任务） | 精确 topic 路由的内存通道（记录带 `sender: "host"`） |
//! | `config` | `AppConfig` 快照 | `PtyHostConfig { default_cols: 80, default_rows: 24, … }` |
//! | `block_on_any` | `runtime_util::block_on_async`（全仓唯一那份桥） | 本夹具的 tokio runtime handle |
//! | `spawn_task` | `spawn_with_error_boundary_on(ambient_handle(), …)` | `handle.spawn` |
//!
//! **真总线的投递语义不在本 crate**：那属宿主机制内核，由 `wasm-core` 的 `pty_e2e`
//! （真 MessageBus + 真组件实例化）与 `src-tauri/tests/pty_session_chain.rs`（真插件
//! 端到端）覆盖——能力 crate 不得有 crate 根 `tests/`（见
//! `src-tauri/tests/capability_crates_unit_tests_only.rs`）。
//!
//! ## 属主夹具 id 为什么是 `pty-test.*` 而不是 `com.wasmnest.*`
//!
//! `capability_crates_no_product_ids` 锁按目录约定扫描本 crate 的**全部** `src/`
//! 文本（含本文件），`com.wasmnest.<段>` 是产品插件 id 形状。夹具里的属主 id 只是
//! 任意标签（域只当字符串用：topic 命名空间 + 属主隔离），故统一改成 `pty-test.*`
//! ——**保留锁对本文件内容的扫描力**（退役面词汇等仍会被抓到），而不是把文件挪进
//! `tests/` 目录躲开扫描。
//!
//! ## 为什么全部用例是同步 `#[test]`（不再有 `#[tokio::test]`）
//!
//! 夹具的 `block_on_any` 用 `Handle::block_on` 驱动，而 `Handle::block_on` 在**该
//! runtime 的异步上下文内**调用会 panic（"Cannot start a runtime from within a
//! runtime"）。域原语本身是同步入口（guest host function 同款），夹具的等待轮询也只
//! 读一条 `std::sync::mpsc`——故一律走同步用例 + `std::thread::sleep`。

use std::any::Any;
use std::collections::HashSet;
use std::sync::{mpsc::Receiver, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::wire::{PERMISSION_PTY_IO, PERMISSION_PTY_SPAWN};
use wasmnest_server_base::constants::{
    PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN, PLUGIN_PTY_MAX_WRITE_BYTES,
    PLUGIN_PTY_RING_FETCH_MAX_BYTES, PLUGIN_PTY_RING_MAX_BYTES,
};

use crate::plugin_binding::output::EVENT_OUTPUT;
use crate::plugin_binding::ports::{BoxedBlocked, BoxedTask, PtyHostConfig, PtyPorts};
use crate::plugin_binding::primitives::*;
use crate::plugin_binding::registry::{
    live_count, purge_for_plugin_with_ports, registered_count_for, EXIT_READ_WINDOW, PTYS,
};
use crate::plugin_binding::registry::{quota_of, register_quota, EVENT_EXIT, NOT_OWNER};
use crate::{PtyEngineConfig, PtyRing};

/// 记录总线投递的 topic（订阅按精确 topic 路由：域只发属主私有 topic）
type Tx = std::sync::mpsc::Sender<serde_json::Value>;

/// 迷你宿主：端口实现 + 权限登记 + topic 订阅表 + runtime 句柄
struct TestCtx {
    ports: Arc<dyn PtyPorts>,
    granted: Arc<Mutex<HashSet<(String, String)>>>,
    subs: Arc<Mutex<Vec<(String, Tx)>>>,
}

impl TestCtx {
    fn new() -> Self {
        let granted = Arc::new(Mutex::new(HashSet::new()));
        let subs = Arc::new(Mutex::new(Vec::new()));
        // 多线程 runtime：域的 `block_on` / 后台任务都跑在它上面。**runtime 由端口
        // 自己持有**（`Handle` 不延长 runtime 寿命：runtime 一 drop，所有 Handle
        // 立即失效），故它必须与端口同生命周期。
        let runtime = tokio::runtime::Runtime::new().expect("tokio multi-thread runtime");
        let handle = runtime.handle().clone();
        let ports: Arc<dyn PtyPorts> = Arc::new(TestPorts {
            granted: Arc::clone(&granted),
            subs: Arc::clone(&subs),
            handle,
            _runtime: runtime,
        });
        Self {
            ports,
            granted,
            subs,
        }
    }

    /// 授权（等价宿主加载漏斗里的 `grant_permissions`）
    fn grant(&self, plugin_id: &str, permissions: &[&str]) {
        let mut granted = self.granted.lock().unwrap_or_else(|e| e.into_inner());
        for permission in permissions {
            granted.insert((plugin_id.to_string(), (*permission).to_string()));
        }
    }

    /// 端口引用（域函数与回收面的第一个参数）
    fn ports(&self) -> &Arc<dyn PtyPorts> {
        &self.ports
    }

    /// 在夹具总线上精确订阅一个 topic（等价插件 activate 期的 `bus_subscribe`）
    fn subscribe(&self, topic: &str) -> Receiver<serde_json::Value> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.subs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((topic.to_string(), tx));
        rx
    }
}

/// 端口实现（逐方法对应 [`TestCtx`] 的表）
struct TestPorts {
    granted: Arc<Mutex<HashSet<(String, String)>>>,
    subs: Arc<Mutex<Vec<(String, Tx)>>>,
    handle: tokio::runtime::Handle,
    /// runtime 本体（`Handle` 不延长其寿命，故随端口一起持有）
    _runtime: tokio::runtime::Runtime,
}

impl PtyPorts for TestPorts {
    fn check_permission(&self, plugin_id: &str, permission: &str, _api: &str) -> bool {
        self.granted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&(plugin_id.to_string(), permission.to_string()))
    }

    fn publish(&self, topic: &str, payload: serde_json::Value) {
        // 与宿主总线同形状：`sender` 恒为 `host`，载荷原样透传
        let event = serde_json::json!({ "topic": topic, "sender": "host", "payload": payload });
        let subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        for (subscribed_topic, tx) in subs.iter() {
            if subscribed_topic == topic {
                let _ = tx.send(event.clone());
            }
        }
    }

    fn config(&self) -> PtyHostConfig {
        // 与宿主 `AppConfig` 默认值同形（80×24 / 16 / 4096）
        PtyHostConfig {
            default_cols: 80,
            default_rows: 24,
            engine: PtyEngineConfig::default(),
        }
    }

    fn block_on_any<'a>(&self, fut: BoxedBlocked<'a>) -> Box<dyn Any + Send> {
        self.handle.block_on(fut)
    }

    fn spawn_task(&self, _name: &'static str, task: BoxedTask) {
        self.handle.spawn(task);
    }
}

// ==================== 测试脚手架 ====================

/// 常驻配置：进程阻塞在 `read`，句柄在整个断言窗口内保持在册
///
/// **为什么不能再用 `/bin/true` 这类短命命令**：票 04 起「终态事件即摘除」——进程
/// 一退出，退出监听任务就把句柄与环从注册表摘掉，随后任何 `ring-fetch` /
/// `is-running` 都会得到 `pty handle not found` 而非预期的行为。凡以「句柄仍在」
/// 为前提的用例一律用本配置（数据面/生命面的载体必须是活进程）。
#[cfg(target_os = "linux")]
const ALIVE: &str = r#"{"command":"/bin/sh","args":["-c","read go"]}"#;

/// 常驻 + 先输出一段文本：`ring-fetch` 主干用例的载体（输出后有内容可读，进程不死）
#[cfg(target_os = "linux")]
fn alive_with_output(text: &str) -> String {
    format!(r#"{{"command":"/bin/sh","args":["-c","echo {text}; read go"]}}"#)
}

/// 授权两域并 spawn，返回可直接驱动宿主函数的上下文
#[cfg(target_os = "linux")]
fn ctx_with_pty(plugin_id: &str, config_json: &str) -> TestCtx {
    let ctx = TestCtx::new();
    ctx.grant(plugin_id, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    pty_spawn(ctx.ports(), plugin_id, config_json).expect("spawn 应成功");
    ctx
}

#[cfg(target_os = "linux")]
fn spawn_ok(plugin_id: &str, config_json: &str) -> String {
    let ctx = TestCtx::new();
    ctx.grant(plugin_id, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    pty_spawn(ctx.ports(), plugin_id, config_json).expect("spawn 应成功")
}

/// 取回某句柄的环（注册表内部视图，仅测试用）
#[cfg(target_os = "linux")]
fn ring_of(pty_id: &str) -> Arc<Mutex<PtyRing>> {
    PTYS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(pty_id)
        .map(|entry| Arc::clone(&entry.ring))
        .expect("句柄应在册")
}

/// 环上当前驻留的全部字节（一次持锁读取）
#[cfg(target_os = "linux")]
fn resident_text(ring: &Arc<Mutex<PtyRing>>) -> String {
    let ring = ring.lock().unwrap_or_else(|e| e.into_inner());
    let (min, max) = ring.watermarks();
    let fetched = ring.fetch(min, (max - min) as usize);
    String::from_utf8_lossy(&fetched.data).into_owned()
}

/// 轮询环直至出现期望内容（真 PTY 产出是异步的：断言内容，不断言时序）
#[cfg(target_os = "linux")]
fn wait_for_output(ring: &Arc<Mutex<PtyRing>>, want: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = resident_text(ring);
        if text.contains(want) || Instant::now() >= deadline {
            return text;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
fn unique_tag(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "WASMNEST_PTY_{prefix}_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

// ==================== 权限门（三态） ====================

/// 反例：完全未授权 → spawn 拒绝，注册表零副作用
#[test]
fn spawn_without_permission_is_denied() {
    let ctx = TestCtx::new();
    let err = pty_spawn(ctx.ports(), "pty-test.no-pty", r#"{"command":"/bin/true"}"#).unwrap_err();
    assert_eq!(err, "permission denied: pty:spawn");
    assert_eq!(
        registered_count_for("pty-test.no-pty"),
        0,
        "权限拒绝不得留下任何句柄"
    );
}

/// 反例：只有数据面权限（pty:io）→ 创建域仍拒绝（两域独立）
#[test]
fn spawn_with_io_permission_only_is_denied() {
    let ctx = TestCtx::new();
    ctx.grant("pty-test.io-only", &[PERMISSION_PTY_IO]);
    let err = pty_spawn(
        ctx.ports(),
        "pty-test.io-only",
        r#"{"command":"/bin/true"}"#,
    )
    .unwrap_err();
    assert_eq!(err, "permission denied: pty:spawn");
    assert_eq!(registered_count_for("pty-test.io-only"), 0);
}

/// 反例：只有创建域权限 → ring-fetch 拒绝（spawn 与 io 互不越界）
#[cfg(target_os = "linux")]
#[test]
fn ring_fetch_without_io_permission_is_denied() {
    let ctx = TestCtx::new();
    ctx.grant("pty-test.spawn-only", &[PERMISSION_PTY_SPAWN]);
    let pty_id = pty_spawn(ctx.ports(), "pty-test.spawn-only", ALIVE).expect("spawn");

    let err = pty_ring_fetch(ctx.ports(), "pty-test.spawn-only", &pty_id, 0, 1024).unwrap_err();
    assert_eq!(err, "permission denied: pty:io");
}

// ==================== 参数校验（fail-visible，无副作用） ====================

/// 反例：command 空白 / 缺 command / 非法 JSON → Err 且不产生句柄
#[test]
fn spawn_rejects_invalid_config_without_side_effects() {
    let ctx = TestCtx::new();
    ctx.grant("pty-test.bad-config", &[PERMISSION_PTY_SPAWN]);
    for bad in [r#"{"command":"   "}"#, r#"{"args":["x"]}"#, "not json"] {
        let err = pty_spawn(ctx.ports(), "pty-test.bad-config", bad).unwrap_err();
        assert!(
            err.contains("command") || err.contains("invalid config"),
            "非法配置应回明确错误，got: {err}"
        );
    }
    assert_eq!(registered_count_for("pty-test.bad-config"), 0);
}

// ==================== 属主隔离 ====================

/// 反例：他人句柄不可寻址；未知句柄回 not found
#[cfg(target_os = "linux")]
#[test]
fn ring_fetch_on_foreign_handle_is_not_owner() {
    let pty_id = spawn_ok("pty-test.owner-a", ALIVE);
    let ctx = TestCtx::new();
    ctx.grant(
        "pty-test.owner-b",
        &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO],
    );

    assert_eq!(
        pty_ring_fetch(ctx.ports(), "pty-test.owner-b", &pty_id, 0, 1024).unwrap_err(),
        NOT_OWNER
    );
    let missing = pty_ring_fetch(
        ctx.ports(),
        "pty-test.owner-b",
        "pty-does-not-exist",
        0,
        1024,
    )
    .unwrap_err();
    assert!(missing.contains("not found"), "got: {missing}");
}

/// 反例：生命面（kill）同样先做属主仲裁（越权不得转化为对他人进程的终止）
#[cfg(target_os = "linux")]
#[test]
fn kill_still_enforces_owner_before_its_own_gate() {
    let pty_id = spawn_ok("pty-test.owner-a", ALIVE);
    let ctx = TestCtx::new();
    ctx.grant(
        "pty-test.owner-b",
        &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO],
    );

    assert_eq!(
        pty_kill(ctx.ports(), "pty-test.owner-b", &pty_id).unwrap_err(),
        NOT_OWNER
    );
}

/// 反例：数据面同样受属主仲裁（write / resize / is-running 三函数）
#[cfg(target_os = "linux")]
#[test]
fn io_apis_enforce_owner() {
    let pty_id = spawn_ok("pty-test.owner-a", ALIVE);
    let ctx = TestCtx::new();
    ctx.grant(
        "pty-test.owner-b",
        &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO],
    );

    assert_eq!(
        pty_write(ctx.ports(), "pty-test.owner-b", &pty_id, b"ls\n").unwrap_err(),
        NOT_OWNER
    );
    assert_eq!(
        pty_resize(ctx.ports(), "pty-test.owner-b", &pty_id, 100, 30).unwrap_err(),
        NOT_OWNER
    );
    assert_eq!(
        pty_is_running(ctx.ports(), "pty-test.owner-b", &pty_id).unwrap_err(),
        NOT_OWNER
    );
}

/// 反例（票 06 矩阵分格）：**完全不授权**的插件调用全部 6 个函数 → 一律权限拒绝，
/// 且证明权限门先于属主仲裁与句柄查表（用不存在的句柄也必须回权限错，而不是 not-found）
#[test]
fn every_api_without_any_permission_is_denied_before_any_lookup() {
    let ctx = TestCtx::new();
    let probe = "pty-never-registered";
    let cases: [(&str, Result<(), String>); 6] = [
        (
            "spawn",
            pty_spawn(ctx.ports(), "pty-test.bare", r#"{"command":"/bin/true"}"#).map(|_| ()),
        ),
        (
            "write",
            pty_write(ctx.ports(), "pty-test.bare", probe, b"x").map(|_| ()),
        ),
        (
            "resize",
            pty_resize(ctx.ports(), "pty-test.bare", probe, 80, 24).map(|_| ()),
        ),
        (
            "kill",
            pty_kill(ctx.ports(), "pty-test.bare", probe).map(|_| ()),
        ),
        (
            "ring-fetch",
            pty_ring_fetch(ctx.ports(), "pty-test.bare", probe, 0, 1024).map(|_| ()),
        ),
        (
            "is-running",
            pty_is_running(ctx.ports(), "pty-test.bare", probe).map(|_| ()),
        ),
    ];
    for (api, result) in cases {
        let err = result.expect_err("未授权调用必须被拒");
        assert!(
            err.starts_with("permission denied: pty:"),
            "{api} 必须先撞权限门，got: {err}"
        );
        assert!(
            !err.contains("not found"),
            "{api} 不得越过权限门去查句柄: {err}"
        );
    }
    assert_eq!(
        registered_count_for("pty-test.bare"),
        0,
        "拒绝不得留下任何副作用"
    );
}

// ==================== 生命周期（票 04：kill / 退出事件 / 停用回收） ====================

/// 漂移锁：宿主发布的事件名必须与 SDK 常量一致，且两侧形状共用 `owned_topic`
///
/// 票 05 前宿主按 `{EVENT_EXIT}.{owner}` 手拼、插件按 SDK `pty_event_topic` 订阅，
/// 两处各写一份就会「订阅成功但永远收不到」，且这类错配在单侧测试里不可见。
/// 现在两侧都走 `crate::wire::owned_topic`（与 SDK `bus::owned_topic` 漂移锁钉死），
/// 形状不再有漂移面；
/// 本用例锁「事件名常量」+「SDK 域助手确实由 owned_topic 组合」，而宿主发布侧
/// 是否真的用了它，由下方按 SDK 助手订阅的投递用例（`exit_event_delivered_once`
/// 等）行为性地兜住——宿主退回手拼即收不到投递。
#[test]
fn exit_event_name_matches_sdk_subscription_helper() {
    use crate::wire as sdk;
    assert_eq!(EVENT_EXIT, sdk::PTY_EXIT, "宿主事件名与 SDK 常量漂移");
    assert_eq!(
        sdk::owned_topic("com.example.plugin", EVENT_EXIT),
        sdk::pty_event_topic(sdk::PTY_EXIT, "com.example.plugin"),
        "SDK 域助手与命名空间原语漂移"
    );
}

/// 按 SDK 订阅助手构造属主定向 topic（`<owner>::pty:exit`）
///
/// 测试订阅侧刻意走 SDK 助手而非宿主侧拼接：宿主发布形状若与插件订阅形状分叉，
/// 下面的投递断言直接收不到事件（票 05 命名空间的行为性漂移锁）。
fn exit_topic(owner: &str) -> String {
    crate::wire::pty_event_topic(crate::wire::PTY_EXIT, owner)
}

/// 在夹具总线上订阅一个 topic（见 [`TestCtx::subscribe`]：记录投递的 topic /
/// sender / payload，供定向投递与恰好一次断言）
fn subscribe(ctx: &TestCtx, topic: &str) -> Receiver<serde_json::Value> {
    ctx.subscribe(topic)
}

/// 等待一条投递（投递是异步的，超时返回 None）
fn wait_event(rx: &Receiver<serde_json::Value>) -> Option<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(event) = rx.try_recv() {
            return Some(event);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 轮询至句柄被监听任务摘除（`kill` 只发起终止，摘除在终态齐备时发生）
fn wait_handle_retired(ctx: &TestCtx, plugin_id: &str, pty_id: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match pty_is_running(ctx.ports(), plugin_id, pty_id) {
            Err(e) if e.contains("not found") => return e,
            _ => {
                if Instant::now() >= deadline {
                    panic!("句柄必须在超时前被摘除，当前仍可寻址: {pty_id}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// 正例：属主 kill → 进程终止 + 句柄摘除 + 属主收到 reason=killed 的退出事件
#[cfg(target_os = "linux")]
#[test]
fn kill_terminates_handle_and_publishes_killed_event() {
    let owner = "pty-test.kill";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    let pty_id = pty_spawn(ctx.ports(), owner, ALIVE).expect("spawn");
    let events = subscribe(&ctx, &exit_topic(owner));

    pty_kill(ctx.ports(), owner, &pty_id).expect("kill 应成功");
    let event = wait_event(&events).expect("属主必须收到 pty:exit");
    assert_eq!(
        event["payload"]["ptyId"].as_str(),
        Some(pty_id.as_str()),
        "事件必须寻址到被杀的那条 PTY: {event}"
    );
    assert_eq!(
        event["payload"]["reason"], "killed",
        "kill 路径 reason 固定: {event}"
    );
    assert_eq!(
        event["topic"],
        exit_topic(owner),
        "topic 为属主私有命名空间"
    );
    assert_eq!(event["sender"], "host", "事件由宿主发布");

    // 摘除即不可寻址（句柄与环同时释放）
    let err = wait_handle_retired(&ctx, owner, &pty_id);
    assert!(err.contains("not found"), "got: {err}");
    assert_eq!(registered_count_for(owner), 0, "kill 后注册表不得留残项");
}

/// 正例：进程自然退出 → 属主收到 reason=stopped + 真实退出码（票 01 的 exitCode 能力）
#[cfg(target_os = "linux")]
#[test]
fn natural_exit_publishes_stopped_event_with_exit_code() {
    let owner = "pty-test.natural-exit";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    // 订阅先于 spawn：宿主不缓冲不重放，短命命令可能在订阅前就终态
    let events = subscribe(&ctx, &exit_topic(owner));

    pty_spawn(
        ctx.ports(),
        owner,
        r#"{"command":"/bin/sh","args":["-c","exit 42"]}"#,
    )
    .expect("spawn");
    let event = wait_event(&events).expect("自然退出必须发出退出事件");
    assert_eq!(
        event["payload"]["reason"], "stopped",
        "非 kill 的退出: {event}"
    );
    assert_eq!(
        event["payload"]["exitCode"], 42,
        "退出码必须如实带出（引擎侧回收所得）: {event}"
    );
}

/// 边界：未显式 exit 的进程退出码为 0，且**不得**与「取不到退出码」混淆为缺字段
#[cfg(target_os = "linux")]
#[test]
fn zero_exit_code_is_reported_as_value_not_absent_field() {
    let owner = "pty-test.exit-zero";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    let events = subscribe(&ctx, &exit_topic(owner));

    pty_spawn(ctx.ports(), owner, r#"{"command":"/bin/true"}"#).expect("spawn");
    let event = wait_event(&events).expect("须有退出事件");
    assert_eq!(
        event["payload"].get("exitCode"),
        Some(&serde_json::json!(0)),
        "退出码 0 与「回收失败无退出码」必须可区分: {event}"
    );
}

/// 事件定向：他人命名空间零投递，属主 topic 恰好一条（不重放、不双发）
#[cfg(target_os = "linux")]
#[test]
fn exit_events_are_owner_scoped_and_exactly_once() {
    let owner = "pty-test.exit-owner";
    let other = "pty-test.exit-other";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    ctx.grant(other, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);

    let owner_events = subscribe(&ctx, &exit_topic(owner));
    let other_events = subscribe(&ctx, &exit_topic(other));

    let mine = pty_spawn(ctx.ports(), owner, ALIVE).expect("spawn owner");
    let theirs = pty_spawn(ctx.ports(), other, ALIVE).expect("spawn other");

    pty_kill(ctx.ports(), owner, &mine).expect("kill");
    let event = wait_event(&owner_events).expect("属主收到自己的事件");
    assert_eq!(event["payload"]["ptyId"], mine);
    assert!(
        other_events.try_recv().is_err(),
        "他人命名空间收不到他人事件（宿主只向属主投递，且他人订阅被门禁拒）"
    );
    // 恰好一次：监听任务与停用回收之外不再有第二个发布者
    assert!(
        wait_event_timeout(&owner_events, Duration::from_secs(1)).is_none(),
        "一条 PTY 只能有一条退出事件（不重放、不双发）"
    );
    // 它插件的句柄不受本次 kill 影响
    assert!(
        pty_is_running(ctx.ports(), other, &theirs).expect("他人句柄应仍可查询"),
        "kill 只作用于属主自己的进程"
    );
}

/// 正例：停用回收 kill 并摘除本人全部 PTY，逐条补发事件，且只碰本人
#[cfg(target_os = "linux")]
#[test]
fn purge_for_plugin_retires_all_owned_handles_and_touches_nobody_else() {
    let owner = "pty-test.purge-owner";
    let other = "pty-test.purge-other";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    ctx.grant(other, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);

    let first = pty_spawn(ctx.ports(), owner, ALIVE).expect("spawn 1");
    let second = pty_spawn(ctx.ports(), owner, r#"{"command":"/bin/cat"}"#).expect("spawn 2");
    let theirs = pty_spawn(ctx.ports(), other, ALIVE).expect("spawn peer");
    let owner_events = subscribe(&ctx, &exit_topic(owner));
    let other_events = subscribe(&ctx, &exit_topic(other));

    assert_eq!(
        purge_for_plugin_with_ports(ctx.ports(), owner),
        2,
        "回收数应为本人全部在册 PTY"
    );

    // 本人：注册表清空、进程终止、逐条补发 reason=killed
    // （事件顺序按注册表遍历，HashMap 不承诺——故断言**集合**而非序列）
    assert_eq!(registered_count_for(owner), 0, "停用回收不得留残项");
    let mut received: Vec<String> = Vec::new();
    for _ in 0..2 {
        let event = wait_event(&owner_events).expect("每条 PTY 各一条补发事件");
        assert_eq!(
            event["payload"]["reason"], "killed",
            "停用即宿主代为终止: {event}"
        );
        received.push(
            event["payload"]["ptyId"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        );
    }
    received.sort();
    let mut want = vec![first.clone(), second.clone()];
    want.sort();
    assert_eq!(received, want, "回收必须逐条寻址到本人每一条 PTY");
    assert!(
        wait_event_timeout(&owner_events, Duration::from_secs(1)).is_none(),
        "恰好一次：停用回收与退出监听不得对同一 PTY 各发一条"
    );

    // 它插件：句柄在册、可用，且收不到任何补发事件
    assert_eq!(registered_count_for(other), 1, "回收越界碰了他插件的句柄");
    assert!(
        pty_is_running(ctx.ports(), other, &theirs).expect("他人句柄仍可查"),
        "他人进程必须未被 kill"
    );
    assert!(
        other_events.try_recv().is_err(),
        "非属主收不到他人的回收事件"
    );

    purge_for_plugin_with_ports(ctx.ports(), other);
}

/// 引擎层**全量**回收的结构锁（系统关停路径；会话引擎下沉 P1 开放点 4）
///
/// **为什么不是行为用例**：`kill_all_registered` 跨属主回收，在本进程内触发会把并行
/// 兄弟用例的夹具一起收掉（README 级的测试隔离常识：全局破坏性函数不进共享进程的
/// 并行用例）。它的行为本体（摘除 → kill → 按属主补发、与退出监听竞争时恰好一次、
/// 不碰无关句柄）已由按属主回收用例
/// `purge_for_plugin_retires_all_owned_handles_and_touches_nobody_else` 逐条覆盖——
/// 两者**共用** `reclaim_handles`，故这里只锁「共用同一实现」与「关停确实接上了」。
///
/// 锁两件事：
/// ① 回收实现单点（不得出现第二份「先摘除后发事件」的拷贝——那是单一发布者不变量的
///    破口，会出现漏发或重发）；
/// ② 关停钩子确实调用它（插件已停用 / 超时时仍能回收孤儿进程，正是它的立项理由）。
/// `live_count` 是「在册即存活」的引擎事实计数
///
/// **并行安全（2026-09-23 实测修正）**：本用例原先断言 `live_count() >= before + 2`
/// （`before` 是本线程读到的全局快照），但兄弟用例随时在按属主 spawn / purge，
/// `before` 里属于别人的那部分会在两次读之间消失——**判据正确也会红**（本线配额用例
/// 把在册条数拉到 10 后必现）。`live_count` 是全局量，在 lib 并行调度下唯一可断言的
/// 是它与「本用例自己控制的在册集合」的包含关系，不是它的差值；守卫的真实判据
/// （P1-b 起 = 「存活 PTY 计数 > 0」）也只用到这个方向。
#[cfg(target_os = "linux")]
#[test]
fn live_count_includes_newly_registered_handles() {
    let owner = "pty-test.live-count";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    assert_eq!(
        registered_count_for(owner),
        0,
        "本用例的属主是全新的，不得继承兄弟句柄"
    );
    let _first = pty_spawn(ctx.ports(), owner, ALIVE).expect("spawn 1");
    let second = pty_spawn(ctx.ports(), owner, ALIVE).expect("spawn 2");
    assert_eq!(registered_count_for(owner), 2);
    assert!(
        live_count() >= registered_count_for(owner),
        "本属主的在册句柄必须被全局计数涵盖（in_owner={}, live={}）",
        registered_count_for(owner),
        live_count()
    );

    pty_kill(ctx.ports(), owner, &second).expect("kill 第二条");
    let deadline = Instant::now() + Duration::from_secs(5);
    while registered_count_for(owner) > 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        registered_count_for(owner),
        1,
        "摘除后本人只剩一条（终态监听已把句柄移出注册表）"
    );

    purge_for_plugin_with_ports(ctx.ports(), owner);
    assert_eq!(registered_count_for(owner), 0, "回收后本人清零");
}

/// 反例：spawn 失败路径零事件、零句柄（无句柄可寻址，spec D5）
#[cfg(target_os = "linux")]
#[test]
fn failed_spawn_publishes_no_event_and_registers_nothing() {
    let owner = "pty-test.spawn-fail";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    let events = subscribe(&ctx, &exit_topic(owner));

    let err = pty_spawn(
        ctx.ports(),
        owner,
        r#"{"command":"/nonexistent/wasmnest-pty-command"}"#,
    )
    .unwrap_err();
    assert!(
        err.contains("启动子进程失败") || err.contains("打开伪终端失败"),
        "spawn 失败必须带操作上下文: {err}"
    );
    assert_eq!(registered_count_for(owner), 0, "失败不得留句柄");
    assert!(
        wait_event_timeout(&events, Duration::from_millis(300)).is_none(),
        "失败路径不得发布任何事件（回归票 02 契约）"
    );
}

/// 短窗口等待（负向断言用：等满即确认「没有投递」）
///
/// 同步实现：夹具的投递记录就在一条 `std::sync::mpsc` 上（域侧 `publish` 即投递），
/// 轮询到窗口耗尽即返回 `None`——不依赖 tokio 定时器（用例全同步，见模块头）。
fn wait_event_timeout(
    rx: &Receiver<serde_json::Value>,
    wait: Duration,
) -> Option<serde_json::Value> {
    let deadline = Instant::now() + wait;
    loop {
        if let Ok(event) = rx.try_recv() {
            return Some(event);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ==================== P2：输出可用通知（限频唤醒） ====================

/// 漂移锁（P2）：输出可用通知的事件名与 SDK 常量一致，形状仍共用 `owned_topic`
///
/// 与 `exit_event_name_matches_sdk_subscription_helper` 同一口径：宿主发布侧与插件
/// 订阅侧各自只有一处字面量，本用例把两处钉在一起——任一侧改名而另一侧未跟，
/// 现象是「订阅成功但永远收不到」（静默退化回纯轮询），单侧测试不可见。
#[test]
fn output_event_name_matches_sdk_subscription_helper() {
    use crate::wire as sdk;
    assert_eq!(EVENT_OUTPUT, sdk::PTY_OUTPUT, "宿主事件名与 SDK 常量漂移");
    assert_eq!(
        sdk::owned_topic("com.example.plugin", EVENT_OUTPUT),
        sdk::pty_event_topic(sdk::PTY_OUTPUT, "com.example.plugin"),
        "SDK 域助手与命名空间原语漂移"
    );
}

/// 按 SDK 订阅助手构造输出可用通知 topic（`<owner>::pty:output`，P2）
fn output_topic(owner: &str) -> String {
    crate::wire::pty_event_topic(crate::wire::PTY_OUTPUT, owner)
}

/// 收集窗口内的全部投递（限频断言用：窗口内不得逐块推送）
fn drain_events(rx: &Receiver<serde_json::Value>, window: Duration) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + window;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(event) => out.push(event),
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    out
}

/// 正例（P2）：真 PTY 产出 → 属主收到 `pty:output`（只带句柄），且**限频**：
/// 一次毫秒级突发含二十余次 4 KiB push，通知数必须远少于 push 数——证明写侧装饰器
/// 确实生效，而不是「每次 push 一条」（那等于把通知退化成逐块 push）。
#[cfg(target_os = "linux")]
#[test]
fn output_notify_is_rate_limited_and_owner_scoped() {
    let owner = "pty-test.out-notify";
    let other = "pty-test.out-notify-other";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    let events = subscribe(&ctx, &output_topic(owner));
    let other_events = subscribe(&ctx, &output_topic(other));

    // 突发约 100 KiB 文本（`read_buffer_size` = 4096 → 二十余次 push），末尾驻留
    // （`read go`）保证句柄与环在断言窗口内不被摘除
    let pty_id = pty_spawn(
        ctx.ports(),
        owner,
        r#"{"command":"/bin/sh","args":["-c","seq 1 20000; read go"]}"#,
    )
    .expect("spawn");

    let event = wait_event(&events).expect("产出必须通知属主");
    assert_eq!(event["payload"]["ptyId"].as_str(), Some(pty_id.as_str()));
    assert_eq!(
        event["topic"],
        output_topic(owner),
        "topic 为属主私有命名空间"
    );
    assert_eq!(event["sender"], "host", "通知由宿主发布");
    assert!(
        other_events.try_recv().is_err(),
        "他人命名空间收不到（定向投递只到属主）"
    );

    // 等产出全部落环（推送异步：按内容断言，不断言时序）
    let ring = ring_of(&pty_id);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let max = ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .watermarks()
            .1;
        if max >= 100_000 || Instant::now() >= deadline {
            assert!(max >= 100_000, "突发产出未落环（max={max}）");
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let chunks = ring.lock().unwrap_or_else(|e| e.into_inner()).chunk_count();
    assert!(
        chunks >= 8,
        "4 KiB 读块下 100 KiB 产出应有多次 push，实际 {chunks}"
    );

    let extra = drain_events(&events, Duration::from_millis(100));
    let notified = 1 + extra.len();
    eprintln!("P2-DEBUG chunks={chunks} notified={notified}");
    assert!(
        notified < chunks,
        "限频窗口内必须合并（push={chunks}, notify={notified}）；逐块通知 = 退化成 push 数据面"
    );
}

/// 反例（P2）：没有订阅者时通知静默丢弃，不影响产出链（环照常收满）
///
/// 订阅是插件的自愿行为（老插件不订阅即回到纯轮询），宿主不得因此报错或丢字节。
#[cfg(target_os = "linux")]
#[test]
fn output_notify_without_subscribers_keeps_ring_intact() {
    let owner = "pty-test.out-notify-nosub";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);

    let pty_id = pty_spawn(
        ctx.ports(),
        owner,
        r#"{"command":"/bin/sh","args":["-c","seq 1 20000; read go"]}"#,
    )
    .expect("spawn");

    let ring = ring_of(&pty_id);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let max = ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .watermarks()
            .1;
        if max >= 100_000 || Instant::now() >= deadline {
            assert!(max >= 100_000, "无订阅者不得影响产出链（max={max}）");
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // 句柄仍可寻址（通知路径不持有任何生命周期副作用）
    assert!(pty_is_running(ctx.ports(), owner, &pty_id).expect("句柄应在册"));
}

// ==================== 数据面（票 03：write / resize / is-running） ====================

/// 反例：只授创建域（pty:spawn）→ 数据面三函数一律拒绝（两域独立）
#[cfg(target_os = "linux")]
#[test]
fn io_apis_without_io_permission_are_denied() {
    let ctx = TestCtx::new();
    ctx.grant("pty-test.spawn-only", &[PERMISSION_PTY_SPAWN]);
    let pty_id = pty_spawn(ctx.ports(), "pty-test.spawn-only", ALIVE).expect("spawn");

    assert_eq!(
        pty_write(ctx.ports(), "pty-test.spawn-only", &pty_id, b"x").unwrap_err(),
        "permission denied: pty:io"
    );
    assert_eq!(
        pty_resize(ctx.ports(), "pty-test.spawn-only", &pty_id, 80, 24).unwrap_err(),
        "permission denied: pty:io"
    );
    assert_eq!(
        pty_is_running(ctx.ports(), "pty-test.spawn-only", &pty_id).unwrap_err(),
        "permission denied: pty:io"
    );
}

/// 正例：write 的字节真的进了进程并被进程变换后回读（`sed` 前缀证明非 tty 回显）
#[cfg(target_os = "linux")]
#[test]
fn write_response_comes_from_process_not_tty_echo() {
    let marker = unique_tag("SED");
    let ctx = ctx_with_pty(
        "pty-test.sed",
        r#"{"command":"/bin/sed","args":["s/^/OUT:/"]}"#,
    );
    let pty_id = find_handle_of("pty-test.sed");

    pty_write(
        ctx.ports(),
        "pty-test.sed",
        &pty_id,
        format!("body-{marker}\n").as_bytes(),
    )
    .expect("write");
    let output = wait_for_output(&ring_of(&pty_id), &format!("OUT:body-{marker}"));
    assert!(
        output.contains(&format!("OUT:body-{marker}")),
        "OUT: 前缀只可能由进程加上（tty 回显不带前缀）: {output}"
    );
}

/// 边界：恰好等于上限放行（`>` 的另一侧），且整块字节确实落到进程
#[cfg(target_os = "linux")]
#[test]
fn write_at_limit_is_accepted_and_delivered_whole() {
    let ctx = ctx_with_pty("pty-test.at-limit", r#"{"command":"/bin/cat"}"#);
    let pty_id = find_handle_of("pty-test.at-limit");

    // 载荷全部由短行组成：canonical 模式的内核输入队列按行放行（MAX_CANON ~4 KiB），
    // 64 KiB 无换行的整块写入会卡在读端，测不到准入判定本身
    let mut payload: Vec<u8> = Vec::with_capacity(PLUGIN_PTY_MAX_WRITE_BYTES);
    while payload.len() < PLUGIN_PTY_MAX_WRITE_BYTES {
        let fill = (PLUGIN_PTY_MAX_WRITE_BYTES - payload.len() - 1).min(59);
        payload.extend(std::iter::repeat_n(b'z', fill));
        payload.push(b'\n');
    }
    assert_eq!(
        payload.len(),
        PLUGIN_PTY_MAX_WRITE_BYTES,
        "边界载荷必须恰好等于上限"
    );

    pty_write(ctx.ports(), "pty-test.at-limit", &pty_id, &payload).expect("等于上限必须放行");

    // cat 原样回吐：环内驻留字节达到写入量即证明「没被截断成半块」
    let ring = ring_of(&pty_id);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let resident = ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .resident_bytes();
        if resident >= PLUGIN_PTY_MAX_WRITE_BYTES as u64 || Instant::now() >= deadline {
            assert!(
                resident >= PLUGIN_PTY_MAX_WRITE_BYTES as u64,
                "等于上限的写入应整块送达，实际环内驻留 {resident} 字节"
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 反例：write 超单次上限 → 明确错误且不写入（不静默截断）
#[cfg(target_os = "linux")]
#[test]
fn write_over_limit_is_rejected_without_partial_input() {
    let ctx = ctx_with_pty(
        "pty-test.limit",
        // 收到一行才回显标记：据此判定「前一次超限写入没有半个字节漏进去」；
        // 末尾再阻塞一次，保证断言窗口内句柄不被退出监听摘走（票 04）
        r#"{"command":"/bin/sh","args":["-c","read line; echo PASSED; read go"]}"#,
    );
    let pty_id = find_handle_of("pty-test.limit");
    let oversized = vec![b'x'; PLUGIN_PTY_MAX_WRITE_BYTES + 1];

    let err = pty_write(ctx.ports(), "pty-test.limit", &pty_id, &oversized).unwrap_err();
    assert!(
        err.contains("too large") && err.contains("limit"),
        "got: {err}"
    );
    assert!(
        err.contains(&PLUGIN_PTY_MAX_WRITE_BYTES.to_string()),
        "错误必须带上限常量（不静默截断）: {err}"
    );

    // 被拒的负载不得有任何字节进入进程 stdin：随后一行合法写入应能被 `read` 取到
    // （若超限负载被部分写入，`read line` 会先消费残渣，PASSED 就永远不来）
    pty_write(ctx.ports(), "pty-test.limit", &pty_id, b"go\n").expect("等于/低于上限应放行");
    let output = wait_for_output(&ring_of(&pty_id), "PASSED");
    assert!(output.contains("PASSED"), "超限拒绝必须零副作用: {output}");
}

/// 正例：resize 改变内核终端尺寸（进程侧 `stty size` 反查 30x100 → 24x80）
#[cfg(target_os = "linux")]
#[test]
fn resize_changes_kernel_winsize_observed_by_process() {
    let ctx = ctx_with_pty(
        "pty-test.resize",
        // 插件自己要求 shell 包装（业务性包装归插件层，宿主不做）：
        // 先报一次尺寸，然后阻塞在 read——第二次报尺寸由本用例 write 解锁，
        // 因此「resize 已生效」与「第二次读取」之间无竞态
        r#"{"command":"/bin/sh","args":["-c","stty size; read go; stty size"],"cols":100,"rows":30}"#,
    );
    let pty_id = find_handle_of("pty-test.resize");
    let before = wait_for_output(&ring_of(&pty_id), "30 100");
    assert!(before.contains("30 100"), "spawn 尺寸应为 30x100: {before}");

    pty_resize(ctx.ports(), "pty-test.resize", &pty_id, 80, 24).expect("resize");
    pty_write(ctx.ports(), "pty-test.resize", &pty_id, b"go\n").expect("write 解锁第二次读取");
    let after = wait_for_output(&ring_of(&pty_id), "24 80");
    assert!(
        after.contains("24 80"),
        "resize 后进程应观察到 24x80: {after}"
    );
}

/// 契约：`is-running` 判据四格真值表（票 03 C-②的确定性锁）
///
/// 「进程自然退出但句柄尚未摘除」这一格在端到端上只有毫秒窗口（EOF 后退出监听
/// 立即摘环，票 04），故把组合判定做成纯函数逐格断言：去掉 `!output_terminated`
/// 的变异必须在此翻红，否则该判据就退化成「只信 `running` 标志」——那会让插件
/// 在丢事件时永远看到一个死进程是活的。
#[test]
fn is_running_verdict_covers_all_four_states() {
    assert!(running_verdict(true, false), "活着且输出未终结 → true");
    assert!(!running_verdict(false, false), "已被要求终止 → false");
    assert!(
        !running_verdict(true, true),
        "running 未翻但读线程已 EOF（自然退出的那一格）→ 必须 false"
    );
    assert!(!running_verdict(false, true), "两路都终结 → false");
}

/// 正例 + 状态迁移：进程存活期 is-running=true，自然退出后句柄最终摘除且不再可寻址
///
/// 判据组合本身见 [`is_running_verdict_covers_all_four_states`]；本用例验端到端
/// 的两端确定态：alive=true，退出后句柄在只读窗口内仍可寻址（#12A：退出处理器
/// 取尾段），窗口到期由延迟任务摘除 ⇒ `Err(not found)`。
#[cfg(target_os = "linux")]
#[test]
fn is_running_true_while_alive_and_handle_retired_after_natural_exit() {
    let owner = "pty-test.running";
    let ctx = ctx_with_pty(owner, ALIVE);
    let pty_id = find_handle_of(owner);
    assert!(
        pty_is_running(ctx.ports(), owner, &pty_id).expect("is-running"),
        "阻塞在 read 的进程应为 running"
    );

    // 解锁 → shell 自然退出 → 终态事件 → 只读窗口 → 窗口到期句柄摘除
    pty_write(ctx.ports(), owner, &pty_id, b"go\n").expect("write");
    let deadline = Instant::now() + EXIT_READ_WINDOW + Duration::from_secs(5);
    while is_registered(&pty_id) {
        if Instant::now() >= deadline {
            panic!("窗口到期后句柄必须被延迟任务摘除，不得永久在册");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let err = pty_is_running(ctx.ports(), owner, &pty_id).unwrap_err();
    assert!(err.contains("not found"), "摘除后必须不可寻址，got: {err}");
}

/// #12A 回归：自然退出后、只读窗口内，环尾段必须仍可 fetch（退出事件先发布、
/// 环后释放）。修复前退出监听先摘环再发布，退出处理器的尾帧 fetch 必然
/// `pty handle not found`，最后一段输出（含 50ms 限频窗口内的最后一批）永久丢失。
#[cfg(target_os = "linux")]
#[test]
fn ring_tail_readable_during_exit_read_window() {
    let owner = "pty-test.exit-window";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    let events = subscribe(&ctx, &exit_topic(owner));
    // 先产出后退出：sleep 保证读线程已把字节搬进环再 EOF，不与事件投递赛跑
    let pty_id = pty_spawn(
        ctx.ports(),
        owner,
        r#"{"command":"/bin/sh","args":["-c","echo tail-marker-12; sleep 0.2; exit 0"]}"#,
    )
    .expect("spawn");
    let event = wait_event(&events).expect("自然退出必须发出退出事件");
    assert_eq!(
        event["payload"]["ptyId"].as_str(),
        Some(pty_id.as_str()),
        "事件必须寻址到本句柄: {event}"
    );

    // 窗口内：句柄在册（配额计数已排除窗口期条目）+ 尾段可读
    assert!(is_registered(&pty_id), "只读窗口内句柄必须在册");
    let tail = pty_ring_fetch(ctx.ports(), owner, &pty_id, 0, 4096)
        .expect("窗口内 ring-fetch 必须成功")
        .expect("环内必须有尾段字节");
    assert!(
        String::from_utf8_lossy(&tail.data).contains("tail-marker-12"),
        "尾段必须含进程最后输出: {:?}",
        String::from_utf8_lossy(&tail.data)
    );

    // 窗口到期：句柄最终摘除（不永久在册）
    let deadline = Instant::now() + EXIT_READ_WINDOW + Duration::from_secs(5);
    while is_registered(&pty_id) {
        assert!(Instant::now() < deadline, "窗口到期后句柄必须被摘除");
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ==================== 限额与背压（票 05） ====================

/// 持续产出的流式载体（`stty -echo` 关掉 tty 回显，环内内容即进程产出）
#[cfg(target_os = "linux")]
fn streaming_config(ring_bytes: u64) -> String {
    format!(
        r#"{{"command":"/bin/sh","args":["-c","stty -echo; while true; do echo line; sleep 0.001; done"],"ringBytes":{ring_bytes}}}"#
    )
}

/// 回显进程载体的就绪标记（`stty` 与 `cat` 之间的同步点，见 `quiet_cat_config`）
#[cfg(target_os = "linux")]
const STTY_READY: &str = "STTY_READY";

/// 回显进程载体（写入什么就产出什么，可逐字节比对）
///
/// 必须等 `stty` 真的生效后再灌载荷：`stty -echo -onlcr` 与 `cat` 是 fork 后异步
/// 执行的，若在它生效前写入，前半段会被 tty 驱动回显一遍并做 `\n → \r\n` 改写，
/// 字节级比对就会挂。故以 `echo STTY_READY` 作为同步点（关掉回显后它只出现一次）。
#[cfg(target_os = "linux")]
fn quiet_cat_config() -> &'static str {
    r#"{"command":"/bin/sh","args":["-c","stty -echo -onlcr; echo STTY_READY; cat"]}"#
}

/// 由短行拼装的 N 字节载荷（canonical 终端下行块才不会卡在内核输入队列，
/// 与票 03 的边界用例同一约束）
#[cfg(target_os = "linux")]
fn line_payload(len: usize) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::with_capacity(len);
    let mut i = 0usize;
    while payload.len() < len {
        let fill = (len - payload.len() - 1).min(50);
        for _ in 0..fill {
            payload.push(b'a' + (i % 26) as u8);
            i += 1;
        }
        payload.push(b'\n');
    }
    payload
}

/// 轮询环直至谓词命中（真 PTY 产出异步：断言最终事实，不断言时序）
#[cfg(target_os = "linux")]
fn wait_until(ring: &Arc<Mutex<PtyRing>>, pred: impl Fn(&PtyRing) -> bool, why: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        {
            let guard = ring.lock().unwrap_or_else(|e| e.into_inner());
            if pred(&guard) {
                return;
            }
        }
        assert!(Instant::now() < deadline, "{why}（5s 内未达成）");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 反例：每插件在册数达上限 → `Err`（fail-visible：不排队、不静默淘汰旧句柄），
/// 配额按属主隔离，且句柄回收后额度归还
#[cfg(target_os = "linux")]
#[test]
fn pty_quota_is_per_plugin_and_rejects_overflow_without_side_effects() {
    let owner = "pty-test.quota";
    let peer = "pty-test.quota-peer";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    ctx.grant(peer, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);

    for _ in 0..PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN {
        pty_spawn(ctx.ports(), owner, ALIVE).expect("上限之内必须放行");
    }
    assert_eq!(
        registered_count_for(owner),
        PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN
    );

    let err = pty_spawn(ctx.ports(), owner, ALIVE).unwrap_err();
    assert!(
        err.contains("too many ptys"),
        "超限必须明确报错，got: {err}"
    );
    assert!(
        err.contains(&PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN.to_string()),
        "错误必须带上限常量: {err}"
    );
    assert_eq!(
        registered_count_for(owner),
        PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN,
        "超限拒绝不得留下第 9 条，也不得动既有句柄"
    );

    // 配额按属主计：同宿主另一插件此刻仍可创建并正常查询
    let theirs = pty_spawn(ctx.ports(), peer, ALIVE).expect("他插件不受该配额影响");
    assert!(pty_is_running(ctx.ports(), peer, &theirs).expect("他插件句柄可用"));

    // 回收即归还额度
    let victim = find_handle_of(owner);
    pty_kill(ctx.ports(), owner, &victim).expect("kill 腾出额度");
    let deadline = Instant::now() + Duration::from_secs(5);
    while registered_count_for(owner) >= PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    pty_spawn(ctx.ports(), owner, ALIVE).expect("腾出额度后同一属主必须可再建");

    purge_for_plugin_with_ports(ctx.ports(), owner);
    purge_for_plugin_with_ports(ctx.ports(), peer);
}

/// 结构锁：配额登记必须接在插件加载漏斗上，且与权限同点
///
/// 为什么是结构锁而不是行为用例：走到 `pty_spawn` 的真实路径要求完整加载一遍
/// WASM 插件（`session_e2e` 级成本），而漂移形态恰恰是「改了 manifest 声明却没生效」——
/// 那只发生在登记线被摘掉/挪走时，与本模块的纯逻辑无关。摘掉接线后所有配额声明会
/// 静默回落默认档 8，业务会话数被内核常量悄悄封顶，正是 H1 要消除的故障形态。
/// 声明式配额（会话引擎下沉 P1 / H1）：manifest `ptyQuota` 就是 `spawn` 的判据
///
/// 取一个**低于默认档**的值，是为了让「读的是声明、不是常量」这一件事在断言里唯一
/// 可辨：若实现仍钉着 `PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN`，第 3 条会成功而不是失败。
/// 反向（高于默认档）由下一例覆盖——两例合起来才排除「巧合相等」。
#[cfg(target_os = "linux")]
#[test]
fn declared_quota_below_default_becomes_the_spawn_ceiling() {
    let owner = "pty-test.quota-low";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    register_quota(owner, Some(2));

    for _ in 0..2 {
        pty_spawn(ctx.ports(), owner, ALIVE).expect("声明额度之内必须放行");
    }
    let err = pty_spawn(ctx.ports(), owner, ALIVE).unwrap_err();
    assert!(
        err.contains("limit 2") && err.contains("too many ptys"),
        "超限文案必须点名**声明值** 2（而非默认档），got: {err}"
    );
    assert_eq!(registered_count_for(owner), 2, "拒绝不得留下第 3 条");

    purge_for_plugin_with_ports(ctx.ports(), owner);
}

/// 验收项「第 9 条会话可创建」：声明高于默认档后，默认档不再是天花板
///
/// 会话产品的并发数（用户可开多少终端）今天落在单一内核常量 8 上——业务会话改走
/// `host-pty` 之后这条天花板会直接变成产品故障，故配额随属主声明走。
#[cfg(target_os = "linux")]
#[test]
fn declared_quota_above_default_allows_the_ninth_session() {
    let owner = "pty-test.quota-high";
    let declared = PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN + 1;
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    register_quota(owner, Some(declared));

    for i in 0..declared {
        pty_spawn(ctx.ports(), owner, ALIVE)
            .unwrap_or_else(|e| panic!("第 {} 条应在声明额度内放行，got: {e}", i + 1));
    }
    assert_eq!(registered_count_for(owner), declared, "声明值即天花板");
    let err = pty_spawn(ctx.ports(), owner, ALIVE).unwrap_err();
    assert!(
        err.contains(&format!("limit {declared}")),
        "越界文案应点名声明值 {declared}，got: {err}"
    );

    purge_for_plugin_with_ports(ctx.ports(), owner);
}

/// 未声明 = 默认档，且登记 `None` 与不登记同义（既有插件零迁移）
#[test]
fn undeclared_plugin_falls_back_to_default_quota() {
    let declared_then_cleared = "pty-test.quota-clear";
    register_quota(declared_then_cleared, None);
    assert_eq!(
        quota_of(declared_then_cleared),
        PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN,
        "显式 None 必须回到默认档（重载时删掉声明的形态）"
    );
    assert_eq!(
        quota_of("pty-test.never-loaded"),
        PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN,
        "表内无记录（未走加载漏斗 / 无头测试上下文）同样落默认档"
    );
}

/// 反例：`ringBytes` 为 0 或超宿主上限 → `Err`（不夹取、不降级），零副作用
/// （配额类判定在开 fd / 起进程之前完成）
#[test]
fn declared_ring_bytes_out_of_range_is_rejected_without_side_effects() {
    let owner = "pty-test.range";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);

    for bad in [0u64, PLUGIN_PTY_RING_MAX_BYTES + 1] {
        let err = pty_spawn(
            ctx.ports(),
            owner,
            &format!(r#"{{"command":"/bin/true","ringBytes":{bad}}}"#),
        )
        .unwrap_err();
        assert!(
            err.contains("ringBytes"),
            "错误必须点名被拒的参数，got: {err}"
        );
        assert!(
            err.contains(&bad.to_string()) || err.contains("greater than 0"),
            "错误必须带上被拒的值（不静默夹取）: {err}"
        );
    }
    assert_eq!(registered_count_for(owner), 0, "容量非法不得留下任何句柄");

    // 恰等于上限的声明必须放行（off-by-one 的另一侧）
    pty_spawn(ctx.ports(),
        owner,
        &format!(r#"{{"command":"/bin/sh","args":["-c","read go"],"ringBytes":{PLUGIN_PTY_RING_MAX_BYTES}}}"#),
    )
    .expect("等于上限必须放行");
    purge_for_plugin_with_ports(ctx.ports(), owner);
}

/// 背压契约：小环 + 从不拉取的消费者 → 产出持续推进，落后游标得到 truncated 并可续拉
///
/// 「源侧零等待」在环这一维的可观测判据是**产出偏移持续增长**（读线程从不因消费者
/// 停摆；无丢帧属引擎侧，票 01 的 `pty_reader` 用例覆盖）。
#[cfg(target_os = "linux")]
#[test]
fn small_declared_ring_evicts_for_a_never_fetching_consumer_without_stalling_output() {
    let owner = "pty-test.backpressure";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    // 环只 512 字节，进程每 ~1ms 产出一行 → 必然远超容量
    let pty_id = pty_spawn(ctx.ports(), owner, &streaming_config(512)).expect("spawn");
    let ring = ring_of(&pty_id);

    // 消费者全程不拉取，直到产出远超环容量
    wait_until(
        &ring,
        |r| r.watermarks().1 > 8 * 512,
        "产出必须持续增长（源侧未被拖住）",
    );

    // 落后于环起点的游标：得到现存最早段 + truncated + 可续拉游标
    let stale = pty_ring_fetch(ctx.ports(), owner, &pty_id, 0, 4096)
        .expect("ring-fetch")
        .expect("驻留非空");
    assert!(stale.truncated, "产出远超容量，游标 0 必然落后于驻留起点");
    assert!(
        stale.next_offset >= stale.data.len() as u64,
        "载荷与续拉游标自洽: {stale:?}"
    );
    assert!(
        stale.next_offset - stale.data.len() as u64 > 0,
        "返回段必须从产出中段起（此前的字节已淘汰）: {stale:?}"
    );
    assert!(
        stale.data.len() <= PLUGIN_PTY_RING_FETCH_MAX_BYTES as usize,
        "单次返回不得越界拷贝: {}",
        stale.data.len()
    );
    assert!(
        String::from_utf8_lossy(&stale.data).contains("line"),
        "返回的必须是真实输出段"
    );

    // 续拉：游标已在驻留区间内，不再报缺口且必须单调前进
    if let Some(more) =
        pty_ring_fetch(ctx.ports(), owner, &pty_id, stale.next_offset, 4096).expect("续拉")
    {
        assert!(
            !more.truncated,
            "从 next-offset 起续拉不得再报缺口: {more:?}"
        );
        assert!(
            more.next_offset > stale.next_offset,
            "游标必须前进: {more:?}"
        );
    }

    pty_kill(ctx.ports(), owner, &pty_id).expect("kill 清场");
}

/// 单次读上限：`max-bytes` 超宿主值即截断（数据面不报错），按游标可拉全量
#[cfg(target_os = "linux")]
#[test]
fn ring_fetch_is_capped_per_call_and_resumes_to_the_end() {
    let owner = "pty-test.fetch-cap";
    let ctx = TestCtx::new();
    ctx.grant(owner, &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    let pty_id = pty_spawn(ctx.ports(), owner, quiet_cat_config()).expect("spawn");
    let ring = ring_of(&pty_id);
    // 同步点：`stty` 生效后才会打印就绪标记（在此之前写入的载荷会被 tty 驱动回显
    // 一遍并做 `\n → \r\n` 改写，字节级比对就不成立）
    wait_for_output(&ring, STTY_READY);
    let prefix = resident_text(&ring);
    let produced = {
        let guard = ring.lock().unwrap_or_else(|e| e.into_inner());
        guard.watermarks().1
    };
    assert_eq!(
        prefix.len() as u64,
        produced,
        "此刻驻留必须等于全部产出（尚未淘汰）"
    );

    // 40 KiB 一次性写入（低于 64 KiB 准入上限；默认环 256 KiB 容得下，不触发淘汰）
    let payload = line_payload(40 * 1024);
    pty_write(ctx.ports(), owner, &pty_id, &payload).expect("write");
    let expected: Vec<u8> = [prefix.as_bytes(), &payload].concat();
    wait_until(
        &ring,
        |r| r.watermarks().1 >= produced + payload.len() as u64,
        "全部产出必须已入环",
    );

    let mut cursor = 0u64;
    let mut reassembled: Vec<u8> = Vec::new();
    let mut calls = 0usize;
    // `max_bytes: u32::MAX` 即「取宿主允许的一批」，用于验截断常量本身
    while let Some(fetched) =
        pty_ring_fetch(ctx.ports(), owner, &pty_id, cursor, u32::MAX).expect("ring-fetch")
    {
        calls += 1;
        assert!(
            !fetched.truncated,
            "环容量足够，全程不该有缺口（calls={calls}）"
        );
        assert!(
            fetched.data.len() <= PLUGIN_PTY_RING_FETCH_MAX_BYTES as usize,
            "单次拷贝必须被截到上限，got {}",
            fetched.data.len()
        );
        if calls == 1 {
            assert_eq!(
                fetched.data.len(),
                PLUGIN_PTY_RING_FETCH_MAX_BYTES as usize,
                "首批必须**正好**被截到上限（截断生效，而不是整块返回或报错）"
            );
        }
        assert!(fetched.next_offset > cursor, "游标必须前进，否则续拉死循环");
        reassembled.extend_from_slice(&fetched.data);
        cursor = fetched.next_offset;
        assert!(calls < 64, "拉取轮次异常，疑似游标不前进");
    }

    assert_eq!(
        calls,
        expected
            .len()
            .div_ceil(PLUGIN_PTY_RING_FETCH_MAX_BYTES as usize),
        "截断轮次必须等于「总量 / 单次上限」（向上取整）"
    );
    assert_eq!(
        reassembled, expected,
        "逐字节重组必须等于进程全部产出（截断不丢不改序）"
    );

    pty_kill(ctx.ports(), owner, &pty_id).expect("kill 清场");
}

// ==================== spawn → ring-fetch 主干（真 PTY） ====================

/// 正例：spawn 真实命令 → 输出经环形缓冲被 `ring-fetch` 拉到，游标可续
#[cfg(target_os = "linux")]
#[test]
fn spawn_runs_real_command_and_output_reaches_ring_fetch() {
    let marker = unique_tag("RING");
    let pty_id = spawn_ok("pty-test.ring", &alive_with_output(&marker));
    assert!(
        pty_id.starts_with("pty-"),
        "句柄形状应为 pty-<uuid>，got: {pty_id}"
    );
    let output = wait_for_output(&ring_of(&pty_id), &marker);
    assert!(output.contains(&marker), "真 PTY 输出必须落入环: {output}");

    let ctx = TestCtx::new();
    ctx.grant("pty-test.ring", &[PERMISSION_PTY_SPAWN, PERMISSION_PTY_IO]);
    let fetched = pty_ring_fetch(ctx.ports(), "pty-test.ring", &pty_id, 0, 4096)
        .expect("ring-fetch")
        .expect("有产出时不得返回 None");
    assert!(
        String::from_utf8_lossy(&fetched.data).contains(&marker),
        "宿主 ring-fetch 应答里必须有输出: {:?}",
        String::from_utf8_lossy(&fetched.data)
    );
    assert!(!fetched.truncated, "首次全量拉取不存在缺口");
    assert_eq!(fetched.next_offset, fetched.data.len() as u64);
}

/// 正例：二次按 `next_offset` 续拉不重复已消费字节（游标契约）
#[cfg(target_os = "linux")]
#[test]
fn second_fetch_from_next_offset_returns_nothing_new() {
    let marker = unique_tag("CONT");
    let ctx = ctx_with_pty("pty-test.cursor", &alive_with_output(&marker));
    let pty_id = find_handle_of("pty-test.cursor");
    wait_for_output(&ring_of(&pty_id), &marker);

    let first = pty_ring_fetch(ctx.ports(), "pty-test.cursor", &pty_id, 0, 4096)
        .unwrap()
        .expect("首批");
    let second = pty_ring_fetch(
        ctx.ports(),
        "pty-test.cursor",
        &pty_id,
        first.next_offset,
        4096,
    )
    .unwrap();
    assert!(
        second.map(|f| f.data).unwrap_or_default().is_empty(),
        "游标已追平时不得重复投递已消费字节"
    );
}

/// 裁剪线证据：参数数组原样 exec，宿主不做 shell 解释（分号不构成第二条命令）
///
/// 载体用常驻 `sed`（票 04 后短命命令会立刻被摘环）：宿主若做 shell 包装
/// （`sh -c "sed s/^/literal; echo PWNED"`），sed 的参数会被截断为 `s/^/literal;`、
/// `echo PWNED` 另行执行，连续字面量 `literal; echo PWNED` 就不会出现在输出里。
#[cfg(target_os = "linux")]
#[test]
fn spawn_executes_argv_verbatim_without_shell_interpretation() {
    let ctx = ctx_with_pty(
        "pty-test.argv",
        r#"{"command":"/bin/sed","args":["s/^/literal; echo PWNED/"]}"#,
    );
    let pty_id = find_handle_of("pty-test.argv");
    pty_write(ctx.ports(), "pty-test.argv", &pty_id, b"body\n").expect("write");

    let output = wait_for_output(&ring_of(&pty_id), "literal");
    assert!(
        output.contains("literal; echo PWNEDbody"),
        "argv 必须原样 exec: {output}"
    );
    assert!(
        !output.contains("\nPWNED\r\n") && !output.contains("PWNEDbody\nPWNED"),
        "宿主不得做 shell 解析（分号后的 echo 不应被执行）: {output}"
    );
}

/// 引擎参数证据：声明的 env 生效、业务 `WASMNEST_SESSION_ID` 不注入
#[cfg(target_os = "linux")]
#[test]
fn spawn_applies_declared_env_without_business_identity() {
    let owner = "pty-test.env";
    let marker = unique_tag("ENV");
    // 环境隔离：本机若在 WasmNest 会话内跑测试（测试进程 env 自带 WASMNEST_SESSION_ID），
    // 子进程按「继承宿主环境」语义会把它带进 env 输出——断言「不得带业务身份」的
    // 意图是引擎不**注入**该变量，故先把宿主 env 里的同名变量清掉再 spawn（事后恢复）。
    let had_session_id = std::env::var("WASMNEST_SESSION_ID").ok();
    // SAFETY: 单测进程内临时移除环境变量，测试结束恢复；不涉及并发读该变量的线程
    unsafe { std::env::remove_var("WASMNEST_SESSION_ID") };
    let ctx = ctx_with_pty(
        owner,
        &format!(
            r#"{{"command":"/bin/sh","args":["-c","env; read go"],"env":{{"WASMNEST_PTY_TEST":"{marker}"}}}}"#
        ),
    );
    let pty_id = find_handle_of(owner);
    let env_output = wait_for_output(&ring_of(&pty_id), &marker);
    assert!(
        env_output.contains(&format!("WASMNEST_PTY_TEST={marker}")),
        "声明的 env 必须进子进程: {env_output}"
    );
    assert!(
        !env_output.contains("WASMNEST_SESSION_ID"),
        "插件私有 PTY 不得带业务会话身份: {env_output}"
    );
    assert!(
        pty_is_running(ctx.ports(), owner, &pty_id).expect("is-running"),
        "载体进程应仍存活（env 输出后阻塞在 read）"
    );
    // 恢复宿主 env（若有）
    if let Some(v) = had_session_id {
        // SAFETY: 同上，恢复原值
        unsafe { std::env::set_var("WASMNEST_SESSION_ID", v) };
    }
}

/// 引擎参数证据：cols/rows 真的作用到终端尺寸（子进程 `stty size` 反查）
#[cfg(target_os = "linux")]
#[test]
fn spawn_applies_requested_terminal_size() {
    let pty_id = spawn_ok(
        "pty-test.size",
        r#"{"command":"/bin/sh","args":["-c","stty size; read go"],"cols":100,"rows":30}"#,
    );
    let output = wait_for_output(&ring_of(&pty_id), "30 100");
    assert!(
        output.contains("30 100"),
        "stty 报告尺寸应为 rows=30 cols=100，got: {output}"
    );
}

// ==================== 业务线零感知 ====================

/// 正例：插件私有 PTY 只活在引擎注册表（业务线的两条注册表都不存在了）
///
/// 票 11：原断言查的是「业务输出总线有没有它 / 业务会话表有没有它」——这两个对象
/// 随 `session/` 目录删除，**类型层面已不可能被登记**。保留的是这个用例仍然有效的
/// 那一半：句柄确实在引擎注册表里在册、输出确实只落引擎环（`ring_of` / `is_registered`
/// 的正向断言），业务线零感知由「没有业务线」这件事本身保证。
#[cfg(target_os = "linux")]
#[test]
fn spawned_pty_lives_only_in_engine_registry() {
    let marker = unique_tag("ISOLATE");
    let _ctx = ctx_with_pty("pty-test.isolate", &alive_with_output(&marker));
    let pty_id = find_handle_of("pty-test.isolate");
    wait_for_output(&ring_of(&pty_id), &marker);

    assert!(is_registered(&pty_id), "插件私有 PTY 必须在引擎注册表在册");
}

/// 句柄是否仍在册（测试断言副作用用）
#[cfg(target_os = "linux")]
fn is_registered(pty_id: &str) -> bool {
    PTYS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(pty_id)
}

/// 在册句柄归属查询（测试断言副作用用）
fn find_handle_of(plugin_id: &str) -> String {
    PTYS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(_, entry)| entry.owner == plugin_id)
        .map(|(pty_id, _)| pty_id.clone())
        .expect("该插件应有在册 PTY")
}
