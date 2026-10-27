//! 异步桥基础设施（core-runtime-util，中立层）
//!
//! WASM host function 是同步的，但宿主能力实现（host-* 原语 / 内核管理面）需要
//! 驱动 async Tokio 代码（数据库、tokio 锁等）。本模块提供同步↔异步桥
//! [`block_on_async`] 及其依赖的 ambient runtime 基础设施（[`ambient_handle`]
//! 与 [`block_on_ambient`]）。
//!
//! **位置纪律（票 01：wasm_core 依赖单向化）**：这三个符号是应用无关的运行时
//! 工具，原定义在 `crate::manager::runtime`，使得 `host_api` 与
//! `security` 只为调桥就反向依赖 manager（见
//! `.scratch/2026-09-24-wasm-core-decouple/spec.md` C2）。归位后本模块**不引用
//! 任何 wasm_core 兄弟模块**，只能被依赖，不得反向依赖
//! （`manager` / `host_api` / `security` 皆可引用本模块）。
//!
//! 语义、重入保护与 ambient runtime 行为逐字保留自 `manager::runtime`——这是
//! CER（actix current_thread 互调自锁 / wasi ambient runtime 共存）的实证产物，
//! 改动前先读下方注释与 `.scratch/2026-09-24-wasm-core-decouple/issues/01`。

// ==================== Async Blocking Helper ====================

thread_local! {
    /// 当前线程是否已处于 block_in_place 让出后的阻塞上下文
    static IN_BLOCK_IN_PLACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 无当前 runtime handle 的线程（spawn_blocking / 纯 std 线程）执行 block_on 时
/// 的全局收益运行时：与 wasmtime-wasi 的 ambient runtime 同策略，供宿主函数在
/// 无 handle 线程上仍可阻塞执行（WASI 预打开模式下插件调用跑在阻塞线程上）
static AMBIENT_RT: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .expect("create ambient tokio runtime")
});

/// 重入标志的 RAII 守卫：作用域退出（含 block_in_place panic 穿透）时复位标志，
/// 避免线程残留 `true` 导致后续调用恒走新线程路径（正确但多一次线程切换）
struct BlockInPlaceGuard;

impl BlockInPlaceGuard {
    /// 进入阻塞上下文：重入时返回 None（调用方改走新线程路径）
    fn enter() -> Option<Self> {
        if IN_BLOCK_IN_PLACE.with(|f| f.get()) {
            return None;
        }
        IN_BLOCK_IN_PLACE.with(|f| f.set(true));
        Some(BlockInPlaceGuard)
    }
}

impl Drop for BlockInPlaceGuard {
    fn drop(&mut self) {
        IN_BLOCK_IN_PLACE.with(|f| f.set(false));
    }
}

thread_local! {
    /// 当前线程是否已处于任意一条异步桥路径（block_in_place 分支 /
    /// AMBIENT_RT.block_on 分支 / 桥内驱动线程）——统一重入检测点（R-04）
    static IN_ASYNC_BRIDGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 桥上下文守卫：进入桥路径时置位，退出（含 panic 穿透）时复位
struct AsyncBridgeGuard;

impl AsyncBridgeGuard {
    fn enter() -> Self {
        debug_assert!(!IN_ASYNC_BRIDGE.with(|f| f.get()), "调用方须先做完重入检查");
        IN_ASYNC_BRIDGE.with(|f| f.set(true));
        Self
    }
}

impl Drop for AsyncBridgeGuard {
    fn drop(&mut self) {
        IN_ASYNC_BRIDGE.with(|f| f.set(false));
    }
}

/// 驱动线程返回处理：透传正常值；原始 panic 载荷原样穿过（R-15）
///
/// `join().expect(...)` 会把驱动线程的 panic 换成新 panic 且丢弃原载荷——
/// guest 侧真实 panic 信息（wasmtime trap 细节）随之丢失，且模块自注释说
/// panic 穿过 WASM 宿主调用会污染 Store；这里保留原载荷让排障看到根因。
fn resume_or_return<T>(result: std::thread::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(payload) => {
            tracing::error!(
                "block_on_async: driver thread panicked, re-raising original panic payload"
            );
            std::panic::resume_unwind(payload);
        }
    }
}

/// 在新线程上经 ambient runtime 驱动 future（R-04 重入路径 / current_thread 分支的共同实现）
///
/// 新线程的 IN_ASYNC_BRIDGE 由守卫置位：该线程驱动期间任何嵌套 block_on_async
/// 都会命中顶层重入检查再开新线程（不 panic、不回到本线程的 runtime 上下文）。
fn run_on_fresh_thread_ambient<F, R>(fut: F) -> R
where
    F: std::future::Future<Output = R> + Send,
    R: Send + 'static,
{
    let result = std::thread::scope(|s| {
        s.spawn(|| {
            let _bridge = AsyncBridgeGuard::enter();
            AMBIENT_RT.block_on(fut)
        })
        .join()
    });
    resume_or_return(result)
}

/// 在同步上下文中执行 async 闭包，兼容多线程和 current_thread 运行时
///
/// WASM host functions 是同步的，但需要调用 async Tokio 代码（数据库、锁等）。
/// 标准做法 `block_in_place(|| block_on(...))` 仅在多线程运行时上可用，
/// Actix Web 的 `actix-rt` 使用 `current_thread` 运行时，会导致 panic。
///
/// 策略：
/// - 多线程运行时：`block_in_place` + `block_on`（不阻塞 worker 线程）
/// - current_thread 运行时或非运行时线程：`std::thread::spawn` + `block_on`（新线程上运行）
///
/// 重入安全：`dispatch_to_wasm` → 插件 on_message → host http_fetch 的调用链会
/// 嵌套调用本函数。嵌套 `block_in_place` 在已让出的线程上会 panic；而嵌套
/// `handle.block_on` 同样 panic——外层 `block_in_place(|| handle.block_on(...))`
/// 的 tokio enter 守卫仍挂在当前线程上（block_in_place 只是把线程让出 worker 池，
/// 守卫不释放），实证见 panic.log 的 wasm_runtime.rs:82 FATAL
/// （"Cannot start a runtime from within a runtime"）。两种 panic 都会穿透污染
/// wasmtime Store、插件永久不可用，故用线程局部标志检测重入，重入时改在
/// **新线程上 block_on**：新线程无 enter 守卫、非 worker，任意 flavor 均合法，
/// 外层线程 join 等待（runtime 其他 worker 推进 IO，无死锁）。
pub fn block_on_async<F, R>(fut: F) -> R
where
    F: std::future::Future<Output = R> + Send,
    R: Send + 'static,
{
    // 统一重入检测（R-04）：本线程已在任一路桥上下文内（block_in_place /
    // AMBIENT_RT.block_on / 桥内驱动线程）又调用本函数时——嵌套 block_in_place
    // 在已让出线程上 panic、嵌套 block_on 触发 enter 守卫 panic（Cannot start a
    // runtime from within a runtime）、非 worker 线程调 block_in_place 同样 panic
    // ——一律改到无上下文的新线程驱动。旧实现只在 block_in_place 分支武装
    // IN_BLOCK_IN_PLACE，无句柄的 ambient 兜底路径可被嵌套进入而漏网。
    if IN_ASYNC_BRIDGE.with(|f| f.get()) {
        return run_on_fresh_thread_ambient(fut);
    }
    match tokio::runtime::Handle::try_current() {
        Err(_) => {
            // 无当前 runtime 上下文（spawn_blocking 阻塞线程 / 纯 std 线程）：
            // 在全局 ambient multi-thread 运行时上阻塞执行。
            // 与 wasmtime-wasi 的 ambient runtime 同策略——这是 WASI 预打开模式的关键：
            // 插件调用被搬到无 handle 线程后，wasi 同步绑定（in_tokio）走其自身 ambient
            // runtime，宿主函数经此 ambient runtime 阻塞执行，两者互不冲突。
            let _bridge = AsyncBridgeGuard::enter();
            AMBIENT_RT.block_on(fut)
        }
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                // guard 持有期间当前线程在 worker 池外阻塞；退出（含 panic）时复位两个标志
                let _guard = BlockInPlaceGuard::enter();
                let _bridge = AsyncBridgeGuard::enter();
                tokio::task::block_in_place(|| handle.block_on(fut))
            }
            _ => {
                // current_thread 运行时（#[tokio::test] / Actix-rt worker）：当前线程
                // 已在 runtime context 内，两条路都走不通：
                // - `handle.block_on`（current_thread 调度器由 owner 线程独占驱动，
                //   本线程即 owner 线程，直接调用必然死锁；跨线程驱动 IO/process
                //   future 同样永久空转——历史死锁：process_kill 测试）；
                // - `AMBIENT_RT.block_on`（本线程）：重入检查 panic
                //   （"Cannot start a runtime from within a runtime"）。
                // 方案：在 scoped 新线程（无 runtime 上下文、支持非 'static future）
                // 上 AMBIENT_RT.block_on。ambient runtime 是 multi_thread + enable_all，
                // IO/process/time 驱动齐全，multi_thread 的 block_on 契约本就允许任意
                // 线程调用（future 在调用线程内执行、spawned 任务进线程池）。
                //
                // ⚠️ 本分支会阻塞调用线程直到 future 完成：**调用方必须是「不驱动
                // future 所依赖资源」的线程**。actix arbiter 是反例——宿主 WS 原语要
                // await arbiter 上的连接 actor，投递任务若在 arbiter 线程上同步等待即
                // 自锁（见 `ambient_handle` 说明）。
                run_on_fresh_thread_ambient(fut)
            }
        },
    }
}

/// 在全局 ambient runtime 上同步阻塞驱动 future（供无 handle 的阻塞线程使用）
///
/// 与 [`block_on_async`] 的 ambient 兜底同 runtime，但**不要求** future/
/// 输出满足 `'static`——仅同步驱动当前 future 并返回结果，不把 future
/// 交给其它执行器接管。`manager::host::call_mutex_blocking` 在
/// `spawn_blocking` 阻塞线程上用它驱动 tokio Mutex 锁获取（借用闭包内 Arc，
/// 无法满足 `'static` 约束）。
///
/// 重入（本线程已在任一路桥内）不可恢复——借用式 future 无法搬去新线程，
/// 直接嵌套 AMBIENT_RT.block_on 会得到 Tokio 难以阅读的
/// "Cannot start a runtime from within a runtime"；这里显式 panic 并点名
/// 约束（R-04）：此类重入是实施错误，不应静默发生。
///
/// 消费方在桌面装配面（`manager/host.rs` 属主路径）：移动形态不消费，
/// wasm-core 单形态共享故保留 + 按形态豁免
#[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
pub(crate) fn block_on_ambient<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
{
    if IN_ASYNC_BRIDGE.with(|f| f.get()) {
        panic!(
            "block_on_ambient called on a thread already inside an async bridge; \
             borrowed futures cannot be moved to a driver thread — this path must not nest"
        );
    }
    let _bridge = AsyncBridgeGuard::enter();
    AMBIENT_RT.block_on(fut)
}

/// ambient runtime 句柄：在「调用方线程不可被占用」的场景派生后台任务
///
/// 典型场景是 **actix arbiter**：它是 `current_thread` 运行时、由本线程独占驱动，
/// 而插件投递用的是同步桥 [`block_on_async`]（会阻塞调用线程）。若投递任务跑在
/// arbiter 上，客人回调里的宿主原语（如 WS 端点的 `send-text-to-client`）需要
/// await arbiter 上的连接 actor —— arbiter 被投递自己占住，双方互等形成自锁
/// （实证：插件端点回显帧）。故此类投递改在 ambient runtime 上派生，arbiter 保持
/// 空闲以推进 actor。
pub fn ambient_handle() -> tokio::runtime::Handle {
    AMBIENT_RT.handle().clone()
}

// ==================== Error Boundary（移动装配面，fork 迁入，票 06 批次 03） ====================
//
// WS 读写任务 / 重连任务在 crate 侧 spawn 的 panic 防护（宿主 system/error_boundary.rs
// 同形状副本；桌面侧消费面在宿主 src-tauri，本 crate 桌面分支不含）。

// block_on_ambient / ambient_handle 双端同名同形（root 既有段已提供，fork 段不重复——
// 票 06 批次 03 迁入时去重；见上方 root 段的同名函数）

// ==================== Error Boundary（宿主 system/error_boundary.rs 同形状副本） ====================
//
// 票 17 批次 2：WS 读写任务 / 重连任务迁入 crate 后在 crate 侧 spawn，需要
// 同款 panic 防护。宿主保留原文件（宿主引擎面多处消费），双份形状由
// fork_boundary_lock 的机制核在场断言钉住；票 19 抽共享核时随机制一并上提。
//
// 常编译（单形态票 02 M5）：错误边界是双端共用的公共设施——桌面包容 WS
// 连接任务、移动壳的 WS 读写 / 重连任务都在 crate 侧 spawn 后台任务——形态
// feature（`common-host` / `bare-host`）已随单形态收口（2026-10-13）退役，
// 本段不再有任何门控。block_on_ambient / ambient_handle（root 常编译段）供
// 同步上下文驱动借用式 future，此处三个符号供 spawn 后盾。

/// 使用错误边界包装 tokio::spawn（当前线程必须有 runtime 上下文）
///
/// 捕获 spawned 任务中的 panic 并记录日志，防止任务静默终止。
pub fn spawn_with_error_boundary<F>(
    task_name: &'static str,
    future: F,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(wrap_with_error_boundary(task_name, future))
}

/// 带显式运行时句柄的错误边界 spawn
///
/// 与 [`spawn_with_error_boundary`] 同一防护，但提交目标由调用方指定：
/// 调用线程可能**没有**当前 runtime 上下文（spawn_blocking / 纯 std 线程上的
/// host fn），此时裸 `tokio::spawn` 直接 panic——句柄版在任意线程均合法。
pub fn spawn_with_error_boundary_on<F>(
    handle: &tokio::runtime::Handle,
    task_name: &'static str,
    future: F,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    handle.spawn(wrap_with_error_boundary(task_name, future))
}

/// 防护包装（共用内部：panic → error! 日志，任务自身吞掉不外泄）
async fn wrap_with_error_boundary<F>(task_name: &'static str, future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let result = std::panic::AssertUnwindSafe(future).catch_unwind().await;

    if let Err(panic_err) = result {
        let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_err.downcast_ref::<String>().cloned() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        tracing::error!(
            target: "error_boundary",
            task = %task_name,
            error = %msg,
            "Task panicked and was caught by error boundary",
        );
    }
}

use futures_util::FutureExt;
