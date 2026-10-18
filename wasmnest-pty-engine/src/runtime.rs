//! 引擎侧异步桥（wasm-core 纯净性收口票 02：移除对 tauri runtime 的依赖）
//!
//! 原 `pty_reader.rs` 的消费任务用 `tauri::async_runtime::spawn` 启动——那是宿主
//! runtime。引擎 crate 不依赖 tauri（否则「可复用 PTY 引擎」被迫背上整个宿主
//! 框架），故本模块提供一个 **ambient runtime 薄壳**：调用方在 tokio 上下文中时
//! 直接用当前 handle；不在（纯 std 线程）时落全局收益 runtime。语义与
//! wasm_core::runtime_util 的 ambient runtime 同构（同源模式，非复制代码——本
//! 模块只有 ~30 行，为引擎可独立发布刻意自持）。

use std::future::Future;

/// 无当前 runtime 线程的全局收益运行时（多线程，与 tokio 默认一致）
static AMBIENT_RT: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()
        .expect("create pty-engine ambient tokio runtime")
});

/// 在可用 runtime 上 spawn：优先当前线程 handle，兜底 ambient
///
/// 与 `tauri::async_runtime::spawn` 的语义对齐（调用方无需关心自己在不在
/// runtime 上下文），但引擎不带 tauri 依赖。
pub(crate) fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.spawn(future),
        Err(_) => AMBIENT_RT.spawn(future),
    }
}