//! Error Boundary
//!
//! 为 tokio::spawn 提供 panic 防护，防止后台任务静默崩溃。
//! 所有重要的后台任务都应使用 spawn_with_error_boundary 启动。

use futures_util::FutureExt;
use std::future::Future;

/// 使用错误边界包装 tokio::spawn
///
/// 捕获 spawned 任务中的 panic 并记录日志，防止任务静默终止。
///
/// # Example
///
/// ```ignore
/// spawn_with_error_boundary("connection_monitor", async move {
///     // ... 可能 panic 的任务逻辑 ...
/// });
/// ```
pub fn spawn_with_error_boundary<F>(task_name: &'static str, future: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(error_guarded(task_name, future))
}

/// 同 [`spawn_with_error_boundary`]，但在**指定运行时句柄**上派生任务
///
/// 用于「调用方线程不能被占用」的场景：actix arbiter 是 `current_thread` 运行时
/// 且由本线程独占驱动，若把「需要 arbiter 自身推进 actor」的任务派生回 arbiter，
/// 该线程同步等待任务完成即自锁（实证：插件 WS 端点回显帧）。
pub fn spawn_with_error_boundary_on<F>(
    handle: &tokio::runtime::Handle,
    task_name: &'static str,
    future: F,
) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    handle.spawn(error_guarded(task_name, future))
}

/// 使用错误边界包装 std OS 线程启动（v20 host-task 线程池 / 其他纯 std 后台线）
///
/// 等价语义：线程体 panic 被捕获并记录（与 tokio 变体同款 error_guarded），
/// 不静默崩溃；返回的 `std::thread::JoinHandle` 由调用方决定是否 join。
pub fn spawn_os_thread(task_name: &'static str, body: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(task_name.to_string())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            if let Err(panic_err) = result {
                let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                tracing::error!(
                    target: "error_boundary",
                    task = %task_name,
                    error = %msg,
                    "OS thread panicked and was caught by error boundary",
                );
            }
        })
        .expect("failed to spawn OS thread with error boundary")
}

/// 错误边界包装体：panic 被捕获并记录，任务不静默崩溃
async fn error_guarded<F>(task_name: &'static str, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let result = std::panic::AssertUnwindSafe(future).catch_unwind().await;

    if let Err(panic_err) = result {
        let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_err.downcast_ref::<String>() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;

    /// 全局 subscriber 是进程级单例且 `set_global_default` 只能成功一次：
    /// 所有 capture_log 测试共享一个静态 buffer + 一次性全局安装，
    /// 锁内串行执行并逐个清空/断言（worker 线程日志只能经全局捕获）。
    static LOG_CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static LOG_BUF: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

    struct StaticBufWriter;
    impl std::io::Write for StaticBufWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            LOG_BUF.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct StaticMaker;
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for StaticMaker {
        type Writer = StaticBufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            StaticBufWriter
        }
    }

    /// 进程内只安装一次全局捕获 subscriber；重复调用静默跳过
    fn ensure_global_capture() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(StaticMaker)
                        .with_ansi(false)
                        .with_target(true),
                ),
            );
        });
    }

    /// 清空 buffer、执行闭包、返回捕获日志（调用方必须先持 LOG_CAPTURE_LOCK）
    fn capture_log<F: FnOnce()>(f: F) -> String {
        ensure_global_capture();
        LOG_BUF.lock().unwrap().clear();
        f();
        String::from_utf8_lossy(&LOG_BUF.lock().unwrap()).to_string()
    }

    /// 执行一个带串行锁 + 捕获的测试场景
    fn run_captured<F: FnOnce() -> String>(scenario: F) -> String {
        let _guard = LOG_CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        scenario()
    }

    /// 核心契约：panic 被捕获、任务不终止进程、错误日志输出（票据 27）
    #[test]
    fn panic_is_caught_and_logged() {
        let out = run_captured(|| {
            capture_log(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let handle = spawn_with_error_boundary("task-a", async {
                        panic!("boom");
                    });
                    handle.await.unwrap(); // 边界内 panic 不会传播到 JoinHandle
                });
            })
        });
        assert!(out.contains("Task panicked and was caught"), "应有错误日志: {out}");
        assert!(out.contains("boom"), "panic 消息应被记录: {out}");
        assert!(out.contains("task-a"), "任务名应被记录: {out}");
    }

    #[test]
    fn normal_future_completes_without_log() {
        let done = Arc::new(AtomicUsize::new(0));
        let done2 = Arc::clone(&done);
        let out = run_captured(move || {
            capture_log(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    let handle = spawn_with_error_boundary("task-ok", async move {
                        done2.fetch_add(1, Ordering::SeqCst);
                    });
                    handle.await.unwrap();
                });
            })
        });
        assert_eq!(done.load(Ordering::SeqCst), 1, "正常任务应完成");
        assert!(!out.contains("panicked"), "正常任务不应有错误日志: {out}");
    }

    /// panic 消息为 &str 字面量
    #[test]
    fn panic_message_as_str_literal_is_captured() {
        let out = run_captured(|| {
            capture_log(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let handle = spawn_with_error_boundary("task-str", async {
                        panic!("str-message");
                    });
                    handle.await.unwrap();
                });
            })
        });
        assert!(out.contains("str-message"), "&str panic 消息应被捕获: {out}");
    }

    /// panic 消息为 String（`panic!(format!(...))` / `panic!(String)`）
    #[test]
    fn panic_message_as_string_is_captured() {
        let out = run_captured(|| {
            capture_log(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let handle = spawn_with_error_boundary("task-string", async {
                        let msg = String::from("owned-string-message");
                        panic!("{msg}");
                    });
                    handle.await.unwrap();
                });
            })
        });
        assert!(out.contains("owned-string-message"), "String panic 消息应被捕获: {out}");
    }

    /// 非字符串 panic（如 panic_any(42)）→ Unknown panic 回退
    #[test]
    fn non_string_panic_falls_back_to_unknown() {
        let out = run_captured(|| {
            capture_log(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let handle = spawn_with_error_boundary("task-num", async {
                        std::panic::panic_any(42u32); // 非字符串 payload → Unknown panic
                    });
                    handle.await.unwrap();
                });
            })
        });
        assert!(out.contains("Unknown panic"), "非字符串 panic 应回退 Unknown: {out}");
    }
}
