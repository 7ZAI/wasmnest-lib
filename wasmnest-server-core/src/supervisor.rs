//! Server Supervisor
//!
//! 管理服务器生命周期：启动、停止、重启
//! Actix Web 在主进程内运行，通过 WebSocketManager 委托启动
//! 指标采集直接调用 MetricsCollector + sysinfo，无需 IPC
//! 服务器启动时登记 mDNS 广播，停止时注销（`await` 保证时序确定性）
//!
//! 本结构只回答「怎么起、怎么停」，不自启、不猜何时该跑：生产宿主经
//! `wasmnest_server_base::service::ServiceRegistry` 按应用引用计数调用
//! [`ServerSupervisor::start`] / [`ServerSupervisor::stop`]（见 `service` 模块）。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use wasmnest_server_base::constants::{
    DEFAULT_SERVER_PORT, METRICS_HISTORY_CAPACITY, METRICS_SAMPLING_INTERVAL_SECS, SERVER_RESTART_DELAY_MS,
    SERVICE_NAME_PREFIX, TXT_KEY_DEVICE_NAME, TXT_KEY_PLATFORM, TXT_KEY_VERSION, TXT_VALUE_PLATFORM,
};
use wasmnest_server_base::error::AppError;
use wasmnest_server_base::error::Result;
use wasmnest_server_base::ports::ServerLifecycleEvent;

use super::metrics::{MetricsCollector, ServerMetrics};

/// crash monitor 轮询间隔（毫秒）
///
/// 正常停止时 supervisor 只置取消信号、不发送广播事件，
/// monitor 需周期性唤醒以感知取消信号并退出，避免任务悬挂
const CRASH_MONITOR_POLL_INTERVAL_MS: u64 = 500;

/// 服务器状态
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerStatus {
    Stopped,
    Starting,
    Running,
}

/// 带时间戳的指标（供前端时序图使用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimestampedMetrics {
    pub timestamp_secs: u64,
    pub ws_sent_rate: f64,
    pub ws_recv_rate: f64,
}

/// 服务器状态信息（前端查询用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerStatusInfo {
    pub status: ServerStatus,
    pub port: u16,
    pub local_ips: Vec<String>,
    pub uptime_secs: Option<u64>,
}

/// Supervisor 内部状态
struct SupervisorInner {
    status: ServerStatus,
    metrics: ServerMetrics,
    metrics_history: VecDeque<TimestampedMetrics>,
    port: u16,
    /// 服务器启动时间，用于 uptime 计算
    start_time: Option<std::time::Instant>,
    /// sysinfo 采集器，用于 CPU/内存指标
    sys: Arc<std::sync::Mutex<sysinfo::System>>,
    /// 指标采样任务取消标志
    metrics_task_cancel: Arc<AtomicBool>,
}

/// 服务器管理器（全局单例）
///
/// 委托 WebSocketManager 启动/停止 Actix Web，直接采集指标。
/// 是否该运行由宿主的应用作用域服务租约决定（`service::TRANSPORT_SERVICE_KEY`）；
/// 本类型不自启、不持有「自启动」偏好。
pub struct ServerSupervisor {
    inner: Arc<RwLock<SupervisorInner>>,
}

impl Default for ServerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerSupervisor {
    /// 创建独立实例（测试隔离用；生产代码应使用 [`global`]）
    ///
    /// 全局单例在 lib test binary 内跨模块共享（票据 14/16 规范）：
    /// 需要隔离状态的测试应构造独立实例，避免并行调度下状态污染。
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SupervisorInner {
                status: ServerStatus::Stopped,
                metrics: ServerMetrics::default(),
                metrics_history: VecDeque::with_capacity(METRICS_HISTORY_CAPACITY),
                port: DEFAULT_SERVER_PORT,
                start_time: None,
                sys: Arc::new(std::sync::Mutex::new(sysinfo::System::new())),
                metrics_task_cancel: Arc::new(AtomicBool::new(false)),
            })),
        }
    }

    /// 获取全局单例
    pub fn global() -> &'static Self {
        static INSTANCE: std::sync::LazyLock<ServerSupervisor> = std::sync::LazyLock::new(ServerSupervisor::new);
        &INSTANCE
    }

    /// 初始化配置（只记录端口；启停由服务租约决定）
    pub async fn init_config(&self, port: u16) {
        let mut inner = self.inner.write().await;
        inner.port = port;
    }

    /// 共享同一底层状态的句柄（服务实现持有；状态仍单一）
    pub fn handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// 启动服务器（主进程内 Actix Web；已运行 → 幂等 `Ok`）
    pub async fn start(&self, port: u16) -> Result<()> {
        {
            let inner = self.inner.read().await;
            if inner.status == ServerStatus::Running {
                return Ok(());
            }
            if inner.status == ServerStatus::Starting {
                return Err(AppError::WebSocket("Server already starting".to_string()));
            }
        }

        {
            let mut inner = self.inner.write().await;
            inner.status = ServerStatus::Starting;
            inner.port = port;
        }

        // 委托宿主壳注入的 ServerLifecyclePort 启动 Actix Web（拆 lib 后
        // 宿主壳实现包装 WebSocketManager；server-core 不再引用 ws 面）
        let Some(ports) = wasmnest_server_base::ports::get() else {
            let mut inner = self.inner.write().await;
            inner.status = ServerStatus::Stopped;
            return Err(AppError::WebSocket(
                "server lifecycle port unavailable (no runtime context)".to_string(),
            ));
        };
        match ports.lifecycle.start_server(port).await {
            Ok(()) => {
                // 重置指标采集器，确保 uptime 和计数器从零开始
                MetricsCollector::global().reset();

                let mut inner = self.inner.write().await;
                inner.status = ServerStatus::Running;
                inner.start_time = Some(std::time::Instant::now());

                // 取消旧的指标采样任务（防御性：确保 stop() 遗漏时也能停止）
                inner.metrics_task_cancel.store(true, Ordering::Relaxed);

                // 取消标志供采样任务与 crash monitor 共用
                let cancel_flag = Arc::new(AtomicBool::new(false));
                inner.metrics_task_cancel = cancel_flag.clone();

                // 指标采样按配置总开关启动（network.metrics_enabled，默认关闭；
                // 调试者需在 config.properties 开启后重启服务生效）
                if ports.config.network().metrics_enabled {
                    let inner_arc = self.inner.clone();
                    wasmnest_server_base::error_boundary::spawn_with_error_boundary(
                        "server_metrics_sampling",
                        metrics_sampling_task(inner_arc, cancel_flag.clone()),
                    );
                }

                // 监听 Actix 线程异常退出事件
                // 当 crash monitor 检测到 Actix 线程崩溃时，会发送 ServerLifecycleEvent::Stopped。
                // 正常停止由 supervisor 自身处理状态，不广播事件（宿主壳实现的
                // WebSocketManager::stop 语义），因此 monitor 只需感知取消信号即退出，避免悬挂
                let event_rx = ports.lifecycle.subscribe();
                let inner_for_monitor = self.inner.clone();
                let monitor_cancel = cancel_flag.clone();
                wasmnest_server_base::error_boundary::spawn_with_error_boundary("server_crash_monitor", async move {
                    let mut rx = event_rx;
                    loop {
                        if monitor_cancel.load(Ordering::Relaxed) {
                            tracing::debug!("Server crash monitor cancelled");
                            break;
                        }
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(CRASH_MONITOR_POLL_INTERVAL_MS),
                            rx.recv(),
                        )
                        .await
                        {
                            // 收到 Started 事件（正常启动广播）：忽略，继续监听崩溃
                            Ok(Ok(ServerLifecycleEvent::Started)) => {}
                            // 收到 Stopped 事件（仅崩溃路径发送）→ 判定为崩溃
                            Ok(Ok(ServerLifecycleEvent::Stopped)) => {
                                let mut inner = inner_for_monitor.write().await;
                                // 仅在 Running 状态下处理（避免与正常 stop 冲突）
                                if inner.status == ServerStatus::Running {
                                    tracing::error!("Server crashed unexpectedly, updating supervisor state");
                                    inner.status = ServerStatus::Stopped;
                                    inner.start_time = None;
                                    inner.metrics_task_cancel.store(true, Ordering::Relaxed);
                                }
                                break;
                            }
                            // 广播通道已关闭或事件丢失（lag）：终止监听
                            Ok(Err(_)) => break,
                            // 轮询超时：回到循环开头检查取消信号
                            Err(_) => {}
                        }
                    }
                });

                tracing::info!("Server started on port {} (in-process)", port);

                // 服务器启动后自动阻止系统休眠
                ports.power.enable();

                // 广播登记必须成功：失败 → 回滚 server（不留「起了但对外不可见」的空壳）
                if let Err(error) = start_mdns_advertisement(port).await {
                    tracing::error!(port, error = %error, "mDNS advertisement failed; rolling back server start");
                    {
                        let inner = self.inner.read().await;
                        inner.metrics_task_cancel.store(true, Ordering::Relaxed);
                    }
                    if let Err(stop_error) = ports.lifecycle.stop_server().await {
                        tracing::error!(error = %stop_error, "server rollback after mDNS failure failed");
                    }
                    ports.power.disable();
                    let mut inner = self.inner.write().await;
                    inner.status = ServerStatus::Stopped;
                    inner.start_time = None;
                    return Err(error);
                }

                Ok(())
            }
            Err(e) => {
                let mut inner = self.inner.write().await;
                inner.status = ServerStatus::Stopped;
                tracing::error!(error = %e, port, "Failed to start server");
                Err(e)
            }
        }
    }

    /// 停止服务器（未运行 → 幂等 `Ok`）
    pub async fn stop(&self) -> Result<()> {
        {
            let inner = self.inner.read().await;
            if inner.status != ServerStatus::Running && inner.status != ServerStatus::Starting {
                // 幂等清理：崩溃监控可能已把状态置 Stopped 但广播仍登记——
                // stop 的契约是「返回时未广播」，不只是改状态
                drop(inner);
                stop_mdns_advertisement().await;
                return Ok(());
            }
        }

        // 取消指标采样任务
        {
            let inner = self.inner.read().await;
            inner.metrics_task_cancel.store(true, Ordering::Relaxed);
        }

        // 先置为 Stopped 再执行实际停止：
        // 即便未来有代码路径在停止期间发送 ServerEvent::Stopped，
        // crash monitor 读到非 Running 状态也不会误判为崩溃
        {
            let mut inner = self.inner.write().await;
            inner.status = ServerStatus::Stopped;
        }

        // 委托宿主壳注入的 ServerLifecyclePort 停止 Actix Web
        let Some(ports) = wasmnest_server_base::ports::get() else {
            return Err(AppError::WebSocket(
                "server lifecycle port unavailable (no runtime context)".to_string(),
            ));
        };
        if let Err(e) = ports.lifecycle.stop_server().await {
            // 停止失败：服务器可能仍在运行，恢复 Running 状态供重试
            let mut inner = self.inner.write().await;
            inner.status = ServerStatus::Running;
            return Err(e);
        }

        let mut inner = self.inner.write().await;
        inner.metrics = ServerMetrics::default();
        inner.metrics_history.clear();
        inner.start_time = None;

        // 服务器停止后释放休眠阻止
        if let Some(ports) = wasmnest_server_base::ports::get() {
            ports.power.disable();
        }

        // 服务器停止时自动注销 mDNS 广播（await：返回即已注销）
        stop_mdns_advertisement().await;

        tracing::info!("Server stopped");
        Ok(())
    }

    /// 重启服务器
    pub async fn restart(&self) -> Result<()> {
        let (port, is_running) = {
            let inner = self.inner.read().await;
            (inner.port, inner.status == ServerStatus::Running)
        };
        if is_running {
            self.stop().await?;
            tokio::time::sleep(std::time::Duration::from_millis(SERVER_RESTART_DELAY_MS)).await;
        }
        self.start(port).await
    }

    /// 获取服务器状态信息
    pub async fn get_status_info(&self) -> ServerStatusInfo {
        let inner = self.inner.read().await;
        let local_ips = wasmnest_server_base::ports::get()
            .map(|p| p.system_info.local_ipv4_addresses())
            .unwrap_or_default();
        let uptime_secs = inner.start_time.map(|t| t.elapsed().as_secs());
        ServerStatusInfo {
            status: inner.status.clone(),
            port: inner.port,
            local_ips,
            uptime_secs,
        }
    }

    /// 获取最新指标
    pub async fn get_metrics(&self) -> ServerMetrics {
        self.inner.read().await.metrics.clone()
    }

    /// 获取指标历史
    pub async fn get_metrics_history(&self) -> Vec<TimestampedMetrics> {
        self.inner.read().await.metrics_history.iter().cloned().collect()
    }

    /// 服务器是否运行中
    pub async fn is_running(&self) -> bool {
        self.inner.read().await.status == ServerStatus::Running
    }

    /// 更新端口配置
    pub async fn update_port(&self, port: u16) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.port = port;
        Ok(())
    }
}

/// 采集当前进程的 CPU/内存占用
///
/// sysinfo 首次 refresh_cpu_usage() 只建立基线，需要两次刷新才能得到准确值。
/// 为避免在调用链中 sleep，在采样任务启动时做一次预热刷新，
/// 此处假设预热已完成，直接读取即可。
fn collect_process_metrics(sys: &mut sysinfo::System) -> (f64, u64) {
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let pid = sysinfo::Pid::from(std::process::id() as usize);
    sys.process(pid)
        .map(|proc| (proc.cpu_usage() as f64, proc.memory()))
        .unwrap_or((0.0, 0))
}

/// 指标采样后台任务（每 5 秒采样一次）
///
/// 首次循环做预热刷新（sysinfo 需要两次 refresh 才能获得准确 CPU 值），
/// 第二次循环开始才有有效数据
async fn metrics_sampling_task(inner: Arc<RwLock<SupervisorInner>>, cancel: Arc<AtomicBool>) {
    // 预热：首次 refresh 建立基线
    {
        let inner_guard = inner.read().await;
        let mut sys = inner_guard.sys.lock().unwrap();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
    }

    loop {
        if cancel.load(Ordering::Relaxed) {
            tracing::debug!("Metrics sampling task cancelled");
            break;
        }

        tokio::time::sleep(std::time::Duration::from_secs(METRICS_SAMPLING_INTERVAL_SECS)).await;

        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let inner_guard = inner.read().await;
        let sys_arc = inner_guard.sys.clone();
        drop(inner_guard);

        // 异步获取连接数（宿主壳经 ServerLifecyclePort 代理 WsSessionRegistry）
        let connections = match wasmnest_server_base::ports::get() {
            Some(ports) => ports.lifecycle.connections_snapshot().await,
            None => 0,
        };

        // 同步采集进程 CPU/内存
        let (cpu_percent, memory_bytes) = {
            let mut sys = sys_arc.lock().unwrap();
            collect_process_metrics(&mut sys)
        };

        let collector = MetricsCollector::global();
        let metrics = collector.sample(connections, cpu_percent, memory_bytes);

        let mut inner = inner.write().await;
        let entry = TimestampedMetrics {
            timestamp_secs: metrics.uptime_secs,
            ws_sent_rate: metrics.ws_sent_rate,
            ws_recv_rate: metrics.ws_recv_rate,
        };
        inner.metrics_history.push_back(entry);
        if inner.metrics_history.len() > METRICS_HISTORY_CAPACITY {
            inner.metrics_history.pop_front();
        }
        inner.metrics = metrics;
    }
}

/// 登记 mDNS 广播（经宿主壳注入的 MdnsAdvertiserPort；await = 登记完成）
async fn start_mdns_advertisement(port: u16) -> Result<()> {
    let Some(ports) = wasmnest_server_base::ports::get() else {
        return Err(AppError::WebSocket(
            "mdns advertiser port unavailable (no runtime context)".to_string(),
        ));
    };
    // 设备名取自系统信息端口（宿主壳代理 SystemInfo：用户设置的电脑名），
    // 与 mDNS 实例名保持一致；版本号走端口（拆 lib 后 core 内 CARGO_PKG_VERSION
    // 是 core crate 版本，不是应用版本）
    let device_name = ports.system_info.device_name();
    let app_version = ports.system_info.app_version();
    let service_name = format!("{}{}", SERVICE_NAME_PREFIX, device_name);

    let mut txt_records = std::collections::HashMap::new();
    txt_records.insert(TXT_KEY_PLATFORM.to_string(), TXT_VALUE_PLATFORM.to_string());
    txt_records.insert(TXT_KEY_DEVICE_NAME.to_string(), service_name.clone());
    txt_records.insert(TXT_KEY_VERSION.to_string(), app_version);
    ports
        .mdns_advertiser
        .advertise(service_name, port, txt_records)
        .await
        .map_err(|e| AppError::Internal(format!("mdns advertise failed: {e}")))
}

/// 注销 mDNS 广播（await = 注销完成；失败只记录，不上抛）
async fn stop_mdns_advertisement() {
    if let Some(ports) = wasmnest_server_base::ports::get() {
        ports.mdns_advertiser.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_is_idempotent_when_already_running() {
        let supervisor = ServerSupervisor::new();
        supervisor.inner.write().await.status = ServerStatus::Running;
        supervisor
            .start(12345)
            .await
            .expect("已在 running 的 start 必须幂等成功");
    }

    #[tokio::test]
    async fn stop_is_idempotent_when_not_running() {
        let supervisor = ServerSupervisor::new();
        supervisor.stop().await.expect("未运行时的 stop 必须幂等成功");
    }

    #[tokio::test]
    async fn start_failure_leaves_status_stopped() {
        let supervisor = ServerSupervisor::new();
        let error = supervisor
            .start(12345)
            .await
            .expect_err("无端口装配时 start 必须显性失败");
        assert!(
            error.to_string().contains("server lifecycle port unavailable"),
            "错误必须点名缺少端口，实际: {error}"
        );
        assert_eq!(
            supervisor.get_status_info().await.status,
            ServerStatus::Stopped,
            "start 失败不得残留 Starting/Running 状态"
        );
    }
}
