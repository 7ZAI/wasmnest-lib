//! WebSocket Manager
//!
//! 单例模式的服务器管理器
//! 使用 Actix Web 提供 HTTP REST API + WebSocket 终端
//! 连接跟踪和按端点消息转发通过 WsSessionRegistry 实现
//!
//! 终态（websocket 业务下沉票 08）：宿主业务 `Message` 发送/广播 API 已随
//! `/ws/event` 与 `/ws/terminal/session/{id}` 删除——本类只负责服务器生命周期
//! （启动 / 优雅停机 / 事件订阅）与连接事实清单（`list_clients` / `client_count`，
//! 供 host-connection 原语与停机守卫使用）。插件的帧收发走
//! `host-websocket` 原语直连 `WsSessionRegistry`，不经本类。
//!
//! 服务依赖全部经 `wasmnest_server_base::ports::get()` 取宿主壳注入的端口实现，本面不存储它们

use crate::registry::{ClientSummary, WsSessionRegistry};
use wasmnest_server_base::constants::WS_EVENT_BROADCAST_CAPACITY;
use wasmnest_server_base::error::AppError;
use wasmnest_server_base::error::Result;
use wasmnest_server_core::TransportFace;
use std::sync::Arc;
use tokio::sync::RwLock;

/// WebSocket 管理器内部状态
struct WsManagerInner {
    /// 服务器端口
    port: RwLock<Option<u16>>,
    /// 是否已初始化
    initialized: RwLock<bool>,
    /// Actix Web 服务器句柄，用于优雅停机
    server_handle: RwLock<Option<actix_web::dev::ServerHandle>>,
    /// 服务器事件广播发送器
    event_tx: tokio::sync::broadcast::Sender<ServerEvent>,
}

impl WsManagerInner {
    fn new() -> Self {
        let (event_tx, _) = tokio::sync::broadcast::channel(WS_EVENT_BROADCAST_CAPACITY);
        Self {
            port: RwLock::new(None),
            initialized: RwLock::new(false),
            server_handle: RwLock::new(None),
            event_tx,
        }
    }
}

/// WebSocket 管理器（单例）
pub struct WebSocketManager {
    inner: Arc<WsManagerInner>,
}

impl WebSocketManager {
    pub fn global() -> &'static Self {
        static INSTANCE: std::sync::LazyLock<WebSocketManager> = std::sync::LazyLock::new(|| WebSocketManager {
            inner: Arc::new(WsManagerInner::new()),
        });
        &INSTANCE
    }

    /// 初始化
    pub async fn init(&self) -> Result<()> {
        let mut initialized = self.inner.initialized.write().await;
        if *initialized {
            tracing::warn!("WebSocketManager already initialized");
            return Ok(());
        }
        *initialized = true;

        tracing::info!("WebSocketManager initialized");
        Ok(())
    }

    /// 启动 Actix Web 服务器（HTTP + WS 统一端口）
    ///
    /// 在独立线程中启动 Actix runtime，返回 `ServerHandle` 供调用方保存用于优雅停机
    ///
    /// `faces` 由宿主组合根装配并传入（HTTP 面 + 本面的路由与中间件）：本面不认识
    /// HTTP 面，装配委托 [`wasmnest_server_core::app::serve`]（I1 靠调用方注入而非引用）
    pub async fn start(&self, port: u16, faces: Vec<Arc<dyn TransportFace>>) -> Result<actix_web::dev::ServerHandle> {
        {
            let initialized = self.inner.initialized.read().await;
            if !*initialized {
                return Err(AppError::WebSocket(
                    "WebSocketManager not initialized, call init() first".to_string(),
                ));
            }
        }

        {
            let port_lock = self.inner.port.read().await;
            if port_lock.is_some() {
                return Err(AppError::WebSocket("Server already running".to_string()));
            }
        }

        // 使用 oneshot 通道从 Actix 线程传回 ServerHandle
        let (handle_tx, handle_rx) = tokio::sync::oneshot::channel::<std::io::Result<actix_web::dev::ServerHandle>>();

        // 使用 oneshot 通道检测 Actix 线程是否异常退出
        // Ok(true) = 异常退出, Ok(false) = 正常退出, Err = 通道关闭（视为异常）
        let (crash_tx, crash_rx) = tokio::sync::oneshot::channel::<bool>();

        // 读取网络配置传入 Actix 线程（宿主壳经 ConfigPort 注入，拆 lib 后
        // ws 面不反向引用宿主 AppConfig）
        let net_config = match wasmnest_server_base::ports::get() {
            Some(ports) => ports.config.network(),
            None => wasmnest_server_base::config::NetworkConfig::default(),
        };

        // 在独立线程中启动 Actix runtime
        // actix-web-actors 的 WS actor 需要 actix system context，不能直接在 tokio runtime 上运行
        std::thread::spawn(move || {
            let rt = actix_rt::Runtime::new().expect("Failed to create Actix runtime");
            rt.block_on(async move {
                let result = wasmnest_server_core::app::serve(port, &net_config, faces).await;
                match result {
                    Ok((handle, server)) => {
                        // 先发送 handle，让调用方可以开始使用服务器
                        let _ = handle_tx.send(Ok(handle));
                        // 然后等待 server 运行，block_on 在 server 停止前不会退出
                        let _ = server.await;
                        // 正常退出
                        let _ = crash_tx.send(false);
                    }
                    Err(e) => {
                        let _ = handle_tx.send(Err(e));
                        let _ = crash_tx.send(true);
                    }
                }
            });
        });

        // 等待 Actix 服务器启动并获取 handle
        let handle = handle_rx
            .await
            .map_err(|_| AppError::WebSocket("Actix server task panicked before returning handle".to_string()))?
            .map_err(|e| AppError::WebSocket(format!("Failed to start Actix server: {}", e)))?;

        {
            let mut port_lock = self.inner.port.write().await;
            *port_lock = Some(port);
        }

        {
            let mut handle_lock = self.inner.server_handle.write().await;
            *handle_lock = Some(handle.clone());
        }

        tracing::info!("Actix Web server (HTTP + WS) started on port {}", port);

        // 启动 Actix 线程退出监控
        // 如果 Actix 线程异常退出（崩溃），自动清理状态并通知 supervisor
        let inner = self.inner.clone();
        let event_tx = self.inner.event_tx.clone();
        wasmnest_server_base::error_boundary::spawn_with_error_boundary("actix_crash_monitor", async move {
            let crashed = crash_rx.await.unwrap_or(true);
            if crashed {
                tracing::error!("Actix server thread exited unexpectedly, cleaning up state");
                {
                    let mut port_lock = inner.port.write().await;
                    *port_lock = None;
                }
                {
                    let mut handle_lock = inner.server_handle.write().await;
                    *handle_lock = None;
                }
                let _ = event_tx.send(ServerEvent::Stopped);
            }
        });

        // 广播服务器启动事件
        let _ = self.inner.event_tx.send(ServerEvent::Started);

        Ok(handle)
    }

    /// 停止服务器
    ///
    /// 调用 `ServerHandle::stop(true)` 优雅停机，等待所有 WS actor 的 stopping() 回调完成
    /// actor stopping() 中已负责 unregister，此处仅做防御性清理残留
    pub async fn stop(&self) -> Result<()> {
        // 插件端点客户端：优雅停机前统一下发 Close(1001)（spec §4.5 停机关闭码）。
        // 此刻 actor 仍在运行 → 消息送达 → 通道层照常上报 client-disconnect
        // （「恰好一次」的停机路径），随后 stop(true) 等待其 stopping() 收尾
        let registry = WsSessionRegistry::global();
        let closed = registry
            .disconnect_all_endpoint_clients(1001, "server shutting down")
            .await;
        if closed > 0 {
            tracing::info!(
                clients = closed,
                "plugin endpoint clients notified before server shutdown"
            );
        }

        // 优雅停机 — stop(true) 会等待所有连接关闭，actor stopping() 在此期间完成
        {
            let mut handle_lock = self.inner.server_handle.write().await;
            if let Some(handle) = handle_lock.take() {
                handle.stop(true).await;
                tracing::info!("Actix Web server stopped via ServerHandle");
            }
        }

        // 防御性清理：actor stopping() 应已清理，此处处理异常残留
        let clients = registry.list_clients().await;
        if !clients.is_empty() {
            tracing::warn!(
                "[WebSocketManager] {} orphaned clients found after server stop, cleaning up",
                clients.len()
            );
            registry.clear_all().await;
        }

        {
            let mut port_lock = self.inner.port.write().await;
            *port_lock = None;
        }

        // 正常停止不广播 ServerEvent::Stopped：该事件仅由 Actix 线程异常退出 monitor 发送
        // （语义为"崩溃"），supervisor 的 crash monitor 依赖此区分正常停止与崩溃；
        // 正常停止的状态更新由调用方（ServerSupervisor::stop）自行处理

        tracing::info!("WebSocketManager stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        self.inner.port.read().await.is_some()
    }

    pub fn port(&self) -> Option<u16> {
        *self.inner.port.blocking_read()
    }

    // ==================== Client Facts（连接注册表原始连接事实） ====================

    /// 获取所有已连接客户端摘要（host-connection 原语的宿主入口）
    pub async fn list_clients(&self) -> Vec<ClientSummary> {
        WsSessionRegistry::global().list_clients().await
    }

    /// 获取客户端数量（关窗守卫 / 诊断）
    pub async fn client_count(&self) -> usize {
        WsSessionRegistry::global().client_count().await
    }

    // ==================== Event Subscription ====================

    /// 订阅服务器事件
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ServerEvent> {
        self.inner.event_tx.subscribe()
    }
}

/// 服务器事件（server-lib-split：真源统一为 `base::ports::ServerLifecycleEvent`，
/// 与 supervisor 端口订阅同一类型，宿主壳 ServerLifecyclePort 无需映射）
pub use wasmnest_server_base::ports::ServerLifecycleEvent as ServerEvent;
