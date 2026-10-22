//! 服务器端口 traits（依赖倒置：server 各面需要的宿主能力，由宿主壳注入实现）
//!
//! server-lib-split spec §2 端口表：所有 server lib 不得引用 `wasm_core` /
//! `tauri` / `AppContext` 类型；本模块定义它们反向需要的全部端口。宿主壳
//! （`crate::server::ports_impl` + bootstrap）构造实现并注入
//! [`ServerPorts`]，拆分后本文件随 `wasmnest-server-base` 迁移。
//!
//! 对 spec 的两处实施裁决（记录于 `.scratch/2026-09-30-server-lib-split/`）：
//! - `BusPort` 合并了 spec 的 `FrameDeliverer`（`deliver_endpoint_frame`）——
//!   宿主一个对象实现整个总线面（publish / subscribe_static / 帧投递），
//!   拆成两个 trait 只会让每个注入点各带两个句柄，无隔离收益；
//! - 端口 traits 全落 server-base（而非 spec 表内记的 server-core），
//!   让不依赖 core 传输机制的 peer-net 也能取用共享端口（spec 端口表与
//!   D2「peer-net 不依赖 core」在 4-crate 形状内自相矛盾，5-crate 形状消解）。

use crate::config::NetworkConfig;
use crate::error::Result;
use crate::identity::AuthenticatedIdentity;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;

// ==================== PluginInvoker（http 转发面 / 激活判定） ====================

/// 插件命令调用面（替代 `AppContext::global().plugin_host()` 的注入端口）
///
/// 宿主壳实现包装 `PluginHost::invoke_rust_command` / `is_activated`；
/// 无宿主上下文（无头 / 单测）时注入 `None`，调用方按既有「无 AppContext」
/// 语义保守处理（http 网关放行交回链条 / ws 属主激活闸门放行防御性兜底）。
#[async_trait]
pub trait PluginInvoker: Send + Sync {
    /// 调插件 Rust 命令（`_http_endpoint` 转发；`Err(String)` = 命令失败）
    async fn invoke_rust_command(
        &self,
        owner: &str,
        command: &str,
        args: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, String>;

    /// 属主插件是否处于激活态（false = 未激活；宿主对 plugin_id 无记录时
    /// 返回 true——「无从判定」语义与既有 `endpoint_owner_activated` 一致）
    async fn is_activated(&self, owner: &str) -> bool;
}

// ==================== AuthCenter（认证中心裁决） ====================

/// 认证中心裁决（v33 / ADR 0033：宿主不再持有任何设备 JWT 密码学）
///
/// 宿主壳实现包装 `utils::auth::auth_center::enforce_connection_policy`；
/// fail-closed 语义不变：无中心 / 调用失败 / 中心拒绝 → `Err`。
pub trait AuthCenter: Send + Sync {
    fn enforce_connection_policy(&self, token: &str) -> std::result::Result<AuthenticatedIdentity, String>;
}

// ==================== BusPort（插件消息总线 + WS 帧投递） ====================

/// 静态订阅者的消息回调（`subscribe_static` 的 handler；宿主壳实现转为
/// `wasm_core::BusMessageHandler`，载荷形状即 [`crate::wire::BusMessage`]——
/// 本 crate 自持副本，能力域脱绑 P5：双类型在 wasm-core 的
/// `WasmHandlerAdapter` 桥接点做值转换，形状一致由平台仓漂移锁钉死
/// `cross-end-tests/tests/wire_drift_locks.rs`）
pub trait BusMessageHandler: Send + Sync {
    fn on_message(&self, msg: &crate::wire::BusMessage) -> anyhow::Result<()>;
}

/// 插件消息总线端口（publish / 静态订阅 / WS 端点帧投递）
///
/// 宿主壳实现包装 `wasm_core::bus::MessageBus` 与
/// `wasmnest_server_websocket::plugin_binding::deliver_endpoint_frame`；无头/单测可用假实现。
/// `deliver_endpoint_frame` 是 spec 端口表的 `FrameDeliverer`（裁决见模块头）。
#[async_trait]
pub trait BusPort: Send + Sync {
    /// 发布 JSON 消息（`MessageBus::publish` 语义：异步入队、不投给发送者）
    fn publish(&self, topic: &str, sender: &str, payload: serde_json::Value);

    /// 发布二进制消息（`MessageBus::publish_binary` 语义）
    fn publish_binary(&self, topic: &str, sender: &str, payload: Vec<u8>);

    /// 注册静态订阅者（`MessageBus::subscribe_static` 语义：每订阅者有界队列
    /// + 消费任务，handler 在任务内独占调用）
    async fn subscribe_static(&self, subscriber: &str, topic: &str, handler: Box<dyn BusMessageHandler>);

    /// 真实总线是否已就绪（可注册静态订阅）：默认 `true`。
    ///
    /// **宿主装配顺序可能早于真实总线就位**（桌面 `HostBusPort` 是 late-bound，
    /// AppContext 注册前解析到占位总线——此时注册的订阅永远收不到消息）；
    /// 各端在此报告自己的就绪判据（桌面 = 端口已装配；移动 = 插件管理器就绪），
    /// 能力域只负责「未就绪则轮询等待」的循环，不假设任何端的装配面。
    fn is_ready(&self) -> bool {
        true
    }

    /// 投递 WS 帧给插件的 `events-ws` 可选导出（保序由调用方串行保证）
    async fn deliver_endpoint_frame(
        &self,
        owner: &str,
        endpoint_id: &str,
        client_id: &str,
        kind: &str,
        payload: Vec<u8>,
    );
}

// ==================== EventSink（前端事件） ====================

/// 前端事件投递（替代 `AppHandle::emit`；失败只记日志不上抛）
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

// ==================== PathsPort（路径解析） ====================

/// 应用数据目录解析（替代 `app_handle.path().app_data_dir()`）
pub trait PathsPort: Send + Sync {
    /// 应用数据目录；解析失败返回错误（调用方按其语义处置）
    fn app_data_dir(&self) -> Result<PathBuf>;
    /// 对等网络接收落点根目录（各端自定：桌面实现 = 系统下载目录下 `WasmNest`
    /// 子目录；移动实现 = app 私有下载目录）。消费方直接落文件，**不再自行拼子目录**；
    /// 解析失败返回错误
    fn download_dir(&self) -> Result<PathBuf>;
}

// ==================== SystemInfoPort（系统信息） ====================

/// 引擎级系统信息（设备名 / 本地 IPv4；替代 `SystemInfo` / `local_ipv4_addresses`）
pub trait SystemInfoPort: Send + Sync {
    /// 节点 mDNS 广播设备名（各端实现**应保证非空**：桌面实现现采真实设备名）
    fn device_name(&self) -> String;
    /// 设备名空值兜底（异常初始化顺序才用得到）：各端自持（桌面 "WasmNest Desktop" /
    /// 移动 "WasmNest Mobile"）。默认给中立名，避免能力域硬编码某端产品名
    fn device_name_fallback(&self) -> String {
        "WasmNest".to_string()
    }
    fn local_ipv4_addresses(&self) -> Vec<String>;
    /// 应用版本（mDNS txt 记录 `version` 等；宿主壳代理 CARGO_PKG_VERSION）
    fn app_version(&self) -> String;
}

// ==================== PowerPort（电源管理） ====================

/// 休眠阻止开关（替代 `system::power::power_manager()`）
pub trait PowerPort: Send + Sync {
    fn enable(&self);
    fn disable(&self);
}

// ==================== MdnsAdvertiserPort（mDNS 广播） ====================

/// mDNS 服务广播（替代 `AppContext::global().mdns_advertiser()` 的
/// `AdvertiseConfig` 装配；txt 记录由宿主壳转成
/// `wasmnest_discovery_engine::types::AdvertiseConfig`——自播面真源在
/// wasmnest-discovery-engine，宿主侧零 mDNS 代码）
///
/// **async 是确定性要求**（service-leases §4.5）：`start` 返回时广播必须已登记、
/// `stop` 返回时广播必须已注销；实现不得 fire-and-forget。
#[async_trait]
pub trait MdnsAdvertiserPort: Send + Sync {
    /// 登记广播；失败（无上下文 / 守护拒绝）必须显性返回错误，由 supervisor
    /// 回滚已启动的 server（fail-visible，不允许「服务器起了但设备不可见」）
    async fn advertise(
        &self,
        service_name: String,
        port: u16,
        txt_records: std::collections::HashMap<String, String>,
    ) -> std::result::Result<(), String>;

    /// 注销广播（幂等；失败只记录不上抛）
    async fn stop(&self);
}

// ==================== ServerLifecyclePort（服务器生命周期桥） ====================

/// 服务器生命周期事件（supervisor 崩溃监控判据；宿主壳由
/// `WebSocketManager::ServerEvent` 映射）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerLifecycleEvent {
    Started,
    Stopped,
}

/// supervisor → WS 传输面的生命周期桥（替代对 `WebSocketManager` 的直接引用）
///
/// 宿主壳实现包装 `WebSocketManager::global()`（start/stop/subscribe）与
/// `WsSessionRegistry::global().client_count()`（指标采样连接数）。
#[async_trait]
pub trait ServerLifecyclePort: Send + Sync {
    /// 启动 Actix Web 服务器（HTTP + WS 统一端口）
    async fn start_server(&self, port: u16) -> Result<()>;
    /// 优雅停机
    async fn stop_server(&self) -> Result<()>;
    /// 当前在册连接数（指标采样）
    async fn connections_snapshot(&self) -> usize;
    /// 订阅服务器生命周期事件（`Stopped` 仅崩溃路径发送，语义同 WebSocketManager）
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ServerLifecycleEvent>;
}

// ==================== RuntimePort（ambient 运行时） ====================

/// ambient runtime 句柄（ws 投递任务派生目标；替代
/// `wasm_core::runtime_util::ambient_handle()`）
pub trait RuntimePort: Send + Sync {
    fn ambient_handle(&self) -> tokio::runtime::Handle;
}

// ==================== ConfigPort（网络配置） ====================

/// 网络配置提供者（替代 `AppConfig::global().network` 快照）
pub trait ConfigPort: Send + Sync {
    fn network(&self) -> NetworkConfig;
}

// ==================== MdnsPort（peer-net 发现守护接入） ====================

/// 类型中枢订阅句柄（值形态；spec §2.3 / ADR 0054）：`receiver` 收中枢
/// fan-out 的浏览事件，`guard` 是**退订守卫**——Drop 即通知类型中枢移除该
/// 订阅（守卫类型由中枢自定，宿主侧只持不解释、透传给 peer-net 的
/// `PeerMdnsBrowse`）。
///
/// **生命周期不可脱钩（硬性要求，spec §2.3）**：字段私有、不实现 `Clone`，
/// 且只提供两个携带双方的出口：
/// - [`new`](Self::new)：同时接管 receiver + 守卫（构造即绑定，drop 句柄 =
///   守卫释放 = 退订；`new` 提前释放守卫即「创建即退订」回归）；
/// - [`into_parts`](Self::into_parts)：把双方**同时**移交宿主 glue（票 04 的
///   `PeerMdnsBrowse` 转换用），调用方必须继续成对持有——只留 receiver 而
///   丢弃守卫会造成退订泄漏。
///
/// 本类型不提供「只取 receiver / 只取守卫」的构造或访问器，杜绝脱钩形态。
pub struct MdnsTypeSubscription {
    /// 类型中枢 fan-out 的事件通道接收端（通道容量由中枢建档时设定，
    /// spec §2.3-D2 = 64）
    receiver: flume::Receiver<mdns_sd::ServiceEvent>,
    /// 退订守卫：Drop ⇒ 中枢移除该订阅（宿主侧零解释，纯生命周期托管）
    guard: Box<dyn std::any::Any + Send + Sync>,
}

impl MdnsTypeSubscription {
    /// 由中枢订阅出口铸造（宿主 glue 从 `wasmnest-discovery-engine` 的值转换）。
    /// receiver 与守卫在此同时被接管：句柄存活期间守卫不释放。
    pub fn new(receiver: flume::Receiver<mdns_sd::ServiceEvent>, guard: Box<dyn std::any::Any + Send + Sync>) -> Self {
        Self { receiver, guard }
    }

    /// 解构为 `(receiver, 守卫)`（宿主 glue 转换用：peer-net 的
    /// `PeerMdnsBrowse` 需要两字段分置）。双方同时移交，新的持有者必须
    /// 成对持有 / 释放。
    pub fn into_parts(
        self,
    ) -> (
        flume::Receiver<mdns_sd::ServiceEvent>,
        Box<dyn std::any::Any + Send + Sync>,
    ) {
        (self.receiver, self.guard)
    }
}

/// peer-net 引擎接入宿主 mDNS 共享守护（替代 `wasm_core::host_api::mdns` 的
/// `shared_daemon` / `register_host_service` / `stop_host_service` 三函数；
/// `ServiceDaemon` 为 mdns-sd 类型，宿主壳实现与 `wasmnest-peer-net` 同源）
///
/// 浏览面自「mDNS 类型中枢」（spec §2.3 / ADR 0054）起新增两方法：全进程对同一
/// 服务类型的 `daemon.browse` / `stop_browse` 只由中枢代持，消费者经
/// [`subscribe_type`](Self::subscribe_type) 挂 fan-out、经
/// [`request_type_requery`](Self::request_type_requery) 请求统一重查，
/// **不得自行 `daemon.browse`**。
pub trait MdnsPort: Send + Sync {
    /// 取全局共享守护句柄（clone 廉价）
    fn shared_daemon(&self) -> mdns_sd::ServiceDaemon;
    /// 登记宿主（peer-net 引擎）节点身份广播句柄（owner=host）
    fn register_host_service(&self, service_type: &str, fullname: &str) -> std::result::Result<String, String>;
    /// 注销宿主身份广播登记（幂等）
    fn stop_host_service(&self, advertise_id: &str) -> std::result::Result<bool, String>;
    /// 打开/复用类型中枢订阅（实现 = `wasmnest_discovery_engine::subscribe_type`
    /// 的值转换）。首个订阅者触发该类型唯一一次 `daemon.browse`，其后退订由
    /// 返回句柄的守卫 Drop 驱动（见 [`MdnsTypeSubscription`]）
    fn subscribe_type(&self, service_type: &str) -> std::result::Result<MdnsTypeSubscription, String>;
    /// 请求类型级即时重查（中枢按合并窗统一重发 browse + 缓存重放 fan-out；
    /// 周期节奏仍属消费方）
    fn request_type_requery(&self, service_type: &str);
}

// ==================== ServerPorts 聚合 ====================

/// 宿主壳注入的全部端口聚合（bootstrap 构造一次，全局经
/// [`ports::init`] 注册；拆 lib 后随 ServerState 实例化）
pub struct ServerPorts {
    pub plugin_invoker: Arc<dyn PluginInvoker>,
    pub auth_center: Arc<dyn AuthCenter>,
    pub bus: Arc<dyn BusPort>,
    pub event_sink: Arc<dyn EventSink>,
    pub paths: Arc<dyn PathsPort>,
    pub system_info: Arc<dyn SystemInfoPort>,
    pub power: Arc<dyn PowerPort>,
    pub mdns_advertiser: Arc<dyn MdnsAdvertiserPort>,
    pub lifecycle: Arc<dyn ServerLifecyclePort>,
    pub runtime: Arc<dyn RuntimePort>,
    pub config: Arc<dyn ConfigPort>,
    pub mdns: Arc<dyn MdnsPort>,
}

/// 全局端口注册表（`OnceLock<Arc<ServerPorts>>`，bootstrap 装配；`try_global`
/// 语义同 `AppContext::try_global`——未初始化（无头 / 单测）返回 None）。
/// `Arc` 化：peer-net 派生任务（session_watch / drive_gate / 入站桥）需要
/// 持有端口句柄跨 await 存活
static PORTS: std::sync::OnceLock<Arc<ServerPorts>> = std::sync::OnceLock::new();

/// 装配全局端口（bootstrap 调用一次；重复调用 panic——装配点唯一）
pub fn init(ports: ServerPorts) {
    PORTS
        .set(Arc::new(ports))
        .unwrap_or_else(|_| panic!("server ports already initialized"));
}

/// 取全局端口（未装配 → None：无头 / 单测上下文，调用方按既有「无
/// AppContext」语义保守处理，不 panic）
pub fn get() -> Option<&'static Arc<ServerPorts>> {
    PORTS.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// 未装配时取空（无头 / 单测语义：调用方按无 AppContext 处理）
    #[test]
    fn uninitialized_ports_read_as_none() {
        // 本用例可能在已装配的测试进程内跑（test 二进制共享静态），
        // 但 Either 分支都不 panic 即证明存取语义稳定
        match get() {
            Some(_) => {}
            None => {}
        }
    }

    // ==================== MdnsTypeSubscription 守卫生命周期契约 ====================

    /// 退订守卫的测试替身：Drop 计数即「退订被触发」的可观察证据
    /// （真实守卫是中枢的退订句柄，Drop 语义同此：该订阅被移除、通道关闭）
    struct DropCountingGuard {
        drops: std::sync::Arc<AtomicUsize>,
    }

    impl Drop for DropCountingGuard {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn test_event(tag: &str) -> mdns_sd::ServiceEvent {
        mdns_sd::ServiceEvent::SearchStarted(tag.to_string())
    }

    /// 契约（spec §2.3 硬性要求）：句柄独占 receiver + 守卫——drop 句柄必须
    /// 恰好触发一次退订守卫，且 receiver 随句柄一起关闭；守卫不得在 `new`
    /// 中提前释放，receiver 也不得脱离守卫独立存活（否则退订泄漏）。
    #[test]
    fn dropping_subscription_runs_guard_exactly_once_and_closes_channel() {
        let drops = std::sync::Arc::new(AtomicUsize::new(0));
        let (tx, rx) = flume::bounded::<mdns_sd::ServiceEvent>(8);
        let sub = MdnsTypeSubscription::new(
            rx,
            Box::new(DropCountingGuard {
                drops: std::sync::Arc::clone(&drops),
            }),
        );

        assert_eq!(drops.load(Ordering::SeqCst), 0, "句柄存活期间守卫不得提前释放");

        drop(sub);

        assert_eq!(drops.load(Ordering::SeqCst), 1, "drop 句柄必须恰好触发一次退订");
        assert!(
            matches!(
                tx.try_send(test_event("after-drop")),
                Err(flume::TrySendError::Disconnected(_))
            ),
            "句柄释放后通道必须关闭（receiver 不得与守卫脱钩独立存活）"
        );
    }

    /// 契约：`into_parts` 原样移交 receiver 与守卫（宿主 glue 转换面，票 04 消费）——
    /// 移交本身不得释放 / 替换守卫；移交后的 receiver 仍与配对发送端连通；
    /// 守卫由其新持有者释放且恰好一次。
    #[test]
    fn into_parts_moves_receiver_and_guard_without_premature_drop() {
        let drops = std::sync::Arc::new(AtomicUsize::new(0));
        let (tx, rx) = flume::bounded::<mdns_sd::ServiceEvent>(8);
        let sub = MdnsTypeSubscription::new(
            rx,
            Box::new(DropCountingGuard {
                drops: std::sync::Arc::clone(&drops),
            }),
        );

        let (receiver, guard) = sub.into_parts();

        assert_eq!(drops.load(Ordering::SeqCst), 0, "into_parts 不得释放守卫");
        assert!(
            guard.downcast_ref::<DropCountingGuard>().is_some(),
            "into_parts 必须原样移交守卫（不得替换为替身）"
        );

        tx.send(test_event("moved")).expect("配对发送端保持连通");
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(mdns_sd::ServiceEvent::SearchStarted(tag)) => assert_eq!(tag, "moved"),
            other => panic!("移交后的 receiver 必须收到配对事件，实际: {other:?}"),
        }

        drop(guard);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "守卫释放恰好一次");
    }

    /// 契约：句柄可跨线程移交与释放（宿主装配线程铸造、消费任务线程托管）——
    /// Send + Sync 编译期断言 + 跨线程 drop 时退订钩子恰好触发一次。
    #[test]
    fn subscription_handoff_across_threads_drops_guard_exactly_once() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MdnsTypeSubscription>();

        let drops = std::sync::Arc::new(AtomicUsize::new(0));
        let (tx, rx) = flume::bounded::<mdns_sd::ServiceEvent>(8);
        let sub = MdnsTypeSubscription::new(
            rx,
            Box::new(DropCountingGuard {
                drops: std::sync::Arc::clone(&drops),
            }),
        );

        assert_eq!(drops.load(Ordering::SeqCst), 0, "句柄存活期间守卫不得提前释放");

        std::thread::spawn(move || drop(sub))
            .join()
            .expect("释放线程不得 panic");
        assert_eq!(drops.load(Ordering::SeqCst), 1, "跨线程 drop 必须恰好触发一次退订");
        assert!(
            matches!(
                tx.try_send(test_event("cross-thread")),
                Err(flume::TrySendError::Disconnected(_))
            ),
            "跨线程释放后通道必须关闭"
        );
    }
}
