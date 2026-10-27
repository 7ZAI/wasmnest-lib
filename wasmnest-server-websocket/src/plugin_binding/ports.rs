//! host-websocket 能力域的宿主端口（边界层）
//!
//! ## 设计依据（`wasmnest-server-base::ports` 先例，票 03 已在 mdns 域跑通）
//!
//! 消费方（本 crate）声明端口，宿主实现。本 crate **不依赖 tauri、不依赖宿主
//! bin crate**，故该域的机制面（连接表 / 帧协议 / 端点表 / 权限门位置）自持，
//! 只把「宿主才有的五件事」经端口要过来。
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | [`WsPorts::check_permission`] | 权限门（`ws:client` / `ws:server`）是**宿主安全闸门**（AGENTS §5.1.3 四类薄壳之二），不该可插拔 ⇒ 留宿主，本域只问结果（拒绝文案与 warn 落宿主侧） |
//! | [`WsPorts::publish`] | 向**已拼好的完整 topic** 投递状态事件；总线订阅方隔离在宿主侧（`owned_topic` 是 SDK 纯函数，留在能力域） |
//! | [`WsPorts::bus_port`] | 入站端点登记要挂一个总线端口（帧从已接连接回灌插件）；端口对象本身由宿主造 |
//! | [`WsPorts::dispatch_frame`] | `events-ws` 可选导出投递：目标在插件实例里（`PluginHost` 实现），本域只能要结果 |
//! | [`WsPorts::block_on_any`] | 同步↔异步桥：宿主 host function 是同步的，能力域要驱动 async 注册表 / 握手。**桥的实现在宿主**（含 wasmtime-wasi ambient runtime 与 actix `current_thread` 自锁规避，见宿主 `runtime_util` 模块头），本域不复制第二份 |
//!
//! ## 为什么本域函数收 `&Arc<dyn WsPorts>` 而不是 `&dyn WsPorts`
//!
//! 出站连接的读任务要活到连接关闭之后，需要一份 `'static` 端口引用
//! （与迁移前「读任务持有 `Arc<MessageBus>`」同款）。收引用（而不是裸
//! `&dyn`）让「长期持有」这件事显式化，且省掉一次 `Arc` 克隆。
//!
//! ## 为什么 `block_on_any` 用类型擦除
//!
//! 端口 trait 必须 **dyn 兼容**（`Arc<dyn WsPorts>` 存进进程级单例），而
//! `async fn`/泛型方法都会破坏 dyn 兼容。故入参出参都擦除成
//! `Box<dyn Any + Send>`，由本模块的泛型助手 [`block_on`] 还原成强类型返回值。

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use wasmnest_server_base::ports::BusPort;

/// 类型擦除的「同步驱动异步」入参（[`WsPorts::block_on_any`]）
pub type BoxedBlocked = Pin<Box<dyn Future<Output = Box<dyn Any + Send>> + Send>>;

/// 帧投递目标（客户端域句柄 / 服务端域「端点 + 对端」）
#[derive(Debug, Clone, Copy)]
pub enum WsFrameTarget<'a> {
    /// 客户端域：出站连接句柄
    Client(&'a str),
    /// 服务端域：入站端点句柄 + 对端 client-id
    EndpointClient { endpoint_id: &'a str, client_id: &'a str },
}

impl WsFrameTarget<'_> {
    /// 日志 / 丢弃计数的目标标识（服务端域 = `<endpoint_id>/<client_id>`）
    pub fn label(&self) -> String {
        match self {
            WsFrameTarget::Client(handle) => (*handle).to_string(),
            WsFrameTarget::EndpointClient { endpoint_id, client_id } => format!("{endpoint_id}/{client_id}"),
        }
    }
}

/// 帧投递结果（与宿主 dispatcher 的三态一一对应）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameDispatch {
    /// 已投递给插件的 `events-ws` 导出
    Delivered,
    /// 插件未导出该接口（按 spec §2.2 降级：丢弃 + 首次 warn + 计数）
    NotExported,
    /// 宿主尚未注入投递器（无头 / 两阶段初始化中间态）：不计数不 panic
    Unavailable,
    /// 投递失败（trap / 实例不可用）：宿主已统一记录并触发重载
    Failed(String),
}

/// 宿主能力端口
///
/// 实现方是各端宿主的适配器（桌面端见 `宿主 adapter（src-tauri/src/plugin/ws.rs）的 HostWsPorts`）。
/// 实现应尽量轻——出站读任务会长期持有一份 `'static` 端口。
pub trait WsPorts: Send + Sync + 'static {
    /// 权限判定（`ws:client` / `ws:server`）
    ///
    /// 返回 `false` 时**宿主侧**必须已按 AGENTS §8 落 `warn`（结构化字段
    /// `plugin_id` / `permission` / `api`）；本域不重复落日志。宿主侧也拿不到
    /// 权限管理器时（无头 / 测试）**必须返回 false**（fail-safe，与既有
    /// `host_api::check_permission` 同向）。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 向**已拼好的完整 topic** 投递状态事件（发送者恒为 `"host"`）
    ///
    /// topic 由本域用 SDK 的 `owned_topic(owner, event)` 拼好（含 `<owner::>`
    /// 前缀与命名空间仲裁所需的 owner）——纯字符串逻辑，留在能力域侧；宿主只负责
    /// 往这个 topic 上发并做订阅方隔离。
    fn publish(&self, topic: &str, payload: serde_json::Value);

    /// 入站端点登记要挂的总线端口（`Arc<dyn BusPort>`）
    ///
    /// 宿主造（它才持有 `MessageBus`）。端点通道的回灌任务据此把入站帧投给插件。
    fn bus_port(&self) -> Arc<dyn BusPort>;

    /// 投递一帧到插件的 `events-ws` 可选导出
    ///
    /// `Ok(false)` 语义在 [`FrameDispatch::NotExported`]，宿主侧不记日志——降级
    /// 的 warn 与计数由本域统一落（避免每帧多一条宿主日志）。
    fn dispatch_frame(&self, plugin_id: &str, target: WsFrameTarget<'_>, kind: &str, payload: Vec<u8>)
        -> FrameDispatch;

    /// 在宿主运行时上**同步驱动**一段异步计算（WASM host function 是同步的）
    ///
    /// 实现即宿主的 `runtime_util::block_on_async`：多线程运行时走
    /// `block_in_place`、current_thread / 无句柄线程走新线程 ambient 兜底。
    /// **必须复用宿主那份实现**，不得在本域复制第二份桥（重入自锁与 ambient
    /// runtime 语义是实测产物）。
    fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send>;
}

// ==================== 泛型助手 ====================

/// 强类型版同步驱动（端口方法的包装：擦除入参 → 驱动 → 还原类型）
///
/// 收 `&Arc<dyn WsPorts>`（与本域域函数同一口径）——`Arc` 借用即可解引用成
/// `&dyn WsPorts`，不需要克隆。
///
/// 类型不符是**装配期编程错误**（调用方传错了 future 的输出类型），直接 panic
/// 点名，不静默返回 `None` 之类的假值。
pub fn block_on<T: Send + 'static>(ports: &Arc<dyn WsPorts>, fut: impl Future<Output = T> + Send + 'static) -> T {
    let erased: BoxedBlocked = Box::pin(async move { Box::new(fut.await) as Box<dyn Any + Send> });
    match ports.block_on_any(erased).downcast::<T>() {
        Ok(value) => *value,
        Err(_) => panic!(
            "ws ports block_on_any returned an unexpected result type (expected {})",
            std::any::type_name::<T>()
        ),
    }
}

// ==================== 端口装配（进程级单例） ====================

/// 进程级端口持有者
///
/// **为什么是全局**：`impl Host for WasmPluginState` 住在本 crate（它用本 crate
/// 的 `bindgen!` 生成的 `Host` trait），而**端口的具体实现属于宿主**，crate 之间
/// 无从互相指名——故用「宿主开机装一次、之后经本函数取」的单向装配，方向单一。
/// 与 mdns 域（`wasmnest_discovery_engine::ports`）同款。
static PORTS: std::sync::OnceLock<Arc<dyn WsPorts>> = std::sync::OnceLock::new();

/// 装配宿主端口实现（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
///
/// 重复装配必须被忽略而不是替换：运行期换掉端口实现会让已建立的出站读任务继续
/// 持旧端口，属难以归因的不一致。首次装配者胜出。
pub fn install_ports(ports: Arc<dyn WsPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的宿主端口
///
/// # Panics
/// 尚未装配时 panic 并点名——**fail-visible**：让一个未接宿主的能力域以
/// 「跑起来但什么都做不了」的面貌存在，比启动即炸难诊断得多。
pub fn ports() -> Arc<dyn WsPorts> {
    PORTS
        .get()
        .cloned()
        .expect("websocket plugin binding ports are not installed — the host must call `install_ports` during boot")
}
