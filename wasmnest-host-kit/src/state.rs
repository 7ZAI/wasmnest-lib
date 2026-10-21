//! 插件实例状态（机制面）：`Store<WasmPluginState>` 的数据体
//!
//! ## 归属说明
//!
//! 本类型住在 `wasmnest-host-kit` 而非宿主 bin crate，**不是风格选择而是结构必需**：
//! `wasmnest::plugin::host_*::add_to_linker::<S, D>` 的 `S` 是单态类型参数，能力 crate
//! 必须能命名它（否则要么退回宿主侧逐接口硬编码，要么与宿主构成 Cargo 环）。
//!
//! 字段只有**机制属性**：实例身份、WASI 上下文、资源上限快照、指标句柄、可选导出
//! 探测句柄。宿主子系统引用一律经 [`HostPorts`]（[`crate::ports`]）——**本结构不
//! 持有任何产品语义**（AGENTS §5.1 B1/B3）。
//!
//! 可选导出句柄是**机制层探测**（native `TypedFunc`，不经 WIT 绑定）：接口形状随端
//! cap 演进（`events-ws` / `events-task` 目前只在桌面 cap 声明，移动侧恒探测为
//! `None`），属共享锚点上的已知端词汇残留——新增可选导出回调需同时改本结构与
//! wasm-core 壳的探测点（见各字段注释）。

use std::sync::Arc;

use wasmtime::component::TypedFunc;
use wasmtime::component::ResourceTable;

use crate::limits::StoreLimits;
use crate::metrics::PluginMetrics;
use crate::ports::HostPorts;

/// 可选导出 `events-binary#on-message-binary` 的探测句柄类型
///
/// （插件 ID, topic, 二进制载荷）→ ()
pub type OnMessageBinaryExport = TypedFunc<(String, String, Vec<u8>), ()>;

/// 可选导出 `events-ws#on-message`（客户端域帧回调）的探测句柄类型
pub type OnWsMessageExport = TypedFunc<(String, String, Vec<u8>), ()>;

/// 可选导出 `events-ws#on-client-message`（服务端域帧回调）的探测句柄类型
///
/// （插件 ID, 广播者 ID, 目标 topic, 载荷）→ ()
pub type OnWsClientMessageExport = TypedFunc<(String, String, String, Vec<u8>), ()>;

/// 可选导出 `events-task#on-task-event`（宿主并发任务进度/终态回调）的探测句柄类型
pub type OnTaskEventExport = TypedFunc<(String,), ()>;

/// 实例化一个插件 Store 所需的全部配置与埋点句柄
///
/// 由宿主 `core-config` × `core-monitor` 交汇产出；本 crate 只收结构不收来源。
#[derive(Clone)]
pub struct StoreSpec {
    /// Store 资源上限快照
    pub limits: StoreLimits,
    /// 燃料看门狗是否开启（Engine 级开关的投影；关闭时 set_fuel/get_fuel 不可用）
    pub fuel_enabled: bool,
    /// 插件指标句柄（埋点入口）
    pub metrics: Arc<PluginMetrics>,
}

/// 单个 WASM 插件实例的状态
///
/// 每个插件实例化时创建独立的 `Store<WasmPluginState>`。
pub struct WasmPluginState {
    /// 插件 ID（用于权限校验和数据隔离）
    pub plugin_id: String,
    /// 宿主上下文（注入宿主能力；见 [`HostPorts`]）
    pub host: Arc<dyn HostPorts>,
    /// WASI 槽（上下文 + 资源表；预打开目录由宿主装配面解析——`manager::runtime::wasi`；
    /// 未开启自身文件访问的插件为空上下文，不干扰 host 文件域路径）
    ///
    /// **常编译**（用户裁决 2026-10-12）：WASI 面双端同源、默认全开、开/关由
    /// `CoreConfig::wasi` 定——不再有「桌面带 ctx / 移动不带」的形态 feature 分叉。
    /// 结构见 [`WasiSlot`]（含 `Mutex` 包裹的 Sync 理由）。
    pub wasi: std::sync::Mutex<WasiSlot>,
    /// Store 资源上限快照（实例化时自内核配置读取）
    pub limits: StoreLimits,
    /// 燃料看门狗是否开启（见 [`StoreSpec::fuel_enabled`]）
    pub fuel_enabled: bool,
    /// 插件指标句柄（埋点入口）
    pub metrics: Arc<PluginMetrics>,
    /// 可选导出 `events-binary#on-message-binary` 的动态探测句柄。
    /// 旧产物不导出该函数 → None，二进制消息对其按「格式不匹配」
    /// 拒绝（总线侧过滤，不会到达本字段为 None 的实例）
    pub on_message_binary: Option<OnMessageBinaryExport>,
    /// 可选导出 `events-ws#on-message`（客户端域帧回调）的探测句柄。
    /// 未导出 → None：宿主按降级语义处理（消息帧丢弃 + 首次 warn + 计数，
    /// 不缓存），状态事件仍经消息总线照常投递
    pub on_ws_message: Option<OnWsMessageExport>,
    /// 可选导出 `events-ws#on-client-message`（服务端域帧回调）的探测句柄
    pub on_ws_client_message: Option<OnWsClientMessageExport>,
    /// 可选导出 `events-task#on-task-event`（宿主并发任务进度/终态回调）的
    /// 探测句柄。未导出 → None：宿主按降级语义处理（事件丢弃 + 首次 warn +
    /// 计数，不缓存），离线查询原语自愈
    pub on_task_event: Option<OnTaskEventExport>,
}

impl WasmPluginState {
    /// 构建插件状态（`wasi_ctx` 由调用方按插件配置构建：需要预打开目录的走
    /// `manager::runtime::wasi::build_ctx`，无声明面走 `wasi::empty_ctx`）
    pub fn new(
        plugin_id: String,
        host: Arc<dyn HostPorts>,
        wasi_ctx: wasmtime_wasi::WasiCtx,
        spec: StoreSpec,
    ) -> Self {
        // 配额上限随实例化写入指标（监控页算使用率用；纯原子写，一次）
        spec.metrics.set_limits(&spec.limits);
        Self {
            plugin_id,
            host,
            wasi: std::sync::Mutex::new(WasiSlot {
                ctx: wasi_ctx,
                table: ResourceTable::new(),
            }),
            limits: spec.limits,
            fuel_enabled: spec.fuel_enabled,
            metrics: spec.metrics,
            // 可选导出在实例化后动态探测（verify_abi 内写入）
            on_message_binary: None,
            on_ws_message: None,
            on_ws_client_message: None,
            on_task_event: None,
        }
    }
}

/// WASI 槽：`WasiCtx` + `ResourceTable`（linker 共享、槽每实例）
///
/// **为什么包一层 `Mutex`**：`WasiCtx` 内含 `Box<dyn StdinStream / StdoutStream /
/// HostWallClock / Rng / Any>` 等**非 `Sync`** 字段，而 store 数据体按 `Sync` 设计
/// （宿主与能力域的实现都以 `&WasmPluginState` 作入口共享该状态，见各端
/// `src-tauri/src/plugin/**` 的 `Host for WasmPluginState` 与端口 adapter）。
/// `Mutex<T: Send>` 即 `Sync`，取用走
/// [`Mutex::get_mut`]（Store 内天然独占，不真加锁、不可能中毒），故 Sync 面由包裹
/// 提供而运行期零成本。
pub struct WasiSlot {
    /// WASI 上下文
    pub ctx: wasmtime_wasi::WasiCtx,
    /// WASI 资源表（文件句柄 / 流等）
    pub table: ResourceTable,
}

/// WASI 视图：`add_to_linker_async` / `add_to_linker` 通过此 trait 访问每个
/// 插件实例的 `WasiCtx` + `ResourceTable`（linker 共享、ctx 每实例）。
///
/// 常编译：p2/p3 注册是双端共享的核心装配面（`manager::runtime::wasi`），
/// 是否注册由 `CoreConfig::wasi` 在运行时构建期决定，与形态无关。
impl wasmtime_wasi::WasiView for WasmPluginState {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        // 独占取用（不加锁；中毒不可能——无跨线程持锁路径，越界也不吞错）
        let slot = self.wasi.get_mut().unwrap_or_else(|e| e.into_inner());
        wasmtime_wasi::WasiCtxView {
            ctx: &mut slot.ctx,
            table: &mut slot.table,
        }
    }
}

/// 插件实例资源限制器
///
/// 直接借用 Store 状态（`Store::limiter` 的闭包返回本状态的可变引用），
/// 限制单插件线性内存与表大小，防止失控/恶意插件耗尽宿主内存。
impl wasmtime::ResourceLimiter for WasmPluginState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.limits.max_memory_bytes {
            tracing::warn!(
                plugin_id = %self.plugin_id,
                desired_bytes = desired,
                max_bytes = self.limits.max_memory_bytes,
                "WASM memory growth denied by resource limiter"
            );
            self.metrics.record_memory_denied();
            Ok(false)
        } else {
            // 指标记账：当前值/峰值（纯原子操作，不进日志）
            self.metrics.record_memory_growth(desired);
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.limits.max_table_entries {
            tracing::warn!(
                plugin_id = %self.plugin_id,
                desired_entries = desired,
                max_entries = self.limits.max_table_entries,
                "WASM table growth denied by resource limiter"
            );
            self.metrics.record_table_denied();
            Ok(false)
        } else {
            Ok(true)
        }
    }
}
