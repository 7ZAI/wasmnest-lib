//! WASM 插件运行时（**单形态**，2026-10-13 起无 common/bare 之分 · 用户裁决）
//!
//! 用户裁决（.scratch/2026-10-13-runtime-single-form/spec.md）：wasm-core 提供
//! **统一的基础 ABI**（core.wit），真正 ABI = 宿主组装各自 SDK WIT 后的产物；
//! Linker 装配**机制一份**，端差异（cap 域实现 / 权限门 / 事件词汇）由各端宿主
//! `HostModule` 自报组装实现差异——全部按桌面形态统一，移动端宿主改造适配。
//!
//! 票 04（桌面）与票 05（移动）把两个壳里的 WIT 绑定全部迁到各端宿主后，本模块
//! 只剩**一份机制接线**：
//!
//! - Engine/Linker/Store 生命周期 + WASI 装配（[`wasi`]，p2/p3，默认全开）+
//!   [`component`]（导出调用骨架 + 宿主自报模块的装配入口；WIT impl 面在各端宿主
//!   `src-tauri/src/plugin/*.rs`）
//! - **组件形态检查参数化**（[`AbiPolicy`]，只管 `abi-form`）：wasm-core 零端知识，
//!   形态要求（桌面 `form = Some(1)` / 移动 `None`）由宿主装配时注入；整数 ABI 与
//!   版本协商已随 wit 包版本化退役（ADR 0051 D2）——版本一致性由 linker 按含版本
//!   import 名精确匹配保证
//! - 端差异宿主侧表达：cap 域 `Host` impl 经 `HostModule` 自报汇入同一个 Linker；
//!   `events` 导出契约由宿主注入 [`guest_events::GuestEventDispatcher`]；
//!   权限门 / 插件私有库布局是宿主实现差异（移动 host_domains，D7 语义不变）。
//!
//! 与 WIT 无关的机制面（组件编译 + AOT 缓存、Store 装配与资源限制接线、燃料注入
//! 与续费、实例生死观测）唯一一份，见 [`engine`]。

// ==================== 组件引擎机制（双端唯一一份） ====================
//
// 组件编译 + AOT 缓存、Store 装配与资源限制接线、燃料注入与续费、实例生死观测、
// Engine 构建纯函数、trap 判定——全部双端一份，见 [`engine`]。
// **`bindgen!` / `impl … Host` / linker 装配 / `verify_abi` / `Loaded*Plugin` 导出
// 调用面不在这里**：core 交集在 [`core_binding`]（唯一一份），cap 与端差异在
// 各端宿主（ADR 0049 + 单形态裁决）。
pub(crate) mod engine;

// ==================== Core 交集绑定层（唯一一份，票 03 Option A） ====================
//
// 绑契约真源 `wit/core.wit` 的 `world core`（双端全等的交集），cap 组合面由各端宿主
// 自有绑定 + `HostModule` 自报汇入同一个 Linker。形态差异（cap / WASI / 端 SDK 类型）
// 不进本模块。
pub(crate) mod core_binding;

// ==================== WASI 装配面（双端同源，配置驱动） ====================
//
// 用户裁决（2026-10-12）：WASI（p2/p3）住核心、双端默认全开、开/关由
// `CoreConfig::wasi` 定——形态（桌面 / 移动）不再是有无 WASI 的差异轴。
// 目的：将来 worker 类别插件双端都要跑 wasm，装配面必须已经双端同源。
// 单形态起无条件编译（wasmtime-wasi 无条件依赖）；装配的 `WasmPluginState` 由
// 本模块（[`component`] 壳）提供。
pub(crate) mod wasi;

// ==================== Guest 事件派发契约面（票 03 / ADR 0022） ====================
//
// 事件循环机制留内核，`events` 导出的调用契约由各端宿主实现本 trait 并注入
// （双端 `events` 词汇完全不同，且带 `result` 返回无法原生探测，见模块文档）。
pub mod guest_events;

// ==================== 组件壳（单形态，桌面形态为准） ====================
//
// linker 装配（core 交集 + 宿主自报 + WASI）+ `LoadedWasmPlugin`（Store + Instance
// 所有权、导出调用骨架、`abi` / 可选导出原生探测）。移动宿主经同一壳装配
// （其 cap 域 `HostModule` 自报汇入同一个 Linker，权限差异在移动宿主实现面）。
// `pub(crate)`：`test_support` 转发面（无头装配 / 移动测试基建）按同 crate 可达性
// 直接引用 `component::add_to_linker`（host-kit 装配面契约，见 test_support）。
pub(crate) mod component;

// 夹具共享 target 目录（测试期编译产物落点，cfg(test) 门控：生产构建不编译本模块）
// pub(crate)：runtime 的夹具构建器与 p3 探针共用同一落点
#[cfg(test)]
pub(crate) mod fixture_target;

// 重导出（glob 过壳：component 分支的全部 pub 符号保持
// `crate::manager::runtime::X` 路径不变——宿主与 crate 内引用零改动）
pub use component::LoadedWasmPlugin;
// 票 02 批次 02：生效能力模块白名单（内建在册 ∪ 宿主自报）——宿主侧集成锁
// （`src-tauri/tests/pty_wiring.rs` 的双向比对）必须用同一份合并结果，不得各拼一份。
pub use component::host_module_whitelist;
// 票 06：实例元数据与可选导出句柄快照（调用模型两侧共用的只读投影）
// 消费方在桌面装配面（`manager/host.rs` / 属主路径）：移动形态经宿主侧装配，
// 不消费本 re-export——单形态共享故保留 + 按形态豁免 unused
#[cfg_attr(not(feature = "desktop-assembly"), allow(unused_imports))]
pub(crate) use component::{InstanceMeta, OptionalExports};

// ==================== 宿主上下文（票 04 迁移 host_api::context） ====================
// 定义已迁 `crate::host_api::context`（host_api 消费方家园）；以下 re-export
// 保持历史路径 `manager::runtime::WasmHostContext` 等编译绿——manager→host_api 合法
// 方向，后续迭代按需清理。
pub use crate::host_api::context::{
    CapabilityProvider, PluginServices, ProcessRegistry, WasmHostContext,
};
// `WasmPluginState` / `StoreSpec` 连同 `WasiView` 与 `ResourceLimiter` 实现整体搬入
// `wasmnest-host-kit`（wasm-core-lib-split 票 03）：它们是**插件实例状态的机制面**，
// 且必须与「能力 crate 能命名状态类型」这一硬约束同 crate。可见性以 `pub use`
// 原样转发，既有 `runtime::WasmPluginState` 等引用路径逐字不变。
pub use wasmnest_host_kit::state::{StoreSpec, WasmPluginState};

// 声明展开（不过滤授权，preauthorize 收集弹窗候选用，见 host.rs `preauthorize_plugin`）
// 消费方在桌面装配面（`manager/host/preauth.rs`）；移动形态不消费——按形态豁免 unused
#[cfg_attr(not(feature = "desktop-assembly"), allow(unused_imports))]
pub(crate) use crate::manager::runtime::wasi::expand_preopen_declarations;
/// WASI 预打开目录解析（激活时重建实例判定用，见 host.rs `rebuild_wasm_instance`）
/// 消费方同上（桌面装配面）；移动形态不消费——按形态豁免 unused
#[cfg_attr(not(feature = "desktop-assembly"), allow(unused_imports))]
pub(crate) use crate::manager::runtime::wasi::resolve_preopen_dirs;

// ==================== 资源限制 & 中断 ====================

// 运行参数单一事实源在配置模块（core-config，见 `crate::config`）：
// Engine 构建参数与 Store 资源上限的默认值即历史生产常量（`config::defaults`），
// 支持配置文件加载与运行时覆盖；燃料看门狗的语义说明随默认值一并迁入。
pub(crate) use crate::config::plugin_debug_mode;
use crate::config::CoreConfig;

use crate::storage::PluginStorage;
// 本模块即其落点（`mod engine` 声明见文件头）；Engine 构建面（build_engine_config
// 等纯函数）亦在其中——桌面为真源、移动侧消费同一份。`tests/engine_config.rs`
// 的判据（配置→wasmtime 的逐项映射、逃生舱锁定项重申）按名消费同一批函数。
#[cfg(test)]
use engine::{
    build_engine_config, wasmtime_backtrace_details, wasmtime_opt_level, wasmtime_profiling,
};
// 异步桥（`block_on_async`）已中立化到 core-runtime-util：本模块与它的消费者
// （host_api / security / task 等）同为其使用方，不再由本模块定义（票 01）；
// 本模块仅测试代码使用它，故 cfg(test) 门控（非 test 构建零 unused import）
use crate::config::ResourceOverrides;
use crate::manifest::WasiPreopenDir;
use crate::monitor::{LifecycleEvent, MetricsRegistry};
#[cfg(test)]
use crate::runtime_util::block_on_async;
use crate::security::fs_auth::FsAuthChecker;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::Manager;
use wasmtime::Engine;

// 统一错误类型/结果（引擎级真源 wasmnest-server-base，lib 再导出）

/// 宿主要求的组件**形态**规格（**端事实**，宿主装配时注入；wasm-core 零端知识）
///
/// **只管形态，不再管版本**（ADR 0051 D2）：整数 `ABI_VERSION` 与 WIT `interface abi`
/// 已退役——契约版本搬上 wire（`package wasmnest:plugin@<version>`，见
/// [`crate::contract`]），宿主与 guest 版本不等由 wasmtime linker 按含版本的完整
/// import 名**精确匹配**直接拒绝，失败诊断自带包名 + 版本（并命中
/// `stale_artifact_rebuild_hint` 的重建指引）。内核不再有任何版本协商代码。
///
/// 形态与版本**正交**：`abi-form.form` 走独立接口（桌面 cap 导出），语义是
/// 「component 形态 vs core 形态」的加载路径判别，故原样保留：
/// - 桌面：`form = Some(FORM_COMPONENT)`（本模块 [`FORM_COMPONENT`] 常量；SDK
///   guest 面持同值拷贝）
/// - 移动：`form = None`（移动 WIT 无 `abi-form` 导出，不要求）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormPolicy {
    /// 要求组件声明的 `abi-form` 值（桌面 cap 导出 `abi-form.form` = 1；
    /// `None` = 不要求，探测到也不比较）
    pub form: Option<u32>,
}

/// 形态检查策略别名：保留 `AbiPolicy` 名以免调用面大改（语义已窄化为形态，见上）
pub type AbiPolicy = FormPolicy;

impl FormPolicy {
    /// 无 form 要求（不探测不拒绝）：第三方 / 无头宿主显式选择。
    ///
    /// **生产桌面宿主必须显式注入真实规格**——默认 UNCONSTRAINED 是给无端事实的
    /// 测试 / 无头装配用的（移动端 WIT 无 form 导出，生产值同样是 `form: None`）。
    pub const UNCONSTRAINED: FormPolicy = FormPolicy { form: None };
}

impl Default for AbiPolicy {
    fn default() -> Self {
        Self::UNCONSTRAINED
    }
}

/// `abi-form.form()` 的组件形态判别值（WIT `abi-form` 接口导出值）
///
/// **只管形态，不管版本**（ADR 0051 D2）：迁移阶段 C 后组件是唯一形态，
/// `FORM_CORE = 0` 已随该阶段删除；保留常量 1 是为了挡住未来误引入 0 值导致
/// 加载路径回退。移动 WIT 无 `abi-form` 导出（`form = None` 不比较），本值对
/// 移动装配无意义。
///
/// 批 2 自桌面 SDK 收口上提（平台仓 issue #36）：宿主装配 [`FormPolicy::form`]
/// 与 SDK guest 宏各持同值拷贝，一致性由跨端 wire 漂移锁断言。
pub const FORM_COMPONENT: u32 = 1;

/// 从 catch_unwind 的 panic 载荷提取人类可读消息（统一 panic 诊断文案）
pub fn panic_payload_to_string(panic: &Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

/// 票 03：桌面插件与测试 fixture 统一 wasm32-wasip3 构建参数
///
/// 单一事实来源 = `scripts/wasip3-toolchain.sh`（WASIP3_NIGHTLY）；stable 1.99
/// （预计 2026-10 中）发布后随工具链迁移移除 nightly pin，见
/// `docs/knowledge/wasip3-toolchain.md`。所有宿主内联 fixture 构建（plas组件测试/
/// SDK 测试/ws 测试/系统组件测试）与本常量保持同步。
// non-test 构建（cargo check --lib）不编译测试使用方 → 允许 dead_code
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const WASIP3_NIGHTLY: &str = "nightly-2026-09-16";

///
/// Engine 和 Linker 是线程安全的可复用结构：
/// - Engine: WASM 编译器，全局单例
/// - Linker: Host function 注册表，所有插件实例共享
pub struct WasmRuntime {
    engine: Engine,
    /// Component 形态插件的 linker（阶段 C 后唯一形态）
    ///
    /// 已接线的 import 接口见 [`component::add_to_linker`]，实例化导入
    /// 未接线接口的组件会报 unknown import 错误
    linker: wasmtime::component::Linker<WasmPluginState>,
    /// 文件系统访问校验器
    fs_auth: Arc<FsAuthChecker>,
    /// AOT 编译产物（`.cwasm`）缓存目录（宿主 cache 目录，非插件目录）
    ///
    /// 插件目录可被安装方/插件自身写入，若把反序列化产物放回插件目录，
    /// 能写插件目录的攻击者可投放伪造产物触发宿主进程 UB
    /// （`Component::deserialize` 是 unsafe，假定数据可信）。
    /// 无 app_handle 时（无头/测试）为 None，禁用文件级 AOT 缓存。
    /// pub(crate)：`crate::test_support` 的无头装配注入临时目录；
    /// 生产面经 `with_config` 构造时设置，无其它写者。
    pub(crate) aot_cache_dir: Option<PathBuf>,
    /// 内核配置（core-config）：Engine 参数构建期固化，Store 上限每次实例化读快照
    /// （运行时覆盖只影响新建立的 Store）
    config: Arc<std::sync::RwLock<CoreConfig>>,
    /// 指标注册表（core-monitor）：内核运行时埋点数据中心
    monitor: Arc<MetricsRegistry>,
    /// ABI 规格（端事实，宿主装配时注入；见 [`AbiPolicy`]）
    abi_policy: AbiPolicy,
    /// 端专属 guest 事件派发器（票 03 / ADR 0022）
    ///
    /// 缺省 `UnwiredGuestEvents`（派发即 fail-visible）；生产由 `PluginHost::new`
    /// 与移动宿主 `PluginManager::init_wasm_runtime_with` 同构地注入各端实现
    /// （宿主自带 `bindgen!`）。
    guest_events: Arc<
        std::sync::RwLock<Arc<dyn crate::manager::runtime::guest_events::GuestEventDispatcher>>,
    >,
}

/// 引擎定制钩子：宿主在**内核自身设置之后**、`Engine::new` **之前**拿到裸
/// [`wasmtime::Config`]，可覆盖任意**非锁定**项——配置面（[`crate::config::EngineTuning`]）枚举不到的
/// 原语都走这里（`target` / `allocation_strategy(pooling)` / 自定义内存分配器…）。
///
/// 返回 `Err` → Engine **构建失败**（错误带操作上下文上抛，不静默降级为一个
/// 「看起来能用但参数不对」的 Engine）。
///
/// **锁定项**：资源看门狗 4 项（`consume_fuel` / `max_wasm_stack` /
/// `memory_reservation` / `memory_may_move`）在钩子执行后被
/// [`engine::reassert_locked_knobs`] 重申，钩子改不动；要改走 [`CoreConfig`]（有跨字段校验）。
///
/// 钩子类型需命名 `&mut wasmtime::Config`——写钩子的宿主**不必自己加 wasmtime 依赖**，
/// 经 `wasmnest_wasm_core::wasmtime` 再导出即可（ADR 0019 双端锁版，宿主侧不重复锁版本）。
pub type EngineCustomizer = Arc<dyn Fn(&mut wasmtime::Config) -> crate::Result<()> + Send + Sync>;

/// 引擎装配输入（[`WasmRuntime::with_setup`] 的配置包）
///
/// 为什么成结构体而不是继续加位置参数：钩子 + 内核配置 + 免弹窗清单 + ABI 规格
/// 同属「宿主装配期的引擎输入」，位置参数超过三个后调用点不可读
/// （`with_config` 的位置参数已经足够难核对）。
#[derive(Default)]
pub struct EngineSetup {
    /// 内核配置（Engine 参数在构建期固化；`store` 部分仍可运行时覆盖）
    pub config: CoreConfig,
    /// 第一方免弹窗归属清单（票 08/P0-2；空表 = 无免弹窗项）
    pub first_party_dirs: Vec<(&'static str, Vec<crate::security::fs_auth::TrustedDir>)>,
    /// 引擎定制钩子（可选，见 [`EngineCustomizer`]）
    pub customizer: Option<EngineCustomizer>,
    /// ABI 规格（默认 [`AbiPolicy::UNCONSTRAINED`]——测试/无头装配用；
    /// **生产宿主必须经 [`Self::with_abi`] 显式注入真实规格**）
    pub abi: AbiPolicy,
}

impl EngineSetup {
    /// 以指定内核配置装配（免弹窗清单为空、无钩子、ABI 规格 UNCONSTRAINED）
    pub fn new(config: CoreConfig) -> Self {
        Self {
            config,
            first_party_dirs: Vec::new(),
            customizer: None,
            abi: AbiPolicy::default(),
        }
    }

    /// 追加第一方免弹窗归属清单（构建器方法）
    pub fn with_first_party_dirs(
        mut self,
        dirs: Vec<(&'static str, Vec<crate::security::fs_auth::TrustedDir>)>,
    ) -> Self {
        self.first_party_dirs = dirs;
        self
    }

    /// 追加引擎定制钩子（构建器方法；重复调用以最后一个为准）
    pub fn with_customizer(
        mut self,
        customize: impl Fn(&mut wasmtime::Config) -> crate::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.customizer = Some(Arc::new(customize));
        self
    }

    /// 注入形态规格（端事实；见 [`AbiPolicy`]——桌面 `form = Some(1)`，移动 `None`）
    pub fn with_abi(mut self, abi: AbiPolicy) -> Self {
        self.abi = abi;
        self
    }
}

impl WasmRuntime {
    /// 创建 WASM 运行时
    ///
    /// 初始化 Engine、Linker，注册所有 Host Functions。
    /// 宿主能力（db / session / permission 等）不在本结构持有，
    /// 而是通过 [`WasmHostContext`] 注入到每个插件实例的 Store state 中。
    /// `app_handle` 为 None 时（无头/测试上下文）依赖前端事件的宿主能力降级。
    ///
    /// `first_party_dirs`：第一方免弹窗归属清单（票 08/P0-2，宿主装配时注入；空表
    /// = 无免弹窗项）——经本构造函数直通 `FsAuthChecker`。
    ///
    /// **形态规格**（[`AbiPolicy`]）：生产桌面宿主必须显式注入；测试/无头
    /// 传 [`AbiPolicy::UNCONSTRAINED`]。
    pub fn new(
        storage: Arc<PluginStorage>,
        app_handle: Option<Arc<tauri::AppHandle>>,
        first_party_dirs: Vec<(&'static str, Vec<crate::security::fs_auth::TrustedDir>)>,
        abi: AbiPolicy,
    ) -> crate::Result<Self> {
        // 内核配置：编译期默认 < 配置文件 < 运行时覆盖（set_config）。
        // 配置文件缺失/非法不阻断启动——`load_or_default` 记录 warn 并回落编译期默认
        let core_config = app_handle
            .as_ref()
            .and_then(|h| h.path().app_config_dir().ok())
            .map(|d| CoreConfig::load_or_default(&d.join(CoreConfig::FILE_NAME)))
            .unwrap_or_default();
        Self::with_setup(
            storage,
            app_handle,
            EngineSetup::new(core_config)
                .with_first_party_dirs(first_party_dirs)
                .with_abi(abi),
        )
    }

    /// 以指定内核配置构建（测试与运行时覆盖路径；配置须先通过 [`CoreConfig::validate`]）
    pub fn with_config(
        storage: Arc<PluginStorage>,
        app_handle: Option<Arc<tauri::AppHandle>>,
        core_config: CoreConfig,
        first_party_dirs: Vec<(&'static str, Vec<crate::security::fs_auth::TrustedDir>)>,
    ) -> crate::Result<Self> {
        Self::with_setup(
            storage,
            app_handle,
            EngineSetup::new(core_config).with_first_party_dirs(first_party_dirs),
        )
    }

    /// 以完整引擎装配输入构建（A+B 面 + ABI 规格入口；`new` / `with_config` 均经此委托）
    ///
    /// 引擎参数优先级链（高者胜，但锁定项除外）：
    /// `编译期默认 < wasm-core.json（Engine 参数构建期固化，重启生效） < 本次传入的
    /// CoreConfig < EngineCustomizer（仅构建期，最后一道）`
    pub fn with_setup(
        storage: Arc<PluginStorage>,
        app_handle: Option<Arc<tauri::AppHandle>>,
        setup: EngineSetup,
    ) -> crate::Result<Self> {
        let EngineSetup {
            config: core_config,
            first_party_dirs,
            customizer,
            abi: abi_policy,
        } = setup;
        if let Err(reason) = core_config.validate() {
            return Err(crate::AppError::Config(format!("内核配置非法: {}", reason)));
        }
        let mut config = engine::build_engine_config(&core_config, plugin_debug_mode());

        // 逃生舱（B 面）：宿主在内核自身设置之后拿到裸 Config，覆盖配置面枚举不到的
        // 原语（`target` / pooling / 自定义分配器…）。返回 Err 直接让构建失败——
        // 定制失败绝不静默降级为一个「看起来能用但参数不对」的 Engine。
        if let Some(customize) = &customizer {
            customize(&mut config).map_err(|e| {
                crate::AppError::Config(format!("引擎定制钩子失败，Engine 未构建: {}", e))
            })?;
            // 锁定项重申：钩子能改 Config 但不可回读校验，而看门狗 4 项在配置面
            // 有跨字段约束（见 engine::reassert_locked_knobs）——不锁则「配置已校验」的
            // 承诺在最后一步静默失效
            engine::reassert_locked_knobs(&mut config, &core_config);
            tracing::info!("WASM engine customizer applied (locked knobs re-asserted)");
        }
        let engine = Engine::new(&config).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to initialize WASM engine: {}", e))
        })?;
        let mut linker = wasmtime::component::Linker::new(&engine);

        // 注册已接线的 Component import 接口（实现见宿主侧域实现 + component）
        // WASI p2/p3 段由 `core_config.wasi` 决定（默认全开）——注册在此一次固化，
        // 运行期 `set_config` 改不动（见 set_config 的 warn）
        component::add_to_linker(&mut linker, &core_config.wasi)?;

        // AOT 缓存目录：宿主 cache 目录（非插件目录，见结构体字段注释）。
        // 须在 app_handle move 进 FsAuthChecker 之前取出
        let aot_cache_dir = app_handle
            .as_ref()
            .and_then(|h| h.path().app_cache_dir().ok())
            .map(|d| d.join("wasm-aot"));
        if let Some(dir) = &aot_cache_dir {
            if let Err(e) = std::fs::create_dir_all(dir) {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "Failed to create AOT cache dir, AOT cache disabled"
                );
            }
        }

        let fs_auth = Arc::new(FsAuthChecker::new(
            storage.clone(),
            app_handle,
            first_party_dirs,
        ));

        let monitor = Arc::new(MetricsRegistry::new());
        // task 段快照源注册（spec 票 02 去环）：monitor 经注册回调取 host-task
        // 指标，monitor.rs 不再内联引用 manager::task。注册幂等；monitor 仅经本
        // runtime 暴露，快照必在注册之后——生产路径无「未注册段降级」窗口
        // （降级仅裸 registry 单测可观测，见 monitor.rs tests）。
        // 单形态：task 引擎是桌面专属装配面（desktop-assembly，移动无 host-task
        // 域）——无该 feature 的宿主（移动 / 无头）跳过注册，monitor 无 task 段。
        #[cfg(feature = "desktop-assembly")]
        crate::manager::task::register_task_metrics_source(&monitor);

        Ok(Self {
            engine,
            linker,
            fs_auth,
            aot_cache_dir,
            config: Arc::new(std::sync::RwLock::new(core_config)),
            monitor,
            abi_policy,
            guest_events: Arc::new(std::sync::RwLock::new(Arc::new(
                crate::manager::runtime::guest_events::UnwiredGuestEvents,
            )
                as Arc<dyn crate::manager::runtime::guest_events::GuestEventDispatcher>)),
        })
    }

    /// 注入端专属 guest 事件派发器（生产在 `PluginHost::new` / 移动宿主
    /// `PluginManager::init_wasm_runtime_with`，与 monitor 同范式）
    ///
    /// **晚绑定**：派发器存入与各实例共享的槽位，实例在派发时实时读取——
    /// 因此对**已创建**的实例同样生效。这很重要：`PluginHost::new` 会在扫描阶段
    /// 即实例化插件，宿主的注入调用只能发生在其后，快照语义会让这批实例永远停在
    /// `UnwiredGuestEvents`。未注入时槽内是 `UnwiredGuestEvents`，派发 fail-visible
    /// 报错（不是静默丢消息）。
    pub fn set_guest_events(
        &self,
        dispatcher: Arc<dyn crate::manager::runtime::guest_events::GuestEventDispatcher>,
    ) {
        *self.guest_events.write().unwrap_or_else(|e| e.into_inner()) = dispatcher;
    }

    /// 当前内核配置快照
    pub fn config(&self) -> CoreConfig {
        self.config
            .read()
            .expect("core config lock poisoned")
            .clone()
    }

    /// 运行时覆盖内核配置：只影响覆盖后新建立的 Store（Engine 参数构建期已固化）
    ///
    /// **Engine 段改动会 warn 不静默**：Engine 在构建期固化，此后 `set_config` 里的
    /// `engine` 段（含 [`crate::config::EngineTuning`] 的 17 个字段）对已建 Engine
    /// 完全无效——不检测的话，宿主「配了没生效」会成为最难查的一类问题
    /// （配置读回来是对的，行为却没变）。要改 Engine 参数只能重新构建
    /// （[`Self::with_setup`] / 重启）。
    pub fn set_config(&self, cfg: CoreConfig) -> crate::Result<()> {
        if let Err(reason) = cfg.validate() {
            return Err(crate::AppError::Config(format!("内核配置非法: {}", reason)));
        }
        {
            let current = self.config.read().expect("core config lock poisoned");
            if current.engine != cfg.engine {
                tracing::warn!(
                    "set_config 携带了 Engine 参数变更，但 Engine 构建期已固化，本次覆盖不会生效（需重建运行时）"
                );
            }
            // WASI 注册面（enabled / p2 / p3）与 Engine 同类：linker 在运行时构建期
            // 一次装配后固化——运行期改它对已建 linker 无效。preopen 装配（build_ctx）
            // 则每次实例化读配置，是即时生效的，故两者要分开说，别让运维以为全无效。
            if current.wasi != cfg.wasi {
                tracing::warn!(
                    "set_config 携带了 WASI 注册面（enabled/p2/p3）变更：linker 在运行时构建期已固化，\
                     已注册的接口集合不变（需重建运行时才生效）；仅「预打开目录装配」随配置即时生效"
                );
            }
        }
        *self.config.write().expect("core config lock poisoned") = cfg;
        Ok(())
    }

    /// 指标注册表句柄（core-monitor）：生命周期事件记账与快照导出入口
    pub fn monitor(&self) -> Arc<MetricsRegistry> {
        self.monitor.clone()
    }

    /// 从字节流编译 WASM 组件（Component Model，迁移阶段 A）
    pub fn compile_component(&self, bytes: &[u8]) -> crate::Result<wasmtime::component::Component> {
        wasmtime::component::Component::from_binary(&self.engine, bytes).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to compile WASM component: {}", e))
        })
    }

    /// 从文件编译 WASM 组件（带 AOT 缓存，与 core 路径同构）
    ///
    /// 机制本体在 [`engine`]（双端唯一一份）；本方法只把形态面（Engine 句柄 +
    /// 宿主 cache 目录）传进去。
    pub fn compile_component_from_file(
        &self,
        path: &Path,
    ) -> crate::Result<wasmtime::component::Component> {
        engine::compile_component_from_file(&self.engine, self.aot_cache_dir.as_deref(), path)
    }

    /// 从文件加载 WASM 插件（阶段 C 起仅组件形态）
    ///
    /// `declared_preopen_dirs`：manifest 声明的 WASI 预打开目录（原始值，
    /// 支持 ${home} 与只读档；实例化时经展开+授权过滤并按档位挂载，
    /// 见 `manager::runtime::wasi::build_ctx`）
    pub fn load_plugin_from_file(
        &self,
        path: &Path,
        plugin_id: &str,
        host_ctx: Arc<WasmHostContext>,
        declared_preopen_dirs: &[WasiPreopenDir],
        resource_overrides: Option<&ResourceOverrides>,
    ) -> crate::Result<LoadedWasmPlugin> {
        let bytes = std::fs::read(path).map_err(|e| {
            crate::AppError::Plugin(format!(
                "Failed to read WASM artifact '{}': {}",
                path.display(),
                e
            ))
        })?;
        let component = self.compile_component(&bytes)?;
        self.instantiate_component(
            &component,
            plugin_id,
            host_ctx,
            declared_preopen_dirs,
            resource_overrides,
        )
    }

    /// 实例化 WASM 组件
    ///
    /// 创建 Store + WasmPluginState，通过 linker 实例化，
    /// 校验 ABI 版本与形态字段（见 [`component::LoadedWasmPlugin::new`]；
    /// 规格来自本运行时装配期注入的 [`AbiPolicy`]，wasm-core 零端 ABI 知识）
    ///
    /// `resource_overrides` 为插件 manifest 的资源覆盖请求，经安全模块仲裁后
    /// 作为本 Store 的限额（见 [`crate::security::SecurityFramework::resolve_store_limits`]）。
    pub fn instantiate_component(
        &self,
        component: &wasmtime::component::Component,
        plugin_id: &str,
        host_ctx: Arc<WasmHostContext>,
        declared_preopen_dirs: &[WasiPreopenDir],
        resource_overrides: Option<&ResourceOverrides>,
    ) -> crate::Result<LoadedWasmPlugin> {
        let (limits, fuel_enabled, wasi_cfg) = {
            let cfg = self.config.read().expect("core config lock poisoned");
            (
                host_ctx
                    .security()
                    .resolve_store_limits(plugin_id, &cfg.store, resource_overrides),
                cfg.engine.consume_fuel,
                // WASI 面开关：preopen 装配随配置即时生效（linker 注册面已在构建期
                // 固化，见 with_setup / set_config 的说明）
                cfg.wasi,
            )
        };
        let metrics = self.monitor.plugin(plugin_id);
        let plugin = component::LoadedWasmPlugin::new(
            &self.engine,
            &self.linker,
            component,
            plugin_id,
            host_ctx,
            declared_preopen_dirs,
            &wasi_cfg,
            StoreSpec {
                limits,
                fuel_enabled,
                metrics: metrics.clone(),
            },
            self.abi_policy,
            // 晚绑定共享槽：注入（`set_guest_events`，可能晚于扫描期实例化）对各实例
            // 即时生效——实例不再持创建时快照，见 `LoadedWasmPlugin` 字段注释
            self.guest_events.clone(),
        )?;
        metrics.record_lifecycle(LifecycleEvent::Instantiate);
        // 实例创建日志：启动加载与热重载均经此路径，与 LoadedWasmPlugin::drop 的
        // 死亡日志成对，构成实例生命周期观测（plugin_id 键控，实现见 engine）
        engine::log_instance_created(plugin_id);
        Ok(plugin)
    }

    /// 获取文件系统访问校验器引用
    pub fn fs_auth(&self) -> &Arc<FsAuthChecker> {
        &self.fs_auth
    }

    /// Engine 句柄（**仅测试可见**：wasmtime `Config` 构建后不可回读，锁定项 /
    /// 逃生舱的行为契约只能经构建出来的 Engine 观测；生产不开放该面，
    /// 避免宿主绕过实例化路径直接用 Engine 编译产物）
    ///
    /// 非 `#[cfg(test)]` 门控的原因：宿主集成测试链的是**不带 cfg(test)** 的
    /// 本 crate，而引擎生效配置断言（逃生舱覆盖项）恰是迁宿主用例的组成部分——
    /// 经 `crate::test_support::runtime_engine` 转发消费（该模块是宿主测试的
    /// 唯一转发面，生产跨 crate 仍不可达：pub(crate)）。
    ///
    /// 移动形态（default-features=false）不编译 test_support 面故无消费；
    /// 单形态共享故保留 + 按形态豁免（测试形态仍经转发面消费）
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn engine(&self) -> &Engine {
        &self.engine
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    // 测试基建上提（wasm-core 纯净性收口票 05b）：无头运行时装配 / 插件私有库根 /
    // 会话中心串行锁 / 认证中心注册表闸门迁至 `crate::test_support`（常编译 pub，
    // lib 集成测试同源消费）。本 mod 及各域测试文件（`use super::*` 继承）经此 glob
    // 继续可见同名符号。
    use crate::test_support::*;

    // A0-3 前置探针（P1/P2/P5）：async store 兼容性 + 资源限制 async 语义 + 性能基线。
    // 文档：.scratch/2026-09-21-a0-3-host-async/spec.md + report.md（只读探针，不碰生产路径）
    mod a03_probe;
    // 终端输出消费插件化性能前置验证（terminal_output_perf，P1-P3）随票 02 批次 02
    // 迁宿主 `src-tauri/tests/terminal_output_perf.rs`（跨 crate 集成测试一律住宿主；
    // 本 crate 已不依赖 wasmnest-pty-engine）。
    // WS 终端输出路径吞吐探针（票 09 性能门禁 §9.3：插件 ring-fetch + WIT binary + WS send）
    // 认证中心热路径性能探针（ADR 0031 v32 fail-closed 裁决的每请求成本：
    // 宿主原生验签 vs 认证中心往返），只读探针
    // 域拆分（P0）：测试函数自本文件拆至 tests/（各域测试文件仍在
    // 本 mod 声明内），共享脚手架留在下方；各域文件 `use super::*` 复用，
    // fixture 互斥与产物构建语义不变
    // component_e2e / sdk_e2e / http_e2e 与 engine_{config,limits} 的夹具功能态用例
    // 随票 04 迁桌面宿主 `src-tauri/tests/{component_e2e,sdk_e2e,http_e2e,engine_e2e}.rs`
    // （wasm-core 不再持有全 world 绑定后，本测试二进制无法实例化 SDK 夹具）；
    // 留本文件的 engine_{config,limits} 只含形态无关纯机制用例。
    //
    // 票 08 批次三（夹具自持）：SDK 夹具的 keeper 与构建器随夹具 crate 全部归位
    // 桌面宿主 `src-tauri/tests/`（宿主 e2e 只读产物、keeper 负责构建）；本 crate
    // 只保留两份**自持夹具**（`fixtures/wasi-test` wasip2 preopen /
    // `fixtures/wasip3-test` async store 探针），绑定能力仓自己的 `wit/core.wit`，
    // 不读平台仓任何目录。
    mod engine_config;
    mod engine_limits;
    // 票 06 P1 的属主任务用例（owner_e2e）随票 04 迁桌面宿主 `src-tauri/tests/
    // owner_e2e.rs`——经 test_support 的属主转发面（spawn_test_owner 一族）直接
    // 驱动属主，内核侧不再持有该测试。
    mod p3_async_host_import;
    // host-pty 端到端矩阵（pty_e2e）随票 02 批次 02 迁宿主
    // `src-tauri/tests/pty_e2e.rs`（本 crate 已不依赖 wasmnest-pty-engine）。
    // host-task 闭环（task_e2e）随票 02 批次 05 迁宿主 `src-tauri/tests/task_e2e.rs`
    // ——WIT impl 迁出后内核测试二进制不再注册 host-task import，task 夹具无法
    // 在内核实例化（产物由桌面宿主 keeper 用例构建供给宿主，见该文件）。
    mod preopen_e2e;
    // WASI 面配置开关（用户裁决 2026-10-12：住核心、双端默认全开、外部配置可关）：
    // 关掉后 wasip2 夹具实例化必失败——开关落在 linker 注册面上的可见证据
    mod wasi_config;

    // ==================== Component Model 测试 ====================

    // SDK 夹具的构建与断言助手（`build_test_component` / `build_sdk_test_component` /
    // `build_ws_test_component` / `build_http_test_component` + ws 串行锁 / 兜底超时 /
    // 快照轮询）随票 04 全部迁桌面宿主 `src-tauri/tests/`：宿主侧 support 有同形副本
    // （宿主测试只读夹具、不承担构建，构建由桌面宿主 `src-tauri/tests/fixture_keeper.rs` 负责）。

    // host-pty 一族测试助手（串行锁 `lock_pty_fixture_e2e` / 构建器
    // `build_pty_test_component` / 断言助手 `pty_command_error` 等）随 wasm-core
    // 纯净性收口票 02 批次 02 迁宿主 `src-tauri/tests/{pty_e2e,terminal_output_perf}.rs`
    // ——本 crate 已不依赖 `wasmnest-pty-engine`，也不链接 pty fixture。

    // host-task fixture 闭环（task_e2e，6 用例）随票 02 批次 05 迁宿主
    // `src-tauri/tests/task_e2e.rs`：host-task 的 WIT impl 迁宿主后内核测试二进制
    // 不再注册该 interface，携带其 import 的 task 夹具无法在内核实例化
    // （与批次 04 crypto 探针同判据）。产物由桌面宿主 keeper 用例构建
    // （`src-tauri/tests/fixture_keeper.rs` 的 task keeper，宿主 e2e 只读）。
    // host-task 消费派发测试替身（MockTaskServices）与 `task_fixture_plugin_id`
    // 同批随用例迁宿主。
    //
    // 原 `build_sdk_test_component`（与 `build_test_component` 同产物同语义）随其
    // 消费者（sdk/engine_limits 等夹具用例）票 04 迁宿主一并删除——宿主经只读
    // 夹具产物读取面（桌面 `tests/support/` 的 `sdk_fixture_artifact_bytes`）取产物。

    /// 构建 wasm32-wasip2 测试组件（WASI preopen E2E / 配置开关用例）
    ///
    /// 夹具 = 能力仓自持 `fixtures/wasi-test`（绑定本 crate `wit/core.wit`，票 08
    /// 批次三）：目标为 WASI preview2（std::fs 直连预打开目录），依赖宿主当前机器
    /// 已安装 wasm32-wasip2 target（rustup target add）。产物直接是组件
    /// （wasm-component-ld 内嵌），无需再编码。
    fn build_wasi_test_component() -> Vec<u8> {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let plugin_dir = manifest_dir.join("fixtures/wasi-test");

        let module_path =
            fixture_target::artifact("wasm32-wasip2", "release", "wasmnest_plugin_wasi_test");

        if module_path.exists() {
            // 源文件含契约真源：夹具绑定 `wit/core.wit`，契约变了必须重建，
            // 否则「测试全绿但跑的是旧产物」（漏文件清单是历史踩坑点）
            let src_files = [
                plugin_dir.join("src/lib.rs"),
                plugin_dir.join("Cargo.toml"),
                plugin_dir.join("plugin.json"),
                manifest_dir.join("wit/core.wit"),
            ];
            let module_modified = std::fs::metadata(&module_path)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

            let needs_rebuild = src_files.iter().any(|f| {
                std::fs::metadata(f)
                    .and_then(|m| m.modified())
                    .map(|t| t > module_modified)
                    .unwrap_or(true)
            });

            if !needs_rebuild {
                return std::fs::read(&module_path)
                    .expect("Failed to read WASI test component module");
            }
        }

        let manifest_path = plugin_dir.join("Cargo.toml");
        let status = std::process::Command::new("cargo")
            .env("CARGO_TARGET_DIR", fixture_target::dir())
            .args([
                "build",
                "--target",
                "wasm32-wasip2",
                "--release",
                "--manifest-path",
                manifest_path.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to run cargo build for WASI test component");
        assert!(status.success(), "WASI test component WASM build failed");

        // 注：preopen 目前只在 wasip2 上真正可用。曾尝试迁到 wasip3（统一夹具
        // target 着想），但实测两个 preopen E2E 均 trap 于
        // `filesystem_method_descriptor_open_at`——p3 linker 虽接上，预打开目录
        // 的能力没建到 p3 filesystem 接口上。故本夹具固定 wasip2。
        // **preopen 仅 worker 类别可用**（ADR 0034）：本夹具是 worker 预留能力的
        // 机制守门测试（在策略闸门之下，不走 manifest 校验路径）；worker 启用
        // 专项需一并解决 wasip3 的 preopen 装配问题（见 ADR 0034 §worker 启用时需补）。
        std::fs::read(&module_path).expect("Failed to read WASI test component after build")
    }

    /// wasip3 工具链（pinned nightly + wasm32-wasip3 target）是否可用
    ///
    /// 工具链版本真源 = 本模块上方的 `WASIP3_NIGHTLY`（经 `use super::*` 可见）。
    /// CI（dtolnay stable）无该 target → 返回 false，调用侧测试值跳过；
    /// 本地经 scripts/wasip3-toolchain.sh install 后为 true。结果惰性缓存。
    fn wasip3_toolchain_ready() -> bool {
        use std::sync::OnceLock;
        static READY: OnceLock<Option<bool>> = OnceLock::new();
        match READY.get_or_init(|| {
            let out = std::process::Command::new("rustup")
                .args([
                    "run",
                    WASIP3_NIGHTLY,
                    "rustup",
                    "target",
                    "list",
                    "--installed",
                ])
                .output()
                .ok()?;
            Some(
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|l| l == "wasm32-wasip3"),
            )
        }) {
            Some(ready) => *ready,
            None => false,
        }
    }

    /// 构建 wasm32-wasip3 测试组件（票 02 A1 async 闭环 / A0-3 探针用）
    ///
    /// 夹具 = 能力仓自持 `fixtures/wasip3-test`（绑定本 crate `wit/core.wit`，
    /// 票 08 批次三）；target 产物 cdylib 直接是 Component（magic \0asm 0d，免
    /// componentize）；pinned nightly 经 RUSTUP_TOOLCHAIN 注入（与
    /// scripts/wasip3-toolchain.sh health 子命令同构）。产物缺失（本地未装工具链）
    /// 时返回 None，测试跳过。
    fn build_wasip3_test_component() -> Option<Vec<u8>> {
        if !wasip3_toolchain_ready() {
            return None;
        }
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let plugin_dir = manifest_dir.join("fixtures/wasip3-test");
        let module_path =
            fixture_target::artifact("wasm32-wasip3", "release", "wasmnest_plugin_wasip3_test");

        if module_path.exists() {
            let src_files = [
                plugin_dir.join("src/lib.rs"),
                plugin_dir.join("Cargo.toml"),
                plugin_dir.join("plugin.json"),
                // test-only world（core + 可选导出 events-binary）
                plugin_dir.join("wit/wasip3-fixture.wit"),
                manifest_dir.join("wit/core.wit"),
            ];
            let module_modified = std::fs::metadata(&module_path)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let needs_rebuild = src_files.iter().any(|f| {
                std::fs::metadata(f)
                    .and_then(|m| m.modified())
                    .map(|t| t > module_modified)
                    .unwrap_or(true)
            });
            if !needs_rebuild {
                return Some(
                    std::fs::read(&module_path)
                        .expect("Failed to read cached wasip3 test component"),
                );
            }
        }

        let status = std::process::Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", WASIP3_NIGHTLY)
            .env("CARGO_TARGET_DIR", fixture_target::dir())
            .args([
                "build",
                "--target",
                "wasm32-wasip3",
                "--release",
                "--manifest-path",
                plugin_dir.join("Cargo.toml").to_str().unwrap(),
            ])
            .status()
            .expect("Failed to run cargo build for wasip3 test component");
        assert!(status.success(), "wasip3 test component WASM build failed");
        Some(std::fs::read(&module_path).expect("Failed to read wasip3 test component after build"))
    }

    // ==================== WASI preopen E2E ====================

    // ==================== host-task 闭环（ABI v20，spec `.scratch/2026-09-21-host-task-concurrency/`） ====================
    //
    // task_e2e（含 MockTaskServices / task_fixture_plugin_id 脚手架）已随票 02 批次 05
    // 迁宿主 `src-tauri/tests/task_e2e.rs`（本文件 task 段的指路注释）。

    // ==================== 无头 harness 的认证边界（ADR 0033） ====================
    //
    // 「为什么 harness 里没有正向认证用例 / 正向认证去哪儿跑」的记录与
    // `positive_auth_needs_dedicated_binary` 跳过助手随 WS / HTTP 用例迁桌面宿主
    // `src-tauri/tests/support/mod.rs`（同文）；本 crate 剩余用例（owner / preopen /
    // a03 探针）不含认证路径。

    // ==================== 会话中心互调 api 清单（已上提 test_support） ====================
}
