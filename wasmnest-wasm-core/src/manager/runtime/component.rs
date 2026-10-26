//! Component Model 壳（**单形态**，2026-10-13 起无 common/bare 之分 · 用户裁决）
//!
//! **本模块不持有任何 WIT 绑定**（原全 world `bindgen!` 已删，其最后消费者是内核
//! 测试替身，随夹具用例迁宿主一并退役；移动那份票 05 一并迁移动宿主）——cap 域
//! `Host` impl 归各端宿主（桌面 `src-tauri/src/plugin/bindings.rs`，移动
//! `src-tauri/src/plugin/host_domains/`），core 交集 8 域归
//! `manager/runtime/core_binding.rs`（绑契约真源 `wit/core.wit`）。
//! 本文件只剩**与 WIT 无关的实例化机制**（桌面形态为准，移动宿主经同一壳装配）：
//! - linker 组装：core 本地表（`core_binding`）+ `inventory` 自报能力模块 + WASI p2/p3
//!   （WASI 实现与开关判据在核心模块 [`crate::manager::runtime::wasi`]，本壳只调用）；
//! - [`LoadedWasmPlugin`]：Store + Instance 所有权、导出调用骨架（`command` /
//!   `lifecycle` / `manifest` 走 core 绑定，`events` 走宿主注入的
//!   [`GuestEventDispatcher`]）、`abi` / 可选导出的原生 `TypedFunc` 探测；
//! - **ABI 版本 / 形态检查参数化**（[`AbiPolicy`]）：wasm-core 零端 ABI 知识，
//!   版本上限与 abi-form 要求由宿主装配时注入（桌面 38 + form=1；移动 21 + None）；
//! - WASI 预打开解析与装配已迁 [`crate::manager::runtime::wasi`]（用户裁决
//!   2026-10-12：WASI 面住核心、双端同源、默认全开）。
//!
//! ## 与 core module 路径的差异（历史，见 WIT 注释）
//!
//! - export 全部为必选：core ABI 中 on_message 等可选导出在组件契约中强制
//!   （组件 world 声明即契约，阶段 B SDK 无条件导出全部）
//! - log 不带 file/line 调用点（core ABI 经 ABI 传插件源码位置；
//!   组件形态暂无传递通道，见 wit/wasmnest.wit 的 host-log 注释）
//! - 内存搬运由绑定层处理，无需 (ptr,len) 配对与 alloc/dealloc

use super::{AbiPolicy, StoreSpec, WasmHostContext, WasmPluginState};
use crate::config::WasiConfig;
use crate::manager::runtime::engine;
/// WASI 装配面（p2/p3 注册 + 预打开上下文）——核心常编译，双端同源
/// （用户裁决 2026-10-12；本壳不再自持任何 WASI 实现，只剩调用）
use crate::manager::runtime::wasi;
// guest 事件派发契约面（票 03 / ADR 0022）：`events` 导出双端词汇不同、且带
// `result` 返回（原生 TypedFunc 表达不了），调用契约由宿主实现并注入，本壳只转发。
use crate::manager::runtime::guest_events::GuestEventDispatcher;
use crate::manifest::WasiPreopenDir;
use crate::monitor::LifecycleEvent;
use crate::runtime_util::block_on_async;
use crate::AppError;
use std::sync::Arc;
use wasmtime::component::{Component, Instance, Linker};
use wasmtime::Store;

// v27（票 10 删除的 `impl wasmnest::plugin::host_terminal::Host`）：
// `host-terminal.send` 是「宿主替插件往交互终端注入按键」的最后一处业务面入口，
// 零生产消费者（P1-b 起属主判定查已清空的内核登记，对真实会话恒拒），随
// `host-session` 同批删除。

/// 在册连接清单（票 04）：独立 interface。
/// **票 10 起是本面唯一入口**——`host-session` 上那条同判据的旧别名随整 interface 删除。
/// 已迁宿主（票 02 批次 05，`src-tauri/src/plugin/connection.rs` 路径 B：WIT impl +
/// 域函数随域走宿主；判据 `connection:read` 不变）。

// v27（票 10 删除的 `impl wasmnest::plugin::host_session::Host`）：
// 12 条原语（list-sessions / get / create-with-spec / lifecycle-register /
// input-register / close / remove / rename / resize / annotate / connections-list
// 别名 / output-ring-fetch）整块退役。会话真源在 `com.wasmnest.bedcode`
// 登记域，宿主侧不再有「会话」这一原语域的对外能力面。

// host-process（v8）/ host-app（v8）/ host-timer（v6）已迁宿主（票 02 批次 05，
// `src-tauri/src/plugin/{process,app,timer}.rs` 路径 B：宿主自带 bindgen + `Host` impl +
// 域函数同处；`ProcessUnitExecutor` 随域走宿主并经 `submit_unit_executor!` 自报注册）。

// host-api-call（互调，ADR-0017）的 **WIT impl** 已迁宿主（票 02 批次 05，
// `src-tauri/src/plugin/api_call.rs` 路径 B 薄转发：无权限门，互调门禁在注册表）。
// 回复道编排（`api_call` + `ReplyHandler` + 属主校验）**留内核** `host_api/api.rs`
// ——内核 `intercall`（通用互调客户端）与 `auth_center` 桥接（注册表留内核裁决）
// 经 `call_plugin_api_host` 消费同一条编排，与 peer/ws/http「内核仍消费引擎面」同判据。

// ==================== host-platform（ADR 0022 v2）====================
//
// host-mdns / host-peer 两个 interface 已随 wasm-core-lib-split 票 03 / 05 迁为
// 能力域（经 `inventory` 自报装配，见下节），本节只剩留 core 的 POSIX / 机制面。

// v36：`host-platform` 的桌面扩展函数（wsl-distros / local-ipv4-addresses /
// reveal-in-dir）拆入 `host-platform-desktop`（桌面独有交集切片），WIT impl 已迁
// 宿主 `src-tauri/src/plugin/platform.rs`（票 02 批次 06）；`pick-folders` 随后
// （2026-10-13 功能级统一，ADR 0052 D3）并入 core `host-platform`，不再在桌面扩展里。

// ==================== Component Linker 组装 ====================

// ==================== 能力模块注册 ====================

/// 生效白名单 = **纯宿主自报期望**（单形态 2026-10-13 收口）
///
/// 原「内建在册 ∪ 宿主自报」（`IN_CRATE_HOST_MODULES` 含 ws/peer/http 三条目）随
/// 单形态删除：三个能力域 crate 的绑定层/自报由**各端宿主**开启（桌面
/// `src-tauri/Cargo.toml` 依赖时带 `common-host` + `plugin/{http,ws,peer}.rs` 的
/// `expect_host_module!`；移动用自有 `host_domains/{http,ws,peer,mdns}` 实现）——
/// 端差异（用能力域 crate 还是自持实现）是宿主组装事实，不进内核。
///
/// 宿主侧来源 = `wasmnest_host_kit::expect_host_module!` 自报（与强制引用行同处，
/// 见 host-kit `assembly` 模块文档）。**常编译 pub**：宿主侧集成锁
/// （`src-tauri/tests/pty_wiring.rs`）要用同一份合并结果做双向比对——两侧各拼一份
/// 就是第二真源。
pub fn host_module_whitelist() -> Vec<&'static str> {
    wasmnest_host_kit::expected_host_modules()
}

// 强制引用行（无条件保留）：三个能力域 crate 的 **rlib 静态必须进最终二进制**
// ——不只 HostModule 自报（那是 `common-host` feature 门控、由宿主决定开不开），
// 还有 **DomainHooks 停用回收钩子**（server-websocket 的 HOOKS，host 的
// deactivate 经 `DomainHooksRegistry::collected().on_plugin_purge` 遍历——漏了
// 这行，ws 出站连接/服务端端点停用不清理）。引擎面消费经普通 `use` 已链接
// rlib，但 inventory/linkme 静态的 linker-section 需要 rlib 被**显式引用**才进
// 二进制（`use <crate> as _;`）。白名单本身已是纯宿主自报（`expected_host_modules`，
// 见 [`host_module_whitelist`]）；桌面宿主另在 `plugin/{http,ws,peer}.rs` 声明
// 这三个模块的期望（其 `common-host` feature 在 src-tauri Cargo 开启），移动
// 不自报（用自有 `host_domains/{http,ws,peer,mdns}` 实现）。
// （`wasmnest-discovery-engine` 的强制引用行随端口 adapter 迁宿主
//  `src-tauri/src/plugin/mdns.rs`；本 crate 不依赖该 crate。）
use wasmnest_server_http as _;
use wasmnest_server_peer_net as _;
use wasmnest_server_websocket as _;

/// 收集已自报的能力模块并与白名单双向比对
fn host_module_registry() -> crate::Result<wasmnest_host_kit::ModuleRegistry> {
    verify_host_module_registry(&host_module_whitelist())
}

/// 白名单校验的可测入口（生产传入 [`host_module_whitelist`]：内建在册 ∪ 宿主自报）
///
/// **为什么多这一层**：失败路径本身必须可测。“能力模块没链上”唯一的信号就是这
/// 条错误，而它只会在真实错配时才出现（平时恒绿）——若只能经 `add_to_linker`
/// 的固定白名单触发，就永远没有用例能证明它真的会红、而且报得可读。
fn verify_host_module_registry(
    whitelist: &[&str],
) -> crate::Result<wasmnest_host_kit::ModuleRegistry> {
    let registry = wasmnest_host_kit::ModuleRegistry::collected();
    registry.verify_whitelist(whitelist).map_err(|e| {
        AppError::Plugin(format!(
            "host capability module whitelist check failed: {e}"
        ))
    })?;
    Ok(registry)
}

/// 将已接线的 import 接口注册到 component linker
///
/// **两段式装配**：
///
/// 1. **core 本地表**：下方那一列 `add_to_linker`——留内核的 interface 逐行列举。
///    域迁出时，其那一行与对应实现一起搬进能力 crate，从此由第 2 段接管。
///    （「逐接口硬编码不可接受」的判据针对**可独立组合的能力实现**，那类一律走
///    第 2 段；core 这些是 POSIX 原生面与通信机制，与宿主进程同生命周期。）
/// 2. **能力模块自动注册**：迁出的域经 `inventory` 自报，这里一次遍历装完。
///
/// 每个接口一个 `add_to_linker`（`HasSelf<T>` 让 getter 返回 `&mut T`）。
///
/// `wasi_cfg`：WASI 面开关（`CoreConfig::wasi`，默认全开）。注册在此**一次固化**
/// ——运行期 `set_config` 改不动已建 linker（见 `WasmRuntime::set_config` 的 warn）。
pub(crate) fn add_to_linker(
    linker: &mut Linker<WasmPluginState>,
    wasi_cfg: &WasiConfig,
) -> crate::Result<()> {
    // 第一段：core 交集 8 域（票 03 Option A 收口进 `core_binding`——双端唯一一份，
    // 绑契约真源 `wit/core.wit` 的 `world core`，不经端生成物）。本壳不再逐行列举。
    crate::manager::runtime::core_binding::add_to_linker(linker)?;
    // 第二段：自动收集到的能力模块（迁出 wasm_core 的域）。当前白名单为空 ⇒ 空转，
    // mdns 域迁出后此处一次装完，**宿主装配代码不再改动**。
    host_module_registry()?
        .install_all(linker)
        .map_err(|e| AppError::Plugin(format!("host capability module install failed: {e}")))?;
    // 第三段：WASI p2/p3（双端同源的核心装配面，用户裁决 2026-10-12；实现与判据见
    // `manager::runtime::wasi::add_to_linker`——含「同步 adapter 在 async store 下
    // 重入 panic ⇒ 用 async adapter」的实证注释）。
    wasi::add_to_linker(linker, wasi_cfg)?;
    // 票 04：本函数至此不再有 `#[cfg(test)]` 分支——cap 域（含桌面扩展三接口）的
    // `Host` impl 全在宿主（`src-tauri/src/plugin/`），内核测试二进制经宿主集成
    // 测试覆盖夹具功能态（原四个内核测试替身已随用例迁宿主删除）。
    Ok(())
}

// ==================== 组件插件实例 ====================

/// 实例元数据：宿主侧只读投影（票 06 §5.1，与 Store/Instance 的所有权分离）
///
/// 拆分动机（调用模型无关）：`mutex` 与 `event-loop` 两种模型下宿主侧都需要
/// **不进实例**就能读到这些量——导出能力探测结果、WASI 预打开目录、创建时刻
/// 都在实例化期一次确定后不再变化。`event-loop` 模型的 Store 归属主任务独占，
/// 宿主侧若还要「锁实例读元数据」就等于开出第二个 Store 入口（破坏 I1）。
#[derive(Clone)]
pub(crate) struct InstanceMeta {
    /// 插件 ID
    pub(crate) plugin_id: String,
    /// 实例化时实际预打开成功的主机目录（manifest 声明 ∩ 当时已授权 ∩ 创建成功）
    ///
    /// 激活时宿主据此判断「新授权目录是否已纳入本次实例」：声明了 WASI 预打开
    /// 目录的插件首次启用时授权发生在 activate() 内部（fs_request_auth 弹窗），
    /// 早于实例化；重试激活时若当前实例未覆盖新授权目录则需重建（见 host.rs
    /// `rebuild_wasm_instance`），使 /data 挂载与授权状态一致。
    pub(crate) preopened_dirs: Vec<String>,
    /// 实例化时探测到的可路由能力接口导出（core-plugin-manager，如
    /// `host-storage`）；空 = 纯应用插件（不提供能力），非空者激活时由
    /// PluginHost 注册进能力注册表（系统组件装配）
    pub(crate) exported_capabilities: Vec<String>,
    /// 实例创建时刻（Drop 日志计算存活时长）
    pub(crate) created_at: std::time::Instant,
}

/// 可选导出句柄快照（实例化期动态探测结果，Copy；属主任务取用）
///
/// 与 store 内同一批句柄同源：`mutex` 模型在调用栈内直接读 store 数据，
/// `event-loop` 模型在进入属主作用域前一次性取出（作用域内只能拿到 `&Accessor`）。
///
/// 消费方在桌面装配面（`manager/host` 属主路径）；移动形态不消费，
/// 单形态共享故保留 + 按形态豁免
#[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) struct OptionalExports {
    pub(crate) on_message_binary:
        Option<wasmtime::component::TypedFunc<(String, String, Vec<u8>), ()>>,
    pub(crate) on_ws_message: Option<wasmtime::component::TypedFunc<(String, String, Vec<u8>), ()>>,
    pub(crate) on_ws_client_message:
        Option<wasmtime::component::TypedFunc<(String, String, String, Vec<u8>), ()>>,
    pub(crate) on_task_event: Option<wasmtime::component::TypedFunc<(String,), ()>>,
}

/// 已加载的组件形态 WASM 插件（阶段 C 后唯一形态）
///
/// 持有 component Instance + Store，全部调用走 bindgen 生成的类型化接口
/// （无 (ptr,len) 内存搬运）。Store 必须与 Instance 一起持有，
/// 否则导出函数无法调用。
///
/// 调用模型（票 06）：本结构是 `mutex` 模型下的实例锁内容物；`event-loop`
/// 模型下整个结构被移动进属主任务（持有 `&mut Store` 的唯一位置），宿主侧
/// 只保留 [`InstanceMeta`] 副本。
pub struct LoadedWasmPlugin {
    meta: InstanceMeta,
    instance: Instance,
    store: Store<WasmPluginState>,
    /// 端专属 guest 事件派发器（票 03 / ADR 0022：机制留内核、契约面上移）
    ///
    /// 与 [`WasmRuntime`] **共享同一槽位**而非实例化时快照：`PluginHost::new`
    /// 会在宿主注入之前扫描即实例化（无头 harness 同序），快照会让这批实例
    /// 永远停在 `UnwiredGuestEvents`。晚绑定使装配期注入对已建实例同样生效，
    /// 派发时实时读取；未注入时槽内仍是 `UnwiredGuestEvents`（fail-visible）。
    /// 本壳不知道 `events` 导出在各端长什么样，只把 `(Store, Instance)` 与消息
    /// 交给宿主侧实现。
    guest_events: Arc<std::sync::RwLock<Arc<dyn GuestEventDispatcher>>>,
}

impl Drop for LoadedWasmPlugin {
    /// 实例死亡日志：Store 被 drop（停用 / 热重载替换 / 应用退出 / 异常清理）时记录，
    /// 与创建日志（`WasmRuntime::instantiate_component`）成对，构成实例生命周期观测。
    /// Drop 内无锁操作，tracing 安全。日志实现见 [`engine::log_instance_dropped`]。
    fn drop(&mut self) {
        engine::log_instance_dropped(&self.meta.plugin_id, self.meta.created_at.elapsed());
    }
}

impl LoadedWasmPlugin {
    /// 实例化组件
    ///
    /// 与 core 路径相同的防护：资源限制、燃料看门狗、ABI 版本协商
    /// （组件必须声明 form=1，版本号语义不变）
    ///
    /// `wasi_cfg`：WASI 面开关（`CoreConfig::wasi`）——关时不给预打开能力
    /// （空上下文），与「无声明」同形（装配真源 `manager::runtime::wasi`）。
    pub(crate) fn new(
        engine: &wasmtime::Engine,
        component_linker: &Linker<WasmPluginState>,
        component: &Component,
        plugin_id: &str,
        host_ctx: Arc<WasmHostContext>,
        declared_preopen_dirs: &[WasiPreopenDir],
        wasi_cfg: &WasiConfig,
        spec: StoreSpec,
        abi: AbiPolicy,
        guest_events: Arc<std::sync::RwLock<Arc<dyn GuestEventDispatcher>>>,
    ) -> crate::Result<Self> {
        // WASI 上下文：按 manifest 声明（wasiPreopenDirs，展开+授权过滤）预打开
        // 目录 /data…；无声明/未授权/配置关闭时为空上下文
        let (wasi_ctx, preopened_dirs) =
            wasi::build_ctx(&host_ctx, plugin_id, declared_preopen_dirs, wasi_cfg);
        let state = WasmPluginState::new(plugin_id.to_string(), host_ctx, wasi_ctx, spec);
        // Store 装配（limiter 接线 + 首调用燃料注入）走引擎模块的唯一一份
        let mut store = engine::new_store(engine, state)?;

        // 票 02：CM_ASYNC 引擎下实例化必须走 async 入口（wasip3 组件导入 async
        // wasi 0.3 函数，同步 instantiate 报 async-required）；同步组件在
        // instantiate_async 下行为等价。形态差异经 `InstantiateMode` 表达，机制
        // 本体在引擎模块（fiber 驱动见 `block_on_async`）。
        let instance = engine::instantiate(
            &mut store,
            component_linker,
            component,
            engine::InstantiateMode::Async,
        )
        .map_err(|e| {
            // v27（票 10）：**旧 SDK 产物的失败形态必须可诊断**。ABI 破坏性变更
            // （删 `host-session` / `host-terminal` 两个 import、删 `terminal-hooks`
            // 导出）后，旧产物在**实例化**阶段就会失败（找不到 import 的实现），
            // 早于 `verify_abi` 的版本协商——wasmtime 的报错本身点名了缺失的
            // interface，这里补一句「按哪个版本重建」，避免运维把它当成 trap 或
            // 插件损坏。
            AppError::Plugin(format!(
                "Failed to instantiate WASM component for plugin '{}': {}{}",
                plugin_id,
                e,
                Self::stale_artifact_rebuild_hint(&e.to_string())
            ))
        })?;

        Self::verify_abi(&mut store, &instance, abi)?;

        // core-plugin-manager：探测能力接口导出（系统组件据此注册为
        // 能力提供者；含票 12 auth-policy 仅探测能力——所有新 SDK 插件默认
        // 导出（拒绝实现），宿主中间件只消费认证中心实例）
        let exported_capabilities =
            crate::manager::capability::probe_exported_capabilities(&instance, &mut store);
        if !exported_capabilities.is_empty() {
            tracing::info!(
                plugin_id = %plugin_id,
                capabilities = ?exported_capabilities,
                "WASM component exports capability interface(s)"
            );
        }

        Ok(Self {
            meta: InstanceMeta {
                plugin_id: plugin_id.to_string(),
                preopened_dirs,
                exported_capabilities,
                created_at: std::time::Instant::now(),
            },
            instance,
            store,
            guest_events,
        })
    }

    /// 实例元数据引用（宿主侧只读投影；调用模型两侧共用）
    ///
    /// 消费方在桌面装配面（`manager/host` 属主路径）；移动形态不消费，
    /// 单形态共享故保留 + 按形态豁免
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn meta(&self) -> &InstanceMeta {
        &self.meta
    }

    // ==================== 属主化访问器（票 06，`event-loop` 模型用） ====================
    //
    // 属主任务在 `run_concurrent` 之外需要预先取出这些量（进入作用域后只能经
    // `&Accessor` 触达 store，无法再 `&mut self`）：Instance 句柄（Copy）、指标句柄、
    // 燃料规格、可选导出句柄（Copy）。

    /// 组件实例句柄（Copy；`get_typed_func` / `start_call_concurrent` 用）
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn instance_handle(&self) -> Instance {
        self.instance
    }

    /// Store 可变引用（属主任务以 `&mut store` 调 `run_concurrent`，常驻作用域）
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn store_mut(&mut self) -> &mut Store<WasmPluginState> {
        &mut self.store
    }

    /// 插件指标句柄（调用计时 / 生命周期记账 / 燃料记账入口）
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn metrics(&self) -> Arc<crate::monitor::PluginMetrics> {
        self.store.data().metrics.clone()
    }

    /// 燃料规格快照 `(enabled, budget)`（Store 内已固化，实例生命周期内不变）
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn fuel_spec(&self) -> (bool, u64) {
        let state = self.store.data();
        (
            state.fuel_enabled,
            state
                .limits
                .fuel_budget_for(crate::config::plugin_debug_mode()),
        )
    }

    /// 可选导出句柄快照（v11 / v14 / v20 动态探测结果；未导出 → None）
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn optional_exports(&self) -> OptionalExports {
        let state = self.store.data();
        OptionalExports {
            on_message_binary: state.on_message_binary,
            on_ws_message: state.on_ws_message,
            on_ws_client_message: state.on_ws_client_message,
            on_task_event: state.on_task_event,
        }
    }

    /// 本次实例实际预打开成功的主机目录（空 = 无声明 / 未授权 / 创建失败）
    ///
    /// 宿主激活时的预打开目录漂移判定自票 06 起直接读装配条目的
    /// [`InstanceMeta::preopened_dirs`]（属主模型下不允许「锁实例读元数据」——
    /// 那是第二个 Store 入口）；本访问器保留给直接持有实例的测试。
    /// **仅 worker 类别可达**（ADR 0034）：非 worker 声明 preopen 已被加载期闸门拒绝。
    #[allow(dead_code)]
    pub(crate) fn preopened_dirs(&self) -> &[String] {
        &self.meta.preopened_dirs
    }

    /// 旧 SDK 产物的实例化失败判据 → 重建指引（空串 = 不是这个原因，不加噪音）
    ///
    /// 本项目迄今的破坏性契约变更（均在**实例化阶段**失败——比 `verify_abi`
    /// 的版本协商更早）：
    /// - **v27**：删了两个 import interface（`host-session` / `host-terminal`）与一个
    ///   export interface（`terminal-hooks`）；
    /// - **v28**：`host-events.broadcast-sync` 函数退役（websocket 业务下沉票 08——
    /// 旧 SDK 产物的实例化失败判据 → 重建指引（空串 = 不是这个原因，不加噪音）
    ///
    /// 项目不承担 ABI 向后兼容义务（研发起步期无外部公开契约，AGENTS.md §0）：破坏性
    /// 契约变更（删 import/export interface）在**实例化阶段**即失败——比 `verify_abi`
    /// 的版本协商更早。组件模型不提供「向后兼容的缺省 import」，失败本身不可避免，
    /// 本条只负责把失败**可诊断**：wasmtime 原文点名缺失的 import/export（文案形态
    /// 「unknown import \`…\` has not been defined」、「… matching implementation
    /// was not found in the linker」、「component does not export …」），这里补一句
    /// 统一的「按当前 SDK 重建」指引。
    ///
    /// 不再按历史 ABI 版本枚举判据矩阵（v27/v28/v31/v33/v36/v37… 逐版文案与「升级
    /// WasmNest」反向分支）：研发起步期无契约旧产物在库，「哪个版本、重建到哪个版本」
    /// 的细节没有诊断对象，保留矩阵只会随每次删项累积维护负担。判据收敛为 wasmtime
    /// 的「缺失 import/export」通用文案，命中则给通用重建指引；与契约无关的失败
    /// （WASI 缺目录 / trap）返回空串，避免噪音掩盖真因。
    ///
    /// 抽成自由函数是为了可单测：判据是「错误文本 → 是否附指引」，与 Store 无关。
    pub(super) fn stale_artifact_rebuild_hint(instantiate_error: &str) -> String {
        // 判据锚 = wasmtime 组件实例化期的缺失 import/export 文案：
        // - `unknown import \`...\` has not been defined`（单函数/import 缺实现形态）
        // - `... matching implementation was not found in the linker`（import instance 形态）
        // - `component does not export ...`（缺必选导出形态）
        // 三者之外的失败（WASI 缺目录、trap、认证文案等）与旧契约无关，不加噪音。
        let is_stale_contract = instantiate_error.contains("has not been defined")
            || instantiate_error.contains("not found in the linker")
            || instantiate_error.contains("component does not export");
        if !is_stale_contract {
            return String::new();
        }
        "（该产物由其他插件协议（ABI）的插件 SDK 构建，请用当前 SDK 重建插件产物）".to_string()
    }
    /// **只检查形态**（ADR 0051 D2：整数 ABI 协商随 wit 包版本化退役）：
    /// - `abi-form.form()` 必须等于 [`AbiPolicy::form`] 要求值（桌面 = 1（component
    ///   形态）；移动 WIT 无 `abi-form` 导出 ⇒ 宿主注入 `form: None` = 不要求）
    /// - 版本不在此检查：宿主与 guest 的 `package wasmnest:plugin@<version>` 不等时，
    ///   linker 在实例化期即拒绝（import 名逐字匹配），失败文案自带包名与版本
    fn verify_abi(
        store: &mut Store<WasmPluginState>,
        instance: &Instance,
        abi: AbiPolicy,
    ) -> crate::Result<()> {
        // 本路径不经 exports()（实例化后立即校验），独立重置燃料
        engine::inject_call_fuel(store)?;

        // 形态检查（版本协商已随 wit 包版本化退役，ADR 0051 D2）：`abi-form.form()`
        // 无 `result` 返回（`() -> u32`），**可以**原生探测——与 `events.*` 那类带
        // `result` 的导出不同（`Result` 不实现 `ComponentNamedList`，原生 TypedFunc
        // 表达不了，见 ticket-03 §9.6）。版本一致性由 wasmtime linker 的含版本
        // import 名匹配保证：不等即实例化期被拒，诊断自带包名 + 版本。（`abi-form` 是桌面 cap 导出；移动 WIT 无此导出，宿主注入
        // `form: None` 即跳过——统一壳按注入规格检查，wasm-core 零端形态知识）
        if let Some(expected_form) = abi.form {
            let form = crate::manager::runtime::core_binding::abi_form(store, instance)?
                .ok_or_else(|| {
                    AppError::Plugin(
                        "WASM component missing required export `abi-form.form` \
                         （该产物由其他插件协议（ABI）的插件 SDK 构建，请用当前 SDK 重建插件产物）"
                            .to_string(),
                    )
                })?;
            if form != expected_form {
                return Err(AppError::Plugin(format!(
                    "WASM component for plugin declares abi form {} (expected {})",
                    form, expected_form
                )));
            }
        }

        // v11：动态探测可选导出 events-binary#on-message-binary。该接口不声明进
        // plugin world（旧插件必选导出会因缺失而实例化失败），此处按名探测，
        // 缺失容忍为 None——旧插件只收 JSON，二进制消息由总线按格式不匹配拒绝。
        // 必须用 ItemName 路径语法（`iface.func` 点号）：组件的接口导出是嵌套
        // 实例形态，`iface#func` 平名字符串的 str 查找恒不命中（wasmtime 47 实证，
        // 票据 06 修复——此前平名探测恒返回 None，二进制导出从未真正被发现）
        let on_message_binary = crate::contract::export_item("events-binary", "on-message-binary")
            .parse::<wasmtime::component::wit_parser::ItemName>()
            .ok()
            .and_then(|item| {
                instance
                    .get_typed_func::<(String, String, Vec<u8>), ()>(&mut *store, &item)
                    .ok()
            });
        store.data_mut().on_message_binary = on_message_binary;

        // v14：动态探测可选导出 events-ws（两条回调分别探测，缺失容忍为 None）。
        // 语义与 events-binary 同构：未导出 → 状态事件照收（bus），消息帧丢弃 +
        // 首次 warn + 计数（宿主不缓存，spec §2.2 D2）；旧插件加载零回归。
        // 同样必须用 ItemName 路径语法（`iface.func` 点号），理由同上
        let on_ws_message = crate::contract::export_item("events-ws", "on-message")
            .parse::<wasmtime::component::wit_parser::ItemName>()
            .ok()
            .and_then(|item| {
                instance
                    .get_typed_func::<(String, String, Vec<u8>), ()>(&mut *store, &item)
                    .ok()
            });
        let on_ws_client_message = crate::contract::export_item("events-ws", "on-client-message")
            .parse::<wasmtime::component::wit_parser::ItemName>()
            .ok()
            .and_then(|item| {
                instance
                    .get_typed_func::<(String, String, String, Vec<u8>), ()>(&mut *store, &item)
                    .ok()
            });
        let data = store.data_mut();
        data.on_ws_message = on_ws_message;
        data.on_ws_client_message = on_ws_client_message;

        // v20：动态探测可选导出 events-task#on-task-event（宿主并发任务进度/终态
        // 回调）。语义同 events-binary / events-ws：旧 SDK 产物未导出 → None，
        // 消费任务内降级（事件丢弃 + 首次 warn + 计数，宿主不缓存）；新 SDK
        // 产物由 wasm_entry! 无条件导出默认空实现 → 探测命中。
        // 同样必须用 ItemName 路径语法（`iface.func` 点号），理由同 events-ws
        let on_task_event = crate::contract::export_item("events-task", "on-task-event")
            .parse::<wasmtime::component::wit_parser::ItemName>()
            .ok()
            .and_then(|item| {
                instance
                    .get_typed_func::<(String,), ()>(&mut *store, &item)
                    .ok()
            });
        store.data_mut().on_task_event = on_task_event;
        Ok(())
    }

    /// 单次调用燃料预算续费（世界导出与能力转发调用共用）：
    /// 实现见 [`engine::refill_call_fuel`]（双端唯一一份）
    fn refill_call_fuel(&mut self) -> crate::Result<()> {
        engine::refill_call_fuel(&mut self.store)
    }

    /// 获取 **core 交集** 导出绑定（command / lifecycle / manifest）
    ///
    /// 与 [`Self::exports`] 的分工：core 交集导出走 `runtime::core_binding` 的
    /// 绑定（双端单份，绑契约真源 `world core`），cap 导出（`events` 等，各端
    /// 形状不同）仍走本壳自有绑定。两者对**同一个** `Instance` 建视图，
    /// 不重复实例化、互不影响。
    ///
    /// 燃料续费语义与 [`Self::exports`] 同（单次调用预算，宿主阻塞期不消耗）。
    fn core_exports(
        &mut self,
    ) -> crate::Result<crate::manager::runtime::core_binding::CoreExports> {
        self.refill_call_fuel()?;
        crate::manager::runtime::core_binding::exports(&mut self.store, &self.instance)
    }

    /// 能力导出调用（core-plugin-manager 装配框架）：按名动态获取组件的
    /// 能力接口导出函数并调用，燃料预算续费语义同 [`Self::exports`]。
    ///
    /// 宿主侧转发专用：能力注册表命中系统组件提供者时，宿主侧域函数
    /// 把应用插件的 import 调用经此方法转发到提供者的同形导出。
    /// 外层 Err = trap/导出缺失等传输层错误；内层 `Results` 元组含 WIT
    /// `result<T, string>` 本体（guest 自报错误），两层语义分离。
    ///
    /// `export_name` 用 `ItemName` 路径语法（`pkg:ns/iface.func`，组件接口
    /// 导出为嵌套实例形态，平名 `iface#func` 无法命中）
    /// pub（票 05c）：lib 集成测试（auth_center_perf 探针）直接驱动能力导出
    pub fn call_capability_export<Params, Results>(
        &mut self,
        export_name: &str,
        params: Params,
    ) -> crate::Result<Results>
    where
        Params: wasmtime::component::ComponentNamedList + wasmtime::component::Lower + Send,
        // async 调用经 block_on_async 驱动：未来输出（Results）需 'static + Send，
        // Params 移入未来需 Send（能力转发代调用方均为 'static 元组，见 capability.rs）
        Results:
            wasmtime::component::ComponentNamedList + wasmtime::component::Lift + Send + 'static,
    {
        let _timer = self.track_call();
        self.refill_call_fuel()?;
        let item: wasmtime::component::wit_parser::ItemName = export_name.parse().map_err(|e| {
            AppError::Plugin(format!(
                "invalid capability export name: {} ({})",
                export_name, e
            ))
        })?;
        let func = self
            .instance
            .get_typed_func::<Params, Results>(&mut self.store, &item)
            .map_err(|e| {
                AppError::Plugin(format!(
                    "capability export not found: {} ({})",
                    export_name, e
                ))
            })?;
        block_on_async(async { func.call_async(&mut self.store, params).await }).map_err(|e| {
            AppError::Plugin(format!("capability call failed: {} ({})", export_name, e))
        })
    }

    /// 实例化时探测到的可路由能力接口导出（core-plugin-manager）；
    /// 空 = 纯应用插件（不提供能力）
    ///
    /// 宿主侧（认证中心候选 / 系统组件装配）自票 06 起直接读装配条目的
    /// [`InstanceMeta::exported_capabilities`]，本访问器保留给测试。
    #[allow(dead_code)]
    /// pub（票 05b）：lib 集成测试断言实例导出能力集（system_component_test）
    pub fn exported_capabilities(&self) -> &[String] {
        &self.meta.exported_capabilities
    }

    /// 导出调用计时起点（core-monitor 埋点）：返回的 RAII 计时器在
    /// 方法返回时落账（次数/耗时直方图）。每导出方法首行调用；实现见
    /// [`engine::start_call_timer`]
    fn track_call(&self) -> crate::monitor::CallTimer {
        engine::start_call_timer(&self.store)
    }

    /// 调用插件的 activate 导出
    /// pub（票 05b）：lib 集成测试（session_e2e）直接驱动真实产物激活
    pub fn activate(&mut self) -> crate::Result<i32> {
        let _timer = self.track_call();
        // 激活耗时单独记账：调用聚合含 `activate`，但监控页需要把「启动成本」
        // 与平时命令调用分开看（激活失败也要落账，否则失败样本消失）
        let started = std::time::Instant::now();
        let outcome = (|| -> crate::Result<i32> {
            let exports = self.core_exports()?;
            let lifecycle = exports.wasmnest_plugin_lifecycle();
            match block_on_async(async { lifecycle.call_activate(&mut self.store).await }) {
                Ok(Ok(())) => {
                    self.store
                        .data()
                        .metrics
                        .record_lifecycle(LifecycleEvent::ActivateOk);
                    Ok(0)
                }
                Ok(Err(msg)) => {
                    self.store
                        .data()
                        .metrics
                        .record_lifecycle(LifecycleEvent::ActivateFail);
                    Err(AppError::Plugin(format!("WASM activate() failed: {}", msg)))
                }
                Err(e) => {
                    self.store
                        .data()
                        .metrics
                        .record_lifecycle(LifecycleEvent::ActivateFail);
                    Err(engine::trapped(&self.store, "activate", e))
                }
            }
        })();
        self.store
            .data()
            .metrics
            .record_activation(started.elapsed().as_micros() as u64);
        outcome
    }

    /// 调用插件的 deactivate 导出
    /// pub（票 05b）：lib 集成测试直接驱动真实产物停用
    pub fn deactivate(&mut self) -> crate::Result<i32> {
        let _timer = self.track_call();
        let exports = self.core_exports()?;
        let lifecycle = exports.wasmnest_plugin_lifecycle();
        match block_on_async(async { lifecycle.call_deactivate(&mut self.store).await }) {
            Ok(Ok(())) => {
                self.store
                    .data()
                    .metrics
                    .record_lifecycle(LifecycleEvent::Deactivate);
                Ok(0)
            }
            Ok(Err(msg)) => Err(AppError::Plugin(format!(
                "WASM deactivate() failed: {}",
                msg
            ))),
            Err(e) => Err(engine::trapped(&self.store, "deactivate", e)),
        }
    }

    /// 调用插件的 invoke_command 导出（JSON 载荷保留，语义与 core 路径 1:1）
    /// pub（票 05b）：lib 集成测试经插件命令面驱动被测行为
    pub fn invoke_command(&mut self, command_name: &str, args_json: &str) -> crate::Result<String> {
        let _timer = self.track_call();
        let exports = self.core_exports()?;
        let cmd = exports.wasmnest_plugin_command();
        match block_on_async(async {
            cmd.call_invoke(&mut self.store, command_name, args_json)
                .await
        }) {
            Ok(v) => Ok(v),
            Err(e) => Err(engine::trapped(&self.store, "invoke_command", e)),
        }
    }

    // v27（票 10 删除的 `on_terminal_input` / `on_terminal_output`）：
    // 对应的 `terminal-hooks` interface 已从 WIT world 删除（票 03 起它已无派发源：
    // 逐帧输入修饰链与终端输出修饰链都不再由宿主调用）。宿主要求的导出集因此少一个
    // interface，SDK 侧对应绑定与缺口说明见 `packages/plugin-sdk-desktop/rust`。

    /// 调用插件的 on_startup 导出
    ///
    /// 双层 Result 语义：外层 = 调用本身失败（trap / 导出缺失 / 燃料耗尽），
    /// 内层 = guest 报告的启动初始化结果（v8 契约 `result<_, string>`）。
    /// 宿主据此区分「插件自报启动失败 → Degraded」与「调用故障」
    pub fn on_startup(&mut self) -> crate::Result<std::result::Result<(), String>> {
        let _timer = self.track_call();
        let exports = self.core_exports()?;
        let lifecycle = exports.wasmnest_plugin_lifecycle();
        match block_on_async(async { lifecycle.call_on_startup(&mut self.store).await }) {
            Ok(v) => Ok(v),
            Err(e) => Err(engine::trapped(&self.store, "on_startup", e)),
        }
    }

    /// 调用插件的 on_shutdown 导出
    ///
    /// 双层 Result 语义同 [`Self::on_startup`]；停用流程对 guest 报告的
    /// 清理失败仅记录，不影响状态机
    pub fn on_shutdown(&mut self) -> crate::Result<std::result::Result<(), String>> {
        let _timer = self.track_call();
        let exports = self.core_exports()?;
        let lifecycle = exports.wasmnest_plugin_lifecycle();
        match block_on_async(async { lifecycle.call_on_shutdown(&mut self.store).await }) {
            Ok(v) => Ok(v),
            Err(e) => Err(engine::trapped(&self.store, "on_shutdown", e)),
        }
    }

    /// 调用插件的消息总线消息接收导出
    ///
    /// 取当前 guest 事件派发器（晚绑定共享槽，见字段注释）
    ///
    /// 先 clone 出 `Arc` 再离开读锁：派发会进 guest（长调用），没有必要持锁跨调用，
    /// 也避免与装配期 `set_guest_events` 的写锁互相阻塞。
    fn dispatcher(&self) -> Arc<dyn GuestEventDispatcher> {
        self.guest_events
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 派发委托给宿主注入的 [`GuestEventDispatcher`]（票 03 / ADR 0022）：本壳不
    /// 持有 `events` 绑定。调用计时与燃料续费仍留机制侧。
    pub fn on_message(
        &mut self,
        topic: &str,
        sender: &str,
        payload: &serde_json::Value,
    ) -> crate::Result<()> {
        let _timer = self.track_call();
        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        self.refill_call_fuel()?;
        let instance = self.instance;
        let dispatcher = self.dispatcher();
        dispatcher.on_message(&mut self.store, instance, topic, sender, &payload_str)
    }

    /// 调用插件的消息总线二进制消息接收导出（v11，可选导出动态探测）
    ///
    /// 仅当实例在实例化时探测到 `events-binary#on-message-binary` 导出才可调用；
    /// 总线侧已按订阅者格式偏好过滤，正常不会对无导出的实例发起本调用，
    /// 此处防御性拒绝（旧插件二进制 → 格式不匹配拒绝的语义由总线保证）
    pub fn on_message_binary(
        &mut self,
        topic: &str,
        sender: &str,
        payload: &[u8],
    ) -> crate::Result<()> {
        let _timer = self.track_call();
        // 燃料续费：本方法不经 `exports()`（直接持探测句柄调用），必须自带
        // 续费，否则本回调的燃料跨调用累积耗尽 → trap → Store 中毒 → 自动重载
        self.refill_call_fuel()?;
        // TypedFunc 先 clone 再调用，避免与 &mut self.store 的借用冲突
        let Some(func) = self.store.data().on_message_binary.clone() else {
            return Err(AppError::Plugin(format!(
                "WASM plugin has no events-binary export (v11 required)"
            )));
        };
        // 无返回值（观察型回调）：guest 内部失败经 host-log 记录；此处仅 trap 上抛
        block_on_async(async {
            func.call_async(
                &mut self.store,
                (topic.to_string(), sender.to_string(), payload.to_vec()),
            )
            .await
        })
        .map_err(|e| engine::trapped(&self.store, "on_message_binary", e))
    }

    /// 调用插件的 WS 帧接收导出（v14，可选导出动态探测）
    ///
    /// 返回 `Ok(true)` = 已投递；`Ok(false)` = 该回调未导出——调用方按 spec §2.2
    /// 降级（丢弃 + 首次 warn + 计数，宿主不缓存）。无返回值（观察型回调）：
    /// guest 内部失败经 host-log 记录；此处仅 trap 上抛
    pub fn on_ws_frame(&mut self, frame: &crate::bus::WsFrameDispatch) -> crate::Result<bool> {
        use crate::bus::WsFrameDispatch;
        let _timer = self.track_call();
        // 燃料续费：同 on_message_binary——不经 exports()，须自带续费
        self.refill_call_fuel()?;
        match frame {
            WsFrameDispatch::Client {
                handle,
                kind,
                payload,
            } => {
                // TypedFunc 先 clone 再调用，避免与 &mut self.store 的借用冲突
                let Some(func) = self.store.data().on_ws_message.clone() else {
                    return Ok(false);
                };
                block_on_async(async {
                    func.call_async(
                        &mut self.store,
                        (handle.clone(), kind.clone(), payload.clone()),
                    )
                    .await
                })
                .map_err(|e| engine::trapped(&self.store, "on_ws_message", e))?;
                Ok(true)
            }
            WsFrameDispatch::EndpointClient {
                endpoint_id,
                client_id,
                kind,
                payload,
            } => {
                let Some(func) = self.store.data().on_ws_client_message.clone() else {
                    return Ok(false);
                };
                block_on_async(async {
                    func.call_async(
                        &mut self.store,
                        (
                            endpoint_id.clone(),
                            client_id.clone(),
                            kind.clone(),
                            payload.clone(),
                        ),
                    )
                    .await
                })
                .map_err(|e| engine::trapped(&self.store, "on_ws_client_message", e))?;
                Ok(true)
            }
        }
    }

    /// 调用插件的宿主并发任务事件导出（v20，可选导出动态探测）
    ///
    /// 返回 `Ok(true)` = 已投递；`Ok(false)` = 该回调未导出——消费派发任务按
    /// spec §5.3 降级（事件丢弃 + 首次 warn + 计数，宿主不缓存；`status`/
    /// `list-jobs` 自愈）。无返回值（观察型回调，同 `on_ws_frame`）。
    ///
    /// pub（票 02 批次 05）：宿主集成测试 `tests/task_e2e.rs` 直驱 SDK 回调链
    /// （dispatch → on_task_event → events-task 导出 → fixture 收集）——迁移前
    /// 内核 task_e2e 在 lib 内直调同款；与 `activate` / `invoke_command` 的
    /// 集成测试公开面先例同口径。
    pub fn on_task_event(&mut self, event_json: &str) -> crate::Result<bool> {
        let _timer = self.track_call();
        // 燃料续费：同 on_message_binary——不经 exports()，须自带续费
        self.refill_call_fuel()?;
        // TypedFunc 先 clone 再调用，避免与 &mut self.store 的借用冲突
        let Some(func) = self.store.data().on_task_event.clone() else {
            return Ok(false);
        };
        block_on_async(async {
            func.call_async(&mut self.store, (event_json.to_string(),))
                .await
        })
        .map_err(|e| engine::trapped(&self.store, "on_task_event", e))?;
        Ok(true)
    }

    // v27（票 10 删除的 `on_session_lifecycle` / `on_input_submitted`）：
    // `events` interface 里的这两个导出已从 WIT world 删除。派发源在票 03 就没了
    // （宿主侧观察注册表 + 派发点退役），留着「实现了但永不触发」的导出正是票 03
    // 明确禁止的状态。会话生命周期事实由插件自驱、跨插件事件走 `host-events` /
    // `host-bus`。`on-message` / `on-process-done` 仍是必选导出，保留。

    /// 调用插件的进程执行完成事件导出（host-process，v8）
    pub fn on_process_done(&mut self, payload_json: &str) -> crate::Result<()> {
        let _timer = self.track_call();
        self.refill_call_fuel()?;
        let instance = self.instance;
        let dispatcher = self.dispatcher();
        dispatcher.on_process_done(&mut self.store, instance, payload_json)
    }

    /// 调用插件的生命周期事件导出（移动端 `PluginLifecycleEvent` 枚举 → 导出映射）
    ///
    /// 映射表：AppStartup/AppShutdown → `lifecycle.on-startup/on-shutdown`（core 绑定）；
    /// AuthSuccess → `events.on-auth-success`；Disconnect → `events.on-disconnect`；
    /// SessionCreated/SessionStopped → `events.on-session-created/on-session-stopped`
    /// （后四者是**移动独有导出**，经宿主注入的派发器投递；桌面 events 词汇不同，
    /// 该方法在桌面不调用——同一 `GuestEventDispatcher` trait 双端各自实现）。
    pub fn call_lifecycle_event(
        &mut self,
        event: &crate::manager::types::PluginLifecycleEvent,
    ) -> crate::Result<()> {
        use crate::manager::types::PluginLifecycleEvent;
        // 事件导出同样消耗 guest 燃料：派发前续费（与 on_bus_message 同款；
        // AppStartup/AppShutdown 走 lifecycle 导出，其续费在 exports() 内）
        match event {
            PluginLifecycleEvent::AppStartup => self.on_startup().and_then(|inner| {
                inner.map_err(|msg| AppError::Plugin(format!("WASM on_startup() failed: {}", msg)))
            }),
            PluginLifecycleEvent::AppShutdown => self.on_shutdown().and_then(|inner| {
                inner.map_err(|msg| AppError::Plugin(format!("WASM on_shutdown() failed: {}", msg)))
            }),
            PluginLifecycleEvent::AuthSuccess => {
                self.refill_call_fuel()?;
                let instance = self.instance;
                let dispatcher = self.dispatcher();
                dispatcher.on_auth_success(&mut self.store, instance)
            }
            PluginLifecycleEvent::Disconnect { reason } => {
                self.refill_call_fuel()?;
                let instance = self.instance;
                let dispatcher = self.dispatcher();
                dispatcher.on_disconnect(&mut self.store, instance, reason)
            }
            PluginLifecycleEvent::SessionCreated { session_id } => {
                self.refill_call_fuel()?;
                let instance = self.instance;
                let dispatcher = self.dispatcher();
                dispatcher.on_session_created(&mut self.store, instance, session_id)
            }
            PluginLifecycleEvent::SessionStopped { session_id } => {
                self.refill_call_fuel()?;
                let instance = self.instance;
                let dispatcher = self.dispatcher();
                dispatcher.on_session_stopped(&mut self.store, instance, session_id)
            }
        }
    }

    /// 获取插件的 manifest JSON
    #[allow(dead_code)] // 测试覆盖,生产侧 manifest 走其他加载路径
    /// pub（票 05b）：lib 集成测试读插件 manifest（api 清单比对）
    pub fn get_manifest(&mut self) -> crate::Result<String> {
        let _timer = self.track_call();
        let exports = self.core_exports()?;
        let manifest = exports.wasmnest_plugin_manifest();
        match block_on_async(async { manifest.call_get(&mut self.store).await }) {
            Ok(v) => Ok(v),
            Err(e) => Err(engine::trapped(&self.store, "manifest", e)),
        }
    }

    /// 测试访问器：直接获取 Store/Instance（燃料断言与耗尽 trap 测试用）
    ///
    /// 非 `#[cfg(test)]` 门控的原因：宿主集成测试链的是**不带 cfg(test)** 的
    /// 本 crate——燃料 / limiter 记账断言随用例迁宿主机后经
    /// `crate::test_support::plugin_raw_store` 转发消费（该模块是宿主测试的
    /// 唯一转发面，生产跨 crate 仍不可达：pub(crate)）。
    #[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
    pub(crate) fn raw_store(&mut self) -> (&mut Store<WasmPluginState>, &Instance) {
        (&mut self.store, &self.instance)
    }
}

// WASI 预打开装配（build_ctx / resolve_preopen_dirs / expand_preopen_declarations）
// 已迁核心模块 `manager::runtime::wasi`（用户裁决 2026-10-12：WASI 面住核心、
// 双端同源、默认全开、开/关由 CoreConfig::wasi 定）——本壳只剩调用与 re-export。

// ==================== 测试 ====================

#[cfg(test)]
mod tests {

    use super::*;
    // 复用 host_api 测试基建（`crate::host_api::tests` 为 pub(super)，同子树可访问）
    use crate::host_api::grant_permissions;
    use crate::host_api::tests::build_host_ctx;

    /// 造一个**已装配 sqlite 域端口**的无头上下文
    ///
    /// 构建测试引擎：**直接走生产构建函数**（`engine::build_engine_config` +
    /// 编译期默认 `CoreConfig`），不再在测试里手工重摆一遍 fuel / backtrace /
    /// 内存预留——手工副本会与生产配置漂移（历史上移动形态就因为各钉一份字面量
    /// 而漏掉了 debug 放大倍率与 backtrace 帧数），且 `Store::set_fuel` 在
    /// consume_fuel 未开启时会在实例化直接报错，trap 错误串形态也会与生产不一致。
    fn test_engine() -> wasmtime::Engine {
        let core_config = crate::config::CoreConfig::default();
        let config = engine::build_engine_config(&core_config, crate::config::plugin_debug_mode());
        wasmtime::Engine::new(&config).expect("create test engine")
    }

    // 组件往返用例与 `build_test_component` 构建器随票 04 迁桌面宿主
    // `src-tauri/tests/{component_e2e,engine_e2e}.rs`（wasm-core 不再持全 world
    // 绑定 ⇒ 本测试二进制无法实例化 SDK 夹具）；夹具构建由桌面宿主
    // `src-tauri/tests/fixture_keeper.rs` 负责（票 08 批次三：构建器随夹具 crate
    // 归位平台仓，内核只持自持夹具 `fixtures/*`）。

    // ==================== 分片测试（common/component/tests/） ====================
    //
    // 自本文件的 `mod tests` 拆出（共享脚手架在 `mod tests`，经 `use super::*` 可见）：
    // - whitelist.rs：能力模块白名单双向校验 + 描述符零产品名词锁
    // - linker.rs：add_to_linker 注册闭环 + 组件完整往返
    // - preopen.rs：WASI 预打开目录解析与 build_ctx 装配（实现真源已在核心
    //   `manager/runtime/wasi.rs`；文件留此处仅为复用本模块脚手架）
    // - stale_hint.rs：旧 SDK 产物实例化失败的 ABI 版本重建指引判据
    mod linker;
    mod preopen;
    mod stale_hint;
    mod whitelist;
}
