//! 组件引擎机制：**双端唯一一份**（与 WIT 无关）
//!
//! 覆盖面：Engine 构建（配置面 → wasmtime 原语）、组件编译 + AOT 缓存、Store
//! 装配与资源限制接线、燃料注入与续费、实例化入口、实例生死观测。
//!
//! ## 这份为什么能合一、绑定层为什么不能
//!
//! wasm-core 自 2026-10-13 起是**单一形态**（runtime-single-form 收口，ADR 0049）：
//! 无 `common-host` / `bare-host` 之分，运行时壳双端共用一份（桌面形态）；WIT 绑定
//! 与端差异全部在两端宿主（`HostModule` 自报汇入同一 Linker，票 04/05 绑定归位）。
//! 插件产物静态 import 的是**本端 world 全集**，宿主必须按本端 world 生成绑定并全量
//! 注册，所以「一份绑定服务两个 world」在工具链层就不成立——绑定层的固有分叉。
//! 但**加载与实例化机制本身与 WIT 无关**：编译产物、AOT 缓存、Store 装配、资源限制、
//! 燃料看门狗、实例生死观测，这些在双端语义完全一致。本模块就是它们的唯一
//! 真源；统一运行时壳（`manager/runtime.rs` + `runtime/component.rs`，单形态起
//! 无 common/bare 之分）只保留「与 WIT 绑定或与端形态接线」的部分：`bindgen!`、
//! `impl … Host`、`add_to_linker`、`verify_abi`、Engine 构建参数、
//! `LoadedWasmPlugin` 实例类型与导出调用面。
//!
//! ## 形态差异如何表达（参数化而非复制）
//!
//! | 差异 | 本模块的收口方式 |
//! | --- | --- |
//! | 实例化 sync / async（桌面 wasip3 组件要求 async 入口） | [`InstantiateMode`] 参数 |
//! | 旧产物实例化失败的错误文案（桌面要拼重建指引，移动不带） | 返回 `wasmtime::Error`，由调用方按形态语境构造 [`AppError`] |
//! | WASI 预打开目录（worker 预留能力） | 不在本模块——双端同源真源是 `manager::runtime::wasi`（用户裁决 2026-10-12：WASI 面住核心） |

use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Duration;

use wasmnest_host_kit::metrics::LifecycleEvent;
use wasmnest_host_kit::state::WasmPluginState;
use wasmtime::component::{Component, Instance, Linker};
use wasmtime::{Cache, CacheConfig, Config, Engine, ResourceLimiter, Store, WasmBacktraceDetails};

use crate::config::{
    plugin_debug_mode, BacktraceDetails, CoreConfig, EngineTuning, OptLevel, Profiling,
};
use crate::runtime_util::block_on_async;

// ==================== AOT 缓存 ====================

/// 根据 wasm 路径生成 AOT 缓存文件名（稳定 hash，避免路径字符/长度问题）
/// 产物key：路径 + 源码大小双因子哈希
///
/// 源码大小进入 key：解压器保留旧 mtime 时，仅 mtime 比较发现不了内容
/// 变更；大小变化必然换 key → 缓存 miss → 重新编译。产物自身长度与源码
/// 长度无固定关系，不能作为新鲜度因子（比较会恒不等、永久禁用缓存）
pub(crate) fn aot_cache_key(path: &Path, source_len: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    source_len.hash(&mut hasher);
    hasher.finish()
}

/// 从文件编译组件，带 AOT `.cwasm` 缓存（双端唯一一份）
///
/// 缓存文件名带 `c` 前缀（组件产物统一前缀，`Component::serialize` 产物与
/// `Module::serialize` 不同，混用会反序列化失败）；缓存目录由宿主给定（宿主 cache
/// 目录，**非插件目录**——能写插件目录的攻击者可投放伪造产物触发宿主进程 UB，
/// `Component::deserialize_file` 是 unsafe，假定数据可信）；`cache_dir = None`
/// （无头/测试上下文）时退化为纯编译。
///
/// 缓存写回失败不阻断加载（下次启动重新编译）；反序列化失败回退到完整编译路径。
pub(crate) fn compile_component_from_file(
    engine: &Engine,
    cache_dir: Option<&Path>,
    path: &Path,
) -> crate::Result<Component> {
    let compile_err = |e: wasmtime::Error| {
        crate::AppError::Plugin(format!(
            "Failed to compile WASM component from '{}': {}",
            path.display(),
            e
        ))
    };
    let Some(cache_dir) = cache_dir else {
        return Component::from_file(engine, path).map_err(compile_err);
    };

    // 源码大小计入缓存 key（内容变化但 mtime 未更新的场景：大小变化必然换 key）；
    // 新鲜度主判据为 mtime——同大小同 mtime 的编辑无法探测（无成本方案），
    // 但旧产物是合法编译代码不会崩溃，仅行为漂移，属可接受残留
    let wasm_md = std::fs::metadata(path).ok();
    let cache_path = cache_dir.join(format!(
        "c{:016x}.cwasm",
        aot_cache_key(path, wasm_md.as_ref().map(|md| md.len()).unwrap_or(0))
    ));

    let cache_fresh = wasm_md
        .and_then(|w| w.modified().ok())
        .zip(
            std::fs::metadata(&cache_path)
                .ok()
                .and_then(|c| c.modified().ok()),
        )
        .map(|(wm, cm)| cm >= wm)
        .unwrap_or(false);

    if cache_fresh {
        // unsafe：产物为本机自写缓存；Engine 版本/特性不匹配时反序列化失败，
        // 回退到完整编译路径
        if let Ok(component) = unsafe { Component::deserialize_file(engine, &cache_path) } {
            tracing::debug!(
                path = %cache_path.display(),
                "Loaded WASM component from AOT cache"
            );
            return Ok(component);
        }
    }

    let component = Component::from_file(engine, path).map_err(compile_err)?;

    // 写回 AOT 缓存：先写临时文件再 rename（原子替换，避免崩溃留半截产物）；
    // 失败不阻断加载（下次启动重新编译）
    match component.serialize() {
        Ok(bytes) => {
            if let Err(e) = std::fs::create_dir_all(cache_dir) {
                tracing::warn!(
                    path = %cache_dir.display(),
                    error = %e,
                    "Failed to create AOT cache dir, will recompile next time"
                );
                return Ok(component);
            }
            let tmp_path = cache_path.with_extension("cwasm.tmp");
            let write_result = std::fs::write(&tmp_path, &bytes)
                .and_then(|_| std::fs::rename(&tmp_path, &cache_path));
            if let Err(e) = write_result {
                tracing::warn!(
                    path = %cache_path.display(),
                    error = %e,
                    "Failed to write AOT cache, will recompile next time"
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to serialize component for AOT cache");
        }
    }

    Ok(component)
}

// ==================== Store 装配 ====================

/// 建 Store 并接好防护（双端唯一一份）
///
/// 两件防护在此处、且只在此处接线：
/// - [`ResourceLimiter`]：单插件线性内存 / 表上限（实现体在 host-kit 的 state 上）
/// - 燃料看门狗：注入**首调用预算**（实例化可能执行 guest 静态构造器）；
///   `fuel_enabled = false` 时整条注入链跳过（Engine 未开 `consume_fuel` 时
///   `set_fuel` 不可用）
pub(crate) fn new_store(
    engine: &Engine,
    state: WasmPluginState,
) -> crate::Result<Store<WasmPluginState>> {
    let mut store = Store::new(engine, state);
    store.limiter(|state| state as &mut dyn ResourceLimiter);
    inject_call_fuel(&mut store)?;
    Ok(store)
}

/// 注入单次调用燃料预算（不经消耗记账）
///
/// 两个调用点形态不同、语义相同：
/// - 实例化后 ABI 协商（[ `new_store` ] 已注入一次，此处是协商前的第二次注入）
/// - 运行时壳在需要重新建立预算时（如协商失败重试路径）直接复用
///
/// 预算取 [`wasmnest_host_kit::limits::StoreLimits::fuel_budget_for`]（debug 构建下
/// 按调用处传入的 [`plugin_debug_mode`] 套放大倍率），**不**取裸常量——双端必须
/// 同口径，否则移动宿主 debug 构建会按 release 预算被过早 trap。
pub(crate) fn inject_call_fuel(store: &mut Store<WasmPluginState>) -> crate::Result<()> {
    if !store.data().fuel_enabled {
        return Ok(());
    }
    let budget = store.data().limits.fuel_budget_for(plugin_debug_mode());
    store.set_fuel(budget).map_err(|e| {
        crate::AppError::Plugin(format!(
            "Failed to set fuel for plugin '{}': {}",
            store.data().plugin_id,
            e
        ))
    })
}

/// 每次导出调用前的燃料续费（顺带把上一区间消耗记进指标）
///
/// 续费是**必需**而非优化：导出调用会消耗燃料，不续费则预算跨调用累积耗尽 → trap
/// → Store 中毒 → 自动重载。宿主调用阻塞期间不消耗燃料（预算只约束单次调用内的
/// guest 计算量），故此处的按调用重置与宿主延迟解耦。
///
/// 不经 [`Self::inject_call_fuel`]：本函数额外做消耗记账，注入点不需要记账。
pub(crate) fn refill_call_fuel(store: &mut Store<WasmPluginState>) -> crate::Result<()> {
    let state = store.data();
    if !state.fuel_enabled {
        return Ok(());
    }
    let budget = state.limits.fuel_budget_for(plugin_debug_mode());
    let metrics = state.metrics.clone();
    if let Ok(remaining) = store.get_fuel() {
        // `remaining <= budget` 排除「上一区间未消耗」的情形：那种情况下的差额
        // 不是本次调用花掉的，记进去会虚高指标
        if remaining <= budget {
            metrics.record_fuel_consumed(budget - remaining);
        }
    }
    store
        .set_fuel(budget)
        .map_err(|e| crate::AppError::Plugin(format!("WASM fuel refill failed: {}", e)))
}

// ==================== 实例化 ====================

/// 实例化入口的 sync / async 分叉（形态参数，非两份实现）
///
/// 桌面形态的 wasip3 组件导入 async wasi 0.3 函数，实例化后 Store 为
/// async-required，同步入口会报 "store configuration requires that `*_async`
/// functions are used"⇒ 必须 [`Async`]。移动形态插件是 `wasm32-unknown-unknown`
/// （无 WASI import），走 [`Sync`] 入口。
///
/// 同步组件在 async 路径下行为等价，故两个取值共用同一段实例化代码，只切换入口。
// `allow(dead_code)`：任一形态只构造其中一个取值（桌面 Async / 移动 Sync），
// 另一个在本形态内不可达——枚举本身是双形态共用的单一词汇。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstantiateMode {
    /// 同步入口（`Linker::instantiate`；移动形态）
    Sync,
    /// 异步入口（`Linker::instantiate_async`，经 `block_on_async` 驱动 fiber）
    Async,
}

/// 按 [`InstantiateMode`] 实例化组件
///
/// **返回 `wasmtime::Error` 而非 [`crate::AppError`]**：错误文案是形态语境的一部分
/// （桌面要在失败时拼「该产物按旧版插件 SDK 构建，请用当前 SDK 重建」的指引，移动
/// 形态不带该指引）。构造带操作描述的 [`crate::AppError`] 是调用方的责任
/// （AGENTS §6：错误构造 / 转换处必须带操作描述）。
pub(crate) fn instantiate(
    store: &mut Store<WasmPluginState>,
    linker: &Linker<WasmPluginState>,
    component: &Component,
    mode: InstantiateMode,
) -> Result<Instance, wasmtime::Error> {
    match mode {
        InstantiateMode::Sync => linker.instantiate(store, component),
        InstantiateMode::Async => {
            // `block_on_async` 驱动 fiber（既有多线程 / current_thread / 无 runtime
            // 三路径重入安全，见 `runtime_util` 模块文档）
            block_on_async(async { linker.instantiate_async(store, component).await })
        }
    }
}

// ==================== 实例生命周期观测 ====================

/// 实例创建日志（与 [`log_instance_dropped`] 成对）
///
/// 启动加载与热重载均经实例化路径，`plugin_id` 键控构成实例生命周期观测。
pub(crate) fn log_instance_created(plugin_id: &str) {
    tracing::info!(
        plugin_id = %plugin_id,
        "WASM plugin instance created (component model)"
    );
}

/// 实例死亡日志（Store 被 drop：停用 / 热重载替换 / 应用退出 / 异常清理）
///
/// 与 [`log_instance_created`] 成对。调用点在各形态 `Loaded*Plugin` 的 `Drop` 内，
/// 其中无锁操作，`tracing` 安全。
pub(crate) fn log_instance_dropped(plugin_id: &str, lifetime: Duration) {
    tracing::info!(
        plugin_id = %plugin_id,
        lifetime_ms = lifetime.as_millis() as u64,
        "WASM plugin instance dropped"
    );
}

// ==================== Engine 构建（配置面 → wasmtime 原语） ====================
//
// 「配置面到 wasmtime 原语的唯一映射点」双端只有这一份，**`CoreConfig` 是唯一
// 真源**（ADR 0045 D5：能力域不得自带配置面）。故本段属机制（不是端差异）：
// 移动宿主消费同一份构建函数，与桌面逐值对齐（consume_fuel / 内存预留 / 栈深度 /
// 内存不搬移 / 编译缓存 / backtrace 帧数皆取同一份配置——单形态收口前两壳各钉
// 一份字面量的历史已消除：移动侧此前硬编码，且漏掉了 backtrace 帧数与
// 「Engine 生效参数」结构化日志）。

/// 由内核配置构建 wasmtime Engine 参数（**配置面 → wasmtime 原语的唯一映射点**）
///
/// 纯函数（除 `plugin_debug_mode` 下设置 `WASMTIME_BACKTRACE_DETAILS` 环境变量外不触
/// 盘、不依赖宿主状态）——单测可直接消费。运行时壳的逃生舱钩子在
/// `WasmRuntime::with_setup` 里于本函数**之后**执行（桌面装配传入 customizer；
/// 移动装配无此钩子，其余步骤同一入口）。
pub(crate) fn build_engine_config(core_config: &CoreConfig, debug_mode: bool) -> Config {
    let engine = &core_config.engine;
    let tuning = engine.tuning.resolve(debug_mode);
    let mut config = Config::new();
    // 票 02 宿主 async 化门禁：CM_ASYNC 引擎级异步支持（wasmtime 46+ 默认
    // 编译进 runtime，此处开启 wasm 特性）。wasip3 组件导入 async wasi 0.3
    // 函数，实例化后 Store 为 async-required；既有同步插件不受影响
    // （/tmp/wasip3-probe 场景 4 实证：同步组件 sync/async 双路径均可用）。
    // wasmtime 48 中 async_support() 配置已废弃为 no-op（异步为引擎级）。
    // 取值来自 A 面 `tuning.component_model_async`（默认 true；validate 硬拒 false）
    config.wasm_component_model_async(tuning.component_model_async);
    // 燃料看门狗：guest 指令计数耗尽即 trap（宿主调用阻塞不消耗，见 config FUEL_PER_CALL）
    config.consume_fuel(engine.consume_fuel);
    // WASM 内部调用栈：trap（panic/栈溢出/燃料耗尽/内存越界）错误串携带
    // 插件内部函数调用链（names section 函数名，release 构建即有），随
    // AppError::Plugin 进 error.log 与插件 Degraded 状态，AI agent 无需重跑
    // 即可定位插件内部故障点。wasmtime 47 的 backtrace 在 default features
    // 内（零编译成本），此处显式钉死 32 帧防止上游默认（20 帧）漂移
    config.wasm_backtrace_max_frames(Some(
        NonZeroUsize::new(engine.wasm_backtrace_max_frames as usize)
            .expect("backtrace frames > 0（配置校验保证）"),
    ));
    // 行号解析：Environment 模式读 WASMTIME_BACKTRACE_DETAILS——无 DWARF 时
    // 零开销回退到函数名栈（release 插件无调试信息，不硬编码强制解析）；
    // 插件调试模式（WASMNEST_PLUGIN_DEBUG=1）下宿主先置该环境变量再构建
    // Engine，并由 tuning.resolve 把 debug_info 推为 true（wasmtime 默认 false
    // 不产 DWARF，只置环境变量拿不到 file:line）
    if debug_mode {
        // edition 2021 下 set_var 非 unsafe；此处单线程启动早期调用，
        // 无并发读写风险。Environment 模式在 wasm_backtrace_details 调用
        // 时读取该变量，必须先设置再配置
        std::env::set_var("WASMTIME_BACKTRACE_DETAILS", "1");
    }
    config.wasm_backtrace_details(wasmtime_backtrace_details(tuning.backtrace_details));
    // 线性内存预留 = 估算的最大线性内存（与 limiter 上限严格一致，见
    // MAX_PLUGIN_MEMORY_BYTES）：实例化时一次性预留 256MiB 虚拟地址空间，
    // 增长零系统调用、基址恒定；相比 64-bit 默认（4GiB 预留 + 32MiB guard/
    // 内存）大幅降低 VA 占用。GC 堆未显式配置时沿用同值（wasmtime 语义：
    // gc_heap_* 缺省继承 memory_* 配置）
    config.memory_reservation(engine.memory_reservation_bytes);
    // 预留即硬顶：初始分配与增长超出预留前均被 limiter 拒绝（memory_growing
    // 在物理分配前调用），内存永不搬移；编译器可静态假设基址不变做优化，
    // 同时杜绝任何路径触发重定位。
    // 取值来自 A 面 `tuning.memory_may_move`（默认 false）
    config.memory_may_move(tuning.memory_may_move);
    // Wasm 执行栈深度上限：深度递归在 wasm 侧确定性栈溢出 trap，
    // 而非打穿真实线程栈导致进程 abort（见 MAX_WASM_STACK_BYTES）
    config.max_wasm_stack(core_config.store.max_wasm_stack_bytes);

    // ==================== A 面：跟随默认组（Some 才调用） ====================
    // `None` = 不调用该 API，逐字继承 wasmtime 默认（见 EngineTuning 组语义注释：
    // 不把上游默认值变成我们的隐性依赖，锁版升级不带进行为变更）
    if let Some(v) = tuning.debug_info {
        config.debug_info(v);
    }
    if let Some(v) = tuning.native_unwind_info {
        config.native_unwind_info(v);
    }
    if let Some(v) = tuning.parallel_compilation {
        config.parallel_compilation(v);
    }
    if let Some(v) = tuning.opt_level {
        config.cranelift_opt_level(wasmtime_opt_level(v));
    }
    if let Some(v) = tuning.profiling {
        config.profiler(wasmtime_profiling(v));
    }
    if let Some(v) = tuning.epoch_interruption {
        config.epoch_interruption(v);
    }
    if let Some(v) = tuning.component_model_error_context {
        config.wasm_component_model_error_context(v);
    }
    if let Some(v) = tuning.wasm_threads {
        config.wasm_threads(v);
    }
    if let Some(v) = tuning.wasm_simd {
        config.wasm_simd(v);
    }
    if let Some(v) = tuning.wasm_bulk_memory {
        config.wasm_bulk_memory(v);
    }
    if let Some(v) = tuning.wasm_multi_memory {
        config.wasm_multi_memory(v);
    }
    if let Some(v) = tuning.wasm_tail_call {
        config.wasm_tail_call(v);
    }
    if let Some(v) = tuning.wasm_reference_types {
        config.wasm_reference_types(v);
    }
    if let Some(v) = tuning.wasm_memory64 {
        config.wasm_memory64(v);
    }
    // 信号式 trap 开关（端事实）：移动宿主取 false——Android ART 经 `libsigchain` 接管
    // 信号处理器，信号式 trap 会被判成非 wasm 故障并交回上一个处理器（WebView/crashpad）
    // ⇒ 任何 guest trap 都变成宿主进程 SIGILL；`false` = 全部 trap 走显式 libcall。
    // 影响代码生成（边界检查不再依赖 guard page）⇒ 换值会换 AOT 产物（旧 cwasm 反序列化
    // 失败后自动回落重编，见 `compile_component_from_file`）
    if let Some(v) = tuning.signals_based_traps {
        config.signals_based_traps(v);
    }

    // 编译缓存：跨进程复用已编译产物（初始化失败降级为不缓存，不阻断运行时）
    if engine.compile_cache {
        match Cache::new(CacheConfig::new()) {
            Ok(cache) => {
                config.cache(Some(cache));
            }
            Err(e) => {
                tracing::warn!(error = %e, "WASM compile cache disabled");
            }
        }
    }
    warn_incoherent_tuning(&tuning);
    log_effective_engine_config(engine, &tuning);
    config
}

/// 锁定项重申：钩子执行后恢复资源看门狗 4 项到配置值
///
/// **为什么锁定**：这 4 项在 [`CoreConfig::validate`] 里有跨字段约束（典型如
/// `memory_reservation_bytes >= store.max_memory_bytes`：预留小于上限会让合法内存
/// 增长退化为搬移/失败路径），而任意闭包能改 `wasmtime::Config` 且**不可回读校验**
/// ——不锁定则「配置面已校验」的承诺在最后一步静默失效（如关掉燃料 = 唯一死循环闸门
/// 被摘除且无任何报错）。宿主要改这 4 项走 `CoreConfig`（经 `with_setup` 传入），
/// 配置面的 `tuning.memory_may_move` 同样可改——只是钩子改不动。
// 仅桌面逃生舱路径消费（运行时壳的 `with_setup` 在 customizer 之后重申锁定项）；
// 移动装配无 customizer 钩子，故在移动侧不可达。
#[allow(dead_code)]
pub(crate) fn reassert_locked_knobs(config: &mut Config, core_config: &CoreConfig) {
    config.consume_fuel(core_config.engine.consume_fuel);
    config.max_wasm_stack(core_config.store.max_wasm_stack_bytes);
    config.memory_reservation(core_config.engine.memory_reservation_bytes);
    config.memory_may_move(core_config.engine.tuning.memory_may_move);
}

/// 无效组合告警（不至于报错，但必须 warn——防「以为生效了」）
///
/// 均为**内核事实**推导的组合，不是通用 wasmtime 规则：
/// 内核的资源看门狗是 fuel（`Store::set_fuel` + 每次导出调用重置），从不调
/// `set_epoch_deadline`，故引擎级 epoch 中断开了也不产生任何墙钟效果。
pub(crate) fn warn_incoherent_tuning(tuning: &EngineTuning) {
    if tuning.epoch_interruption == Some(true) {
        tracing::warn!(
            "engine.tuning.epoch_interruption=true 无效：内核看门狗用 fuel（未调用 set_epoch_deadline），\
             引擎级 epoch 中断不会触发任何墙钟中断"
        );
    }
    if tuning.debug_info == Some(true) {
        if tuning.backtrace_details == BacktraceDetails::Disable {
            tracing::warn!(
                "engine.tuning.debug_info=true 但 backtrace_details=disable：trap 错误串拿不到 file:line 行号"
            );
        }
        if tuning.native_unwind_info == Some(false) {
            tracing::warn!(
                "engine.tuning.debug_info=true 但 native_unwind_info=false：宿主栈回溯信息缺失，\
                 行号解析可能失败"
            );
        }
    }
}

/// Engine 生效参数的结构化日志（Engine 构建后不可回读，日志是唯一的可观测面）
pub(crate) fn log_effective_engine_config(
    engine: &crate::config::EngineConfig,
    tuning: &EngineTuning,
) {
    tracing::info!(
        consume_fuel = engine.consume_fuel,
        memory_reservation_bytes = engine.memory_reservation_bytes,
        wasm_backtrace_max_frames = engine.wasm_backtrace_max_frames,
        compile_cache = engine.compile_cache,
        component_model_async = tuning.component_model_async,
        memory_may_move = tuning.memory_may_move,
        debug_info = ?tuning.debug_info,
        opt_level = ?tuning.opt_level,
        profiling = ?tuning.profiling,
        parallel_compilation = ?tuning.parallel_compilation,
        signals_based_traps = ?tuning.signals_based_traps,
        "WASM engine configured"
    );
}

/// 配置面 `OptLevel` → wasmtime 原语
pub(crate) fn wasmtime_opt_level(level: OptLevel) -> wasmtime::OptLevel {
    match level {
        OptLevel::None => wasmtime::OptLevel::None,
        OptLevel::Speed => wasmtime::OptLevel::Speed,
        OptLevel::SpeedAndSize => wasmtime::OptLevel::SpeedAndSize,
    }
}

/// 配置面 `Profiling` → wasmtime 原语
pub(crate) fn wasmtime_profiling(profiling: Profiling) -> wasmtime::ProfilingStrategy {
    match profiling {
        Profiling::None => wasmtime::ProfilingStrategy::None,
        Profiling::PerfMap => wasmtime::ProfilingStrategy::PerfMap,
        Profiling::JitDump => wasmtime::ProfilingStrategy::JitDump,
        Profiling::VTune => wasmtime::ProfilingStrategy::VTune,
    }
}

/// 配置面 `BacktraceDetails` → wasmtime 原语
pub(crate) fn wasmtime_backtrace_details(details: BacktraceDetails) -> WasmBacktraceDetails {
    match details {
        BacktraceDetails::Enable => WasmBacktraceDetails::Enable,
        BacktraceDetails::Disable => WasmBacktraceDetails::Disable,
        BacktraceDetails::Environment => WasmBacktraceDetails::Environment,
    }
}

// ==================== 导出调用的结果判定（双端唯一一份） ====================
//
// 一次导出调用的结果形状固定是**两层**：外层 = 调用级失败（trap / 栈溢出 /
// 燃料耗尽 / 内存越界 / 导出缺失），内层 = guest 自报的业务失败
//（WIT `result<T, string>`）。两层语义不同、处理不同（外层必记账 trap 并落
// error 日志，内层按调用点是「命令」还是「观察」分流），因此判定不能压成
// 一层，也不该在运行时壳里重写一遍——**判定与记账与宿主绑定类型无关**
//（单形态收口前两壳各写一遍的历史已消除）。

/// trap 的统一记账 + 日志（双端唯一一份）
///
/// 错误串在此已携带 wasm backtrace（见 [`build_engine_config`] 的
/// `wasm_backtrace_max_frames` 配置）。即使调用方静默忽略返回错误，此处
/// error 级日志保证崩溃证据落盘；AI agent grep error 日志即可定位「哪个插件
/// 在哪个导出上崩了」。
///
/// `trap_detail` 打 `wasmtime::Error` 的 **Debug 全链**：Display 只有顶层
/// context（`error while executing at wasm backtrace:`），真正的原因
/// （`wasm trap: wasm `unreachable` instruction executed` / 燃料耗尽 /
/// host 调用错误）在 `Caused by:` 里——只打 Display 会丢原因。
pub(crate) fn log_trap(store: &Store<WasmPluginState>, export: &str, err: &wasmtime::Error) {
    store.data().metrics.record_lifecycle(LifecycleEvent::Trap);
    // 原因分类用 Debug 全链（`{:#}` 含 `Caused by:`）：只打 Display 会丢
    // 「all fuel consumed / call stack exhausted / out of bounds」这些真正原因。
    // 分类失败的落 Other，原始文本仍由下方 `trap_detail` 保全。
    store
        .data()
        .metrics
        .record_trap(crate::monitor::TrapKind::classify(&format!("{:#}", err)));
    tracing::error!(
        plugin_id = %store.data().plugin_id,
        export = %export,
        trap = %err,
        trap_detail = ?err,
        "WASM plugin export call trapped"
    );
}

/// trap 的记账 + 构造带操作描述的错误（[`log_trap`] 的返回值面）
pub(crate) fn trapped(
    store: &Store<WasmPluginState>,
    export: &str,
    err: wasmtime::Error,
) -> crate::AppError {
    log_trap(store, export, &err);
    crate::AppError::Plugin(format!("WASM {}() call failed: {}", export, err))
}

/// 单值导出调用的结果判定（WIT 返回值即业务结果，无 guest 自报失败层）
///
/// 覆盖 `invoke`（返回 JSON 串）/ `manifest.get` / 可选导出的 TypedFunc 调用
/// 等形状：只有「投递成功 / 调用级失败」两种结果。
///
/// 防回接锁保留（engine.rs 锁测试 NEEDLES 钉住 `fn settle_guest_event(` 源码
/// 存在；settle / settle_guest 为同族结果判定机制一并保留，无运行时调用方）：
/// 当前 engine 路径在调用点直接 match outcome，未挂靠这三个 helper。
#[allow(dead_code)]
pub(crate) fn settle<T>(
    store: &Store<WasmPluginState>,
    export: &str,
    outcome: std::result::Result<T, wasmtime::Error>,
) -> crate::Result<T> {
    outcome.map_err(|e| trapped(store, export, e))
}

/// 命令型导出调用的结果判定（guest 自报失败 = 失败）
///
/// 宿主流程依赖该结果（activate / invoke / on_startup …）：guest 返回
/// `Err(msg)` 即上抛，驱动插件 Degraded 状态机。
#[allow(dead_code)]
pub(crate) fn settle_guest<T>(
    store: &Store<WasmPluginState>,
    export: &str,
    outcome: std::result::Result<std::result::Result<T, String>, wasmtime::Error>,
) -> crate::Result<T> {
    match outcome {
        Ok(value) => value
            .map_err(|msg| crate::AppError::Plugin(format!("WASM {}() failed: {}", export, msg))),
        Err(e) => Err(trapped(store, export, e)),
    }
}

/// 观察型（事件）导出调用的结果判定（guest 自报失败不阻断宿主流程）
///
/// 事件投递是 fire-and-forget：guest 报 `Err(msg)` 只记 warn 并返回 Ok——
/// 否则一个处理失败的消息处理器会让整条事件分发链失败。调用级失败（外层 Err）
/// 仍然上抛：那是 trap，属宿主侧问题。
#[allow(dead_code)]
pub(crate) fn settle_guest_event(
    store: &Store<WasmPluginState>,
    export: &str,
    outcome: std::result::Result<std::result::Result<(), String>, wasmtime::Error>,
) -> crate::Result<()> {
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(msg)) => {
            tracing::warn!(export = %export, "WASM export reported failure: {msg}");
            Ok(())
        }
        Err(e) => Err(trapped(store, export, e)),
    }
}

/// 导出调用的计时起点（core-monitor 埋点，RAII：返回值 drop 时落账）
pub(crate) fn start_call_timer(
    store: &Store<WasmPluginState>,
) -> wasmnest_host_kit::metrics::CallTimer {
    store.data().metrics.start_call()
}

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 运行时壳文件（相对 crate 根）——防回接锁的扫描面
    ///
    /// 单形态（2026-10-13）后壳收为一份（`runtime.rs` 本体 + `runtime/component.rs`），
    /// 与 `src/lib.rs` 的 `SHELL_FILES` 同源两份（那边供 `binding_surface` 锁判「壳不
    /// 得持 bindgen」，这边供本锁判「壳不许自持 Engine 构建」）。
    const SHELL_FILES: &[&str] = &[
        "/src/manager/runtime.rs",
        "/src/manager/runtime/component.rs",
    ];

    /// 读源码并剥掉整行 `//` 注释
    ///
    /// 判据只对**代码**生效：文档与注释里提到某个机制名（"instantiate_async 下行为
    /// 等价" / "`Store::set_fuel` 在实例化时直接报错"）是解释性文字，不构成"实现又
    /// 回来了"的证据。全行注释剥离是最小可靠口径（块注释在本 crate 的这几个文件里
    /// 不承载判据，故不处理）。
    fn shell_source(relative: &str) -> String {
        let path = format!("{}{}", env!("CARGO_MANIFEST_DIR"), relative);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read shell source {}: {e}", path));
        raw.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 信号式 trap 开关必须真到达 Engine（配置面 → wasmtime 原语的接线锁）
    ///
    /// 背景：Android 上 ART 经 `libsigchain` 接管信号处理器，信号式 trap 会被判成
    /// 「非 wasm 故障」并交回上一个处理器（WebView/crashpad）⇒ 任何 guest trap 变成
    /// 宿主进程 SIGILL。移动宿主取 `Some(false)`（显式 libcall 抛 trap，不经信号链）——
    /// 本用例钉住「配置值确实进到 Engine」这一步：漏接就是崩溃照旧且无任何报错。
    /// `None` 分支同样要留痕：它必须逐字继承 wasmtime 默认（本机 `cfg!(has_native_signals)`）。
    #[test]
    fn signals_based_traps_tuning_reaches_engine() {
        let mut off = CoreConfig::default();
        off.engine.tuning.signals_based_traps = Some(false);
        let engine_off =
            wasmtime::Engine::new(&build_engine_config(&off, false)).expect("engine (off)");
        assert!(
            !engine_off.get_signals_based_traps(),
            "Some(false) 必须关闭信号式 trap"
        );

        let mut on = CoreConfig::default();
        on.engine.tuning.signals_based_traps = Some(true);
        let engine_on =
            wasmtime::Engine::new(&build_engine_config(&on, false)).expect("engine (on)");
        assert!(
            engine_on.get_signals_based_traps(),
            "Some(true) 必须开启信号式 trap"
        );

        // 跟随默认组：None = 不调用 API，逐字继承上游默认
        // （与未触碰的 `Config::new()` 逐值对比——比写死 true 更严谨：本判据不假设平台）
        let plain = wasmtime::Engine::new(&wasmtime::Config::new()).expect("engine (plain)");
        let engine_default =
            wasmtime::Engine::new(&build_engine_config(&CoreConfig::default(), false))
                .expect("engine (default)");
        assert_eq!(
            engine_default.get_signals_based_traps(),
            plain.get_signals_based_traps(),
            "None 必须逐字继承上游默认（不得自作主张）"
        );
    }

    /// AOT 缓存键：同输入稳定、随源码大小与路径变化（双形态共用同一份判据）
    #[test]
    fn aot_cache_key_factors_source_size_and_path() {
        let p = Path::new("/tmp/x/plugin.wasm");
        assert_eq!(
            aot_cache_key(p, 1024),
            aot_cache_key(p, 1024),
            "同输入必须稳定"
        );
        assert_ne!(
            aot_cache_key(p, 1024),
            aot_cache_key(p, 2048),
            "缓存键必须随源码大小变化"
        );
        assert_ne!(
            aot_cache_key(p, 1024),
            aot_cache_key(Path::new("/tmp/y/plugin.wasm"), 1024),
            "缓存键必须随路径变化"
        );
    }

    /// 机制真源确实在引擎模块里（正向锚点：防「锁绿但实现被搬走」）
    #[test]
    fn engine_module_owns_the_mechanism() {
        let engine_src = shell_source("/src/manager/runtime/engine.rs");
        for needle in [
            // 加载与实例化
            "fn aot_cache_key",
            "c{:016x}.cwasm",
            ".limiter(",
            ".set_fuel(",
            "instantiate_async(",
            // 生命周期观测
            "\"WASM plugin instance created",
            "\"WASM plugin instance dropped",
            // 导出调用判定
            "fn log_trap(",
            "fn trapped(",
            "fn settle_guest_event(",
            "fn start_call_timer(",
            // Engine 构建（桌面 CoreConfig 为唯一真源，移动侧消费同一份）
            "fn build_engine_config(",
            "fn reassert_locked_knobs(",
            "config.consume_fuel(",
        ] {
            assert!(
                engine_src.contains(needle),
                "引擎模块必须持有机制实现 `{needle}`（否则运行时壳里那份就成第二真源）"
            );
        }
    }

    /// 防回接锁：运行时壳不得重新自持组件引擎机制
    ///
    /// 本批次的全部收益就是「同一份机制」——只要运行时壳里重新长出 Engine 构建
    /// 参数、AOT 缓存键、limiter 接线、燃料注入、实例生死日志、导出调用的 trap
    /// 判定，或直接的 instantiate 调用，机制就退回两份实现且行为会各自漂移
    /// （历史上移动侧就因此漏掉了 debug 燃料放大倍率、Engine 参数漏掉了
    /// backtrace 帧数）。锁用文本针脚而非类型系统：运行时壳与引擎之间没有可借用
    /// 的类型边界，机制以自由函数 + 参数传递（`InstantiateMode`）表达，只有源码
    /// 形态可判。
    #[test]
    fn runtime_shell_does_not_reimplement_component_engine() {
        const NEEDLES: &[&str] = &[
            // 加载与实例化
            "fn aot_cache_key",
            "c{:016x}.cwasm",
            ".limiter(",
            ".set_fuel(",
            "instantiate_async(",
            ".instantiate(",
            ".start_call()",
            // 生命周期观测
            "\"WASM plugin instance created",
            "\"WASM plugin instance dropped",
            // 导出调用判定
            "fn log_trap(",
            "self.log_trap(",
            "\"WASM activate() call failed",
            "\"WASM invoke_command() call failed",
            // Engine 构建（配置面真源在 config，映射点唯一）
            "fn build_engine_config(",
            "fn reassert_locked_knobs(",
            "config.consume_fuel(",
            "config.memory_reservation(",
            "config.max_wasm_stack(",
            "CacheConfig::new()",
        ];
        for file in SHELL_FILES {
            let src = shell_source(file);
            for needle in NEEDLES {
                assert!(
                    !src.contains(needle),
                    "运行时壳 `{file}` 重新自持机制 `{needle}`——机制真源在 \
                     `manager/runtime/engine.rs`，运行时壳只做接线（ADR 0045 D6）"
                );
            }
        }
    }
}
