//! 引擎定制面行为契约（A 面 `EngineTuning` 接线 + B 面 `EngineCustomizer` 逃生舱）
//!
//! 链路：`wasm-core.json` → `CoreConfig::validate` → `EngineTuning::resolve`
//! → `build_engine_config` →（逃生舱）→ `reassert_locked_knobs` → `Engine::new`。
//!
//! 观测手段（按可得性分三层，逐层不依赖下一层）：
//! 1. **`Engine` 生效值直读**：wasmtime 48 的 `Engine` 带 `get_*`（含锁定 4 项：
//!    `get_consume_fuel` / `get_max_wasm_stack` / `get_memory_reservation` /
//!    `get_memory_may_move`）。`Config` 不可回读（默认未显式化的项读不出），
//!    `Engine` 才是完整生效配置——逐字断言映射与「零漂移」；
//! 2. **Engine 生效参数日志**：对无 getter 的项（`component_model_async` /
//!    `backtrace_details` / `profiling`）断言结构化字段；
//! 3. **真实 trap 错误串**：端到端证明钩子确实作用在生产 Engine 上。
//!
//! 纯逻辑（默认值 / 推导规则 / 枚举解析 / 校验规则）在 `crate::config` 的单测里。
//!
//! **票 04 拆分**：`customizer_overrides_unlocked_knobs_end_to_end`（第 3 层
//! 「真实 trap」端到端，需实例化 SDK 夹具）随「wasm-core 不再持全 world 绑定」
//! 迁桌面宿主 `src-tauri/tests/engine_e2e.rs` 同名用例；留本文件的用例全部只建
//! Engine / 运行时、不实例化组件。

use super::*;
use crate::config::{CoreConfig, OptLevel};
use crate::host_api::log::capture::{capture, CapturedEvent};
use crate::manager::runtime::EngineSetup;
use tracing::Level;

// ==================== B 面：逃生舱 ====================

/// 锁定项：钩子**改不动**资源看门狗 4 项
///
/// 钩子把 4 项全部改成「拔掉闸门」的极值（燃料关、栈深放大到 1GiB、内存预留缩到
/// 1MiB、允许搬移），构建出的 Engine 必须仍是配置值——否则宿主能在最后一步静默
/// 摘掉死循环闸门 / 防栈打穿 / 「预留即硬顶」语义，而 `CoreConfig::validate`
/// 的跨字段校验已经形同虚设（`Config` 不可回读校验，故只能靠锁定）。
///
/// 变异自检：删掉 `reassert_locked_knobs` 任一行 → 本用例对应断言立刻翻红。
#[test]
fn customizer_cannot_override_locked_knobs() {
    let mut core_config = CoreConfig::default();
    core_config.engine.tuning.memory_may_move = true; // 配置面显式允许搬移（钩子本来就改不动它）
    let (fuel, stack, reservation, may_move) = (
        core_config.engine.consume_fuel,
        core_config.store.max_wasm_stack_bytes,
        core_config.engine.memory_reservation_bytes,
        core_config.engine.tuning.memory_may_move,
    );

    let runtime = runtime_with_setup(EngineSetup::new(core_config).with_customizer(
        move |config| {
            config.consume_fuel(false);
            config.max_wasm_stack(1 << 30);
            config.memory_reservation(1 << 20);
            config.memory_may_move(!may_move);
            Ok(())
        },
    ));
    let effective = runtime.engine();

    assert_eq!(
        effective.get_consume_fuel(),
        fuel,
        "燃料看门狗必须在逃生舱之后仍然开启（锁定项）"
    );
    assert_eq!(
        effective.get_max_wasm_stack(),
        stack,
        "wasm 执行栈上限必须回到配置值（锁定项）"
    );
    assert_eq!(
        effective.get_memory_reservation(),
        reservation,
        "线性内存预留必须回到配置值（锁定项：预留小于 store 上限会让合法增长退化）"
    );
    assert_eq!(
        effective.get_memory_may_move(),
        may_move,
        "内存搬移语义必须回到配置值（锁定项）"
    );
}

/// 定制失败必须显性报错，不静默降级为一个「看起来能用但参数不对」的 Engine
#[test]
fn customizer_error_is_reported_with_context() {
    let storage = Arc::new(PluginStorage::new(Arc::new(std::sync::Mutex::new(
        crate::db::Database::new(&PathBuf::from(":memory:")).expect("内存库应可建"),
    ))));
    let result = WasmRuntime::with_setup(
        storage,
        None,
        EngineSetup::new(CoreConfig::default())
            .with_customizer(|_| Err(crate::AppError::Config("宿主要求的 target 不支持".into()))),
    );
    // WasmRuntime 不实现 Debug（持有 Engine/Linker），故不能用 expect_err
    let err = match result {
        Ok(_) => panic!("定制钩子返 Err 必须让 Engine 构建失败（不得静默降级为默认参数 Engine）"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("引擎定制钩子"), "错误须带操作上下文: {msg}");
    assert!(
        msg.contains("宿主要求的 target 不支持"),
        "错误须带上游原因: {msg}"
    );
}

// ==================== A 面：配置面 → wasmtime 原语 ====================

/// A 面定制项逐字落到 `wasmtime::Config`（getter 直读，非日志推断）
///
/// 反向一半同样重要：**未配置的项不得被调用**（`None` = 跟随 wasmtime 默认），
/// 否则「开放配置」会把上游默认值变成内核的隐性依赖。
#[test]
fn tuning_maps_onto_wasmtime_config() {
    // 零漂移锚点：默认配置构建出的 Engine 与「裸 wasmtime 默认 Config」逐项相等
    // ——`None` 组不调用任何 API，故生效值必须与上游默认完全一致（升级不引入行为变更）
    let upstream = wasmtime::Engine::new(&wasmtime::Config::new()).expect("裸默认引擎应可建");
    let ours = effective_engine(&CoreConfig::default(), false);
    assert_eq!(
        ours.get_debug_info(),
        upstream.get_debug_info(),
        "未配置 debug_info 时不得偏离 wasmtime 默认"
    );
    assert_eq!(
        ours.get_native_unwind_info(),
        upstream.get_native_unwind_info(),
        "未配置 native_unwind_info 时不得偏离 wasmtime 默认"
    );
    assert_eq!(
        ours.get_parallel_compilation(),
        upstream.get_parallel_compilation(),
        "未配置 parallel_compilation 时不得偏离 wasmtime 默认"
    );
    assert_eq!(
        ours.get_cranelift_opt_level(),
        upstream.get_cranelift_opt_level(),
        "未配置 opt_level 时不得偏离 wasmtime 默认"
    );
    assert_eq!(
        ours.get_epoch_interruption(),
        upstream.get_epoch_interruption(),
        "未配置 epoch 中断时不得偏离 wasmtime 默认"
    );
    assert_eq!(
        ours.get_wasm_features(),
        upstream.get_wasm_features(),
        "未配置 proposal 开关时不得偏离 wasmtime 默认（threads/simd/bulk_memory/…）"
    );
    // 显式钉死组逐字等于内核配置（回归锚点：历史写死值）
    let default_config = CoreConfig::default();
    assert_eq!(
        ours.get_max_wasm_stack(),
        default_config.store.max_wasm_stack_bytes
    );
    assert_eq!(
        ours.get_memory_reservation(),
        default_config.engine.memory_reservation_bytes
    );
    assert!(!ours.get_memory_may_move(), "默认不允许内存搬移");
    assert_eq!(
        ours.get_wasm_backtrace_max_frames(),
        default_config.engine.wasm_backtrace_max_frames as usize
    );

    // 显式配置：逐字生效
    let mut core_config = CoreConfig::default();
    core_config.engine.wasm_backtrace_max_frames = 7;
    let tuning = &mut core_config.engine.tuning;
    tuning.debug_info = Some(true);
    tuning.native_unwind_info = Some(false);
    tuning.parallel_compilation = Some(false);
    tuning.opt_level = Some(OptLevel::SpeedAndSize);
    tuning.epoch_interruption = Some(true);
    tuning.wasm_threads = Some(false);
    tuning.wasm_multi_memory = Some(true);
    let engine = effective_engine(&core_config, false);

    assert!(engine.get_debug_info(), "tuning.debug_info 未落到生效配置");
    assert_eq!(
        engine.get_native_unwind_info(),
        Some(false),
        "tuning.native_unwind_info 未落到生效配置"
    );
    assert!(
        !engine.get_parallel_compilation(),
        "tuning.parallel_compilation 未落到生效配置"
    );
    assert_eq!(
        engine.get_cranelift_opt_level(),
        Some(wasmtime::OptLevel::SpeedAndSize),
        "tuning.opt_level 未落到生效配置"
    );
    assert!(
        engine.get_epoch_interruption(),
        "tuning.epoch_interruption 未落到生效配置"
    );
    assert!(
        !engine.get_wasm_features().threads(),
        "tuning.wasm_threads 未落到生效配置"
    );
    assert!(
        engine.get_wasm_features().multi_memory(),
        "tuning.wasm_multi_memory 未落到生效配置"
    );
    assert_eq!(
        engine.get_wasm_backtrace_max_frames(),
        7,
        "engine.wasm_backtrace_max_frames 未落到生效配置"
    );
    assert_ne!(
        engine.get_wasm_features(),
        upstream.get_wasm_features(),
        "显式改动的 proposal 必须真的改变生效配置（wasmtime 48 默认几乎全开，故反向关掉才看得出）\
         ——否则上面的相等断言是恒真的"
    );
}

/// 配置面枚举词汇 → wasmtime 原语的逐字映射（纯函数）
///
/// **不建 Engine**：`ProfilingStrategy::JitDump` / `PerfMap` 会在进程 cwd 落
/// `jit-<pid>.dump` / `perf-<pid>.map`（测试污染仓库），且上游无对应 getter；
/// 映射正确性在这里逐项钉住，`tuning` 接线则由上面的生效值用例与日志用例覆盖。
#[test]
fn vocabulary_maps_onto_wasmtime_primitives() {
    use crate::config::{BacktraceDetails, Profiling};

    assert_eq!(wasmtime_opt_level(OptLevel::None), wasmtime::OptLevel::None);
    assert_eq!(
        wasmtime_opt_level(OptLevel::Speed),
        wasmtime::OptLevel::Speed
    );
    assert_eq!(
        wasmtime_opt_level(OptLevel::SpeedAndSize),
        wasmtime::OptLevel::SpeedAndSize
    );

    assert_eq!(
        wasmtime_profiling(Profiling::None),
        wasmtime::ProfilingStrategy::None
    );
    assert_eq!(
        wasmtime_profiling(Profiling::PerfMap),
        wasmtime::ProfilingStrategy::PerfMap
    );
    assert_eq!(
        wasmtime_profiling(Profiling::JitDump),
        wasmtime::ProfilingStrategy::JitDump
    );
    assert_eq!(
        wasmtime_profiling(Profiling::VTune),
        wasmtime::ProfilingStrategy::VTune
    );

    // WasmBacktraceDetails 无 PartialEq（上游未 derive），故比对 Debug 串
    assert_eq!(
        format!("{:?}", wasmtime_backtrace_details(BacktraceDetails::Enable)),
        "Enable"
    );
    assert_eq!(
        format!(
            "{:?}",
            wasmtime_backtrace_details(BacktraceDetails::Disable)
        ),
        "Disable"
    );
    assert_eq!(
        format!(
            "{:?}",
            wasmtime_backtrace_details(BacktraceDetails::Environment)
        ),
        "Environment"
    );
}

/// A 面无 getter 且不产生副作用的三项（`component_model_async` /
/// `backtrace_details` / `profiling`）走生效参数日志核对——日志是这些项唯一的
/// 可观测面，缺了它「生效值」事后无从核对
#[test]
fn tuning_without_getters_reach_engine_build_log() {
    let mut core_config = CoreConfig::default();
    core_config.engine.tuning.backtrace_details = crate::config::BacktraceDetails::Disable;
    core_config.engine.tuning.profiling = Some(crate::config::Profiling::None);

    let captured = capture(|| {
        let _ = runtime_with_setup(EngineSetup::new(core_config));
    });
    let engine_cfg = captured
        .iter()
        .find(|e: &&CapturedEvent| {
            e.level == Level::INFO
                && e.fields
                    .iter()
                    .any(|(k, _)| k.as_str() == "component_model_async")
        })
        .unwrap_or_else(|| {
            panic!("Engine 生效参数日志缺失（配置面不可观测即等于不可验证）: {captured:?}")
        });

    let fields: std::collections::HashMap<&str, &str> = engine_cfg
        .fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        fields.get("component_model_async"),
        Some(&"true"),
        "tuning.component_model_async 未落到 Engine 构建: {fields:?}"
    );
    assert_eq!(
        fields.get("profiling"),
        Some(&"Some(None)"),
        "tuning.profiling 未落到 Engine 构建: {fields:?}"
    );
}

/// 无效组合必须 warn（防「以为生效了」）：`epoch_interruption=true` 在本内核里
/// 无效——资源看门狗是 fuel，从不调 `set_epoch_deadline`
#[test]
fn incoherent_tuning_warns_instead_of_silently_doing_nothing() {
    let mut core_config = CoreConfig::default();
    core_config.engine.tuning.epoch_interruption = Some(true);

    let captured = capture(|| {
        let _ = runtime_with_setup(EngineSetup::new(core_config));
    });
    let warned = captured
        .iter()
        .any(|e| e.level == Level::WARN && e.message.contains("epoch_interruption"));
    assert!(
        warned,
        "开 epoch 中断而不设截止时间必须 warn（否则宿主以为拿到了墙钟看门狗）: {captured:?}"
    );
}

// ==================== 运行时覆盖：Engine 段的静默陷阱 ====================

/// `set_config` 携带 **Engine 段** 变更必须 warn
///
/// Engine 构建期固化，此后 `set_config` 里的 `engine` 段（含 17 个 tuning 字段）
/// 对已建 Engine 完全无效——不检测的话，「配了没生效」就是最难查的一类问题
/// （配置读回来是对的，行为却没变）。反向对照：只改 `store` 段（运行时真生效的
/// 部分）不得产生该告警，否则告警会被噪声淹没而失去意义。
#[test]
fn set_config_with_engine_change_warns_instead_of_doing_nothing() {
    let runtime = runtime_with_setup(EngineSetup::new(CoreConfig::default()));

    // 正例：Engine 段变了 → warn
    let mut with_engine_change = CoreConfig::default();
    with_engine_change.engine.tuning.debug_info = Some(true);
    let captured = capture(|| {
        runtime
            .set_config(with_engine_change)
            .expect("合法配置应被接受（warn 不等于拒绝）");
    });
    assert!(
        captured
            .iter()
            .any(|e| e.level == Level::WARN && e.message.contains("Engine 参数变更")),
        "Engine 段变更必须 warn（否则「配了不生效」静默）: {captured:?}"
    );

    // 反例：只改 Store 段（真生效面）→ 不告警
    let mut store_only = runtime.config();
    store_only.store.max_table_entries = 4096;
    let captured = capture(|| {
        runtime.set_config(store_only).expect("合法配置应被接受");
    });
    assert!(
        !captured
            .iter()
            .any(|e| e.level == Level::WARN && e.message.contains("Engine 参数变更")),
        "Store 段变更是运行时真生效的，不该告警（否则告警被噪声淹没）: {captured:?}"
    );
}

// ==================== 本用例文件内共享脚手架 ====================

/// 以指定装配输入构建无头运行时（经 test_support 的生产同构夹具）
fn runtime_with_setup(setup: EngineSetup) -> WasmRuntime {
    setup_wasm_runtime_with_setup(setup).0
}

/// 按内核配置构建 Engine 并取生效值句柄（`Config` 不可回读，`Engine` 才完整）
fn effective_engine(core_config: &CoreConfig, debug_mode: bool) -> wasmtime::Engine {
    wasmtime::Engine::new(&build_engine_config(core_config, debug_mode))
        .expect("按内核配置构建的引擎应可建")
}
