//! 测试基建（常编译公开，lib / 宿主测试消费）。
//!
//! ## 两个消费面（**测试面**分叉，不是运行时形态）
//!
//! 单形态（2026-10-13）后运行时无 common/bare 之分，但测试基建按**宿主消费面**
//! 分两个子模块——两侧消费的夹具与转发面不同，合并会造出一个谁都不用的超集：
//!
//! - **桌面宿主消费面**（`desktop-assembly`）：[`common`] —— setup_wasm_runtime /
//!   build_host_ctx_at / TestInstanceDispatcher / SDK 夹具字节读取…
//! - **移动宿主消费面**（`test-support`）：[`bare`]（**历史模块名**：fork 期的
//!   形态词，运行时单形态后仅指「移动 `src-tauri` 测试面」）—— MockPorts /
//!   夹具组件构建器 / mock_plugin_ws / build_component_state…，内部引用已改指
//!   统一运行时壳（`LoadedWasmPlugin` / 统一 `add_to_linker`）。
//!
//! 两子模块各由一侧宿主测试编译（桌面宿主开默认 features、移动宿主
//! `default-features = false` + dev-deps `test-support`）；**两侧都用的符号只在本
//! 模块定义一份**——第二份副本是第二真源，改动时会静默漂移。

#[cfg(feature = "desktop-assembly")]
mod common;

#[cfg(feature = "desktop-assembly")]
pub use common::*;

#[cfg(feature = "test-support")]
pub mod bare;

#[cfg(feature = "test-support")]
pub use bare::*;

// ==================== 两消费面共享符号（单点定义） ====================

/// 测试用插件 ID（宿主主库表前缀校验依赖它）
///
/// `manager/host.rs` 内联测试模块另有同值自持常量（模块树不同，互不引用）。
pub const TEST_PLUGIN_ID: &str = "com.wasmnest.test";

/// 取插件实例的裸 Store / Instance（燃料注入、limiter 记账、导出直调断言用）
///
/// 壳内 `raw_store` 是 `pub(crate)`；宿主集成测试链的是**不带 `cfg(test)`** 的
/// lib（`#[cfg(test)]` 项等价于不可达），本转发面是宿主测试唯一可达路径
/// （与 [`runtime_engine`] 同章程）。
pub fn plugin_raw_store(
    plugin: &mut crate::manager::runtime::LoadedWasmPlugin,
) -> (
    &mut wasmtime::Store<crate::manager::runtime::WasmPluginState>,
    &wasmtime::component::Instance,
) {
    plugin.raw_store()
}

/// 运行时 Engine 转发（统一壳 `engine()` 是 pub(crate)，跨 crate 消费经此面）
///
/// 引擎生效配置断言用（`Config` 不可回读，`Engine` 才完整）；无条件
/// （desktop-assembly 与 test-support 两消费面都编译）——两侧宿主测试共用同一
/// 转发面。
pub fn runtime_engine(runtime: &crate::manager::runtime::WasmRuntime) -> &wasmtime::Engine {
    runtime.engine()
}

// ==================== 说明：应用仓读取已全部归位平台仓（票 08 批次三） ====================
//
// 能力仓测试**不读应用仓任何目录**：曾在此的 `apps_root` / `app_dir` resolver 随
// 其消费者（bedcode 桌面 manifest 清单 / 移动插件构建）一并迁平台仓测试面
// （桌面 `src-tauri/tests/support/app_paths.rs` 与移动测试同名 helper）。
// 能力仓夹具已自持（`fixtures/*` 绑定本 crate `wit/core.wit`），无需外部路径。
