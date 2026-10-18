//! add_to_linker 注册闭环（component.rs 直测）
//!
//! 自 `common/component.rs` 的 `mod tests` 拆出（共享脚手架在父 `mod tests`，
//! 经 `use super::*` 可见）；fixture 互斥与产物构建语义不变。
//!
//! **票 04 迁移记录**：原第三条用例 `test_loaded_plugin_component_roundtrip`
//! （组件完整往返 + activate 燃料消耗）随「wasm-core 不再持全 world 绑定」删除，
//! 覆盖等价迁移到桌面宿主：
//! - 往返本体（activate/deactivate/manifest/invoke_command + 跨边界 storage 往返）
//!   → `src-tauri/tests/component_e2e.rs::test_component_roundtrip`（逐条覆盖）；
//! - activate 消耗燃料 → `src-tauri/tests/engine_e2e.rs::test_component_fuel_watchdog`
//!   （更强：含「每次调用前续费」断言）。
//!
//! 留本文件的两条只做 linker 注册（不实例化组件），属内核机制单测。

use super::*;
// WASI 面开关（默认全开）：注册面判据见 `manager/runtime/wasi.rs`
use crate::config::WasiConfig;

/// 内核本地表里逐行列举的 import 接口全部注册成功（add_to_linker 是纯接线代码，
/// 任何一组接口名冲突/接线参数错误都会在此失败）。含 ADR 0036 归位的
/// `host-storage` / `host-database` / `host-plugin-database` 三组。
#[test]
fn test_add_to_linker_registers_all_interfaces() {
    let engine = test_engine();
    let mut linker = Linker::new(&engine);
    add_to_linker(&mut linker, &WasiConfig::default()).expect("register all host interfaces");
}

/// 重复注册同一组接口必须报错
///
/// 防止 add_to_linker 被调用两次时静默覆盖接线（实例化时会以
/// 意外行为失败，不如注册期直接暴露）
#[test]
fn test_add_to_linker_rejects_duplicate_registration() {
    let engine = test_engine();
    let mut linker = Linker::new(&engine);
    add_to_linker(&mut linker, &WasiConfig::default()).expect("first registration");

    let err = add_to_linker(&mut linker, &WasiConfig::default()).expect_err("duplicate registration should fail");
    // wasmtime 对已注册的同名 interface instance 报 "defined twice"
    assert!(
        err.to_string().contains("defined twice"),
        "unexpected duplicate registration error: {}",
        err
    );
}
