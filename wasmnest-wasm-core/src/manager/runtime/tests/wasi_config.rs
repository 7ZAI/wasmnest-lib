//! WASI 面配置开关（用户裁决 2026-10-12：住核心、双端默认全开、外部配置可关）
//!
//! 判据落在 **linker 注册**上：关掉后 import WASI 的插件在**实例化**阶段即失败
//! （缺 import 实现，fail-visible，不静默降级）；开着则照常实例化。
//!
//! 夹具用 `build_wasi_test_component()`（wasm32-wasip2，与 preopen 闭环同款产物）：
//! 它静态 import wasi 0.2（std::fs/clock 等）⇒ 「关 p2 后能不能实例化」就是开关
//! 是否真的生效的可见证据。默认配置下的成功路径由 `preopen_e2e` 覆盖（同一产物、
//! 同一装配入口），本条只钉开关的**判别力**。

use super::*;

use crate::config::WasiConfig;

/// 默认配置（enabled/p2/p3 全开）：wasip2 夹具正常实例化
///
/// 与 `wasi_disabled_config_blocks_wasip2_plugin` 同产物成对——一条钉「开着能用」，
/// 一条钉「关了就断」，两条一起才排除「其实一直不能实例化」的假阳性。
#[test]
fn wasi_default_config_instantiates_wasip2_plugin() {
    let (wasm_runtime, host_ctx) = setup_wasm_runtime();
    let component = wasm_runtime
        .compile_component(&build_wasi_test_component())
        .expect("compile wasi test component");
    wasm_runtime
        .instantiate_component(&component, "com.wasmnest.wasi-test", host_ctx, &[], None)
        .expect("默认配置下 wasip2 插件必须能实例化");
}

/// `wasi.enabled=false`：同一产物实例化失败（缺 import 实现）
#[test]
fn wasi_disabled_config_blocks_wasip2_plugin() {
    let (wasm_runtime, host_ctx) = {
        let cfg = CoreConfig {
            wasi: WasiConfig {
                enabled: false,
                ..WasiConfig::default()
            },
            ..CoreConfig::default()
        };
        setup_wasm_runtime_with_config(cfg)
    };
    let component = wasm_runtime
        .compile_component(&build_wasi_test_component())
        .expect("compile wasi test component");
    // 不用 `expect_err`：成功值 `LoadedWasmPlugin` 未实现 Debug（也没必要为一个
    // 测试断言给它加 Debug 面）
    let err = match wasm_runtime.instantiate_component(
        &component,
        "com.wasmnest.wasi-test",
        host_ctx,
        &[],
        None,
    ) {
        Ok(_) => panic!("关闭 WASI 面后 import WASI 的插件必须实例化失败"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to instantiate WASM component"),
        "失败必须来自实例化阶段（缺 import），实际: {msg}"
    );
}

/// `wasi.p2=false`（p3 仍开）：wasip2 产物同样实例化失败
///
/// 与「只关 p3」对照：p2/p3 是两个独立开关（版本不同名可共存），
/// 不能实现成「任一为 false 就全关」——那会让只想回退 p3 的宿主连带失去 p2 插件。
#[test]
fn wasi_p2_disabled_blocks_wasip2_plugin_while_p3_stays_on() {
    let (wasm_runtime, host_ctx) = {
        let cfg = CoreConfig {
            wasi: WasiConfig {
                enabled: true,
                p2: false,
                p3: true,
            },
            ..CoreConfig::default()
        };
        setup_wasm_runtime_with_config(cfg)
    };
    let component = wasm_runtime
        .compile_component(&build_wasi_test_component())
        .expect("compile wasi test component");
    let err = match wasm_runtime.instantiate_component(
        &component,
        "com.wasmnest.wasi-test",
        host_ctx,
        &[],
        None,
    ) {
        Ok(_) => panic!("关掉 p2 后 wasip2 插件必须实例化失败"),
        Err(e) => e,
    };
    assert!(
        err.to_string()
            .contains("Failed to instantiate WASM component"),
        "失败必须来自实例化阶段（缺 p2 import），实际: {err}"
    );
}

/// `wasi.p3=false`（p2 仍开）：wasip2 产物照样实例化
///
/// 反例锁：把开关实现成「p3=false ⇒ 整段 WASI 不注册」会红本条。
#[test]
fn wasi_p3_disabled_keeps_wasip2_plugin_working() {
    let (wasm_runtime, host_ctx) = {
        let cfg = CoreConfig {
            wasi: WasiConfig {
                enabled: true,
                p2: true,
                p3: false,
            },
            ..CoreConfig::default()
        };
        setup_wasm_runtime_with_config(cfg)
    };
    let component = wasm_runtime
        .compile_component(&build_wasi_test_component())
        .expect("compile wasi test component");
    wasm_runtime
        .instantiate_component(&component, "com.wasmnest.wasi-test", host_ctx, &[], None)
        .expect("只关 p3 不得影响 wasip2 插件（两个开关独立）");
}
