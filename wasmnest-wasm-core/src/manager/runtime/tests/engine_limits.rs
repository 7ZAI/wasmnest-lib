//! Engine/AOT 缓存 key/配置校验/桥重入——**形态无关纯机制用例**
//!
//! 票 04 拆分：本文件原含 18 条用例，其中 14 条需要真实 SDK 夹具实例（燃料看门狗 /
//! AOT 缓存全链 / limiter 记账 / monitor / trap 证据链 / 资源覆盖），随
//! 「wasm-core 不再持全 world 绑定」迁桌面宿主 `src-tauri/tests/engine_e2e.rs`；
//! 留本文件的 3 条不实例化组件（缓存 key 纯函数 / 配置校验 / block_on_async 重入），
//! 属内核机制单测，与形态无关。
//!
//! 原文件的 `use super::*` 共享脚手架语义不变（`mod tests` 在 `common.rs`）。

use super::*;
// `aot_cache_key` 双源（父模块私有 `use engine::aot_cache_key` 与 test_support 的
// 宿主转发面同名函数）——显式导入胜过两个 glob，消歧义
use crate::manager::runtime::engine::aot_cache_key;

/// 缓存 key：源码大小变化必须换 key（防解压器保留旧 mtime 时误加载旧产物）
#[test]

fn test_aot_cache_key_factors_source_size() {
    let path = std::path::Path::new("plugin.wasm");
    assert_eq!(aot_cache_key(path, 100), aot_cache_key(path, 100));
    assert_ne!(aot_cache_key(path, 100), aot_cache_key(path, 200));
}

/// 票据 02 验收：非法配置（燃料为 0）被 set_config 拒绝且带上下文；旧配置不受影响
#[test]

fn test_set_config_rejects_invalid() {
    let (wasm_runtime, _host_ctx) = setup_wasm_runtime();
    let mut cfg = CoreConfig::default();
    cfg.store.fuel_per_call = 0;
    let err = wasm_runtime.set_config(cfg).expect_err("zero fuel must be rejected");
    assert!(format!("{err}").contains("fuel_per_call"));
    assert_eq!(wasm_runtime.config(), CoreConfig::default());
}

#[test]

fn block_on_async_reentrant_nested_call_no_panic() {
    // 回归（panic.log 实证 wasm_runtime.rs:82 FATAL）：
    // 插件分发路径 dispatch_*_to_plugin → block_on_async（block_in_place +
    // handle.block_on）包着插件调用，插件回调里的宿主函数（session_get /
    // config_get / db 查询等）再调 block_on_async 构成重入。旧实现重入分支
    // 直接 handle.block_on —— 外层 block_on 的 enter 守卫仍挂在当前线程上，
    // 必然 panic（Cannot start a runtime from within a runtime），panic 穿透
    // 污染 wasmtime Store 导致插件 trap → 重载循环 → 插件整体失效。
    // 修复：重入分支改在新线程上 block_on，此处验证重入可返回且嵌套 future
    // 真正挂起（sleep）时也能被 runtime 唤醒（无死锁）。
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // tokio::spawn：模拟真实分发在 worker 线程执行（block_in_place 前置条件）
        tokio::spawn(async move {
            // 外层 block_on_async：模拟 dispatch_*_to_plugin 的同步桥接
            let outer = block_on_async(async {
                // 内层 block_on_async：模拟插件回调内的宿主函数调用（重入分支）
                let inner = block_on_async(async {
                    // 真实挂起：验证新线程上的 block_on 能被 runtime 定时器唤醒
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    42u32
                });
                inner * 2
            });
            assert_eq!(outer, 84);
        })
        .await
        .expect("spawned task must not panic");
    });
}
