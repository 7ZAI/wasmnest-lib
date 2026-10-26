//! WASI preopen 测试插件（wasm32-wasip2 目标，能力仓自持夹具）
//!
//! 与组件共存插件（wasm32-unknown-unknown）的区别：本插件编译到 WASI preview2
//! 目标（rustup target add wasm32-wasip2），std::fs 直连 WASI 文件系统——宿主在
//! 实例化时按插件配置预打开目录 `/data` 后，插件即拥有对该目录的直接读写能力
//! （无需宿主 fs_* 转发）。
//!
//! **preopen 仅 worker 类别可用（ADR 0034）**：主 wasm-app 文件访问一律走宿主
//! host-fs 授权机制；本夹具是 worker 预留能力的**机制守门测试**（在策略闸门
//! 之下，不走 manifest 校验路径），worker 启用专项需一并解决 wasip3 的 preopen
//! 装配问题。
//!
//! 绑定面是能力仓契约真源 `wit/core.wit` 的 `world core`（三仓拆分票 08 批次三）：
//! 夹具只验证运行时壳的 WASI 装配 / preopen，不需要任何端 cap 与端 SDK——绑定
//! 能力仓自己的 WIT 即可自足。`world core` 的必选导出（command / lifecycle /
//! manifest）由本文件全量实现；`events-binary` 是可选导出面，不在 world 内，本
//! 夹具不提供。
//!
//! 产物形态：wasm32-wasip2 目标下 Rust std 直连 WASI p2，产物直接是组件
//! （wasm-component-ld 内嵌），无需 wit-component 再编码。

wit_bindgen::generate!({
    // 契约真源：本 crate 的 `wit/core.wit`（夹具目录上溯两级即 crate 根）
    path: "../../wit/core.wit",
    world: "core",
});

use exports::wasmnest::plugin::{
    command::Guest as CommandGuest, lifecycle::Guest as LifecycleGuest,
    manifest::Guest as ManifestGuest,
};

/// wasi-test 插件（无状态）
struct WasiTestPlugin;

impl CommandGuest for WasiTestPlugin {
    /// 宿主 `invoke_command` 的 JSON 字符串契约（与 SDK `wasm_entry!` 同形）：
    /// 成功回结果 JSON，失败回 `{"error": "..."}`（宿主据此解析错误）
    fn invoke(name: String, _args_json: String) -> String {
        match name.as_str() {
            // 经 WASI preopen `/data` 直接写文件（宿主侧校验落盘）
            "wasi-test.write-file" => match std::fs::write("/data/demo.txt", "hello-from-wasi") {
                Ok(()) => json_ok(serde_json::json!({ "ok": true })),
                Err(e) => json_error(&format!("wasi write failed: {e}")),
            },
            // 读回（内容应为上一次写入的字面量）
            "wasi-test.read-file" => match std::fs::read_to_string("/data/demo.txt") {
                Ok(content) => json_ok(serde_json::json!({ "content": content })),
                Err(e) => json_error(&format!("wasi read failed: {e}")),
            },
            // 列举预打开目录（证明 preopen 对 guest 可见）
            "wasi-test.list" => match std::fs::read_dir("/data") {
                Ok(entries) => {
                    let entries: Vec<String> = entries
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect();
                    json_ok(serde_json::json!({ "entries": entries }))
                }
                Err(e) => json_error(&format!("wasi read_dir failed: {e}")),
            },
            // 访问预打开根之外的路径必须失败（WASI 沙箱边界断言）
            "wasi-test.outside-root" => match std::fs::metadata("/tmp/outside.txt") {
                Ok(_) => json_ok(serde_json::json!({ "leaked": true })),
                Err(e) => json_ok(serde_json::json!({ "leaked": false, "error": e.to_string() })),
            },
            other => json_error(&format!("unknown command: {other}")),
        }
    }
}

impl LifecycleGuest for WasiTestPlugin {
    fn activate() -> Result<(), String> {
        Ok(())
    }

    fn deactivate() -> Result<(), String> {
        Ok(())
    }

    fn on_startup() -> Result<(), String> {
        Ok(())
    }

    fn on_shutdown() -> Result<(), String> {
        Ok(())
    }
}

impl ManifestGuest for WasiTestPlugin {
    /// manifest 真源 = 同目录 plugin.json（JSON 字符串原样上抛，宿主自行解析）
    fn get() -> String {
        include_str!("../plugin.json").to_string()
    }
}

/// 成功结果序列化（`serde_json::to_string` 对 JSON 值不会失败，失败退化为 error 形状）
fn json_ok(value: serde_json::Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|e| json_error(&format!("serialize result: {e}")))
}

/// 失败结果（与 SDK `wasm_entry!` 相同的 `{"error": ...}` 形状；经 serde_json 转义）
fn json_error(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

export!(WasiTestPlugin);
