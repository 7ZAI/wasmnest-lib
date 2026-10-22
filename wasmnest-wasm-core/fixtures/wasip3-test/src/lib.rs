//! wasip3 async 机制测试插件（wasm32-wasip3 目标，能力仓自持夹具）
//!
//! A0-3 前置探针（P1 async store 兼容性 / P2 资源限制 async 语义）的 guest 载体
//! （原平台 `plugin-sdk-fixtures` 的 `wasip3` feature 分支，三仓拆分票 08 批次三
//! 迁入能力仓）：绑定 wasm-core 契约真源 `wit/core.wit` 的 `world core`，零 SDK
//! 依赖——探针要验的是运行时壳机制，与端 cap 无关。
//!
//! 行为契约（宿主探针用例断言依据）：
//! - `a03.host-log-roundtrip`：调宿主 host-log 原语三条（async store 下
//!   `block_on_async` 桥不得 panic）→ `{ ok, host, calls }`；
//! - `a03.spin`：确定性 guest 计算（`{ iters }` 原样回显，供燃料缩放断言）；
//! - `a03.allocate`：显式 guest 内存分配（调用期 memory.grow 探针）；
//! - `wasip3-test.read-clock`：wasip3 时钟可读性（std::time → wasi:clocks）；
//! - `wasip3-test.get-random` / `a03.get-random`：async wasi:random 熵源
//!   （宿主断言非零 + 跨调用不等）。
//!
//! `world core` 的必选导出（command / lifecycle / manifest）由本文件全量实现；
//! `events-binary` 是可选导出面，不在 world 内，本夹具不提供。

wit_bindgen::generate!({
    // 契约真源 + test-only world：先加载 crate `wit/`（core.wit 契约真源），再加载
    // 夹具 `wit/`（`wasip3-fixture` = core + 可选导出 events-binary）。world 与
    // import 接口分属两个 package ⇒ 按 wit-bindgen 要求给 import 面 `with: generate`
    // （绑定名仍是 `wasmnest:plugin/...`，与生产契约逐字一致）。
    path: ["../../wit", "wit"],
    world: "wasmnest:fixture-wasip3/wasip3-fixture",
    with: {
        "wasmnest:plugin/host-storage@0.0.2": generate,
        "wasmnest:plugin/host-events@0.0.2": generate,
        "wasmnest:plugin/host-bus@0.0.2": generate,
        "wasmnest:plugin/host-platform@0.0.2": generate,
        "wasmnest:plugin/host-fs@0.0.2": generate,
        "wasmnest:plugin/host-log@0.0.2": generate,
        "wasmnest:plugin/host-config@0.0.2": generate,
        "wasmnest:plugin/host-plugin-database@0.0.2": generate,
        "wasmnest:plugin/host-metrics@0.0.2": generate,
    },
});

use exports::wasmnest::plugin::{
    command::Guest as CommandGuest, events_binary::Guest as EventsBinaryGuest,
    lifecycle::Guest as LifecycleGuest, manifest::Guest as ManifestGuest,
};
use wasmnest::plugin::host_log;

/// wasip3-test 插件（无状态）
struct Wasip3TestPlugin;

impl CommandGuest for Wasip3TestPlugin {
    fn invoke(name: String, args_json: String) -> String {
        let args: serde_json::Value =
            serde_json::from_str(&args_json).unwrap_or(serde_json::Value::Null);
        match dispatch(&name, &args) {
            Ok(value) => json_ok(value),
            Err(e) => json_error(&e.to_string()),
        }
    }
}

/// 命令分派（`anyhow::Result` 收口，错误经 `{"error": ...}` 上抛）
fn dispatch(name: &str, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    match name {
        // P1-a：同步注册的宿主原语（host-log）在 async store 下由 wasip3 组件调用
        "a03.host-log-roundtrip" => {
            host_log::info("[a03] host-log info under async store");
            host_log::debug("[a03] host-log debug under async store");
            host_log::warn("[a03] host-log warn under async store");
            Ok(serde_json::json!({ "ok": true, "host": "host-log", "calls": 3 }))
        }
        // P2 燃料：确定性 guest 计算，iters 原样回显（非法 JSON 会静默退回默认值，
        // 探针据此把「载荷真的抵达 guest」钉成强断言）
        "a03.spin" => {
            let iters = args
                .get("iters")
                .and_then(|v| v.as_u64())
                .unwrap_or(1_000_000);
            let mut acc: u64 = 0;
            for i in 0..iters {
                acc = acc.wrapping_add(i ^ (i >> 13));
            }
            Ok(serde_json::json!({ "ok": true, "iters": iters, "acc": acc }))
        }
        // P2 ResourceLimiter 调用期探针：显式分配触发 memory.grow → 宿主
        // memory_growing 拒绝线
        "a03.allocate" => {
            let bytes = args.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let buf = vec![0u8; bytes as usize];
            let len = buf.len();
            drop(buf);
            Ok(serde_json::json!({ "ok": true, "allocated": len }))
        }
        // wasip3 时钟可读性：std::time 在 WASI 0.3 下走 wasi:clocks 导入
        "wasip3-test.read-clock" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            Ok(serde_json::json!({ "unix_ms": now }))
        }
        // async wasi:random 熵源（32 字节）
        "wasip3-test.get-random" => {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("getrandom failed: {e}"))?;
            Ok(serde_json::json!({ "hex": hex(&buf) }))
        }
        // P1-a 别名：async wasi:random 与 sync host 原语在同一调用链共存（16 字节）
        "a03.get-random" => {
            let mut buf = [0u8; 16];
            getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("getrandom failed: {e}"))?;
            Ok(serde_json::json!({ "ok": true, "hex": hex(&buf) }))
        }
        other => Err(anyhow::anyhow!("unknown command: {other}")),
    }
}

/// 字节列 → 小写 hex（探针断言用）
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl LifecycleGuest for Wasip3TestPlugin {
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

impl ManifestGuest for Wasip3TestPlugin {
    fn get() -> String {
        include_str!("../plugin.json").to_string()
    }
}

impl EventsBinaryGuest for Wasip3TestPlugin {
    /// 可选导出面（世界声明见 `wit/wasip3-fixture.wit`）：探针只验证「在 async
    /// store 下可调」（原生 TypedFunc 探测路径），回调体不产生副作用。
    fn on_message_binary(_topic: String, _sender: String, _payload: Vec<u8>) {}
}

fn json_ok(value: serde_json::Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|e| json_error(&format!("serialize result: {e}")))
}

fn json_error(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

export!(Wasip3TestPlugin);
