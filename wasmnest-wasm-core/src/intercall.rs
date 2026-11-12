//! 宿主→插件互调客户端（中立层，ADR 0033）
//!
//! **归属更正**：本模块原住在 `utils/auth/auth_center.rs`（注释写「调用认证中心
//! 互调 api」），但它实际是**通用** JSON-RPC 客户端——会话中心、认证中心、任何
//! 插件互调 api 都经它发起，唯一的差别只是目标 api 名。把通用客户端放在认证域
//! 会让「会话 API 依赖认证模块」这种错位在代码里成立，也会诱导后来人以为
//! `call_api` 只服务认证。故上提到 `wasm_core::intercall`（ADR 0033 §附带清理）。
//!
//! wire 形状与 SDK `api_call` 约定一致（ADR 0017：JSON-RPC 2.0 over host-bus）：
//! 请求 `{jsonrpc, id, method, params}`，响应 `{jsonrpc, id, result | error}`。
//! 请求 topic `wasmnest.api.<plugin-id>.<method>`，回复 topic
//! `wasmnest.api.reply.<caller>.<request-id>`；caller 是宿主虚拟身份
//! [`crate::host_api::api::HOST_API_CALLER_ID`]（互调门禁只校验目标 api
//! 的声明，不校验调用方身份——宿主对插件一律同权）。
//!
//! 这是 ADR 0022 §5.1.3 允许的**零解析窄转发**之一：宿主不解释 `method` 语义、
//! 不拆 `params` 字段（装进 JSON-RPC 信封只是为了发出去）、`result` 原样回传。

use std::sync::atomic::{AtomicU64, Ordering};

use crate::manager::runtime::WasmHostContext;
use crate::{AppError, Result};

/// 宿主→插件互调默认超时（毫秒）：单次操作远快于此，超时视为故障走拒绝（fail-closed）
pub const INTERCALL_TIMEOUT_MS: u64 = 5_000;

/// 认证中心调用超时（毫秒）——沿用互调默认档，单独具名以便审计
pub const AUTH_CENTER_TIMEOUT_MS: u64 = INTERCALL_TIMEOUT_MS;

/// 宿主互调请求 id 计数器（全局单调）
///
/// reply topic 含 caller+id，id 必须全局唯一防止并发调用串台——SDK 侧用
/// `thread_local`（wasm 单线程），宿主多线程必须用 `Atomic`。
static HOST_REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 取下一个全局唯一的宿主请求 id
pub fn next_host_request_id() -> String {
    let n = HOST_REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    format!("host-req-{n}")
}

/// 调插件互调 api：构造 JSON-RPC 请求 → 发布等待 → 解码 reply → 取 `result`
///
/// `api` 是**全限定** api 名 `<plugin-id>.<method>`（如
/// `com.wasmnest.bedcode.session-list`）；JSON-RPC 的 `method` 字段取短名
/// （插件侧宏按短名分派，同 SDK client 约定）。
///
/// 失败面全部 `Err`（不回退成「空结果」）：传输失败 / reply 非法 JSON / 错误信封
/// / 缺 `result`——四种都在错误里点名 api 名，排障不靠猜。
pub fn call_api(
    host_ctx: &WasmHostContext,
    api: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let request_topic = format!("wasmnest.api.{api}");
    let method = api.rsplit_once('.').map(|(_, m)| m).unwrap_or(api);
    let id = next_host_request_id();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let reply_json = host_ctx
        .call_plugin_api_host(&request_topic, &payload.to_string(), INTERCALL_TIMEOUT_MS)
        .map_err(|e| AppError::Plugin(format!("plugin api call '{api}' failed: {e}")))?;
    let reply: serde_json::Value = serde_json::from_str(&reply_json)
        .map_err(|e| AppError::Plugin(format!("plugin api '{api}' reply invalid JSON: {e}")))?;
    if let Some(err) = reply.get("error") {
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("rpc error")
            .to_string();
        return Err(AppError::Plugin(format!(
            "plugin api '{api}' error: {message}"
        )));
    }
    reply
        .get("result")
        .cloned()
        .ok_or_else(|| AppError::Plugin(format!("plugin api '{api}' reply missing result/error")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 请求 id 全局单调递增且带宿主前缀（回复 topic 用它寻址，重复即串台）
    #[test]
    fn request_ids_are_unique_and_prefixed() {
        let a = next_host_request_id();
        let b = next_host_request_id();
        assert_ne!(a, b, "id 必须唯一（否则并发调用串台）");
        for id in [&a, &b] {
            assert!(id.starts_with("host-req-"), "前缀约定: {id}");
            assert!(
                id["host-req-".len()..].parse::<u64>().is_ok(),
                "尾部是计数: {id}"
            );
        }
        // 单调
        let a_n: u64 = a["host-req-".len()..].parse().expect("n");
        let b_n: u64 = b["host-req-".len()..].parse().expect("n");
        assert!(b_n > a_n, "必须单调递增: {a} -> {b}");
    }
}
