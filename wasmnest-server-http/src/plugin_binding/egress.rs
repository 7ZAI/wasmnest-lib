//! host-http 能力域的**出站**段（guest → 外部 HTTP 服务端）
//!
//! spec：`.scratch/2026-10-04-wasm-core-lib-split/spec.md` §7 D10（http 出站并入
//! `wasmnest-server-http`，不建独立 crate）；票 06。
//!
//! **零业务代码红线（D1）**：本模块只做引擎原语——连接发起、超时/响应体上限、
//! 跳转裁决、载荷与响应打包；**不解析任何供应商协议**（`sseFormat` 只有「raw 逐
//! chunk 透传」与「通用 SSE 按分隔符切分、透传 data 原文」两档，OpenAI/Anthropic
//! 等格式一律由插件消费侧自管，票据 02 的语义原样保留）。
//!
//! ## 为什么出站住在传输面 crate（spec §7.1 的实测结论）
//!
//! 「出站是 HTTP 客户端、入站是 HTTP 服务端技术栈」——两者在代码上**零依赖**，
//! 只是同名。但入站注册表本来就在本 crate，而出站只有 1 条 WIT 原语、独立 crate
//! 过薄，故同归本 crate、分成两个模块（入站见 [`crate::plugin_binding`]）。
//!
//! ## 安全语义（逐字保留，不得作为可调参数放宽）
//!
//! - **跳转裁决**：reqwest 默认跟随 10 跳且不重校验目标——公网插件 API 302 到内网 /
//!   云元数据在无系统代理环境（直连）下即 SSRF。本域的 [`redirect_decision`] 是
//!   **执行期**裁决，与授权层的档位正交（授权层只回答「要不要问用户」），
//!   实测锁见 [`crate::plugin_binding::tests`]；
//! - **私网直连**：局域网文件服务走 `no_proxy` 客户端（避免系统代理把请求劫持到
//!   本地代理端口），判定用标准库 `is_private()` 动态识别 RFC1918/回环/链路本地，
//!   不硬编码网段；
//! - **响应体上限**：带上限流式读取，超限立即中止连接并引导 `stream:true`
//!   （防止无上限载荷拷进 guest 内存 + guest 解析耗尽 fuel 触发 trap 污染 Store）。
//!
//! ## 分层
//!
//! ```text
//!   本文件        出站机制（客户端池 / 跳转裁决 / 请求执行 / SSE 切分）
//!   ports.rs      边界：权限门 / 出站授权裁决 / 前端事件通道 / 异步桥
//! ```

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crate::wire::PERMISSION_NETWORK_HTTP;
use futures_util::StreamExt;
use wasmnest_server_base::constants::{
    PLUGIN_HTTP_CONNECT_TIMEOUT_SECS, PLUGIN_HTTP_RESPONSE_BODY_LIMIT_BYTES, PLUGIN_HTTP_TIMEOUT_SECS,
};
use wasmnest_server_base::error_boundary::spawn_with_error_boundary;

use crate::plugin_binding::ports::{block_on, HttpEventSink, HttpPorts, OutboundAuth};

// ==================== 客户端池 ====================

/// 非流式 HTTP 客户端（连接超时 + 总超时，全宿主复用连接池）
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(PLUGIN_HTTP_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(PLUGIN_HTTP_TIMEOUT_SECS))
        .redirect(redirect_policy())
        .build()
        .unwrap_or_default()
});

/// 流式 HTTP 客户端（仅连接超时，不设总超时 — SSE 长连接不应被截断）
static HTTP_STREAM_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(PLUGIN_HTTP_CONNECT_TIMEOUT_SECS))
        .redirect(redirect_policy())
        .build()
        .unwrap_or_default()
});

/// 判断目标地址是否为私网/回环/链路本地地址（动态判定，无硬编码网段）
///
/// 系统代理（如 Clash）只应代理外网：局域网文件服务（对端共享目录）请求若
/// 走代理，会被劫持到本地代理端口（127.0.0.1:10808），对端服务器收不到请求。
/// 标准库 `Ipv4Addr::is_private()` 即 RFC1918（10/8、172.16/12、192.168/16），
/// 配合 loopback/link-local，覆盖内网传输场景的全部直连目标。
pub(crate) fn is_private_target(url: &str) -> bool {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().and_then(|h| h.parse::<std::net::IpAddr>().ok()))
        .map(|ip| match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
        })
        .unwrap_or(false)
}

/// 跳转裁决（纯函数，供 `redirect_policy` 与单测共用）：
///
/// reqwest 默认跟随 10 跳且不重校验目标——公网插件 API 302 到内网/云元数据
/// 在无系统代理环境（直连）下即 SSRF。规则：
/// - 公网目标：跟随；
/// - 私网目标：仅当链上前序 URL 全为私网时跟随（局域网文件服务站内跳转）；
///   其余（公网 → 私网）Stop，调用方拿到 3xx 自行处理。
pub(crate) fn redirect_decision(next_url: &str, previous: &[&str]) -> bool {
    if !is_private_target(next_url) {
        return true;
    }
    !previous.iter().any(|p| !is_private_target(p))
}

/// reqwest 跳转策略：`redirect_decision` 的适配层（同步裁决，见其文档）
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let prev: Vec<&str> = attempt.previous().iter().map(|u| u.as_str()).collect();
        if redirect_decision(attempt.url().as_str(), &prev) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// 直连客户端（禁系统代理）：私网目标（局域网文件服务）专用，
/// 配置与对应默认 client 一致（超时/响应上限语义不变）
static HTTP_DIRECT_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(PLUGIN_HTTP_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(PLUGIN_HTTP_TIMEOUT_SECS))
        .redirect(redirect_policy())
        .build()
        .unwrap_or_default()
});

/// 流式直连客户端（禁系统代理，仅连接超时）
static HTTP_DIRECT_STREAM_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(PLUGIN_HTTP_CONNECT_TIMEOUT_SECS))
        .redirect(redirect_policy())
        .build()
        .unwrap_or_default()
});

/// 按目标地址选择客户端：私网直连，其余走系统代理（外网插件 API 不受影响）
fn client_for(url: &str) -> &'static reqwest::Client {
    if is_private_target(url) {
        &HTTP_DIRECT_CLIENT
    } else {
        &HTTP_CLIENT
    }
}

/// 流式客户端选择（同上）
fn stream_client_for(url: &str) -> &'static reqwest::Client {
    if is_private_target(url) {
        &HTTP_DIRECT_STREAM_CLIENT
    } else {
        &HTTP_STREAM_CLIENT
    }
}

// ==================== 出站原语 ====================

/// 发起 HTTP 请求（宿主代发，支持 SSE 流式推流）
///
/// request_json 格式：
/// ```json
/// {
///   "method": "POST",
///   "url": "https://api.example.com/v1/chat",
///   "headers": { "Authorization": "Bearer xxx", "Content-Type": "application/json" },
///   "body": "{...}",
///   "stream": true,
///   "streamEvent": "ai-chatbox:stream:xxx"
/// }
/// ```
///
/// 流式模式：宿主 spawn tokio 任务执行 HTTP 请求，逐 chunk 通过事件通道推送，
/// 本函数立即返回 stream_id
/// 非流式模式：block_on 执行，返回完整响应
///
/// `may_prompt` 决定未记录目标怎么处理：WIT import 路径（插件主流程）传 `true`
/// （可弹窗询问用户）；**任务单元（core-task 池线程）传 `false`**——弹窗会占住池槽位
/// 最短 30s，且用户在错误的时机看到问题（与 fs 任务单元同款约束）。池线程侧只认授权
/// 记录，未记录即 fail-visible 拒绝（端口的 `may_prompt = false` 分支）。
pub fn http_fetch(
    ports: &Arc<dyn HttpPorts>,
    plugin_id: &str,
    request_json: &str,
    may_prompt: bool,
) -> Result<Option<String>, String> {
    // 权限仲裁：未声明 network:http 的插件（WASM 路径）在宿主侧直接拒绝。
    // 前端 TS 路径已 fast-fail，此处是 Rust 端最终仲裁（安全边界，AGENTS.md §8）。
    if !ports.check_permission(plugin_id, PERMISSION_NETWORK_HTTP, "host_http_fetch") {
        return Err(format!(
            "http error: permission denied: plugin '{}' does not declare network:http",
            plugin_id
        ));
    }
    let request: serde_json::Value =
        serde_json::from_str(request_json).map_err(|e| format!("http error: invalid request JSON: {}", e))?;

    // 出站授权（票 05 / spec §6.1）：位置在声明门之后、**任何网络动作之前**——
    // 流式与非流式两条分支都在此之前收敛，被拒的请求绝不会触达网络。
    // 缺 `url` 的请求不在此处拦（归执行层的「Missing 'url'」错误），错误分类保持不变。
    if let Some(url) = request.get("url").and_then(|v| v.as_str()) {
        match ports.authorize_outbound(plugin_id, url, may_prompt) {
            OutboundAuth::Allowed { origin } => {
                tracing::debug!(
                    plugin_id = %plugin_id,
                    origin = %origin,
                    may_prompt,
                    "host-http: 出站授权放行"
                );
            }
            OutboundAuth::Denied { reason, origin } => {
                // 错误串只带归一化 origin（不带 path / query：AGENTS §8 凭据红线）
                return Err(format!(
                    "http error: network authorization denied ({}): plugin '{}' -> {}",
                    reason, plugin_id, origin
                ));
            }
            OutboundAuth::CheckFailed(e) => {
                return Err(format!("http error: network authorization check failed: {}", e));
            }
        }
    }

    let is_stream = request.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

    if is_stream {
        // 流式模式：spawn 后台任务，立即返回 stream_id
        let stream_id = uuid::Uuid::new_v4().to_string();
        let stream_event = request
            .get("streamEvent")
            .and_then(|v| v.as_str())
            .unwrap_or(&stream_id)
            .to_string();

        // 流式推送依赖前端事件通道，无头上下文不可用（缺席 ≠ 投递失败，见 ports 文档）
        let Some(event_sink) = ports.event_sink() else {
            return Err("http error: streaming requires app_handle".to_string());
        };

        let plugin_id_clone = plugin_id.to_string();
        let stream_event_clone = stream_event.clone();
        spawn_with_error_boundary("streaming_http", async move {
            if let Err(e) =
                execute_streaming_http(&request, event_sink.as_ref(), &stream_event_clone, &plugin_id_clone).await
            {
                tracing::error!(
                    error = %e,
                    plugin_id = %plugin_id_clone,
                    stream_event = %stream_event_clone,
                    "Streaming HTTP request failed"
                );
                // 发送错误事件通知插件
                event_sink.emit(
                    &stream_event_clone,
                    serde_json::json!({ "error": e.to_string(), "done": true }),
                );
            }
        });

        let result_json = serde_json::json!({
            "streamId": stream_id,
            "streamEvent": stream_event,
        });
        serde_json::to_string(&result_json)
            .map(Some)
            .map_err(|e| format!("http error: response serialization failed: {}", e))
    } else {
        // 非流式模式：同步执行 HTTP 请求
        //
        // `request` 先取有主副本再进 future：端口的异步桥是类型擦除的（要求
        // `'static` future），借用形式过不去。语义与迁移前逐字相同。
        //
        // `jwtAuth` 代注：token 由宿主经端口给（不给 = 本宿主无此概念，见
        // [`HttpPorts::jwt_auth_token`] 的默认实现），本域只做一次头注入。
        let jwt_auth = request.get("jwtAuth").and_then(|v| v.as_bool()).unwrap_or(false);
        let bearer = if jwt_auth {
            ports
                .jwt_auth_token(plugin_id)
                .map_err(|e| format!("http error: {}", e))?
        } else {
            None
        };
        let request = request.clone();
        let response = block_on(ports, async move { execute_http_request(&request, bearer).await })
            .map_err(|e| format!("http error: {}", e))?;
        serde_json::to_string(&response)
            .map(Some)
            .map_err(|e| format!("http error: response serialization failed: {}", e))
    }
}

// ==================== Streaming Execution ====================

/// 执行非流式 HTTP 请求
///
/// 宿主代为执行 HTTP 请求，返回完整响应
/// request 格式：{ "method", "url", "headers", "body", "jwtAuth"?: bool }
/// response 格式：{ "status", "body", "headers" }
///
/// `bearer` = 宿主代注的 Bearer token（由 [`http_fetch`] 经端口取来；`None` =
/// 本宿主无全局 token 概念，也不替 guest 改写自带头）。
pub(crate) async fn execute_http_request(
    request: &serde_json::Value,
    bearer: Option<String>,
) -> anyhow::Result<serde_json::Value> {
    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    let url = request
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'url' in HTTP request"))?;
    let headers = request.get("headers").and_then(as_string_map);
    let body = request.get("body").and_then(|v| v.as_str());

    let mut req_builder = client_for(url).request(method.parse()?, url);

    if let Some(hdrs) = &headers {
        for (key, value) in hdrs {
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }
    }

    // 宿主代注 Bearer（顺序同请求自带头之后：代注优先，且不多生产一个头）
    if let Some(token) = bearer {
        req_builder = req_builder.bearer_auth(token);
    }

    if let Some(b) = body {
        req_builder = req_builder.body(b.to_string());
    }

    let response = req_builder.send().await?;
    let status = response.status().as_u16();

    let resp_headers: serde_json::Map<String, serde_json::Value> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                serde_json::Value::String(v.to_str().unwrap_or("").to_string()),
            )
        })
        .collect();

    // 响应体带上限流式读取：防止无上限响应体拷入 guest 内存 + guest serde 解析
    // 耗尽单次调用 fuel 预算（触发 trap 污染 Store）。超限立即中止连接并报错，
    // 引导插件改用 stream:true（宿主后台任务经事件逐 chunk 推送，不经 guest 内存）。
    let mut body_bytes = Vec::new();
    let mut body_stream = response.bytes_stream();
    while let Some(chunk) = body_stream.next().await {
        let chunk = chunk.map_err(|e| anyhow::anyhow!("http error: read response body failed: {}", e))?;
        if body_bytes.len() + chunk.len() > PLUGIN_HTTP_RESPONSE_BODY_LIMIT_BYTES {
            return Err(anyhow::anyhow!(
                "http error: response body exceeds {} bytes limit (use stream:true for large payloads)",
                PLUGIN_HTTP_RESPONSE_BODY_LIMIT_BYTES
            ));
        }
        body_bytes.extend_from_slice(&chunk);
    }
    let resp_body =
        String::from_utf8(body_bytes).map_err(|e| anyhow::anyhow!("http error: response body is not UTF-8: {}", e))?;

    Ok(serde_json::json!({
        "status": status,
        "body": resp_body,
        "headers": resp_headers,
    }))
}

/// 执行流式 HTTP 请求
///
/// 宿主 spawn tokio 任务执行 HTTP 请求，逐 chunk 通过事件通道推送到前端
/// 插件通过监听 streamEvent 事件接收流式数据
///
/// `sseFormat` 不再有供应商语义（票据 02 宿主零业务语义）：空串 = raw 模式
/// （逐网络 chunk 透传原始字节，消费侧自行切分）；非空 = 通用 SSE 模式（按事件
/// 分隔符切分、透传 data 行原文）。OpenAI/Anthropic 等格式解析全部由插件消费侧自管。
async fn execute_streaming_http(
    request: &serde_json::Value,
    event_sink: &dyn HttpEventSink,
    stream_event: &str,
    plugin_id: &str,
) -> anyhow::Result<()> {
    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("POST");
    let url = request
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'url' in streaming HTTP request"))?;
    let headers = request.get("headers").and_then(as_string_map);
    let body = request.get("body").and_then(|v| v.as_str());
    let sse_format = request.get("sseFormat").and_then(|v| v.as_str()).unwrap_or("");

    let mut req_builder = stream_client_for(url).request(method.parse()?, url);

    if let Some(hdrs) = &headers {
        for (key, value) in hdrs {
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }
    }

    if let Some(b) = body {
        req_builder = req_builder.body(b.to_string());
    }

    let response = req_builder.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_body = response.text().await.unwrap_or_default();
        tracing::warn!(status, stream_event, "Streaming HTTP non-2xx response");
        // 非 2xx 响应通过事件通知前端，而非 bail（因为 tokio::spawn 中的 Err 只记录日志）
        event_sink.emit(
            stream_event,
            serde_json::json!({
                "error": format!("API error {}: {}", status, error_body),
                "done": true,
            }),
        );
        return Ok(());
    }

    tracing::debug!(
        status = response.status().as_u16(),
        sse_format = %sse_format,
        stream_event,
        "Streaming HTTP connected"
    );

    let mut emitted_events: usize = 0;
    if sse_format.is_empty() {
        // 原始模式：逐 chunk emit 原始字节（消费侧自行切分 SSE 事件）
        let mut stream = response.bytes_stream();
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    let chunk_str = String::from_utf8_lossy(&chunk).to_string();
                    emitted_events += 1;
                    event_sink.emit(
                        stream_event,
                        serde_json::json!({
                            "chunk": chunk_str,
                            "done": false,
                        }),
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        plugin_id = %plugin_id,
                        stream_event = %stream_event,
                        "Streaming HTTP chunk read error"
                    );
                    break;
                }
            }
        }
    } else {
        // 通用 SSE 模式：按事件分隔符切分、透传 data 行原文（票据 02 宿主零业务语义）。
        // 不做任何供应商格式解析（OpenAI/Anthropic 等语义由插件消费侧自管）。
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    buffer.push_str(&String::from_utf8_lossy(&chunk));
                    for data in extract_sse_data_lines(&mut buffer) {
                        emitted_events += 1;
                        event_sink.emit(stream_event, serde_json::json!({ "chunk": data, "done": false }));
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        plugin_id = %plugin_id,
                        stream_event = %stream_event,
                        "Streaming HTTP chunk read error"
                    );
                    break;
                }
            }
        }
    }

    // 发送完成事件
    event_sink.emit(stream_event, serde_json::json!({ "done": true }));

    tracing::debug!(
        emitted_events,
        plugin_id = %plugin_id,
        stream_event,
        "Streaming HTTP finished"
    );

    Ok(())
}

/// 通用 SSE 事件切分与 data 提取（宿主零业务语义，票据 02）
///
/// SSE 规范允许 `\n\n`、`\r\n\r\n`、`\r\r` 三种事件分隔符，取缓冲区中最先出现的
/// 切分（部分服务端使用 CRLF 行尾）；每条完整事件抽取 `data:` 行原文透传，
/// 不做任何供应商格式解析（chunk 内容 JSON 语义由插件消费侧自管）。
/// 跨 chunk 缓冲：未闭合的半截事件留在缓冲区，下次追加后补齐。
/// 返回本次提取的 data 行内容列表（无完整事件时为空）。
pub(crate) fn extract_sse_data_lines(buffer: &mut String) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        // 查找最先出现的事件分隔符：(位置, 分隔符字节长度)
        let separator = [
            buffer.find("\r\n\r\n").map(|p| (p, 4)),
            buffer.find("\n\n").map(|p| (p, 2)),
            buffer.find("\r\r").map(|p| (p, 2)),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|(pos, _)| *pos);

        let Some((pos, sep_len)) = separator else {
            break;
        };

        let event_text = buffer[..pos].to_string();
        buffer.drain(..pos + sep_len);

        for line in event_text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                let data = data.trim();
                if !data.is_empty() {
                    out.push(data.to_string());
                }
            }
        }
    }
    out
}

/// 将 serde_json::Value 转换为 HashMap<String, String>
fn as_string_map(value: &serde_json::Value) -> Option<std::collections::HashMap<String, String>> {
    let obj = value.as_object()?;
    let mut map = std::collections::HashMap::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            map.insert(k.clone(), s.to_string());
        }
    }
    Some(map)
}
