//! 流式分支用例组：无头缺席的显性报错 / 通用 SSE 切分后的逐条 chunk 投递 / 终止事件

use serde_json::json;

use super::scaffold::*;
use crate::plugin_binding::egress::http_fetch;

/// 无头上下文（事件通道缺席）：流式请求显性报错，**不得**静默成功
///
/// 变异判据：把「事件通道缺席」降级成「照发不可达的事件」（返回 streamId）⇒
/// 插件侧会永远等不到数据，本条转红。
#[tokio::test]
async fn streaming_without_event_channel_is_denied() {
    let ports = granting().with_auth(AuthScript::Allow);
    let err = http_fetch(
        &as_ports(&ports),
        "p1",
        r#"{"method":"POST","url":"https://api.example.com/v1/chat","stream":true,"streamEvent":"x:y"}"#,
        true,
    )
    .expect_err("无头上下文的流式请求必须显性报错");
    assert!(
        err.contains("streaming requires app_handle"),
        "错误须点明缺前端事件通道: {err}"
    );
}

/// 流式闭环（raw 模式）：立即返回 streamId / streamEvent，chunk 逐条经事件通道到达
///
/// **必须 multi_thread**：出站原语是同步函数（内部经端口的桥阻塞调用线程），夹具
/// 服务要与被阻塞的调用线程分处不同执行上下文。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_raw_mode_delivers_chunks_then_done() {
    let addr = spawn_chunked_server(vec![b"alpha ".to_vec(), b"beta".to_vec()]).await;
    let sink = RecordingEventSink::new();
    let ports = granting()
        .with_auth(AuthScript::AllowOrigins {
            allowed: vec![normalize_origin(&format!("http://{addr}"))],
            reason: "no-record",
        })
        .with_event_sink(std::sync::Arc::clone(&sink));

    let payload = http_fetch(
        &as_ports(&ports),
        "p1",
        &json!({
            "method": "GET",
            "url": format!("http://{addr}/stream"),
            "stream": true,
            "streamEvent": "demo:stream"
        })
        .to_string(),
        true,
    )
    .expect("有事件通道时流式请求应受理")
    .expect("fetch returns payload");

    let parsed: serde_json::Value = serde_json::from_str(&payload).expect("受理结果是合法 JSON");
    assert_eq!(parsed["streamEvent"], "demo:stream", "事件名按请求回显");
    assert!(parsed["streamId"].as_str().is_some(), "必须铸出 streamId");

    // 等终止事件落定（后台任务驱动）
    let waiting = std::sync::Arc::clone(&sink);
    tokio::time::timeout(std::time::Duration::from_secs(5), async move {
        while !waiting.saw_done("demo:stream") {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("流式任务必须在超时前投递终止事件");

    // 断言拼接后的字节序列而非分块边界：**分块边界由 TCP 报文决定**（夹具两次
    // write 可能被合并成一次读），把它钉进断言就是写一条偶发红的用例。被断言的
    // 契约是「逐 chunk 原样透传、不丢不转」+「末帧 done」。
    let chunks = sink.chunks("demo:stream");
    assert!(!chunks.is_empty(), "流式必须至少投递一块内容");
    assert_eq!(
        chunks.concat(),
        "alpha beta",
        "raw 模式逐 chunk 透传原始字节（消费侧自行切分）"
    );
    assert!(sink.saw_done("demo:stream"), "末帧必须是 done: true");
}

/// 流式闭环（通用 SSE 模式）：按分隔符切分后逐条投递 data 原文
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_sse_mode_splits_events_across_chunks() {
    // 事件刻意跨网络 chunk 断开：第一块只有半截 data 行
    let addr = spawn_chunked_server(vec![b"data: {\"a\":".to_vec(), b"1}\n\ndata: [DONE]\n\n".to_vec()]).await;
    let sink = RecordingEventSink::new();
    let ports = granting()
        .with_auth(AuthScript::AllowOrigins {
            allowed: vec![normalize_origin(&format!("http://{addr}"))],
            reason: "no-record",
        })
        .with_event_sink(std::sync::Arc::clone(&sink));

    let payload = http_fetch(
        &as_ports(&ports),
        "p1",
        &json!({
            "method": "GET",
            "url": format!("http://{addr}/sse"),
            "stream": true,
            "streamEvent": "demo:sse",
            "sseFormat": "sse"
        })
        .to_string(),
        true,
    )
    .expect("受理")
    .expect("fetch returns payload");
    assert!(payload.contains("streamId"), "受理结果须带 streamId: {payload}");

    let waiting = std::sync::Arc::clone(&sink);
    tokio::time::timeout(std::time::Duration::from_secs(5), async move {
        while !waiting.saw_done("demo:sse") {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("SSE 模式必须在超时前投递终止事件");

    assert_eq!(
        sink.chunks("demo:sse"),
        ["{\"a\":1}", "[DONE]"],
        "跨 chunk 的半截事件必须补齐后按 data 原文透传（宿主不做供应商语义解析）"
    );
}
