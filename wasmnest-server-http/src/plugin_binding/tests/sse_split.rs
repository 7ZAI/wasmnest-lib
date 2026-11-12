//! 通用 SSE 切分用例组（宿主零业务语义，票据 02）

use crate::plugin_binding::egress::extract_sse_data_lines;

/// 通用 SSE 事件切分：三种分隔符都能切分并提取 data 行原文
#[test]
fn sse_extract_supports_all_separators() {
    let mut buf = "data: a\n\ndata: b\r\n\r\ndata: c\r\r".to_string();
    let events = extract_sse_data_lines(&mut buf);
    assert_eq!(events, ["a", "b", "c"]);
    assert!(buf.is_empty());
}

/// 跨 chunk 缓冲：半截事件留在缓冲区，下次追加后补齐
#[test]
fn sse_extract_buffers_across_chunks() {
    let mut buf = "data: hel".to_string();
    assert!(extract_sse_data_lines(&mut buf).is_empty());
    buf.push_str("lo\n\n");
    assert_eq!(extract_sse_data_lines(&mut buf), ["hello"]);
    assert!(buf.is_empty());
}

/// 无 data 行的事件（注释/仅 event 字段）：忽略，不产出
#[test]
fn sse_extract_ignores_events_without_data() {
    let mut buf = ": keep-alive\n\ndata: ok\n\n".to_string();
    assert_eq!(extract_sse_data_lines(&mut buf), ["ok"]);
}

/// 供应商标记（如 [DONE]）按 data 原文透传，宿主不做任何供应商语义解析（票据 02）
#[test]
fn sse_extract_passes_through_vendor_markers_raw() {
    let mut buf = "data: [DONE]\n\n".to_string();
    assert_eq!(extract_sse_data_lines(&mut buf), ["[DONE]"]);
}
