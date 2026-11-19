//! 提取脚本生成与脚本输出解析
//!
//! 页面上下文只执行**固定逻辑**：选择器来自请求，但只作为 JSON 字面量注入，
//! 不拼接进可执行代码。插件无法注入任意表达式，能力域也不接受整页 HTML。
//!
//! 生成物返回 JSON 文本（`title` / `text` / `contentText` / `items` / `location`），
//! 由 [`parse_payload`] 解析并把相对链接按最终 URL 绝对化。

use serde::Deserialize;
use url::Url;

use crate::error::{BrowserError, BrowserErrorKind};
use crate::guard::ValidatedRequest;
use crate::model::{BrowserResponse, ExtractedItem};

/// 脚本最多返回 `MAX_ITEMS + 1` 条，多出的一条用于让能力域判定「是否超限」
const SCRIPT_ITEM_LIMIT: usize = crate::limits::MAX_ITEMS + 1;

/// 生成页面内提取脚本（IIFE，返回 JSON 字符串）
///
/// 所有选择器经 `serde_json` 序列化后注入：引号、反斜杠与换行都被转义，
/// 页面无法把选择器内容解释成额外语句。
pub fn build(request: &ValidatedRequest) -> String {
    let spec = serde_json::json!({
        "list": request.extract_list.as_ref().map(|list| serde_json::json!({
            "item": list.item,
            "title": list.title,
            "url": list.url,
            "time": list.time,
            "summary": list.summary,
        })),
        "page": request.extract_page.as_ref().map(|page| serde_json::json!({
            "content": page.content,
        })),
    });

    format!(
        r#"(() => {{
  const spec = {spec};
  const limit = {limit};
  const textOf = (el) => {{
    if (!el) return null;
    const value = (el.innerText || el.textContent || '').trim();
    return value === '' ? null : value;
  }};
  const attrName = (selector) => selector.indexOf('attr:') === 0 ? selector.slice(5) : null;
  const textValue = (root, selector) => {{
    if (!selector) return null;
    const attr = attrName(selector);
    if (attr !== null) {{
      if (!root.getAttribute) return null;
      const raw = root.getAttribute(attr);
      if (raw === null) return null;
      const trimmed = String(raw).trim();
      return trimmed === '' ? null : trimmed;
    }}
    return textOf(root.querySelector(selector));
  }};
  const urlValue = (root, selector) => {{
    if (!selector) {{
      if (root.href) return String(root.href);
      const anchor = root.querySelector ? root.querySelector('a[href]') : null;
      return anchor && anchor.href ? String(anchor.href) : '';
    }}
    const attr = attrName(selector);
    if (attr !== null) {{
      if (!root.getAttribute) return '';
      const raw = root.getAttribute(attr);
      return raw === null ? '' : String(raw).trim();
    }}
    const el = root.querySelector(selector);
    if (!el) return '';
    if (el.href) return String(el.href);
    if (el.getAttribute) {{
      const raw = el.getAttribute('href') || el.getAttribute('src');
      if (raw) return String(raw).trim();
    }}
    return '';
  }};
  const items = [];
  if (spec.list) {{
    let nodes;
    try {{
      nodes = Array.from(document.querySelectorAll(spec.list.item));
    }} catch (error) {{
      throw new Error('invalid item selector: ' + spec.list.item);
    }}
    for (let index = 0; index < nodes.length && items.length < limit; index += 1) {{
      const el = nodes[index];
      const title = spec.list.title ? textValue(el, spec.list.title) : textOf(el);
      const url = urlValue(el, spec.list.url || null);
      items.push({{
        title: title || '',
        url: url || '',
        timeText: spec.list.time ? textValue(el, spec.list.time) : null,
        summary: spec.list.summary ? textValue(el, spec.list.summary) : null,
      }});
    }}
  }}
  let contentText = null;
  if (spec.page) {{
    if (spec.page.content) {{
      contentText = textOf(document.querySelector(spec.page.content));
    }} else {{
      contentText = textOf(document.body);
    }}
  }}
  return JSON.stringify({{
    title: document.title && document.title.trim() ? document.title.trim() : null,
    text: textOf(document.body),
    contentText: contentText,
    items: items,
    location: location.href,
  }});
}})()"#,
        spec = spec,
        limit = SCRIPT_ITEM_LIMIT,
    )
}

/// 页面脚本返回的 JSON 形状
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScriptPayload {
    title: Option<String>,
    text: Option<String>,
    content_text: Option<String>,
    #[serde(default)]
    items: Vec<ScriptItem>,
    location: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScriptItem {
    title: String,
    url: String,
    time_text: Option<String>,
    summary: Option<String>,
}

/// 解析脚本输出并绝对化条目链接
///
/// # Errors
///
/// 脚本输出不是合法 JSON、最终 URL 无法解析、或选择器命中的条目全部缺少可用
/// URL 时返回 `ParseError`；目标状态码 ≥400 时返回 `HttpError`。
pub fn parse_payload(
    status: u16,
    final_url: &str,
    payload: &str,
) -> Result<BrowserResponse, BrowserError> {
    if status >= 400 {
        return Err(BrowserError::new(
            BrowserErrorKind::HttpError,
            format!("target responded with HTTP {status}"),
        ));
    }

    let payload: ScriptPayload = serde_json::from_str(payload)
        .map_err(|error| parse_error(format!("script payload is not valid JSON: {error}")))?;

    let base = resolve_base(final_url, payload.location.as_deref())
        .ok_or_else(|| parse_error("final url is not a valid absolute URL"))?;

    let matched = payload.items.len();
    let items: Vec<ExtractedItem> = payload
        .items
        .into_iter()
        .filter_map(|item| normalize_item(item, &base))
        .collect();
    if matched > 0 && items.is_empty() {
        return Err(parse_error(
            "item selector matched elements but none produced a usable absolute url",
        ));
    }

    Ok(BrowserResponse {
        status,
        final_url: base.as_str().to_string(),
        title: non_empty(payload.title),
        text: non_empty(payload.text),
        content_text: non_empty(payload.content_text),
        items,
        truncated: false,
    })
}

fn resolve_base(final_url: &str, location: Option<&str>) -> Option<Url> {
    Url::parse(final_url)
        .ok()
        .or_else(|| location.and_then(|value| Url::parse(value).ok()))
}

fn normalize_item(item: ScriptItem, base: &Url) -> Option<ExtractedItem> {
    let raw_url = item.url.trim();
    let title = item.title.trim().to_string();
    if raw_url.is_empty() && title.is_empty() {
        return None;
    }
    let url = absolute_url(raw_url, base)?;
    Some(ExtractedItem {
        title,
        url,
        time_text: non_empty(item.time_text),
        summary: non_empty(item.summary),
    })
}

fn absolute_url(raw: &str, base: &Url) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    Url::parse(raw)
        .or_else(|_| base.join(raw))
        .ok()
        .map(|url| url.as_str().to_string())
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

fn parse_error(message: impl Into<String>) -> BrowserError {
    BrowserError::new(BrowserErrorKind::ParseError, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ListSpec, PageSpec, WaitUntil};

    fn validated(url: &str) -> ValidatedRequest {
        ValidatedRequest {
            url: Url::parse(url).expect("url"),
            wait_until: WaitUntil::DomContentLoaded,
            timeout_ms: 5_000,
            extract_list: None,
            extract_page: None,
        }
    }

    /// 选择器作为 JSON 字面量注入：引号 / 反斜杠 / 换行都被转义
    #[test]
    fn selectors_are_json_escaped_in_the_script() {
        let mut request = validated("https://example.com/");
        request.extract_list = Some(ListSpec {
            item: "li\"].item\\x".to_string(),
            ..ListSpec::default()
        });
        let script = build(&request);
        assert!(script.contains("\\\""));
        assert!(script.contains("\\\\"));
        assert!(!script.contains("\"li\""), "原始引号不应直接进入脚本");
    }

    /// 未指定提取面时脚本仍返回整页文本与标题
    #[test]
    fn empty_specs_still_produce_a_page_payload_script() {
        let script = build(&validated("https://example.com/"));
        assert!(script.contains("const spec = {\"list\":null,\"page\":null}"));
        assert!(script.contains("JSON.stringify"));
    }

    /// 正常 payload：相对链接按最终 URL 绝对化，空字段收敛为 None
    #[test]
    fn payload_is_parsed_and_links_are_absolutized() {
        let payload = r#"{
            "title": "Example",
            "text": "page text",
            "contentText": "article body",
            "items": [
                {"title": "One", "url": "/one", "timeText": "2026-11-19", "summary": "first"},
                {"title": "Two", "url": "https://other.example/two", "timeText": null, "summary": null}
            ],
            "location": "https://example.com/list"
        }"#;
        let response = parse_payload(200, "https://example.com/list", payload).expect("parsed");
        assert_eq!(response.title.as_deref(), Some("Example"));
        assert_eq!(response.text.as_deref(), Some("page text"));
        assert_eq!(response.content_text.as_deref(), Some("article body"));
        assert_eq!(response.items.len(), 2);
        assert_eq!(response.items[0].url, "https://example.com/one");
        assert_eq!(response.items[1].url, "https://other.example/two");
        assert_eq!(response.items[0].time_text.as_deref(), Some("2026-11-19"));
    }

    /// 状态码 ≥400 显性失败
    #[test]
    fn http_error_status_is_reported() {
        let error = parse_payload(503, "https://example.com/", "{}").expect_err("503");
        assert_eq!(error.kind(), BrowserErrorKind::HttpError);
    }

    /// 非法 JSON / 非法最终 URL 都是 parse-error
    #[test]
    fn malformed_payload_and_base_url_are_parse_errors() {
        let bad_json = parse_payload(200, "https://example.com/", "not json").expect_err("json");
        assert_eq!(bad_json.kind(), BrowserErrorKind::ParseError);

        let bad_base = parse_payload(200, "not a url", "{}").expect_err("base");
        assert_eq!(bad_base.kind(), BrowserErrorKind::ParseError);
    }

    /// 选择器命中条目但 URL 全坏 → parse-error（页面结构变化，不静默返回空列表）
    #[test]
    fn matched_items_without_usable_urls_are_a_parse_error() {
        let payload = r#"{"items":[{"title":"x","url":"http://[::1"}]}"#;
        let error = parse_payload(200, "https://example.com/", payload).expect_err("bad urls");
        assert_eq!(error.kind(), BrowserErrorKind::ParseError);
    }

    /// 没有标题也没有 URL 的条目被丢弃；部分可用时保留可用条目
    #[test]
    fn unusable_individual_items_are_skipped() {
        let payload = r#"{
            "items": [
                {"title": "", "url": ""},
                {"title": "ok", "url": "/ok"}
            ]
        }"#;
        let response = parse_payload(200, "https://example.com/base/", payload).expect("parsed");
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].url, "https://example.com/ok");
    }

    /// page 规格参与脚本生成（正文容器选择器进入 JSON 字面量）
    #[test]
    fn page_spec_is_embedded() {
        let mut request = validated("https://example.com/");
        request.extract_page = Some(PageSpec {
            content: Some("article.body".to_string()),
        });
        let script = build(&request);
        assert!(script.contains("\"content\":\"article.body\""));
    }
}
