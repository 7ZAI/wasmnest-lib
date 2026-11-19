//! 响应上限：文本按 UTF-8 边界截断，条目按契约条数截断
//!
//! 截断是**显性**的：任一字段被截断时 `truncated = true`，调用方据此提示
//! 「结果不完整」，而不是把半截内容当完整结果入库。超限不拒绝整次请求——
//! 页面文本通常远超上限，拒绝会让源永久失效；返回前缀 + 标记更可用。

use crate::model::BrowserResponse;

/// 整页 / 正文文本的字节上限（256 KiB）
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

/// 列表条目上限
pub const MAX_ITEMS: usize = 200;

/// 页面 HTML 字节上限（供后端在进入提取前限制内存占用）
pub const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;

/// 按上限收敛响应，返回 `truncated` 是否被置位
///
/// 空字符串收敛为 `None`：空文本与「页面没有文本」在消费侧同义，保留 `Some("")`
/// 只会让调用方多写一次判空。
pub fn apply(mut response: BrowserResponse) -> BrowserResponse {
    let mut truncated = response.truncated;

    if let Some(text) = response.text.take() {
        let (text, cut) = truncate_utf8(text, MAX_TEXT_BYTES);
        truncated |= cut;
        response.text = non_empty(text);
    }
    if let Some(content) = response.content_text.take() {
        let (content, cut) = truncate_utf8(content, MAX_TEXT_BYTES);
        truncated |= cut;
        response.content_text = non_empty(content);
    }
    if response.items.len() > MAX_ITEMS {
        response.items.truncate(MAX_ITEMS);
        truncated = true;
    }

    response.truncated = truncated;
    response
}

/// 按字节上限截断字符串并回退到最近的 UTF-8 字符边界
///
/// 返回 `(截断后的字符串, 是否发生截断)`。
pub fn truncate_utf8(mut text: String, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

fn non_empty(text: String) -> Option<String> {
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ExtractedItem;

    fn response(
        text: String,
        content: Option<String>,
        items: Vec<ExtractedItem>,
    ) -> BrowserResponse {
        BrowserResponse {
            status: 200,
            final_url: "https://example.com/".to_string(),
            title: None,
            text: Some(text),
            content_text: content,
            items,
            truncated: false,
        }
    }

    /// 未超限时保持原值且不置截断标记
    #[test]
    fn under_limit_is_untouched() {
        let applied = apply(response(
            "hello".to_string(),
            Some("body".to_string()),
            Vec::new(),
        ));
        assert_eq!(applied.text.as_deref(), Some("hello"));
        assert_eq!(applied.content_text.as_deref(), Some("body"));
        assert!(!applied.truncated);
    }

    /// 超限文本截到上限内并回退到字符边界
    #[test]
    fn over_limit_text_is_cut_on_a_char_boundary() {
        let text = "中".repeat(MAX_TEXT_BYTES);
        let applied = apply(response(text, None, Vec::new()));
        let kept = applied.text.expect("截断后仍有内容");
        assert!(kept.len() <= MAX_TEXT_BYTES);
        assert!(kept.is_char_boundary(kept.len()));
        assert!(applied.truncated);
    }

    /// 空文本收敛为 None
    #[test]
    fn empty_text_becomes_none() {
        let applied = apply(response(String::new(), Some(String::new()), Vec::new()));
        assert_eq!(applied.text, None);
        assert_eq!(applied.content_text, None);
        assert!(!applied.truncated);
    }

    /// 条目超限只保留前 200 条并置截断标记
    #[test]
    fn over_limit_items_are_truncated() {
        let items = (0..MAX_ITEMS + 1)
            .map(|index| ExtractedItem {
                title: format!("item {index}"),
                url: format!("https://example.com/{index}"),
                time_text: None,
                summary: None,
            })
            .collect();
        let applied = apply(response(String::new(), None, items));
        assert_eq!(applied.items.len(), MAX_ITEMS);
        assert!(applied.truncated);
        assert_eq!(applied.items[0].title, "item 0");
    }
}
