//! 能力域的请求 / 响应形状（与 `wit/browser.wit` 的 record 一一对应）
//!
//! 这些类型是纯机制载荷：不解释标题、时间或摘要的业务语义，只保证形状、
//! 绝对化与上限。端实现（桌面浏览器进程 / 移动 stub）只经端口交换这些值，
//! 不依赖 WIT 绑定层。

/// 导航完成的判定时机
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WaitUntil {
    /// 页面 `load` 事件
    Load,
    /// DOM 解析完成
    DomContentLoaded,
    /// 网络空闲
    NetworkIdle,
}

impl WaitUntil {
    /// 线协议取值（供后端映射到浏览器引擎的导航参数）
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::DomContentLoaded => "dom-content-loaded",
            Self::NetworkIdle => "network-idle",
        }
    }
}

/// 列表提取规格：`item` 命中条目容器，其余字段相对容器查找
///
/// 每个字段值是 CSS 选择器；`url` / `time` 额外接受 `attr:<name>` 形式。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListSpec {
    /// 条目容器选择器（必填且非空）
    pub item: String,
    /// 标题选择器；缺省取容器可读文本
    pub title: Option<String>,
    /// 链接选择器或 `attr:<name>`；缺省取容器内首个 `a[href]`
    pub url: Option<String>,
    /// 时间选择器或 `attr:<name>`
    pub time: Option<String>,
    /// 摘要选择器
    pub summary: Option<String>,
}

/// 正文提取规格
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageSpec {
    /// 正文容器选择器；缺省取整页可读文本
    pub content: Option<String>,
}

/// 一次渲染请求
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserRequest {
    /// 目标 URL（只接受 `http` / `https`）
    pub url: String,
    /// 导航完成判定
    pub wait_until: WaitUntil,
    /// 请求的总超时（毫秒）；闸门收敛到 1..=30000
    pub timeout_ms: u32,
    /// 私网访问申请；是否放行由宿主授权记录裁决
    pub allow_private_network: bool,
    /// 列表提取规格
    pub extract_list: Option<ListSpec>,
    /// 正文提取规格
    pub extract_page: Option<PageSpec>,
}

/// 列表条目；`url` 已绝对化
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedItem {
    /// 标题文本
    pub title: String,
    /// 绝对 URL
    pub url: String,
    /// 原始时间文本（不做语义解析）
    pub time_text: Option<String>,
    /// 摘要文本
    pub summary: Option<String>,
}

/// 渲染结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserResponse {
    /// 目标最终 HTTP 状态码
    pub status: u16,
    /// 重定向后的最终 URL
    pub final_url: String,
    /// 页面标题
    pub title: Option<String>,
    /// 整页可读文本
    pub text: Option<String>,
    /// 正文文本
    pub content_text: Option<String>,
    /// 列表条目
    pub items: Vec<ExtractedItem>,
    /// 任一字段被上限截断即 true
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 线协议取值与 WIT 枚举逐字一致（后端按此映射导航参数）
    #[test]
    fn wait_until_wire_names_match_the_contract() {
        assert_eq!(WaitUntil::Load.as_str(), "load");
        assert_eq!(WaitUntil::DomContentLoaded.as_str(), "dom-content-loaded");
        assert_eq!(WaitUntil::NetworkIdle.as_str(), "network-idle");
    }
}
