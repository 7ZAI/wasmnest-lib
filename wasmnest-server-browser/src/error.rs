//! 浏览器渲染能力域的错误分类
//!
//! 错误串格式固定为 `<code>: <message>`：`code` 是稳定前缀，调用方按前缀分类
//! 并决定 UI 文案与退避策略；`message` 只承载可诊断文本（状态码 / 选择器名 /
//! 超时值），**不得**放入页面正文、Cookie 或凭据。
//!
//! 分类表（与 `host-browser` 契约注释一致）：
//!
//! | 前缀 | 含义 | 调用方处理 |
//! | --- | --- | --- |
//! | `browser.denied` | 用户 / 宿主拒绝该 origin 或未声明权限 | 标红，提供重新授权入口 |
//! | `browser.unsupported` | 当前端不支持浏览器能力 | 显性提示，不重试 |
//! | `browser.blocked-private` | 私网目标被闸门拒绝 | 提示需显式允许 |
//! | `browser.timeout` | 导航或脚本执行超时 | 进入退避 |
//! | `browser.http-error` | 目标返回 4xx / 5xx | 进入退避并展示状态码 |
//! | `browser.parse-error` | 选择器无命中或页面结构变化 | 进入退避，提示源可能失效 |
//! | `browser.too-large` | 响应超过上限 | 按截断标记或失败处理 |
//! | `browser.unavailable` | 浏览器进程不可用 | 标红，提示重启宿主 |
//! | `browser.invalid-request` | 请求形状非法（协议 / 选择器 / 超时） | 不重试，修正源配置 |

use std::fmt;

/// 稳定错误分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BrowserErrorKind {
    /// 权限未声明、用户拒绝该 origin，或私网授权缺失
    Denied,
    /// 当前端不提供浏览器能力
    Unsupported,
    /// 目标指向回环 / 私网 / 链路本地 / 云元数据地址且未获授权
    BlockedPrivate,
    /// 导航或页面脚本超时
    Timeout,
    /// 目标返回非成功 HTTP 状态
    HttpError,
    /// 选择器无命中、脚本输出不可解析或页面结构变化
    ParseError,
    /// 响应超过契约上限
    TooLarge,
    /// 浏览器进程未就绪、崩溃或分发产物缺失
    Unavailable,
    /// 请求本身非法（协议、URL 语法、选择器形状、超时区间）
    InvalidRequest,
}

impl BrowserErrorKind {
    /// 稳定错误码前缀（跨语言契约的一部分，不随文案调整）
    pub const fn code(self) -> &'static str {
        match self {
            Self::Denied => "browser.denied",
            Self::Unsupported => "browser.unsupported",
            Self::BlockedPrivate => "browser.blocked-private",
            Self::Timeout => "browser.timeout",
            Self::HttpError => "browser.http-error",
            Self::ParseError => "browser.parse-error",
            Self::TooLarge => "browser.too-large",
            Self::Unavailable => "browser.unavailable",
            Self::InvalidRequest => "browser.invalid-request",
        }
    }

    /// 从错误串前缀还原分类；未知前缀返回 `None`
    ///
    /// 只匹配完整前缀（含结尾冒号或整串相等），避免 `browser.timeout-x` 误判。
    pub fn from_code(code: &str) -> Option<Self> {
        const KINDS: [BrowserErrorKind; 9] = [
            BrowserErrorKind::Denied,
            BrowserErrorKind::Unsupported,
            BrowserErrorKind::BlockedPrivate,
            BrowserErrorKind::Timeout,
            BrowserErrorKind::HttpError,
            BrowserErrorKind::ParseError,
            BrowserErrorKind::TooLarge,
            BrowserErrorKind::Unavailable,
            BrowserErrorKind::InvalidRequest,
        ];
        KINDS.into_iter().find(|kind| code == kind.code())
    }
}

impl fmt::Display for BrowserErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// 带稳定分类的浏览器能力错误
///
/// 宿主侧后端可直接构造本类型；能力域把它转成 WIT `result` 的错误串。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserError {
    kind: BrowserErrorKind,
    message: String,
}

impl BrowserError {
    /// 构造错误；`message` 为空时 `Display` 只输出错误码
    pub fn new(kind: BrowserErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// 错误分类
    pub const fn kind(&self) -> BrowserErrorKind {
        self.kind
    }

    /// 稳定错误码前缀
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// 可诊断文本（不含正文 / 凭据）
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            f.write_str(self.code())
        } else {
            write!(f, "{}: {}", self.code(), self.message)
        }
    }
}

impl std::error::Error for BrowserError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个分类的错误码互不重复，且 `from_code` 往返一致
    #[test]
    fn codes_round_trip() {
        let kinds = [
            BrowserErrorKind::Denied,
            BrowserErrorKind::Unsupported,
            BrowserErrorKind::BlockedPrivate,
            BrowserErrorKind::Timeout,
            BrowserErrorKind::HttpError,
            BrowserErrorKind::ParseError,
            BrowserErrorKind::TooLarge,
            BrowserErrorKind::Unavailable,
            BrowserErrorKind::InvalidRequest,
        ];
        for kind in kinds {
            assert_eq!(BrowserErrorKind::from_code(kind.code()), Some(kind));
        }
        let mut codes: Vec<&str> = kinds.iter().map(|kind| kind.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), kinds.len(), "错误码必须唯一：{codes:?}");
    }

    /// 错误串 = 稳定前缀 + 可诊断消息；空消息只留前缀
    #[test]
    fn display_keeps_the_stable_prefix() {
        let with_message =
            BrowserError::new(BrowserErrorKind::Timeout, "navigation exceeded 30000ms");
        assert_eq!(
            with_message.to_string(),
            "browser.timeout: navigation exceeded 30000ms"
        );
        assert_eq!(with_message.code(), "browser.timeout");

        let bare = BrowserError::new(BrowserErrorKind::Unavailable, "");
        assert_eq!(bare.to_string(), "browser.unavailable");
    }

    /// 分类还原不接受模糊前缀
    #[test]
    fn from_code_rejects_unknown_or_partial_codes() {
        assert_eq!(BrowserErrorKind::from_code("browser.timeout-x"), None);
        assert_eq!(BrowserErrorKind::from_code("browser.timeout: late"), None);
        assert_eq!(BrowserErrorKind::from_code("timeout"), None);
    }
}
