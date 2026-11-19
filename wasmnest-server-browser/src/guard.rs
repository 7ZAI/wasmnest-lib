//! 请求闸门：协议白名单 / 私网裁决 / 超时收敛 / 选择器形状
//!
//! 闸门只做**可判定**的部分：URL 语法、字面量 IP 与保留主机名、选择器形状。
//! 域名解析发生在浏览器进程内，能力域看不到中间结果——后端必须在**每次**
//! 地址解析与重定向后调用 [`ensure_public_ip`] 复检，否则域名可解析到私网
//! 绕过本闸门。这条约束写在端口文档里，不是可选优化。
//!
//! 私网策略比静态 HTTP 更严：回环、RFC1918、链路本地、唯一本地、CGNAT、
//! 文档地址、云元数据主机名一律默认拒绝；`allow-private-network` 只是申请，
//! 还要宿主按 origin 的授权记录放行。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::error::{BrowserError, BrowserErrorKind};
use crate::model::{BrowserRequest, ListSpec, PageSpec, WaitUntil};

/// 超时下界（毫秒）
pub const MIN_TIMEOUT_MS: u32 = 1;

/// 超时上界（毫秒）；与浏览器引擎的脚本截止时间对齐
pub const MAX_TIMEOUT_MS: u32 = 30_000;

/// 单条选择器的字节上限
pub const MAX_SELECTOR_BYTES: usize = 512;

/// 通过闸门的请求：URL 已解析、超时已收敛、选择器已校验
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRequest {
    /// 目标 URL
    pub url: Url,
    /// 导航完成判定
    pub wait_until: WaitUntil,
    /// 收敛后的总超时（1..=30000）
    pub timeout_ms: u32,
    /// 列表提取规格
    pub extract_list: Option<ListSpec>,
    /// 正文提取规格
    pub extract_page: Option<PageSpec>,
}

/// 校验请求并返回可执行计划
///
/// `authorize_private` 只在目标被判定为私网时调用一次：参数是归一化 origin
/// （默认端口已省略），返回 `true` 表示用户已对该 origin 授权私网访问。
///
/// # Errors
///
/// 返回 [`BrowserErrorKind::InvalidRequest`]（协议 / URL 语法 / 选择器形状 /
/// 超时区间）或 [`BrowserErrorKind::BlockedPrivate`]（私网目标未获授权）。
pub fn validate<F>(
    request: &BrowserRequest,
    authorize_private: F,
) -> Result<ValidatedRequest, BrowserError>
where
    F: FnOnce(&str) -> bool,
{
    let url = validate_url(&request.url)?;
    if let Some(spec) = &request.extract_list {
        validate_list_spec(spec)?;
    }
    if let Some(page) = &request.extract_page {
        if let Some(content) = &page.content {
            validate_css_selector("extract-page.content", content)?;
        }
    }

    if is_private_url(&url) {
        if !request.allow_private_network {
            return Err(blocked_private(format!(
                "{} resolves to a private or reserved address; set allow-private-network and authorize the origin",
                url.host_str().unwrap_or("<unknown>"),
            )));
        }
        let origin = url.origin().ascii_serialization();
        if !authorize_private(&origin) {
            return Err(blocked_private(format!(
                "private network access to {origin} has not been authorized by the user"
            )));
        }
    }

    Ok(ValidatedRequest {
        url,
        wait_until: request.wait_until,
        timeout_ms: clamp_timeout(request.timeout_ms),
        extract_list: request.extract_list.clone(),
        extract_page: request.extract_page.clone(),
    })
}

/// 收敛超时到 `1..=30000` 毫秒
///
/// 超界不报错：调用方按「越小越安全」传值，0 与超大值都落到边界；
/// 后端仍需独立执行同一上界，不能只信能力域。
pub const fn clamp_timeout(timeout_ms: u32) -> u32 {
    if timeout_ms < MIN_TIMEOUT_MS {
        MIN_TIMEOUT_MS
    } else if timeout_ms > MAX_TIMEOUT_MS {
        MAX_TIMEOUT_MS
    } else {
        timeout_ms
    }
}

/// 校验 URL 只使用 `http` / `https` 且带主机
///
/// # Errors
///
/// 协议不在白名单、URL 语法非法或缺少主机时返回 `InvalidRequest`。
pub fn validate_url(raw: &str) -> Result<Url, BrowserError> {
    let url = Url::parse(raw.trim()).map_err(|error| invalid(format!("malformed url: {error}")))?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(invalid(format!(
                "scheme '{other}' is not allowed; only http and https are accepted"
            )))
        }
    }
    if url.host().is_none() {
        return Err(invalid("url has no host"));
    }
    Ok(url)
}

/// 判定 URL 是否指向私网 / 保留地址或保留主机名
///
/// 域名只按保留主机名判定（`localhost`、云元数据别名）；其他域名需要在解析后
/// 用 [`ensure_public_ip`] 复检。
pub fn is_private_url(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => is_private_ipv4(ip),
        Some(Host::Ipv6(ip)) => is_private_ipv6(ip),
        Some(Host::Domain(domain)) => is_private_domain(domain),
        None => true,
    }
}

/// 判定 IP 是否属于私网 / 保留地址
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

/// 后端在解析 / 重定向后复检：目标必须是全局可路由地址
///
/// # Errors
///
/// 命中私网 / 保留地址时返回 `BlockedPrivate`。
pub fn ensure_public_ip(ip: IpAddr) -> Result<(), BrowserError> {
    if is_private_ip(ip) {
        Err(blocked_private(format!(
            "resolved address {ip} is private or reserved; navigation stopped"
        )))
    } else {
        Ok(())
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || octets[0] == 0
        // 100.64.0.0/10 运营商级 NAT
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        // 198.18.0.0/15 基准测试
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_private_ipv4(mapped);
    }
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7 唯一本地
        || (segments[0] & 0xfe00) == 0xfc00
        // fe80::/10 链路本地
        || (segments[0] & 0xffc0) == 0xfe80
        // fec0::/10 站点本地（已弃用，仍按私网处理）
        || (segments[0] & 0xffc0) == 0xfec0
        // 2001:db8::/32 文档地址
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn is_private_domain(domain: &str) -> bool {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || matches!(
            normalized.as_str(),
            "metadata.google.internal" | "metadata.goog"
        )
}

fn validate_list_spec(spec: &ListSpec) -> Result<(), BrowserError> {
    if spec.item.trim().starts_with("attr:") {
        return Err(invalid(
            "extract-list.item must be an element selector, not an attr: value",
        ));
    }
    validate_css_selector("extract-list.item", &spec.item)?;
    if let Some(selector) = &spec.title {
        validate_css_selector("extract-list.title", selector)?;
    }
    if let Some(selector) = &spec.url {
        validate_value_selector("extract-list.url", selector)?;
    }
    if let Some(selector) = &spec.time {
        validate_value_selector("extract-list.time", selector)?;
    }
    if let Some(selector) = &spec.summary {
        validate_css_selector("extract-list.summary", selector)?;
    }
    Ok(())
}

/// 校验选择器可用于「取文本」场景
fn validate_css_selector(field: &str, selector: &str) -> Result<(), BrowserError> {
    let trimmed = selector.trim();
    if trimmed.is_empty() {
        return Err(invalid(format!("{field} selector is empty")));
    }
    if trimmed.len() > MAX_SELECTOR_BYTES {
        return Err(invalid(format!(
            "{field} selector exceeds {MAX_SELECTOR_BYTES} bytes"
        )));
    }
    if trimmed.chars().any(is_unsafe_selector_char) {
        return Err(invalid(format!(
            "{field} selector contains control characters or line separators"
        )));
    }
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.contains(":has(") || lowered.contains(":has (") {
        return Err(invalid(format!(
            "{field} selector uses :has(), which is not accepted"
        )));
    }
    Ok(())
}

/// 校验选择器可用于「取值」场景（CSS 或 `attr:<name>`）
fn validate_value_selector(field: &str, selector: &str) -> Result<(), BrowserError> {
    let trimmed = selector.trim();
    if let Some(attribute) = trimmed.strip_prefix("attr:") {
        if attribute.is_empty() {
            return Err(invalid(format!("{field} selector has an empty attr: name")));
        }
        if attribute.len() > MAX_SELECTOR_BYTES {
            return Err(invalid(format!(
                "{field} attr name exceeds {MAX_SELECTOR_BYTES} bytes"
            )));
        }
        if !attribute
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':'))
        {
            return Err(invalid(format!(
                "{field} attr name may only contain ASCII letters, digits, '-', '_' and ':'"
            )));
        }
        return Ok(());
    }
    validate_css_selector(field, selector)
}

fn is_unsafe_selector_char(ch: char) -> bool {
    ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}')
}

fn invalid(message: impl Into<String>) -> BrowserError {
    BrowserError::new(BrowserErrorKind::InvalidRequest, message)
}

fn blocked_private(message: impl Into<String>) -> BrowserError {
    BrowserError::new(BrowserErrorKind::BlockedPrivate, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> BrowserRequest {
        BrowserRequest {
            url: url.to_string(),
            wait_until: WaitUntil::DomContentLoaded,
            timeout_ms: 5_000,
            allow_private_network: false,
            extract_list: None,
            extract_page: None,
        }
    }

    fn public_only(_origin: &str) -> bool {
        false
    }

    /// 公网 https 请求通过且超时原样保留
    #[test]
    fn public_https_passes_untouched() {
        let validated =
            validate(&request("https://example.com/list"), public_only).expect("public url");
        assert_eq!(validated.url.as_str(), "https://example.com/list");
        assert_eq!(validated.timeout_ms, 5_000);
    }

    /// 非 http(s) 协议一律拒绝
    #[test]
    fn non_http_schemes_are_rejected() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<p>x</p>",
            "blob:https://example.com/1",
            "ftp://example.com/",
        ] {
            let error = validate(&request(url), public_only).expect_err(url);
            assert_eq!(error.kind(), BrowserErrorKind::InvalidRequest, "{url}");
        }
    }

    /// 字面量私网 / 回环 / 链路本地 / 云元数据 / IPv4 映射全部默认拒绝
    #[test]
    fn private_targets_are_blocked_by_default() {
        for url in [
            "http://127.0.0.1/",
            "http://10.1.2.3/",
            "http://172.16.0.5/",
            "http://192.168.1.10/",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.0.1/",
            "http://198.18.0.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
            "http://[::ffff:192.168.1.1]/",
            "http://localhost/",
            "http://app.localhost/",
            "http://metadata.google.internal/",
        ] {
            let error = validate(&request(url), public_only).expect_err(url);
            assert_eq!(error.kind(), BrowserErrorKind::BlockedPrivate, "{url}");
        }
    }

    /// 私网申请必须命中宿主授权记录，不能由插件单方面放宽
    #[test]
    fn private_network_requires_host_authorization() {
        let mut local = request("http://127.0.0.1:8080/dashboard");
        local.allow_private_network = true;

        let denied = validate(&local, |_origin: &str| false).expect_err("unauthorized");
        assert_eq!(denied.kind(), BrowserErrorKind::BlockedPrivate);

        let authorized = validate(&local, |origin: &str| origin == "http://127.0.0.1:8080")
            .expect("authorized private request");
        assert_eq!(authorized.url.port(), Some(8080));
    }

    /// 超时收敛到 1..=30000
    #[test]
    fn timeout_is_clamped() {
        assert_eq!(clamp_timeout(0), MIN_TIMEOUT_MS);
        assert_eq!(clamp_timeout(30_001), MAX_TIMEOUT_MS);
        assert_eq!(clamp_timeout(1_500), 1_500);

        let mut huge = request("https://example.com/");
        huge.timeout_ms = u32::MAX;
        assert_eq!(
            validate(&huge, public_only).expect("clamped").timeout_ms,
            MAX_TIMEOUT_MS
        );
    }

    /// 选择器形状：空 / 超长 / 控制字符 / :has() 全部拒绝
    #[test]
    fn selector_shape_is_validated() {
        let invalid_selectors = [
            "",
            "   ",
            &"a".repeat(MAX_SELECTOR_BYTES + 1),
            "div\nspan",
            "div\u{2028}span",
            "div:has(> a)",
            "div:has (> a)",
        ];
        for selector in invalid_selectors {
            let mut spec_request = request("https://example.com/");
            spec_request.extract_list = Some(ListSpec {
                item: selector.to_string(),
                ..ListSpec::default()
            });
            let error = validate(&spec_request, public_only).expect_err(selector);
            assert_eq!(
                error.kind(),
                BrowserErrorKind::InvalidRequest,
                "{selector:?}"
            );
        }
    }

    /// url / time 字段接受 attr: 形式，但 attr 名必须是安全字符集
    #[test]
    fn attr_selectors_are_validated() {
        let mut ok = request("https://example.com/");
        ok.extract_list = Some(ListSpec {
            item: "li.item".to_string(),
            url: Some("attr:data-href".to_string()),
            time: Some("attr:datetime".to_string()),
            ..ListSpec::default()
        });
        assert!(validate(&ok, public_only).is_ok());

        for selector in ["attr:", "attr:data href", "attr:a]b", "attr:名字"] {
            let mut bad = request("https://example.com/");
            bad.extract_list = Some(ListSpec {
                item: "li.item".to_string(),
                url: Some(selector.to_string()),
                ..ListSpec::default()
            });
            let error = validate(&bad, public_only).expect_err(selector);
            assert_eq!(error.kind(), BrowserErrorKind::InvalidRequest, "{selector}");
        }
    }

    /// item 必须是元素选择器，不接受 attr: 形式
    #[test]
    fn item_selector_rejects_attr_form() {
        let mut bad = request("https://example.com/");
        bad.extract_list = Some(ListSpec {
            item: "attr:href".to_string(),
            ..ListSpec::default()
        });
        let error = validate(&bad, public_only).expect_err("attr item");
        assert_eq!(error.kind(), BrowserErrorKind::InvalidRequest);
    }

    /// 后端复检接口对私网地址显性失败
    #[test]
    fn resolved_private_ip_is_rejected() {
        let ip: IpAddr = "192.168.0.10".parse().expect("ip");
        let error = ensure_public_ip(ip).expect_err("private ip");
        assert_eq!(error.kind(), BrowserErrorKind::BlockedPrivate);

        let public: IpAddr = "1.1.1.1".parse().expect("ip");
        assert!(ensure_public_ip(public).is_ok());
    }
}
