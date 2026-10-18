//! general — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::*;

/// C6 正例：`HTTPS://API.X.com:443/` 与 `https://api.x.com` 归一到同一条记录
#[test]
fn normalize_target_makes_equivalent_urls_one_target() {
    let a = normalize_target("HTTPS://API.X.com:443/").expect("normalize");
    let b = normalize_target("https://api.x.com/v1/models?token=secret").expect("normalize");
    assert_eq!(a.origin, "https://api.x.com:443");
    assert_eq!(b.origin, a.origin, "大小写 / 默认端口 / 尾斜杠必须归一到同一 origin");
    assert_eq!(a.path, "/");
    assert_eq!(b.path, "/v1/models");
}

/// C6 反例（凭据红线 AGENTS §8）：query / fragment / userinfo 绝不进 target
#[test]
fn normalize_target_never_carries_query_fragment_or_userinfo() {
    let t = normalize_target("https://user:pw@api.x.com:443/v1?access_token=SECRET#frag").expect("normalize");
    assert_eq!(t.origin, "https://api.x.com:443", "userinfo 不得进入 origin");
    assert_eq!(t.path, "/v1");
    let rendered = format!("{}/{}", t.origin, t.path);
    for secret in ["SECRET", "user", "pw", "frag"] {
        assert!(
            !rendered.contains(secret),
            "凭据/片段不得出现在目标里（{secret}）: {rendered}"
        );
    }
}
/// C6 边界：http 默认端口显式化、IPv6 字面量保留方括号、尾斜杠归一
#[test]
fn normalize_target_explicit_ports_and_ipv6_literals() {
    assert_eq!(
        normalize_target("http://10.0.0.5/share").expect("normalize").origin,
        "http://10.0.0.5:80"
    );
    assert_eq!(
        normalize_target("http://[::1]:8080/x").expect("normalize").origin,
        "http://[::1]:8080"
    );
    assert_eq!(
        normalize_target("https://h.example/v1/").expect("normalize").path,
        "/v1"
    );
}
/// C6 异常：不可归一化的 URL 返回 `None`（调用方据此显性报错，不猜不放行）
#[test]
fn normalize_target_rejects_unusable_urls() {
    assert!(normalize_target("not a url").is_none());
    assert!(normalize_target("https://").is_none(), "缺 host");
    assert!(normalize_target("").is_none());
}
