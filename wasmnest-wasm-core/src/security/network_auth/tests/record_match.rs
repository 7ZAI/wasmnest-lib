//! C7 记录匹配（origin + 段边界前缀） — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::scaffold::*;
use super::*;

/// C7 正例：整站记录覆盖任意 path；前缀记录覆盖同段前缀与自身
#[test]
fn record_covers_matches_origin_and_segment_prefix() {
    let target = normalize_target("https://api.x.com:443/v1/models").expect("normalize");
    assert!(record_covers(
        &match_row("https://api.x.com:443", AUTH_EFFECT_ALLOW, false),
        &target
    ));
    assert!(record_covers(
        &match_row("https://api.x.com:443/v1", AUTH_EFFECT_ALLOW, true),
        &target
    ));
    assert!(record_covers(
        &match_row("https://api.x.com:443/v1/models", AUTH_EFFECT_ALLOW, true),
        &target
    ));
}
/// C7 反例：`/v1` 前缀不得命中 `/v1abc`（子串比较的经典放行漏洞）
#[test]
fn record_covers_respects_path_segment_boundary() {
    let target = normalize_target("https://api.x.com:443/v1abc/models").expect("normalize");
    assert!(
        !record_covers(
            &match_row("https://api.x.com:443/v1", AUTH_EFFECT_ALLOW, true),
            &target
        ),
        "/v1 前缀不得命中 /v1abc"
    );
}
/// C7 反例：不同 origin / 端口 / scheme 一律不命中
#[test]
fn record_covers_is_scoped_to_the_exact_origin() {
    let target = normalize_target("https://api.x.com:443/v1").expect("normalize");
    for stored in [
        "https://other.x.com:443",
        "https://api.x.com:8443",
        "http://api.x.com:80",
    ] {
        assert!(
            !record_covers(&match_row(stored, AUTH_EFFECT_ALLOW, false), &target),
            "{stored} 不得覆盖 {}",
            target.origin
        );
    }
}
/// C7 边界：畸形行（带 path 却标整站 / 无法解析）按不覆盖处理（fail-closed）
#[test]
fn record_covers_treats_malformed_rows_as_no_match() {
    let target = normalize_target("https://api.x.com:443/v1").expect("normalize");
    assert!(
        !record_covers(
            &match_row("https://api.x.com:443/v1", AUTH_EFFECT_ALLOW, false),
            &target
        ),
        "flag 与形状不一致的行不得被当成整站授权"
    );
    assert!(!record_covers(
        &match_row("garbage", AUTH_EFFECT_ALLOW, true),
        &target
    ));
}
/// C7 边界：origin 比较忽略大小写（手改过的 deny 行不得因大小写逃逸）
#[test]
fn record_covers_ignores_origin_case() {
    let target = normalize_target("https://api.x.com:443/v1").expect("normalize");
    assert!(record_covers(
        &match_row("HTTPS://API.X.com:443", AUTH_EFFECT_DENY, false),
        &target
    ));
}
