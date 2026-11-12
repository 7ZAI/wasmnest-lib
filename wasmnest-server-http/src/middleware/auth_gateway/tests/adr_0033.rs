//! ADR 0033：认证问中心（中间件单测） — crate 内单元测试（自 packages/wasmnest-server-http/src/middleware/auth_gateway.rs 迁出）

use super::*;

/// 凭证提取：Bearer scheme 逐字取出；缺头 / 非 Bearer / 畸形 scheme → None
#[test]
fn bearer_credential_extraction_matrix() {
    let req = srv_req_with_bearer("token-abc");
    assert_eq!(bearer_credential(&req), Some("token-abc"));
    // 只剥前缀、不 trim：凭证原样交中心判定（空格/空串都原样透传，
    // 判「形不对」是中心的活，提取层不猜）
    assert_eq!(bearer_credential(&srv_req_with_bearer(" ")), Some(" "));
    assert_eq!(bearer_credential(&srv_req_with_bearer("")), Some(""));

    // 无 Authorization 头
    let req = actix_web::test::TestRequest::get()
        .uri("/api/sessions")
        .to_srv_request();
    assert_eq!(bearer_credential(&req), None, "无 Authorization 头 → None");

    // 非 Bearer scheme
    for scheme in ["Basic abc", "bearer token-abc", "Token token-abc"] {
        let req = actix_web::test::TestRequest::get()
            .uri("/api/sessions")
            .insert_header(("Authorization", scheme))
            .to_srv_request();
        assert_eq!(bearer_credential(&req), None, "非 Bearer scheme: {scheme}");
    }
}
/// 无端口注册表（无头 / 单测）时**任何**凭证都拿不到身份 → fail-closed。
///
/// 这条不是「测试环境将就」：它锁的是「本面不得在没有中心的情况下放行」——
/// 中间件里已经没有任何本地验签面，凭证形如与否都不影响结论。
/// 前提断言取 `ports::get()`（票 04 后面不认识宿主 AppContext，
/// 注入与否的唯一可观测形态就是端口注册表本身）。
#[test]
fn no_runtime_context_denies_every_credential() {
    assert!(
        wasmnest_server_base::ports::get().is_none(),
        "本用例前提：单测上下文未注入宿主端口实现"
    );
    for token in ["not-a-jwt", "a.b.c", "", "eyJhbGciOiJIUzI1NiJ9.e30.x"] {
        let req = srv_req_with_bearer(token);
        assert!(
            authenticate_with_center(&req).is_none(),
            "无中心在册时凭证一律不得放行: {token}"
        );
    }
    // 无 Authorization 头同样 None
    let req = actix_web::test::TestRequest::get()
        .uri("/api/sessions")
        .to_srv_request();
    assert!(authenticate_with_center(&req).is_none());
}
