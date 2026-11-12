//! 判定链：记录命中 / 硬拒绝 / 策略守卫 — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::scaffold::*;
use super::*;

/// C1 正例：授权记录命中 ⇒ 免询问放行（无头上下文也能过：判定在弹窗层之前）
#[tokio::test]
async fn allow_record_releases_without_prompt() {
    let checker = headless().await;
    seed_allow(&checker, "com.wasmnest.test", "https://api.x.com:443").await;

    let verdict = checker
        .authorize_outbound(
            "com.wasmnest.test",
            "https://api.x.com:443/v1/models?token=x",
        )
        .await
        .expect("authorize");
    assert_eq!(
        verdict,
        OutboundVerdict::Allow {
            origin: "https://api.x.com:443".to_string(),
            layer: "record",
        }
    );
}
/// C1 反例：deny 记录优先于同 origin 的 allow 记录，且**不询问**
#[tokio::test]
async fn deny_record_wins_over_allow_and_skips_the_prompt() {
    let (checker, log) = promptable(TINY, TINY).await;
    seed_allow(&checker, "com.wasmnest.test", "https://api.x.com:443").await;
    seed_deny(&checker, "com.wasmnest.test", "https://api.x.com:443").await;

    let verdict = checker
        .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
        .await
        .expect("authorize");
    assert_eq!(
        verdict,
        OutboundVerdict::Deny {
            origin: "https://api.x.com:443".to_string(),
            reason: "deny-record",
        },
        "deny 记录必须优先于同 origin 的 allow"
    );
    assert_eq!(log.len(), 0, "deny 命中不得弹窗（否则 deny 记录等于作废）");
}
/// C8 边界：私网 / 回环目标不因「是内网」而免询问（授权层没有内网白名单）
#[tokio::test]
async fn private_target_gets_no_authorization_free_pass() {
    let (checker, log) = promptable(IMMEDIATE, TINY).await;
    let verdict = checker
        .authorize_outbound(
            "com.wasmnest.test",
            "http://169.254.169.254/latest/meta-data",
        )
        .await
        .expect("authorize");
    assert!(
        !verdict.is_allowed(),
        "私网/链路本地目标不得被授权层自动放行: {verdict:?}"
    );
    assert_eq!(
        log.len(),
        1,
        "私网目标与公网目标走同一条询问路径（无内网免询问旁路）"
    );
}
/// 异常：URL 不可归一化 ⇒ 显性报错，错误串不含原始 url（token 不外泄）
#[tokio::test]
async fn malformed_url_is_reported_without_echoing_the_url() {
    let checker = headless().await;
    let err = checker
        .authorize_outbound("com.wasmnest.test", "not-a-url?access_token=SECRET")
        .await
        .expect_err("不可归一化的 URL 必须报错");
    assert!(
        !err.to_string().contains("SECRET"),
        "错误串不得回显 url（凭据红线）: {err}"
    );
}
