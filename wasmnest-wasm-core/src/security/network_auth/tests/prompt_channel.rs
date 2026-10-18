//! 询问通道：合并 / 落账 / 超时 — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::scaffold::*;
use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

/// C9 正例：同 origin 的 3 个并发请求只发**一次**弹窗，答一次全部放行
#[tokio::test]
async fn concurrent_requests_to_same_origin_share_one_prompt() {
    let (checker, log) = promptable(TINY, TINY).await;
    let counter = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let checker = checker.clone();
        let counter = counter.clone();
        tasks.push(tokio::spawn(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1/models")
                .await
        }));
    }
    // 等首条询问发出（三条请求都已进入判定链的询问步骤）
    let request_id = wait_for_request_id(&log).await;
    assert!(
        checker.respond(&request_id, NetworkDecision::AllowOnce).await,
        "应答必须命中在途询问"
    );

    for task in tasks {
        let verdict = task.await.expect("join").expect("authorize");
        assert!(
            verdict.is_allowed(),
            "同 origin 的一批请求应被同一次允许放行: {verdict:?}"
        );
    }
    assert_eq!(log.len(), 1, "同 origin 并发只弹一次（票 05 C9）");
    assert_eq!(counter.load(Ordering::SeqCst), 3, "三条请求都真的走过判定链");
}
/// 不同 origin 各自独立弹窗（合并键必须含 origin，不得跨站点合并）
#[tokio::test]
async fn different_origins_prompt_separately() {
    let (checker, log) = promptable(IMMEDIATE, TINY).await;
    let first = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://a.example/v1")
                .await
        }
    });
    let second = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://b.example/v1")
                .await
        }
    });
    wait_for_event_count(&log, 2).await;
    assert_eq!(log.len(), 2, "不同 origin 必须各自弹窗");
    // 两次询问都超时（无人应答）→ 按拒绝收尾
    assert!(!first.await.expect("join").expect("authorize").is_allowed());
    assert!(!second.await.expect("join").expect("authorize").is_allowed());
}
/// 票 05 首句：同意后同一 origin 后续请求免询问（落 allow 记录 + 零弹窗）
#[tokio::test]
async fn allow_once_records_origin_so_later_requests_are_silent() {
    let (checker, log) = promptable(TINY, TINY).await;
    let task = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }
    });
    let request_id = wait_for_request_id(&log).await;
    assert!(checker.respond(&request_id, NetworkDecision::AllowOnce).await);
    assert!(task.await.expect("join").expect("authorize").is_allowed());

    let stored = records(&checker, "com.wasmnest.test").await;
    assert_eq!(stored.len(), 1, "允许必须落一条 origin 记录");
    assert_eq!(stored[0].target, "https://api.x.com:443");
    assert_eq!(stored[0].effect, AUTH_EFFECT_ALLOW);
    assert_eq!(stored[0].ops, Vec::<String>::new(), "网络记录恒无操作集");

    // 同 origin 后续请求：命中记录，零弹窗
    let verdict = checker
        .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v2/other")
        .await
        .expect("authorize");
    assert!(verdict.is_allowed(), "记录命中后续请求必须免询问: {verdict:?}");
    assert_eq!(log.len(), 1, "记录命中不得再弹窗");
}
/// 「以后都拒绝」：落 deny 记录 → 后续请求被硬拒绝且零弹窗
#[tokio::test]
async fn deny_always_records_deny_and_later_requests_are_blocked() {
    let (checker, log) = promptable(TINY, TINY).await;
    let task = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }
    });
    let request_id = wait_for_request_id(&log).await;
    assert!(checker.respond(&request_id, NetworkDecision::DenyAlways).await);
    let verdict = task.await.expect("join").expect("authorize");
    assert_eq!(
        verdict,
        OutboundVerdict::Deny {
            origin: "https://api.x.com:443".to_string(),
            reason: "user-denied-always",
        }
    );

    let stored = records(&checker, "com.wasmnest.test").await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].effect, AUTH_EFFECT_DENY);

    // 后续请求被 deny 记录拦住（不询问）
    let again = checker
        .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
        .await
        .expect("authorize");
    assert_eq!(
        again,
        OutboundVerdict::Deny {
            origin: "https://api.x.com:443".to_string(),
            reason: "deny-record",
        }
    );
    assert_eq!(log.len(), 1, "deny 记录命中不得再弹窗");
}
/// 拒绝（不记）：本次拒绝 + 窗口内复用 + 窗口过后重新询问，且库里无任何记录
#[tokio::test]
async fn plain_deny_leaves_no_record_and_asks_again_after_window() {
    let (checker, log) = promptable(TINY, IMMEDIATE).await;
    let task = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }
    });
    let request_id = wait_for_request_id(&log).await;
    assert!(checker.respond(&request_id, NetworkDecision::Deny).await);
    assert!(!task.await.expect("join").expect("authorize").is_allowed());
    assert!(
        records(&checker, "com.wasmnest.test").await.is_empty(),
        "「拒绝」不落账（否则与「以后都拒绝」无从区分）"
    );

    // 合并窗口内：复用同一决定，不再打扰用户
    let within = checker
        .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
        .await
        .expect("authorize");
    assert_eq!(
        within,
        OutboundVerdict::Deny {
            origin: "https://api.x.com:443".to_string(),
            reason: "user-denied",
        },
        "窗口内应复用刚落定的拒绝"
    );
    assert_eq!(log.len(), 1, "窗口内不得重复弹窗");

    // 窗口过后：重新询问（显式常量，不是永不重问的滑动窗口）
    tokio::time::sleep(IMMEDIATE * 2).await;
    let after = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }
    });
    wait_for_event_count(&log, 2).await;
    assert!(
        !after.await.expect("join").expect("authorize").is_allowed(),
        "无应答按拒绝"
    );
    assert_eq!(records(&checker, "com.wasmnest.test").await.len(), 0, "超时不得落账");
}
/// C10：无人应答时超时按拒绝、不落账、条目不残留
#[tokio::test]
async fn prompt_timeout_denies_without_recording() {
    let (checker, log) = promptable(IMMEDIATE, TINY).await;
    let verdict = checker
        .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
        .await
        .expect("authorize must not error");
    assert!(!verdict.is_allowed(), "超时必须按拒绝: {verdict:?}");
    assert_eq!(log.len(), 1);
    assert!(records(&checker, "com.wasmnest.test").await.is_empty(), "超时不得落账");
    assert!(
        checker.prompts.lock().await.is_empty(),
        "超时后不得残留悬空询问（否则 map 无界增长）"
    );
}
