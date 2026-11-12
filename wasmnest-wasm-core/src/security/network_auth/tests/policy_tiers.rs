//! 策略档位（票 06：三档在网络侧与文件侧同语义） — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::scaffold::*;
use super::*;

use crate::security::auth_policy::AuthStrategy;
use std::sync::atomic::{AtomicUsize, Ordering};

//
// 变异自检（spec §12.2）：
// - M1 把 `StrategyStep::Ask` 分支改成继续读记录 ⇒ `always_ask_prompts_again_despite_an_allow_record` 转红
// - M2 把 `StrategyStep::AutoAllow` 改成询问 ⇒ `always_allow_releases_unrecorded_origin_and_records_it_as_unconfirmed`、
//   `both_decision_faces_agree_on_every_tier` 转红
// - M3 把 lands_allow_record 恒置真 ⇒ `always_ask_allow_leaves_no_record_behind` 转红
// - M4 把 deny 判定移到策略层之后 ⇒ `always_ask_still_honors_deny_records_without_prompting`、
//   `always_allow_never_overrides_a_deny_record` 转红
/// C2 正例：「总是询问」档下**已有 allow 记录也仍询问**（该档不读记录）
#[tokio::test]
async fn always_ask_prompts_again_despite_an_allow_record() {
    let (checker, log) = promptable(TINY, TINY).await;
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;
    seed_allow(&checker, "com.wasmnest.test", "https://api.x.com:443").await;

    let task = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }
    });
    // 已有记录却仍弹了窗 = 该档确实跳过了记录（不弹 ⇒ 等待超时直接失败）
    let request_id = wait_for_request_id(&log).await;
    assert!(
        checker
            .respond(&request_id, NetworkDecision::AllowOnce)
            .await
    );
    assert!(task.await.expect("join").expect("authorize").is_allowed());
}
/// C1 反例：「总是询问」跳过的**只是** allow 记录——deny 记录仍拦住且不再弹窗
#[tokio::test]
async fn always_ask_still_honors_deny_records_without_prompting() {
    let (checker, log) = promptable(TINY, TINY).await;
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;
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
        "「总是询问」不等于「忽略用户已经说过的拒绝」"
    );
    assert_eq!(
        log.len(),
        0,
        "deny 记录命中不得再弹窗（否则同一条硬拒绝会在每次访问时重新问一遍）"
    );
}
/// 票 06 的落账口径：「总是询问」档下允许**不落账**（落一条没人读的记录 =
/// 在管理界面谎称「用户已授权」）
#[tokio::test]
async fn always_ask_allow_leaves_no_record_behind() {
    let (checker, log) = promptable(TINY, TINY).await;
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;

    let task = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }
    });
    let request_id = wait_for_request_id(&log).await;
    assert!(
        checker
            .respond(&request_id, NetworkDecision::AllowOnce)
            .await
    );
    assert!(task.await.expect("join").expect("authorize").is_allowed());

    assert!(
        records(&checker, "com.wasmnest.test").await.is_empty(),
        "总是询问档不读记录：落一条永远不会被命中的 allow 记录只会让界面显示假授权"
    );
    assert_eq!(
        source_of(&checker, "com.wasmnest.test", "https://api.x.com:443").await,
        None
    );
}
/// 边界：「总是询问」档下「以后都拒绝」仍落 deny 记录，并在下一次访问生效
/// （不弹窗）
#[tokio::test]
async fn always_ask_keeps_the_deny_the_user_ever_gave() {
    let (checker, log) = promptable(TINY, TINY).await;
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;

    let task = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }
    });
    let request_id = wait_for_request_id(&log).await;
    assert!(
        checker
            .respond(&request_id, NetworkDecision::DenyAlways)
            .await
    );
    assert!(!task.await.expect("join").expect("authorize").is_allowed());

    let stored = records(&checker, "com.wasmnest.test").await;
    assert_eq!(stored.len(), 1, "「以后都拒绝」在任何档位下都要落账");
    assert_eq!(stored[0].effect, AUTH_EFFECT_DENY);

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
    assert_eq!(
        log.len(),
        1,
        "落下的 deny 记录必须免询问（否则该档把 deny 作废了）"
    );
}
/// 票 06 第二条：合并规则在「总是询问」档下**同样生效**（否则一次刷新几十次弹窗）
#[tokio::test]
async fn always_ask_still_merges_one_prompt_per_origin_batch() {
    let (checker, log) = promptable(TINY, TINY).await;
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAsk).await;
    let counter = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let checker = checker.clone();
        let counter = counter.clone();
        tasks.push(tokio::spawn(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            checker
                .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
                .await
        }));
    }
    let request_id = wait_for_request_id(&log).await;
    assert!(
        checker
            .respond(&request_id, NetworkDecision::AllowOnce)
            .await
    );
    for task in tasks {
        assert!(task.await.expect("join").expect("authorize").is_allowed());
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        3,
        "三条请求都真的走过判定链"
    );
    assert_eq!(
        log.len(),
        1,
        "同 origin 的一批在途请求在「总是询问」档下也只弹一次"
    );
}
/// C3 正例：「始终允许」档下未记录 origin 免询问放行，并以「未经确认」落账
#[tokio::test]
async fn always_allow_releases_unrecorded_origin_and_records_it_as_unconfirmed() {
    let (checker, log) = promptable(TINY, TINY).await;
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAllow).await;

    // URL 带 query：落库 target 绝不能含它（凭据红线，票 05 的约束对自动落账同样成立）
    let verdict = checker
        .authorize_outbound(
            "com.wasmnest.test",
            "https://api.x.com:443/v1/models?token=secret",
        )
        .await
        .expect("authorize");
    assert_eq!(
        verdict,
        OutboundVerdict::Allow {
            origin: "https://api.x.com:443".to_string(),
            layer: "always-allow",
        },
        "始终允许档免询问放行，且层名须能回答「走的哪一支」"
    );
    assert_eq!(log.len(), 0, "始终允许不得弹窗");

    let stored = records(&checker, "com.wasmnest.test").await;
    assert_eq!(stored.len(), 1, "免询问也必须留痕（spec §4.3）");
    assert_eq!(
        stored[0].target, "https://api.x.com:443",
        "落库 target 是 origin，不含 path / query"
    );
    assert_eq!(stored[0].effect, AUTH_EFFECT_ALLOW);
    assert_eq!(
        source_of(&checker, "com.wasmnest.test", "https://api.x.com:443")
            .await
            .as_deref(),
        Some(AuthRecordSource::AlwaysAllow.as_str()),
        "自动放行的记录来源必须是 always_allow（界面据此标「未经确认」）"
    );
}
