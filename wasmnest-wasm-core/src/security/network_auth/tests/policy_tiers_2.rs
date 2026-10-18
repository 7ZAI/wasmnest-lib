//! 策略档位（票 06：三档在网络侧与文件侧同语义） — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::scaffold::*;
use super::*;

use crate::monitor::MetricsRegistry;
use crate::security::auth_policy::{AuthStrategy, AUTH_RECORDS_CAP};

/// C8 边界：策略档位**放行不了**硬拒绝记录（任一档位都不得让 deny 失效）
#[tokio::test]
async fn always_allow_never_overrides_a_deny_record() {
    let (checker, log) = promptable(TINY, TINY).await;
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAllow).await;
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
        }
    );
    assert_eq!(log.len(), 0, "硬拒绝记录命中不得弹窗");
}
/// C3 边界：容量封顶时**放行方向不变**，只是不留痕，且丢弃进 core-monitor 计数
#[tokio::test]
async fn always_allow_keeps_allowing_when_the_record_cap_is_reached() {
    let (checker, _db, log) = promptable_with_db(TINY, TINY).await;
    let monitor = Arc::new(MetricsRegistry::new());
    checker.set_monitor(monitor.clone());
    set_strategy(&checker, "com.wasmnest.test", AuthStrategy::AlwaysAllow).await;
    for i in 0..AUTH_RECORDS_CAP {
        checker
            .store
            .grant(
                "com.wasmnest.test",
                AuthResource::Network,
                &format!("https://cap-{i}.example:443"),
                &[],
                AuthRecordSource::AlwaysAllow,
            )
            .await
            .expect("seed cap");
    }

    let verdict = checker
        .authorize_outbound("com.wasmnest.test", "https://overflow.example:443/v1")
        .await
        .expect("authorize");
    assert!(
        verdict.is_allowed(),
        "留痕失败不得反过来拒绝访问（档位语义是「不问」）: {verdict:?}"
    );
    assert_eq!(log.len(), 0);
    assert_eq!(
        records(&checker, "com.wasmnest.test").await.len(),
        AUTH_RECORDS_CAP,
        "超上限的新 origin 不得落账"
    );
    assert_eq!(
        monitor.snapshot()["plugins"]["com.wasmnest.test"]["authz"]["records_dropped"]
            .as_u64()
            .unwrap(),
        1,
        "容量丢弃必须进 core-monitor（spec §8.2；靠 set_monitor 接线才成立）"
    );
}
/// 两个判定面（弹窗 / 无询问）对**每一档**必须给出同一个答案
///
/// 无头弹窗面在需要询问时按拒绝收场（无事件通道），所以这组用例同时锁住
/// 「总是询问档下无询问面不因弹窗面记录过 allow 就放行」。
#[tokio::test]
async fn both_decision_faces_agree_on_every_tier() {
    for (tier, seeded_allow, expect_allowed) in [
        (AuthStrategy::Default, true, true),
        (AuthStrategy::Default, false, false),
        (AuthStrategy::AlwaysAsk, true, false),
        (AuthStrategy::AlwaysAsk, false, false),
        (AuthStrategy::AlwaysAllow, true, true),
        (AuthStrategy::AlwaysAllow, false, true),
    ] {
        let checker = headless().await;
        set_strategy(&checker, "com.wasmnest.test", tier).await;
        if seeded_allow {
            seed_allow(&checker, "com.wasmnest.test", "https://api.x.com:443").await;
        }
        let popup = checker
            .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
            .await
            .expect("authorize");
        let quiet = checker
            .authorize_outbound_quiet("com.wasmnest.test", "https://api.x.com:443/v1")
            .await
            .expect("authorize");
        let label = format!("tier={tier:?} seeded_allow={seeded_allow}");
        assert_eq!(
            popup.is_allowed(),
            expect_allowed,
            "弹窗面在 {label} 下答案不符: {popup:?}"
        );
        assert_eq!(
            quiet.is_allowed(),
            expect_allowed,
            "无询问面在 {label} 下与弹窗面不是同一个答案: {quiet:?}"
        );
    }
}
/// 异常：档位读不出来（表缺失）⇒ fail-safe 退化成询问，且这次允许**仍落账**
/// （用户点了允许就得留痕；按更宽松的档走才是危险方向）
#[tokio::test]
async fn strategy_read_failure_falls_back_to_asking_and_still_records() {
    let (checker, db, log) = promptable_with_db(TINY, TINY).await;
    db.lock()
        .expect("db lock")
        .conn()
        .execute("DROP TABLE plugin_auth_policies", [])
        .expect("drop policies table");

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
    assert!(
        task.await.expect("join").expect("authorize").is_allowed(),
        "档位读不出来时应询问而不是报错/放行"
    );
    assert_eq!(
        source_via_raw_sql(&db, "com.wasmnest.test", "https://api.x.com:443")
            .await
            .as_deref(),
        Some(AuthRecordSource::User.as_str()),
        "退化路径按默认档口径落账（用户点了允许就该被记住）"
    );
}
