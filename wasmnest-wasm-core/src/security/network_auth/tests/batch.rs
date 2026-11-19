//! 批量出站授权判定链用例组
//!
//! 断言口径：一次询问覆盖全部未决 origin / 记录与档位过滤 / 三态应答的落账 /
//! 超时与无头路径显性失败 / 容量丢弃透传 / 逐项结果按入参顺序回填。

use serde_json::json;

use crate::security::auth_policy::{AuthStrategy, AUTH_RECORDS_CAP};

use super::scaffold::*;
use super::*;

fn urls(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

fn event_request_id(log: &EmittedLog) -> String {
    log.events()[0]
        .get("requestId")
        .and_then(|value| value.as_str())
        .expect("批量事件缺 requestId")
        .to_string()
}

/// 默认档 3 个未决 origin：只发一次批量事件，允许后逐 origin 落 user allow 记录，
/// 再次批量零弹窗且全部命中 record
#[tokio::test]
async fn pending_origins_share_one_prompt_and_record_after_allow() {
    let (checker, log) = promptable(TINY, TINY).await;
    let batch = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_batch(
                    "com.wasmnest.test",
                    &urls(&[
                        "https://a.example/v1",
                        "https://b.example/v1",
                        "https://c.example/v1",
                    ]),
                )
                .await
        }
    });

    wait_for_event_count(&log, 1).await;
    let events = log.events();
    assert_eq!(events.len(), 1, "3 个未决 origin 必须只发一次批量事件");
    assert_eq!(
        events[0]["origins"],
        json!([
            "https://a.example:443",
            "https://b.example:443",
            "https://c.example:443",
        ])
    );
    assert_eq!(events[0]["pluginId"], "com.wasmnest.test");
    assert_eq!(events[0]["remembers"], json!(true));
    assert!(
        events[0]["batchId"].as_str().is_some(),
        "批量事件必须携带 batchId 供审计"
    );
    assert_ne!(
        events[0]["batchId"], events[0]["requestId"],
        "batchId 与 requestId 必须是独立标识"
    );

    let request_id = event_request_id(&log);
    assert!(
        checker
            .respond_batch(&request_id, NetworkBatchDecision::Allow)
            .await,
        "批量应答必须命中在途询问"
    );

    let BatchAuth::Verdicts {
        verdicts,
        dropped_records,
    } = batch.await.expect("join")
    else {
        panic!("允许应答必须返回逐项裁决");
    };
    assert_eq!(verdicts.len(), 3);
    assert_eq!(dropped_records, 0);
    for verdict in &verdicts {
        assert_eq!(verdict.reason(), "user", "用户允许的来源必须是 user");
    }
    assert_eq!(records(&checker, "com.wasmnest.test").await.len(), 3);
    for origin in [
        "https://a.example:443",
        "https://b.example:443",
        "https://c.example:443",
    ] {
        assert_eq!(
            source_of(&checker, "com.wasmnest.test", origin)
                .await
                .as_deref(),
            Some("user"),
            "允许必须逐 origin 落 user allow 记录"
        );
    }

    let again = checker
        .authorize_batch(
            "com.wasmnest.test",
            &urls(&[
                "https://a.example/v2",
                "https://b.example/v2",
                "https://c.example/v2",
            ]),
        )
        .await;
    let BatchAuth::Verdicts { verdicts, .. } = again else {
        panic!("记录命中必须返回逐项裁决");
    };
    for verdict in &verdicts {
        assert_eq!(verdict.reason(), "record", "第二次批量必须命中记录");
    }
    assert_eq!(log.len(), 1, "记录命中不得再次弹窗");
}

/// 混合已有 allow / deny：只询问未决部分；deny 不弹窗且返回 deny-record
#[tokio::test]
async fn existing_records_filter_before_the_single_prompt() {
    let (checker, log) = promptable(TINY, TINY).await;
    let plugin = "com.wasmnest.test";
    seed_allow(&checker, plugin, "https://allowed.example:443").await;
    seed_deny(&checker, plugin, "https://denied.example:443").await;

    let batch = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_batch(
                    plugin,
                    &urls(&[
                        "https://allowed.example/v1",
                        "https://denied.example/v1",
                        "https://pending.example/v1",
                    ]),
                )
                .await
        }
    });

    wait_for_event_count(&log, 1).await;
    assert_eq!(
        log.events()[0]["origins"],
        json!(["https://pending.example:443"]),
        "已有记录的目标不得进入批量弹窗"
    );
    let request_id = event_request_id(&log);
    assert!(
        checker
            .respond_batch(&request_id, NetworkBatchDecision::Allow)
            .await
    );

    let BatchAuth::Verdicts { verdicts, .. } = batch.await.expect("join") else {
        panic!("必须返回逐项裁决");
    };
    assert_eq!(
        verdicts[0],
        OutboundVerdict::Allow {
            origin: "https://allowed.example:443".to_string(),
            layer: "record",
        }
    );
    assert_eq!(
        verdicts[1],
        OutboundVerdict::Deny {
            origin: "https://denied.example:443".to_string(),
            reason: "deny-record",
        }
    );
    assert_eq!(
        verdicts[2],
        OutboundVerdict::Allow {
            origin: "https://pending.example:443".to_string(),
            layer: "user",
        }
    );
    assert_eq!(records(&checker, plugin).await.len(), 3);
}

/// 「总是询问」档：批量语义不成立，整体失败，零弹窗、零落账
#[tokio::test]
async fn always_ask_tier_rejects_batch_without_prompting() {
    let (checker, log) = promptable(TINY, TINY).await;
    let plugin = "com.wasmnest.test";
    set_strategy(&checker, plugin, AuthStrategy::AlwaysAsk).await;

    let result = checker
        .authorize_batch(
            plugin,
            &urls(&["https://a.example/v1", "https://b.example/v1"]),
        )
        .await;
    assert_eq!(result, BatchAuth::AlwaysAsk);
    assert_eq!(log.len(), 0, "总是询问档不得弹批量窗");
    assert!(
        records(&checker, plugin).await.is_empty(),
        "总是询问档不得落账"
    );
}

/// 「始终允许」档：零弹窗，全部落 always_allow 记录
#[tokio::test]
async fn always_allow_tier_records_every_origin_without_prompting() {
    let (checker, log) = promptable(TINY, TINY).await;
    let plugin = "com.wasmnest.test";
    set_strategy(&checker, plugin, AuthStrategy::AlwaysAllow).await;

    let result = checker
        .authorize_batch(
            plugin,
            &urls(&["https://a.example/v1", "https://b.example/v1"]),
        )
        .await;
    let BatchAuth::Verdicts {
        verdicts,
        dropped_records,
    } = result
    else {
        panic!("始终允许档必须返回逐项裁决");
    };
    assert_eq!(verdicts.len(), 2);
    assert_eq!(dropped_records, 0);
    for verdict in &verdicts {
        assert_eq!(verdict.reason(), "always-allow");
        assert!(verdict.is_allowed());
    }
    assert_eq!(log.len(), 0, "始终允许档不得弹窗");
    assert_eq!(
        source_of(&checker, plugin, "https://a.example:443")
            .await
            .as_deref(),
        Some("always_allow"),
        "免询问放行必须留痕"
    );
}

/// 超时 / 关闭：按本次拒绝，不落账、不留悬空批量询问
#[tokio::test]
async fn batch_prompt_timeout_denies_without_recording() {
    let (checker, log) = promptable(IMMEDIATE, TINY).await;
    let result = checker
        .authorize_batch(
            "com.wasmnest.test",
            &urls(&["https://a.example/v1", "https://b.example/v1"]),
        )
        .await;
    let BatchAuth::Verdicts { verdicts, .. } = result else {
        panic!("超时必须返回逐项裁决");
    };
    for verdict in &verdicts {
        assert_eq!(
            verdict,
            &OutboundVerdict::Deny {
                origin: verdict.origin().to_string(),
                reason: "user-denied",
            }
        );
    }
    assert_eq!(log.len(), 1);
    assert!(
        records(&checker, "com.wasmnest.test").await.is_empty(),
        "超时不得落账"
    );
    assert!(
        checker.batch_prompts.lock().await.is_empty(),
        "超时后不得残留批量询问"
    );
}

/// 无头上下文：整体不可用，不伪造逐项拒绝，也不落账
#[tokio::test]
async fn headless_context_reports_batch_unavailable() {
    let checker = headless().await;
    let result = checker
        .authorize_batch("com.wasmnest.test", &urls(&["https://a.example/v1"]))
        .await;
    assert!(
        matches!(&result, BatchAuth::Unavailable(_)),
        "无头上下文必须显性不可用: {result:?}"
    );
    assert!(records(&checker, "com.wasmnest.test").await.is_empty());
    assert!(checker.batch_prompts.lock().await.is_empty());
}

/// 事件投递失败：整体不可用，不落账
#[tokio::test]
async fn prompt_delivery_failure_reports_unavailable() {
    let db = Arc::new(DbMutex::new(
        Database::new(std::path::Path::new(":memory:")).expect("open in-memory db"),
    ));
    db.lock()
        .expect("db lock")
        .init_schema()
        .expect("init schema");
    let checker = NetworkAuthChecker::with_emitter(
        db,
        Some(Arc::new(|_event: &str, _payload: serde_json::Value| {
            Err("emit unavailable".to_string())
        })),
    );

    let result = checker
        .authorize_batch("com.wasmnest.test", &urls(&["https://a.example/v1"]))
        .await;
    assert!(
        matches!(&result, BatchAuth::Unavailable(_)),
        "投递失败必须显性不可用: {result:?}"
    );
    assert!(records(&checker, "com.wasmnest.test").await.is_empty());
    assert!(checker.batch_prompts.lock().await.is_empty());
}

/// 容量触顶：放行方向不变，未落账条数透传
#[tokio::test]
async fn dropped_records_are_reported_when_cap_is_reached() {
    let (checker, log) = promptable(TINY, TINY).await;
    let plugin = "com.wasmnest.test";
    for index in 0..AUTH_RECORDS_CAP {
        seed_allow(
            &checker,
            plugin,
            &format!("https://seed-{index}.example:443"),
        )
        .await;
    }
    assert_eq!(records(&checker, plugin).await.len(), AUTH_RECORDS_CAP);

    let batch = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_batch(
                    plugin,
                    &urls(&[
                        "https://new-a.example/v1",
                        "https://new-b.example/v1",
                        "https://new-c.example/v1",
                    ]),
                )
                .await
        }
    });
    wait_for_event_count(&log, 1).await;
    let request_id = event_request_id(&log);
    assert!(
        checker
            .respond_batch(&request_id, NetworkBatchDecision::Allow)
            .await
    );

    let BatchAuth::Verdicts {
        verdicts,
        dropped_records,
    } = batch.await.expect("join")
    else {
        panic!("容量触顶仍必须返回逐项裁决");
    };
    assert_eq!(verdicts.len(), 3);
    assert!(verdicts.iter().all(OutboundVerdict::is_allowed));
    assert_eq!(dropped_records, 3, "三条新记录都应因容量上限被丢弃");
    assert_eq!(
        records(&checker, plugin).await.len(),
        AUTH_RECORDS_CAP,
        "容量上限不得被批量落账突破"
    );
}

/// 同一 origin 的多个 URL：弹窗只占一行，逐项结果按入参索引回填
#[tokio::test]
async fn duplicate_origin_occupies_one_prompt_row_and_backfills_every_index() {
    let (checker, log) = promptable(TINY, TINY).await;
    let batch = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_batch(
                    "com.wasmnest.test",
                    &urls(&[
                        "https://same.example/semver/latest",
                        "https://same.example/npm/latest",
                        "https://other.example/v1",
                    ]),
                )
                .await
        }
    });
    wait_for_event_count(&log, 1).await;
    assert_eq!(
        log.events()[0]["origins"],
        json!(["https://same.example:443", "https://other.example:443"]),
        "同一 origin 只占弹窗一行"
    );

    let request_id = event_request_id(&log);
    assert!(
        checker
            .respond_batch(&request_id, NetworkBatchDecision::DenyAlways)
            .await
    );
    let BatchAuth::Verdicts { verdicts, .. } = batch.await.expect("join") else {
        panic!("必须返回逐项裁决");
    };
    assert_eq!(verdicts.len(), 3);
    for verdict in &verdicts {
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.reason(), "user-denied-always");
    }
    assert_eq!(verdicts[0].origin(), "https://same.example:443");
    assert_eq!(verdicts[1].origin(), "https://same.example:443");
    assert_eq!(verdicts[2].origin(), "https://other.example:443");
    assert_eq!(
        records(&checker, "com.wasmnest.test").await.len(),
        2,
        "「以后都拒绝」按去重后的 origin 落 deny 记录"
    );
}

/// 「以后都拒绝」后再次批量：硬拒绝记录命中，零弹窗
#[tokio::test]
async fn deny_always_blocks_later_batches_without_prompting() {
    let (checker, log) = promptable(TINY, TINY).await;
    let plugin = "com.wasmnest.test";
    let batch = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_batch(plugin, &urls(&["https://a.example/v1"]))
                .await
        }
    });
    wait_for_event_count(&log, 1).await;
    let request_id = event_request_id(&log);
    assert!(
        checker
            .respond_batch(&request_id, NetworkBatchDecision::DenyAlways)
            .await
    );
    let _ = batch.await.expect("join");

    let again = checker
        .authorize_batch(plugin, &urls(&["https://a.example/v2"]))
        .await;
    let BatchAuth::Verdicts { verdicts, .. } = again else {
        panic!("必须返回逐项裁决");
    };
    assert_eq!(
        verdicts[0],
        OutboundVerdict::Deny {
            origin: "https://a.example:443".to_string(),
            reason: "deny-record",
        }
    );
    assert_eq!(log.len(), 1, "deny 记录命中不得再次弹窗");
}

/// 未知 / 重复应答：显性失败，不改变已落定结果
#[tokio::test]
async fn unknown_or_repeated_batch_response_is_rejected() {
    let (checker, log) = promptable(TINY, TINY).await;
    assert!(
        !checker
            .respond_batch("no-such-request", NetworkBatchDecision::Allow)
            .await,
        "未知 request_id 必须返回失败"
    );

    let batch = tokio::spawn({
        let checker = checker.clone();
        async move {
            checker
                .authorize_batch("com.wasmnest.test", &urls(&["https://a.example/v1"]))
                .await
        }
    });
    wait_for_event_count(&log, 1).await;
    let request_id = event_request_id(&log);
    assert!(
        checker
            .respond_batch(&request_id, NetworkBatchDecision::Allow)
            .await
    );
    assert!(
        !checker
            .respond_batch(&request_id, NetworkBatchDecision::Deny)
            .await,
        "重复应答必须返回失败"
    );
    let BatchAuth::Verdicts { verdicts, .. } = batch.await.expect("join") else {
        panic!("必须返回逐项裁决");
    };
    assert!(verdicts[0].is_allowed(), "迟到应答不得改写已落定决定");
}

/// 空列表与不可归一化 URL 的防御性分支
#[tokio::test]
async fn empty_and_unparsable_inputs_are_handled_explicitly() {
    let (checker, log) = promptable(TINY, TINY).await;
    assert_eq!(
        checker.authorize_batch("com.wasmnest.test", &[]).await,
        BatchAuth::Verdicts {
            verdicts: Vec::new(),
            dropped_records: 0,
        }
    );
    assert!(
        matches!(
            checker
                .authorize_batch("com.wasmnest.test", &urls(&["not a url"]))
                .await,
            BatchAuth::Internal(_)
        ),
        "不可归一化 URL 必须显性失败"
    );
    assert_eq!(log.len(), 0);
}
