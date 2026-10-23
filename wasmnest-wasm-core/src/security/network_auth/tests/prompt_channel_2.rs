//! 询问通道：合并 / 落账 / 超时 — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::scaffold::*;
use super::*;

use std::path::Path;

/// fail-safe 默认：无头上下文（无事件通道）⇒ 未记录目标直接拒绝
#[tokio::test]
async fn headless_context_denies_unrecorded_origin() {
    let checker = headless().await;
    let verdict = checker
        .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
        .await
        .expect("authorize must not error");
    assert!(!verdict.is_allowed(), "无弹窗通道时必须拒绝: {verdict:?}");
    assert!(
        checker.prompts.lock().await.is_empty(),
        "无头失败不得留下悬空询问"
    );
}
/// 事件投递失败（前端通道断）⇒ 整批拒绝，且不留下悬空询问
#[tokio::test]
async fn emit_failure_denies_and_cleans_the_prompt() {
    let db = Database::new(Path::new(":memory:")).expect("open in-memory db");
    db.init_schema().expect("init schema");
    let checker = NetworkAuthChecker::with_emitter(
        Arc::new(std::sync::Mutex::new(db)),
        Some(Arc::new(|_event: &str, _payload: serde_json::Value| {
            Err("event channel closed".to_string())
        })),
    );
    let verdict = checker
        .authorize_outbound("com.wasmnest.test", "https://api.x.com:443/v1")
        .await
        .expect("authorize must not error");
    assert!(!verdict.is_allowed(), "事件送不出去时不得放行: {verdict:?}");
    assert!(checker.prompts.lock().await.is_empty());
}
/// 二次应答不生效：已作答的询问不得被迟到点击改写
#[tokio::test]
async fn second_response_for_same_request_is_ignored() {
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
    assert!(checker.respond(&request_id, NetworkDecision::Deny).await);
    assert!(
        !checker
            .respond(&request_id, NetworkDecision::AllowOnce)
            .await,
        "重复应答必须被拒绝（否则已放行批次会被迟到点击改写）"
    );
    assert!(!task.await.expect("join").expect("authorize").is_allowed());
    assert!(
        records(&checker, "com.wasmnest.test").await.is_empty(),
        "被忽略的重复应答不得留下记录"
    );
}
