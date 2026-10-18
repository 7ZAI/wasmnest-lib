//! 桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出的跨分组测试脚手架（用例文件经 `use super::scaffold::*` 引用）

use super::*;
use std::sync::Mutex;

use crate::security::auth_policy::AuthStrategy;
use std::path::Path;

/// 事件通道替身：记录每次投递的载荷，供用例断言「弹了几次、弹给谁」
///
/// 用**同步**互斥量：投递口是同步闭包（与 `AppHandle.emit` 同签名），在 tokio
/// worker 上调 `block_on` 会 panic（"Cannot block the current thread from within
/// a runtime"），因此这里不能复用 `tokio::sync::Mutex`。
#[derive(Clone, Default)]
pub(super) struct EmittedLog(Arc<std::sync::Mutex<Vec<serde_json::Value>>>);

impl EmittedLog {
    pub(super) fn events(&self) -> Vec<serde_json::Value> {
        self.0.lock().expect("emitted log lock").clone()
    }

    pub(super) fn len(&self) -> usize {
        self.0.lock().expect("emitted log lock").len()
    }

    /// 唯一事件的 request_id（多于一条即说明没合并，调用方据此失败）
    pub(super) fn sole_request_id(&self) -> String {
        let events = self.events();
        assert_eq!(
            events.len(),
            1,
            "同 origin 的并发请求必须只弹一次（实际 {} 次）",
            events.len()
        );
        events[0]
            .get("requestId")
            .and_then(|v| v.as_str())
            .expect("弹窗载荷缺 requestId")
            .to_string()
    }
}

/// 弹窗面校验器（内存库 + 捕获式事件通道 + 短超时，避免用例挂 30 秒）
///
/// 返回 `Arc`：并发用例要把校验器 move 进 `tokio::spawn`（要求 `'static`），
/// 借用局部变量会编译不过。
pub(super) async fn promptable(
    prompt_timeout: Duration,
    merge_window: Duration,
) -> (Arc<NetworkAuthChecker>, EmittedLog) {
    let (checker, _db, log) = promptable_with_db(prompt_timeout, merge_window).await;
    (checker, log)
}

/// 同 [`promptable`]，但多返回一份**同一**内存库句柄
///
/// 仅供需要直接动 schema 的用例（制造读失败）；其余用例走 `promptable`，
/// 避免「两条构造路径」本身成为漂移源。
pub(super) async fn promptable_with_db(
    prompt_timeout: Duration,
    merge_window: Duration,
) -> (Arc<NetworkAuthChecker>, Arc<Mutex<Database>>, EmittedLog) {
    let db = Arc::new(Mutex::new(
        Database::new(Path::new(":memory:")).expect("open in-memory db"),
    ));
    db.lock().expect("db lock").init_schema().expect("init schema");
    let log = EmittedLog::default();
    let sink = log.0.clone();
    let mut checker = NetworkAuthChecker::with_emitter(
        db.clone(),
        Some(Arc::new(move |_event: &str, payload: serde_json::Value| {
            // 测试通道只记录不失败：投递成功 = 前端收到弹窗
            sink.lock().expect("emitted log lock").push(payload);
            Ok(())
        })),
    );
    checker.prompt_timeout = prompt_timeout;
    checker.merge_window = merge_window;
    (Arc::new(checker), db, log)
}

/// 无头校验器（无事件通道 ⇒ 询问层不可用）
pub(super) async fn headless() -> Arc<NetworkAuthChecker> {
    let db = Database::new(Path::new(":memory:")).expect("open in-memory db");
    db.init_schema().expect("init schema");
    Arc::new(NetworkAuthChecker::new(Arc::new(Mutex::new(db)), None))
}

/// 该应用的 network 授权记录（用例断言落账用）
pub(super) async fn records(checker: &NetworkAuthChecker, plugin: &str) -> Vec<AuthRecordMatch> {
    checker
        .store
        .records_for_match(plugin, AuthResource::Network)
        .await
        .expect("read records")
}

pub(super) fn match_row(target: &str, effect: &str, prefix_match: bool) -> AuthRecordMatch {
    AuthRecordMatch {
        target: target.to_string(),
        effect: effect.to_string(),
        ops: Vec::new(),
        prefix_match,
    }
}

/// 造一条 network 记录（走生产写面，避免用例自己拼 SQL 造成两套口径）
pub(super) async fn seed_allow(checker: &NetworkAuthChecker, plugin: &str, target: &str) {
    checker
        .store
        .grant(plugin, AuthResource::Network, target, &[], AuthRecordSource::User)
        .await
        .expect("seed allow");
}

pub(super) async fn seed_deny(checker: &NetworkAuthChecker, plugin: &str, target: &str) {
    checker
        .store
        .deny(plugin, AuthResource::Network, target, AuthRecordSource::UserDeny)
        .await
        .expect("seed deny");
}

/// 写网络侧策略档位（走生产写面，与设置页策略控件同一入口）
pub(super) async fn set_strategy(checker: &NetworkAuthChecker, plugin: &str, tier: AuthStrategy) {
    checker
        .store
        .set_strategy(plugin, AuthResource::Network, tier)
        .await
        .expect("set strategy");
}

/// 某应用某 target 的 allow 记录的 `source`（经读模型读，不自己拼 SQL）
pub(super) async fn source_of(checker: &NetworkAuthChecker, plugin: &str, target: &str) -> Option<String> {
    checker
        .store
        .overview(plugin, "T", Vec::new())
        .await
        .expect("overview")
        .records
        .into_iter()
        .find(|r| r.target == target && r.effect == AUTH_EFFECT_ALLOW)
        .map(|r| r.source)
}

/// 直查 allow 记录的 `source`
///
/// 仅供「读模型不可用」的用例（读模型 `overview` 也要读策略表，而那些用例
/// 故意把策略表弄没了）；其余用例走 [`source_of`]，避免测试自建第二套口径。
pub(super) async fn source_via_raw_sql(db: &Arc<Mutex<Database>>, plugin: &str, target: &str) -> Option<String> {
    db.lock()
        .expect("db lock")
        .conn()
        .query_row(
            "SELECT source FROM plugin_auth_records \
             WHERE plugin_id = ?1 AND resource = 'network' AND target = ?2 AND effect = 'allow'",
            rusqlite::params![plugin, target],
            |row| row.get::<_, String>(0),
        )
        .ok()
}

/// 测试用短时限（够跑完一次调度，又不会让慢 CI 假失败）
pub(super) const TINY: Duration = Duration::from_millis(300);
/// 够触发一轮调度但几乎瞬时的等待上限
pub(super) const IMMEDIATE: Duration = Duration::from_millis(50);

// ==================== C6 目标归一化 ====================

// ==================== 测试辅助 ====================
/// 等到出现唯一一条弹窗事件并返回其 request_id
pub(super) async fn wait_for_request_id(log: &EmittedLog) -> String {
    wait_for_event_count(log, 1).await;
    log.sole_request_id()
}

/// 轮询等到事件数达到 `expected`（弹窗经事件通道抵达，用例不睡固定时长）
pub(super) async fn wait_for_event_count(log: &EmittedLog, expected: usize) {
    for _ in 0..200 {
        if log.len() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("等待 {} 条弹窗事件超时（实际 {} 条）", expected, log.len());
}
