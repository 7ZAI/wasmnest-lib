//! 应用作用域共享服务的租约模板（service-leases）
//!
//! 依赖服务（传输面、对等网络节点等）不再由宿主常驻：由**插件 id** 按引用记账，
//! 首个引用拉起、最后一个引用关停。记账 / 幂等 / 回滚 / 串行化 / 顺序 / 日志全部
//! 由 [`ServiceRegistry`] 完成；能力服务只实现 [`ScopedService`] 的两个领域动作
//! 「怎么起、怎么停」。
//!
//! 本模块只有机制词汇：服务键（由定义服务的能力 crate 导出常量）与 holder
//! （插件 id 字符串），不含任何应用 id / 产品类型 / 业务状态机。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

/// 传输面服务键（机制词汇：WS + HTTP 单端口 + mDNS 广播 + 防休眠 + 指标采样）
///
/// **真源住本模块**（与 [`ServiceRegistry`] 同处）：机制内核（wasm-core）按
/// manifest `backgroundTransport` 声明在插件启动成功后 acquire 该槽位，而内核
/// 不能依赖 `wasmnest-server-core`（传输实现 + actix）；实现 crate 再导出本常量，
/// 宿主与实现侧的 import 路径不变。
pub const TRANSPORT_SERVICE_KEY: &str = "net.transport";

/// 应用作用域共享服务的机制契约。
///
/// 记账 / 幂等 / 回滚 / 串行化 / 顺序 / 日志全部由 [`ServiceRegistry`] 模板方法完成；
/// 实现者只提供两个真正与领域相关的动作。
#[async_trait]
pub trait ScopedService: Send + Sync + 'static {
    /// 稳定服务键（机制词汇，全仓唯一；由定义服务的能力 crate 导出常量）
    fn key(&self) -> &'static str;

    /// 0→1：真正拉起服务。模板保证只在「引用集合从空变为非空」时调用一次。
    ///
    /// 实现必须幂等（已被拉起时返回 `Ok`），且失败时自行回滚半成品。
    async fn start(&self) -> Result<(), String>;

    /// 1→0：真正关停服务。模板保证只在「最后一个引用释放」时调用一次。
    ///
    /// 实现必须幂等（未运行时返回 `Ok`）。
    async fn stop(&self) -> Result<(), String>;
}

/// [`ServiceRegistry::acquire`] 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireOutcome {
    /// 该 holder 已持有引用（幂等命中，未触碰服务本身）
    AlreadyHeld,
    /// 服务已在运行（他人持有或上次 stop 失败残留），本次只挂引用
    Attached,
    /// 引用集合原本为空，本次调用真正拉起了服务
    Started,
}

/// [`ServiceRegistry::release`] 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// 该 holder 未持有引用（调用方决定是否翻错误）
    NotHeld,
    /// 已释放该 holder，但仍有其它引用（服务继续运行）
    Released,
    /// 释放的是最后一个引用，服务已真正关停
    Stopped,
}

/// 单个服务槽位的诊断快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSnapshot {
    pub key: String,
    pub running: bool,
    /// 按字典序排列的 holder（插件 id）集合
    pub holders: Vec<String>,
}

/// 批量释放 / 关停的逐项结果（单 key 失败不影响其它 key）。
#[derive(Debug)]
pub struct ReleaseReport {
    pub key: String,
    pub outcome: Result<ReleaseOutcome, ServiceError>,
}

/// 注册表错误（全部显性：不静默降级）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// 未注册的服务键（装配期 / 调用方编程错误）
    #[error("service `{key}` is not registered")]
    UnknownService { key: String },
    /// 同 key 重复注册（装配期编程错误）
    #[error("service `{key}` is already registered")]
    AlreadyRegistered { key: String },
    /// 拉起失败；holder 未被记录，下次 acquire 可重试
    #[error("service `{key}` failed to start: {error}")]
    StartFailed { key: String, error: String },
    /// 关停失败；槽位保留 `running = true`（不假装已停），重新取得引用后的 release / shutdown_all 重试
    #[error("service `{key}` failed to stop: {error}")]
    StopFailed { key: String, error: String },
}

struct Slot {
    service: Arc<dyn ScopedService>,
    state: tokio::sync::Mutex<SlotState>,
}

#[derive(Default)]
struct SlotState {
    /// 插件 id 集合（Q4：一应用一条）
    holders: BTreeSet<String>,
    running: bool,
}

/// 应用作用域共享服务注册表（实例，非全局单例）。
///
/// 桌面 / 移动各持一份，经宿主上下文的晚绑槽位注入；测试各自 `new`，互不干扰；
/// 无头进程天然没有注册表。
pub struct ServiceRegistry {
    slots: RwLock<BTreeMap<&'static str, Arc<Slot>>>,
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            slots: RwLock::new(BTreeMap::new()),
        }
    }

    /// 注册一个服务实现（装配期调用；同 key 重复注册 = 显性错误）。
    pub fn register(&self, service: Arc<dyn ScopedService>) -> Result<(), ServiceError> {
        let key = service.key();
        let mut slots = self.slots.write().unwrap_or_else(|e| e.into_inner());
        if slots.contains_key(key) {
            return Err(ServiceError::AlreadyRegistered { key: key.to_string() });
        }
        slots.insert(
            key,
            Arc::new(Slot {
                service,
                state: tokio::sync::Mutex::new(SlotState::default()),
            }),
        );
        tracing::info!(service_key = key, "scoped service registered");
        Ok(())
    }

    /// 该服务键是否已注册（按端装配差异判定可用性）
    ///
    /// 用途：机制内核按 manifest 声明 acquire 某服务前先判「本端是否装配了它」——
    /// 例如传输面只在桌面端装配，移动端同一份内核不应把「本端没有该服务」当成
    /// 启动失败。未注册与「注册了但没启动」是两件事，后者看 [`Self::snapshot`]。
    pub fn has(&self, key: &str) -> bool {
        self.slots.read().unwrap_or_else(|e| e.into_inner()).contains_key(key)
    }

    fn slot(&self, key: &str) -> Result<Arc<Slot>, ServiceError> {
        self.slots
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
            .ok_or_else(|| ServiceError::UnknownService { key: key.to_string() })
    }

    /// 获取引用（幂等；0→1 时调用 `start`，成功后才落 holder）。
    pub async fn acquire(&self, key: &str, holder: &str) -> Result<AcquireOutcome, ServiceError> {
        let slot = self.slot(key)?;
        let mut state = slot.state.lock().await;

        if state.holders.contains(holder) {
            tracing::debug!(
                service_key = key,
                holder,
                outcome = "already-held",
                "scoped service acquire"
            );
            return Ok(AcquireOutcome::AlreadyHeld);
        }

        // 服务已在跑（他人持有，或上次 stop 失败残留）：只挂引用，不再 start
        if state.running {
            state.holders.insert(holder.to_string());
            tracing::info!(
                service_key = key,
                holder,
                holders = state.holders.len(),
                outcome = "attached",
                "scoped service acquire"
            );
            return Ok(AcquireOutcome::Attached);
        }

        // 持槽位锁跨 await：同 key 的 acquire/release 串行，start 恰好一次
        match slot.service.start().await {
            Ok(()) => {
                state.running = true;
                state.holders.insert(holder.to_string());
                tracing::info!(
                    service_key = key,
                    holder,
                    holders = state.holders.len(),
                    outcome = "started",
                    "scoped service acquire"
                );
                Ok(AcquireOutcome::Started)
            }
            Err(error) => {
                // 失败不污染记账：holder 不落，下次 acquire 可重试
                tracing::error!(
                    service_key = key,
                    holder,
                    error = %error,
                    outcome = "start-failed",
                    "scoped service acquire"
                );
                Err(ServiceError::StartFailed {
                    key: key.to_string(),
                    error,
                })
            }
        }
    }

    /// 释放引用（幂等；1→0 时调用 `stop`，失败保留 `running = true`）。
    pub async fn release(&self, key: &str, holder: &str) -> Result<ReleaseOutcome, ServiceError> {
        let slot = self.slot(key)?;
        let mut state = slot.state.lock().await;

        if !state.holders.remove(holder) {
            tracing::debug!(
                service_key = key,
                holder,
                outcome = "not-held",
                "scoped service release"
            );
            return Ok(ReleaseOutcome::NotHeld);
        }

        if !state.holders.is_empty() {
            tracing::info!(
                service_key = key,
                holder,
                holders = state.holders.len(),
                outcome = "released",
                "scoped service release"
            );
            return Ok(ReleaseOutcome::Released);
        }

        match slot.service.stop().await {
            Ok(()) => {
                state.running = false;
                tracing::info!(service_key = key, holder, outcome = "stopped", "scoped service release");
                Ok(ReleaseOutcome::Stopped)
            }
            Err(error) => {
                // 不撒谎：服务可能仍在跑，保留 running；重新取得引用后的 release /
                // shutdown_all 会重试 stop（失败那次已移除 holder，单独重放 release 不触发）
                tracing::error!(
                    service_key = key,
                    holder,
                    error = %error,
                    outcome = "stop-failed",
                    "scoped service release"
                );
                Err(ServiceError::StopFailed {
                    key: key.to_string(),
                    error,
                })
            }
        }
    }

    /// 插件离开运行态时的通用回收：按 key 字典序释放该 holder 的全部引用。
    ///
    /// 单个 key 失败只记录并继续，不阻断停用流程。返回的报告中只含该 holder
    /// 实际持有过的 key。
    pub async fn release_all_for(&self, holder: &str) -> Vec<ReleaseReport> {
        let slots: Vec<(&'static str, Arc<Slot>)> = self
            .slots
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(key, slot)| (*key, Arc::clone(slot)))
            .collect();

        let mut reports = Vec::new();
        for (key, slot) in slots {
            if !slot.state.lock().await.holders.contains(holder) {
                continue;
            }
            match self.release(key, holder).await {
                Ok(outcome) => {
                    reports.push(ReleaseReport {
                        key: key.to_string(),
                        outcome: Ok(outcome),
                    });
                }
                Err(error) => {
                    tracing::error!(
                        service_key = key,
                        holder,
                        error = %error,
                        outcome = "release-all-failed",
                        "scoped service release_all_for"
                    );
                    reports.push(ReleaseReport {
                        key: key.to_string(),
                        outcome: Err(error),
                    });
                }
            }
        }
        reports
    }

    /// 宿主退出兜底：对全部 `running` 槽位执行 stop（含之前 stop 失败的槽），并清空 holder。
    ///
    /// 按 key 字典序处理；单个失败只记录并继续。
    pub async fn shutdown_all(&self) -> Vec<ReleaseReport> {
        let slots: Vec<(&'static str, Arc<Slot>)> = self
            .slots
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(key, slot)| (*key, Arc::clone(slot)))
            .collect();

        let mut reports = Vec::new();
        for (key, slot) in slots {
            let mut state = slot.state.lock().await;
            let was_running = state.running;
            state.holders.clear();
            if !was_running {
                continue;
            }
            match slot.service.stop().await {
                Ok(()) => {
                    state.running = false;
                    tracing::info!(service_key = key, outcome = "stopped", "scoped service shutdown");
                    reports.push(ReleaseReport {
                        key: key.to_string(),
                        outcome: Ok(ReleaseOutcome::Stopped),
                    });
                }
                Err(error) => {
                    tracing::error!(
                        service_key = key,
                        error = %error,
                        outcome = "stop-failed",
                        "scoped service shutdown"
                    );
                    reports.push(ReleaseReport {
                        key: key.to_string(),
                        outcome: Err(ServiceError::StopFailed {
                            key: key.to_string(),
                            error,
                        }),
                    });
                }
            }
        }
        reports
    }

    /// 诊断快照（按 key 字典序）。
    pub async fn snapshot(&self) -> Vec<ServiceSnapshot> {
        let slots: Vec<(&'static str, Arc<Slot>)> = self
            .slots
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(key, slot)| (*key, Arc::clone(slot)))
            .collect();

        let mut snapshots = Vec::with_capacity(slots.len());
        for (key, slot) in slots {
            let state = slot.state.lock().await;
            snapshots.push(ServiceSnapshot {
                key: key.to_string(),
                running: state.running,
                holders: state.holders.iter().cloned().collect(),
            });
        }
        snapshots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// 计数 / 故障注入用替身；`starts` / `stops` 即「真正启停次数」证据。
    struct FakeService {
        key: &'static str,
        starts: AtomicUsize,
        stops: AtomicUsize,
        fail_start: AtomicBool,
        fail_stop: AtomicBool,
    }

    impl FakeService {
        fn new(key: &'static str) -> Arc<Self> {
            Arc::new(Self {
                key,
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                fail_start: AtomicBool::new(false),
                fail_stop: AtomicBool::new(false),
            })
        }

        fn starts(&self) -> usize {
            self.starts.load(Ordering::SeqCst)
        }

        fn stops(&self) -> usize {
            self.stops.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ScopedService for FakeService {
        fn key(&self) -> &'static str {
            self.key
        }

        async fn start(&self) -> Result<(), String> {
            if self.fail_start.load(Ordering::SeqCst) {
                return Err("injected start failure".to_string());
            }
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn stop(&self) -> Result<(), String> {
            if self.fail_stop.load(Ordering::SeqCst) {
                return Err("injected stop failure".to_string());
            }
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn registry_with(fakes: &[Arc<FakeService>]) -> ServiceRegistry {
        let registry = ServiceRegistry::new();
        for fake in fakes {
            registry.register(fake.clone() as Arc<dyn ScopedService>).unwrap();
        }
        registry
    }

    #[tokio::test]
    async fn start_and_stop_exactly_once_at_zero_one_boundaries() {
        let fake = FakeService::new("test.one");
        let reg = registry_with(&[fake.clone()]);

        assert_eq!(reg.acquire("test.one", "app.a").await.unwrap(), AcquireOutcome::Started);
        assert_eq!(fake.starts(), 1);
        assert_eq!(fake.stops(), 0);

        assert_eq!(reg.release("test.one", "app.a").await.unwrap(), ReleaseOutcome::Stopped);
        assert_eq!(fake.stops(), 1);

        // 再次 acquire 可复用：重新 0→1
        assert_eq!(reg.acquire("test.one", "app.a").await.unwrap(), AcquireOutcome::Started);
        assert_eq!(fake.starts(), 2);
    }

    #[tokio::test]
    async fn multiple_holders_share_until_last_release() {
        let fake = FakeService::new("test.shared");
        let reg = registry_with(&[fake.clone()]);

        assert_eq!(
            reg.acquire("test.shared", "app.a").await.unwrap(),
            AcquireOutcome::Started
        );
        assert_eq!(
            reg.acquire("test.shared", "app.b").await.unwrap(),
            AcquireOutcome::Attached
        );
        assert_eq!(fake.starts(), 1);

        assert_eq!(
            reg.release("test.shared", "app.a").await.unwrap(),
            ReleaseOutcome::Released
        );
        assert_eq!(fake.stops(), 0);

        assert_eq!(
            reg.release("test.shared", "app.b").await.unwrap(),
            ReleaseOutcome::Stopped
        );
        assert_eq!(fake.stops(), 1);
        assert_eq!(fake.starts(), 1);
    }

    #[tokio::test]
    async fn acquire_and_release_are_idempotent() {
        let fake = FakeService::new("test.idem");
        let reg = registry_with(&[fake.clone()]);

        reg.acquire("test.idem", "app.a").await.unwrap();
        assert_eq!(
            reg.acquire("test.idem", "app.a").await.unwrap(),
            AcquireOutcome::AlreadyHeld
        );
        assert_eq!(fake.starts(), 1);

        reg.release("test.idem", "app.a").await.unwrap();
        assert_eq!(
            reg.release("test.idem", "app.a").await.unwrap(),
            ReleaseOutcome::NotHeld
        );
        assert_eq!(fake.stops(), 1);
    }

    #[tokio::test]
    async fn start_failure_does_not_record_holder_and_can_retry() {
        let fake = FakeService::new("test.fail-start");
        fake.fail_start.store(true, Ordering::SeqCst);
        let reg = registry_with(&[fake.clone()]);

        let error = reg.acquire("test.fail-start", "app.a").await.unwrap_err();
        assert!(matches!(error, ServiceError::StartFailed { .. }));
        assert_eq!(fake.starts(), 0);
        assert!(reg.snapshot().await[0].holders.is_empty());
        assert!(!reg.snapshot().await[0].running);

        fake.fail_start.store(false, Ordering::SeqCst);
        assert_eq!(
            reg.acquire("test.fail-start", "app.a").await.unwrap(),
            AcquireOutcome::Started
        );
        assert_eq!(fake.starts(), 1);
        assert_eq!(reg.snapshot().await[0].holders, vec!["app.a".to_string()]);
    }

    #[tokio::test]
    async fn stop_failure_keeps_running_and_acquire_attaches_without_start() {
        let fake = FakeService::new("test.fail-stop");
        let reg = registry_with(&[fake.clone()]);

        reg.acquire("test.fail-stop", "app.a").await.unwrap();
        fake.fail_stop.store(true, Ordering::SeqCst);
        let error = reg.release("test.fail-stop", "app.a").await.unwrap_err();
        assert!(matches!(error, ServiceError::StopFailed { .. }));

        let snapshot = reg.snapshot().await;
        assert!(snapshot[0].running, "stop 失败必须保留 running=true（不假装已停）");
        assert!(snapshot[0].holders.is_empty());

        // 下一次 acquire 只挂引用，不再 start
        assert_eq!(
            reg.acquire("test.fail-stop", "app.b").await.unwrap(),
            AcquireOutcome::Attached
        );
        assert_eq!(fake.starts(), 1);

        // shutdown_all 重试 stop
        fake.fail_stop.store(false, Ordering::SeqCst);
        let reports = reg.shutdown_all().await;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].outcome.is_ok());
        assert_eq!(fake.stops(), 1);
        assert!(!reg.snapshot().await[0].running);
    }

    /// `has` 只回答「注册表里有没有这个槽位」：未注册与注册未启动必须可区分
    #[tokio::test]
    async fn has_distinguishes_unregistered_from_registered_not_running() {
        let fake = FakeService::new("test.presence");
        let reg = registry_with(&[fake.clone()]);

        assert!(reg.has("test.presence"));
        assert!(!reg.has("test.absent"));
        // 注册但零 holder：仍是「已装配」（与 unknown key 不同）
        assert!(!reg.snapshot().await[0].running);
        assert!(reg.has("test.presence"));
    }

    #[tokio::test]
    async fn unknown_service_and_duplicate_registration_are_explicit_errors() {
        let fake = FakeService::new("test.dup");
        let reg = registry_with(&[fake.clone()]);

        let error = reg.acquire("test.missing", "app.a").await.unwrap_err();
        match error {
            ServiceError::UnknownService { key } => assert_eq!(key, "test.missing"),
            other => panic!("expected UnknownService, got {other:?}"),
        }

        let duplicate = FakeService::new("test.dup");
        let error = reg
            .register(duplicate as Arc<dyn ScopedService>)
            .expect_err("同 key 重复注册必须报错");
        match error {
            ServiceError::AlreadyRegistered { key } => assert_eq!(key, "test.dup"),
            other => panic!("expected AlreadyRegistered, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn release_all_for_only_releases_holder_keys_in_key_order() {
        let alpha = FakeService::new("test.alpha");
        let beta = FakeService::new("test.beta");
        let reg = registry_with(&[beta.clone(), alpha.clone()]);

        reg.acquire("test.beta", "app.a").await.unwrap();
        reg.acquire("test.alpha", "app.a").await.unwrap();
        reg.acquire("test.alpha", "app.b").await.unwrap();

        let reports = reg.release_all_for("app.a").await;
        let keys: Vec<&str> = reports.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["test.alpha", "test.beta"], "按 key 字典序处理");
        assert!(reports.iter().all(|r| r.outcome.is_ok()));

        assert_eq!(alpha.starts(), 1);
        assert_eq!(alpha.stops(), 0, "app.b 仍持有 alpha");
        assert_eq!(beta.stops(), 1);
    }

    #[tokio::test]
    async fn release_all_for_continues_after_single_key_failure() {
        let alpha = FakeService::new("test.alpha");
        let beta = FakeService::new("test.beta");
        let reg = registry_with(&[alpha.clone(), beta.clone()]);

        reg.acquire("test.alpha", "app.a").await.unwrap();
        reg.acquire("test.beta", "app.a").await.unwrap();
        alpha.fail_stop.store(true, Ordering::SeqCst);

        let reports = reg.release_all_for("app.a").await;
        assert_eq!(reports.len(), 2);
        assert!(matches!(
            &reports[0].outcome,
            Err(ServiceError::StopFailed { key, .. }) if key == "test.alpha"
        ));
        assert!(reports[1].outcome.is_ok(), "单 key 失败不得阻断其它 key");
        assert_eq!(beta.stops(), 1);
        assert!(
            reg.snapshot()
                .await
                .iter()
                .find(|s| s.key == "test.alpha")
                .unwrap()
                .running
        );
    }

    #[tokio::test]
    async fn concurrent_acquire_starts_service_exactly_once() {
        let fake = FakeService::new("test.concurrent");
        let reg = Arc::new(registry_with(&[fake.clone()]));

        let (a, b) = tokio::join!(
            {
                let reg = Arc::clone(&reg);
                async move { reg.acquire("test.concurrent", "app.a").await.unwrap() }
            },
            {
                let reg = Arc::clone(&reg);
                async move { reg.acquire("test.concurrent", "app.b").await.unwrap() }
            }
        );

        assert_eq!(fake.starts(), 1, "并发 acquire 必须只 start 一次");
        let mut outcomes = [a, b];
        outcomes.sort_by_key(|o| match o {
            AcquireOutcome::Started => 0,
            AcquireOutcome::Attached => 1,
            AcquireOutcome::AlreadyHeld => 2,
        });
        assert_eq!(outcomes[0], AcquireOutcome::Started);
        assert_eq!(outcomes[1], AcquireOutcome::Attached);
        assert_eq!(reg.snapshot().await[0].holders.len(), 2);
    }

    #[tokio::test]
    async fn shutdown_all_stops_running_slots_and_clears_holders() {
        let alpha = FakeService::new("test.alpha");
        let beta = FakeService::new("test.beta");
        let reg = registry_with(&[alpha.clone(), beta.clone()]);

        reg.acquire("test.beta", "app.a").await.unwrap();
        reg.acquire("test.alpha", "app.b").await.unwrap();

        let reports = reg.shutdown_all().await;
        let keys: Vec<&str> = reports.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["test.alpha", "test.beta"]);
        assert_eq!(alpha.stops(), 1);
        assert_eq!(beta.stops(), 1);
        assert!(reg.snapshot().await.iter().all(|s| !s.running && s.holders.is_empty()));
    }

    #[test]
    fn module_uses_mechanism_vocabulary_only() {
        let source = include_str!("service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in ["file-transfer", "bedcode", "com.wasmnest", "FILE_TRANSFER"] {
            assert!(
                !production.contains(forbidden),
                "服务租约模块不得出现产品名词：{forbidden}"
            );
        }
    }
}
