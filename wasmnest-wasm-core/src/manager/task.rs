//! host-task 执行引擎（core-task，ABI v20）
//!
//! 宿主专用 OS 线程池 + 任务注册表：插件把「单元操作计划」（plan）交给宿主，
//! 池线程真并行执行既有宿主原语（`fs`·`process`·`http` 域直调，零新
//! DTO；入口权限 `task:run` 由宿主侧 task 域实现仲裁，执行时另过 kind 对应
//! 域权限门）。本模块只管**执行与事件管道**，不接触 WASM / Store——单元执行体
//! 为普通 std 阻塞函数（内部走 `block_on_async` 的 ambient 分支，F3），从机制
//! 上杜绝重入（spec §8.1：池线程永不回调进插件，回调只经消费派发任务）。
//!
//! 并发模型（spec §5.2/§5.4）：
//! - 全局队列 + 每任务「并发窗口」：`maxConcurrency` 显式时，完成一个单元把
//!   下一个未开始单元入队（每任务同时在跑 ≤ maxConcurrency，不饿死其他任务）；
//!   缺省 = 全部单元直接入队，全局池（[`PLUGIN_TASK_POOL_THREADS`] 条线程）
//!   自然限流——跨任务公平性由队列顺序近似保证（v20 不做多任务公平调度承诺）。
//! - 协作式取消 / 墙钟超时：phase 翻转后未开始单元不再入队（快照补 skipped
//!   条目），运行中单元跑完（结果照记）；终态通知经 condvar（`execute-batch`
//!   同步等待用）。
//! - **不提供单元级抢占**（审计票 09 裁决 B）：单元执行体是同步阻塞直调
//!   （`fs` / `http` / `process`），池线程内没有中断点 ⇒ v20 不承诺单元超时，兜底
//!   只有任务墙钟 `PLUGIN_TASK_JOB_TIMEOUT_MS`；阻塞型单元（如 `process.run-sync`）
//!   的超时由被调用方自带参数负责。原 `PLUGIN_TASK_UNIT_TIMEOUT_MS` 常量因不可
//!   兑现已退役（不再留下「常量与实现脱钩」的漂移）。
//! - 生命周期：`purge_for_plugin`（宿主停用回收）cancel 全部在册任务 + 清回调
//!   队列。**没有「应用 shutdown 时 cancel 全任务并等池排空」这一步**（审计票 09
//!   核实后删除该承诺，避免注释漂移）：池是进程级 std OS 线程，应用退出即随进程
//!   回收，且退出后已无结果消费方；生命周期入口只有 `purge_for_plugin`（按插件）
//!   与 `cancel`（按任务）两处。
//!
//! 回调管道（spec §5.3）：每插件一条**有界** tokio channel（深度
//! [`PLUGIN_TASK_CALLBACK_QUEUE_DEPTH`]）+ 单消费派发任务（tokio，串行 = 实例锁
//! 天然要求）——经 `PluginServices::dispatch_task_event` 投递 `events-task` 可选
//! 导出。溢出策略：progress 可丢 + `warn!` + `droppedEvents` 计数；terminal 优先
//! 入队，极端也丢则 `error!` 留痕——回调是尽力投递，`status` 是权威快照。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::mpsc as tmpsc;

use crate::host_api::context::TaskEngine;
use crate::host_api::unit_executor::UnitExecutor;
use crate::manager::runtime::WasmHostContext;
use crate::monitor::{MetricsRegistry, MetricsSource};
use crate::runtime_util::ambient_handle;
use crate::system::constants as C;

/// execute-batch 超时后等待在途单元落盘的结果宽限期（M-02）
///
/// 单元是同步宿主调用（各自带超时），在途数 <= 初始并发窗口，此宽限有界；
/// 到期仍未落盘则按当时快照返回（失败仍可见，不无限阻塞调用方）。
const DRAIN_GRACE: Duration = Duration::from_secs(3);

// ==================== 数据类型 ====================

/// 单元定义（plan 解析产物；结果槽下标 = units 下标）
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlanUnit {
    pub(crate) id: String,
    pub(crate) kind: String,
    /// 对应宿主原语既有请求 JSON 原样内嵌（零新 DTO 映射）
    pub(crate) params: serde_json::Value,
}

/// plan（`execute-batch` / `submit` 共用），camelCase
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Plan {
    pub(crate) units: Vec<PlanUnit>,
    #[serde(default)]
    pub(crate) max_concurrency: Option<usize>,
    #[serde(default)]
    pub(crate) job_timeout_ms: Option<u64>,
    #[serde(default)]
    pub(crate) progress: Option<ProgressCfg>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProgressCfg {
    #[serde(default)]
    pub(crate) every_units: Option<u32>,
    #[serde(default)]
    pub(crate) every_ms: Option<u64>,
}

/// 任务阶段（终态互斥）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobPhase {
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobPhase {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            JobPhase::Running => "running",
            JobPhase::Completed => "completed",
            JobPhase::Failed => "failed",
            JobPhase::Cancelled => "cancelled",
        }
    }
}

/// 单个单元的终态
#[derive(Debug, Clone)]
struct UnitDone {
    id: String,
    ok: bool,
    /// ok=true：单元原语的原返回 JSON 字符串（`process.run-sync` / `fs.read-dir` /
    /// `fs.stat` 本身即 JSON 文本；`fs.read` / `fs.exists` / `http.fetch` 为原生值
    /// 的 JSON 编码）；超限截断 + truncated 标记
    value: Option<String>,
    /// ok=false：错误消息
    error: Option<String>,
    duration_ms: u64,
    truncated: bool,
}

/// 任务内部状态（一把锁串行化所有写路径；热路径只在单元完成瞬间短暂持锁）
pub(crate) struct JobInner {
    owner: String,
    units: Vec<PlanUnit>,
    phase: JobPhase,
    /// 结果槽（`None` = 未开始；快照时补 skipped 条目）
    results: Vec<Option<UnitDone>>,
    /// 未终态单元数（初始 = units.len()）
    remaining: usize,
    /// 下一个未开始单元下标（完成一个 → 入队下一个；cancel/超时后停驻）
    next_to_start: usize,
    done: usize,
    failed: usize,
    created_at_ms: u64,
    started_at_ms: u64,
    job_timeout_ms: u64,
    /// progress 事件节流（plan 可配置；缺省每 10 单元 / 500ms）
    progress_every_units: u32,
    progress_every_ms: u64,
    last_progress_ms: u64,
    dropped_events: u64,
}

/// 任务句柄（注册表条目）
pub(crate) struct JobHandle {
    pub(crate) inner: Mutex<JobInner>,
    /// 终态谓词（condvar 配套）
    pub(crate) finished: Mutex<bool>,
    pub(crate) condvar: Condvar,
    /// 是否投递 events-task 回调（execute-batch = false：同步返回，不回调）
    pub(crate) emit_events: bool,
    /// 宿主上下文（池线程 / 消费任务经此访问 services 与权限门）
    pub(crate) host_ctx: Arc<WasmHostContext>,
    /// 终态事件已投递（M-02：仅 Running→terminal 转移投递一次；cancel /
    /// 超时 / 后完成单元不得重复排终态事件）
    pub(crate) terminal_notified: std::sync::atomic::AtomicBool,
}

impl JobHandle {
    fn owner(&self) -> String {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .owner
            .clone()
    }

    fn phase(&self) -> JobPhase {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).phase
    }

    fn done_failed(&self) -> (usize, usize) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.done, inner.failed)
    }
}

// ==================== 注册表与池（进程级单例） ====================

struct TaskRegistry {
    /// job_id（`task-<hex>`）→ 任务
    jobs: Mutex<HashMap<String, Arc<JobHandle>>>,
    /// 每插件回调 channel 发送端（深度 = PLUGIN_TASK_CALLBACK_QUEUE_DEPTH；
    /// 消费任务持有 receiver，purge 时移除 entry → tx drop → 消费任务退出）
    queues: Mutex<HashMap<String, tmpsc::Sender<EventEntry>>>,
    job_seq: AtomicU64,
}

/// host-task 进程级指标（core-monitor 的 `task` 段数据源；纯原子，热路径零锁，
/// 零日志——AGENTS.md §8 红线）。`jobs_active` 不单独记账：实时读注册表长度，
/// 避免「插入/移除埋点漂移」风险。
pub(crate) struct TaskMetrics {
    /// 累计提交计划数（submit + execute-batch）
    jobs_submitted_total: AtomicU64,
    /// 配额类拒绝累计（超每插件在册上限 / plan 无效，fail-visible）
    jobs_rejected_total: AtomicU64,
    /// 单元完成累计（含失败，ok/fail 归任务结果）
    units_completed_total: AtomicU64,
    /// 同时执行单元数高水位（≈ 池利用率代理）
    concurrent_units_peak: AtomicU64,
    concurrent_units_current: AtomicU64,
    /// 回调事件丢弃累计（progress + terminal，channel 满）
    events_dropped_total: AtomicU64,
}

// 全局实例（core-task 为进程级单例，指标随注册表生命周期）
static TASK_METRICS: LazyLock<TaskMetrics> = LazyLock::new(|| TaskMetrics {
    jobs_submitted_total: AtomicU64::new(0),
    jobs_rejected_total: AtomicU64::new(0),
    units_completed_total: AtomicU64::new(0),
    concurrent_units_peak: AtomicU64::new(0),
    concurrent_units_current: AtomicU64::new(0),
    events_dropped_total: AtomicU64::new(0),
});

/// task 段快照（MetricsRegistry::snapshot 汇入 core-monitor；键 camelCase 沿
/// JSON 惯例）：jobs submitted/active/rejected + units completed + 并发高水位
/// + 回调丢弃 + 池线程数常量
pub(crate) fn task_metrics_snapshot() -> serde_json::Value {
    let active = REGISTRY
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    serde_json::json!({
        "jobsSubmittedTotal": TASK_METRICS.jobs_submitted_total.load(Ordering::Relaxed),
        "jobsActive": active,
        "jobsRejectedTotal": TASK_METRICS.jobs_rejected_total.load(Ordering::Relaxed),
        "unitsCompletedTotal": TASK_METRICS.units_completed_total.load(Ordering::Relaxed),
        "concurrentUnitsPeak": TASK_METRICS.concurrent_units_peak.load(Ordering::Relaxed),
        "eventsDroppedTotal": TASK_METRICS.events_dropped_total.load(Ordering::Relaxed),
        "poolThreads": C::PLUGIN_TASK_POOL_THREADS,
    })
}

/// host-task 维度快照源（monitor 注册制，spec 票 02）：把 [`task_metrics_snapshot`]
/// 包装为 [`MetricsSource`] trait 对象。core-monitor 不再内联 import manager::task
/// （隐藏环 host_api/fs → monitor → manager → host_api 破除），全量快照经
/// 注册回调取得 `task` 段
pub(crate) struct TaskMetricsSource;

impl MetricsSource for TaskMetricsSource {
    fn snapshot(&self) -> serde_json::Value {
        task_metrics_snapshot()
    }
}

/// 向 core-monitor 注册 `task` 段快照源（幂等：同名重复注册覆盖不叠加）。
/// 注册点 = runtime 初始化 `with_config`——晚于 monitor 创建、早于任何
/// 快照消费方，无「未注册段降级」时序窗口
pub(crate) fn register_task_metrics_source(registry: &MetricsRegistry) {
    registry.register_source("task", Box::new(TaskMetricsSource));
}

/// 事件条目：属主 + 事件 JSON + 投递目标上下文（消费任务经 host_ctx.services() 取 services）
struct EventEntry {
    owner: String,
    host_ctx: Arc<WasmHostContext>,
    event: serde_json::Value,
}

static REGISTRY: LazyLock<Arc<TaskRegistry>> = LazyLock::new(|| {
    Arc::new(TaskRegistry {
        jobs: Mutex::new(HashMap::new()),
        queues: Mutex::new(HashMap::new()),
        job_seq: AtomicU64::new(0),
    })
});

/// 池队列条目：job_id + 单元下标（入队时已由 next_to_start 游标固定）
struct QueuedUnit {
    job_id: String,
    index: usize,
}

/// 全局专用 OS 线程池（惰性启动：首次提交 plan 时建池）
struct TaskPool {
    tx: mpsc::Sender<QueuedUnit>,
}

static POOL: LazyLock<Mutex<Option<TaskPool>>> = LazyLock::new(|| Mutex::new(None));

fn pool_tx() -> mpsc::Sender<QueuedUnit> {
    let mut guard = POOL.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(p) => p.tx.clone(),
        None => {
            let (tx, rx) = mpsc::channel::<QueuedUnit>();
            let rx = Arc::new(Mutex::new(rx));
            for _ in 0..C::PLUGIN_TASK_POOL_THREADS {
                let rx = rx.clone();
                crate::system::error_boundary::spawn_os_thread("host-task-pool", move || {
                    pool_loop(&rx);
                });
            }
            *guard = Some(TaskPool { tx: tx.clone() });
            tx
        }
    }
}

fn pool_loop(rx: &Arc<Mutex<mpsc::Receiver<QueuedUnit>>>) {
    loop {
        let item = {
            let rx = rx.lock().unwrap_or_else(|e| e.into_inner());
            match rx.recv() {
                Ok(item) => item,
                Err(_) => break, // 发送端全部 drop → 池退出
            }
        };
        let job = REGISTRY
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&item.job_id)
            .cloned();
        let Some(removed_job) = job else {
            // 注册表无此任务（execute-batch 已摘除 / purge 已清）：丢弃队列残留
            continue;
        };
        run_unit(&item, &removed_job);
    }
}

/// 单元执行开始：并发计数 + 高水位（与完成时 fetch_sub 成对）
fn unit_started() {
    let cur = TASK_METRICS
        .concurrent_units_current
        .fetch_add(1, Ordering::Relaxed)
        + 1;
    TASK_METRICS
        .concurrent_units_peak
        .fetch_max(cur, Ordering::Relaxed);
}

// ==================== 单元执行 ====================

// ==================== 单元执行器注册表（C4：core-task 经接口分发，零 host_api 具体域引用） ====================

/// 已注册执行器条目（`type_id` 用于幂等去重：组合根与测试装配都可能注册同一执行器）
struct RegisteredExecutor {
    executor: Arc<dyn UnitExecutor>,
    type_id: std::any::TypeId,
}

/// 进程级执行器注册表（组合根/测试装配经 [`Self::register_unit_executor`] 注入；
/// 本模块零 host_api 具体域函数引用）
static UNIT_EXECUTORS: LazyLock<Mutex<Vec<RegisteredExecutor>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// 注册单元执行器（幂等：同具体类型只注册一次）
pub(crate) fn register_unit_executor(executor: Arc<dyn UnitExecutor>) {
    let type_id = (executor.as_ref() as &dyn std::any::Any).type_id();
    let mut executors = UNIT_EXECUTORS.lock().unwrap_or_else(|e| e.into_inner());
    if !executors.iter().any(|re| re.type_id == type_id) {
        executors.push(RegisteredExecutor { executor, type_id });
    }
}

/// kind → 执行器分发（域权限门 + fs_auth 已授权校验在各执行器内部，绝不从池线程
/// 触发用户弹窗——spec §6；fs 单元的授权预判按管线顺序预检，判据同源）。
/// 未注册的 kind 显性报 unknown（fail-visible，不静默）。
/// 返回 `value` 的 JSON 编码：字符串返回型（read-dir / stat / run-sync）直接透传
/// 原 JSON 文本；其他类型按原生值 JSON 编码；`value.len()` 超上限截断 + truncated。
fn execute_unit(host_ctx: &Arc<WasmHostContext>, owner: &str, unit: &PlanUnit) -> UnitDone {
    let started = Instant::now();
    let result: Result<Option<String>, String> = {
        let executors = UNIT_EXECUTORS.lock().unwrap_or_else(|e| e.into_inner());
        match executors
            .iter()
            .find(|re| re.executor.matches(unit.kind.as_str()))
        {
            Some(re) => re
                .executor
                .execute(host_ctx, owner, unit.kind.as_str(), &unit.params),
            None => Err(format!("task: unknown unit kind '{}'", unit.kind)),
        }
    };

    let (ok, value, error, truncated) = match result {
        Ok(Some(v)) => {
            let (v, t) = truncate_json(v);
            (true, Some(v), None, t)
        }
        Ok(None) => (true, None, None, false),
        Err(e) => (false, None, Some(e), false),
    };

    UnitDone {
        id: unit.id.clone(),
        ok,
        value,
        error,
        duration_ms: started.elapsed().as_millis() as u64,
        truncated,
    }
}

/// 单元结果按字节上限截断（JSON 文本长度；保护回调载荷与插件线性内存）
fn truncate_json(v: String) -> (String, bool) {
    if v.len() > C::PLUGIN_TASK_UNIT_RESULT_MAX_BYTES {
        let cut: String = v
            .chars()
            .take(C::PLUGIN_TASK_UNIT_RESULT_MAX_BYTES / 4)
            .collect();
        (format!("{}…[truncated]", cut), true)
    } else {
        (v, false)
    }
}

// ==================== 执行引擎 trait 实现（C3：host_api/task.rs 经接口调用） ====================

/// core-task 执行引擎（[`TaskEngine`] 接口的实现）
///
/// host_api/task.rs 做权限门（本质是门禁不是引擎），执行走本引擎；两者经两阶段注入
/// （PluginHost 构造时 [`WasmHostContext::set_task_engine`]，PluginServices 先例）解耦——
/// host_api 不再 import `manager::task`（spec C3「消费方定义接口」）。
pub(crate) struct CoreTaskEngine {
    /// 自持的宿主上下文句柄（见 [`TaskEngine::execute_batch`] 的「注入时捕获」说明）
    host_ctx: Arc<WasmHostContext>,
}

impl CoreTaskEngine {
    pub(crate) fn new(host_ctx: Arc<WasmHostContext>) -> Self {
        Self { host_ctx }
    }
}

impl TaskEngine for CoreTaskEngine {
    fn execute_batch(&self, owner: &str, plan_json: &str) -> Result<String, String> {
        execute_batch(self.host_ctx.clone(), owner, plan_json)
    }

    fn submit(&self, owner: &str, plan_json: &str) -> Result<String, String> {
        submit(self.host_ctx.clone(), owner, plan_json)
    }

    fn status(&self, owner: &str, job_id: &str) -> Result<Option<String>, String> {
        status(owner, job_id)
    }

    fn cancel(&self, owner: &str, job_id: &str) -> Result<bool, String> {
        cancel(owner, job_id)
    }

    fn list_jobs(&self, owner: &str) -> Result<String, String> {
        list_jobs(owner)
    }
}

// ==================== 对外 API（宿主侧 task 域实现入口） ====================

/// 登记任务并立即返回 `task-<hex>`（`submit`）：started 事件 + 池执行 + 回调
pub(crate) fn submit(
    host_ctx: Arc<WasmHostContext>,
    owner: &str,
    plan_json: &str,
) -> Result<String, String> {
    let plan = parse_plan(plan_json)?;
    // started 事件在 register_job 内、池分派**之前**投出（M-03）：快单单元作业
    // 若先投 started 再分派，单单元可在 started 入队前完成 → 插件观察到终态先于
    // 启动（「完成比启动早」的乱序）。
    let job_id = register_job(host_ctx, owner, plan, true)?;
    Ok(job_id)
}

/// 同步批：登记 → 并发执行 → join 返回全量结果（`execute-batch`）。
/// 阻塞调用线程至全部单元终态（或墙钟超时）——同 `run-sync` 语义，不投回调。
pub(crate) fn execute_batch(
    host_ctx: Arc<WasmHostContext>,
    owner: &str,
    plan_json: &str,
) -> Result<String, String> {
    let plan = parse_plan(plan_json)?;
    let units_len = plan.units.len();
    let job_id = register_job(host_ctx, owner, plan, false)?;
    let job = REGISTRY
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&job_id)
        .cloned()
        .ok_or_else(|| "task: job disappeared during submit".to_string())?;

    // 同步等待终态（condvar + 墙钟超时）；wait_timeout_while 返回即检查谓词
    let timeout = {
        let inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
        Duration::from_millis(inner.job_timeout_ms.saturating_add(1))
    };
    let mut finished = job.finished.lock().unwrap_or_else(|e| e.into_inner());
    if !*finished {
        // wait_timeout_while 按值收守卫（self：&mut self autoref），返回新的守卫
        let (guard, _res) = job
            .condvar
            .wait_timeout_while(finished, timeout, |f: &mut bool| !*f)
            .unwrap_or_else(|e| e.into_inner());
        finished = guard;
    }
    // 墙钟超时兜底（register_job 后无人翻转 phase 的情形——防御）：强制取消
    if job.phase() == JobPhase::Running {
        let mut inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.phase = JobPhase::Cancelled;
    }
    drop(finished);

    // drain 在途单元（M-02）：取消后仍在执行的单元会把真实结果写回结果槽；
    // 等它们落盘再快照，避免「误导性 skipped + 在途真实结果永不返回」。
    // 单元是同步宿主调用（各自有超时），在途数 <= 初始窗口，等待有界。
    // （未开始单元经 run_unit 顶部 phase 检查返回，槽保持 None → 快照补 skipped，如实）
    let drain_deadline = std::time::Instant::now() + DRAIN_GRACE;
    loop {
        let filled = {
            let inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.results.iter().filter(|r| r.is_some()).count()
        };
        if filled == units_len || std::time::Instant::now() >= drain_deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    // 同步批不留痕（避免占每插件 MAX_JOBS 配额）
    REGISTRY
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&job_id);

    Ok(result_json(&job_id, &job).to_string())
}

/// 任务状态快照（自愈查询）：`Ok(None)` = 不存在 / 非属主（防枚举）
pub(crate) fn status(owner: &str, job_id: &str) -> Result<Option<String>, String> {
    let job = REGISTRY
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(job_id)
        .cloned();
    let Some(job) = job else { return Ok(None) };
    if job.owner() != owner {
        return Ok(None);
    }
    Ok(Some(status_json(job_id, &job)))
}

/// 取消（协作式、幂等）：返回是否命中（不存在 / 非属主 / 已终态 → false）
pub(crate) fn cancel(owner: &str, job_id: &str) -> Result<bool, String> {
    let job = REGISTRY
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(job_id)
        .cloned();
    let Some(job) = job else { return Ok(false) };
    if job.owner() != owner {
        return Ok(false);
    }
    let mut inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
    if inner.phase != JobPhase::Running {
        return Ok(false);
    }
    inner.phase = JobPhase::Cancelled;
    let owner = inner.owner.clone();
    drop(inner);
    // 终态事件经 notify_terminal（M-02）：terminal_notified 标志恰好一次——
    // 在途单元随后完成不再重复排终态事件
    notify_terminal(&job, job_id, &owner);
    Ok(true)
}

/// 本插件在册任务清单（自愈快照）
pub(crate) fn list_jobs(owner: &str) -> Result<String, String> {
    let jobs = REGISTRY.jobs.lock().unwrap_or_else(|e| e.into_inner());
    let list: Vec<serde_json::Value> = jobs
        .iter()
        .filter(|(_, h)| h.owner() == owner)
        .map(|(job_id, h)| {
            let inner = h.inner.lock().unwrap_or_else(|e| e.into_inner());
            serde_json::json!({
                "jobId": job_id,
                "state": inner.phase.as_str(),
                "doneUnits": inner.done,
                "failedUnits": inner.failed,
                "createdAt": inner.created_at_ms,
            })
        })
        .collect();
    serde_json::to_string(&list).map_err(|e| format!("task: list_jobs serialize failed: {}", e))
}

/// 停用回收：cancel 全部在册任务 + 清回调队列（只碰本人）
pub(crate) fn purge_for_plugin(plugin_id: &str) -> usize {
    let job_ids: Vec<String> = {
        let jobs = REGISTRY.jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.iter()
            .filter(|(_, h)| h.owner() == plugin_id)
            .map(|(id, _)| id.clone())
            .collect()
    };
    let mut cancelled = 0usize;
    for id in job_ids {
        if cancel(plugin_id, &id).unwrap_or(false) {
            cancelled += 1;
        }
    }
    // 摘除该插件全部在册任务（含已终态残留）：停用后无人可访问，防孤儿占
    // 配额（惰性 GC 只在下一次提交时清本插件的）与内存；jobs_active 随之归零
    {
        let mut jobs = REGISTRY.jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.retain(|_, h| h.owner() != plugin_id);
    }
    // 移除回调 channel → tx drop → 消费任务 recv 返回 None 自行退出
    REGISTRY
        .queues
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(plugin_id);
    cancelled
}

// ==================== 登记与调度 ====================

fn parse_plan(plan_json: &str) -> Result<Plan, String> {
    let plan: Plan =
        serde_json::from_str(plan_json).map_err(|e| format!("task: invalid plan JSON: {}", e))?;
    if plan.units.is_empty() {
        return Err("task: plan has no units".to_string());
    }
    if plan.units.len() > C::PLUGIN_TASK_MAX_UNITS_PER_PLAN {
        return Err(format!(
            "task: plan exceeds max units per plan ({} > {})",
            plan.units.len(),
            C::PLUGIN_TASK_MAX_UNITS_PER_PLAN
        ));
    }
    if plan.max_concurrency == Some(0) {
        return Err("task: maxConcurrency must be > 0".to_string());
    }
    Ok(plan)
}

/// 配额检查 + 登记 + 提交初始并发窗口
fn register_job(
    host_ctx: Arc<WasmHostContext>,
    owner: &str,
    plan: Plan,
    emit_events: bool,
) -> Result<String, String> {
    // 每插件在册任务上限（含 running + queued；execute-batch 瞬时登记同算）
    {
        let mut jobs = REGISTRY.jobs.lock().unwrap_or_else(|e| e.into_inner());
        // 惰性 GC：先移除本插件**终态**任务（终态已不在 running/queued，不占配额；
        // 否则 submit 任务完成后残留 map，第 5 个 submit 被配额误拒）。终态任务
        // 在下次同插件提交前仍可 status 自愈查询；purge 时全量清。
        jobs.retain(|_, h| h.owner() != owner || h.phase() == JobPhase::Running);
        let count = jobs.values().filter(|h| h.owner() == owner).count();
        if count >= C::PLUGIN_TASK_MAX_JOBS_PER_PLUGIN {
            TASK_METRICS
                .jobs_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "task: too many jobs for plugin (limit {})",
                C::PLUGIN_TASK_MAX_JOBS_PER_PLUGIN
            ));
        }
        TASK_METRICS
            .jobs_submitted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    let units_len = plan.units.len();
    // 缺省 = 池满即排队（全部入队，全局池自然限流）；显式时 ≤ 池线程数
    let window = plan
        .max_concurrency
        .map(|n| n.clamp(1, C::PLUGIN_TASK_POOL_THREADS))
        .unwrap_or(units_len);
    let job_timeout_ms = plan.job_timeout_ms.unwrap_or(C::PLUGIN_TASK_JOB_TIMEOUT_MS);
    let now_ms = unix_ms();
    let progress_cfg = plan.progress.unwrap_or(ProgressCfg {
        every_units: None,
        every_ms: None,
    });

    let job_id = REGISTRY.next_job_id();
    let handle = Arc::new(JobHandle {
        inner: Mutex::new(JobInner {
            owner: owner.to_string(),
            units: plan.units,
            phase: JobPhase::Running,
            results: vec![None; units_len],
            remaining: units_len,
            next_to_start: window.min(units_len),
            done: 0,
            failed: 0,
            created_at_ms: now_ms,
            started_at_ms: now_ms,
            job_timeout_ms,
            progress_every_units: progress_cfg.every_units.unwrap_or(10).max(1),
            progress_every_ms: progress_cfg.every_ms.unwrap_or(500),
            last_progress_ms: now_ms,
            dropped_events: 0,
        }),
        finished: Mutex::new(false),
        condvar: Condvar::new(),
        emit_events,
        host_ctx: host_ctx.clone(),
        terminal_notified: std::sync::atomic::AtomicBool::new(false),
    });
    REGISTRY
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(job_id.clone(), handle);

    // started 事件：注册表插入后、池分派前投出（M-03）——池线程可能立即完成
    // 单单元并触发终态事件，若 started 晚于分派会被终态抢先（乱序）
    if emit_events {
        enqueue_event(
            &host_ctx,
            owner,
            serde_json::json!({ "jobId": job_id, "phase": "started" }),
            true,
        );
    }

    // 提交初始并发窗口（cursor 已停在 window 处，剩余由完成回调推进）
    let tx = pool_tx();
    for i in 0..window.min(units_len) {
        let _ = tx.send(QueuedUnit {
            job_id: job_id.clone(),
            index: i,
        });
    }
    Ok(job_id)
}

/// 执行一个单元（池线程内）：取消/超时检查 → 直调宿主原语 → 结果写回 →
/// 推进并发窗口 → 终态判定 → 事件 / 终态通知
fn run_unit(item: &QueuedUnit, job: &Arc<JobHandle>) {
    // 单元快照 + 前置检查（锁内取，锁外执行——执行体不持 state 锁）
    let (unit, owner) = {
        let mut inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.phase != JobPhase::Running || item.index >= inner.units.len() {
            return; // cancelled / 已终态 / 非法下标
        }
        // 墙钟超时 → 翻终态，未开始单元不再推进
        if job_timeout_exceeded(&inner) {
            inner.phase = JobPhase::Cancelled;
            let owner = inner.owner.clone();
            let jid = item.job_id.clone();
            drop(inner);
            notify_terminal(job, &jid, &owner);
            return;
        }
        (inner.units[item.index].clone(), inner.owner.clone())
    };

    // 单元执行开始：并发计数 + 高水位（完成时 fetch_sub 成对）
    unit_started();
    let done = execute_unit(&job.host_ctx, &owner, &unit);
    // 单元完成：累计 + 并发归位（开始计数在 execute_unit 前成对）
    TASK_METRICS
        .units_completed_total
        .fetch_add(1, Ordering::Relaxed);
    TASK_METRICS
        .concurrent_units_current
        .fetch_sub(1, Ordering::Relaxed);

    let mut inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
    // cancel 竞态下结果照记（spec：运行中单元跑完）
    inner.results[item.index] = Some(done);
    inner.remaining = inner.remaining.saturating_sub(1);
    let ok = inner.results[item.index]
        .as_ref()
        .map(|d| d.ok)
        .unwrap_or(false);
    inner.done += 1;
    if !ok {
        inner.failed += 1;
    }

    // 终态判定 / 推进
    // phase 离开 Running 后**停推游标**（M-02）：cancel/超时后不再派发新单元——
    // 未开始单元保持 skipped（终态快照如实），在途单元照常完成写结果
    let next_index = if inner.phase != JobPhase::Running || inner.remaining == 0 {
        None
    } else if job_timeout_exceeded(&inner) {
        inner.phase = JobPhase::Cancelled;
        None
    } else {
        let n = inner.next_to_start;
        if n < inner.units.len() {
            inner.next_to_start += 1;
            Some(n)
        } else {
            None
        }
    };
    // 仅 Running→terminal 转移（M-02）：cancel 已置 Cancelled 后完成的单元不得
    // 把 phase 覆写回 Completed/Failed（末单元翻回 = 终态被污染）
    if let Some(terminal) = terminal_phase_for(&inner) {
        inner.phase = terminal;
    }
    let phase = inner.phase;
    let jid = item.job_id.clone();
    let owner = inner.owner.clone();
    let progress_event = if job.emit_events && inner.should_emit_progress() {
        let (done, failed) = (inner.done, inner.failed);
        Some(serde_json::json!({
            "jobId": jid,
            "phase": "progress",
            "doneUnits": done,
            "failedUnits": failed,
        }))
    } else {
        None
    };
    drop(inner);

    // 推进并发窗口（锁外）
    if let Some(n) = next_index {
        let _ = pool_tx().send(QueuedUnit {
            job_id: jid.clone(),
            index: n,
        });
    }

    // 事件与通知
    if let Some(ev) = progress_event {
        enqueue_event(&job.host_ctx, &owner, ev, false);
    }
    if phase != JobPhase::Running {
        notify_terminal(job, &jid, &owner);
    }
}

/// 终态通知：condvar 唤醒 + 终态事件（terminal 必达；**恰好一次**，M-02）
///
/// `terminal_notified` 标志内锁设置：cancel / 超时 / 后完成单元都会到达这里，
/// 但只有首个 Running→terminal 转移者投递事件；重复到达只唤醒 condvar 不再
/// 排终态事件（插件侧不会收到两条终态）。
fn notify_terminal(job: &Arc<JobHandle>, job_id: &str, owner: &str) {
    if job
        .terminal_notified
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    if job.emit_events {
        let (done, failed) = job.done_failed();
        let ev = serde_json::json!({
            "jobId": job_id,
            "phase": job.phase().as_str(),
            "doneUnits": done,
            "failedUnits": failed,
            "result": result_json(job_id, job),
        });
        enqueue_event(&job.host_ctx, owner, ev, true);
    }
    notify_finished(job);
}

fn notify_finished(job: &Arc<JobHandle>) {
    *job.finished.lock().unwrap_or_else(|e| e.into_inner()) = true;
    job.condvar.notify_all();
}

// ==================== 快照 / 结果 JSON ====================

/// 任务状态快照 JSON（status / list-jobs 条目用；成功后事件丢失可自愈）
fn status_json(job_id: &str, job: &Arc<JobHandle>) -> String {
    let inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
    serde_json::json!({
        "jobId": job_id,
        "state": inner.phase.as_str(),
        "doneUnits": inner.done,
        "failedUnits": inner.failed,
        "droppedEvents": inner.dropped_events,
        "results": bounded_results(&inner),
    })
    .to_string()
}

/// execute-batch 终态 / submit 终态事件 result：`{ jobId, results, cancelled }`
fn result_json(job_id: &str, job: &Arc<JobHandle>) -> serde_json::Value {
    let inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
    serde_json::json!({
        "jobId": job_id,
        "results": all_results(&inner),
        "cancelled": inner.phase == JobPhase::Cancelled,
    })
}

/// 全部单元结果（未开始补 skipped 条目，结果按 units 原顺序）
fn all_results(inner: &JobInner) -> Vec<serde_json::Value> {
    (0..inner.units.len())
        .map(|i| match &inner.results[i] {
            Some(d) => {
                let mut m = serde_json::Map::new();
                m.insert("id".into(), serde_json::json!(d.id));
                m.insert("ok".into(), serde_json::json!(d.ok));
                if let Some(v) = &d.value {
                    m.insert("value".into(), serde_json::json!(v));
                }
                if let Some(e) = &d.error {
                    m.insert("error".into(), serde_json::json!(e));
                }
                m.insert("durationMs".into(), serde_json::json!(d.duration_ms));
                if d.truncated {
                    m.insert("truncated".into(), serde_json::json!(true));
                }
                serde_json::Value::Object(m)
            }
            None => serde_json::json!({
                "id": inner.units[i].id,
                "ok": false,
                "error": "skipped: job cancelled or phase ended",
            }),
        })
        .collect()
}

/// status 的终态结果保留（有界：只留最近 STATUS_RESULTS_MAX 条 + 计数）
fn bounded_results(inner: &JobInner) -> serde_json::Value {
    let max = C::PLUGIN_TASK_STATUS_RESULTS_MAX;
    let total = inner.units.len();
    let shown = total.min(max);
    let slice = &inner.results[total - shown..];
    serde_json::json!({
        "retained": shown,
        "total": total,
        "entries": slice.iter().map(|r| match r {
            Some(d) => serde_json::json!({
                "id": d.id,
                "ok": d.ok,
                "value": d.value,
                "error": d.error,
                "durationMs": d.duration_ms,
            }),
            None => serde_json::json!({ "error": "skipped" }),
        }).collect::<Vec<_>>(),
    })
}

fn job_timeout_exceeded(inner: &JobInner) -> bool {
    unix_ms().saturating_sub(inner.started_at_ms) > inner.job_timeout_ms
}

/// 终态转移判定（M-02）：**仅 Running → terminal**——cancel/超时已置终态时
/// 保持（在途单元后完成不得把 Cancelled 覆写回 Completed/Failed）。
/// 纯函数便于直测。
fn terminal_phase_for(inner: &JobInner) -> Option<JobPhase> {
    if inner.phase != JobPhase::Running || inner.remaining != 0 {
        return None;
    }
    Some(if inner.failed == inner.units.len() {
        JobPhase::Failed
    } else {
        JobPhase::Completed
    })
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl JobInner {
    /// progress 事件节流：完成数达到 every_units 的倍数 **且** 距上次事件
    /// 超过 every_ms 才放行（spec §4.3 progress 节流；溢出时事件可丢有计数）
    fn should_emit_progress(&mut self) -> bool {
        if !self.done.is_multiple_of(self.progress_every_units as usize) {
            return false;
        }
        let now = unix_ms();
        if now.saturating_sub(self.last_progress_ms) < self.progress_every_ms {
            return false;
        }
        self.last_progress_ms = now;
        true
    }
}

impl TaskRegistry {
    fn next_job_id(&self) -> String {
        let n = self.job_seq.fetch_add(1, Ordering::Relaxed);
        let tick = unix_ms() as u32 & 0xffff;
        format!("task-{:x}{:x}", n, tick)
    }
}

// ==================== 回调管道（每插件有界 channel + 消费派发任务） ====================

/// 是否允许为该属主新建回调 channel（审计票 09）
///
/// 只有「注册表里还有该属主的在册任务」才允许新建：purge（插件停用回收）之后到期的
/// 在飞单元会走到 `enqueue_event`，若此时重建 channel + 消费派发任务，二者会永久残留
/// 且事件会派发给已停用的插件。
fn may_open_callback_channel(owner: &str) -> bool {
    REGISTRY
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .any(|h| h.owner() == owner)
}

/// 入队回调事件（无返回值、尽力投递；terminal 优先，progress 可丢）
///
/// 每插件一条有界 channel（深度 = PLUGIN_TASK_CALLBACK_QUEUE_DEPTH）：满时
/// progress 丢弃 + `warn!` + `droppedEvents` 计数；terminal 也丢则 `error!` 留痕。
/// 入队失败只在插件侧事件计数上反映（status 可见），不阻塞任务执行。
///
/// 属主已从注册表摘除（purge / 从未登记任务）时直接丢弃，不重建 channel——见
/// [`may_open_callback_channel`]。
fn enqueue_event(
    host_ctx: &Arc<WasmHostContext>,
    owner: &str,
    event: serde_json::Value,
    terminal: bool,
) {
    // purge 后到达的事件不得重建回调 channel（审计票 09）：插件已停用、其任务已从注册表
    // 摘除，此处若新建 channel + consumer 会永久残留（停用后不会再有人 purge 它）并把
    // 事件派发给已停用的插件。快路径判据 = 注册表里已无该属主的在册任务；真正创建前的
    // 复查在下方锁内（M-04）。
    if !may_open_callback_channel(owner) {
        tracing::debug!(
            plugin_id = %owner,
            "[host-task] no registered job for owner (purged/unregistered), event dropped"
        );
        return;
    }

    let entry = EventEntry {
        owner: owner.to_string(),
        host_ctx: host_ctx.clone(),
        event,
    };
    let tx = {
        // 原子 check-and-create（M-04）：属主在册任务检查与回调通道创建同一临界区，
        // 与 purge（jobs→queues 同锁序）不插缝——purge 摘任务与清队列之间不会
        // 再插入一条新建通道 + 永久 consumer（审计票 09 注释警告的孤儿通道）。
        let jobs = REGISTRY.jobs.lock().unwrap_or_else(|e| e.into_inner());
        if !jobs.values().any(|h| h.owner() == owner) {
            tracing::debug!(
                plugin_id = %owner,
                "[host-task] owner purged between check and create, event dropped"
            );
            return;
        }
        let mut queues = REGISTRY.queues.lock().unwrap_or_else(|e| e.into_inner());
        match queues.get(owner) {
            Some(tx) => tx.clone(),
            None => {
                let (tx, rx) = tmpsc::channel::<EventEntry>(C::PLUGIN_TASK_CALLBACK_QUEUE_DEPTH);
                // 消费派发任务（每插件至多一个；串行 = F1 实例锁天然要求）
                ambient_handle().spawn(consumer_loop(rx));
                queues.insert(owner.to_string(), tx.clone());
                tx
            }
        }
    };
    match tx.try_send(entry) {
        Ok(()) => {}
        Err(tmpsc::error::TrySendError::Full(failed_entry)) => {
            TASK_METRICS
                .events_dropped_total
                .fetch_add(1, Ordering::Relaxed);
            if terminal {
                tracing::error!(
                    plugin_id = %owner,
                    "[host-task] terminal event dropped (callback queue full) — status is authoritative"
                );
            } else {
                tracing::warn!(
                    plugin_id = %owner,
                    "[host-task] progress event dropped (callback queue full)"
                );
            }
            // droppedEvents 计数（status 可见，spec §5.3）——按事件自身的 jobId
            // 归账（M-21）：旧实现按 HashMap 迭代序给「第一个匹配属主」的作业计数，
            // 多作业在途时自愈 status 错报。
            if let Some(job) = job_for_drop_counting(owner, &failed_entry.event) {
                let mut inner = job.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.dropped_events = inner.dropped_events.saturating_add(1);
            }
        }
        Err(tmpsc::error::TrySendError::Closed(_)) => {
            // consumer 已退出（purge / 插件停用）：静默丢弃（宿主不缓存）
            tracing::debug!(plugin_id = %owner, "[host-task] callback channel closed, event dropped");
        }
    }
}

/// 为丢弃事件找归账作业（M-21）：按事件自身 `jobId` 精确匹配且校验属主——
/// 多作业在途时 droppedEvents 只记到真正丢了事件的作业上。
fn job_for_drop_counting(owner: &str, event: &serde_json::Value) -> Option<Arc<JobHandle>> {
    let job_id = event.get("jobId").and_then(|v| v.as_str())?;
    let jobs = REGISTRY.jobs.lock().unwrap_or_else(|e| e.into_inner());
    let job = jobs.get(job_id).cloned()?;
    if job.owner() == owner {
        Some(job)
    } else {
        None
    }
}

/// 消费派发任务：串行取事件 → `PluginServices::dispatch_task_event`
/// （同步门面；内部经宿主 `call_guest_blocking` 加锁调用，F4 模式）。
/// channel 关闭（purge 移除 tx）后退出。
async fn consumer_loop(mut rx: tmpsc::Receiver<EventEntry>) {
    while let Some(entry) = rx.recv().await {
        let services = match entry.host_ctx.services().await {
            Some(s) => s,
            None => {
                tracing::warn!(plugin_id = %entry.owner, "[host-task] plugin services unavailable, task event dropped");
                continue;
            }
        };
        services.dispatch_task_event(entry.owner, entry.event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 票 07：fs.* 单元的预检按管线顺序判两件事，且**不弹窗**
    ///
    #[test]
    fn truncate_json_marks_truncated() {
        // 超过 PLUGIN_TASK_UNIT_RESULT_MAX_BYTES（1 MiB）才截断
        let big = "x".repeat(crate::system::constants::PLUGIN_TASK_UNIT_RESULT_MAX_BYTES + 64);
        let (out, t) = truncate_json(big);
        assert!(t);
        assert!(out.contains("[truncated]"));
        assert!(out.len() < crate::system::constants::PLUGIN_TASK_UNIT_RESULT_MAX_BYTES);
    }

    #[test]
    fn truncate_json_passes_small() {
        let (out, t) = truncate_json("ok".to_string());
        assert!(!t);
        assert_eq!(out, "ok");
    }

    #[test]
    fn parse_plan_rejects_empty_units() {
        let e = parse_plan(r#"{"units":[]}"#).unwrap_err();
        assert!(e.contains("no units"));
    }

    /// purge 之后到期的在飞单元不得重建回调 channel（审计票 09）：重建出来的 channel 与
    /// 消费派发任务无人再回收，且事件会派发给已停用的插件。
    #[test]
    fn may_open_callback_channel_requires_registered_job() {
        let owner = "com.wasmnest.task-purge-probe";
        purge_for_plugin(owner);
        assert!(
            !may_open_callback_channel(owner),
            "purge 后该属主已无在册任务，不得再新建回调 channel"
        );
        let queues = REGISTRY.queues.lock().unwrap_or_else(|e| e.into_inner());
        assert!(queues.get(owner).is_none(), "purge 后回调队列不得残留/复活");
    }

    /// M-02：终态转移只发生在 Running → terminal——cancel/超时已置终态后，
    /// 在途单元完成不得把 phase 覆写回 Completed/Failed。变异判据：把判定改回
    /// 「remaining == 0 即覆写」⇒ 本条转红（Cancelled 被末单元翻回）。
    #[test]
    fn terminal_phase_only_transitions_from_running() {
        let inner = |phase: JobPhase, remaining: usize, failed: usize| JobInner {
            owner: "t".to_string(),
            units: vec![PlanUnit {
                id: "u".to_string(),
                kind: "fs.stat".to_string(),
                params: serde_json::json!({}),
            }],
            phase,
            results: vec![None; 1],
            remaining,
            next_to_start: 1,
            done: 1,
            failed,
            created_at_ms: 0,
            started_at_ms: 0,
            job_timeout_ms: 60000,
            progress_every_units: 10,
            progress_every_ms: 500,
            last_progress_ms: 0,
            dropped_events: 0,
        };

        // Running + 全单元完成 → Completed / Failed
        assert_eq!(
            terminal_phase_for(&inner(JobPhase::Running, 0, 0)),
            Some(JobPhase::Completed)
        );
        assert_eq!(
            terminal_phase_for(&inner(JobPhase::Running, 0, 1)),
            Some(JobPhase::Failed)
        );
        // Running 但还有单元未完成 → 不终态
        assert_eq!(terminal_phase_for(&inner(JobPhase::Running, 1, 0)), None);
        // 已 Cancelled（cancel/超时）即使 remaining==0 也不得翻回
        assert_eq!(
            terminal_phase_for(&inner(JobPhase::Cancelled, 0, 0)),
            None,
            "Cancelled 不得被覆写"
        );
        // 已 Completed / Failed 幂等保持
        assert_eq!(terminal_phase_for(&inner(JobPhase::Completed, 0, 0)), None);
        assert_eq!(terminal_phase_for(&inner(JobPhase::Failed, 0, 1)), None);
    }

    /// M-21：丢弃事件按**事件自身 jobId** 归账——多作业在途时不得错记到
    /// 「第一个匹配属主」的作业上。
    #[test]
    fn dropped_events_are_counted_per_job_not_first_match() {
        purge_for_plugin("drop-probe");
        // 造两个同属主作业（直接插注册表；submit 依赖真实执行链，这里只测归账）
        let mk = |job_id: &str, phase: JobPhase| {
            let handle = Arc::new(JobHandle {
                inner: Mutex::new(JobInner {
                    owner: "drop-probe".to_string(),
                    units: vec![PlanUnit {
                        id: "u".to_string(),
                        kind: "fs.stat".to_string(),
                        params: serde_json::json!({}),
                    }],
                    phase,
                    results: vec![None; 1],
                    remaining: 0,
                    next_to_start: 1,
                    done: 1,
                    failed: 0,
                    created_at_ms: 0,
                    started_at_ms: 0,
                    job_timeout_ms: 60000,
                    progress_every_units: 10,
                    progress_every_ms: 500,
                    last_progress_ms: 0,
                    dropped_events: 0,
                }),
                finished: Mutex::new(true),
                condvar: Condvar::new(),
                emit_events: false,
                host_ctx: build_test_ctx().clone(),
                terminal_notified: std::sync::atomic::AtomicBool::new(true),
            });
            REGISTRY
                .jobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(job_id.to_string(), handle.clone());
            handle
        };
        let job_a = mk("task-aaa", JobPhase::Completed);
        let job_b = mk("task-bbb", JobPhase::Completed);

        // 事件属于 B → 归账 B（旧实现会记到迭代序第一个 = A）
        let ev = serde_json::json!({ "jobId": "task-bbb", "phase": "progress" });
        let found = job_for_drop_counting("drop-probe", &ev).expect("必须命中 B");
        assert_eq!(
            found.inner.lock().unwrap_or_else(|e| e.into_inner()).owner,
            "drop-probe"
        );
        // 直接走计数语义：给 B 记一笔
        let b = job_for_drop_counting("drop-probe", &ev).unwrap();
        b.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dropped_events += 1;
        assert_eq!(
            job_a
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .dropped_events,
            0,
            "A 不得被错记"
        );
        assert_eq!(
            job_b
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .dropped_events,
            1
        );

        // 未知 jobId / 无 jobId / 非属主 → None（不归账）
        assert!(
            job_for_drop_counting("drop-probe", &serde_json::json!({ "jobId": "task-zzz" }))
                .is_none()
        );
        assert!(
            job_for_drop_counting("drop-probe", &serde_json::json!({ "phase": "progress" }))
                .is_none()
        );
        assert!(job_for_drop_counting("other-owner", &ev).is_none());
        purge_for_plugin("drop-probe");
    }

    #[test]
    fn parse_plan_rejects_too_many_units() {
        let units: Vec<serde_json::Value> = (0..(C::PLUGIN_TASK_MAX_UNITS_PER_PLAN + 1))
            .map(|i| serde_json::json!({ "id": format!("u{}", i), "kind": "fs.stat", "params": { "path": "/tmp/a" } }))
            .collect();
        let plan = serde_json::json!({ "units": units }).to_string();
        let e = parse_plan(&plan).unwrap_err();
        assert!(e.contains("exceeds max units"));
    }

    #[test]
    fn parse_plan_accepts_camel_case_fields() {
        let plan = parse_plan(
            r#"{"units":[{"id":"u1","kind":"fs.stat","params":{"path":"/tmp/a"}}],"maxConcurrency":2,"jobTimeoutMs":5000}"#,
        )
        .unwrap();
        assert_eq!(plan.units.len(), 1);
        assert_eq!(plan.max_concurrency, Some(2));
        assert_eq!(plan.job_timeout_ms, Some(5000));
    }

    #[test]
    fn parse_plan_rejects_zero_max_concurrency() {
        let e = parse_plan(
            r#"{"units":[{"id":"u1","kind":"fs.stat","params":{}}],"maxConcurrency":0}"#,
        )
        .unwrap_err();
        assert!(e.contains("maxConcurrency"));
    }

    #[test]
    fn metrics_snapshot_shape_is_stable() {
        // 快照形状（camelCase 键）锚定，防监控消费方（诊断页 / CLI）断档
        let snap = task_metrics_snapshot();
        for key in [
            "jobsSubmittedTotal",
            "jobsActive",
            "jobsRejectedTotal",
            "unitsCompletedTotal",
            "concurrentUnitsPeak",
            "eventsDroppedTotal",
            "poolThreads",
        ] {
            assert!(snap.get(key).is_some(), "task 指标缺 {key}");
        }
        assert_eq!(
            snap["poolThreads"],
            C::PLUGIN_TASK_POOL_THREADS,
            "池线程数与常量一致"
        );
    }

    #[test]
    fn unit_metrics_peak_monotonic_and_rebalanced() {
        // 并发计数成对：started 后 current=1、peak≥1；完成（fetch_sub）归位后
        // 不影响累计指标（unitsCompletedTotal 单调增）
        TASK_METRICS
            .units_completed_total
            .store(0, Ordering::Relaxed);
        unit_started();
        let after_start = TASK_METRICS
            .concurrent_units_current
            .load(Ordering::Relaxed);
        assert_eq!(after_start, 1, "开始后当前并发 = 1");
        TASK_METRICS
            .concurrent_units_current
            .fetch_sub(1, Ordering::Relaxed);
        assert_eq!(
            TASK_METRICS
                .concurrent_units_current
                .load(Ordering::Relaxed),
            0,
            "完成归位"
        );
        assert!(
            TASK_METRICS.concurrent_units_peak.load(Ordering::Relaxed) >= 1,
            "peak 高水位不为 0"
        );
        assert_eq!(
            TASK_METRICS.units_completed_total.load(Ordering::Relaxed),
            0,
            "累计由 run_unit 负责"
        );
    }

    #[test]
    fn register_job_lazy_gc_frees_terminal_jobs() {
        // submit 终态后占在册配额是 bug：惰性 GC 在下一次提交时移除本插件终态任务。
        // 直接验证 retain 语义（不依赖真实 submit 的异步终态时序）：
        // 构造一个终态 + 一个 running 的同属主任务，retain 后只剩 running。
        let job_terminal = Arc::new(JobHandle {
            inner: Mutex::new(JobInner {
                owner: "gc-test".to_string(),
                units: vec![PlanUnit {
                    id: "u".to_string(),
                    kind: "fs.stat".to_string(),
                    params: serde_json::json!({}),
                }],
                phase: JobPhase::Completed,
                results: vec![None; 1],
                remaining: 0,
                next_to_start: 1,
                done: 1,
                failed: 0,
                created_at_ms: 0,
                started_at_ms: 0,
                job_timeout_ms: 60000,
                progress_every_units: 10,
                progress_every_ms: 500,
                last_progress_ms: 0,
                dropped_events: 0,
            }),
            finished: Mutex::new(true),
            condvar: Condvar::new(),
            emit_events: true,
            host_ctx: build_test_ctx().clone(),
            terminal_notified: std::sync::atomic::AtomicBool::new(true),
        });
        let job_running = Arc::new(JobHandle {
            inner: Mutex::new(JobInner {
                owner: "gc-test".to_string(),
                units: vec![PlanUnit {
                    id: "u".to_string(),
                    kind: "fs.stat".to_string(),
                    params: serde_json::json!({}),
                }],
                phase: JobPhase::Running,
                results: vec![None; 1],
                remaining: 1,
                next_to_start: 0,
                done: 0,
                failed: 0,
                created_at_ms: 0,
                started_at_ms: 0,
                job_timeout_ms: 60000,
                progress_every_units: 10,
                progress_every_ms: 500,
                last_progress_ms: 0,
                dropped_events: 0,
            }),
            finished: Mutex::new(false),
            condvar: Condvar::new(),
            emit_events: true,
            host_ctx: build_test_ctx().clone(),
            terminal_notified: std::sync::atomic::AtomicBool::new(false),
        });
        {
            let mut jobs = REGISTRY.jobs.lock().unwrap_or_else(|e| e.into_inner());
            // 只操作本测试插入的条目，不依赖全局 REGISTRY 为空（其他测试如 task_e2e
            // 会经 register_job 残留真实 job）——断言只数本属主，清理只删自己的。
            let before_others = jobs.values().filter(|h| h.owner() != "gc-test").count();
            jobs.insert("task-gc-a".to_string(), job_terminal);
            jobs.insert("task-gc-b".to_string(), job_running);
            // 惰性 GC 语义（register_job 中的 retain 谓词）
            jobs.retain(|_, h| h.owner() != "gc-test" || h.phase() == JobPhase::Running);
            let gc_remaining = jobs.values().filter(|h| h.owner() == "gc-test").count();
            assert_eq!(gc_remaining, 1, "终态任务被 GC，running 保留");
            assert!(jobs.contains_key("task-gc-b"));
            assert_eq!(jobs.len(), before_others + 1, "不得影响其他属主 job");
            jobs.remove("task-gc-a");
            jobs.remove("task-gc-b");
        }
    }

    /// 测试构造 helper：无头 WasmHostContext（与 `host_api::tests` 同源）
    fn build_test_ctx() -> Arc<WasmHostContext> {
        crate::host_api::tests::build_host_ctx()
    }

    #[test]
    fn next_job_id_is_unique_and_prefixed() {
        let r = TaskRegistry {
            jobs: Mutex::new(HashMap::new()),
            queues: Mutex::new(HashMap::new()),
            job_seq: AtomicU64::new(0),
        };
        let a = r.next_job_id();
        let b = r.next_job_id();
        assert!(a.starts_with("task-"));
        assert_ne!(a, b);
    }
}
