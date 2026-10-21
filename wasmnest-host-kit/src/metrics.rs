//! 单插件指标值对象（机制面）：内存 / 燃料 / 调用耗时 / 生命周期 / 授权决策记账
//!
//! 与宿主 `core-monitor` 的关系：宿主保留 [`crate::metrics`] 之外的**注册表**与
//! **诊断面**（`MetricsRegistry` / `MetricsSource` / JSON 快照拼装 / `/api` 出口），
//! 本文件只保留「一个插件的原子计数器」这一层——它是
//! [`crate::state::WasmPluginState`] 的字段类型，与消费方同 crate 才有意义。
//!
//! **为什么值对象不能上移 wasm-core**（2026-10-14 复核）：它是 `WasmPluginState`
//! 的字段类型，而 state 必须住本 crate（单态 `S` 与 Cargo 环，见 crate 头注），
//! wasm-core 又依赖本 crate ⇒ 上移即硬环。把 state 字段退化为 `Arc<dyn 指标写入
//! trait>`、由 core 实现可以绕开环，但 trait 的方法集仍是同一份接口留在本 crate
//! （接口面不缩小），却给内存增长 / 调用计时等**热路径**加上动态分发与装箱——
//! 收益为零、代价在热路径，故不采用。监控的**注册表与诊断面**已在 core
//! （`monitor.rs`），本层只是它消费的值对象。
//!
//! 红线：热路径埋点为纯原子操作，零日志（日志级别语义见 AGENTS §8）；
//! 指标标签只用 `plugin_id` 等结构化维度，禁止拼消息字符串。

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// 授权决策类别（埋点维度；安全决策管线的 `AuthDecision` 映射到此）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecisionKind {
    /// 放行
    Allow,
    /// 拒绝
    Deny,
    /// 需用户确认
    RequireApproval,
}

// ==================== 生命周期事件 ====================

/// 插件生命周期事件（计数维度）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// WASM 实例创建（Store 建立完成）
    Instantiate,
    /// activate() 成功
    ActivateOk,
    /// activate() 失败（含 guest 自报失败与 trap）
    ActivateFail,
    /// deactivate() 成功
    Deactivate,
    /// 导出调用 trap（panic/栈溢出/燃料耗尽/内存越界）
    Trap,
    /// 插件被标记为 Degraded（带病运行）
    Degraded,
}

impl LifecycleEvent {
    /// 数组索引（事件计数存储为定长数组，避免 map 开销）
    fn idx(self) -> usize {
        match self {
            Self::Instantiate => 0,
            Self::ActivateOk => 1,
            Self::ActivateFail => 2,
            Self::Deactivate => 3,
            Self::Trap => 4,
            Self::Degraded => 5,
        }
    }

    /// 快照导出的稳定键名（JSON 字段，面向诊断消费方）
    fn key(self) -> &'static str {
        match self {
            Self::Instantiate => "instantiate",
            Self::ActivateOk => "activate_ok",
            Self::ActivateFail => "activate_fail",
            Self::Deactivate => "deactivate",
            Self::Trap => "trap",
            Self::Degraded => "degraded",
        }
    }

    const ALL: [Self; 6] = [
        Self::Instantiate,
        Self::ActivateOk,
        Self::ActivateFail,
        Self::Deactivate,
        Self::Trap,
        Self::Degraded,
    ];
}

// ==================== trap 原因 ====================

/// trap 原因（诊断维度；由宿主按 wasmtime 错误全链文本分类）
///
/// 与 [`LifecycleEvent::Trap`] 的关系：后者只记「发生了 trap」的总数，
/// 本枚举把总数拆成可行动的类别——死循环（燃料耗尽）/ 递归过深（栈溢出）/
/// 越界访问 / 显式 panic（unreachable）/ 宿主调用失败 / 其他。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapKind {
    /// 燃料耗尽（guest 死循环或单次计算量超预算）
    FuelExhausted,
    /// wasm 栈溢出（深递归）
    StackOverflow,
    /// 线性内存越界
    MemoryOutOfBounds,
    /// `unreachable` 指令（Rust panic / 显式 trap）
    Unreachable,
    /// 宿主函数返回错误穿过 wasm 边界
    HostError,
    /// 其他（无法分类时保留原始日志，不丢事件）
    Other,
}

impl TrapKind {
    fn idx(self) -> usize {
        match self {
            Self::FuelExhausted => 0,
            Self::StackOverflow => 1,
            Self::MemoryOutOfBounds => 2,
            Self::Unreachable => 3,
            Self::HostError => 4,
            Self::Other => 5,
        }
    }

    /// 快照导出的稳定键名
    fn key(self) -> &'static str {
        match self {
            Self::FuelExhausted => "fuel_exhausted",
            Self::StackOverflow => "stack_overflow",
            Self::MemoryOutOfBounds => "memory_out_of_bounds",
            Self::Unreachable => "unreachable",
            Self::HostError => "host_error",
            Self::Other => "other",
        }
    }

    const ALL: [Self; 6] = [
        Self::FuelExhausted,
        Self::StackOverflow,
        Self::MemoryOutOfBounds,
        Self::Unreachable,
        Self::HostError,
        Self::Other,
    ];

    /// 从 wasmtime 错误全链文本分类（`{:#}` 含 `Caused by:`，只打 Display 会丢原因）
    ///
    /// 大小写不敏感子串匹配：wasmtime 文案随版本微调，分类失败一律落 `Other`
    /// （不丢事件；原始文本仍由宿主 `trap_detail` 日志保全）。
    pub fn classify(message: &str) -> Self {
        let m = message.to_ascii_lowercase();
        if m.contains("all fuel consumed") || m.contains("out of fuel") {
            Self::FuelExhausted
        } else if m.contains("call stack exhausted") || m.contains("stack overflow") {
            Self::StackOverflow
        } else if m.contains("out of bounds memory access")
            || m.contains("memory out of bounds")
            || m.contains("out of bounds")
        {
            Self::MemoryOutOfBounds
        } else if m.contains("unreachable") {
            Self::Unreachable
        } else if m.contains("host function") || m.contains("host call") {
            Self::HostError
        } else {
            Self::Other
        }
    }
}

// ==================== 耗时直方图 ====================

/// 直方图桶上界（微秒）：1ms / 10ms / 100ms / 1s / 10s / +Inf
///
/// 覆盖插件调用的典型分布：存储读写 ~ms 内，HTTP/进程调用可至秒级；
/// 桶界为 10 的幂，诊断时肉眼可读
const DURATION_BUCKET_BOUNDS_US: [u64; 5] = [1_000, 10_000, 100_000, 1_000_000, 10_000_000];
const DURATION_BUCKET_COUNT: usize = DURATION_BUCKET_BOUNDS_US.len() + 1;

// ==================== 插件维度指标 ====================

/// 单插件指标集（全原子字段，埋点热路径零分配零锁）
pub struct PluginMetrics {
    /// 线性内存当前值（字节，ResourceLimiter 增长回调记账）
    memory_current_bytes: AtomicU64,
    /// 线性内存峰值（字节）
    memory_peak_bytes: AtomicU64,
    /// 导出调用总次数
    calls_total: AtomicU64,
    /// 当前在飞（已开始未结束）的导出调用数
    calls_in_flight: AtomicU64,
    /// 燃料消耗总量（指令数；口径：两次燃料注入之间的消耗，首次含实例化与 ABI 协商）
    fuel_consumed_total: AtomicU64,
    /// 导出调用耗时总量（微秒）
    call_duration_us_total: AtomicU64,
    /// 导出调用单次耗时最大值（微秒）
    call_duration_us_max: AtomicU64,
    /// 耗时直方图：桶计数（桶界见 [`DURATION_BUCKET_BOUNDS_US`]）
    call_duration_buckets: [AtomicU64; DURATION_BUCKET_COUNT],
    /// 生命周期事件计数（按 [`LifecycleEvent::idx`] 索引）
    lifecycle_counts: [AtomicU64; 6],
    /// 生命周期事件最近发生时间（unix 秒）
    lifecycle_last_unix: [AtomicU64; 6],
    /// trap 原因计数（按 [`TrapKind::idx`] 索引）
    trap_counts: [AtomicU64; 6],
    /// 线性内存增长被 ResourceLimiter 拒绝的次数（触及 256 MiB 上限的健康信号）
    memory_grow_denied_total: AtomicU64,
    /// 表增长被 ResourceLimiter 拒绝的次数
    table_grow_denied_total: AtomicU64,
    /// activate() 累计耗时（微秒；与 it 调用聚合分开，便于看启动成本）
    activation_us_total: AtomicU64,
    /// activate() 单次最大耗时（微秒）
    activation_us_max: AtomicU64,
    /// 授权决策计数（按 [`AuthzDecisionKind`] 索引：allow/deny/require_approval）
    authz_decisions: [AtomicU64; 3],
    /// 授权记录落账被容量上限丢弃的计数（安全账本封顶，非决策计数）
    authz_records_dropped_total: AtomicU64,
    /// 消息总线丢弃计数：订阅者队列满时丢弃（背压保护）
    bus_dropped_total: AtomicU64,
    /// 消息总线格式不匹配拒绝计数（订阅方格式偏好与消息格式不符）
    bus_format_rejected_total: AtomicU64,
    /// 配额上限快照（实例化时由 [`crate::limits::StoreLimits`] 写入一次）：
    /// 燃料预算 / 内存上限 / 表元素上限 / 实例数 / 内存数 / 表数
    quota_fuel_per_call: AtomicU64,
    quota_memory_bytes: AtomicU64,
    quota_table_entries: AtomicU64,
    quota_instances: AtomicU64,
    quota_memories: AtomicU64,
    quota_tables: AtomicU64,
}

impl Default for PluginMetrics {
    fn default() -> Self {
        Self {
            memory_current_bytes: AtomicU64::new(0),
            memory_peak_bytes: AtomicU64::new(0),
            calls_total: AtomicU64::new(0),
            calls_in_flight: AtomicU64::new(0),
            fuel_consumed_total: AtomicU64::new(0),
            call_duration_us_total: AtomicU64::new(0),
            call_duration_us_max: AtomicU64::new(0),
            call_duration_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            lifecycle_counts: std::array::from_fn(|_| AtomicU64::new(0)),
            lifecycle_last_unix: std::array::from_fn(|_| AtomicU64::new(0)),
            trap_counts: std::array::from_fn(|_| AtomicU64::new(0)),
            memory_grow_denied_total: AtomicU64::new(0),
            table_grow_denied_total: AtomicU64::new(0),
            activation_us_total: AtomicU64::new(0),
            activation_us_max: AtomicU64::new(0),
            authz_decisions: std::array::from_fn(|_| AtomicU64::new(0)),
            authz_records_dropped_total: AtomicU64::new(0),
            bus_dropped_total: AtomicU64::new(0),
            bus_format_rejected_total: AtomicU64::new(0),
            quota_fuel_per_call: AtomicU64::new(0),
            quota_memory_bytes: AtomicU64::new(0),
            quota_table_entries: AtomicU64::new(0),
            quota_instances: AtomicU64::new(0),
            quota_memories: AtomicU64::new(0),
            quota_tables: AtomicU64::new(0),
        }
    }
}

impl PluginMetrics {
    /// 内存增长记账（limiter 批准路径调用）：current = desired，峰值取大
    ///
    /// current 与 peak 用同序（SeqCst，R-16）：Relaxed 下较晚提交的较小
    /// current 可被观测先于较早的较大值（重排），出现 current < peak 而真实
    /// 分配其实回落的矛盾读数；同序后一次快照内两指标自洽（last-writer 语义
    /// 下的瞬时一致性）。
    pub fn record_memory_growth(&self, desired: usize) {
        let desired = desired as u64;
        self.memory_current_bytes.store(desired, Ordering::SeqCst);
        self.memory_peak_bytes.fetch_max(desired, Ordering::SeqCst);
    }

    /// 燃料消耗记账（exports() 续费前调用：consumed = 预算 - 剩余）
    pub fn record_fuel_consumed(&self, consumed: u64) {
        self.fuel_consumed_total
            .fetch_add(consumed, Ordering::Relaxed);
    }

    /// 写入配额上限快照（实例化时一次；纯原子写，不参与热路径）
    ///
    /// 监控页据此算「内存使用率 / 燃料预算使用率」——只下发上限与当前值，
    /// 不在宿主侧算业务阈值（阈值是应用的产品策略）。
    pub fn set_limits(&self, limits: &crate::limits::StoreLimits) {
        self.quota_fuel_per_call
            .store(limits.fuel_per_call, Ordering::Relaxed);
        self.quota_memory_bytes
            .store(limits.max_memory_bytes as u64, Ordering::Relaxed);
        self.quota_table_entries
            .store(limits.max_table_entries as u64, Ordering::Relaxed);
        self.quota_instances
            .store(limits.max_instances as u64, Ordering::Relaxed);
        self.quota_memories
            .store(limits.max_memories as u64, Ordering::Relaxed);
        self.quota_tables
            .store(limits.max_tables as u64, Ordering::Relaxed);
    }

    /// 一次导出调用计时开始（RAII：drop 时记录耗时并计数）
    ///
    /// 计时器持有 `Arc<Self>`（owning），不借用调用方上下文——
    /// 插件方法拿到计时器后还需 `&mut self` 驱动导出调用
    pub fn start_call(self: &Arc<Self>) -> CallTimer {
        // 在飞计数在起点 +1、终点 -1（`record_call_duration`）——
        // 监控页用它区分「正常运行」与「卡在长调用里」
        self.calls_in_flight.fetch_add(1, Ordering::Relaxed);
        CallTimer {
            metrics: self.clone(),
            start: Instant::now(),
        }
    }

    /// 记账一次导出调用耗时（内部由 [`CallTimer`] 的 `Drop` 驱动）
    ///
    /// **可见性说明**：`pub` 而非私有，因为埋点分桶是纯函数但只有通过真实计时
    /// 才会触发——单测要断言「1ms→桶 0 / 1ms→桶 1 / 10s→末桶」这类分桶边界而不
    /// sleep（CI 无 flake，仓库既有做法），只能直接喂入耗时值。
    pub fn record_call_duration(&self, duration_us: u64) {
        // 在飞计数回落：单测会直接调用本函数（不经 `start_call`），
        // 用 checked_sub 防下溢——否则 0-1 回卷成 u64::MAX，监控页出现不可能的读数
        let _ = self
            .calls_in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        self.calls_total.fetch_add(1, Ordering::Relaxed);
        self.call_duration_us_total
            .fetch_add(duration_us, Ordering::Relaxed);
        self.call_duration_us_max
            .fetch_max(duration_us, Ordering::Relaxed);
        let bucket = DURATION_BUCKET_BOUNDS_US
            .iter()
            .position(|&bound| duration_us < bound)
            .unwrap_or(DURATION_BUCKET_COUNT - 1);
        self.call_duration_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    /// 生命周期事件记账（计数 + 最近发生时间）
    pub fn record_lifecycle(&self, event: LifecycleEvent) {
        self.lifecycle_counts[event.idx()].fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.lifecycle_last_unix[event.idx()].store(now, Ordering::Relaxed);
    }

    /// trap 原因记账（调用级失败路径；由宿主按 wasmtime 错误文本分类）
    pub fn record_trap(&self, kind: TrapKind) {
        self.trap_counts[kind.idx()].fetch_add(1, Ordering::Relaxed);
    }

    /// 线性内存增长被 limiter 拒绝的记账（触及上限的健康信号）
    pub fn record_memory_denied(&self) {
        self.memory_grow_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 表增长被 limiter 拒绝的记账
    pub fn record_table_denied(&self) {
        self.table_grow_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// activate() 耗时记账（微秒；调用聚合之外单列，便于看启动成本）
    pub fn record_activation(&self, duration_us: u64) {
        self.activation_us_total
            .fetch_add(duration_us, Ordering::Relaxed);
        self.activation_us_max
            .fetch_max(duration_us, Ordering::Relaxed);
    }

    /// 授权决策记账（安全决策管线的唯一埋点点）
    pub fn record_authz_decision(&self, kind: AuthzDecisionKind) {
        let idx = match kind {
            AuthzDecisionKind::Allow => 0,
            AuthzDecisionKind::Deny => 1,
            AuthzDecisionKind::RequireApproval => 2,
        };
        self.authz_decisions[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// 授权记录因容量上限被丢弃的记账
    ///
    /// 与决策计数分开：丢弃是「安全闸门账本满了」，不是某次放行/拒绝判定，
    /// 混进 `authz.allow` 会让「放行次数」这个口径失真。
    pub fn record_authz_record_dropped(&self) {
        self.authz_records_dropped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 消息总线队列满丢弃记账（背压保护）
    pub fn record_bus_dropped(&self) {
        self.bus_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 消息总线格式不匹配拒绝记账
    pub fn record_bus_format_rejected(&self) {
        self.bus_format_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 取本插件的全量快照（宿主诊断面与 JSON 导出消费）
    pub fn snapshot(&self) -> PluginMetricsSnapshot {
        let mut lifecycle = HashMap::new();
        let mut lifecycle_last_unix = HashMap::new();
        for event in LifecycleEvent::ALL {
            let count = self.lifecycle_counts[event.idx()].load(Ordering::Relaxed);
            lifecycle.insert(event.key().to_string(), count);
            let last = self.lifecycle_last_unix[event.idx()].load(Ordering::Relaxed);
            if last > 0 {
                lifecycle_last_unix.insert(event.key().to_string(), last);
            }
        }
        let mut trap_reasons = HashMap::new();
        for kind in TrapKind::ALL {
            trap_reasons.insert(
                kind.key().to_string(),
                self.trap_counts[kind.idx()].load(Ordering::Relaxed),
            );
        }
        PluginMetricsSnapshot {
            memory_current_bytes: self.memory_current_bytes.load(Ordering::SeqCst),
            memory_peak_bytes: self.memory_peak_bytes.load(Ordering::SeqCst),
            calls_total: self.calls_total.load(Ordering::Relaxed),
            calls_in_flight: self.calls_in_flight.load(Ordering::Relaxed),
            fuel_consumed_total: self.fuel_consumed_total.load(Ordering::Relaxed),
            call_duration_us_total: self.call_duration_us_total.load(Ordering::Relaxed),
            call_duration_us_max: self.call_duration_us_max.load(Ordering::Relaxed),
            call_duration_buckets: self
                .call_duration_buckets
                .iter()
                .map(|b| b.load(Ordering::Relaxed))
                .collect(),
            lifecycle,
            lifecycle_last_unix,
            trap_reasons,
            memory_grow_denied_total: self
                .memory_grow_denied_total
                .load(Ordering::Relaxed),
            table_grow_denied_total: self.table_grow_denied_total.load(Ordering::Relaxed),
            activation_us_total: self.activation_us_total.load(Ordering::Relaxed),
            activation_us_max: self.activation_us_max.load(Ordering::Relaxed),
            quota: HashMap::from([
                (
                    "fuel_per_call".to_string(),
                    self.quota_fuel_per_call.load(Ordering::Relaxed),
                ),
                (
                    "memory_bytes".to_string(),
                    self.quota_memory_bytes.load(Ordering::Relaxed),
                ),
                (
                    "table_entries".to_string(),
                    self.quota_table_entries.load(Ordering::Relaxed),
                ),
                (
                    "instances".to_string(),
                    self.quota_instances.load(Ordering::Relaxed),
                ),
                (
                    "memories".to_string(),
                    self.quota_memories.load(Ordering::Relaxed),
                ),
                (
                    "tables".to_string(),
                    self.quota_tables.load(Ordering::Relaxed),
                ),
            ]),
            authz: HashMap::from([
                (
                    "allow".to_string(),
                    self.authz_decisions[0].load(Ordering::Relaxed),
                ),
                (
                    "deny".to_string(),
                    self.authz_decisions[1].load(Ordering::Relaxed),
                ),
                (
                    "require_approval".to_string(),
                    self.authz_decisions[2].load(Ordering::Relaxed),
                ),
                (
                    "records_dropped".to_string(),
                    self.authz_records_dropped_total.load(Ordering::Relaxed),
                ),
            ]),
            bus: HashMap::from([
                (
                    "dropped".to_string(),
                    self.bus_dropped_total.load(Ordering::Relaxed),
                ),
                (
                    "format_rejected".to_string(),
                    self.bus_format_rejected_total.load(Ordering::Relaxed),
                ),
            ]),
        }
    }
}

/// 导出调用计时器（RAII）：drop 时把耗时记入指标
pub struct CallTimer {
    metrics: Arc<PluginMetrics>,
    start: Instant,
}

impl Drop for CallTimer {
    fn drop(&mut self) {
        self.metrics
            .record_call_duration(self.start.elapsed().as_micros() as u64);
    }
}

/// 单插件指标快照（serde 字段名即对外契约，保持稳定）
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PluginMetricsSnapshot {
    /// 线性内存当前值（字节）
    pub memory_current_bytes: u64,
    /// 线性内存峰值（字节）
    pub memory_peak_bytes: u64,
    /// 导出调用总次数
    pub calls_total: u64,
    /// 当前在飞（已开始未结束）的导出调用数
    pub calls_in_flight: u64,
    /// 燃料消耗总量（指令数）
    pub fuel_consumed_total: u64,
    /// 导出调用耗时总量（微秒）
    pub call_duration_us_total: u64,
    /// 导出调用单次耗时最大值（微秒）
    pub call_duration_us_max: u64,
    /// 耗时直方图：长度恒为 6，桶界见 `DURATION_BUCKET_BOUNDS_US`
    pub call_duration_buckets: Vec<u64>,
    /// 生命周期事件计数（key 见 [`LifecycleEvent::key`]）
    pub lifecycle: HashMap<String, u64>,
    /// 生命周期事件最近发生时间 unix 秒（仅发生过的事件出现）
    pub lifecycle_last_unix: HashMap<String, u64>,
    /// trap 原因计数（key 见 [`TrapKind::key`]）
    pub trap_reasons: HashMap<String, u64>,
    /// 线性内存增长被 limiter 拒绝的次数
    pub memory_grow_denied_total: u64,
    /// 表增长被 limiter 拒绝的次数
    pub table_grow_denied_total: u64,
    /// activate() 累计耗时（微秒）
    pub activation_us_total: u64,
    /// activate() 单次最大耗时（微秒）
    pub activation_us_max: u64,
    /// 配额上限（实例化时写入；key 见 `set_limits`）
    pub quota: HashMap<String, u64>,
    /// 授权决策计数（allow / deny / require_approval）
    pub authz: HashMap<String, u64>,
    /// 消息总线指标：dropped = 队列满丢弃；format_rejected = 格式不匹配拒绝
    pub bus: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::StoreLimits;

    /// 六类 trap 文案映射：classify 是监控页「Trap 原因」分布的唯一入口，
    /// 任何一类落错桶都会让死循环 / 递归过深 / 越界无从区分。
    #[test]
    fn trap_kind_classifies_known_wasmtime_messages() {
        let cases = [
            (
                "wasm trap: all fuel consumed by WebAssembly",
                TrapKind::FuelExhausted,
            ),
            ("wasm trap: OUT OF FUEL", TrapKind::FuelExhausted),
            ("wasm trap: call stack exhausted", TrapKind::StackOverflow),
            (
                "wasm trap: out of bounds memory access",
                TrapKind::MemoryOutOfBounds,
            ),
            (
                "wasm trap: wasm `unreachable` instruction executed",
                TrapKind::Unreachable,
            ),
            (
                "host function `host-net` returned an error",
                TrapKind::HostError,
            ),
            ("wasm trap: unknown failure", TrapKind::Other),
        ];
        for (message, expected) in cases {
            assert_eq!(TrapKind::classify(message), expected, "message: {message}");
        }
    }

    /// 在飞计数：start_call +1，计时器 drop 时 -1；总调用数只由 drop 落账
    #[test]
    fn calls_in_flight_tracks_call_timer_lifecycle() {
        let metrics = Arc::new(PluginMetrics::default());
        let first = metrics.start_call();
        assert_eq!(metrics.snapshot().calls_in_flight, 1);
        let second = metrics.start_call();
        assert_eq!(metrics.snapshot().calls_in_flight, 2);

        drop(first);
        assert_eq!(metrics.snapshot().calls_in_flight, 1);
        drop(second);

        let snap = metrics.snapshot();
        assert_eq!(snap.calls_in_flight, 0, "全部计时器 drop 后在飞必须归零");
        assert_eq!(snap.calls_total, 2);
    }

    /// 直接喂耗时（单测分桶路径）不得把在飞计数减到 u64::MAX
    #[test]
    fn record_call_duration_without_in_flight_saturates_at_zero() {
        let metrics = PluginMetrics::default();
        metrics.record_call_duration(42);

        let snap = metrics.snapshot();
        assert_eq!(snap.calls_in_flight, 0);
        assert_eq!(snap.calls_total, 1);
        assert_eq!(snap.call_duration_us_total, 42);
    }

    /// 配额上限六字段逐一写入快照（上限不是实时占用，但必须完整）
    #[test]
    fn set_limits_snapshots_all_quota_fields() {
        let limits = StoreLimits {
            fuel_per_call: 11,
            max_memory_bytes: 22,
            max_table_entries: 33,
            max_instances: 44,
            max_memories: 55,
            max_tables: 66,
            ..StoreLimits::default()
        };
        let metrics = PluginMetrics::default();
        metrics.set_limits(&limits);

        let quota = metrics.snapshot().quota;
        assert_eq!(quota["fuel_per_call"], 11);
        assert_eq!(quota["memory_bytes"], 22);
        assert_eq!(quota["table_entries"], 33);
        assert_eq!(quota["instances"], 44);
        assert_eq!(quota["memories"], 55);
        assert_eq!(quota["tables"], 66);
    }

    /// 激活耗时累计 / 峰值与 grow 拒绝计数各自独立落账
    #[test]
    fn activation_and_grow_denied_counters_are_independent() {
        let metrics = PluginMetrics::default();
        metrics.record_activation(100);
        metrics.record_activation(250);
        metrics.record_memory_denied();
        metrics.record_memory_denied();
        metrics.record_table_denied();

        let snap = metrics.snapshot();
        assert_eq!(snap.activation_us_total, 350);
        assert_eq!(snap.activation_us_max, 250);
        assert_eq!(snap.memory_grow_denied_total, 2);
        assert_eq!(snap.table_grow_denied_total, 1);
    }

    /// trap 原因分布六桶齐全且互不串位（快照消费方按 key 取值）
    #[test]
    fn snapshot_exposes_all_trap_reason_buckets() {
        let metrics = PluginMetrics::default();
        for kind in TrapKind::ALL {
            metrics.record_trap(kind);
        }

        let reasons = metrics.snapshot().trap_reasons;
        assert_eq!(reasons.len(), 6);
        for kind in TrapKind::ALL {
            assert_eq!(reasons[kind.key()], 1, "trap 桶 {} 计数错误", kind.key());
        }
    }
}
