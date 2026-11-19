//! 采集会话编排（句柄表 / 状态机 / 配额 / 属主隔离 / 实时线程纪律）
//!
//! ## 分层
//!
//! ```text
//!   AudioHub      会话表 + 配额表 + 属主校验（本文件，纯机制，零宿主类型）
//!     └ Session   一路采集：后端流句柄 + 运行态（归一器 / 帧环 / 电平计 / 计数）
//!         └ StreamSink  后端采集线程的唯一入口（实现 CaptureSink）
//! ```
//!
//! 引擎面**不读权限、不发事件、不起异步任务**——那些是宿主能力，经 `plugin_binding::ports`
//! 注入。本文件因此能在无宿主、无硬件的进程里被完整测试（配 `test_util::ScriptedBackend`）。
//!
//! ## 两把锁与锁序（改动前必读）
//!
//! 一路会话有两个互斥域：
//!
//! - `runtime`：状态机 + 归一器 + 帧环 + 电平计 + 计数——**采集线程每次回调都要拿它**。
//! - `stream`：后端流对象本身（`start` / `stop` 需要 `&mut`，`close` 需要 Drop）。
//!
//! **唯一合法顺序是 `stream` → `runtime`**：状态迁移先锁 `stream` 做串行化，再在其内取
//! `runtime` 读写状态；采集侧只取 `runtime`，**绝不**回调后端。于是：
//!
//! 1. 采集回调被 `start` / `stop` 持锁影响的窗口只有一次状态读写，不是整次后端调用；
//! 2. **绝不在持有 `runtime` 锁时 Drop 后端流**——cpal 的 `Stream::drop` 会等采集回调返回，
//!    而回调可能正等这把锁 ⇒ 死锁。`close` / `purge` 一律「先从 stream 槽取出、释放槽
//!    锁、再 Drop」。
//!
//! 状态迁移用 `stream` 锁串行化（而不是第三个标志位）：两条并发的 `start` 若都放行，
//! 后端会被 `start()` 两次，其语义取决于驱动，不可接受。
//!
//! ## 状态机
//!
//! ```text
//!   open ──▶ Idle ──start──▶ Running ──stop──▶ Stopped ──start──▶ Running
//!                              │                                    │
//!                              └────── 后端上报 terminated ─────────┘
//!                                              ▼
//!                                   Terminated ──start──▶ InvalidState（必须重开）
//!                                              └──stop──▶ Ok（幂等：已不再采集）
//! ```
//!
//! `stop` 只停采集、**保留句柄与历史**（插件可继续 `ring-fetch` 收尾）；`close` 才摘句柄。
//! `start` 复位重采样相位与电平窗口（续采一段音频不该带着上一段的滤波器历史），但
//! **不复位帧环偏移**——消费者游标对「停—起」完全无感。

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;

use crate::backend::{
    CaptureBackend, CaptureSink, CaptureStream, DeviceId, DeviceInfo, OpenRequest,
    TerminationReason,
};
use crate::error::AudioError;
use crate::format::{PcmBuffer, PcmFormat, PcmNormalizer, TargetFormat};
use crate::level::{LevelMeter, LevelSnapshot};
use crate::ring::{FrameRing, RingFetch};

/// 句柄前缀再导出（真源在 [`crate::wire`]，与桌面 SDK 权限 / 句柄词汇同层）
///
/// 前缀是**契约面**：宿主侧日志与本域 `FromStr` 校验都按它辨认，改名即破坏性变更。
pub use crate::wire::HANDLE_PREFIX;

/// 一路采集流的句柄（本域内唯一、不透明、跨重启不保证稳定）
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamHandle(String);

impl StreamHandle {
    /// 生成新句柄（`audio-` + UUIDv4）
    pub fn generate() -> Self {
        Self(format!("{HANDLE_PREFIX}{}", uuid::Uuid::new_v4()))
    }

    /// 借出原文
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StreamHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for StreamHandle {
    type Err = AudioError;

    /// 解析调用方传来的句柄
    ///
    /// 只判「形状对不对」，不判「存不存在」——后者要查表，属主校验也在表里一起做。
    /// 拒空 id 段与含分隔符的值：句柄会被拼进日志，不能让调用方塞进任意文本。
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(rest) = value.strip_prefix(HANDLE_PREFIX) else {
            return Err(AudioError::InvalidConfig {
                reason: format!("audio handle must start with `{HANDLE_PREFIX}`: `{value}`"),
            });
        };
        if rest.is_empty()
            || rest
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        {
            return Err(AudioError::InvalidConfig {
                reason: format!("audio handle `{value}` has an empty or non-token id part"),
            });
        }
        Ok(Self(value.to_string()))
    }
}

/// 会话配额与窗口参数（宿主事实的引擎侧快照，构造 [`AudioHub`] 时定死）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioLimits {
    /// 每插件默认在册流上限（manifest 未声明 `audioQuota` 时生效）
    pub max_sessions_per_owner: usize,
    /// 每插件可声明的上限天花板（超出即拒绝登记，**不夹取**）
    pub max_sessions_ceiling_per_owner: usize,
    /// 默认帧环字节容量
    pub default_ring_bytes: usize,
    /// 帧环字节容量天花板
    pub max_ring_bytes: usize,
    /// 单次 `ring-fetch` 字节上限（约束一次 wasm 边界拷贝量）
    pub max_fetch_bytes: usize,
    /// 电平统计窗口时长（毫秒）
    pub meter_window_ms: u32,
}

impl Default for AudioLimits {
    fn default() -> Self {
        Self {
            // 一路给用户说话、一路留给后台转写，再多就是产品编排问题（会话复用），
            // 不是采集机制问题；天花板留 4 倍余量给显式声明的插件。
            max_sessions_per_owner: 2,
            max_sessions_ceiling_per_owner: 8,
            // 16k 单声道 S16 = 32 KiB/秒 ⇒ 512 KiB ≈ 16 秒历史，够慢消费者兜底一轮重连
            default_ring_bytes: 512 * 1024,
            // 8 MiB ≈ 4 分钟；再大的缓冲属于「落盘」问题域，不该由内存环承担
            max_ring_bytes: 8 * 1024 * 1024,
            max_fetch_bytes: 256 * 1024,
            // 20 ms 是语音帧的通行长度，也与 ASR 前端的典型步长对齐
            meter_window_ms: 20,
        }
    }
}

/// `open` 的调用方意图（未校验；字段全可缺省）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenParams {
    /// 指定设备 id 原文；`None` = 系统默认输入设备
    pub device: Option<String>,
    /// 目标采样率；与 `target_channels` 同时缺省 ⇒ 用 [`TargetFormat::default()`]
    pub target_sample_rate: Option<u32>,
    /// 目标声道数
    pub target_channels: Option<u16>,
    /// 帧环字节容量
    pub ring_bytes: Option<usize>,
}

/// 校验后的打开决议（[`OpenParams::resolve`] 的产物）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOpen {
    /// 目标设备
    pub device: Option<DeviceId>,
    /// 目标产出格式（已校验）
    pub target: TargetFormat,
    /// 生效的帧环容量（字节）
    pub ring_bytes: usize,
}

impl OpenParams {
    /// 按引擎限额校验并补齐缺省
    ///
    /// **只补「没填」，不修「填错」**：越界的采样率 / 声道数 / 环容量一律显性失败
    /// （AGENTS §6.6 不静默降级）。只填一半的目标格式是允许的：缺的那一半取默认，
    /// 因为另一半在场已经说明调用方要自定义。
    ///
    /// # Errors
    /// [`AudioError::InvalidConfig`] —— 目标格式越界，或 `ring_bytes` 为 0 / 超
    /// `limits.max_ring_bytes`。
    pub fn resolve(self, limits: &AudioLimits) -> Result<ResolvedOpen, AudioError> {
        let default_target = TargetFormat::default();
        let target = TargetFormat::new(
            self.target_sample_rate
                .unwrap_or(default_target.sample_rate),
            self.target_channels.unwrap_or(default_target.channels),
        )?;
        let ring_bytes = match self.ring_bytes {
            Some(0) => {
                return Err(AudioError::InvalidConfig {
                    reason: "ringBytes must be greater than zero".to_string(),
                })
            }
            Some(bytes) if bytes > limits.max_ring_bytes => {
                return Err(AudioError::InvalidConfig {
                    reason: format!(
                        "ringBytes {bytes} exceeds the host ceiling {}",
                        limits.max_ring_bytes
                    ),
                })
            }
            Some(bytes) => bytes,
            None => limits.default_ring_bytes,
        };
        Ok(ResolvedOpen {
            device: self.device.map(DeviceId::new),
            target,
            ring_bytes,
        })
    }
}

/// 会话状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// 已打开、未启动（可 `start` / `close`）
    Idle,
    /// 采集中
    Running,
    /// 已停止（保留句柄与历史，可 `start` / `close`）
    Stopped,
    /// 后端自行终止（原因随状态携带；只能 `close` 后重开）
    Terminated(TerminationReason),
}

impl SessionState {
    /// 状态词汇（进 `status` JSON 的 `state` 字段，稳定面）
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Terminated(_) => "terminated",
        }
    }

    /// 是否正在采集
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// 终止详情（非终止态 `None`）
    pub fn termination(&self) -> Option<&TerminationReason> {
        match self {
            Self::Terminated(reason) => Some(reason),
            _ => None,
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// 终止详情视图（`SessionStatus.termination`）
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminationView {
    /// 稳定词汇（见 [`TerminationReason::code`]）
    pub code: String,
    /// 后端原文
    pub detail: String,
    /// 是否建议调用方重新 `open`
    pub suggests_reopen: bool,
}

/// `status` 的可序列化视图（WIT 文档里那段 JSON 形状的真源）
///
/// 字段形状与 `wit/audio.wit` 的 `status` 文档注释逐字对应（camelCase）：搬运任何
/// 字段都是在改插件侧消费契约，属破坏性变更。`handle` / `ringBytes` / 三个回调计数
/// 是诊断附加项，插件可忽略。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatus {
    /// 句柄
    pub handle: String,
    /// 状态词汇（`idle` / `running` / `stopped` / `terminated`）
    pub state: String,
    /// 后端名
    pub backend: String,
    /// 目标采样率（帧环里字节的解释方式）
    pub target_sample_rate: u32,
    /// 目标声道数
    pub target_channels: u16,
    /// 后端实际使用的原生格式（`open` 时协商结果）
    pub actual_format: PcmFormat,
    /// 已累计产出的帧数（按目标格式计，每帧含全部目标声道）
    pub frames_captured: u64,
    /// 已累计产出的字节数（= 帧环产出端绝对偏移）
    pub bytes_produced: u64,
    /// 帧环实际字节容量（按帧取整后）
    pub ring_bytes: usize,
    /// 帧环当前驻留字节
    pub ring_usage_bytes: usize,
    /// 累计被淘汰（含覆盖写丢弃）的字节数
    pub ring_dropped_bytes: u64,
    /// 已累计产出的音频时长（毫秒，按目标格式换算）
    pub produced_ms: u64,
    /// 终止详情（仅终止态非 null）
    pub termination: Option<TerminationView>,
    /// 采集回调次数（写入帧环的那批）
    pub callbacks: u64,
    /// 后端错误回调次数
    pub backend_errors: u64,
    /// 非采集态收到的回调次数（> 0 说明后端没按契约在 `stop` 后停手）
    pub ignored_callbacks: u64,
}

/// 运行态（`runtime` 锁内；采集线程每次回调都进这里）
struct Runtime {
    state: SessionState,
    normalizer: PcmNormalizer,
    ring: FrameRing,
    meter: LevelMeter,
    /// 归一输出缓冲（复用，稳态零分配）
    scratch: Vec<u8>,
    callbacks: u64,
    backend_errors: u64,
    ignored_callbacks: u64,
}

/// 采集线程的数据汇（后端唯一的引擎入口）
///
/// 只持 `runtime`，不持会话：因此后端即使在句柄已被 `close` 之后投来一帧，最坏结果是
/// 写进一个没人看的环并随 `Arc` 一起回收，**不会**触及已释放的后端流。
struct StreamSink {
    runtime: Arc<Mutex<Runtime>>,
}

impl CaptureSink for StreamSink {
    fn push(&self, format: PcmFormat, buffer: &PcmBuffer<'_>) {
        // 只解一次 Deref：`MutexGuard` 的 DerefMut 是方法调用而非内建投影，
        // 直接写 `guard.a` / `&mut guard.b` 会得到两次可变借用；先落到 `&mut Runtime`
        // 之后字段借用才是编译器可分辨的互斥借用。
        let mut guard = lock(&self.runtime);
        let runtime = &mut *guard;
        if !runtime.state.is_running() {
            runtime.ignored_callbacks += 1;
            return;
        }
        runtime.scratch.clear();
        // 归一器只读借用 `buffer`（后端切片），产出写进自有 scratch：稳态零分配
        runtime
            .normalizer
            .process(format, buffer, &mut runtime.scratch);
        runtime.callbacks += 1;
        if runtime.scratch.is_empty() {
            // 无法解释的输入（畸形帧 / 空回调）：如实计数，不入环、不猜测
            return;
        }
        runtime.ring.append(&runtime.scratch);
        let channels = runtime.normalizer.target().channels;
        runtime.meter.observe(&runtime.scratch, channels);
    }

    fn terminated(&self, reason: TerminationReason) {
        // 只改状态：从后端回调线程 Drop 自己的流会自等（见模块头锁序说明）
        let mut runtime = lock(&self.runtime);
        if !matches!(runtime.state, SessionState::Terminated(_)) {
            runtime.state = SessionState::Terminated(reason);
        }
        runtime.backend_errors += 1;
    }
}

/// 一路采集会话（对外只读，写操作全走 [`AudioHub`] 的属主校验）
pub struct Session {
    handle: StreamHandle,
    owner: String,
    backend_id: String,
    target: TargetFormat,
    actual: PcmFormat,
    ring_bytes: usize,
    runtime: Arc<Mutex<Runtime>>,
    /// 后端流槽（`None` = 已释放；状态迁移以本锁串行化）
    stream: Mutex<Option<Box<dyn CaptureStream>>>,
}

impl Session {
    /// 会话句柄
    pub fn handle(&self) -> &StreamHandle {
        &self.handle
    }

    /// 属主插件 id
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// 目标产出格式
    pub fn target(&self) -> TargetFormat {
        self.target
    }

    /// 状态快照
    pub fn status(&self) -> SessionStatus {
        let runtime = lock(&self.runtime);
        let termination = runtime.state.termination().map(|reason| TerminationView {
            code: reason.code().to_string(),
            detail: reason.detail().to_string(),
            suggests_reopen: reason.suggests_reopen(),
        });
        let produced = runtime.ring.end();
        SessionStatus {
            handle: self.handle.to_string(),
            state: runtime.state.slug().to_string(),
            backend: self.backend_id.clone(),
            target_sample_rate: self.target.sample_rate,
            target_channels: self.target.channels,
            actual_format: self.actual,
            frames_captured: produced / self.target.bytes_per_frame() as u64,
            bytes_produced: produced,
            ring_bytes: self.ring_bytes,
            ring_usage_bytes: runtime.ring.usage(),
            ring_dropped_bytes: runtime.ring.dropped(),
            produced_ms: self.target.duration_ms(produced as usize),
            termination,
            callbacks: runtime.callbacks,
            backend_errors: runtime.backend_errors,
            ignored_callbacks: runtime.ignored_callbacks,
        }
    }

    /// 当前电平（`None` = 窗口里还没有任何一帧）
    pub fn level(&self) -> Option<LevelSnapshot> {
        lock(&self.runtime).meter.snapshot()
    }

    /// 按游标拉取历史
    pub fn ring_fetch(&self, from_offset: u64, max_bytes: usize) -> RingFetch {
        lock(&self.runtime).ring.fetch(from_offset, max_bytes)
    }

    /// 启动采集（`Idle` / `Stopped` ⇒ `Running`）
    ///
    /// **状态先置 `Running`，再调后端 `start`**：设备回调可能在 `play()` 返回前就投来
    /// 第一帧，若等后端返回后才改状态，那段音频会被当成「非采集态回调」丢弃并污染
    /// `ignored_callbacks`（该计数只应用来说明后端没按契约停手）。起流失败时回滚到原
    /// 状态——不得声称在采集。
    fn start(&self) -> Result<(), AudioError> {
        // `stream` 锁串行化状态迁移（锁序 stream → runtime，见模块头）
        let mut slot = lock(&self.stream);
        let state = lock(&self.runtime).state.clone();
        match state {
            SessionState::Running => {
                return Err(invalid_state(&self.handle, &state, "idle or stopped"))
            }
            // 后端流已不存在，重试 start 只会掩盖「设备没了」这个真问题
            SessionState::Terminated(_) => {
                return Err(invalid_state(
                    &self.handle,
                    &state,
                    "reopen (close this handle and open a new stream)",
                ))
            }
            SessionState::Idle | SessionState::Stopped => {}
        }
        {
            // 相位与电平窗口复位，帧环偏移**不**复位（消费者无感）；
            // 这里只短持 runtime，绝不跨后端调用持锁
            let mut runtime = lock(&self.runtime);
            runtime.normalizer.reset();
            runtime.meter.reset();
            runtime.state = SessionState::Running;
        }
        let Some(stream) = slot.as_mut() else {
            lock(&self.runtime).state = state;
            return Err(AudioError::HandleNotFound {
                id: self.handle.to_string(),
            });
        };
        if let Err(err) = stream.start() {
            // 回滚：状态必须反映「没在采集」这个事实
            lock(&self.runtime).state = state;
            return Err(err);
        }
        Ok(())
    }

    /// 停止采集（`Running` ⇒ `Stopped`；终止态幂等成功）
    fn stop(&self) -> Result<(), AudioError> {
        let mut slot = lock(&self.stream);
        let state = lock(&self.runtime).state.clone();
        match state {
            SessionState::Terminated(_) => return Ok(()), // 后置条件已成立：不再采集
            SessionState::Idle | SessionState::Stopped => {
                return Err(invalid_state(&self.handle, &state, "running"))
            }
            SessionState::Running => {}
        }
        let Some(stream) = slot.as_mut() else {
            return Err(AudioError::HandleNotFound {
                id: self.handle.to_string(),
            });
        };
        // 停手失败 = 确实还在采集：状态保持 Running（不假装已停）
        stream.stop()?;
        lock(&self.runtime).state = SessionState::Stopped;
        Ok(())
    }

    /// 关闭并释放后端资源（**不持 `runtime` 锁**地 Drop，见模块头死锁说明）
    ///
    /// 返回 `Err(StreamFailed)` 只表示后端停手失败——句柄已经从表里摘掉，调用方
    /// 不需要（也无法）重试。
    fn release(&self) -> Result<(), AudioError> {
        let stream = {
            let mut slot = lock(&self.stream);
            slot.take()
        };
        match stream {
            Some(mut stream) => {
                // 尽力停手：失败也不阻断摘句柄（资源必须由 Drop 收口）
                let stopped = stream.stop();
                drop(stream);
                let mut runtime = lock(&self.runtime);
                if matches!(runtime.state, SessionState::Running) {
                    runtime.state = SessionState::Stopped;
                }
                match stopped {
                    Ok(()) => Ok(()),
                    Err(err) => Err(AudioError::StreamFailed {
                        detail: format!(
                            "close: backend stop failed, stream released anyway: {err}"
                        ),
                    }),
                }
            }
            None => {
                // 二次释放：句柄早已消失，显性回答而不是静默 Ok
                Err(AudioError::HandleNotFound {
                    id: self.handle.to_string(),
                })
            }
        }
    }
}

/// 构造「当前状态不允许该动作」错误（不再取锁：调用方已持有状态快照）
fn invalid_state(handle: &StreamHandle, state: &SessionState, needs: &str) -> AudioError {
    AudioError::InvalidState {
        id: handle.to_string(),
        state: state.slug().to_string(),
        needs: needs.to_string(),
    }
}

/// 会话表 + 配额表（引擎的对外面；宿主适配层按 `(ports, hub, plugin_id, …)` 调用）
pub struct AudioHub {
    backend: Arc<dyn CaptureBackend>,
    limits: AudioLimits,
    sessions: Mutex<HashMap<StreamHandle, Arc<Session>>>,
    quotas: Mutex<HashMap<String, usize>>,
}

impl AudioHub {
    /// 以指定后端与限额构造
    pub fn new(backend: Arc<dyn CaptureBackend>, limits: AudioLimits) -> Self {
        Self {
            backend,
            limits,
            sessions: Mutex::new(HashMap::new()),
            quotas: Mutex::new(HashMap::new()),
        }
    }

    /// 生效限额
    pub const fn limits(&self) -> &AudioLimits {
        &self.limits
    }

    /// 后端名
    pub fn backend_id(&self) -> &str {
        self.backend.id()
    }

    /// 当前输入设备清单（直通后端）
    pub fn devices(&self) -> Result<Vec<DeviceInfo>, AudioError> {
        self.backend.input_devices()
    }

    /// 登记某插件的在册流上限（`None` = 默认档）
    ///
    /// 仲裁在此发生：0 与超天花板都**拒绝登记**，不夹取（同 host-pty 的 `ptyQuota`
    /// 口径——静默降级会让插件按自己声明的并发数规划业务、实际却少得多）。
    ///
    /// # Errors
    /// [`AudioError::InvalidConfig`] —— 声明值越界。
    pub fn set_quota(&self, owner: &str, declared: Option<usize>) -> Result<(), AudioError> {
        let effective = match declared {
            None => self.limits.max_sessions_per_owner,
            Some(0) => {
                return Err(AudioError::InvalidConfig {
                    // 文案点名越界值（与上界分支同口径）：插件作者据此一眼定位声明
                    reason: "audioQuota 0 must be greater than zero".to_string(),
                });
            }
            Some(quota) if quota > self.limits.max_sessions_ceiling_per_owner => {
                return Err(AudioError::InvalidConfig {
                    reason: format!(
                        "audioQuota {quota} exceeds the host ceiling {}",
                        self.limits.max_sessions_ceiling_per_owner
                    ),
                })
            }
            Some(quota) => quota,
        };
        lock(&self.quotas).insert(owner.to_string(), effective);
        Ok(())
    }

    /// 生效上限（未登记 ⇒ 默认档）
    pub fn quota_of(&self, owner: &str) -> usize {
        lock(&self.quotas)
            .get(owner)
            .copied()
            .unwrap_or(self.limits.max_sessions_per_owner)
    }

    /// 打开一路采集（不启动）
    ///
    /// # Errors
    /// 见 [`OpenParams::resolve`] 与 [`CaptureBackend::open`]，另有配额满
    /// [`AudioError::QuotaExceeded`]。失败时表里**不留半成品会话**。
    pub fn open(&self, owner: &str, params: OpenParams) -> Result<StreamHandle, AudioError> {
        let ResolvedOpen {
            device,
            target,
            ring_bytes,
        } = params.resolve(&self.limits)?;
        let quota = self.quota_of(owner);
        if self.sessions_of(owner).len() >= quota {
            return Err(AudioError::QuotaExceeded { limit: quota });
        }

        let frame_bytes = target.bytes_per_frame();
        let ring = FrameRing::new(ring_bytes, frame_bytes)?;
        let actual_ring_bytes = ring.capacity();
        let window_frames = target.samples_for_ms(self.limits.meter_window_ms);
        let runtime = Arc::new(Mutex::new(Runtime {
            state: SessionState::Idle,
            normalizer: PcmNormalizer::new(target),
            ring,
            meter: LevelMeter::new(window_frames),
            scratch: Vec::new(),
            callbacks: 0,
            backend_errors: 0,
            ignored_callbacks: 0,
        }));
        let sink: Arc<dyn CaptureSink> = Arc::new(StreamSink {
            runtime: Arc::clone(&runtime),
        });
        let stream = self
            .backend
            .open(&OpenRequest::new(device, target), Arc::clone(&sink))?;
        let actual = stream.format();
        let session = Arc::new(Session {
            handle: StreamHandle::generate(),
            owner: owner.to_string(),
            backend_id: self.backend.id().to_string(),
            target,
            actual,
            ring_bytes: actual_ring_bytes,
            runtime,
            stream: Mutex::new(Some(stream)),
        });
        let handle = session.handle.clone();
        lock(&self.sessions).insert(handle.clone(), session);
        tracing::debug!(
            handle = %handle,
            owner,
            backend = self.backend_id(),
            actual_format = ?actual,
            "audio: 采集流已打开"
        );
        Ok(handle)
    }

    /// 启动采集
    pub fn start(&self, owner: &str, handle: &StreamHandle) -> Result<(), AudioError> {
        self.session_of(owner, handle)?.start()
    }

    /// 停止采集（保留句柄与历史）
    pub fn stop(&self, owner: &str, handle: &StreamHandle) -> Result<(), AudioError> {
        self.session_of(owner, handle)?.stop()
    }

    /// 关闭并摘句柄
    pub fn close(&self, owner: &str, handle: &StreamHandle) -> Result<(), AudioError> {
        let session = self.session_of(owner, handle)?;
        // 先摘表再释放：并发的第二次 close 得到 HandleNotFound（而不是去操作一个
        // 正在释放中的会话），语义与「句柄消失」一致。
        lock(&self.sessions).remove(handle);
        session.release()
    }

    /// 状态快照
    pub fn status(&self, owner: &str, handle: &StreamHandle) -> Result<SessionStatus, AudioError> {
        Ok(self.session_of(owner, handle)?.status())
    }

    /// 按游标拉取历史（单次上限 = `limits.max_fetch_bytes`，超出钳到上限）
    ///
    /// `Ok(None)` = 游标**正好**在产出端且无缺口（调用方不需要做任何事）；
    /// `Ok(Some)` = 自游标起的整帧字节 + 续拉游标。
    ///
    /// 未来游标（大于产出端）返回 `Ok(Some)` 且 `data` 为空、`next_offset` 回带产出端：
    /// 调用方据此自纠，不至于拿着一个永远追不上的游标一直拿到「无新数据」。
    pub fn ring_fetch(
        &self,
        owner: &str,
        handle: &StreamHandle,
        from_offset: u64,
        max_bytes: usize,
    ) -> Result<Option<RingFetch>, AudioError> {
        let session = self.session_of(owner, handle)?;
        // 上限约束的是「一次 wasm 边界拷贝量」，不是调用方的意图 ⇒ 钳制而不是报错
        let budget = max_bytes.min(self.limits.max_fetch_bytes);
        let fetched = session.ring_fetch(from_offset, budget);
        if fetched.data.is_empty() && !fetched.truncated && fetched.next_offset == from_offset {
            return Ok(None);
        }
        Ok(Some(fetched))
    }

    /// 当前电平
    pub fn level(
        &self,
        owner: &str,
        handle: &StreamHandle,
    ) -> Result<Option<LevelSnapshot>, AudioError> {
        Ok(self.session_of(owner, handle)?.level())
    }

    /// 某插件在册句柄（排序稳定，供停用回收与测试断言）
    pub fn sessions_of(&self, owner: &str) -> Vec<StreamHandle> {
        let mut out: Vec<StreamHandle> = lock(&self.sessions)
            .iter()
            .filter(|(_, session)| session.owner == owner)
            .map(|(handle, _)| handle.clone())
            .collect();
        out.sort();
        out
    }

    /// 全进程在册流条数（生命周期审计面）
    pub fn live_count(&self) -> usize {
        lock(&self.sessions).len()
    }

    /// 回收某插件的全部会话（停用 / 卸载路径），返回回收条数
    ///
    /// 顺带摘掉该插件的配额登记：配额来自 manifest 声明，插件不在了就没有下一轮
    /// （重新装载会重新登记，缺省档兜底）。
    pub fn purge(&self, owner: &str) -> usize {
        let handles = self.sessions_of(owner);
        let mut reclaimed = 0usize;
        for handle in handles {
            // 摘表与释放在同一轮完成；快照之后被别处 close 的句柄拿不到会话 ⇒ 不计数
            let session = lock(&self.sessions).remove(&handle);
            match session {
                Some(session) => {
                    let _ = session.release();
                    reclaimed += 1;
                }
                None => tracing::debug!(handle = %handle, "audio: purge 跳过已消失的句柄"),
            }
        }
        lock(&self.quotas).remove(owner);
        reclaimed
    }

    /// 关停全量回收（宿主退出路径），返回回收条数
    pub fn close_all(&self) -> usize {
        let handles: Vec<StreamHandle> = lock(&self.sessions).keys().cloned().collect();
        let mut closed = 0usize;
        for handle in handles {
            let session = lock(&self.sessions).remove(&handle);
            if let Some(session) = session {
                let _ = session.release();
                closed += 1;
            }
        }
        closed
    }

    /// 查会话并校验属主（属主隔离红线：句柄不是你的，连「它存不存在」都不告诉你）
    ///
    /// 只克隆 `Arc`，查表锁随即释放——后续操作可能耗时（后端 `start`），不能持表锁。
    fn session_of(&self, owner: &str, handle: &StreamHandle) -> Result<Arc<Session>, AudioError> {
        let session = lock(&self.sessions).get(handle).cloned();
        match session {
            None => Err(AudioError::HandleNotFound {
                id: handle.to_string(),
            }),
            Some(session) if session.owner != owner => Err(AudioError::NotOwner {
                id: handle.to_string(),
            }),
            Some(session) => Ok(session),
        }
    }
}

/// 统一取锁：锁中毒（持锁线程 panic）不连带打断采集链路，取回内部值继续
fn lock<T>(cell: &Mutex<T>) -> MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests;
