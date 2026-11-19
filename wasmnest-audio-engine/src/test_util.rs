//! 可编排采集后端（无硬件 CI、单测与手工灌帧）
//!
//! ## 为什么需要它
//!
//! 引擎的契约（游标拉取、掉帧 `truncated`、配额、属主隔离、终止语义）全部可以在没有
//! 麦克风的进程里被完整验证——前提是采集后端**可编排**：设备清单、协商格式、起停失败、
//! 终止原因都按脚本给定，采集帧由测试直接投喂。
//!
//! 本模块因此只实现 [`CaptureBackend`] / [`CaptureStream`] / [`CaptureSink`] 三个 trait
//! 的替身，**不模拟任何真实音频行为**（不产帧、不计时、不做重采样）：
//!
//! - 设备清单：[`ScriptedBackend::new`] 由协商格式派生一台「默认输入设备」，
//!   或用 [`ScriptedBackend::with_devices`] 显式给定；[`ScriptedBackend::without_devices`]
//!   枚举返回 `NoInputDevice`（「没有输入设备」是后端故障面，不是空清单）。
//! - 起停/打开失败注入：`with_*_failure` 系列（失败路径的可执行判据，见 `engine::tests`）。
//! - 采集帧投喂：[`ScriptedBackend::push`] 把帧交给 `open` 时登记的 sink，
//!   与真实后端回调走**同一条**路径（引擎的 `CaptureSink` 实现）。
//!
//! ## 台账
//!
//! 每次 `open` / `start` / `stop` 与流对象 Drop 都进 [`ScriptedOp`] 台账（顺序可见），
//! 用于断言「close 真的释放了后端流」「release 先 stop 再 drop」这类生命周期契约。
//!
//! 线程安全：全部状态在 `Mutex` 后，后端的 `open` 只登记 sink 与台账，不持锁回调，
//! 因此测试可以从多个线程并发投喂。

use std::sync::{Arc, Mutex, MutexGuard};

use crate::backend::{
    CaptureBackend, CaptureSink, CaptureStream, DeviceInfo, OpenRequest, TerminationReason,
};
use crate::error::AudioError;
use crate::format::{PcmBuffer, PcmFormat};

/// 台账条目（按发生顺序记录）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedOp {
    /// 后端被要求打开一路流（携请求参数，便于断言设备 / 目标格式）
    Open(OpenRequest),
    /// 流对象 `start` 被调用
    Start,
    /// 流对象 `stop` 被调用
    Stop,
    /// 流对象被 Drop（后端资源的真实释放点）
    Dropped,
}

/// 失败注入与设备清单（构造后只读，故用 `Mutex` 只为让 `open(&self)` 可读）
#[derive(Debug, Clone)]
struct Script {
    devices: Result<Vec<DeviceInfo>, AudioError>,
    open_error: Option<AudioError>,
    fail_start: bool,
    fail_stop: bool,
    /// `start` 返回**之前**投喂的帧数（模拟真实后端在 `play()` 返回前就回调首帧）
    push_on_start: usize,
}

/// 后端共享状态（backend 与每个 stream 各持一份 `Arc`）
struct Inner {
    id: String,
    actual: PcmFormat,
    script: Mutex<Script>,
    /// `open` 登记的 sink（同一时刻只有最后一条流的 sink，够测试用）
    sink: Mutex<Option<Arc<dyn CaptureSink>>>,
    ops: Mutex<Vec<ScriptedOp>>,
}

/// 可编排后端（`Clone` 共享同一份状态，便于 `Arc<dyn CaptureBackend>` 与测试侧同时持有）
#[derive(Clone)]
pub struct ScriptedBackend {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ScriptedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedBackend")
            .field("id", &self.inner.id)
            .field("actual", &self.inner.actual)
            .finish_non_exhaustive()
    }
}

impl ScriptedBackend {
    /// 以协商格式构造：设备清单派生一台默认输入设备（id `scripted-input`）
    pub fn new(actual: PcmFormat) -> Self {
        let devices = vec![DeviceInfo::new(
            "scripted-input",
            "Scripted Input",
            true,
            actual.channels,
            vec![actual.sample_rate],
            vec![actual.sample],
        )];
        let inner = Inner {
            id: "scripted".to_string(),
            actual,
            script: Mutex::new(Script {
                devices: Ok(devices),
                open_error: None,
                fail_start: false,
                fail_stop: false,
                push_on_start: 0,
            }),
            sink: Mutex::new(None),
            ops: Mutex::new(Vec::new()),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// 后端名（进 `status.backend`；可用它构造非默认后端身份的用例）
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.id = id.into();
        }
        self
    }

    /// 显式设备清单（覆盖 [`ScriptedBackend::new`] 的派生值）
    pub fn with_devices(self, devices: Vec<DeviceInfo>) -> Self {
        lock(&self.inner.script).devices = Ok(devices);
        self
    }

    /// 枚举设备即失败（`NoInputDevice` / `BackendUnavailable` 等后端故障面）
    pub fn with_devices_error(self, error: AudioError) -> Self {
        lock(&self.inner.script).devices = Err(error);
        self
    }

    /// `open` 直接失败（不产生流，也不登记 sink）
    pub fn with_open_failure(self, error: AudioError) -> Self {
        lock(&self.inner.script).open_error = Some(error);
        self
    }

    /// `start` 失败注入
    pub fn with_start_failure(self) -> Self {
        lock(&self.inner.script).fail_start = true;
        self
    }

    /// `stop` 失败注入
    pub fn with_stop_failure(self) -> Self {
        lock(&self.inner.script).fail_stop = true;
        self
    }

    /// 在 `start` 返回前投喂指定帧数（每声道）
    ///
    /// 真实后端（cpal 的 `play()`）可能在返回前就从采集线程回调首帧。引擎若在后端返回
    /// 之后才把状态置为 running，那段音频就会被当成「非采集态回调」丢弃——本注入让那条
    /// 时序可被确定性断言（见 `engine::tests` 的首帧用例）。
    pub fn with_push_on_start(self, frames_per_channel: usize) -> Self {
        lock(&self.inner.script).push_on_start = frames_per_channel;
        self
    }

    /// 已登记的采集数据汇（`None` = 还没有 `open` 成功）
    pub fn sink(&self) -> Option<Arc<dyn CaptureSink>> {
        lock(&self.inner.sink).clone()
    }

    /// 把一帧原生 PCM 投给已登记的 sink（等价真实后端的采集回调）
    ///
    /// 未 `open` 时静默忽略：调用方在断言里显式 `expect` 出 sink 更能定位问题，
    /// 而这个便捷入口服务于「先 open 再 push」的常规顺序。
    pub fn push(&self, format: PcmFormat, buffer: &PcmBuffer<'_>) {
        if let Some(sink) = self.sink() {
            sink.push(format, buffer);
        }
    }

    /// 让已登记的 sink 上报流终止（等价后端错误回调）
    pub fn terminate(&self, reason: TerminationReason) {
        if let Some(sink) = self.sink() {
            sink.terminated(reason);
        }
    }

    /// 台账快照（发生顺序）
    pub fn ops(&self) -> Vec<ScriptedOp> {
        lock(&self.inner.ops).clone()
    }

    /// 台账里某类操作的次数
    pub fn op_count(&self, kind: fn(&ScriptedOp) -> bool) -> usize {
        lock(&self.inner.ops).iter().filter(|op| kind(op)).count()
    }

    /// 最近一次 `open` 的请求（未打开过 ⇒ `None`）
    pub fn last_open_request(&self) -> Option<OpenRequest> {
        lock(&self.inner.ops).iter().rev().find_map(|op| match op {
            ScriptedOp::Open(request) => Some(request.clone()),
            _ => None,
        })
    }

    fn record(&self, op: ScriptedOp) {
        lock(&self.inner.ops).push(op);
    }
}

impl CaptureBackend for ScriptedBackend {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn input_devices(&self) -> Result<Vec<DeviceInfo>, AudioError> {
        lock(&self.inner.script).devices.clone()
    }

    fn open(
        &self,
        request: &OpenRequest,
        sink: Arc<dyn CaptureSink>,
    ) -> Result<Box<dyn CaptureStream>, AudioError> {
        self.record(ScriptedOp::Open(request.clone()));
        let script = lock(&self.inner.script);
        if let Some(error) = script.open_error.clone() {
            return Err(error);
        }
        drop(script);
        *lock(&self.inner.sink) = Some(sink);
        Ok(Box::new(ScriptedStream {
            inner: Arc::clone(&self.inner),
            format: self.inner.actual,
        }))
    }
}

/// 编排出的采集流（Drop 即记台账，等价后端资源释放）
struct ScriptedStream {
    inner: Arc<Inner>,
    format: PcmFormat,
}

impl ScriptedStream {
    fn record(&self, op: ScriptedOp) {
        lock(&self.inner.ops).push(op);
    }
}

impl CaptureStream for ScriptedStream {
    fn start(&mut self) -> Result<(), AudioError> {
        self.record(ScriptedOp::Start);
        let (fail_start, push_on_start) = {
            let script = lock(&self.inner.script);
            (script.fail_start, script.push_on_start)
        };
        if fail_start {
            return Err(AudioError::StreamFailed {
                detail: "scripted backend: start failure injected".to_string(),
            });
        }
        if push_on_start > 0 {
            // 模拟「play() 返回前就回调首帧」：走与真实后端完全相同的 sink 入口
            self.push_before_start_returns(push_on_start);
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), AudioError> {
        self.record(ScriptedOp::Stop);
        if lock(&self.inner.script).fail_stop {
            return Err(AudioError::StreamFailed {
                detail: "scripted backend: stop failure injected".to_string(),
            });
        }
        Ok(())
    }

    fn format(&self) -> PcmFormat {
        self.format
    }
}

impl ScriptedStream {
    /// 按实际协商格式投喂一帧（每声道 `frames` 个样本）
    fn push_before_start_returns(&self, frames: usize) {
        let Some(sink) = lock(&self.inner.sink).clone() else {
            return;
        };
        let samples_per_channel = frames.max(1) * usize::from(self.format.channels.max(1));
        match self.format.sample {
            crate::format::SampleFormat::S16 => {
                let samples = vec![0i16; samples_per_channel];
                sink.push(self.format, &PcmBuffer::S16(&samples));
            }
            crate::format::SampleFormat::F32 => {
                let samples = vec![0f32; samples_per_channel];
                sink.push(self.format, &PcmBuffer::F32(&samples));
            }
        }
    }
}

impl Drop for ScriptedStream {
    fn drop(&mut self) {
        self.record(ScriptedOp::Dropped);
    }
}

/// 取锁：编排状态不参与正确性判定，中毒（某个测试 panic）后取回内部值继续
fn lock<T>(cell: &Mutex<T>) -> MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::SampleFormat;

    fn format() -> PcmFormat {
        PcmFormat::new(16_000, 1, SampleFormat::S16)
    }

    /// 编排后端自证：open 登记请求与 sink，start/stop/drop 进台账
    #[test]
    fn scripted_backend_records_the_lifecycle() {
        let backend = ScriptedBackend::new(format());
        let request = OpenRequest::new(None, crate::format::SPEECH_16K_MONO);
        let mut stream = backend
            .open(&request, Arc::new(NullSink))
            .expect("未注入失败");
        stream.start().expect("start 成功");
        stream.stop().expect("stop 成功");
        drop(stream);
        assert_eq!(
            backend.ops(),
            vec![
                ScriptedOp::Open(request.clone()),
                ScriptedOp::Start,
                ScriptedOp::Stop,
                ScriptedOp::Dropped,
            ]
        );
        assert_eq!(backend.last_open_request(), Some(request));
        assert!(backend.sink().is_some(), "open 必须登记数据汇");
    }

    /// 失败注入：三个注入点各自生效，且 open 失败时不登记 sink
    #[test]
    fn failures_are_injectable_at_each_boundary() {
        let backend = ScriptedBackend::new(format()).with_start_failure();
        let mut stream = backend
            .open(
                &OpenRequest::new(None, crate::format::SPEECH_16K_MONO),
                Arc::new(NullSink),
            )
            .expect("open 未注入失败");
        assert!(stream.start().is_err(), "start 失败必须可见");
        assert!(stream.stop().is_ok(), "stop 未注入失败");

        let backend = ScriptedBackend::new(format()).with_stop_failure();
        let mut stream = backend
            .open(
                &OpenRequest::new(None, crate::format::SPEECH_16K_MONO),
                Arc::new(NullSink),
            )
            .expect("open 未注入失败");
        assert!(stream.start().is_ok());
        assert!(stream.stop().is_err(), "stop 失败必须可见");

        let backend = ScriptedBackend::new(format()).with_open_failure(AudioError::DeviceBusy {
            detail: "in use".to_string(),
        });
        let err = backend
            .open(
                &OpenRequest::new(None, crate::format::SPEECH_16K_MONO),
                Arc::new(NullSink),
            )
            .err()
            .expect("open 失败必须可见");
        assert!(matches!(err, AudioError::DeviceBusy { .. }));
        assert!(backend.sink().is_none(), "失败的 open 不得登记 sink");
    }

    /// 设备清单：派生默认设备可按格式配置，`with_devices_error` 直通故障
    #[test]
    fn device_list_is_configurable() {
        let backend = ScriptedBackend::new(PcmFormat::new(48_000, 2, SampleFormat::F32));
        let devices = backend.input_devices().expect("派生清单");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].sample_rates, vec![48_000]);
        assert!(devices[0].is_default);

        let backend = backend.with_devices(vec![]);
        assert!(backend.input_devices().expect("空清单是事实").is_empty());

        let backend = ScriptedBackend::new(format()).with_devices_error(AudioError::NoInputDevice);
        assert!(matches!(
            backend.input_devices(),
            Err(AudioError::NoInputDevice)
        ));
    }

    /// 无副作用的采集汇：本模块只验台账，不验引擎归一
    struct NullSink;

    impl CaptureSink for NullSink {
        fn push(&self, _: PcmFormat, _: &PcmBuffer<'_>) {}
        fn terminated(&self, _: TerminationReason) {}
    }
}
