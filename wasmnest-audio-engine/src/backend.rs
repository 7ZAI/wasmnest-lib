//! 采集后端抽象（平台差异的唯一出口）
//!
//! ## 为什么是 trait 而不是依赖
//!
//! 本 crate 的**默认形态 = 纯引擎 + 端口抽象**（AGENTS §3.1）：零平台 SDK、零原生音频库。
//! 「怎么从硬件拿到 PCM」是端差异——桌面 Linux 走 ALSA/PipeWire、Windows 走 WASAPI、
//! Android 走 AAudio/Oboe、iOS 走 AVAudioEngine。把这些收进一个 trait，引擎只认
//! [`CaptureBackend`]，具体实现可以来自：
//!
//! 1. 本 crate 的可选适配器 `backend-cpal`
//!    （feature `backend-cpal`，四个桌面/移动平台共用一套 cpal 实现）；
//! 2. **宿主自带的后端**（移动端若要精确控制 `RECORD_AUDIO` 生命周期与音频焦点，
//!    实现本 trait 注入即可，引擎一行不改）；
//! 3. 测试用的 `test_util::ScriptedBackend`（无硬件、按脚本投喂帧）。
//!
//! ## 线程契约（实现方必读）
//!
//! - [`CaptureSink::push`] 由后端在**自己的采集线程**调用：那里不能阻塞、不能分配、
//!   不能回调本 trait 的其它方法（引擎的锁序见 `engine` 模块文档）。
//! - 采集线程**只**持有 `Arc<dyn CaptureSink>`；[`CaptureStream`] 的 `start` / `stop`
//!   由调用方线程持有。后端不得在流对象里再放一份 sink 的可变状态，否则 `stop` 与
//!   回调会互相等。
//! - [`CaptureSink::terminated`] 是「流自己死了」的唯一上报口：实现方在错误回调里调它，
//!   **不要**在其中销毁自己的流（引擎只改状态，流由 `close` / 回收路径释放）。

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::AudioError;
use crate::format::{PcmBuffer, PcmFormat, SampleFormat, TargetFormat};

/// 输入设备 id（后端给定的不透明字符串）
///
/// **不透明是刻意的**：Linux 是 ALSA card 名、Windows 是端点 id、Android 是产品名 +
/// 类型组合，跨端比较没有意义，因此本类型只做等值与传输，不提供任何「解析」能力。
/// 稳定性提醒：多数后端的 id 在**设备重插或系统重启后会变**，插件侧应当存 `name`
/// 或直接不存（每次 `list-devices` 现取），不要把 id 当长期标识持久化。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    /// 从后端原文构造
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出原文
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for DeviceId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for DeviceId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// 输入设备清单条目（`list-devices` 的数据面）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    /// 后端给出的不透明 id（`open` 时回传）
    pub id: DeviceId,
    /// 人类可读名称
    pub name: String,
    /// 是否系统默认输入设备
    pub is_default: bool,
    /// 该设备能提供的最大输入声道数（0 = 后端没报上来）
    pub max_input_channels: u16,
    /// 该设备支持的采样率（去重升序；空 = 后端没报上来）
    pub sample_rates: Vec<u32>,
    /// 该设备支持的样本宽度（去重；空 = 后端没报上来）
    pub sample_formats: Vec<SampleFormat>,
}

impl DeviceInfo {
    /// 构造清单条目（`sample_rates` 会被去重升序，避免后端重复上报造成 UI 抖动）
    pub fn new(
        id: impl Into<DeviceId>,
        name: impl Into<String>,
        is_default: bool,
        max_input_channels: u16,
        sample_rates: Vec<u32>,
        sample_formats: Vec<SampleFormat>,
    ) -> Self {
        let mut rates = sample_rates;
        rates.sort_unstable();
        rates.dedup();
        Self {
            id: id.into(),
            name: name.into(),
            is_default,
            max_input_channels,
            sample_rates: rates,
            sample_formats,
        }
    }
}

/// 打开一路采集的请求（引擎侧已校验过的参数）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    /// 指定设备；`None` = 用系统默认输入设备
    pub device: Option<DeviceId>,
    /// 期望的产出格式（后端**不必**按它采集，归一管线负责将真实格式转成它；
    /// 后端只需如实报告 [`CaptureStream::format`]）
    pub target: TargetFormat,
}

impl OpenRequest {
    /// 构造打开请求
    pub fn new(device: Option<DeviceId>, target: TargetFormat) -> Self {
        Self { device, target }
    }
}

/// 流终止原因（后端 → 引擎的唯一「我死了」通道）
///
/// `code` 是**线协议词汇**（进 `status` 的 JSON），跨端稳定；改名等于破坏性变更。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    /// 设备消失（拔出 / 系统清单里没了）
    DeviceLost {
        /// 后端原文
        detail: String,
    },
    /// 音频路由变化（切到蓝牙 / 插耳机导致当前流失效）
    RouteChanged {
        /// 后端原文
        detail: String,
    },
    /// 平台在运行期撤回了录音权限（Android 撤销授权、macOS 隐私设置改动）
    AccessDenied {
        /// 后端原文
        detail: String,
    },
    /// 设备被更高优先级的使用者独占
    DeviceBusy {
        /// 后端原文
        detail: String,
    },
    /// 后端整体不可用（音频服务退出）
    HostUnavailable {
        /// 后端原文
        detail: String,
    },
    /// 其它流级失败（后端给不出更细的分类）
    Failed {
        /// 后端原文
        detail: String,
    },
}

impl TerminationReason {
    /// 线协议词汇（蛇形小写，稳定面）
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DeviceLost { .. } => "device_lost",
            Self::RouteChanged { .. } => "route_changed",
            Self::AccessDenied { .. } => "access_denied",
            Self::DeviceBusy { .. } => "device_busy",
            Self::HostUnavailable { .. } => "host_unavailable",
            Self::Failed { .. } => "failed",
        }
    }

    /// 后端原文
    pub fn detail(&self) -> &str {
        match self {
            Self::DeviceLost { detail }
            | Self::RouteChanged { detail }
            | Self::AccessDenied { detail }
            | Self::DeviceBusy { detail }
            | Self::HostUnavailable { detail }
            | Self::Failed { detail } => detail,
        }
    }

    /// 该原因下调用方是否应当**重新 open**（而不是重试 start）
    ///
    /// 除 `Failed` 外全部建议重开：`Failed` 语义太宽，交给调用方自己决定，本域不猜。
    pub const fn suggests_reopen(&self) -> bool {
        !matches!(self, Self::Failed { .. })
    }
}

/// 采集数据汇：后端把原生帧交给引擎的唯一入口
///
/// 实现住在引擎侧（`engine::StreamSink`），由后端在采集线程调用。
pub trait CaptureSink: Send + Sync {
    /// 交付一段原生 PCM（借用切片：实时线程不做字节拷贝的第二次分配）
    fn push(&self, format: PcmFormat, buffer: &PcmBuffer<'_>);

    /// 上报流终止（幂等由引擎保证：第二次及以后只计入错误计数，不再改状态）
    fn terminated(&self, reason: TerminationReason);
}

/// 一路已打开、尚未启动的采集流
///
/// 生命周期：`open` 得到它 → `start` / `stop` 反复切换 → **Drop 即释放后端资源**。
/// 实现方必须保证 `stop` 后不再有 `push`（引擎按此契约丢弃残留帧，但不该依赖它）。
pub trait CaptureStream: Send {
    /// 启动采集（后端在采集线程回调 sink）
    ///
    /// # Errors
    /// 后端起流失败时返回 [`AudioError`]（`StreamFailed` / `AccessDenied` / `DeviceBusy`）。
    fn start(&mut self) -> Result<(), AudioError>;

    /// 暂停采集（保留设备句柄，`start` 可再次启动）
    ///
    /// # Errors
    /// 后端暂停失败时返回 [`AudioError::StreamFailed`]。
    fn stop(&mut self) -> Result<(), AudioError>;

    /// 后端**实际**使用的原生格式（归一管线的输入解释方式，必须如实报告）
    fn format(&self) -> PcmFormat;
}

/// 采集后端
pub trait CaptureBackend: Send + Sync {
    /// 后端名（进 `status`，如 `cpal` / `aaudio` / `scripted`）
    fn id(&self) -> &str;

    /// 当前输入设备清单
    ///
    /// # Errors
    /// 后端整体不可用返回 [`AudioError::BackendUnavailable`]；无输入设备返回
    /// [`AudioError::NoInputDevice`]（**不是**空清单——空清单让调用方分不清「没设备」
    /// 与「设备被隐藏」）。
    fn input_devices(&self) -> Result<Vec<DeviceInfo>, AudioError>;

    /// 打开一路采集（不启动；返回的流由调用方持有）
    ///
    /// 失败时**不返回半成品流**：直接 `Err`，调用方无需清理（设备句柄在实现内部释放）。
    ///
    /// # Errors
    /// 设备不存在 [`AudioError::DeviceNotFound`]、无输入设备 [`AudioError::NoInputDevice`]、
    /// 配置协商失败 [`AudioError::FormatUnsupported`]、权限 [`AudioError::AccessDenied`]、
    /// 占用 [`AudioError::DeviceBusy`]、后端故障 [`AudioError::BackendUnavailable`]。
    fn open(
        &self,
        request: &OpenRequest,
        sink: Arc<dyn CaptureSink>,
    ) -> Result<Box<dyn CaptureStream>, AudioError>;
}

#[cfg(test)]
mod tests {
    use super::{DeviceId, DeviceInfo, OpenRequest, TerminationReason};
    use crate::format::{SampleFormat, TargetFormat};

    /// D-001 正例：id 是透明字符串（线协议面），Display 与 serde 一致
    #[test]
    fn device_id_is_a_transparent_string() {
        let id = DeviceId::new("hw:Card");
        assert_eq!(id.as_str(), "hw:Card");
        assert_eq!(id.to_string(), "hw:Card");
        let json = serde_json::to_string(&id).expect("序列化");
        assert_eq!(json, "\"hw:Card\"");
        let back: DeviceId = serde_json::from_str(&json).expect("反序列化");
        assert_eq!(back, id);
    }

    /// D-002 副作用：清单构造把采样率去重升序（后端重复上报不抖动 UI）
    #[test]
    fn device_info_normalizes_rates() {
        let info = DeviceInfo::new(
            "d",
            "Mic",
            true,
            2,
            vec![48_000, 8_000, 48_000, 16_000],
            vec![SampleFormat::S16, SampleFormat::F32],
        );
        assert_eq!(info.sample_rates, vec![8_000, 16_000, 48_000]);
        assert!(info.is_default);
        let json = serde_json::to_string(&info).expect("序列化");
        assert!(
            json.contains("\"maxInputChannels\":2") && json.contains("\"isDefault\":true"),
            "清单字段是 camelCase 线协议，实得 {json}"
        );
    }

    /// D-003 正例：终止原因的 code 是稳定词汇，detail 原样透传
    #[test]
    fn termination_codes_are_stable_vocabulary() {
        let cases = [
            (
                TerminationReason::DeviceLost {
                    detail: "unplugged".into(),
                },
                "device_lost",
            ),
            (
                TerminationReason::RouteChanged {
                    detail: "bt".into(),
                },
                "route_changed",
            ),
            (
                TerminationReason::AccessDenied {
                    detail: "revoked".into(),
                },
                "access_denied",
            ),
            (
                TerminationReason::DeviceBusy { detail: "x".into() },
                "device_busy",
            ),
            (
                TerminationReason::HostUnavailable { detail: "x".into() },
                "host_unavailable",
            ),
            (TerminationReason::Failed { detail: "x".into() }, "failed"),
        ];
        for (reason, code) in cases {
            assert_eq!(reason.code(), code);
            assert!(!reason.detail().is_empty());
        }
        // Failed 语义太宽 ⇒ 不替调用方决定重开
        assert!(!TerminationReason::Failed { detail: "x".into() }.suggests_reopen());
        assert!(TerminationReason::DeviceLost { detail: "x".into() }.suggests_reopen());
    }

    /// D-004 正例：`OpenRequest` 允许「默认设备 + 目标格式」的最小组合
    #[test]
    fn open_request_accepts_default_device() {
        let request = OpenRequest::new(None, TargetFormat::default());
        assert!(request.device.is_none());
        assert_eq!(request.target.sample_rate, 16_000);
    }

    /// D-005 类型面：后端与流必须能跨线程（会话表在宿主线程读写、回调在采集线程）
    #[test]
    fn backend_and_stream_traits_require_send_sync() {
        fn assert_object_safe<T: ?Sized>() {}
        assert_object_safe::<dyn crate::backend::CaptureBackend>();
        assert_object_safe::<dyn crate::backend::CaptureStream>();
        assert_object_safe::<dyn crate::backend::CaptureSink>();
    }
}
