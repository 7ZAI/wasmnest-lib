//! cpal 跨平台采集后端（feature `backend-cpal`）
//!
//! ## 覆盖范围
//!
//! 一套代码覆盖四端原生输入：Linux/BSD → ALSA（cpal 默认未开 pipewire / pulseaudio /
//! jack feature，故走 ALSA 直连），Windows → WASAPI，Apple → CoreAudio，Android → AAudio。
//! **默认关**这一层：它带原生链接依赖（Linux 需 `libasound2-dev`，Android 需 NDK 的
//! `aaudio`），开在默认树上会让「默认形态任何宿主可直接引用」失真（AGENTS §3.1）。
//!
//! ## 设计取舍
//!
//! - **不持有 `cpal::Host`**：`Host` 的 `Send`/`Sync` 由平台 impl 决定，把它塞进
//!   [`CpalBackend`] 会让「后端可跨线程」变成平台相关的偶然事实。控制面（枚举 / 打开）
//!   频率极低，每次现取一份 host 足够便宜，也让本类型退化成无状态单元结构。
//!   host 经 `available_hosts()` + `host_from_id` 取得（**不用** `default_host()`：
//!   它在多数平台内部 `expect`，会把「音频子系统起不来」变成 panic 而不是
//!   [`AudioError::BackendUnavailable`]）。
//! - **打开即协商、打开不启动**：`build_input_stream_raw` 返回的流是 stopped 的，
//!   `start` 才 `play()`——与引擎契约（`open` 不采集）一致；设备原生格式如实回报，
//!   归一由引擎负责（本适配器不重采样、不混音）。
//! - **采集线程零阻塞**：数据回调只做「切片 → 交给 [`CaptureSink`]」，不做日志、不做
//!   IO、不分配；后端错误回调只上报终止原因。
//! - **`stop` 的降级**：cpal 文档说明部分后端不支持 `pause`。此时本适配器把
//!   `UnsupportedOperation` 当成功返回（引擎随即把状态置为 stopped 并丢弃后续回调），
//!   语义仍成立，只是不省电——比把「插件以为停了、实际还在录」留给上层要好。

use std::sync::Arc;
use std::time::Duration;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::Device;

use crate::backend::{
    CaptureBackend, CaptureSink, CaptureStream, DeviceInfo, OpenRequest, TerminationReason,
};
use crate::error::AudioError;
use crate::format::{PcmBuffer, PcmFormat, SampleFormat, TargetFormat};

/// 后端名（进 `status.backend`）
const BACKEND_ID: &str = "cpal";

/// 打开流的超时上限
///
/// `build_input_stream_raw` 的 `timeout: None` 表示**无限等待**设备就绪；一个卡住的
/// 驱动会把 guest 的 host 调用一起钉死。2 秒足够覆盖正常初始化，且不是所有后端都
/// 严格遵守该值（文档明示），故它只是「不要让调用无限挂起」的上限。
const OPEN_TIMEOUT: Duration = Duration::from_secs(2);

/// cpal 跨平台采集后端（无状态，可 `Clone` / `Copy`）
#[derive(Debug, Default, Clone, Copy)]
pub struct CpalBackend;

impl CpalBackend {
    /// 构造后端（不需要初始化，每次调用现取 host）
    pub const fn new() -> Self {
        Self
    }
}

impl CaptureBackend for CpalBackend {
    fn id(&self) -> &str {
        BACKEND_ID
    }

    fn input_devices(&self) -> Result<Vec<DeviceInfo>, AudioError> {
        let host = host()?;
        let default = host.default_input_device();
        let devices = host
            .input_devices()
            .map_err(|err| backend_unavailable("enumerating input devices", &err))?;
        let mut out = Vec::new();
        for device in devices {
            if !device.supports_input() {
                continue;
            }
            let is_default = default
                .as_ref()
                .is_some_and(|candidate| candidate == &device);
            out.push(describe(&device, is_default));
        }
        // 「没有输入设备」是事实而不是故障（WIT 文档口径）：空清单原样返回
        Ok(out)
    }

    fn open(
        &self,
        request: &OpenRequest,
        sink: Arc<dyn CaptureSink>,
    ) -> Result<Box<dyn CaptureStream>, AudioError> {
        let host = host()?;
        let device = match &request.device {
            Some(wanted) => find_device(&host, wanted.as_str())?,
            None => host
                .default_input_device()
                .ok_or(AudioError::NoInputDevice)?,
        };
        if !device.supports_input() {
            return Err(AudioError::FormatUnsupported {
                detail: format!("device `{device}` has no input capability"),
            });
        }
        let (stream_config, pcm) = negotiate(&device, request.target)?;

        let data_sink = Arc::clone(&sink);
        let data_callback = move |data: &cpal::Data, _info: &cpal::InputCallbackInfo| {
            // 只做借用切片转发：实时线程不分配、不打日志、不重采样
            match pcm.sample {
                SampleFormat::S16 => {
                    if let Some(samples) = data.as_slice::<i16>() {
                        data_sink.push(pcm, &PcmBuffer::S16(samples));
                    }
                }
                SampleFormat::F32 => {
                    if let Some(samples) = data.as_slice::<f32>() {
                        data_sink.push(pcm, &PcmBuffer::F32(samples));
                    }
                }
            }
        };
        let error_sink = Arc::clone(&sink);
        let error_callback = move |err: cpal::Error| {
            // 错误回调在 cpal 自己的线程上；只转成终止原因，**不**在这里 Drop 流
            tracing::warn!(backend = BACKEND_ID, error = %err, "cpal 采集流出错");
            error_sink.terminated(stream_termination(&err));
        };

        let stream = device
            .build_input_stream_raw(
                stream_config,
                cpal_sample_format(pcm.sample),
                data_callback,
                error_callback,
                Some(OPEN_TIMEOUT),
            )
            .map_err(|err| open_error(device.to_string(), &err))?;
        // 返回时流是 stopped 的：引擎 `start` 才 play（open 不采集）
        Ok(Box::new(CpalStream {
            stream,
            format: pcm,
        }))
    }
}

/// 一路 cpal 采集流（Drop 即释放设备句柄）
struct CpalStream {
    stream: cpal::Stream,
    format: PcmFormat,
}

impl CaptureStream for CpalStream {
    fn start(&mut self) -> Result<(), AudioError> {
        self.stream
            .play()
            .map_err(|err| stream_operation_error("start", &err))
    }

    fn stop(&mut self) -> Result<(), AudioError> {
        match self.stream.pause() {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == cpal::ErrorKind::UnsupportedOperation => {
                // 后端不支持悬挂：回调继续，但引擎在 stop 成功后会把状态置为 stopped
                // 并丢弃后续帧（`ignored_callbacks` 如实计数）——语义成立，只是不省电
                tracing::debug!(
                    backend = BACKEND_ID,
                    "该后端不支持 pause，回调继续但引擎侧丢弃（不省电）"
                );
                Ok(())
            }
            Err(err) => Err(stream_operation_error("stop", &err)),
        }
    }

    fn format(&self) -> PcmFormat {
        self.format
    }
}

// ==================== host / device 解析 ====================

/// 取一个可用的 cpal host（首选平台默认顺序里的第一个可用 host）
fn host() -> Result<cpal::Host, AudioError> {
    let wanted = cpal::available_hosts().first().copied().ok_or_else(|| {
        backend_unavailable("selecting an audio host", "no cpal host is available")
    })?;
    cpal::host_from_id(wanted).map_err(|err| backend_unavailable("creating an audio host", &err))
}

/// 按后端 id 原文找设备（id 形状 = cpal `DeviceId` 的 `Display`，见 [`describe`]）
fn find_device(host: &cpal::Host, wanted: &str) -> Result<Device, AudioError> {
    let devices = host
        .input_devices()
        .map_err(|err| backend_unavailable("enumerating input devices", &err))?;
    for device in devices {
        if device_id(&device) == wanted && device.supports_input() {
            return Ok(device);
        }
    }
    Err(AudioError::DeviceNotFound {
        id: wanted.to_string(),
    })
}

/// 设备 id 原文（cpal 失败时回落到设备名——仍可用于展示，且 open 会显性报找不到）
fn device_id(device: &Device) -> String {
    match device.id() {
        Ok(id) => id.to_string(),
        Err(_) => device.to_string(),
    }
}

/// 设备清单条目（`is_default` 由调用方比较默认设备得出）
fn describe(device: &Device, is_default: bool) -> DeviceInfo {
    let mut max_channels = 0u16;
    let mut sample_rates = Vec::new();
    let mut sample_formats = Vec::new();
    if let Ok(configs) = device.supported_input_configs() {
        for range in configs {
            max_channels = max_channels.max(range.channels());
            sample_rates.push(range.min_sample_rate());
            sample_rates.push(range.max_sample_rate());
            if let Some(format) = supported_sample_format(range.sample_format()) {
                sample_formats.push(format);
            }
        }
    }
    DeviceInfo::new(
        device_id(device),
        device.to_string(),
        is_default,
        max_channels,
        sample_rates,
        sample_formats,
    )
}

// ==================== 配置协商 ====================

/// 在与设备协商出的配置里挑一条「归一代价最小」的
///
/// 打分顺序（字典序）：采样率离目标最近 → 声道数离目标最近 → 样本宽度优先 `S16`
/// （解码更便宜）。目标格式只约束**产出**，设备原生格式由归一管线转换；因此这里
/// 能就近取整就不强行要求目标采样率（设备不支持 16 k 时强行要求会直接失败）。
fn negotiate(
    device: &Device,
    target: TargetFormat,
) -> Result<(cpal::StreamConfig, PcmFormat), AudioError> {
    let configs = device.supported_input_configs().map_err(|err| {
        backend_unavailable(&format!("querying input configs of `{device}`"), &err)
    })?;

    let mut best: Option<Candidate> = None;
    let mut sampled_formats = Vec::new();
    for range in configs {
        let Some(sample) = supported_sample_format(range.sample_format()) else {
            sampled_formats.push(format!("{:?}", range.sample_format()));
            continue;
        };
        if range.channels() == 0 || range.max_sample_rate() == 0 {
            continue;
        }
        let rate = target
            .sample_rate
            .clamp(range.min_sample_rate(), range.max_sample_rate());
        let candidate = Candidate {
            rate,
            channels: range.channels(),
            sample,
        };
        if best
            .as_ref()
            .is_none_or(|current| candidate.score(target) < current.score(target))
        {
            best = Some(candidate);
        }
    }

    let Some(best) = best else {
        return Err(AudioError::FormatUnsupported {
            detail: format!(
                "device `{device}` offers no s16/f32 input config (saw {sampled_formats:?})"
            ),
        });
    };
    let pcm = PcmFormat::new(best.rate, best.channels, best.sample);
    Ok((
        cpal::StreamConfig {
            channels: best.channels,
            sample_rate: best.rate,
            buffer_size: cpal::BufferSize::Default,
        },
        pcm,
    ))
}

/// 协商打分用的候选
struct Candidate {
    rate: u32,
    channels: u16,
    sample: SampleFormat,
}

impl Candidate {
    fn score(&self, target: TargetFormat) -> (u32, u16, u8) {
        let rate_penalty = self.rate.abs_diff(target.sample_rate);
        let channels_penalty = self.channels.abs_diff(target.channels);
        let format_penalty = match self.sample {
            SampleFormat::S16 => 0,
            SampleFormat::F32 => 1,
        };
        (rate_penalty, channels_penalty, format_penalty)
    }
}

/// cpal 样本宽度 → 引擎样本宽度（`None` = 本引擎不解释该宽度）
fn supported_sample_format(format: cpal::SampleFormat) -> Option<SampleFormat> {
    match format {
        cpal::SampleFormat::I16 => Some(SampleFormat::S16),
        cpal::SampleFormat::F32 => Some(SampleFormat::F32),
        // u8 / i8 / i32 / f64 / i24 … 不覆盖：麦克风实际不会交出来，遇到即为
        // `FormatUnsupported`（不静默按错的宽度读字节）
        _ => None,
    }
}

/// 引擎样本宽度 → cpal 宽度（构造期已过滤，故是穷尽映射）
fn cpal_sample_format(format: SampleFormat) -> cpal::SampleFormat {
    match format {
        SampleFormat::S16 => cpal::SampleFormat::I16,
        SampleFormat::F32 => cpal::SampleFormat::F32,
    }
}

// ==================== 错误映射 ====================

fn backend_unavailable(action: &str, err: impl std::fmt::Display) -> AudioError {
    AudioError::BackendUnavailable {
        backend: BACKEND_ID.to_string(),
        reason: format!("{action}: {err}"),
    }
}

/// 打开期错误 → 引擎错误（按调用方能据此行动的事分类）
///
/// `device` 只进文案（不借用 `cpal::Device`）：错误映射因此可在无硬件的用例里验证。
fn open_error(device: String, err: &cpal::Error) -> AudioError {
    use cpal::ErrorKind;
    let detail = format!("device `{device}`: {err}");
    match err.kind() {
        ErrorKind::PermissionDenied => AudioError::AccessDenied { detail },
        ErrorKind::DeviceBusy => AudioError::DeviceBusy { detail },
        ErrorKind::DeviceNotAvailable => AudioError::DeviceNotFound { id: detail },
        ErrorKind::HostUnavailable => backend_unavailable("building capture stream", err),
        ErrorKind::UnsupportedConfig
        | ErrorKind::UnsupportedOperation
        | ErrorKind::InvalidInput => AudioError::FormatUnsupported { detail },
        _ => AudioError::StreamFailed { detail },
    }
}

/// 运行期错误回调 → 终止原因（引擎据此决定插件是否要重开）
fn stream_termination(err: &cpal::Error) -> TerminationReason {
    use cpal::ErrorKind;
    let detail = err.to_string();
    match err.kind() {
        ErrorKind::DeviceChanged => TerminationReason::RouteChanged { detail },
        ErrorKind::DeviceNotAvailable | ErrorKind::StreamInvalidated => {
            TerminationReason::DeviceLost { detail }
        }
        ErrorKind::PermissionDenied => TerminationReason::AccessDenied { detail },
        ErrorKind::DeviceBusy => TerminationReason::DeviceBusy { detail },
        ErrorKind::HostUnavailable => TerminationReason::HostUnavailable { detail },
        _ => TerminationReason::Failed { detail },
    }
}

/// 起停流错误 → 引擎错误
fn stream_operation_error(action: &str, err: &cpal::Error) -> AudioError {
    use cpal::ErrorKind;
    let detail = format!("{action}: {err}");
    match err.kind() {
        ErrorKind::PermissionDenied => AudioError::AccessDenied { detail },
        ErrorKind::DeviceBusy => AudioError::DeviceBusy { detail },
        // 流失效 = 设备没了：调用方应重开（`start` 会得到 InvalidState，插件走 close+open）
        ErrorKind::DeviceNotAvailable | ErrorKind::StreamInvalidated => {
            AudioError::StreamFailed { detail }
        }
        _ => AudioError::StreamFailed { detail },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只支持 s16 / f32 两档：其它宽度显性拒绝（不静默按错的宽度读字节）
    #[test]
    fn sample_format_mapping_is_narrow_and_symmetric() {
        assert_eq!(
            supported_sample_format(cpal::SampleFormat::I16),
            Some(SampleFormat::S16)
        );
        assert_eq!(
            supported_sample_format(cpal::SampleFormat::F32),
            Some(SampleFormat::F32)
        );
        for unsupported in [
            cpal::SampleFormat::I8,
            cpal::SampleFormat::I32,
            cpal::SampleFormat::U16,
            cpal::SampleFormat::F64,
        ] {
            assert_eq!(supported_sample_format(unsupported), None);
        }
        for format in [SampleFormat::S16, SampleFormat::F32] {
            assert_eq!(
                supported_sample_format(cpal_sample_format(format)),
                Some(format)
            );
        }
    }

    /// 终止原因映射：路由切换 / 设备消失 / 权限撤回必须落到不同词汇（插件据此决策）
    #[test]
    fn stream_errors_map_to_distinct_termination_vocabulary() {
        let cases = [
            (cpal::ErrorKind::DeviceChanged, "route_changed"),
            (cpal::ErrorKind::DeviceNotAvailable, "device_lost"),
            (cpal::ErrorKind::StreamInvalidated, "device_lost"),
            (cpal::ErrorKind::PermissionDenied, "access_denied"),
            (cpal::ErrorKind::DeviceBusy, "device_busy"),
            (cpal::ErrorKind::HostUnavailable, "host_unavailable"),
            (cpal::ErrorKind::Other, "failed"),
        ];
        for (kind, code) in cases {
            let err = cpal::Error::new(kind);
            assert_eq!(stream_termination(&err).code(), code, "kind {kind:?}");
        }
    }

    /// 打开期错误：权限与占用是「可重开」类，配置不支持是「改参数」类
    ///
    /// 错误映射只借用错误本身（设备只进文案），故无需真实设备。
    #[test]
    fn open_errors_are_classified_by_recoverability() {
        let label = || "test-device".to_string();
        let denied = open_error(
            label(),
            &cpal::Error::new(cpal::ErrorKind::PermissionDenied),
        );
        assert!(denied.needs_reopen(), "权限被拒应提示重开");
        assert!(matches!(denied, AudioError::AccessDenied { .. }));

        let unsupported = open_error(
            label(),
            &cpal::Error::new(cpal::ErrorKind::UnsupportedConfig),
        );
        assert!(matches!(unsupported, AudioError::FormatUnsupported { .. }));
        assert!(!unsupported.needs_reopen(), "配置问题不是设备故障");

        let busy = open_error(label(), &cpal::Error::new(cpal::ErrorKind::DeviceBusy));
        assert!(matches!(busy, AudioError::DeviceBusy { .. }));
        assert!(busy.needs_reopen());

        let missing = open_error(
            label(),
            &cpal::Error::new(cpal::ErrorKind::DeviceNotAvailable),
        );
        assert!(matches!(missing, AudioError::DeviceNotFound { .. }));
        assert!(missing.needs_reopen());
    }
}
