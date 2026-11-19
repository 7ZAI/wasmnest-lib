//! PCM 格式描述与归一管线（机制层，零业务语义）
//!
//! ## 为什么要归一
//!
//! 设备交出来的东西在各端差异极大：Windows 共享模式给 48 k 立体声 `f32`，ALSA 常见
//! 48 k `s16`（也可能是 44.1 k 或 `f32`），Android AAudio 给 48 k/44.1 k 的 `i16` 或
//! `f32`，而语音识别侧几乎都想要 **16 k 单声道 16 bit**。本模块把「设备格式」与
//! 「产出格式」拆成两个类型（[`PcmFormat`] / [`TargetFormat`]），中间用一条固定管线
//! 连接：解码 → 声道混合 → 重采样 → 编码成交错 S16LE 字节。
//!
//! ```text
//!   PcmBuffer（设备原生，借用回调切片）
//!        │ decode_into      → f32 交织（[-1.0, 1.0]）
//!        ▼
//!   mix_to_planes          → target.channels 个 f32 平面
//!        ▼
//!   Resampler（每平面一份相位） → 目标采样率的 f32 平面
//!        ▼
//!   encode_s16_interleaved → 交错 S16LE 字节（进帧环的就是它）
//! ```
//!
//! ## 红线
//!
//! - **样本宽度只支持 `s16` / `f32`**：这两者覆盖了四个目标平台上麦克风实际会交出的
//!   全部格式（cpal 的 `u8`/`i32`/`i24` 路径在麦克风上不出现）。遇到其它格式是
//!   [`AudioError::FormatUnsupported`]，**不是**静默按错的解释读字节。
//! - **重采样是可替换的策略**：[`Resampler`] trait 是扩展位，默认 [`LinearResampler`]
//!   （跨块相位连续，见其文档）。宿主若要接高质量多相重采样，换一个 `Resampler`
//!   实现即可，不改本模块其它代码、也不改帧环里的字节格式。
//! - **稳态零分配**：所有中间缓冲都住在 [`PcmNormalizer`] 里复用，产出的字节写进调用方
//!   传入的 `Vec`（采集回调线程不做分配式拼装）。

use serde::{Deserialize, Serialize};

use std::fmt;

use crate::error::AudioError;

/// 单声道样本宽度（本引擎支持的两种设备原生格式）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SampleFormat {
    /// 16 bit 有符号整数（小端），满刻度 32767 / 32768
    S16,
    /// 32 bit IEEE 浮点，约定满刻度为 ±1.0
    F32,
}

impl SampleFormat {
    /// 一个样本占几字节
    pub const fn sample_size(self) -> usize {
        match self {
            Self::S16 => 2,
            Self::F32 => 4,
        }
    }

    /// 线协议里的格式名（`actual-format` 的 `sample-format` 字段值）
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S16 => "s16",
            Self::F32 => "f32",
        }
    }
}

/// 采样率下界（电话档，也是多数 ASR 模型的最低输入率）
pub const MIN_SAMPLE_RATE: u32 = 8_000;
/// 采样率上界（高解析音频档；再高不属于「语音采集」的问题域）
pub const MAX_SAMPLE_RATE: u32 = 96_000;
/// 目标声道数上界（单声道 = ASR 档，立体声 = 保留左右信息；多于两个是混音问题，不是采集问题）
pub const MAX_TARGET_CHANNELS: u16 = 2;

/// 设备侧格式：采样率 + 声道数 + 样本宽度
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcmFormat {
    /// 采样率（Hz）
    pub sample_rate: u32,
    /// 声道数（设备侧真实声道数，1..=8 都可能）
    pub channels: u16,
    /// 样本宽度
    // `status.actualFormat.sampleFormat` 是 WIT 记录的字段名（`sample-format`），
    // 序列化名必须与之一致；Rust 侧字段名保持 `sample` 以免与 `SampleFormat` 类型重名。
    #[serde(rename = "sampleFormat")]
    pub sample: SampleFormat,
}

impl PcmFormat {
    /// 构造设备格式（不校验采样率区间——设备清单是平台事实，校验在 [`TargetFormat`] 侧）
    pub const fn new(sample_rate: u32, channels: u16, sample: SampleFormat) -> Self {
        Self {
            sample_rate,
            channels,
            sample,
        }
    }

    /// 一帧（所有声道各一个样本）占几字节
    pub const fn bytes_per_frame(self) -> usize {
        self.channels as usize * self.sample.sample_size()
    }
}

/// 产出侧格式：帧环里字节的解释方式（样本宽度恒为交错 S16LE）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetFormat {
    /// 目标采样率（Hz）
    pub sample_rate: u32,
    /// 目标声道数（1 或 2）
    pub channels: u16,
}

/// 语音识别通用档位：16 kHz 单声道（缺省档，ASR 模型的常见输入）
pub const SPEECH_16K_MONO: TargetFormat = TargetFormat {
    sample_rate: 16_000,
    channels: 1,
};

impl Default for TargetFormat {
    fn default() -> Self {
        SPEECH_16K_MONO
    }
}

impl TargetFormat {
    /// 构造目标格式（**校验一次**：采样率区间 + 声道数区间，越界即
    /// [`AudioError::InvalidConfig`]，不夹取）
    ///
    /// # Errors
    /// [`AudioError::InvalidConfig`] —— 采样率落在 [`MIN_SAMPLE_RATE`]..=
    /// [`MAX_SAMPLE_RATE`] 之外，或声道数为 0 / 超 [`MAX_TARGET_CHANNELS`]。
    pub fn new(sample_rate: u32, channels: u16) -> Result<Self, AudioError> {
        if !(MIN_SAMPLE_RATE..=MAX_SAMPLE_RATE).contains(&sample_rate) {
            return Err(AudioError::InvalidConfig {
                reason: format!(
                    "targetSampleRate {sample_rate} is outside {MIN_SAMPLE_RATE}..={MAX_SAMPLE_RATE} Hz"
                ),
            });
        }
        if channels == 0 || channels > MAX_TARGET_CHANNELS {
            return Err(AudioError::InvalidConfig {
                reason: format!("targetChannels {channels} is outside 1..={MAX_TARGET_CHANNELS}"),
            });
        }
        Ok(Self {
            sample_rate,
            channels,
        })
    }

    /// 产出侧每帧字节数（S16LE = 2 字节 / 声道）
    pub const fn bytes_per_frame(self) -> usize {
        self.channels as usize * SampleFormat::S16.sample_size()
    }

    /// 若干产出字节等于多少毫秒（向上取整到毫秒）
    pub fn duration_ms(self, bytes: usize) -> u64 {
        let frames = bytes / self.bytes_per_frame();
        // 先除后乘会丢精度，故按 1000 倍帧数除采样率
        (frames as u64 * 1_000).div_ceil(self.sample_rate as u64)
    }

    /// 一个时长窗口对应多少样本（每声道计数，用于电平窗口）
    pub fn samples_for_ms(self, ms: u32) -> usize {
        (self.sample_rate as usize * ms as usize) / 1_000
    }
}

/// 一次回调交出的 PCM 数据（借用后端切片，零拷贝进管线）
#[derive(Debug, Clone, Copy)]
pub enum PcmBuffer<'a> {
    /// 交织的 `s16` 样本
    S16(&'a [i16]),
    /// 交织的 `f32` 样本（约定 ±1.0 满刻度）
    F32(&'a [f32]),
}

impl<'a> PcmBuffer<'a> {
    /// 样本总数（各声道合计，非帧数）
    pub fn sample_count(&self) -> usize {
        match self {
            Self::S16(s) => s.len(),
            Self::F32(s) => s.len(),
        }
    }

    /// 该缓冲是否空
    pub fn is_empty(&self) -> bool {
        self.sample_count() == 0
    }

    /// 解码成 `[-1.0, 1.0]` 的 f32 交织序列写进 `out`（`out` 由调用方复用）
    ///
    /// `s16` 按 `/ 32768.0` 归一（负满刻度精确落到 -1.0）；正满刻度 32767 落在
    /// `-1.0..1.0` 内，不做「补偿放大」——那是产品侧的增益策略。
    pub fn decode_into(&self, out: &mut Vec<f32>) {
        out.clear();
        match self {
            Self::S16(samples) => {
                out.reserve(samples.len());
                out.extend(samples.iter().map(|&s| f32::from(s) / 32_768.0));
            }
            Self::F32(samples) => {
                out.extend_from_slice(samples);
            }
        }
    }

    /// 缓冲自身的样本宽度
    pub const fn sample_format(&self) -> SampleFormat {
        match self {
            Self::S16(_) => SampleFormat::S16,
            Self::F32(_) => SampleFormat::F32,
        }
    }
}

/// 重采样策略（扩展位）
///
/// 实现方按「每声道平面独立一份实例」被调用（[`PcmNormalizer`] 为每个目标声道各造一份，
/// 相位互不干扰）。输入是单声道 f32 平面，输出写进调用方给的 `out`。
///
/// 契约：
/// - 同一实例的多次 `resample` 调用描述**同一条时间线**（跨块必须相位连续，不得每块
///   从头对齐——否则每个回调边界都会跳变，ASR 侧表现为周期性毛刺）；
/// - `out` 先被清空再写入，长度即本次产出样本数；
/// - 不得阻塞、不得 IO（调用发生在设备采集线程上）。
pub trait Resampler: Send + Sync + 'static {
    /// 重采样一个声道平面
    fn resample(&mut self, input: &[f32], input_rate: u32, output_rate: u32, out: &mut Vec<f32>);

    /// 复位相位（新一轮采集开始时调用；保留历史样本语义由实现自定）
    fn reset(&mut self);
}

/// 线性插值重采样（默认策略）
///
/// 跨块相位连续的实现要点：内部记「全局输入样本序号」与「下一个待产出样本的序号」，
/// 需要但本块还没有的样本一律**留到下一块**再产出，故任意块边界切分都不改变输出序列
/// （性质测试：一次喂全量 vs 分块喂，结果逐样本相等）。
#[derive(Debug, Default)]
pub struct LinearResampler {
    /// 已交给本实例的全局输入样本总数（= 下一块首样本的全局序号）
    consumed: u64,
    /// 下一块首样本的前一个样本（跨界插值用）
    history: Option<f32>,
    /// 下一个待产出样本的序号
    next_output: u64,
}

impl Resampler for LinearResampler {
    fn resample(&mut self, input: &[f32], input_rate: u32, output_rate: u32, out: &mut Vec<f32>) {
        out.clear();
        if input.is_empty() || input_rate == 0 || output_rate == 0 {
            return;
        }
        if input_rate == output_rate {
            out.extend_from_slice(input);
            self.history = input.last().copied();
            self.consumed += input.len() as u64;
            self.next_output += input.len() as u64;
            return;
        }

        let start = self.consumed;
        let end = start + input.len() as u64;
        // 每个产出样本需要 `ratio` 个输入样本跨度，且必须能取到 pos 与其后一个样本
        let ratio = f64::from(input_rate) / f64::from(output_rate);
        let at = |global: u64| -> f32 {
            if global + 1 == start {
                // 唯一可能落到上一块的索引就是 start-1
                self.history.unwrap_or(input[0])
            } else {
                input[(global - start) as usize]
            }
        };
        loop {
            let pos = self.next_output as f64 * ratio;
            // 需要 pos 与其后一个样本都落在本块内（`[start, end)`）：严格小于 end-1，
            // 即 pos + 1 < end。写成 `<= end` 会让 lower + 1 == end 越界读取。
            if pos + 1.0 >= end_u64_to_f64(end) {
                break;
            }
            let lower = pos.floor() as u64;
            let frac = (pos - lower as f64) as f32;
            let (a, b) = (at(lower), at(lower + 1));
            out.push(a + (b - a) * frac);
            self.next_output += 1;
        }
        self.history = input.last().copied();
        self.consumed = end;
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// `u64` 到 `f64` 的显式转换（音频时长计数远不到 2^53，越界即视为不可能并断言）
fn end_u64_to_f64(value: u64) -> f64 {
    debug_assert!(
        value <= (1u64 << 53),
        "audio sample counters exceeded 2^53, f64 position math would lose precision: {value}"
    );
    value as f64
}

/// 重采样器工厂（每个目标声道一份实例，故必须是可重复调用的工厂而非单个实例）
pub type ResamplerFactory = std::sync::Arc<dyn Fn() -> Box<dyn Resampler> + Send + Sync>;

/// PCM 归一器：设备格式 → 交错 S16LE 目标字节
///
/// 一份实例服务**一条采集流**（内部缓冲与重采样相位都是该流的时间线状态），
/// 因此不是 `Sync`：它只在设备采集线程上被 [`PcmNormalizer::process`] 调用。
pub struct PcmNormalizer {
    target: TargetFormat,
    /// 解码后的交织 f32
    interleaved: Vec<f32>,
    /// 每目标声道一份：混音输出平面
    mix_planes: Vec<Vec<f32>>,
    /// 每目标声道一份：重采样输出平面
    resampled: Vec<Vec<f32>>,
    resamplers: Vec<Box<dyn Resampler>>,
}

impl fmt::Debug for PcmNormalizer {
    // `dyn Resampler` 不要求 Debug（策略实现无需为日志付出代价），故手写并只报策略数
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcmNormalizer")
            .field("target", &self.target)
            .field("resamplers", &self.resamplers.len())
            .finish_non_exhaustive()
    }
}

impl PcmNormalizer {
    /// 用默认 [`LinearResampler`] 造归一器
    pub fn new(target: TargetFormat) -> Self {
        Self::with_resampler(
            target,
            std::sync::Arc::new(|| Box::new(LinearResampler::default())),
        )
    }

    /// 指定重采样策略造归一器（高质量重采样 / 恒定速率快路径等替换点）
    pub fn with_resampler(target: TargetFormat, factory: ResamplerFactory) -> Self {
        let channels = usize::from(target.channels);
        Self {
            target,
            interleaved: Vec::new(),
            mix_planes: vec![Vec::new(); channels],
            resampled: vec![Vec::new(); channels],
            resamplers: (0..channels).map(|_| factory()).collect(),
        }
    }

    /// 目标格式
    pub const fn target(&self) -> TargetFormat {
        self.target
    }

    /// 复位各声道重采样相位（新一轮采集开始时由引擎调用）
    pub fn reset(&mut self) {
        for resampler in &mut self.resamplers {
            resampler.reset();
        }
    }

    /// 归一一块数据，把交错 S16LE 字节写进 `out`
    ///
    /// `input_format.channels` 与缓冲实际样本数不符（畸形后端）时按 `max(1, channels)`
    /// 处理并保持字节数一致——宁可产出「声道解释不同的同一批样本」，也不 panic：
    /// 采集线程上的 panic 会带走整条宿主流。
    ///
    /// # Panics
    /// 不会 panic（本函数在设备回调线程上执行，见模块文档红线）。
    pub fn process(&mut self, input_format: PcmFormat, buffer: &PcmBuffer<'_>, out: &mut Vec<u8>) {
        out.clear();
        let source_channels = usize::from(input_format.channels).max(1);
        let total = buffer.sample_count();
        if total == 0 {
            for plane in &mut self.mix_planes {
                plane.clear();
            }
            return;
        }
        // 样本总数不是声道数的整数倍（畸形输入）：只处理完整帧，尾样本次丢弃并计入日志面
        let frames = total / source_channels;
        if frames == 0 {
            return;
        }
        let usable = frames * source_channels;

        self.interleaved.clear();
        self.interleaved.reserve(usable);
        buffer.decode_into(&mut self.interleaved);
        self.interleaved.truncate(usable);

        self.mix_to_planes(frames, source_channels);

        // 重采样（同速率走快路径：不调用策略，避免任何实现的舍入差异）
        //
        // 按字段解构借用：`mix_planes`（只读）与 `resampled` / `resamplers`（写）是
        // 不同字段，解构后编译器按字段粒度放行——于是重采样路径**零拷贝**，
        // 「稳态零分配」在采集线程上是真的（写成 `mixed.clone()` 会是每块一次堆分配）。
        let plane_count = self.target.channels as usize;
        let target_rate = self.target.sample_rate;
        let Self {
            mix_planes,
            resampled,
            resamplers,
            ..
        } = self;
        for plane_index in 0..plane_count {
            let (mixed, sink) = (&mix_planes[plane_index], &mut resampled[plane_index]);
            if input_format.sample_rate == target_rate {
                sink.clear();
                sink.extend_from_slice(mixed);
            } else {
                resamplers[plane_index].resample(
                    mixed,
                    input_format.sample_rate,
                    target_rate,
                    sink,
                );
            }
        }

        encode_s16_interleaved(resampled, out);
    }

    /// 交织 f32 → 目标声道平面（混音规则见下方注释，是机制不是产品策略）
    fn mix_to_planes(&mut self, frames: usize, source_channels: usize) {
        let plane_count = self.target.channels as usize;
        for plane in &mut self.mix_planes {
            plane.clear();
            plane.reserve(frames);
        }
        if source_channels == plane_count {
            // 声道一一对应：直接抽平面
            for plane_index in 0..plane_count {
                let plane = &mut self.mix_planes[plane_index];
                plane.extend(
                    self.interleaved
                        .chunks_exact(source_channels)
                        .map(|frame| frame[plane_index]),
                );
            }
            return;
        }
        if plane_count == 1 {
            // 目标单声道：所有源声道求均值
            let plane = &mut self.mix_planes[0];
            plane.extend(
                self.interleaved
                    .chunks_exact(source_channels)
                    .map(|frame| frame.iter().sum::<f32>() / source_channels as f32),
            );
            return;
        }
        if source_channels == 1 {
            // 源单声道、目标多声道：复制
            for plane in &mut self.mix_planes {
                plane.extend_from_slice(&self.interleaved[..frames]);
            }
            return;
        }
        // 其余情形（如 4 → 2）：源声道按目标声道数**连续分组求均值**——
        // 不猜设备语义（哪两个是前置 / 环绕），只做等分下混。
        for plane_index in 0..plane_count {
            let group_start = plane_index * source_channels / plane_count;
            let group_end =
                ((plane_index + 1) * source_channels / plane_count).max(group_start + 1);
            let divisor = (group_end - group_start) as f32;
            let plane = &mut self.mix_planes[plane_index];
            plane.extend(
                self.interleaved
                    .chunks_exact(source_channels)
                    .map(|frame| frame[group_start..group_end].iter().sum::<f32>() / divisor),
            );
        }
    }
}

/// 交错编码成 S16LE 字节（平面 → 帧 → 小端字节），超出 ±1.0 的样本**削顶**
///
/// 削顶而不是取模：`f32` 设备在 AGC 打开时可能交出 >1.0 的样本，取模会产出反相的
/// 爆音，削顶只是失真。
fn encode_s16_interleaved(planes: &[Vec<f32>], out: &mut Vec<u8>) {
    let frames = planes.iter().map(Vec::len).min().unwrap_or(0);
    out.reserve(frames * planes.len() * SampleFormat::S16.sample_size());
    for frame in 0..frames {
        for plane in planes {
            // 32768 刻度与解码侧 `/ 32768.0` 互逆：s16 输入经归一往返后逐样本相等
            // （32767 刻度会让每个样本偏移 1，且 -1.0 无法回到 -32768）。
            let sample = (plane[frame] * 32_768.0).clamp(-32_768.0, 32_767.0) as i16;
            out.extend_from_slice(&sample.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s16_bytes(samples: &[i16]) -> Vec<u8> {
        let mut out = Vec::new();
        for &s in samples {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out
    }

    /// 目标格式校验：区间两端可构造，越界点名字段名与允许区间（不夹取）
    #[test]
    fn target_format_validates_ranges_without_clamping() {
        assert_eq!(
            TargetFormat::new(MIN_SAMPLE_RATE, 1).unwrap().sample_rate,
            MIN_SAMPLE_RATE
        );
        assert_eq!(
            TargetFormat::new(MAX_SAMPLE_RATE, MAX_TARGET_CHANNELS)
                .unwrap()
                .channels,
            MAX_TARGET_CHANNELS
        );
        for bad_rate in [7_999, 0, MAX_SAMPLE_RATE + 1] {
            let err = TargetFormat::new(bad_rate, 1).unwrap_err().to_string();
            assert!(
                err.contains("targetSampleRate") && err.contains(&bad_rate.to_string()),
                "错误必须点名字段与越界值，实得 {err}"
            );
        }
        for bad_channels in [0u16, MAX_TARGET_CHANNELS + 1, 8] {
            let err = TargetFormat::new(16_000, bad_channels)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("targetChannels") && err.contains(&bad_channels.to_string()),
                "错误必须点名字段与越界值，实得 {err}"
            );
        }
    }

    /// 缺省档 = ASR 通用档位（16k 单声道）
    #[test]
    fn default_target_is_the_speech_preset() {
        assert_eq!(TargetFormat::default(), SPEECH_16K_MONO);
        assert_eq!(SPEECH_16K_MONO.bytes_per_frame(), 2);
    }

    /// 时长换算：16k 单声道 32000 字节 = 1000 ms；不足一帧按 0 计
    #[test]
    fn duration_ms_rounds_up_to_the_millisecond() {
        assert_eq!(SPEECH_16K_MONO.duration_ms(32_000), 1_000);
        // 16k 单声道 s16 = 32 字节/ms ⇒ 320 字节 = 10 ms
        assert_eq!(SPEECH_16K_MONO.duration_ms(320), 10);
        assert_eq!(SPEECH_16K_MONO.duration_ms(1), 0);
        assert_eq!(
            TargetFormat::new(48_000, 2)
                .unwrap()
                .duration_ms(48_000 * 2 * 2),
            1_000
        );
    }

    /// s16 解码满刻度：-32768 → -1.0，32767 → 接近 +1.0（不做补偿放大）
    #[test]
    fn decode_maps_full_scale() {
        let mut out = Vec::new();
        PcmBuffer::S16(&[-32_768, 0, 32_767]).decode_into(&mut out);
        assert_eq!(out[0], -1.0);
        assert_eq!(out[1], 0.0);
        assert!((out[2] - 0.999_969_5).abs() < 1e-6, "实得 {}", out[2]);
    }

    /// 同速率同声道：产出字节 == 输入字节的 s16 形态（快路径不引入任何数值变化）
    #[test]
    fn passthrough_when_rates_and_channels_match() {
        let samples = [-32_768i16, -1, 0, 1, 1_000, 32_767];
        let mut normalizer = PcmNormalizer::new(SPEECH_16K_MONO);
        let mut out = Vec::new();
        normalizer.process(
            PcmFormat::new(16_000, 1, SampleFormat::S16),
            &PcmBuffer::S16(&samples),
            &mut out,
        );
        assert_eq!(out, s16_bytes(&samples));
    }

    /// f32 → s16：±1.0 满刻度映射，超出部分削顶而不是回绕
    #[test]
    fn f32_encodes_with_clamping_not_wraparound() {
        let mut normalizer = PcmNormalizer::new(SPEECH_16K_MONO);
        let mut out = Vec::new();
        normalizer.process(
            PcmFormat::new(16_000, 1, SampleFormat::F32),
            &PcmBuffer::F32(&[1.0, -1.0, 2.5, -8.0, 0.5]),
            &mut out,
        );
        assert_eq!(out, s16_bytes(&[32_767, -32_768, 32_767, -32_768, 16_384]));
    }

    /// 立体声 → 单声道：逐帧求均值
    #[test]
    fn downmix_to_mono_averages_channels() {
        let mut normalizer = PcmNormalizer::new(SPEECH_16K_MONO);
        let mut out = Vec::new();
        normalizer.process(
            PcmFormat::new(16_000, 2, SampleFormat::S16),
            &PcmBuffer::S16(&[1_000, 3_000, -2_000, 0]),
            &mut out,
        );
        assert_eq!(out, s16_bytes(&[2_000, -1_000]));
    }

    /// 单声道 → 立体声：左右复制（不猜「哪个声道该有信号」）
    #[test]
    fn upmix_stereo_duplicates_the_mono_plane() {
        let stereo = TargetFormat::new(16_000, 2).unwrap();
        let mut normalizer = PcmNormalizer::new(stereo);
        let mut out = Vec::new();
        normalizer.process(
            PcmFormat::new(16_000, 1, SampleFormat::S16),
            &PcmBuffer::S16(&[500, -500]),
            &mut out,
        );
        assert_eq!(out, s16_bytes(&[500, 500, -500, -500]));
    }

    /// 四声道 → 二声道：源声道连续分组均值（等分下混，不解释设备语义）
    #[test]
    fn quadrophonic_groups_are_averaged() {
        let stereo = TargetFormat::new(16_000, 2).unwrap();
        let mut normalizer = PcmNormalizer::new(stereo);
        let mut out = Vec::new();
        normalizer.process(
            PcmFormat::new(16_000, 4, SampleFormat::S16),
            &PcmBuffer::S16(&[0, 0, 100, 100, 200, 200, 300, 300]),
            &mut out,
        );
        // 组一 = 声道 0,1（每帧 0 与 200）→ 均值 0, 200；组二 = 声道 2,3 → 均值 100, 300
        assert_eq!(out, s16_bytes(&[0, 100, 200, 300]));
    }

    /// 跨块相位连续性：一次喂全量与分块喂必须产出逐样本相同的结果
    ///
    /// 这是 48k → 16k 的关键性质。若每个回调都从头对齐，块边界会出现采样位置跳变，
    /// ASR 侧表现为周期性毛刺。
    #[test]
    fn linear_resampling_is_block_boundary_independent() {
        let plane: Vec<f32> = (0..601).map(|i| (i as f32 * 0.05).sin()).collect();
        let mut whole = Vec::new();
        LinearResampler::default().resample(&plane, 48_000, 16_000, &mut whole);

        let mut chunked = Vec::new();
        let mut resampler = LinearResampler::default();
        let mut scratch = Vec::new();
        for chunk in plane.chunks(97) {
            resampler.resample(chunk, 48_000, 16_000, &mut scratch);
            chunked.extend_from_slice(&scratch);
        }
        assert_eq!(
            chunked,
            whole,
            "分块与整块产出必须一致（块数 {}",
            plane.len() / 97 + 1
        );
        // 48k → 16k 是 1/3 抽取：601 个输入样本至少产出 200 个输出样本
        assert!(
            whole.len() >= 200 && whole.len() <= 201,
            "输出长度应约等于输入的 1/3，实得 {}",
            whole.len()
        );
    }

    /// 同速率快路径：重采样器完全不被调用（避免任何实现引入的舍入）
    #[test]
    fn same_rate_skips_the_resampler() {
        struct Fail;
        impl Resampler for Fail {
            fn resample(&mut self, _: &[f32], _: u32, _: u32, out: &mut Vec<f32>) {
                out.push(999.0);
            }
            fn reset(&mut self) {}
        }
        let mut normalizer =
            PcmNormalizer::with_resampler(SPEECH_16K_MONO, std::sync::Arc::new(|| Box::new(Fail)));
        let mut out = Vec::new();
        normalizer.process(
            PcmFormat::new(16_000, 1, SampleFormat::S16),
            &PcmBuffer::S16(&[1_000, 2_000]),
            &mut out,
        );
        assert_eq!(out, s16_bytes(&[1_000, 2_000]));
    }

    /// 48k 立体声 f32（Windows 共享模式典型）→ 16k 单声道 s16：字节数与时长自洽
    #[test]
    fn windows_typical_stereo_f32_lands_as_mono_s16() {
        let stereo = TargetFormat::new(16_000, 1).unwrap();
        let mut normalizer = PcmNormalizer::new(stereo);
        let mut out = Vec::new();
        let frames = 480usize; // 10 ms @ 48k
        let buffer: Vec<f32> = (0..frames * 2).map(|i| ((i % 2) as f32) * 0.25).collect();
        normalizer.process(
            PcmFormat::new(48_000, 2, SampleFormat::F32),
            &PcmBuffer::F32(&buffer),
            &mut out,
        );
        // 10 ms @ 16k 单声道 = 160 帧 = 320 字节（线性重采样允许 ±2 帧）
        assert!(
            out.len() % 2 == 0 && (158..=162).contains(&(out.len() / 2)),
            "产出帧数异常：{} 字节",
            out.len()
        );
    }

    /// 畸形输入（空缓冲 / 样本数不足一帧）产出空字节，绝不 panic
    #[test]
    fn malformed_input_produces_nothing_and_never_panics() {
        let mut normalizer = PcmNormalizer::new(SPEECH_16K_MONO);
        let mut out = vec![7u8];
        normalizer.process(
            PcmFormat::new(16_000, 2, SampleFormat::S16),
            &PcmBuffer::S16(&[]),
            &mut out,
        );
        assert!(out.is_empty(), "空缓冲必须清空输出");
        // 立体声只给 1 个样本（不足一帧）
        normalizer.process(
            PcmFormat::new(16_000, 2, SampleFormat::S16),
            &PcmBuffer::S16(&[1_000]),
            &mut out,
        );
        assert!(out.is_empty(), "不足一帧的尾样本必须丢弃而不是补零");
    }
}
