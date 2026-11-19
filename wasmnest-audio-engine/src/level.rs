//! 电平计（窗口 RMS + 峰值，供 UI 指示与「有没有在录」判定）
//!
//! ## 为什么需要它
//!
//! 采集侧最容易出问题的是**静音失败**：权限被拒、设备被独占、路由切走但流还活着——
//! 这些情况下帧环里全是零字节，插件按游标拉得到数据却听不出「是环境安静」还是「根本没进声」。
//! 电平是**机制层可判定**的最小信号，不属于产品语义（它不判断「有没有人说话」——那是 VAD，
//! 明确不在本域范围）。
//!
//! ## 形状
//!
//! - 观察对象是**归一后的产出字节**（交错 S16LE），不是设备原生数据：电平因此与目标
//!   格式一致（同一个消费者拉到的字节就是被测量的字节），后端差异不改变读数含义。
//! - 滑窗按**帧**计数（窗口长度由调用方按时长换算，见 `engine::AudioLimits::meter_window_ms`），
//!   窗内 RMS 用累计平方和 O(1) 得出；峰值需扫描窗口（窗长上限 ≈ 1 秒，量级 ≤ 数千项，
//!   发生在消费者线程而非采集线程）。
//! - **零分配稳态**：窗口条目是 `VecDeque` 复用，`observe` 不新分配。
//!
//! 归一约定：`i16` 满刻度映射到 `[-1.0, 1.0]`，故 `rms` / `peak` 天然落在 `0.0..=1.0`。

use std::collections::VecDeque;

/// 窗内电平读数（对应 WIT `level-snapshot`）
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LevelSnapshot {
    /// 均方根电平（0.0..=1.0）
    pub rms: f32,
    /// 窗口内峰值绝对值（0.0..=1.0）
    pub peak: f32,
    /// 参与本次统计的样本数（各声道合计；0 表示窗口内还没数据）
    pub window_samples: u32,
}

/// 一帧的统计量：平方和 + 帧内峰值绝对值
#[derive(Debug, Clone, Copy, Default)]
struct FrameLevel {
    sum_sq: f64,
    peak: f64,
}

/// 滑窗电平计
pub struct LevelMeter {
    /// 窗口帧数（≥1）
    window_frames: usize,
    /// 每帧统计量（队首最旧）
    frames: VecDeque<FrameLevel>,
    /// 窗内平方和（O(1) RMS 的来源）
    sum_sq: f64,
    /// 声道数（最近一次 `observe` 使用；用于把帧数换算成样本数）
    channels: u16,
}

impl LevelMeter {
    /// 以窗口帧数构造（0 按 1 帧处理：零长窗口没有可观测含义，不做静默失效）
    pub fn new(window_frames: usize) -> Self {
        Self {
            window_frames: window_frames.max(1),
            frames: VecDeque::new(),
            sum_sq: 0.0,
            channels: 1,
        }
    }

    /// 窗口帧数（可观测面，装配 / 测试用）
    pub const fn window_frames(&self) -> usize {
        self.window_frames
    }

    /// 观察一段归一产出（交错 S16LE 字节）
    ///
    /// 尾随不足一帧的字节被忽略（不猜测半样本）；`channels` 为 0 时同样直接返回——
    /// 两者都是「调用方给的东西解释不了」的退化输入，电平计对此**不做报警**，
    /// 因为它的正确性不依赖输入合法（数据面另有校验）。
    pub fn observe(&mut self, s16le_interleaved: &[u8], channels: u16) {
        if channels == 0 {
            return;
        }
        let bytes_per_frame = channels as usize * 2;
        let frame_count = s16le_interleaved.len() / bytes_per_frame;
        if frame_count == 0 {
            return;
        }
        self.channels = channels;
        for frame in
            s16le_interleaved[..frame_count * bytes_per_frame].chunks_exact(bytes_per_frame)
        {
            let mut level = FrameLevel::default();
            for sample in frame.as_chunks::<2>().0 {
                let raw = i16::from_le_bytes([sample[0], sample[1]]) as f64 / 32768.0;
                let abs = raw.abs();
                level.sum_sq += raw * raw;
                if abs > level.peak {
                    level.peak = abs;
                }
            }
            self.sum_sq += level.sum_sq;
            self.frames.push_back(level);
            while self.frames.len() > self.window_frames {
                if let Some(evicted) = self.frames.pop_front() {
                    self.sum_sq -= evicted.sum_sq;
                }
            }
        }
    }

    /// 当前窗口读数；窗口内还没有任何帧时返回 `None`
    ///
    /// 返回 `None` 而不是全零，是为了让「没采到东西」与「采到了静音」在调用方那里
    /// 是两个不同的事实（前者通常意味着还没 `start`，后者意味着链路通但环境安静）。
    pub fn snapshot(&self) -> Option<LevelSnapshot> {
        let frames = self.frames.len();
        if frames == 0 {
            return None;
        }
        let samples = frames as u64 * self.channels as u64;
        // 浮点累计可能因舍入略微越界，故两端钳位（钳位是表示层修正，不是策略夹取）
        let rms = (self.sum_sq / samples as f64).sqrt().clamp(0.0, 1.0) as f32;
        let peak = self
            .frames
            .iter()
            .fold(0.0f64, |acc, frame| acc.max(frame.peak))
            .clamp(0.0, 1.0) as f32;
        Some(LevelSnapshot {
            rms,
            peak,
            window_samples: samples.min(u32::MAX as u64) as u32,
        })
    }

    /// 复位（丢弃窗口与累计量）
    ///
    /// 由 `start` 调用：重启后的电平不应被上一段会话的余音拉平（`resume` 语义见
    /// `engine`——复位窗口但**不**复位帧环偏移）。
    pub fn reset(&mut self) {
        self.frames.clear();
        self.sum_sq = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::LevelMeter;

    /// 交错 S16LE 编码（测试专用，一行一帧）
    fn s16le(samples: &[i16]) -> Vec<u8> {
        samples.iter().flat_map(|s| s.to_le_bytes()).collect()
    }

    const FULL_SCALE: f32 = 1.0;
    const NEAR_FULL: i16 = 32767;

    /// L-001 反例：窗口还没数据时必须是 `None`，不能报「静音」
    #[test]
    fn empty_window_is_absence_not_silence() {
        let mut meter = LevelMeter::new(10);
        assert!(meter.snapshot().is_none(), "未采集不得伪装成 0 电平");
        meter.observe(&[], 1);
        assert!(meter.snapshot().is_none());
    }

    /// L-002 正例：满刻度方波 ⇒ rms / peak 都是满刻度
    #[test]
    fn full_scale_square_reads_max() {
        let mut meter = LevelMeter::new(64);
        meter.observe(&s16le(&[NEAR_FULL; 32]), 1);
        let snapshot = meter.snapshot().expect("已观察");
        assert!(
            (snapshot.rms - 0.99997).abs() < 1e-3,
            "rms 应接近满刻度，实得 {}",
            snapshot.rms
        );
        assert!((snapshot.peak - FULL_SCALE).abs() < 1e-3);
        assert_eq!(snapshot.window_samples, 32);
    }

    /// L-003 正例：静音 ⇒ 两个读数都是 0，且**有**读数（与 L-001 的缺席区分开）
    #[test]
    fn silence_reads_zero_but_is_present() {
        let mut meter = LevelMeter::new(16);
        meter.observe(&s16le(&[0; 8]), 1);
        let snapshot = meter.snapshot().expect("静音也有读数");
        assert_eq!((snapshot.rms, snapshot.peak), (0.0, 0.0));
    }

    /// L-004 正例：正弦的 rms ≈ peak / √2（这是 rms 定义的可执行判据）
    #[test]
    fn sine_rms_is_peak_over_root_two() {
        let mut meter = LevelMeter::new(1_000);
        let mut samples = Vec::new();
        for i in 0..640 {
            let t = i as f64 / 640.0 * std::f64::consts::TAU * 8.0; // 8 个整周期
            samples.push((t.sin() * 32_000.0) as i16);
        }
        meter.observe(&s16le(&samples), 1);
        let snapshot = meter.snapshot().expect("已观察");
        let ratio = snapshot.rms / snapshot.peak;
        assert!(
            (ratio - std::f32::consts::FRAC_1_SQRT_2).abs() < 0.02,
            "正弦 rms/peak 应≈0.707，实得 {ratio}"
        );
    }

    /// L-005 滑窗：超出窗口的旧帧被淘汰，读数回落到近期水平
    #[test]
    fn window_slides_out_old_frames() {
        let mut meter = LevelMeter::new(4);
        assert_eq!(meter.window_frames(), 4);
        // 先灌满 4 帧满刻度，再灌 4 帧静音：窗口只剩静音
        meter.observe(&s16le(&[NEAR_FULL; 4]), 1);
        assert!(meter.snapshot().expect("有读数").rms > 0.9);
        meter.observe(&s16le(&[0; 4]), 1);
        let after = meter.snapshot().expect("有读数");
        assert_eq!(after.window_samples, 4, "窗口只剩 4 帧");
        assert!(after.rms < 1e-6, "旧的高电平必须被淘汰，实得 {}", after.rms);
    }

    /// L-006 一次观察跨多帧也要正确淘汰（窗口边界不是观察边界）
    #[test]
    fn eviction_happens_inside_a_multi_frame_observe() {
        let mut meter = LevelMeter::new(2);
        meter.observe(&s16le(&[1_000, NEAR_FULL, 0, 0, 0, 0]), 1);
        let snapshot = meter.snapshot().expect("有读数");
        assert_eq!(snapshot.window_samples, 2);
        assert_eq!(snapshot.peak, 0.0, "最后两帧是静音");
    }

    /// L-007 立体声：逐帧取两声道，样本数按声道累计，峰值取两声道最大
    #[test]
    fn stereo_counts_both_planes() {
        let mut meter = LevelMeter::new(8);
        // 帧 = (左, 右)：左声道静音，右声道满刻度
        meter.observe(&s16le(&[0, NEAR_FULL, 0, NEAR_FULL]), 2);
        let snapshot = meter.snapshot().expect("有读数");
        assert_eq!(snapshot.window_samples, 4, "2 帧 × 2 声道");
        assert!((snapshot.peak - FULL_SCALE).abs() < 1e-3);
        assert!(
            (snapshot.rms - 0.707).abs() < 0.02,
            "一半声道满刻度 ⇒ rms≈0.707"
        );
    }

    /// L-008 退化输入：半样本尾字节与 channels=0 被忽略且不 panic
    #[test]
    fn malformed_input_is_ignored() {
        let mut meter = LevelMeter::new(4);
        meter.observe(&[0x00, 0x40, 0x7f], 1);
        let first = meter.snapshot().expect("半帧外的 1 帧仍被统计");
        meter.observe(&[0x00; 1], 1);
        meter.observe(&s16le(&[1, 2]), 0);
        assert_eq!(
            meter.snapshot().expect("有读数").window_samples,
            first.window_samples,
            "无法解释的字节不得进窗口"
        );
    }

    /// L-009 复位清空窗口（重启语义）
    #[test]
    fn reset_clears_the_window() {
        let mut meter = LevelMeter::new(4);
        meter.observe(&s16le(&[NEAR_FULL; 4]), 1);
        assert!(meter.snapshot().is_some());
        meter.reset();
        assert!(meter.snapshot().is_none());
        meter.observe(&s16le(&[0; 2]), 1);
        assert_eq!(meter.snapshot().expect("有读数").window_samples, 2);
    }

    /// L-010 窗口为 0 的调用不得做成永久静默失效
    #[test]
    fn zero_window_degrades_to_one_frame() {
        let mut meter = LevelMeter::new(0);
        assert_eq!(meter.window_frames(), 1);
        meter.observe(&s16le(&[NEAR_FULL, 0]), 1);
        let snapshot = meter.snapshot().expect("窗口至少一帧");
        assert_eq!(snapshot.window_samples, 1, "只驻留最后一帧");
        assert_eq!(snapshot.peak, 0.0);
    }

    /// L-011 读数范围不变量：任意输入下 rms / peak 都落在 0..=1
    #[test]
    fn readings_stay_in_range() {
        let mut meter = LevelMeter::new(16);
        for i in 0..2_000i32 {
            let mut buf = Vec::new();
            for j in 0..8 {
                buf.extend_from_slice(&((i * 31 + j * 7) as i16).to_le_bytes());
            }
            meter.observe(&buf, 2);
            if let Some(snapshot) = meter.snapshot() {
                assert!((0.0..=1.0).contains(&snapshot.rms), "rms {}", snapshot.rms);
                assert!(
                    (0.0..=1.0).contains(&snapshot.peak),
                    "peak {}",
                    snapshot.peak
                );
                assert!(snapshot.window_samples > 0);
            }
        }
        assert_eq!(meter.window_frames(), 16);
    }
}
