//! PCM 机制：S16LE ↔ f32、时长换算、输入形状校验
//!
//! 本域只认 16 kHz 单声道交错 S16LE 裸字节（无容器头）。容器解码与采样率转换
//! 由调用方（应用层 / host-audio 归一）完成。

/// 本域固定的采样率（Hz）
pub const SAMPLE_RATE: u32 = 16_000;

/// 本域固定的声道数
pub const CHANNELS: u16 = 1;

/// S16 样本宽度（字节）
pub const SAMPLE_WIDTH: usize = 2;

/// 把交错 S16LE 字节转成 whisper 需要的 f32 样本（-1.0..=1.0）
///
/// 偶数长度由调用方保证（会话 append 已校验）；这里对尾部奇数字节做丢弃，
/// 不 panic（纯函数对坏输入只做「可解释的截断」）。
pub fn s16le_to_f32(pcm: &[u8]) -> Vec<f32> {
    pcm.as_chunks::<SAMPLE_WIDTH>()
        .0
        .iter()
        .map(|chunk| f32::from(i16::from_le_bytes(*chunk)) / 32768.0)
        .collect()
}

/// 校验 PCM 形状：偶数长度；采样率 / 声道数必须是本域固定值
pub fn validate_pcm(sample_rate: u32, channels: u16, byte_len: usize) -> crate::Result<()> {
    if sample_rate != SAMPLE_RATE {
        return Err(crate::error::SttError::InvalidOptions(format!(
            "sample rate must be {SAMPLE_RATE} Hz, got {sample_rate}"
        )));
    }
    if channels != CHANNELS {
        return Err(crate::error::SttError::InvalidOptions(format!(
            "channel count must be {CHANNELS}, got {channels}"
        )));
    }
    if !byte_len.is_multiple_of(SAMPLE_WIDTH) {
        return Err(crate::error::SttError::OddPcmLength(byte_len));
    }
    Ok(())
}

/// PCM 字节对应的毫秒时长（16 kHz 单声道 S16）
pub fn duration_ms(byte_len: usize) -> u64 {
    let samples = (byte_len / SAMPLE_WIDTH) as u64;
    samples * 1_000 / u64::from(SAMPLE_RATE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_s16le_to_normalized_f32() {
        let pcm = [0x00, 0x00, 0xFF, 0x7F, 0x00, 0x80];
        let samples = s16le_to_f32(&pcm);
        assert_eq!(samples.len(), 3);
        assert_eq!(samples[0], 0.0);
        assert!((samples[1] - (32767.0 / 32768.0)).abs() < 1e-6);
        assert_eq!(samples[2], -1.0);
    }

    #[test]
    fn ignores_trailing_odd_byte() {
        let samples = s16le_to_f32(&[0x01, 0x00, 0x02]);
        assert_eq!(samples.len(), 1);
    }

    #[test]
    fn validates_format() {
        assert!(validate_pcm(16_000, 1, 32).is_ok());
        assert!(validate_pcm(48_000, 1, 32).is_err());
        assert!(validate_pcm(16_000, 2, 32).is_err());
        assert!(validate_pcm(16_000, 1, 31).is_err());
    }

    #[test]
    fn computes_duration() {
        assert_eq!(duration_ms(32_000), 1_000);
        assert_eq!(duration_ms(0), 0);
    }
}
