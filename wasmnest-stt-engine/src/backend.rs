//! 推理后端边界：引擎只认 [`SttBackend`]，不认 whisper.cpp / 其它实现
//!
//! 输入是已经归一好的 16 kHz 单声道 S16LE 裸字节；后端返回全文与分段。
//! v1 的后端是同步阻塞调用——引擎把它放在后台线程里跑，wasm 侧只轮询任务。

use std::path::{Path, PathBuf};

/// 一段识别结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptSegment {
    /// 文本
    pub text: String,
    /// 起始毫秒
    pub start_ms: u64,
    /// 结束毫秒
    pub end_ms: u64,
}

/// 一次识别的结果
#[derive(Debug, Clone)]
pub struct Transcript {
    /// 全文（去掉首尾空白）
    pub text: String,
    /// 分段（v1 允许单段或多段；isFinal 恒为 true）
    pub segments: Vec<TranscriptSegment>,
    /// 实际识别语种（后端返回；未知为 None）
    pub language: Option<String>,
    /// 后端内部耗时（毫秒；0 表示由引擎补）
    pub elapsed_ms: u64,
}

/// 一次识别请求
#[derive(Debug, Clone)]
pub struct TranscribeRequest {
    /// 16 kHz 单声道 S16LE 裸字节
    pub pcm_s16le: Vec<u8>,
    /// 采样率（固定 16_000；由引擎校验）
    pub sample_rate: u32,
    /// 声道数（固定 1；由引擎校验）
    pub channels: u16,
    /// 语种（None = auto）
    pub language: Option<String>,
    /// 是否翻译成英文
    pub translate: bool,
    /// 初始提示（可空）
    pub prompt: Option<String>,
    /// 模型文件绝对路径（宿主已校验存在）
    pub model_path: PathBuf,
    /// 取消标志（后端可在推理循环中检查）
    pub cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// 后端失败分类 + 可读原因
#[derive(Debug, Clone, thiserror::Error)]
#[error("{kind}: {message}")]
pub struct BackendFailure {
    /// 稳定分类（进入 `job-status.error.kind`）
    pub kind: String,
    /// 可读原因
    pub message: String,
}

impl BackendFailure {
    /// 构造一个后端失败
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
        }
    }
}

/// 推理后端
pub trait SttBackend: Send + Sync {
    /// 识别一段 16 kHz 单声道 PCM
    fn transcribe(&self, request: &TranscribeRequest) -> Result<Transcript, BackendFailure>;

    /// 释放某模型路径的缓存资源（删除模型前调用；默认无缓存）
    ///
    /// 后端若持有模型文件句柄（如内存映射），必须在删除文件前丢弃它，
    /// 否则 Windows 上删除会因共享冲突失败、其他平台会留下陈旧缓存。
    fn release_model(&self, _model_path: &Path) {}
}

/// 可编排后端：无模型 / 无硬件环境下的端到端单测与开发自检
///
/// 不是生产后端；只在 `cfg(test)` 或 `test-util` feature 下编译。
#[cfg(any(test, feature = "test-util"))]
pub struct MockBackend {
    /// 模拟推理耗时（毫秒）
    pub delay_ms: u64,
    /// 固定返回文本
    pub text: String,
}

#[cfg(any(test, feature = "test-util"))]
impl MockBackend {
    /// 构造一个立即返回的 mock 后端
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            delay_ms: 0,
            text: text.into(),
        }
    }

    /// 构造一个带模拟耗时的 mock 后端
    pub fn with_delay(text: impl Into<String>, delay_ms: u64) -> Self {
        Self {
            delay_ms,
            text: text.into(),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl SttBackend for MockBackend {
    fn transcribe(&self, request: &TranscribeRequest) -> Result<Transcript, BackendFailure> {
        if request.pcm_s16le.is_empty() {
            return Err(BackendFailure::new("empty-audio", "no pcm bytes"));
        }
        let duration = crate::pcm::duration_ms(request.pcm_s16le.len());
        if self.delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(self.delay_ms));
        }
        if request.cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(BackendFailure::new("cancelled", "cancelled by caller"));
        }
        let text = self.text.clone();
        Ok(Transcript {
            segments: vec![TranscriptSegment {
                text: text.clone(),
                start_ms: 0,
                end_ms: duration,
            }],
            text,
            language: request
                .language
                .clone()
                .or_else(|| Some("auto".to_string())),
            elapsed_ms: self.delay_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    fn request(pcm_len: usize) -> TranscribeRequest {
        TranscribeRequest {
            pcm_s16le: vec![0; pcm_len],
            sample_rate: 16_000,
            channels: 1,
            language: Some("zh".to_string()),
            translate: false,
            prompt: None,
            model_path: PathBuf::from("/tmp/model.bin"),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn mock_returns_text_and_segment() {
        let backend = MockBackend::new("你好 world");
        let transcript = backend.transcribe(&request(32_000)).unwrap();
        assert_eq!(transcript.text, "你好 world");
        assert_eq!(transcript.segments.len(), 1);
        assert_eq!(transcript.segments[0].end_ms, 1_000);
        assert_eq!(transcript.language.as_deref(), Some("zh"));
    }

    #[test]
    fn mock_honours_cancel_flag() {
        let backend = MockBackend::new("x");
        let mut req = request(3_200);
        req.cancel = Arc::new(AtomicBool::new(true));
        let err = backend.transcribe(&req).unwrap_err();
        assert_eq!(err.kind, "cancelled");
    }

    #[test]
    fn mock_rejects_empty_audio() {
        let backend = MockBackend::new("x");
        let err = backend.transcribe(&request(0)).unwrap_err();
        assert_eq!(err.kind, "empty-audio");
    }
}
