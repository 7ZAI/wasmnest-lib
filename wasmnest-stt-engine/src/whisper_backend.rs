//! whisper.cpp 后端（`whisper-rs`，GGML 模型，CPU 默认）
//!
//! 模型上下文按路径缓存（加载一次、多次推理复用）；每个任务创建一个 state，
//! 支持 abort 回调（取消标志在推理循环中被 whisper.cpp 检查）。
//!
//! 输入固定为 16 kHz 单声道 S16LE；这里转成 f32 后交给 whisper。输出分段直接来自
//! whisper.cpp 的 segment 时间戳（centisecond，乘 10 得毫秒）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};

use crate::backend::{
    BackendFailure, SttBackend, TranscribeRequest, Transcript, TranscriptSegment,
};

/// whisper.cpp 推理后端
pub struct WhisperBackend {
    /// 模型路径 → 已加载上下文（加载失败不缓存）
    contexts: Mutex<HashMap<PathBuf, Arc<WhisperContext>>>,
}

impl Default for WhisperBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl WhisperBackend {
    /// 新建空缓存的后端
    pub fn new() -> Self {
        Self {
            contexts: Mutex::new(HashMap::new()),
        }
    }

    fn evict(&self, path: &Path) {
        let mut guard = match self.contexts.lock() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        };
        guard.remove(path);
    }

    fn context(&self, path: &Path) -> Result<Arc<WhisperContext>, BackendFailure> {
        let mut guard = self.contexts.lock().map_err(|err| {
            BackendFailure::new("internal", format!("model cache poisoned: {err}"))
        })?;
        if let Some(ctx) = guard.get(path) {
            return Ok(Arc::clone(ctx));
        }
        let ctx = WhisperContext::new_with_params(path, WhisperContextParameters::default())
            .map_err(|err| {
                BackendFailure::new(
                    "model-load",
                    format!("failed to load {}: {err}", path.display()),
                )
            })?;
        let ctx = Arc::new(ctx);
        guard.insert(path.to_path_buf(), Arc::clone(&ctx));
        Ok(ctx)
    }
}

impl SttBackend for WhisperBackend {
    fn transcribe(&self, request: &TranscribeRequest) -> Result<Transcript, BackendFailure> {
        if request.sample_rate != crate::pcm::SAMPLE_RATE
            || request.channels != crate::pcm::CHANNELS
        {
            return Err(BackendFailure::new(
                "audio-invalid",
                format!(
                    "expected {} Hz mono, got {} Hz / {} ch",
                    crate::pcm::SAMPLE_RATE,
                    request.sample_rate,
                    request.channels
                ),
            ));
        }
        if request.cancel.load(Ordering::Relaxed) {
            return Err(BackendFailure::new(
                "cancelled",
                "cancelled before inference",
            ));
        }

        let ctx = self.context(&request.model_path)?;
        let mut state = ctx.create_state().map_err(|err| {
            BackendFailure::new("state", format!("failed to create state: {err}"))
        })?;

        let samples = crate::pcm::s16le_to_f32(&request.pcm_s16le);
        let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
        params.set_language(request.language.as_deref());
        params.set_detect_language(request.language.is_none());
        params.set_translate(request.translate);
        params.set_no_timestamps(false);
        params.set_single_segment(false);
        params.set_print_special(false);
        params.set_print_progress(false);
        params.set_print_realtime(false);
        params.set_print_timestamps(false);
        params.set_n_threads(
            std::thread::available_parallelism()
                .map(|n| n.get().min(4) as i32)
                .unwrap_or(2),
        );
        if let Some(prompt) = request.prompt.as_deref().filter(|p| !p.trim().is_empty()) {
            params.set_initial_prompt(prompt);
        }
        let cancel = Arc::clone(&request.cancel);
        params.set_abort_callback_safe(move || cancel.load(Ordering::Relaxed));

        let started = std::time::Instant::now();
        state.full(params, &samples).map_err(|err| {
            if request.cancel.load(Ordering::Relaxed) {
                BackendFailure::new("cancelled", "cancelled during inference")
            } else {
                BackendFailure::new("inference", format!("whisper full failed: {err}"))
            }
        })?;

        let mut segments = Vec::new();
        let mut text = String::new();
        for index in 0..state.full_n_segments() {
            let Some(segment) = state.get_segment(index) else {
                continue;
            };
            let piece = segment
                .to_str_lossy()
                .map_err(|err| BackendFailure::new("decode", format!("bad segment text: {err}")))?
                .trim()
                .to_string();
            if piece.is_empty() {
                continue;
            }
            let start_ms = u64::try_from(segment.start_timestamp()).unwrap_or(0) * 10;
            let end_ms = u64::try_from(segment.end_timestamp()).unwrap_or(0) * 10;
            text.push_str(&piece);
            segments.push(TranscriptSegment {
                text: piece,
                start_ms,
                end_ms,
            });
        }

        let language = whisper_rs::get_lang_str(state.full_lang_id_from_state())
            .map(str::to_string)
            .or_else(|| request.language.clone());

        if text.is_empty() {
            return Err(BackendFailure::new("no-speech", "no speech detected"));
        }

        Ok(Transcript {
            text,
            segments,
            language,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn release_model(&self, model_path: &Path) {
        self.evict(model_path);
    }
}
