//! 引擎错误类型：语义变体 + 可读消息
//!
//! 错误只跨能力域边界（引擎 → 绑定层 → WIT `result<_, string>`）；宿主侧要落
//! 结构化信封时按变体显式映射，不依赖 `From` 的隐式连带。

use std::path::PathBuf;

/// 引擎结果
pub type Result<T> = std::result::Result<T, SttError>;

/// 语音识别引擎错误
#[derive(Debug, thiserror::Error)]
pub enum SttError {
    /// 模型 id 不在宿主 catalog 内
    #[error("unknown model: {0}")]
    UnknownModel(String),

    /// catalog 模型尚未下载 / 导入
    #[error("model not installed: {0}")]
    ModelNotInstalled(String),

    /// 模型正在下载，暂不可用
    #[error("model is downloading: {0}")]
    ModelDownloading(String),

    /// 模型正在被在途任务使用，拒绝删除
    #[error("model is in use by a running job: {0}")]
    ModelInUse(String),

    /// 模型文件缺失 / 不是普通文件
    #[error("model file missing: {0}")]
    ModelFileMissing(PathBuf),

    /// 模型完整性校验失败
    #[error("model checksum mismatch for {model_id}: expected {expected}, got {actual}")]
    ModelChecksumMismatch {
        /// 模型 id
        model_id: String,
        /// catalog 声明值
        expected: String,
        /// 实际计算值
        actual: String,
    },

    /// 模型下载器未装配（宿主构建缺口）
    #[error("model downloader is not available: {0}")]
    DownloaderUnavailable(String),

    /// 模型下载失败
    #[error("model download failed for {model_id}: {message}")]
    DownloadFailed {
        /// 模型 id
        model_id: String,
        /// 可读原因
        message: String,
    },

    /// 会话 options-json 非法
    #[error("invalid session options: {0}")]
    InvalidOptions(String),

    /// 会话句柄不存在
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// 会话不属于调用插件
    #[error("not owner of session handle: {0}")]
    SessionNotOwner(String),

    /// 任务句柄不存在
    #[error("job not found: {0}")]
    JobNotFound(String),

    /// 任务不属于调用插件
    #[error("not owner of job handle: {0}")]
    JobNotOwner(String),

    /// 任务尚未完成
    #[error("job is not completed (state: {0})")]
    JobNotCompleted(String),

    /// 每个插件的在途任务数超限
    #[error("too many running jobs for this plugin (limit {0})")]
    JobQuotaExceeded(usize),

    /// 每个插件的会话数超限
    #[error("too many sessions for this plugin (limit {0})")]
    SessionQuotaExceeded(usize),

    /// PCM 长度不是偶数（S16 样本宽度）
    #[error("pcm byte length must be even for s16le (got {0})")]
    OddPcmLength(usize),

    /// 单会话累计 PCM 超限
    #[error("session audio too large: {bytes} bytes exceeds limit {limit}")]
    SessionTooLarge {
        /// 当前累计字节
        bytes: usize,
        /// 上限
        limit: usize,
    },

    /// 音频过短，无法识别
    #[error("audio too short: {bytes} bytes is below the minimum {minimum}")]
    AudioTooShort {
        /// 当前字节
        bytes: usize,
        /// 下限
        minimum: usize,
    },

    /// 推理后端未装配
    #[error("stt backend is not available: {0}")]
    BackendUnavailable(String),

    /// 推理失败
    #[error("transcription failed ({kind}): {message}")]
    BackendFailed {
        /// 后端分类
        kind: String,
        /// 可读原因
        message: String,
    },

    /// 文件系统 / 路径操作失败
    #[error("stt io error: {0}")]
    Io(String),

    /// 内部状态损坏（锁中毒等不可恢复的编程错误）
    #[error("stt internal error: {0}")]
    Internal(String),
}

impl SttError {
    /// 稳定的错误分类（用于 `job-status.error.kind` 与宿主日志）
    pub fn kind(&self) -> &'static str {
        match self {
            Self::UnknownModel(_) => "unknown-model",
            Self::ModelNotInstalled(_) => "model-not-installed",
            Self::ModelDownloading(_) => "model-downloading",
            Self::ModelInUse(_) => "model-in-use",
            Self::ModelFileMissing(_) => "model-file-missing",
            Self::ModelChecksumMismatch { .. } => "model-checksum-mismatch",
            Self::DownloaderUnavailable(_) => "downloader-unavailable",
            Self::DownloadFailed { .. } => "download-failed",
            Self::InvalidOptions(_) => "invalid-options",
            Self::SessionNotFound(_) => "session-not-found",
            Self::SessionNotOwner(_) => "session-not-owner",
            Self::JobNotFound(_) => "job-not-found",
            Self::JobNotOwner(_) => "job-not-owner",
            Self::JobNotCompleted(_) => "job-not-completed",
            Self::JobQuotaExceeded(_) => "job-quota-exceeded",
            Self::SessionQuotaExceeded(_) => "session-quota-exceeded",
            Self::OddPcmLength(_) => "odd-pcm-length",
            Self::SessionTooLarge { .. } => "session-too-large",
            Self::AudioTooShort { .. } => "audio-too-short",
            Self::BackendUnavailable(_) => "backend-unavailable",
            Self::BackendFailed { .. } => "backend-failed",
            Self::Io(_) => "io",
            Self::Internal(_) => "internal",
        }
    }
}

impl From<std::io::Error> for SttError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
