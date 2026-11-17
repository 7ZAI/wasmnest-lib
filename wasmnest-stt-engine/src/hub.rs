//! 引擎核心：会话表 / 异步任务表 / 模型库编排
//!
//! 会话是插件私有的 PCM 缓冲；`finalize` 把它交给后台线程跑后端推理，插件只轮询
//! 任务状态。模型库是宿主共享资产，删除前检查在途任务。
//!
//! 属性不变量：
//! - 会话 / 任务句柄只认创建者插件；
//! - 插件停用或宿主关停时按属主回收（取消在途任务、丢弃会话）；
//! - 任何超限都是显性错误，不截断、不静默丢弃。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::backend::{BackendFailure, SttBackend, TranscribeRequest, Transcript};
use crate::catalog::default_model;
use crate::error::{Result, SttError};
use crate::model_store::{DownloadView, ModelStore, ModelView};
use crate::pcm;
use crate::wire::{JOB_HANDLE_PREFIX, SESSION_HANDLE_PREFIX};

/// 单插件的引擎配额
#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    /// 每个插件同时在册的会话数
    pub max_sessions_per_plugin: usize,
    /// 每个插件同时在途的推理任务数
    pub max_running_jobs_per_plugin: usize,
    /// 单会话累计 PCM 字节上限（默认约 10 分钟 16 kHz mono S16）
    pub max_session_bytes: usize,
    /// 单会话最少 PCM 字节（默认 100 ms）
    pub min_session_bytes: usize,
    /// 每个插件保留的已完成任务历史条数
    pub max_jobs_history_per_plugin: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_sessions_per_plugin: 2,
            max_running_jobs_per_plugin: 2,
            max_session_bytes: 20 * 1024 * 1024,
            min_session_bytes: 3_200,
            max_jobs_history_per_plugin: 32,
        }
    }
}

/// 任务状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// 推理中
    Running,
    /// 已完成
    Completed,
    /// 失败
    Failed,
    /// 已取消
    Cancelled,
}

impl JobState {
    /// 稳定的状态字符串（进入 JSON 与日志）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// 任务状态快照（WIT `job-status` 的 JSON 形状）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobStatusView {
    /// 任务 id
    pub job_id: String,
    /// 状态
    pub state: String,
    /// 模型 id
    pub model_id: String,
    /// 已耗时（毫秒）
    pub elapsed_ms: u64,
    /// 失败原因
    pub error: Option<JobErrorView>,
}

/// 任务错误视图
#[derive(Debug, Clone, Serialize)]
pub struct JobErrorView {
    /// 稳定分类
    pub kind: String,
    /// 可读原因
    pub message: String,
}

/// 任务结果（WIT `job-result` 的 JSON 形状）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobResultView {
    /// 任务 id
    pub job_id: String,
    /// 全文
    pub text: String,
    /// 实际语种
    pub language: Option<String>,
    /// 总耗时（毫秒）
    pub elapsed_ms: u64,
    /// 分段
    pub segments: Vec<SegmentView>,
}

/// 结果分段
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SegmentView {
    /// 文本
    pub text: String,
    /// 起始毫秒
    pub start_ms: u64,
    /// 结束毫秒
    pub end_ms: u64,
    /// v1 恒为 true（字段为将来的流式预留）
    pub is_final: bool,
}

/// 会话 options-json
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenOptions {
    model_id: Option<String>,
    language: Option<String>,
    translate: Option<bool>,
    prompt: Option<String>,
}

struct Session {
    id: String,
    owner: String,
    model_id: String,
    language: Option<String>,
    translate: bool,
    prompt: Option<String>,
    pcm: Vec<u8>,
}

struct JobRecord {
    id: String,
    owner: String,
    model_id: String,
    language: Option<String>,
    state: JobState,
    transcript: Option<Transcript>,
    error: Option<JobErrorView>,
    started: Instant,
    elapsed_ms: Option<u64>,
    cancel: Arc<AtomicBool>,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, Session>,
    jobs: HashMap<String, Arc<Mutex<JobRecord>>>,
}

/// 语音识别引擎
pub struct SttHub {
    backend: Arc<dyn SttBackend>,
    store: Arc<ModelStore>,
    limits: SessionLimits,
    inner: Mutex<Inner>,
    next_id: AtomicU64,
}

impl SttHub {
    /// 新建引擎
    pub fn new(
        backend: Arc<dyn SttBackend>,
        store: Arc<ModelStore>,
        limits: SessionLimits,
    ) -> Self {
        Self {
            backend,
            store,
            limits,
            inner: Mutex::new(Inner::default()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 模型库（模型管理面）
    pub fn store(&self) -> &Arc<ModelStore> {
        &self.store
    }

    /// 打开会话
    pub fn open_session(&self, plugin_id: &str, options_json: &str) -> Result<String> {
        let options: OpenOptions = serde_json::from_str(options_json)
            .map_err(|err| SttError::InvalidOptions(err.to_string()))?;
        let model_id = options
            .model_id
            .unwrap_or_else(|| default_model().id.to_string());
        if self.store.entry(&model_id).is_none() {
            return Err(SttError::UnknownModel(model_id));
        }
        let language = normalize_language(options.language)?;
        let prompt = options
            .prompt
            .map(|prompt| prompt.trim().to_string())
            .filter(|prompt| !prompt.is_empty());
        let mut inner = self.lock_inner();
        let count = inner
            .sessions
            .values()
            .filter(|s| s.owner == plugin_id)
            .count();
        if count >= self.limits.max_sessions_per_plugin {
            return Err(SttError::SessionQuotaExceeded(
                self.limits.max_sessions_per_plugin,
            ));
        }
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = format!("{SESSION_HANDLE_PREFIX}{seq}-{}", uuid::Uuid::new_v4());
        inner.sessions.insert(
            id.clone(),
            Session {
                id: id.clone(),
                owner: plugin_id.to_string(),
                model_id,
                language,
                translate: options.translate.unwrap_or(false),
                prompt,
                pcm: Vec::new(),
            },
        );
        Ok(id)
    }

    /// 追加 PCM
    pub fn append(&self, plugin_id: &str, session_id: &str, pcm: &[u8]) -> Result<u64> {
        if !pcm.len().is_multiple_of(pcm::SAMPLE_WIDTH) {
            return Err(SttError::OddPcmLength(pcm.len()));
        }
        let mut inner = self.lock_inner();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SttError::SessionNotFound(session_id.to_string()))?;
        if session.owner != plugin_id {
            return Err(SttError::SessionNotOwner(session_id.to_string()));
        }
        let total = session.pcm.len().saturating_add(pcm.len());
        if total > self.limits.max_session_bytes {
            return Err(SttError::SessionTooLarge {
                bytes: total,
                limit: self.limits.max_session_bytes,
            });
        }
        session.pcm.extend_from_slice(pcm);
        Ok(total as u64)
    }

    /// 结束会话并提交异步任务
    pub fn finalize(self: &Arc<Self>, plugin_id: &str, session_id: &str) -> Result<String> {
        let session = {
            let mut inner = self.lock_inner();
            let session = inner
                .sessions
                .remove(session_id)
                .ok_or_else(|| SttError::SessionNotFound(session_id.to_string()))?;
            if session.owner != plugin_id {
                // 不是属主：把会话放回去（不能因为一次越权访问丢掉别人的数据）
                inner.sessions.insert(session.id.clone(), session);
                return Err(SttError::SessionNotOwner(session_id.to_string()));
            }
            session
        };

        if session.pcm.len() < self.limits.min_session_bytes {
            return Err(SttError::AudioTooShort {
                bytes: session.pcm.len(),
                minimum: self.limits.min_session_bytes,
            });
        }
        if !self.store.is_installed(&session.model_id) {
            return Err(SttError::ModelNotInstalled(session.model_id));
        }
        {
            let inner = self.lock_inner();
            let running = inner
                .jobs
                .values()
                .filter(|job| {
                    let job = lock_job(job);
                    job.owner == plugin_id && job.state == JobState::Running
                })
                .count();
            if running >= self.limits.max_running_jobs_per_plugin {
                return Err(SttError::JobQuotaExceeded(
                    self.limits.max_running_jobs_per_plugin,
                ));
            }
        }

        let job_id = format!("{JOB_HANDLE_PREFIX}{}", uuid::Uuid::new_v4());
        let cancel = Arc::new(AtomicBool::new(false));
        let record = Arc::new(Mutex::new(JobRecord {
            id: job_id.clone(),
            owner: plugin_id.to_string(),
            model_id: session.model_id.clone(),
            language: session.language.clone(),
            state: JobState::Running,
            transcript: None,
            error: None,
            started: Instant::now(),
            elapsed_ms: None,
            cancel: Arc::clone(&cancel),
        }));

        {
            let mut inner = self.lock_inner();
            inner.jobs.insert(job_id.clone(), Arc::clone(&record));
            prune_jobs(
                &mut inner,
                plugin_id,
                self.limits.max_jobs_history_per_plugin,
            );
        }

        let hub = Arc::clone(self);
        let record_for_thread = Arc::clone(&record);
        let session_for_thread = session;
        let spawn = std::thread::Builder::new()
            .name(format!("stt-job-{job_id}"))
            .spawn(move || {
                run_job(hub, record_for_thread, session_for_thread);
            });
        if let Err(err) = spawn {
            let mut job = lock_job(&record);
            job.state = JobState::Failed;
            job.error = Some(JobErrorView {
                kind: "internal".to_string(),
                message: format!("failed to spawn inference thread: {err}"),
            });
            return Err(SttError::Internal(
                job.error.as_ref().unwrap().message.clone(),
            ));
        }
        Ok(job_id)
    }

    /// 放弃会话
    pub fn abort_session(&self, plugin_id: &str, session_id: &str) -> Result<bool> {
        let mut inner = self.lock_inner();
        match inner.sessions.get(session_id) {
            Some(session) if session.owner == plugin_id => {
                inner.sessions.remove(session_id);
                Ok(true)
            }
            Some(_) => Err(SttError::SessionNotOwner(session_id.to_string())),
            None => Err(SttError::SessionNotFound(session_id.to_string())),
        }
    }

    /// 任务状态
    pub fn job_status(&self, plugin_id: &str, job_id: &str) -> Result<JobStatusView> {
        let record = self.job(plugin_id, job_id)?;
        let job = lock_job(&record);
        Ok(JobStatusView {
            job_id: job.id.clone(),
            state: job.state.as_str().to_string(),
            model_id: job.model_id.clone(),
            elapsed_ms: job.elapsed_ms.unwrap_or_else(|| {
                u64::try_from(job.started.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
            error: job.error.clone(),
        })
    }

    /// 任务结果（仅完成态）
    pub fn job_result(&self, plugin_id: &str, job_id: &str) -> Result<JobResultView> {
        let record = self.job(plugin_id, job_id)?;
        let job = lock_job(&record);
        if job.state != JobState::Completed {
            return Err(SttError::JobNotCompleted(job.state.as_str().to_string()));
        }
        let transcript = job
            .transcript
            .as_ref()
            .ok_or_else(|| SttError::Internal("completed job has no transcript".to_string()))?;
        Ok(JobResultView {
            job_id: job.id.clone(),
            text: transcript.text.clone(),
            language: transcript.language.clone().or_else(|| job.language.clone()),
            elapsed_ms: job.elapsed_ms.unwrap_or(transcript.elapsed_ms),
            segments: transcript
                .segments
                .iter()
                .map(|segment| SegmentView {
                    text: segment.text.clone(),
                    start_ms: segment.start_ms,
                    end_ms: segment.end_ms,
                    is_final: true,
                })
                .collect(),
        })
    }

    /// 取消任务
    pub fn job_cancel(&self, plugin_id: &str, job_id: &str) -> Result<bool> {
        let record = self.job(plugin_id, job_id)?;
        let mut job = lock_job(&record);
        if job.state != JobState::Running {
            return Ok(false);
        }
        job.cancel.store(true, Ordering::SeqCst);
        job.state = JobState::Cancelled;
        job.elapsed_ms = Some(u64::try_from(job.started.elapsed().as_millis()).unwrap_or(u64::MAX));
        Ok(true)
    }

    /// 模型清单
    pub fn models_list(&self) -> Vec<ModelView> {
        self.store.models()
    }

    /// 开始下载模型
    pub fn download_model(self: &Arc<Self>, model_id: &str) -> Result<String> {
        self.store.download(model_id)
    }

    /// 下载状态
    pub fn model_status(&self, model_id: &str) -> Result<DownloadView> {
        self.store.status(model_id)
    }

    /// 删除模型（在途任务使用中拒绝）
    pub fn remove_model(&self, model_id: &str) -> Result<bool> {
        {
            let inner = self.lock_inner();
            let in_use = inner.jobs.values().any(|job| {
                let job = lock_job(job);
                job.model_id == model_id && job.state == JobState::Running
            });
            if in_use {
                return Err(SttError::ModelInUse(model_id.to_string()));
            }
        }
        // 先让后端丢弃该模型的缓存（内存映射会持有文件句柄，删除前必须释放）
        let path = self.store.path(model_id)?;
        self.backend.release_model(&path);
        self.store.remove(model_id)
    }

    /// 导入模型
    pub fn import_model(&self, model_id: &str, source: &std::path::Path) -> Result<bool> {
        self.store.import(model_id, source)
    }

    /// 插件停用回收：丢弃会话、取消任务、移除任务历史
    pub fn purge(&self, plugin_id: &str) -> usize {
        let mut inner = self.lock_inner();
        let before = inner.sessions.len() + inner.jobs.len();
        inner
            .sessions
            .retain(|_, session| session.owner != plugin_id);
        for job in inner.jobs.values() {
            let mut job = lock_job(job);
            if job.owner == plugin_id && job.state == JobState::Running {
                job.cancel.store(true, Ordering::SeqCst);
                job.state = JobState::Cancelled;
            }
        }
        inner.jobs.retain(|_, job| {
            let job = lock_job(job);
            job.owner != plugin_id
        });
        before - (inner.sessions.len() + inner.jobs.len())
    }

    /// 系统关停回收：取消全部在途任务、丢弃全部会话与任务历史
    pub fn close_all(&self) -> usize {
        let mut inner = self.lock_inner();
        let count = inner.sessions.len() + inner.jobs.len();
        for job in inner.jobs.values() {
            let mut job = lock_job(job);
            if job.state == JobState::Running {
                job.cancel.store(true, Ordering::SeqCst);
                job.state = JobState::Cancelled;
            }
        }
        inner.sessions.clear();
        inner.jobs.clear();
        count
    }

    /// 在册会话数（诊断）
    pub fn session_count(&self) -> usize {
        self.lock_inner().sessions.len()
    }

    /// 在册任务数（诊断）
    pub fn job_count(&self) -> usize {
        self.lock_inner().jobs.len()
    }

    fn job(&self, plugin_id: &str, job_id: &str) -> Result<Arc<Mutex<JobRecord>>> {
        let inner = self.lock_inner();
        let job = inner
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| SttError::JobNotFound(job_id.to_string()))?;
        let owner = lock_job(&job).owner.clone();
        if owner != plugin_id {
            return Err(SttError::JobNotOwner(job_id.to_string()));
        }
        Ok(job)
    }

    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }
}

fn run_job(hub: Arc<SttHub>, record: Arc<Mutex<JobRecord>>, session: Session) {
    let (model_id, language, translate, prompt, pcm, cancel) = {
        let job = lock_job(&record);
        (
            job.model_id.clone(),
            job.language.clone(),
            session.translate,
            session.prompt.clone(),
            session.pcm,
            Arc::clone(&job.cancel),
        )
    };
    let model_path = match hub.store.path(&model_id) {
        Ok(path) => path,
        Err(err) => {
            finish_failed(&record, err.kind(), err.to_string());
            return;
        }
    };
    if !model_path.is_file() {
        finish_failed(
            &record,
            "model-file-missing",
            SttError::ModelFileMissing(model_path).to_string(),
        );
        return;
    }
    let request = TranscribeRequest {
        pcm_s16le: pcm,
        sample_rate: pcm::SAMPLE_RATE,
        channels: pcm::CHANNELS,
        language,
        translate,
        prompt,
        model_path,
        cancel: Arc::clone(&cancel),
    };
    let started = Instant::now();
    match hub.backend.transcribe(&request) {
        Ok(mut transcript) => {
            if transcript.elapsed_ms == 0 {
                transcript.elapsed_ms =
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            }
            let mut job = lock_job(&record);
            if job.state == JobState::Cancelled || cancel.load(Ordering::SeqCst) {
                return;
            }
            job.state = JobState::Completed;
            job.elapsed_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            job.transcript = Some(transcript);
        }
        Err(err) => {
            let mut job = lock_job(&record);
            if job.state == JobState::Cancelled || cancel.load(Ordering::SeqCst) {
                return;
            }
            job.state = JobState::Failed;
            job.elapsed_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            job.error = Some(JobErrorView {
                kind: err.kind.clone(),
                message: err.message.clone(),
            });
            tracing::warn!(model_id = %model_id, kind = %err.kind, "stt job failed");
        }
    }
}

fn finish_failed(record: &Arc<Mutex<JobRecord>>, kind: &str, message: String) {
    let mut job = lock_job(record);
    if job.state == JobState::Cancelled {
        return;
    }
    job.state = JobState::Failed;
    job.elapsed_ms = Some(u64::try_from(job.started.elapsed().as_millis()).unwrap_or(u64::MAX));
    job.error = Some(JobErrorView {
        kind: kind.to_string(),
        message,
    });
}

fn prune_jobs(inner: &mut Inner, plugin_id: &str, keep: usize) {
    let mut finished: Vec<(Instant, String)> = inner
        .jobs
        .iter()
        .filter_map(|(id, job)| {
            let job = lock_job(job);
            (job.owner == plugin_id && job.state != JobState::Running)
                .then_some((job.started, id.clone()))
        })
        .collect();
    if finished.len() <= keep {
        return;
    }
    finished.sort_by_key(|(started, _)| *started);
    let remove_count = finished.len() - keep;
    for (_, id) in finished.into_iter().take(remove_count) {
        inner.jobs.remove(&id);
    }
}

fn normalize_language(language: Option<String>) -> Result<Option<String>> {
    let Some(language) = language else {
        return Ok(None);
    };
    let language = language.trim().to_ascii_lowercase();
    if language.is_empty() || language == "auto" {
        return Ok(None);
    }
    if !(2..=3).contains(&language.len()) || !language.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(SttError::InvalidOptions(format!(
            "language must be auto or a 2-3 letter ISO code, got {language:?}"
        )));
    }
    Ok(Some(language))
}

fn lock_job(job: &Arc<Mutex<JobRecord>>) -> MutexGuard<'_, JobRecord> {
    job.lock().unwrap_or_else(|err| err.into_inner())
}

/// 后端失败 → 任务错误视图（供宿主日志复用）
impl From<BackendFailure> for JobErrorView {
    fn from(value: BackendFailure) -> Self {
        Self {
            kind: value.kind,
            message: value.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::catalog::ModelEntry;
    use crate::model_store::{ModelFetcher, ModelStore};
    use crate::pcm;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const MODEL_BYTES: &[u8] = b"test-model";

    struct NoFetcher;
    impl ModelFetcher for NoFetcher {
        fn fetch(
            &self,
            _url: &str,
            _dest: &Path,
            _progress: &mut dyn FnMut(u64, Option<u64>),
        ) -> std::result::Result<(), String> {
            Err("not used".to_string())
        }
    }

    fn entry() -> ModelEntry {
        ModelEntry {
            id: "tiny",
            name: "Tiny",
            description: "test",
            filename: "tiny.bin",
            url: "https://example.invalid/tiny.bin",
            sha256: Box::leak(format!("{:x}", Sha256::digest(MODEL_BYTES)).into_boxed_str()),
            size_bytes: MODEL_BYTES.len() as u64,
            languages: &["zh", "en"],
            recommended: true,
        }
    }

    fn setup(backend: Arc<dyn SttBackend>) -> (Arc<SttHub>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("wasmnest-stt-hub-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.bin");
        fs::write(&source, MODEL_BYTES).unwrap();
        let store = Arc::new(
            ModelStore::with_catalog(
                dir.join("models"),
                Some(Arc::new(NoFetcher)),
                None,
                vec![entry()],
            )
            .unwrap(),
        );
        store.import("tiny", &source).unwrap();
        let hub = Arc::new(SttHub::new(backend, store, SessionLimits::default()));
        (hub, dir)
    }

    fn pcm_bytes(ms: usize) -> Vec<u8> {
        let samples = 16_000 * ms / 1000;
        vec![0u8; samples * pcm::SAMPLE_WIDTH]
    }

    fn wait_state(hub: &SttHub, job: &str, state: JobState) -> JobStatusView {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = hub.job_status("p1", job).unwrap();
            if status.state == state.as_str() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "job {job} did not reach {}: {}",
                state.as_str(),
                status.state
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn session_to_job_to_result() {
        let (hub, dir) = setup(Arc::new(MockBackend::new("hello")));
        let session = hub
            .open_session("p1", r#"{"modelId":"tiny","language":"zh"}"#)
            .unwrap();
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let job = hub.finalize("p1", &session).unwrap();
        wait_state(&hub, &job, JobState::Completed);
        let result = hub.job_result("p1", &job).unwrap();
        assert_eq!(result.text, "hello");
        assert_eq!(result.language.as_deref(), Some("zh"));
        assert_eq!(result.segments.len(), 1);
        assert!(result.segments[0].is_final);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn owner_isolation_is_enforced() {
        let (hub, dir) = setup(Arc::new(MockBackend::new("hello")));
        let session = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        let err = hub.append("p2", &session, &pcm_bytes(100)).unwrap_err();
        assert_eq!(err.kind(), "session-not-owner");
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let job = hub.finalize("p1", &session).unwrap();
        wait_state(&hub, &job, JobState::Completed);
        let err = hub.job_result("p2", &job).unwrap_err();
        assert_eq!(err.kind(), "job-not-owner");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn quota_and_too_short_are_visible() {
        let (hub, dir) = setup(Arc::new(MockBackend::new("hello")));
        let a = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        let _b = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        let err = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap_err();
        assert_eq!(err.kind(), "session-quota-exceeded");
        hub.append("p1", &a, &pcm_bytes(10)).unwrap();
        let err = hub.finalize("p1", &a).unwrap_err();
        assert_eq!(err.kind(), "audio-too-short");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cancellation_is_visible() {
        let (hub, dir) = setup(Arc::new(MockBackend::with_delay("hello", 500)));
        let session = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let job = hub.finalize("p1", &session).unwrap();
        assert!(hub.job_cancel("p1", &job).unwrap());
        wait_state(&hub, &job, JobState::Cancelled);
        assert_eq!(
            hub.job_result("p1", &job).unwrap_err().kind(),
            "job-not-completed"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn close_all_cancels_jobs_and_clears_tables() {
        let (hub, dir) = setup(Arc::new(MockBackend::with_delay("hello", 300)));
        let session = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let job = hub.finalize("p1", &session).unwrap();
        assert!(hub.close_all() >= 1);
        assert_eq!(hub.session_count(), 0);
        assert_eq!(hub.job_count(), 0);
        assert_eq!(
            hub.job_status("p1", &job).unwrap_err().kind(),
            "job-not-found"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_model_blocks_finalize() {
        let dir =
            std::env::temp_dir().join(format!("wasmnest-stt-missing-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(
            ModelStore::with_catalog(dir.join("models"), None, None, vec![entry()]).unwrap(),
        );
        let hub = Arc::new(SttHub::new(
            Arc::new(MockBackend::new("x")),
            store,
            SessionLimits::default(),
        ));
        let session = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let err = hub.finalize("p1", &session).unwrap_err();
        assert_eq!(err.kind(), "model-not-installed");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn purge_removes_sessions_and_jobs() {
        let (hub, dir) = setup(Arc::new(MockBackend::new("hello")));
        let session = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let job = hub.finalize("p1", &session).unwrap();
        assert!(hub.purge("p1") >= 1);
        assert!(hub.job_status("p1", &job).is_err());
        assert!(hub.session_count() == 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn remove_model_rejects_when_job_running() {
        let (hub, dir) = setup(Arc::new(MockBackend::with_delay("hello", 300)));
        let session = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let _job = hub.finalize("p1", &session).unwrap();
        let err = hub.remove_model("tiny").unwrap_err();
        assert_eq!(err.kind(), "model-in-use");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn result_json_shape_is_camel_case() {
        let (hub, dir) = setup(Arc::new(MockBackend::new("hello")));
        let session = hub.open_session("p1", r#"{"modelId":"tiny"}"#).unwrap();
        hub.append("p1", &session, &pcm_bytes(500)).unwrap();
        let job = hub.finalize("p1", &session).unwrap();
        wait_state(&hub, &job, JobState::Completed);
        let json = serde_json::to_value(hub.job_result("p1", &job).unwrap()).unwrap();
        assert_eq!(json["jobId"], job);
        assert_eq!(json["segments"][0]["isFinal"], true);
        assert!(json.get("elapsedMs").is_some());
        let _ = fs::remove_dir_all(dir);
    }
}
