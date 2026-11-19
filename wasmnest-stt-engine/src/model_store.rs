//! 宿主共享模型目录：catalog 投影 / 下载 / 校验 / 导入 / 删除
//!
//! - **目录是宿主资产**：插件只拿模型 id；文件路径与下载 URL 都不出宿主。
//! - **下载源受限**：只来自 catalog；镜像模式只替换目录前缀，不接受插件 URL。
//! - **落盘纪律**：临时文件 → SHA-256 校验 → 原子 rename；失败清临时文件并显性报错。
//! - **进度面**：下载状态放在共享表里，WIT 侧轮询 `model-status`，不做事件面。

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
#[cfg(feature = "model-download")]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::catalog::{ModelEntry, CATALOG};
use crate::error::{Result, SttError};

/// 模型清单的只读投影（WIT `model-info` 的引擎侧形状）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelView {
    /// 模型 id
    pub id: String,
    /// 名称
    pub name: String,
    /// 说明
    pub description: String,
    /// 支持语种
    pub languages: Vec<String>,
    /// 体积（字节）
    pub size_bytes: u64,
    /// 是否已安装
    pub installed: bool,
    /// 是否在下载
    pub downloading: bool,
    /// 是否推荐
    pub recommended: bool,
}

/// 下载状态（WIT `model-status` 的引擎侧形状）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadView {
    /// 模型 id
    pub model_id: String,
    /// `idle` | `downloading` | `verifying` | `installed` | `error`
    pub state: String,
    /// 已下载字节
    pub downloaded_bytes: u64,
    /// 总字节（catalog 声明；未知为 0）
    pub total_bytes: u64,
    /// 错误原因（仅 `error`）
    pub message: Option<String>,
}

/// 下载器边界：真实实现走 HTTP，测试用可编排替身
pub trait ModelFetcher: Send + Sync {
    /// 把 `url` 下载到 `dest`；`progress(已下载, 总大小)` 由实现按块回调
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        progress: &mut dyn FnMut(u64, Option<u64>),
    ) -> std::result::Result<(), String>;
}

/// 阻塞式 HTTP 下载器（模型目录固定；仅宿主构建启用）
#[cfg(feature = "model-download")]
pub struct HttpFetcher {
    agent: ureq::Agent,
}

#[cfg(feature = "model-download")]
impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "model-download")]
impl HttpFetcher {
    /// 新建下载器（连接 15s 超时、单次读 60s 超时）
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(15))
            .timeout_read(std::time::Duration::from_secs(60))
            .build();
        Self { agent }
    }
}

#[cfg(feature = "model-download")]
impl ModelFetcher for HttpFetcher {
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        progress: &mut dyn FnMut(u64, Option<u64>),
    ) -> std::result::Result<(), String> {
        let response = self
            .agent
            .get(url)
            .call()
            .map_err(|err| format!("GET {url} failed: {err}"))?;
        let total = response
            .header("Content-Length")
            .and_then(|value| value.parse::<u64>().ok());
        let mut reader = response.into_reader();
        let mut file =
            File::create(dest).map_err(|err| format!("create {}: {err}", dest.display()))?;
        let mut buffer = [0u8; 64 * 1024];
        let mut downloaded = 0u64;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|err| format!("read from {url}: {err}"))?;
            if read == 0 {
                break;
            }
            file.write_all(&buffer[..read])
                .map_err(|err| format!("write {}: {err}", dest.display()))?;
            downloaded += read as u64;
            progress(downloaded, total);
        }
        file.flush()
            .map_err(|err| format!("flush {}: {err}", dest.display()))?;
        Ok(())
    }
}

/// 宿主共享模型库
pub struct ModelStore {
    dir: PathBuf,
    catalog: Vec<ModelEntry>,
    fetcher: Option<Arc<dyn ModelFetcher>>,
    mirror_base: Option<String>,
    downloads: Mutex<HashMap<String, DownloadView>>,
}

impl ModelStore {
    /// 用固定 catalog 新建模型库（`mirror_base` 为宿主可配镜像前缀）
    pub fn new(
        dir: PathBuf,
        fetcher: Option<Arc<dyn ModelFetcher>>,
        mirror_base: Option<String>,
    ) -> Result<Self> {
        Self::with_catalog(dir, fetcher, mirror_base, CATALOG.to_vec())
    }

    /// 指定 catalog 新建（测试 / 受限宿主用）
    pub fn with_catalog(
        dir: PathBuf,
        fetcher: Option<Arc<dyn ModelFetcher>>,
        mirror_base: Option<String>,
        catalog: Vec<ModelEntry>,
    ) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            catalog,
            fetcher,
            mirror_base,
            downloads: Mutex::new(HashMap::new()),
        })
    }

    /// 模型库目录
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// catalog 条目
    pub fn entry(&self, id: &str) -> Option<&ModelEntry> {
        self.catalog.iter().find(|entry| entry.id == id)
    }

    /// 模型是否已安装
    pub fn is_installed(&self, id: &str) -> bool {
        self.entry(id)
            .map(|entry| self.dir.join(entry.filename).is_file())
            .unwrap_or(false)
    }

    /// 模型文件路径（未安装也返回目标路径；调用方先查 [`Self::is_installed`]）
    pub fn path(&self, id: &str) -> Result<PathBuf> {
        self.entry(id)
            .map(|entry| self.dir.join(entry.filename))
            .ok_or_else(|| SttError::UnknownModel(id.to_string()))
    }

    /// 模型清单投影
    pub fn models(&self) -> Vec<ModelView> {
        let downloads = self.lock_downloads();
        self.catalog
            .iter()
            .map(|entry| {
                let installed = self.dir.join(entry.filename).is_file();
                let downloading = downloads
                    .get(entry.id)
                    .map(|state| state.state == "downloading" || state.state == "verifying")
                    .unwrap_or(false);
                ModelView {
                    id: entry.id.to_string(),
                    name: entry.name.to_string(),
                    description: entry.description.to_string(),
                    languages: entry
                        .languages
                        .iter()
                        .map(|lang| (*lang).to_string())
                        .collect(),
                    size_bytes: entry.size_bytes,
                    installed,
                    downloading,
                    recommended: entry.recommended,
                }
            })
            .collect()
    }

    /// 下载状态投影
    pub fn status(&self, id: &str) -> Result<DownloadView> {
        let entry = self
            .entry(id)
            .ok_or_else(|| SttError::UnknownModel(id.to_string()))?;
        if self.dir.join(entry.filename).is_file() {
            return Ok(installed_view(entry));
        }
        if let Some(state) = self.lock_downloads().get(id) {
            return Ok(state.clone());
        }
        Ok(DownloadView {
            model_id: entry.id.to_string(),
            state: "idle".to_string(),
            downloaded_bytes: 0,
            total_bytes: entry.size_bytes,
            message: None,
        })
    }

    /// 开始下载（幂等：已安装 / 下载中直接返回 id）
    pub fn download(self: &Arc<Self>, id: &str) -> Result<String> {
        let entry = *self
            .entry(id)
            .ok_or_else(|| SttError::UnknownModel(id.to_string()))?;
        if self.dir.join(entry.filename).is_file() {
            return Ok(entry.id.to_string());
        }
        let fetcher = self.fetcher.clone().ok_or_else(|| {
            SttError::DownloaderUnavailable(
                "host was built without the model-download feature".to_string(),
            )
        })?;
        {
            let mut downloads = self.lock_downloads();
            if downloads
                .get(id)
                .map(|state| state.state == "downloading" || state.state == "verifying")
                .unwrap_or(false)
            {
                return Ok(entry.id.to_string());
            }
            downloads.insert(
                id.to_string(),
                DownloadView {
                    model_id: id.to_string(),
                    state: "downloading".to_string(),
                    downloaded_bytes: 0,
                    total_bytes: entry.size_bytes,
                    message: None,
                },
            );
        }
        let store = Arc::clone(self);
        std::thread::Builder::new()
            .name(format!("stt-download-{id}"))
            .spawn(move || run_download(store, entry, fetcher))
            .map_err(|err| SttError::DownloadFailed {
                model_id: id.to_string(),
                message: format!("failed to spawn download thread: {err}"),
            })?;
        Ok(entry.id.to_string())
    }

    /// 从本地文件导入（校验 SHA-256；原子落位）
    pub fn import(&self, id: &str, source: &Path) -> Result<bool> {
        let entry = self
            .entry(id)
            .ok_or_else(|| SttError::UnknownModel(id.to_string()))?;
        if !source.is_file() {
            return Err(SttError::ModelFileMissing(source.to_path_buf()));
        }
        let target = self.dir.join(entry.filename);
        if target.is_file() {
            verify_file(&target, entry)?;
            self.lock_downloads()
                .insert(id.to_string(), installed_view(entry));
            return Ok(false);
        }
        verify_file(source, entry)?;
        let tmp = self.tmp_path(entry.filename);
        fs::copy(source, &tmp)?;
        fs::rename(&tmp, &target)?;
        self.lock_downloads()
            .insert(id.to_string(), installed_view(entry));
        Ok(true)
    }

    /// 删除已安装模型（下载中拒绝）
    pub fn remove(&self, id: &str) -> Result<bool> {
        let entry = self
            .entry(id)
            .ok_or_else(|| SttError::UnknownModel(id.to_string()))?;
        let mut downloads = self.lock_downloads();
        if downloads
            .get(id)
            .map(|state| state.state == "downloading" || state.state == "verifying")
            .unwrap_or(false)
        {
            return Err(SttError::ModelDownloading(id.to_string()));
        }
        let path = self.dir.join(entry.filename);
        let removed = if path.is_file() {
            fs::remove_file(&path)?;
            true
        } else {
            false
        };
        downloads.remove(id);
        Ok(removed)
    }

    fn tmp_path(&self, filename: &str) -> PathBuf {
        self.dir
            .join(format!(".{filename}.part-{}", uuid::Uuid::new_v4()))
    }

    fn lock_downloads(&self) -> std::sync::MutexGuard<'_, HashMap<String, DownloadView>> {
        self.downloads.lock().unwrap_or_else(|err| err.into_inner())
    }
}

fn installed_view(entry: &ModelEntry) -> DownloadView {
    DownloadView {
        model_id: entry.id.to_string(),
        state: "installed".to_string(),
        downloaded_bytes: entry.size_bytes,
        total_bytes: entry.size_bytes,
        message: None,
    }
}

fn run_download(store: Arc<ModelStore>, entry: ModelEntry, fetcher: Arc<dyn ModelFetcher>) {
    let tmp = store.tmp_path(entry.filename);
    let target = store.dir.join(entry.filename);
    let url = match &store.mirror_base {
        Some(base) if !base.trim().is_empty() => {
            format!("{}/{}", base.trim_end_matches('/'), entry.filename)
        }
        _ => entry.url.to_string(),
    };

    let progress_store = Arc::clone(&store);
    let model_id = entry.id.to_string();
    let mut last_reported = 0u64;
    let result = fetcher.fetch(&url, &tmp, &mut |downloaded, total| {
        if downloaded.saturating_sub(last_reported) < 1024 * 1024 && total.is_some() {
            return;
        }
        last_reported = downloaded;
        if let Some(state) = progress_store.lock_downloads().get_mut(model_id.as_str()) {
            state.downloaded_bytes = downloaded;
            if let Some(total) = total {
                state.total_bytes = total;
            }
        }
    });

    if let Err(message) = result {
        let _ = fs::remove_file(&tmp);
        if let Some(state) = store.lock_downloads().get_mut(entry.id) {
            state.state = "error".to_string();
            state.message = Some(message);
        }
        tracing::warn!(model_id = %entry.id, "stt model download failed");
        return;
    }

    if let Some(state) = store.lock_downloads().get_mut(entry.id) {
        state.state = "verifying".to_string();
        state.downloaded_bytes = fs::metadata(&tmp).map(|meta| meta.len()).unwrap_or(0);
    }
    if let Err(err) = verify_file(&tmp, &entry) {
        let _ = fs::remove_file(&tmp);
        if let Some(state) = store.lock_downloads().get_mut(entry.id) {
            state.state = "error".to_string();
            state.message = Some(err.to_string());
        }
        tracing::warn!(model_id = %entry.id, "stt model checksum failed");
        return;
    }
    if let Err(err) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        if let Some(state) = store.lock_downloads().get_mut(entry.id) {
            state.state = "error".to_string();
            state.message = Some(format!("rename model into place: {err}"));
        }
        return;
    }
    store
        .lock_downloads()
        .insert(entry.id.to_string(), installed_view(&entry));
    tracing::info!(model_id = %entry.id, "stt model installed");
}

fn verify_file(path: &Path, entry: &ModelEntry) -> Result<()> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != entry.sha256 {
        return Err(SttError::ModelChecksumMismatch {
            model_id: entry.id.to_string(),
            expected: entry.sha256.to_string(),
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const BODY: &[u8] = b"tiny-model-bytes";

    struct StubFetcher {
        body: Vec<u8>,
        calls: AtomicUsize,
    }

    impl StubFetcher {
        fn new(body: &[u8]) -> Self {
            Self {
                body: body.to_vec(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl ModelFetcher for StubFetcher {
        fn fetch(
            &self,
            _url: &str,
            dest: &Path,
            progress: &mut dyn FnMut(u64, Option<u64>),
        ) -> std::result::Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            fs::write(dest, &self.body).map_err(|err| err.to_string())?;
            progress(self.body.len() as u64, Some(self.body.len() as u64));
            Ok(())
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn entry_with(hash: String) -> ModelEntry {
        ModelEntry {
            id: "tiny",
            name: "Tiny",
            description: "test model",
            filename: "tiny.bin",
            url: "https://example.invalid/tiny.bin",
            sha256: Box::leak(hash.into_boxed_str()),
            size_bytes: BODY.len() as u64,
            languages: &["zh", "en"],
            recommended: true,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wasmnest-stt-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wait_installed(store: &ModelStore, id: &str) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if store.is_installed(id) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("model {id} did not install in time: {:?}", store.status(id));
    }

    #[test]
    fn download_verifies_and_installs() {
        let dir = temp_dir("download");
        let fetcher = Arc::new(StubFetcher::new(BODY));
        let store = Arc::new(
            ModelStore::with_catalog(
                dir.clone(),
                Some(fetcher.clone()),
                None,
                vec![entry_with(sha256_hex(BODY))],
            )
            .unwrap(),
        );
        assert!(!store.is_installed("tiny"));
        store.download("tiny").unwrap();
        wait_installed(&store, "tiny");
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.status("tiny").unwrap().state, "installed");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn checksum_mismatch_surfaces_error() {
        let dir = temp_dir("bad-hash");
        let fetcher = Arc::new(StubFetcher::new(BODY));
        let store = Arc::new(
            ModelStore::with_catalog(
                dir.clone(),
                Some(fetcher),
                None,
                vec![entry_with("0".repeat(64))],
            )
            .unwrap(),
        );
        store.download("tiny").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = store.status("tiny").unwrap();
            if status.state == "error" {
                assert!(status.message.unwrap().contains("checksum"));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "download did not fail: {status:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!store.is_installed("tiny"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn import_copies_and_verifies() {
        let dir = temp_dir("import");
        let source_dir = temp_dir("import-src");
        let source = source_dir.join("tiny.bin");
        fs::write(&source, BODY).unwrap();
        let store =
            ModelStore::with_catalog(dir.clone(), None, None, vec![entry_with(sha256_hex(BODY))])
                .unwrap();
        assert!(store.import("tiny", &source).unwrap());
        assert!(store.is_installed("tiny"));
        assert_eq!(fs::read(store.path("tiny").unwrap()).unwrap(), BODY);
        assert!(!store.import("tiny", &source).unwrap());
        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(source_dir);
    }

    #[test]
    fn remove_rejects_while_downloading() {
        struct SlowFetcher;
        impl ModelFetcher for SlowFetcher {
            fn fetch(
                &self,
                _url: &str,
                _dest: &Path,
                _progress: &mut dyn FnMut(u64, Option<u64>),
            ) -> std::result::Result<(), String> {
                std::thread::sleep(Duration::from_millis(500));
                Err("slow".to_string())
            }
        }
        let dir = temp_dir("remove");
        let store = Arc::new(
            ModelStore::with_catalog(
                dir.clone(),
                Some(Arc::new(SlowFetcher)),
                None,
                vec![entry_with(sha256_hex(BODY))],
            )
            .unwrap(),
        );
        store.download("tiny").unwrap();
        let err = store.remove("tiny").unwrap_err();
        assert_eq!(err.kind(), "model-downloading");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mirror_replaces_directory_prefix() {
        struct UrlFetcher;
        impl ModelFetcher for UrlFetcher {
            fn fetch(
                &self,
                url: &str,
                dest: &Path,
                _progress: &mut dyn FnMut(u64, Option<u64>),
            ) -> std::result::Result<(), String> {
                assert_eq!(url, "https://mirror.invalid/tiny.bin");
                fs::write(dest, BODY).map_err(|err| err.to_string())
            }
        }
        let dir = temp_dir("mirror");
        let store = Arc::new(
            ModelStore::with_catalog(
                dir.clone(),
                Some(Arc::new(UrlFetcher)),
                Some("https://mirror.invalid/".to_string()),
                vec![entry_with(sha256_hex(BODY))],
            )
            .unwrap(),
        );
        store.download("tiny").unwrap();
        wait_installed(&store, "tiny");
        let _ = fs::remove_dir_all(dir);
    }
}
