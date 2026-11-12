//! Plugin Downloader / Installer（桌面端）
//!
//! 插件包（zip）本地安装：选择 zip → 解压（体积/条目上限）→ manifest/身份校验
//! → 路径穿越防护 → wasm 存在性与内容摘要校验 → 写来源标记 → 移动到用户插件目录
//! （app_data_dir/plugins）
//!
//! 分发单元为单个 zip（内含 plugin.json、index.js 与可选的 .wasm），与
//! scripts/package-plugins.mjs 产物（dist/plugin-packages/<target>/<id>.zip）一致。
//! 与移动端 downloader.rs 同形：`rust_library` 声明的 wasm 文件必须存在，
//! manifest 声明 `wasm_hash` 时再比对 SHA-256（缺省空串 = 发布者未声明，跳过）。
//!
//! 升级安装（`upgrade_from_file`）：同 id 已装时替换目录内容，仅保留插件私有库
//! （`plugin.db` 家族）。所有安全门禁（manifest/身份/路径/摘要/platform）在升级
//! 路径同样生效——升级只放宽「同 id 覆盖」这一条，其余裁决与首装完全一致。
//!
//! 归位说明（票 11 第 5 项）：本模块是 core-plugin-manager 的**安装**职责，
//! 已自 `plugin/downloader.rs` 迁到 `plugin/manager/`，引用路径同步为
//! `crate::manager::downloader`。

use crate::manager::validation::validate_plugin_id;
use crate::system::constants::{
    PLUGIN_DOWNLOAD_TEMP_DIR, PLUGIN_MANIFEST_FILE, PLUGIN_SOURCE_MARKER, SOURCE_FILE_INSTALL,
    WASM_FILE_EXT,
};
use crate::Result;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// zip 解压上限（宿主上下限；越界 fail-visible，绝不静默截断）
///
/// 取值面向「插件包」这一分发形态：产物是一个 index.js + 一个 wasm 模块，正常包
/// 在数 MB 量级。上限既拒绝 zip 炸弹（高压缩比膨胀填满磁盘），也拒绝单文件异常膨胀。
/// 「调用方声明」维度留给后续插件包元数据演进，本轮以宿主上下限为准。
struct ZipLimits {
    /// 条目总数上限
    max_entries: usize,
    /// 解压后总字节上限
    max_total_bytes: u64,
    /// 单文件解压后字节上限
    max_single_file_bytes: u64,
}

impl Default for ZipLimits {
    fn default() -> Self {
        Self {
            max_entries: 512,
            max_total_bytes: 64 * 1024 * 1024,
            max_single_file_bytes: 32 * 1024 * 1024,
        }
    }
}

/// 插件下载安装器
pub struct PluginDownloader;

/// fresh install 替换同 id 残留目录时的数据策略（宿主裁决后传入、默认丢弃）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallDataPolicy {
    /// 丢弃旧数据：残留目录整体清除（含 `plugin.db` 家族）
    Discard,
    /// 恢复旧数据：只保留 `plugin.db` 家族，代码文件全部换新
    Restore,
}

/// 安装模式（内部；决定同 id 目录能否替换、私有库是否保留）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallMode {
    /// 新装：同 id 有效安装目录一律拒绝覆盖
    RejectExisting,
    /// 升级：替换目录内容，恒保留私有库
    Upgrade,
    /// 替换残留：宿主已确认该 id 无运行时安装，按策略替换
    ReplaceResidue(InstallDataPolicy),
}

impl InstallMode {
    /// 同 id 目录存在时是否允许替换
    fn allows_replace(self) -> bool {
        !matches!(self, Self::RejectExisting)
    }

    /// 是否保留同 id 目录里的 `plugin.db` 家族
    fn preserves_private_db(self) -> bool {
        match self {
            // 新装遇到无 plugin.json 的孤儿目录（keep-data 残留）时保留私有库：
            // 与升级同口径，目录本身不构成有效安装，删除前先搬走数据。
            Self::RejectExisting | Self::Upgrade => true,
            Self::ReplaceResidue(policy) => matches!(policy, InstallDataPolicy::Restore),
        }
    }

    /// 日志标签
    fn label(self) -> &'static str {
        match self {
            Self::RejectExisting => "fresh",
            Self::Upgrade => "upgrade",
            Self::ReplaceResidue(InstallDataPolicy::Discard) => "replace-residue-discard",
            Self::ReplaceResidue(InstallDataPolicy::Restore) => "replace-residue-restore",
        }
    }
}

impl PluginDownloader {
    /// 从本地 zip 插件包安装
    ///
    /// 1. 打开 zip，校验 plugin.json 必填字段与 id 格式
    /// 2. 解压到临时目录（路径穿越防护）
    /// 3. wasm 文件存在性校验（manifest 声明 rust_library 时）
    /// 4. 写来源标记（file-install）
    /// 5. 移动到 user_plugins_dir/{plugin_id}/
    ///
    /// 拒绝覆盖已存在的同 id 插件（无签名链时无法区分「同作者更新」与
    /// 「冒名顶替替换」，升级走 `upgrade_from_file`，与移动端一致）。
    pub fn install_from_file(zip_path: &str, user_plugins_dir: &Path) -> Result<String> {
        let zip_path = Path::new(zip_path);
        if !zip_path.exists() {
            return Err(crate::AppError::Plugin(format!(
                "Plugin package not found: {}",
                zip_path.display()
            )));
        }
        Self::install_zip(zip_path, user_plugins_dir, InstallMode::RejectExisting)
    }

    /// 宿主已裁决「同 id 无运行时安装」后的 fresh install
    ///
    /// 磁盘上的同 id 目录不可能是当前生效安装，只可能是：
    /// - `keep_data` 卸载留下的私有库目录（无 plugin.json）；
    /// - 装载期重复裁决被拒的休眠副本 / tombstone 后的内置重装残留（含 plugin.json）。
    ///
    /// 这类目录不能交给 `install_from_file`（它按「有效安装」拒绝覆盖），否则
    /// 重装被旧目录卡死。是否保留旧数据由 `data_policy` 决定——**默认丢弃**，
    /// 只有用户显式选择恢复才保留 `plugin.db` 家族。manifest / 身份 / 路径 /
    /// 摘要 / platform 门禁与普通安装完全一致。
    pub fn install_from_file_replacing_residue(
        zip_path: &str,
        user_plugins_dir: &Path,
        data_policy: InstallDataPolicy,
    ) -> Result<String> {
        let zip_path = Path::new(zip_path);
        if !zip_path.exists() {
            return Err(crate::AppError::Plugin(format!(
                "Plugin package not found: {}",
                zip_path.display()
            )));
        }
        Self::install_zip(
            zip_path,
            user_plugins_dir,
            InstallMode::ReplaceResidue(data_policy),
        )
    }

    /// 升级安装（同 id 已装时替换目录内容；升级的应用版本更新链路专用）
    ///
    /// 与 `install_from_file` 的唯一差异：目标 id 已有有效安装时不再拒绝，而是
    /// **只保留插件私有库（`plugin.db` 家族）**后整体替换目录内容。manifest 校验、
    /// 身份校验、路径安全、wasm 摘要与 platform 门禁在升级路径一字不差——升级
    /// 放宽的只有「同 id 覆盖」，绝不放宽任何安全裁决。目标 id 未安装时退化为
    /// 普通安装（调用方不为「先查后装」多付一次竞态窗口）。
    pub fn upgrade_from_file(zip_path: &str, user_plugins_dir: &Path) -> Result<String> {
        let zip_path = Path::new(zip_path);
        if !zip_path.exists() {
            return Err(crate::AppError::Plugin(format!(
                "Plugin package not found: {}",
                zip_path.display()
            )));
        }
        Self::install_zip(zip_path, user_plugins_dir, InstallMode::Upgrade)
    }

    /// 读取 zip 内 plugin.json 的插件 id（升级前置：宿主层先于任何落盘动作裁决运行态）
    ///
    /// 校验口径与 `install_zip` 一致（manifest 必填 + id 反向域名），保证「预读通过
    /// 的 id」就是后续安装会落地的 id。
    pub fn peek_plugin_id(zip_path: &Path) -> Result<String> {
        let file = std::fs::File::open(zip_path).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to open plugin package: {}", e))
        })?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|e| crate::AppError::Plugin(format!("Invalid plugin package: {}", e)))?;
        let mut manifest_str = String::new();
        archive
            .by_name(PLUGIN_MANIFEST_FILE)
            .map_err(|e| {
                crate::AppError::Plugin(format!("Plugin package missing plugin.json: {}", e))
            })?
            .read_to_string(&mut manifest_str)
            .map_err(|e| crate::AppError::Plugin(format!("Failed to read plugin.json: {}", e)))?;
        let manifest = crate::manager::validation::parse_manifest_json(&manifest_str)?;
        if !validate_plugin_id(&manifest.id) {
            return Err(crate::AppError::Plugin(format!(
                "plugin.json id {:?} is invalid: must be a reverse-domain name like com.example.plugin",
                manifest.id
            )));
        }
        Ok(manifest.id)
    }

    /// zip 解压安装（本地文件；模式见 [`InstallMode`]）
    fn install_zip(zip_path: &Path, user_plugins_dir: &Path, mode: InstallMode) -> Result<String> {
        // 1. 打开 zip
        let file = std::fs::File::open(zip_path).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to open plugin package: {}", e))
        })?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|e| crate::AppError::Plugin(format!("Invalid plugin package: {}", e)))?;

        // 2. 读取并校验 manifest
        let mut manifest_str = String::new();
        archive
            .by_name(PLUGIN_MANIFEST_FILE)
            .map_err(|e| {
                crate::AppError::Plugin(format!("Plugin package missing plugin.json: {}", e))
            })?
            .read_to_string(&mut manifest_str)
            .map_err(|e| crate::AppError::Plugin(format!("Failed to read plugin.json: {}", e)))?;
        // 解析与必填字段校验走唯一真源（票 11 第 6 项）
        //
        // 注意：**域侧声明仲裁不在本入口**（票 02 批次 03 起，如 host-pty 的
        // `ptyQuota` 区间）——它挂在装载漏斗的 `DomainHooks::on_manifest_load` 上，
        // 故越界声明在安装期可通过、**装载期被该域拒绝**（fail-visible：插件不装载，
        // 错误日志点名越界值与字段名）。安装期只保证结构性必填字段成立。
        let manifest = crate::manager::validation::parse_manifest_json(&manifest_str)?;
        // 身份校验：id 必须为反向域名格式（防伪造 id 冒名顶替/路径注入）——安装入口独有的一道
        if !validate_plugin_id(&manifest.id) {
            return Err(crate::AppError::Plugin(format!(
                "plugin.json id {:?} is invalid: must be a reverse-domain name like com.example.plugin",
                manifest.id
            )));
        }

        let plugin_id = manifest.id.clone();
        let temp_dir = user_plugins_dir
            .join(PLUGIN_DOWNLOAD_TEMP_DIR)
            .join(&plugin_id);

        // 3. 解压到临时目录
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir)
                .map_err(|e| crate::AppError::Plugin(format!("Failed to clear temp dir: {}", e)))?;
        }
        std::fs::create_dir_all(&temp_dir)
            .map_err(|e| crate::AppError::Plugin(format!("Failed to create temp dir: {}", e)))?;

        // 3. 解压到临时目录（含体积/条目上限裁决）；失败路径清理临时目录，不留半成品
        if let Err(e) = Self::extract_entries(&mut archive, &temp_dir, &ZipLimits::default()) {
            Self::cleanup_temp_dir(&temp_dir);
            return Err(e);
        }

        // 4. WASM 文件校验：声明 rust_library 时必须存在；声明 wasm_hash 时必须摘要一致
        if !manifest.rust_library.is_empty() {
            let wasm_path = temp_dir.join(format!("{}{}", manifest.rust_library, WASM_FILE_EXT));
            if !wasm_path.exists() {
                Self::cleanup_temp_dir(&temp_dir);
                return Err(crate::AppError::Plugin(format!(
                    "Plugin package missing WASM file: {}{}",
                    manifest.rust_library, WASM_FILE_EXT
                )));
            }
            if !manifest.wasm_hash.trim().is_empty() {
                let actual = match Self::sha256_file(&wasm_path) {
                    Ok(hash) => hash,
                    Err(e) => {
                        Self::cleanup_temp_dir(&temp_dir);
                        return Err(e);
                    }
                };
                if !actual.eq_ignore_ascii_case(manifest.wasm_hash.trim()) {
                    Self::cleanup_temp_dir(&temp_dir);
                    return Err(crate::AppError::Plugin(format!(
                        "Plugin package WASM content mismatch for {}{}: manifest declares {}, actual {}",
                        manifest.rust_library, WASM_FILE_EXT, manifest.wasm_hash, actual
                    )));
                }
            } else {
                tracing::debug!(
                    plugin_id = %plugin_id,
                    "[PluginDownloader] manifest 未声明 wasm_hash，跳过 WASM 内容摘要校验（内容钉扎由审批门禁承担）"
                );
            }
        }

        // 4b. worker 产物摘要：`workers[].wasmHash` 与主 `wasmHash` **同语义**——
        // 声明即校验、缺省跳过（spec §3.7「wasmHash 语义与主 wasm 一致」）。
        // 只校验声明了摘要的条目：未声明时按「安装期只保结构性必填、文件存在性
        // 交装载入口」的分层**不查**（与 ptyQuota 同款，见 install_zip 头注）；
        // 声明了就无法跳过——读不到文件等于摘要无从比对，直接拒绝并点名。
        //
        // 落在这里而不是装载入口：主 wasm 的摘要校验就在这里，两处同一入口才有
        // 「语义一致」可言；装载入口（`validate_worker_files`）只保文件存在性。
        for worker in &manifest.workers {
            if worker.wasm_hash.trim().is_empty() {
                continue;
            }
            let wasm_path = temp_dir.join("worker").join(&worker.file);
            if !wasm_path.is_file() {
                Self::cleanup_temp_dir(&temp_dir);
                return Err(crate::AppError::Plugin(format!(
                    "Plugin package missing worker WASM: worker/{}\
                     （workers[{}] 声明了 wasmHash，摘要校验需要文件在场）",
                    worker.file, worker.name
                )));
            }
            let actual = match Self::sha256_file(&wasm_path) {
                Ok(hash) => hash,
                Err(e) => {
                    Self::cleanup_temp_dir(&temp_dir);
                    return Err(e);
                }
            };
            if !actual.eq_ignore_ascii_case(worker.wasm_hash.trim()) {
                Self::cleanup_temp_dir(&temp_dir);
                return Err(crate::AppError::Plugin(format!(
                    "Plugin package worker WASM content mismatch for worker/{} (workers[{}]): \
                     manifest declares {}, actual {}",
                    worker.file, worker.name, worker.wasm_hash, actual
                )));
            }
        }

        // 5. 写来源标记（供 dev 副本刷新/未来磁盘审计区分安装来源）
        let marker = temp_dir.join(PLUGIN_SOURCE_MARKER);
        std::fs::write(&marker, SOURCE_FILE_INSTALL).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to write source marker: {}", e))
        })?;

        // 6. 移动到最终目录
        //
        // 默认拒绝覆盖已存在的同 id 有效安装：无签名链时无法区分「同作者更新」与
        // 「冒名顶替替换」，静默替换会让既有权限继续作用于被替换后的新代码，
        // 是权限门禁的旁路。只有两种模式允许替换：
        // - `Upgrade`：宿主已裁决可更新（保数据换代码）；
        // - `ReplaceResidue`：宿主已确认该 id **无运行时安装**，目录只能是残留
        //   （keep-data 卸载 / 被重复裁决拒绝的休眠副本 / tombstone 后重装），
        //   按 `InstallDataPolicy` 决定是否保留旧数据（默认丢弃）。
        //
        // 例外：目录内无 plugin.json 的「孤儿残留」不构成有效安装，默认新装也
        // 先搬走私有库再清目录；Discard 策略则连私有库一起删。
        let final_dir = user_plugins_dir.join(&plugin_id);
        let preserves_db = mode.preserves_private_db();
        if final_dir.exists() && final_dir.join(PLUGIN_MANIFEST_FILE).exists() {
            if !mode.allows_replace() {
                let _ = std::fs::remove_dir_all(&temp_dir);
                return Err(crate::AppError::Plugin(format!(
                    "Plugin '{}' is already installed. Uninstall it first to install a new version.",
                    plugin_id
                )));
            }
            if preserves_db {
                // 私有库（plugin.db 家族）先搬进新包临时目录，再整体换目录——
                // 主库侧的插件存储 / 审批记录按 plugin_id 键存续（宿主层不经卸载路径）
                Self::preserve_private_db(&final_dir, &temp_dir)?;
            } else {
                tracing::info!(
                    plugin_id = %plugin_id,
                    dir = %final_dir.display(),
                    "[PluginDownloader] Discarding retained plugin data before install"
                );
            }
            std::fs::remove_dir_all(&final_dir).map_err(|e| {
                crate::AppError::Plugin(format!(
                    "Failed to remove old plugin dir '{}': {}",
                    final_dir.display(),
                    e
                ))
            })?;
        } else if final_dir.exists() {
            // 无 plugin.json 的孤儿目录（历史安装 / keep-data 卸载留下的插件私有库）：
            // 默认先保留 `plugin.db` 家族再清目录（否则重装会静默丢数据）；
            // Discard 策略按用户选择丢弃旧数据。
            if preserves_db {
                Self::preserve_private_db(&final_dir, &temp_dir)?;
                tracing::warn!(
                    plugin_id = %plugin_id,
                    dir = %final_dir.display(),
                    "[PluginDownloader] Preserving private db from orphan residue dir (no plugin.json) before install"
                );
            } else {
                tracing::info!(
                    plugin_id = %plugin_id,
                    dir = %final_dir.display(),
                    "[PluginDownloader] Discarding orphan residue dir (no plugin.json) before install"
                );
            }
            std::fs::remove_dir_all(&final_dir).map_err(|e| {
                crate::AppError::Plugin(format!(
                    "Failed to remove orphan dir '{}': {}",
                    final_dir.display(),
                    e
                ))
            })?;
        }
        std::fs::rename(&temp_dir, &final_dir).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to move plugin into place: {}", e))
        })?;

        tracing::info!(
            "[PluginDownloader] Plugin '{}' installed to {:?} (source: {}, mode: {})",
            plugin_id,
            final_dir,
            SOURCE_FILE_INSTALL,
            mode.label()
        );
        Ok(plugin_id)
    }

    /// 升级路径的私有库保留：`plugin.db` 及其 sqlite 伴生文件（-wal / -shm）搬进新包目录
    ///
    /// 前置：宿主层已停用插件并丢弃私有库连接（`drop_plugin_db`），文件不再被打开；
    /// 同卷 rename 保证原子性。伴生文件一并保留：连接被正常关闭时它们应已被 sqlite
    /// 收敛，但「升级途中丢数据」的代价远高于多搬两个文件。
    fn preserve_private_db(old_dir: &Path, new_dir: &Path) -> Result<()> {
        let entries = std::fs::read_dir(old_dir).map_err(|e| {
            crate::AppError::Plugin(format!(
                "Failed to read old plugin dir '{}': {}",
                old_dir.display(),
                e
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                crate::AppError::Plugin(format!(
                    "Failed to read old plugin dir entry '{}': {}",
                    old_dir.display(),
                    e
                ))
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name != "plugin.db" && !name.starts_with("plugin.db-") {
                continue;
            }
            let from = entry.path();
            let to = new_dir.join(entry.file_name());
            std::fs::rename(&from, &to).map_err(|e| {
                crate::AppError::Plugin(format!(
                    "Failed to preserve plugin database '{}': {}",
                    from.display(),
                    e
                ))
            })?;
            tracing::info!(
                file = %name,
                "[PluginDownloader] Preserved plugin private database on upgrade"
            );
        }
        Ok(())
    }

    /// zip 条目路径安全校验：拒绝绝对路径、盘符、.. 路径穿越
    fn is_safe_zip_name(name: &str) -> bool {
        if name.starts_with('/') || name.starts_with('\\') {
            return false;
        }
        if name.contains(':') {
            return false;
        }
        // 规范化后检查是否有 .. 段
        let normalized = name.replace('\\', "/");
        if normalized.split('/').any(|seg| seg == ".." || seg == ".") {
            return false;
        }
        true
    }

    /// 解压全部条目到 `temp_dir`，逐层裁决上限（条目数 / 单文件 / 总量）
    ///
    /// 上限按**实际写入字节数**裁决：zip 头部声明的 uncompressed size 可被伪造
    /// （读取时被 `take` 截断即报错），因此不以声明值为准。
    fn extract_entries(
        archive: &mut zip::ZipArchive<std::fs::File>,
        temp_dir: &Path,
        limits: &ZipLimits,
    ) -> Result<()> {
        if archive.len() > limits.max_entries {
            return Err(crate::AppError::Plugin(format!(
                "Plugin package has too many entries: {} (limit {})",
                archive.len(),
                limits.max_entries
            )));
        }

        let mut total_bytes: u64 = 0;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).map_err(|e| {
                crate::AppError::Plugin(format!("Failed to read plugin package entry: {}", e))
            })?;
            let name = entry.name().to_string();
            if entry.is_dir() {
                continue;
            }
            if !Self::is_safe_zip_name(&name) {
                return Err(crate::AppError::Plugin(format!(
                    "Plugin package contains unsafe path: {}",
                    name
                )));
            }
            let dest = temp_dir.join(&name);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    crate::AppError::Plugin(format!("Failed to create '{}': {}", name, e))
                })?;
            }
            let mut out = std::fs::File::create(&dest).map_err(|e| {
                crate::AppError::Plugin(format!("Failed to create '{}': {}", name, e))
            })?;
            let written = {
                // 多读 1 字节以识别「刚好越界」；上限取 u64::MAX 时饱和，避免探测值溢出
                let mut limited = (&mut entry).take(limits.max_single_file_bytes.saturating_add(1));
                std::io::copy(&mut limited, &mut out).map_err(|e| {
                    crate::AppError::Plugin(format!("Failed to extract '{}': {}", name, e))
                })?
            };
            if written > limits.max_single_file_bytes {
                return Err(crate::AppError::Plugin(format!(
                    "Plugin package entry '{}' exceeds size limit ({} bytes)",
                    name, limits.max_single_file_bytes
                )));
            }
            total_bytes = total_bytes.saturating_add(written);
            if total_bytes > limits.max_total_bytes {
                return Err(crate::AppError::Plugin(format!(
                    "Plugin package exceeds total size limit ({} bytes)",
                    limits.max_total_bytes
                )));
            }
        }
        Ok(())
    }

    /// 失败路径清理临时目录（残留会在下次安装时被「先清后建」兜底，但白占磁盘）
    fn cleanup_temp_dir(dir: &Path) {
        if dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(dir) {
                tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "[PluginDownloader] 清理插件安装临时目录失败"
                );
            }
        }
    }

    /// 计算文件 SHA-256（小写十六进制）
    fn sha256_file(path: &Path) -> Result<String> {
        let content = std::fs::read(path).map_err(|e| {
            crate::AppError::Plugin(format!(
                "Failed to read '{}' for digest: {}",
                path.display(),
                e
            ))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// 构造一个合法插件 zip：plugin.json + index.js + 可选 wasm 文件
    /// `declares_wasm` 控制 manifest 是否声明 rust_library；`includes_wasm_file` 控制 zip 是否含该文件
    fn build_plugin_zip(
        dir: &Path,
        id: &str,
        declares_wasm: bool,
        includes_wasm_file: bool,
    ) -> PathBuf {
        build_plugin_zip_with_platform(dir, id, declares_wasm, includes_wasm_file, "both")
    }

    /// 同上，manifest `platform` 可指定（端门禁用例构造另一端专属声明）
    fn build_plugin_zip_with_platform(
        dir: &Path,
        id: &str,
        declares_wasm: bool,
        includes_wasm_file: bool,
        platform: &str,
    ) -> PathBuf {
        let zip_path = dir.join(format!("{}.zip", id));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);

        let wasm_name = format!("lib_{}", id.replace('.', "_"));
        let manifest = serde_json::json!({
            "id": id,
            "name": "Test Plugin",
            "version": "1.0.0",
            "platform": platform,
            "main": "index.js",
            "pluginType": if declares_wasm { "full" } else { "frontend" },
            "rustLibrary": if declares_wasm { wasm_name.clone() } else { String::new() },
            "permissions": [],
            "contributes": {}
        })
        .to_string();
        writer
            .start_file(
                PLUGIN_MANIFEST_FILE,
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(manifest.as_bytes()).unwrap();
        writer
            .start_file("index.js", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"console.log('test')").unwrap();
        if includes_wasm_file {
            writer
                .start_file(
                    format!("{}.wasm", wasm_name),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            writer.write_all(&[0u8; 8]).unwrap();
        }
        writer.finish().unwrap();
        zip_path
    }

    /// 构造一个带 worker 声明的插件 zip（`worker/hasher.wasm` + `workers[]`）
    ///
    /// `declared_hash` 直接写进 manifest（`None` = 未声明）。
    fn build_worker_zip(
        dir: &Path,
        id: &str,
        declared_hash: Option<&str>,
        payload: &[u8],
    ) -> PathBuf {
        let zip_path = dir.join(format!("{}.zip", id));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);

        let mut worker = serde_json::json!({ "name": "hasher", "file": "hasher.wasm" });
        if let Some(hash) = declared_hash {
            worker["wasmHash"] = serde_json::Value::String(hash.to_string());
        }
        let manifest = serde_json::json!({
            "id": id,
            "name": "Worker Plugin",
            "version": "1.0.0",
            "platform": "both",
            "pluginType": "backend",
            "workers": [worker],
            "permissions": [],
            "contributes": {}
        })
        .to_string();
        writer
            .start_file(
                PLUGIN_MANIFEST_FILE,
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(manifest.as_bytes()).unwrap();
        writer
            .start_file(
                "worker/hasher.wasm",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(payload).unwrap();
        writer.finish().unwrap();
        zip_path
    }

    /// worker 产物摘要与主 `wasmHash` 同入口校验（worker 机制 spec §3.7）
    ///
    /// 变异判据：摘掉 `install_zip` 的 4b 段，摘要不符的包会静默安装成功——声明了
    /// 摘要却不校验，等于把完整性声明当装饰。三条覆盖：不符拒绝 / 相符放行 /
    /// 未声明跳过（缺省不校验 = 与主 wasm 同语义）。
    #[test]
    fn install_checks_worker_wasm_hash() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        let payload = b"worker-wasm-bytes";

        // 反例：摘要不符 → 拒绝，且错误点名 worker 名与文件名
        let id = "com.test.worker-bad";
        let zip = build_worker_zip(tmp.path(), id, Some("deadbeef"), payload);
        let err =
            PluginDownloader::install_from_file(zip.to_str().unwrap(), &plugins_dir).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("worker WASM content mismatch")
                && text.contains("worker/hasher.wasm")
                && text.contains("hasher"),
            "摘要不符必须点名 worker 与文件，got: {text}"
        );
        assert!(!plugins_dir.join(id).exists(), "拒绝后不得留下半个插件目录");

        // 正例：摘要相符 → 安装成功，worker 产物落在插件包 worker/ 下
        let id = "com.test.worker-ok";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let real = format!("{:x}", hasher.finalize());
        assert_eq!(real.len(), 64, "sha256 十六进制摘要定长");
        let zip = build_worker_zip(tmp.path(), id, Some(&real), payload);
        PluginDownloader::install_from_file(zip.to_str().unwrap(), &plugins_dir).unwrap();
        assert!(plugins_dir
            .join(id)
            .join("worker")
            .join("hasher.wasm")
            .is_file());

        // 未声明摘要 → 跳过校验（缺省不校验，与主 wasm 同语义）
        let id = "com.test.worker-nohash";
        let zip = build_worker_zip(tmp.path(), id, None, payload);
        PluginDownloader::install_from_file(zip.to_str().unwrap(), &plugins_dir).unwrap();
    }

    #[test]
    fn install_from_file_ok_and_writes_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let zip_path = build_plugin_zip(tmp.path(), "com.test.install-ok", false, false);

        let id =
            PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        assert_eq!(id, "com.test.install-ok");

        let final_dir = plugins_dir.join(&id);
        assert!(final_dir.join("plugin.json").exists());
        assert!(final_dir.join("index.js").exists());
        // 来源标记写入（file-install）
        assert_eq!(
            std::fs::read_to_string(final_dir.join(PLUGIN_SOURCE_MARKER)).unwrap(),
            SOURCE_FILE_INSTALL
        );
        // 临时目录已清理（rename 而非残留）
        assert!(!plugins_dir
            .join(PLUGIN_DOWNLOAD_TEMP_DIR)
            .join(&id)
            .exists());
    }

    #[test]
    fn install_requires_wasm_file_when_declared() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        // 声明了 rust_library 但 zip 缺失 wasm 文件 → 拒绝安装
        let zip_path = build_plugin_zip(tmp.path(), "com.test.missing-wasm", true, false);

        let err = PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        assert!(err.to_string().contains("missing WASM"));
        assert!(!plugins_dir.join("com.test.missing-wasm").exists());
    }

    #[test]
    fn install_accepts_wasm_plugin_with_file() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let zip_path = build_plugin_zip(tmp.path(), "com.test.with-wasm", true, true);

        let id =
            PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        assert_eq!(id, "com.test.with-wasm");
        let installed = std::fs::read_dir(plugins_dir.join(&id)).unwrap();
        assert!(installed.into_iter().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".wasm")));
    }

    #[test]
    fn install_rejects_duplicate_id() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let zip_path = build_plugin_zip(tmp.path(), "com.test.dup", false, false);

        PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        let err = PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        assert!(err.to_string().contains("already installed"));
    }

    /// 孤儿残留目录（无 plugin.json，如历史安装遗留的私有数据库 plugin.db）不阻塞
    /// 重装：安装前识别为无效安装，清除后继续安装新版本
    #[test]
    fn install_replaces_orphan_dir_without_plugin_json() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.orphan-replace";

        // 预置孤儿残留：只有私有数据库文件，无 plugin.json（loader 会跳过它）
        let orphan_dir = plugins_dir.join(id);
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("plugin.db"), b"orphan db").unwrap();

        let zip_path = build_plugin_zip(tmp.path(), id, false, false);
        let installed =
            PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        assert_eq!(installed, id);

        // 孤儿残留被替换：新插件文件就位；默认入口保留私有库（keep-data 重装语义，
        // 是否丢弃由宿主调用 `install_from_file_replacing_residue(Discard)` 决定）
        assert_eq!(
            std::fs::read(orphan_dir.join("plugin.db")).unwrap(),
            b"orphan db"
        );
        assert!(orphan_dir.join("plugin.json").exists());
        assert!(orphan_dir.join("index.js").exists());
    }

    /// 有效安装目录（含 plugin.json）仍拒绝覆盖：无签名链时无法区分同作者更新与
    /// 冒名顶替，静默替换是权限门禁旁路，升级必须先卸载
    #[test]
    fn install_still_rejects_valid_existing_install() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.valid-exists";

        // 预置含 plugin.json 的同 id 安装目录（模拟已安装的旧版本）
        let existing = plugins_dir.join(id);
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(
            existing.join("plugin.json"),
            "{\"id\":\"com.test.valid-exists\"}",
        )
        .unwrap();
        std::fs::write(existing.join("index.js"), "old").unwrap();

        let zip_path = build_plugin_zip(tmp.path(), id, false, false);
        let err = PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        assert!(err.to_string().contains("already installed"));

        // 原安装目录保持原样，未被替换；临时目录已清理
        assert_eq!(
            std::fs::read_to_string(existing.join("index.js")).unwrap(),
            "old"
        );
        assert!(!plugins_dir.join(PLUGIN_DOWNLOAD_TEMP_DIR).join(id).exists());
    }

    /// 宿主裁决「无运行时安装」后替换残留（含 plugin.json 的休眠副本）：默认丢弃旧数据
    #[test]
    fn install_replacing_residue_discards_private_db() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.residue-discard";

        // 预置带 plugin.json 的同 id 残留（装载期重复裁决留下的休眠副本）
        let residue = plugins_dir.join(id);
        std::fs::create_dir_all(&residue).unwrap();
        std::fs::write(
            residue.join("plugin.json"),
            r#"{"id":"com.test.residue-discard"}"#,
        )
        .unwrap();
        std::fs::write(residue.join("index.js"), "old").unwrap();
        std::fs::write(residue.join("plugin.db"), b"old-db").unwrap();
        std::fs::write(residue.join("plugin.db-wal"), b"old-wal").unwrap();

        let zip_path = build_plugin_zip(tmp.path(), id, false, false);
        let installed = PluginDownloader::install_from_file_replacing_residue(
            zip_path.to_str().unwrap(),
            &plugins_dir,
            InstallDataPolicy::Discard,
        )
        .unwrap();
        assert_eq!(installed, id);

        // 包内容换新；旧数据（私有库 + 伴生文件）全部丢弃
        assert_eq!(
            std::fs::read_to_string(residue.join("index.js")).unwrap(),
            "console.log('test')"
        );
        assert!(
            !residue.join("plugin.db").exists(),
            "Discard 必须删除 plugin.db"
        );
        assert!(
            !residue.join("plugin.db-wal").exists(),
            "Discard 必须删除 plugin.db-wal"
        );
        assert!(!plugins_dir.join(PLUGIN_DOWNLOAD_TEMP_DIR).join(id).exists());
    }

    /// 恢复旧数据：只保留 plugin.db 家族，代码文件全部换新
    #[test]
    fn install_replacing_residue_restores_private_db() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.residue-restore";

        let residue = plugins_dir.join(id);
        std::fs::create_dir_all(&residue).unwrap();
        std::fs::write(
            residue.join("plugin.json"),
            r#"{"id":"com.test.residue-restore"}"#,
        )
        .unwrap();
        std::fs::write(residue.join("index.js"), "old").unwrap();
        std::fs::write(residue.join("plugin.db"), b"keep-db").unwrap();
        std::fs::write(residue.join("plugin.db-wal"), b"keep-wal").unwrap();

        let zip_path = build_plugin_zip(tmp.path(), id, false, false);
        let installed = PluginDownloader::install_from_file_replacing_residue(
            zip_path.to_str().unwrap(),
            &plugins_dir,
            InstallDataPolicy::Restore,
        )
        .unwrap();
        assert_eq!(installed, id);

        // 代码换新，私有库与伴生文件保留
        assert_eq!(
            std::fs::read_to_string(residue.join("index.js")).unwrap(),
            "console.log('test')"
        );
        assert_eq!(
            std::fs::read(residue.join("plugin.db")).unwrap(),
            b"keep-db"
        );
        assert_eq!(
            std::fs::read(residue.join("plugin.db-wal")).unwrap(),
            b"keep-wal"
        );
        assert!(!plugins_dir.join(PLUGIN_DOWNLOAD_TEMP_DIR).join(id).exists());
    }

    /// 数据-only 孤儿目录 + Discard：旧私有库不得复活到新包
    #[test]
    fn install_replacing_residue_discards_orphan_private_db() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.orphan-discard";

        let orphan = plugins_dir.join(id);
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join("plugin.db"), b"orphan-db").unwrap();

        let zip_path = build_plugin_zip(tmp.path(), id, false, false);
        PluginDownloader::install_from_file_replacing_residue(
            zip_path.to_str().unwrap(),
            &plugins_dir,
            InstallDataPolicy::Discard,
        )
        .unwrap();

        assert!(orphan.join("plugin.json").exists(), "新包已落地");
        assert!(
            !orphan.join("plugin.db").exists(),
            "Discard 必须丢弃孤儿私有库"
        );
    }

    #[test]
    fn is_safe_zip_name_rejects_traversal() {
        assert!(PluginDownloader::is_safe_zip_name("index.js"));
        assert!(PluginDownloader::is_safe_zip_name("sub/dir/file.js"));
        assert!(!PluginDownloader::is_safe_zip_name("../evil.js"));
        assert!(!PluginDownloader::is_safe_zip_name("/abs/path.js"));
        assert!(!PluginDownloader::is_safe_zip_name("C:\\windows\\evil.exe"));
        assert!(!PluginDownloader::is_safe_zip_name("sub/../evil.js"));
    }

    #[test]
    fn install_rejects_invalid_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        // 无 plugin.json 的 zip
        let bad_zip = tmp.path().join("bad.zip");
        let file = std::fs::File::create(&bad_zip).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("index.js", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        writer.finish().unwrap();

        let err = PluginDownloader::install_from_file(bad_zip.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        assert!(err.to_string().contains("missing plugin.json"));
    }

    /// `platform` 门禁（桌面端）：仅移动端声明的 zip 在安装期显性拒绝
    ///
    /// 与目录扫描侧 `validate_platform` 同判据：两条安装入口都经
    /// `parse_manifest_json` 漏斗，任一侧摘掉门禁即转红。拒绝必须发生在
    /// 任何落盘之前（目标目录与临时目录都不该出现）。
    #[cfg(feature = "desktop-assembly")]
    #[test]
    fn install_rejects_platform_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let zip_path = build_plugin_zip_with_platform(
            tmp.path(),
            "com.test.mobile-only",
            false,
            false,
            "mobile",
        );

        let err = PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("platform") && text.contains("mobile") && text.contains("both"),
            "拒绝必须点名字段、声明值与可用取值，got: {text}"
        );
        assert!(!plugins_dir.join("com.test.mobile-only").exists());
        assert!(!plugins_dir
            .join(PLUGIN_DOWNLOAD_TEMP_DIR)
            .join("com.test.mobile-only")
            .exists());
    }

    /// 构造声明 rust_library + wasmHash 的 full 形态插件 zip
    fn build_wasm_zip(dir: &Path, id: &str, wasm_bytes: &[u8], declared_hash: &str) -> PathBuf {
        let zip_path = dir.join(format!("{}.zip", id));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);

        let wasm_name = format!("lib_{}", id.replace('.', "_"));
        let manifest = serde_json::json!({
            "id": id,
            "name": "Test Plugin",
            "version": "1.0.0",
            "platform": "both",
            "main": "index.js",
            "pluginType": "full",
            "rustLibrary": wasm_name,
            "wasmHash": declared_hash,
            "permissions": [],
            "contributes": {}
        })
        .to_string();
        writer
            .start_file(
                PLUGIN_MANIFEST_FILE,
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(manifest.as_bytes()).unwrap();
        writer
            .start_file("index.js", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"console.log('test')").unwrap();
        writer
            .start_file(
                format!("{}.wasm", wasm_name),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(wasm_bytes).unwrap();
        writer.finish().unwrap();
        zip_path
    }

    /// 测试侧独立计算摘要（不复用被测实现，避免自证）
    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    /// 构造含任意文件的 zip（用于解压上限裁决）
    fn build_files_zip(dir: &Path, name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let zip_path = dir.join(name);
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (entry_name, content) in files {
            writer
                .start_file(*entry_name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
        zip_path
    }

    fn open_archive(path: &Path) -> zip::ZipArchive<std::fs::File> {
        zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap()
    }

    /// 声明的 wasmHash 与实际文件不符 → 拒绝安装（内容被替换的包不得落地）
    #[test]
    fn install_rejects_wasm_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.hash-mismatch";
        let wasm_bytes = b"REAL-WASM-BYTES";

        let zip_path = build_wasm_zip(tmp.path(), id, wasm_bytes, &sha256_hex(b"TAMPERED-BYTES"));
        let err = PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        assert!(
            err.to_string().contains("WASM content mismatch"),
            "错误必须点明是内容摘要不符，实际: {err}"
        );
        assert!(!plugins_dir.join(id).exists(), "校验失败不得留下安装目录");
        assert!(
            !plugins_dir.join(PLUGIN_DOWNLOAD_TEMP_DIR).join(id).exists(),
            "校验失败必须清理临时目录"
        );
    }

    /// 声明的 wasmHash 与实际文件一致 → 安装成功（正例，含大小写不敏感）
    #[test]
    fn install_accepts_matching_wasm_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.hash-match";
        let wasm_bytes = b"REAL-WASM-BYTES";

        let declared = sha256_hex(wasm_bytes).to_uppercase();
        let zip_path = build_wasm_zip(tmp.path(), id, wasm_bytes, &declared);
        let installed =
            PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        assert_eq!(installed, id);
        assert!(plugins_dir.join(id).join("plugin.json").exists());
    }

    /// 未声明 wasmHash（空串）→ 跳过摘要校验（既有包零迁移）
    #[test]
    fn install_skips_digest_when_hash_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.hash-absent";

        let zip_path = build_wasm_zip(tmp.path(), id, b"ANY-WASM", "");
        let installed =
            PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        assert_eq!(installed, id);
    }

    /// 跨语言真源锁（票 14）：生产者 `packages/plugin-sdk-desktop/bin/wasm-hash.js` 与宿主
    /// 必须算出同一个串。这里的向量与 SDK 用例 `__tests__/wasm-hash.test.ts` 的
    /// `WASM_BYTES_SHA256` 是同一条（外部独立实现算出后双向钉死）——换算法、换大小写、
    /// 换取文件规则，两侧任一偏离都在此转红。
    #[test]
    fn producer_and_host_share_the_same_digest_vector() {
        const VECTOR_BYTES: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        const VECTOR_SHA256: &str =
            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476";

        // 取文件规则同源：JS 侧 `${rustLibrary}.wasm` 用的字面量必须等于本常量
        assert_eq!(
            WASM_FILE_EXT, ".wasm",
            "生产者按 `.wasm` 后缀取文件，改这里要同步改 wasm-hash.js"
        );

        let tmp = tempfile::tempdir().unwrap();
        let wasm = tmp.path().join("wasmnest_plugin_vector.wasm");
        std::fs::write(&wasm, VECTOR_BYTES).unwrap();
        assert_eq!(
            PluginDownloader::sha256_file(&wasm).unwrap(),
            VECTOR_SHA256,
            "宿主摘要与生产者钉死的向量不符（算法/输出形态漂移）"
        );

        // 生产者产出的清单值确实被宿主接受（小写 64 位十六进制、trim 后比对）
        let plugins_dir = tmp.path().join("plugins");
        let zip_path = build_wasm_zip(
            tmp.path(),
            "com.test.vector-pin",
            VECTOR_BYTES,
            VECTOR_SHA256,
        );
        let installed =
            PluginDownloader::install_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        assert_eq!(installed, "com.test.vector-pin");

        // 反例：同一批字节但摘要被换成另一条合法形态的向量 → 拒装
        let bad_zip = build_wasm_zip(
            tmp.path(),
            "com.test.vector-drift",
            VECTOR_BYTES,
            "3f499bf4c9e7483e804244d5e485b3537b2135690a7ce7b3fd7cb2544217d729",
        );
        let err = PluginDownloader::install_from_file(bad_zip.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        assert!(
            err.to_string().contains("WASM content mismatch"),
            "摘要漂移必须被拒装，实际: {err}"
        );
    }

    /// 条目数超上限 → 拒绝（限内放行，验证裁决确实按 limits 走）
    #[test]
    fn extract_rejects_entry_count_over_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = build_files_zip(
            tmp.path(),
            "entries.zip",
            &[("a.js", b"a"), ("b.js", b"b"), ("c.js", b"c")],
        );
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();

        let over = ZipLimits {
            max_entries: 2,
            ..Default::default()
        };
        let err = PluginDownloader::extract_entries(&mut open_archive(&zip_path), &out, &over)
            .unwrap_err();
        assert!(err.to_string().contains("too many entries"), "实际: {err}");

        let within = ZipLimits {
            max_entries: 3,
            ..Default::default()
        };
        PluginDownloader::extract_entries(&mut open_archive(&zip_path), &out, &within).unwrap();
        assert!(out.join("a.js").exists());
        assert!(out.join("c.js").exists());
    }

    /// 单文件超上限 → 拒绝（声明尺寸不可信，按实际写入字节裁决）
    #[test]
    fn extract_rejects_single_file_over_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = build_files_zip(tmp.path(), "single.zip", &[("big.bin", &[0u8; 16])]);
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();

        let limits = ZipLimits {
            max_single_file_bytes: 8,
            ..Default::default()
        };
        let err = PluginDownloader::extract_entries(&mut open_archive(&zip_path), &out, &limits)
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds size limit"),
            "实际: {err}"
        );

        // 上限放到 16 → 放行
        let limits_ok = ZipLimits {
            max_single_file_bytes: 16,
            ..Default::default()
        };
        PluginDownloader::extract_entries(&mut open_archive(&zip_path), &out, &limits_ok).unwrap();
        assert_eq!(std::fs::metadata(out.join("big.bin")).unwrap().len(), 16);
    }

    /// 解压总量超上限 → 拒绝（多个小文件合计越界也要拦住）
    #[test]
    fn extract_rejects_total_bytes_over_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = build_files_zip(
            tmp.path(),
            "total.zip",
            &[
                ("a.bin", &[0u8; 10]),
                ("b.bin", &[0u8; 10]),
                ("c.bin", &[0u8; 10]),
            ],
        );
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();

        let limits = ZipLimits {
            max_total_bytes: 25,
            max_single_file_bytes: u64::MAX,
            ..Default::default()
        };
        let err = PluginDownloader::extract_entries(&mut open_archive(&zip_path), &out, &limits)
            .unwrap_err();
        assert!(err.to_string().contains("total size limit"), "实际: {err}");

        let limits_ok = ZipLimits {
            max_total_bytes: 30,
            max_single_file_bytes: u64::MAX,
            ..Default::default()
        };
        PluginDownloader::extract_entries(&mut open_archive(&zip_path), &out, &limits_ok).unwrap();
    }

    // ==================== 升级安装（应用版本更新链路） ====================

    /// 构造自定义 index.js 内容的合法插件 zip（升级用例区分新旧版本内容）
    fn build_plugin_zip_body(dir: &Path, id: &str, index_body: &str) -> PathBuf {
        let zip_path = dir.join(format!("{id}.zip"));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let manifest = serde_json::json!({
            "id": id,
            "name": "Test Plugin",
            "version": "2.0.0",
            "platform": "both",
            "main": "index.js",
            "pluginType": "frontend",
            "rustLibrary": "",
            "permissions": [],
            "contributes": {}
        })
        .to_string();
        writer
            .start_file(
                PLUGIN_MANIFEST_FILE,
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(manifest.as_bytes()).unwrap();
        writer
            .start_file("index.js", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(index_body.as_bytes()).unwrap();
        writer.finish().unwrap();
        zip_path
    }

    /// 升级：目录内容被替换，私有库 plugin.db 原样保留
    #[test]
    fn upgrade_replaces_content_and_preserves_private_db() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.upgrade-ok";

        let v1 = build_plugin_zip(tmp.path(), id, false, false);
        PluginDownloader::install_from_file(v1.to_str().unwrap(), &plugins_dir).unwrap();
        std::fs::write(plugins_dir.join(id).join("plugin.db"), b"old-data").unwrap();

        let v2 = build_plugin_zip_body(tmp.path(), id, "new-version-marker");
        PluginDownloader::upgrade_from_file(v2.to_str().unwrap(), &plugins_dir).unwrap();

        let final_dir = plugins_dir.join(id);
        assert_eq!(
            std::fs::read_to_string(final_dir.join("plugin.db")).unwrap(),
            "old-data",
            "私有库必须在升级后保留"
        );
        assert_eq!(
            std::fs::read_to_string(final_dir.join("index.js")).unwrap(),
            "new-version-marker",
            "包内容必须被替换为新版本"
        );
        assert!(final_dir.join(PLUGIN_SOURCE_MARKER).exists());
        assert!(!plugins_dir.join(PLUGIN_DOWNLOAD_TEMP_DIR).join(id).exists());
    }

    /// 升级目标未安装 → 退化为普通安装（不为「先查后装」留竞态窗口）
    #[test]
    fn upgrade_on_missing_install_behaves_as_install() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.upgrade-fresh";

        let zip_path = build_plugin_zip_body(tmp.path(), id, "fresh");
        let installed =
            PluginDownloader::upgrade_from_file(zip_path.to_str().unwrap(), &plugins_dir).unwrap();
        assert_eq!(installed, id);
        assert!(plugins_dir.join(id).join("index.js").exists());
    }

    /// peek_plugin_id：合法包返回 id；zip 内无 plugin.json / id 非法 → 显性拒绝
    #[test]
    fn peek_plugin_id_validates_like_install() {
        let tmp = tempfile::tempdir().unwrap();
        let ok = build_plugin_zip(tmp.path(), "com.test.peek-ok", false, false);
        assert_eq!(
            PluginDownloader::peek_plugin_id(&ok).unwrap(),
            "com.test.peek-ok"
        );

        // 与 install_rejects_invalid_manifest 同构造：合法 zip 容器但无 plugin.json
        let bad = build_files_zip(tmp.path(), "no-manifest.zip", &[("index.js", b"x")]);
        let err = PluginDownloader::peek_plugin_id(&bad).unwrap_err();
        assert!(err.to_string().contains("plugin.json"), "实际: {err}");
    }

    /// 升级路径 platform 门禁照走：mobile-only 包拒升级，旧安装原样保留
    #[cfg(feature = "desktop-assembly")]
    #[test]
    fn upgrade_still_enforces_platform_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.upgrade-platform";

        let v1 = build_plugin_zip(tmp.path(), id, false, false);
        PluginDownloader::install_from_file(v1.to_str().unwrap(), &plugins_dir).unwrap();
        std::fs::write(plugins_dir.join(id).join("plugin.db"), b"keep").unwrap();

        let mobile_only = build_plugin_zip_with_platform(tmp.path(), id, false, false, "mobile");
        let err = PluginDownloader::upgrade_from_file(mobile_only.to_str().unwrap(), &plugins_dir)
            .unwrap_err();
        assert!(err.to_string().contains("platform"), "实际: {err}");
        assert_eq!(
            std::fs::read_to_string(plugins_dir.join(id).join("plugin.db")).unwrap(),
            "keep",
            "被拒升级不得破坏旧安装"
        );
        assert_eq!(
            std::fs::read_to_string(plugins_dir.join(id).join("index.js")).unwrap(),
            "console.log('test')",
            "被拒升级不得替换包内容"
        );
    }

    /// 升级路径 wasm 摘要门禁照走：摘要不符拒升级，旧安装原样保留
    #[test]
    fn upgrade_still_enforces_wasm_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let plugins_dir = tmp.path().join("plugins");
        let id = "com.test.upgrade-digest";

        let v1 = build_wasm_zip(
            tmp.path(),
            id,
            b"REAL-WASM-V1",
            &sha256_hex(b"REAL-WASM-V1"),
        );
        PluginDownloader::install_from_file(v1.to_str().unwrap(), &plugins_dir).unwrap();

        let v2 = build_wasm_zip(tmp.path(), id, b"REAL-WASM-V2", &sha256_hex(b"TAMPERED"));
        let err =
            PluginDownloader::upgrade_from_file(v2.to_str().unwrap(), &plugins_dir).unwrap_err();
        assert!(
            err.to_string().contains("WASM content mismatch"),
            "实际: {err}"
        );
        let wasm_name = format!("lib_{}", id.replace('.', "_"));
        assert_eq!(
            std::fs::read(plugins_dir.join(id).join(format!("{wasm_name}.wasm"))).unwrap(),
            b"REAL-WASM-V1",
            "被拒升级不得替换 wasm"
        );
    }
}
