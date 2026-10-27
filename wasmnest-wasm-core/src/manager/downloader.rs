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
    /// 「冒名顶替替换」，升级需先卸载旧版本，与移动端一致）。
    pub fn install_from_file(zip_path: &str, user_plugins_dir: &Path) -> Result<String> {
        let zip_path = Path::new(zip_path);
        if !zip_path.exists() {
            return Err(crate::AppError::Plugin(format!(
                "Plugin package not found: {}",
                zip_path.display()
            )));
        }
        Self::install_zip(zip_path, user_plugins_dir)
    }

    /// zip 解压安装（本地文件）
    fn install_zip(zip_path: &Path, user_plugins_dir: &Path) -> Result<String> {
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

        // 5. 写来源标记（供 dev 副本刷新/未来磁盘审计区分安装来源）
        let marker = temp_dir.join(PLUGIN_SOURCE_MARKER);
        std::fs::write(&marker, SOURCE_FILE_INSTALL).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to write source marker: {}", e))
        })?;

        // 6. 移动到最终目录
        //
        // 拒绝覆盖已存在的同 id 插件：无签名链时无法区分「同作者更新」与
        // 「冒名顶替替换」，静默替换会让既有权限继续作用于被替换后的新代码，
        // 是权限门禁的旁路。升级需先卸载旧版本。
        //
        // 例外：目录内无 plugin.json 的「孤儿残留」不构成有效安装——这类目录
        // 通常是历史安装/激活遗留的插件私有数据库（plugin.db），loader 因缺
        // plugin.json 会跳过它（UI 不可见、卸载按 extension_path 也够不着），
        // 但磁盘查重会误判为已安装，卡死同 id 重装。此处识别后清除再安装。
        let final_dir = user_plugins_dir.join(&plugin_id);
        if final_dir.exists() {
            if final_dir.join(PLUGIN_MANIFEST_FILE).exists() {
                let _ = std::fs::remove_dir_all(&temp_dir);
                return Err(crate::AppError::Plugin(format!(
                    "Plugin '{}' is already installed. Uninstall it first to install a new version.",
                    plugin_id
                )));
            }
            tracing::warn!(
                plugin_id = %plugin_id,
                dir = %final_dir.display(),
                "[PluginDownloader] Removing orphan residue dir (no plugin.json) before install"
            );
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
            "[PluginDownloader] Plugin '{}' installed to {:?} (source: {})",
            plugin_id,
            final_dir,
            SOURCE_FILE_INSTALL
        );
        Ok(plugin_id)
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
            "pluginType": if declares_wasm { "rust-ts" } else { "ts-only" },
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

        // 孤儿残留被清除：plugin.db 消失，新插件文件就位
        assert!(!orphan_dir.join("plugin.db").exists());
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

    /// 构造声明 rust_library + wasmHash 的 rust-ts 插件 zip
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
            "pluginType": "rust-ts",
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
        assert_eq!(std::fs::metadata(out.join("c.bin")).unwrap().len(), 10);
    }
}
