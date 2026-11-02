//! Plugin Loader
//!
//! 扫描插件目录，解析所有 plugin.json
//! 验证必填字段和权限合法性，返回已加载的插件列表
//! 仅处理文件扫描加载，Rust+TS WASM 插件由 PluginHost 通过 WasmRuntime 加载

use crate::manager::types::{LoadedPlugin, PluginSource};
use crate::manager::validation::{validate_dir_binding, validate_plugin_id};
use crate::permission::PermissionManager;
use crate::system::constants::PLUGIN_DOWNLOAD_TEMP_DIR;
// 中性词汇（票 02 M4）：清单/状态/类型统一取自 crate::manifest
use crate::manifest::{PluginManifest, PluginState, PluginType};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// 插件加载器
pub struct PluginLoader;

impl PluginLoader {
    /// 扫描插件目录并加载所有 plugin.json
    ///
    /// 目录约定：`plugins/desktop/{plugin-id}/plugin.json`
    /// 解析失败的插件跳过并记录警告，不影响其他插件
    ///
    /// 去重（`seen_ids`）只在**本次调用内**生效。需要「随包内置目录 + 用户安装目录」
    /// 之间同样按先到先得去重时，走 [`Self::load_builtin_and_user`]——两次独立调用
    /// 各持一份 `seen_ids`，互相看不见对方加载过的 id。
    pub fn load_all(
        plugins_dir: &Path,

        permission_mgr: &PermissionManager,

        source: Option<PluginSource>,
    ) -> HashMap<String, LoadedPlugin> {
        let mut seen_ids: HashSet<String> = HashSet::new();
        Self::load_all_with_seen(plugins_dir, permission_mgr, source, &mut seen_ids)
    }

    /// 扫描「随包内置目录 + 用户安装目录」，并按更新声明裁决同 id 冲突
    ///
    /// 返回 `(内置插件, 用户安装插件)`，调用方分别计数后再合并入表。
    ///
    /// **同 id 的裁决（2026-11-02 应用版本更新全链路）**：
    /// - 默认仍由**内置条目胜出**：内置属应用构建信任域（`Wasm` / `FileScan`，
    ///   免审批），用户副本属 `UserInstalled`（须人工批准）。放任用户副本无条件
    ///   顶替，会把随包插件整体降级为「待审批」而拒绝激活，并让同 id 运行的是
    ///   用户目录里那份代码（防冒名顶替语义失效）。
    /// - **唯一例外 = 显式更新覆盖**：两侧都声明了同一条 `update` 更新源，且用户
    ///   副本版本**严格新于**内置版本——这是用户在应用管理页显式执行「更新」后
    ///   的产物。该副本仍走 `UserInstalled` 审批门禁：安装后内容哈希失配 → 下次
    ///   激活落 NeedsApproval，新代码必须重新授权（升级保数据，不保信任）。
    /// - 版本相同 / 更旧 / 更新源不一致 / 任一版本非法 → 一律保留内置条目，
    ///   用户副本拒绝加载并留痕（不静默覆盖）。
    pub fn load_builtin_and_user(
        plugins_dir: &Path,
        user_plugins_dir: &Path,
        permission_mgr: &PermissionManager,
    ) -> (HashMap<String, LoadedPlugin>, HashMap<String, LoadedPlugin>) {
        // 两次扫描各自去重（同一目录内的重复 id 仍先到先得），跨目录冲突由下面的
        // 显式裁决处理——此前共享 seen_ids 会让用户副本在扫描阶段就被丢掉，
        // 无法区分「重复」与「合法的更新覆盖」。
        let builtin = Self::load_all(plugins_dir, permission_mgr, None);
        let user = Self::load_all(
            user_plugins_dir,
            permission_mgr,
            Some(PluginSource::UserInstalled),
        );

        let mut accepted_user = HashMap::new();
        for (id, candidate) in user {
            let Some(builtin_entry) = builtin.get(&id) else {
                accepted_user.insert(id, candidate);
                continue;
            };
            if Self::update_shadows_builtin(builtin_entry, &candidate) {
                tracing::info!(
                    plugin_id = %id,
                    builtin_version = %builtin_entry.manifest.version,
                    user_version = %candidate.manifest.version,
                    "[PluginLoader] 用户安装的更新副本覆盖内置应用（需按 UserInstalled 审批）"
                );
                accepted_user.insert(id, candidate);
            } else {
                tracing::warn!(
                    plugin_id = %id,
                    builtin_version = %builtin_entry.manifest.version,
                    user_version = %candidate.manifest.version,
                    "[PluginLoader] Rejecting duplicate plugin id: 用户副本不是合法更新覆盖，保留内置条目"
                );
            }
        }
        (builtin, accepted_user)
    }

    /// 用户副本是否构成对内置换新的「合法更新覆盖」
    ///
    /// 三条同时成立才放行：两侧都声明了更新源、两侧更新源逐字段一致、用户版本
    /// 严格新于内置版本。更新源一致性防止「同名 id 但发布源不同」的变体顶替。
    fn update_shadows_builtin(builtin: &LoadedPlugin, candidate: &LoadedPlugin) -> bool {
        let builtin_source = crate::app_update::resolve_update_source(
            builtin.manifest.update.as_ref(),
            &builtin.manifest.id,
        );
        let candidate_source = crate::app_update::resolve_update_source(
            candidate.manifest.update.as_ref(),
            &candidate.manifest.id,
        );
        let (Ok(Some(builtin_source)), Ok(Some(candidate_source))) =
            (builtin_source, candidate_source)
        else {
            return false;
        };
        if builtin_source != candidate_source {
            return false;
        }
        crate::app_update::version_is_newer(&candidate.manifest.version, &builtin.manifest.version)
            .unwrap_or(false)
    }

    /// [`Self::load_all`] 的共享去重状态变体：`seen_ids` 由调用方持有并跨调用复用
    fn load_all_with_seen(
        plugins_dir: &Path,
        permission_mgr: &PermissionManager,
        source: Option<PluginSource>,
        seen_ids: &mut HashSet<String>,
    ) -> HashMap<String, LoadedPlugin> {
        tracing::info!(
            "[PluginLoader] Scanning plugin directory: {:?}",
            plugins_dir
        );

        if !plugins_dir.exists() {
            tracing::warn!(
                "[PluginLoader] Plugin directory does not exist: {:?}",
                plugins_dir
            );

            return HashMap::new();
        }

        let mut plugins = HashMap::new();

        // 已加载 id 集合（复用调用方持有的集合时含前序目录的结果）：重复 id

        // 先到先得，后出现的目录拒绝加载，防止冒名插件顶替已加载插件

        // （HashMap insert 覆盖语义是漏洞本体）

        let entries = match fs::read_dir(plugins_dir) {
            Ok(entries) => entries,

            Err(e) => {
                tracing::error!("[PluginLoader] Failed to read plugin directory: {}", e);

                return HashMap::new();
            }
        };

        let mut dir_count = 0;

        for entry in entries.flatten() {
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            dir_count += 1;

            let manifest_path = path.join("plugin.json");

            if !manifest_path.exists() {
                // 下载临时区容器目录（user_plugins_dir/plugins/_download_tmp）不是插件

                // 目录，静默跳过；其余无 plugin.json 的目录是孤儿残留（如历史安装遗留

                // 的私有数据库 plugin.db），warn 提升可见性——这类目录会被安装查重误判

                // 为已安装，卡住同 id 插件重装（install 时磁盘查重 final_dir.exists()）。

                let temp_container = PLUGIN_DOWNLOAD_TEMP_DIR.split('/').next().unwrap_or("");

                if path.file_name().and_then(|n| n.to_str()) == Some(temp_container) {
                    tracing::debug!(
                        "[PluginLoader] Skipping download temp container: {:?}",
                        path
                    );
                } else {
                    // 票 16：孤儿目录（历史安装遗留 / 插件 id 改名后的空壳）**不影响内置
                    // 插件加载**（内置插件来自 resources 目录，与本扫描路径无关），
                    // 每次启动刷 warn 是把排查噪音当信号。它唯一的实际影响——「安装查重
                    // 误判已安装、卡住同 id 重装」——在**安装路径**上已有专职处理与留痕
                    // （`downloader.rs` / `host/install.rs` 安装前主动删除孤儿目录），
                    // 故此处降级为 debug，并把「由谁处理」写进文案。
                    tracing::debug!(

                        dir = %path.display(),

                        "[PluginLoader] Skipping dir without plugin.json (orphan residue; does not affect built-in plugins; cleaned up on install)"

                    );
                }

                continue;
            }

            match Self::load_manifest(&manifest_path) {
                Ok(manifest) => {
                    let dir_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();

                    let plugin_id = manifest.id.clone();

                    // ==================== 身份校验（防冒名顶替） ====================

                    // 1. id 必须为反向域名格式（拒绝大写/下划线/单段等非约定格式）

                    if !validate_plugin_id(&plugin_id) {
                        tracing::error!(
                            "[PluginLoader] Rejecting plugin from {:?}: invalid id format {:?}",
                            dir_name,
                            plugin_id
                        );

                        continue;
                    }

                    // 2. 目录名必须与 manifest id 一致

                    //    （watcher 热重载/卸载/文件服务路径全部依赖「目录名 = id」约定，

                    //    不一致说明目录被复制改名或 manifest 被替换，直接拒绝）

                    if !validate_dir_binding(&dir_name, &plugin_id) {
                        tracing::error!(

                            "[PluginLoader] Rejecting plugin {:?} from {:?}: dir name does not match manifest id (possible impersonation)",

                            plugin_id, dir_name

                        );

                        continue;
                    }

                    // 3. 重复 id：先到先得，后到目录拒绝（防静默覆盖已加载插件）

                    if !seen_ids.insert(plugin_id.clone()) {
                        tracing::error!(

                            "[PluginLoader] Rejecting duplicate plugin id {:?} from {:?}: already loaded from another directory",

                            plugin_id, dir_name

                        );

                        continue;
                    }

                    // Windows read_dir 返回带 \\?\ verbatim 前缀的路径，该形式不允许

                    // 正斜杠拼接（插件用 "{resource_dir}/{file}" 拼接会触发

                    // ERROR_INVALID_NAME os error 123），统一剥离为常规路径

                    let extension_path = strip_verbatim_prefix(&path.to_string_lossy());

                    // 纯前端插件的形态缺省与 main 必填判据在 load_manifest 收口
                    // （历史遗留空块，随 2026-10-26 形态三档重定义清理语义注释）

                    let manifest = manifest;
                    let _ = &manifest;

                    // 非核心能力域的装载期回调（票 02 批次 02 / 批次 03）：manifest
                    // **原文**下发，解析权与**声明仲裁权**都在能力域——内核不解释
                    // manifest 字段（AGENTS §5.1 B6）。`Err` = 该域拒绝此 manifest ⇒
                    // **不装载**（fail-visible，不静默降级；如 host-pty 的 `ptyQuota`
                    // 越界）。故本回调**必须先于任何副作用**（授权登记在下一条）执行：
                    // 被拒插件不留半成品状态（权限 / 配额登记都不该发生）。
                    // 原文重读失败不阻断装载（域侧声明落各自默认档），但必须留痕。
                    match std::fs::read_to_string(&manifest_path) {
                        Ok(raw) => {
                            if let Err(reason) = wasmnest_host_kit::DomainHooksRegistry::collected()
                                .on_manifest_load(&plugin_id, &raw)
                            {
                                tracing::error!(
                                    plugin_id = %plugin_id,
                                    reason = %reason,
                                    "[PluginLoader] Rejecting plugin: capability domain refused its manifest declaration"
                                );

                                continue;
                            }
                        }
                        Err(error) => tracing::warn!(
                            plugin_id = %plugin_id,
                            error = %error,
                            "manifest 原文重读失败：能力域装载期回调跳过，域侧声明落默认档"
                        ),
                    }

                    // 授权并过滤非法权限

                    // 授权结果只落在 PermissionManager（唯一真源）；LoadedPlugin 不再
                    // 镜像一份 granted 列表（票 11 第 4 项：镜像字段只写不读）
                    permission_mgr.grant_permissions(&plugin_id, &manifest.permissions);

                    // 配额登记（会话引擎下沉 P1 / H1）：manifest `ptyQuota` → host-pty
                    // 生效上限，已在上面的域侧回调内完成（同一漏斗，声明面只有一个入口）。
                    // 静态注册（inventory）插件不经本函数、也不经 host-pty 原语（它们
                    // 直接用 SessionManager），故无需在 host.rs 那处授权点补登记。

                    // 根据 rust_library 字段判断来源：有 WASM 模块则为 Wasm，否则为 FileScan；

                    // 用户插件目录（zip 安装）显式标 UserInstalled，不参与推断。

                    // clone：source 在循环内被逐插件消费，参数本身不可移动

                    let source = match source.clone() {
                        Some(s) => s,

                        None => {
                            if !manifest.rust_library.is_empty() {
                                PluginSource::Wasm
                            } else {
                                PluginSource::FileScan
                            }
                        }
                    };

                    tracing::info!(
                        "[PluginLoader] Plugin loaded: {} v{} (type={:?}, source={:?}, path={})",
                        manifest.id,
                        manifest.version,
                        manifest.plugin_type,
                        source,
                        extension_path
                    );

                    let loaded = LoadedPlugin {
                        manifest,

                        state: PluginState::Loaded,

                        extension_path,

                        activated_at: None,

                        source,
                    };

                    plugins.insert(plugin_id, loaded);
                }

                Err(e) => {
                    let dir_name = path.file_name().unwrap_or_default().to_string_lossy();

                    tracing::error!(
                        "[PluginLoader] Failed to load plugin from {}: {}",
                        dir_name,
                        e
                    );
                }
            }
        }

        tracing::info!(
            "[PluginLoader] Scanned {} dir(s), loaded {} plugin(s)",
            dir_count,
            plugins.len()
        );

        plugins
    }

    /// 解析单个 plugin.json

    fn load_manifest(path: &PathBuf) -> crate::Result<PluginManifest> {
        let content = fs::read_to_string(path)
            .map_err(|e| crate::AppError::Plugin(format!("Failed to read plugin.json: {}", e)))?;

        // 解析与必填字段校验走唯一真源（票 11 第 6 项）
        let manifest = crate::manager::validation::parse_manifest_json(&content)?;

        // worker 声明的 wasm 文件存在性（装载入口独有的一道：结构面已在
        // parse_manifest_json 的必填校验里过掉；zip 安装入口按「结构性必填」口径
        // 不查，与 ptyQuota 同款分层——安装期可通过、装载期拒绝）
        crate::manager::validation::validate_worker_files(
            &manifest,
            path.parent().unwrap_or_else(|| std::path::Path::new(".")),
        )?;

        // 纯前端插件必须有 main 字段（目录扫描入口独有的一道）

        if manifest.plugin_type == PluginType::Frontend && manifest.main.is_empty() {
            return Err(crate::AppError::Plugin(
                "frontend plugin.json missing main field".to_string(),
            ));
        }

        Ok(manifest)
    }
}

/// 剥离 Windows verbatim 路径前缀（`\\?\`）
///
/// Windows `read_dir` 返回带 `\\?\` 前缀的路径。该形式严格要求反斜杠分隔，
/// 插件侧用 `format!("{}/{}", resource_dir, file)` 拼接正斜杠会触发
/// `ERROR_INVALID_NAME`（os error 123）。统一剥离为常规路径后，
/// 正斜杠/反斜杠均可正常使用。非 Windows 平台原样返回。
///
/// 唯一实现；`PluginHost` 注入 `resource_dir` 时复用（见 host.rs）。
pub(crate) fn strip_verbatim_prefix(path: &str) -> String {
    path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_manifest_valid() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let plugin_dir = tmp_dir.path().join("com.test.plugin");
        fs::create_dir_all(&plugin_dir).unwrap();

        let manifest_json = serde_json::json!({
            "id": "com.test.plugin",
            "name": "Test Plugin",
            "version": "1.0.0",
            "platform": "both",
            "main": "index.ts",
            "permissions": ["terminal:input", "storage"],
            "contributes": {
                "commands": [{
                    "id": "test.hello",
                    "title": "Hello"
                }]
            }
        });

        let manifest_path = plugin_dir.join("plugin.json");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        let manifest = PluginLoader::load_manifest(&manifest_path).unwrap();
        assert_eq!(manifest.id, "com.test.plugin");
        assert_eq!(manifest.permissions.len(), 2);
        assert_eq!(manifest.contributes.commands.len(), 1);
    }

    /// worker 声明的 wasm 文件存在性在装载期拒绝（worker 机制 / ADR 0059）
    ///
    /// 反例先拒（点名 worker 与 worker/ 目录），文件在场后同 manifest 放行——
    /// 证明拒绝来自 file 存在性而不是声明本身。结构面（重名 / 路径注入）的用例
    /// 在 `validation.rs`（parse 漏斗），本用例钉装载入口的接线。
    #[test]
    fn test_load_manifest_rejects_missing_worker_file() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let plugin_dir = tmp_dir.path().join("com.test.worker");
        fs::create_dir_all(plugin_dir.join("worker")).unwrap();

        let manifest_json = serde_json::json!({
            "id": "com.test.worker",
            "name": "Worker Plugin",
            "version": "1.0.0",
            "platform": "both",
            "pluginType": "backend",
            "workers": [{ "name": "n", "file": "n.wasm" }]
        });
        let manifest_path = plugin_dir.join("plugin.json");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        let err = PluginLoader::load_manifest(&manifest_path)
            .err()
            .expect("缺 worker wasm 必须装载期拒绝");
        let text = err.to_string();
        assert!(
            text.contains("workers[n]") && text.contains("n.wasm") && text.contains("worker/"),
            "错误必须点名 worker 名、文件与 worker/ 目录，got: {text}"
        );

        fs::write(plugin_dir.join("worker").join("n.wasm"), b"wasm").unwrap();
        let manifest = PluginLoader::load_manifest(&manifest_path).expect("在场文件放行");
        assert_eq!(manifest.workers.len(), 1);
        assert_eq!(manifest.workers[0].name, "n");
    }

    #[test]
    fn test_load_manifest_missing_id() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let plugin_dir = tmp_dir.path().join("bad-plugin");
        fs::create_dir_all(&plugin_dir).unwrap();

        let manifest_json = serde_json::json!({
            "name": "No ID",
            "version": "1.0.0",
            "platform": "both",
            "main": "index.ts"
        });

        let manifest_path = plugin_dir.join("plugin.json");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        let result = PluginLoader::load_manifest(&manifest_path);
        assert!(result.is_err());
    }

    /// 退役字段兼容（审计票 06 裁决 2）：`sandbox` 已退役（前端不做隔离，安全边界只在
    /// Rust 端与 WASM 端），旧产物带该键时按「老端忽略未知字段」的演进约定照常加载
    #[test]
    fn test_load_manifest_ignores_retired_sandbox_field() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let plugin_dir = tmp_dir.path().join("legacy-sandbox-plugin");
        fs::create_dir_all(&plugin_dir).unwrap();

        let manifest_json = serde_json::json!({
            "id": "com.test.legacy-sandbox",
            "name": "Legacy Sandbox Plugin",
            "version": "1.0.0",
            "platform": "both",
            "main": "index.ts",
            "sandbox": "isolated"
        });

        let manifest_path = plugin_dir.join("plugin.json");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        let manifest = PluginLoader::load_manifest(&manifest_path).expect("退役字段不得阻塞加载");
        assert_eq!(manifest.id, "com.test.legacy-sandbox");
    }

    // ==================== 内置 / 用户目录跨扫描去重（内置先到先得） ====================

    /// 在 `dir` 下写一个最小可加载插件目录（目录名 = manifest id，满足身份绑定校验）
    fn write_minimal_plugin(dir: &Path, id: &str) {
        write_plugin(dir, id, "1.0.0", None);
    }

    /// 写一个带可选 `update` 声明的插件（版本 / 更新源可控）
    fn write_plugin(dir: &Path, id: &str, version: &str, update: Option<serde_json::Value>) {
        let plugin_dir = dir.join(id);
        fs::create_dir_all(&plugin_dir).unwrap();
        let mut manifest = serde_json::json!({
            "id": id,
            "name": format!("Test {}", id),
            "version": version,
            "platform": "both",
            "main": "index.js",
        });
        if let Some(update) = update {
            manifest["update"] = update;
        }
        fs::write(
            plugin_dir.join("plugin.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(plugin_dir.join("index.js"), "export default {}").unwrap();
    }

    /// 应用更新覆盖：同更新源且用户副本版本更新 → 用户副本胜出（UserInstalled，
    /// 仍需审批）；版本相同 / 更旧 / 更新源不一致 / 用户副本无声明 → 内置胜出。
    #[test]
    fn test_user_update_shadows_builtin_only_when_newer_same_source() {
        let update = || serde_json::json!({ "provider": "github-release" });
        let cases = [
            // (内置版本, 用户版本, 内置 update, 用户 update, 是否覆盖)
            ("1.0.0", "1.0.1", Some(update()), Some(update()), true),
            ("1.0.0", "1.0.0", Some(update()), Some(update()), false),
            ("1.0.1", "1.0.0", Some(update()), Some(update()), false),
            ("1.0.0", "1.0.1", Some(update()), None, false),
            ("1.0.0", "1.0.1", None, Some(update()), false),
            (
                "1.0.0",
                "1.0.1",
                Some(update()),
                Some(serde_json::json!({ "provider": "github-release", "repo": "other/repo" })),
                false,
            ),
        ];
        for (builtin_version, user_version, builtin_update, user_update, expect_override) in cases {
            let builtin_dir = tempfile::TempDir::new().unwrap();
            let user_dir = tempfile::TempDir::new().unwrap();
            let id = "com.test.updatable";
            write_plugin(builtin_dir.path(), id, builtin_version, builtin_update);
            write_plugin(user_dir.path(), id, user_version, user_update);

            let permission = PermissionManager::new();
            let (builtin, user) = PluginLoader::load_builtin_and_user(
                builtin_dir.path(),
                user_dir.path(),
                &permission,
            );
            assert!(builtin.contains_key(id), "内置条目必须始终加载");
            assert_eq!(
                user.contains_key(id),
                expect_override,
                "内置 {builtin_version} / 用户 {user_version} 的覆盖裁决不符"
            );
            if expect_override {
                assert_eq!(
                    user.get(id).unwrap().source,
                    PluginSource::UserInstalled,
                    "更新覆盖必须标 UserInstalled（审批门禁据此分档）"
                );
            }
        }
    }

    /// 同 id 同时存在于内置与用户目录：内置条目胜出，用户副本必须被拒绝。
    ///
    /// 回归锁：用户副本顶替内置条目 → 信任档从 Wasm/FileScan 降级为 UserInstalled
    /// → 随包插件被审批门禁拒绝激活（现象：随包插件报 requires user approval）。
    #[test]
    fn test_builtin_plugin_wins_over_user_copy_of_same_id() {
        let builtin_dir = tempfile::TempDir::new().unwrap();
        let user_dir = tempfile::TempDir::new().unwrap();
        let shared_id = "com.test.shadowed";
        write_minimal_plugin(builtin_dir.path(), shared_id);
        write_minimal_plugin(user_dir.path(), shared_id);

        let permission = PermissionManager::new();
        let (builtin, user) =
            PluginLoader::load_builtin_and_user(builtin_dir.path(), user_dir.path(), &permission);

        assert!(
            builtin.contains_key(shared_id),
            "内置目录里的插件必须加载，实际: {:?}",
            builtin.keys().collect::<Vec<_>>()
        );
        assert!(
            !user.contains_key(shared_id),
            "同 id 的用户副本必须被拒绝（先到先得），实际: {:?}",
            user.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            builtin
                .get(shared_id)
                .expect("builtin entry")
                .extension_path,
            builtin_dir
                .path()
                .join(shared_id)
                .to_string_lossy()
                .to_string(),
            "胜出条目的扩展路径必须指向内置目录（用户副本不得顶替）"
        );
    }

    /// 反例（共享去重不得扩大化）：id 不与内置冲突的用户插件照常加载，来源标 UserInstalled
    #[test]
    fn test_user_plugin_without_id_collision_is_loaded() {
        let builtin_dir = tempfile::TempDir::new().unwrap();
        let user_dir = tempfile::TempDir::new().unwrap();
        write_minimal_plugin(builtin_dir.path(), "com.test.builtin-only");
        write_minimal_plugin(user_dir.path(), "com.test.user-only");

        let permission = PermissionManager::new();
        let (builtin, user) =
            PluginLoader::load_builtin_and_user(builtin_dir.path(), user_dir.path(), &permission);

        assert_eq!(
            builtin.keys().collect::<Vec<_>>(),
            vec!["com.test.builtin-only"],
            "内置目录只含自己的插件"
        );
        assert_eq!(
            user.keys().collect::<Vec<_>>(),
            vec!["com.test.user-only"],
            "无冲突的用户插件必须加载"
        );
        assert_eq!(
            user.get("com.test.user-only").expect("user entry").source,
            PluginSource::UserInstalled,
            "用户目录来源必须显式标 UserInstalled（审批门禁据此分档）"
        );
    }

    /// 边界：用户目录不存在（尚未安装任何插件）→ 用户侧空结果，内置侧不受影响
    #[test]
    fn test_missing_user_dir_yields_empty_user_map() {
        let builtin_dir = tempfile::TempDir::new().unwrap();
        write_minimal_plugin(builtin_dir.path(), "com.test.builtin-only");
        let missing_user_dir = tempfile::TempDir::new().unwrap().path().join("not-created");

        let permission = PermissionManager::new();
        let (builtin, user) =
            PluginLoader::load_builtin_and_user(builtin_dir.path(), &missing_user_dir, &permission);

        assert!(user.is_empty(), "缺失目录不得凭空产出插件");
        assert!(
            builtin.contains_key("com.test.builtin-only"),
            "内置目录加载不得因用户目录缺失而中断"
        );
    }
}
