//! `install` — PluginHost 职责面拆分（P2）
//!
//! 自 `host.rs` 主 impl 拆出；经 `use super::*` 继承 host 模块的
//! 全部导入与常量，方法与字段可见性规则与内联时一致。

use super::*;
use tauri::Manager;
impl PluginHost {
    /// 从 zip 分发包安装插件（dev 合入；fresh install 默认不恢复旧数据）
    ///
    /// 解压校验（manifest/身份/路径安全）→ 重新扫描用户目录 → WASM 实例化 →
    /// 注册 manifest 扩展点。同 id 已安装时回滚安装目录并报错（需先卸载）。
    ///
    /// `upgrade = true`（应用版本更新链路）：同 id **用户安装**插件的就地升级——
    /// 先裁决（未安装 / 非 user-installed 来源 / 运行中一律 fail-visible 点名拒绝），
    /// 再摘除旧实例与注册记录（**不走卸载路径**：插件存储 / 授权策略 / 审批记录 /
    /// 监控计数全部保留），最后换目录内容（私有库 plugin.db 家族保留，见 downloader
    /// `upgrade_from_file`）并重装载。目录内容变化使审批内容哈希失配 → 下次激活落
    /// NeedsApproval 重新批准（新代码需重新授权，安全语义）。
    ///
    /// 本入口保留既有调用面；fresh install 的数据恢复策略见
    /// [`Self::install_from_zip_with_options`]（默认丢弃旧数据）。
    pub async fn install_from_zip(&self, zip_path: &str, upgrade: bool) -> crate::Result<String> {
        self.install_from_zip_with_options(zip_path, upgrade, InstallOptions::default())
            .await
    }

    /// 从 zip 分发包安装插件（带 fresh install 数据恢复策略）
    ///
    /// 与 [`Self::install_from_zip`] 相同，只是 fresh install 时可指定是否恢复
    /// keep-data 卸载留下的旧数据（插件私有库 + 主库 KV）；`upgrade = true` 时
    /// 本策略不生效——升级恒保数据（升级保数据，重装才需要用户裁决）。
    pub async fn install_from_zip_with_options(
        &self,
        zip_path: &str,
        upgrade: bool,
        options: InstallOptions,
    ) -> crate::Result<String> {
        let zip_path = std::path::Path::new(zip_path);
        if upgrade {
            // 升级前置：先解出目标 id（任何落盘动作之前），注册表里裁决运行态与来源。
            let plugin_id = crate::manager::downloader::PluginDownloader::peek_plugin_id(zip_path)?;
            {
                let plugins = self.plugins.read().await;
                let loaded = plugins.get(&plugin_id).ok_or_else(|| {
                    crate::AppError::Plugin(format!(
                        "Plugin '{}' is not installed; use install instead of upgrade.",
                        plugin_id
                    ))
                })?;
                if loaded.source != PluginSource::UserInstalled {
                    // 应用版本更新（2026-11-02）：随包内置的**可更新应用**允许被用户
                    // 目录里的更新副本覆盖（load_builtin_and_user 只接受同更新源且
                    // 版本更新者）。静态注册插件（StaticRegistry）无目录可换，仍然拒。
                    let updatable_builtin =
                        matches!(loaded.source, PluginSource::Wasm | PluginSource::FileScan)
                            && loaded.manifest.update.is_some();
                    if !updatable_builtin {
                        return Err(crate::AppError::Plugin(format!(
                            "Plugin '{}' (source: {}) cannot be upgraded in place; builtin apps are updated with the host release.",
                            plugin_id,
                            loaded.source.as_str()
                        )));
                    }
                }
                // 与卸载同判据：运行中（含激活进行中 / 降级）拒绝升级
                if matches!(
                    loaded.state,
                    PluginState::Activated | PluginState::Activating | PluginState::Degraded { .. }
                ) {
                    return Err(crate::AppError::Plugin(format!(
                        "Plugin '{}' is running, deactivate it before upgrading.",
                        plugin_id
                    )));
                }
            }
            // 摘除旧实例（防御性停用清残留 → 丢私有库连接 → 停属主 → 移除记录）。
            // 与 uninstall_plugin 的差异：不清插件存储 / 授权策略 / 审批记录 /
            // 监控计数——升级保数据，卸载清数据，两条语义不混用。
            self.deactivate_plugin(&plugin_id, true).await?;
            self.wasm_host_ctx.drop_plugin_db(&plugin_id).await;
            let removed_entry = { self.wasm_plugins.write().await.remove(&plugin_id) };
            if let Some(entry) = removed_entry {
                if let Some(report) = entry.shutdown().await {
                    if report.forced_abort || report.abandoned_requests > 0 {
                        tracing::warn!(
                            plugin_id = %plugin_id,
                            abandoned_requests = report.abandoned_requests,
                            forced_abort = report.forced_abort,
                            "plugin instance owner stopped on upgrade with unresolved requests"
                        );
                    }
                }
            }
            self.plugins.write().await.remove(&plugin_id);
        }
        let plugin_id = if upgrade {
            crate::manager::downloader::PluginDownloader::upgrade_from_file(
                zip_path.to_str().ok_or_else(|| {
                    crate::AppError::Plugin("Plugin package path is not valid UTF-8".to_string())
                })?,
                &self.user_plugins_dir,
            )?
        } else {
            let path_str = zip_path.to_str().ok_or_else(|| {
                crate::AppError::Plugin("Plugin package path is not valid UTF-8".to_string())
            })?;
            // fresh install 前置：注册表没有该 id 的运行时记录，磁盘上同 id 目录
            // 不可能是当前生效安装（keep-data 残留 / 被装载期重复裁决拒绝的休眠
            // 副本 / tombstone 后重装）。宿主在这里裁决后交给替换入口，避免旧目录
            // 把重装卡成 "already installed"；是否保留旧数据由 options 决定。
            let target_id = crate::manager::downloader::PluginDownloader::peek_plugin_id(zip_path)?;
            if self.plugins.read().await.contains_key(&target_id) {
                return Err(crate::AppError::Plugin(format!(
                    "Plugin '{}' is already installed. Uninstall it first to install a new version.",
                    target_id
                )));
            }
            let data_policy = if options.restore_data {
                crate::manager::downloader::InstallDataPolicy::Restore
            } else {
                crate::manager::downloader::InstallDataPolicy::Discard
            };
            crate::manager::downloader::PluginDownloader::install_from_file_replacing_residue(
                path_str,
                &self.user_plugins_dir,
                data_policy,
            )?
        };

        if self.plugins.read().await.contains_key(&plugin_id) {
            let dir = self.user_plugins_dir.join(&plugin_id);
            if dir.exists() {
                std::fs::remove_dir_all(&dir).map_err(|e| {
                    crate::AppError::Plugin(format!("Failed to rollback plugin dir: {}", e))
                })?;
            }
            return Err(crate::AppError::Plugin(format!(
                "Plugin '{}' is already installed. Uninstall it first to install a new version.",
                plugin_id
            )));
        }

        if !upgrade && !options.restore_data {
            // 用户选择不恢复（默认）：主库 KV 也是旧数据，安装成功后清掉。
            // 失败只告警——包已落地，不把安装判失败（与卸载清理口径一致）。
            if let Err(e) = self.storage.clear_all(&plugin_id).await {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "[PluginHost] Failed to clear retained plugin storage after fresh install"
                );
            }
        }

        // 重新扫描用户目录，加载新插件（含 WASM 实例化，与 new() 初始化路径一致）
        let loaded_map = PluginLoader::load_all(
            &self.user_plugins_dir,
            &self.permission,
            Some(PluginSource::UserInstalled),
        );
        let Some(loaded) = loaded_map.get(&plugin_id).cloned() else {
            return Err(crate::AppError::Plugin(format!(
                "Plugin installed but failed to load: {}",
                plugin_id
            )));
        };

        // 实例化收为一条路径（票 11 第 2 项）：与 `new()` 扫描路径共用同一函数，
        // 失败态语义也由它裁决（Error 入表、列表可见可诊断）
        let (record, instance) = self.instantiate_wasm_plugin(&loaded);
        self.plugins.write().await.insert(plugin_id.clone(), record);
        if let Some(instance) = instance {
            self.wasm_plugins
                .write()
                .await
                .insert(plugin_id.clone(), instance);
        }
        // 注册 manifest contributes 扩展点（commands/views/fileHandlers 等）
        self.register_plugin_contributions(&plugin_id).await;

        tracing::info!(
            plugin_id = %plugin_id,
            "[PluginHost] Plugin installed from zip and registered"
        );
        Ok(plugin_id)
    }

    /// 该应用是否还有可恢复的旧数据（keep-data 卸载 / 重装残留）
    ///
    /// 判据 =「插件私有库 `plugin.db` 家族」或「主库 `plugin_storage` 行」，
    /// 与卸载 `keep_data` 的保留面一致；审批 / 授权记录在卸载时已撤销，不在此列。
    /// 只有 fresh install 的前端提示消费本判定——已安装应用的自身数据不算「旧数据」。
    ///
    /// 目录读失败按错误上抛（fail-visible）：静默当成“无数据”会让用户丢数据。
    pub async fn has_retained_data(&self, plugin_id: &str) -> crate::Result<bool> {
        if let Some(dir) = self.plugin_data_dir(plugin_id) {
            if dir.is_dir() {
                let has_db = dir_has_private_db(&dir).map_err(|e| {
                    crate::AppError::Plugin(format!(
                        "Failed to inspect plugin data dir '{}': {}",
                        dir.display(),
                        e
                    ))
                })?;
                if has_db {
                    return Ok(true);
                }
            }
        }
        self.storage.has_any(plugin_id).await
    }

    // ==================== 权限审批（ADR 0020 / 审计票 03） ====================

    /// 人工批准用户安装插件的权限清单（审批弹层的前端命令落点）
    ///
    /// 语义（与移动端一致）：
    /// - 只对 `UserInstalled` 来源生效——随包内置插件属应用构建信任域，免审批；
    /// - 记录「词汇表内的声明权限」+ 批准时刻的插件目录内容哈希（内容钉扎）；
    /// - 批准只解除闸门，不隐式启用：激活仍由用户显式触发（下一次
    ///   `activate_plugin` 由审批门禁按哈希复核）。
    ///
    /// 返回本次批准的权限清单（供前端 toast/日志用）。
    pub async fn approve_plugin(&self, plugin_id: &str) -> crate::Result<Vec<String>> {
        let (source, extension_path, version, requested) = {
            let plugins = self.plugins.read().await;
            let loaded = plugins.get(plugin_id).ok_or_else(|| {
                crate::AppError::Plugin(format!("Plugin not found: {}", plugin_id))
            })?;
            (
                loaded.source.clone(),
                loaded.extension_path.clone(),
                loaded.manifest.version.clone(),
                loaded.manifest.permissions.clone(),
            )
        };

        if source != PluginSource::UserInstalled {
            return Err(crate::AppError::Plugin(format!(
                "Plugin '{}' (source: {}) is trusted by build, approval is not required",
                plugin_id,
                source.as_str()
            )));
        }
        if extension_path.is_empty() {
            return Err(crate::AppError::Plugin(format!(
                "Plugin '{}' has no extension path, cannot pin approval content",
                plugin_id
            )));
        }

        let approved = crate::security::approval::known_permissions(&requested);
        // 目录哈希不进 async 事件循环（插件目录可能较大，避免阻塞 runtime worker）
        let dir = PathBuf::from(&extension_path);
        let content_hash =
            tokio::task::spawn_blocking(move || crate::security::approval::compute_dir_hash(&dir))
                .await
                .map_err(|e| {
                    crate::AppError::Plugin(format!("Approval hash task failed: {}", e))
                })??;

        crate::security::approval::PluginApprovalStore::new(self.storage.clone())
            .approve(plugin_id, &approved, &content_hash, &version)
            .await?;

        // 词汇表外的声明不写进批准集，此处如实告警（否则用户看不出差异）
        let dropped: Vec<&String> = requested.iter().filter(|p| !approved.contains(p)).collect();
        // 待授权态复位为「已停用」：批准解除了闸门，但未启用仍是事实，
        // 前端据此把状态徽章从「待授权」换成「已停用」
        {
            let mut plugins = self.plugins.write().await;
            if let Some(loaded) = plugins.get_mut(plugin_id) {
                if matches!(loaded.state, PluginState::NeedsApproval) {
                    loaded.state = PluginState::Deactivated;
                }
            }
        }

        tracing::info!(
            plugin_id = %plugin_id,
            permission_count = approved.len(),
            "[PluginHost] 用户安装插件已获人工批准（内容哈希已钉扎）"
        );
        if !dropped.is_empty() {
            tracing::warn!(
                plugin_id = %plugin_id,
                dropped = ?dropped,
                "manifest 声明的权限不在 SDK 词汇表内，未写入批准清单"
            );
        }

        Ok(approved)
    }

    /// 卸载插件：默认删除插件所有数据（存储 + 安装目录 + 私有数据库，dev 合入）
    ///
    /// 适用范围：**所有来源的插件**（内置随包 / 用户 zip 安装 / 文件扫描 / 静态注册）。
    /// 前置条件：插件存在、**未启用**（Activated/Activating/Degraded 拒绝卸载），
    /// 且装配角色是 L3 业务应用（`business-app`）；L1/L2 系统服务随宿主发布，
    /// 不提供卸载面。
    /// 执行：停用（hooks 清理/总线退订/扩展点注销）→ 丢弃私有数据库连接 →
    /// 删除安装目录 → 移除运行时实例与记录 → 清空插件存储 → 撤销持久化审批
    /// 记录 → 清理持久化激活状态与限频簿记。
    pub async fn uninstall_plugin(&self, plugin_id: &str) -> crate::Result<()> {
        self.uninstall_plugin_with_options(plugin_id, UninstallOptions::default())
            .await
    }

    /// 卸载插件（带数据 / 安装目录保留策略）
    ///
    /// `UninstallOptions` 是宿主侧的**数据保留策略**，机制语义仍是同一次卸载：
    /// - `keep_data`：保留 `plugin.db` 家族与主库 `plugin_storage` 行，重装后继续
    ///   使用；审批记录与授权策略/记录**仍会撤销**（安全面，不随数据保留）；
    /// - `keep_install_dir`：保留安装目录（随包内置插件位于只读资源目录，桌面宿主
    ///   用 tombstone 抑制重载；用户安装插件应传 false 真正删包）。
    ///
    /// `keep_data=true` 时，用户安装插件的安装目录只删代码文件、留下 `plugin.db`
    /// 家族；目录因缺 `plugin.json` 不再被 loader 装载，重装时由 install 侧保留。
    pub async fn uninstall_plugin_with_options(
        &self,
        plugin_id: &str,
        options: UninstallOptions,
    ) -> crate::Result<()> {
        // 安装目录取自插件自身的 extension_path：内置插件在资源目录、用户插件在
        // app_data_dir/plugins，二者都是「插件自有的安装目录」，删除语义一致
        let (plugin_dir, kind) = {
            let plugins = self.plugins.read().await;
            let loaded = plugins.get(plugin_id).ok_or_else(|| {
                crate::AppError::Plugin(format!("Plugin not found: {}", plugin_id))
            })?;
            // 规则：仅未启用插件可卸载（Activating 是激活进行中的瞬时态，同样拒绝）
            if matches!(
                loaded.state,
                PluginState::Activated | PluginState::Activating | PluginState::Degraded { .. }
            ) {
                return Err(crate::AppError::Plugin(format!(
                    "Plugin is running, deactivate it before uninstalling: {}",
                    plugin_id
                )));
            }
            (
                std::path::PathBuf::from(&loaded.extension_path),
                loaded.manifest.kind,
            )
        };
        if kind.is_role_driven() {
            return Err(crate::AppError::Plugin(format!(
                "System service cannot be uninstalled: {}",
                plugin_id
            )));
        }

        // 停用（防御性：前置条件已保证未运行，此处只做残留资源清理，幂等）
        self.deactivate_plugin(plugin_id, true).await?;

        // 丢弃私有数据库缓存连接：删除目录前释放文件句柄
        self.wasm_host_ctx.drop_plugin_db(plugin_id).await;

        // 私有数据库目录：用户安装插件 = 安装目录；随包内置插件 = app_data_dir/plugins
        // （内置资源目录只读且随宿主更新，不可承载可保留的数据）。
        let data_dir = self.plugin_data_dir(plugin_id);
        let data_dir_is_install_dir = data_dir.as_deref() == Some(plugin_dir.as_path())
            || plugin_dir.starts_with(&self.user_plugins_dir);

        // 删除插件安装目录（插件文件与私有 plugin.db 同目录）。目录名须与插件 id
        // 一致才删，防止 manifest 的异常 extension_path 指向非插件目录；静态注册
        // 插件（随二进制分发，无独立目录）extension_path 为空 → 跳过。
        // `keep_install_dir=true`（随包内置插件）只卸载运行时记录，目录交给宿主
        // tombstone 抑制；`keep_data=true` 且安装目录承载私有库时只删代码文件。
        if options.keep_install_dir {
            tracing::info!(
                plugin_id = %plugin_id,
                "[PluginHost] Keeping install dir on uninstall (host tombstone owns suppression)"
            );
        } else if plugin_dir.as_os_str().is_empty() {
            tracing::debug!(plugin_id = %plugin_id, "[PluginHost] No plugin dir to remove (static/builtin)");
        } else if plugin_dir.file_name().and_then(|n| n.to_str()) != Some(plugin_id) {
            tracing::warn!(
                plugin_id = %plugin_id,
                path = %plugin_dir.display(),
                "[PluginHost] Skip plugin dir removal: extension path does not match plugin id"
            );
        } else if plugin_dir.exists() {
            if options.keep_data && data_dir_is_install_dir {
                Self::remove_package_files_keep_db(&plugin_dir).map_err(|e| {
                    crate::AppError::Plugin(format!(
                        "Failed to remove plugin package files '{}': {}",
                        plugin_dir.display(),
                        e
                    ))
                })?;
            } else {
                std::fs::remove_dir_all(&plugin_dir).map_err(|e| {
                    crate::AppError::Plugin(format!(
                        "Failed to remove plugin dir '{}': {}",
                        plugin_dir.display(),
                        e
                    ))
                })?;
            }
        }

        // 数据目录与安装目录分离时（随包内置插件），删除数据也在这里收口：
        // 只删确认不是有效安装副本的目录（含 plugin.json 的用户安装副本保留）。
        if !options.keep_data {
            if let Some(data_dir) = data_dir.as_ref() {
                if data_dir != &plugin_dir
                    && data_dir.exists()
                    && !data_dir.join(PLUGIN_MANIFEST_FILE).exists()
                {
                    match std::fs::remove_dir_all(data_dir) {
                        Ok(()) => tracing::info!(
                            plugin_id = %plugin_id,
                            dir = %data_dir.display(),
                            "[PluginHost] Removed plugin data dir on uninstall"
                        ),
                        Err(e) => tracing::warn!(
                            plugin_id = %plugin_id,
                            dir = %data_dir.display(),
                            error = %e,
                            "[PluginHost] Failed to remove plugin data dir on uninstall"
                        ),
                    }
                }
            }
        }

        // 移除 WASM 实例与插件记录：**先停属主再动 map**（I3③——条目摘除即
        // 触发 `OwnerHandle::drop` 兜底，但显式 stop 才能等到 store 真正 drop）
        let removed_entry = { self.wasm_plugins.write().await.remove(plugin_id) };
        if let Some(entry) = removed_entry {
            if let Some(report) = entry.shutdown().await {
                if report.forced_abort || report.abandoned_requests > 0 {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        abandoned_requests = report.abandoned_requests,
                        forced_abort = report.forced_abort,
                        "plugin instance owner stopped on uninstall with unresolved requests"
                    );
                }
            }
        }
        self.plugins.write().await.remove(plugin_id);

        // 指标注册表与已加载插件集合求一致：不清会让卸载后的旧计数以幽灵卡
        // 出现在监控快照里，直到宿主重启；只清卸载路径，重载 / 重装保留累计值
        self.wasm_runtime.monitor().remove(plugin_id);

        // 顺带清理用户插件目录下同 id 的孤儿残留（无 plugin.json 的数据目录）：
        // 这类目录不参与加载、UI 不可见，但会卡住同 id 重装（install 的磁盘查重
        // 会误判为已安装）。含 plugin.json 时视为另一来源的有效安装，保留不删。
        let orphan_dir = self.user_plugins_dir.join(plugin_id);
        if !options.keep_data
            && orphan_dir != plugin_dir
            && orphan_dir.exists()
            && !orphan_dir.join(PLUGIN_MANIFEST_FILE).exists()
        {
            match std::fs::remove_dir_all(&orphan_dir) {
                Ok(()) => {
                    tracing::info!(
                        plugin_id = %plugin_id,
                        dir = %orphan_dir.display(),
                        "[PluginHost] Removed orphan residue dir on uninstall"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        error = %e,
                        dir = %orphan_dir.display(),
                        "[PluginHost] Failed to remove orphan residue dir on uninstall"
                    );
                }
            }
        }

        // 清理插件存储（插件私有数据 + fs 授权 / 预授权记录）。
        // `keep_data=true` 时保留主库行（插件 KV 与应用私有库一起构成「应用数据」）。
        if !options.keep_data {
            if let Err(e) = self.storage.clear_all(plugin_id).await {
                tracing::warn!(plugin_id = %plugin_id, error = %e, "Failed to clear plugin storage on uninstall");
            }
        } else {
            tracing::info!(
                plugin_id = %plugin_id,
                "[PluginHost] Keeping plugin storage on uninstall (keep_data)"
            );
        }
        // 撤销持久化审批记录：审批 map 位于 `__system__` 空间，clear_all 清不到
        if let Err(e) = crate::security::approval::PluginApprovalStore::new(self.storage.clone())
            .revoke(plugin_id)
            .await
        {
            tracing::warn!(
                plugin_id = %plugin_id,
                error = %e,
                "Failed to revoke plugin approval on uninstall"
            );
        }
        // 授权策略与授权记录（spec §8.3）：**卸载清空 / 重装即全新授权**。
        // 不跟着 `clear_all` 走 —— 那是插件私有存储，这两张表在主库。停用不清空，
        // 那是另一条语义（见 auth_policy::purge_plugin 的文档与 lifecycle 用例）
        let auth_store = crate::security::auth_policy::AuthPolicyStore::new(self.storage.db());
        if let Err(e) = auth_store.purge_plugin(plugin_id).await {
            tracing::warn!(
                plugin_id = %plugin_id,
                error = %e,
                "Failed to purge auth policies/records on uninstall"
            );
        }
        self.persist_activation_state().await;

        // 清理限频簿记：避免重装同 id 插件沿用旧记录
        self.wasm_reload_throttle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(plugin_id);
        self.runtime_error_notify_throttle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(plugin_id);

        tracing::info!(
            plugin_id = %plugin_id,
            keep_data = options.keep_data,
            keep_install_dir = options.keep_install_dir,
            "[PluginHost] Plugin uninstalled"
        );
        Ok(())
    }

    /// 插件私有数据库目录（与 `WasmHostContext::get_or_create_plugin_db` 同一布局）
    ///
    /// 无头上下文没有 AppHandle 时返回 None；此时调用方以安装目录作为数据目录。
    fn plugin_data_dir(&self, plugin_id: &str) -> Option<PathBuf> {
        self.wasm_host_ctx
            .app_handle()
            .and_then(|handle| handle.path().app_data_dir().ok())
            .map(|dir| dir.join("plugins").join(plugin_id))
    }

    /// 删除安装目录中的代码文件，只保留插件私有库（`plugin.db` 家族）
    ///
    /// 目录本身保留：loader 因缺 `plugin.json` 跳过；重装时 install 侧把私有库
    /// 搬进新包目录（见 `PluginDownloader::preserve_private_db`）。
    fn remove_package_files_keep_db(dir: &Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "plugin.db" || name.starts_with("plugin.db-") {
                continue;
            }
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
        }
        Ok(())
    }
}

/// 目录里是否留有插件私有库家族（`plugin.db` / `plugin.db-wal` / `plugin.db-shm`）
///
/// 抽成自由函数：无头测试没有 AppHandle（`plugin_data_dir` 不可用），
/// 但“旧数据是否存在”的目录判据本身需要可独立回归。
pub(super) fn dir_has_private_db(dir: &std::path::Path) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if name == "plugin.db" || name.starts_with("plugin.db-") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 卸载策略（宿主侧数据保留选择；默认 = 删除全部数据与安装目录）
#[derive(Debug, Clone, Copy, Default)]
pub struct UninstallOptions {
    /// 保留应用数据：插件私有库 `plugin.db` 家族 + 主库 `plugin_storage` 行
    pub keep_data: bool,
    /// 保留安装目录（随包内置插件：宿主以 tombstone 抑制重载）
    pub keep_install_dir: bool,
}

/// 安装策略（宿主侧 fresh install 数据恢复选择；默认 = 不恢复旧数据）
#[derive(Debug, Clone, Copy, Default)]
pub struct InstallOptions {
    /// 是否恢复 keep-data 卸载留下的旧数据（私有库 + 主库 KV）
    ///
    /// 只对 fresh install 生效；`upgrade = true` 恒保数据。默认 false =
    /// 丢弃旧数据，避免“卸载时没删”变成“重装静默继承”。
    pub restore_data: bool,
}
