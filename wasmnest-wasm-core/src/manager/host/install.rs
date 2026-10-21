//! `install` — PluginHost 职责面拆分（P2）
//!
//! 自 `host.rs` 主 impl 拆出；经 `use super::*` 继承 host 模块的
//! 全部导入与常量，方法与字段可见性规则与内联时一致。

use super::*;
impl PluginHost {
    /// 从 zip 分发包安装插件（dev 合入）
    ///
    /// 解压校验（manifest/身份/路径安全）→ 重新扫描用户目录 → WASM 实例化 →
    /// 注册 manifest 扩展点。同 id 已安装时回滚安装目录并报错（需先卸载）。
    pub async fn install_from_zip(&self, zip_path: &str) -> crate::Result<String> {
        let plugin_id = crate::manager::downloader::PluginDownloader::install_from_file(
            zip_path,
            &self.user_plugins_dir,
        )?;

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

    /// 卸载插件：删除插件所有数据（存储 + 激活状态 + 安装目录 + 私有数据库，dev 合入）
    ///
    /// 适用范围：**所有来源的插件**（内置随包 / 用户 zip 安装 / 文件扫描 / 静态注册）。
    /// 前置条件：插件存在且**未启用**（Activated/Activating/Degraded 拒绝卸载）。
    /// 执行：停用（hooks 清理/总线退订/扩展点注销）→ 丢弃私有数据库连接 →
    /// 删除安装目录 → 移除运行时实例与记录 → 清空插件存储 → 撤销持久化审批
    /// 记录 → 清理持久化激活状态与限频簿记。

    /// 卸载插件：删除插件所有数据（存储 + 激活状态 + 安装目录 + 私有数据库，dev 合入）
    ///
    /// 适用范围：**所有来源的插件**（内置随包 / 用户 zip 安装 / 文件扫描 / 静态注册）。
    /// 前置条件：插件存在且**未启用**（Activated/Activating/Degraded 拒绝卸载）。
    /// 执行：停用（hooks 清理/总线退订/扩展点注销）→ 丢弃私有数据库连接 →
    /// 删除安装目录 → 移除运行时实例与记录 → 清空插件存储 → 撤销持久化审批
    /// 记录 → 清理持久化激活状态与限频簿记。
    pub async fn uninstall_plugin(&self, plugin_id: &str) -> crate::Result<()> {
        // 安装目录取自插件自身的 extension_path：内置插件在资源目录、用户插件在
        // app_data_dir/plugins，二者都是「插件自有的安装目录」，删除语义一致
        let plugin_dir = {
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
            std::path::PathBuf::from(&loaded.extension_path)
        };

        // 停用（防御性：前置条件已保证未运行，此处只做残留资源清理，幂等）
        self.deactivate_plugin(plugin_id, true).await?;

        // 丢弃私有数据库缓存连接：删除目录前释放文件句柄
        self.wasm_host_ctx.drop_plugin_db(plugin_id).await;

        // 删除插件安装目录（插件文件与私有 plugin.db 同目录）。目录名须与插件 id
        // 一致才删，防止 manifest 的异常 extension_path 指向非插件目录；静态注册
        // 插件（随二进制分发，无独立目录）extension_path 为空 → 跳过
        if plugin_dir.as_os_str().is_empty() {
            tracing::debug!(plugin_id = %plugin_id, "[PluginHost] No plugin dir to remove (static/builtin)");
        } else if plugin_dir.file_name().and_then(|n| n.to_str()) != Some(plugin_id) {
            tracing::warn!(
                plugin_id = %plugin_id,
                path = %plugin_dir.display(),
                "[PluginHost] Skip plugin dir removal: extension path does not match plugin id"
            );
        } else if plugin_dir.exists() {
            std::fs::remove_dir_all(&plugin_dir).map_err(|e| {
                crate::AppError::Plugin(format!(
                    "Failed to remove plugin dir '{}': {}",
                    plugin_dir.display(),
                    e
                ))
            })?;
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
        if orphan_dir != plugin_dir
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

        // 清理插件存储（插件私有数据 + fs 授权 / 预授权记录）
        if let Err(e) = self.storage.clear_all(plugin_id).await {
            tracing::warn!(plugin_id = %plugin_id, error = %e, "Failed to clear plugin storage on uninstall");
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

        tracing::info!(plugin_id = %plugin_id, "[PluginHost] Plugin uninstalled");
        Ok(())
    }
}
