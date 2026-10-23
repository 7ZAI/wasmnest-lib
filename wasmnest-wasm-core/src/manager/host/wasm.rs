//! `wasm` — PluginHost 职责面拆分（P2）
//!
//! 自 `host.rs` 主 impl 拆出；经 `use super::*` 继承 host 模块的
//! 全部导入与常量，方法与字段可见性规则与内联时一致。

use super::*;
impl PluginHost {
    /// 插件 WASM 实例化的**唯一实现**（票 11 第 2 项）
    ///
    /// 启动扫描路径（`host.rs::new` → [`Self::instantiate_scanned_wasm_plugins`]）
    /// 与 zip 安装路径（`install.rs::install_from_zip`）此前各持一份近乎复制的
    /// 实例化逻辑（连 wasm 后缀都是一处硬编码 `".wasm"`、一处走 `WASM_FILE_EXT`
    /// 常量），实例化策略升级必须同改两处——这正是「一处修复要同步两处」的漂移面，
    /// 故收为一条，两入口只负责落表。
    ///
    /// 实例化需要 `&self`：调用模型（`event-loop`）的属主任务必须拿到失败回报
    /// 端口（[`HostOwnerFailureSink`]，持 `Weak<PluginHost>`）——端口只能在宿主
    /// 构造完成后注入，故实例化整体后移到 `Arc<Self>` 就绪之后。
    ///
    /// 返回 `(入表记录, WASM 实例条目)`：
    /// - 未声明 `rust_library` → 纯前端插件：原记录入表，无实例；
    /// - wasm 文件缺失（部署残缺）/ 加载失败（编译或 link 错） → 记录降级为
    ///   `PluginState::Error` 而**不丢弃**：插件仍见于列表且状态可诊断。
    pub(crate) fn instantiate_wasm_plugin(
        &self,
        loaded: &LoadedPlugin,
    ) -> (LoadedPlugin, Option<Arc<WasmInstanceEntry>>) {
        let manifest = &loaded.manifest;
        if manifest.rust_library.is_empty() {
            return (loaded.clone(), None);
        }

        let wasm_path = Path::new(&loaded.extension_path).join(format!(
            "{}{}",
            manifest.rust_library,
            crate::system::constants::WASM_FILE_EXT
        ));
        if !wasm_path.exists() {
            tracing::error!(
                plugin_id = %manifest.id,
                path = %wasm_path.display(),
                "WASM module not found for plugin; plugin kept as Error state"
            );
            return (
                LoadedPlugin {
                    state: PluginState::Error {
                        error: format!("WASM module not found: {}", wasm_path.display()),
                    },
                    ..loaded.clone()
                },
                None,
            );
        }

        match self.wasm_runtime.load_plugin_from_file(
            &wasm_path,
            &manifest.id,
            self.wasm_host_ctx.clone(),
            &manifest.wasi_preopen_dirs,
            manifest.resource_overrides.as_ref(),
        ) {
            Ok(instance) => {
                tracing::info!(
                    plugin_id = %manifest.id,
                    version = %manifest.version,
                    call_model = %self.wasm_runtime.config().call_model.as_str(),
                    "WASM plugin loaded"
                );
                (loaded.clone(), Some(self.assemble_instance_entry(instance)))
            }
            Err(e) => {
                tracing::error!(
                    plugin_id = %manifest.id,
                    error = %e,
                    path = %wasm_path.display(),
                    "Failed to load WASM plugin instance; plugin kept as Error state"
                );
                (
                    LoadedPlugin {
                        state: PluginState::Error {
                            error: format!("WASM load failed: {}", e),
                        },
                        ..loaded.clone()
                    },
                    None,
                )
            }
        }
    }

    /// 按当前配置把已加载实例装配成装配条目（调用模型在这里定一次，实例级快照）
    pub(crate) fn assemble_instance_entry(
        &self,
        plugin: LoadedWasmPlugin,
    ) -> Arc<WasmInstanceEntry> {
        let call_model = self.wasm_runtime.config().call_model;
        Arc::new(WasmInstanceEntry::new(
            plugin,
            call_model,
            self.owner_sink.clone(),
        ))
    }

    /// 把已加载实例装配入表（调用模型**显式指定**）
    ///
    /// 生产路径经 [`Self::instantiate_wasm_plugin`] / [`Self::assemble_instance_entry`]
    /// （模型取配置快照）；测试用本方法按模型直接装配——两模型对照用例因此不必
    /// 改全局配置，可并行跑。
    ///
    /// **常编译 pub（wasm-core 纯净性收口票 05b）**：lib 集成测试（system_component_test
    /// / 后续 05c 迁移文件）经 `PluginHost::new` 真实装配后注入实例；原 `#[cfg(test)]`
    /// 门控使 lib 依赖链（非 test 构建）不可见。
    pub async fn install_instance(
        &self,
        plugin_id: &str,
        plugin: LoadedWasmPlugin,
        call_model: CallModel,
    ) -> Arc<WasmInstanceEntry> {
        let entry = Arc::new(WasmInstanceEntry::new(
            plugin,
            call_model,
            self.owner_sink.clone(),
        ));
        self.wasm_plugins
            .write()
            .await
            .insert(plugin_id.to_string(), entry.clone());
        entry
    }

    /// 启动扫描路径的实例化：为 `plugins` 表里声明了 `rust_library` 的记录建实例
    ///
    /// 必须在 `Arc<Self>` 构造之后调用（属主失败端口必须先绑定）；zip 安装路径
    /// 单独经 [`Self::instantiate_wasm_plugin`] 落表。
    pub(crate) async fn instantiate_scanned_wasm_plugins(&self) {
        let candidates: Vec<LoadedPlugin> = {
            let plugins = self.plugins.read().await;
            plugins
                .values()
                .filter(|p| !p.manifest.rust_library.is_empty())
                .cloned()
                .collect()
        };
        for loaded in candidates {
            let plugin_id = loaded.manifest.id.clone();
            let (record, instance) = self.instantiate_wasm_plugin(&loaded);
            if let Some(instance) = instance {
                self.wasm_plugins
                    .write()
                    .await
                    .insert(plugin_id.clone(), instance);
            }
            let mut plugins = self.plugins.write().await;
            if let Some(slot) = plugins.get_mut(&plugin_id) {
                *slot = record;
            }
        }
    }

    /// 重建 WASM 插件实例（load_plugin_from_file + 替换 map 条目）
    ///
    /// 激活路径：声明 WASI 预打开目录的插件首次授权后实例未覆盖新授权目录时
    /// 重建，使 /data 挂载与授权一致；热重载路径同样复用（停用 → 重建 → 重注册）。
    /// 失败上抛（原实例保留，激活流程走既有错误分支置 Error 态）。
    pub(crate) async fn rebuild_wasm_instance(&self, plugin_id: &str) -> crate::Result<()> {
        let (rust_library, extension_path, declared_preopen_dirs, resource_overrides) = {
            let plugins = self.plugins.read().await;
            let loaded = plugins.get(plugin_id).ok_or_else(|| {
                crate::AppError::Plugin(format!("Plugin not found: {}", plugin_id))
            })?;
            (
                loaded.manifest.rust_library.clone(),
                loaded.extension_path.clone(),
                loaded.manifest.wasi_preopen_dirs.clone(),
                loaded.manifest.resource_overrides,
            )
        };

        let plugin_dir = Path::new(&extension_path);
        let wasm_filename = format!("{}.wasm", rust_library);
        let wasm_path = plugin_dir.join(&wasm_filename);

        // 先停旧属主再动 map（I3③：旧实例的 store 丢弃后才做后续回收；
        // 禁止先替换 Arc——那会让旧属主与资源回收竞争）
        let old_entry = { self.wasm_plugins.read().await.get(plugin_id).cloned() };
        if let Some(old_entry) = old_entry {
            if let Some(report) = old_entry.shutdown().await {
                if report.forced_abort || report.abandoned_requests > 0 {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        abandoned_requests = report.abandoned_requests,
                        forced_abort = report.forced_abort,
                        "old plugin instance owner stopped before rebuild"
                    );
                }
            }
        }

        let new_wasm_plugin = self.wasm_runtime.load_plugin_from_file(
            &wasm_path,
            plugin_id,
            self.wasm_host_ctx.clone(),
            &declared_preopen_dirs,
            resource_overrides.as_ref(),
        )?;
        let new_entry = self.assemble_instance_entry(new_wasm_plugin);
        self.wasm_plugins
            .write()
            .await
            .insert(plugin_id.to_string(), new_entry);

        // core-plugin-manager：L1 基础服务实例重建后，能力注册表中的旧实例句柄
        // 已失效，按新实例重新装配（trap 自愈回落宿主原语的场景亦在此恢复）
        let provides_capabilities = {
            let plugins = self.plugins.read().await;
            plugins
                .get(plugin_id)
                .map(|p| p.manifest.kind.provides_host_capabilities())
                .unwrap_or(false)
        };
        if provides_capabilities {
            self.wasm_host_ctx.capabilities().revert_all_from(plugin_id);
            self.register_system_capabilities(plugin_id).await;
        }
        Ok(())
    }

    /// 热重载 WASM 插件（开发模式）
    ///
    /// 执行完整的卸载-重载-激活循环：
    /// 1. 停用插件
    /// 2. 重新编译并实例化 WASM 模块
    /// 3. 重新激活插件
    pub async fn reload_wasm_plugin(&self, plugin_id: &str) -> crate::Result<()> {
        {
            let plugins = self.plugins.read().await;
            let loaded = plugins.get(plugin_id).ok_or_else(|| {
                crate::AppError::Plugin(format!("Plugin not found: {}", plugin_id))
            })?;
            if loaded.source != PluginSource::Wasm {
                return Err(crate::AppError::Plugin(format!(
                    "Plugin {} is not a WASM plugin, cannot hot-reload",
                    plugin_id
                )));
            }
        }

        tracing::info!(plugin_id = %plugin_id, "Hot-reloading WASM plugin");

        // 1. 停用插件（不持久化）
        self.deactivate_plugin(plugin_id, false).await?;

        // 2. 重新编译并实例化 WASM 模块（替换 wasm_plugins map 条目）
        self.rebuild_wasm_instance(plugin_id).await?;

        // 3. 重新注册 manifest contributes（委派单条注册唯一实现，票 11 第 3 项）
        self.register_plugin_contributions(plugin_id).await;

        // 4. 重新激活
        self.activate_plugin(plugin_id, false).await?;

        tracing::info!(plugin_id = %plugin_id, "WASM plugin hot-reloaded successfully");
        Ok(())
    }
}
