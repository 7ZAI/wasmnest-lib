//! `boot` — PluginHost 职责面拆分（P2）
//!
//! 自 `host.rs` 主 impl 拆出；经 `use super::*` 继承 host 模块的
//! 全部导入与常量，方法与字段可见性规则与内联时一致。

use super::*;
use futures_util::FutureExt;
use std::pin::Pin;

/// 回调执行结果（M-01 圈护后的分类）
#[derive(Debug)]
enum CallbackOutcome {
    /// 正常完成
    Done,
    /// 返回 Err（同步或未来内）
    Failed(String),
    /// panic（同步调用段或未来 poll 段）
    Panicked(String),
}

/// 圈护静态插件回调（M-01）：`on_startup` / `on_shutdown` 是第三方链接代码，
/// 同步调用段与未来 poll 段的 panic 都不得 unwind 穿透宿主任务——两段分别
/// `catch_unwind`，载荷转 [`CallbackOutcome`] 供日志点名。
fn guarded_callback<F>(
    invoke: F,
) -> Pin<Box<dyn std::future::Future<Output = CallbackOutcome> + Send>>
where
    F: FnOnce() -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + 'static,
{
    // 同步调用段（返回 future 之前可能 panic）
    let invoked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(invoke));
    match invoked {
        Ok(fut) => Box::pin(
            std::panic::AssertUnwindSafe(fut)
                .catch_unwind()
                .map(|r| match r {
                    Ok(Ok(())) => CallbackOutcome::Done,
                    Ok(Err(e)) => CallbackOutcome::Failed(format!("{e:#}")),
                    Err(payload) => CallbackOutcome::Panicked(panic_message(&payload)),
                }),
        ),
        Err(payload) => Box::pin(futures_util::future::ready(CallbackOutcome::Panicked(
            panic_message(&payload),
        ))),
    }
}

/// panic 载荷的人类可读描述（M-01 日志用）：优先 downcast 到 `&str` / `String`，
/// 其余落类型名——让「插件回调 panic」至少有点名信息可排障
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("<non-string panic payload: {:?}>", payload.type_id())
    }
}

/// L2 层「静态声明 + 动态就绪」的运行时判据（ADR 0031 K9 · fail-visible 形态②）
///
/// 抽成纯函数只为可单测：boot 循环本身要整套 `PluginHost` 才跑得起来，而这条判据
/// 决定「是否必须在就位点点名报错」——fail-closed 下它唯一的可见信号就是这条日志，
/// 判据本身不能只能靠端到端观察。
///
/// `registered_owner` = L2 层激活完毕后注册表里的认证中心属主（`None` = 无人注册）。
/// 单中心（K4）下只判「有没有中心」，**不比对属主**：L2 层允许多插件共存
/// （auth-center + monitor），逐插件要求「自己是中心」会在正常启动时误报全拒
/// （2026-10-26 dev 实证：auth-center 已在册，monitor 激活后仍刷「认证面全部拒绝」）。
fn l2_auth_center_unready(kind: PluginKind, registered_owner: Option<&str>) -> bool {
    kind.is_internal_business() && registered_owner.is_none()
}

impl PluginHost {
    /// 通知所有已激活的 Rust 插件应用启动完成
    pub async fn notify_startup(&self) {
        // 静态注册插件（按 ID 排序，确定性顺序，M-07）
        let mut static_plugins: Vec<&'static wasmnest_plugin_api::WasmNestPluginEntry> =
            inventory::iter::<wasmnest_plugin_api::WasmNestPluginEntry>
                .into_iter()
                .collect();
        static_plugins.sort_by_key(|e| e.id);
        for entry in &static_plugins {
            if self.is_activated(entry.id).await {
                tracing::debug!(plugin_id = %entry.id, "Notifying plugin on_startup");
                // catch_unwind 圈护（M-01）：on_startup 是第三方链接代码，panic 会
                // unwind 穿透宿主任务（乃至整个宿主）；记录载荷后继续其余插件
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(PLUGIN_CALLBACK_TIMEOUT_SECS),
                    guarded_callback(entry.on_startup),
                )
                .await;
                match result {
                    Err(_) => tracing::error!(plugin_id = %entry.id, "Plugin on_startup timed out"),
                    Ok(CallbackOutcome::Panicked(panic)) => {
                        tracing::error!(plugin_id = %entry.id, panic = %panic, "Plugin on_startup panicked");
                    }
                    Ok(CallbackOutcome::Done) => {}
                    // v8 契约：启动初始化失败如实记录（静态插件无 Degraded 态，
                    // 仅日志可观测；builtin 常驻语义见 ticket 03）
                    Ok(CallbackOutcome::Failed(e)) => {
                        tracing::error!(plugin_id = %entry.id, error = %e, "Plugin on_startup failed")
                    }
                }
            }
        }

        // WASM 插件的 on_startup 已在 activate_plugin() 中自动调用，此处不再重复

        // TS-only 插件：通过 Tauri 事件通知
        // 无头/测试上下文无 AppHandle（`self.wasm_host_ctx().app_handle()` 为
        // None）：降级为纯日志跳过（与统一异常通道同策略），不影响上方静态插件的
        // 回调分发。整核抽出：不再经 lib `AppContext::try_global()`，直接取
        // 本 host 的 WasmHostContext（AppHandleScope，spec §2.3）。
        if let Some(handle) = self.wasm_host_ctx().app_handle() {
            let _ = handle.emit(LIFECYCLE_STARTUP, serde_json::json!({}));
        }

        tracing::info!("PluginHost notify_startup completed");
    }

    /// 通知所有已激活的 Rust 插件应用即将关闭
    ///
    /// **职责边界（M-08，显式受检契约）**：本方法只通知**静态注册**插件的
    /// on_shutdown；WASM 插件的 on_shutdown 由 `deactivate_plugin()` 负责。
    /// 调用方（`system/lifecycle.rs` 的 shutdown 链）必须保证顺序：
    /// `notify_shutdown`（优先级 15）先于 `deactivate_all`（优先级 20）——
    /// 静态回调先跑完，WASM 插件随后逐个停用并各跑自己的 on_shutdown。
    pub async fn notify_shutdown(&self) {
        // 静态注册插件（按 ID 排序，确定性顺序，M-07）
        let mut static_plugins: Vec<&'static wasmnest_plugin_api::WasmNestPluginEntry> =
            inventory::iter::<wasmnest_plugin_api::WasmNestPluginEntry>
                .into_iter()
                .collect();
        static_plugins.sort_by_key(|e| e.id);
        for entry in &static_plugins {
            if self.is_activated(entry.id).await {
                tracing::debug!(plugin_id = %entry.id, "Notifying plugin on_shutdown");
                // catch_unwind 圈护（M-01）：on_shutdown panic 不得打断其余插件收尾
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(PLUGIN_CALLBACK_TIMEOUT_SECS),
                    guarded_callback(entry.on_shutdown),
                )
                .await;
                match result {
                    Err(_) => {
                        tracing::error!(plugin_id = %entry.id, "Plugin on_shutdown timed out")
                    }
                    Ok(CallbackOutcome::Panicked(panic)) => {
                        tracing::error!(plugin_id = %entry.id, panic = %panic, "Plugin on_shutdown panicked");
                    }
                    Ok(CallbackOutcome::Done) => {}
                    // 清理失败仅记录：停用流程继续，不影响状态机
                    Ok(CallbackOutcome::Failed(e)) => {
                        tracing::error!(plugin_id = %entry.id, error = %e, "Plugin on_shutdown failed")
                    }
                }
            }
        }

        // WASM 插件的 on_shutdown 已在 deactivate_plugin() 中自动调用，此处不再重复

        // TS-only 插件：通过 Tauri 事件通知（无头/测试上下文降级跳过，同 notify_startup）
        if let Some(handle) = self.wasm_host_ctx().app_handle() {
            let _ = handle.emit(LIFECYCLE_SHUTDOWN, serde_json::json!({}));
        }

        tracing::info!("PluginHost notify_shutdown completed");
    }

    /// 角色驱动层先于业务应用激活（L1 基础服务 → L2 内部统一业务，ADR 0032）
    ///
    /// 三张加载层：**L1 → L2 → L3**。L1 最先（其 host-* 同形能力要先装配进
    /// 能力注册表，否则消费方激活时的依赖检查会误报缺失）；L2 次之（宿主网关的
    /// 裁决依赖方须先于业务应用就绪）；L3 = [`Self::auto_activate_from_persisted_state`]
    /// 那一批，本方法不碰。
    ///
    /// 层的顺序取自 SDK 常量 [`PluginKind::ROLE_DRIVEN_LOAD_ORDER`]（真源在
    /// 角色定义旁，宿主只遍历不认识具体角色值——新增角色不必改宿主）；批内按
    /// 插件 ID 排序（确定性，不引入隐式优先级规则）。
    ///
    /// 「单个失败不阻断其余」沿用：失败组件落 Error 态，其余照常激活。L2 失败时
    /// L3 仍会激活、但认证面全拒（fail-closed，ADR 0031）——因此该失败必须有
    /// 可见信号（`error` 日志 + 插件列表 Error 态），不能只落内部状态。
    pub(crate) async fn activate_role_driven_components(&self) {
        for kind in PluginKind::ROLE_DRIVEN_LOAD_ORDER {
            let mut ids: Vec<String> = {
                let plugins = self.plugins.read().await;
                plugins
                    .values()
                    .filter(|p| p.manifest.kind == kind && p.source != PluginSource::StaticRegistry)
                    .map(|p| p.manifest.id.clone())
                    .collect()
            };
            ids.sort();
            if ids.is_empty() {
                continue;
            }
            tracing::info!(
                role = kind.label(),
                count = ids.len(),
                "[PluginHost] 角色驱动层先于 L3 业务应用激活"
            );
            for id in ids {
                if let Err(e) = self.activate_plugin(&id, false).await {
                    tracing::error!(
                        plugin_id = %id,
                        role = kind.label(),
                        error = %e,
                        "[PluginHost] 角色驱动组件激活失败（其余组件照常激活；L2 失败时认证面 fail-closed）"
                    );
                    continue;
                }
            }
            // L2 的「静态声明 + 动态就绪」两段（ADR 0031 K9）：**整层激活完毕后**
            // 仍无认证中心在册，才是 fail-closed 的报错条件。不能逐个插件比属主——
            // L2 可以有多插件（auth-center + monitor），非属主的同级插件是常态。
            // 该报错是「旧产物 / 中心忘注册」的 fail-visible 形态②：必须在就位点
            // 点名「按当前 SDK 重建并注册」，而不是等用户撞到「所有东西都连不上」。
            if kind.is_internal_business() {
                let registered_owner =
                    crate::host_api::auth_center::center().map(|entry| entry.owner);
                if l2_auth_center_unready(kind, registered_owner.as_deref()) {
                    tracing::error!(
                        role = kind.label(),
                        deny_kind = "no_center",
                        "[PluginHost] L2 层激活完成但无认证中心在册——认证面将全部拒绝 \
                         (fail-closed)。旧产物请按当前 SDK 重建（activate 内调 \
                         auth-center-register）；新产物请在 activate 里调用并检查失败日志"
                    );
                }
            }
        }
    }

    /// 存量兼容（ADR 0020 迁移）：升级前已启用的用户插件首启自动批准一次
    ///
    /// 审批门禁上线前，用户安装的插件按 manifest 全量授权即可运行；直接按新门禁拒绝
    /// 会把用户现有功能打死（票 03 裁决 1）。因此对「持久化状态为已启用 且 尚无批准
    /// 记录」的用户安装插件补一条批准记录并 `warn` 留痕——用户仍可在插件详情页看到
    /// 完整权限清单。从未启用过的用户插件不在此列，照常走人工审批。
    ///
    /// 不做「权限清单变更时重弹」——本轮不加（裁决 1，留作后续可选项）。
    async fn auto_approve_legacy_user_plugin(&self, plugin_id: &str) {
        use crate::security::approval;

        let (is_user_installed, extension_path, version, requested) = {
            let plugins = self.plugins.read().await;
            match plugins.get(plugin_id) {
                Some(loaded) => (
                    loaded.source == PluginSource::UserInstalled,
                    loaded.extension_path.clone(),
                    loaded.manifest.version.clone(),
                    loaded.manifest.permissions.clone(),
                ),
                // 列表对账已过滤过期 id，此处兜底静默跳过
                None => return,
            }
        };
        if !is_user_installed || extension_path.is_empty() {
            return;
        }

        let store = approval::PluginApprovalStore::new(self.storage.clone());
        match store.get(plugin_id).await {
            // 已有批准记录（含哈希不匹配的失效记录）：交给审批门禁按哈希裁决，不越权补批
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "[PluginHost] 读取审批记录失败，跳过存量用户插件自动批准"
                );
                return;
            }
        }

        let approved = approval::known_permissions(&requested);
        let dir = PathBuf::from(&extension_path);
        let content_hash =
            match tokio::task::spawn_blocking(move || approval::compute_dir_hash(&dir)).await {
                Ok(Ok(hash)) => hash,
                Ok(Err(e)) => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "[PluginHost] 计算插件目录哈希失败，跳过存量用户插件自动批准"
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "[PluginHost] 哈希任务失败，跳过存量用户插件自动批准"
                    );
                    return;
                }
            };

        match store
            .approve(plugin_id, &approved, &content_hash, &version)
            .await
        {
            Ok(()) => tracing::warn!(
                plugin_id = %plugin_id,
                permission_count = approved.len(),
                "[PluginHost] 存量用户安装插件首启自动批准一次（审批门禁上线前的遗留启用状态）"
            ),
            Err(e) => tracing::warn!(
                plugin_id = %plugin_id,
                error = %e,
                "[PluginHost] 存量用户插件自动批准写入失败"
            ),
        }
    }

    /// 根据持久化状态自动激活之前已激活的插件
    pub(crate) async fn auto_activate_from_persisted_state(&self) {
        let activated_map = match self.storage.load_activated_plugins().await {
            Ok(map) => {
                tracing::info!(
                    "[PluginHost] Loaded persisted activation state: {} entry/entries",
                    map.len()
                );
                for (id, active) in &map {
                    tracing::debug!(plugin_id = %id, persist = active, "[PluginHost]   Persisted");
                }
                map
            }
            Err(e) => {
                tracing::warn!(
                    "[PluginHost] Failed to load persisted activation state, skipping auto-activation: {}",
                    e
                );
                return;
            }
        };

        if activated_map.is_empty() {
            tracing::info!("[PluginHost] No persisted activation state, skipping auto-activation");
            return;
        }

        let to_activate: Vec<String> = {
            let plugins = self.plugins.read().await;
            activated_map
                .iter()
                .filter(|(id, &is_active)| {
                    if !is_active {
                        return false;
                    }
                    plugins
                        .get(*id)
                        // L3 批 = 业务应用面（ADR 0032）：角色驱动层（L1/L2）由
                        // `activate_role_driven_components` 按角色激活，其启停不
                        // 持久化（见 `get_activated_state`），故本批不重复激活它们
                        .map(|p| {
                            p.source != PluginSource::StaticRegistry
                                && p.manifest.kind.is_business_app()
                        })
                        .unwrap_or(false)
                })
                .map(|(id, _)| id.clone())
                .collect()
        };

        tracing::info!(
            "[PluginHost] Auto-activating {} plugin(s) from persisted state",
            to_activate.len()
        );

        let mut activated_count = 0usize;
        for plugin_id in &to_activate {
            tracing::info!(plugin_id = %plugin_id, "[PluginHost] Auto-activating plugin");
            // 存量兼容（ADR 0020）：审批门禁上线前就已启用的用户插件，首启补一次自动批准
            self.auto_approve_legacy_user_plugin(plugin_id).await;
            match self.activate_plugin(plugin_id, false).await {
                Ok(()) => activated_count += 1,
                Err(e) => {
                    tracing::error!(plugin_id = %plugin_id, error = %e, "[PluginHost] Failed to auto-activate plugin");
                }
            }
        }

        // 清理已不存在的插件 ID
        let current_ids: HashSet<String> = self.plugins.read().await.keys().cloned().collect();
        let original_len = activated_map.len();
        let mut cleaned_map = activated_map;
        cleaned_map.retain(|id, _| current_ids.contains(id));
        if cleaned_map.len() != original_len {
            tracing::info!(
                "[PluginHost] Cleaning {} stale plugin ID(s) from persisted state",
                original_len - cleaned_map.len()
            );
            if let Err(e) = self.storage.save_activated_plugins(&cleaned_map).await {
                tracing::warn!(
                    "[PluginHost] Failed to clean up stale activation entries: {}",
                    e
                );
            }
        }

        // 最终计数报**实际成功数**（M-18）：尝试数在部分失败时误导诊断
        tracing::info!(
            "[PluginHost] Auto-activated {} plugin(s) from persisted state",
            activated_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::l2_auth_center_unready;
    use crate::manifest::PluginKind;

    /// C-1（正例）：L2 整层激活完但注册表空 → 未就位（fail-closed 全拒，必须点名）
    #[test]
    fn l2_activation_without_registered_center_is_flagged() {
        assert!(l2_auth_center_unready(PluginKind::InternalBusiness, None));
    }

    /// C-2（反例，回归 2026-10-26）：中心已在册即就位——非属主的同级 L2 插件
    /// （monitor）不得再被误判为「认证中心未就位」刷全拒错误。
    #[test]
    fn non_owner_l2_is_not_flagged_when_center_is_registered() {
        assert!(!l2_auth_center_unready(
            PluginKind::InternalBusiness,
            Some("com.wasmnest.auth-center")
        ));
        // 中心属主为自身的边界同样不得误报
        assert!(!l2_auth_center_unready(
            PluginKind::InternalBusiness,
            Some("com.wasmnest.bedcode")
        ));
    }

    /// C-3（反例）：L1 / L3 永不参与该判据——L1 无认证中心语义，L3 未注册是正常态
    #[test]
    fn non_l2_kinds_are_never_flagged() {
        for kind in [PluginKind::BasicService, PluginKind::BusinessApp] {
            assert!(
                !l2_auth_center_unready(kind, None),
                "{} 不得被判为认证中心未就位",
                kind.label()
            );
            assert!(!l2_auth_center_unready(
                kind,
                Some("com.wasmnest.auth-center")
            ));
        }
    }
}
