//! `activation` — PluginHost 职责面拆分（P2）
//!
//! 自 `host.rs` 主 impl 拆出；经 `use super::*` 继承 host 模块的
//! 全部导入与常量，方法与字段可见性规则与内联时一致。

use super::*;
impl PluginHost {
    /// 检查插件是否处于激活状态（用于 API 调用的调用者身份校验）
    pub async fn is_activated(&self, plugin_id: &str) -> bool {
        let plugins = self.plugins.read().await;
        let result = plugins
            .get(plugin_id)
            .map(|p| matches!(p.state, PluginState::Activated))
            .unwrap_or(false);
        // 高频校验路径（每插件 API 调用都会经过），仅 trace 级别可见，避免刷屏
        tracing::trace!(plugin_id = %plugin_id, activated = result, "[PluginHost] is_activated");
        result
    }

    /// 插件实例是否在运行（`Activated` / `Degraded`）
    ///
    /// 与 [`Self::is_activated`] 的区别：Degraded 的实例是活的（前端模块会加载、扩展点已注册），
    /// 只是启动初始化未完成。前端通道令牌的签发条件是「运行中」而非严格 Activated
    /// （审计票 06；功能门禁仍严格 Activated）。
    pub async fn is_running(&self, plugin_id: &str) -> bool {
        let plugins = self.plugins.read().await;
        plugins
            .get(plugin_id)
            .map(|p| matches!(p.state, PluginState::Activated | PluginState::Degraded { .. }))
            .unwrap_or(false)
    }

    /// 停用所有已激活的插件（应用关闭流程）
    pub async fn deactivate_all(&self) -> crate::Result<()> {
        // 置关闭标志：deactivate 内的卸载动作（CLI 清理等）跳过，
        // 保留随包产物供下次启动重新激活（幂等安装）
        self.shutting_down.store(true, std::sync::atomic::Ordering::SeqCst);

        let plugin_ids: Vec<String> = {
            let plugins = self.plugins.read().await;
            // Degraded 也是活实例（前端模块已加载、扩展点已注册、持久化态按启用计，
            // 见 `get_activated_state`）→ 退出时必须同样收到 `on_shutdown`；
            // 此前只收 Activated，Degraded 插件在应用关闭时被静默跳过（审计票 09）。
            plugins
                .values()
                .filter(|p| matches!(p.state, PluginState::Activated | PluginState::Degraded { .. }))
                .map(|p| p.manifest.id.clone())
                .collect()
        };

        for id in plugin_ids {
            if let Err(e) = self.deactivate_plugin(&id, false).await {
                tracing::error!(plugin_id = %id, error = %e, "Failed to deactivate plugin during shutdown");
            }
        }

        // 残留属主清扫（I6）：Error 态 / 未走 deactivate 的实例不得留孤儿属主任务
        // （属主任务持着 Store，进程退出前必须收敛；已在 deactivate 中停过的是幂等 no-op）
        self.shutdown_all_owners().await;

        tracing::info!("PluginHost deactivate_all completed");
        Ok(())
    }

    /// 激活插件
    ///
    /// 预授权(启用前置):收集插件需授权路径 → 调 `fs_auth::check_batch`
    /// 单次合并弹窗。失败直接 `mark_error` + 返回 `AppError::Plugin`,
    /// 不进入 `Activating` 中间态。**必须在 `activate_plugin` 阶段1 入口
    /// (置 Activating 之前)调用,持有 plugins 锁时禁止调用**(check_batch
    /// 会发事件、可能回调宿主,持锁会死锁)。
    ///
    /// 路径来源:已注册的 `PreauthProvider` 优先;否则从 `PluginStorage`
    /// `preauth_paths` 数组读(file-transfer mount-local 同步写入);
    /// 另并入 manifest `wasiPreopenDirs` 展开后的声明目录(如 ai-chatbox
    /// 数据目录)——插件 activate 内 fs_request_auth 的弹窗晚于前端 loading
    /// 遮罩,声明目录必须提前到本阶段统一弹窗。
    /// 路径为空 → 直接放行(启用先行:file-transfer 首次启用/全部目录移除后
    /// 均可空目录激活,共享目录配置由插件设置面板引导;硬拒绝会造成
    /// 「配置需激活 → 激活需先配置」死锁)。

    /// - 静态注册插件：仅标记状态
    /// - WASM 插件：调用 __wasmnest_activate 导出函数
    /// - TS-only 插件：前端模块加载在 PluginLoader 中完成
    pub async fn activate_plugin(&self, plugin_id: &str, persist: bool) -> crate::Result<()> {
        // 外壳（审计票 12）：激活**失败**时按属主回收 peer-net 节点。
        // 节点生命周期已改由插件自己经 `host-peer.start-node` 请求，内核不再认得
        // 任何产品 id；这里只剩一条与产品无关的补偿——插件可能在 activate() 里已经
        // 把节点带起来、随后才失败，若不回收就会出现「插件未激活、本机仍在
        // `_wasmnest-peer` 广播」。旧实现靠「外壳只在成功时才起节点」天然没有这个
        // 窗口，改成插件自起之后，补偿必须显式存在。属主不匹配即 no-op，
        // 所以任何插件都能安全走这一条
        let result = self.activate_plugin_inner(plugin_id, persist).await;
        if result.is_err() {
            self.release_peer_node_if_owned(plugin_id, "activation failed").await;
        }
        result
    }

    /// 按属主释放 peer-net 节点（审计票 12）：该插件起着节点就停掉，没起过是 no-op
    ///
    /// 无 app_handle 或未注入 `PeerCtxProvider` 端口的无头上下文（测试）直接跳过。
    /// 停用与激活失败两条生命周期路径共用它，替代旧的两个
    /// `plugin_id == FILE_TRANSFER_PLUGIN_ID` 硬编码分支
    async fn release_peer_node_if_owned(&self, plugin_id: &str, reason: &str) {
        let Some(app) = self.wasm_host_ctx.app_handle() else {
            return;
        };
        let Some(provider) = self.wasm_host_ctx.peer_ctx_provider() else {
            return;
        };
        let ctx = provider(&app);
        match wasmnest_server_peer_net::release_node_for(ctx, plugin_id).await {
            Ok(true) => {
                tracing::info!(
                    plugin_id = %plugin_id,
                    reason = %reason,
                    "peer-net node released: its owning plugin stopped running"
                );
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %error,
                    reason = %reason,
                    "peer-net node release on plugin lifecycle failed"
                );
            }
        }
    }

    /// 审批门禁（ADR 0020 / 审计票 03）：返回用户安装插件的生效权限集
    ///
    /// - `Ok(None)`：来源免审批（静态注册 / 随包扫描 / 内置 WASM）→ 宿主按 manifest 全量授权；
    /// - `Ok(Some(effective))`：用户 zip 安装且批准有效 → 生效权限 = 批准 ∩ 请求；
    /// - `Err`：无批准记录（Pending）或批准后目录内容变化（HashMismatch）→ 置
    ///   `NeedsApproval` + 拒绝激活（**禁止**静默降级为「部分权限」——用户必须先看见
    ///   「这个插件要哪些权限」再决定）。
    ///
    /// 必须在持有 `plugins` 锁之外调用：目录哈希是阻塞 IO（走 `spawn_blocking`），
    /// 且失败路径要回写插件状态。
    async fn approval_gate(&self, plugin_id: &str) -> crate::Result<Option<HashSet<String>>> {
        use crate::security::approval::{self, ApprovalStatus};

        let (source, extension_path, requested) = {
            let plugins = self.plugins.read().await;
            match plugins.get(plugin_id) {
                Some(loaded) => (
                    loaded.source.clone(),
                    loaded.extension_path.clone(),
                    loaded.manifest.permissions.clone(),
                ),
                None => return Err(crate::AppError::Plugin(format!("Plugin not found: {}", plugin_id))),
            }
        };
        // 信任分档（裁决 2）：随包内置插件属应用构建信任域，本门禁只作用 UserInstalled
        if source != PluginSource::UserInstalled {
            return Ok(None);
        }

        let approvals = approval::PluginApprovalStore::new(self.storage.clone());
        let record = approvals.get(plugin_id).await?;
        // 目录哈希不进 async 事件循环
        let dir = PathBuf::from(&extension_path);
        let record_for_hash = record.clone();
        let (status, _current_hash) =
            tokio::task::spawn_blocking(move || approval::verify_approval(record_for_hash.as_ref(), &dir))
                .await
                .map_err(|e| crate::AppError::Plugin(format!("Approval verify task failed: {}", e)))??;

        match status {
            ApprovalStatus::Approved => Ok(Some(approval::effective_permissions(
                &requested,
                record.as_ref(),
                false,
            ))),
            ApprovalStatus::Pending | ApprovalStatus::HashMismatch => {
                let mismatch = status == ApprovalStatus::HashMismatch;
                if mismatch {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        "[PluginHost] 插件目录内容与批准时不一致，撤销批准并要求重新审批"
                    );
                    // 撤销失败不阻断本次拒绝（插件仍无法激活），但必须留痕
                    if let Err(e) = approvals.revoke(plugin_id).await {
                        tracing::error!(
                            plugin_id = %plugin_id,
                            error = %e,
                            "[PluginHost] 撤销失效批准失败（本次拒绝激活不受影响）"
                        );
                    }
                }
                {
                    let mut plugins = self.plugins.write().await;
                    if let Some(loaded) = plugins.get_mut(plugin_id) {
                        loaded.state = PluginState::NeedsApproval;
                    }
                }
                tracing::warn!(
                    plugin_id = %plugin_id,
                    hash_mismatch = mismatch,
                    "[PluginHost] 激活被审批门禁拒绝"
                );
                Err(crate::AppError::Plugin(format!(
                    "Plugin '{}' requires user approval before activation (or its files changed since approval)",
                    plugin_id
                )))
            }
        }
    }

    pub(crate) async fn activate_plugin_inner(&self, plugin_id: &str, persist: bool) -> crate::Result<()> {
        tracing::info!(plugin_id = %plugin_id, persist, "[PluginHost] activate_plugin");

        // 阶段 0.0（无锁）：审批门禁（ADR 0020）——用户 zip 安装的插件必须先获人工批准，
        // 且批准与目录内容哈希绑定。排在预授权之前：未获批准的插件不该先弹文件系统授权窗
        let approval_effective = self.approval_gate(plugin_id).await?;

        // 阶段 0(无锁):预授权 — 必须在持 plugins 锁之前完成,失败直接
        // 返回 Err,前端 catch 后回退 toggle。loading 遮罩由前端 toggle
        // 推迟到此调用之后才显示,确保授权弹窗与 loading 不会同时出现
        self.preauthorize_plugin(plugin_id).await?;

        // 阶段 1（短写锁）：读取状态与 manifest 字段、重新授权后立即释放锁。
        // 禁止持 plugins 锁执行 WASM activate：activate 内可能回调宿主
        // （如 scheduler 的 cli_install 经 services.install_cli 读 plugins map），
        // 持写锁回调会死锁（锁约定见 PluginManager::activate，双侧一致）
        struct ActivatePlan {
            source: PluginSource,
            api: Vec<String>,
            subscribes: Vec<String>,
            declared_preopen_dirs: Vec<crate::manifest::WasiPreopenDir>,
            kind: crate::manifest::PluginKind,
            dependencies: Vec<String>,
            /// 票 09a：manifest `contributes.wsEndpoints`——在激活成功阶段登记进宿主
            /// WS 端点注册表（声明驱动的静态路由，expand 阶段与旧硬编码分发并存）
            ws_endpoints: Vec<crate::manifest::WsEndpointContribution>,
        }
        let plan = {
            let mut plugins = self.plugins.write().await;

            // 插件名唯一性（用户裁定 ⑨：激活为最终闸门）：路由注册表按 plugin_id
            // 分组（命名空间隔离），同名插件共存会破坏「插件名唯一 → 路由命名空间
            // 不冲突」的硬约束。plugins map 以 id 为键，正常情形不存在第二条同名
            // 记录（扫描面先到先得 / 安装面同 id 拒绝已有基础）；本校验是显式闸门——
            // 若因竞态/异常插入出现了「另一条记录声明同一 manifest.id」（键不一致
            // 的插入），激活必须失败（fail-visible），不得静默共存或覆盖。
            if let Some(other_key) = find_duplicate_id_claim(&plugins, plugin_id) {
                let msg = format!(
                    "Plugin id '{}' is already claimed by another plugin record (map key '{}'); \
                     duplicate plugin id rejected at activation (route namespace isolation)",
                    plugin_id, other_key
                );
                tracing::error!(
                    plugin_id = %plugin_id,
                    conflicting_key = %other_key,
                    "[PluginHost] 同名插件拒绝激活（命名空间隔离）"
                );
                return Err(crate::AppError::Plugin(msg));
            }

            let loaded = plugins.get_mut(plugin_id).ok_or_else(|| {
                tracing::error!(plugin_id = %plugin_id, "[PluginHost] activate_plugin: plugin not found in plugins map");
                crate::AppError::Plugin(format!("Plugin not found: {}", plugin_id))
            })?;

            match &loaded.state {
                PluginState::Activated => {
                    tracing::debug!(plugin_id = %plugin_id, "[PluginHost] Plugin already activated, skipping");
                    return Ok(());
                }
                // 并发双激活去重（审计票 09）：实例锁只保证串行、不保证去重，落进 `_`
                // 分支会让第二次调用再跑一次 guest `activate()`（现仅靠 SDK OnceLock 兜底）。
                // 此处幂等返回 Ok——返回 Ok 只表示「已在激活中」，终态以状态机为准；
                // 「等待在途激活完成」需要跨调用同步原语与额外死锁面，本轮不引入。
                PluginState::Activating => {
                    tracing::debug!(
                        plugin_id = %plugin_id,
                        "[PluginHost] Plugin already activating, duplicate activation ignored"
                    );
                    return Ok(());
                }
                PluginState::Error { error: e } => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "[PluginHost] Plugin in error state, attempting re-activation"
                    );
                }
                // Degraded 重试激活：启动初始化上次失败，本次重新走完整流程
                PluginState::Degraded { error: e } => {
                    tracing::info!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "[PluginHost] Plugin in degraded state, attempting re-activation"
                    );
                }
                _ => {
                    tracing::debug!(
                        plugin_id = %plugin_id,
                        state = ?loaded.state,
                        "[PluginHost] Plugin current state, proceeding with activation"
                    );
                }
            }

            // 重新授权：deactivate 会 revoke_all，再次激活时必须重新授予
            //
            // 只授「生效权限」：用户安装插件是 批准 ∩ 请求（approval_gate），内置来源是
            // manifest 全量。多授一位就等于审批门禁被绕过——PermissionManager 是宿主机能门
            // 的运行时真源（guest 内嵌权限集只作上限，见 wasm 实例化注释）。
            let permissions = match &approval_effective {
                Some(effective) => effective.iter().cloned().collect::<Vec<String>>(),
                None => loaded.manifest.permissions.clone(),
            };
            let granted = self.permission.grant_permissions(plugin_id, &permissions);
            // 词汇表外的声明会在授权时被过滤（= 没声明）。票 01 已把生产 manifest 的
            // 装饰词汇清零、票 02 又取消了 storage 的默认授予，因此「声明了却没生效」
            // 必须可见——否则第三方插件作者只能靠运行时 permission denied 反推。
            let dropped: Vec<&String> = loaded
                .manifest
                .permissions
                .iter()
                .filter(|p| !granted.contains(p.as_str()))
                .collect();
            if !dropped.is_empty() {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    dropped = ?dropped,
                    "manifest 声明的权限不在 SDK 词汇表内，授权时被过滤"
                );
            }
            // 授权结果留在 PermissionManager 才是权限判定的唯一入口；此处不再写
            // LoadedPlugin 镜像字段（票 11 第 4 项）

            // 置中间态后再释放锁执行 WASM activate：列表查询在激活期间
            // 可见 Activating（瞬时态，终态由下方 phase 2/3 写入）
            loaded.state = PluginState::Activating;

            ActivatePlan {
                source: loaded.source.clone(),
                api: loaded.manifest.api.clone(),
                subscribes: loaded.manifest.contributes.subscribes.clone(),
                declared_preopen_dirs: loaded.manifest.wasi_preopen_dirs.clone(),
                kind: loaded.manifest.kind,
                dependencies: loaded.manifest.dependencies.clone(),
                ws_endpoints: loaded.manifest.contributes.ws_endpoints.clone(),
            }
        };

        // 阶段 1.5（无锁）：能力依赖装配检查（core-plugin-manager）——manifest
        // `dependencies` 声明的每个能力必须已有提供者（宿主原语或已激活的
        // 系统组件实例）；缺失即激活失败并指明能力名。系统组件先于应用插件
        // 激活（见 PluginHost::new 的 activate_system_components），故此处的
        // 注册表快照对应用插件而言已含全部系统组件提供者。
        if !plan.dependencies.is_empty() {
            let missing = self.wasm_host_ctx.capabilities().missing(&plan.dependencies);
            if !missing.is_empty() {
                let msg = format!(
                    "plugin dependencies not satisfied, missing capabilities: {}",
                    missing.join(", ")
                );
                tracing::error!(
                    plugin_id = %plugin_id,
                    missing = ?missing,
                    "[PluginHost] 能力依赖未装配，激活失败"
                );
                self.mark_error(plugin_id, msg.clone()).await;
                return Err(crate::AppError::Plugin(format!(
                    "Plugin {} activation failed: {}",
                    plugin_id, msg
                )));
            }
        }

        // 阶段 2（无 map 锁）：执行 WASM activate + on_startup
        // 仅持单插件实例锁（避免重入死锁），失败置 Error 状态
        // on_startup 的 guest 自报失败记录于此，phase 3 据此写 Degraded 终态
        let mut startup_failure: Option<String> = None;
        if plan.source == PluginSource::Wasm {
            // 实例就绪性 + WASI 预打开目录漂移检测（合并为一次判定，避免连续重建）：
            // ① `event-loop` 实例在上次停用后属主已停（store 已丢）⇒ 必须重建才能
            //    再入（停用即丢 store 是 I3③ 的语义）；
            // ② 声明了预打开目录且当前实例未覆盖「现在已授权」的目录 ⇒ 重建。
            //    首次启用时授权经 activate() 内 fs_request_auth 弹窗才落库（早于
            //    实例化），实例预打开为空；重试激活（停用再启用）时授权已持久化，
            //    若实例未覆盖则重建——否则 /data 永远挂不上，激活自检必失败
            //    （Bug B 死循环）。未声明目录的 `mutex` 实例跳过（零开销）。
            //    **仅 worker 类别可达**（ADR 0034）：非 worker 声明 preopen 在加载期
            //    被显性拒绝，主 wasm-app 数据目录走 host-fs + fs_request_auth，
            //    无实例漂移——本分支是 worker 预留能力的重建前置。
            let rebuild_reason: Option<String> = {
                let entry = self.get_instance(plugin_id).await;
                match &entry {
                    Some(entry) if entry.owner_stopped() => {
                        Some("instance owner stopped (previous deactivation dropped the store)".to_string())
                    }
                    Some(entry) if !plan.declared_preopen_dirs.is_empty() => {
                        let resolved = crate::manager::runtime::resolve_preopen_dirs(
                            &self.wasm_host_ctx,
                            plugin_id,
                            &plan.declared_preopen_dirs,
                        );
                        // 只比路径不比挂载档：档位由 manifest 决定，而 manifest 变更
                        // （重装 / dev-reload）必然走 load_plugin_from_file 重新实例化，
                        // 不存在「路径相同档位陈旧」的实例存活窗口
                        let preopened = entry.meta().preopened_dirs.clone();
                        (!resolved.iter().all(|d| preopened.iter().any(|p| p == d.path()))).then(|| {
                            format!(
                                "preopen dirs changed after instance creation (declared {:?}, resolved {:?})",
                                plan.declared_preopen_dirs, resolved
                            )
                        })
                    }
                    // 实例缺失：走重建路径补建（与 reload 语义一致）
                    None if !plan.declared_preopen_dirs.is_empty() => Some("no wasm instance".to_string()),
                    _ => None,
                }
            };
            if let Some(reason) = rebuild_reason {
                tracing::info!(
                    plugin_id = %plugin_id,
                    reason = %reason,
                    "Rebuilding WASM instance before activation"
                );
                self.rebuild_wasm_instance(plugin_id).await?;
            }

            if self.get_instance(plugin_id).await.is_none() {
                tracing::error!(plugin_id = %plugin_id, "WASM plugin not found in wasm_plugins map");
                // phase 1 已置 Activating 中间态：失败路径必须落终态，不留悬挂
                self.mark_error(plugin_id, "WASM module not loaded".to_string()).await;
                return Err(crate::AppError::Plugin(format!(
                    "Plugin {} WASM module not loaded",
                    plugin_id
                )));
            }

            match self.call_guest(plugin_id, GuestOp::Activate).await {
                Ok(GuestReply::Code(0)) => {
                    tracing::info!(plugin_id = %plugin_id, "[PluginHost] Plugin activated");
                }
                Ok(GuestReply::Code(code)) => {
                    tracing::error!(
                        plugin_id = %plugin_id,
                        code = %code,
                        "[PluginHost] Plugin activate() returned error code"
                    );
                    self.mark_error(plugin_id, format!("activate() returned error code {}", code))
                        .await;
                    return Err(crate::AppError::Plugin(format!(
                        "Plugin {} activate() returned error code {}",
                        plugin_id, code
                    )));
                }
                Ok(other) => {
                    let msg = format!("activate() returned unexpected guest reply: {:?}", other);
                    tracing::error!(plugin_id = %plugin_id, reply = ?other, "[PluginHost] Plugin activate() reply unexpected");
                    self.mark_error(plugin_id, msg.clone()).await;
                    return Err(crate::AppError::Plugin(format!("Plugin {} {}", plugin_id, msg)));
                }
                Err(failure) => match failure.panic_message {
                    // panic：与改造前同文案分支（Store 已污染，恢复依赖 trap 自动重载）
                    Some(msg) => {
                        self.mark_error(plugin_id, format!("activate() panicked: {}", msg))
                            .await;
                        return Err(crate::AppError::Plugin(format!(
                            "Plugin {} activate() panicked: {}",
                            plugin_id, msg
                        )));
                    }
                    None => {
                        tracing::error!(plugin_id = %plugin_id, error = %failure.error, "[PluginHost] Plugin activate() failed");
                        self.mark_error(plugin_id, format!("activate() failed: {}", failure.error))
                            .await;
                        return Err(crate::AppError::Plugin(format!(
                            "Plugin {} activate() failed: {}",
                            plugin_id, failure.error
                        )));
                    }
                },
            }

            // 激活成功后自动调用 on_startup（启动初始化；结果决定 Activated / Degraded）
            // v8 契约：guest 自报失败不再静默吞掉——Degraded 终态如实反映
            // 「实例可用、扩展点已注册，但启动初始化未完成」
            tracing::info!(plugin_id = %plugin_id, "[PluginHost] Calling on_startup");
            match self.call_guest(plugin_id, GuestOp::OnStartup).await {
                Ok(GuestReply::Lifecycle(Ok(()))) => {
                    tracing::info!(plugin_id = %plugin_id, "[PluginHost] Plugin on_startup completed");
                }
                Ok(GuestReply::Lifecycle(Err(e))) => {
                    tracing::error!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "[PluginHost] Plugin on_startup reported failure"
                    );
                    startup_failure = Some(e);
                }
                Ok(other) => {
                    let msg = format!("on_startup returned unexpected guest reply: {:?}", other);
                    tracing::error!(plugin_id = %plugin_id, reply = ?other, "[PluginHost] Plugin on_startup reply unexpected");
                    startup_failure = Some(msg);
                }
                Err(failure) => match failure.panic_message {
                    Some(msg) => {
                        tracing::error!(
                            plugin_id = %plugin_id,
                            error = %msg,
                            "[PluginHost] Plugin on_startup panicked"
                        );
                        // panic 已污染 Store，后续调用必然失败：按故障态处理（区别于可用的
                        // 降级），恢复依赖既有 trap 自动重载机制
                        self.mark_error(plugin_id, format!("on_startup panicked: {}", msg))
                            .await;
                        return Err(crate::AppError::Plugin(format!(
                            "Plugin {} on_startup panicked: {}",
                            plugin_id, msg
                        )));
                    }
                    None => {
                        // 调用层错误（非 trap）：导出不可达 / 燃料异常等，启动初始化同样未完成
                        tracing::error!(
                            plugin_id = %plugin_id,
                            error = %failure.error,
                            "[PluginHost] Plugin on_startup call failed"
                        );
                        startup_failure = Some(failure.error.to_string());
                    }
                },
            }
        }

        // 阶段 3（短写锁）：写入终态（Activated 或 Degraded），然后释放锁执行订阅登记。
        // Degraded 同样完成订阅/api 登记：WASM 实例本身是活的，
        // 与「启动初始化部分失败」正交
        {
            let mut plugins = self.plugins.write().await;
            if let Some(loaded) = plugins.get_mut(plugin_id) {
                loaded.state = match &startup_failure {
                    Some(reason) => PluginState::Degraded { error: reason.clone() },
                    None => PluginState::Activated,
                };
                loaded.activated_at = Some(Utc::now());
            }
        }
        // core-monitor：启动初始化部分失败（Degraded 终态）埋点
        if startup_failure.is_some() {
            self.wasm_runtime
                .monitor()
                .plugin(plugin_id)
                .record_lifecycle(crate::monitor::LifecycleEvent::Degraded);
        }

        // 登记互调 api 清单（ADR-0017）：激活后 `wasmnest.api.*` 请求可路由到本插件。
        // 未声明 api 的插件登记空清单，幂等无操作。
        // 票 07 B2：改名插件额外登记旧 api 名（双投窗口）——仍指向本插件，
        // 未更新的旧调用方按旧名互调时照常可达
        let api_list = with_api_aliases(plugin_id, &plan.api);
        self.wasm_host_ctx
            .api_registry()
            .register(plugin_id, &api_list)
            .map_err(|e| {
                // fail-closed（S-01）：api 名被其它激活插件占用时激活显性失败，
                // 避免被拒后插件仍在运行但其 api 静默不可达（fail-visible）
                crate::AppError::Plugin(format!("插件 '{}' 登记互调 api 失败: {}", plugin_id, e))
            })?;

        // 票 09a：manifest 声明的 WS 端点登记（expand——声明式静态路由与宿主硬编码
        // 分发并存）。这里的登记必须以「激活期」为锚点：deactivate 会 `purge_for_plugin`
        // 回收该插件全部 ws 端点，只有激活期重登记才能让 deactivate→activate 循环后
        // 声明端点不丢（与 httpEndpoints 的 load 期登记不同——ws 端点生命周期随激活）。
        // 插件未导出 `events-ws` 的端点帧投递会降级为丢弃（宿主不缓存，spec §2.2），
        // 声明了但没接事件的插件即时看到的形态是可连但无回包——fail-visible 需按插件端
        // 是否实现回调判定，宿主只负责「按声明登记、按声明可达」。
        if !plan.ws_endpoints.is_empty() {
            self.register_declared_ws_endpoints(plugin_id, &plan.ws_endpoints).await;
        }

        // L1 基础服务激活后装配能力注册表——实例化时探测到的可路由能力导出
        // （host-* 同形接口）注册为该组件的提供者，应用插件的对应 import
        // 自此经 Linker 路由转发到本组件实例（host-side 转发）
        if plan.kind.provides_host_capabilities() {
            self.register_system_capabilities(plugin_id).await;
        }

        // 注册 manifest 中声明的 topic 订阅
        if !plan.subscribes.is_empty() {
            let plugin_id_owned = plugin_id.to_string();
            for topic in &plan.subscribes {
                self.message_bus.subscribe_wasm(&plugin_id_owned, topic).await;
            }
            tracing::info!(
                plugin_id = %plugin_id_owned,
                topic_count = plan.subscribes.len(),
                "[PluginHost] Plugin subscribed to topic(s): {:?}",
                plan.subscribes
            );
        }

        // 终态日志：成功与降级分别如实呈现（汇总日志在 PluginHost::new 尾部）
        match &startup_failure {
            Some(reason) => tracing::info!(
                plugin_id = %plugin_id,
                persist,
                "[PluginHost] Plugin activated with degradation: {}",
                reason
            ),
            None => {
                tracing::info!(plugin_id = %plugin_id, persist, "[PluginHost] Plugin activated successfully");
            }
        }

        if persist {
            tracing::debug!(plugin_id = %plugin_id, "[PluginHost] Persisting activation state after activating");
            self.persist_activation_state().await;
        }

        Ok(())
    }

    ///
    /// 注册系统组件的能力提供者（core-plugin-manager）
    ///
    /// 读取实例化时探测到的可路由能力导出，逐项注册进能力注册表；
    /// 导出缺失/不可路由的能力跳过并告警（不阻断激活——组件仍可提供
    /// 其余能力，缺失能力由依赖检查在消费方激活时报错）。
    pub(crate) async fn register_system_capabilities(&self, plugin_id: &str) {
        let entry = self.get_instance(plugin_id).await;
        let Some(entry) = entry else {
            tracing::warn!(
                plugin_id = %plugin_id,
                "[PluginHost] 系统组件无 WASM 实例，跳过能力注册（非 WASM 来源？）"
            );
            return;
        };
        // 元数据外提（I1）：能力探测结果在实例元数据里，不锁实例
        let exported = entry.meta().exported_capabilities.clone();
        if exported.is_empty() {
            tracing::warn!(
                plugin_id = %plugin_id,
                "[PluginHost] 系统组件未导出任何可路由能力接口（manifest type=system 但无能力导出）"
            );
        }
        // 提供者句柄 = 装配条目（经窄端口 `CapabilityTarget` 转发，两种调用模型同构）
        let target: Arc<dyn crate::host_api::context::CapabilityTarget> = entry;
        for capability in exported {
            if let Err(e) =
                self.wasm_host_ctx
                    .capabilities()
                    .register_system_component(&capability, plugin_id, target.clone())
            {
                tracing::error!(
                    plugin_id = %plugin_id,
                    capability = %capability,
                    error = %e,
                    "[PluginHost] 系统组件能力注册失败"
                );
            }
        }
    }

    pub(crate) fn abort_plugin_timer(&self, plugin_id: &str) {
        let mut timers = self.plugin_timers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(handle) = timers.remove(plugin_id) {
            handle.abort();
            tracing::info!(plugin_id = %plugin_id, "[PluginHost] Timer aborted");
        }
    }

    pub async fn deactivate_plugin(&self, plugin_id: &str, persist: bool) -> crate::Result<()> {
        // 外壳（审计票 12）：停用**成功**后按属主回收 peer-net 节点（对端即时感知
        // 下线；该插件没起过节点则 no-op，幂等）。插件自己也会经
        // `host-peer.stop-node` 关停，这一层是它没能关停（忘了调 / deactivate 里
        // 提前返回）时的兜底——按属主判断，不认产品 id
        let result = self.deactivate_plugin_inner(plugin_id, persist).await;
        if result.is_ok() {
            self.release_peer_node_if_owned(plugin_id, "plugin deactivated").await;
        }
        result
    }

    pub(crate) async fn deactivate_plugin_inner(&self, plugin_id: &str, persist: bool) -> crate::Result<()> {
        tracing::info!(plugin_id = %plugin_id, persist, "[PluginHost] deactivate_plugin");

        // 步骤 ①（票 06 §5.6 / I3③）：先停属主 + 丢 store，再做资源回收。
        // `event-loop` 实例的属主是先于任何宿主资源回收被停止的唯一在飞 guest
        // 执行者——不这样做，回收（pty/ws/http/mdns/task）会与挂起的 guest task
        // 竞争。代价：guest `on_shutdown` / `deactivate` 无法执行（见下方针数），
        // 这是与改造前**唯一的实质语义差异**（spec I3③ 已定稿：宁可显性跳过，
        // 也不赌一个挂起 task 永不放行）。`mutex` 实例无属主，此处 no-op。
        if let Some(report) = self.stop_instance_owner(plugin_id).await {
            if report.forced_abort || report.abandoned_requests > 0 {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    abandoned_requests = report.abandoned_requests,
                    forced_abort = report.forced_abort,
                    "plugin instance owner stopped on deactivate with unresolved requests"
                );
            }
        }

        // mDNS 基础能力服务（spec v2 §5.1）：插件停用即回收其全部浏览 + 广播句柄
        // （只碰本人）。**票 02 批次 03 起走自报钩子**（见下方
        // `DomainHooksRegistry::on_plugin_purge`；域侧钩子在
        // `wasmnest-discovery-engine::HOOKS`）——adapter 迁出内核后内核不再点名该域。

        // 认证中心注册表（ADR 0031）：属主停用即回收其认证中心角色——认证面随之
        // fail-closed（无中心 = 拒绝），不静默降级成“无认证放行”（只碰本人）
        crate::host_api::auth_center::purge_for_plugin(plugin_id);

        // 非核心能力域的停用回收（票 02 批次 01 机制）：遍历**自报**的生命周期钩子。
        // 内核不点名任何能力域 crate——这是内核能摘掉对应依赖的前提。
        //
        // 已接入的域（批次 02/03）：pty（kill 全部私有 PTY 并逐条补发
        // `<owner>::pty:exit`，reason=killed——本遍历必须在下方 `remove_all_subscriptions`
        // 之前，否则补发的事件无人可投）、mdns（浏览 / 广播句柄）、ws（出站连接 +
        // 服务端端点 + 在线客户端）、http（动态路由含对外 URL 别名——别名随属主消失，
        // 未激活插件的 host 别名不再可达 404，fail-visible，不静默占用对外 URL 空间）。
        //
        // 尚未自报的域（auth_center / task）仍走各自直接调用，随各自批次迁到钩子后
        // 两类入口合一。
        wasmnest_host_kit::DomainHooksRegistry::collected().on_plugin_purge(plugin_id);

        // 并发任务域（ABI v20）：插件停用即 cancel 其全部在册任务 + 清回调队列
        // （只碰本人；运行中单元协作式跑完或超时，未开始单元 skipped）
        crate::manager::task::purge_for_plugin(plugin_id);

        // WASM 插件：调用 on_shutdown + __wasmnest_deactivate
        //
        // 步骤 ① 已停属主：`event-loop` 实例的 store 已丢，guest 清理**无法执行**
        // ——按 spec I3③ 显性告警 + 计数（fail-visible），不静默跳过；`mutex`
        // 实例仍走原路径（行为与改造前逐字一致）。
        let wasm_source = {
            let plugins = self.plugins.read().await;
            plugins.get(plugin_id).map(|p| p.source.clone())
        };
        if wasm_source == Some(PluginSource::Wasm) {
            match self.get_instance(plugin_id).await {
                Some(entry) if entry.call_model() == CallModel::EventLoop => {
                    let skipped_total = self.owner_cleanup_skipped.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        skipped = "on_shutdown+deactivate",
                        skipped_total = skipped_total,
                        "guest cleanup skipped: instance owner already stopped (store dropped per I3③)"
                    );
                }
                Some(_) => {
                    tracing::info!(plugin_id = %plugin_id, "[PluginHost] Calling on_shutdown");
                    // v8 契约：guest 自报的清理失败单独记录，不与调用故障混淆；
                    // 停用流程继续，不影响状态机
                    match self.call_guest(plugin_id, GuestOp::OnShutdown).await {
                        Ok(GuestReply::Lifecycle(Ok(()))) => {
                            tracing::info!(plugin_id = %plugin_id, "[PluginHost] Plugin on_shutdown completed");
                        }
                        Ok(GuestReply::Lifecycle(Err(e))) => {
                            tracing::warn!(
                                plugin_id = %plugin_id,
                                error = %e,
                                "[PluginHost] Plugin on_shutdown reported failure"
                            );
                        }
                        Ok(other) => {
                            tracing::warn!(
                                plugin_id = %plugin_id,
                                reply = ?other,
                                "[PluginHost] Plugin on_shutdown returned unexpected guest reply"
                            );
                        }
                        Err(failure) => {
                            tracing::warn!(
                                plugin_id = %plugin_id,
                                error = %failure.error,
                                "[PluginHost] Plugin on_shutdown call failed"
                            );
                        }
                    }

                    match self.call_guest(plugin_id, GuestOp::Deactivate).await {
                        Ok(GuestReply::Code(0)) => {
                            tracing::info!(plugin_id = %plugin_id, "[PluginHost] Plugin deactivated");
                        }
                        Ok(GuestReply::Code(code)) => {
                            tracing::warn!(
                                plugin_id = %plugin_id,
                                code = %code,
                                "[PluginHost] Plugin deactivate() returned error code"
                            );
                        }
                        Ok(other) => {
                            tracing::warn!(
                                plugin_id = %plugin_id,
                                reply = ?other,
                                "[PluginHost] Plugin deactivate() returned unexpected guest reply"
                            );
                        }
                        Err(failure) => {
                            tracing::error!(plugin_id = %plugin_id, error = %failure.error, "[PluginHost] Plugin deactivate() failed");
                        }
                    }
                }
                // 实例缺失（纯前端插件 / 加载失败）：无可调用，静默跳过（与改造前一致）
                None => {}
            }
        }

        // 二次清扫（审计票 09）：`task::purge_for_plugin` 在本函数早段执行，早于 guest
        // `on_shutdown` / `deactivate`，在飞单元可能在 purge 之后才跑完并补投终态事件。
        // guest 清理结束后再收一次（幂等：已终态任务 cancel 返回 false、注册表条目与
        // 回调队列已摘除），补上这个次序小窗。
        crate::manager::task::purge_for_plugin(plugin_id);

        // 统一清理：取消注册和撤销权限
        self.registry.unregister_plugin(plugin_id).await;
        self.permission.revoke_all(plugin_id);
        // 前端通道令牌随停用回收（审计票 06）：令牌是「该插件当前这次激活」的凭证，
        // 停用后旧令牌不得继续解析出身份（下次激活由 loader 重新签发）
        self.frontend_channel().revoke_plugin(plugin_id);
        // 注销互调 api 清单（ADR-0017）：停用后目标调用被门禁拒绝
        self.wasm_host_ctx.api_registry().unregister(plugin_id);
        // core-plugin-manager：系统组件停用即撤销其能力提供，能力回落宿主原语
        // （二选一装配：注册表对消费方恒可用；条件回落防误撤重建后的新注册）
        self.wasm_host_ctx.capabilities().revert_all_from(plugin_id);

        // 中止插件定时器（若有）：停用后不再到点回调
        self.abort_plugin_timer(plugin_id);

        // 清理消息总线订阅
        self.message_bus.remove_all_subscriptions(plugin_id).await;

        // 票 03：会话生命周期 / 输入监听器的注册表已退役，停用时无需再按 plugin_id
        // 摘除（原 `remove_lifecycle_listener` / `remove_input_listener` 调用点）。

        let mut plugins = self.plugins.write().await;
        let loaded = plugins
            .get_mut(plugin_id)
            .ok_or_else(|| crate::AppError::Plugin(format!("Plugin not found: {}", plugin_id)))?;

        loaded.state = PluginState::Deactivated;
        loaded.activated_at = None;
        tracing::info!(plugin_id = %plugin_id, persist, "[PluginHost] Plugin deactivated successfully");

        // 释放写锁后再持久化
        drop(plugins);

        if persist {
            tracing::debug!(plugin_id = %plugin_id, "[PluginHost] Persisting activation state after deactivating");
            self.persist_activation_state().await;
        }

        Ok(())
    }

    /// 热重载 WASM 插件（开发模式）
    ///
    /// 执行完整的卸载-重载-激活循环：
    /// 1. 停用插件
    /// 2. 重新编译并实例化 WASM 模块
    /// 3. 重新激活插件

    /// 获取当前所有非 StaticRegistry 插件的激活状态映射
    ///
    /// 持久化语义为用户意图：Activated 与 Degraded 均记 true——降级是健康
    /// 快照而非启停意图，下次启动仍按 persisted=true 重试激活；
    /// Error/Deactivated 等记 false（与既有行为一致）
    pub async fn get_activated_state(&self) -> HashMap<String, bool> {
        let plugins = self.plugins.read().await;
        let mut map = HashMap::new();
        for (id, loaded) in plugins.iter() {
            if loaded.source == PluginSource::StaticRegistry {
                continue;
            }
            // core-plugin-manager · ADR 0032：角色驱动层（L1 基础服务 / L2 内部
            // 统一业务应用）启动时按角色无条件激活（activate_role_driven_components），
            // 其启停不持久化——持久化真源是「角色」而非用户状态，停用仅对当前会话生效
            if loaded.manifest.kind.is_role_driven() {
                continue;
            }
            let is_active = matches!(loaded.state, PluginState::Activated | PluginState::Degraded { .. });
            map.insert(id.clone(), is_active);
        }
        tracing::debug!(
            "[PluginHost] get_activated_state() returning {} entry/entries",
            map.len()
        );
        map
    }

    /// 持久化当前激活状态到 SQLite

    /// 持久化当前激活状态到 SQLite
    pub(crate) async fn persist_activation_state(&self) {
        let activated_map = self.get_activated_state().await;
        tracing::debug!(
            "[PluginHost] Persisting activation state: {} plugin(s)",
            activated_map.len()
        );
        for (id, active) in &activated_map {
            tracing::debug!(plugin_id = %id, persist = active, "[PluginHost]   Persist");
        }
        if let Err(e) = self.storage.save_activated_plugins(&activated_map).await {
            tracing::error!("[PluginHost] Failed to persist plugin activation state: {}", e);
        }
    }

    /// 角色驱动层先于业务应用激活（L1 基础服务 → L2 内部统一业务，ADR 0032）——**本段为历史残留注释**
    ///
    /// 实现已迁至 [`Self::activate_role_driven_components`]（`boot.rs`）：层序取自 SDK 常量
    /// `PluginKind::ROLE_DRIVEN_LOAD_ORDER`，含 L2 第二批。保留本段仅记录旧口径：
    /// **不**承诺「只停不删」（按 kind 拒绝卸载的守卫未实现，见 ADR 0032 §6 L1 清单第 3 项）。

    /// 判断插件是否应该按需激活
    pub async fn should_lazy_activate(&self, plugin_id: &str) -> bool {
        let plugins = self.plugins.read().await;
        if let Some(loaded) = plugins.get(plugin_id) {
            if loaded.source == PluginSource::StaticRegistry {
                return false;
            }
            if !matches!(loaded.state, PluginState::Loaded) {
                return false;
            }
            let c = &loaded.manifest.contributes;
            !c.commands.is_empty() || c.terminal.is_some() || !c.views.is_empty()
        } else {
            false
        }
    }
}

// ==================== 插件名唯一性（用户裁定 ⑨，激活期最终闸门） ====================

/// 查找「键不一致但 manifest.id 相同」的重复插件记录
///
/// `plugins` 以 id 为键，正常情形下同名记录不可能共存（扫描面先到先得 / 安装面
/// 同 id 拒绝）；本函数是激活闸门的判据——若某条记录被以**其他键**插入（竞态 /
/// 异常路径），且其 manifest.id 与目标插件一致，返回该键（激活必须失败，否则
/// 两条同名记录会同时拥有路由命名空间，破坏隔离）。
///
/// 纯函数（供单测）：`key == manifest.id` 的正常记录不算冲突。
fn find_duplicate_id_claim(
    plugins: &std::collections::HashMap<String, LoadedPlugin>,
    plugin_id: &str,
) -> Option<String> {
    plugins
        .iter()
        .filter(|(key, loaded)| loaded.manifest.id == plugin_id && **key != plugin_id)
        .map(|(key, _)| key.clone())
        .next()
}

// ==================== 旧 api 名双投窗口（票 07 B2） ====================

/// 改名插件的 api 名别名：`(新插件 id, 旧插件 id)`。
///
/// 双投窗口语义：改名插件激活时除现名 api 外，还把旧名 api 一并登记到
/// `ApiRegistry`（属主仍是本插件）——未更新的旧调用方按旧名互调（`wasmnest.api
/// .com.wasmnest.session.*`）时照常可达；`owner_of` 解旧名时也落到本插件，
/// 回复道 sender 校验口径一致。与 HTTP 前缀别名（`legacy_http_alias`）同一决策；
/// 窗口关闭（全量更新后）时删除本条即可。
const LEGACY_API_PLUGIN_ALIASES: &[(&str, &str)] = &[("com.wasmnest.terminal-session", "com.wasmnest.session")];

/// 为新 plugin_id 的 api 清单附加旧名别名；无别名命中时原样返回。
///
/// 纯函数（测试直接断言）：api 名 = `{plugin_id}.{连字符方法名}`，按 id 精确
/// 命中改名表后，把每个现名 api 生成旧名等价项；已在清单里的旧名去重。
fn with_api_aliases(plugin_id: &str, apis: &[String]) -> Vec<String> {
    let Some((_, old_id)) = LEGACY_API_PLUGIN_ALIASES
        .iter()
        .find(|(new_id, _)| *new_id == plugin_id)
    else {
        return apis.to_vec();
    };
    let mut out = apis.to_vec();
    for api in apis {
        if let Some(suffix) = api.strip_prefix(&format!("{plugin_id}.")) {
            let old = format!("{old_id}.{suffix}");
            if !out.contains(&old) {
                out.push(old);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== 插件名唯一性（用户裁定 ⑨，激活期最终闸门） ====================

    fn loaded_plugin(id: &str) -> LoadedPlugin {
        LoadedPlugin {
            manifest: crate::manifest::PluginManifest {
                id: id.to_string(),
                name: id.to_string(),
                version: "1.0.0".to_string(),
                ..Default::default()
            },
            state: PluginState::Activated,
            extension_path: String::new(),
            activated_at: None,
            source: PluginSource::Wasm,
        }
    }

    fn map_of(entries: Vec<(&str, &str)>) -> std::collections::HashMap<String, LoadedPlugin> {
        // (键, manifest.id)
        entries
            .into_iter()
            .map(|(key, id)| (key.to_string(), loaded_plugin(id)))
            .collect()
    }

    /// 正常注册表：目标 id 的记录以自身为键 → 无冲突
    #[test]
    fn duplicate_claim_absent_in_normal_registry() {
        let map = map_of(vec![("com.a.plugin", "com.a.plugin"), ("com.b.plugin", "com.b.plugin")]);
        assert!(find_duplicate_id_claim(&map, "com.a.plugin").is_none());
        assert!(find_duplicate_id_claim(&map, "com.b.plugin").is_none());
    }

    /// 竞态/异常插入：另一条记录以**其他键**声明了同一 manifest.id → 点名冲突键
    #[test]
    fn duplicate_claim_detected_on_rogue_insert() {
        let map = map_of(vec![
            ("com.a.plugin", "com.a.plugin"),
            ("rogue-key", "com.a.plugin"), // 冒名记录插在别的键下
        ]);
        assert_eq!(
            find_duplicate_id_claim(&map, "com.a.plugin").as_deref(),
            Some("rogue-key")
        );
        // 目标插件自身（正常键）不构成冲突
        assert!(find_duplicate_id_claim(&map, "rogue-key").is_none());
    }

    /// 同名不同插件（manifest.id 不同）互不干扰
    #[test]
    fn duplicate_claim_ignores_distinct_ids() {
        let map = map_of(vec![("com.a.plugin", "com.a.plugin"), ("com.b.plugin", "com.b.plugin")]);
        assert!(find_duplicate_id_claim(&map, "com.nonexistent").is_none());
    }

    /// 空表：无冲突
    #[test]
    fn duplicate_claim_absent_in_empty_registry() {
        let map: std::collections::HashMap<String, LoadedPlugin> = std::collections::HashMap::new();
        assert!(find_duplicate_id_claim(&map, "anything").is_none());
    }

    fn apis(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// 改名插件：旧 api 名补齐、新名保留、无重复
    #[test]
    fn aliases_latest_renamed_plugin_apis() {
        let out = with_api_aliases(
            "com.wasmnest.terminal-session",
            &apis(&[
                "com.wasmnest.terminal-session.pairing-code-generate",
                "com.wasmnest.terminal-session.config-list",
            ]),
        );
        assert_eq!(
            out,
            apis(&[
                "com.wasmnest.terminal-session.pairing-code-generate",
                "com.wasmnest.terminal-session.config-list",
                "com.wasmnest.session.pairing-code-generate",
                "com.wasmnest.session.config-list",
            ])
        );
    }

    /// 已在清单里显式声明旧名：去重，不重复登记
    #[test]
    fn aliases_dedupe_explicit_old_name() {
        let out = with_api_aliases(
            "com.wasmnest.terminal-session",
            &apis(&[
                "com.wasmnest.terminal-session.trust-list",
                "com.wasmnest.session.trust-list",
            ]),
        );
        assert_eq!(
            out,
            apis(&[
                "com.wasmnest.terminal-session.trust-list",
                "com.wasmnest.session.trust-list",
            ]),
            "显式旧名不得重复"
        );
    }

    /// 未改名插件 / 未知前缀：原样返回，不生成别名
    #[test]
    fn aliases_off_for_other_plugins() {
        let out = with_api_aliases(
            "com.wasmnest.file-transfer",
            &apis(&["com.wasmnest.file-transfer.list-remote"]),
        );
        assert_eq!(out, apis(&["com.wasmnest.file-transfer.list-remote"]));
        // 前缀必须精确命中改名插件 id（不得把其它 id 误当改名者）
        let out = with_api_aliases(
            "com.wasmnest.terminal-session-extra",
            &apis(&["com.wasmnest.terminal-session-extra.x"]),
        );
        assert_eq!(out, apis(&["com.wasmnest.terminal-session-extra.x"]));
    }

    /// 空清单：返回空（不生成无意义别名）
    #[test]
    fn aliases_empty_list_stays_empty() {
        let out = with_api_aliases("com.wasmnest.terminal-session", &[]);
        assert!(out.is_empty());
    }
}
