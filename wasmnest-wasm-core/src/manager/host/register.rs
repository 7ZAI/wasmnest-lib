//! `register` — PluginHost 职责面拆分（P2）
//!
//! 自 `host.rs` 主 impl 拆出；经 `use super::*` 继承 host 模块的
//! 全部导入与常量，方法与字段可见性规则与内联时一致。

use super::*;
impl PluginHost {
    /// 将所有已加载插件的 manifest contributes 注册到 registry
    ///
    /// 只负责取 id 清单，逐个委派给 [`Self::register_plugin_contributions`]——**单条注册
    /// 是唯一实现**（票 11 第 3 项）：启动期全量 / zip 安装单条 / 热重载三条路径共用它，
    /// 避免同一份六项注册被手抄三遍（历史上一次 contributes 演进要同改三处）。
    ///
    /// 读数与注册分离：id 清单在读锁内收集后立即释放，注册本身 `await`（还会回调宿主），
    /// 不在持锁期间做 I/O。
    pub(crate) async fn register_manifest_contributions(&self) {
        let plugin_ids: Vec<String> = {
            let plugins = self.plugins.read().await;
            plugins.keys().cloned().collect()
        };
        for id in plugin_ids {
            self.register_plugin_contributions(&id).await;
        }
    }

    /// 注册 Rust 插件的 command handlers 到运行时注册表（inventory 静态注册）
    pub(crate) async fn register_rust_command_handlers(&self) {
        let static_plugins: Vec<&'static wasmnest_plugin_api::WasmNestPluginEntry> =
            inventory::iter::<wasmnest_plugin_api::WasmNestPluginEntry>
                .into_iter()
                .collect();

        let mut handlers = self.rust_command_handlers.write().await;
        for entry in static_plugins {
            let commands = (entry.register_commands)();
            let plugin_id = entry.id;
            for cmd in commands {
                let full_name = format!("{}::{}", plugin_id, cmd.name);
                tracing::info!("Registered Rust command: {}", full_name);
                handlers.insert(full_name, cmd);
            }
        }
    }

    /// 注册 Rust 插件的 terminal handlers 到运行时注册表（inventory 静态注册）
    pub(crate) async fn register_rust_terminal_handlers(&self) {
        let static_plugins: Vec<&'static wasmnest_plugin_api::WasmNestPluginEntry> =
            inventory::iter::<wasmnest_plugin_api::WasmNestPluginEntry>
                .into_iter()
                .collect();

        let mut handlers = self.rust_terminal_handlers.write().await;
        for entry in static_plugins {
            let plugin_handlers = (entry.terminal_handlers)();
            for handler in plugin_handlers {
                tracing::info!(plugin_id = %entry.id, "Registered Rust terminal handler");
                handlers.push(handler);
            }
        }
    }

    // ==================== manifests 扩展点注册 ====================

    /// 注册单个插件的 manifest contributes 扩展点（唯一实现：启动期 / 安装 / 热重载共用）
    ///
    /// 覆盖四项：commands / views / terminal handlers / file handlers。**刻意不覆盖**
    /// `configuration` / `lifecycle`（boot 期装配）与 `provides` / `subscribes`（激活期走
    /// 总线订阅，见 `host/activation.rs`）——在未激活时注册这两项会造成「未激活即订阅」。
    ///
    /// **ABI v29（HTTP 路由代码注册下沉）**：`httpEndpoints` 静态声明面退役（用户裁定 ④：
    /// 不通过声明配置路由，插件代码运行时经 `host-http.register-endpoint` 注册）——
    /// HTTP 路由的登记权整体移交插件，宿主不再从 manifest 读路由；`toolProviders` 声明面
    /// 从未落地消费实现（前端注释明示），随 http 端点面一并退役。
    ///
    /// 幂等：registry 侧按 plugin_id 存放，重复注册结果一致（[`Self::register_manifest_contributions`]
    /// 与热重载都会重复走到这里）。插件不在表中时静默返回（卸载竞态）。
    pub(crate) async fn register_plugin_contributions(&self, plugin_id: &str) {
        let loaded = self.plugins.read().await.get(plugin_id).cloned();
        let Some(loaded) = loaded else {
            return;
        };
        let m = &loaded.manifest;
        self.registry.register_commands(&m.id, &m.contributes.commands).await;
        self.registry.register_views(&m.id, &m.contributes.views).await;
        if let Some(ref term) = m.contributes.terminal {
            self.registry
                .register_terminal_handlers(&m.id, &term.input_handlers, &term.output_parsers)
                .await;
        }
        self.registry
            .register_file_handlers(&m.id, &m.contributes.file_handlers)
            .await;
    }

    /// 登记 manifest 声明的 WS 端点（票 09a，contributes.wsEndpoints）
    ///
    /// 与 HTTP 端点的**登记时机不同**：httpEndpoints 在 load 期经
    /// `register_plugin_contributions` 一次性登记进 registry（生命周期随 load），而
    /// WS 端点的生命周期**随激活**——deactivate 会 `purge_for_plugin` 回收该插件全部
    /// WS 端点（`wasmnest_server_websocket::endpoint` 表）。因此声明端点必须在**激活成功**时
    /// 登记，才能在 deactivate→activate 循环后不丢（否则首次激活后 deactivate 即丢，
    /// reactivate 不重登记）。调用方：`activate_plugin_inner` 激活成功分支。
    ///
    /// 路径校验与运行时 `ws_register_endpoint` 同口径（非空、不含 `/` 与 `.`、
    /// 不超长）；认证档位缺省 = `none`（WS 面历史行为，与 `host-websocket`
    /// `register-endpoint` 一致）。非法条目 → warn + 跳过（不致命，插件仍激活，
    /// 该端点不可达）；本方法幂等（重复登记由端点表冲突判定拦截）。
    pub(crate) async fn register_declared_ws_endpoints(
        &self,
        plugin_id: &str,
        endpoints: &[crate::manifest::WsEndpointContribution],
    ) {
        if !self
            .permission
            .check(plugin_id, wasmnest_plugin_api::permission::PERMISSION_WS_SERVER)
        {
            tracing::warn!(
                plugin_id = %plugin_id,
                "manifest declared ws endpoints skipped: missing ws:server permission"
            );
            return;
        }
        // ws 域脱绑后（能力域脱绑 P3）端点认证档位为 `wasmnest_server_websocket::wire`
        // 自持副本（与 SDK 原版漂移锁钉死）；manifest 声明面仍用 SDK 类型解析
        // `auth_raw`，判定面（register 签名）换 ws 域 wire 版。
        use wasmnest_server_websocket::wire::EndpointAuth;
        for endpoint in endpoints {
            let path = endpoint.path().trim();
            // 与 ws host_api 同一形状校验：空 / 含 `/` / 含 `.` / 超长 → 跳过
            if path.is_empty()
                || path.contains('/')
                || path.contains('.')
                || path.chars().count() > crate::system::constants::PLUGIN_WS_ENDPOINT_PATH_MAX_LEN
            {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    declared = %endpoint.path(),
                    "manifest declared ws endpoint path invalid, endpoint not registered (unreachable by design)"
                );
                continue;
            }
            // WS 面缺省档 = none（与 host-websocket register-endpoint 一致）；
            // 未知取值报错 + 跳过（绝不静默降级为较宽档位）
            let auth = match EndpointAuth::parse_with(endpoint.auth_raw(), EndpointAuth::None) {
                Ok(auth) => auth,
                Err(e) => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        declared = %endpoint.path(),
                        error = %e,
                        "manifest declared ws endpoint has invalid auth, not registered"
                    );
                    continue;
                }
            };
            match wasmnest_server_websocket::endpoint::register(
                plugin_id,
                path,
                auth,
                None,
                None,
                Arc::new(crate::bus::HostBusPort::new(
                    self.message_bus.clone(),
                    // 帧投递窄端口：必须与本总线同源（多上下文下错绑会把帧投进别的实例）。
                    // 本处仍是内核侧构造 —— 批次 03 第 4 步 adapter 迁宿主后由宿主注入，
                    // 见票面「批次 03 · 第 2–4 步设计定稿」。
                    Arc::new(crate::bus::BusBoundWsPorts::new(self.message_bus.clone())),
                )),
            ) {
                Ok(entry) => {
                    tracing::info!(
                        plugin_id = %plugin_id,
                        endpoint_id = %entry.endpoint_id,
                        mount_path = %entry.mount_path,
                        auth = auth.as_str(),
                        "manifest-declared ws endpoint registered"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        declared = %endpoint.path(),
                        error = %e,
                        "plugin ws endpoint registration failed"
                    );
                }
            }
        }
    }
}
