//! PluginHost 的 trait 实现（PluginServices / MessageDispatcher / Clone）
//! 与会话事件分发
//!
//! 从 `host.rs` 拆出：WASM host 函数回路的服务侧实现、定时器管理、
//! 会话生命周期/输入事件分发。

use std::pin::Pin;

use super::owner::{GuestOp, GuestReply};
use super::PluginHost;
use crate::manager::runtime::PluginServices;
use crate::manifest::PluginState;

// ==================== 观察面派发（票 03 已退役） ====================
//
// 本文件原有 `PluginHost::{dispatch_lifecycle_to_plugin, dispatch_input_to_plugin}`
// 两个派发点（连同 `is_activated_block` 门禁）——把宿主会话事件序列化后送给插件的
// `on_session_lifecycle` / `on_input_submitted` 导出。派发源（SessionManager 的
// 两张监听器注册表）与监听器实现（`manager/host/listeners.rs`）随票 03 一并退役，
// 派发点因此无消费者，同批删除。插件侧那两个导出仍存在（WIT 面随票 10 收口）。

// ==================== PluginServices Implementation ====================

impl PluginServices for PluginHost {
    fn mark_plugin_error(&self, plugin_id: String, error: String) {
        crate::runtime_util::block_on_async(async move {
            // 仅通知前端提示：不置 Error、不持久化，插件保持激活，会话照常运行。
            // hooks 安装失败等自检错误属可恢复/局部问题，不应因此禁用整个插件。
            // 详情（error）只进日志；前端收错误信封（见 notify_plugin_self_check_error）
            self.notify_plugin_self_check_error(&plugin_id, &error)
                .await;
        });
    }

    fn register_plugin_timer(&self, plugin_id: String, interval_secs: u64, command: String) {
        // 重复注册替换旧定时器：先中止旧任务再插入新句柄，
        // 同一插件仅保留一个定时器实例
        let mut timers = self.plugin_timers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = timers.remove(&plugin_id) {
            old.abort();
        }

        let host = self.clone();
        let pid = plugin_id.clone();
        let cmd = command.clone();
        let handle = crate::system::error_boundary::spawn_with_error_boundary(
            "plugin_timer_loop",
            async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                // 首个 tick 立即触发：跳过，从下一个周期开始（避免注册瞬间就回调）
                interval.tick().await;
                loop {
                    interval.tick().await;

                    let now = chrono::Utc::now();
                    let args = serde_json::json!({
                        "now_ms": now.timestamp_millis(),
                        // 与 SQLite datetime('now') 同格式（UTC，无时区后缀），
                        // 便于插件在 SQL 中直接字符串比较到期时间
                        "now_utc": now.format("%Y-%m-%d %H:%M:%S").to_string(),
                        // 本地时区基准（task-scheduler spec §5.1）：
                        // 调度时间表达式按用户本地时间解释，由宿主注入（WASM 无系统时钟）
                        "now_local": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    });

                    // 到点调用插件 command；插件未激活/已卸载时返回 Err，
                    // 属预期内路径（定时器中止前的空窗期），仅记 debug 日志
                    match host.invoke_rust_command(&pid, &cmd, args).await {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::debug!(
                                plugin_id = %pid,
                                command = %cmd,
                                error = %e,
                                "[PluginHost] timer tick skipped"
                            );
                        }
                    }
                }
            },
        );

        timers.insert(plugin_id.clone(), handle);
        drop(timers);

        tracing::info!(
            "[PluginHost] Timer started for '{}': interval={}s command={}",
            plugin_id,
            interval_secs,
            command
        );
    }

    fn dispatch_process_done(&self, plugin_id: String, event: serde_json::Value) {
        // 与 dispatch_to_wasm 同模式：同步门面（两模型同构；调用失败自动重载
        // 恢复；插件未激活/已卸载时仅记日志，尽力而为）
        let event_str = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "[PluginHost] dispatch_process_done: serialize event failed"
                );
                return;
            }
        };
        match self.call_guest_blocking(
            &plugin_id,
            GuestOp::OnProcessDone {
                payload_json: event_str,
            },
        ) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "[PluginHost] dispatch_process_done failed"
                );
            }
        }
    }

    fn dispatch_task_event(&self, plugin_id: String, event: serde_json::Value) {
        // 同 dispatch_process_done 模式：同步门面（两模型同构；调用失败自动重载
        // 恢复；插件未激活/已卸载时仅记日志，尽力而为）。
        // 未导出 events-task 的旧产物：on_task_event 返回 Ok(false) → 事件丢弃 +
        // 首次 warn + 计数（宿主不缓存；status/log-jobs 自愈，spec §5.3）
        let event_str = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "[PluginHost] dispatch_task_event: serialize event failed"
                );
                return;
            }
        };
        match self.call_guest_blocking(
            &plugin_id,
            GuestOp::OnTaskEvent {
                event_json: event_str,
            },
        ) {
            Ok(GuestReply::Bool(true)) => {}
            Ok(GuestReply::Bool(false)) => {
                // 旧 SDK 产物（未导出 events-task）：事件丢弃 + 计数
                tracing::warn!(
                    plugin_id = %plugin_id,
                    "[PluginHost] task event dropped (plugin lacks events-task export)"
                );
            }
            Ok(other) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    reply = ?other,
                    "[PluginHost] dispatch_task_event: unexpected guest reply"
                );
            }
            Err(e) => {
                tracing::error!(
                    plugin_id = %plugin_id,
                    error = %e,
                    "[PluginHost] dispatch_task_event failed"
                );
            }
        }
    }

    fn install_cli(
        &self,
        plugin_id: String,
        file_name: String,
        bin_dir: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            // 源文件位于插件包目录 cli/<file-name>（宿主按已加载插件的 extension_path 解析）
            let extension_path = {
                let plugins = self.plugins.read().await;
                plugins
                    .get(&plugin_id)
                    .map(|p| p.extension_path.clone())
                    .ok_or_else(|| format!("install_cli: plugin not found: {}", plugin_id))?
            };
            let exe = super::app_cli::exe_name(&file_name);
            let src = std::path::Path::new(&extension_path).join("cli").join(&exe);
            if !src.exists() {
                return Err(format!(
                    "install_cli: CLI artifact not found: {}",
                    src.display()
                ));
            }

            let bin_dir = if bin_dir.is_empty() {
                super::app_cli::default_bin_dir()
            } else {
                std::path::PathBuf::from(&bin_dir)
            };
            std::fs::create_dir_all(&bin_dir)
                .map_err(|e| format!("install_cli: create bin dir failed: {}", e))?;
            let dst = bin_dir.join(&exe);
            std::fs::copy(&src, &dst).map_err(|e| {
                format!(
                    "install_cli: copy {} -> {} failed: {}",
                    src.display(),
                    dst.display(),
                    e
                )
            })?;

            // PATH 注册（幂等）
            #[cfg(target_os = "windows")]
            super::app_cli::register_path_windows(&bin_dir).await?;
            #[cfg(not(target_os = "windows"))]
            super::app_cli::register_path_unix(&bin_dir, &exe)?;

            tracing::info!(
                "[PluginHost] CLI installed for '{}': {} -> {}",
                plugin_id,
                src.display(),
                dst.display()
            );
            Ok(bin_dir.to_string_lossy().to_string())
        })
    }

    fn uninstall_cli(
        &self,
        plugin_id: String,
        file_name: String,
        bin_dir: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            // 应用关闭流程（deactivate_all 置位）：保留随包 CLI，下次激活幂等重装
            if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
                tracing::debug!(
                    "[PluginHost] uninstall_cli skipped for '{}': app shutting down",
                    plugin_id
                );
                return Ok(());
            }

            let exe = super::app_cli::exe_name(&file_name);
            let bin_dir = if bin_dir.is_empty() {
                super::app_cli::default_bin_dir()
            } else {
                std::path::PathBuf::from(&bin_dir)
            };

            // 删除文件（不存在视为已卸载，幂等）
            let file = bin_dir.join(&exe);
            if file.exists() {
                std::fs::remove_file(&file).map_err(|e| {
                    format!("uninstall_cli: remove {} failed: {}", file.display(), e)
                })?;
            }

            // PATH 条目移除（仅本插件条目，保留用户原有项）
            #[cfg(target_os = "windows")]
            super::app_cli::unregister_path_windows(&bin_dir).await?;
            #[cfg(not(target_os = "windows"))]
            super::app_cli::unregister_path_unix(&bin_dir, &exe)?;

            tracing::info!(plugin_id = %plugin_id, "[PluginHost] CLI uninstalled: {}", file.display());
            Ok(())
        })
    }

    fn plugin_resource_dir(
        &self,
        plugin_id: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            // 与生命周期事件 payload 的 `resource_dir` 同一形态（剥离 verbatim 前缀，
            // 保证插件侧正斜杠拼接可用，见 loader.rs strip_verbatim_prefix）
            let plugins = self.plugins.read().await;
            plugins
                .get(&plugin_id)
                .map(|p| crate::manager::loader::strip_verbatim_prefix(&p.extension_path))
                .ok_or_else(|| format!("plugin_resource_dir: plugin not found: {}", plugin_id))
        })
    }

    fn register_path(
        &self,
        plugin_id: String,
        dir: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let path = std::path::PathBuf::from(&dir);
            // allowlist：目录必须落在应用数据根 / 用户 bin 根之内——PATH 是持久化
            // 用户环境面，越界目录一律拒绝并点名实际路径（fail-visible）
            if !super::app_cli::path_dir_allowed(&path) {
                return Err(format!(
                    "register_path: directory outside allowed roots: {}",
                    path.display()
                ));
            }
            if !path.is_dir() {
                return Err(format!(
                    "register_path: directory not found: {}",
                    path.display()
                ));
            }
            super::app_cli::register_path_dir(&path).await?;
            tracing::info!(
                plugin_id = %plugin_id,
                "[PluginHost] PATH dir registered: {}",
                path.display()
            );
            Ok(())
        })
    }

    fn unregister_path(
        &self,
        plugin_id: String,
        dir: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let path = std::path::PathBuf::from(&dir);
            // 摘除同样过 allowlist：不让插件借「摘除」面探测任意路径是否存在
            if !super::app_cli::path_dir_allowed(&path) {
                return Err(format!(
                    "unregister_path: directory outside allowed roots: {}",
                    path.display()
                ));
            }
            super::app_cli::unregister_path_dir(&path).await?;
            tracing::info!(
                plugin_id = %plugin_id,
                "[PluginHost] PATH dir unregistered: {}",
                path.display()
            );
            Ok(())
        })
    }
}

// 通过 Arc 共享内部状态实现 Clone
impl Clone for PluginHost {
    fn clone(&self) -> Self {
        Self {
            plugins: self.plugins.clone(),
            registry: self.registry.clone(),
            permission: self.permission.clone(),
            storage: self.storage.clone(),
            rust_command_handlers: self.rust_command_handlers.clone(),
            rust_terminal_handlers: self.rust_terminal_handlers.clone(),
            wasm_runtime: self.wasm_runtime.clone(),
            wasm_plugins: self.wasm_plugins.clone(),
            owner_sink: self.owner_sink.clone(),
            owner_cleanup_skipped: self.owner_cleanup_skipped.clone(),
            wasm_host_ctx: self.wasm_host_ctx.clone(),
            message_bus: self.message_bus.clone(),
            plugin_timers: self.plugin_timers.clone(),
            wasm_reload_throttle: self.wasm_reload_throttle.clone(),
            runtime_error_notify_throttle: self.runtime_error_notify_throttle.clone(),
            shutting_down: self.shutting_down.clone(),
            user_plugins_dir: self.user_plugins_dir.clone(),
            frontend_channel: self.frontend_channel.clone(),
        }
    }
}

// ==================== MessageDispatcher Implementation ====================

impl crate::bus::MessageDispatcher for PluginHost {
    fn dispatch_to_wasm(
        &self,
        plugin_id: &str,
        msg: &crate::bus::BusMessage,
    ) -> anyhow::Result<()> {
        // v11：按载荷格式路由——二进制消息走可选导出 on_message_binary
        // （总线已按订阅者格式偏好过滤，不会对无导出的旧插件发二进制消息）
        let op = if let Some(bytes) = &msg.payload_binary {
            GuestOp::OnMessageBinary {
                topic: msg.topic.clone(),
                sender: msg.sender.clone(),
                payload: bytes.clone(),
            }
        } else {
            GuestOp::OnMessage {
                topic: msg.topic.clone(),
                sender: msg.sender.clone(),
                // 与改造前一致：JSON 文本由宿主序列化（`Value` 序列化确定性）
                payload_json: serde_json::to_string(&msg.payload).unwrap_or_default(),
            }
        };
        // 调用失败（trap/store 中毒）时自动重载恢复，见 PluginHost::call_guest
        self.call_guest_blocking(plugin_id, op)
            .map(|_reply| ())
            .map_err(anyhow::Error::from)
    }

    /// 投递 WS 帧给插件的 `events-ws` 可选导出（ABI v14）
    ///
    /// 与 `dispatch_to_wasm` 同桥（同步门面 + `call_guest`）：trap 走自动重载恢复。
    /// 返回 `Ok(false)` = 插件未导出该接口（调用方降级）
    fn dispatch_ws_frame(
        &self,
        plugin_id: &str,
        frame: &crate::bus::WsFrameDispatch,
    ) -> anyhow::Result<bool> {
        use crate::bus::WsFrameDispatch;
        let op = match frame {
            WsFrameDispatch::Client {
                handle,
                kind,
                payload,
            } => GuestOp::WsClientMessage {
                handle: handle.clone(),
                kind: kind.clone(),
                payload: payload.clone(),
            },
            WsFrameDispatch::EndpointClient {
                endpoint_id,
                client_id,
                kind,
                payload,
            } => GuestOp::WsEndpointMessage {
                endpoint_id: endpoint_id.clone(),
                client_id: client_id.clone(),
                kind: kind.clone(),
                payload: payload.clone(),
            },
        };
        match self.call_guest_blocking(plugin_id, op) {
            Ok(GuestReply::Bool(delivered)) => Ok(delivered),
            Ok(other) => Err(anyhow::anyhow!(
                "plugin {} ws frame dispatch returned unexpected guest reply: {:?}",
                plugin_id,
                other
            )),
            Err(e) => Err(anyhow::anyhow!("{}", e)),
        }
    }

    fn is_activated(&self, plugin_id: &str) -> bool {
        let plugins = self.plugins.clone();
        crate::runtime_util::block_on_async(async move {
            let plugins = plugins.read().await;
            plugins
                .get(plugin_id)
                .map(|p| matches!(p.state, PluginState::Activated))
                .unwrap_or(false)
        })
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// 构造最小 PluginHost（与 commands.rs 测试同模式）
    async fn test_plugin_host() -> Arc<PluginHost> {
        let db = Arc::new(Mutex::new(
            Database::new(Path::new(":memory:")).expect("in-memory db"),
        ));
        db.lock()
            .expect("db lock")
            .init_schema()
            .expect("init schema");
        let dir = std::env::temp_dir().join(format!("wasmnest-svc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let host = PluginHost::new(
            db,
            &dir,
            &dir,
            None,
            None,
            Vec::new(),
            crate::manager::runtime::AbiPolicy::UNCONSTRAINED,
            std::sync::Arc::new(crate::host_api::ports::UnimplementedHostFacts),
            None,
            None, // 服务租约注册表
        )
        .await;
        host.init_message_bus().await;
        host
    }

    /// 在册插件取自身资源目录：等于其 `extension_path`（剥离 verbatim 前缀的形态）
    ///
    /// 这是 P1-b 的硬前置：创建编排移交插件后宿主不再产生 `Creating` 事件，
    /// 插件只能经本原语拿到资源目录（Agent 集成 hook 脚本源在该目录下）。
    #[test]
    fn plugin_resource_dir_returns_extension_path_of_registered_plugin() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "wasmnest-resdir-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let plugin_id = "com.wasmnest.test-resdir";
        let plugin_dir = dir.join(plugin_id);
        std::fs::create_dir_all(&plugin_dir).expect("plugin dir");
        // 最小 TS-only 插件（无 rust_library → 不需要 wasm 产物，排除无关变量）
        std::fs::write(
            plugin_dir.join(crate::system::constants::PLUGIN_MANIFEST_FILE),
            format!(
                r#"{{"id": "{}", "name": "ResDir Test", "version": "1.0.0", "platform": "both", "main": "index.js", "permissions": ["storage"]}}"#,
                plugin_id
            ),
        )
        .expect("manifest");

        let host = rt.block_on(async {
            let db = Arc::new(Mutex::new(
                Database::new(Path::new(":memory:")).expect("in-memory db"),
            ));
            db.lock()
                .expect("db lock")
                .init_schema()
                .expect("init schema");
            let host = PluginHost::new(
                db,
                &dir,
                &dir,
                None,
                None,
                Vec::new(),
                crate::manager::runtime::AbiPolicy::UNCONSTRAINED,
                std::sync::Arc::new(crate::host_api::ports::UnimplementedHostFacts),
                None,
                None,
            )
            .await;
            host.init_message_bus().await;
            Arc::new(host)
        });

        let got = rt.block_on(host.plugin_resource_dir(plugin_id.to_string()));
        let got = got.expect("已扫描注册的插件必须能取到资源目录");
        assert!(
            !got.trim().is_empty(),
            "资源目录不得为空串（空串会让插件拼出不存在的路径）"
        );
        assert_eq!(
            std::path::Path::new(&got),
            plugin_dir.as_path(),
            "资源目录必须等于插件安装目录（剥离 verbatim 前缀后的形态）"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 未注册插件取资源目录：显性报错（不静默返回空串）
    #[test]
    fn plugin_resource_dir_unknown_plugin_errors() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let host = rt.block_on(test_plugin_host());
        let err = rt
            .block_on(host.plugin_resource_dir("com.wasmnest.nonexistent".to_string()))
            .unwrap_err();
        assert!(
            err.contains("plugin not found"),
            "未知插件必须显性报错，got: {err}"
        );
    }
}
