//! 插件 Rust 命令分发与终端 handler 管道
//!
//! 从 `host.rs` 拆出的 `impl PluginHost` 块：Rust command 路由（WASM /
//! 静态注册）、trap 自动重载、TerminalHandler 输入/输出管道。

use wasmnest_plugin_api::PluginCommandEntry;

use super::owner::{GuestOp, GuestReply};
use super::{PluginHost, PLUGIN_AUTO_RELOAD_MIN_INTERVAL_SECS};
use crate::manager::types::PluginSource;

/// ADR 0030 决定 6：插件错误字符串 → 信封 AppError
///
/// - 标记 JSON（SDK `bail_with_code!` / `user_facing_string` 产物）→ 校验形状后透传
///   `UserFacing{code, params}`（宿主**不解释业务语义**）；
/// - 未标记 / 畸形 → 按兜底码 + 插件标识参数，原文只进日志（detail）。
fn plugin_command_error(plugin_id: &str, command_name: &str, raw: &str) -> crate::AppError {
    if let Some((code, params)) = parse_business_marker(raw) {
        return crate::AppError::user_facing(
            code,
            params,
            format!("plugin {plugin_id} command {command_name} failed: {raw}"),
        );
    }
    crate::AppError::user_facing(
        crate::system::error::DEFAULT_ERROR_CODE,
        serde_json::json!({ "plugin": plugin_id }),
        format!("plugin {plugin_id} command {command_name} failed: {raw}"),
    )
}

/// 解析 SDK 标记信封 JSON：`{"__wasmnest_error__":true,"code":"<str>","params":…}`
///
/// 形状校验（畸形 → `None` → 兜底）：标记必须为布尔 true、code 必须是字符串；
/// params 缺失 → `Value::Null` 透传。
fn parse_business_marker(raw: &str) -> Option<(String, serde_json::Value)> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = v.as_object()?;
    let marked = obj.get("__wasmnest_error__")?;
    if !marked.as_bool().unwrap_or(false) {
        return None;
    }
    let code = obj.get("code")?.as_str()?;
    let params = obj
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Some((code.to_string(), params))
}

impl PluginHost {
    // ==================== Rust Command Dispatch ====================
    /// 执行 Rust 插件的 command handler
    ///
    /// 路由逻辑：
    /// - WASM 插件：通过 WASM 导出函数调用 invoke_command
    /// - 静态注册插件：通过运行时注册表查找 handler
    pub async fn invoke_rust_command(
        &self,
        plugin_id: &str,
        command_name: &str,
        args: serde_json::Value,
    ) -> crate::Result<serde_json::Value> {
        if !self.is_activated(plugin_id).await {
            // 机制失败：显式友好码（ADR 0030 注册表 v0），detail 只进日志
            return Err(crate::AppError::user_facing(
                "host.plugin.not-activated",
                serde_json::json!({ "plugin": plugin_id }),
                format!(
                    "plugin {} is not activated (command {})",
                    plugin_id, command_name
                ),
            ));
        }

        let source = {
            let plugins = self.plugins.read().await;
            plugins
                .get(plugin_id)
                .map(|p| p.source.clone())
                .ok_or_else(|| {
                    crate::AppError::user_facing(
                        "host.plugin.not-found",
                        serde_json::json!({ "plugin": plugin_id }),
                        format!("plugin not found: {plugin_id} (command {command_name})"),
                    )
                })?
        };

        match source {
            PluginSource::Wasm => {
                self.invoke_wasm_command(plugin_id, command_name, args)
                    .await
            }
            // 用户 zip 安装的 rust-ts 插件：走 WASM 命令调用（与 Wasm 语义一致）；
            // ts-only 用户插件无 Rust 命令，wasm 实例缺失时报错
            PluginSource::UserInstalled => {
                self.invoke_wasm_command(plugin_id, command_name, args)
                    .await
            }
            PluginSource::StaticRegistry => {
                self.invoke_static_command(plugin_id, command_name, args)
                    .await
            }
            PluginSource::FileScan => Err(crate::AppError::user_facing(
                "host.plugin.not-found",
                serde_json::json!({ "plugin": plugin_id }),
                format!(
                    "plugin {} is TS-only, cannot invoke Rust command {}",
                    plugin_id, command_name
                ),
            )),
        }
    }

    /// WASM 插件调用失败（trap / store 中毒）后的自动恢复
    ///
    /// wasmtime 同步引擎下任何一次 trap 都会 `set_trapped()` 污染 Store，
    /// 之后该实例所有调用持续报 `CannotEnterComponent`，唯一恢复途径是整体重载
    /// （deactivate → 重新实例化 → activate，即 [`reload_wasm_plugin`]）。
    /// 本方法只做：限频（防重载风暴）+ 后台调度 + 失败时置 Error 态。
    ///
    /// 同步上下文可调用（内部 spawn 不阻塞）；调用方须先释放插件实例锁。
    pub fn schedule_plugin_reload_after_trap(&self, plugin_id: &str) {
        let plugin_id = plugin_id.to_string();

        // 限频：距上次自动重载不足最小间隔则跳过（已在上次恢复或仍属持久性故障）
        {
            let mut throttle = self
                .wasm_reload_throttle
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(last) = throttle.get(&plugin_id) {
                if last.elapsed()
                    < std::time::Duration::from_secs(PLUGIN_AUTO_RELOAD_MIN_INTERVAL_SECS)
                {
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        "plugin trap recovery throttled (recent reload), keeping error state"
                    );
                    return;
                }
            }
            throttle.insert(plugin_id.clone(), std::time::Instant::now());
        }

        let host = self.clone();
        tracing::warn!(
            plugin_id = %plugin_id,
            "plugin WASM trap detected, scheduling auto reload"
        );
        tokio::spawn(async move {
            // 恢复窗口内用户已停用（或正在停用）时不擅自重载
            if !host.is_activated(&plugin_id).await {
                tracing::info!(
                    plugin_id = %plugin_id,
                    "plugin no longer activated, skip auto reload"
                );
                return;
            }
            match host.reload_wasm_plugin(&plugin_id).await {
                Ok(()) => {
                    tracing::info!(plugin_id = %plugin_id, "plugin auto reloaded after trap");
                }
                Err(e) => {
                    tracing::error!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "plugin auto reload after trap failed"
                    );
                    // 统一异常通道：自动恢复失败，插件进入 Error 态（前端收信封提示）
                    host.notify_plugin_runtime_error(&plugin_id, "recovery_failed", &e.to_string())
                        .await;
                    // 置 Error 态：is_activated 门禁停止后续分发。原因串是宿主侧
                    // 诊断事实（UI 只出徽标 + 通用文案，不渲染），见 mark_error 文档
                    host.mark_error(&plugin_id, format!("auto reload after trap failed: {}", e))
                        .await;
                }
            }
        });
    }

    /// 调用 WASM 插件的 command
    ///
    /// guest 调用经统一门面（[`PluginHost::call_guest`]）：`mutex` 模型逐字保留
    /// 既有「实例锁 + 无 handle 阻塞线程 + trap/panic 恢复」语义，`event-loop`
    /// 模型投递属主队列——调用点不需要知道模型。
    pub(super) async fn invoke_wasm_command(
        &self,
        plugin_id: &str,
        command_name: &str,
        args: serde_json::Value,
    ) -> crate::Result<serde_json::Value> {
        // 为需要 resource_dir 的命令自动注入插件 extension_path
        // （剥离 verbatim 前缀，保证插件侧正斜杠拼接可用，见 loader.rs strip_verbatim_prefix）
        let mut enriched_args = args;
        if enriched_args.get("resource_dir").is_none() {
            let plugins = self.plugins.read().await;
            if let Some(loaded) = plugins.get(plugin_id) {
                enriched_args.as_object_mut().map(|obj| {
                    obj.insert(
                        "resource_dir".to_string(),
                        serde_json::Value::String(crate::manager::loader::strip_verbatim_prefix(
                            &loaded.extension_path,
                        )),
                    );
                });
            }
        }

        let args_str = serde_json::to_string(&enriched_args).map_err(|e| {
            crate::AppError::Plugin(format!("Failed to serialize command args: {}", e))
        })?;

        // 调用失败（trap/store 中毒）时自动重载恢复，见 PluginHost::call_guest
        let reply = self
            .call_guest(
                plugin_id,
                GuestOp::InvokeCommand {
                    name: command_name.to_string(),
                    args_json: args_str,
                },
            )
            .await
            .map_err(|failure| failure.error)?;
        let result_str = match reply {
            GuestReply::Str(value) => value,
            // 门面出口是与 op 一一对应的闭集：invoke-command 只能回 `Str`，
            // 其它形态属实现缺陷，显性失败（fail-visible，不静默当成功）
            other => {
                return Err(crate::AppError::Plugin(format!(
                    "WASM plugin {} invoke_command() returned unexpected guest reply: {:?}",
                    plugin_id, other
                )))
            }
        };

        let value: serde_json::Value = serde_json::from_str(&result_str).map_err(|e| {
            crate::AppError::Plugin(format!(
                "WASM plugin {} invoke_command() returned invalid JSON: {}",
                plugin_id, e
            ))
        })?;

        // 插件 invoke_command 的 Err 经 SDK 宏序列化为 {"error": "..."} 的**成功**
        // JSON（非 WIT Err），此处还原为真正错误——否则前端把失败当成功
        // （真机实证：dial-peer 被拒仍 markConnected，桌面显示「已连接」）。
        // ADR 0030 决定 6：SDK `bail_with_code!` 产标记 JSON 错误字符串，宿主只做
        // 机制检测 + 形状校验 + 透传，不解释业务语义；未标记/畸形 → 兜底 + 插件标识。
        if let Some(err) = value.get("error").and_then(|v| v.as_str()) {
            if !err.is_empty() {
                return Err(plugin_command_error(plugin_id, command_name, err));
            }
        }

        Ok(value)
    }

    /// 调用静态注册插件的 command handler
    pub(super) async fn invoke_static_command(
        &self,
        plugin_id: &str,
        command_name: &str,
        args: serde_json::Value,
    ) -> crate::Result<serde_json::Value> {
        let handlers = self.rust_command_handlers.read().await;
        let full_name = format!("{}::{}", plugin_id, command_name);
        let cmd = handlers
            .get(&full_name)
            .ok_or_else(|| crate::AppError::Plugin(format!("Command not found: {}", full_name)))?;

        let result = (cmd.handler)(args)
            .await
            .map_err(|e| crate::AppError::Plugin(format!("Command execution error: {}", e)))?;

        Ok(result)
    }

    /// 获取所有 Rust 插件的 command 列表
    pub async fn list_rust_commands(&self) -> Vec<PluginCommandEntry> {
        let handlers = self.rust_command_handlers.read().await;
        handlers
            .iter()
            .map(|(full_name, cmd)| {
                let parts: Vec<&str> = full_name.splitn(2, "::").collect();
                let plugin_id = parts.first().map(|s| s.to_string()).unwrap_or_default();
                let command_name = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
                PluginCommandEntry {
                    plugin_id,
                    command_name,
                    title: cmd.title.clone(),
                }
            })
            .collect()
    }

    // ==================== Terminal Handler Pipeline ====================

    /// 是否有已注册的 Rust terminal handler
    pub async fn has_terminal_handlers(&self) -> bool {
        !self.rust_terminal_handlers.read().await.is_empty()
    }

    /// 通过插件 TerminalHandler 管道处理终端输出
    pub async fn process_terminal_output(&self, session_id: &str, data: &str) -> String {
        let handlers = self.rust_terminal_handlers.read().await;
        let mut result = data.to_string();
        for handler in handlers.iter() {
            if let Some(modified) = handler.on_output(session_id, &result) {
                tracing::debug!(
                    "Terminal output modified by plugin handler: session_id={}, original_len={}, modified_len={}",
                    session_id,
                    result.len(),
                    modified.len()
                );
                result = modified;
            }
        }
        result
    }

    // 票 03 删除的两条输入侧管道：
    // - `process_terminal_input`（逐帧修饰链）——宿主不再修改用户键入的字节；
    //   终端输入由 `com.wasmnest.terminal-session` 经 `host-pty.write` 原样写入。
    // - `process_input_submitted`（提交行观察分发）——行重建与任务域分发都在插件内。
    // 输出侧 `process_terminal_output` / `has_terminal_handlers` 暂留：它服务的是
    // 业务输出环（`session/session_output.rs`），随内核会话目录在票 11 一并退役。
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::system::error::AppError;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::Mutex;
    /// 构造最小 PluginHost（票据 32：路由错误分支测试）
    ///
    /// 空插件目录 + 内存 DB；wasmtime 初始化一次。auth_service 测试同模式。
    async fn test_plugin_host() -> Arc<PluginHost> {
        let db = Arc::new(Mutex::new(
            Database::new(Path::new(":memory:")).expect("in-memory db"),
        ));
        db.lock()
            .expect("db lock")
            .init_schema()
            .expect("init schema");
        let dir = std::env::temp_dir().join(format!("wasmnest-cmd-test-{}", std::process::id()));
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
            None,
        )
        .await;
        host.init_message_bus().await;
        host
    }

    /// 未激活插件 → 拒绝（票据 32：路由首道门禁）
    #[tokio::test]
    async fn invoke_rust_command_rejects_inactive_plugin() {
        let host = test_plugin_host().await;
        let err = host
            .invoke_rust_command("com.wasmnest.nonexistent", "foo", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not activated"), "实际: {err}");
    }

    /// list_rust_commands：返回的条目 plugin_id 非空（静态注册表可能含内置项）
    #[tokio::test]
    async fn list_rust_commands_entries_have_plugin_ids() {
        let host = test_plugin_host().await;
        let commands = host.list_rust_commands().await;
        assert!(commands.iter().all(|c| !c.plugin_id.is_empty()));
    }

    /// 终端 handler 管道：输出处理无 handler 时原样返回
    #[tokio::test]
    async fn process_terminal_output_without_handlers_passthrough() {
        let host = test_plugin_host().await;
        let out = host.process_terminal_output("sess-1", "out-data").await;
        assert_eq!(out, "out-data", "无 handler 时应原样返回输出");
    }

    // ==================== 插件错误信封（ADR 0030 决定 6） ====================

    /// 正例：标记 JSON → UserFacing 透传 code + params
    #[test]
    fn business_marker_passthrough_code_and_params() {
        let err = plugin_command_error(
            "com.wasmnest.terminal-session",
            "session.input",
            r#"{"__wasmnest_error__":true,"code":"com.wasmnest.terminal-session.session.error.sessionNotFound","params":{"sessionId":"s-1"}}"#,
        );
        let AppError::UserFacing {
            code,
            params,
            detail,
        } = err
        else {
            panic!("应为 UserFacing，实际: {err}");
        };
        assert_eq!(
            code,
            "com.wasmnest.terminal-session.session.error.sessionNotFound"
        );
        assert_eq!(params, serde_json::json!({ "sessionId": "s-1" }));
        assert!(
            detail.contains("session.input"),
            "detail 应带命令上下文: {detail}"
        );
    }

    /// 正例：标记信封 params 缺失 → Null 透传
    #[test]
    fn business_marker_without_params_passthrough_null() {
        let err = plugin_command_error(
            "com.wasmnest.demo",
            "cmd",
            r#"{"__wasmnest_error__":true,"code":"com.wasmnest.demo.simple"}"#,
        );
        let AppError::UserFacing { params, .. } = err else {
            panic!("应为 UserFacing")
        };
        assert_eq!(params, serde_json::Value::Null);
    }

    /// 反例：普通错误字符串（未标记）→ 兜底码 + plugin 标识参数，原文只进 detail
    #[test]
    fn plain_error_falls_back_to_host_internal() {
        let err = plugin_command_error(
            "com.wasmnest.legacy",
            "old.cmd",
            "database locked at path /secret/db",
        );
        let AppError::UserFacing {
            code,
            params,
            detail,
        } = err
        else {
            panic!("应为 UserFacing")
        };
        assert_eq!(code, crate::system::error::DEFAULT_ERROR_CODE);
        assert_eq!(
            params,
            serde_json::json!({ "plugin": "com.wasmnest.legacy" })
        );
        assert!(
            detail.contains("database locked"),
            "detail 只进日志: {detail}"
        );
    }

    /// 反例：畸形标记（marker 非 true / code 非字符串 / 非法 JSON）→ 兜底
    #[test]
    fn malformed_marker_falls_back_to_host_internal() {
        for raw in [
            r#"{"__wasmnest_error__":false,"code":"x"}"#,
            r#"{"__wasmnest_error__":true,"code":123}"#,
            r#"{"__wasmnest_error__":true}"#,
            r#"not json at all"#,
            r#"{"code":"x"}"#,
        ] {
            assert!(
                parse_business_marker(raw).is_none(),
                "畸形标记应当拒绝: {raw}"
            );
        }
    }

    /// 正例：parse_business_marker 形状矩阵（合法输入全部透传）
    #[test]
    fn parse_business_marker_accepts_valid_shapes() {
        assert_eq!(
            parse_business_marker(r#"{"__wasmnest_error__":true,"code":"a.b.c","params":{}}"#),
            Some(("a.b.c".to_string(), serde_json::json!({})))
        );
        assert!(
            parse_business_marker(r#"{"__wasmnest_error__":true,"code":"a.b","params":null}"#)
                .is_some()
        );
        assert!(
            parse_business_marker(r#"{"__wasmnest_error__":true,"code":"a.b","extra":1}"#)
                .is_some(),
            "额外字段应忽略"
        );
    }

    /// 机制码：未激活 → host.plugin.not-activated；Display 语义保持（既有断言兼容）
    #[tokio::test]
    async fn invoke_rust_command_mechanism_codes_are_user_facing() {
        let host = test_plugin_host().await;
        let err = host
            .invoke_rust_command("com.wasmnest.nonexistent", "foo", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not activated"), "实际: {err}");
    }
}
