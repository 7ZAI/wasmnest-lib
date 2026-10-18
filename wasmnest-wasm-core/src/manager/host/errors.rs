//! `errors` — PluginHost 职责面拆分（P2）
//!
//! 自 `host.rs` 主 impl 拆出；经 `use super::*` 继承 host 模块的
//! 全部导入与常量，方法与字段可见性规则与内联时一致。

use super::*;
use crate::system::error::EventEnvelope;

/// 插件运行时异常语义码（trap / panic 合并，ADR 0030 注册表 v0）
pub const PLUGIN_TRAP_CODE: &str = "host.plugin.trap";
/// 自动恢复失败语义码（插件进入 Error 态）
pub const PLUGIN_RECOVERY_FAILED_CODE: &str = "host.plugin.recovery-failed";
/// 插件自检失败语义码（插件主动上报，如 hooks 脚本拷贝失败）
pub const PLUGIN_SELF_CHECK_FAILED_CODE: &str = "host.plugin.self-check-failed";

/// 运行时异常 `kind` → 语义码（ADR 0030 决定 7）
///
/// `panic` 与 `trap` 对用户是同一件事（应用异常退出、宿主已尝试自动重载），合并为
/// 同一码；未知 kind 落兜底 `host.internal`——宁可通用文案，不臆造语义。
pub fn runtime_error_code(kind: &str) -> &'static str {
    match kind {
        "panic" | "trap" => PLUGIN_TRAP_CODE,
        "recovery_failed" => PLUGIN_RECOVERY_FAILED_CODE,
        _ => crate::system::error::DEFAULT_ERROR_CODE,
    }
}

/// 运行时异常事件信封（纯函数：形状可独立回归测试，调用方不接触详情）
///
/// `params.name` 是 manifest 显示名——用户面唯一允许出现的应用标识。
pub fn runtime_error_envelope(plugin_name: &str, kind: &str) -> EventEnvelope {
    EventEnvelope::new(runtime_error_code(kind), serde_json::json!({ "name": plugin_name }))
}

/// 自检失败事件信封（纯函数，同上）
pub fn self_check_envelope(plugin_name: &str) -> EventEnvelope {
    EventEnvelope::new(
        PLUGIN_SELF_CHECK_FAILED_CODE,
        serde_json::json!({ "plugin": plugin_name }),
    )
}

impl PluginHost {
    /// 标记插件为错误状态
    ///
    /// `error` 是**宿主侧诊断事实**（故障分类、失败原因），按 ADR 0030 决定 11
    /// 不得被 UI 渲染——用户面只出徽标 + 通用文案，技术详情走本函数调用点的日志。
    pub async fn mark_error(&self, plugin_id: &str, error: String) {
        let mut plugins = self.plugins.write().await;
        if let Some(loaded) = plugins.get_mut(plugin_id) {
            loaded.state = PluginState::Error { error };
        }
    }

    /// 插件展示名（manifest.name），查不到时退回插件 ID
    ///
    /// 用户可见文案的插值参数来源：只允许显示名这类**已消毒**值进 params。
    pub async fn display_name(&self, plugin_id: &str) -> String {
        let plugins = self.plugins.read().await;
        plugins
            .get(plugin_id)
            .map(|p| p.manifest.name.clone())
            .unwrap_or_else(|| plugin_id.to_string())
    }

    /// 插件运行时异常统一上报前端（全局异常通道，`PLUGIN_RUNTIME_ERROR`）
    ///
    /// 宿主检测到插件异常（非插件主动上报）时调用，覆盖三类场景：
    /// - `panic`：宿主函数 panic 穿透 wasmtime（catch_unwind 兜底，Store 已污染）
    /// - `trap`：wasm trap / 导出绑定失败 / store 中毒（已调度自动重载）
    /// - `recovery_failed`：自动重载失败，插件进入 Error 态
    ///
    /// 载荷是错误信封 `{ code, request_id, params: { name } }`（ADR 0030 决定 7），
    /// 语义码由 [`runtime_error_code`] 映射；全量错误（panic 消息 / 回溯 / 错误链）
    /// **只进日志**，与信封的 `request_id` 同条带出（日志始终记录，重载循环期间不丢现场）。
    ///
    /// 前端 toast 按插件节流（见 [`PLUGIN_RUNTIME_ERROR_NOTIFY_INTERVAL_SECS`]），
    /// 连发异常只弹一次，避免 trap 重载风暴刷屏。无 AppContext（测试/无头）时
    /// 降级为纯日志，不 panic。
    pub async fn notify_plugin_runtime_error(&self, plugin_id: &str, kind: &str, error: &str) {
        let envelope = runtime_error_envelope(&self.display_name(plugin_id).await, kind);

        // 日志始终记录（调用方也各自记日志，此处为统一通道的兜底记录）
        tracing::error!(
            plugin_id = %plugin_id,
            kind = %kind,
            request_id = %envelope.request_id,
            error = %error,
            "Plugin runtime error (unified channel)"
        );

        // 节流：同一插件窗口内已提示过则跳过 toast（日志不受影响）；
        // recovery_failed 不节流——它每次重载失败只发一次（重载循环 30s 间隔），
        // 若落在 trap 通知的 15s 窗口内会被吞，用户看到「已恢复」实际进入 Error 态
        if kind != "recovery_failed" {
            let mut throttle = self
                .runtime_error_notify_throttle
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(last) = throttle.get(plugin_id) {
                if last.elapsed() < std::time::Duration::from_secs(PLUGIN_RUNTIME_ERROR_NOTIFY_INTERVAL_SECS) {
                    tracing::debug!(
                        plugin_id = %plugin_id,
                        kind = %kind,
                        "plugin runtime error toast throttled (recent notification)"
                    );
                    return;
                }
            }
            throttle.insert(plugin_id.to_string(), std::time::Instant::now());
        }

        // 无头/测试上下文无 AppHandle：降级为纯日志（整核抽出：直接取
        // `self.wasm_host_ctx().app_handle()`，不再经 lib `AppContext::try_global()`）
        let Some(handle) = self.wasm_host_ctx().app_handle() else {
            return;
        };
        if let Err(e) = handle.emit(crate::system::constants::PLUGIN_RUNTIME_ERROR, envelope.payload()) {
            // 前端事件派发失败不致命：日志已全量记录，仅提示通道中断
            tracing::warn!(
                plugin_id = %plugin_id,
                "Failed to emit PLUGIN_RUNTIME_ERROR to frontend: {}",
                e
            );
        }
    }

    /// 插件自检失败上报（`PLUGIN_ERROR` 通道）
    ///
    /// 语义与 [`Self::mark_error`] 相反：**不改插件状态、不持久化**，插件保持激活、
    /// 会话照常运行（hooks 安装失败等自检错误属可恢复/局部问题，不应禁用整个应用）。
    /// 载荷同样是信封 `{ code, request_id, params: { plugin } }`，详情只进日志。
    pub async fn notify_plugin_self_check_error(&self, plugin_id: &str, error: &str) {
        let envelope = self_check_envelope(&self.display_name(plugin_id).await);
        tracing::error!(
            plugin_id = %plugin_id,
            request_id = %envelope.request_id,
            error = %error,
            "[PluginHost] Plugin self-check failed"
        );

        // 无头/测试上下文无 AppHandle：跳过前端提示（纯日志）
        let Some(handle) = self.wasm_host_ctx().app_handle() else {
            return;
        };
        if let Err(e) = handle.emit(crate::system::constants::PLUGIN_ERROR, envelope.payload()) {
            tracing::warn!(
                plugin_id = %plugin_id,
                "Failed to emit PLUGIN_ERROR to frontend: {}",
                e
            );
        }
    }
}
