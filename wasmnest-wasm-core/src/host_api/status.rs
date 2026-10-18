//! 插件状态域宿主实现
//!
//! 提供插件向宿主上报自身状态的能力。目前仅支持错误标记：
//! 插件检测到配置失败（如 hooks 脚本拷贝失败、settings.json 写入失败）时，
//! 通知宿主，宿主仅弹窗提示前端，不改插件状态。

use crate::runtime_util::block_on_async;

/// 标记插件为错误状态
///
/// 宿主仅 emit `plugin:error` 事件通知前端弹窗提示，不改变插件激活状态。
pub(crate) fn mark_plugin_error(
    svc: &dyn crate::host_api::context::ServicesScope,
    plugin_id: String,
    error: String,
) {
    block_on_async(async move {
        match svc.services().await {
            Some(services) => services.mark_plugin_error(plugin_id, error),
            None => tracing::error!("[PluginHost] mark_plugin_error: plugin services not initialized"),
        }
    });
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_api::tests::build_host_ctx;

    /// services 未注入时静默降级（记录 error 日志，不 panic）
    ///
    /// 成功路径依赖 PluginHost 注入的 services（前端弹窗通知），测试环境无
    /// PluginHost；函数返回 () 无错误通道，此处验证降级路径不崩溃即可
    #[tokio::test]
    async fn mark_plugin_error_services_not_ready_no_panic() {
        let ctx = build_host_ctx();
        mark_plugin_error(ctx.as_ref(), "test-plugin".to_string(), "boom".to_string());
    }
}
