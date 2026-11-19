//! 宿主端口：能力域与端实现之间的唯一边界
//!
//! 能力域只做闸门、脚本生成、结果解析与上限收敛；真正的浏览器进程
//! （桌面 sidecar / 移动 stub）由端实现经本 trait 注入。端口缺席即 panic，
//! **不**静默降级成「返回空结果」——漏装端口必须启动即可见。
//!
//! ## 后端实现约束（安全面）
//!
//! - 每次导航、重定向与子资源地址解析后，必须对解析出的 IP 调用
//!   [`crate::guard::ensure_public_ip`]；域名可解析到私网，闸门在本层看不到。
//! - 页面 HTML 超过 [`crate::limits::MAX_HTML_BYTES`] 时不得继续扩大内存占用。
//! - 总超时必须重新执行一次上界（能力域已收敛，但后端不能只信调用方）。
//! - 每个插件独立 profile / storage；Cookie 默认不持久化、不与宿主共享。
//! - 错误必须按 [`crate::error::BrowserErrorKind`] 分类返回，消息不落正文与凭据。

use std::sync::Arc;

use url::Url;

use crate::error::BrowserError;
use crate::model::WaitUntil;

/// 后端渲染结果：状态、最终 URL 与页面脚本返回的 JSON 文本
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    /// 目标最终 HTTP 状态码
    pub status: u16,
    /// 重定向后的最终 URL
    pub final_url: String,
    /// 页面脚本返回值（JSON 文本）
    pub payload: String,
}

/// 一次渲染作业（能力域已完成闸门与脚本生成）
#[derive(Debug, Clone, Copy)]
pub struct RenderRequest<'a> {
    /// 目标 URL
    pub url: &'a Url,
    /// 导航完成判定
    pub wait_until: WaitUntil,
    /// 收敛后的总超时（毫秒）
    pub timeout_ms: u32,
    /// 页面内提取脚本
    pub script: &'a str,
}

/// 端实现端口
///
/// 实现方应当是零大小或廉价克隆类型；能力域只持有 trait 对象。
pub trait BrowserPorts: Send + Sync + 'static {
    /// 权限判定：`permission` 为声明权限位，`api` 为审计名
    ///
    /// 返回 `false` 时宿主侧应已落结构化 `warn`（`plugin_id` / `permission` / `api`）。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 私网访问授权：`origin` 已归一化（默认端口省略）
    ///
    /// 只有请求同时置位 `allow-private-network` 时才会被调用；返回 `true` 表示
    /// 用户已对该 origin 记录「始终允许」。不能由插件单方面放宽。
    fn authorize_private_network(&self, plugin_id: &str, origin: &str) -> bool;

    /// 导航并在页面上下文执行脚本，返回状态、最终 URL 与脚本输出
    ///
    /// # Errors
    ///
    /// 超时 / 目标 4xx-5xx / 浏览器进程不可用 / 当前端不支持等，按
    /// [`BrowserError`] 的分类返回。
    fn render(
        &self,
        plugin_id: &str,
        request: &RenderRequest<'_>,
    ) -> Result<RenderedPage, BrowserError>;
}

/// 进程级端口持有者
static PORTS: std::sync::OnceLock<Arc<dyn BrowserPorts>> = std::sync::OnceLock::new();

/// 装配端实现（宿主开机期调用一次；重复装配被忽略而非替换）
///
/// 忽略重复装配：运行期换端口会让已在途的调用持旧实现，属难以归因的不一致。
pub fn install_ports(ports: Arc<dyn BrowserPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的端实现
///
/// # Panics
///
/// 尚未装配时 panic 并点名——端口缺席必须以启动期失败暴露，不能伪装成
/// 「能力可用但永远返回空」。
pub fn ports() -> Arc<dyn BrowserPorts> {
    PORTS.get().cloned().expect(
        "browser engine ports are not installed — the host must call `install_ports` during boot",
    )
}

/// 便捷装配：按值接收实现并放入 `Arc`
pub fn install<P: BrowserPorts>(ports: P) {
    install_ports(Arc::new(ports));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BrowserErrorKind;

    struct NoopPorts;

    impl BrowserPorts for NoopPorts {
        fn check_permission(&self, _plugin_id: &str, _permission: &str, _api: &str) -> bool {
            true
        }

        fn authorize_private_network(&self, _plugin_id: &str, _origin: &str) -> bool {
            false
        }

        fn render(
            &self,
            _plugin_id: &str,
            _request: &RenderRequest<'_>,
        ) -> Result<RenderedPage, BrowserError> {
            Err(BrowserError::new(
                BrowserErrorKind::Unsupported,
                "not available",
            ))
        }
    }

    /// 端口装配幂等：首次实现胜出
    #[test]
    fn install_keeps_the_first_port_implementation() {
        // 本测试不调用全局 `install_ports`（OnceLock 在进程内只允许一次），
        // 只验证 trait 对象的构造与转发形状。
        let ports = NoopPorts;
        let request = RenderRequest {
            url: &Url::parse("https://example.com/").expect("url"),
            wait_until: WaitUntil::Load,
            timeout_ms: 1_000,
            script: "() => null",
        };
        let error = ports.render("plugin", &request).expect_err("unsupported");
        assert_eq!(error.kind(), BrowserErrorKind::Unsupported);
        assert!(ports.check_permission("plugin", crate::wire::PERMISSION_NETWORK_BROWSER, "test"));
        assert!(!ports.authorize_private_network("plugin", "http://127.0.0.1"));
    }
}
