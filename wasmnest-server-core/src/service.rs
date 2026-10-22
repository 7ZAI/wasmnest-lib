//! `net.transport` 应用作用域服务（service-leases spec §3.4）
//!
//! 把 [`ServerSupervisor`] 的生命周期映射到
//! [`wasmnest_server_base::service::ScopedService`]：0→1 启动 Actix（WS + HTTP
//! 同一端口）+ mDNS 广播 + 防休眠 + 指标采样，1→0 全部关停。
//!
//! 键由本 crate 导出，宿主只 import 常量，不另写字符串。

use std::sync::Arc;

use async_trait::async_trait;
use wasmnest_server_base::service::{ScopedService, ServiceError, ServiceRegistry};

use crate::supervisor::ServerSupervisor;

/// 传输面服务键（机制词汇：WS + HTTP 单端口 + mDNS 广播 + 防休眠 + 指标采样）
pub const TRANSPORT_SERVICE_KEY: &str = "net.transport";

/// 传输面服务实现：只做「怎么起、怎么停」，记账在注册表模板里。
pub struct TransportService {
    supervisor: ServerSupervisor,
}

impl TransportService {
    /// 绑定一个 supervisor 实例（测试隔离用；生产用 [`Self::from_global`]）
    pub fn new(supervisor: ServerSupervisor) -> Self {
        Self { supervisor }
    }

    /// 绑定全局 supervisor（状态与 `get_server_status` 等命令面同源）
    pub fn from_global() -> Self {
        Self::new(ServerSupervisor::global().handle())
    }

    /// 注册到给定注册表（宿主装配点唯一）
    pub fn register_global(registry: &ServiceRegistry) -> Result<(), ServiceError> {
        registry.register(Arc::new(Self::from_global()))
    }
}

#[async_trait]
impl ScopedService for TransportService {
    fn key(&self) -> &'static str {
        TRANSPORT_SERVICE_KEY
    }

    async fn start(&self) -> Result<(), String> {
        // 端口以 supervisor 当前配置为准（用户改端口后无需重建服务）
        let port = self.supervisor.get_status_info().await.port;
        self.supervisor.start(port).await.map_err(|e| e.to_string())
    }

    async fn stop(&self) -> Result<(), String> {
        self.supervisor.stop().await.map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_mechanism_vocabulary() {
        assert_eq!(TRANSPORT_SERVICE_KEY, "net.transport");
        let source = include_str!("service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in ["file-transfer", "bedcode", "com.wasmnest", "FILE_TRANSFER"] {
            assert!(
                !production.contains(forbidden),
                "传输服务模块不得出现产品名词：{forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn start_failure_is_propagated_and_stop_is_idempotent() {
        // 未装配 server ports（无头）：start 必须显性失败，而不是假成功
        let service = TransportService::new(ServerSupervisor::new());
        let error = service.start().await.expect_err("no ports → start must fail");
        assert!(
            error.contains("server lifecycle port unavailable"),
            "错误必须点名缺少端口，实际: {error}"
        );

        // 未运行 stop → 幂等 Ok
        service.stop().await.expect("stop on stopped supervisor must be Ok");
    }
}
