//! `net.tunnel` 应用作用域服务（T06 / service-leases §3.4 同款模板）。
//!
//! 把隧道管理器的生命周期映射到 [`ScopedService`]：0→1 启动对等网络节点与入站流
//! 接收器，1→0 停对等面 / 中止接收器 / 释放 reservation / 清空状态。
//!
//! **引用记账只在注册表模板里**：`expose` / `connect` 等原语按插件 acquire，最后
//! 一个引用释放时才真正关停；管理器内部**不再**维护第二套服务生命周期。
//!
//! 对等 HTTP/WS 面由宿主注入的 `PeerFaceStarter` 在第一次 `expose` 时启动，不参与
//! 本服务的 0→1 判定（移动端可以不提供）。

use std::sync::Arc;

use async_trait::async_trait;
use wasmnest_server_base::service::{ScopedService, ServiceError, ServiceRegistry};

use crate::tunnel::manager::TunnelManager;

/// 隧道服务键（机制词汇；宿主只 import 常量，不另写字符串）
pub const NET_TUNNEL_SERVICE_KEY: &str = "net.tunnel";

pub struct TunnelService {
    manager: Arc<TunnelManager>,
}

impl TunnelService {
    pub fn new(manager: Arc<TunnelManager>) -> Self {
        Self { manager }
    }

    /// 注册到给定注册表（宿主装配点，必须早于任何插件激活）
    pub fn register(registry: &ServiceRegistry, manager: Arc<TunnelManager>) -> Result<(), ServiceError> {
        registry.register(Arc::new(Self::new(manager)))
    }
}

#[async_trait]
impl ScopedService for TunnelService {
    fn key(&self) -> &str {
        NET_TUNNEL_SERVICE_KEY
    }

    async fn start(&self) -> Result<(), String> {
        self.manager.start().await.map_err(|e| e.as_wire_error())
    }

    async fn stop(&self) -> Result<(), String> {
        self.manager.stop().await.map_err(|e| e.as_wire_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 服务键必须是机制词汇（前缀 = 机制域）
    #[test]
    fn key_is_mechanism_vocabulary() {
        assert_eq!(NET_TUNNEL_SERVICE_KEY, "net.tunnel");
        let prefix = NET_TUNNEL_SERVICE_KEY.split(':').next().unwrap();
        let domain = prefix.split('.').next().unwrap();
        assert!(["net", "io", "compute", "storage"].contains(&domain));
        let source = include_str!("service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in ["bedcode", "file-transfer", "com.wasmnest"] {
            assert!(
                !production.contains(forbidden),
                "隧道服务模块不得出现产品名词：{forbidden}"
            );
        }
    }
}
