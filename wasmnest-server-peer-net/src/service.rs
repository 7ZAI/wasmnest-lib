//! `net.peer-node` 应用作用域服务（service-leases spec §3.4）
//!
//! 把对等网络节点的生命周期映射到
//! [`wasmnest_server_base::service::ScopedService`]：0→1 装配节点监听 +
//! `_wasmnest-peer._tcp` 广播 + host service 登记，1→0 排水连接 / 退订 browse /
//! 注销广播。引用记账（多应用共享、最后引用关停）在注册表模板里。
//!
//! 键由本 crate 导出，宿主只 import 常量，不另写字符串。

use std::sync::Arc;

use async_trait::async_trait;
use wasmnest_server_base::service::{ScopedService, ServiceError, ServiceRegistry};

use crate::PeerCtx;

/// 对等网络节点服务键（机制词汇）
pub const PEER_NODE_SERVICE_KEY: &str = "net.peer-node";

/// 节点服务实现：只做「怎么起、怎么停」。
pub struct PeerNodeService {
    ctx: Arc<PeerCtx>,
}

impl PeerNodeService {
    pub fn new(ctx: Arc<PeerCtx>) -> Self {
        Self { ctx }
    }

    /// 注册到给定注册表（宿主装配点）
    pub fn register(registry: &ServiceRegistry, ctx: Arc<PeerCtx>) -> Result<(), ServiceError> {
        registry.register(Arc::new(Self::new(ctx)))
    }
}

#[async_trait]
impl ScopedService for PeerNodeService {
    fn key(&self) -> &str {
        PEER_NODE_SERVICE_KEY
    }

    async fn start(&self) -> Result<(), String> {
        // start_peer_node 自带幂等（已运行返回现状）并解析数据目录 / 设备名
        crate::start_peer_node(self.ctx.clone())
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn stop(&self) -> Result<(), String> {
        // stop_locked 对「未运行」幂等返回 Ok
        crate::stop_peer_node(self.ctx.clone()).await.map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 服务键必须是机制词汇（前缀 = 机制域，后缀 = 调用方身份或无）
    ///
    /// per-app 实例后键可能形如 `"net.peer-node:com.wasmnest.file-transfer"`，
    /// 但前缀段（`:` 前）必须是机制词汇，不得直接是产品名。
    #[test]
    fn key_is_mechanism_vocabulary() {
        assert_eq!(PEER_NODE_SERVICE_KEY, "net.peer-node");
        let prefix = PEER_NODE_SERVICE_KEY.split(':').next().unwrap();
        let domain = prefix.split('.').next().unwrap();
        let allowed_domains = ["net", "io", "compute", "storage"];
        assert!(
            allowed_domains.contains(&domain),
            "服务键前缀必须是机制域词汇 ({allowed_domains:?})，实际: {domain:?}"
        );
        // 动态键不得把产品名词硬编码进本模块（交由注册表按调用方拼装）
        let source = include_str!("service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in ["file-transfer", "bedcode", "com.wasmnest", "FILE_TRANSFER"] {
            assert!(
                !production.contains(forbidden),
                "节点服务模块不得出现产品名词：{forbidden}"
            );
        }
    }
}
