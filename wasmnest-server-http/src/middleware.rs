//! Server Middleware
//!
//! HTTP 中间件 - CORS、认证闸门与流量过滤器责任链接线

pub mod auth_gateway;
pub mod http_filter;
/// 请求完成事件的秒级聚合计数（成功完成日志降为 trace 后的可见性兜底）
pub mod http_stats;
