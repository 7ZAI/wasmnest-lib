//! WebSocket 传输面（server-lib-split 票 05）
//!
//! 连接骨架（`conn`）、插件端点通道（`channel`）、连接/端点注册表（`registry` /
//! `endpoint`）、生命周期与优雅停机（`websocket_manager`）与路由装配
//! （`routes`：`/ws/plugin/{plugin_id}/{path}` 通用插件端点 + 帧上限）。
//!
//! **终态（websocket 业务下沉票 08）**：本 crate 只剩通用传输能力——连接生命周期、
//! 认证策略、帧过滤、限流、端点/连接注册表与按属主回收；旧 `/ws/event` 与
//! `/ws/terminal/session/{id}` 业务路由、宿主 `Message` 业务枚举、会话/终端服务、
//! 输出订阅器与终端协议模块已整体删除（协议归 `com.wasmnest.bedcode` 插件，
//! 宿主只转原始 text/binary 帧）。
//!
//! 依赖方向：只**向下**依赖 `wasmnest-server-core`（过滤器链 / 链路加密 / 指标 /
//! 组合装配）与 `wasmnest-server-base`（错误 / 常量 / 端口 traits），与 HTTP 面
//! `wasmnest-server-http` 之间零横向依赖（I1）——两向都由 crate 依赖清单静态钉死
//! （见 `dependency_direction_lock`），本 crate 亦不依赖宿主 crate。
//!
//! **不依赖宿主类型**：需要宿主做的事全部经 `wasmnest_server_base::ports::get()` 取注入
//! 端口——`BusPort`（总线发布/订阅 + 插件端点帧投递）、`EventSink`（前端事件）、
//! `ConfigPort`（网络配置）、`RuntimePort`（ambient AppHandle）。服务器启动所需的
//! faces 由宿主组合根经 [`WebSocketManager::start`] 传入（本面不认识 HTTP 面）。
//!
//! 认证档位词汇 `EndpointAuth`、权限位 `ws:client` / `ws:server` 与 WS 状态事件
//! 名 / topic 构造为本 crate **自持副本**（[`wire`] 模块；能力域脱绑 P3：能力域
//! 默认形态零 WIT / 零桌面 SDK 依赖，任何宿主可直接引用）。副本与桌面 SDK 原版
//! 逐字一致由平台仓漂移锁 `cross-end-tests/tests/wire_drift_locks.rs` 钉死（漂移即红）。
//!
//! **插件绑定层（wasm-core-lib-split 票 04）**：[`plugin_binding`] 是本 crate 的
//! `host-websocket` 能力域——客户端域 WIT 接线（契约真源
//! `wasmnest-ws-client-engine/wit/ws.wit`，Q4 裁决）＋服务端/客户端引擎域函数，
//! 经 [`wasmnest_host_kit`] 的能力模块注册表自动装配（服务端 `host-websocket-server`
//! 的声明与 Host impl 已随 ADR 0052 D4 归桌面宿主 `plugin/ws.rs`）。宿主侧只剩一个
//! 端口 adapter 与一次开机装配调用，不再有该域的逐接口接线。

pub mod channel;
pub mod conn;
pub mod endpoint;
pub mod plugin_binding;
pub mod registry;
pub mod routes;
pub mod websocket_manager;
pub mod wire;

use actix_web::web;
use wasmnest_server_core::TransportFace;

pub use routes::configure_routes;
pub use websocket_manager::{ServerEvent, WebSocketManager};

/// WS 面：只装配路由
///
/// WS 没有 app 级中间件——帧级过滤在 `conn` 的收发点做（HTTP 面的 `TrafficFilter`
/// 对 WS 帧是透传的），故 [`TransportFace::wrap`] 走 trait 默认实现。
pub struct WebSocketTransportFace;

impl TransportFace for WebSocketTransportFace {
    fn configure(&self, cfg: &mut web::ServiceConfig) {
        crate::configure_routes(cfg);
    }
}

#[cfg(test)]
mod dependency_direction_lock;
