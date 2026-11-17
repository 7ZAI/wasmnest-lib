//! wasmnest-server-core：服务器内核层
//!
//! **跨传输**的引擎与共享面：生命周期（`supervisor`）、跨传输流量过滤器链
//! （`filter`）、链路加密（`link_crypto`）、指标（`metrics`）、组合装配
//! （`app`：`TransportFace` + `serve`）。
//!
//! **「跨传输」不等于「传输无关」（显式记录）**：本 crate 的默认
//! 依赖树**含 actix**（`serve` / `app` 的组合运行时）与 `rusqlite`（`link_crypto`
//! 的 app policy 持久化）。它对 http / ws 是共享的、可依赖倒置的，但不属「宿主无关
//! 默认形态」——真正的拆分（`serve` 归组合根、`link_crypto` 的宿主职责归位）
//! 不在此承诺内。
//!
//! 依赖方向（crate 边界不变量）：http / ws 面只**向下**依赖本 crate，
//! 彼此之间零横向 import；本 crate 不反向引用任何传输面——组合经
//! [`app::TransportFace`] 依赖倒置（宿主壳装配 faces 注入）。
//!
//! 迁移时对职责边界的两处裁决：
//! - `port_checker` 未随迁（留在宿主 `server/host_port.rs`）：其主体是配置
//!   文件读写（`AppConfig::load/save`）+ 用户选择端口 UI 弹窗
//!   （`tauri_plugin_dialog`），纯宿主交互，不是引擎原语；纯端口扫描逻辑
//!   （`find_next_available_port`）仍留宿主同文件（164 行整体保持宿主侧）。
//! - `link_crypto` 的 DB 读写改 `&rusqlite::Connection`（宿主 `Database` 是
//!   宿主类型，经 `Database::conn()` 暴露）；`init_at_startup` /
//!   `ensure_identity_fingerprint` 改收 `&Path`（宿主壳解析数据目录后传入）。

pub mod app;
pub mod filter;
pub mod link_crypto;
pub mod metrics;
/// `net.transport` 应用作用域服务（supervisor 生命周期的租约适配）
pub mod service;
pub mod supervisor;

pub use app::{serve, TransportFace};
