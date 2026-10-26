//! host-peer 能力域的 wire 契约词汇（自持副本）
//!
//! ## 为什么自持（能力域脱绑 P4，2026-10-08）
//!
//! 能力域默认形态 = 纯引擎机制 + 端口抽象（零 WIT 依赖），任何宿主（桌面 / 移动端 /
//! 无头测试宿主）可直接引用。本 crate 原先直连桌面 SDK（`wasmnest-plugin-api`）的
//! 权限位判据字符串因此改为**本域自持副本**：权限门的判据是宿主安全闸门与能力域
//! 之间的 wire 契约，漂移会让插件声明 `peer` 却匹配不上宿主权限位。
//!
//! 桌面 SDK 原常量**不删除**（插件侧 manifest / WIT 契约面仍有消费方），副本与
//! 原版逐字一致由平台仓漂移锁钉死（三仓拆分 L2/E2b 票 08 迁出本 crate：
//! `cross-end-tests/tests/wire_drift_locks.rs`）：任一侧漂移即红。
//!
//! 注意：本模块定义块的注释与桌面 SDK **逐字一致**（漂移锁按文本块比对），
//! 本地说明一律写在本模块文档里，不要改动定义块内注释。
//!
//! ## 引擎面 SDK 类型引用（P4 proc 记录，已随 P5 收口清零）
//!
//! - `lib.rs` 的 `impl wasmnest_server_base::ports::BusMessageHandler` 原引用
//!   `&wasmnest_plugin_api::BusMessage`；P5「server-base 常量下沉」后 base trait
//!   签名收 `wasmnest_server_base::wire::BusMessage`（base 自持副本，形状由
//!   base 侧漂移锁钉死），本 crate 的 `wasmnest-plugin-api` 依赖已随之移除——
//!   引擎面零桌面 SDK 直接依赖。

/// 权限位：`peer`（与桌面 SDK `wasmnest_plugin_api::permission` 逐字一致）
pub const PERMISSION_PEER: &str = "peer";
