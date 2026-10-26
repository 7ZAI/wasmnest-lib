//! Config DTOs
//!
//! 跨端 wire 黄金样本（路由真身已在插件侧，ABI v29）。仅供 `#[cfg(test)]` 形状锁
//! 与 `wasmnest-wasm-core` 的跨 crate 黄金比对使用，生产路径不构造。
//!
//! 曾有一行 `pub use crate::dtos::file_dto::{FileTreeNode, FileTreeRequest,
//! FileTreeResponseData};`（单文件 DTO 时代的转发），全仓零消费者——它同时是
//! 「配置域模块转出文件浏览域类型」的坏内聚，以及 `file_dto` 无法整组门控的阻碍，
//! 故随本轮清理删除。

use serde::Serialize;

/// GET /api/configs response data
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigListResponseData {
    pub configs: Vec<ConfigItem>,
}

/// Single config item
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigItem {
    pub id: String,
    pub name: String,
    pub environment: String,
    pub wsl_distro: Option<String>,
    pub working_dir: String,
    pub command: String,
}

/// GET /api/quick-actions response data
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickActionListResponseData {
    pub actions: Vec<QuickActionItem>,
}

/// Quick action item
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickActionItem {
    pub id: String,
    pub name: String,
    pub content: String,
    pub icon: Option<String>,
    pub color: Option<String>,
}
