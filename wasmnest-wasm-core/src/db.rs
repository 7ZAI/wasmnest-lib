//! Database module
//!
//! 数据库模块 - 连接管理、数据模型和 CRUD 操作
//!
//! **归属纪律（ADR 0036）**：本模块是宿主主库的**引擎面**——连接管理、`schema.sql`
//! （主库 schema 单一事实源，AGENTS §9）、幂等迁移、模型与设置项查询。SQLite 方言与
//! 文件格式属应用层（WASI 预览 3 无此物），故引擎面必须整体出宿主；但**机制面**
//! （`host-database` / `host-plugin-database` / `host-storage` 三个 interface 的权限门、
//! 表名前缀纵深、护栏与属主分区）留在 `crate::host_api`，与机制真源同处一
//! 侧——`bedcode-sqlite-engine` 能力域 crate 已整体撤销（2026-10-04 拆分）。

mod database;
mod models;
mod operations;

pub use database::Database;
pub use models::Setting;
