//! `host-plugin-database` 的用例入口（宿主 `wasm_core` 内）
//!
//! 分组：权限门（`db_faces`）· 执行护栏（`db_guards`）· 事务批次（`db_batch`）。
//!
//! **2026-10-09 双端机制决策**：主库面（`host-database`）退役（主库由 wasm-core
//! 管理、不给插件直接调用），`db_isolation`（主库 authorizer 纵深）与 `sql_parse`
//! （主库前缀校验）随机制退役删除——插件数据库能力 = 插件私有库
//! （`host-plugin-database`，`storage` 位）。
//!
//! 用例文件经 `use crate::host_api::sqlite_scaffold::*` 取假端口（跨分组
//! 共享脚手架，见该文件模块头）；`host-storage` 的 kv 用例在 `super::super::storage::tests`。

mod db_batch;
mod db_faces;
mod db_guards;
