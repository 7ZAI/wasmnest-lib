//! `host-storage` 域的用例入口（宿主 `wasm_core` 内）
//!
//! 分组：键值原语三态（`kv`）——权限门、系统空间 fail-closed 守卫、能力路由。
//!
//! 用例文件经 `use crate::host_api::sqlite_scaffold::*` 取假端口（与
//! `host-database` 两域共用同一份脚手架，见该文件模块头）。

mod kv;
