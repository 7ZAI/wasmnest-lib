//! `plugin_binding` 的用例分组（票 05：自宿主 host_api 域的 peer 适配器迁入）
//!
//! 分组对应四类被锁行为：权限门与判定顺序（`gates`）、句柄表与属主仲裁
//! （`handle_table`）、载荷契约与 fail-visible（`payload_contract`）、暂停/恢复
//! 的方向路由（`pause_resume_routing`——单一原语管双向的 miss 回退顺序）。
//!
//! 宿主上下文（权限管理器 + `AppHandle`）换成本 crate 内的假端口（见
//! [`scaffold`]），被断言的行为契约（权限门 / 属主仲裁 / 判定顺序 / 退役字段
//! 检测 / 无头口径）逐字保留。

use super::*;
mod gates;
mod handle_table;
mod pause_resume_routing;
mod payload_contract;
mod scaffold;
