//! `plugin_binding` 的单元测试入口（用例按功能拆至 `tests/`）
//!
//! 迁移说明（wasm-core-lib-split 票 04）：本组用例自宿主
//! `src-tauri/src/wasm_core/host_api/ws.rs` 逐条迁入。宿主上下文（权限管理器 +
//! 消息总线）换成本 crate 内的假端口（见 [`scaffold`]），被断言的行为契约
//! （权限门 / 属主仲裁 / 队列背压 / 降级计数 / 端点限流 / 凭据红线）逐字保留。

use super::*;
mod connect_wss;
mod connection_context;
mod events_ws_fallback;
mod fail_visible;
mod isolation;
mod permission_gate;
mod reclaim;
mod scaffold;
mod server_domain;
mod was_clean;
