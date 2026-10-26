//! `plugin_binding` 的单元测试入口（用例按功能拆至 `tests/`）
//!
//! 迁移说明（wasm-core-lib-split 票 06）：本组用例自宿主 host_api 域的 http
//! 实现文件逐条迁入。宿主上下文（权限管理器 + 出站授权记录库 + AppHandle）
//! 换成本 crate 内的假端口（见 [`scaffold`］），被断言的行为契约逐条保留：
//! 声明门 / 出站授权门的位置与错误分类 / 凭据红线 / 响应体上限 / 跳转裁决
//! （SSRF 闸门）/ 私网判定 / SSE 通用切分 / 端点属主仲裁 / 回收只碰本人。

use super::*;

mod egress_gates;
mod inbound;
mod scaffold;
mod sse_split;
mod ssrf_gate;
mod streaming;
