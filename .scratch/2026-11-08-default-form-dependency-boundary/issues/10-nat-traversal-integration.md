# 10: 穿透分支整合：合流到含 P0 的 dev 并重跑验证矩阵

**What to build:** `feat/nat-traversal`（T01/T02、T03、T04、T05 已提交）合流到含 P0 的 dev：解决已知 3 处内容冲突（链路加密、HTTP 过滤器、WS 路由）与 17 个提交的漂移（WIT 拆包、链路加密演进），保留 P0 的错误映射与穿透的面标记判据；穿透验证矩阵在 P0 后的依赖面上全绿。

**Blocked by:** 07

**Status:** done (2026-11-08)

- [x] 合流到 dev；3 处已知内容冲突解决，语义同时保留 P0 的链路加密错误映射与穿透的面标记 / 不变量 15 判据。
- [x] 17 个提交的漂移对齐（WIT 按能力域拆包、链路加密策略演进），无静默回退。
- [x] T03 / T04 / T05 验证矩阵全绿：不变量 15 三条测试锁、隧道 40 条、relay 45 条、四个受影响 crate `cargo test --offline`。
- [x] 穿透功能在 P0 后的依赖面上仍成立：peer face、隧道、relay 无回归。
- [x] 合流完成后通知 P0 发版（本票由穿透项目负责）。

**实施记录（2026-11-08）**：实际合流线为 `feat/nat-traversal-v2`（活线），合流提交 `4851a35`；内容冲突 **2 处**（`link_crypto` 测试块、`p2p-engine` 清单）——v2 基线已自带 http/ws 面标记演进，故不是 v1 口径的 3 处。v1（`feat/nat-traversal`，`974c813`）经符号/WIT/行为三级核对确认被 v2 覆盖后删除。隧道测试 94 条、peer-net 236（common-host,relay 237）、p2p-engine 42（relay 45）。
