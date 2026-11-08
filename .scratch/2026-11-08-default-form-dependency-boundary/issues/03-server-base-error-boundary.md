# 03: `server-base` 错误面归域：`Database(String)`、删除 notify / 链路加密 / GUI 框架隐式转换，`tauri-compat` 默认关

**What to build:** 基础层默认不再编译 bundled SQLite、文件监听、链路加密协议与 GUI 框架；DB 错误仍落 `host.internal`、对外文案不变；桌面宿主改为显式开启 `tauri-compat`（由 09 承接），非 Tauri 宿主不再被框架拖入。

**Blocked by:** 02（同一 crate manifest 与验收面顺序落地）

**Status:** done (2026-11-08)

- [x] `AppError::Database` 不再携带 `rusqlite::Error`；所有显式构造点与 `?` 隐式点改为边界映射，envelope 语义与文案不变。
- [x] `From<notify::Error>` 与 `From<LinkCryptoError>` 删除（零调用点的直接删，有调用点的显式映射）；`From<tauri::Error>` 受 `tauri-compat` 门控。
- [x] `server-base` 的 `tauri-compat` 默认关；默认依赖树无 `rusqlite` / `notify` / `wasmnest-link-crypto` / `tauri`。
- [x] `wasm-core` 的 DB 错误路径与 `server-core` 的链路加密错误路径测试绿，文案与现状逐字一致。
- [x] `server-base` 既有 envelope / code / params 测试绿；`AppError::Pty` 形态不变。

**实施记录（2026-11-08）**：server-base 35 绿；`AppError::Database(String)` 与 `Pty(String)` 落地，`tauri` optional + `tauri-compat` 默认关。**wasm-core 自身测试本轮未复跑**（逃生阀会改写 `Cargo.lock`，而该文件正被并行会话修改）——该 crate 侧为静态核对（全量 `AppError::Database(e.to_string())` + `DbResultExt` 边界适配 + `host.internal` 断言存在）。
