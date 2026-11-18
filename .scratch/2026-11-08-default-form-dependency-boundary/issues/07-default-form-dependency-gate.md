# 07: 默认形态依赖门禁上线（CI + 本地脚本）

**What to build:** 7 个声明「宿主无关」的 crate 的正常依赖树禁止出现宿主框架、bundled SQLite、系统信息采集与文件监听；门禁在 PR 上运行，失败时打印反向依赖路径，直接指出是哪条边引入；CI 不再为测试安装只服务 Tauri 的系统包。

**Blocked by:** 02、03、04、05、06

**Status:** done (2026-11-08)

- [x] 门禁覆盖 `wasmnest-server-base` / `-crypto-engine` / `-cli-engine` / `-pty-engine` / `-discovery-engine` / `-ws-client-engine` / `-p2p-engine`，正常依赖树禁止 `tauri` / `actix` / `rusqlite` / `sysinfo` / `notify` / `inotify`。
- [x] 失败输出包含违规 crate 与 `cargo tree -i` 反向依赖路径。
- [x] 本地与 CI 同一判据；本地仓库路径含 `tauriProject` 时不假红（按 crate 名 token 精确匹配，不用裸 grep）。
- [x] CI 新增门禁步骤；删除仅为 Tauri 测试安装的系统包；CI 注释与 crate 计数按实际树更新。
- [x] 无头探针既有门禁（wasmtime / wit-bindgen / inventory / host-kit）并存且仍绿；门禁对 7 个 crate 全绿。

**实施记录（2026-11-08）**：`sh scripts/check-default-form-deps.sh --offline` 7 crate 全绿；CI job `default-form-deps`（含逐 crate `cargo fetch`）已上线，`webkit2gtk` 等 apt 步骤已删。
