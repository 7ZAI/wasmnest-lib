# 02: 跨层常量上移契约仓，`server-base` 摘掉 `host-api-core` 依赖

**What to build:** `PLUGIN_DB_*` 四个跨层护栏常量住进零依赖契约仓；`server-base::constants` 与 `host-api-core::database` 两条旧路径继续可用；`server-base` 不再为 4 个常量依赖机制内核，向「叶子地基」迈出第一步。

**Blocked by:** None (can start immediately；与 01 同改 manifest 不同段，建议先 01 后 02 顺序执行)

**Status:** ready-for-agent

- [ ] 四个常量在 `wasmnest-contract` 定义，取值与现状逐字一致（120 / 10_000 / 32 MiB / 64）。
- [ ] `wasmnest_server_base::constants::*` 与 `wasmnest_host_api_core::database::*` 两条旧路径继续可用（re-export）。
- [ ] `server-base` 依赖清单不再含 `wasmnest-host-api-core`；`cargo tree --offline -e normal -i wasmnest-host-api-core` 从 `server-base` 无输出。
- [ ] `wasmnest-contract` 保持零依赖，并有常驻断言（清单无任何 `[dependencies]`）。
- [ ] `wasmnest-contract` / `wasmnest-host-api-core` / `wasmnest-server-base` 及下游 `cargo test --offline` 绿。
