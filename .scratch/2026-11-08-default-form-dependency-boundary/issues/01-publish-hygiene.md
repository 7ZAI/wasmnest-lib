# 01: 依赖诚实性：内部 crate `publish = false` + 摘除 `server-core` 死依赖 `uuid`

**What to build:** 仓内全部顶层 crate 明确标记为不可发布，`server-core` 的依赖清单不再出现无引用的 `uuid`——维护者看依赖清单即可相信它，发布工程师不会误把内部 crate 推到 crates.io。

**Blocked by:** None (can start immediately)

**Status:** done (2026-11-08)

- [x] 仓根全部顶层 crate（含合流后的 `wasmnest-relay`）已声明 `publish = false`；夹具 crate 保持既有声明。
- [x] `wasmnest-server-core` 正常依赖树不再出现 `uuid`（`cargo tree --offline -e normal -i uuid` 无输出）。
- [x] 受影响 crate 的 `Cargo.lock` 经 cargo 刷新后随提交，未手编。
- [x] 全部顶层 crate `cargo check --offline` 绿；`wasmnest-server-core` `cargo test --offline` 绿。

**实施记录（2026-11-08）**：dev 的 19 个顶层 crate 全部 `publish = false`；第 20 个 `wasmnest-relay` 已随 `integration/relay`（`14c6353`）就位（同样声明），ff 进 dev 后生效。`cargo tree --offline -e normal -i uuid`（server-core）无匹配。
