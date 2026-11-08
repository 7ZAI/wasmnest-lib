# 01: 依赖诚实性：内部 crate `publish = false` + 摘除 `server-core` 死依赖 `uuid`

**What to build:** 仓内全部顶层 crate 明确标记为不可发布，`server-core` 的依赖清单不再出现无引用的 `uuid`——维护者看依赖清单即可相信它，发布工程师不会误把内部 crate 推到 crates.io。

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] 仓根全部顶层 crate（含合流后的 `wasmnest-relay`）已声明 `publish = false`；夹具 crate 保持既有声明。
- [ ] `wasmnest-server-core` 正常依赖树不再出现 `uuid`（`cargo tree --offline -e normal -i uuid` 无输出）。
- [ ] 受影响 crate 的 `Cargo.lock` 经 cargo 刷新后随提交，未手编。
- [ ] 全部顶层 crate `cargo check --offline` 绿；`wasmnest-server-core` `cargo test --offline` 绿。
