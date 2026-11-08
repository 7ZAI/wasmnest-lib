# 08: 文档与 crate 真源修正（AGENTS / README / 描述符）

**What to build:** 三份人读文档与各 crate 的 `Cargo.toml` 描述、`lib.rs` 头注同步到 P0 后的真实状态：crate 表完整、默认形态措辞准确、契约仓定位扩容、传输面边界不再宣称「任何宿主可直接引用」、契约房与 `cli-engine` 豁免理由写清。

**Blocked by:** 02、03、04、05、06、07

**Status:** ready-for-agent

- [ ] AGENTS / README / README_en 的 crate 表条数与仓根 `ls -d */` 实际一致（含合流后的 `wasmnest-relay`）；补 `wasmnest-cli-engine` / `wasmnest-clipboard-engine` / `wasmnest-p2p-engine`。
- [ ] 「默认形态」表述改为「零 WIT / 零 SDK / 零宿主框架」；明确 `server-http` / `-websocket` / `-core` / `wasm-core` 仍依赖 actix / Tauri。
- [ ] 契约仓定位改为「零依赖共享词汇（包名 / 版本 + 跨层常量）」；消费口径改为「宿主经 `wasm-core` re-export；库内零依赖共享词汇可直接依赖」。
- [ ] `server-core` 描述、`notify-engine` / `clipboard-engine` 契约房标注、`cli-engine` 不登记 `SPLIT_CRATES` 的豁免理由、`server-base` feature 默认值同批修正。
- [ ] 各 crate `Cargo.toml` 描述与 `lib.rs` 头注同步；文档中不出现平台仓目录名（`platform_reference_registry_lock` 绿）。
