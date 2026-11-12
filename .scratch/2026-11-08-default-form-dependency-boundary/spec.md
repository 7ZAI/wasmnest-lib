# 默认形态依赖边界收口（P0）spec（2026-11-08）

> 来源：同日能力仓 crate 架构审查（静态审查 + `cargo tree --offline -e normal` 实测）。
> 本文只覆盖 **P0：恢复「能力域默认形态可被任何宿主引用」的依赖不变量**。
> P1/P2（`wasm-core` 去传输面 / 去 Tauri、`server-core` actix 拆分等）在
> §Further Notes 列为后续票据，不在本票实施。
>
> 跨会话真源 = GitHub issue（`7ZAI/wasmnest-lib`，待用户确认后发布）。
> 实施前先读 AGENTS §0 / §3.5 / §6；通用提交 / 测试 / 版本规范不在此复制。

## Problem Statement

当前能力仓的文档承诺是：带 `common-host` 的能力域 crate，**默认形态 = 纯引擎机制 +
端口抽象，任何宿主（移动端 / 无头 / 第三方）可直接引用**。但依赖图与这条承诺不一致：

- `wasmnest-server-base` 被文档称为「叶子地基」，实际依赖 `wasmnest-host-api-core`
  （为 4 个 `PLUGIN_DB_*` 常量）、`wasmnest-link-crypto`（为一个 `From` impl）、
  `rusqlite`（为一个 `AppError::Database` 变体）、`notify`（为一个 `From` impl）、
  `mdns-sd` + `flume`（为 `MdnsPort` 的具体类型）、`sysinfo` + `local-ip-address`
  （为 `SystemInfo::collect()`），默认还开 `tauri`。
- 后果是真实的构建成本，而不只是文档瑕疵：`wasmnest-crypto-engine`（中性密码原语）
  的正常依赖树里出现 `tauri v2`、`rusqlite`、`mdns-sd`、`sysinfo`、`notify`；
  `wasmnest-cli-engine`（argv / 帧解析）的 232 行正常依赖树里出现 bundled SQLite、
  `inotify`、`mdns-sd`、`sysinfo`；`wasmnest-pty-engine` 同样被传染。
- 现有门禁无法发现这件事：`wasmnest-headless-host-probe` 只 grep
  `wasmtime|wit-bindgen|inventory|wasmnest-host-kit`（另有 `wasmnest-plugin-api`
  反向树断言），它证明的是「默认形态不需要插件宿主机制」，**不是**「默认形态
  没有桌面框架依赖」。它的绿灯被误读成后者。
- `server-base` 的 12 端口聚合与全局 `OnceLock` 让「共享基础」进一步变成事实上的
  重量级聚合器；而 `crypto-engine` / `cli-engine` 只是想要一个错误信封，却被迫接受
  整个桌面 server 依赖面。

对用户（移动 / 无头 / 第三方宿主维护者）的直接体验是：**只想复用某一个能力域，
却要为 Tauri、actix、bundled SQLite、文件监听和系统信息采集付出编译时间、二进制体积和
供应链面**；对维护者则是：文档、边界锁与真实依赖图三者不一致，后续任何人按文档做
设计都会踩空。

## Solution

把「默认形态」从文档承诺变成可执行的依赖不变量，P0 交付：

1. **`server-base` 变为真叶子**（只依赖零依赖的 `wasmnest-contract`）：跨层常量
   上移 `wasmnest-contract`；删除 `host-api-core` / `rusqlite` / `notify` /
   `link-crypto` 依赖与对应 `From` impl；`tauri` 保持 optional 但 `tauri-compat`
   默认关（桌面宿主显式开）；`MdnsPort` 与系统信息采集器改为可选 feature。
2. **错误类型归域**：`crypto-engine` 自带 `CryptoError`，`cli-engine` 只保留
   `WireError`；两者都不再依赖 `server-base`。
3. **新增默认形态依赖门禁**：在 CI 对声明「宿主无关」的 crate 跑 `cargo tree`，
   命中 `tauri` / `actix` / `rusqlite` / `sysinfo` / `notify` / `inotify` 即红，
   并打印反向依赖路径。
4. **清理诚实性债务**：删死依赖、给内部 crate 加 `publish = false`、修正 AGENTS /
   README 的 crate 表与「默认形态」措辞。
5. **明确边界**：`server-http` / `server-websocket` / `server-core` / `wasm-core`
   仍带 actix / Tauri / rusqlite；P0 只改文档表述（不再宣称"任何宿主可引用"），
   真正的解耦在 P1/P2。

P0 完成后，以下 crate 的正常依赖树不再出现 Tauri / actix / bundled SQLite /
sysinfo / notify / inotify：`wasmnest-server-base`、`wasmnest-crypto-engine`、
`wasmnest-cli-engine`、`wasmnest-pty-engine`。`discovery-engine` /
`ws-client-engine` / `p2p-engine` 保持现状（已是合规形态），并由同一门禁长期钉住。

**不改 WIT / ABI / 权限词汇 / wire 形状**，因此不需要重拼 WIT、不需要重建插件产物、
不产生契约 bump。

## User Stories

1. 作为移动宿主维护者，我想让 `wasmnest-crypto-engine` 的正常依赖树不含 Tauri，
   以便移动构建不再被桌面 GUI 框架拖慢。
2. 作为移动宿主维护者，我想让 `wasmnest-pty-engine` 的默认形态不含 bundled SQLite
   与 sysinfo，以便能力域可以被无 GUI 宿主直接引用。
3. 作为无头 / CLI 宿主维护者，我想让 `wasmnest-cli-engine` 只依赖 serde 与零依赖
   契约常量，以便 CLI 二进制保持小体积。
4. 作为第三方宿主开发者，我想让「默认形态任何宿主可引用」成为可验证事实，以便我
   不必逐个审计传递依赖。
5. 作为能力仓维护者，我想让 `wasmnest-server-base` 只依赖零依赖的
   `wasmnest-contract`（不再依赖任何 server / 能力域 crate），以便「叶子地基」
   与依赖图一致。
6. 作为能力仓维护者，我想让跨层常量住在 `wasmnest-contract`，以便 `server-base`
   不再为 4 个常量依赖 `host-api-core`。
7. 作为能力仓维护者，我想让 `AppError::Database` 不再携带 `rusqlite::Error`，
   以便基础层不编译 bundled SQLite。
8. 作为能力仓维护者，我想让 `notify` / `link-crypto` 的 `From` impl 删除、
   `tauri` 的 `From` impl 改为 `tauri-compat` 门控，以便基础层不依赖文件监听、
   链路加密、GUI 框架。
9. 作为能力仓维护者，我想让 `crypto-engine` 定义自己的 `CryptoError`，以便中性
   算法原语不再返回桌面 server 的错误类型。
10. 作为能力仓维护者，我想让 `cli-engine` 只使用自己的 `WireError`，以便 argv /
    帧解析不依赖 server 错误信封。
11. 作为桌面宿主维护者，我想显式开启 `tauri-compat`，并让 rusqlite / tauri 错误
    在边界显式映射，以便底层 crate 默认不反向依赖桌面框架。
12. 作为桌面宿主维护者，我想按需开启 `mdns` / `system-info` feature，以便不需要
    这些能力的消费者不付出依赖代价。
13. 作为 CI 维护者，我想让默认形态依赖门禁在 PR 上运行，以便依赖回退在合并前被
    拦住。
14. 作为评审者，我想让门禁打印「哪个 crate 经哪条路径引入了违规依赖」，以便快速
    定位修复点。
15. 作为测试作者，我想让 `PLUGIN_DB_*` 与 `DEFAULT_ERROR_CODE` 的旧路径继续可用，
    以便下游代码不因常量搬家而大面积改动。
16. 作为测试作者，我想让 DB 错误文案与 envelope 语义保持不变、文件监听错误路径
    不变，以便用户可见错误不回归。
17. 作为测试作者，我想让 crypto 错误文案在 `server-core` 映射后保持不变，以便
    链路加密的诊断日志不漂移。
18. 作为测试作者，我想让 CLI wire 的错误码 / 参数形状保持不变，以便 CLI 客户端
    不需要同步升级。
19. 作为插件开发者，我想让本票不修改 WIT / ABI / 权限 / wire，以便我不用重建
    已发布插件。
20. 作为发布工程师，我想让本票不产生契约版本 bump，以便发版流程与哈希校验不变。
21. 作为发布工程师，我想在平台宿主完成适配后再打新 lib tag，以便 `release-manifest`
    的精确 tag 指针不会指向一个宿主编译不过的提交。
22. 作为安全评审者，我想让基础层与中性 crate 的传递依赖面变小，以便供应链审计
    范围收窄。
23. 作为文档读者，我想让 AGENTS / README 的 crate 表列出全部 19 个 crate，以便
    导航不再漏项。
24. 作为文档读者，我想让 `notify-engine` / `clipboard-engine` 的「契约房」定位在
    名字与描述上都清楚，以便不把它们误当引擎。
25. 作为维护者，我想让死依赖（如 `server-core` 的 `uuid`）被删除，以便依赖清单
    可信。
26. 作为维护者，我想让内部 / 夹具 crate 带 `publish = false`，以便不会误发到
    crates.io。
27. 作为维护者，我想让 P1/P2 的结构性重构有明确的后续票据清单，以便 P0 不被
    扩张成一次大爆炸重构。

## Implementation Decisions

### 1. 范围与不变量

- 本票只修「默认形态」的依赖面与错误类型归属；**不改运行时行为、WIT、ABI、
  权限词汇、wire 形状、数据库 schema**。
- 「默认形态」的判据从「零 WIT / 零 SDK」扩展为「零 WIT / 零 SDK / **零宿主框架
  （Tauri、actix）** / 零 bundled SQLite / 零宿主信息采集」。
- `server-http` / `server-websocket` / `server-core` / `wasm-core` **不在**本票的
  「默认形态」承诺内；它们仍带 actix / Tauri / rusqlite。P0 只修正文档，真正的
  拆分见后续票据。
  **这是对 AGENTS §3.1（http/ws 默认形态）与 §3.3（server-core 传输无关）的
  显式让行**：需在本票批准时同步修订 AGENTS；P1/P2 票据按 §Further Notes 的条件
  决定恢复不变量或记录永久例外，不是文档笔误，也不得静默降级。
- `wasmnest-headless-host-probe` 的定位保持为「默认形态不需要插件宿主机制」的
  装配级门禁（`wasmtime` / `wit-bindgen` / `inventory` / `host-kit`），**不要**把
  Tauri/actix 断言塞进探针——它本来就故意链接 server 栈，会假红。

### 2. 跨层常量上移

`wasmnest-contract` 从「包名 / 版本常量」扩展为「零依赖共享词汇」，收纳：

- `PLUGIN_DB_STATEMENT_TIMEOUT_SECS`
- `PLUGIN_DB_QUERY_MAX_ROWS`
- `PLUGIN_DB_QUERY_MAX_BYTES`
- `PLUGIN_DB_EXECUTE_BATCH_MAX_STATEMENTS`
- `DEFAULT_ERROR_CODE`（CLI wire 的兜底码）

旧路径按常量现居位置分别保留（`pub use` 自 `wasmnest-contract`）：

- `PLUGIN_DB_*` 四常量：`wasmnest_server_base::constants::*` 与
  `wasmnest_host_api_core::database::*` 两条旧路径都不变；删除
  `server-base → host-api-core` 依赖边，`host-api-core` 改依赖 `wasmnest-contract`
  （其 `boundary_lock` 只扫源码 needle：plugin_api / wasm_core / tauri / tokio，
  contract 零依赖不命中，符合机制级纪律）。
- `DEFAULT_ERROR_CODE`：现居 `wasmnest_server_base::error`（**不在 constants**），
  `error.rs` 保留 `pub use wasmnest_contract::DEFAULT_ERROR_CODE;`——wasm-core 的
  `pub mod error { pub use wasmnest_server_base::error::*; }` glob 链与
  cli-engine 的旧导入都经此路径（story 15）。

新增内部边 `server-base → contract` / `host-api-core → contract` 不触平台边锁：
contract 不在 `SPLIT_CRATES`（桌面宿主边锁断言①只管辖表内成员）。平台仓两处
node 解析器按**常量名**正则取值（`pub const PACKAGE_VERSION: &str = "…"` 等），
新增常量不改变既有 `PACKAGE_*` 的文本形状，解析器无需改。contract 必须保持
零依赖；建议加一条常驻断言（`Cargo.toml` 无任何 `[dependencies]`），避免
「零依赖共享词汇」随新增常量静默失效。

### 3. `AppError` 形态与转换

- `Database(#[from] rusqlite::Error)` → `Database(String)`。调用点编译器驱动全量
  改为边界 `e.to_string()`，已知两类：① 显式构造点——wasm-core 的 `storage.rs` /
  `security/auth_policy.rs`；② `?` 隐式转换点——wasm-core 的
  `db/{operations,database}.rs`（`set_setting` / `init_schema` / `run_migrations`
  等返回 `crate::Result` 的函数）与 server-core `link_crypto.rs` 的
  `persist_app_policies_to_db`。envelope 语义不变（`Database` 仍落 `host.internal`
  兜底码）。
- 删除 `From<notify::Error>`：该 impl 目前**零调用点**（watcher 在
  `manager/watcher.rs` 内对 `notify::Error` 只做 `tracing::debug!` 后返回，
  不转 `AppError`），也无既有测试；随 `notify` 依赖一并删除，无调用点需要改。
- 删除 `From<LinkCryptoError>`；`server-core` 的 `link_crypto` 边界显式映射为
  `AppError::Internal(e.to_string())`，保留原文案。
- `tauri` 保持 `optional`，`tauri-compat` 改为**默认关**；桌面宿主在自己的依赖声明里
  显式开启（不能依赖传递 feature，否则移动端也会被打开）。开启时
  `From<tauri::Error>` 仍可用；默认形态不编译该 impl，因此不引入 GUI 框架。
  这是比「整体移除」更小的跨仓改动；若后续确认 feature 仍无人主动关闭，再评估
  整体移除（独立票据）。
- `AppError::Pty`（`cfg(not(android/ios))`）保持不动：它是域变体但不引入依赖。
- `Serialize for AppError` 的「生成 request_id + 落日志」副作用**本票不改**；
  纯化属于错误信封的独立票据，避免把行为变更混进依赖收口。

### 4. `server-base` feature 与依赖面

目标形态：

```text
[features]
default = []
tauri-compat = ["dep:tauri"]              # 桌面宿主显式开启
mdns         = ["dep:mdns-sd", "dep:flume"]
system-info  = ["dep:sysinfo", "dep:local-ip-address"]

[dependencies]
serde / serde_json / thiserror / tracing / rand / futures-util / async-trait / tokio
anyhow（保留：From<anyhow::Error> 与 BusMessageHandler::on_message 的生产消费）
wasmnest-contract（零依赖）
# 移除：rusqlite / notify / wasmnest-link-crypto / wasmnest-host-api-core
```

- `mdns` feature 门控 `MdnsPort`、`MdnsTypeSubscription` 与 `ServerPorts.mdns`
  字段。`wasmnest-server-peer-net`（必须在其 `Cargo.toml` 对 base 开
  `features = ["mdns"]`）与需要构造 `ServerPorts` 的桌面宿主开启；
  `crypto-engine` / `cli-engine` / `pty-engine` 不开启。波及面已核实：lib 内
  `ports.mdns` 消费方仅 peer-net；桌面宿主 `ports_impl` 构造 `ServerPorts` 含
  `mdns` 字段；移动宿主不构造 `ServerPorts`，但 `peer/ports.rs` 直接导入并实现
  `MdnsPort` / `MdnsTypeSubscription`（经 peer-net 的 feature 合并获得，建议移动
  宿主显式声明）；peer-net 的 `src/test_ctx.rs` 也构造含 `mdns` 字段的
  `ServerPorts`，测试同样依赖该 feature。
- `system-info` feature 门控 `SystemInfo::collect()`、`local_ipv4_addresses()` 及
  其私有 helper `desktop_device_name()` / `fallback_os_ip_name()`；`SystemInfo`
  DTO 与 `SystemInfoPort` 常编译。lib 内无自由函数调用点（消费全在
  桌面宿主：`system/info.rs` re-export base info，bootstrap / ports_impl 调
  `collect()`），桌面宿主必须开启；无头宿主可自行实现 `SystemInfoPort`。
- `ServerPorts` 的全局 `OnceLock` 与 12 端口聚合**本票不改**（P1 的实例注入票据
  处理）；只把 mdns 字段改为可选，避免把 mdns-sd 钉进所有 base 消费者。
- `wasmnest-server-base` 的既有测试按 feature 加 `#[cfg]`；默认 `cargo test`
  不依赖 mdns / sysinfo。

### 5. `crypto-engine` 错误类型

```text
CryptoError =
  | InvalidKeyLength { detail: String }      // 旧 AppError::InvalidInput 文案（含算法名/措辞）
  | InvalidNonceLength { detail: String }    // 同上
  | UnsupportedAlgorithm { detail: String }  // 未知 AEAD/KDF/密钥交换算法
  | InvalidInput { detail: String }          // 其它旧 InvalidInput 文案（base64/RSA 参数/长度不匹配）
  | OperationFailed { detail: String }       // 旧 AppError::Internal 文案（算法执行失败）

type CryptoResult<T> = Result<T, CryptoError>
```

- 所有 provider trait / 注册表 / 算法实现的返回类型从 `wasmnest_server_base::Result`
  改为 `CryptoResult`。
- 依赖面：保留全部既有算法依赖（`aes-gcm` / `chacha20poly1305` / `x25519-dalek` /
  `hkdf` / `sha2` / `rsa` / `rand` / `base64` / `serde` / `serde_json`），新增
  `thiserror`（`CryptoError` derive）；**零内部 crate**（摘 `server-base`）。
- **文案保留约束**：现状错误是具体中文串（如「未知 AEAD 算法: '{name}'（不在白名单）」、
  「AES-256-GCM 加密失败: {e}」）；实现时把旧文案完整放入对应变体的
  `detail`，`CryptoError` 的 `Display` 返回 `detail` 原文；`server-core` 按变体
  语义映射回 `AppError::InvalidInput` / `AppError::Internal` 后由变体前缀补回
  `Invalid input:` / `Internal error:`，对外错误文本与现状逐字一致，测试逐字
  断言。P0 优先保证文案兼容，结构化字段（`expected` / `actual` / `alg`）留待
  P2 再细化。
- 消费方适配：`server-core` 增加边界映射，按变体语义分派——`InvalidKeyLength` /
  `InvalidNonceLength` / `UnsupportedAlgorithm` / `InvalidInput` →
  `AppError::InvalidInput(detail)`，`OperationFailed` → `AppError::Internal(detail)`，
  保留旧 Display 前缀与 detail；供 `link_crypto` 使用。桌面宿主 `plugin/crypto.rs`
  直调 registry（`resolve_aead` / `resolve_kdf` / `resolve_key_agreement`），同批
  改型适配。移动宿主不引用 crypto-engine，无适配。

### 6. `cli-engine` 错误类型

- 删除 `wasmnest-server-base` 依赖；`WireError` 保持现有 wire 形状
  （`{ code, params? }`）。
- `WireError::from_app_error` 在 P0 **删除**（或保留为纯 `from_code` 构造）；
  CLI 前端 / 无头宿主的 `AppError → WireError` 映射随平台仓 CLI 票据落地，不在
  P0 的跨仓硬依赖内——当前工作区没有 `wasmnest-cli-engine` 的生产消费方。
  `cli-engine` 只负责编码 / 解码与目录 / 解析 / 帮助。
- `DEFAULT_ERROR_CODE` 从 `wasmnest-contract` 取；`cli-engine` 只依赖
  `wasmnest-contract`（零传递依赖）+ `serde` / `serde_json`。
- 现有 `builtin` / `catalog` / `parse` / `help` / `wire` 测试保留；依赖 `AppError`
  的测试迁到宿主侧或改用 `WireError` 直接构造。

### 7. 调用面更新

- `wasmnest-pty-engine`：无需改代码；`server-base` 变瘦后自动去掉
  tauri / SQLite / sysinfo / notify（已核实其测试不引用被移除的 `From` impl）。
- `wasmnest-server-core`：删除死依赖 `uuid`；在 `link_crypto` 边界映射
  `LinkCryptoError` 与 `CryptoError`；`persist_app_policies_to_db` 等 rusqlite `?`
  点改显式 `Database(e.to_string())`（编译器驱动全量）；`actix` / `rusqlite` /
  `chrono` / `sysinfo` 保留到 P1。
- `wasmnest-wasm-core`：改 `AppError::Database` 全部调用点（显式构造 +
  `db/{operations,database}.rs` 的 `?` 隐式点，见 §3）；watcher 不消费
  `From<notify::Error>`（见 §3）；已核实无 `tauri::Error` 的 `?` 转换
  （`app_data_dir()` 等已显式 `map_err`）。**不**在本票移除 Tauri 或传输面依赖。
- 平台仓桌面宿主（跨仓同批，硬依赖）：src-tauri 的 `src/server/crate_boundary_lock.rs`
  中 `ALLOWED_DOWNWARD_EDGES`（crypto-engine 行改 `&[]`）与
  `REQUIRED_DOWNWARD_EDGES`（删 `("wasmnest-crypto-engine", "wasmnest-server-base")`）
  同批更新——断言②「缺边即红」且该锁读能力仓兄弟工作树，lib 落地即红；
  宿主清单 base 依赖显式开 `tauri-compat` / `mdns` / `system-info`；
  `plugin/crypto.rs` 适配 `CryptoResult`；rusqlite / tauri 错误边界显式
  `map_err`（`notify` 由 wasm-core watcher 内部消费，宿主无需适配）。
  移动宿主：实测无 `AppError::Database` 构造、`tauri::Error` 已显式
  `map_err`，验证 feature 默认值变更后编译即可。CLI 宿主侧的 `AppError →
  WireError` 承接随平台仓 CLI 票据，P0 不要求同批实现（见 §6）。
- `wasmnest-server-base` 自身：既有测试未覆盖 notify / link-crypto 的 `From`
  impl（零调用点、无测试需删）；把 DB 错误测试改为字符串形态；保留 envelope /
  code / params 的既有断言。

### 8. 默认形态依赖门禁（CI）

新增一个 CI 步骤（或由 CI 调用的仓内脚本），对下列 crate 跑
`cargo tree --offline -e normal`：

- `wasmnest-server-base`
- `wasmnest-crypto-engine`
- `wasmnest-cli-engine`
- `wasmnest-pty-engine`
- `wasmnest-discovery-engine`
- `wasmnest-ws-client-engine`
- `wasmnest-p2p-engine`

禁止出现的 crate（大小写不敏感，按 crate 名精确匹配）：

```text
tauri | actix | actix-web | actix-web-actors | rusqlite | sysinfo | notify | inotify
```

- `mdns-sd` 对 `discovery-engine` / `peer-net`（以及经 peer-net 传导的 crate）
  是合法能力依赖，不在禁止列表；对 `crypto-engine` / `cli-engine` / `pty-engine`
  则应自然消失——若仍出现，说明 `server-base` 的 mdns feature 泄漏，门禁报错。
- 失败时打印 `cargo tree -i <违规 crate>` 的反向路径，直接指出是哪条边。
- 该门禁与现有 `wasmnest-headless-host-probe` 门禁**并存**：探针管
  `wasmtime/wit-bindgen/inventory/host-kit`，新门禁管宿主框架 / SQLite / 系统信息。
- CI 全新检出无 registry 缓存：门禁步骤先逐 crate `cargo fetch`（或 CI 内不带
  `--offline` 跑）；本地跑保持 `--offline`。
- CI 同批清理：P0 后 test 遍历面内不再有 crate 拉 tauri（仅 server-base 与
  wasm-core 声明 tauri，前者默认关、后者是登记例外不进 test 遍历），删除
  webkit2gtk 等 apt 步骤与「server-base 默认 tauri-compat」注释；ci.yml 头注
  「16 个顶层 crate」更新为 19。
- 不把 `server-http` / `server-websocket` / `server-core` / `wasm-core` 纳入
  禁止列表（它们仍带 actix / Tauri / rusqlite）；P1 完成后再逐 crate 收紧。

### 9. 文档、登记与发布

- AGENTS：crate 数 17 → **19**，一览表补 `wasmnest-cli-engine` /
  `wasmnest-clipboard-engine` 两条（p2p-engine 已在表内，不重复补）；
  README / README_en：crate 数改 **19**，补 `wasmnest-cli-engine` /
  `wasmnest-clipboard-engine` / `wasmnest-p2p-engine` 三条。三文件「默认形态」
  表述改为「零 WIT / 零 SDK / 零宿主框架（P0 后）」，并明确 `server-http` /
  `-websocket` / `-core` / `wasm-core` 仍依赖 actix / Tauri。
  **crate 真源同批修正**（AGENTS §1：`Cargo.toml` description 与 `src/lib.rs`
  头注才是真源）：`wasmnest-server-http` / `wasmnest-server-websocket` 现仍写
  「任何宿主可直接引用」，改为与 P0 边界一致（二者默认形态含 actix）；
  `wasmnest-server-base` 的 `tauri-compat`（默认开）改为默认关 + `mdns` /
  `system-info` 可选；`wasmnest-host-api-core` 的「主要消费方 = server-base
  （re-export 护栏常量）」随摘边更新。
- contract 定位扩容的文档同步：AGENTS §1 表 / §2.2 / §6.3 与 contract
  `src/lib.rs` 头注的「包名 / 版本常量唯一真源」改为「零依赖共享词汇（契约包名 /
  版本 + 跨层常量）」，`PACKAGE_*` 真源地位不变；§6.3 的「契约只允许经
  `wasmnest-wasm-core` 的 re-export 消费」改为「宿主只允许经 `wasmnest-wasm-core`
  的 re-export 消费；库内零依赖共享词汇（`server-base` / `host-api-core`）可直接
  依赖」。
- 顺带收拢 AGENTS 既有漂移（同批文档修正，均已核实）：契约版本字面量
  `@0.0.2` → `@0.1.0`（真源现值；README / README_en 同批修正）；CI 触发口径
  「PR / dev 推送」→「仅 PR（dev 推送不触发）」；跨仓依赖口径「宿主直接 path
  依赖」→「桌面宿主 git tag + 平台仓根 `.cargo/config.toml` 的 [patch] 指回兄弟
  目录；移动宿主 path」。
  **范围限定**：ADR 0061 拆包后 AGENTS §2.2 的 bump 流程已结构性过期（域 WIT
  已是 `wasmnest:mdns@0.0.1` 等独立包，不再是 `wasmnest:plugin@0.0.2` 全局字面量）；
  本票只修正 `wasmnest:plugin` 真源表述与被点名的字面量，§2.2 全量重写另立文档
  票据。
- `server-core` 的描述从「与传输无关」改为「跨传输过滤器 / 生命周期 / 指标 +
  actix 组合运行时」；`link_crypto` 的宿主职责在 P1 再迁。该描述变更与 §1 的
  规范让行同批记录（AGENTS §3.3 同步修订）。
- `notify-engine` / `clipboard-engine` 在表内明确标注「契约房（零 Rust 实现）」；
  是否改名 / 合并在 P2 票据决定，本票只修文档。
- `wasmnest-cli-engine` 不登记 `SPLIT_CRATES`（沿既有 CLI spec 裁决：消费方是
  平台仓 CLI / 无头 bin（当前尚未实施），不是宿主 bin 本体）；在 AGENTS 里补一句
  豁免理由，避免下一个 crate 新增时反复讨论。
- `publish = false` 口径：本仓全部 crate 目前只经 sibling path / git tag 消费，
  没有 crates.io 发布计划 ⇒ P0 给**全部内部 crate**加 `publish = false`
  （夹具已有）；若实施前确认某个 crate 需要单独发布，列白名单并在本 spec 修订中
  写明理由。
- **不发版承诺**：本票是 breaking lib 变更（`crypto-engine` 错误类型、
  `cli-engine` 错误 API、`AppError::Database` 形态、`server-base` 的
  `tauri-compat` 默认关）。平台宿主适配完成后再打新 `lib-vX.Y.Z` 并更新
  `release-manifest`；在适配前，开发侧经平台仓根 [patch]（桌面）/ path 依赖
  （移动）直接编译同一工作树。

## Testing Decisions

**好测试的判据**：只断言外部可观察行为与构建不变量，不断言私有模块结构；依赖
门禁断言的是一种「图的性质」，不是某个实现细节。

### Seam 1（最高、已有）：CI 依赖门禁

- 复用现有 CI 作为唯一 seam，新增「默认形态依赖」步骤；不新建测试 crate、不在
  每个 crate 里复制 7 份 `Cargo.toml` 扫描。
- 这是覆盖「无 Tauri / actix / SQLite / sysinfo / notify」整条不变量的最小面。
- 失败输出必须包含违规 crate 与反向依赖路径（`cargo tree -i`），否则修复者要
  自己重新推导。

### Seam 2（已有）：无头探针

- 保持 `wasmnest-headless-host-probe` 只做 `wasmtime/wit-bindgen/inventory/
  host-kit` 的装配级断言；不要把它扩成 Tauri/actix 门禁（它会链接 server 栈，
  必然假红）。
- 探针的 smoke 断言继续覆盖 wire / 常量 / 端口可独立消费。

### Seam 3（已有）：逐 crate 单元测试

按 crate 更新 / 新增：

- `wasmnest-server-base`：
  - `AppError` envelope 测试：`UserFacing` 的 code/params、兜底码、DB 错误字符串。
  - `tauri` `From` impl 的测试加 `#[cfg(feature = "tauri-compat")]`；`notify` /
    `link-crypto` 的 `From` impl 为零调用死代码，随依赖删除，无既有测试需迁。
  - `constants` 的旧路径 re-export 编译通过（可用一个引用测试或既有下游编译）。
  - `mdns` / `system-info` feature 的测试加 `#[cfg(feature = ...)]`。
- `wasmnest-crypto-engine`：
  - 既有算法向量测试保留（行为不变）；注册表 / provider 测试的错误类型断言随
    `CryptoError` 改型（语义不变：未知算法 / 非法长度仍显式拒绝）。
  - 新增 `CryptoError` 的 Display / 映射测试：`detail` 逐字复刻旧文案，映射回
    `AppError` 后 Display 与现状逐字一致（§5 约束）。
- `wasmnest-server-core`：
  - `CryptoError → AppError`、`LinkCryptoError → AppError` 的映射测试，断言
    文案与既有过滤器断言逐字一致。
  - `persist_app_policies_to_db` 失败路径：rusqlite 错误显式映射后 envelope
    语义不变。
  - 既有 `link_crypto` 测试保留。
- `wasmnest-cli-engine`：
  - 既有 catalog / parse / help / wire 测试保留。
  - `WireError` 编解码与兜底码测试；`from_app_error` 删除/改为 `from_code` 后，
    本仓只保留编解码与兜底码测试，宿主侧映射测试随平台仓 CLI 票据（不在本仓新建）。
- `wasmnest-wasm-core`：
  - `storage` / `auth_policy` 与 `db/{operations,database}` 的 DB 错误测试更新为
    字符串形态（含 `init_schema` / 迁移失败路径）；断言 envelope 的 code 仍为
    `host.internal`。
- `wasmnest-pty-engine`：
  - 既有测试全绿即可；额外断言 `cargo tree` 门禁覆盖它。

**Prior art**：

- `wasmnest-ws-client-engine/src/boundary_lock.rs`：manifest 依赖段 + 生产源码的
  静态锁（本票的 CI 门禁是它的传递闭包补充）。
- `wasmnest-host-api-core/src/boundary_lock.rs`、`wasmnest-p2p-engine/src/
  boundary_lock.rs`：机制级依赖 / 越界 needle 的既有判据。
- `wasmnest-wasm-core/tests/platform_reference_registry_lock.rs`：仓根全文扫描。
- `wasmnest-headless-host-probe`：默认形态的编译 / 链接 smoke。
- 测试仓 `wire_drift_locks` / `permission_vocabulary_lock`：本票不改 wire /
  权限，但收口时跑一次确认零漂移。

### 验证矩阵

- 每个受影响 crate：`cargo test --offline`（`wasm-core` 走 AGENTS §4.2 逃生阀）。
- CI：默认形态依赖门禁全绿；无头探针既有门禁全绿。
- 跨仓：平台桌面宿主编译通过（显式 `map_err` + 三 feature 显式开启 +
  `plugin/crypto.rs` 改型）；桌面 `crate_boundary_lock`（断言①②③）边表同批
  更新后全绿；移动宿主编译通过（不再经 base 引入 Tauri；wasm-core 的 Tauri 仍在，
  P1 清偿）；测试仓 wire / permission 锁全绿。
- 不跑插件产物重建（无 WIT / ABI 变更）。

## Out of Scope

- `wasm-core` 去传输面：把 `HttpPorts` / `WsPorts` / `FrameDispatch` /
  `PeerCtx` / `UnitExecutor` 下沉 `host-kit`，删除对 `server-http` /
  `server-websocket` / `server-peer-net` 的生产依赖。
- `wasm-core` 去 Tauri：`desktop-assembly` 整体迁桌面宿主，`system/config` /
  `opener` / `auth_center` / `api_bridge` / `app_update` / `downloader` 的归位。
- `server-core` 与 actix 解耦：`serve` / `app` 迁组合根，`link_crypto` 宿主
  职责归位。
- `server-http` / `server-websocket` 拆出无 actix 的 engine 面（按移动端是否
  需要无 actix 编译再定）。
- `notify-engine` / `clipboard-engine` 的合并或改名。
- `AppError` 的完整域错误分层与 `Serialize` 纯化（request_id / 日志副作用）。
- `server-base` 全局 `OnceLock<ServerPorts>` → 实例注入。
- god-file 模块化（`fs_auth` / `link_crypto` / `peer-net lib` / `p2p engine` /
  `type_hub` / `auth_policy`）。
- wire 副本 codegen。
- 任何 WIT / ABI / 权限 / wire / schema 变更；插件产物重建；契约 bump。
- `wasmnest-server-peer-net` 的 `base/` 再拆分。

## Further Notes

### 审查证据（本票问题陈述的来源）

在 2026-11-08 工作树上实跑 `cargo tree --offline -e normal`：

- `wasmnest-cli-engine`：232 行正常依赖树；含 `inotify` / `mdns-sd` / `notify` /
  `rusqlite` / `sysinfo` / `tokio` / `wasmnest-link-crypto`。
- `wasmnest-crypto-engine`：含 `tauri v2.12.0` / `rusqlite` / `mdns-sd` /
  `sysinfo` / `notify`。
- `wasmnest-pty-engine`：含 `tauri` / `rusqlite` / `mdns-sd` / `sysinfo` /
  `notify`。
- `wasmnest-headless-host-probe`：含 `tauri` / `actix-web` / `actix` /
  `actix-web-actors` / `rusqlite` / `sysinfo` / `mdns-sd`——但其中 actix / SQLite
  来自它故意链接的 server 栈，**不能**据此把它改成 actix 门禁；正确做法是新增
  §8 的逐 crate 门禁。

> 以上为 P0 前基线；P0 完成后 `server-base` / `crypto-engine` / `cli-engine` /
> `pty-engine` 的正常树应不再出现上述禁止项（§8 门禁钉住）。

### 后续票据（P1/P2，按审查结论拆分）

1. **`wasm-core` 去传输面**：扩展点 / 端口词汇下沉 `host-kit`；`UnitExecutor`
   的执行上下文抽象化；`register_declared_ws_endpoints` 归宿主；验收
   `cargo tree -i actix-web` 在 `wasm-core` 正常图无输出。
2. **`wasm-core` 去 Tauri**：`desktop-assembly` 与宿主胶水迁桌面宿主；
   `app_update` / `downloader` 归应用生命周期；验收移动形态 `-i tauri` 无输出。
3. **`server-core` actix 拆分**：`serve` / `app` 归组合根；`link_crypto` 的
   身份落盘 / app policy DB 归宿主；验收 `server-core` 无 `actix-web` / `rusqlite`。
4. **`server-http` / `server-websocket` engine 拆分**：条件 = 移动/无头需要无
   actix 编译；否则在 AGENTS 记录永久例外（P0 已做显式让行），不再宣称
   「任何宿主可直接引用」。
5. **契约房合并/改名**：`notify-engine` + `clipboard-engine` → 一个
   `wasmnest-wit-contracts` 或改名 `-contract`；需同步平台 `compose.json` 路径。
6. **`AppError` 域错误分层 + `Serialize` 纯化**：信封与领域错误分离；`to_envelope`
   取代副作用 `Serialize`。
7. **端口 DI 统一**：`server-base` 全局 `OnceLock` → `Arc<ServerPorts>` 实例注入，
   对齐 `host-kit` 的 `domain_ports`。
8. **god-file 模块化**：仅按职责拆模块目录，不跨 crate。
9. **wire 副本 codegen**：7 份自持副本 + 外部漂移锁 → 单一 schema 生成 + 本仓
   `--check`。

### 跨仓与发布影响

- **breaking lib 变更**：`crypto-engine` 错误类型、`cli-engine` 错误 API、
  `AppError::Database` 形态、`server-base` 的 `tauri-compat` 默认值变更。同批
  适配清单（实施条款见 §7）：桌面宿主——base 依赖显式开 `tauri-compat` /
  `mdns` / `system-info`，`plugin/crypto.rs` 适配 `CryptoResult`，rusqlite /
  tauri 边界显式 `map_err`（`notify` 由 wasm-core watcher 内部消费），桌面
  `crate_boundary_lock` 的 ALLOWED / REQUIRED 边表摘 crypto→base；移动宿主——
  实测无 `AppError::Database` 构造、`tauri::Error` 已显式 `map_err`，验证编译即可；
  CLI 宿主侧——`AppError → WireError` 承接随平台仓 CLI 票据，P0 不要求同批实现
  （当前无消费方）。
- 无 WIT / ABI / 权限 / wire 变更 ⇒ 不重拼 WIT、不重建插件、不改
  `contract.witSha256`。
- 发版时按 AGENTS §4.5：本仓提交 → `lib-vX.Y.Z` tag → 平台
  `release-manifest.json` 的 `repos.lib.tag` 指向该 tag → `check:manifest`；
  适配完成前不要打 tag 指向不可编译的提交。
- 测试仓收口：`wire_drift_locks` + `permission_vocabulary_lock`（本票无 wire /
  权限变更，跑一次确认零漂移）。

### 发布 / 标签口径

本仓 issue 标签是 `kind:bug` / `kind:feature` / `kind:contract` / `kind:chore` /
`cross-repo`，**没有** `ready-for-agent`；发布本 spec 时按 `kind:chore`
（依赖治理 / 重构）或 `kind:feature` 选择，不自建标签。按
`../wasmnest/docs/public/issues.md` §6，建 issue 前先征得用户同意；本文件先作为
定稿 spec 落盘，issue 正文以本文为主体。
