# AGENTS.md

> **wasmnest-lib（能力仓）= 三仓中唯一的应用无关引擎仓。**
> 本文件只写会改变行为的内容：边界、红线、判据、命令、路由。机制细节去真源读（各 crate `Cargo.toml` description、`src/lib.rs` 头注、WIT、锁源码）。
> 读法：§0–§3 规则 · §4–§5 操作 · §6–§7 红线与验收。

## 0. 定位与裁决

**边界一句话**：产品语义（会话 / 终端 / 文件传输 / AI / Agent）→ 应用仓；端差异与装配（宿主薄壳 / SDK / WIT 组合 / 权限门落点）→ 平台仓；本仓只做**可复用机制 + 端口抽象 + 契约**，不读平台 / 应用源码，不做产品判断。

**产出**：插件机制（`wasm-core` / `host-kit` / `host-api-core`）、能力域引擎（`*-engine` / `server-*`）、共享底座（`link-crypto`、peer-net `base/`）、契约真源（`wasmnest-contract` + 各 `wit/*.wit`）。

**冲突优先级**（高者胜）：

1. 用户当前明确指令
2. 安全与架构红线（§3 / §6 + 所有边界锁）——越线先停下确认；禁止放松锁或把锁改红
3. 本文「必须 / 禁止」
4. 跨仓真源（`wasmnest-contract` / WIT / 平台仓锁与 SDK / `release-manifest.json` / 代码自身）
5. 通用工程经验

**维护口径**：

- **路径**：相对能力仓根；跨仓按 R1 同场布局 `../wasmnest`（平台仓）/ `../wasmnest-apps` / `../wasmnest-test`（跨端工程在 `wasmnest-test/cross-end-tests/`）。
- **零平台目录名**：平台仓两端一律写 `wasmnest-{desktop,mobile}`，复制命令前先展开花括号。本仓任何文本（注释 / 测试字符串 / 文档）不得出现平台仓目录名字面量——`wasmnest-wasm-core/tests/platform_reference_registry_lock.rs` 扫仓根全文；唯二豁免是 `wasmnest-server-websocket` / `wasmnest-server-peer-net` 两个 `dependency_direction_lock.rs` 里作为**被判对象**的依赖名。提端用「桌面宿主 / 移动宿主」。
- **文档字面 ≠ 事实**：引用路径 / 命令 / 锁名 / 版本前先 `ls` / `rg` / `cargo metadata` 核对，不符先修文档。
- **最小改动**：只改必要文件；不顺手重构、不擅自升级依赖、不批量重排格式；取舍不猜，先问。
- **版本**：只在发布时 bump；跨仓契约按**精确 tag** 钉（§4.5）。退役面必须 fail-visible（点名缺失 + 给出路），禁止「查不到就返回空」。
- **CI**：`.github/workflows/ci.yml`，仅 `pull_request` + `workflow_dispatch`（dev 推送不触发）；fmt --check + 默认形态依赖门禁 + 按 crate `cargo test`（wasm-core 例外，§4.2）。
- **文档白名单**：本文件 + `README.md` / `README_en.md` + `.scratch/<定稿票>/spec.md`；其余不新增。
- **通用规范**（git / 注释命名 / 测试 / 版本 / issue）真源 `../wasmnest/docs/public/{git,commenting,testing,versioning,issues}.md`，与本文件同级；本文件只留仓特有增量。

### 0.1 交流准则

结论先行、有据可查（区分事实 / 推断 / 猜测 / 待验证）、被问什么答什么、路径命令用可复制字面；准确性、安全、契约、跨仓同步不得以「简洁」为由省略。

---

## 1. 仓速览

**无根 workspace**：19 个独立 crate（各自 `Cargo.toml` + 跟踪的 `Cargo.lock`）+ 4 个夹具。**命令在 crate 目录跑，一个 crate 一次 cargo；没有仓级 `cargo test`。**

```text
插件（应用仓）
   │ WIT host-* · bus · events · 互调
   ▼
能力域 crate（默认 = 纯引擎 + 端口；common-host 才装 WIT 绑定层）
   ▼
host-kit（装配期：状态 / 模块契约 / 注册表）
   ▼
wasm-core（运行期：运行时壳 + core 绑定 + host_api adapter，消费 host-api-core）
   ▼
双端宿主 src-tauri/src/（组合根 · 薄壳）——平台仓
```

**crate 一览**（真源 = 各 crate `Cargo.toml` description 与 `src/lib.rs` 头注；`[]+ch` = `default = []`、`common-host` 装 WIT 绑定层）：

| crate | 定位 | 形态 / WIT |
| --- | --- | --- |
| `wasmnest-contract` | 零依赖共享词汇：`PACKAGE*` 唯一真源 + 跨层常量（`PLUGIN_DB_*` / `DEFAULT_ERROR_CODE`） | 零依赖，`[dependencies]` 恒空 |
| `wasmnest-wasm-core` | 插件机制整核：wasmtime 组件运行时壳 + host_api adapter + 安全闸门 + 主库 | `default = ["desktop-assembly"]`；`test-support`；`wit/core.wit` + `wit/worker.wit` |
| `wasmnest-host-kit` | 装配期内核：`WasmPluginState` / `HostModule` / 自动注册表 / limits / metrics | 无 feature；`tests/` 与 `fixtures/` 在此 |
| `wasmnest-host-api-core` | host_api 无 WIT 域实现层：gate / storage / bus / database / log / events / fs | 无 feature |
| `wasmnest-server-base` | server 叶子地基：错误信封 / 常量 / 端口 traits / wire | `[]`；`tauri-compat` / `mdns` / `system-info` 默认关 |
| `wasmnest-server-core` | 跨传输内核：supervisor / 过滤链 / link_crypto / `TransportFace` + actix `serve` | 仍依赖 actix / rusqlite |
| `wasmnest-server-http` | HTTP 传输面 + `host-http` 绑定层 | `[]+ch`；`wit/http.wit` |
| `wasmnest-server-websocket` | WS 传输面 + `host-websocket` 客户端域 / 服务端引擎函数 | `[]+ch`；`wit/ws.wit` |
| `wasmnest-server-peer-net` | 对等网络引擎域（`base/` 底座 + `host-peer` 绑定；非传输面） | `[]+ch`；`wit/{peer,tunnel}.wit` |
| `wasmnest-p2p-engine` | libp2p 机制引擎：身份桥 / swarm / 入站准入闸门 / 具名流协议 | 无 feature |
| `wasmnest-discovery-engine` | mDNS：共享守护 + 类型中枢 + 浏览 / 广播句柄表 | `[]+ch`；`wit/mdns.wit` |
| `wasmnest-pty-engine` | PTY：进程生命周期 / 读取线程 / 环形缓冲 | `[]+ch`；`wit/pty.wit` |
| `wasmnest-ws-client-engine` | WS 出站客户端：句柄表 / 双任务 / 心跳 / 退避重连 / 停用回收 | 无 feature；`wit/ws.wit` |
| `wasmnest-cli-engine` | CLI 机制骨架：命令目录 / argv 解析 / 帮助补全 / 本机 IPC wire | 零内部依赖 |
| `wasmnest-crypto-engine` | 中性加密原语 + 名称寻址注册表；自带 `CryptoError` | 零内部依赖 |
| `wasmnest-clipboard-engine` / `wasmnest-notify-engine` | 契约房：只持 WIT，零 Rust 实现 | `wit/{clipboard,notify}.wit` |
| `link-crypto`（包 `wasmnest-link-crypto`） | 链路加密协议：HTTP 信封 / WS 握手 IKM / 二进制帧 | 目录名 ≠ 包名唯一例外 |
| `wasmnest-headless-host-probe` | 无头探针：非桌面形态引用全部能力域，钉默认形态可引用性 | 永不开 `common-host`；零 dev-deps；**不进任何宿主清单** |

夹具（不入表、不发布）：`wasmnest-host-kit/fixtures/forced-link-probe`、`wasmnest-wasm-core/fixtures/{wasi-test,wasip3-test,p3-async-host-import-test}`（自持、绑 `wit/core.wit`、零 SDK）。

**跨仓装配（R1 兄弟布局）**：

- 平台仓无 submodule：桌面宿主 `src-tauri/Cargo.toml` 声明版本 + 平台仓根 `.cargo/config.toml` 的 `[patch]` 解析到 `../wasmnest-lib/<crate>`；移动宿主直接 path 依赖。不复制 / 不镜像源码。
- 测试仓同样经 `../wasmnest-lib/<crate>`（`tests/common/repo_paths.rs::lib_root()`，`WASMNEST_LIB_ROOT` 可覆盖）。**全链路只有这一条物理路径**——第二份拷贝 = 两个同名 crate → 类型同一性断裂。
- 版本线 `0.0.1`，本仓独立打 `lib-vX.Y.Z`；平台 `release-manifest.json` 的 `repos.lib.tag` 指精确 tag。

**命名**：目录名 = 包名 `wasmnest-<域>`（`link-crypto` 例外）；`plugin-sdk-*` / `wasmnest-componentize` 不属本仓。

---

## 2. 跨仓边界与契约

### 2.1 依赖方向

- **本仓 → 平台仓**：零源码读取；唯一耦合 = `wasmnest-contract` 常量 / `wit/*.wit` / crate 版本。平台读本仓 = sibling path + `pnpm run check:manifest`（校验 HEAD == tag 且工作树干净）。
- **平台仓 → 本仓**：path 依赖；桌面宿主开 `common-host`（5 个能力域），移动宿主不开（自有 `host_domains/*`，只取引擎面）。
- **架构债**：`wasm-core` 的 `desktop-assembly`（默认开）依赖未发布 SDK `wasmnest-plugin-api = "0.0.1"`；消费侧 `[patch.crates-io]` 指回工作树 SDK，版本须与 SDK `Cargo.toml` 逐字一致。**勿扩大**（§4.2 / §8）。
- **能力域 `[dependencies]` 禁止**：SDK（`wasmnest-plugin-api*`）、双端 wasm-core、`wasmnest-host-kit`（只经 `common-host` 装配）、`tauri`、`actix`（传输面自身除外）。每条有配对锁（§2.4）。
- 依赖被重命名时必须显式写 `package = "..."`。

### 2.2 契约真源与版本（改 WIT 前必读）

- **包版本真源**：`wasmnest:plugin`（core import + 全部 guest 导出面）= `wasmnest-contract/src/lib.rs` 的 `PACKAGE_NAME` / `PACKAGE_VERSION` / `PACKAGE`；各域包（`wasmnest:{pty,mdns,peer,tunnel,http,ws,notify,clipboard}@0.0.1`）= 该域 `wit/<domain>.wit` 首行 + 本 crate 的 `WIT_PACKAGE` / `MODULE_INTERFACES` / `EXPORTS` 字面量（`inventory` 要求编译期常量、跨 crate 无 const 插值——这些副本同批改）。
- **文本形状是跨语言契约**：常量必须保持 `pub const <NAME>: &str = "<值>";` 精确形态（含 `: &str`、无 macro / `env!` / `concat!`）——平台仓 node 解析器按此形状取值，改形状会静默打穿拼装与清单门禁。
- **消费口径**：宿主只经 `wasm-core` re-export 消费契约包名 / 版本；库内零依赖共享词汇（`server-base` / `host-api-core` / `cli-engine`）可直接依赖 `wasmnest-contract`。
- **WIT 分片**：`wasm-core/wit/core.wit`（**内核唯一合法绑定**，只收机制必需面）+ `wasm-core/wit/worker.wit`（worker world，零宿主 import，一期不进 compose）+ 各域 `wit/<domain>.wit`（域自持，`world cap-<domain>`）+ 端 cap（平台仓 `wit-src/cap-*.wit`）。本仓不做 union world；端组合在平台仓 `compose.json`。
- **bump 政策**：改哪个包 bump 哪个包（函数级追加 → patch；interface 增删 / 签名变 → minor）。`wasmnest:plugin` 改动 = 全部插件产物重建；域包改动只牵连真正 import 它的 app（平台 `compat.witPackages` 逐包校验）。
- **bump 流程**（缺一步断链）：
  1. 改本仓版本字面量（上两条列的位置）；
  2. 平台仓 `node scripts/compose-wit.mjs --all` → `pnpm run check:wit`；
  3. `node scripts/check-release-manifest.mjs --print-hash` 取新指纹写回 `contract.witSha256`，并同步 `contract.packages`（= 双端生成物并集，逐包一致）；
  4. 重建受影响插件产物（版本进 import 名，宿主与 guest 不等即实例化失败）。
- **改 WIT 不动实现，改实现不动契约**；契约是跨端 wire 面——移动端不跟演桌面破坏性接口，新增能力走端 cap 或双端功能级交集，不往 `core.wit` 塞端专属面。
- **权限词汇**真源 = `wasm-core/src/permission.rs`（`PERMISSION_VOCABULARY` / `VALID_PERMISSIONS` / `PERMISSION_API_MAP`）；平台生成物由 `pnpm run gen:permissions` 重出，**禁止手抄**，不得自造词汇。
- **主库 schema** 真源 = `wasm-core/src/db/schema.sql`（5 张机制表）；迁移必须幂等且失败显性。

### 2.3 wire 自持副本（改之前先确认「这是不是契约同步」）

能力域脱绑后，7 个 crate 以自持副本承载 SDK 的 wire 词汇（避免默认形态反向依赖 SDK）：

| 副本 | 平台 SDK 真源（`plugin-sdk-desktop/rust/src/…`；移动域同理） |
| --- | --- |
| `wasmnest-server-base/src/wire.rs` | `lib.rs`（`BusMessage`） |
| `wasmnest-server-http/src/wire.rs` | `types.rs` + `permission.rs` |
| `wasmnest-server-websocket/src/wire.rs` | `host/ws.rs` + `types.rs` + `permission.rs` + `host/bus.rs` |
| `wasmnest-server-peer-net/src/wire.rs` | `permission.rs` |
| `wasmnest-discovery-engine/src/wire.rs` | `host/bus.rs`（topic ×2）+ `host/mdns.rs`（事件名） |
| `wasmnest-pty-engine/src/wire.rs` | `host/bus.rs`（topic ×2）+ `host/pty.rs`（事件名）+ `permission.rs`（行级）+ `wire::key` |
| `wasmnest-ws-client-engine/src/wire.rs` | 移动 SDK `host/ws.rs` + `permission.rs`（事件名 / topic / 帧头） |

- 副本**定义块与 SDK 逐字一致**（漂移锁按行 / 块比对，换行归一化）；本地说明只写模块文档，**不改定义块内注释**。
- 改任一侧先问「真源是谁」：先改平台 SDK 再逐字同步副本（或反向），然后跑测试仓 `wire_drift_locks`（逐字比对全绿）。
- 副本里的权限常量必须与 `permission.rs` 同值（`permission_vocabulary_lock` 钉到生成物与 manifest）。

### 2.4 跨仓锁清单（改结构 / 文案前先看）

| 锁 | 钉住什么 |
| --- | --- |
| 本仓 `wasm-core/src/crate_boundary_lock.rs` | `SPLIT_CRATES` 登记表（单一事实源）+ 边合法性；新增 / 改名 / 移出改这一处 |
| 本仓 `*/src/{dependency_direction_lock,boundary_lock}.rs` | server 传输面 / peer-net / host-api-core / ws-client-engine：只向下、零横向、零回接宿主 |
| 本仓 `wasm-core/tests/platform_reference_registry_lock.rs` | 仓根全文零平台仓目录名（唯二豁免见 §0） |
| 平台仓 `capability_crates_unit_tests_only.rs` | 治理 crate 根无 `tests/` / `benches/` / `examples/` 与内部 dev-deps（豁免 `wasmnest-host-kit` + 已登记的 `platform_reference_registry_lock.rs`） |
| 平台仓 `capability_crates_no_product_ids.rs` | 能力 crate 生产代码零产品插件 id / 零退役宿主面词汇（`SCANNED_CRATES` 登记；wasm-core 暂不在面内，§8） |
| 平台仓 `host_module_desc_noun_lock.rs`（双端）/ `wasm_core_whole_crate_lock.rs` / `l2_gating_lock.rs` / `wit_package_version_lock.rs` | 描述符零产品名词 / 整核形态 / L2 反向依赖白名单 / 契约版本字面量 |
| 平台仓 `wasmnest-{mobile}/src-tauri/tests/{mobile_wasm_core_purity_lock,kernel_schema_single_truth_lock,peer_engine_consolidation_lock,mobile_host_websocket_client_domain_lock,retired_*}.rs` | 内核纯净性七判据 / 主库 schema / 引擎集中化 / 客户端域边界 / fork 与退役面不复活 |
| 测试仓 `wasmnest-test/cross-end-tests/tests/{wire_drift_locks,permission_vocabulary_lock,command_vocabulary_lock,mdns_browse_singleton_lock,bedcode_app_identity_lock,file_transfer_wiring_lock}.rs` | wire / 权限 / 命令词汇 / mDNS 单 browse 出口 / 身份与接线 |

> 锁是**可执行判据**：改对应面必须跑相关套件（§4.3）。锁红 = 同步真源与副本 / 修形态，**不是**改锁放行；豁免必须显式登记 + 写明理由。

---

## 3. 形态不变量

### 3.1 能力域默认形态（`default = []` + `common-host`）

带 `common-host` 的 5 个 crate：`wasmnest-{discovery,pty}-engine` + `wasmnest-server-{http,websocket,peer-net}`。

- **默认形态 = 纯引擎 + 端口**：零 WIT / 零 SDK / 零 wasmtime / 零宿主框架（Tauri、actix）/ 零 bundled SQLite / 零系统信息与文件监听——任何宿主可直接引用。
- **例外**：`server-http` / `-websocket` / `-core` 与 `wasm-core` 不在此承诺内（默认树仍有 actix / rusqlite；wasm-core 带 Tauri / actix / rusqlite）——不得描述为「任何宿主可直接引用」。
- **判据**：`sh scripts/check-default-form-deps.sh --offline`（CI 不带 `--offline`）覆盖 7 个宿主无关 crate（server-base / crypto / cli / pty / discovery / ws-client / p2p），命中 `tauri` / `actix*` / `rusqlite` / `sysinfo` / `notify` / `inotify` 即红（按 crate 名 token 精确匹配，别用裸 grep——路径含 `tauriProject`）。
- **`common-host` 才装配** `bindgen!` / `HostModule` 自报 / `inventory::submit!` / `impl Host`；开 feature 后 ABI / WIT / 权限位 / 事件形状 / 注册零变化（装配桌面 WIT 依赖，不是行为分叉）。
- 平台边经端口 trait 注入；**端口缺席 fail-visible**；引擎里不写 `#[cfg]` 端分支、不自建平台判断。
- **无头探针门禁**：永不开 `common-host`；`cargo tree -e normal` 出现 `wasmtime` / `wit-bindgen` / `inventory` / `wasmnest-host-kit` / `wasmnest-plugin-api` 即违规。
- 新增域 WIT：`world cap-<domain>` + `inventory` 自报，`CAPABILITY` / `FORWARD_PREFIX` / `EXPORTS` 三层命名一致 + 自洽漂移单测。

### 3.2 机制内核三件套

- **`host-kit`（装配期）**：只装机制——实例状态（含 WASI 槽）、`HostModule` 契约、自动注册表、生命周期钩子、端口装配自报、路由词汇、limits / metrics。**crate 内禁止产品名词**（判据 `registry.rs::product_noun_violations`）。
- **`host-api-core`（运行期实现层）**：只收「不依赖 WIT bindgen trait / 任何一端独有类型」的机制语义；每域两层 = 本 crate 实现 + 端 adapter。准入由 `src/boundary_lock.rs` 钉：只允许机制级依赖（`serde_json` / `tracing` / `rusqlite` 等），禁 SDK / wasm-core / `tauri` / `tokio`。`config` / `http` 已判定不抽，不要「顺手统一」。
- **`wasm-core`（运行期整核，单形态）**：`manager/`（加载 / 生命周期 / 实例调用 / 任务 / 热重载）、`manager/runtime/`（运行时壳 + **唯一合法 core 绑定** `core_binding.rs`）、`host_api/`、`security/`、`db/`、`test_support*`。
  - 无 common / bare 之分：端差异经 `HostModule` 自报、`GuestEventDispatcher`、`AbiPolicy` / `HostFactsPort` 注入——内核零端名、零端 `#[cfg]`。
  - `desktop-assembly`（默认开）= 桌面装配面；移动宿主 `default-features = false`。`test-support` = 测试面，不随生产发布。
  - **加 `bindgen!` / `impl … Host` 前先停下**：唯一合法绑定是 `core_binding.rs`；`runtime.rs` / `runtime/component.rs` 不得出现 `bindgen!` 与 `wasmnest::plugin::` 路径（移动纯净性锁判据 2）。
  - WASI 双端同源、常编译、默认全开，开 / 关由运行期 `CoreConfig::wasi` 定——不要用 feature 表达端差异。

### 3.3 server 分层

- **`server-base` = 叶子地基**：改它的依赖面影响全仓。默认依赖树只依赖 `wasmnest-contract`；`tauri` / `mdns-sd` / `sysinfo` / `local-ip-address` 全 optional 且 feature 默认关（`tauri-compat` / `mdns` / `system-info`）。桌面宿主**显式**开启，不靠传递 feature 合并；不开时在边界显式 `map_err`。
- **`server-core` = 跨传输内核**（supervisor / filter / link_crypto / metrics / `TransportFace` + actix `serve`）。它不是「传输无关」：actix / rusqlite 仍在默认树。http / ws 只向下依赖它，彼此零横向 import，也不得反向认识宿主（各自 `dependency_direction_lock.rs` 双向钉死）。
- **`server-peer-net` = 引擎域**（不过 actix 组合 / 过滤链 / 链路加密）：只向下依赖 base + `wasmnest-p2p-engine`；清单不得含 core / http / websocket / discovery-engine（mDNS 句柄经 `MdnsPort` 以纯值注入）。产品业务（传输任务 / 策略 / 历史 / 共享根 / 浏览编排）在 file-transfer 插件，本 crate 只留引擎原语与生命周期。
- 改依赖方向 = 改边界锁判据：**锁与清单一起改，先说明不变量为何改变**。

### 3.4 引擎、底座与契约房

- **crypto-engine**：只暴露无业务语义的中性算法原语；不做认证编排 / 协商 / 密钥策略；密钥材料由调用方提供。`CryptoError` 五类语义，`Display` 保持旧文案；映射回信封错误是消费方责任。
- **discovery-engine**：全进程共享守护只允许 `engine.rs` 创建一次；同一服务类型只允许 `type_hub.rs` 调 `daemon.browse` / `stop_browse`（重复 browse 会静默杀死别人的事件流）；新增调用点必须改测试仓 `mdns_browse_singleton_lock` 白名单并写理由。
- **pty-engine**：跨平台零 wasm；只接受调用方算好的 argv，**不做 shell 包装**；输出走环形缓冲 + 水印通知。
- **ws-client-engine**：`host-websocket` 客户端 5 原语 + 停用回收；平台差（权限门 / 投递 / 后台任务 / jwt 代发 / 退避）全经 `WsClientPorts` 注入；生产清单零内部依赖。
- **notify / clipboard-engine**：契约房，只持 WIT、零 Rust 实现；平台不支持项**静默忽略**（写死在契约文档），实现端不得改成报错。
- **cli-engine**：CLI 机制骨架；零内部依赖（只 contract + serde）；`WireError` 是纯 wire 类型，宿主错误 → 语义码映射住宿主侧。
- **peer-net `base/`**：重装即新身份（与设备身份刻意分离）；指纹即身份（`node_id = hex(SHA-256(raw ed25519 key))`，PeerId 经 `identity_bridge` 互验）；未信任拨入停应用层确认闸门；`_wasmnest-peer._tcp.local.` 与旧 `_wasmnest._tcp` 完全独立。
- **link-crypto**：只做纯字节协议（配置域 / 身份落盘 / 过滤器接线留宿主）；常量与算法**是协议兼容性表面**，与移动 TS 实现逐字节一致——改常量 = 跨端破坏性变更，先读头注。

### 3.5 写代码前的归属三问（顺序不可颠倒）

1. **机制还是产品语义？** 产品语义（设备 / 会话 / 配对 / 传输任务 / AI）→ 应用仓；机制 → 本仓；端差异与装配 → 平台仓。
2. **谁需要它？** 双端都要 → 共享 crate；仅一端 → 平台仓该端宿主；仅测试观测 → 测试仓。
3. **哪种可复用形态？** 纯引擎 + 端口 / 契约房（只持 WIT）/ 机制内核（host-kit 面）/ 传输面（server-*）——形态决定 feature、依赖纪律与锁。

任一答不上来，停下问用户；不要在能力 crate 里开业务口子。

---

## 4. 命令

> 无根 workspace：`cargo check/test/fmt/clippy` 在**目标 crate 目录**执行，没有仓级测试。CI 同样按 crate 遍历。

### 4.1 单 crate

| 命令 | 说明 |
| --- | --- |
| `cd <crate> && cargo check --lib --offline` | 快速编译检查（`--offline` 用本地索引；首次跑会刷新陈旧 lock，§4.4） |
| `cd <crate> && cargo test --offline` | 单测 + 集成测试（`host-kit` 的 `tests/forced_link*.rs` 是两个独立二进制：链接期属性无法同进程既「有」又「无」） |
| `cd <crate> && cargo test --lib --offline` | 只跑 `src/` 内单测 |
| `cargo fmt --manifest-path <crate>/Cargo.toml` | 先看 crate 根有无 `rustfmt.toml`：6 份（5 个 server crate + crypto）为 120 列，其余默认 100 列 |
| `cargo tree --offline -e normal -i <crate>` | 依赖倒查（门禁 / 反向边） |

### 4.2 `wasm-core` 的独立克隆解析限制（重要）

`desktop-assembly` 依赖未发布的 `wasmnest-plugin-api = "0.0.1"`，独立克隆直接 `cargo test` / `cargo metadata` 会报 `no matching package named wasmnest-plugin-api found`（`--no-default-features` 或删 lock 条目也一样）。**唯一本仓内测试路径 = 逃生阀**：

```bash
cd wasmnest-wasm-core
cargo test --offline \
  --config 'patch.crates-io.wasmnest-plugin-api.path="../../wasmnest/wasmnest-{desktop}/packages/plugin-sdk-desktop/rust"'
```

- 花括号先展开为端目录真名（§0）；补丁路径版本须与 SDK `Cargo.toml` 的 `version` 逐字一致。**不要把补丁写进任何 `Cargo.toml`**。
- 报 `failed to download` 时先去掉 `--offline` 跑一次补齐索引。
- **逃生阀会改写 `Cargo.lock`**：会把 `wasmnest-plugin-api` 的 `source` / `checksum` 两行删掉。提交前从 `HEAD` 还原；`git diff -- '*Cargo.lock' | grep -E '^[-+].*(source|checksum)'` 应只剩合法整包增删。
- **平台装配不能跑 wasm-core 自身测试**：非 workspace 成员 + dev-deps 会被 cargo 拒绝（`requires dev-dependencies and is not a member of the workspace`）。宿主侧价值 = 编译同图 + 宿主集成测试 + 读本仓源码的结构锁（§2.4）；测试仓的 `[patch.crates-io]` 也只服务它自己的成员。
- 其余 crate 独立克隆可直接构建测试。

### 4.3 门禁与验证矩阵（改动对应面时跑）

测试仓锁：`cd ../wasmnest-test/cross-end-tests && cargo test --test <lock> --offline`；平台仓锁：`cd ../wasmnest/wasmnest-{desktop}/src-tauri && cargo test --test <lock> --offline`。

| 改动面 | 必跑 |
| --- | --- |
| 任一 crate 代码 | 该 crate `cargo test --offline`（wasm-core 走 §4.2） |
| 默认形态 / 依赖 / feature | `sh scripts/check-default-form-deps.sh --offline`（CI 不带 `--offline`）；探针形态另跑下方代码块 |
| WIT / 契约版本 | §2.2 四步（compose → `check:wit` → manifest 指纹 + packages → 重建产物） |
| wire 副本 | `wire_drift_locks`（逐字比对全绿） |
| 权限词汇 | `permission_vocabulary_lock` + SDK 生成物重出 |
| discovery browse / 守护 | `mdns_browse_singleton_lock` |
| db/schema | 本 crate 幂等迁移用例 + 移动 `kernel_schema_single_truth_lock` |
| wasm-core 形态 / 绑定面 | 本 crate 测试 + 移动 `mobile_wasm_core_purity_lock` + 整核结构锁 |
| host-kit / 注册面 | host-kit 测试（含 `forced_link*`）+ 平台 `host_module_desc_noun_lock`（双端） |
| crate 根 `tests/` / dev-deps / 新增能力 crate | `capability_crates_unit_tests_only` / `capability_crates_no_product_ids` |
| 注释 / 文档 / 测试字符串 | `platform_reference_registry_lock`（扫仓根全文） |
| crate 增删改名 | §5 对应行 + `cargo metadata` 确认无重复能力 crate（两份 = 类型同一性断裂） |

```bash
cd wasmnest-headless-host-probe
cargo tree --offline -e normal | grep -E 'wasmtime|wit-bindgen|inventory|wasmnest-host-kit'   # 期望无输出
cargo tree --offline -e normal -i wasmnest-plugin-api                                        # 期望「did not match」
```

> 跨仓锁依赖 R1 同场布局或 `WASMNEST_PLATFORM_ROOT`（解析见测试仓 `tests/common/repo_paths.rs`）。**迁移期口径：不逐项跑全量回归**——按改动面跑针对性单测 + 相关锁，收口后统一全量。

### 4.4 target 落点与构建资源（含陷阱）

- crate 级 `target-dir` 相对该 crate 根解析：**平台装配**（宿主构建，本仓 crate 以 sibling path 入图）→ 落宿主 `target/<bucket>`，本仓 `.cargo/config.toml` 不参与；**独立克隆** → 落本仓根 `target/<bucket>`。
- 判据以运行时为准：`cargo metadata --no-deps --format-version 1` 的 `target_directory`（或 `CARGO_TARGET_DIR=<crate>/target`）。改 `target-dir` 后逐 crate 核验——**写错一层 `..` 不报错，只会安静落错地方**。
- 桶位：`server-libs` = 5 个 server crate + crypto；`host-kits` = host-kit / discovery / pty / wasm-core；夹具在 `<crate>/target/fixtures`；`wasmnest-test/cross-end-tests/target` 独立。
- **worktree 先做这一步再构建**：在平台仓根跑 `pnpm run target:worktrees`（把该 worktree 的 `target` / `<crate>/target` 软链到 `<容器根>/target-shared/wasmnest-lib/…`）。脚本幂等、活构建自动跳过；已有实体目录用 `--migrate`；清理删共享桶内容（删链接不省空间）。真源：平台仓 `docs/public/git.md` §8。
- 仓根 `.cargo/config.toml` 强制 `jobs = 4` + `rustc-wrapper = "sccache"`：**未装 sccache 一切 cargo 直接失败**（显性设计，不绕过）。**绝不要设 `CARGO_INCREMENTAL=1`**（sccache 拒绝执行）；`SCCACHE_CACHE_SIZE` 只认纯字节数字。
- `Cargo.lock` 随仓库跟踪，只经 cargo 变更、禁止手编。部分 lock 内部版本仍残留 `0.1.0`（应 `0.0.1`）：首次构建自动刷新，`--locked` 会失败（预期）；刷新结果作为独立 `chore(lib)` 提交，不混进功能提交。

### 4.5 发版钉平台指针（未经授权不要动平台仓）

```text
本仓：改 → 提交 → 打 tag（lib-vX.Y.Z）
平台仓：release-manifest.json 的 repos.lib.tag = 该精确 tag（contract.version 同步）
        → pnpm run check:manifest（校验本仓 HEAD == tag 且工作树干净）
        → 平台仓提交 manifest
```

三个 tag 各自独立（`lib-` / `apps-` / `test-` 前缀）。WIT 变更另走 §2.2。

---

## 5. 任务路由：改 X 先读 Y

| 任务 | 动手前必读 |
| --- | --- |
| WIT / 契约包版本 | §2.2 + `wasmnest-contract/src/lib.rs` + `wit/core.wit` / 域 WIT；版本字面量 + 平台 `compose-wit.mjs --all` / `check:wit` / `check:manifest --print-hash` + 重建产物 |
| 权限词汇 | `wasm-core/src/permission.rs`（真源）→ 平台 `pnpm run gen:permissions` → 测试仓 `permission_vocabulary_lock`；同步 §2.3 副本权限常量 |
| wire 词汇 / 事件名 / topic | §2.3；先确认真源（平台 SDK），逐字同步副本，跑 `wire_drift_locks`；不改定义块内注释 |
| 主库 schema / 迁移 | `wasm-core/src/db/{schema.sql,database.rs}`；平台移动 `kernel_schema_single_truth_lock`；禁止手改生产库、禁止宿主自持 DDL |
| host_api 机制语义 | `wasmnest-host-api-core` 对应域 + `src/boundary_lock.rs` + 头注「域进度」；adapter 改动看两端消费面 |
| wasm-core 机制 / 运行时 / 安全闸门 | `wasm-core/src/lib.rs` 头注 + `manager/runtime/{core_binding,wasi}` + `security/`；先确认绑定面不回流（§3.2）；移动 `mobile_wasm_core_purity_lock` |
| 能力域原语 / 引擎 | 对应 crate 头注 + `plugin_binding/` + 端口 trait；`default` 与 `common-host` 两形态都要能编译；discovery 另跑 `mdns_browse_singleton_lock` |
| host-kit 注册面 / 描述符 / 路由词汇 | `host-kit/src/{module,registry,route,assembly}.rs` + `tests/forced_link*.rs` + 平台 `host_module_desc_noun_lock`（双端） |
| server 分层依赖方向 | §3.3 + 对应 `dependency_direction_lock.rs` + `crate_boundary_lock.rs` 的 `SPLIT_CRATES` / `ALLOWED_*`；清单与锁同批改 |
| 新增 / 改名 / 删除 crate | §3.5 三问 → 目录 = 包名 → 本仓 `SPLIT_CRATES` 登记（纯契约 / 夹具类不登记，§6.3）→ 平台 `SCANNED_CRATES` + 宿主 `Cargo.toml` / `common-host` + `compose.json`（若持 WIT）+ 强制引用 → 属默认形态则加进无头探针 → 平台 manifest tag |
| 依赖版本 / 新增依赖 | 各 crate `Cargo.toml` 注释（双端锁步：wasmtime 48、inventory 0.3.24；wasm-core 的 `reqwest` 必须 `default-features = false`，防 Android 拉 openssl-sys）；机制级依赖白名单（§3.2）；跑该 crate 测试 + 边界锁 |
| 增加 crates.io 依赖 / 升级 | 先问用户；`Cargo.lock` 随改随提交（§4.4） |
| 发版 / 钉指针 | §4.5；未经授权不改平台仓 |
| 独立克隆测试 / 构建失败 | §4.2 + §4.4（`target_directory` / `--locked` 与陈旧 lock） |
| 清理 target / 磁盘吃紧 | 先 `df -h` / `du -sh`；可整删：旧落点 `${WASMNEST}/target/{host-kits,server-libs}`（无活引用）、测试仓 target、夹具 target；本仓 `target/*` 是**活跃桶**，`cargo clean` 只对单 crate 且确认不误伤平台装配桶 |
| 排查「改了没生效」 | 先确认构建读哪份源码（平台装配读 sibling `<平台>/../wasmnest-lib/<crate>`，与独立克隆是同一物理路径）；再确认 target 桶与 sccache |
| 定位 crate / 符号 | `rg` + `cargo metadata`；真源先在 `Cargo.toml` description 与 `src/lib.rs` 头注 |

---

## 6. 硬约束

### 6.1 无产品语义

- 能力域 / 引擎 / 传输面 / 机制内核的生产代码**不得出现产品插件 id**（`com.wasmnest.<产品段>`）与退役宿主面词汇（`host-session` / `host-terminal` / `output-ring-fetch` 等）；注释里点名产品解释「为什么」可以，代码 / 常量 / 字符串不行。
- `host-kit` 描述符（模块名 / 接口路径 / 权限位）不得含产品名词词段。
- 「引擎实现」允许的形态 = 参数透传 + 机制语义（属主隔离 / 事件定向投递 / 停用回收）；业务含义由插件解释。做不到 = 放错仓。

### 6.2 依赖与边界

- 生产 `[dependencies]` 只允许机制级依赖；`dev-dependencies` 不得新增内部 crate 边（唯一豁免 `wasmnest-host-kit` 的强制链接探针）。
- 禁止用 `#[cfg(end)]` / feature 表达端差异（端事实经 `HostFactsPort` / `AbiPolicy` / 端口注入）。
- 不允许旁路：不得用 `[patch]` / 本地重导出 / 复制源码绕过边界锁。
- `wasmnest-headless-host-probe` 不进任何宿主依赖清单、不登记 `SPLIT_CRATES`。

### 6.3 契约与版本

- 包名 / 版本只在真源改一处（§2.2）；其余字面量是同批同步副本，由平台锁断言。
- `wasmnest-contract` **不登记 `SPLIT_CRATES`**：该表同时驱动「宿主清单声明全部拆分产物」，登记会要求宿主直连契约 crate；而宿主只允许经 `wasm-core` re-export 消费。库内零依赖词汇 crate 可直接依赖它。
- `wasmnest-cli-engine` **不登记 `SPLIT_CRATES`**：消费方是平台仓 CLI / 无头 bin（尚未实施），不是宿主 bin 本体。新增 crate 按此判据复核，不要反复讨论。
- WIT 变更必须 bump + 重拼 + 重建产物（§2.2）；禁止手改平台端生成物 `rust/wit/`。
- 权限词汇不得自造；主库 DDL 只在 `db/schema.sql`；迁移必须幂等且失败显性。

### 6.4 测试

> 通用测试规范（两种形态 / 禁止交付 / 临时目录 / 锁纪律 / 验证底线）真源 `../wasmnest/docs/public/testing.md`，不复制。

- 单测住 `src/` 内（`#[cfg(test)]`）；crate 根 `tests/` 是例外面：仅 `wasmnest-host-kit` 与 `wasm-core/tests/platform_reference_registry_lock.rs`（已登记）。新增 crate 根 `tests/` 前先确认平台锁状态。
- 新增能力域必须自持至少一条自洽漂移单测（范式：`routing.rs` 的「EXPORTS 条数 == 端口 `forward_*` 方法数」）；机制不变量必须有可执行判据，不能只写文档。

### 6.5 注释、命名与提交

> 通用规范真源 `../wasmnest/docs/public/{commenting,git}.md`，不复制。

- 注释 / 文档禁止写平台仓目录名与跨仓读取路径（§0）；端词汇（桌面宿主 / 移动宿主）可用。
- rustfmt 列宽按 crate 根 `rustfmt.toml`（120 vs 默认 100），不跨 crate 统一重排。
- Commit scope 用 `(lib)`（`refactor(lib):` / `fix(lib):` / `chore(lib):`）；格式 / 禁 AI 标记 / `--force` 禁令 / 只提交源码等见 git.md。

### 6.6 安全

- 禁止提交密钥 / 凭据 / token；禁止进日志、进文档；凭据只记长度不落明文（唯一指定存储 = 宿主 `plugin_secrets` 表）。
- 不新增旁路认证 / 静默降级；失败一律 fail-closed 或 fail-visible（端口缺席 / 未声明权限的 WIT 调用 / 非法 JSON 载荷都要显性失败）。
- 对等网络：指纹即身份（双向 verifier 真实签名验证）；未信任方停应用层确认闸门；不要为「好用」加静默信任。

### 6.7 Rust 编写与审核（强制 skill）

> **规则**：本仓全是 Rust——任何 crate / 模块 / `Cargo.toml` / 测试 / rustdoc / unsafe 的**编写与审核**，动手前与完成审核时**必须**显式加载并遵循 `/skill:rust-best-practices`（skill 落点 `~/.agents/skills/rust-best-practices/SKILL.md`）；未加载即开始写或评审 = 流程违规，视为未完成交付 / 无效评审。该 skill 是通用惯用法与 API 设计判据层（占 §0 裁决第 5 档「通用工程经验」），与本仓硬约束（§2 契约 / §3 形态不变量 / §6 各节 / crate 根 `rustfmt.toml`）冲突时**以本仓为准**；其自带的自检命令（fmt / clippy）不替代 §4.3 的测试与锁门禁。

---

## 7. 完成定义

按 §4.3 跑对应门禁 + 该 crate `cargo test --offline` 全绿，**贴实际命令与结果**；无法运行要说明原因与风险。下游 crate 显式声明自己用到的 feature（不靠消费图并集救场）；依赖边新增 / crate 增删改名另核 `crate_boundary_lock` 与平台治理锁。通用验证底线（实跑贴结果、钩子跳过 ≠ 通过）见 `testing.md` §5。

---

## 8. 已知债（动手前复核）

1. **wasm-core 的 SDK 版本依赖**：`desktop-assembly` → 未发布 `wasmnest-plugin-api = "0.0.1"`，导致独立克隆无法解析（§4.2）。终态票据未做，**勿扩大**。
2. **`Cargo.lock` 版本残留**：部分 crate 内部版本仍 `0.1.0`（应 `0.0.1`）；首次 cargo 运行自动刷新，刷前 `--locked` 失败（预期）；刷新单独提交（§4.4）。
3. **wasm-core 两处产品 id 泄漏**：`security/fs_auth.rs` 的 `FIRST_PARTY_TRUSTED_DIRS`、`manager/host/activation.rs` 的 `LEGACY_API_PLUGIN_ALIASES`——独立票据处置；平台语义锁暂不扫 wasm-core。

---

> 本文件与真源冲突时，以真源 + 可执行锁为准，并回来修正本文件。
