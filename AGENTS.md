# AGENTS.md

> **本文件是 wasmnest-lib（能力仓）的 crate 开发导航与硬约束。**
> 只给方向、判据与导航；机制细节、历史与踩坑在真源里（各 crate 的 `Cargo.toml` description、`src/lib.rs` 头注、`wasmnest-contract/src/lib.rs`、WIT、平台仓锁），需要时按指针去读，不在本文件复制。

## 0. 定位与冲突裁决

**本仓定位**：三仓（应用仓 / 平台仓 / 能力仓）里唯一的**应用无关引擎仓**。提供四类东西：

1. **插件机制**：`wasmnest-wasm-core`（运行期整核）+ `wasmnest-host-kit`（装配期内核）+ `wasmnest-host-api-core`（域实现层）；
2. **能力域引擎**：`wasmnest-{discovery,pty,ws-client,crypto,notify}-engine` + 五个 `wasmnest-server-*`（传输面与内核）；
3. **共享底座**：`peer-net`（对等网络身份/TLS/发现）、`link-crypto`（链路加密协议）；
4. **契约真源**：`wasmnest-contract` crate（`src/lib.rs`）与各 `wit/<domain>.wit`——`wasmnest:plugin@0.0.2` 包名/版本只在本仓手写。

**边界一句话**：产品语义（会话 / 终端 / 文件传输 / AI / Agent）住应用仓；端差异与装配（宿主薄壳、SDK、WIT 组合、权限门落点）住平台仓；本仓只做**可复用机制 + 端口抽象 + 契约**，不读平台/应用源码、不做产品判断。

冲突按下述优先级裁决（高者胜）：

1. **用户当前明确指令**
2. **安全与架构红线**（§3 / §6，含所有边界锁）——确需越线时停下向用户确认，禁止自行放松锁或把锁改红
3. **本文档硬约束**（「必须 / 禁止」字样）
4. **跨仓真源**（`wasmnest-contract`、WIT、平台仓锁与 SDK、`release-manifest.json`、代码自身）
5. **通用工程经验**

维护口径：

- **路径基准**：仓内路径相对能力仓根。跨仓按 R1 同场布局记为 `../wasmnest`（平台仓：双端宿主 + SDK + 构建工具）、`../wasmnest-apps`（应用仓）、`../wasmnest-test`（测试容器仓，跨端工程在 `cross-end-tests/`）。
- **平台仓两端目录在本文一律记作 `wasmnest-{desktop,mobile}`**（需要某端时写 `wasmnest-{desktop}`）——**复制命令 / 引用路径前先展开花括号**。原因：本仓全文不得出现平台仓目录名字面量（零平台引用锁 `wasmnest-wasm-core/tests/platform_reference_registry_lock.rs` 扫描仓根一切文本文件；唯二豁免是 `wasmnest-server-websocket` 与 `wasmnest-server-peer-net` 两个 `src/dependency_direction_lock.rs` 里作为**被判对象**的依赖名字面量）。**写任何注释 / 文档 / 测试字符串时都适用这条**：提端用「桌面宿主 / 移动宿主」等端词汇，不提跨仓目录名或跨仓读取路径。
- **文档字面 ≠ 事实**：引用任何路径 / 命令 / 锁名 / 版本前先用 `ls` / `rg` / `cargo metadata` 核对；与实际不符先修文档再继续。
- **最小改动**：只改任务必要文件；禁止顺手重构相邻代码、擅自升级依赖、批量重排格式；设计取舍不猜，先问用户。
- **项目阶段（内部研发起步期）**：版本线自 `0.0.1` 重开，无对外 ABI 兼容义务——破坏性变更可直接进行，但跨仓契约按**精确 tag** 钉住（§2.2 / §5「发版钉平台指针」）；退役面必须 **fail-visible**（点名缺失 + 给出路），禁止静默降级成「查不到就返回空」。
- **本仓无独立 CI、无文档面**：唯一人读文档是本文件（`.md` 白名单之外不新增文档，除非用户明确要求）；验证 = 本地命令实跑 + 平台仓 / 测试仓相关锁（§7）。
- **四仓通用规范（git 提交 / 注释命名 / 测试与验证 / 版本号管理 / issue 管理）真源在 `../wasmnest`/`docs/public/`**（`git.md` / `commenting.md` / `testing.md` / `versioning.md` / `issues.md`），与本文件硬约束同级；通用内容不在此复制，本文件只留仓特有增量（§6.4 / §6.5）。

---

## 1. 仓速览

**工程形态**：**无根 workspace**——17 个独立 crate（各自 `Cargo.toml` + 自带 `Cargo.lock`，随仓库跟踪） + 4 个夹具 crate。**命令一律在 crate 目录执行**，一个 crate 一个 cargo 调用；不存在「仓级 cargo test」。

```text
wasmnest-lib/
├─ wasmnest-contract/                     # 契约包名/版本唯一手写真源（零依赖，只装常量；§2.2）
├─ wasmnest-wasm-core/                    # 插件机制整核 + wit/core.wit + db/schema.sql
├─ wasmnest-host-kit/                     # 装配期机制内核（tests/ 与 fixtures/ 在此）
├─ wasmnest-host-api-core/                # host_api 无 WIT 域实现层
├─ wasmnest-server-{base,core,http,websocket,peer-net}/
├─ wasmnest-{discovery,pty,crypto,ws-client,notify}-engine/
├─ link-crypto/  peer-net/                # 包名分别是 wasmnest-link-crypto / wasmnest-peer-net
└─ wasmnest-headless-host-probe/          # 默认形态可引用性的长期门禁
```

**依赖分层**（唯一合法方向自上而下；横向边由各锁钉死）：

```text
插件（wasm-apps / 第三方）——应用仓
   │  WIT host-* · bus · events · 互调
   ▼
能力域 crate（默认 = 纯引擎 + 端口；common-host 才装 WIT 绑定层）
   ▼
host-kit（装配期：状态 / 模块契约 / 注册表）
   ▼
wasm-core（运行期：运行时壳 + core 绑定 + host_api adapter，消费 host-api-core）
   ▼
双端宿主 src-tauri/src/（组合根 · 薄壳）——平台仓
```

**crate 一览**（真源 = 各 crate `Cargo.toml` description 与 `src/lib.rs` 头注；本表只是导航）：

| 目录（包名） | 定位（一句话） | 形态 / feature | WIT 真源 | 主要消费方 |
| --- | --- | --- | --- | --- |
| `wasmnest-contract` | **契约常量**：`PACKAGE` / `PACKAGE_NAME` / `PACKAGE_VERSION` 唯一手写真源；零依赖、不装 WIT | 无 feature | — | wasm-core（`use` 后派生）、平台仓脚本与锁（正则读源文件） |
| `wasmnest-wasm-core` | 插件机制**整核**：wasmtime 组件宿主运行时壳 + host_api adapter + 安全闸门 + 主库/引擎面 | `default = ["desktop-assembly"]`；`test-support` | `wit/core.wit` | 平台双端宿主（桌面默认开 / 移动 `default-features = false`）、测试仓 |
| `wasmnest-host-kit` | 装配期机制内核：`WasmPluginState` / `HostModule` 契约 / 自动注册表 / limits / metrics | 无 feature | — | 双端宿主、全部 `common-host` 能力域、wasm-core |
| `wasmnest-host-api-core` | host_api 无 WIT 域**实现层**：gate / storage / bus / database / log / events / fs | 无 feature | — | wasm-core adapter、server-base（re-export 护栏常量） |
| `wasmnest-server-base` | server **叶子地基**：错误信封 / 常量 / 系统信息 / 网络配置形状 / 连接身份 / 端口 traits / wire | `tauri-compat`（默认开） | — | 几乎全仓 + 双端宿主 + 测试仓 |
| `wasmnest-server-core` | 与传输无关的 server 内核：supervisor / 过滤链 / link_crypto / metrics / `TransportFace` + serve | 无 feature | — | 平台双端装配、http/ws 向下依赖、测试仓 |
| `wasmnest-server-http` | HTTP 传输面 + `host-http` 绑定层（端点注册表 / 网关 / 中间件 / DTO 锚点） | `default = []`；`common-host` | `wit/http.wit` | 桌面宿主（common-host）、wasm-core（引擎面）、移动宿主（引擎面）、测试仓 |
| `wasmnest-server-websocket` | WebSocket 传输面 + `host-websocket` 客户端域接线 / 服务端引擎函数 | 同上 | `wit/ws.wit` | 同 http |
| `wasmnest-server-peer-net` | 对等网络**引擎域** + `host-peer` 绑定层（非传输面，不参与 actix 组合） | 同上 | `wit/peer.wit` | 桌面（common-host）、移动（引擎面）、wasm-core（`PeerCtx`）、测试仓 |
| `wasmnest-discovery-engine` | mDNS 能力域：共享守护 + 类型中枢 + 浏览/广播双句柄表 + 宿主自播面 | 同上 | `wit/mdns.wit` | 桌面（common-host）、移动（引擎面）、测试仓 |
| `wasmnest-pty-engine` | PTY 能力域 + 跨平台伪终端引擎（进程生命周期 / 读取线程 / 环形缓冲） | 同上 | `wit/pty.wit` | 桌面宿主（common-host） |
| `wasmnest-ws-client-engine` | WS **出站客户端**能力域：句柄表 / 双任务 / 心跳 / 退避重连 / 停用回收 | 无 feature | `wit/ws.wit` | 移动宿主、测试仓 |
| `wasmnest-crypto-engine` | 中性加密算法原语（aes_gcm/chacha/hybrid/kdf/rsa/x25519）+ 名称寻址注册表 | 无 feature | —（WIT 面在宿主 `plugin/crypto.rs`） | 桌面宿主、server-core |
| `wasmnest-notify-engine` | 通知域**契约房**：只持 WIT + 端口词汇（当前无端口），零实现 | 无 feature | `wit/notify.wit` | 双端 `compose.json` 组合——**无 Rust 消费者** |
| `peer-net`（`wasmnest-peer-net`） | 对等网络共享底座：Ed25519 节点身份 / 自签证书 / TLS 直连 / 信任闸门 / mDNS 发现 | 无 feature | — | wasm-core、server-peer-net、discovery-engine、双端宿主、测试仓 |
| `link-crypto`（`wasmnest-link-crypto`） | 链路报文加密协议核心：HTTP 信封 / WS 握手 IKM / 二进制帧 | 无 feature | — | wasm-core（`link_crypto`）、双端宿主 |
| `wasmnest-headless-host-probe` | 无头宿主探针：以非桌面形态引用全部能力域，钉「默认形态任何宿主可引用」 | 无 feature（永不开 `common-host`）、零 dev-deps | — | 仅门禁——**不得进任何宿主依赖清单** |

**夹具 crate**（不入一览表、不发布）：`wasmnest-host-kit/fixtures/forced-link-probe`（强制链接实证）、`wasmnest-wasm-core/fixtures/{wasi-test,wasip3-test,p3-async-host-import-test}`（自持夹具，绑定本 crate `wit/core.wit`，零 SDK 依赖）。

**跨仓装配（R1 兄弟布局）**：

- 平台仓**不再挂 submodule**：平台宿主 `src-tauri/Cargo.toml` 直接 path 依赖 `../../../wasmnest-lib/<crate>`，消费的就是本仓工作树；平台仓不复制、不镜像本仓源码。
- 测试仓（`../wasmnest-test/cross-end-tests`）同样经兄弟目录 `../wasmnest-lib/<crate>` 依赖本仓（`tests/common/repo_paths.rs::lib_root()`，`WASMNEST_LIB_ROOT` 可覆盖）。**全链路只有这一条物理路径**——若再出现第二份本仓拷贝，依赖图会出现两个同名 crate、编译期类型同一性断裂（跨端夹具实测踩过）。
- 本仓**不读**平台 / 应用源码（零平台引用锁钉死）；曾存在的夹具构建器 / 应用路径 resolver 已全部归位平台仓或改为仓内自持。
- 版本线 `0.0.1` 与 tag：本仓独立打 `lib-vX.Y.Z`（当前线 `lib-v0.0.x`）；平台仓 `release-manifest.json` 的 `repos.lib.tag` 指向**精确 tag**，平台侧校验本仓 HEAD == 该 tag 且工作树干净。
- **版本号只在发布时 bump**：crate `version` / `PACKAGE_VERSION` 不随 dev 日常改动（功能 / 修复 / 重构）变动；发布时联动打 tag + 平台仓 manifest（规则见 `../wasmnest`/`docs/public/versioning.md`；契约版本另有 §2.2 流程，与普通发版解耦）。

**命名纪律**：新 crate 目录名 = 包名（`wasmnest-<域>`）；唯二例外是历史底座 `link-crypto` / `peer-net`（目录名与包名不同形，引用时看清）。`plugin-sdk-*` / `wasmnest-componentize` 等**不属于本仓**（分别在平台仓 SDK 与平台仓 `tools/`）。

---

## 2. 跨仓边界与契约

### 2.1 依赖方向（禁止反向引用）

- **本仓 → 平台仓**：零源码读取（文本面零目录名字面量，§0）。唯一合法耦合物是**契约**：`wasmnest-contract` 常量、`wit/*.wit`、crate 版本号。平台仓读本仓的入口是 sibling path 与 `pnpm run check:manifest`（校验本仓 HEAD 精确 tag + clean）。
- **平台仓 → 本仓**：宿主 `src-tauri/Cargo.toml` 直接 path 依赖 `../../../wasmnest-lib/<crate>`；`common-host` feature 由桌面宿主开启（5 个能力域），移动宿主不开（用自有 `host_domains/*` 实现，只取引擎面）。
- **唯一已知反向边（架构债）**：`wasmnest-wasm-core` 的 `desktop-assembly`（默认开）对桌面 SDK 的 `wasmnest-plugin-api = { version = "0.0.1" }` 版本依赖。该 SDK 未发布到 crates.io，消费侧（桌面宿主、测试仓）用 `[patch.crates-io]` 指回工作树 SDK（`<平台>/wasmnest-{desktop}/packages/plugin-sdk-desktop/rust`）；**版本必须与 SDK `Cargo.toml` 逐字一致**，否则 patch 不生效、解析失败。终态由票据清偿（`desktop-assembly` 整体迁桌面宿主、依赖删除）——本次勿扩大该债。
- **能力域 crate 的 `[dependencies]` 不得含任何下游 crate**：禁 SDK（`wasmnest-plugin-api*`）、禁双端 wasm-core、禁 `wasmnest-host-kit`（机制内核只经 `common-host` 装配）、禁宿主平台（`tauri`）与传输栈（`actix`，传输面自身除外）。每条规则都有配对锁（§2.4）。
- **路径依赖重命名**：依赖被重命名时（如跨端夹具 `package = "..."`）依赖键必须显式写 `package`；lib name 与 package name 不同形（`link-crypto` / `peer-net`）是本仓的检查重点。

### 2.2 契约真源与版本（改 WIT 前必读）

- **包名 / 版本唯一手写真源** = `wasmnest-contract/src/lib.rs`（`PACKAGE_NAME` / `PACKAGE_VERSION` / `PACKAGE`，零依赖 crate）。三条使用路径：① `wasm-core` 以普通 crate 依赖 `use` 后运行期拼导出名（`contract::export_item`）；② 能力域在 `const` / `static` 位置写导出名字面量（`inventory` 自报要求编译期常量；跨 crate **纯拷贝**可行，但版本嵌在串中段的组合名无 const 插值机制——锁钉的正是组合串）；③ 平台仓 `scripts/compose-wit.mjs` 与发布清单锁正则读该 crate 源文件。
- **文本形状是跨语言契约**：常量必须保持 `pub const <NAME>: &str = "<值>";` 精确形态（含 `: &str`、无 macro、无 `env!` / `concat!`）——平台仓两处 node 解析器按此形状取值，改成 `concat!` / `env!` 会静默打穿拼装与清单门禁。
- **WIT 分片**：`wasmnest-wasm-core/wit/core.wit`（**内核唯一合法绑定**，只收机制必需面）+ 各能力域 `wit/<domain>.wit`（域自持，`world cap-<domain>`）+ 端 cap（平台仓 `wit-src/cap-*.wit`）。本仓**不做 union world**；端组合在平台仓 `compose.json` 驱动。
- **bump 政策**：任何 WIT 变更（含函数级追加）→ patch；interface 增删 / 签名变 → minor。bump 流程（跨仓，缺一步就断链）：
  1. 改本仓 `wasmnest-contract/src/lib.rs` 的 `PACKAGE_*` + 同步所有硬编码 `@0.0.1` 字面量（`wasmnest-discovery-engine/src/{routing.rs,lib.rs}` 的 `EXPORTS` / `MODULE_INTERFACES`、其余域 `plugin_binding.rs` 的 `MODULE_INTERFACES`；值层由平台仓 `wit_package_version_lock.rs` 与内核 `manager::capability` 对偶锁钉住）；
  2. 平台仓重拼生成物：`node scripts/compose-wit.mjs --all` → `pnpm run check:wit`；
  3. **重建全部插件产物**（版本进入 import 名，宿主与 guest 版本不等即实例化失败）；
  4. `node scripts/check-release-manifest.mjs --print-hash` 更新 `contract.witSha256` → `pnpm run check:manifest`。
- **改 WIT 不动实现**、改实现不动契约；契约是跨端 wire 面，移动端**不跟演**桌面端破坏性接口——新增能力默认走端 cap 或双端功能级交集，不要往 `core.wit` 里塞端专属面。
- 权限词汇真源 = `wasmnest-wasm-core/src/permission.rs` 的 `PERMISSION_VOCABULARY` / `VALID_PERMISSIONS` / `PERMISSION_API_MAP`；平台 SDK 的生成物（`permission-vocabulary.json`）由 `pnpm run gen:permissions`（即 SDK 的 `cargo run --example gen_permission_vocabulary`）重出，**禁止手抄**；不得自造词汇表外的权限字符串。主库 schema 真源 = `wasmnest-wasm-core/src/db/schema.sql`（5 张机制表，迁移**必须幂等**）。

### 2.3 wire 自持副本（改之前先确认「这是不是契约同步」）

能力域脱绑后，7 个 crate 以**自持副本**承载桌面/移动 SDK 的 wire 词汇（避免默认形态反向依赖 SDK）：

| 副本文件 | 对应的平台 SDK 真源（`plugin-sdk-desktop/rust/src/…`，移动域同理） |
| --- | --- |
| `wasmnest-server-base/src/wire.rs` | `lib.rs`（`BusMessage` 形状） |
| `wasmnest-server-http/src/wire.rs` | `types.rs` + `permission.rs` |
| `wasmnest-server-websocket/src/wire.rs` | `host/ws.rs` + `types.rs` + `permission.rs` + `host/bus.rs` |
| `wasmnest-server-peer-net/src/wire.rs` | `permission.rs` |
| `wasmnest-discovery-engine/src/wire.rs` | `host/bus.rs`（topic 命名两处）+ `host/mdns.rs`（事件名） |
| `wasmnest-pty-engine/src/wire.rs` | `host/bus.rs`（topic 两处）+ `host/pty.rs`（事件名）+ `permission.rs`（行级）+ `wire::key` 整段 |
| `wasmnest-ws-client-engine/src/wire.rs` | 移动 SDK `host/ws.rs` + `permission.rs`（事件名 / topic / 帧头布局） |

铁律：

- 副本的**定义块与 SDK 逐字一致**（漂移锁按行/块级文本比对，换行归一化）；本地说明只写模块文档，**不要改定义块内注释**。
- 改任一侧先问「真源是谁」：**先改平台 SDK，再逐字同步副本**（或反向），然后跑测试仓 `cross-end-tests/tests/wire_drift_locks.rs`（19 条断言，读双侧源文件）。
- 副本文件里的权限常量（如 `PERMISSION_PTY_IO` / `PERMISSION_NETWORK_HTTP` / `PERMISSION_PEER` / `ws:client`）必须与 `permission.rs` 真源同值；`permission_vocabulary_lock` 会把真源钉到平台生成物与生产 manifest。

### 2.4 跨仓锁清单（平台仓 / 测试仓读本仓源码；改结构 / 文案前先看它们）

| 锁（所在仓 → 文件） | 钉住什么 |
| --- | --- |
| 本仓 · `wasmnest-wasm-core/src/crate_boundary_lock.rs` | `SPLIT_CRATES` 登记表（**单一事实源**）+ 边合法性；新增/改名/移出 split crate 改这一处，平台侧锁同步消费 |
| 本仓 · `*/src/dependency_direction_lock.rs`、`boundary_lock.rs` | server 传输面 / peer-net / host-api-core / ws-client-engine 的「只向下、零横向、零回接宿主路径」 |
| 本仓 · `wasmnest-wasm-core/tests/platform_reference_registry_lock.rs` | 仓根全文零平台仓目录名字面量（唯二豁免见 §0） |
| 平台仓 · `wasmnest-{desktop}/src-tauri/tests/capability_crates_unit_tests_only.rs` | 治理 crate 根不得有 `tests/`/`benches/`/`examples/` 与内部 dev-dependencies（豁免：`wasmnest-host-kit`；`wasm-core/tests/platform_reference_registry_lock.rs` 已按文件登记在 `CRATE_TEST_DIR_EXCEPTIONS`） |
| 平台仓 · `capability_crates_no_product_ids.rs` | 能力 crate 生产代码零产品插件 id / 零退役宿主面词汇（按 `SCANNED_CRATES` 登记；`wasm-core` 暂不在面内，见 §8） |
| 平台仓 · `host_module_desc_noun_lock.rs`（双端）/ `wasm_core_whole_crate_lock.rs` / `l2_gating_lock.rs` / `wit_package_version_lock.rs` | 描述符零产品名词 / 整核垫片形态 / L2 反向依赖白名单 / 契约版本字面量（`@0.0.1`） |
| 平台仓 · `wasmnest-{mobile}/src-tauri/tests/{mobile_wasm_core_purity_lock, kernel_schema_single_truth_lock, peer_engine_consolidation_lock, mobile_host_websocket_client_domain_lock, retired_*}.rs` | 内核纯净性七判据 / 主库 schema / 引擎集中化 / 客户端域边界 / fork 与退役面不复活 |
| 测试仓 · `cross-end-tests/tests/{wire_drift_locks, permission_vocabulary_lock, command_vocabulary_lock, mdns_browse_singleton_lock, bedcode_app_identity_lock, file_transfer_wiring_lock}.rs` | wire / 权限 / 命令面词汇 / mDNS 单 browse 出口 / 身份与接线不变量 |

> 这些锁是**可执行判据**，不是文档：改本仓对应面时必须在平台仓 / 测试仓跑相关套件（§7）。锁红时的正确动作是同步真源与副本 / 修形态，**不是**改锁放行；确需豁免必须显式登记条目 + 写明理由。

---

## 3. Crate 形态与不变量

### 3.1 能力域默认形态（`default = []` + `common-host`）

带 `common-host` 的五个 crate：`wasmnest-{discovery,pty}-engine`、`wasmnest-server-{http,websocket,peer-net}`。

- **默认形态 = 纯引擎机制 + 端口抽象**：零 WIT / 零 SDK / 零 wasmtime 依赖，任何宿主（移动端 / 无头 / 第三方）可直接引用。
- **`common-host` 才装配** `bindgen!` / `HostModule` 自报 / `inventory::submit!` / `impl Host`；开 feature 后 ABI / WIT / 权限位 / 事件形状 / 注册零变化（「装配桌面 WIT 依赖」而非行为分叉）。
- 平台边经端口 trait 注入（权限门 / 事件投递 / 后台任务 / 路径 / 系统信息等），**端口缺席 fail-visible**；不要在引擎里 `#[cfg]` 端分支、不要自建平台判断。
- 长期门禁 = `wasmnest-headless-host-probe`：永不开 `common-host`，`cargo tree` 出现 `wasmtime` / `wit-bindgen` / `inventory` / `wasmnest-host-kit` / `wasmnest-plugin-api` 即违规（命令见 §4）。
- 新增域 WIT 一律 `world cap-<domain>` + `inventory` 自报（`routing.rs` 范式：`CAPABILITY` / `FORWARD_PREFIX` / `EXPORTS` 三层命名一致，且有自洽漂移单测）。

### 3.2 机制内核三件套

- **`wasmnest-host-kit`（装配期）**：只装机制——实例状态（含 WASI 槽，常编译）、`HostModule` 契约、自动注册表（收集 → 排序 → 白名单 → linker 装配）、生命周期钩子、端口装配自报、路由词汇、limits / metrics。必须独立成 crate 的两条硬约束（被链接性 + Cargo 环）与实证在头注；**crate 内禁止任何产品名词**（`HostModuleDesc` 只描述接口路径 / 权限位 / ABI 下界；词段判据真源在 `registry.rs::product_noun_violations`，双端宿主各有全量扫描点）。
- **`wasmnest-host-api-core`（运行期实现层）**：host_api 中「不依赖 WIT bindgen trait / 任何一端独有类型」的机制语义；每域两层 = 实现层（本 crate）+ 各端 adapter（住 wasm-core 或宿主）。准入判据与边界由 `src/boundary_lock.rs` 钉：只允许机制级依赖（`serde_json` / `tracing` / `rusqlite` 等），禁 SDK / wasm-core / `tauri` / `tokio`。`config` / `http` 已判定**不抽**（各有原因，见头注）——不要「顺手统一」。
- **`wasmnest-wasm-core`（运行期整核，单形态）**：`manager/`（加载 / 生命周期 / 实例调用 / 任务 / 热重载）、`manager/runtime/`（统一运行时壳 + **唯一合法 core 绑定** `core_binding.rs`）、`host_api/`（adapter）、`security/`、`db/`、`system/`、`test_support*`。形态纪律：
  - **无 common/bare 之分**（2026-10-13 收口）：端差异（cap 域实现 / 权限门 / 事件词汇 / ABI 规格 / 端事实）全部经 `HostModule` 自报、`GuestEventDispatcher`、`AbiPolicy` / `HostFactsPort` 注入——内核零端名、零端 `#[cfg]`。
  - `desktop-assembly`（默认开）= 桌面专属装配面（`PluginHost` / watcher / intercall / auth_center 等）；移动宿主 `default-features = false` 不开。`test-support` = 测试面（无头装配 / MockPorts / 夹具消费），不随生产形态发布。
  - **要往 wasm-core 加 `bindgen!` / `impl … Host` 先停下**：唯一合法绑定是 `core_binding.rs`；`runtime.rs` / `runtime/component.rs` 不得出现 `bindgen!` 与 `wasmnest::plugin::` 路径（移动纯净性锁判据 2）。
  - WASI 面双端同源、常编译、默认全开，开/关由运行期 `CoreConfig::wasi` 定——**不要用 feature 表达端差异**。

### 3.3 server 分层（`base` / `core` / 传输面 / 引擎域）

- `server-base` 是叶子地基，在地基位置——改它的依赖面影响全仓（含无头宿主）。`tauri-compat` 默认开只为 `From<tauri::Error> for AppError` 一个 impl；非 Tauri 消费方 `default-features = false`，代价是边界处显式 `map_err`（孤儿规则，无法下游补写）。
- `server-core` 传输无关（supervisor / filter / link_crypto / metrics / `TransportFace` + serve，依赖倒置）；http / ws 只**向下**依赖它，**彼此零横向 import**，也不得反向认识宿主（由各自 `dependency_direction_lock.rs` 双向钉死）。
- `server-peer-net` 是**引擎域**不是传输面（不过 actix 组合、不过过滤链、不用链路加密）：只向下依赖 base 与共享 `peer-net`；清单不得含 core/http/websocket、`wasmnest-discovery-engine`（mDNS 句柄以纯值经 `MdnsPort` 注入，ADR 0054 单 listener 不变量）；「产品业务（传输任务 / 策略 / 历史 / 共享根 / 浏览编排）真源在 file-transfer 插件」，本 crate 只留无业务语义的引擎原语与生命周期。
- 改依赖方向 = 改边界锁的判据：**锁与清单一起改，且要先说明不变量为何改变**。

### 3.4 引擎、底座与契约房

- `wasmnest-crypto-engine`：只暴露**无业务语义的中性算法原语**；不做认证编排 / 协商 / 密钥策略；密钥材料一律由调用方提供，不触碰宿主身份密钥。
- `wasmnest-discovery-engine`：全进程共享守护只允许 `engine.rs` 创建一次；对同一服务类型只允许 `type_hub.rs` 调 `daemon.browse` / `stop_browse`（重复 browse 会静默杀死别人的事件流——跨端实测根因）；新增调用点必须改测试仓 `mdns_browse_singleton_lock` 的白名单并写明理由。
- `wasmnest-pty-engine`：引擎面（跨平台、零 wasm）+ 能力域（句柄表 / 配额仲裁 / 退出事件 / 限频通知 / 6 原语）；只接受调用方算好的 argv，**不做 shell 包装**；输出走环形缓冲 + 水印通知。
- `wasmnest-ws-client-engine`：`host-websocket` 客户端子集 5 原语 + 停用回收；平台差（权限门 / 投递 / 后台任务 / jwt 代发 / 退避）全经 `WsClientPorts` 注入；生产清单零内部 crate 依赖（锁钉死）。
- `wasmnest-notify-engine`：契约房，只持 WIT，零实现；平台不支持项（桌面无震动等）**静默忽略写死在契约文档**，实现端不得改成报错。
- `peer-net`：重装即新身份（与设备身份刻意分离）；证书公钥即节点公钥、指纹即身份（`node_id = hex(SHA-256(raw ed25519 key))`）；未信任拨入停应用层确认闸门；`_wasmnest-peer._tcp.local.` 与终端链路旧 `_wasmnest._tcp` 完全独立。
- `link-crypto`：只做纯字节协议（配置域 / 身份落盘 / 过滤器接线留宿主）；常量与算法**是协议兼容性表面**，与移动 TS 实现逐字节一致——改常量 = 跨端破坏性变更，先读头注的兼容性清单。

### 3.5 写代码前的归属三问（顺序不可颠倒）

1. **这是机制还是产品语义？** 产品语义（设备 / 会话 / 配对 / 传输任务 / AI）→ 应用仓；机制（可被任何宿主复用的能力）→ 本仓；端差异与装配 → 平台仓。
2. **谁需要它？** 双端宿主都要 → 共享 crate（能力域 / 内核）；仅一端 → 住平台仓该端宿主；仅测试观测 → 测试仓。
3. **可复用形态是哪一种？** 纯引擎 + 端口（默认形态）／契约房（只持 WIT）／机制内核（host-kit 面）／传输面（server-*）——形态决定 feature、依赖纪律与锁。

三问任一答不上来，停下问用户；不要在能力 crate 里开业务口子。

---

## 4. 命令

> **心智模型**：无根 workspace。`cargo check/test/fmt/clippy` 在**目标 crate 目录**执行；本仓没有「仓级测试」。CI 重建明确不立项（当前无 CI），验证 = 本地实跑 + 平台/测试仓锁。

### 4.1 单 crate（默认可用）

| 命令 | 说明 |
| --- | --- |
| `cd <crate> && cargo check --lib --offline` | 快速编译检查（`--offline` 用本地缓存索引，防网络抖动；首次跑会刷新陈旧 lock，见 §4.4） |
| `cd <crate> && cargo test --offline` | 该 crate 单测 + 集成测试（`wasmnest-host-kit` 的 `tests/forced_link*.rs` 是两个独立测试二进制——链接期属性无法同进程既「有」又「无」） |
| `cd <crate> && cargo test --lib --offline` | 只跑 `src/` 内单元测试（不含 crate 根 `tests/`） |
| `cargo fmt --manifest-path <crate>/Cargo.toml` | 格式化（`rustfmt.toml` 在 5 个 server crate + crypto-engine（共 6 份），`max_width = 120`；其余 crate 无配置 = 100 列默认——先看 crate 根有没有 `rustfmt.toml`） |
| `cargo tree --offline -e normal -i <crate>` | 依赖倒查（门禁 / 排查反向边） |

### 4.2 `wasmnest-wasm-core` 的独立克隆解析限制（重要）

`desktop-assembly`（默认开）依赖 `wasmnest-plugin-api = "0.0.1"`，该 SDK **未发布到 registry**；独立克隆里直接 `cargo test` / `cargo metadata` 会报 `no matching package named wasmnest-plugin-api found`（即使 `--no-default-features` 或删 lock 条目也一样——Cargo 会解析声明了的可选依赖）。两条合法路径：

1. **平台装配（首选，与生产同图）**：
   ```bash
   cd ../wasmnest/wasmnest-{desktop}/src-tauri
   cargo test -p wasmnest-wasm-core --offline          # 宿主 manifest 的 [patch.crates-io] 生效
   cargo test -p wasmnest-wasm-core --lib --offline    # 只跑单元测试
   ```
   （测试仓 `../wasmnest-test/cross-end-tests` 也有自己的 `[patch.crates-io]`。）
2. **独立克隆逃生阀（仅本地开发）**：用 `--config` 临时把补丁指回工作树 SDK——
   ```bash
   cd wasmnest-wasm-core
   cargo test --offline \
     --config 'patch.crates-io.wasmnest-plugin-api.path="../wasmnest/wasmnest-{desktop}/packages/plugin-sdk-desktop/rust"'
   ```
   补丁路径版本必须与 SDK `Cargo.toml` 的 `version` 逐字一致。**不要把补丁写进任何 `Cargo.toml`**（那会破坏独立克隆 / 发布装配）。

其余 15 个 crate 独立克隆可直接构建测试。

### 4.3 门禁与跨仓锁（改动对应面时跑）

| 命令 | 判据 |
| --- | --- |
| 无头探针默认形态门禁 | 见下方代码块；grep 期望**无输出**、倒查应报「did not match」 |
| `cd ../wasmnest-test/cross-end-tests && cargo test --test wire_drift_locks --offline` | wire 副本 ↔ 平台 SDK 逐字一致（改 `wire.rs` 后必跑） |
| 同目录 `cargo test --test permission_vocabulary_lock --offline` | 权限词汇真源 ↔ 平台生成物 / manifest（改 `permission.rs` 后必跑） |
| 同目录 `cargo test --test mdns_browse_singleton_lock --offline` | browse / 守护唯一出口（改 discovery-engine 后必跑） |
| `cd ../wasmnest/wasmnest-{desktop}/src-tauri && cargo test --test capability_crates_unit_tests_only --offline` | 治理 crate 形态（改 crate 根 `tests/` / dev-deps 前后对照） |
| `cd ../wasmnest/wasmnest-{desktop}/src-tauri && cargo test --test capability_crates_no_product_ids --offline` | 能力 crate 语义（新增能力 crate 必须登记 `SCANNED_CRATES`，否则锁指出「未登记」） |

无头探针门禁的具体命令：

```bash
cd wasmnest-headless-host-probe
cargo tree --offline -e normal | grep -E 'wasmtime|wit-bindgen|inventory|wasmnest-host-kit'   # 期望无输出
cargo tree --offline -e normal -i wasmnest-plugin-api                                        # 期望「did not match」
```

> 跨仓锁命令依赖平台仓与测试仓在工作区同场布局（R1）或 `WASMNEST_PLATFORM_ROOT`；前置条件与路径解析见测试仓 `tests/common/repo_paths.rs`。**迁移期口径（用户 2026-10-18）：不逐项跑全量回归**——按改动面跑针对性单测与相关锁，收口后统一全量。

### 4.4 target 落点与构建资源（含已知陷阱）

- **同一份 `.cargo/config.toml` 在两种装配下解析到不同位置**：crate 级 `target-dir` 相对该 crate 根解析——
  - **平台装配下**（宿主从 `<平台>/<end>/src-tauri` 构建，本仓 crate 以 sibling path 入图）：产物落**宿主的** `target/<bucket>`；本仓 crate 的 `.cargo/config.toml` 不参与宿主编译；
  - **独立克隆下**（crate 在 `<能力仓>/<crate>`）：落到**本仓根** `<能力仓>/target/<bucket>`（2026-10-20 收口：平台仓删除 `packages/` submodule 挂载点后 crate 深度少一层，10 个 crate 的 `target-dir` 从 `../../target/*` 统一改为 `../target/*`）。
- **判据以运行时为准**：`cargo metadata --no-deps --format-version 1` 的 `target_directory`（或 `CARGO_TARGET_DIR=<crate>/target` 强制落点）。改任何 `target-dir` 后必须逐 crate 核验——写错一层 `..` **不会报错**，只会安静落到别处（2026-10-20 前就曾整体落到三仓共同父目录 `${WASMNEST}/target/*`）。
- 桶位对照：`server-libs` = 5 个 server crate + crypto-engine；`host-kits` = host-kit / discovery / pty / wasm-core；夹具 = `<crate>/target/fixtures`（wasm-core 自持夹具）；`cross-end-tests/target` 独立（平台/测试仓侧）。
- 构建资源：仓根 `.cargo/config.toml` 强制 `jobs = 4` + `rustc-wrapper = "sccache"`（**未装 sccache 一切 cargo 命令直接失败**——显性失败设计，不绕过；本机已装 0.18）。**绝不要设 `CARGO_INCREMENTAL=1`**（sccache 0.18 检测到会拒绝执行，成批失败）；`SCCACHE_CACHE_SIZE` 只认纯字节数字。磁盘吃紧先 `sccache --show-stats`，清理见 §5「清理 target/磁盘」。
- `Cargo.lock` **随仓库跟踪**（夹具 / 探针需要可复现构建），只经 cargo 变更、禁止手编。**当前已知状态**：部分 crate 的 lock 里内部 crate 版本仍残留 `0.1.0`（版本线重开为 `0.0.1` 后只刷新了 7 个根包），首次构建/测试会自动把它刷新成 `0.0.1`——这会让 `--locked` 失败（预期）。刷新结果作为独立 `chore(lib)` 提交（先例：`chore(lib): 7 个 crate 的 Cargo.lock 根包版本随 0.0.1 刷新`），不要混进功能提交。

### 4.5 发版钉平台指针（改完本仓后的收口；未经用户授权不要动）

```text
本仓：改 → 提交 → 打 tag（lib-vX.Y.Z）
平台仓：release-manifest.json 的 repos.lib.tag = 该精确 tag（contract.version 同步）
        → pnpm run check:manifest（校验本仓 HEAD == tag 且工作树干净）
        → 平台仓提交 manifest
```

三个 tag 各自独立（`lib-` / `apps-` / `test-` 前缀），不与其他仓同号。WIT 变更另需 §2.2 的流程。

---

## 5. 任务路由：改 X 先读 Y

| 任务 | 动手前必读 |
| --- | --- |
| 改 WIT / 契约包版本 | §2.2 + `wasmnest-contract/src/lib.rs` + `wit/core.wit` / 域 WIT；同步全仓 `@0.0.1` 字面量；平台 `compose-wit.mjs` / `check:wit` / `check:manifest --print-hash` + 重建插件产物 |
| 改权限词汇 | `wasmnest-wasm-core/src/permission.rs`（真源）→ 平台 SDK 重出生成物（`pnpm run gen:permissions`）→ 测试仓 `permission_vocabulary_lock`；同步 §2.3 副本中的权限常量 |
| 改 wire 词汇 / 事件名 / topic | §2.3；先确认真源（平台 SDK），逐字同步副本，跑 `wire_drift_locks`；**不要改副本定义块内注释** |
| 改主库 schema / 迁移 | `wasmnest-wasm-core/src/db/{schema.sql,database.rs}`（真源 + 幂等迁移）；平台移动侧 `kernel_schema_single_truth_lock`（五表定义与 `init_schema` 接线）；禁止手改生产库、禁止宿主自持 DDL 副本 |
| 改 host_api 机制语义（storage/bus/db/log/events/fs/gate） | `wasmnest-host-api-core` 对应域 + `src/boundary_lock.rs` 准入判据 + 头注「域进度」；adapter 改动看两端消费面 |
| 改 wasm-core 机制 / 运行时壳 / 安全闸门 | `wasmnest-wasm-core/src/lib.rs` 头注 + `manager/runtime/{core_binding,wasi}` + `security/`；**先确认绑定面不回流**（§3.2）；平台移动 `mobile_wasm_core_purity_lock` 七判据 |
| 改能力域原语 / 引擎（discovery / pty / ws-client / http / ws / peer） | 对应 crate 头注 + `plugin_binding/` + 端口 trait；`default` 与 `common-host` 两形态都要能编译；discovery 另跑 `mdns_browse_singleton_lock` |
| 改 host-kit 注册面 / 描述符 / 路由词汇 | `wasmnest-host-kit/src/{module,registry,route,assembly}.rs` + `tests/forced_link*.rs`（链接期不变量两侧）+ 平台 `host_module_desc_noun_lock`（双端） |
| 改 server 分层依赖方向 | §3.3 + 对应 `dependency_direction_lock.rs` + `crate_boundary_lock.rs` 的 `SPLIT_CRATES` / `ALLOWED_*` 表；清单与锁同批改 |
| 新增 / 改名 / 删除 crate | 先过 §3.5 三问 → 目录 = 包名 `wasmnest-*` → 本仓 `SPLIT_CRATES` 登记（纯契约 / 夹具类不登记，见 §6.3）→ 平台侧：`capability_crates_no_product_ids` 的 `SCANNED_CRATES`（新能力 crate 必须登记，否则锁指出未登记）、宿主 `Cargo.toml` + `common-host`（若属能力域）+ `compose.json`（若持 WIT）+ 强制引用 / `expect_host_module!` → 属默认形态能力域则加进无头探针引用行 → 平台 `release-manifest.json` tag（无 submodule 指针） |
| 改依赖版本 / 新增依赖 | 各 crate `Cargo.toml` 注释（双端锁步版本：wasmtime 48、inventory 0.3.24、wasm-core 的 `reqwest` 必须 `default-features = false`——防 Android 交叉编译拉 openssl-sys，TLS 后端由各端宿主声明）；机制级依赖白名单（§3.2）；跑该 crate 测试 + 边界锁 |
| 增加 crates.io 依赖 / 升级依赖 | 先问用户；`Cargo.lock` 随改随提交（§4.4） |
| 发版 / 钉平台指针 | §4.5；未经授权不改平台仓 |
| 独立克隆测试 / 构建失败 | §4.2（wasm-core 解析点）+ §4.4（`target_directory` 判据 + `--locked` 与陈旧 lock） |
| 清理 target / 磁盘吃紧 | 先 `df -h` / `du -sh` 定位；安全优先级：旧落点 `${WASMNEST}/target/{host-kits,server-libs}`（2026-10-20 前的漂移产物，无活引用可整删）、`cross-end-tests/target`、夹具 target；本仓 `target/*` 是**活跃桶**（host-kits ≈11G 可复用），`cargo clean` 只对该 crate 且确认不误伤平台装配桶（§4.4） |
| 排查「改了没生效」 | 先确认构建读的是哪一份源码：平台装配读 sibling `<平台>/../wasmnest-lib/<crate>`，独立克隆读本仓工作树（现在两者是同一物理路径）；再确认 target 桶与 sccache 状态 |
| 定位 crate / 符号 | `rg` 全文 + `cargo metadata`；真源先在 `Cargo.toml` description 与 `src/lib.rs` 头注 |

---

## 6. 硬约束

### 6.1 无产品语义（结构锁之外的语义红线）

- 能力域 / 引擎 / 传输面 / 机制内核的生产代码**不得出现产品插件 id**（`com.wasmnest.<产品段>` 字面量）与退役宿主面词汇（`host-session` / `host-terminal` / `output-ring-fetch` 等）；注释里点名产品解释「为什么」可以（语义锁剥注释），代码 / 常量 / 字符串不行。
- `host-kit` 描述符（模块名 / 接口路径 / 权限位）不得含产品名词词段（`product_noun_violations`）。
- 「引擎实现」允许的形态 = 参数透传 + 机制语义（属主隔离 / 事件定向投递 / 停用回收）；业务含义由插件自己解释。做不到就说明放错了仓。

### 6.2 依赖与边界

- 生产 `[dependencies]` 只允许机制级依赖；`dev-dependencies` 不得新增内部 crate 边（`capability_crates_unit_tests_only` 判据；唯豁免 `wasmnest-host-kit` 的强制链接探针）。
- 禁止端形态的编译期分支：不用 `#[cfg(end)]` / feature 表达端差异（端事实经 `HostFactsPort` / `AbiPolicy` / 端口注入）。
- 不允许旁路：不得用 `[patch]` / 本地重导出 / 复制源码绕过边界锁（曾有 crate 以 dev-dep 横向引用三 crate 的用例，已按锁迁宿主）。
- `wasmnest-headless-host-probe` 不进任何宿主依赖清单、不登记进 `SPLIT_CRATES`（它是验证夹具，受治理锁自动管辖）。

### 6.3 契约与版本

- 包名 / 版本只改 `wasmnest-contract/src/lib.rs` 一处；其余 `@0.0.1` 字面量是同批同步副本，由平台锁断言。
- `wasmnest-contract` **不登记 `SPLIT_CRATES`**：该表同时驱动「宿主清单声明全部拆分产物」的对偶断言，登记会要求宿主直接声明契约 crate；而契约只允许经 `wasmnest-wasm-core` 的 re-export 消费。它是新建契约 crate，不是宿主 bin 拆分产物，结构管辖在平台仓 crate 结构锁 + 能力 crate 语义锁。
- WIT 变更必须 bump（含函数级追加）+ 重拼 + 重建产物（§2.2）；禁止手改平台端生成物 `rust/wit/`。
- 权限词汇不得自造；主库 DDL 只在 `db/schema.sql`；迁移必须幂等且失败显性。

### 6.4 测试

> **通用测试规范（两种形态 / 禁止交付 / 测试数据临时目录 / Seam 3 锁纪律 / 验证底线）真源 = `../wasmnest`/`docs/public/testing.md`**（不复制）。本段只保留本仓特有规则：

- 单测住 `src/` 内（`#[cfg(test)]`），crate 根 `tests/` 是例外面：仅 `wasmnest-host-kit`（平台锁登记豁免）与 `wasmnest-wasm-core/tests/platform_reference_registry_lock.rs`（票 08 新增，平台治理锁待同步——见 §8）。新增 crate 根 `tests/` 前先确认平台锁状态。
- 新增能力域必须自持至少一条自洽漂移单测（如 `routing.rs` 的「EXPORTS 条数 == 端口 `forward_*` 方法数」范式）；机制不变量必须有可执行判据（锁），不能只写文档。

### 6.5 注释、命名与提交

> **通用注释 / 命名规范真源 = `../wasmnest`/`docs/public/commenting.md`；通用 git 提交规范真源 = `../wasmnest`/`docs/public/git.md`**（不复制）。本段只保留本仓特有规则：

- **注释 / 文档里禁止写平台仓目录名与跨仓读取路径**（§0，`platform_reference_registry_lock` 扫描仓根全文）；端词汇（桌面宿主 / 移动宿主）可用。
- 命名 rustfmt：先看 crate 根有无 `rustfmt.toml`（120 vs 默认 100 列），不要跨 crate 统一重排。
- Commit scope 用 `(lib)`（先例：`refactor(lib):` / `chore(lib):` / `fix(lib):`）——commit 格式、禁止 AI 标记、--force 禁令、只提交源码等其他通用规则见 `../wasmnest`/`docs/public/git.md`。

### 6.6 安全

- 禁止提交密钥 / 凭据 / token；禁止进日志、进文档；凭据只记长度不落明文（唯一指定存储是宿主 `plugin_secrets` 表，见 `schema.sql` 注释）。
- 不新增旁路认证 / 静默降级；失败一律 fail-closed 或 fail-visible——引擎端口缺席、WIT 调用未声明权限、事件载荷非法 JSON 等都要显性失败。
- 对等网络：指纹即身份（双向 verifier 真实签名验证）；未信任方停应用层确认闸门；不要为「好用」加静默信任。

---

## 7. 完成定义与验证

**当前口径（用户 2026-10-18，研发起步期 + 迁移收口）**：不逐项跑全量集成回归；日常改动至少跑**针对性单测 + 所在面相关锁**，并贴出实际命令与结果；无法运行要说明原因与风险。（通用验证底线——无 CI 门禁口径、实跑贴结果、钩子跳过 ≠ 通过——真源 `../wasmnest`/`docs/public/testing.md` §5。）以下按改动类型执行：

- **改任一 crate 代码** → 该 crate `cargo test --offline` 全绿（`wasmnest-wasm-core` 走 §4.2 的两种路径之一）；改动涉及默认形态 → 无头探针门禁（§4.3）。
- **改 WIT / 契约版本** → 全仓 `@0.0.1` 字面量已同步；平台 `compose-wit.mjs --all` + `check:wit` 通过；受影响插件产物重建成功；`check:manifest --print-hash` 后的 manifest 通过 `check:manifest`。
- **改 wire 副本** → 平台 SDK 侧已同步（或本仓侧逐字跟改）；`wire_drift_locks` 全绿。
- **改权限词汇** → SDK 生成物重出；`permission_vocabulary_lock` 全绿；涉及应用 manifest 的改动在应用仓同步（本仓不代改）。
- **改 host-kit / 能力域注册面** → host-kit `cargo test`（含 `forced_link` / `forced_link_absent`）+ 平台 `host_module_desc_noun_lock`（双端）；若新增能力域，无头探针引用行与平台 `SCANNED_CRATES` 已补。
- **改 discovery browse / 守护** → 测试仓 `mdns_browse_singleton_lock` 全绿。
- **改 db/schema** → 本 crate 幂等迁移用例全绿 + 平台移动 `kernel_schema_single_truth_lock`。
- **改 wasm-core 形态 / 绑定面** → 本 crate `cargo test` + 平台移动 `mobile_wasm_core_purity_lock` + 整核结构锁（宿主侧）。
- **改依赖 / 新增依赖** → 该 crate 测试 + 相关边界锁；内部依赖边新增时 `crate_boundary_lock` / 平台治理锁核对。
- **新增 / 删除 / 改名 crate** → §5 对应行逐项核对（本仓登记表 + 平台锁登记 + 消费方清单 + 探针 + tag/manifest）；`cargo metadata` 确认依赖图无重复能力 crate（两份 = 类型同一性断裂）。
- **独立克隆可用性** → `wasmnest-wasm-core/tests/platform_reference_registry_lock.rs` 全绿（改任何注释 / 文档 / 测试字符串后都建议跑一次，它扫仓根全文）；其余 crate 单克隆 `cargo test` 可过。

---

## 8. 已知漂移与遗留（截至 2026-10-18；动手前按需复核）

1. **旧路径注释**：本仓（~30 处）与应用仓（4 处）注释仍引旧路径 `cross-end-tests/...`。更新本仓注释需同步 `release-manifest.json` 的 tag，**用户当前未授权**——不要顺手改（详见 pi scratchpad 的同名条目）。
2. **wasm-core 的 SDK 版本依赖（架构债）**：`desktop-assembly` → `wasmnest-plugin-api = "0.0.1"`（未发布）导致独立克隆无法解析（§4.2）。终态清偿票据未做，勿扩大。
3. **`Cargo.lock` 版本残留**：多个 crate 的 lock 里内部 crate 版本仍是 `0.1.0`（应 `0.0.1`，§4.4）；这些 crate 首次 cargo 运行会自动刷新（刷完才可用 `--locked`，刷前 `--locked` 直接失败）。
4. **（已收口 2026-10-20）`target-dir` 落点漂移**：10 个 crate 已统一改为 `../target/<bucket>`，独立克隆落本仓根；旧落点 `${WASMNEST}/target/{host-kits,server-libs}` 为漂移产物（无活引用，可整删），本仓 `target/host-kits` 的历史残留即当前活跃桶。核查方法见 §4.4。
5. **（已收口 2026-10-21）平台治理锁滞后于拆分**：平台仓 `capability_crates_no_product_ids` 的 `crate_dir()` 已对 `wasmnest-componentize` 单独解析 `tools/componentize`（目录存在，不会 panic）；`capability_crates_unit_tests_only` 的 `CRATE_TEST_DIR_EXCEPTIONS` 已登记 `wasmnest-wasm-core/tests/platform_reference_registry_lock.rs`。两把锁在平台仓实测全绿：`cargo test --offline --test capability_crates_no_product_ids --test capability_crates_unit_tests_only` → 6 + 5 passed。
6. **wasm-core 两处产品 id 泄漏**：`security/fs_auth.rs` 的 `FIRST_PARTY_TRUSTED_DIRS`、`manager/host/activation.rs` 的 `LEGACY_API_PLUGIN_ALIASES`——由独立票据处置；平台语义锁因此暂不扫 `wasm-core`。
7. **本仓无 CI**（CI 重建明确不立项）；验证靠本地命令与跨仓锁。
8. 平台仓桌面 SDK 的 `README.md` / `template/` 仍与 ADR 0057 挂载包形态不一致（dev-shell 已于 2026-10-21 对齐；属平台仓侧漂移，本仓不代改；跟踪 `7ZAI/wasmnest#1`）。

---

## 9. 文档索引（真源指针）

| 需求 | 入口 |
| --- | --- |
| 插件机制整核 / 运行时壳 / host_api adapter / 安全闸门 | `wasmnest-wasm-core/src/lib.rs`、`manager/runtime.rs` + `manager/runtime/{core_binding.rs,wasi.rs,engine.rs}`、`manager/{capability.rs,registry.rs}`、`security/`、`host_api/`、`test_support.rs` |
| 主库 schema / 迁移 / 护栏常量 | `wasmnest-wasm-core/src/db/schema.sql`、`db/{database,operations,models}.rs`、`host_api/database.rs` |
| 权限词汇真源 | `wasmnest-wasm-core/src/permission.rs` |
| 契约包名 / 版本真源 | `wasmnest-contract/src/lib.rs` |
| 核心 WIT / 域 WIT | `wasmnest-wasm-core/wit/core.wit`、各能力域 `wit/<domain>.wit`（mdns / pty / http / peer / ws / notify） |
| 机制内核契约 / 注册表 / 描述符判据 | `wasmnest-host-kit/src/{module,registry,route,assembly,lifecycle}.rs` + `tests/forced_link*.rs` |
| 能力域默认形态 / 端口纪律 | `wasmnest-host-api-core/src/boundary_lock.rs`、`wasmnest-ws-client-engine/src/boundary_lock.rs`、各域 `ports.rs` |
| 跨仓路径解析 / 测试仓接入口 | `../wasmnest-test/cross-end-tests/{Cargo.toml,tests/common/repo_paths.rs}` |
| 跨仓 wire / 权限 / mDNS 锁 | `../wasmnest-test/cross-end-tests/tests/{wire_drift_locks,permission_vocabulary_lock,mdns_browse_singleton_lock}.rs` |
| 平台仓治理锁（形态 / 语义 / 整核 / 纯净性） | `../wasmnest/wasmnest-{desktop,mobile}/src-tauri/tests/`（按 §2.4 表点名） |
| WIT 组合与产物重建 | 平台仓 `scripts/compose-wit.mjs`、`wasmnest-{desktop,mobile}/packages/plugin-sdk-*/compose.json` |
| 跨仓版本 / 发布 | `../wasmnest/release-manifest.json`、`../wasmnest/scripts/check-release-manifest.mjs`、`../wasmnest/package.json`（`check:wit` / `check:manifest`） |
| 四仓通用规范（git 提交 / 注释命名 / 测试验证 / 版本号管理 / issue 管理） | `../wasmnest`/`docs/public/{git,commenting,testing,versioning,issues}.md` |
| crate 历史索引（旧单仓时期，代码冻结） | 旧仓 `BedCode` 的留守分支 `marker/bedcode-pre-lib-split-20261016`：`packages/README.md`（crate 作用索引）、`docs/adr/`、`docs/knowledge/build-process.md`（target 治理与历史事故） |

> 本文件与真源冲突时，以真源 + 可执行锁为准，并回来修正本文件。
