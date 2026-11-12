# wasmnest-lib

**WasmNest 能力仓（应用无关引擎仓）**：四仓（平台 / 能力 / 应用 / 测试）中唯一的**可复用机制 + 端口抽象 + 契约**仓库。本仓不读平台 / 应用源码、不做产品判断，只提供任何宿主（桌面宿主 / 移动宿主 / 无头宿主）都能直接引用的插件机制与能力域引擎。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![WebAssembly](https://img.shields.io/badge/WebAssembly-Component-654FF0?logo=webassembly&logoColor=white)](https://component-model.bytecodealliance.org)
[![Status](https://img.shields.io/badge/status-alpha-orange)](#9-项目状态)

简体中文 | [English](README_en.md)

> 本 README 是**导航性介绍**，不是开发规范。硬约束、边界锁、任务路由以 [AGENTS.md](./AGENTS.md) 与各 crate 真源（`Cargo.toml` description、`src/lib.rs` 头注、WIT）为准；文档字面与事实冲突时以真源 + 可执行锁为准。

## 1. 工程形态

- **无根 workspace**：20 个独立 crate（各自 `Cargo.toml` + 随仓库跟踪的 `Cargo.lock`）+ 4 个夹具 crate。命令一律在 crate 目录执行，不存在「仓级 cargo test」。
- **版本线**：全部 crate 自 `0.0.1` 重开；契约版本 `wasmnest:plugin@0.1.0` 唯一手写真源在 `wasmnest-contract`（该 crate 同时是**零依赖共享词汇**：包名 / 版本 + 跨层护栏常量）。
- **WIT 按包拆分**：`wasmnest:plugin@0.1.0`（core import + guest 导出面）+ 各域包独立版本（`wasmnest:{mdns,pty,peer,tunnel,http,ws,notify,clipboard}@0.0.1`）；改哪个包 bump 哪个包，平台 `release-manifest.json` 的 `contract.packages` 逐包钉版本。
- **消费方式**：平台双端宿主与测试仓经 sibling path 直接依赖本仓工作树（本仓不复制、不发布到 registry；唯一例外是 `wasmnest-wasm-core` 的 `desktop-assembly` 对桌面 SDK `wasmnest-plugin-api` 的版本依赖，消费侧用 `[patch.crates-io]` 指回 SDK 工作树）。

## 2. 依赖分层

能力 crate 默认形态 = **纯引擎机制 + 端口抽象**（零 WIT / 零 SDK / 零 wasmtime / **零宿主框架（Tauri、actix）/ 零 bundled SQLite / 零系统信息采集与文件监听**），任何宿主可直接引用；`common-host` feature 才装配 WIT 绑定层。判据可执行：`sh scripts/check-default-form-deps.sh`（CI 同一条命令）。

> **边界声明**：`wasmnest-server-http` / `-websocket` / `-core` 与 `wasmnest-wasm-core` **不在**上述承诺内——前三个默认形态仍带 actix（`server-core` 另带 rusqlite），`wasm-core` 仍带 Tauri / actix / rusqlite；它们的解耦是后续票据（P1/P2），本文不再把它们描述为「任何宿主可直接引用」。

依赖方向自上而下，横向边由各 crate 的 `dependency_direction_lock.rs` / `boundary_lock.rs` 钉死：

```text
插件（wasm-apps / 第三方）
   │  WIT host-* · bus · events · 互调
   ▼
能力域 crate（默认 = 纯引擎 + 端口；common-host 才装 WIT 绑定层）
   ▼
wasmnest-host-kit（装配期：状态 / 模块契约 / 注册表）
   ▼
wasmnest-wasm-core（运行期：运行时壳 + core 绑定 + host_api adapter）
   ▼
双端宿主 src-tauri/src/（组合根 · 薄壳）——平台仓
```

## 3. crate 一览

| 目录（包名） | 定位（一句话） | 形态 / feature | WIT 真源 | 主要消费方 |
| --- | --- | --- | --- | --- |
| `wasmnest-contract` | **零依赖共享词汇**：`PACKAGE` / `PACKAGE_NAME` / `PACKAGE_VERSION` 唯一手写真源 + 跨层护栏常量（`PLUGIN_DB_*` / `DEFAULT_ERROR_CODE`）；零依赖、不装 WIT | 无 feature | — | wasm-core（`use` 后派生）、server-base / host-api-core / cli-engine（常量 re-export）、平台仓脚本与锁（正则读源文件） |
| `wasmnest-wasm-core` | 插件机制**整核**：wasmtime 组件宿主运行时壳 + host_api adapter + 安全闸门 + 主库/引擎面 | `default = ["desktop-assembly"]`；`test-support` | `wit/core.wit` + `wit/worker.wit`（worker world 自持分片，双端同源） | 平台双端宿主（桌面默认开 / 移动 `default-features = false`）、测试仓 |
| `wasmnest-host-kit` | 装配期机制内核：`WasmPluginState` / `HostModule` 契约 / 自动注册表 / limits / metrics | 无 feature | — | 双端宿主、全部 `common-host` 能力域、wasm-core |
| `wasmnest-host-api-core` | host_api 无 WIT 域**实现层**：gate / storage / bus / database / log / events / fs | 无 feature | — | wasm-core adapter |
| `wasmnest-server-base` | server **叶子地基**：错误信封 / 常量 / 系统信息 DTO / 网络配置形状 / 连接身份 / 端口 traits / wire。默认依赖树只依赖零依赖契约仓 | `default = []`；`tauri-compat` / `mdns` / `system-info` 可选且默认关 | — | 几乎全仓 + 双端宿主 + 测试仓 |
| `wasmnest-server-core` | **跨传输**的 server 内核：supervisor / 过滤链 / link_crypto / metrics / `TransportFace` + actix 组合运行时（`serve`）；仍带 actix / rusqlite（P1 再拆） | 无 feature | — | 平台双端装配、http/ws 向下依赖、测试仓 |
| `wasmnest-server-http` | HTTP 传输面 + `host-http` 绑定层（端点注册表 / 网关 / 中间件 / DTO 锚点） | `default = []`；`common-host` | `wit/http.wit` | 桌面宿主（common-host）、wasm-core（引擎面）、移动宿主（引擎面）、测试仓 |
| `wasmnest-server-websocket` | WebSocket 传输面 + `host-websocket` 客户端域接线 / 服务端引擎函数 | 同上 | `wit/ws.wit`（与 ws-client-engine 共享契约分片） | 同 http |
| `wasmnest-server-peer-net` | 对等网络**引擎域**（含底座机制 `base/`：身份/libp2p 传输/信任/mDNS 注册/传输会话引擎原语——原 `wasmnest-peer-net` 拆分并入）+ `host-peer` 绑定层（非传输面，不参与 actix 组合） | 同上 | `wit/{peer,tunnel}.wit` | 桌面（common-host）、移动（引擎面）、wasm-core（`PeerCtx`）、测试仓 |
| `wasmnest-p2p-engine` | **libp2p 机制引擎**：节点身份桥（node_id ↔ PeerId）/ swarm 生命周期 / 入站准入闸门 / 具名流协议与链路登记（P1 起 peer-net 传输栈消费） | `default = []`；`relay` 可选 | — | `wasmnest-server-peer-net`、测试仓 |
| `wasmnest-discovery-engine` | mDNS 能力域：共享守护 + 类型中枢 + 浏览/广播双句柄表 + 宿主自播面 | 同上 | `wit/mdns.wit` | 桌面（common-host）、移动（引擎面）、测试仓 |
| `wasmnest-pty-engine` | PTY 能力域 + 跨平台伪终端引擎（进程生命周期 / 读取线程 / 环形缓冲） | 同上 | `wit/pty.wit` | 桌面宿主（common-host） |
| `wasmnest-ws-client-engine` | WS **出站客户端**能力域：句柄表 / 双任务 / 心跳 / 退避重连 / 停用回收 | 无 feature | `wit/ws.wit`（共享契约真源） | 移动宿主、测试仓 |
| `wasmnest-cli-engine` | CLI 能力域机制骨架：内建命令目录（词汇真源）/ argv 解析 / 帮助与补全 / 本机 IPC wire 帧契约；零内部 crate 依赖 | 无 feature | —（CLI 无 guest 面） | 平台仓 CLI / 无头 bin（尚未实施）、无头探针（仅链接） |
| `wasmnest-clipboard-engine` | 剪贴板域**契约房**：只持 WIT，零 Rust 实现 | 无 feature | `wit/clipboard.wit` | 双端 `compose.json` 组合——**无 Rust 消费者** |
| `wasmnest-crypto-engine` | 中性加密算法原语（aes_gcm/chacha/hybrid/kdf/rsa/x25519）+ 名称寻址注册表 + 自带 `CryptoError`；零内部 crate 依赖 | 无 feature | —（WIT 面在宿主 `plugin/crypto.rs`） | 桌面宿主、server-core |
| `wasmnest-notify-engine` | 通知域**契约房**：只持 WIT + 端口词汇（当前无端口），零 Rust 实现 | 无 feature | `wit/notify.wit` | 双端 `compose.json` 组合——**无 Rust 消费者** |
| `link-crypto`（`wasmnest-link-crypto`） | 链路报文加密协议核心：HTTP 信封 / WS 握手 IKM / 二进制帧 | 无 feature | — | wasm-core（`link_crypto`）、双端宿主 |
| `wasmnest-relay` | **内网穿透中继守护进程**：libp2p Circuit Relay v2 服务端 + 配额 / 指标 / enrollment token + `init`/`run`/`doctor`/`print-addrs` 一键运维；独立 Linux 二进制 + Docker + Compose（`deploy/relay/`），零内部 crate 依赖 | 无 feature | — | 仅公网 relay 部署（**不进宿主依赖清单**） |
| `wasmnest-headless-host-probe` | 无头宿主探针：以非桌面形态引用全部能力域，钉「默认形态不需要插件宿主机制」 | 无 feature（永不开 `common-host`）、零 dev-deps | — | 仅门禁——**不得进任何宿主依赖清单** |

> 目录名与包名不同形的唯一例外：`link-crypto`（包名 `wasmnest-link-crypto`），引用时看清。

## 4. 分组详述

### 4.1 契约与内核（插件机制三件套）

- **`wasmnest-contract`**：**零依赖共享词汇**——契约包名 / 版本唯一手写真源 + 跨层护栏常量（`PLUGIN_DB_*` / `DEFAULT_ERROR_CODE`）；`[dependencies]` 恒空（常驻断言）。宿主只经 `wasm-core` re-export 消费包名 / 版本，库内零依赖共享词汇可直接依赖它。`PACKAGE_NAME` / `PACKAGE_VERSION` / `PACKAGE` 必须保持 `pub const <NAME>: &str = "<值>";` 精确形态（含 `: &str`、无 macro、无 `env!` / `concat!`）——平台仓两处 node 解析器按此形状取值，是跨语言文本契约。
- **`wasmnest-host-kit`（装配期）**：只装机制——实例状态（含 WASI 槽，常编译）、`HostModule` 契约、自动注册表（收集 → 排序 → 白名单 → linker 装配）、生命周期钩子、端口装配自报、路由词汇、limits / metrics。crate 内禁止任何产品名词。
- **`wasmnest-host-api-core`（运行期实现层）**：host_api 中「不依赖 WIT bindgen trait / 任何一端独有类型」的机制语义；每域两层 = 实现层（本 crate）+ 各端 adapter（住 wasm-core 或宿主）。`config` / `http` 已判定**不抽**，不要顺手统一。
- **`wasmnest-wasm-core`（运行期整核，单形态）**：插件系统微内核——`manager/`（加载 / 生命周期 / 实例调用 / 任务 / 热重载）、`manager/runtime/`（统一运行时壳 + **唯一合法 core 绑定** `core_binding.rs`）、`host_api/`（adapter）、`security/`、`db/`、`system/`。无 common/bare 之分：端差异全部经 `HostModule` 自报、`GuestEventDispatcher`、`AbiPolicy` / `HostFactsPort` 注入。`desktop-assembly`（默认开）= 桌面专属装配面；移动宿主 `default-features = false` 不开。`test-support` = 测试面。

### 4.2 能力域引擎（五个带 `common-host` 的 crate）

默认形态 = **纯引擎机制 + 端口抽象**，零 WIT / 零 SDK / 零 wasmtime / 零宿主框架；`common-host` 才装配 `bindgen!` / `HostModule` 自报 / `inventory::submit!` / `impl Host`，开 feature 后 ABI / WIT / 权限位 / 事件形状 / 注册零变化。平台边经端口 trait 注入（权限门 / 事件投递 / 后台任务 / 路径 / 系统信息等），**端口缺席 fail-visible**。

- **`wasmnest-server-http`**：HTTP 传输面 + `host-http` 能力域绑定层（入站 2 + 出站 1 原语）。
- **`wasmnest-server-websocket`**：WebSocket 传输面（连接骨架 / 插件端点通道 / 注册表 / 优雅停机）+ `host-websocket` 绑定层。
- **`wasmnest-server-peer-net`**：对等网络**引擎域**，不是传输面——不过 actix 组合、不过过滤链、不用链路加密；mDNS 句柄以纯值经 `MdnsPort` 注入（单 listener 不变量）。产品业务（传输任务 / 策略 / 历史 / 共享根 / 浏览编排）在应用仓插件，本 crate 只留引擎原语与生命周期；底座机制（原 `wasmnest-peer-net` 拆分并入 `base/`：身份/信任/mDNS 注册/传输会话引擎原语）为 crate 自身内容，传输栈经 `wasmnest-p2p-engine`（noise/yamux 具名流）。
- **`wasmnest-discovery-engine`**：mDNS 能力域。全进程共享守护只允许 `engine.rs` 创建一次；对同一服务类型只允许 `type_hub.rs` 调 `daemon.browse` / `stop_browse`（重复 browse 会静默杀死别人的事件流）。
- **`wasmnest-pty-engine`**：PTY 能力域（`host-pty` 6 原语）+ 插件私有伪终端引擎面。引擎面跨平台零 wasm；只接受调用方算好的 argv，不做 shell 包装；输出走环形缓冲 + 水印通知。

### 4.3 server 分层（`base` / `core` / 传输面）

- **`wasmnest-server-base`** 是叶子地基：默认依赖树只依赖零依赖契约仓（无 tauri / rusqlite / notify / link-crypto / mdns-sd / sysinfo）。`tauri-compat` / `mdns` / `system-info` 三个 feature **默认关**，由消费方显式开启（桌面宿主开全部三项，`server-peer-net` 开 `mdns`）；不开时边界处显式 `map_err`（孤儿规则）。改它的依赖面影响全仓（含无头宿主）。
- **`wasmnest-server-core`** 跨传输（**不是**传输无关）：supervisor / 过滤链 / link_crypto / metrics / `TransportFace` + actix 组合运行时 `serve`，依赖倒置；http / ws 只向下依赖它，彼此零横向 import，也不得反向认识宿主。默认依赖树仍带 actix / rusqlite（P1 再拆）。
- 能力域默认形态禁止 actix；传输面、`server-core`（组合运行时）与 `wasm-core` 是例外。

### 4.4 底座、独立能力域与契约房

- **对等网络底座机制**（原 `wasmnest-peer-net` crate 拆分并入 `wasmnest-server-peer-net` 的 `base/`）：重装即新身份（与设备身份刻意分离）；libp2p noise 身份公钥即节点公钥、指纹即身份（`node_id = hex(SHA-256(raw ed25519 key))`，PeerId 经 `identity_bridge` 互验）；未信任拨入停应用层确认闸门；`_wasmnest-peer._tcp.local.` 与终端链路旧 `_wasmnest._tcp` 完全独立。
- **`wasmnest-p2p-engine`**：libp2p 机制引擎（P1 起 peer-net 传输栈）——连接怎么建 / 流怎么开 / 身份怎么验 / 闸门怎么拦；信任列表、线协议语义与 `host-peer` WIT 域留 peer-net。零内部 crate 依赖，`relay` feature（Circuit Relay v2 客户端）可选。
- **`link-crypto`**：链路报文加密协议核心，只做纯字节协议。常量与算法是协议兼容性表面，与移动 TS 实现逐字节一致——改常量 = 跨端破坏性变更。
- **`wasmnest-ws-client-engine`**：WS 出站客户端能力域（`host-websocket` 客户端子集 5 原语 + 停用回收）。平台差（权限门 / 投递 / 后台任务 / jwt 代发 / 退避）全经 `WsClientPorts` 注入；生产清单零内部 crate 依赖。
- **`wasmnest-crypto-engine`**：只暴露无业务语义的中性算法原语；不做认证编排 / 协商 / 密钥策略；密钥材料一律由调用方提供，不触碰宿主身份密钥。自带 `CryptoError`（`Display` 返回旧文案原文），零内部 crate 依赖——映射回信封错误是消费方边界的显式责任。
- **`wasmnest-notify-engine`** / **`wasmnest-clipboard-engine`**：**契约房**，只持 WIT，零 Rust 实现。平台不支持项（桌面无震动等）静默忽略写死在契约文档，实现端不得改成报错。
- **`wasmnest-cli-engine`**：CLI 机制骨架（命令目录 / argv 解析 / 帮助补全 / 本机 IPC wire 帧），零内部 crate 依赖；`WireError` 是纯 wire 类型，宿主错误 → 语义码的映射住宿主侧。

### 4.5 门禁探针

- **`wasmnest-headless-host-probe`**：无头宿主探针，钉「能力域默认形态不需要插件宿主机制」（零 WIT / 零桌面 SDK / 零 wasmtime 机制依赖）。宿主框架 / SQLite / 系统信息 / 文件监听另由 `scripts/check-default-form-deps.sh` 钉（探针故意链接 server 栈，不能兼作该判据）。永不开 `common-host`、零 dev-deps；`cargo tree` 出现 `wasmtime` / `wit-bindgen` / `inventory` / `wasmnest-host-kit` / `wasmnest-plugin-api` 即违规。不进任何宿主依赖清单、不登记 `SPLIT_CRATES`。

## 5. 夹具 crate（不入一览表、不发布）

- `wasmnest-host-kit/fixtures/forced-link-probe`：强制链接实证——链接期属性无法同进程既「有」又「无」，对应两个独立测试二进制（`forced_link` / `forced_link_absent`）。
- `wasmnest-wasm-core/fixtures/{wasi-test,wasip3-test,p3-async-host-import-test}`：自持 WASI / WASI p3 / 异步宿主导入测试夹具，绑定本 crate `wit/`（core.wit 契约真源；wasip3 夹具按目录加载），零 SDK 依赖。

## 6. 四仓协作

本仓是四仓里的**机制真源**：平台双端宿主经 Cargo sibling path 直接消费，测试仓以同一物理路径读取（保证依赖图中只有一份，类型同一性成立），应用仓只经 SDK 使用能力。

```text
wasmnest/        平台仓：双端宿主 + 端内 SDK + 构建 / 发布工具
wasmnest-lib/    能力仓（本仓）：应用无关引擎 + 端口抽象 + WIT 契约真源
wasmnest-apps/   应用仓：全部业务 wasm 应用
wasmnest-test/   测试仓：跨端真实互连 + 跨仓契约锁
```

| 仓 | 与本仓的关系 |
| --- | --- |
| [wasmnest](https://github.com/7ZAI/wasmnest) | 经 `../../../wasmnest-lib/<crate>` 直接依赖；版本由平台仓 `release-manifest.json` 的 `repos.lib.tag` 钉住 |
| [wasmnest-lib](https://github.com/7ZAI/wasmnest-lib)（本仓） | 不读平台 / 应用源码；契约与机制的单一真源 |
| [wasmnest-apps](https://github.com/7ZAI/wasmnest-apps) | 不直接依赖本仓；应用只使用平台仓 SDK，本仓机制经宿主装配后生效 |
| [wasmnest-test](https://github.com/7ZAI/wasmnest-test) | 以 sibling path 引用本仓与两端宿主，跑真实互连与跨仓锁 |

平台仓不复制、不镜像、不挂 submodule；默认同级目录 `../wasmnest-lib`，可用 `WASMNEST_LIB_ROOT` 覆盖（node resolver = 平台仓 `scripts/lib-paths.mjs`，测试仓 = `tests/common/repo_paths.rs::lib_root()`）。

## 7. 快速验证

本仓**无根 workspace**，命令一律在 crate 目录执行：

```bash
cd wasmnest-host-kit && cargo test --offline
cd ../wasmnest-server-base && cargo test --offline
cd ../wasmnest-headless-host-probe && cargo test --offline
```

- `wasmnest-wasm-core` 不能直接 `cargo test`：`desktop-assembly` 依赖未发布的 `wasmnest-plugin-api`，需按 AGENTS §4.2 的 `--config patch.crates-io...` 逃生阀（会改写 `Cargo.lock`，提交前还原）。
- 根 `.cargo/config.toml` 强制 `rustc-wrapper = "sccache"`；未安装时 cargo 直接失败，这是显性设计，不要绕过。
- `jobs = 4` 是内存兜底；内存充足时用 `CARGO_BUILD_JOBS` 覆盖。**不要设 `CARGO_INCREMENTAL=1`**，sccache 会拒绝执行。
- 跨仓契约与真实互连验证在测试仓 `wasmnest-test/cross-end-tests`（wire / 权限词汇 / mDNS 锁 + 跨端场景）。

## 8. 相关指针

| 需求 | 入口 |
| --- | --- |
| 开发导航与硬约束 | 本仓 [AGENTS.md](./AGENTS.md) |
| 契约包名 / 版本真源 | `wasmnest-contract/src/lib.rs` |
| 核心 WIT / 域 WIT | `wasmnest-wasm-core/wit/core.wit` + `wit/worker.wit`、各能力域 `wit/<domain>.wit`（mdns / pty / http / peer / tunnel / ws / notify / clipboard） |
| 权限词汇真源 | `wasmnest-wasm-core/src/permission.rs` |
| 主库 schema | `wasmnest-wasm-core/src/db/schema.sql` |
| 跨仓锁（wire / 权限 / mDNS） | 测试仓 `wasmnest-test/cross-end-tests/tests/{wire_drift_locks,permission_vocabulary_lock,mdns_browse_singleton_lock}.rs` |
| 平台仓治理锁 | 平台仓双端 `src-tauri/tests/`（形态 / 语义 / 整核 / 纯净性锁） |
| 四仓通用规范 | 平台仓 `docs/public/{git,commenting,testing,versioning,issues}.md` |

## 9. 项目状态

- 研发起步期，版本线 `0.0.1`；无对外 ABI 兼容义务，破坏性变更可直接进行，但跨仓契约按精确 tag 钉住。
- 本仓独立 tag 线 `lib-vX.Y.Z`；发布时由平台仓 `release-manifest.json` 钉住精确 tag，并同步契约版本、`contract.packages`（逐包版本）与 WIT 指纹。
- 只有发布时才 bump 版本号 / 打 tag；日常开发不 bump。

## 10. 许可证

[MIT](LICENSE) © 2026 7ZAI
