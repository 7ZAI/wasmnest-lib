# 拆分 peer-net 底座、最终去除该 crate — 实施规格

> 状态：设计定稿（2026-10-22 用户确认方向；实施记录见 §10）。
> 关联仓：能力仓 `wasmnest-lib`（拆分主体 / AGENTS 同步）、平台仓 `wasmnest`（双端宿主依赖键与 use 路径 / 锁登记）、测试仓 `wasmnest-test`（依赖键）。
> 一句话：**删除 `peer-net/`（`wasmnest-peer-net`）整个 crate——底座机制并入能力域 `wasmnest-server-peer-net`（新 `base/` 子模块），mDNS 机制 `disable_virtual_interfaces` 归位 `wasmnest-discovery-engine`，业务语义（策略/暴露面/内置目录）全部由 wasm-app 插件经既有 WIT 接口驱动，能力域只留无业务语义机制。**

## 1. 背景与动机（现状证据）

### 1.1 审计发现（2026-10-22 架构归属审计）

`wasmnest-peer-net`（`peer-net/`，10029 行）定位文档（`src/lib.rs` 头注 + Cargo.toml description）只写：Ed25519 节点身份 / 自签证书 / TLS 直连 / 信任闸门 / mDNS 发现。但 crate 内实际还装有：

| 证据 | 内容 |
| --- | --- |
| `src/transfer.rs`（2121 行）+ `transfer/{message,batch,crypto}.rs`（1141 行） | 完整文件传输会话引擎：Offer/Decision/StartFile/Data/FileDone/BatchDone 批协商、断点续传（`.part`）、取消/暂停/进度；`batch.rs` 自述「移植自 git v2.0.0 移动端 file_service 传输语义」 |
| `src/transfer/batch.rs:142` `ReceivePolicy` | 硬编码枚举（AlwaysAccept / Ask{timeout 超时自动拒} / AlwaysDeny）——应用层确认策略实住在底座（§6.6 确认闸门属应用层） |
| `src/shared.rs`（1530 行）+ `shared/registry.rs`（649 行） | 共享目录浏览/拉取会话编排、`SharedDirRoot{Fs,Saf}` 暴露面注册表+持久化、`BUILTIN_DOWNLOADS_ID="local-downloads"`（注释「UI 据此识别」= 产品常量）+ 免授权内置条目（产品授权决策） |

冲突条款：AGENTS §3.4 peer-net 定位不含传输；§3.3「产品业务（传输任务 / 策略 / 历史 / 共享根 / 浏览编排）真源在 file-transfer 插件」——三个点名词全部命中；§6.1 无产品语义红线。§8 已知漂移未登记。git 历史 = 拆分迁移 init 提交时随旧移动端 file_service 语义整体迁入。

### 1.2 现状的「业务已下沉大半」事实（本 spec 的立足点）

- file-transfer 插件（wasm guest，`wasmnest-plugin-api {features=["wasm"]}` + 纯逻辑 core，零网络依赖）**已经**经 host-peer WIT 接口驱动业务：
  - `rust/core/src/settings.rs:112` 调 `peer_set_receive_policy`（「变更后经保留的引擎原语推送宿主闸门」）；
  - `rust/core/src/roots.rs:66` 调 `peer_set_shared_roots`（「任何增删后调引擎广播面全量推送」）。
- host-peer WIT（`wasmnest-server-peer-net/wit/peer.wit`）已有 `set-receive-policy(mode, timeout-secs)` / `set-shared-roots(dirs-json)` / `set-download-dir(path)` / `send-files` / `respond-transfer` / `pause-transfer` / `resume-transfer` / `browse-directory` / `pull-files` ——**业务配置入口已在契约里，插件侧驱动**。
- 硬约束：wasm guest 无网络栈/不能跑 tokio/TLS/文件 IO——**传输会话引擎（帧收发、断点续传、落盘、取消暂停）物理上无法下沉 wasm-app，必须留宿主侧能力域**。可下沉/已下沉的是策略数据、暴露面配置、内置目录、任务编排/事件归约。

### 1.3 附带发现的清理项

- **wasm-core 对 `wasmnest-peer-net` 的死依赖**：`wasmnest-wasm-core/Cargo.toml` 声明了 `wasmnest-peer-net`，但 src 零 use（`PeerCtx` 来自 `wasmnest_server_peer_net::PeerCtx`，host_api/context.rs:40；`use wasmnest_server_peer_net as _` 只做强制链接）。拆分时直接删。
- **discovery-engine 的「唯一合法方向边」**：AGENTS §3.3 记载 `wasmnest-discovery-engine → wasmnest-peer-net`（`engine.rs::init_daemon` 调 `disable_virtual_interfaces`）。`disable_virtual_interfaces` 本质是 **mDNS 机制**（禁用虚拟网卡接口避免幽灵广播），定义在 peer-net/discovery.rs:543，只被 discovery-engine 消费 → 应归位 discovery-engine。拆掉后该边消失，discovery-engine 变**零内部 crate 依赖**。
- **peer-net 逃过平台语义锁**：`capability_crates_no_product_ids` 的 SCANNED_CRATES 未登记 peer-net（底座带产品语义却不在扫描面）。拆分后产品语义随插件/注入走，server-peer-net 已登记在案，扫描面自动闭合。
- **AGENTS.md 文档漂移一并修正**（§1 表格、§2.4 锁表、§3.3/§3.4、§9 索引、命名纪律「唯二例外」→「唯一例外 link-crypto」）。

## 2. 用户裁决（2026-10-22，不再重开）

| # | 裁决 |
| --- | --- |
| Q1 | **「业务下沉 wasm-app」接受修正口径**：传输协议引擎（帧收发/断点/落盘/取消暂停）是宿主侧机制、物理上无法进 guest，留能力域 `wasmnest-server-peer-net`；可下沉的是策略数据（ReceivePolicy 配置化）、内置下载目录、共享目录暴露面配置、任务编排/事件归约（编排已下沉）——「业务语义不留在底座，全部经宿主端口注入或插件承载」。 |
| Q2 | **底座落点 = `wasmnest-server-peer-net`**（peer 能力域 = host-peer 域 + 底座机制，新 `base/` 子模块组织）。不并入 wasm-core（会破坏 discovery-engine 的边）。 |
| Q3 | **实施节奏**：本仓拆分（删 peer-net + 并底座 + 收 disable_virtual_interfaces + AGENTS 同步 + 测试全绿）→ 平台仓（宿主依赖键 + 移动 4 处 use + 平台锁登记）→ 测试仓（依赖键）。跨仓动作已授权，但**不覆盖三仓并发会话的未提交改动**（平台/应用/测试仓各有未提交工作树，见 §7.4）。 |

## 3. 目标形态（拆除后）

```text
插件（wasm-apps file-transfer 等）——业务：策略/暴露面/内置目录经 WIT set-receive-policy / set-shared-roots 驱动
   │  WIT host-peer
   ▼
wasmnest-server-peer-net（peer 能力域 = host-peer 域 + base/ 底座机制）
   │  只向下依赖 wasmnest-server-base（错误/端口 traits）
   ▼
wasmnest-discovery-engine（mDNS 能力域，收 disable_virtual_interfaces，零内部 crate 依赖）
   │
wasmnest-wasm-core（整核；删 wasmnest-peer-net 死依赖，PeerCtx 仍来自 server-peer-net）
   │
双端宿主 / 测试仓（依赖键：wasmnest-peer-net → wasmnest-server-peer-net）
```

- **`peer-net/` 目录与 `wasmnest-peer-net` 包名彻底消失**（本仓唯一例外底座目录名剩 `link-crypto`）。
- **零 WIT / ABI / wire / 权限词汇变更**（host-peer 接口面不动，插件产物不重建）。
- 产品语义面：`ReceivePolicy` 值由插件经 WIT 写入（现状）；暴露面由插件全量推送（现状）；`BUILTIN_DOWNLOADS_ID` 与「免授权内置条目」逻辑**删除**（插件 roots 全量推送即覆盖，内置条目是双写冗余）。

## 4. 拆分映射

### 4.1 peer-net → server-peer-net（`src/base/` 新子模块）

| 原 peer-net 模块 | 行数 | 去向与改造 |
| --- | --- | --- |
| `identity.rs` | 394 | → `base/identity.rs`（NodeId/NodeIdentity 原样） |
| `cert.rs` | 225 | → `base/cert.rs` 原样 |
| `tls.rs`（原 `mod tls` 私有） | 535 | → `base/tls.rs`，`pub(crate)` 可见（transfer 消费） |
| `trust_store.rs` | 606 | → `base/trust_store.rs` 原样（持久化机制，数据目录经注入——现状已是注入） |
| `frame.rs` | 254 | → `base/frame.rs` 原样 |
| `node.rs` | 201 | → `base/node.rs`（PeerNetNode/PeerNetNodeConfig/StaticPeerRecord 原样） |
| `transport.rs` | 675 | → `base/transport.rs` 原样（Connection/ConnectionHandler/TrustEvent；「上层缝」挂载点） |
| `discovery.rs` | 1296 | → `base/discovery.rs`：`disable_virtual_interfaces` **移出**（→ discovery-engine，§6.2）；其余（spawn_peer_mdns_daemon/PeerMdnsBrowse/DiscoveryCache，均接收外部 daemon 参数、不自建守护、不 browse）原样 |
| `error.rs` | 323 | → `base/error.rs` 原样（PeerNetError 继续与 AppError 刻意解耦，宿主 map_err） |
| `transfer.rs` | 2121 | → `base/transfer.rs`：机制全留（帧协议/断点续传/取消/暂停/FileLanding 注入缝/TransferConfig 的 chunk_size·download_dir·landing 注入字段）；`ReceivePolicy` 枚举**保留执行机制**（值由 WIT set-receive-policy 写入），引擎 `Default` 改 **fail-closed（AlwaysDeny）**，产品默认（Ask 60s）由 file-transfer 插件 activate 时经 WIT 设定（应用仓 `settings.rs` 已有该通路，仅默认值归属调整，见 §7.3） |
| `transfer/message.rs` | 607 | → `base/transfer/message.rs` 原样（线协议编解码，纯机制） |
| `transfer/batch.rs` | 317 | → `base/transfer/batch.rs`：状态机/RejectReason 保留（机制词汇），`ReceivePolicy` 定义随 transfer.rs |
| `transfer/crypto.rs` | 217 | → `base/transfer/crypto.rs` 原样 |
| `shared.rs` | 1530 | → `base/shared.rs`：浏览/拉取线协议、`resolve_rel_path` 路径安全、`SharedSafAccess`/`SeqReader` 注入缝全留；`SharedDirHandler` 的事件桥保留 |
| `shared/registry.rs` | 649 | → `base/shared/registry.rs`：`SharedDirRoot{Fs,Saf}` 数据形状 + 注册表存储/持久化机制保留（数据目录经注入）；**`BUILTIN_DOWNLOADS_ID` 与「内置免授权条目」逻辑删除**（插件 roots 全量推送接管，双写冗余） |
| `lib.rs` 的 `pub mod/pub use` | 79 | → 并入 server-peer-net `base/mod.rs`，re-export 由 `server-peer-net/src/lib.rs` 统一对外（消费方 `wasmnest_peer_net::X` → `wasmnest_server_peer_net::base::X` 或经 lib re-export `wasmnest_server_peer_net::X`） |

### 4.2 peer-net → discovery-engine

| 符号 | 去向 |
| --- | --- |
| `disable_virtual_interfaces(daemon: &ServiceDaemon)` | → `wasmnest-discovery-engine/src/`（mDNS 机制，`engine.rs::init_daemon` 调自己的实现；AGENTS §3.3「唯一合法方向边」删除，discovery-engine 零内部 crate 依赖） |

### 4.3 删除项

- `peer-net/` 目录整体删除；`wasmnest-wasm-core/Cargo.toml` 的 `wasmnest-peer-net` 死依赖删除。

## 5. 机制设计（server-peer-net 内部布局）

```text
wasmnest-server-peer-net/src/
├─ lib.rs                 # 现有 host-peer 域（PeerCtx/引擎控制面/plugin_binding/service/wire…）不变
├─ base/                  # ← 从 peer-net 并入的底座机制（§4.1 表）
│  ├─ mod.rs              # 原 peer-net lib.rs 的 pub mod/pub use 落点
│  ├─ identity.rs / cert.rs / tls.rs / trust_store.rs / frame.rs / node.rs / transport.rs / discovery.rs / error.rs
│  ├─ transfer.rs + transfer/{message,batch,crypto}.rs
│  └─ shared.rs + shared/registry.rs
└─ …（engine_ports / peer_engine_* / plugin_binding / service / source_collect / wire / 锁）
```

- **对外 re-export 策略**：`server-peer-net/src/lib.rs` 保持现状导出面（PeerCtx 等），`base::*` 经 `pub use` 上提为 `wasmnest_server_peer_net::{NodeId, Connection, TransferEvent, …}`，**消费方（宿主/测试仓）的 `use wasmnest_peer_net::X` 全部改写为 `use wasmnest_server_peer_net::X`**（名称不变，仅前缀变，改动机械）。
- **消费方自引用改写**：server-peer-net 现有代码里 `wasmnest_peer_net::…`（lib.rs:109 `init_node_identity` 返回类型、peer_engine_receive/transfer/remote/source_collect 的 `wasmnest_peer_net::transfer::…` 等）→ `crate::base::…`。
- **依赖面**：server-peer-net 现有 `Cargo.toml` 依赖（tokio/serde/…/base/）不变；删 `wasmnest-peer-net` 行。**不新增任何依赖**（底座机制只用 std + 已有依赖：tls 用 tokio-rustls/rustls/ring 已由 tokio 等覆盖？——核对：peer-net 的 tls 依赖 tokio-rustls/rustls/ring/socket2/x509-parser/rcgen/ed25519-dalek 等，这些依赖要随文件**平移进 server-peer-net 的 Cargo.toml**，见 §5.1）。
- **错误**：`base/error.rs` 的 `PeerNetError`/`Result` 保留在 base 内（继续与 AppError 解耦）；server-peer-net 顶层错误信封维持现状（宿主 map_err 不变）。

### 5.1 Cargo.toml 依赖平移（peer-net → server-peer-net，逐项核对后并入）

peer-net 现有：ed25519-dalek / rand_core / sha2 / hex / serde / serde_json / rcgen / x509-parser / thiserror / tracing / local-ip-address / chrono / tokio / tokio-rustls / socket2 / rustls / ring / x25519-dalek / hkdf / aes-gcm / mdns-sd / flume。
并入时**按实际使用收窄**（删除 peer-net 可能未用的，如 aes-gcm/hkdf/x25519 若 transfer/crypto 已不用则删）——实施时 `cargo machete`/`cargo tree` 核对，**不引入任何新依赖版本**（双端锁步版本纪律：mdns-sd 0.20、flume 0.12、rustls 0.23 ring、tokio-rustls 0.26 等与现网一致）。

## 6. 依赖重排与锁更新（本仓）

| 文件 | 改动 |
| --- | --- |
| `wasmnest-server-peer-net/Cargo.toml` | 删 `wasmnest-peer-net` 行；并入 §5.1 平移依赖（收窄后） |
| `wasmnest-server-peer-net/src/dependency_direction_lock.rs` | 判据更新：REQUIRED_DEPS 从「base + peer-net（共享引擎）」改为「仅 base」；「D5 取用共享引擎」段落改为「底座机制为 crate 自身内容（base/ 子模块）」；「唯一合法方向边 discovery-engine → peer-net」段落删除；防回接锁（任务状态表/并发闸门/封顶不复发）**保留**并继续覆盖 base/transfer 与 base/shared |
| `wasmnest-server-peer-net/src/*.rs` | `wasmnest_peer_net::` → `crate::base::` 或 `wasmnest_server_peer_net::base::`（自引用） |
| `wasmnest-discovery-engine/src/engine.rs`（+ 新 `disable_virtual_interfaces`） | 实现移入本 crate；删 `wasmnest-peer-net` 依赖 → **零内部 crate 依赖** |
| `wasmnest-discovery-engine/Cargo.toml` | 删 `wasmnest-peer-net` 行 |
| `wasmnest-wasm-core/Cargo.toml` | 删 `wasmnest-peer-net` 死依赖行 |
| `wasmnest-headless-host-probe/` | 无改动（不引用 peer-net） |
| `wasmnest-server-{base,core,http,websocket}/` | 无改动 |
| `AGENTS.md` | §1 表格删 peer-net 行（包名一览表第 11 行 + 表格行）；§3.3「唯一合法方向边」段改写（discovery-engine 零内部依赖）；§3.4「底座与契约房」段改写（底座机制入 server-peer-net base/；`link-crypto` 为唯一目录名例外）；§2.4 锁表（如引用 peer-net 的条目更新）；§9 索引；§5 任务路由「改 server 分层」相关行；README.md 同步（如含 peer-net 描述） |
| `wasmnest-wasm-core/src/crate_boundary_lock.rs` | SPLIT_CRATES 不含 peer-net（从未登记）——核对无需改；server-peer-net 条目注释更新 |

## 7. 跨仓清单（用户已授权；不覆盖并发会话未提交改动）

### 7.1 平台仓 `wasmnest`

| 文件 | 改动 |
| --- | --- |
| 桌面宿主 `src-tauri/Cargo.toml` | `wasmnest-peer-net` → `wasmnest-server-peer-net`（宿主已依赖后者，键改） |
| 移动宿主 `src-tauri/Cargo.toml` | 同上 |
| 移动宿主 `src-tauri/src/peer/{seam,net}.rs`、`plugin/host_ports.rs`、`system/logging.rs`（4 处） | `wasmnest_peer_net::X` → `wasmnest_server_peer_net::X`（名称不变仅前缀） |
| 桌面宿主 `src-tauri/src/`（若有 `wasmnest_peer_net::` use） | 同上（rg 核对） |
| 7 个锁文件（`wit_package_version_lock.rs` / `peer_engine_consolidation_lock.rs` / `retired_mobile_receive_orchestration_lock.rs` / `session_e2e.rs` / `l2_gating_lock.rs` / `capability_crates_no_product_ids.rs` / `domain_contract_structure_locks.rs`） | peer-net 路径引用改 server-peer-net；SCANNED_CRATES 无需新增（server-peer-net 已登记）；若锁判据含 peer-net 源码路径则同步 |
| `release-manifest.json`（lib.tag） | 拆分是 lib 发版动作：提交 → 打 `lib-vX.Y.Z` tag → manifest 钉新 tag（§4.5 流程；是否发版由用户定，本 spec 按需执行） |

### 7.2 测试仓 `wasmnest-test`

| 文件 | 改动 |
| --- | --- |
| `cross-end-tests/Cargo.toml`（若依赖 peer-net） | 依赖键改 server-peer-net |
| 锁/夹具引用 `wasmnest_peer_net::` 的文件 | 前缀改写 |

### 7.3 应用仓 `wasmnest-apps`（file-transfer，guest 不依赖底座——核对后应零依赖改动）

- file-transfer 插件 **Cargo.toml 零改动**（不依赖 peer-net，已核实）；
- 可选小改：ReceivePolicy 引擎默认改 AlwaysDeny 后，file-transfer `activate` 若未设策略则行为变保守——核对 `settings.rs` 是否 activate 时推送（现状已有推送通路），必要时补一次 activate 默认推送（属应用仓并发工作树，实施时先核对再动，优先不动）。

### 7.4 并发会话保护

- 平台仓（未提交：release-manifest / scripts / SDK bin）、应用仓（未提交：CI/AGENTS/agent-hub 等）、测试仓（未提交：desktop_ctx/mdns_health_flow 等）工作树均有并发改动——**只改 §7.1/§7.2 点名文件，且改动前 `git diff` 核对目标文件未被并发会话触碰；冲突则停下询问**，不 merge、不覆盖。

## 8. 验证计划

| 面 | 命令 | 判据 |
| --- | --- | --- |
| 本仓编译 | 逐 crate `cargo check --offline`（server-peer-net / discovery-engine / wasm-core / host-kit / 全部） | 全绿；无 `wasmnest_peer_net` 残留引用 |
| 本仓测试 | `cd <crate> && cargo test --offline`（server-peer-net、discovery-engine 必跑；wasm-core 走 §4.2 路径） | 全绿 |
| 无头探针门禁 | §4.3 两连 grep | 无输出 / did not match |
| 平台引用锁 | wasm-core `platform_reference_registry_lock`（逃生阀 patch） | 1 passed |
| 依赖图 | `cargo tree --offline -e normal`（wasm-core、discovery-engine、server-peer-net） | 无 peer-net；无新增未声明依赖 |
| 残留扫描 | `rg 'wasmnest_peer_net|peer-net' --glob '!target/**'` | 仅 AGENTS.md 历史叙述/豁免字面量（§0 零平台引用锁豁免除外） |
| 跨仓（§7 完成后） | 平台仓双端 `cargo test`（相关锁）+ 测试仓 `cargo test`（相关锁） | 全绿 |
| 文档字面核对 | `rg 'peer-net' AGENTS.md README*.md` | 与事实一致 |

## 9. 风险与注意

1. **server-peer-net 规模**：~6384 行（现有）→ ~1.6 万行（+底座 ~1 万行 −shared/transfer 产品部分）。用 `base/` 子模块 + 头注分区可读性；职责仍单一（对等网络能力域）。若后续仍嫌大，可再拆「对等网络底座」独立 crate（本轮不做，避免范围蔓延）。
2. **tls 可见性**：`mod tls` 私有 → `base/tls.rs` `pub(crate)`；确认 transfer/crypto 的加解密路径可见性。
3. **ReceivePolicy 默认值变更**：引擎 Default Ask{60s} → AlwaysDeny 是行为变化（fail-closed），需应用仓 file-transfer activate 补策略推送（§7.3 核对，避免产品行为回退）。
4. **平台锁判据**：`peer_engine_consolidation_lock` / `retired_mobile_receive_orchestration_lock` 判据可能含「peer-net 不复活」类断言，改写时保持语义（改名不断言力）。
5. **AGENTS 零平台引用锁**：本 spec 与实施中**不得写平台仓目录名**（§0；锁扫仓根一切文本文件含 `.scratch/`）。本 spec 用端词汇（桌面宿主 / 移动宿主 / 平台仓）表述跨仓清单，不写目录名字面量。实施提交前跑该锁确认。
6. **git 提交**：本仓拆分一次提交（`refactor(lib): …`）；`Cargo.lock` 随改随提交（peer-net 删除后 lock 刷新）。

## 10. 实施记录

- 2026-10-22：设计定稿（用户确认 Q1/Q2/Q3）。本 spec 落盘 `.scratch/2026-10-22-peer-net-dissolve/`。
- 2026-10-22（Phase 1 本仓，已提交 `1c1a85e`）：`peer-net/` 删除（git 识别为 rename → `wasmnest-server-peer-net/src/base/`，15 文件 + 新 mod.rs）；域代码 `wasmnest_peer_net::` → `crate::base::`；顶层 re-export 保持符号名不变（`wasmnest_server_peer_net::X`）；`disable_virtual_interfaces` 归位 discovery-engine（该 crate 零内部依赖，§3.3 唯一边退役）；wasm-core 删死依赖；dot 方向锁更新（REQUIRED 仅 base，共享引擎断言退役）；AGENTS/README 同步。验证：server-peer-net 153 / discovery-engine 39 / wasm-core 577+1 / 探针门禁 / platform_reference_registry_lock 全绿。
- 2026-10-22（Phase 2 跨仓，已提交）：测试仓 `417350d`（peer 集成测试迁入 `tests/peer_*` 依赖 server-peer-net）；平台仓 `e8cd1eb`（双端删 peer-net 依赖 / 移动 4 处 use 前缀 / config patch）+ `6ccd24a`（移动锁 KEPT_ADAPTER_FACE 退役 FILE_TRANSFER_PLUGIN_ID 判据——服务租约既定方向）。双端编译绿 + 迁移集成测试 24 全绿 + 平台锁全绿。
- 2026-10-22（业务下沉轮，已提交）：lib `e738bcf`（`ReceivePolicy::default` → AlwaysDeny fail-closed + 共享目录删除 `BUILTIN_DOWNLOADS_ID`/内置免授权/不落盘/list 置首 + `PeerPlatformSeam::builtin_shared_dirs` → `default_shared_dirs` 普通条目注册）；test `d192727`（peer_shared_dirs 用例适配）；platform `595845d`（移动平台缝同步）；apps `635a3c2`（file-transfer 激活期 load+save_and_push 推送产品默认策略）。验证：server-peer-net 152 / cross-end 24 / 平台双端编译 / apps plugin host-check 全绿。
- **遗留（已知）**：`DEFAULT_ASK_TIMEOUT_SECS` 常量保留（Ask 策略仍可用，仅非默认）；产品默认策略的权威值在 file-transfer 插件 settings（Ask + 60s 审批窗口），双端行为与拆分前一致。
- **过程教训（两次）**：平台仓 `e8cd1eb` 的移动 `peer/net.rs` 与 apps 仓 `635a3c2` 的 file-transfer `plugin/lib.rs` 均混入并发会话（服务租约波次）的改动——提交前只核对了目标 diff 片段未看整份 diff。正确动作：并发工作树文件须逐项核验 diff 归属再 add（AGENTS §0 并发保护）；已提交部分方向一致且编译绿，未回退。
