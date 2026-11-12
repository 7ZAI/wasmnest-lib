//! host_api **共享实现核**（票 18 · ADR 0040 选项 C 第二步）
//!
//! 双端 wasm-core（桌面同源 crate / 移动端退役 fork 同名 crate）的 host_api 域中，
//! **不依赖 WIT
//! bindgen trait、不依赖任何一端独有类型**的机制实现层抽到本 crate。每域两层：
//!
//! ```text
//! 实现层（本 crate）：      纯机制语义——权限门（权限词汇经参数传入）、纵深守卫、
//!                           属主分区、能力路由、真源接入；端口 trait 定义在此
//! 各端 adapter（wasm-core）：把本端宿主服务（SqlitePorts / host_ctx /
//!                           granted_permissions …）接到实现层的端口 trait 上
//! WIT 绑定层（各自）：      component.rs 的 bindgen trait impl → 域函数 → adapter
//! ```
//!
//! ## 边界判据（实现层的准入条件，违者应留在各端）
//!
//! - **禁止**引用 `wasmnest_plugin_api` / `wasmnest_plugin_api_mobile`（双端 WIT SDK）
//!   与双端 wasm-core 的宿主胶水（`crate::plugin` 等）；
//! - **只允许**：机制词汇（permission 常量经参数传入）、本 crate 定义的端口 trait、
//!   机制级依赖（serde_json / tracing）；
//! - **禁止**宿主平台（tauri）与运行时（tokio）依赖——阻塞 / 驱动异步是各端 adapter
//!   的职责（桌面 `runtime_util::block_on_async`、移动 `block_in_place` + `block_on`）。
//!
//! 上述判据由 `tests/boundary_lock.rs` 强制（票 18 §6）。
//!
//! ## 域进度（每域一步、可回退，迁移顺序见票 18 §3）
//!
//! | 域 | 状态 |
//! | --- | --- |
//! | `storage` | 已抽（批次 1） |
//! | `bus` | 已抽语义（批次 2：topic 形态机制 + 命名空间/订阅面/互调门禁 + 发布门禁链；队列与订阅簿留各端） |
//! | `database` | 已抽（批次 3，2026-10-09）——**双端机制决策收缩（同日用户指令）**：主库由 wasm-core 管理、不给任何 wasm-app / 插件直接调用的方法，`host-database` 接口自双端 WIT 面移除（ABI 桌面 34→35 / 移动 18→19），authorizer 纵深 / 主库前缀校验 / `database:main` 权限位随之退役；本层收缩为**插件私有库面**（`host-plugin-database`）：权限门（`storage`）→ 语句超时护栏 → 结果集护栏 → 批次事务 |
//! | `log` | 已抽（批次 4，2026-10-09）——callsite 缓存 + 按调用点 `'static` Metadata + per-plugin 级别阈值（`WASMNEST_PLUGIN_LOG`）+ `[plugin:xxx]` 前缀，全套上移；移动端 host-log 接入后获得桌面全套日志机制（此前仅裸 tracing 输出） |
//! | `events` | 已抽（批次 4，2026-10-09）——事件载荷严格 JSON 解析语义（H-05 fail-visible）；移动端 emit 接入后行为对齐（非法载荷不再宽松降级） |
//! | `fs` | **已抽（2026-10-10，wasm-core-mobile-purity 票 05）**——交集 6 原语的机制面（权限门 → 访问裁决 → 路径形状守卫）自移动 wasm-core `runtime/bare/host_impl/fs.rs` 上移；平台差（Android MediaStore/SAF 删除）经 [`fs::FsHostPorts::platform_delete`] 端口注入。**桌面侧的 WSL 桥 / 任务单元消费面不在本次抽取范围**，其实现体仍在桌面 wasm-core `host_api/fs.rs`——后续是否改用本层另票，不影响本层成立 |
//! | `config` / `http` | **判定不抽**（2026-10-09，逐域按 §2 判据核对；票 05 复核维持）：config 实现层直接引用各端 SDK `ConfigKey` 枚举（判据「不得引用 SDK 类型」不满足）；http 桌面已抽能力域 crate（`wasmnest-server-http::plugin_binding`）+ 端口、移动同为能力域 crate 形态（票 05）——两端都各自接第八方端口，无第二份共享实现层 |
//!
//! ## 与 `wasmnest-host-kit` 的边界
//!
//! host-kit 是「机制锚点」最小面（实例状态 / 能力模块契约 / 注册表，wasmtime
//! **装配期**）；本 crate 是 host_api **域实现层**（原语语义，**运行期**）。同族
//! 不合并：host_api 实现层塞入会模糊 host-kit 的最小面边界（票 18 §4 选项 A 裁决）。

#![deny(missing_docs)]

pub mod bus;
pub mod database;
pub mod events;
pub mod fs;
pub mod gate;
pub mod log;
pub mod storage;

// 边界锁随 crate 单元测试跑（治理面漂移 P3 收口：跨 crate 集成测试归宿主，
// 本锁是 crate 内单元级自检——tests/ 面不可用于治理 crate）
#[cfg(test)]
mod boundary_lock;
