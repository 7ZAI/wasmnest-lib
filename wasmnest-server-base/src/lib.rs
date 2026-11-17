//! wasmnest-server-base：桌面 server 基础层
//!
//! 传输无关、宿主无关的**共享基础**：错误类型（`error`，宿主 `system::error`
//! 与其同源，经 `pub use` 薄壳回导）、引擎常量（`constants`）、错误边界工具
//! （`error_boundary`）、系统信息（`info`）、网络配置形状（`config`）、认证
//! 中心裁决返回的连接身份（`identity`）与**端口 traits**（`ports`——server
//! 各面反向需要的宿主能力，由宿主壳注入实现）。
//!
//! 本 crate 是 `wasmnest-server-core` / `-http` / `-websocket` / `-peer-net`
//! 的共同底座；`-peer-net` 只依赖本 crate（底座机制
//! 拆分并入该 crate 自身 `base/`，不再有独立共享引擎），不依赖 core 的传输机制。
//! 共享端口 traits 因此落本 crate：peer-net 不依赖 core，却同样需要它们——
//! 放本 crate 才能在「peer-net 只向下依赖」的形状内成立。
//!
//! **依赖面（默认形态依赖边界）**：本 crate 的**默认依赖树只依赖
//! 零依赖契约仓**——`AppError::Database(String)` 不再携带 `rusqlite::Error`、
//! `notify` / `link-crypto` 的 `From` impl 已删、`tauri` / `mdns-sd` + `flume` /
//! `sysinfo` + `local-ip-address` 全部 optional 且 feature **默认关**：
//!
//! | feature | 打开后 | 消费方 |
//! | --- | --- | --- |
//! | `tauri-compat` | `From<tauri::Error> for AppError` | 桌面宿主（显式开） |
//! | `mdns` | `MdnsPort` / `MdnsTypeSubscription` / `ServerPorts.mdns` | `wasmnest-server-peer-net`、桌面宿主 |
//! | `system-info` | `SystemInfo::collect()` / `local_ipv4_addresses()` | 桌面宿主（无头宿主可自行实现 `SystemInfoPort`） |
//!
//! 「叶子地基」不是形容词：`cargo tree -e normal` 只应看到 serde / tokio / tracing
//! 这类机制级依赖 + 契约仓；`scripts/check-default-form-deps.sh` 钉住这条判据。

pub mod config;
pub mod constants;
pub mod error;
pub mod error_boundary;
/// 传输面标记（listener 注入的信任判据，供 caller 分类与链加密豁免共用）
pub mod face;
pub mod identity;
pub mod info;
pub mod ports;
/// 私钥 / 身份文件的「只在不存在时发布」落盘原语（模板见模块文档）
pub mod private_file;
pub mod process;
/// 应用作用域共享服务的租约模板（依赖服务按插件引用记账启停）
pub mod service;
pub mod wire;
