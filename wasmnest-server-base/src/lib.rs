//! wasmnest-server-base：桌面 server 基础层（server-lib-split 票 02）
//!
//! 传输无关、宿主无关的**共享基础**：错误类型（`error`，宿主 `system::error`
//! 与其同源，经 `pub use` 薄壳回导）、引擎常量（`constants`）、错误边界工具
//! （`error_boundary`）、系统信息（`info`）、网络配置形状（`config`）、认证
//! 中心裁决返回的连接身份（`identity`）与**端口 traits**（`ports`——server
//! 各面反向需要的宿主能力，由宿主壳注入实现）。
//!
//! 本 crate 是 `wasmnest-server-core` / `-http` / `-websocket` / `-peer-net`
//! 的共同底座；peer-net 只依赖本 crate（+ `wasmnest-peer-net`），不依赖 core
//! 的传输机制（spec D2 意图）。spec 端口表把 `BusPort` / `EventSink` /
//! `PathsPort` 记在 server-core 而 peer-net 又不依赖 core，是 4-crate 形状内
//! 的自相矛盾——实施裁决：共享端口 traits 落本 crate，peer-net 依赖本 crate
//! 取用。

pub mod config;
pub mod constants;
pub mod error;
pub mod error_boundary;
pub mod identity;
pub mod info;
pub mod ports;
pub mod process;
pub mod wire;
