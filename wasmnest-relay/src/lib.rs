//! # wasmnest-relay：内网穿透中继守护进程
//!
//! **定位**：跑在公网 VPS / 用户自建 Linux 服务器上的独立守护进程，提供 libp2p
//! Circuit Relay v2 转发。它不是 wasm 插件、不是宿主内嵌服务，也不参与任何产品
//! 语义——中继只做「按配额转发密文字节」，看不到文件内容、终端内容与 HTTP 路径。
//!
//! ## 边界（实现必须守住的四条）
//!
//! 1. **relay 不是授权点**：reservation 只代表「可以经我转发」，不代表「可以访问
//!    目标」。真正的匹配校验发生在目标宿主；allowlist / enrollment token 只用于
//!    防滥用，不能当成设备配对。
//! 2. **只转发不终止**：Noise 在 libp2p 层完成，中继不持有任何会话密钥，也不
//!    解析内层协议；因此抓包只能看到密文。
//! 3. **不记业务面**：指标只聚合计数（reservation / circuit / 拒绝原因），不含
//!    文件名、路径、payload、token 明文；日志只打 PeerId 短指纹与事件。
//! 4. **失败显性**：身份缺失、配置非法、端口不可用、配额越界一律报错退出，不
//!    静默降级成「开放转发」。
//!
//! ## 模块分工
//!
//! - [`config`]：TOML 配置与校验（未知字段即报错，防止手改配置被静默忽略）
//! - [`identity`]：ed25519 身份密钥（落盘即 PeerId；丢失 = 所有客户端需重新导入）
//! - [`quota`]：配额解析、`libp2p::relay::Config` 映射、每 IP 连接计数
//! - [`access`]：开放 / 白名单两种准入模式 + enrollment 后的持久白名单
//! - [`tokens`]：一次性 enrollment token（只落 SHA-256 摘要）
//! - [`control`] / [`wire`]：`/wasmnest/relay-control/1` 控制协议（版本 / 模式 / 兑换）
//! - [`server`]：swarm 装配与事件循环
//! - [`metrics`] / [`metrics_server`]：计数聚合与 `127.0.0.1:9090` 健康/指标端点
//! - [`addrs`]：`print-addrs` 导入载荷（应用侧导入契约的产出方）
//! - [`doctor`]：自检（身份 / 配置 / 端口 / 时钟 / 目录可写 / 版本）
//! - [`cli`]：`init` / `run` / `doctor` / `print-addrs` / `token create`
//!
//! ## 部署形态
//!
//! 单文件静态二进制 + Docker 镜像 + Compose；身份与配置落 `/data`，重启不换
//! PeerId。`init` 生成身份与配置，`run` 起服务，两者可独立使用。

pub mod access;
pub mod addrs;
pub mod boundary_lock;
pub mod cli;
pub mod config;
pub mod control;
pub mod doctor;
pub mod error;
pub mod fsutil;
pub mod identity;
pub mod logging;
pub mod metrics;
pub mod metrics_server;
pub mod quota;
pub mod server;
pub mod tokens;
pub mod wire;

pub use error::{RelayError, Result};

/// 中继版本（`print-addrs` 与应用导入/自检的版本面）
pub const RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");
