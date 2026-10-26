//! WasmNest PTY 能力域（`host-pty`，6 条原语）+ 可复用 PTY 引擎面
//!
//! ## 两层结构
//!
//! ```text
//!   pty_process / pty_reader / pty_ring / lifecycle / output_sink   引擎面（零 wasm）
//!   plugin_binding（primitives / registry / output / ports）        能力域（WIT 接线）
//! ```
//!
//! 引擎面是**跨平台伪终端引擎**：进程生命周期（创建 / 启动 / 终止 / 回收）、输出读取
//! 线程、输出环形缓冲（`PtyRing`，游标拉取）、终态汇聚门。引擎面只依赖
//! `wasmnest-server-base`（常量 / 错误边界）与第三方（portable-pty / tokio）——
//! **任何宿主可复用**（不依赖 wasmtime、不依赖宿主 bin crate）。
//!
//! 能力域层随 [.scratch/2026-10-06-pty-capability-domain/spec.md] D1/D2 迁入：
//! WIT 接线（`bindgen!` provider 侧生成 + 6 条原语的宿主实现 + 能力模块自报）与域
//! 机制（句柄表 / 配额仲裁 / 退出事件 / 限频通知）一并住在这里，宿主侧只剩一个端口
//! adapter 与一次开机装配调用——与 http / ws / peer-net / mdns 四域同形。
//!
//! **依赖方向**：本 crate 依赖 `wasmnest-host-kit`（能力模块契约 + 插件实例状态）与
//! `wasmnest-server-base`，**不依赖 wasm-core / 不依赖宿主**。
//!
//! ## 零业务语义（2026-09-23 PTY 解耦票，迁移时保留）
//!
//! 引擎只接受调用方**算好的 argv**（`portable_pty::CommandBuilder`）——不做 shell
//! 包装 / WSL 路径转换 / 业务环境注入。shell 包装与业务环境注入在消费侧
//! （业务会话 = 插件 `com.wasmnest.bedcode` 的 `launch.rs`；插件私有 PTY =
//! 插件自己）。业务输出汇实现亦不在引擎面（调用方自备 `PtyOutputSink`；本 crate 的
//! 限频通知装饰器是机制，不是业务汇）。
//!
//! ## 引擎级配置（E1/D5：AppConfig 读点参数化）
//!
//! 引擎面**不感知宿主配置**——生命周期广播容量 / 读缓冲大小由调用方在
//! [`PtySession::with_command`] / [`PtySession::with_private_command`] 时经
//! [`PtyEngineConfig`] 传入；能力域层则经端口向宿主要快照
//! （[`plugin_binding::ports::PtyPorts::config`]）。

pub mod lifecycle;
pub mod output_sink;
pub mod plugin_binding;
pub mod pty_process;
pub mod pty_reader;
pub mod pty_ring;
pub mod pty_status;
mod runtime;
/// wire 契约词汇自持副本（能力域脱绑 P4：topic 规则 / PTY 事件名 / 权限位 /
/// 按键组合线协议，与桌面 SDK 原版逐字一致由平台仓漂移锁
/// `cross-end-tests/tests/wire_drift_locks.rs` 钉死）
pub mod wire;

pub use lifecycle::{PtyTerminated, PtyTerminationGate};
pub use output_sink::PtyOutputSink;
pub use pty_process::PtySession;
pub use pty_ring::{PtyRing, PtyRingFetch, PtyRingSink};
pub use pty_status::PtySessionStatus;

/// PTY 引擎消费的宿主配置快照（E1/D5 参数化：原 `AppConfig::global()` 的两处读点）
///
/// 引擎不感知宿主配置来源（文件 / 环境 / 注入皆可），只收这份与 PTY 行为相关的
/// 快照。`Default` 提供与旧 `AppConfig` 默认值一致的数值（16 / 4096），以便
/// 无配置宿主与测试零成本使用。
#[derive(Debug, Clone, Copy)]
pub struct PtyEngineConfig {
    /// 生命周期事件广播容量（原 `channels.lifecycle_capacity`，默认 16）
    pub lifecycle_capacity: usize,
    /// PTY 输出读缓冲大小（原 `terminal.read_buffer_size`，默认 4096）
    pub read_buffer_size: usize,
}

impl Default for PtyEngineConfig {
    fn default() -> Self {
        Self {
            lifecycle_capacity: 16,
            read_buffer_size: 4096,
        }
    }
}
