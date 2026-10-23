//! 日志域能力域 **adapter**（实现层已上移共享核，票 18 批次 4）
//!
//! 机制语义（统一 callsite / 按调用点缓存的 `'static` Metadata / per-plugin 级别
//! 阈值过滤 / `[plugin:xxx]` 前缀格式化）在 `wasmnest-host-api-core::log`（双端单点，
//! 以桌面机制为完整基准）；本文件 re-export 保符号面——`component.rs` 绑定层
//! （`log::log_info` 等四函数）与测试基建（`log::capture`，engine_config /
//! engine_limits 消费）路径零改动。
//!
//! target 命名统一为共享核 `wasmnest_host_api_core::plugin_log`（原桌面
//! `wasmnest_desktop_lib::wasm_core::plugin_log` 无过滤消费者，实测）。

pub use wasmnest_host_api_core::log::{log_debug, log_error, log_info, log_warn};
// `plugin_log_metadata` / `LOG_TARGET` 无任何消费者（含宿主），不再 re-export
// `capture` 单独拆行：只被桌面装配面 / test-support 的测试基建（engine_config /
// engine_limits 消费）引用——单形态共享故保留，按形态豁免 unused
#[cfg_attr(
    not(any(feature = "desktop-assembly", feature = "test-support")),
    allow(unused_imports)
)]
pub use wasmnest_host_api_core::log::capture;
