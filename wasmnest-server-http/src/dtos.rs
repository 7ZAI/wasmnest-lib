//! Server DTOs
//!
//! 请求/响应数据传输对象
//!
//! ## 编译面纪律（AGENTS §5.1.1 B1/B4）
//!
//! 本模块只有 `common_dto` 进生产构建——通用 `ApiResponse` 信封与两个业务码常量，
//! 是传输面自己要的机制面东西。
//!
//! 其余四组（会话 / 配置 / 文件 / git）是**跨端 wire 形状的历史真身**，生产路由早已
//! 移交插件（ABI v29），宿主不再构造它们。它们只作为「移动端看到的字节」这一契约的
//! 黄金样本存在，故整组 `#[cfg(test)]` 门控：门控即锁——生产代码一旦引用这些类型，
//! **编译器**直接报错，不需要另设断言锁（这是本仓库少见的「锁即类型系统」位置）。
//!
//! `config_dto` 是唯一的例外，见下。

pub mod common_dto;
/// 跨端 wire 黄金样本：配置域 DTO（configs / quick-actions）。
///
/// **唯一非纯本 crate 消费的一组**：`wasmnest-wasm-core` 的
/// `manager/runtime/tests/session_e2e.rs` 用 `ConfigItem` / `ConfigListResponseData`
/// 作「插件面输出 == 宿主旧形状」的跨 crate 黄金比对，把契约锚在**双方共用的同一份
/// 类型**上而不是两份复刻。代价是本组进了依赖方的非测试构建（依赖编译不带
/// `cfg(test)`），故不能整组门控。
///
/// 该跨 crate 依赖是已知的方向性耦合（机制核 → 传输面的产品 DTO），待
/// `wasmnest-wasm-core` 侧改自持黄金形状后即可收回本组并整组门控。
pub mod config_dto;
/// 跨端 wire 黄金样本：文件浏览 / diff DTO。
#[cfg(test)]
pub mod file_dto;
/// 跨端 wire 黄金样本：git 域 DTO（status / branches / checkout）。
#[cfg(test)]
pub mod git_dto;
/// 跨端 wire 黄金样本：会话域 DTO（list / start / resize / input / history）。
#[cfg(test)]
pub mod session_dto;

pub use common_dto::{ApiResponse, CODE_INVALID_REQUEST, CODE_PLUGIN_AUTH_FAILED};
