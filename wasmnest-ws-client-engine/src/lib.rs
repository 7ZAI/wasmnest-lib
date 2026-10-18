//! WasmNest WS 出站连接能力域（`host-websocket` **客户端子集**：5 条原语 + 停用回收）
//!
//! 一个「可独立组合的宿主能力」的完整样板：连接引擎、wire 契约词汇、宿主端口边界与
//! 边界锁全部住在这一个 crate 里；各端宿主只留薄适配器（装配端口 + 转发 WIT/ABI 面）。
//!
//! ## 分层
//!
//! ```text
//!   engine.rs  机制：句柄表（属主化）+ reader/writer 双任务 + 心跳 + 自动重连 +
//!              帧信封 + 停用回收（零宿主依赖）
//!   ports.rs   边界：宿主能力端口（权限门 / 总线投递 / 宿主运行时任务 / jwt 代发 token /
//!              重连退避策略）
//!   wire.rs    契约：事件名 / 属主私有 topic 拼法 / 帧信封 kind 与头长 / 权限字面量
//!              （自持副本，与移动 SDK 逐字一致由平台仓漂移锁
//!              `cross-end-tests/tests/wire_drift_locks.rs` 钉死）
//!   lib.rs     出口：模块与常量再导出
//! ```
//!
//! ## 通用能力形态（AGENTS §0 路径基准 / §5 无业务内核）
//!
//! 默认形态 = **纯引擎 + 端口抽象**：零 WIT、零 SDK、零平台依赖，任何宿主
//! （移动端 / 桌面端 / 无头测试宿主 / 第三方宿主）换一个 [`ports::WsClientPorts`]
//! 实现即可引用。平台差异四类全部经端口注入：
//!
//! | 差异面 | 端口方法 | 为什么不能住引擎 |
//! | --- | --- | --- |
//! | 权限门（`ws:client`，fail-closed） | [`ports::WsClientPorts::check_permission`] | 授权表是宿主安全闸门（AGENTS §5.1.3 ②） |
//! | 事件 / 帧投递（总线 topic） | [`ports::WsClientPorts::publish`] / `publish_binary` | 总线与会话隔离是宿主机制 |
//! | 后台任务（reader/writer/重连） | [`ports::WsClientPorts::spawn`] | 宿主调用栈不保证处于 runtime 上下文 |
//! | jwt 代发 token / 重连退避策略 | `global_token` / `reconnect_policy` / `reconnect_bounds` | 凭据（C4）与全局退避单一事实源都在宿主 |
//!
//! ## 红线（AGENTS §5.1）
//!
//! 本 crate **不含任何产品概念**：无「会话」「终端」「设备」「配对」等名词。连接目标
//! （url / headers / subprotocols）与帧内容都是**纯字节透传**——引擎只搬字节，不解释字节；
//! 产品语义（订阅协议 / 心跳编排 / ack-resync）归各 wasm 应用。属主隔离、事件定向投递、
//! 停用回收三项语义在 [`engine`] 中逐字保留。

#![deny(missing_docs)]

pub mod engine;
pub mod ports;
pub mod wire;

/// 边界锁（crate 内单测，随治理 crate 规则：集成测试面不落 crate 根 `tests/`）
#[cfg(test)]
mod boundary_lock;
