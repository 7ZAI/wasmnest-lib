//! WS 通道处理器实现
//!
//! 骨架（本 crate `conn`）负责连接生命周期，通道负责协议语义。
//! 终态（websocket 业务下沉票 08）只有[`plugin`]一个实现：插件端点
//! `/ws/plugin/{plugin_id}/{path}`——宿主零业务语义，认证策略由端点声明，
//! 帧转投属主插件。旧终端路由 `/ws/terminal/session/{id}` 与事件通道
//! `/ws/event` 的通道实现已随业务硬切删除（协议归插件）。
//!
//! 新增通道 = 新增一个 `ChannelHandler` 实现 + 路由构造点，不改骨架
//! （阶段 A 抽取骨架的全部意义所在，spec §3.2 A1）。

pub mod plugin;
