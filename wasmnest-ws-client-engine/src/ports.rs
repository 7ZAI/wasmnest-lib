//! 宿主端口：本能力域与宿主之间**唯一**的边界
//!
//! ## 设计依据（`wasmnest-discovery-engine::ports` / `wasmnest-server-base::ports` 先例）
//!
//! 消费方（本 crate）声明端口，宿主实现。本 crate **不依赖平台、不依赖宿主 bin crate、
//! 不依赖任何一侧 SDK**，任何宿主换一个端口实现即可复用。
//!
//! ## 七个方法的取舍
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | [`WsClientPorts::check_permission`] | 权限门（`ws:client`）是**宿主安全闸门**（AGENTS §5.1.3 四类薄壳之二），不该可插拔 ⇒ 留宿主，本 crate 只问结果（出站是 SSRF 面，fail-closed） |
//! | [`WsClientPorts::publish`] / `publish_binary` | 事件（JSON）与入站帧（二进制信封）都走**已拼好的完整 topic**；总线订阅方隔离在宿主侧。帧必须走二进制通道：零 JSON 编解码是性能红线（大块终端输出禁止经 JSON 搬运） |
//! | [`WsClientPorts::spawn`] | reader / writer / 重连都是后台任务，**必须挂在宿主运行时上**（宿主调用栈不保证处于 runtime 上下文：wasmtime 的 fiber 内直接 `tokio::spawn` 会 panic） |
//! | [`WsClientPorts::global_token`] | `jwt-auth` 首帧代发要宿主认证状态里的 token（凭据不落插件，C4）；宿主只交出「代发时那一刻的 token 值」 |
//! | [`WsClientPorts::reconnect_bounds`] / `reconnect_policy` | 退避重连的**全局退避单一事实源**在宿主（下限钳制是自愈风暴的教训沉淀）；本 crate 只按策略推进循环 |
//!
//! ## 为什么 `spawn` 返回可取消句柄而不是丢弃
//!
//! 停用回收 / 队列满强关 / 连接关闭收尾都必须能**中止**读或写任务——不中止的话，
//! 已关闭连接的任务会留在宿主运行时里等一个永不到来的唤醒（任务泄漏），
//! 且单插件连接配额会被已死条目占死。故 [`WsTask`] 只暴露 `cancel()`，
//! **不暴露宿主运行时句柄类型**（tokio / tauri 的 `JoinHandle` 不外泄到本 crate）。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

/// 能力域可用的宿主类型别名（boxed future；`async fn` 在 trait 里会破坏 dyn 兼容）
pub type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// 后台任务句柄（宿主实现提供取消能力）
///
/// 本 trait 只承诺「可取消」，不暴露宿主运行时类型。新增能力域若需要等待任务
/// 结束（join），另加方法并同步评估各端实现——当前域不需要。
pub trait WsTask: Send + Sync + 'static {
    /// 取消任务（幂等：重复调用不 panic）
    fn cancel(&self);
}

/// WS 自动重连的退避策略面（票 12 R1）
///
/// 策略对象由宿主实现（真源 = 宿主全局退避：指数退避 + 抖动 + 下限钳制）；
/// 本 crate 只按「排期 → 等延迟 → 重建连接 → 成功回报」推进循环。
#[async_trait]
pub trait ReconnectPolicy: Send + Sync {
    /// 推进一轮排期（无限重试下恒 `Some`；防御性保留放弃分支）
    async fn start(&self) -> Option<()>;
    /// 当前轮次的退避延迟
    async fn get_delay(&self) -> Duration;
    /// 重连成功回报（重置退避状态）
    async fn on_success(&self);
}

/// 宿主能力端口
///
/// 实现方是各端宿主的适配器（移动端见 fork crate 的 `MobileWsClientPorts`）。
/// 实现应当尽量做成**可克隆的轻量句柄**——reader / writer / 重连任务都会长期持有
/// 本端口（`'static`），故字段只放 `Arc` / 可克隆宿主句柄。
pub trait WsClientPorts: Send + Sync + 'static {
    /// 权限判定：出站连接是 SSRF 面（插件可代宿主访问任意 `ws://` 地址），
    /// 权限位独立且 **fail-closed**（未在 manifest 声明即拒）。
    ///
    /// 返回 `false` 时**宿主侧**应已按 AGENTS §8 落 `warn`（结构化字段
    /// `plugin_id` / `permission` / `api`）；本 crate 只负责把拒绝转成统一错误文案。
    fn check_permission(&self, plugin_id: &str) -> bool;

    /// 全局 JWT token（`jwt-auth` 首帧代发用）；未认证时空串。
    ///
    /// 只记长度不落明文（AGENTS §8 凭据红线），本 crate 侧也不打印其值。
    fn global_token(&self) -> String;

    /// 重连退避钳制边界 `(min_delay_ms, max_delay_ms)`（宿主全局常量的投影；
    /// 本 crate 在运行期取，不持常量副本——杜绝双真源漂移）
    fn reconnect_bounds(&self) -> (u64, u64);

    /// 重连策略对象（参数钳制已在域内完成，宿主实现只出策略）
    fn reconnect_policy(
        &self,
        max_retries: u32,
        base_ms: u64,
        max_ms: u64,
    ) -> Box<dyn ReconnectPolicy>;

    /// 向**已拼好的完整 topic** 投递 JSON 状态事件
    ///
    /// topic 由本 crate 用 [`crate::wire::ws_event_topic`] 拼好（属主私有命名空间：
    /// `<plugin-id>:ws:<event>`）——那是纯字符串逻辑，留在能力域侧；宿主只负责
    /// 「往这个 topic 上发」并做总线的订阅方隔离。
    fn publish(&self, topic: &str, payload: serde_json::Value);

    /// 向**已拼好的完整 topic** 投递二进制帧信封（零 JSON 编解码）
    fn publish_binary(&self, topic: &str, payload: Vec<u8>);

    /// 在**宿主运行时**上派生后台任务，返回可取消句柄
    ///
    /// `task_name` 供宿主侧错误边界 / 日志标识任务（如 `ws_client_writer`）。
    /// 宿主实现应包上 panic 错误边界（任务 panic 不得静默终止，也不得污染宿主状态）。
    fn spawn(&self, task_name: &'static str, task: BoxedTask) -> Arc<dyn WsTask>;
}
