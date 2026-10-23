//! host-pty 能力域的 wire 契约词汇（自持副本）
//!
//! ## 为什么自持（能力域脱绑 P4，2026-10-08）
//!
//! 能力域默认形态 = 纯引擎机制 + 端口抽象（零 WIT 依赖），任何宿主（桌面 / 移动端 /
//! 无头测试宿主）可直接引用。本 crate 原先直连桌面 SDK（`wasmnest-plugin-api`）的
//! wire 词汇因此改为**本域自持副本**：
//!
//! - [`TOPIC_NS_SEP`] + [`owned_topic`]：属主私有 topic 拼接规则（`::` 分隔符）；
//! - [`PTY_EXIT`] / [`PTY_OUTPUT`]：PTY 生命周期事件名（属主私有 topic 的 name 段）；
//! - [`pty_event_topic`]：PTY 事件 topic 构造（形状与 SDK 逐字等价）；
//! - [`PERMISSION_PTY_IO`] / [`PERMISSION_PTY_SPAWN`]：权限位判据字符串；
//! - [`key`] 子模块：按键组合线协议（`KeyCombo` / `KeyCode` / modifiers，整段复制）。
//!
//! 全部都是纯 wire 契约（事件名 / 命名空间 / 线协议形状），不携带宿主机制。
//! 桌面 SDK 原常量**不删除**（宿主 bus 面 / 插件侧仍有消费方），副本与原版逐字
//! 一致（或语义等价）由平台仓漂移锁钉死（三仓拆分 L2/E2b 票 08 迁出本 crate：
//! `cross-end-tests/tests/wire_drift_locks.rs`）：漂移即红。
//!
//! 注意：本模块定义块的注释与桌面 SDK **逐字一致**（漂移锁按文本块比对），
//! 本地说明一律写在本模块文档与下方分隔注释里，不要改动定义块内注释。

// ==================== 以下 topic 词汇块与桌面 SDK host/bus.rs 逐字一致 ====================
// （漂移锁分别提取「行首为三个斜杠 + 空格 + 私有 topic 命名空间分隔符」至「行首为
// 三个斜杠 + 空格 + 互调请求道前缀」、以及「行首为三个斜杠 + 空格 + 构造属主私有
// topic」至「行首为三个斜杠 + 空格 + 解析 topic 的属主」之间的文本块比对。）

/// 私有 topic 命名空间分隔符（插件 id 字符集不含 `:`，故无歧义）
pub const TOPIC_NS_SEP: &str = "::";

/// 互调请求道前缀
// （上面这行是与桌面 SDK host/bus.rs 下一条注释的共享起笔文本，漂移锁用作
// TOPIC_NS_SEP 提取块的结束标记。）

/// 构造属主私有 topic：`<owner>::<name>`
pub fn owned_topic(owner: &str, name: &str) -> String {
    format!("{owner}{TOPIC_NS_SEP}{name}")
}

/// 解析 topic 的属主
// （上面这行是与桌面 SDK host/bus.rs 下一条注释的共享起笔文本，漂移锁用作 owned_topic
// 提取块的结束标记；本 crate 不复制 topic_owner / is_reply_topic 等宿主面助手。）

// ==================== 以下 PTY 事件常量块与桌面 SDK host/pty.rs 逐字一致 ====================
// （漂移锁提取「行首为三个斜杠 + 空格 + PTY 进程退出」至「行首为三个斜杠 + 空格 +
// 生成属主私有事件 topic」之间的文本块比对，不要改动块内任何字符——含注释。）

/// PTY 进程退出（唯一的生命周期事件）
pub const PTY_EXIT: &str = "pty:exit";

/// 输出可用通知（限频唤醒；**提示非承诺**，数据仍走 `ring-fetch`）
///
/// 宿主在句柄的输出环**有新字节**时按属主私有 topic（`<owner>::pty:output`）
/// 限频发布——同一句柄两次通知间隔 ≥ 50 ms，窗口内的产出合并丢弃，payload `{ ptyId }`。
/// 用途：把「空闲期新输出到达」的感知延迟从轮询档位（几十~几百 ms）压到毫秒级。
///
/// 三条必须遵守的语义（与 [`PTY_EXIT`] 的「先消费完再等退出」相反，本事件**不是真源**）：
/// 1. **可丢**：无订阅者 / 订阅队列满 / 插件未激活 / 被限频合并——任一情况都会少收，
///    宿主不补发、不重放（总线无重放缓冲）；
/// 2. **不带数据**：payload 只有句柄，字节仍由 [`HostPty::pty_ring_fetch`] 按游标拉取，
///    背压与 `truncated` 语义一字未变；
/// 3. **不替代轮询**：事件只用来提前触发一轮拉取，自己的兜底节奏必须保留。
///
/// 订阅方式与 [`PTY_EXIT`] 相同（`activate` 期 `bus_subscribe` + [`pty_event_topic`]）；
/// 订阅失败只降级为「退回纯轮询」，不必阻断激活。
pub const PTY_OUTPUT: &str = "pty:output";

/// 生成属主私有事件 topic
// （上面这行是与桌面 SDK host/pty.rs 下一条注释的共享起笔文本，漂移锁用作 PTY 事件
// 常量块的结束标记。）

/// 生成属主私有事件 topic：`<owner>::pty:<event>`
///
/// `owner` 必须传本插件 ID（票 05 命名空间：定向事件只投属主收件箱，
/// 他人订阅被宿主拒绝）。`event` 用 [`PTY_EXIT`] 常量，避免手拼拼错导致
/// 「订阅了却永远收不到」。
///
/// 语义与 SDK `host::pty::pty_event_topic` 逐字等价：SDK 实现调 `host::bus::owned_topic`，
/// 本 crate 调上方 [`owned_topic`]（它本身与 SDK `bus::owned_topic` 逐字一致、由漂移锁
/// 钉死），故形状与 SDK 完全一致。
pub fn pty_event_topic(event: &str, plugin_id: &str) -> String {
    owned_topic(plugin_id, event)
}

// ==================== 以下权限位常量与桌面 SDK permission.rs 行级比对 ====================

/// 权限位：`pty:spawn`（spawn / kill 的高风险面）
pub const PERMISSION_PTY_SPAWN: &str = "pty:spawn";
/// 权限位：`pty:io`（write / resize / ring-fetch / is-running 数据面）
pub const PERMISSION_PTY_IO: &str = "pty:io";

/// 按键组合线协议（`KeyCombo` / `KeyCode` / modifiers；与桌面 SDK `wire::key` 逐字一致）
pub mod key;

#[cfg(test)]
mod tests {
    use super::{pty_event_topic, PTY_EXIT, PTY_OUTPUT};

    /// [`pty_event_topic`] 的对外形状：属主私有命名空间 + 事件名常量拼接
    ///
    /// 与桌面 SDK 的 wire 契约逐字比对锁已随三仓拆分 L2/E2b（票 08）迁平台仓
    /// `cross-end-tests/tests/wire_drift_locks.rs`（能力仓不再读平台源文件），
    /// 本用例只断言本 crate 自己的形状语义。
    #[test]
    fn pty_event_topic_shape() {
        assert_eq!(pty_event_topic(PTY_EXIT, "com.x"), "com.x::pty:exit");
        assert_eq!(pty_event_topic(PTY_OUTPUT, "com.x"), "com.x::pty:output");
        assert_ne!(
            pty_event_topic(PTY_EXIT, "a"),
            pty_event_topic(PTY_EXIT, "b"),
            "属主私有命名空间必须隔离"
        );
    }
}
