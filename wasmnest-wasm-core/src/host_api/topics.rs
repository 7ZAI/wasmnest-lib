//! 宿主事件 topic 词汇（pty / ws 域事件常量与订阅 topic 构建器）
//!
//! 批 2 自桌面 SDK 收口上提（平台仓 issue #36）：事件名与 topic 形态是
//! 宿主→插件的总线 wire 契约，真源归机制层；SDK 侧同名拷贝是 guest 编译期
//! 消费面（guest 据此在 `activate` 期 `bus_subscribe`），一致性由跨端漂移锁断言。
//!
//! topic 命名空间机制（私有 `<owner>::<name>` / 公开、门禁判定）真源在
//! [`wasmnest_host_api_core::bus`]；本模块只登记**域事件名**与便捷构建器，
//! 禁止手拼 topic。

use wasmnest_host_api_core::bus::owned_topic;

/// 进程退出事件（宿主发布属主私有 topic，payload `{ ptyId, reason, exitCode? }`，
/// camelCase；`reason = "stopped" | "killed" | "error"`）
pub const PTY_EXIT: &str = "pty:exit";
/// 输出块事件（宿主发布属主私有 topic）
pub const PTY_OUTPUT: &str = "pty:output";

/// 生成属主私有状态事件 topic：`<owner>::<event>`
///
/// `owner` 必须传本插件 ID（命名空间语义：宿主把状态事件定向投进属主收件箱，
/// 他人订阅被宿主拒绝）。`event` 用 [`PTY_EXIT`] / [`PTY_OUTPUT`] 常量，避免
/// 手拼拼错导致「订阅了却永远收不到」（漏订阅不报错）。
pub fn pty_event_topic(event: &str, plugin_id: &str) -> String {
    owned_topic(plugin_id, event)
}

/// WebSocket 出站连接状态事件
pub const WS_OPEN: &str = "ws:open";
pub const WS_ERROR: &str = "ws:error";
pub const WS_CLOSE: &str = "ws:close";
/// 入站端点连接事件
pub const WS_CLIENT_CONNECT: &str = "ws:client-connect";
pub const WS_CLIENT_DISCONNECT: &str = "ws:client-disconnect";

/// 生成属主私有状态事件 topic：`<owner>::<event>`（`event` 用本模块 `WS_*` 常量）
pub fn ws_event_topic(event: &str, plugin_id: &str) -> String {
    owned_topic(plugin_id, event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmnest_host_api_core::bus::topic_owner;

    #[test]
    fn pty_topic_is_owner_private() {
        assert_eq!(pty_event_topic(PTY_EXIT, "com.x"), "com.x::pty:exit");
        assert_eq!(
            topic_owner(&pty_event_topic(PTY_OUTPUT, "com.x")),
            Some("com.x")
        );
    }

    #[test]
    fn ws_topic_is_owner_private() {
        assert_eq!(
            ws_event_topic(WS_CLIENT_CONNECT, "com.y"),
            "com.y::ws:client-connect"
        );
        assert_eq!(
            topic_owner(&ws_event_topic(WS_CLOSE, "com.y")),
            Some("com.y")
        );
    }
}
