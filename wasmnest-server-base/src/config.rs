//! 网络配置形状（`NetworkConfig`）
//!
//! 从宿主 `system::config` 拆出（server-lib-split）：HTTP/WS 传输面与 supervisor
//! 需要「服务器网络参数」这一形状，但不该反向依赖宿主的 `AppConfig`（含配置
//! 文件解析）。本模块只持有形状 + 缺省值，宿主 `system::config::AppConfig` 的
//! `network` 字段复用同一类型（`pub use` 回导，见 `system/config.rs` 头部）。

/// 网络配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkConfig {
    /// WebSocket 服务器端口
    pub port: u16,
    /// 应用启动时是否自动开启服务器
    pub auto_start: bool,
    /// 服务器运行时阻止系统休眠（允许屏幕熄灭）
    #[serde(default = "default_prevent_sleep")]
    pub prevent_sleep: bool,
    /// Actix Web worker 线程数（0 = CPU 核心数）
    #[serde(default)]
    pub workers: usize,
    /// HTTP Keep-Alive 超时秒数（0 = 禁用）
    #[serde(default = "default_keep_alive_secs")]
    pub keep_alive_secs: u64,
    /// 客户端请求头读取超时秒数
    #[serde(default = "default_client_request_timeout_secs")]
    pub client_request_timeout_secs: u64,
    /// 客户端断开连接等待超时秒数
    #[serde(default = "default_client_disconnect_timeout_secs")]
    pub client_disconnect_timeout_secs: u64,
    /// 每 worker 最大并发连接数
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// TCP 半连接队列上限
    #[serde(default = "default_backlog")]
    pub backlog: u32,
    /// 启用 TCP_NODELAY
    #[serde(default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,
    /// 优雅停机超时秒数
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
    /// WebSocket 单帧最大大小（KB）
    #[serde(default = "default_ws_max_frame_size_kb")]
    pub ws_max_frame_size_kb: usize,
    /// WebSocket 单消息最大大小（MB）
    #[serde(default = "default_ws_max_message_size_mb")]
    pub ws_max_message_size_mb: usize,
    /// 服务器性能监控采集总开关（默认关闭；开启时采集 CPU/内存/WS 速率指标）
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,
}

pub fn default_prevent_sleep() -> bool {
    true
}

pub fn default_keep_alive_secs() -> u64 {
    5
}
pub fn default_client_request_timeout_secs() -> u64 {
    5
}
pub fn default_client_disconnect_timeout_secs() -> u64 {
    5
}
pub fn default_max_connections() -> usize {
    25000
}
pub fn default_backlog() -> u32 {
    2048
}
pub fn default_tcp_nodelay() -> bool {
    true
}
pub fn default_shutdown_timeout_secs() -> u64 {
    30
}
pub fn default_ws_max_frame_size_kb() -> usize {
    64
}
pub fn default_ws_max_message_size_mb() -> usize {
    16
}
pub fn default_metrics_enabled() -> bool {
    false
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: 8765,
            auto_start: true,
            prevent_sleep: true,
            workers: 0,
            keep_alive_secs: default_keep_alive_secs(),
            client_request_timeout_secs: default_client_request_timeout_secs(),
            client_disconnect_timeout_secs: default_client_disconnect_timeout_secs(),
            max_connections: default_max_connections(),
            backlog: default_backlog(),
            tcp_nodelay: default_tcp_nodelay(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            ws_max_frame_size_kb: default_ws_max_frame_size_kb(),
            ws_max_message_size_mb: default_ws_max_message_size_mb(),
            metrics_enabled: default_metrics_enabled(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_serializable_and_roundtrip() {
        let cfg = NetworkConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: NetworkConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.port, 8765);
        assert!(back.prevent_sleep);
        assert!(!back.metrics_enabled);
        assert_eq!(back.ws_max_frame_size_kb, 64);
        assert_eq!(back.ws_max_message_size_mb, 16);
    }

    #[test]
    fn defaults_match_appconfig_from_properties_baseline() {
        // from_properties 用同一批 default_* 函数兜底（宿主 config.rs），
        // 这里锁住缺省值的稳定性，防止两侧静默漂移
        assert_eq!(default_keep_alive_secs(), 5);
        assert_eq!(default_client_request_timeout_secs(), 5);
        assert_eq!(default_client_disconnect_timeout_secs(), 5);
        assert_eq!(default_max_connections(), 25000);
        assert_eq!(default_backlog(), 2048);
        assert!(default_tcp_nodelay());
        assert_eq!(default_shutdown_timeout_secs(), 30);
        assert_eq!(default_ws_max_frame_size_kb(), 64);
        assert_eq!(default_ws_max_message_size_mb(), 16);
        assert!(!default_metrics_enabled());
        assert!(default_prevent_sleep());
    }
}
