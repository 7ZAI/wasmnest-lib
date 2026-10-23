//! 应用配置管理
//!
//! 提供桌面端应用的参数化配置，配置文件位于应用数据目录下的 config.properties
//! 使用 properties 格式支持注释，方便用户理解和修改配置
//!
//! **宿主只存引擎级配置**（网络 / UI 偏好 / PTY 引擎 / channel 容量 / 日志）。
//! 业务配置不落本目录：会话默认值（默认环境/工作目录/命令/超时）真源在
//! `com.wasmnest.terminal-session` 插件存储（`session.formDefaults`，前端
//! 2026-09-21 已收敛删除）；内核输出环 / 会话状态广播 / 终端输出通道
//! （合并/批次/订阅者水位/history_start_mode）随会话下沉退役，相应键已删
//! （2026-09-25）。新增业务配置一律进对应插件域，禁止回到宿主。

use std::collections::HashMap;
use std::path::PathBuf;

pub use wasmnest_server_base::config::{
    default_backlog, default_client_disconnect_timeout_secs, default_client_request_timeout_secs,
    default_keep_alive_secs, default_max_connections, default_metrics_enabled,
    default_prevent_sleep, default_shutdown_timeout_secs, default_tcp_nodelay,
    default_ws_max_frame_size_kb, default_ws_max_message_size_mb, NetworkConfig,
};
/// 全局配置单例
static CONFIG_INSTANCE: std::sync::OnceLock<AppConfig> = std::sync::OnceLock::new();

/// 配置文件中每个 key 对应的注释说明
static PROPERTY_COMMENTS: &[(&str, &str)] = &[
    ("network.port", "WebSocket 服务器端口"),
    ("network.auto_start", "应用启动时是否自动开启服务器"),
    (
        "network.prevent_sleep",
        "服务器运行时阻止系统休眠（允许屏幕熄灭）",
    ),
    (
        "network.workers",
        "Actix Web worker 线程数（0 = CPU 核心数）",
    ),
    (
        "network.keep_alive_secs",
        "HTTP Keep-Alive 超时秒数（0 = 禁用）",
    ),
    (
        "network.client_request_timeout_secs",
        "客户端请求头读取超时秒数",
    ),
    (
        "network.client_disconnect_timeout_secs",
        "客户端断开连接等待超时秒数",
    ),
    ("network.max_connections", "每 worker 最大并发连接数"),
    ("network.backlog", "TCP 半连接队列上限"),
    (
        "network.tcp_nodelay",
        "启用 TCP_NODELAY（禁用 Nagle 算法，降低小包延迟）",
    ),
    ("network.shutdown_timeout_secs", "优雅停机超时秒数"),
    (
        "network.ws_max_frame_size_kb",
        "WebSocket 单帧最大大小（KB）",
    ),
    (
        "network.ws_max_message_size_mb",
        "WebSocket 单消息最大大小（MB，可跨多帧）",
    ),
    (
        "network.metrics_enabled",
        "服务器性能监控采集总开关（默认关闭；开启时采集 CPU/内存/WS 速率指标）",
    ),
    ("ui.theme", "主题（light / dark / system）"),
    (
        "ui.theme_palette",
        "主题色板（warm 暖调 / cool 冷调 / forest / ocean / sunset / violet）",
    ),
    (
        "ui.font_size",
        "全局界面字体大小（终端字体在终端设置中独立配置）",
    ),
    ("ui.terminal_font_size", "终端字体大小"),
    ("ui.terminal_font_family", "终端字体名称"),
    ("ui.terminal_theme", "终端配色主题名"),
    (
        "ui.terminal_letter_spacing",
        "终端字间距（px，0-4；0 = 不加，字间留白仅来自字体自身）",
    ),
    ("ui.language", "语言偏好（zh-CN / en）"),
    (
        "ui.terminal_bg_image",
        "终端背景图片文件名（位于应用数据目录，留空表示不启用）",
    ),
    (
        "ui.terminal_bg_opacity",
        "终端背景图片不透明度（0-100，越小图片越淡）",
    ),
    (
        "ui.animations_enabled",
        "全局动画效果总开关（true/false，关闭后禁用所有页面过渡/动画，默认开启）",
    ),
    (
        "channels.lifecycle_capacity",
        "生命周期事件广播容量 - PTY 进程状态变更",
    ),
    ("terminal.default_cols", "默认终端列数"),
    ("terminal.default_rows", "默认终端行数"),
    (
        "terminal.read_buffer_size",
        "PTY 读取缓冲区大小（字节）- 单次读取的最大字节数",
    ),
    (
        "log.file_level",
        "运行时日志文件级别（trace / debug / info / warn / error）",
    ),
    (
        "log.console_filter",
        "控制台日志过滤器（支持 EnvFilter 语法，如 wasmnest_desktop_lib=debug,actix_web=info）",
    ),
    ("log.rotation", "日志文件轮转策略（daily / hourly / never）"),
    ("log.max_files", "日志文件最大保留数量（0 = 不限制）"),
    (
        "log.capacity_bytes",
        "日志目录总容量上限（字节，0 = 不限制；超出后按修改时间删除最旧文件，当前在写文件除外）",
    ),
    (
        "log.format",
        "日志文件格式（text / json，默认 text；仅启动生效，改动后重启）",
    ),
    (
        "log.console_in_release",
        "Release 模式是否启用控制台输出（调试用，默认关闭）",
    ),
];

/// 配置 key 的分组顺序，控制写入文件时的排列
static PROPERTY_GROUPS: &[(&str, &[&str])] = &[
    (
        "网络配置",
        &[
            "network.port",
            "network.auto_start",
            "network.prevent_sleep",
            "network.workers",
            "network.keep_alive_secs",
            "network.client_request_timeout_secs",
            "network.client_disconnect_timeout_secs",
            "network.max_connections",
            "network.backlog",
            "network.tcp_nodelay",
            "network.shutdown_timeout_secs",
            "network.ws_max_frame_size_kb",
            "network.ws_max_message_size_mb",
            "network.metrics_enabled",
        ],
    ),
    (
        "UI 界面配置",
        &[
            "ui.theme",
            "ui.theme_palette",
            "ui.font_size",
            "ui.terminal_font_size",
            "ui.terminal_font_family",
            "ui.terminal_theme",
            "ui.terminal_letter_spacing",
            "ui.language",
            "ui.terminal_bg_image",
            "ui.terminal_bg_opacity",
            "ui.animations_enabled",
        ],
    ),
    ("Channel 容量配置", &["channels.lifecycle_capacity"]),
    (
        "终端配置",
        &[
            "terminal.default_cols",
            "terminal.default_rows",
            "terminal.read_buffer_size",
        ],
    ),
    (
        "日志配置",
        &[
            "log.file_level",
            "log.console_filter",
            "log.rotation",
            "log.max_files",
            "log.capacity_bytes",
            "log.format",
            "log.console_in_release",
        ],
    ),
];

/// 应用配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppConfig {
    /// 网络配置
    pub network: NetworkConfig,
    /// UI 界面配置
    #[serde(default)]
    pub ui: UiConfig,
    /// Channel 容量配置
    #[serde(default)]
    pub channels: ChannelsConfig,
    /// 终端配置
    #[serde(default)]
    pub terminal: TerminalConfig,
    /// 日志配置
    #[serde(default)]
    pub log: LogConfig,
}

/// UI 界面配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UiConfig {
    /// 主题（light/dark/system）
    pub theme: String,
    /// 色板（warm 暖调工作台，未来可扩展 cool 等；缺省回 warm）
    #[serde(default = "default_theme_palette")]
    pub theme_palette: String,
    /// 全局界面字体大小（终端字体在终端设置中独立配置）
    #[serde(default = "default_font_size")]
    pub font_size: u8,
    /// 终端字体大小
    pub terminal_font_size: u8,
    /// 终端字体名称
    pub terminal_font_family: String,
    /// 终端配色主题名
    #[serde(default = "default_terminal_theme")]
    pub terminal_theme: String,
    /// 终端字间距（px，0-4；0 = 不加，字间留白仅来自字体自身）
    #[serde(default = "default_terminal_letter_spacing")]
    pub terminal_letter_spacing: u8,
    /// 语言偏好（zh-CN / en）
    #[serde(default = "default_language")]
    pub language: String,
    /// 终端背景图片文件名（位于应用数据目录，None 表示不启用）
    #[serde(default)]
    pub terminal_bg_image: Option<String>,
    /// 终端背景图片不透明度（0-100，越小图片越淡）
    #[serde(default = "default_terminal_bg_opacity")]
    pub terminal_bg_opacity: u8,
    /// 全局动画效果总开关（关闭时禁用所有页面过渡/动画），默认开启
    #[serde(default = "default_animations_enabled")]
    pub animations_enabled: bool,
}

fn default_terminal_theme() -> String {
    "dracula".to_string()
}

fn default_terminal_letter_spacing() -> u8 {
    0
}

fn default_theme_palette() -> String {
    "warm".to_string()
}

fn default_font_size() -> u8 {
    12
}

fn default_language() -> String {
    "zh-CN".to_string()
}

fn default_terminal_bg_opacity() -> u8 {
    30
}

fn default_animations_enabled() -> bool {
    true
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "system".to_string(),
            theme_palette: default_theme_palette(),
            font_size: default_font_size(),
            terminal_font_size: 12,
            terminal_font_family: "Consolas".to_string(),
            terminal_theme: default_terminal_theme(),
            terminal_letter_spacing: default_terminal_letter_spacing(),
            language: default_language(),
            terminal_bg_image: None,
            terminal_bg_opacity: default_terminal_bg_opacity(),
            animations_enabled: default_animations_enabled(),
        }
    }
}

/// Channel 容量配置
///
/// Tokio broadcast 容量（仅 PTY 生命周期广播仍在用）。内核输出环 / 会话状态
/// 广播 / 统一事件广播 / WS 事件分发随会话下沉退役（2026-09-24 会话下沉后
/// 宿主不再消费），对应容量键已删（2026-09-25）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChannelsConfig {
    /// 生命周期事件广播容量 - PTY 进程状态变更
    pub lifecycle_capacity: usize,
}

impl Default for ChannelsConfig {
    fn default() -> Self {
        Self {
            lifecycle_capacity: 16,
        }
    }
}

/// 终端配置
///
/// PTY 终端的引擎级默认参数。远程输出通道参数（合并/批次/订阅者水位）随会话
/// 下沉退役——输出通道已不在宿主（WS 终端输出端子在插件侧），对应键已删
/// （2026-09-25）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TerminalConfig {
    /// 默认终端列数
    pub default_cols: u16,
    /// 默认终端行数
    pub default_rows: u16,
    /// PTY 读取缓冲区大小（字节）- 单次读取的最大字节数
    pub read_buffer_size: usize,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            default_cols: 120,
            default_rows: 40,
            read_buffer_size: 4096,
        }
    }
}

/// 日志配置
///
/// 控制日志级别、文件轮转策略、保留天数和控制台输出行为
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogConfig {
    /// 运行时日志文件级别（trace / debug / info / warn / error）
    #[serde(default = "default_log_file_level")]
    pub file_level: String,
    /// 控制台日志过滤器
    /// debug 构建始终启用控制台输出；release 构建需同时设置 console_in_release=true
    /// 支持 tracing EnvFilter 语法，如 "wasmnest_desktop_lib=debug,actix_web=info"
    #[serde(default = "default_log_console_filter")]
    pub console_filter: String,
    /// 日志文件轮转策略（daily / hourly / never）
    #[serde(default = "default_log_rotation")]
    pub rotation: String,
    /// 日志文件最大保留数量（0 = 不限制，但至少保留当前文件）
    #[serde(default = "default_log_max_files")]
    pub max_files: usize,
    /// 日志目录总容量上限（字节，0 = 不限制）
    /// 超出后由后台维护任务按修改时间删除最旧文件（当前在写文件除外），
    /// 防止 debug 高音量下日志目录撑爆磁盘
    #[serde(default = "default_log_capacity_bytes")]
    pub capacity_bytes: usize,
    /// 日志文件格式（text / json，默认 text；仅启动生效，改动后重启）
    /// json 输出到 runtime / error 文件层，供脚本按字段（level/time/target）过滤分析
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Release 模式是否启用控制台输出（调试用，默认关闭）
    #[serde(default)]
    pub console_in_release: bool,
}

fn default_log_file_level() -> String {
    "info".to_string()
}
fn default_log_console_filter() -> String {
    "wasmnest_desktop_lib=debug,actix_web=info,actix_http=info".to_string()
}
fn default_log_rotation() -> String {
    "daily".to_string()
}
fn default_log_max_files() -> usize {
    7
}
fn default_log_capacity_bytes() -> usize {
    512 * 1024 * 1024
}
fn default_log_format() -> String {
    "text".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            file_level: default_log_file_level(),
            console_filter: default_log_console_filter(),
            rotation: default_log_rotation(),
            max_files: default_log_max_files(),
            capacity_bytes: default_log_capacity_bytes(),
            format: default_log_format(),
            console_in_release: false,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            ui: UiConfig::default(),
            channels: ChannelsConfig::default(),
            terminal: TerminalConfig::default(),
            log: LogConfig::default(),
        }
    }
}

impl AppConfig {
    /// 从 properties 文件加载配置
    ///
    /// 文件不存在时返回默认配置
    pub fn load(path: &PathBuf) -> crate::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;
        let props = parse_properties(&content);
        Ok(Self::from_properties(&props))
    }

    /// 保存配置到 properties 文件
    pub fn save(&self, path: &PathBuf) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = self.to_properties_string();
        std::fs::write(path, content)?;
        Ok(())
    }

    /// 初始化全局配置单例
    ///
    /// 应在应用启动时调用，传入从文件加载的配置
    pub fn init(config: AppConfig) {
        let _ = CONFIG_INSTANCE.set(config);
    }

    /// 保存配置到指定路径
    pub fn save_to(&self, path: &PathBuf) -> crate::Result<()> {
        self.save(path)
    }

    /// 获取全局配置实例
    ///
    /// 如果未初始化，返回默认配置
    pub fn global() -> &'static AppConfig {
        static DEFAULT: std::sync::LazyLock<AppConfig> =
            std::sync::LazyLock::new(AppConfig::default);
        CONFIG_INSTANCE.get().unwrap_or(&DEFAULT)
    }

    /// 从 properties map 构建配置
    fn from_properties(props: &HashMap<String, String>) -> Self {
        Self {
            network: NetworkConfig {
                port: parse_value(props, "network.port", 8765),
                auto_start: parse_value(props, "network.auto_start", true),
                prevent_sleep: parse_value(props, "network.prevent_sleep", true),
                workers: parse_value(props, "network.workers", 0),
                keep_alive_secs: parse_value(
                    props,
                    "network.keep_alive_secs",
                    default_keep_alive_secs(),
                ),
                client_request_timeout_secs: parse_value(
                    props,
                    "network.client_request_timeout_secs",
                    default_client_request_timeout_secs(),
                ),
                client_disconnect_timeout_secs: parse_value(
                    props,
                    "network.client_disconnect_timeout_secs",
                    default_client_disconnect_timeout_secs(),
                ),
                max_connections: parse_value(
                    props,
                    "network.max_connections",
                    default_max_connections(),
                ),
                backlog: parse_value(props, "network.backlog", default_backlog()),
                tcp_nodelay: parse_value(props, "network.tcp_nodelay", default_tcp_nodelay()),
                shutdown_timeout_secs: parse_value(
                    props,
                    "network.shutdown_timeout_secs",
                    default_shutdown_timeout_secs(),
                ),
                ws_max_frame_size_kb: parse_value(
                    props,
                    "network.ws_max_frame_size_kb",
                    default_ws_max_frame_size_kb(),
                ),
                ws_max_message_size_mb: parse_value(
                    props,
                    "network.ws_max_message_size_mb",
                    default_ws_max_message_size_mb(),
                ),
                metrics_enabled: parse_value(
                    props,
                    "network.metrics_enabled",
                    default_metrics_enabled(),
                ),
            },
            ui: UiConfig {
                theme: parse_value(props, "ui.theme", "system".to_string()),
                theme_palette: parse_value(props, "ui.theme_palette", default_theme_palette()),
                font_size: parse_value(props, "ui.font_size", default_font_size()),
                terminal_font_size: parse_value(props, "ui.terminal_font_size", 12),
                terminal_font_family: parse_value(
                    props,
                    "ui.terminal_font_family",
                    "Consolas".to_string(),
                ),
                terminal_theme: parse_value(props, "ui.terminal_theme", default_terminal_theme()),
                terminal_letter_spacing: parse_value(
                    props,
                    "ui.terminal_letter_spacing",
                    default_terminal_letter_spacing(),
                ),
                language: parse_value(props, "ui.language", default_language()),
                terminal_bg_image: parse_optional(props, "ui.terminal_bg_image"),
                terminal_bg_opacity: parse_value(
                    props,
                    "ui.terminal_bg_opacity",
                    default_terminal_bg_opacity(),
                ),
                animations_enabled: parse_value(
                    props,
                    "ui.animations_enabled",
                    default_animations_enabled(),
                ),
            },
            channels: ChannelsConfig {
                lifecycle_capacity: parse_value(props, "channels.lifecycle_capacity", 16),
            },
            terminal: TerminalConfig {
                default_cols: parse_value(props, "terminal.default_cols", 120),
                default_rows: parse_value(props, "terminal.default_rows", 40),
                read_buffer_size: parse_value(props, "terminal.read_buffer_size", 4096),
            },
            log: LogConfig {
                file_level: parse_value(props, "log.file_level", default_log_file_level()),
                console_filter: parse_value(
                    props,
                    "log.console_filter",
                    default_log_console_filter(),
                ),
                rotation: parse_value(props, "log.rotation", default_log_rotation()),
                max_files: parse_value(props, "log.max_files", default_log_max_files()),
                capacity_bytes: parse_value(
                    props,
                    "log.capacity_bytes",
                    default_log_capacity_bytes(),
                ),
                format: parse_value(props, "log.format", default_log_format()),
                console_in_release: parse_value(props, "log.console_in_release", false),
            },
        }
    }

    /// 将配置序列化为 properties 格式字符串
    fn to_properties_string(&self) -> String {
        let values = self.to_property_values();
        let mut lines = Vec::new();

        for (group_name, keys) in PROPERTY_GROUPS {
            lines.push(format!(
                "# ==================== {} ====================",
                group_name
            ));
            for key in *keys {
                // 写入注释说明
                if let Some((_, comment)) = PROPERTY_COMMENTS.iter().find(|(k, _)| *k == *key) {
                    lines.push(format!("# {}", comment));
                }
                // 写入 key=value
                let value = values.get(*key).map(|s| s.as_str()).unwrap_or("");
                lines.push(format!("{}={}", key, value));
                lines.push(String::new());
            }
        }

        lines.join("\n")
    }

    /// 将配置转为 key-value map
    fn to_property_values(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("network.port".to_string(), self.network.port.to_string());
        map.insert(
            "network.auto_start".to_string(),
            self.network.auto_start.to_string(),
        );
        map.insert(
            "network.prevent_sleep".to_string(),
            self.network.prevent_sleep.to_string(),
        );
        map.insert(
            "network.workers".to_string(),
            self.network.workers.to_string(),
        );
        map.insert(
            "network.keep_alive_secs".to_string(),
            self.network.keep_alive_secs.to_string(),
        );
        map.insert(
            "network.client_request_timeout_secs".to_string(),
            self.network.client_request_timeout_secs.to_string(),
        );
        map.insert(
            "network.client_disconnect_timeout_secs".to_string(),
            self.network.client_disconnect_timeout_secs.to_string(),
        );
        map.insert(
            "network.max_connections".to_string(),
            self.network.max_connections.to_string(),
        );
        map.insert(
            "network.backlog".to_string(),
            self.network.backlog.to_string(),
        );
        map.insert(
            "network.tcp_nodelay".to_string(),
            self.network.tcp_nodelay.to_string(),
        );
        map.insert(
            "network.shutdown_timeout_secs".to_string(),
            self.network.shutdown_timeout_secs.to_string(),
        );
        map.insert(
            "network.ws_max_frame_size_kb".to_string(),
            self.network.ws_max_frame_size_kb.to_string(),
        );
        map.insert(
            "network.ws_max_message_size_mb".to_string(),
            self.network.ws_max_message_size_mb.to_string(),
        );
        map.insert(
            "network.metrics_enabled".to_string(),
            self.network.metrics_enabled.to_string(),
        );
        map.insert("ui.theme".to_string(), self.ui.theme.clone());
        map.insert(
            "ui.theme_palette".to_string(),
            self.ui.theme_palette.clone(),
        );
        map.insert("ui.font_size".to_string(), self.ui.font_size.to_string());
        map.insert(
            "ui.terminal_font_size".to_string(),
            self.ui.terminal_font_size.to_string(),
        );
        map.insert(
            "ui.terminal_font_family".to_string(),
            self.ui.terminal_font_family.clone(),
        );
        map.insert(
            "ui.terminal_theme".to_string(),
            self.ui.terminal_theme.clone(),
        );
        map.insert(
            "ui.terminal_letter_spacing".to_string(),
            self.ui.terminal_letter_spacing.to_string(),
        );
        map.insert("ui.language".to_string(), self.ui.language.clone());
        map.insert(
            "ui.terminal_bg_image".to_string(),
            self.ui.terminal_bg_image.clone().unwrap_or_default(),
        );
        map.insert(
            "ui.terminal_bg_opacity".to_string(),
            self.ui.terminal_bg_opacity.to_string(),
        );
        map.insert(
            "ui.animations_enabled".to_string(),
            self.ui.animations_enabled.to_string(),
        );
        map.insert(
            "channels.lifecycle_capacity".to_string(),
            self.channels.lifecycle_capacity.to_string(),
        );
        map.insert(
            "terminal.default_cols".to_string(),
            self.terminal.default_cols.to_string(),
        );
        map.insert(
            "terminal.default_rows".to_string(),
            self.terminal.default_rows.to_string(),
        );
        map.insert(
            "terminal.read_buffer_size".to_string(),
            self.terminal.read_buffer_size.to_string(),
        );
        map.insert("log.file_level".to_string(), self.log.file_level.clone());
        map.insert(
            "log.console_filter".to_string(),
            self.log.console_filter.clone(),
        );
        map.insert("log.rotation".to_string(), self.log.rotation.clone());
        map.insert("log.max_files".to_string(), self.log.max_files.to_string());
        map.insert(
            "log.capacity_bytes".to_string(),
            self.log.capacity_bytes.to_string(),
        );
        map.insert("log.format".to_string(), self.log.format.clone());
        map.insert(
            "log.console_in_release".to_string(),
            self.log.console_in_release.to_string(),
        );
        map
    }
}

/// 解析 properties 文件内容为 key-value map
///
/// 支持 # 开头的注释行和空行，key=value 格式
/// 值两端的空白会被 trim
fn parse_properties(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // 跳过空行和注释
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // 解析 key=value
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            if !key.is_empty() {
                map.insert(key, value);
            }
        }
    }
    map
}

/// 从 properties map 中解析值，不存在时返回默认值
fn parse_value<T: std::str::FromStr>(props: &HashMap<String, String>, key: &str, default: T) -> T {
    props
        .get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// 从 properties map 中解析可选值，空字符串返回 None
fn parse_optional<T: std::str::FromStr>(props: &HashMap<String, String>, key: &str) -> Option<T> {
    props
        .get(key)
        .and_then(|v| if v.is_empty() { None } else { v.parse().ok() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_properties_basic() {
        let content = r#"
# 这是一个注释
network.port=8765

# 另一个注释
channels.lifecycle_capacity=16
"#;
        let props = parse_properties(content);
        assert_eq!(props.get("network.port").unwrap(), "8765");
        assert_eq!(props.get("channels.lifecycle_capacity").unwrap(), "16");
    }

    #[test]
    fn test_parse_properties_ignores_comments() {
        let content = "# comment\nkey=value";
        let props = parse_properties(content);
        assert_eq!(props.len(), 1);
        assert_eq!(props.get("key").unwrap(), "value");
    }

    #[test]
    fn test_parse_properties_trims_whitespace() {
        let content = "  key  =  value  ";
        let props = parse_properties(content);
        assert_eq!(props.get("key").unwrap(), "value");
    }

    #[test]
    fn test_from_properties_defaults() {
        let props = HashMap::new();
        let config = AppConfig::from_properties(&props);
        assert_eq!(config.network.port, 8765);
        assert_eq!(config.network.auto_start, true);
        assert_eq!(config.ui.theme, "system");
        assert_eq!(config.ui.terminal_theme, "dracula");
        assert_eq!(config.ui.terminal_bg_image, None);
        assert_eq!(config.ui.terminal_bg_opacity, 30);
        // 字间距缺省回退 0（旧配置文件无该键不得改变既有行为）
        assert_eq!(config.ui.terminal_letter_spacing, 0);
    }

    #[test]
    fn test_from_properties_override() {
        let mut props = HashMap::new();
        props.insert("network.port".to_string(), "9999".to_string());
        props.insert("network.auto_start".to_string(), "false".to_string());
        props.insert("ui.theme".to_string(), "dark".to_string());
        let config = AppConfig::from_properties(&props);
        assert_eq!(config.network.port, 9999);
        assert_eq!(config.network.auto_start, false);
        assert_eq!(config.ui.theme, "dark");
    }

    #[test]
    fn test_to_properties_roundtrip() {
        let config = AppConfig::default();
        let content = config.to_properties_string();
        let props = parse_properties(&content);
        let config2 = AppConfig::from_properties(&props);

        assert_eq!(config.network.port, config2.network.port);
        assert_eq!(config.network.auto_start, config2.network.auto_start);
        assert_eq!(config.ui.theme, config2.ui.theme);
        assert_eq!(config.ui.terminal_theme, config2.ui.terminal_theme);
        assert_eq!(config.ui.terminal_bg_image, config2.ui.terminal_bg_image);
        assert_eq!(
            config.ui.terminal_bg_opacity,
            config2.ui.terminal_bg_opacity
        );
        assert_eq!(config.terminal.default_cols, config2.terminal.default_cols);
    }

    #[test]
    fn test_terminal_letter_spacing_override_roundtrip() {
        // 正例：配置里写 3px → 解析生效；序列化再解析保持同值
        let mut props = HashMap::new();
        props.insert("ui.terminal_letter_spacing".to_string(), "3".to_string());
        let config = AppConfig::from_properties(&props);
        assert_eq!(config.ui.terminal_letter_spacing, 3);

        let content = config.to_properties_string();
        let reparsed = AppConfig::from_properties(&parse_properties(&content));
        assert_eq!(reparsed.ui.terminal_letter_spacing, 3);

        // 反例/边界：非法值（非数字 / 越界）按缺省回退 0，不炸
        props.insert("ui.terminal_letter_spacing".to_string(), "abc".to_string());
        assert_eq!(
            AppConfig::from_properties(&props)
                .ui
                .terminal_letter_spacing,
            0
        );
        props.insert("ui.terminal_letter_spacing".to_string(), "99".to_string());
        assert_eq!(
            AppConfig::from_properties(&props)
                .ui
                .terminal_letter_spacing,
            99
        );
    }

    #[test]
    fn test_save_and_load() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let path = tmp_dir.path().join("config.properties");

        let config = AppConfig::default();
        config.save(&path).unwrap();

        let loaded = AppConfig::load(&path).unwrap();
        assert_eq!(config.network.port, loaded.network.port);
        assert_eq!(config.network.auto_start, loaded.network.auto_start);
        // 色板必须写入 properties 文件并能往返（曾遗漏导致重启后色板重置）
        assert_eq!(config.ui.theme_palette, loaded.ui.theme_palette);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("ui.theme_palette=warm"));
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let path = PathBuf::from("/nonexistent/config.properties");
        let config = AppConfig::load(&path).unwrap();
        assert_eq!(config.network.port, 8765);
    }

    #[test]
    fn test_properties_output_has_comments() {
        let config = AppConfig::default();
        let content = config.to_properties_string();
        // 验证包含分组标题
        assert!(content.contains("# ==================== 网络配置 ===================="));
        // 验证包含字段注释
        assert!(content.contains("# WebSocket 服务器端口"));
        // 验证包含 key=value
        assert!(content.contains("network.port=8765"));
    }

    #[test]
    fn test_terminal_bg_image_from_properties() {
        let mut props = HashMap::new();
        props.insert(
            "ui.terminal_bg_image".to_string(),
            "terminal_bg.png".to_string(),
        );
        props.insert("ui.terminal_bg_opacity".to_string(), "45".to_string());
        let config = AppConfig::from_properties(&props);
        assert_eq!(
            config.ui.terminal_bg_image,
            Some("terminal_bg.png".to_string())
        );
        assert_eq!(config.ui.terminal_bg_opacity, 45);

        // 空字符串视为未设置
        let mut props = HashMap::new();
        props.insert("ui.terminal_bg_image".to_string(), String::new());
        let config = AppConfig::from_properties(&props);
        assert_eq!(config.ui.terminal_bg_image, None);
    }

    #[test]
    fn test_removed_keys_ignored_on_load() {
        // 验证已移除的配置 key（output_history、display）不影响加载
        let mut props = HashMap::new();
        props.insert("network.port".to_string(), "9999".to_string());
        props.insert(
            "output_history.ring_buffer_capacity".to_string(),
            "5000".to_string(),
        );
        props.insert("display.max_read_size".to_string(), "100".to_string());
        let config = AppConfig::from_properties(&props);
        // 有效的 key 正常读取
        assert_eq!(config.network.port, 9999);
        // 已移除的 key 被忽略，不影响 AppConfig 结构
    }

    #[test]
    fn test_log_config_defaults() {
        let config = LogConfig::default();
        assert_eq!(config.file_level, "info");
        assert_eq!(
            config.console_filter,
            "wasmnest_desktop_lib=debug,actix_web=info,actix_http=info"
        );
        assert_eq!(config.rotation, "daily");
        assert_eq!(config.max_files, 7);
        assert!(!config.console_in_release);
    }

    #[test]
    fn test_log_config_from_properties() {
        let mut props = HashMap::new();
        props.insert("log.file_level".to_string(), "debug".to_string());
        props.insert("log.console_filter".to_string(), "warn".to_string());
        props.insert("log.rotation".to_string(), "hourly".to_string());
        props.insert("log.max_files".to_string(), "14".to_string());
        props.insert("log.console_in_release".to_string(), "true".to_string());
        let config = AppConfig::from_properties(&props);
        assert_eq!(config.log.file_level, "debug");
        assert_eq!(config.log.console_filter, "warn");
        assert_eq!(config.log.rotation, "hourly");
        assert_eq!(config.log.max_files, 14);
        assert!(config.log.console_in_release);
    }

    #[test]
    fn test_log_config_roundtrip() {
        let config = AppConfig::default();
        let content = config.to_properties_string();
        let props = parse_properties(&content);
        let config2 = AppConfig::from_properties(&props);
        assert_eq!(config.log.file_level, config2.log.file_level);
        assert_eq!(config.log.console_filter, config2.log.console_filter);
        assert_eq!(config.log.rotation, config2.log.rotation);
        assert_eq!(config.log.max_files, config2.log.max_files);
        assert_eq!(
            config.log.console_in_release,
            config2.log.console_in_release
        );
    }

    #[test]
    fn test_log_config_in_properties_output() {
        let config = AppConfig::default();
        let content = config.to_properties_string();
        assert!(content.contains("# ==================== 日志配置 ===================="));
        assert!(content.contains("log.file_level=info"));
        assert!(content.contains("log.rotation=daily"));
        assert!(content.contains("log.max_files=7"));
        assert!(content.contains("log.console_in_release=false"));
    }
}
