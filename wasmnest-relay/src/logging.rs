//! 日志初始化。
//!
//! 只用环境变量控制级别（`WASMNEST_RELAY_LOG`，与 Rust 生态惯例一致），默认 `info`
//! 用于 `run`、`warn` 用于一次性命令，避免 CLI 输出被日志淹没。
//!
//! 日志纪律：PeerId 只打短指纹；token / 票据 / payload / 路径一律不打。

use tracing_subscriber::EnvFilter;

/// 初始化全局日志（重复调用安全：第二次静默忽略）
pub fn init(default_level: &str) {
    let filter = std::env::var("WASMNEST_RELAY_LOG")
        .ok()
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn 重复初始化不panic() {
        super::init("warn");
        super::init("warn");
    }
}
