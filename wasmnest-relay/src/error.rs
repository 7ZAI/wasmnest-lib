//! 统一错误类型。
//!
//! 守护进程的错误一律**显性**：每条消息都要能让运维直接行动（缺哪个文件、哪个
//! 配置项非法、该跑什么命令补救），不允许「查不到就返回空」这类静默降级。

use std::{io, path::Path};

use thiserror::Error;

/// 中继的对外错误类型
#[derive(Debug, Error)]
pub enum RelayError {
    /// 命令行参数错误（缺参 / 未知子命令 / 互斥项）
    #[error("参数错误：{0}")]
    Args(String),

    /// 配置文件内容非法（版本不符 / 字段越界 / multiaddr 形状不对）
    #[error("配置错误：{0}")]
    Config(String),

    /// 身份密钥缺失 / 非 ed25519 / 已存在且未显式覆盖
    #[error("身份错误：{0}")]
    Identity(String),

    /// 文件 I/O（带路径，便于直接定位）
    #[error("文件操作失败（{path}）：{source}")]
    File {
        /// 出错的路径
        path: String,
        /// 底层 I/O 错误
        #[source]
        source: io::Error,
    },

    /// TOML 解析失败
    #[error("TOML 解析失败（{path}）：{source}")]
    TomlParse {
        /// 配置文件路径
        path: String,
        /// 解析错误
        #[source]
        source: toml::de::Error,
    },

    /// TOML 序列化失败（配置写盘）
    #[error("TOML 序列化失败：{0}")]
    TomlEncode(#[from] toml::ser::Error),

    /// JSON 解析失败
    #[error("JSON 解析失败（{path}）：{source}")]
    JsonParse {
        /// 文件路径
        path: String,
        /// 解析错误
        #[source]
        source: serde_json::Error,
    },

    /// JSON 序列化失败
    #[error("JSON 序列化失败：{0}")]
    JsonEncode(#[from] serde_json::Error),

    /// swarm / 监听装配失败
    #[error("中继节点启动失败：{0}")]
    Swarm(String),

    /// enrollment token 校验失败（过期 / 用尽 / 不存在）
    #[error("令牌错误：{0}")]
    Token(String),

    /// 未归类的 I/O
    #[error("I/O 失败：{0}")]
    Io(#[from] io::Error),
}

impl RelayError {
    /// 带路径的 I/O 错误（写 / 读失败时点名文件）
    pub fn file(path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::File {
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    /// 配置错误（取任意可显示内容）
    pub fn config(reason: impl Into<String>) -> Self {
        Self::Config(reason.into())
    }

    /// 参数错误
    pub fn args(reason: impl Into<String>) -> Self {
        Self::Args(reason.into())
    }
}

/// 本 crate 的 Result 别名
pub type Result<T> = std::result::Result<T, RelayError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 文件错误消息点名路径与原因() {
        let err = RelayError::file(
            "/data/identity.key",
            io::Error::new(io::ErrorKind::NotFound, "no such file"),
        );
        let text = err.to_string();
        assert!(
            text.contains("/data/identity.key"),
            "消息应点名路径：{text}"
        );
        assert!(text.contains("no such file"), "消息应保留底层原因：{text}");
    }

    #[test]
    fn 配置错误与参数错误的消息前缀可区分() {
        assert!(RelayError::config("quota 越界")
            .to_string()
            .starts_with("配置错误："));
        assert!(RelayError::args("缺 --dir")
            .to_string()
            .starts_with("参数错误："));
    }
}
