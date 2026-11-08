//! 加密引擎错误类型（2026-11-08，P0 默认形态依赖边界）
//!
//! **为什么自带错误类型**：本 crate 是**中性算法原语**——不含业务语义、不含平台
//! 判断、不碰宿主身份密钥（AGENTS §3.4）。此前它复用 `wasmnest-server-base` 的
//! `AppError`，只为拿一个错误信封，就把整个桌面 server 依赖面（tauri / rusqlite /
//! mdns-sd / sysinfo / notify）钉进了自己的正常依赖树。
//!
//! **与 `AppError` 的关系**：变体按**语义**划分，消费方（`server-core` 的链路加密
//! 边界、宿主 `plugin/crypto.rs`）在边界显式映射回信封错误——映射是显式的、可测的，
//! 不是 `From` 的隐式连带。
//!
//! **文案兼容约束（P0 硬要求）**：每个变体的 `detail` 是旧 `AppError` 文案的**原文**
//! （含具体算法名 / 期望与实际长度），`Display` 只返回 `detail`。映射回
//! `AppError::InvalidInput(detail)` / `AppError::Internal(detail)` 后由变体前缀补回
//! `Invalid input:` / `Internal error:`，对外错误文本与改造前**逐字一致**。
//! 结构化字段（`expected` / `actual` / `alg`）留待 P2 再细化——P0 优先文案兼容。
//!
//! 变体语义：
//!
//! | 变体 | 语义 | 旧 `AppError` 形态 |
//! | --- | --- | --- |
//! | [`CryptoError::InvalidKeyLength`] | 密钥 / 公私钥长度不符 | `InvalidInput` |
//! | [`CryptoError::InvalidNonceLength`] | nonce 长度不符 | `InvalidInput` |
//! | [`CryptoError::UnsupportedAlgorithm`] | 算法名不在白名单 | `InvalidInput` |
//! | [`CryptoError::InvalidInput`] | 其它非法输入（base64 / PEM / 参数 / 签名格式） | `InvalidInput` |
//! | [`CryptoError::OperationFailed`] | 算法执行失败（底层 crypto crate 报错） | `Internal` |

/// 加密引擎错误（语义变体 + 原文 `detail`）
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// 密钥 / 公私钥长度不符（`detail` 含算法名、期望与实际长度）
    #[error("{detail}")]
    InvalidKeyLength { detail: String },
    /// nonce 长度不符（`detail` 含算法名、期望与实际长度）
    #[error("{detail}")]
    InvalidNonceLength { detail: String },
    /// 算法名不在白名单（AEAD / KDF / 密钥交换）
    #[error("{detail}")]
    UnsupportedAlgorithm { detail: String },
    /// 其它非法输入：base64 / PEM / RSA 参数 / 签名格式 / 长度不匹配
    #[error("{detail}")]
    InvalidInput { detail: String },
    /// 算法执行失败（底层 crate 返回错误）
    #[error("{detail}")]
    OperationFailed { detail: String },
}

impl CryptoError {
    /// 构造「密钥长度不符」（`detail` 用旧 `AppError::InvalidInput` 原文）
    pub fn invalid_key_length(detail: impl Into<String>) -> Self {
        Self::InvalidKeyLength { detail: detail.into() }
    }

    /// 构造「nonce 长度不符」
    pub fn invalid_nonce_length(detail: impl Into<String>) -> Self {
        Self::InvalidNonceLength { detail: detail.into() }
    }

    /// 构造「未知算法」
    pub fn unsupported_algorithm(detail: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm { detail: detail.into() }
    }

    /// 构造「其它非法输入」
    pub fn invalid_input(detail: impl Into<String>) -> Self {
        Self::InvalidInput { detail: detail.into() }
    }

    /// 构造「算法执行失败」
    pub fn operation_failed(detail: impl Into<String>) -> Self {
        Self::OperationFailed { detail: detail.into() }
    }

    /// 原文 `detail`（边界映射用：映射方据此还原旧 `AppError` 的 `String` 载荷）
    pub fn detail(&self) -> &str {
        match self {
            Self::InvalidKeyLength { detail }
            | Self::InvalidNonceLength { detail }
            | Self::UnsupportedAlgorithm { detail }
            | Self::InvalidInput { detail }
            | Self::OperationFailed { detail } => detail,
        }
    }

    /// 是否属于「调用方输入问题」（映射到 `AppError::InvalidInput` 的那一类）
    ///
    /// `OperationFailed` 是算法内部失败（映射到 `AppError::Internal`），其余四类
    /// 都是输入非法。边界映射按此分派，避免每个消费方各自 match 五个变体。
    pub fn is_invalid_input(&self) -> bool {
        !matches!(self, Self::OperationFailed { .. })
    }
}

/// 加密引擎结果别名
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Display 必须返回 `detail` 原文——消费方映射回 `AppError` 后靠变体前缀
    /// 补 `Invalid input:` / `Internal error:`，文案与改造前逐字一致
    #[test]
    fn display_returns_detail_verbatim() {
        let cases = [
            CryptoError::invalid_key_length("aes-256-gcm: 密钥长度必须为 32 字节，收到 5"),
            CryptoError::invalid_nonce_length("aes-256-gcm: nonce 长度必须为 12 字节，收到 3"),
            CryptoError::unsupported_algorithm("未知 AEAD 算法: 'nope'（不在白名单）"),
            CryptoError::invalid_input("base64 解码失败: invalid symbol"),
            CryptoError::operation_failed("AES-256-GCM 加密失败: boom"),
        ];
        for err in cases {
            assert_eq!(err.to_string(), err.detail());
            assert!(!err.detail().is_empty());
        }
    }

    /// 变体语义分类锁：四类输入错误落 `InvalidInput`，算法执行失败落 `Internal`
    #[test]
    fn invalid_input_classification_matches_legacy_app_error_mapping() {
        assert!(CryptoError::invalid_key_length("k").is_invalid_input());
        assert!(CryptoError::invalid_nonce_length("n").is_invalid_input());
        assert!(CryptoError::unsupported_algorithm("a").is_invalid_input());
        assert!(CryptoError::invalid_input("i").is_invalid_input());
        assert!(!CryptoError::operation_failed("o").is_invalid_input());
    }
}
