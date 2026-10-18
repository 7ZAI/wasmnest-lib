//! HKDF-SHA256 密钥派生
//!
//! 将任意长度的输入密钥材料（IKM），如 ECDH 共享密钥或预共享密钥，派生为
//! 密码学安全、长度确定的对称密钥。供 AES-256-GCM / ChaCha20-Poly1305 使用。
//!
//! 使用 HKDF 而非直接截断 IKM，可避免同源不同用途密钥之间的相关性，
//! 并支持通过 `info` 绑定用途上下文。

use wasmnest_server_base::error::{AppError, Result};
use sha2::Sha256;

/// AES-256-GCM / ChaCha20-Poly1305 派生密钥长度（32 字节）
pub const AES_KEY_LEN: usize = 32;

/// HKDF-SHA256 密钥派生
///
/// - `salt`：可选盐值，可为空；若长期复用同一 IKM，建议使用随机盐。
/// - `ikm`：输入密钥材料（如 ECDH 共享密钥）。
/// - `info`：用途/上下文绑定信息，如 `b"wasmnest-http-session-key"`。
/// - `length`：输出长度（字节），上限 255 * 32。
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| AppError::Internal(format!("HKDF-SHA256 派生失败: {e}")))?;
    Ok(okm)
}

/// 从输入密钥材料派生 AES-256 会话密钥
///
/// `context` 用于绑定用途，如 `"http-session"`、`"file-transfer"`，
/// 避免同一 IKM 派生出的密钥在不同场景间被误用。
pub fn derive_aes_key(ikm: &[u8], context: &[u8]) -> Result<[u8; AES_KEY_LEN]> {
    let mut key = [0u8; AES_KEY_LEN];
    // HKDF 无盐派生：IKM 已足够随机（ECDH 共享密钥）时安全
    let hk = hkdf::Hkdf::<Sha256>::new(None, ikm);
    let info = context;
    hk.expand(info, &mut key)
        .map_err(|e| AppError::Internal(format!("派生 AES 会话密钥失败: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let a = hkdf_sha256(Some(b"salt"), b"ikm", b"ctx", 32).unwrap();
        let b = hkdf_sha256(Some(b"salt"), b"ikm", b"ctx", 32).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_context_yields_different_key() {
        let k1 = derive_aes_key(b"shared", b"http").unwrap();
        let k2 = derive_aes_key(b"shared", b"file").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn aes_key_length_is_32() {
        let k = derive_aes_key(b"ikm", b"ctx").unwrap();
        assert_eq!(k.len(), AES_KEY_LEN);
    }
}
