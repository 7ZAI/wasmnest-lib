//! ChaCha20-Poly1305 对称加密
//!
//! 作为 AES-256-GCM 的备选 AEAD 方案。在不支持 AES-NI 硬件加速的平台（部分移动端、
//! 低端嵌入式）上，ChaCha20-Poly1305 性能更稳定且常量时间，避免时序侧信道。
//!
//! 接口与 [`crate::aes_gcm`] 完全一致，调用方可按平台能力择一使用。

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

use wasmnest_server_base::error::{AppError, Result};

/// ChaCha20-Poly1305 密钥长度（字节，256 bit）
pub const KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce 长度（字节，96 bit，IETF 变体）
pub const NONCE_LEN: usize = 12;

/// 生成随机 ChaCha20-Poly1305 密钥
pub fn generate_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// 生成随机 nonce（96 bit）
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// 使用 ChaCha20-Poly1305 加密
///
/// 语义与 [`crate::aes_gcm::encrypt`] 一致，返回密文 + Poly1305 认证标签。
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload {
        msg: plaintext,
        aad: aad.unwrap_or(&[]),
    };
    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|e| AppError::Internal(format!("ChaCha20-Poly1305 加密失败: {e}")))
}

/// 使用 ChaCha20-Poly1305 解密
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload {
        msg: ciphertext,
        aad: aad.unwrap_or(&[]),
    };
    cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|e| AppError::Internal(format!("ChaCha20-Poly1305 解密失败: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = generate_key();
        let nonce = generate_nonce();
        let ct = encrypt(&key, &nonce, b"chacha payload", Some(b"hdr")).unwrap();
        let pt = decrypt(&key, &nonce, &ct, Some(b"hdr")).unwrap();
        assert_eq!(pt, b"chacha payload");
    }
}
