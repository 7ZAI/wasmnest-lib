//! AES-256-GCM 对称加密
//!
//! 提供 AEAD（Authenticated Encryption with Associated Data）语义的对称加密，
//! 适合 HTTP 报文与文件分块的加密传输。GCM 模式同时保证机密性与完整性，
//! 调用方可通过 `aad` 绑定上下文（如请求头、文件名），防止重放与替换。
//!
//! # 安全约束
//!
//! - 密钥长度固定 32 字节（AES-256）；nonce 长度固定 12 字节。
//! - 同一密钥下，nonce **绝不可重复**，否则破坏 GCM 安全性。建议每次调用使用
//!   [`generate_nonce`] 生成随机 nonce，并将 nonce 与密文一同传输。
//! - 高层封装见 [`crate::hybrid`]，调用方无需手动管理 nonce。

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

use wasmnest_server_base::error::{AppError, Result};

/// AES-256-GCM 密钥长度（字节）
pub const KEY_LEN: usize = 32;
/// AES-256-GCM nonce 长度（字节，GCM 推荐 96 bit）
pub const NONCE_LEN: usize = 12;

/// 生成随机 AES-256 密钥
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

/// 使用 AES-256-GCM 加密
///
/// - `key`：32 字节密钥
/// - `nonce`：12 字节 nonce，调用方需保证同一密钥下唯一
/// - `plaintext`：待加密数据
/// - `aad`：可选的关联数据（不加密但参与认证），如协议头、文件元数据
///
/// 返回值包含密文与 GCM 认证标签（标签附在密文末尾，长度 = 明文长度 + 16 字节）。
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let payload = Payload {
        msg: plaintext,
        aad: aad.unwrap_or(&[]),
    };
    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|e| AppError::Internal(format!("AES-256-GCM 加密失败: {e}")))
}

/// 使用 AES-256-GCM 解密
///
/// 参数与 [`encrypt`] 对应；若密文或 aad 被篡改，返回 `AppError::Internal`，
/// 调用方应将其视为完整性校验失败而非普通错误。
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let payload = Payload {
        msg: ciphertext,
        aad: aad.unwrap_or(&[]),
    };
    cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|e| AppError::Internal(format!("AES-256-GCM 解密失败: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_aad() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"hello wasmnest http payload";
        let aad = b"request-id:42";

        let ct = encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let pt = decrypt(&key, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn tampered_aad_fails() {
        let key = generate_key();
        let nonce = generate_nonce();
        let ct = encrypt(&key, &nonce, b"data", Some(b"aad")).unwrap();
        assert!(decrypt(&key, &nonce, &ct, Some(b"tampered")).is_err());
    }

    #[test]
    fn without_aad() {
        let key = generate_key();
        let nonce = generate_nonce();
        let ct = encrypt(&key, &nonce, b"plain", None).unwrap();
        let pt = decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, b"plain");
    }
}
