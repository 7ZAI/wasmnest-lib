//! 混合加密
//!
//! 用非对称密钥封装一次性对称会话密钥，再用对称 AEAD 加密任意大小载荷，
//! 兼顾非对称的便利性与对称的高吞吐。这是 HTTP 报文加密与文件加密传输的推荐方案。
//!
//! 当前提供基于 **X25519 ECDH + AES-256-GCM** 的 [ECIES-like](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) 方案：
//!
//! 1. 接收方提前生成 X25519 密钥对并公示公钥。
//! 2. 发送方生成临时 X25519 密钥对，与接收方公钥做 ECDH 得到共享密钥。
//! 3. 共享密钥经 HKDF 派生为 AES-256-GCM 会话密钥。
//! 4. 用会话密钥加密载荷，连同临时公钥、nonce 一并发送。
//! 5. 接收方用自己的私钥与收到临时公钥做 ECDH，恢复相同共享密钥 → 派生 → 解密。
//!
//! 载荷字段以 base64 字符串携带，可直接 JSON 序列化经 HTTP / WebSocket 传输。

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::aes_gcm::{self, NONCE_LEN};
use crate::kdf::derive_aes_key;
use crate::x25519::{x25519_diffie_hellman, X25519KeyPair, X25519PublicKeyEnvelope, KEY_LEN as X25519_KEY_LEN};
use wasmnest_server_base::error::{AppError, Result};

/// 加密用途上下文（绑定 HKDF info），防止会话密钥跨场景复用
const INFO_HTTP: &[u8] = b"wasmnest-hybrid-http";
const INFO_FILE: &[u8] = b"wasmnest-hybrid-file";

/// 加密用途，决定 HKDF 派生 info，跨场景密钥隔离
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridPurpose {
    /// HTTP 报文加密
    Http,
    /// 文件加密传输
    File,
}

impl HybridPurpose {
    fn info(self) -> &'static [u8] {
        match self {
            HybridPurpose::Http => INFO_HTTP,
            HybridPurpose::File => INFO_FILE,
        }
    }
}

/// 混合加密密文（内部结构，字段为原始字节）
#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    /// 发送方临时 X25519 公钥（32 字节）
    pub ephemeral_public: [u8; X25519_KEY_LEN],
    /// AES-256-GCM nonce（12 字节）
    pub nonce: [u8; NONCE_LEN],
    /// 密文 + GCM 认证标签
    pub ciphertext: Vec<u8>,
}

/// 可序列化、便于 HTTP/WS 传输的 base64 信封
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEnvelope {
    /// 发送方临时公钥（base64）
    pub ephemeral_public_b64: String,
    /// nonce（base64）
    pub nonce_b64: String,
    /// 密文 + GCM 标签（base64）
    pub ciphertext_b64: String,
    /// 加密用途
    pub purpose: HybridPurpose,
}

impl HybridCiphertext {
    /// 转换为可传输信封
    pub fn to_envelope(&self, purpose: HybridPurpose) -> HybridEnvelope {
        let b64 = base64::engine::general_purpose::STANDARD;
        HybridEnvelope {
            ephemeral_public_b64: b64.encode(self.ephemeral_public),
            nonce_b64: b64.encode(self.nonce),
            ciphertext_b64: b64.encode(&self.ciphertext),
            purpose,
        }
    }

    /// 从信封还原
    pub fn from_envelope(env: &HybridEnvelope) -> Result<Self> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let ephemeral_public = decode_fixed(&env.ephemeral_public_b64)
            .map_err(|e| AppError::InvalidInput(format!("临时公钥 base64 解码失败: {e}")))?;
        let nonce =
            decode_fixed(&env.nonce_b64).map_err(|e| AppError::InvalidInput(format!("nonce base64 解码失败: {e}")))?;
        let ciphertext = b64
            .decode(&env.ciphertext_b64)
            .map_err(|e| AppError::InvalidInput(format!("密文 base64 解码失败: {e}")))?;
        Ok(Self {
            ephemeral_public,
            nonce,
            ciphertext,
        })
    }
}

fn decode_fixed<const N: usize>(b64: &str) -> Result<[u8; N]> {
    let buf = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| AppError::InvalidInput(format!("base64 解码失败: {e}")))?;
    buf.try_into()
        .map_err(|buf: Vec<u8>| AppError::InvalidInput(format!("长度不匹配：期望 {N} 字节，得到 {}", buf.len())))
}

/// 使用接收方 X25519 公钥进行混合加密
///
/// 传入接收方公钥与待加密载荷。返回 [`HybridCiphertext`]，可转为 [`HybridEnvelope`]
/// 经 HTTP / WS 传输。`purpose` 用于跨场景密钥隔离。
pub fn x25519_encrypt(
    recipient_public: &[u8; X25519_KEY_LEN],
    plaintext: &[u8],
    purpose: HybridPurpose,
) -> Result<HybridCiphertext> {
    // 发送方临时密钥对，每次加密新生成，避免 nonce 复用风险传导到长期密钥
    let ephemeral = crate::x25519::x25519_generate();
    let shared = x25519_diffie_hellman(&ephemeral, recipient_public)?;
    let session_key = derive_aes_key(shared.as_bytes(), purpose.info())?;
    let nonce = aes_gcm::generate_nonce();

    let ciphertext = aes_gcm::encrypt(&session_key, &nonce, plaintext, None)?;
    Ok(HybridCiphertext {
        ephemeral_public: *ephemeral.public(),
        nonce,
        ciphertext,
    })
}

/// 使用接收方 X25519 私钥解密
///
/// `recipient_key_pair` 为接收方长期密钥对，`env` 为对端发来的信封。
pub fn x25519_decrypt(recipient_key_pair: &X25519KeyPair, env: &HybridEnvelope) -> Result<Vec<u8>> {
    let ct = HybridCiphertext::from_envelope(env)?;
    let shared = x25519_diffie_hellman(recipient_key_pair, &ct.ephemeral_public)?;
    let session_key = derive_aes_key(shared.as_bytes(), env.purpose.info())?;
    aes_gcm::decrypt(&session_key, &ct.nonce, &ct.ciphertext, None)
}

/// 便捷构造接收端密钥对的信封（公钥 base64）
pub fn recipient_public_envelope(public: &[u8; X25519_KEY_LEN]) -> X25519PublicKeyEnvelope {
    let b64 = base64::engine::general_purpose::STANDARD;
    X25519PublicKeyEnvelope {
        public_key_b64: b64.encode(public),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_roundtrip() {
        let recipient = crate::x25519::x25519_generate();
        let msg = b"hydrbrid encrypted file chunk payload";
        let env = x25519_encrypt(recipient.public(), msg, HybridPurpose::File)
            .unwrap()
            .to_envelope(HybridPurpose::File);
        let pt = x25519_decrypt(&recipient, &env).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_purpose_fails() {
        let recipient = crate::x25519::x25519_generate();
        let env = x25519_encrypt(recipient.public(), b"d", HybridPurpose::Http)
            .unwrap()
            .to_envelope(HybridPurpose::Http);
        // 篡改用途使派生密钥不匹配，解密应失败
        let mut tampered = env.clone();
        tampered.purpose = HybridPurpose::File;
        assert!(x25519_decrypt(&recipient, &tampered).is_err());
    }

    #[test]
    fn large_payload() {
        let recipient = crate::x25519::x25519_generate();
        let msg = vec![7u8; 64 * 1024]; // 64KB，模拟文件分块
        let env = x25519_encrypt(recipient.public(), &msg, HybridPurpose::File)
            .unwrap()
            .to_envelope(HybridPurpose::File);
        let pt = x25519_decrypt(&recipient, &env).unwrap();
        assert_eq!(pt, msg);
    }
}
