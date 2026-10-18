//! RSA 常规非对称加密
//!
//! 提供 RSA-OAEP 加解密与 RSA-PSS 签名/验签，作为 X25519 之外的常规非对称方案。
//! 适用于需要兼容既有 PKI / X.509 体系、或对端不支持 X25519 的场景。建议密钥位数
//! 不低于 2048，推荐 3072。
//!
//! # 注意
//!
//! - RSA 加密体积受限于密钥长度（如 2048 位密钥 OAEP-SHA256 最多约 190 字节明文），
//!   因此直接用 RSA 加密大文件不现实；请改用 [`crate::hybrid`] 混合方案。
//! - OAEP 填充默认使用 SHA-256 作为 MGF 哈希，已满足现代安全要求。

use base64::Engine;
use rand::rngs::OsRng;
use rsa::signature::SignatureEncoding;
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{Signature, SigningKey, VerifyingKey},
    signature::{RandomizedSigner, Verifier},
    Oaep, RsaPrivateKey, RsaPublicKey as RawRsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use wasmnest_server_base::error::{AppError, Result};

/// 默认 RSA 密钥位数（推荐值）
pub const DEFAULT_KEY_BITS: usize = 3072;
/// 最小允许的 RSA 密钥位数（低于此值拒绝生成）
pub const MIN_KEY_BITS: usize = 2048;

/// RSA 密钥对（持有私钥）
pub struct RsaKeyPair {
    private: RsaPrivateKey,
}

/// 可序列化、可传输的 RSA 公钥信封
///
/// 持有 SPKI / PKCS#1 PEM 文本，便于经 HTTP / WebSocket 公开分发。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaPublicKey {
    /// SPKI（`-----BEGIN PUBLIC KEY-----`）或 PKCS#1 PEM 公钥
    pem: String,
}

/// RSA 密钥对生成
///
/// `bits` 为模数位数，低于 [`MIN_KEY_BITS`] 时返回错误。生成耗时与位数正相关，
/// 2048 位通常 < 500ms，3072 位约 1-3s（视 CPU）。
pub fn rsa_generate(bits: usize) -> Result<RsaKeyPair> {
    if bits < MIN_KEY_BITS {
        return Err(AppError::InvalidInput(format!(
            "RSA 密钥位数 {bits} 低于最小允许值 {MIN_KEY_BITS}"
        )));
    }
    let mut rng = OsRng;
    let private = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| AppError::Internal(format!("生成 RSA 密钥对失败（{bits} 位）: {e}")))?;
    Ok(RsaKeyPair { private })
}

impl RsaKeyPair {
    /// 导出 SPKI PEM 格式公钥（可公开分发，X.509 兼容）
    pub fn public_key_pem(&self) -> Result<String> {
        let public = RawRsaPublicKey::from(&self.private);
        public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| AppError::Internal(format!("导出 RSA 公钥 PEM 失败: {e}")))
    }

    /// 导出 PKCS#8 PEM 格式私钥（须严格保密存储）
    pub fn private_key_pem(&self) -> Result<String> {
        self.private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| AppError::Internal(format!("导出 RSA 私钥 PEM 失败: {e}")))
    }

    /// 从 PKCS#8 或 PKCS#1 PEM 恢复私钥
    pub fn from_pem(pem: &str) -> Result<Self> {
        // 优先尝试 PKCS#8，失败则回退 PKCS#1
        let private = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| AppError::InvalidInput(format!("解析 RSA 私钥 PEM 失败: {e}")))?;
        Ok(Self { private })
    }

    /// 内部私钥引用（供签名/解密使用）
    fn private(&self) -> &RsaPrivateKey {
        &self.private
    }
}

impl RsaPublicKey {
    /// 从 SPKI / PKCS#1 PEM 构造
    pub fn from_pem(pem: &str) -> Result<Self> {
        // 校验 PEM 可解析
        let _ = RawRsaPublicKey::from_public_key_pem(pem)
            .map_err(|e| AppError::InvalidInput(format!("解析 RSA 公钥 PEM 失败: {e}")))?;
        Ok(Self { pem: pem.to_string() })
    }

    /// PEM 字符串
    pub fn pem(&self) -> &str {
        &self.pem
    }

    fn inner(&self) -> Result<RawRsaPublicKey> {
        RawRsaPublicKey::from_public_key_pem(&self.pem)
            .map_err(|e| AppError::Internal(format!("解析 RSA 公钥失败: {e}")))
    }
}

/// 使用 RSA 公钥 + OAEP-SHA256 加密
///
/// 明文长度受密钥位数限制，超限返回错误。大体积载荷请用混合加密。
pub fn rsa_encrypt_public(public: &RsaPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let pub_key = public.inner()?;
    let mut rng = OsRng;
    pub_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), plaintext)
        .map_err(|e| AppError::Internal(format!("RSA-OAEP 加密失败: {e}")))
}

/// 使用 RSA 私钥 + OAEP-SHA256 解密
pub fn rsa_decrypt(key_pair: &RsaKeyPair, ciphertext: &[u8]) -> Result<Vec<u8>> {
    key_pair
        .private()
        .decrypt(Oaep::new::<Sha256>(), ciphertext)
        .map_err(|e| AppError::Internal(format!("RSA-OAEP 解密失败: {e}")))
}

/// 使用 RSA 私钥 + PSS-SHA256 签名
pub fn rsa_sign(key_pair: &RsaKeyPair, data: &[u8]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::<Sha256>::new(key_pair.private().clone());
    let mut rng = OsRng;
    let signature: Signature = signing_key.sign_with_rng(&mut rng, data);
    Ok(signature.to_vec())
}

/// 使用对应公钥验签（PSS-SHA256）
pub fn rsa_verify_public(public: &RsaPublicKey, data: &[u8], signature: &[u8]) -> Result<()> {
    let pub_key = public.inner()?;
    let verifying = VerifyingKey::<Sha256>::new(pub_key);
    let sig = Signature::try_from(signature).map_err(|e| AppError::InvalidInput(format!("RSA 签名格式无效: {e}")))?;
    verifying
        .verify(data, &sig)
        .map_err(|e| AppError::Internal(format!("RSA-PSS 验签失败: {e}")))
}

/// 便于传输的 base64 信封（公钥）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaPublicKeyEnvelope {
    /// RSA 公钥 PEM 文本
    pub pem: String,
}

/// 签名信封（base64）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaSignatureEnvelope {
    /// base64 编码的 RSA-PSS 签名
    pub signature_b64: String,
}

impl RsaSignatureEnvelope {
    /// 从原始签名字节构造
    pub fn from_bytes(signature: &[u8]) -> Self {
        Self {
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature),
        }
    }

    /// 还原为原始签名字节
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.signature_b64)
            .map_err(|e| AppError::InvalidInput(format!("base64 解码签名失败: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = rsa_generate(2048).unwrap();
        let pub_pem = kp.public_key_pem().unwrap();
        let public = RsaPublicKey::from_pem(&pub_pem).unwrap();

        let msg = b"top secret";
        let ct = rsa_encrypt_public(&public, msg).unwrap();
        let pt = rsa_decrypt(&kp, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = rsa_generate(2048).unwrap();
        let pub_pem = kp.public_key_pem().unwrap();
        let public = RsaPublicKey::from_pem(&pub_pem).unwrap();

        let data = b"important payload";
        let sig = rsa_sign(&kp, data).unwrap();
        rsa_verify_public(&public, data, &sig).unwrap();
        // 篡改数据后验签应失败
        assert!(rsa_verify_public(&public, b"tampered", &sig).is_err());
    }

    #[test]
    fn b64_envelope_roundtrip() {
        let sig = vec![1u8, 2, 3, 250, 251];
        let env = RsaSignatureEnvelope::from_bytes(&sig);
        assert_eq!(env.to_bytes().unwrap(), sig);
    }
}
