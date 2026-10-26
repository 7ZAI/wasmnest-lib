//! Crypto Provider 协议与实现
//!
//! 定义宿主加密引擎各个能力域的**抽象 trait**（只约束「做什么、收什么、返回什么」，
//! 不约束具体算法），并提供基于 [`crate`] 的算法实现作为注册素材。
//!
//! 本模块遵循裁剪线（ADR 0022）：只提供**无业务语义的中性算法原语**，绝不给
//! 「认证编排 / 协商流程 / 密钥策略」等产品规则（AGENTS §8：认证链路只走既有 auth 模块）。
//!
//! 首版落地三个能力域（对齐 spec O5 最小子集起步）：
//! - **AEAD**：`aes-256-gcm`、`chacha20-poly1305`
//! - **KDF**：`hkdf-sha256`
//! - **随机协商**：`x25519`
//!
//! `rsa` / `hybrid` 已作为白名单词保留，但 provider 实现留待按需扩展（spec O5）。

use crate::{aes_gcm, chacha, kdf, x25519};
use wasmnest_server_base::error::{AppError, Result};

// ==================== 算法名（白名单词汇，单一真源） ====================

/// AEAD：AES-256-GCM
pub const AEAD_AES_256_GCM: &str = "aes-256-gcm";
/// AEAD：ChaCha20-Poly1305
pub const AEAD_CHACHA20_POLY1305: &str = "chacha20-poly1305";
/// KDF：HKDF-SHA256
pub const KDF_HKDF_SHA256: &str = "hkdf-sha256";
/// 随机协商: X25519 ECDH
pub const KEY_AGREEMENT_X25519: &str = "x25519";

// ==================== AEAD 域 ====================

/// AEAD 对称加密能力抽象
///
/// 密钥/ nonce 以字节切片传入，由实现方校验长度（AES-256-GCM 与 ChaCha20-Poly1305
/// 均为 32/12，但 trait 不假定），供宿主原语与内部过滤器统一调度。
pub trait AeadProvider: Send + Sync {
    /// 稳定算法名（白名单单点）
    fn name(&self) -> &'static str;
    /// 生成随机密钥（长度由实现定）
    fn generate_key(&self) -> Vec<u8>;
    /// 生成随机 nonce（长度由实现定）
    fn generate_nonce(&self) -> Vec<u8>;
    /// 认证加密；密文与认证标签同返
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    /// 认证明文；完整性失败返回错误
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
}

/// AES-256-GCM 实现（包装 [`crate::aes_gcm`]）
pub struct AesGcmProvider;

impl AeadProvider for AesGcmProvider {
    fn name(&self) -> &'static str {
        AEAD_AES_256_GCM
    }
    fn generate_key(&self) -> Vec<u8> {
        aes_gcm::generate_key().to_vec()
    }
    fn generate_nonce(&self) -> Vec<u8> {
        aes_gcm::generate_nonce().to_vec()
    }
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let key: [u8; aes_gcm::KEY_LEN] = key.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: 密钥长度必须为 {} 字节，收到 {}",
                self.name(),
                aes_gcm::KEY_LEN,
                key.len()
            ))
        })?;
        let nonce: [u8; aes_gcm::NONCE_LEN] = nonce.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: nonce 长度必须为 {} 字节，收到 {}",
                self.name(),
                aes_gcm::NONCE_LEN,
                nonce.len()
            ))
        })?;
        aes_gcm::encrypt(&key, &nonce, plaintext, aad)
    }
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let key: [u8; aes_gcm::KEY_LEN] = key.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: 密钥长度需为 {} 字节，收到 {}",
                self.name(),
                aes_gcm::KEY_LEN,
                key.len()
            ))
        })?;
        let nonce: [u8; aes_gcm::NONCE_LEN] = nonce.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: nonce 长度需为 {} 字节，收到 {}",
                self.name(),
                aes_gcm::NONCE_LEN,
                nonce.len()
            ))
        })?;
        aes_gcm::decrypt(&key, &nonce, ciphertext, aad)
    }
}

/// ChaCha20-Poly1305 实现（包装 [`crate::chacha`]），参数口径同 AES-GCM
pub struct ChaCha20Poly1305Provider;

impl AeadProvider for ChaCha20Poly1305Provider {
    fn name(&self) -> &'static str {
        AEAD_CHACHA20_POLY1305
    }
    fn generate_key(&self) -> Vec<u8> {
        chacha::generate_key().to_vec()
    }
    fn generate_nonce(&self) -> Vec<u8> {
        chacha::generate_nonce().to_vec()
    }
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let key: [u8; chacha::KEY_LEN] = key.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: 密钥长度需为 {} 字节，收到 {}",
                self.name(),
                chacha::KEY_LEN,
                key.len()
            ))
        })?;
        let nonce: [u8; chacha::NONCE_LEN] = nonce.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: nonce 长度需为 {} 字节，收到 {}",
                self.name(),
                chacha::NONCE_LEN,
                nonce.len()
            ))
        })?;
        chacha::encrypt(&key, &nonce, plaintext, aad)
    }
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let key: [u8; chacha::KEY_LEN] = key.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: 密钥长度需为 {} 字节，收到 {}",
                self.name(),
                chacha::KEY_LEN,
                key.len()
            ))
        })?;
        let nonce: [u8; chacha::NONCE_LEN] = nonce.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: nonce 长度需为 {} 字节，收到 {}",
                self.name(),
                chacha::NONCE_LEN,
                nonce.len()
            ))
        })?;
        chacha::decrypt(&key, &nonce, ciphertext, aad)
    }
}

// ==================== KDF 域 ====================

/// KDF 密钥派生能力
pub trait KdfProvider: Send + Sync {
    /// 稳定算法名（白名单条目）
    fn name(&self) -> &'static str;
    /// 输入密钥材料派生指定长度密钥
    fn derive(&self, salt: Option<&[u8]>, ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>>;
}

/// HKDF-SHA256 实现（包装 [`crate::kdf`]）
pub struct HkdfSha256Provider;

impl KdfProvider for HkdfSha256Provider {
    fn name(&self) -> &'static str {
        KDF_HKDF_SHA256
    }
    fn derive(&self, salt: Option<&[u8]>, ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        kdf::hkdf_sha256(salt, ikm, info, length)
    }
}

// ==================== 随机协商（密钥交换）域 ====================

/// ECDH 密钥交换能力：生成临时密钥对 + 计算共享密钥
pub trait KeyAgreementProvider: Send + Sync {
    /// 稳定算法名（白名单条目）
    fn name(&self) -> &'static str;
    /// 生成临时密钥对，返回 (私钥, 公钥) 字节
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
    /// 用本端私钥 + 对端公钥计算共享密钥
    fn compute_shared(&self, local_private: &[u8], peer_public: &[u8]) -> Result<Vec<u8>>;
}

/// X25519 实现（包装 [`crate::x25519`]）
pub struct X25519Provider;

impl KeyAgreementProvider for X25519Provider {
    fn name(&self) -> &'static str {
        KEY_AGREEMENT_X25519
    }
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let kp = x25519::x25519_generate();
        (kp.private().to_vec(), kp.public().to_vec())
    }
    fn compute_shared(&self, local_private: &[u8], peer_public: &[u8]) -> Result<Vec<u8>> {
        let privat_: [u8; x25519::KEY_LEN] = local_private.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: 私钥长度需为 {} 字节，收到 {}",
                self.name(),
                x25519::KEY_LEN,
                local_private.len()
            ))
        })?;
        let pub_: [u8; x25519::KEY_LEN] = peer_public.try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "{}: 公钥长度需为 {} 字节，收到 {}",
                self.name(),
                x25519::KEY_LEN,
                peer_public.len()
            ))
        })?;
        let kp = x25519::X25519KeyPair::from_private(&privat_);
        let shared = x25519::x25519_diffie_hellman(&kp, &pub_)?;
        Ok(shared.as_bytes().to_vec())
    }
}
