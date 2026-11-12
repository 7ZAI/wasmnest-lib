//! X25519 椭圆曲线 Diffie-Hellman 密钥协商
//!
//! 用于端到端加密的密钥协商：双方各自生成 X25519 密钥对，交换公钥后独立计算出
//! 相同的共享密钥，再经 HKDF 派生为对称密钥（见 [`crate::kdf`]）。
//!
//! X25519 提供约 128 bit 安全强度，公钥仅 32 字节，远小于同等安全强度的 RSA 密钥，
//! 非常适合带宽受限的移动端握手。
//!
//! # 典型流程
//!
//! 1. 本端 [`x25519_generate`] 生成密钥对，将公钥发送给对端。
//! 2. 对端同样生成密钥对并回传公钥。
//! 3. 双方调用 [`x25519_diffie_hellman`] 各自计算共享密钥。
//! 4. 用 [`crate::kdf::derive_aes_key`] 派生 AES-256-GCM 会话密钥。

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, SharedSecret as DalekSharedSecret, StaticSecret};

use crate::error::CryptoResult;

/// X25519 公钥/私钥长度（字节，32）
pub const KEY_LEN: usize = 32;

/// X25519 密钥对
#[derive(Clone)]
pub struct X25519KeyPair {
    /// 32 字节私钥，须严格保密
    private: [u8; KEY_LEN],
    /// 32 字节公钥，可公开传输
    public: [u8; KEY_LEN],
}

impl std::fmt::Debug for X25519KeyPair {
    /// 手写 Debug：密钥材料不进日志 / panic 消息
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public", &hex_encode(&self.public))
            .finish_non_exhaustive()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        // 写 String 不会失败
        let _ = write!(out, "{byte:02x}");
    }
    out
}

impl X25519KeyPair {
    /// 从已有私钥恢复密钥对（如从持久化存储加载）
    pub fn from_private(private: &[u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(*private);
        let public = PublicKey::from(&secret);
        Self {
            private: *private,
            public: public.to_bytes(),
        }
    }

    /// 私钥字节切片
    pub fn private(&self) -> &[u8; KEY_LEN] {
        &self.private
    }

    /// 公钥字节切片（可安全公开）
    pub fn public(&self) -> &[u8; KEY_LEN] {
        &self.public
    }
}

/// ECDH 共享密钥（32 字节）
///
/// 注意：不应直接用作对称密钥，须先经 HKDF 派生。
pub struct X25519SharedSecret([u8; KEY_LEN]);

impl X25519SharedSecret {
    /// 原始共享密钥字节，供 HKDF 派生使用
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// 生成随机 X25519 密钥对
pub fn x25519_generate() -> X25519KeyPair {
    // 通过 OsRng 生成保证密码学安全随机性
    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    X25519KeyPair {
        private: secret.to_bytes(),
        public: public.to_bytes(),
    }
}

/// 用本端私钥与对端公钥计算 ECDH 共享密钥
///
/// `peer_public` 必须为对端 X25519 公钥（32 字节）。低阶公钥（全零及其它小阶点）
/// 会让共享密钥无贡献（全零），按 RFC 7748 §6.1 拒绝而不是继续派生——对端公钥
/// 常来自协议头（对端可控），静默接受会把会话密钥降级为可被在路观察者解开的零密钥。
///
/// # Errors
/// 共享密钥为全零（低阶点）时返回 [`CryptoError::invalid_input`](crate::error::CryptoError)。
pub fn x25519_diffie_hellman(local: &X25519KeyPair, peer_public: &[u8; KEY_LEN]) -> CryptoResult<X25519SharedSecret> {
    let secret = StaticSecret::from(*local.private());
    let peer = PublicKey::from(*peer_public);
    let shared: DalekSharedSecret = secret.diffie_hellman(&peer);
    if !shared.was_contributory() {
        return Err(crate::error::CryptoError::invalid_input(
            "x25519: peer public key is a low-order point (shared secret is all-zero)",
        ));
    }
    Ok(X25519SharedSecret(shared.to_bytes()))
}

/// 便于序列化传输的公钥信封（base64）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X25519PublicKeyEnvelope {
    /// base64 编码的 32 字节公钥
    pub public_key_b64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_shared_secret_matches() {
        let alice = x25519_generate();
        let bob = x25519_generate();
        let s_a = x25519_diffie_hellman(&alice, bob.public()).unwrap();
        let s_b = x25519_diffie_hellman(&bob, alice.public()).unwrap();
        assert_eq!(s_a.as_bytes(), s_b.as_bytes());
    }

    #[test]
    fn from_private_recovers_public() {
        let kp = x25519_generate();
        let restored = X25519KeyPair::from_private(kp.private());
        assert_eq!(kp.public(), restored.public());
    }

    #[test]
    fn low_order_peer_public_key_is_rejected() {
        let kp = x25519_generate();
        // 全零是小阶点：共享密钥无贡献，必须 fail-closed
        let err = match x25519_diffie_hellman(&kp, &[0u8; KEY_LEN]) {
            Ok(_) => panic!("低阶公钥必须被拒绝"),
            Err(err) => err,
        };
        assert!(err.is_invalid_input(), "低阶公钥必须按非法输入拒绝: {err}");
        // 另一小阶点（阶 8 的 u=1 编码）同样拒绝
        let mut low_order = [0u8; KEY_LEN];
        low_order[0] = 1;
        assert!(x25519_diffie_hellman(&kp, &low_order).is_err());
    }

    #[test]
    fn keypair_debug_does_not_leak_private_key() {
        let kp = x25519_generate();
        let rendered = format!("{kp:?}");
        let private_hex = hex_encode(kp.private());
        assert!(!rendered.contains(&private_hex), "Debug 不得输出私钥: {rendered}");
        assert!(rendered.contains(&hex_encode(kp.public())), "Debug 应保留可诊断的公钥");
    }
}
