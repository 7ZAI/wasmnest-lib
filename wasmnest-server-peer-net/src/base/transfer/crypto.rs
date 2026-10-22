//! 传输数据面应用层加密：临时 X25519 ECDH + HKDF-SHA256 → AES-256-GCM 分块加密。
//!
//! 协商语义（「自定义请求头」）：发送端在 [`crate::base::transfer::message::TransferFrame::Offer`]
//! 携带 `encrypted=true` + 临时 X25519 公钥（即加密请求头）；接收端放行时在
//! `Decision` 回带自己的临时公钥——两个头都齐了才算协商成立，任一侧缺头
//! 即视为对端不支持，由发送端 fail-fast（静默明文降级比失败更危险）。
//!
//! 密钥派生：双方各自 `ECDH(本端临时私钥, 对端临时公钥)` 得共享秘密，
//! 经 HKDF-SHA256（salt = batch_id、固定 info）展开为 AES-256-GCM 密钥
//! （32B）+ nonce 随机前缀（4B）。每会话全新临时密钥对，跨会话密钥不复用。
//!
//! 分块加密约定（断点续传友好，nonce 确定性可重放）：
//! - 第 n 个数据块（会话内全局计数，含跨文件）nonce = prefix[0..4] || u64BE(n)；
//!   发送/接收按帧严格锁步计数，两侧天然一致；重试换新会话即新密钥，计数归零无碰撞；
//! - AAD 绑定 (file_index, offset)，防跨位置拼接/重排。

use std::io;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// GCM nonce 长度（字节；NIST 推荐 96 bit）
pub const NONCE_LEN: usize = 12;
/// AES-256-GCM 认证标签长度（字节）
pub const TAG_LEN: usize = 16;
/// X25519 公钥长度（字节）
const X25519_KEY_LEN: usize = 32;
/// HKDF info：用途上下文绑定（与两端宿主既有 crypto 工具的惯例一致）
const HKDF_INFO: &[u8] = b"wasmnest-peer-transfer-encryption/v1";
/// HKDF 输出总长：AES 密钥 32B + nonce 随机前缀 4B
const OKM_LEN: usize = 32 + 4;

/// 发送端会话临时 X25519 密钥对（每会话全新生成，不落盘）
pub struct EphemeralKeys {
    secret: StaticSecret,
    public_hex: String,
}

impl EphemeralKeys {
    /// 生成新会话临时密钥对
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_hex = hex::encode(PublicKey::from(&secret).as_bytes());
        Self { secret, public_hex }
    }

    /// 本端临时公钥（64 字符小写 hex，进 Offer / Decision 头）
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// 与对端临时公钥完成 ECDH 并派生会话密码上下文
    ///
    /// `batch_id` 作 HKDF salt 把密钥绑定到具体批；对端公钥非法（非 hex /
    /// 长度不符 / all-zero 反序列化拒绝）返回 InvalidData。
    pub fn derive_cipher(&self, peer_public_hex: &str, batch_id: &str) -> io::Result<SessionCipher> {
        let mut peer_public = [0u8; X25519_KEY_LEN];
        hex::decode_to_slice(peer_public_hex.trim(), &mut peer_public).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("peer encryption public key is not valid hex[32]: {e}"),
            )
        })?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer_public));
        if !shared.was_contributory() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "x25519 shared secret is not contributory",
            ));
        }
        let hk = Hkdf::<Sha256>::new(Some(batch_id.as_bytes()), shared.as_bytes());
        let mut okm = [0u8; OKM_LEN];
        // expand 失败仅因输出超长上限，OKM_LEN 为常量必然合法
        hk.expand(HKDF_INFO, &mut okm)
            .expect("hkdf expand within constant length");
        Ok(SessionCipher {
            key: *Key::<Aes256Gcm>::from_slice(&okm[..32]),
            nonce_prefix: okm[32..].try_into().expect("prefix slice is 4 bytes"),
        })
    }
}

/// 会话对称密码上下文：AES-256-GCM 加解密单个数据块
#[derive(Clone)]
pub struct SessionCipher {
    key: Key<Aes256Gcm>,
    nonce_prefix: [u8; 4],
}

impl SessionCipher {
    /// nonce = prefix[0..4] || u64BE(counter)；counter 为会话内已推流数据块序号
    fn build_nonce(&self, counter: u64) -> Nonce<U12> {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        *Nonce::<U12>::from_slice(&nonce)
    }

    /// AAD = u32BE(file_index) || u64BE(offset)：把密文钉死在其批内位置上
    fn position_aad(file_index: u32, offset: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(12);
        aad.extend_from_slice(&file_index.to_be_bytes());
        aad.extend_from_slice(&offset.to_be_bytes());
        aad
    }

    /// 加密一个数据块，输出 ciphertext || tag（等长于明文 + TAG_LEN）
    pub fn encrypt_chunk(
        &self,
        file_index: u32,
        offset: u64,
        counter: u64,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes256Gcm::new(&self.key);
        cipher
            .encrypt(
                &self.build_nonce(counter),
                Payload {
                    msg: plaintext,
                    aad: Self::position_aad(file_index, offset).as_slice(),
                },
            )
            .expect("aes-gcm encrypt with valid nonce cannot fail")
    }

    /// 解密一个数据块（payload = ciphertext || tag）；认证失败即密文被篡改或
    /// 两侧计数错位，返回 InvalidData 由引擎按会话失败结算
    pub fn decrypt_chunk(
        &self,
        file_index: u32,
        offset: u64,
        counter: u64,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key);
        cipher
            .decrypt(
                &self.build_nonce(counter),
                Payload {
                    msg: payload,
                    aad: Self::position_aad(file_index, offset).as_slice(),
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "encrypted chunk failed gcm authentication (corrupted or out of sync)",
                )
            })
    }
}

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    const BATCH: &str = "b-test";

    /// 双端各自生成临时密钥并互派生，得到同一把会话密钥
    #[test]
    fn both_sides_derive_same_cipher() {
        let sender = EphemeralKeys::generate();
        let receiver = EphemeralKeys::generate();

        let s_cipher = sender.derive_cipher(receiver.public_hex(), BATCH).unwrap();
        let r_cipher = receiver.derive_cipher(sender.public_hex(), BATCH).unwrap();

        let ct = s_cipher.encrypt_chunk(0, 0, 0, b"hello wasmnest");
        assert_eq!(ct.len(), b"hello wasmnest".len() + TAG_LEN);
        let pt = r_cipher.decrypt_chunk(0, 0, 0, &ct).unwrap();
        assert_eq!(pt, b"hello wasmnest");
    }

    /// 位置参数参与认证：挪用他处密文必被 GCM 拒绝
    #[test]
    fn chunk_cannot_be_spliced_across_positions_or_sessions() {
        let sender = EphemeralKeys::generate();
        let receiver = EphemeralKeys::generate();
        let enc = sender.derive_cipher(receiver.public_hex(), BATCH).unwrap();
        let dec = receiver.derive_cipher(sender.public_hex(), BATCH).unwrap();

        let ct = enc.encrypt_chunk(1, 1024, 5, b"data");

        // 文件下标 / 偏移 / 块计数 任一错位都解不出
        assert!(dec.decrypt_chunk(0, 1024, 5, &ct).is_err());
        assert!(dec.decrypt_chunk(1, 2048, 5, &ct).is_err());
        assert!(dec.decrypt_chunk(1, 1024, 6, &ct).is_err());
        assert_eq!(dec.decrypt_chunk(1, 1024, 5, &ct).unwrap(), b"data");
    }

    /// 不同 batch_id（salt 不同）派生出不同密钥：重试新批不共享密钥材料
    #[test]
    fn batch_id_salts_derivation() {
        let sender = EphemeralKeys::generate();
        let receiver = EphemeralKeys::generate();
        let c1 = sender.derive_cipher(receiver.public_hex(), "b-1").unwrap();
        let c2 = sender.derive_cipher(receiver.public_hex(), "b-2").unwrap();
        let ct = c1.encrypt_chunk(0, 0, 0, b"x");
        assert!(c2.decrypt_chunk(0, 0, 0, &ct).is_err());
    }

    /// 非法对端公钥显式报错而非 panic
    #[test]
    fn invalid_peer_public_key_is_rejected() {
        let keys = EphemeralKeys::generate();
        assert!(keys.derive_cipher("zz-not-hex", BATCH).is_err());
        assert!(keys.derive_cipher("aabb", BATCH).is_err()); // 长度不足
    }
}
