//! AEAD 按名全流程往返 — crate 内单元测试（自 packages/wasmnest-crypto-engine/src/registry.rs 迁出）

use super::*;

use crate::provider::{AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305};

#[test]
fn aead_roundtrip_via_registry_both_algorithms() {
    for name in [AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305] {
        let p = resolve_aead(name).unwrap();
        let key = p.generate_key();
        let nonce = p.generate_nonce();
        let plaintext = b"registry roundtrip payload";
        let aad = Some(b"ctx-v1" as &[u8]);
        let ct = p.encrypt(&key, &nonce, plaintext, aad).unwrap();
        let pt = p.decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext, "算法 {name} 加解密往返不一致");
    }
}
#[test]
fn aead_wrong_key_length_rejected() {
    let p = resolve_aead(AEAD_AES_256_GCM).unwrap();
    // 31 字节密钥，非法
    let err = p.encrypt(&[0u8; 31], &[0u8; 12], b"data", None).unwrap_err();
    assert!(matches!(err, AppError::InvalidInput(_)), "变长密钥必须显式拒绝: {err}");
}
#[test]
fn aead_wrong_nonce_length_rejected() {
    let p = resolve_aead(AEAD_AES_256_GCM).unwrap();
    let err = p.encrypt(&[0u8; 32], &[0u8; 4], b"data", None).unwrap_err();
    assert!(matches!(err, AppError::InvalidInput(_)));
}
