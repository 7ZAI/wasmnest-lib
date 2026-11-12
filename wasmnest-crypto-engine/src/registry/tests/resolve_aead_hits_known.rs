//! 按名调度：合法名命中 — crate 内单元测试（自 packages/wasmnest-crypto-engine/src/registry.rs 迁出）

use super::*;

use crate::provider::{AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305, KDF_HKDF_SHA256, KEY_AGREEMENT_X25519};

#[test]
fn resolve_aead_hits_known_names() {
    assert_eq!(resolve_aead(AEAD_AES_256_GCM).unwrap().name(), AEAD_AES_256_GCM);
    assert_eq!(
        resolve_aead(AEAD_CHACHA20_POLY1305).unwrap().name(),
        AEAD_CHACHA20_POLY1305
    );
}
#[test]
fn resolve_kdf_hits_known_name() {
    assert_eq!(resolve_kdf(KDF_HKDF_SHA256).unwrap().name(), KDF_HKDF_SHA256);
}
#[test]
fn resolve_key_agreement_hits_known_name() {
    assert_eq!(
        resolve_key_agreement(KEY_AGREEMENT_X25519).unwrap().name(),
        KEY_AGREEMENT_X25519
    );
}
