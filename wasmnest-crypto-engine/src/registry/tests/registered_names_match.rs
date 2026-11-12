//! 白名单词汇 — crate 内单元测试（自 packages/wasmnest-crypto-engine/src/registry.rs 迁出）

use super::*;

use crate::provider::{AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305, KDF_HKDF_SHA256, KEY_AGREEMENT_X25519};

#[test]
fn registered_names_match_expected_minimal_set() {
    let mut aead = registered_aead_names();
    aead.sort();
    assert_eq!(aead, vec![AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305]);
    assert_eq!(registered_kdf_names(), vec![KDF_HKDF_SHA256]);
    assert_eq!(registered_key_agreement_names(), vec![KEY_AGREEMENT_X25519]);
}
