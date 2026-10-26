//! 密钥交换按名往返 — crate 内单元测试（自 packages/wasmnest-crypto-engine/src/registry.rs 迁出）

use super::*;

use crate::provider::KEY_AGREEMENT_X25519;

#[test]
fn x25519_shared_secret_via_registry() {
    let p = resolve_key_agreement(KEY_AGREEMENT_X25519).unwrap();
    let (alice_priv, alice_pub) = p.generate_keypair();
    let (bob_priv, bob_pub) = p.generate_keypair();
    let a = p.compute_shared(&alice_priv, &bob_pub).unwrap();
    let b = p.compute_shared(&bob_priv, &alice_pub).unwrap();
    assert_eq!(a, b, "X25519 双方共享密钥必须一致");
    assert_eq!(a.len(), 32);
}
#[test]
fn x25519_wrong_key_length_rejected() {
    let p = resolve_key_agreement(KEY_AGREEMENT_X25519).unwrap();
    let err = p.compute_shared(&[0u8; 31], &[0u8; 32]).unwrap_err();
    assert!(matches!(err, AppError::InvalidInput(_)));
}
