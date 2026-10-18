//! KDF 按名往返 — crate 内单元测试（自 packages/wasmnest-crypto-engine/src/registry.rs 迁出）

use super::*;

use crate::provider::{KDF_HKDF_SHA256};

#[test]
fn kdf_derive_via_registry() {
    let p = resolve_kdf(KDF_HKDF_SHA256).unwrap();
    let key = p.derive(Some(b"salt"), b"ikm", b"ctx", 32).unwrap();
    assert_eq!(key.len(), 32);
    // 幂等：同输入同输出
    let again = p.derive(Some(b"salt"), b"ikm", b"ctx", 32).unwrap();
    assert_eq!(key, again);
}
