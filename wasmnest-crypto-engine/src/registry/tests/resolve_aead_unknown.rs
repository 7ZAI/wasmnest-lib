//! 白名单拒绝：未知名显式失败 — crate 内单元测试（自 packages/wasmnest-crypto-engine/src/registry.rs 迁出）

use super::*;

#[test]
fn resolve_aead_unknown_rejected() {
    match resolve_aead("toy-cipher") {
        Ok(_) => panic!("未知名必须 fail-visible"),
        Err(e) => {
            assert!(
                matches!(e, AppError::InvalidInput(_)),
                "未知名必须 fail-visible，实际: {e}"
            );
            assert!(e.to_string().contains("toy-cipher"), "错误应含算法名: {e}");
        }
    }
}
#[test]
fn resolve_kdf_unknown_rejected() {
    assert!(matches!(resolve_kdf("md5"), Err(AppError::InvalidInput(_))));
}
#[test]
fn resolve_key_agreement_unknown_rejected() {
    assert!(matches!(
        resolve_key_agreement("aes-gcm"),
        Err(AppError::InvalidInput(_))
    ));
}
