//! Crypto 引擎注册表 —— 算法名 → 实现（聚合全局加密方法大全）
//!
//! 宿主加密引擎的唯一入口：按算法名解析出对应能力实现，供内部过滤器与宿主原语
//! （host-crypto，票 03/04）统一调度。白名单是引擎级词汇表（单一真源），未知算法名
//! **显式失败**（fail-visible），绝不留静默回退。
//!
//! 本模块只做「名称 → 实现」映射，不含任何具体算法逻辑（逻辑在 provider）。

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::provider::{
    AeadProvider, AesGcmProvider, ChaCha20Poly1305Provider, HkdfSha256Provider, KdfProvider, KeyAgreementProvider,
    X25519Provider,
};
use wasmnest_server_base::error::{AppError, Result};

// ==================== 域注册表 ====================

/// 加密能力注册表：各能力域独立命名空间（避免跨域算法名冲突），名字即白名单
pub struct CryptoProviders {
    aead: HashMap<&'static str, &'static dyn AeadProvider>,
    kdf: HashMap<&'static str, &'static dyn KdfProvider>,
    key_agreement: HashMap<&'static str, &'static dyn KeyAgreementProvider>,
}

impl CryptoProviders {
    fn new() -> Self {
        let mut aead: HashMap<&'static str, &'static dyn AeadProvider> = HashMap::new();
        aead.insert(AesGcmProvider.name(), &AesGcmProvider);
        aead.insert(ChaCha20Poly1305Provider.name(), &ChaCha20Poly1305Provider);

        let mut kdf: HashMap<&'static str, &'static dyn KdfProvider> = HashMap::new();
        kdf.insert(HkdfSha256Provider.name(), &HkdfSha256Provider);

        let mut key_agreement: HashMap<&'static str, &'static dyn KeyAgreementProvider> = HashMap::new();
        key_agreement.insert(X25519Provider.name(), &X25519Provider);

        Self {
            aead,
            kdf,
            key_agreement,
        }
    }
}

/// 静态单例注册表（进程级，不可变）
pub static PROVIDERS: LazyLock<CryptoProviders> = LazyLock::new(CryptoProviders::new);

// ==================== 按名调度（宿主唯一入口） ====================

/// 按名取 AEAD（认证加密）实现
pub fn resolve_aead(name: &str) -> Result<&'static dyn AeadProvider> {
    PROVIDERS
        .aead
        .get(name)
        .copied()
        .ok_or_else(|| AppError::InvalidInput(format!("未知 AEAD 算法: '{name}'（不在白名单）")))
}

/// 按名取 KDF（密钥派生）实现
pub fn resolve_kdf(name: &str) -> Result<&'static dyn KdfProvider> {
    PROVIDERS
        .kdf
        .get(name)
        .copied()
        .ok_or_else(|| AppError::InvalidInput(format!("未知 KDF 算法: '{name}'（不在白名单）")))
}

/// 按名取密钥交换（ECDH）实现
pub fn resolve_key_agreement(name: &str) -> Result<&'static dyn KeyAgreementProvider> {
    PROVIDERS
        .key_agreement
        .get(name)
        .copied()
        .ok_or_else(|| AppError::InvalidInput(format!("未知密钥交换算法: '{name}'（不在白名单）")))
}

// ==================== 白名单词汇（供审计 / 校验 / 测试断言） ====================

/// 已注册 AEAD 算法名列表
pub fn registered_aead_names() -> Vec<&'static str> {
    PROVIDERS.aead.keys().copied().collect()
}

/// 已注册 KDF 算法名列表
pub fn registered_kdf_names() -> Vec<&'static str> {
    PROVIDERS.kdf.keys().copied().collect()
}

/// 已注册密钥交换算法名列表
pub fn registered_key_agreement_names() -> Vec<&'static str> {
    PROVIDERS.key_agreement.keys().copied().collect()
}

// ==================== Tests ====================

// 用例按功能拆至 `registry/tests/`（本内联模块的子模块路径由 rustc
// 自动解析到该目录；模块树 `registry::tests::<文件>` 与内联形态等价，私有项可见性不受影响）。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305, KDF_HKDF_SHA256, KEY_AGREEMENT_X25519};
    mod resolve_aead_hits_known;
    mod resolve_aead_unknown;
    mod aead;
    mod kdf;
    mod x25519_shared_secret_via;
    mod registered_names_match;
}
