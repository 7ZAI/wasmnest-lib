//! wasmnest-crypto-engine：宿主加密引擎（server-lib-split 票 02，D5）
//!
//! 聚合全局加密方法大全：算法实现（`aes_gcm` / `chacha` / `hybrid` / `kdf` /
//! `rsa` / `x25519`）+ **名称寻址的统一入口**（`provider` 抽象 trait + `registry`
//! 注册表），供内部过滤器与宿主原语（host-crypto）按算法名调度，插件无需感知
//! 具体实现。
//!
//! 裁剪线约束（ADR 0022 / AGENTS §8）：本引擎只暴露**无业务语义的中性算法原语**，
//! 绝不提供「认证编排 / 协商流程 / 密钥策略」等产品规则；密钥材料一律由调用方提供，
//! 引擎不触碰宿主身份密钥。
//!
//! 宿主经 `crate::crypto` / `crate::utils::crypto` 两个薄壳回导本 crate 的
//! 同名模块，其余代码引用路径不变。

pub mod aes_gcm;
pub mod chacha;
pub mod hybrid;
pub mod kdf;
pub mod provider;
pub mod registry;
pub mod rsa;
pub mod x25519;

pub use registry::{resolve_aead, resolve_kdf, resolve_key_agreement, PROVIDERS};

// 平铺便捷名（与旧 `utils::crypto` 根导出对齐）
pub use aes_gcm::{
    decrypt as aes_decrypt, encrypt as aes_encrypt, generate_key as aes_generate_key,
    generate_nonce as aes_generate_nonce,
};
pub use chacha::{
    decrypt as chacha_decrypt, encrypt as chacha_encrypt, generate_key as chacha_generate_key,
    generate_nonce as chacha_generate_nonce,
};
pub use hybrid::{x25519_decrypt, x25519_encrypt, HybridCiphertext, HybridEnvelope};
pub use kdf::{derive_aes_key, hkdf_sha256};
pub use rsa::{rsa_decrypt, rsa_encrypt_public, rsa_generate, rsa_sign, rsa_verify_public, RsaKeyPair, RsaPublicKey};
pub use x25519::{x25519_diffie_hellman, x25519_generate, X25519KeyPair, X25519SharedSecret};
