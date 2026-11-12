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
//!
//! **依赖面（2026-11-08，P0 默认形态依赖边界）**：本 crate **零内部 crate 依赖**
//! ——错误类型自带 [`CryptoError`] / [`CryptoResult`]（此前为拿一个错误信封复用
//! `server-base` 的 `AppError`，把 tauri / rusqlite / mdns-sd / sysinfo / notify
//! 整条桌面依赖链钉进了中性算法原语）。消费方在边界按变体语义显式映射回自己的
//! 错误类型，映射是显式且可测的（见 `error` 模块的文案兼容约束）。

pub mod aes_gcm;
pub mod chacha;
/// 加密引擎错误类型（`CryptoError` / `CryptoResult`）
pub mod error;
pub mod hybrid;
pub mod kdf;
pub mod provider;
pub mod registry;
pub mod rsa;
pub mod x25519;

pub use error::{CryptoError, CryptoResult};
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
