//! 自签 TLS 证书：由节点身份产出 DER 证书，及证书 ↔ node_id 绑定校验。
//!
//! ## 为什么证书密钥必须来自节点身份种子（决策 D4 关键点）
//!
//! 「证书公钥 == 节点公钥」是对端信任的第一性依据（ADR 0028：校验对方证书指纹
//! 即校验其身份）；若让 rcgen 随机新生成密钥，证书就与节点 ID 无关，绑定校验
//! 形同虚设。因此用 Ed25519 的固定 PKCS#8 结构把身份种子喂给 rcgen，并以单测
//! 锁死该一致性。
//!
//! rustls 栈（ticket 02）将复用同一密钥材料，本模块先只负责生成与验证，
//! 不引入 TLS 依赖（决策 D4：控制本票编译面）。

use rcgen::{CertificateParams, DnType, KeyPair};
use x509_parser::prelude::*;

use crate::error::{PeerNetError, Result};
use crate::identity::{NodeId, NodeIdentity};

/// X.509 证书的 DER 编码字节
pub type CertDer = Vec<u8>;

/// Ed25519 PKCS#8 私钥的固定 DER 前缀（16 字节，RFC 5958 / RFC 8410）
///
/// 结构完全由标准定死：SEQUENCE{INTEGER 0, SEQUENCE{OID 1.3.101.112},
/// OCTET STRING{内层 OCTET STRING{32B 种子}}}，仅末尾 32 字节种子可变。
/// rcgen 的 `KeyPair` 只接受 PKCS#8 编码输入，故从原始种子构造需补此包装。
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2E, // SEQUENCE，载荷 46 字节
    0x02, 0x01, 0x00, // INTEGER version = 0
    0x30, 0x05, // SEQUENCE AlgorithmIdentifier
    0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING privateKey，34 字节
    0x04, 0x20, // 内层 OCTET STRING，32 字节种子
];

// ==================== 生成 ====================

/// 由节点身份生成自签证书（DER 编码），CN = 节点 ID
///
/// 密钥必须经 [`NodeIdentity::seed_bytes`] 构造而非随机新生成——理由见模块文档。
pub fn generate_self_signed_cert(identity: &NodeIdentity) -> Result<CertDer> {
    let node_id = identity.node_id();

    // 关键：从身份种子拼 PKCS#8 再交给 rcgen（TryFrom<&[u8]> 自动识别算法），
    // 保证「证书公钥 == 身份公钥 == node_id 指纹源」；rustls 侧（tls.rs）复用
    // 同一构造入口，杜绝两套密钥材料路径漂移
    let pkcs8 = identity_pkcs8_private_key(identity);
    let key_pair =
        KeyPair::try_from(pkcs8.as_slice()).map_err(|e| PeerNetError::KeyPairFromSeed {
            node_id: node_id.to_string(),
            source: e,
        })?;

    // 无 SAN 列表：节点以 ID 而非域名寻址，CN 承载完整身份
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| {
        PeerNetError::CertGenerate {
            node_id: node_id.to_string(),
            source: e,
        }
    })?;
    params.distinguished_name.push(DnType::CommonName, node_id.as_str());

    let cert = params.self_signed(&key_pair).map_err(|e| {
        PeerNetError::CertGenerate {
            node_id: node_id.to_string(),
            source: e,
        }
    })?;

    Ok(cert.der().as_ref().to_vec())
}

/// 由节点身份构造 PKCS#8 私钥 DER（rcgen 与 rustls 共用的唯一密钥材料入口）
///
/// 同一密钥材料喂证书生成（cert.rs）与 TLS 握手签名（tls.rs），保证「握手时
/// 证明的身份 == 证书里的身份 == node_id」三者一致。
pub(crate) fn identity_pkcs8_private_key(identity: &NodeIdentity) -> Vec<u8> {
    let mut pkcs8 = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32);
    pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(&identity.seed_bytes());
    pkcs8
}

// ==================== 绑定校验 ====================

/// 由证书 DER 直接派生节点 ID（重算指纹）
///
/// ticket 02 的 TLS verifier 与既有绑定校验共用同一解析入口，杜绝双实现漂移。
pub(crate) fn node_id_from_cert(cert_der: &[u8]) -> Result<NodeId> {
    let raw = extract_spki_raw_public_key(cert_der)?;
    Ok(NodeId::from_public_key(&raw))
}

/// 校验证书公钥的指纹是否等于给定节点 ID（ticket 02 可信连接的根基）
///
/// 解析失败按 `false` 处理并记 debug 日志：对绑定校验而言「无法确认一致」与
/// 「确认不一致」同样意味着拒绝信任；错误细节经 [`PeerNetError::CertParse`]
/// 路径落日志供排查。
pub fn verify_cert_matches_node_id(cert_der: &[u8], node_id: &NodeId) -> bool {
    match extract_spki_raw_public_key(cert_der) {
        Ok(raw) => NodeId::from_public_key(&raw) == *node_id,
        Err(e) => {
            tracing::debug!(node_id = %node_id, "certificate binding check failed to parse cert: {e}");
            false
        }
    }
}

/// 从证书 DER 提取 SPKI 原始公钥（Ed25519 应为 32 字节）
///
/// crate 内公开给 tls.rs：verifier 重算指纹与签名验证取公钥走同一提取路径。
pub(crate) fn extract_spki_raw_public_key(cert_der: &[u8]) -> Result<[u8; 32]> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| PeerNetError::CertParse {
        detail: format!("read certificate SPKI: {e}"),
    })?;

    // BIT STRING 首字节是 unused-bits 计数（整字节密钥应为 0）；兼容底层库已
    // 剥离计数的形态（len == 32）。选原始钥而非 DER SPKI 整体哈希的原因见
    // crate 文档「指纹算法」段。
    let bits: &[u8] = cert.public_key().subject_public_key.data.as_ref();
    let raw: &[u8] = if bits.len() == 33 && bits[0] == 0 {
        &bits[1..33]
    } else if bits.len() == 32 {
        &bits[..]
    } else {
        return Err(PeerNetError::CertParse {
            detail: format!(
                "unexpected SPKI bit-string length {} (expected 33 with counter or 32 raw)",
                bits.len()
            ),
        });
    };

    let key: [u8; 32] = raw.try_into().map_err(|_| PeerNetError::CertParse {
        detail: format!("SPKI public key length {} != 32", raw.len()),
    })?;
    Ok(key)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    /// 独立身份辅助构造（各自 tempdir，互不共享目录）
    fn fresh_identity() -> (tempfile::TempDir, NodeIdentity) {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity =
            NodeIdentity::load_or_create(dir.path()).expect("load_or_create identity");
        (dir, identity)
    }

    #[test]
    fn generated_cert_public_key_equals_identity_public_key() {
        let (_dir, identity) = fresh_identity();
        let cert = generate_self_signed_cert(&identity).expect("generate cert");

        // AC #3 核心：证书里的 SPKI 原始公钥必须逐字节等于身份公钥
        let spki_raw = extract_spki_raw_public_key(&cert).expect("extract SPKI");
        assert_eq!(spki_raw, identity.public_key_raw());
    }

    #[test]
    fn binding_verification_accepts_own_certificate() {
        let (_dir, identity) = fresh_identity();
        let cert = generate_self_signed_cert(&identity).expect("generate cert");

        assert!(verify_cert_matches_node_id(&cert, identity.node_id()));
    }

    #[test]
    fn forged_certificate_is_rejected_for_same_node_id() {
        let (_dir_a, honest) = fresh_identity();
        let (_dir_b, attacker) = fresh_identity();

        let honest_cert = generate_self_signed_cert(&honest).expect("honest cert");
        let forged_cert = generate_self_signed_cert(&attacker).expect("forged cert");

        // 各自证书对自己的身份成立……
        assert!(verify_cert_matches_node_id(&forged_cert, attacker.node_id()));

        // ……但伪造证书冒充诚实节点 ID 必须被拒止（身份拒止雏形）
        assert!(!verify_cert_matches_node_id(&forged_cert, honest.node_id()));
        assert!(verify_cert_matches_node_id(&honest_cert, honest.node_id()));
    }

    #[test]
    fn tampered_node_id_fails_binding_check() {
        let (_dir, identity) = fresh_identity();
        let cert = generate_self_signed_cert(&identity).expect("generate cert");

        // 篡改 node_id 首字符（保持合法 hex 形状）：绑定校验必须为假
        let mut tampered = identity.node_id().as_str().to_owned().into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        let tampered_id = NodeId::parse(std::str::from_utf8(&tampered).expect("utf8"))
            .expect("still valid hex");

        assert_ne!(&tampered_id, identity.node_id());
        assert!(!verify_cert_matches_node_id(&cert, &tampered_id));
    }

    #[test]
    fn garbage_certificate_bytes_fail_binding_check_as_false() {
        let (_dir, identity) = fresh_identity();
        assert!(!verify_cert_matches_node_id(b"not a certificate", identity.node_id()));
    }

    #[test]
    fn cert_subject_cn_carries_node_id() {
        let (_dir, identity) = fresh_identity();
        let cert = generate_self_signed_cert(&identity).expect("generate cert");

        let (_, parsed) =
            X509Certificate::from_der(&cert).expect("parse own generated cert");
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .and_then(|c| c.as_str().ok())
            .expect("CN present");
        assert_eq!(cn, identity.node_id().as_str());
    }
}
