//! rustls 配置与自定义证书 verifier：「证书指纹即身份」的 TLS 层落地（ADR 0028）。
//!
//! ## Decision 1 —— 两层校验的不对称分工
//!
//! | 方向 | TLS verifier 职责 |
//! |---|---|
//! | 拨号侧（[`PinningServerCertVerifier`]）| 从服务端证书 SPKI 重算指纹，**精确比对**发现记录带外持有的期望 [`NodeId`]，不符即 TLS 层拒绝——这是 AC#3 的断言点 |
//! | 接听侧（[`ShapeCheckingClientCertVerifier`]）| 仅做形状校验：SPKI 可解析出合法 Ed25519 公钥（32B）即可派生合法 NodeId。首连本就无先验期望，不存在「不符」可比对 |
//!
//! 「指纹是否在可信集」的判断在握手后的应用层（transport 查 trust store）：
//! 若 TLS 层拒绝一切未信任指纹，AC#1 的「未信任拨入触发确认回调」物理上不可能发生。
//!
//! ## 为何 `verify_tls13_signature` 必须真实验证签名（安全关键，勿退化为恒 Ok）
//!
//! 攻击者无需私钥就能把受害者公钥嵌进自签证书——绑定校验会通过；只有 TLS 1.3
//! CertificateVerify 对握手 transcript 的签名才能证明对端确实持有对应私钥
//! （RFC 8446 §4.4.3）。因此本模块经 ring 对该签名做真实 Ed25519 验证：
//! 「伪造身份」要么持有该 ID 私钥（那你就是它），要么握手失败——AC#3 由密码学
//! 机制保证而非字符串比对。
//!
//! 签名输入的拼装（64×0x20 ‖ context‖0x00 ‖ transcript hash）由 rustls 在调用
//! verifier **之前**完成（对照 rustls src/tls13/mod.rs 的
//! `construct_{server,client}_verify_message` 与 client/server tls13.rs 的调用点，
//! 0.23 版本传入的 `message` 即完整拼装结果）：verifier 只需对收到的内容原样
//! 验证，不得再拼前缀——双重构造必然验证失败。client/server 两个方向的 context
//! 区分同样由 rustls 负责。
//!
//! 协议版本锁 TLS 1.3：双方同栈无遗留对端，verifier 只实现 `_tls13_signature`
//! 路径，`verify_tls12_signature` 恒报不支持。

use std::sync::Arc;

use ring::signature::UnparsedPublicKey;
// 别名避免与外部 crate `ring` 同名遮蔽（use 绑定会遮蔽 extern prelude 名）
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as crypto_ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError};
use rustls::{SignatureScheme, version};

use crate::cert::{extract_spki_raw_public_key, identity_pkcs8_private_key, node_id_from_cert};
use crate::error::{PeerNetError, Result};
use crate::identity::{NodeId, NodeIdentity};

// ==================== 常量 ====================

/// 绑定不符错误经 rustls `Error::General` 文本透传后的识别前缀
///
/// rustls 自定义 verifier 只能返回 [`RustlsError`]，错误经 tokio-rustls 的
/// io::Error 包装到达拨号侧后类型信息已丢失；固定前缀使 transport 能把「指纹
/// 不符」与其他握手失败区分开（AC#3 要求错误种类级断言）。
pub(crate) const BINDING_MISMATCH_PREFIX: &str = "peer-net binding mismatch";

/// 从 rustls General 错误文本识别绑定不符，拆出 expected / actual
pub(crate) fn parse_binding_mismatch(msg: &str) -> Option<(String, String)> {
    let rest = msg.strip_prefix(BINDING_MISMATCH_PREFIX)?;
    // 消息形态："{PREFIX}: expected=<id>, actual=<id>"
    let expected = rest.split("expected=").nth(1)?.split(',').next()?.to_string();
    let actual = rest.split("actual=").nth(1)?.to_string();
    Some((expected, actual))
}

// ==================== 拨号侧 verifier ====================

/// 拨号侧服务端证书 verifier：以期望 NodeId 钉扎校验对端证书
#[derive(Debug)]
pub(crate) struct PinningServerCertVerifier {
    expected: NodeId,
}

impl PinningServerCertVerifier {
    /// 以发现记录带外持有的期望节点 ID 构造钉扎 verifier
    pub(crate) fn new(expected: NodeId) -> Self {
        Self { expected }
    }
}

impl ServerCertVerifier for PinningServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        // 对端恒为自签单证书：不做链校验与有效期校验——身份由指纹钉扎唯一确定，
        // 「是否可信」属应用层闸门职责（Decision 1 分层）
        match node_id_from_cert(end_entity.as_ref()) {
            Ok(actual) if actual == self.expected => Ok(ServerCertVerified::assertion()),
            Ok(actual) => Err(RustlsError::General(format!(
                "{BINDING_MISMATCH_PREFIX}: expected={}, actual={actual}",
                self.expected
            ))),
            Err(e) => Err(RustlsError::General(format!(
                "peer-net dial peer certificate unparseable: {e}"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        // 配置已锁 TLS 1.3 单版本，此路径不应触达；防御性拒绝而非放行
        Err(RustlsError::General(
            "peer-net does not support TLS 1.2 handshake signatures".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        // message 已是 rustls 拼装好的完整签名输入，原样送验
        verify_ed25519_signature_core(message, cert.as_ref(), dss.scheme, dss.signature())?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

// ==================== 接听侧 verifier ====================

/// 接听侧客户端证书 verifier：仅做 SPKI 形状校验（Decision 1）
///
/// 首连本就无先验期望 ID 可比对；能解析出合法 Ed25519 公钥即可派生合法
/// NodeId，交给应用层闸门决定信任与否。
#[derive(Debug)]
pub(crate) struct ShapeCheckingClientCertVerifier;

impl ClientCertVerifier for ShapeCheckingClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // 无 CA 体系：不向客户端提示任何可接受主体；身份由 SPKI 指纹唯一确定
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // mandatory client auth：非 WasmNest 的 TLS 客户端直接握手失败，
        // 符合 ADR 0027「协议私有是接受的成本」，也让闸门只面对已认证连接
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, RustlsError> {
        match extract_spki_raw_public_key(end_entity.as_ref()) {
            // 形状合法即放行——此处不产生信任，只保证「可派生 NodeId」
            Ok(_) => Ok(ClientCertVerified::assertion()),
            Err(e) => Err(RustlsError::General(format!(
                "peer-net client certificate has no usable Ed25519 SPKI: {e}"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "peer-net does not support TLS 1.2 handshake signatures".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        // message 已是 rustls 拼装好的完整签名输入，原样送验
        verify_ed25519_signature_core(message, cert.as_ref(), dss.scheme, dss.signature())?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

// ==================== 真实签名验证 ====================

/// 真实验证 TLS 1.3 CertificateVerify 的 Ed25519 签名（两个方向共享的核心）
///
/// 安全关键：禁止把本函数退化成无条件 Ok——绑定校验只证明「证书里的公钥是
/// 谁」，本函数才证明「对端持有该公钥对应的私钥」。scheme 与签名字节直接传参
/// 而非收 [`DigitallySignedStruct`]：其构造器是 pub(crate)，直参形态让单测能
/// 用真实密钥锁死验证语义，trait 方法内部分发路径一致。
fn verify_ed25519_signature_core(
    signed_content: &[u8],
    cert_der: &[u8],
    scheme: SignatureScheme,
    signature_bytes: &[u8],
) -> std::result::Result<(), RustlsError> {
    if scheme != SignatureScheme::ED25519 {
        return Err(RustlsError::General(format!(
            "peer-net only supports ED25519 handshake signatures, got {scheme:?}"
        )));
    }

    let spki_raw = extract_spki_raw_public_key(cert_der).map_err(|e| {
        RustlsError::General(format!(
            "peer-net cannot extract Ed25519 public key from handshake certificate: {e}"
        ))
    })?;

    let public_key = UnparsedPublicKey::new(&ring::signature::ED25519, spki_raw);
    public_key.verify(signed_content, signature_bytes).map_err(|_| {
        RustlsError::General("peer-net TLS 1.3 CertificateVerify signature invalid".to_string())
    })
}

// ==================== 配置构建 ====================

/// 构建拨号侧 TLS 客户端配置：期望身份钉扎 + 本端 mTLS 客户端证书 + TLS 1.3 单版本
///
/// - crypto provider 显式传入 ring（不用全局 install_default，避免污染宿主进程
///   全局状态、规避多 provider 安装竞态）
/// - `own_cert_der` 即本节自签证书，与本端身份同一密钥材料生成，mTLS 双向互验
pub(crate) fn client_config(
    expected_peer_id: &NodeId,
    identity: &NodeIdentity,
    own_cert_der: &[u8],
) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(crypto_ring::default_provider());
    let key_der = PrivatePkcs8KeyDer::from(identity_pkcs8_private_key(identity));

    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|e| PeerNetError::TlsConfig {
            detail: format!("enable TLS 1.3 for client config: {e}"),
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningServerCertVerifier::new(
            expected_peer_id.clone(),
        )))
        .with_client_auth_cert(
            vec![CertificateDer::from(own_cert_der.to_vec())],
            PrivateKeyDer::from(key_der),
        )
        .map_err(|e| PeerNetError::TlsConfig {
            detail: format!("load own client cert/key for mTLS failed: {e}"),
        })
}

/// 构建接听侧 TLS 服务端配置：mandatory client auth + 形状校验 verifier
pub(crate) fn server_config(identity: &NodeIdentity, own_cert_der: &[u8]) -> Result<rustls::ServerConfig> {
    let provider = Arc::new(crypto_ring::default_provider());
    let key_der = PrivatePkcs8KeyDer::from(identity_pkcs8_private_key(identity));

    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|e| PeerNetError::TlsConfig {
            detail: format!("enable TLS 1.3 for server config: {e}"),
        })?
        .with_client_cert_verifier(Arc::new(ShapeCheckingClientCertVerifier))
        .with_single_cert(
            vec![CertificateDer::from(own_cert_der.to_vec())],
            PrivateKeyDer::from(key_der),
        )
        .map_err(|e| PeerNetError::TlsConfig {
            detail: format!("load server cert/key for mTLS failed: {e}"),
        })
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// 独立身份辅助构造（各自 tempdir，互不共享目录）
    fn fresh_identity() -> (tempfile::TempDir, NodeIdentity) {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity =
            NodeIdentity::load_or_create(dir.path()).expect("load_or_create identity");
        (dir, identity)
    }

    fn identity_cert(identity: &NodeIdentity) -> Vec<u8> {
        crate::cert::generate_self_signed_cert(identity).expect("generate cert")
    }

    fn dummy_server_name() -> ServerName<'static> {
        // pki-types 的 IpAddr 是自有枚举（无 FromStr）：先解析 std 形态再转换
        let ip: std::net::IpAddr = "127.0.0.1".parse().expect("loopback ip");
        ServerName::from(ip)
    }

    /// 由身份种子重建签名私钥（测试签名用；seed_bytes 为 crate 内可见）
    fn signing_key_of(identity: &NodeIdentity) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&identity.seed_bytes())
    }

    /// 按 rustls 的调用约定构造 CertificateVerify 签名输入并签名
    ///
    /// rustls 在调用 verifier 前已拼装完整内容（64×0x20 ‖ context‖0x00 ‖
    /// transcript hash，逐字节对照 rustls src/tls13/mod.rs 常量）；本助手复刻
    /// 该拼装后用真实 dalek 私钥签名，返回 (message, signature)——单测据此
    /// 锁死「对 rustls 送入的 message 原样验证」的语义。
    fn sign_certificate_verify(signing_key: &ed25519_dalek::SigningKey) -> (Vec<u8>, Vec<u8>) {
        const SERVER_CONTEXT: &[u8; 34] = b"TLS 1.3, server CertificateVerify\x00";
        // transcript hash 取任意定长字节即可：Ed25519 对拼装后的整体消息签名
        let transcript_hash = vec![0x5Au8; 32];
        let mut message = Vec::new();
        message.extend_from_slice(&[0x20u8; 64]);
        message.extend_from_slice(SERVER_CONTEXT);
        message.extend_from_slice(&transcript_hash);
        let sig = signing_key.sign(&message).to_bytes().to_vec();
        (message, sig)
    }

    #[test]
    fn tls13_signature_verification_accepts_genuine_signer_only() {
        let (_dir, identity) = fresh_identity();
        let cert_der = identity_cert(&identity);
        let (message, sig) = sign_certificate_verify(&signing_key_of(&identity));

        // 与证书公钥对应的私钥所签：通过
        assert!(verify_ed25519_signature_core(
            &message,
            &cert_der,
            SignatureScheme::ED25519,
            &sig
        )
        .is_ok());

        // 内容被替换（transcript 不同）：必须拒绝——签名与消息必须逐字节对应
        let mut other_content = message.clone();
        other_content[100] ^= 0x01;
        assert!(verify_ed25519_signature_core(
            &other_content,
            &cert_der,
            SignatureScheme::ED25519,
            &sig
        )
        .is_err());
    }

    #[test]
    fn tls13_signature_verification_rejects_forged_signer() {
        // 攻击者无需私钥即可把诚实节点公钥嵌进自签证书；此处证明签名验证环节
        // 能拦住「无对应私钥的冒充者」——Decision 1 安全约束的机制保证
        let (_dir_a, honest) = fresh_identity();
        let (_dir_b, attacker) = fresh_identity();

        let (message, _) = sign_certificate_verify(&signing_key_of(&attacker));

        let err = verify_ed25519_signature_core(
            &message,
            &identity_cert(&honest), // 证书公钥 = honest
            SignatureScheme::ED25519,
            &sign_certificate_verify(&signing_key_of(&attacker)).1,
        )
        .expect_err("attacker signature over honest public key must fail");
        match err {
            RustlsError::General(msg) => assert!(msg.contains("invalid")),
            other => panic!("expected General error, got: {other:?}"),
        }
    }

    #[test]
    fn tls13_signature_verification_rejects_tampered_signature_and_wrong_scheme() {
        let (_dir, identity) = fresh_identity();
        let cert_der = identity_cert(&identity);
        let (message, mut sig) = sign_certificate_verify(&signing_key_of(&identity));

        sig[10] ^= 0xFF;
        let tampered = verify_ed25519_signature_core(
            &message.clone(),
            &cert_der.clone(),
            SignatureScheme::ED25519,
            &sig,
        );
        assert!(tampered.is_err(), "tampered signature must be rejected");

        let wrong_scheme = verify_ed25519_signature_core(
            &message,
            &cert_der,
            SignatureScheme::RSA_PSS_SHA256,
            &sig,
        );
        assert!(wrong_scheme.is_err(), "non-ed25519 scheme must be rejected");
    }

    #[test]
    fn pinning_verifier_accepts_matching_peer_certificate() {
        let (_dir, peer_identity) = fresh_identity();
        let verifier = PinningServerCertVerifier::new(peer_identity.node_id().clone());

        let verdict = verifier.verify_server_cert(
            &CertificateDer::from(identity_cert(&peer_identity)),
            &[],
            &dummy_server_name(),
            &[],
            unix_now(),
        );
        assert!(verdict.is_ok());
    }

    #[test]
    fn pinning_verifier_rejects_foreign_certificate_as_binding_mismatch() {
        let (_dir_a, honest) = fresh_identity();
        let (_dir_b, attacker) = fresh_identity();
        // 期望连到 honest，实际收到 attacker 的自签证书（地址劫持场景）：
        // 必须携带 binding-mismatch 标记且 expected/actual 可解析
        let verifier = PinningServerCertVerifier::new(honest.node_id().clone());

        let err = verifier
            .verify_server_cert(
                &CertificateDer::from(identity_cert(&attacker)),
                &[],
                &dummy_server_name(),
                &[],
                unix_now(),
            )
            .expect_err("foreign certificate must be pinned-rejected");
        match err {
            RustlsError::General(msg) => {
                assert!(
                    msg.starts_with(BINDING_MISMATCH_PREFIX),
                    "must carry binding-mismatch marker: {msg}"
                );
                let (expected, actual) = parse_binding_mismatch(&msg).expect("parsable");
                assert_eq!(expected, honest.node_id().as_str());
                assert_eq!(actual, attacker.node_id().as_str());
            }
            other => panic!("expected General error, got: {other:?}"),
        }
    }

    #[test]
    fn pinning_verifier_rejects_garbage_certificate() {
        let (_dir, identity) = fresh_identity();
        let verifier = PinningServerCertVerifier::new(identity.node_id().clone());

        assert!(verifier
            .verify_server_cert(
                &CertificateDer::from(b"not a certificate".to_vec()),
                &[],
                &dummy_server_name(),
                &[],
                unix_now(),
            )
            .is_err());
    }

    #[test]
    fn pinning_verifier_rejects_tampered_certificate_der() {
        // 截断合法证书 DER（AC#3 辅助：篡改字节同样 TLS 拒绝）：
        // ASN.1 长度声明与实际字节不符，解析必须失败而非静默放行
        let (_dir, identity) = fresh_identity();
        let cert = identity_cert(&identity);
        assert!(cert.len() > 9, "generated cert large enough to truncate");
        let truncated = &cert[..cert.len() - 9];
        let verifier = PinningServerCertVerifier::new(identity.node_id().clone());

        assert!(verifier
            .verify_server_cert(
                &CertificateDer::from(truncated.to_vec()),
                &[],
                &dummy_server_name(),
                &[],
                unix_now(),
            )
            .is_err());
    }

    #[test]
    fn shape_client_verifier_accepts_ed25519_and_rejects_garbage() {
        let verifier = ShapeCheckingClientCertVerifier;
        let (_dir, identity) = fresh_identity();

        assert!(verifier
            .verify_client_cert(
                &CertificateDer::from(identity_cert(&identity)),
                &[],
                unix_now(),
            )
            .is_ok());
        assert!(verifier
            .verify_client_cert(
                &CertificateDer::from(b"garbage der bytes".to_vec()),
                &[],
                unix_now(),
            )
            .is_err());
    }

    #[test]
    fn both_verifiers_only_advertise_ed25519_scheme() {
        let (_dir, identity) = fresh_identity();
        assert_eq!(
            PinningServerCertVerifier::new(identity.node_id().clone()).supported_verify_schemes(),
            vec![SignatureScheme::ED25519]
        );
        assert_eq!(
            ShapeCheckingClientCertVerifier.supported_verify_schemes(),
            vec![SignatureScheme::ED25519]
        );
    }

    #[test]
    fn built_configs_load_own_cert_and_key() {
        let (_dir, identity) = fresh_identity();
        let cert = identity_cert(&identity);

        // 构建成功即证明 cert/key 匹配（rustls 装载时校验私钥与证书 SPKI 一致）；
        // verifier 行为与 client-auth 策略已由上方独立用例覆盖，端到端握手路径
        // 由 harness 的 AC 测试验证
        let _client = client_config(identity.node_id(), &identity, &cert).expect("client config");
        let _server = server_config(&identity, &cert).expect("server config");
    }

    fn unix_now() -> UnixTime {
        UnixTime::now()
    }
}
