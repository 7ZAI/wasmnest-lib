//! WasmNest 局域网链路报文加密协议核心（issue 09 共享 crate）
//!
//! 桌面端 server（`server/link_crypto.rs`）与移动端 Rust 侧（event WS 客户端）
//! 的共同消费层，消除第三份协议实现。字节级表面与移动端 TS 实现
//! （移动端前端 `src/services/linkCrypto.ts`）逐字节一致：
//!
//! - HTTP 信封 `{v:1, n:b64(12B nonce), ct}`；AAD = "v1"‖dir‖u32be(pathLen)‖path
//! - HKDF info = `wasmnest-link-crypto/v1/{http/{request,response},ws/{c2s,s2c}}`
//! - WS 握手 IKM = ECDH(eph,eph) ‖ ECDH(Kd,eph)、salt = "bc-link-crypto/v1"‖m_ek‖s_ek、
//!   OKM 36B = key32 + noncePrefix4
//! - WS 二进制帧 = [ver u8][seq u64be][ct]；文本帧信封含 seq 字段；nonce = prefix‖u64BE(seq)
//!
//! 本 crate 只做纯字节协议：配置域/身份落盘/过滤器接线留在桌面宿主，
//! 运行期开关上下文由移动宿主持有。

pub mod ws;

pub use ws::{
    derive_server_handshake, generate_ephemeral, ClientWsCrypto, Direction, ServerHandshake,
    WsDirectionCipher, WsTextEnvelope, X25519_KEY_LEN,
};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ==================== 错误类型 ====================

/// 协议错误（字符串携带失败原因；宿主按需映射为自己的错误类型）
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct LinkCryptoError(pub String);

/// crate 内统一 Result 别名
pub type Result<T> = std::result::Result<T, LinkCryptoError>;

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(LinkCryptoError(msg.into()))
}

// ==================== 常量 ====================

/// 线上信封版本与协商头 "vN" 前缀共用此源
pub const PROTOCOL_VERSION: u8 = 1;

/// HTTP 链路加密协商请求头
pub const NEGOTIATION_HEADER: &str = "X-WasmNest-Crypto";

// HKDF info 常量——协议兼容性表面，各端实现必须逐字节一致
/// HTTP 请求方向派生 info
pub const HTTP_INFO_REQUEST: &[u8] = b"wasmnest-link-crypto/v1/http/request";
/// HTTP 响应方向派生 info
pub const HTTP_INFO_RESPONSE: &[u8] = b"wasmnest-link-crypto/v1/http/response";
/// WS 客户端→服务端方向派生 info
pub const WS_INFO_CLIENT_TO_SERVER: &[u8] = b"wasmnest-link-crypto/v1/ws/c2s";
/// WS 服务端→客户端方向派生 info
pub const WS_INFO_SERVER_TO_CLIENT: &[u8] = b"wasmnest-link-crypto/v1/ws/s2c";

/// WS 握手 transcript salt 前缀
pub const WS_TRANSCRIPT_PREFIX: &[u8] = b"bc-link-crypto/v1";

/// WS 二进制帧头长度：ver(u8) + seq(u64be)
pub const WS_BINARY_HEADER_LEN: usize = 9;
/// WS 帧版本字节
pub const WS_FRAME_VERSION: u8 = 1;
/// 帧来源类型字节（AAD 绑定，防 text/binary 载荷互换重放）
pub const ORIGIN_TEXT: u8 = 0x01;
/// 帧来源类型字节（AAD 绑定）
pub const ORIGIN_BINARY: u8 = 0x02;

// ==================== 基础原语 ====================

/// base64 std 编码
pub fn b64_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    STANDARD.encode(data)
}

/// base64 std 解码（非法输入报错，不静默截断）
pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    STANDARD
        .decode(text)
        .map_err(|e| LinkCryptoError(format!("base64 decode failed: {e}")))
}

/// 指纹：SHA-256(公钥) 前 16 hex 小写（设置页展示 + 移动端 pin 比对锚点）
pub fn fingerprint_of(public: &[u8; 32]) -> String {
    let digest = Sha256::digest(public);
    let hex = hex_encode(&digest);
    hex[..16].to_string()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// X25519 DH（原始字节进出；错误即非法输入）
pub(crate) fn x25519_dh(
    private: &[u8; X25519_KEY_LEN],
    peer_public: &[u8; X25519_KEY_LEN],
) -> Result<[u8; X25519_KEY_LEN]> {
    let shared = x25519_dalek::x25519(*private, *peer_public);
    // 全零输出是 x25519 的小子群约束失败信号（RFC 7748 §6.2 建议）
    if shared == [0u8; X25519_KEY_LEN] {
        return err("x25519 all-zero shared secret");
    }
    Ok(shared)
}

/// HKDF-SHA256 单次 expand（OKM 长度 ≤ 255*32B，本协议只用 32/36B）
pub(crate) fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; okm_len];
    hk.expand(info, &mut okm)
        .map_err(|e| LinkCryptoError(format!("hkdf expand failed: {e}")))?;
    Ok(okm)
}

// ==================== 协商头解析 ====================

/// 解析协商头 "v1 <ek_b64>"；当前仅接受 v1（版本升级时在此扩展兼容矩阵）
pub fn parse_negotiation(negotiation: &str) -> Option<&str> {
    let mut parts = negotiation.trim().split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(v), Some(ek), None) if *v == format!("v{PROTOCOL_VERSION}") && !ek.is_empty() => {
            Some(ek)
        }
        _ => None,
    }
}

// ==================== AAD / nonce ====================

/// WS 帧 AAD："v1" ‖ channel ‖ direction 字节 ‖ origin 字节。
/// 方向/来源绑定防跨通道、跨方向、text/binary 载荷互换的重放。
pub fn ws_aad(channel_str: &str, direction: Direction, origin: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(3 + channel_str.len());
    aad.extend_from_slice(b"v1");
    aad.extend_from_slice(channel_str.as_bytes());
    aad.push(match direction {
        Direction::Inbound => 0x01,
        Direction::Outbound => 0x02,
    });
    aad.push(origin);
    aad
}

/// HTTP AAD："v1" ‖ dir ‖ u32be(len) ‖ path。路径绑定防信封跨端点搬运。
pub fn http_aad(direction: Direction, path: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(7 + path.len());
    aad.extend_from_slice(b"v1");
    aad.push(match direction {
        Direction::Inbound => 0x01,
        Direction::Outbound => 0x02,
    });
    aad.extend_from_slice(&(path.len() as u32).to_be_bytes());
    aad.extend_from_slice(path.as_bytes());
    aad
}

/// WS nonce：4B 方向前缀 ‖ 8B BE 序号（严格单调，防重放）
pub fn ws_nonce(prefix: &[u8; 4], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

// ==================== AES-256-GCM 载荷 ====================

const AES_KEY_LEN: usize = 32;
const AES_NONCE_LEN: usize = 12;

/// AES-256-GCM 加密（密文尾部拼 16B tag；错误信息与既有实现逐字一致）
pub(crate) fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;
    let key_arr: [u8; AES_KEY_LEN] = key
        .try_into()
        .map_err(|_| LinkCryptoError("aes key length mismatch".to_string()))?;
    let nonce_arr: [u8; AES_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| LinkCryptoError("aes nonce length mismatch".to_string()))?;
    let cipher = Aes256Gcm::new((&key_arr).into());
    let payload = aad
        .map(|a| Payload {
            msg: plaintext,
            aad: a,
        })
        .unwrap_or(Payload {
            msg: plaintext,
            aad: b"",
        });
    cipher
        .encrypt((&nonce_arr).into(), payload)
        .map_err(|_| LinkCryptoError("AES-256-GCM 加密失败".to_string()))
}

/// AES-256-GCM 解密（tag 校验失败即错，fail-closed）
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;
    let key_arr: [u8; AES_KEY_LEN] = key
        .try_into()
        .map_err(|_| LinkCryptoError("aes key length mismatch".to_string()))?;
    let nonce_arr: [u8; AES_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| LinkCryptoError("aes nonce length mismatch".to_string()))?;
    let cipher = Aes256Gcm::new((&key_arr).into());
    let payload = aad
        .map(|a| Payload {
            msg: ciphertext,
            aad: a,
        })
        .unwrap_or(Payload {
            msg: ciphertext,
            aad: b"",
        });
    cipher
        .decrypt((&nonce_arr).into(), payload)
        .map_err(|_| LinkCryptoError("AES-256-GCM 解密失败: aead::Error".to_string()))
}

// ==================== HTTP 信封 ====================

/// HTTP 加密信封（线上格式，字段 base64 std）
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpEnvelope {
    /// 协议版本
    pub v: u8,
    /// AES-256-GCM nonce（12B，base64，随机）
    pub n: String,
    /// 密文 + GCM 认证标签（base64）
    pub ct: String,
}

/// HTTP 双方向会话密钥（单请求作用域；与前端 `deriveHttpKeys` 逐字节一致）
pub struct HttpTrafficKeys {
    /// 请求方向 AES-256-GCM 密钥
    pub request: [u8; X25519_KEY_LEN],
    /// 响应方向 AES-256-GCM 密钥
    pub response: [u8; X25519_KEY_LEN],
}

/// 归一化 wire 路径：剥离 query string。桌面端服务端按 `req.path()`（不含
/// query）计算 HKDF salt 与 AAD；调用方传入的 path 可能带 query（GET 参数
/// 端点），两端口径必须一致——对齐前端 `linkCrypto.ts` 的 `wirePath`。
fn wire_path(path: &str) -> &str {
    match path.find('?') {
        Some(q) => &path[..q],
        None => path,
    }
}

/// 由临时私钥与 pin 的 Kd 公钥派生两方向会话密钥（字节级对齐前端
/// `deriveHttpKeys`）：`shared = X25519(eph_priv, kd_public)`；HKDF salt =
/// `wirePath(path)`（剥 query）；request/response 分别以
/// `HTTP_INFO_REQUEST` / `HTTP_INFO_RESPONSE` 派生 32B 密钥。
pub fn derive_http_keys(
    ephemeral_private: &[u8; X25519_KEY_LEN],
    kd_public: &[u8; X25519_KEY_LEN],
    path: &str,
) -> Result<HttpTrafficKeys> {
    let shared = x25519_dh(ephemeral_private, kd_public)?;
    let salt = wire_path(path).as_bytes();
    let request = hkdf_sha256(Some(salt), &shared, HTTP_INFO_REQUEST, X25519_KEY_LEN)?;
    let response = hkdf_sha256(Some(salt), &shared, HTTP_INFO_RESPONSE, X25519_KEY_LEN)?;
    let mut request_key = [0u8; X25519_KEY_LEN];
    request_key.copy_from_slice(&request);
    let mut response_key = [0u8; X25519_KEY_LEN];
    response_key.copy_from_slice(&response);
    Ok(HttpTrafficKeys {
        request: request_key,
        response: response_key,
    })
}

/// 明文 → 信封 JSON 字节（随机 nonce；HTTP 密钥每次请求全新，无 nonce 复用风险）
pub fn encrypt_http_body(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    getrandom(&mut nonce_bytes);
    let ciphertext = aes_gcm_encrypt(key, &nonce_bytes, plaintext, Some(aad))?;
    let envelope = HttpEnvelope {
        v: PROTOCOL_VERSION,
        n: b64_encode(&nonce_bytes),
        ct: b64_encode(&ciphertext),
    };
    serde_json::to_vec(&envelope)
        .map_err(|e| LinkCryptoError(format!("serialize envelope failed: {e}")))
}

/// 信封 JSON 字节 → 明文（fail-closed：格式/版本/nonce 长度/GCM 校验任一失败即错）
pub fn decrypt_http_body(key: &[u8; 32], body: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let envelope: HttpEnvelope = serde_json::from_slice(body)
        .map_err(|e| LinkCryptoError(format!("http envelope malformed: {e}")))?;
    if envelope.v != PROTOCOL_VERSION {
        return err(format!("unsupported envelope version {}", envelope.v));
    }
    let nonce_v = b64_decode(&envelope.n)?;
    let nonce: [u8; AES_NONCE_LEN] = nonce_v.try_into().map_err(|v: Vec<u8>| {
        LinkCryptoError(format!(
            "nonce length mismatch: expected 12, got {}",
            v.len()
        ))
    })?;
    let ciphertext = b64_decode(&envelope.ct)?;
    aes_gcm_decrypt(key, &nonce, &ciphertext, Some(aad))
}

fn getrandom(buf: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(buf);
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// HTTP 编解码往返 + 篡改拒收 + 版本拒绝
    #[test]
    fn http_body_roundtrip_and_tamper_rejection() {
        let key = [7u8; 32];
        let aad = http_aad(Direction::Inbound, "/api/sessions");
        let sealed = encrypt_http_body(&key, b"{\"ping\":1}", &aad).unwrap();

        let opened = decrypt_http_body(&key, &sealed, &aad).unwrap();
        assert_eq!(opened, b"{\"ping\":1}");

        // 篡改密文 → AEAD 失败
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(decrypt_http_body(&key, &tampered, &aad).is_err());

        // AAD 不匹配（换路径）→ AEAD 失败
        let other_aad = http_aad(Direction::Inbound, "/api/configs");
        assert!(decrypt_http_body(&key, &sealed, &other_aad).is_err());

        // 版本不匹配 → 明确拒绝
        let env: HttpEnvelope = serde_json::from_slice(&sealed).unwrap();
        assert_eq!(env.v, PROTOCOL_VERSION);
    }

    /// 协商头解析：仅接受 "v1 <非空 ek>"
    #[test]
    fn negotiation_parsing_accepts_only_v1_pair() {
        assert_eq!(parse_negotiation("v1 QUJD"), Some("QUJD"));
        assert_eq!(parse_negotiation("  v1   QUJD  "), Some("QUJD"));
        assert_eq!(parse_negotiation("v2 QUJD"), None);
        assert_eq!(parse_negotiation("v1"), None);
        assert_eq!(parse_negotiation("v1 "), None);
        assert_eq!(parse_negotiation(""), None);
        assert_eq!(parse_negotiation("v1 QUJD extra"), None);
    }

    /// 指纹：SHA-256 前 16 hex 小写（跨端 pin 比对锚点）
    #[test]
    fn fingerprint_is_16_lowercase_hex() {
        let fp = fingerprint_of(&[0xABu8; 32]);
        assert_eq!(fp.len(), 16);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// derive_http_keys 金样：固定向量来自真实前端 linkCrypto.ts（@noble
    /// 实现）——断言 Rust 派生逐字节一致；带 query 的 path 与不带 query
    /// 结果一致（wirePath 剥 query 对齐）。
    #[test]
    fn derive_http_keys_matches_frontend_golden() {
        let eph_priv: [u8; X25519_KEY_LEN] = core::array::from_fn(|i| (i as u8) + 1);
        let kd_pub: [u8; X25519_KEY_LEN] = core::array::from_fn(|i| (i as u8) + 0x21);
        let keys = derive_http_keys(&eph_priv, &kd_pub, "/api/sessions").unwrap();
        assert_eq!(
            hex_encode(&keys.request),
            "4ca4d417ecaf763ff3802caa1982fc6183c8da9d4f1f703f0b25f1fb6b2e4f74"
        );
        assert_eq!(
            hex_encode(&keys.response),
            "f19e9a951ff96ac43f568eba84da8ddbab0a856a3a378b0a01d3d28b118e5557"
        );
        // 剥 query：带 query 的 path 派生与不带 query 一致
        let with_query =
            derive_http_keys(&eph_priv, &kd_pub, "/api/sessions?offset=0&limit=10").unwrap();
        assert_eq!(with_query.request, keys.request);
        assert_eq!(with_query.response, keys.response);
    }
}
