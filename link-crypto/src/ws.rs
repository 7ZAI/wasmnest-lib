//! WS 会话加密：方向密码派生 + 双端握手 + 客户端会话编解码
//!
//! 双 ECDH 握手（spec §3）：
//! - 客户端生成临时 m_eph，auth 首消息携 m_ek_b64 提案
//! - 服务端生成新鲜 s_eph，IKM = ECDH(s_eph,m_eph) ‖ ECDH(Kd,m_eph)
//! - 客户端复算 IKM = ECDH(m_eph,s_eph) ‖ ECDH(m_eph,Kd_pub)
//! - salt = "bc-link-crypto/v1" ‖ m_ek_b64 ‖ s_ek_b64；OKM 36B = key32 + noncePrefix4
//!
//! 字节拼接顺序是跨端兼容性表面（TS 实现金样互验钉死），不得调整。

use crate::{
    aes_gcm_decrypt, aes_gcm_encrypt, b64_decode, b64_encode, err, hkdf_sha256, ws_aad, ws_nonce,
    x25519_dh, Result, WS_FRAME_VERSION, WS_INFO_CLIENT_TO_SERVER, WS_INFO_SERVER_TO_CLIENT,
    WS_TRANSCRIPT_PREFIX,
};

use serde::{Deserialize, Serialize};

/// X25519 密钥长度
pub const X25519_KEY_LEN: usize = 32;

/// 传输方向（AAD 绑定用；宿主各自的 Direction 枚举经 From 映射）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 入站：客户端 → 桌面端
    Inbound,
    /// 出站：桌面端 → 客户端
    Outbound,
}

/// 单方向密码上下文（HKDF OKM 切片：32B key + 4B nonce 前缀）
#[derive(Debug, Clone)]
pub struct WsDirectionCipher {
    pub key: [u8; 32],
    pub nonce_prefix: [u8; 4],
}

/// 派生单个 WS 方向密码上下文
fn derive_direction_cipher(
    transcript_salt: &[u8],
    ikm: &[u8],
    info: &[u8],
) -> Result<WsDirectionCipher> {
    let okm = hkdf_sha256(Some(transcript_salt), ikm, info, 36)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    let mut nonce_prefix = [0u8; 4];
    nonce_prefix.copy_from_slice(&okm[32..36]);
    Ok(WsDirectionCipher { key, nonce_prefix })
}

/// 生成临时密钥对（返回 私钥, 公钥）
pub fn generate_ephemeral() -> ([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN]) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    (*secret.as_bytes(), public.to_bytes())
}

// ==================== 服务端握手 ====================

/// 服务端握手产物：临时公钥回执 + 两方向密码
#[derive(Debug, Clone)]
pub struct ServerHandshake {
    /// 服务端临时公钥（base64，随 auth/auth_ok 回执下发）
    pub server_ek_b64: String,
    pub client_to_server: WsDirectionCipher,
    pub server_to_client: WsDirectionCipher,
}

/// 服务端双 ECDH 派生（纯函数；宿主负责身份私钥与临时密钥生命周期）
///
/// `kd_private`：静态身份私钥；`s_ephemeral_private`：本次连接的临时私钥。
pub fn derive_server_handshake(
    m_ek_b64: &str,
    kd_private: &[u8; X25519_KEY_LEN],
    s_ephemeral_private: &[u8; X25519_KEY_LEN],
) -> Result<ServerHandshake> {
    let m_raw = b64_decode(m_ek_b64)?;
    let m_public: [u8; X25519_KEY_LEN] = m_raw.try_into().map_err(|v: Vec<u8>| {
        crate::LinkCryptoError(format!(
            "ws handshake key length mismatch: expected 32, got {}",
            v.len()
        ))
    })?;

    let eph_eph = x25519_dh(s_ephemeral_private, &m_public)?;
    let auth = x25519_dh(kd_private, &m_public)?;
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&eph_eph);
    ikm[32..].copy_from_slice(&auth);

    let server_ek_b64 =
        b64_encode(&x25519_dalek::PublicKey::from(StaticSecretRef(s_ephemeral_private)).to_bytes());
    let salt = [
        WS_TRANSCRIPT_PREFIX,
        m_ek_b64.as_bytes(),
        server_ek_b64.as_bytes(),
    ]
    .concat();
    let c2s = derive_direction_cipher(&salt, &ikm, WS_INFO_CLIENT_TO_SERVER)?;
    let s2c = derive_direction_cipher(&salt, &ikm, WS_INFO_SERVER_TO_CLIENT)?;

    Ok(ServerHandshake { server_ek_b64, client_to_server: c2s, server_to_client: s2c })
}

/// 内部小包装：从已有原始私钥借用构造公钥（避免公开 StaticSecret 语义）
struct StaticSecretRef<'a>(&'a [u8; X25519_KEY_LEN]);

impl<'a> From<StaticSecretRef<'a>> for x25519_dalek::PublicKey {
    fn from(r: StaticSecretRef<'a>) -> Self {
        let secret = x25519_dalek::StaticSecret::from(*r.0);
        x25519_dalek::PublicKey::from(&secret)
    }
}

// ==================== 客户端会话编解码 ====================

/// WS 文本帧信封（控制/业务 JSON；类型保持原则——text 帧仍以 text 发送）
#[derive(Debug, Serialize, Deserialize)]
pub struct WsTextEnvelope {
    pub v: u8,
    pub seq: u64,
    pub n: String,
    pub ct: String,
}

/// 客户端侧 WS 会话编解码（发送 c2s / 接收 s2c，序号严格单调）
///
/// 与服务端的 `WsSessionCiphers` 注册表互为镜像；序号纪律一致：
/// 发送侧严格递增、接收侧严格校验且失败不推进。
pub struct ClientWsCrypto {
    c2s: WsDirectionCipher,
    s2c: WsDirectionCipher,
    send_seq: u64,
    recv_seq: u64,
}

impl ClientWsCrypto {
    /// 客户端双 ECDH 派生（收到 auth 回执的服务端临时公钥后调用）
    ///
    /// `m_ephemeral_private`：提案时生成的临时私钥；`m_ek_b64`：提案公钥
    /// （参与 transcript）；`s_ek_b64`：回执公钥；`kd_public`：已 pin 的服务端身份公钥。
    pub fn derive(
        m_ephemeral_private: &[u8; X25519_KEY_LEN],
        m_ek_b64: &str,
        s_ek_b64: &str,
        kd_public: &[u8; X25519_KEY_LEN],
    ) -> Result<Self> {
        let s_raw = b64_decode(s_ek_b64)?;
        let s_public: [u8; X25519_KEY_LEN] = s_raw.try_into().map_err(|v: Vec<u8>| {
            crate::LinkCryptoError(format!(
                "ws handshake key length mismatch: expected 32, got {}",
                v.len()
            ))
        })?;

        let eph_eph = x25519_dh(m_ephemeral_private, &s_public)?;
        let auth = x25519_dh(m_ephemeral_private, kd_public)?;
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&eph_eph);
        ikm[32..].copy_from_slice(&auth);

        let salt = [
            WS_TRANSCRIPT_PREFIX,
            m_ek_b64.as_bytes(),
            s_ek_b64.as_bytes(),
        ]
        .concat();
        let c2s = derive_direction_cipher(&salt, &ikm, WS_INFO_CLIENT_TO_SERVER)?;
        let s2c = derive_direction_cipher(&salt, &ikm, WS_INFO_SERVER_TO_CLIENT)?;

        Ok(ClientWsCrypto { c2s, s2c, send_seq: 0, recv_seq: 0 })
    }

    /// 加密一条出站文本帧 → 信封 JSON 字符串（推进发送序号）
    pub fn seal_text(&mut self, channel_str: &str, text: &str) -> Result<String> {
        let seq = self.send_seq;
        let aad = ws_aad(channel_str, Direction::Inbound, crate::ORIGIN_TEXT);
        let nonce = ws_nonce(&self.c2s.nonce_prefix, seq);
        let ciphertext = aes_gcm_encrypt(&self.c2s.key, &nonce, text.as_bytes(), Some(&aad))?;
        self.send_seq = seq.checked_add(1).ok_or_else(|| crate::LinkCryptoError("ws seq overflow".into()))?;
        let envelope = WsTextEnvelope {
            v: WS_FRAME_VERSION,
            seq,
            n: b64_encode(&nonce),
            ct: b64_encode(&ciphertext),
        };
        serde_json::to_string(&envelope)
            .map_err(|e| crate::LinkCryptoError(format!("serialize ws envelope failed: {e}")))
    }

    /// 解密一条入站文本帧（信封 JSON → 原 JSON 字符串；严格接收序号，失败不推进）
    pub fn open_text(&mut self, channel_str: &str, body: &str) -> Result<String> {
        let envelope: WsTextEnvelope = serde_json::from_str(body)
            .map_err(|e| crate::LinkCryptoError(format!("ws text envelope malformed: {e}")))?;
        if envelope.v != WS_FRAME_VERSION {
            return err(format!("unsupported ws frame version {}", envelope.v));
        }
        let nonce_v = b64_decode(&envelope.n)?;
        let nonce: [u8; 12] = nonce_v
            .try_into()
            .map_err(|v: Vec<u8>| crate::LinkCryptoError(format!("nonce length mismatch: {}", v.len())))?;
        if envelope.seq != self.recv_seq {
            return err(format!(
                "ws seq mismatch: expected {}, got {}",
                self.recv_seq, envelope.seq
            ));
        }
        let ciphertext = b64_decode(&envelope.ct)?;
        let plain = aes_gcm_decrypt(
            &self.s2c.key,
            &nonce,
            &ciphertext,
            Some(&ws_aad(channel_str, Direction::Outbound, crate::ORIGIN_TEXT)),
        )?;
        self.recv_seq += 1;
        String::from_utf8(plain).map_err(|e| crate::LinkCryptoError(format!("decrypted text not utf-8: {e}")))
    }

    /// 加密一条出站二进制帧（ver+seq+ct，推进发送序号）
    pub fn seal_binary(&mut self, channel_str: &str, frame: &[u8]) -> Result<Vec<u8>> {
        let seq = self.send_seq;
        let aad = ws_aad(channel_str, Direction::Inbound, crate::ORIGIN_BINARY);
        let nonce = ws_nonce(&self.c2s.nonce_prefix, seq);
        let ciphertext = aes_gcm_encrypt(&self.c2s.key, &nonce, frame, Some(&aad))?;
        self.send_seq = seq.checked_add(1).ok_or_else(|| crate::LinkCryptoError("ws seq overflow".into()))?;
        let mut out = Vec::with_capacity(crate::WS_BINARY_HEADER_LEN + ciphertext.len());
        out.push(WS_FRAME_VERSION);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// 解密一条入站二进制帧（严格接收序号，失败不推进）
    pub fn open_binary(&mut self, channel_str: &str, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < crate::WS_BINARY_HEADER_LEN {
            return err(format!("ws binary frame too short: {}", data.len()));
        }
        if data[0] != WS_FRAME_VERSION {
            return err(format!("unsupported ws frame version {}", data[0]));
        }
        let seq = u64::from_be_bytes(data[1..9].try_into().expect("seq slice is 8 bytes"));
        if seq != self.recv_seq {
            return err(format!("ws seq mismatch: expected {}, got {}", self.recv_seq, seq));
        }
        let nonce = ws_nonce(&self.s2c.nonce_prefix, seq);
        let plain = aes_gcm_decrypt(
            &self.s2c.key,
            &nonce,
            &data[crate::WS_BINARY_HEADER_LEN..],
            Some(&ws_aad(channel_str, Direction::Outbound, crate::ORIGIN_BINARY)),
        )?;
        self.recv_seq += 1;
        Ok(plain)
    }
}

// ==================== 单元测试 ====================

// ==================== Tests ====================

// 用例按功能拆至 `ws/tests/`（本内联模块的子模块路径由 rustc
// 自动解析到该目录；模块树 `ws::tests::<文件>` 与内联形态等价，私有项可见性不受影响）。
#[cfg(test)]
mod tests {
    use super::*;
    // 跨分组共享的测试脚手架（子模块经 `use super::*` 可见）

    /// 服务端视角镜像编解码（与桌面 WsSessionCiphers 注册表逻辑一致：
    /// 发送 s2c/接收 c2s），用于与客户端 ClientWsCrypto 做真互通
    struct TestServerCrypto {
        hs: ServerHandshake,
        send_seq: u64,
        recv_seq: u64,
    }
    impl TestServerCrypto {
        fn new(hs: ServerHandshake) -> Self {
            Self { hs, send_seq: 0, recv_seq: 0 }
        }

        fn seal_text(&mut self, channel: &str, text: &str) -> Result<String> {
            let seq = self.send_seq;
            let nonce = ws_nonce(&self.hs.server_to_client.nonce_prefix, seq);
            let ct = aes_gcm_encrypt(
                &self.hs.server_to_client.key,
                &nonce,
                text.as_bytes(),
                Some(&ws_aad(channel, Direction::Outbound, crate::ORIGIN_TEXT)),
            )?;
            self.send_seq += 1;
            serde_json::to_string(&WsTextEnvelope {
                v: WS_FRAME_VERSION,
                seq,
                n: b64_encode(&nonce),
                ct: b64_encode(&ct),
            })
            .map_err(|e| crate::LinkCryptoError(e.to_string()))
        }

        fn open_text(&mut self, channel: &str, body: &str) -> Result<String> {
            let env: WsTextEnvelope =
                serde_json::from_str(body).map_err(|e| crate::LinkCryptoError(e.to_string()))?;
            if env.seq != self.recv_seq {
                return err(format!("seq mismatch: expected {}, got {}", self.recv_seq, env.seq));
            }
            let plain = aes_gcm_decrypt(
                &self.hs.client_to_server.key,
                &b64_decode(&env.n)?,
                &b64_decode(&env.ct)?,
                Some(&ws_aad(channel, Direction::Inbound, crate::ORIGIN_TEXT)),
            )?;
            self.recv_seq += 1;
            String::from_utf8(plain).map_err(|e| crate::LinkCryptoError(e.to_string()))
        }
    }
    mod handshake_interop_and_frame;
}
