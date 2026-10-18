//! general — crate 内单元测试（自 packages/link-crypto/src/ws.rs 迁出）

use super::*;

/// 双端握手互通锚点：同一字节公式下两端各自派生的两方向密码逐字等价，
/// 跨角色文本往返、重放拒绝、篡改拒收全部成立
#[test]
fn handshake_interop_and_frame_roundtrip() {
    // 客户端临时密钥对 + 服务端静态身份对（公钥经基点派生）
    let (m_priv, m_pub) = generate_ephemeral();
    let m_ek_b64 = b64_encode(&m_pub);
    let kd_priv = [9u8; 32];
    let kd_pub = x25519_dalek::x25519(kd_priv, x25519_dalek::X25519_BASEPOINT_BYTES);
    let (s_priv, s_pub) = generate_ephemeral();

    let hs = derive_server_handshake(&m_ek_b64, &kd_priv, &s_priv).unwrap();
    assert_eq!(hs.server_ek_b64, b64_encode(&s_pub), "回执公钥必须来自同一临时私钥");
    let mut server = TestServerCrypto::new(hs.clone());

    let mut client =
        ClientWsCrypto::derive(&m_priv, &m_ek_b64, &hs.server_ek_b64, &kd_pub).unwrap();

    // 客户端 → 服务端文本往返（c2s）
    let up = client.seal_text("ws-event", "{\"type\":\"subscribe\"}").unwrap();
    assert_eq!(server.open_text("ws-event", &up).unwrap(), "{\"type\":\"subscribe\"}");
    // 重放拒绝：接收序号已推进，同一帧再次到达报 mismatch
    assert!(server.open_text("ws-event", &up).is_err());

    // 服务端 → 客户端文本往返（s2c）
    let down = server.seal_text("ws-event", "sync payload").unwrap();
    assert_eq!(client.open_text("ws-event", &down).unwrap(), "sync payload");
    assert!(client.open_text("ws-event", &down).is_err());

    // 二进制结构断言：同一连接共享发送序号（文本帧已发 seq 0，二进制帧应为 1）
    let sealed_bin = client.seal_binary("ws-event", &[0xABu8; 37]).unwrap();
    assert_eq!(sealed_bin[0], WS_FRAME_VERSION);
    let bin_seq = u64::from_be_bytes(sealed_bin[1..9].try_into().unwrap());
    assert_eq!(bin_seq, 1);

    // 篡改拒收：合法新序号帧上翻转 ct 末字节
    let tampered_src = client.seal_text("ws-event", "y").unwrap();
    let mut tampered: WsTextEnvelope = serde_json::from_str(&tampered_src).unwrap();
    let mut ct_bytes = b64_decode(&tampered.ct).unwrap();
    let last = ct_bytes.len() - 1;
    ct_bytes[last] ^= 0xFF;
    tampered.ct = b64_encode(&ct_bytes);
    assert!(server
        .open_text("ws-event", &serde_json::to_string(&tampered).unwrap())
        .is_err());
}
