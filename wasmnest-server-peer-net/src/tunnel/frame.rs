//! `/wasmnest/tunnel/1` 首帧与响应帧线协议。
//!
//! 帧形状：`u32be len | JSON`；首帧 `{v:1, port, kind:"http"|"tcp", ticket?}`，
//! 响应 `{ok:true, caller:"peer", peerNodeId}`（失败时 `ok:false` + `error` 错误码）。
//! 响应之后是裸字节双向 pipe，本模块不再参与。
//!
//! 长度上限是内存防线：未匹配 peer 在拨入后即可发首帧，不允许用超大长度前缀
//! 触发分配。错误原因只写类别与长度，不回显票据明文。

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tunnel::{Result, TunnelError, CODE_INVALID_FRAME};

pub const PROTOCOL_VERSION: u32 = 1;
pub const LEN_PREFIX_BYTES: usize = 4;
pub const MAX_FRAME_BYTES: usize = 4096;
pub const MAX_TICKET_CHARS: usize = 512;
pub const CALLER_PEER: &str = "peer";

/// 通道种类：`http` 走对等 HTTP/WS 面，`tcp` 只连回环目标端口
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelKind {
    Http,
    Tcp,
}

impl TunnelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
        }
    }

    /// WIT 边界层 / 配置解析入口：只认 `http` 与 `tcp`，其余显性拒绝
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "http" => Some(Self::Http),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }
}

/// 客户端首帧（每条 TCP 连接一条流，故每条流都必须重新裁决）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelHello {
    pub v: u32,
    pub port: u16,
    pub kind: TunnelKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

impl TunnelHello {
    pub fn new(port: u16, kind: TunnelKind, ticket: Option<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            port,
            kind,
            ticket,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.v != PROTOCOL_VERSION {
            return Err(TunnelError::new(
                CODE_INVALID_FRAME,
                format!("不支持的首帧版本 {}", self.v),
            ));
        }
        if self.port == 0 {
            return Err(TunnelError::new(CODE_INVALID_FRAME, "目标端口为 0"));
        }
        if let Some(ticket) = &self.ticket {
            if ticket.is_empty() || ticket.chars().count() > MAX_TICKET_CHARS {
                return Err(TunnelError::new(
                    CODE_INVALID_FRAME,
                    format!("票据长度非法：{}（上限 {MAX_TICKET_CHARS}）", ticket.chars().count()),
                ));
            }
            if ticket.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(TunnelError::new(CODE_INVALID_FRAME, "票据含控制字符"));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let payload = serde_json::to_vec(self)
            .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("首帧序列化失败：{e}")))?;
        encode_frame(&payload)
    }

    pub fn decode(frame: &[u8]) -> Result<Self> {
        let hello: Self = serde_json::from_slice(decode_frame(frame)?)
            .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("首帧反序列化失败：{e}")))?;
        hello.validate()?;
        Ok(hello)
    }

    /// 从流上读一帧：`read_frame` 已剥掉长度前缀，这里直接反序列化 payload
    pub async fn read_from<R: AsyncRead + Unpin>(io: &mut R) -> Result<Self> {
        let payload = read_frame(io).await?;
        let hello: Self = serde_json::from_slice(&payload)
            .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("首帧反序列化失败：{e}")))?;
        hello.validate()?;
        Ok(hello)
    }
}

/// 服务端首帧响应（无论成功失败，`caller` 恒为 `peer`）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelReply {
    pub ok: bool,
    pub caller: String,
    #[serde(rename = "peerNodeId", default, skip_serializing_if = "Option::is_none")]
    pub peer_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TunnelReply {
    /// 已验证的 node id 由隧道层给出；配对窗口允许为 `None`
    pub fn accepted(peer_node_id: Option<String>) -> Self {
        Self {
            ok: true,
            caller: CALLER_PEER.to_string(),
            peer_node_id,
            error: None,
        }
    }

    /// 只回错误码，不回显票据 / 首帧内容
    pub fn rejected(code: &'static str) -> Self {
        Self {
            ok: false,
            caller: CALLER_PEER.to_string(),
            peer_node_id: None,
            error: Some(code.to_string()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload = serde_json::to_vec(self)
            .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("响应序列化失败：{e}")))?;
        encode_frame(&payload)
    }

    pub fn decode(frame: &[u8]) -> Result<Self> {
        serde_json::from_slice(decode_frame(frame)?)
            .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("响应反序列化失败：{e}")))
    }
}

/// 加 `u32be` 长度前缀
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(TunnelError::new(
            CODE_INVALID_FRAME,
            format!("载荷长度 {} 超出 1..={MAX_FRAME_BYTES}", payload.len()),
        ));
    }
    let mut frame = Vec::with_capacity(LEN_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// 校验并剥掉长度前缀；尾部多余字节一律拒绝（避免帧边界模糊）
pub fn decode_frame(frame: &[u8]) -> Result<&[u8]> {
    if frame.len() < LEN_PREFIX_BYTES {
        return Err(TunnelError::new(CODE_INVALID_FRAME, "缺长度前缀"));
    }
    let len = u32::from_be_bytes(frame[..LEN_PREFIX_BYTES].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(TunnelError::new(
            CODE_INVALID_FRAME,
            format!("声明长度 {len} 超出 1..={MAX_FRAME_BYTES}"),
        ));
    }
    let payload = &frame[LEN_PREFIX_BYTES..];
    if payload.len() != len {
        return Err(TunnelError::new(
            CODE_INVALID_FRAME,
            format!("声明长度 {len} 与实际 {} 不符", payload.len()),
        ));
    }
    Ok(payload)
}

pub async fn read_frame<R: AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>> {
    let mut prefix = [0u8; LEN_PREFIX_BYTES];
    io.read_exact(&mut prefix)
        .await
        .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("读取长度前缀失败：{:?}", e.kind())))?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(TunnelError::new(
            CODE_INVALID_FRAME,
            format!("声明长度 {len} 超出 1..={MAX_FRAME_BYTES}"),
        ));
    }
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload)
        .await
        .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("读取载荷失败：{:?}", e.kind())))?;
    Ok(payload)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(io: &mut W, payload: &[u8]) -> Result<()> {
    let frame = encode_frame(payload)?;
    io.write_all(&frame)
        .await
        .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("写帧失败：{:?}", e.kind())))
}

/// 写响应帧（成功 / 拒绝都走同一形状）
pub async fn write_reply<W: AsyncWrite + Unpin>(io: &mut W, reply: &TunnelReply) -> Result<()> {
    let frame = reply.encode()?;
    io.write_all(&frame)
        .await
        .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("写响应失败：{:?}", e.kind())))
}

/// 读响应帧；只解析形状，不采信响应之外的任何客户端字段
pub async fn read_reply<R: AsyncRead + Unpin>(io: &mut R) -> Result<TunnelReply> {
    let payload = read_frame(io).await?;
    serde_json::from_slice(&payload).map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("响应反序列化失败：{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip_keeps_wire_shape() {
        let hello = TunnelHello::new(8765, TunnelKind::Http, None);
        let frame = hello.encode().unwrap();
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        assert_eq!(TunnelHello::decode(&frame).unwrap(), hello);
        let json = String::from_utf8_lossy(decode_frame(&frame).unwrap());
        assert!(json.contains("\"v\":1"));
        assert!(json.contains("\"kind\":\"http\""));
        assert!(!json.contains("ticket"), "无票据时字段必须省略");

        let paired = TunnelHello::new(8765, TunnelKind::Http, Some("tk-1".into()));
        assert_eq!(TunnelHello::decode(&paired.encode().unwrap()).unwrap(), paired);
    }

    #[test]
    fn malformed_frames_are_rejected_fail_visible() {
        assert!(decode_frame(&[0, 0]).is_err(), "缺长度前缀");
        assert!(decode_frame(&[0, 0, 0, 2, b'{']).is_err(), "长度与载荷不符");
        assert!(decode_frame(&[0, 0, 0, 0]).is_err(), "零长度");
        assert!(decode_frame(&[0x00, 0x10, 0x00, 0x00]).is_err(), "超上限声明");
        assert!(decode_frame(&[0, 0, 0, 2, b'{', b'}', b'x']).is_err(), "尾部多余字节");

        let bad_version = br#"{"v":2,"port":8765,"kind":"http"}"#;
        assert!(TunnelHello::decode(&encode_frame(bad_version).unwrap()).is_err());
        let bad_kind = br#"{"v":1,"port":8765,"kind":"raw"}"#;
        assert!(TunnelHello::decode(&encode_frame(bad_kind).unwrap()).is_err());
        let zero_port = br#"{"v":1,"port":0,"kind":"tcp"}"#;
        assert!(TunnelHello::decode(&encode_frame(zero_port).unwrap()).is_err());
    }

    #[test]
    fn ticket_shape_is_bounded_and_never_echoed() {
        let long = "a".repeat(MAX_TICKET_CHARS + 1);
        let err = TunnelHello::new(8765, TunnelKind::Http, Some(long))
            .encode()
            .unwrap_err();
        assert_eq!(err.code, CODE_INVALID_FRAME);
        assert!(!err.detail.contains('a'), "错误原因不得回显票据内容");

        let control = TunnelHello::new(8765, TunnelKind::Http, Some("tk\n1".into()));
        assert!(control.encode().is_err());
    }

    #[test]
    fn reply_is_always_peer_caller() {
        let ok = TunnelReply::accepted(Some("node-1".into()));
        let json = String::from_utf8_lossy(decode_frame(&ok.encode().unwrap()).unwrap()).to_string();
        assert!(json.contains("\"caller\":\"peer\""));
        assert!(json.contains("\"peerNodeId\":\"node-1\""));
        assert_eq!(TunnelReply::decode(&ok.encode().unwrap()).unwrap(), ok);

        let rejected = TunnelReply::rejected(crate::tunnel::CODE_NOT_MATCHED);
        assert!(!rejected.ok);
        assert_eq!(rejected.caller, CALLER_PEER);
        assert_eq!(rejected.error.as_deref(), Some("not-matched"));
        assert!(rejected.peer_node_id.is_none());
    }

    #[tokio::test]
    async fn async_frame_io_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let hello = TunnelHello::new(8765, TunnelKind::Tcp, Some("tk-2".into()));
        write_frame(&mut a, decode_frame(&hello.encode().unwrap()).unwrap())
            .await
            .unwrap();
        let payload = read_frame(&mut b).await.unwrap();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        assert_eq!(TunnelHello::decode(&frame).unwrap(), hello);
    }

    /// 生产路径锁：服务端经 `read_from` 读客户端 `encode()` 的完整帧，不得把
    /// 已剥掉长度前缀的 payload 再当完整帧解码
    #[tokio::test]
    async fn read_from_accepts_wire_hello_and_reply() {
        let (mut a, mut b) = tokio::io::duplex(512);
        let hello = TunnelHello::new(8765, TunnelKind::Http, Some("tk-3".into()));
        let frame = hello.encode().unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut a, &frame).await.unwrap();
        assert_eq!(TunnelHello::read_from(&mut b).await.unwrap(), hello);

        let reply = TunnelReply::accepted(Some("node-1".into()));
        tokio::io::AsyncWriteExt::write_all(&mut a, &reply.encode().unwrap())
            .await
            .unwrap();
        assert_eq!(read_reply(&mut b).await.unwrap(), reply);
    }
}
