//! `/wasmnest/relay-control/1` 线协议：分帧 + 请求/响应形状。
//!
//! 帧格式与穿透通道 `/wasmnest/tunnel/1` 同款：`u32be len | JSON`。选 JSON 而不是
//! protobuf 的理由是这个协议只承载「版本 / 模式 / 兑换」三条低频消息，可读性比
//! 字节效率重要得多（排查现场用 `xxd` 就能看懂）。
//!
//! 版本纪律：协议名里的 `1` 是**线上主版本**，只允许新增协议名（`/2`），不允许
//! 原地改语义。控制面是可选面——老的客户端不实现它也能正常用中继，因此这里不做
//! 版本协商，只回报本端版本供客户端提示。

use serde::{Deserialize, Serialize};

/// 协议命名空间（与对等栈的 `/wasmnest/` 前缀一致）
pub const PROTOCOL_NAMESPACE: &str = "/wasmnest/";
/// 控制协议名（主版本 1）
pub const CONTROL_PROTOCOL: &str = "/wasmnest/relay-control/1";
/// 控制协议的载荷版本
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
/// 单帧上限（控制消息只有几百字节；4 KiB 足够防呆，且挡住恶意大帧占内存）
pub const MAX_FRAME_BYTES: usize = 4096;

/// 控制请求
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ControlRequest {
    /// 查询版本 / 模式 / 本 peer 是否在白名单内
    Hello {
        /// 客户端支持的载荷版本
        v: u32,
    },
    /// 用 enrollment token 兑换白名单席位（仅 `allowlist` 模式有意义）
    Enroll {
        /// 客户端支持的载荷版本
        v: u32,
        /// token 明文（Noise 内层传输，中继侧只存摘要）
        token: String,
    },
}

impl ControlRequest {
    /// 载荷版本
    pub fn version(&self) -> u32 {
        match self {
            Self::Hello { v } | Self::Enroll { v, .. } => *v,
        }
    }
}

/// 控制响应（成功 / 失败共用一张表，未用字段不序列化）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    /// 中继侧载荷版本（客户端据此判断是否需要提示升级）
    pub v: u32,
    /// 是否成功
    pub ok: bool,
    /// 失败原因词汇（`invalid-request` / `invalid-token` / `unsupported-version`）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    /// 中继版本（`hello` 回带）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub relay_version: Option<String>,
    /// 中继 PeerId（`hello` 回带；客户端可据此校验导入地址）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub peer_id: Option<String>,
    /// 准入模式（`hello` 回带）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access: Option<String>,
    /// 本 peer 当前是否可预留（`hello` 回带）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allowed: Option<bool>,
    /// 是否完成 enrollment（`enroll` 回带）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enrolled: Option<bool>,
}

impl ControlResponse {
    /// 成功响应骨架
    pub fn ok() -> Self {
        Self {
            v: CONTROL_PROTOCOL_VERSION,
            ok: true,
            error: None,
            relay_version: None,
            peer_id: None,
            access: None,
            allowed: None,
            enrolled: None,
        }
    }

    /// 失败响应（原因词汇固定，便于客户端分支处理）
    pub fn error(reason: &str) -> Self {
        Self {
            v: CONTROL_PROTOCOL_VERSION,
            ok: false,
            error: Some(reason.to_string()),
            relay_version: None,
            peer_id: None,
            access: None,
            allowed: None,
            enrolled: None,
        }
    }
}

/// 帧编码：`u32be len | payload`
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            size: payload.len(),
        });
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 从 4 字节头解析帧长
pub fn decode_frame_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { size: len });
    }
    if len == 0 {
        return Err(FrameError::Empty);
    }
    Ok(len)
}

/// 帧错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// 帧超过 [`MAX_FRAME_BYTES`]
    TooLarge {
        /// 实际声明的长度
        size: usize,
    },
    /// 零长帧（非法：请求/响应都是非空 JSON）
    Empty,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { size } => {
                write!(f, "帧过大（{size} > {MAX_FRAME_BYTES} 字节）")
            }
            Self::Empty => write!(f, "零长帧"),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 协议名在命名空间内且带版本段() {
        assert!(CONTROL_PROTOCOL.starts_with(PROTOCOL_NAMESPACE));
        let rest = &CONTROL_PROTOCOL[PROTOCOL_NAMESPACE.len()..];
        let (domain, version) = rest.rsplit_once('/').expect("应有版本段");
        assert_eq!(domain, "relay-control");
        assert_eq!(version, "1");
    }

    #[test]
    fn 帧编码为_u32be_长度前缀() {
        let payload = br#"{"op":"hello"}"#;
        let frame = encode_frame(payload).expect("编码");
        assert_eq!(&frame[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(&frame[4..], payload);
        assert_eq!(payload.len(), 14);
    }

    #[test]
    fn 帧长解码拒绝超限与零长() {
        assert_eq!(decode_frame_len(16u32.to_be_bytes()).expect("合法"), 16);
        assert_eq!(
            decode_frame_len(u32::MAX.to_be_bytes()),
            Err(FrameError::TooLarge {
                size: u32::MAX as usize
            })
        );
        assert_eq!(decode_frame_len(0u32.to_be_bytes()), Err(FrameError::Empty));
    }

    #[test]
    fn 超限载荷拒绝编码() {
        let payload = vec![b'x'; MAX_FRAME_BYTES + 1];
        assert!(matches!(
            encode_frame(&payload),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn 请求以_op_标签序列化且拒绝未知字段() {
        let hello = serde_json::to_string(&ControlRequest::Hello { v: 1 }).expect("序列化");
        assert_eq!(hello, r#"{"op":"hello","v":1}"#);

        let enroll = serde_json::to_string(&ControlRequest::Enroll {
            v: 1,
            token: "ab".into(),
        })
        .expect("序列化");
        assert_eq!(enroll, r#"{"op":"enroll","v":1,"token":"ab"}"#);

        assert!(
            serde_json::from_str::<ControlRequest>(r#"{"op":"hello","v":1,"x":2}"#).is_err(),
            "未知字段应拒绝"
        );
        assert!(
            serde_json::from_str::<ControlRequest>(r#"{"op":"nope","v":1}"#).is_err(),
            "未知 op 应拒绝"
        );
    }

    #[test]
    fn 响应只序列化已填字段() {
        let mut response = ControlResponse::ok();
        response.peer_id = Some("12D3KooW".into());
        let json = serde_json::to_string(&response).expect("序列化");
        assert_eq!(json, r#"{"v":1,"ok":true,"peer_id":"12D3KooW"}"#);

        let failed = ControlResponse::error("invalid-token");
        let json = serde_json::to_string(&failed).expect("序列化");
        assert_eq!(json, r#"{"v":1,"ok":false,"error":"invalid-token"}"#);
    }

    #[test]
    fn 请求版本可从两种形态取出() {
        assert_eq!(ControlRequest::Hello { v: 1 }.version(), 1);
        assert_eq!(
            ControlRequest::Enroll {
                v: 1,
                token: "x".into()
            }
            .version(),
            1
        );
    }
}
