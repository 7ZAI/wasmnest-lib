//! 首连信任状态帧编解码：服务端 → 客户端的单条控制帧（长度前缀 + JSON）。
//!
//! ## 为何每条新连接无条件先收一帧（Decision 3 附带取舍）
//!
//! 双向信任态天然不对称（A 已信 B，但 B 可能已撤销对 A 的信任），若只在闸门
//! 拦截时才发状态帧，「谁该等帧」就依赖双方各自猜测对方信任态；统一为「握手
//! 完成 → 服务端必发一帧 → 客户端读帧分流」消除该歧义。代价是放弃 curl 等
//! 通用 TLS 工具直连调试——协议私有已在 ADR 0027 接受。
//!
//! 线格式：u32 BE 载荷长度 ‖ JSON 载荷。字段名与枚举变体名即 v1 线上契约，
//! 演进只允许追加字段/变体（[`PROTOCOL_VERSION`] 供接收端拒绝不认识的大版本）。
//!
//! 编解码函数只依赖 `AsyncRead` / `AsyncWrite` trait 与内存缓冲：单测以
//! `&[u8]`（实现 AsyncRead）/ `Vec<u8>`（实现 AsyncWrite）直接驱动，无需运行时。

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 控制帧协议版本 v1
pub const PROTOCOL_VERSION: u32 = 1;

/// 单帧载荷上限（64 KiB）
///
/// 状态帧合法载荷不足 200 字节；上限只为防御同网恶意节点发超长长度前缀
/// 诱导预分配耗尽内存，而非真实业务需求。
const MAX_FRAME_PAYLOAD_LEN: usize = 64 * 1024;

// ==================== 帧类型 ====================

/// 信任状态种类（线上契约 v1，变体名不可改名）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    /// 对端已信任本节点（或宿主刚接受了首连确认）：连接放行
    Accepted,
    /// 首连进入确认闸门，等待对端宿主应答（客户端继续等下一帧）
    PendingConfirmation,
    /// 宿主拒绝、超时或资源保护拒绝：连接即将被对端关闭
    Denied,
}

/// 信任状态控制帧：状态 + 所指节点
///
/// `node_id` 是状态所指对象（拨入方自身 ID）。客户端收到后必须校验其等于
/// 本节身份——不符说明对端状态机错乱，按 [`crate::error::PeerNetError::UnknownPeer`]
/// 处理，防止未来多路复用演进时把 A 的状态误投给 B。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStatusFrame {
    /// 协议版本（预留演进；接收端拒绝大于 [`PROTOCOL_VERSION`] 的版本）
    pub protocol_version: u32,
    /// 状态种类
    pub status: TrustStatus,
    /// 状态所指节点的 hex ID（64 位小写 hex）
    pub node_id: String,
}

impl TrustStatusFrame {
    /// 构造指向指定节点的 Accepted 帧
    pub fn accepted(node_id: &crate::identity::NodeId) -> Self {
        Self::new(TrustStatus::Accepted, node_id)
    }

    /// 构造指向指定节点的 PendingConfirmation 帧
    pub fn pending_confirmation(node_id: &crate::identity::NodeId) -> Self {
        Self::new(TrustStatus::PendingConfirmation, node_id)
    }

    /// 构造指向指定节点的 Denied 帧
    pub fn denied(node_id: &crate::identity::NodeId) -> Self {
        Self::new(TrustStatus::Denied, node_id)
    }

    fn new(status: TrustStatus, node_id: &crate::identity::NodeId) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            status,
            node_id: node_id.as_str().to_string(),
        }
    }
}

// ==================== 编解码 ====================

/// 写入一帧：u32 BE 长度前缀 + JSON 载荷，写毕 flush
pub async fn write_frame<W>(sink: &mut W, frame: &TrustStatusFrame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(frame)
        // 序列化失败意味着内部不变量破坏（帧结构不可能产生非法 JSON），按
        // InvalidData 上抛由调用方归入 ControlFrame 错误域
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "trust status frame payload {} exceeds cap {MAX_FRAME_PAYLOAD_LEN}",
                payload.len()
            ),
        ));
    }

    let len_prefix = u32::try_from(payload.len())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trust status frame payload does not fit u32",
            )
        })?
        .to_be_bytes();
    sink.write_all(&len_prefix).await?;
    sink.write_all(&payload).await?;
    sink.flush().await
}

/// 读取一帧：先读 u32 BE 长度，再定长读取并解析 JSON 载荷
///
/// 截断流（长度声明与实际字节不符）由 `read_exact` 的 UnexpectedEof 报告；
/// 零长度、超上限与非法 JSON 按 InvalidData 报告——三者都意味着对端不是
/// 本协议的对端或已被篡改，无重试价值。
pub async fn read_frame<R>(stream: &mut R) -> std::io::Result<TrustStatusFrame>
where
    R: AsyncRead + Unpin,
{
    let mut len_prefix = [0u8; 4];
    stream.read_exact(&mut len_prefix).await?;
    let payload_len = u32::from_be_bytes(len_prefix) as usize;
    if payload_len == 0 || payload_len > MAX_FRAME_PAYLOAD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("trust status frame length {payload_len} out of range 1..={MAX_FRAME_PAYLOAD_LEN}"),
        ));
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    let frame: TrustStatusFrame = serde_json::from_slice(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    if frame.protocol_version > PROTOCOL_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "trust status frame protocol version {} is newer than supported {PROTOCOL_VERSION}",
                frame.protocol_version
            ),
        ));
    }
    Ok(frame)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeId;

    fn sample_node_id(byte0: u8) -> NodeId {
        // 同一字节重复 32 次构成 64 位合法 hex，仅测试区分用
        let hex = format!("{byte0:02x}").repeat(32);
        NodeId::parse(&hex).expect("valid node id")
    }

    #[test]
    fn roundtrip_preserves_status_and_subject() {
        for status in [
            TrustStatusFrame::accepted(&sample_node_id(0x01)),
            TrustStatusFrame::pending_confirmation(&sample_node_id(0x02)),
            TrustStatusFrame::denied(&sample_node_id(0x03)),
        ] {
            let mut buf = Vec::new();
            futures_block_on(write_frame(&mut buf, &status))
                .expect("encode into memory buffer");
            let mut reader: &[u8] = &buf;
            let decoded = futures_block_on(read_frame(&mut reader));

            assert_eq!(decoded.expect("decode"), status);
            assert!(reader.is_empty(), "frame must be consumed exactly");
        }
    }

    #[test]
    fn truncated_stream_is_reported_not_hang() {
        let mut buf = Vec::new();
        futures_block_on(write_frame(
            &mut buf,
            &TrustStatusFrame::denied(&sample_node_id(0x04)),
        ))
        .expect("encode");

        // 截掉尾部若干字节：read_exact 必须报 UnexpectedEof 而非挂起/误解析
        let truncated = &buf[..buf.len() - 5];
        let mut reader: &[u8] = truncated;
        let err = futures_block_on(read_frame(&mut reader)).expect_err("truncated must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocation() {
        // 恶意长度前缀：4 GiB-1。必须在预分配前拒绝，防内存耗尽
        let mut reader: &[u8] = &u32::MAX.to_be_bytes();
        let err = futures_block_on(read_frame(&mut reader)).expect_err("oversize must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn garbage_payload_and_newer_protocol_are_rejected() {
        // 合法长度但非 JSON
        let mut reader: &[u8] = &[0, 0, 0, 3, b'a', b'b', b'c'];
        let err = futures_block_on(read_frame(&mut reader)).expect_err("garbage must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // 未来大版本：拒绝而非误读
        let future = TrustStatusFrame {
            protocol_version: PROTOCOL_VERSION + 1,
            status: TrustStatus::Accepted,
            node_id: sample_node_id(0x05).as_str().to_string(),
        };
        let mut buf = Vec::new();
        futures_block_on(write_frame(&mut buf, &future)).expect("encode future frame");
        let mut reader: &[u8] = &buf;
        let err = futures_block_on(read_frame(&mut reader)).expect_err("newer version must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// 无运行时驱动 async codec 的最小执行器
    ///
    /// 这些用例的 future 只含同步 IO（内存缓冲），单线程轮询即可完成；
    /// 不引入 dev-dependency 的完整 tokio 运行时，保持 codec 测试零环境依赖。
    fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop_raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                noop_raw_waker()
            }
            fn noop(_: *const ()) {}
            static VTABLE: RawWakerVTable =
                RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(std::ptr::null::<()>(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => panic!("in-memory io must not pend"),
            }
        }
    }
}
