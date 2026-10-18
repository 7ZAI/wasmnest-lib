//! 传输会话线协议：控制帧（JSON）与数据块帧的编解码。
//!
//! 线格式沿用 `frame.rs` 首连状态帧先例：u32 BE 长度前缀 + 载荷，但增加
//! 单字节帧种类（kind）以在同一条连接上复用控制面与数据面：
//!
//! ```text
//! [u32 BE payload_len][u8 kind][payload]
//! ```
//!
//! - kind = `0x01`：控制帧，payload 为 [`TransferFrame`] 的 JSON；
//! - kind = `0x02`：数据块帧，payload 为原始文件字节（无内嵌结构——顺序
//!   语义由「StartFile 声明起点、FileDone 确认终点」的控制帧承担，接收端
//!   按剩余字节数定长读取即可，不为每块付 JSON 编解码税）。
//!
//! 编解码只依赖 `AsyncRead` / `AsyncWrite` trait 与内存缓冲：单测以
//! `&[u8]` / `Vec<u8>` 直接驱动，无需运行时。

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::batch::{DirEntry, FileMeta, RejectReason};

/// 传输协议版本 v1（与首连帧各自独立演进）
pub const TRANSFER_PROTOCOL_VERSION: u32 = 1;

/// 控制帧 kind 字节
pub const KIND_CONTROL: u8 = 0x01;
/// 数据块帧 kind 字节
pub const KIND_DATA: u8 = 0x02;

/// 控制帧载荷上限（256 KiB）：Offer 清单可能很长（万级文件批），仍远小于
/// 该上限；上限只为防御恶意长度前缀诱导预分配耗尽内存
const MAX_CONTROL_PAYLOAD_LEN: usize = 256 * 1024;

/// 数据块载荷上限（4 MiB）：防御性上限；引擎实际分块大小由配置决定且更小
pub const MAX_DATA_CHUNK_LEN: usize = 4 * 1024 * 1024;

// ==================== 控制帧 ====================

/// 传输控制帧（serde internally tagged，`type` 字段即线上契约）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransferFrame {
    /// 发送端 → 接收端：批协商请求（一次发送动作的全部文件清单）
    Offer {
        /// 协议版本（接收端拒绝大于自身支持的版本）
        protocol_version: u32,
        /// 批 ID（发送方生成）
        batch_id: String,
        /// 批内文件清单（相对路径 + 大小）
        files: Vec<FileMeta>,
        /// 批内文件总大小（字节）
        total_size: u64,
        // ==================== 应用层加密请求头（自定义头协商）====================
        /// 本批数据块为 AES-256-GCM 密文；旧版对端反序列化缺省 false（向后兼容）。
        /// true 时 enc_pub_key 必须同时携带。
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        encrypted: bool,
        /// 发送方临时 X25519 公钥（64 字符小写 hex）；仅 encrypted=true 时携带，
        /// 接收方用它 + 自己的临时私钥派生会话密钥完成自动解密
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enc_pub_key: Option<String>,
    },
    /// 接收端 → 发送端：批协商应答
    Decision {
        /// 是否放行
        accepted: bool,
        /// 拒绝原因（accepted=true 时省略）
        reason: Option<RejectReason>,
        // ==================== 加密协商回执头 ====================
        /// 接收方临时 X25519 公钥（hex）：对加密 Offer 放行时必须携带——
        /// 双头齐全即双方约定本会话数据面加密。旧版对端不识别加密头、
        /// 回包无此字段 → 发送端据此 fail-fast，禁止静默明文降级
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enc_pub_key: Option<String>,
    },
    /// 接收端 → 发送端：指示从某文件某偏移开始推流
    ///
    /// `offset` 即「接收端已写字节」（断点真源，issue 06 续传在此生效）：
    /// 首次为 0，中断重试时为 .part 已落盘字节数。发送端必须从该偏移起读，
    /// 不允许自行从头开始。
    StartFile {
        /// 批内文件下标（按 Offer.files 顺序）
        index: u32,
        /// 接收端已写偏移（字节）
        offset: u64,
    },
    /// 接收端 → 发送端：单个文件已完整落位（.part 已原子 rename）
    FileDone {
        /// 批内文件下标
        index: u32,
    },
    /// 接收端 → 发送端：批内全部文件完成（终态帧）
    BatchDone {},
    /// 任一方向 → 对端：取消进行中的传输
    ///
    /// 收到方据此把任务落 Cancelled{by_peer} 终态并停止读写；发送方保留
    /// 接收端已写偏移供后续续传（issue 06），故接收端不删除 .part。
    Cancel {
        /// 取消发起方（sender / receiver，kebab 由 rename_all 保证）
        by: CancelOrigin,
    },
    /// 浏览方 → 暴露方：列共享目录（issue 07；单连接单请求，响应后即收尾）
    ///
    /// `rel_path` 为目录内相对路径（空串 = 目录根）；暴露端校验信任（结构性
    /// 由连接闸门保证）、路径安全与条目存在性，失败以 [`TransferFrame::Decision`]
    /// 回 not-found / read-failed。
    BrowseRequest {
        /// 协议版本（暴露端拒绝大于自身支持的版本，语义同 Offer）
        protocol_version: u32,
        /// 共享目录 ID（注册表分配）
        dir_id: String,
        /// 目录内相对路径（`/` 分隔，空串 = 根）
        rel_path: String,
    },
    /// 暴露方 → 浏览方：列目录应答（条目已按「目录优先、按名排序」排好）
    BrowseResponse {
        /// 子条目列表
        entries: Vec<DirEntry>,
        /// 列表可能不全的提示位：暴露端为 Android 且可能因存储权限过滤了条目
        /// （issue 11，沿用既有 notice 语义）。旧对端不携带此字段时反序列化
        /// 取缺省 false，前后版本兼容。
        #[serde(default)]
        filtered: bool,
    },
    /// 浏览方 → 暴露方：拉取共享目录内单个文件（issue 07）
    ///
    /// 应答成功即进入标准推送数据面：暴露端以本请求的文件发 [`TransferFrame::Offer`]，
    /// 随后 StartFile/Data/FileDone/BatchDone 与 push 完全同构（浏览端为接收角色，
    /// 策略恒放行——拉取是用户主动发起的获取，不再走询问弹窗）。
    PullRequest {
        /// 协议版本（语义同上）
        protocol_version: u32,
        /// 共享目录 ID
        dir_id: String,
        /// 文件相对路径（`/` 分隔，必须指向文件而非目录）
        rel_path: String,
    },
    /// 浏览方 → 暴露方：列共享根清单（issue 11）
    ///
    /// 浏览方无从得知对端注册了哪些 dir_id，先取根清单再逐根 BrowseRequest。
    /// 单请求会话（响应后即收尾），信任门禁与 Browse 相同（结构性由连接闸门保证）。
    RootsRequest {
        /// 协议版本（语义同 Offer）
        protocol_version: u32,
    },
    /// 暴露方 → 浏览方：共享根清单应答（issue 11；按注册序，含内置免授权条目）
    RootsResponse {
        /// 暴露中的共享根（id 供后续 Browse/Pull 寻址，name 为展示名）
        dirs: Vec<crate::shared::SharedRootMeta>,
    },
    /// 任一侧 → 对端：暂停本批数据面（pause 门控，不关连接、不弃断点）
    ///
    /// 语义（双端同步部署，见 file-transfer 暂停/恢复协议）：
    /// - 数据供方（发送端 / pull serve）收到 Pause 后停止推流（门控自身写），
    ///   连接保持；数据消费方（接收端）收到 Pause 后任务置 paused 并静待，
    ///   不停止读（对端已停发，读循环自然空闲）——恢复必须先到消费方。
    /// - 恢复以 [`TransferFrame::Resume`] 同向续流；取消仍走 \[`TransferFrame::Cancel`]。
    /// - 暂停/恢复可由任一侧发起（暂停者自行门控己方数据面并通知对端），
    ///   对端按本帧同步任务状态；两端各自展示 paused/running。
    Pause {
        /// 批 ID（与 Offer/PullServed 同源）
        batch_id: String,
    },
    /// 任一侧 → 对端：恢复此前 [`TransferFrame::Pause`] 暂停的批
    Resume {
        /// 批 ID（与 Offer/PullServed 同源）
        batch_id: String,
    },
}

/// 取消发起方（wire snake_case）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelOrigin {
    /// 发送方取消
    Sender,
    /// 接收方取消
    Receiver,
}

// ==================== 编解码 ====================

/// 读出的一帧（控制帧已解析为结构，数据块保持原始字节）
#[derive(Debug, Clone, PartialEq)]
pub enum IncomingFrame {
    /// 控制帧（JSON 已反序列化）
    Control(Box<TransferFrame>),
    /// 数据块帧（原始文件字节）
    Data(Vec<u8>),
}

/// 写入一帧：u32 BE 长度前缀 + kind 字节 + 载荷，写毕 flush
async fn write_raw<W>(sink: &mut W, kind: u8, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body_len = payload
        .len()
        .checked_add(1)
        .filter(|len| *len <= u32::MAX as usize)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transfer frame payload does not fit u32",
            )
        })?;
    sink.write_all(&(body_len as u32).to_be_bytes()).await?;
    sink.write_all(&[kind]).await?;
    sink.write_all(payload).await?;
    sink.flush().await
}

/// 序列化并写入一条控制帧
pub async fn write_control<W>(sink: &mut W, frame: &TransferFrame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(frame)
        // 帧结构不可能产生非法 JSON：失败即内部不变量破坏，按 InvalidData 上抛
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if payload.len() > MAX_CONTROL_PAYLOAD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "transfer control frame payload {} exceeds cap {MAX_CONTROL_PAYLOAD_LEN}",
                payload.len()
            ),
        ));
    }
    write_raw(sink, KIND_CONTROL, &payload).await
}

/// 写入一个数据块帧（payload 为原始文件字节）
pub async fn write_data<W>(sink: &mut W, chunk: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if chunk.len() > MAX_DATA_CHUNK_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "transfer data chunk {} exceeds cap {MAX_DATA_CHUNK_LEN}",
                chunk.len()
            ),
        ));
    }
    write_raw(sink, KIND_DATA, chunk).await
}

/// 读取一帧头（长度 + kind），返回载荷长度供调用方定长读取
///
/// 零长度、超上限的声明在预分配前拒绝——恶意长度前缀不得诱导内存耗尽。
async fn read_frame_header<R>(stream: &mut R) -> std::io::Result<(u8, usize)>
where
    R: AsyncRead + Unpin,
{
    let mut len_prefix = [0u8; 4];
    stream.read_exact(&mut len_prefix).await?;
    let body_len = u32::from_be_bytes(len_prefix) as usize;
    if body_len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer frame length must not be zero",
        ));
    }

    let mut kind_byte = [0u8; 1];
    stream.read_exact(&mut kind_byte).await?;

    let cap = match kind_byte[0] {
        KIND_CONTROL => MAX_CONTROL_PAYLOAD_LEN,
        KIND_DATA => MAX_DATA_CHUNK_LEN,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown transfer frame kind {other:#04x}"),
            ))
        }
    };
    let payload_len = body_len - 1;
    if payload_len > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("transfer frame payload {payload_len} exceeds kind cap {cap}"),
        ));
    }
    Ok((kind_byte[0], payload_len))
}

/// 读取一条控制帧并解析（供明确只期待控制的场景；数据块到达时报错）
pub async fn read_control<R>(stream: &mut R) -> std::io::Result<TransferFrame>
where
    R: AsyncRead + Unpin,
{
    match read_frame(stream).await? {
        IncomingFrame::Control(frame) => Ok(*frame),
        IncomingFrame::Data(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected data frame where control frame was required",
        )),
    }
}

/// 读取一帧：先头后载荷，控制帧就地反序列化
///
/// 截断流（长度声明与实际字节不符）由 `read_exact` 的 UnexpectedEof 报告；
/// 非法 JSON 按 InvalidData 报告——都意味着对端不是本协议的对端或已被篡改，
/// 无重试价值。
pub async fn read_frame<R>(stream: &mut R) -> std::io::Result<IncomingFrame>
where
    R: AsyncRead + Unpin,
{
    let (kind, payload_len) = read_frame_header(stream).await?;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    match kind {
        KIND_CONTROL => {
            let frame: TransferFrame = serde_json::from_slice(&payload)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(IncomingFrame::Control(Box::new(frame)))
        }
        KIND_DATA => Ok(IncomingFrame::Data(payload)),
        _ => unreachable!("read_frame_header rejects unknown kinds"),
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::batch::FileMeta;

    fn sample_offer() -> TransferFrame {
        TransferFrame::Offer {
            protocol_version: TRANSFER_PROTOCOL_VERSION,
            batch_id: "b-42".to_string(),
            files: vec![FileMeta::new("a.txt", 11), FileMeta::new("d/b.bin", 7)],
            total_size: 18,
            encrypted: false,
            enc_pub_key: None,
        }
    }

    /// 无运行时驱动 async codec 的最小执行器（frame.rs 同款惯例：内存 IO
    /// 的 future 单线程轮询即可完成，不为 codec 测试引入完整 tokio 运行时）
    fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop_raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                noop_raw_waker()
            }
            fn noop(_: *const ()) {}
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
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

    #[test]
    fn control_frames_roundtrip_exactly() {
        let frames = [
            sample_offer(),
            TransferFrame::Decision {
                accepted: false,
                reason: Some(RejectReason::Timeout),
                enc_pub_key: None,
            },
            TransferFrame::Decision {
                accepted: true,
                reason: None,
                enc_pub_key: None,
            },
            TransferFrame::StartFile { index: 1, offset: 4096 },
            TransferFrame::FileDone { index: 0 },
            TransferFrame::BatchDone {},
            TransferFrame::Cancel {
                by: CancelOrigin::Receiver,
            },
            TransferFrame::BrowseRequest {
                protocol_version: TRANSFER_PROTOCOL_VERSION,
                dir_id: "d-1".to_string(),
                rel_path: "sub/dir".to_string(),
            },
            TransferFrame::BrowseResponse {
                entries: vec![
                    DirEntry::new("docs", true, 0),
                    DirEntry::new("a.txt", false, 3),
                ],
                filtered: true,
            },
            TransferFrame::PullRequest {
                protocol_version: TRANSFER_PROTOCOL_VERSION,
                dir_id: "d-1".to_string(),
                rel_path: "a.txt".to_string(),
            },
            TransferFrame::RootsRequest {
                protocol_version: TRANSFER_PROTOCOL_VERSION,
            },
            TransferFrame::RootsResponse {
                dirs: vec![
                    crate::shared::SharedRootMeta {
                        id: "r-1".to_string(),
                        name: "docs".to_string(),
                    },
                    crate::shared::SharedRootMeta {
                        id: "r-2".to_string(),
                        name: "downloads".to_string(),
                    },
                ],
            },
        ];
        for frame in frames {
            let mut buf = Vec::new();
            futures_block_on(write_control(&mut buf, &frame)).expect("encode");
            let mut reader: &[u8] = &buf;
            let decoded = futures_block_on(read_frame(&mut reader));
            assert_eq!(decoded.expect("decode"), IncomingFrame::Control(Box::new(frame)));
            assert!(reader.is_empty(), "frame must be consumed exactly");
        }
    }

    #[test]
    fn data_chunks_roundtrip_as_raw_bytes() {
        // 数据块载荷含任意字节（含 kind 值本身），确保无转义/歧义假设
        let chunk = [0x01u8, 0x02, 0x00, 0xFF, 0xAB];
        let mut buf = Vec::new();
        futures_block_on(write_data(&mut buf, &chunk)).expect("encode chunk");

        let mut reader: &[u8] = &buf;
        let decoded = futures_block_on(read_frame(&mut reader));
        assert_eq!(decoded.expect("decode"), IncomingFrame::Data(chunk.to_vec()));
        assert!(reader.is_empty());
    }

    #[test]
    fn control_and_data_interleave_in_one_stream() {
        let mut buf = Vec::new();
        futures_block_on(async {
            write_control(&mut buf, &sample_offer()).await.expect("offer");
            write_data(&mut buf, b"hello").await.expect("chunk");
            write_control(
                &mut buf,
                &TransferFrame::StartFile { index: 0, offset: 5 },
            )
            .await
            .expect("start");
        });

        let mut reader: &[u8] = &buf;
        let first = futures_block_on(read_frame(&mut reader)).expect("first");
        assert_eq!(
            first,
            IncomingFrame::Control(Box::new(sample_offer()))
        );
        let second = futures_block_on(read_frame(&mut reader)).expect("second");
        assert_eq!(second, IncomingFrame::Data(b"hello".to_vec()));
        let third = futures_block_on(read_frame(&mut reader)).expect("third");
        assert!(matches!(
            third,
            IncomingFrame::Control(boxed)
                if matches!(*boxed, TransferFrame::StartFile { index: 0, offset: 5 })
        ));
    }

    #[test]
    fn wire_tag_names_are_snake_locked() {
        // 线上契约逐字锁定：变体名即 type 字段值，两端必须一致
        let json = serde_json::to_string(&TransferFrame::BatchDone {}).expect("serde");
        assert_eq!(json, r#"{"type":"batch_done"}"#);

        let cancel = serde_json::to_string(&CancelOrigin::Sender).expect("serde");
        assert_eq!(cancel, r#""sender""#);

        // issue 07 浏览/拉取帧的线上形状
        let browse = serde_json::to_string(&TransferFrame::BrowseRequest {
            protocol_version: 1,
            dir_id: "d".to_string(),
            rel_path: String::new(),
        })
        .expect("serde");
        assert!(browse.starts_with(r#"{"type":"browse_request""#), "{browse}");

        let pull = serde_json::to_string(&TransferFrame::PullRequest {
            protocol_version: 1,
            dir_id: "d".to_string(),
            rel_path: "a.txt".to_string(),
        })
        .expect("serde");
        assert!(pull.starts_with(r#"{"type":"pull_request""#), "{pull}");
    }

    #[test]
    fn truncated_stream_is_reported_not_hang() {
        let mut buf = Vec::new();
        futures_block_on(write_control(
            &mut buf,
            &TransferFrame::FileDone { index: 3 },
        ))
        .expect("encode");
        let truncated = &buf[..buf.len() - 2];
        let mut reader: &[u8] = truncated;
        let err = futures_block_on(read_frame(&mut reader)).expect_err("truncated must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocation() {
        // 恶意长度前缀（4 GiB-1）+ 合法 kind 字节：载荷上限校验必须发生在
        // 预分配前，防内存耗尽
        let mut reader: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, KIND_CONTROL];
        let err = futures_block_on(read_frame(&mut reader)).expect_err("oversize must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn zero_length_unknown_kind_and_garbage_json_are_rejected() {
        // 零长度帧
        let mut reader: &[u8] = &[0, 0, 0, 0];
        let err = futures_block_on(read_frame(&mut reader)).expect_err("zero must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // 未知 kind
        let mut reader: &[u8] = &[0, 0, 0, 2, 0x7F];
        let err = futures_block_on(read_frame(&mut reader)).expect_err("unknown kind must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // 合法长度但非 JSON 控制载荷
        let mut reader: &[u8] = &[0, 0, 0, 4, KIND_CONTROL, b'a', b'b', b'c'];
        let err = futures_block_on(read_frame(&mut reader)).expect_err("garbage must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn future_protocol_version_is_carried_not_parsed_away() {
        // 版本字段是 Offer 载荷的一部分：接收端引擎负责按版本分流拒绝，
        // 编解码层保证字段原样往返即可
        let offer = TransferFrame::Offer {
            protocol_version: TRANSFER_PROTOCOL_VERSION + 9,
            batch_id: "b-future".to_string(),
            files: vec![],
            total_size: 0,
            encrypted: false,
            enc_pub_key: None,
        };
        let json = serde_json::to_string(&offer).expect("serde");
        assert!(json.contains(r#""protocol_version":10"#));
    }

    /// 加密请求头线上形状：缺省字段不出现（旧对端零感知），开启时逐字锁定
    #[test]
    fn encryption_header_wire_format() {
        let plain = serde_json::to_string(&sample_offer()).expect("serde");
        assert!(!plain.contains("encrypted") && !plain.contains("enc_pub_key"));

        let encrypted = TransferFrame::Offer {
            protocol_version: TRANSFER_PROTOCOL_VERSION,
            batch_id: "b-42".to_string(),
            files: vec![FileMeta::new("a.txt", 11)],
            total_size: 11,
            encrypted: true,
            enc_pub_key: Some("aa".repeat(32)),
        };
        let json = serde_json::to_string(&encrypted).expect("serde");
        assert!(json.starts_with(r#"{"type":"offer","#), "{json}");
        assert!(json.contains(r#""encrypted":true"#));
        assert!(json.contains(r#""enc_pub_key":"#));

        // Decision 加密回执头：无头时字段省略（旧对端零感知），有头时原样往返
        let ack_plain = serde_json::to_string(&TransferFrame::Decision {
            accepted: true,
            reason: None,
            enc_pub_key: None,
        })
        .expect("serde");
        assert!(ack_plain.starts_with(r#"{"type":"decision""#), "{ack_plain}");
        assert!(!ack_plain.contains("enc_pub_key"));

        let ack_enc = TransferFrame::Decision {
            accepted: true,
            reason: None,
            enc_pub_key: Some("bb".repeat(32)),
        };
        let mut buf = Vec::new();
        futures_block_on(write_control(&mut buf, &ack_enc)).expect("encode");
        let mut reader: &[u8] = &buf;
        match futures_block_on(read_frame(&mut reader)).expect("decode") {
            IncomingFrame::Control(boxed) => {
                assert_eq!(*boxed, ack_enc);
                assert!(reader.is_empty());
            }
            other => panic!("expected control frame, got {other:?}"),
        }
    }
}
