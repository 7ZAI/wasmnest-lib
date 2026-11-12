//! `/wasmnest/relay-control/1` 服务端：版本/模式查询 + enrollment 兑换。
//!
//! 为什么需要这条控制面：`allowlist` 模式下新设备要「自助开通」，而开通的前提是
//! 它已经能和中继建立一条 Noise 连接——这条连接正好也是控制面的载体。于是准入判定
//! 放在 relay 行为面的限量器里（而不是连接层），设备连上来先兑换，再预留。
//!
//! 安全口径：
//! - token 只存 `sha256`，兑换即消耗（默认一次），日志只打标签与 PeerId 短指纹；
//! - 兑换成功把 PeerId 写进白名单并落盘（重启仍有效）；
//! - 失败统一回 `invalid-token`，不区分「不存在 / 已用尽 / 格式错」，少泄信息。

use std::sync::{Arc, Mutex};

use futures_util::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    StreamExt,
};
use libp2p::PeerId;
use libp2p_stream::IncomingStreams;

use crate::{
    access::{AccessMode, AllowedPeers},
    identity::short_peer,
    tokens::TokenStore,
    wire::{
        decode_frame_len, encode_frame, ControlRequest, ControlResponse, FrameError,
        CONTROL_PROTOCOL_VERSION, MAX_FRAME_BYTES,
    },
};

/// 控制面共享状态
pub struct ControlContext {
    /// 准入集合（兑换后立即生效）
    pub allowed: AllowedPeers,
    /// token 表（进程内串行化兑换：并发兑换不能超额）
    pub tokens: Mutex<TokenStore>,
    /// 中继版本（`hello` 回带）
    pub relay_version: &'static str,
    /// 本节点 PeerId（`hello` 回带，客户端可据此校验导入地址）
    pub peer_id: PeerId,
}

/// 控制面错误
#[derive(Debug)]
pub enum ControlError {
    /// 底层 I/O
    Io(std::io::Error),
    /// JSON 载荷非法
    Json(serde_json::Error),
    /// 分帧非法
    Frame(FrameError),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O 错误：{e}"),
            Self::Json(e) => write!(f, "载荷不是合法控制消息：{e}"),
            Self::Frame(e) => write!(f, "分帧错误：{e}"),
        }
    }
}

impl std::error::Error for ControlError {}

impl From<std::io::Error> for ControlError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ControlError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<FrameError> for ControlError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

/// 控制面接受循环：每条入站流开一个任务
pub struct ControlService {
    incoming: IncomingStreams,
    context: Arc<ControlContext>,
}

impl ControlService {
    /// 绑定共享状态
    pub fn new(incoming: IncomingStreams, context: Arc<ControlContext>) -> Self {
        Self { incoming, context }
    }

    /// 持续接受控制流（直到接收器被 drop / 协议注销）
    pub async fn run(mut self) {
        while let Some((peer, stream)) = self.incoming.next().await {
            let context = Arc::clone(&self.context);
            tokio::spawn(async move {
                if let Err(err) = handle_stream(stream, peer, context).await {
                    // 失败只记 debug：恶意或半途断开的探测流不该刷满日志
                    tracing::debug!(peer = %short_peer(&peer), error = %err, "控制流处理失败");
                }
            });
        }
    }
}

/// 处理一条控制流（一请求一响应后关闭）
pub async fn handle_stream<S>(
    mut stream: S,
    peer: PeerId,
    context: Arc<ControlContext>,
) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(err) => {
            // 分帧/载荷非法：尽量回一个可读错误再关，帮客户端定位
            let response = ControlResponse::error("invalid-request");
            let _ = write_response(&mut stream, &response).await;
            return Err(err);
        }
    };
    let response = handle_request(&context, peer, request);
    write_response(&mut stream, &response).await
}

/// 请求处理（纯逻辑，便于无端口单测）
pub fn handle_request(
    context: &ControlContext,
    peer: PeerId,
    request: ControlRequest,
) -> ControlResponse {
    if request.version() != CONTROL_PROTOCOL_VERSION {
        return ControlResponse::error("unsupported-version");
    }
    match request {
        ControlRequest::Hello { .. } => {
            let mut response = ControlResponse::ok();
            response.relay_version = Some(context.relay_version.to_string());
            response.peer_id = Some(context.peer_id.to_base58());
            response.access = Some(context.allowed.mode().as_str().to_string());
            response.allowed = Some(context.allowed.admits(&peer));
            response
        }
        ControlRequest::Enroll { token, .. } => {
            if context.allowed.mode() == AccessMode::Open {
                // 开放模式本来就能预留：不消耗 token，如实回报「已可用」而不是假装兑换成功
                let mut response = ControlResponse::ok();
                response.enrolled = Some(false);
                response.allowed = Some(true);
                return response;
            }
            let label = {
                let mut tokens = context.tokens.lock().expect("token 表锁中毒");
                match tokens.verify_and_consume(&token) {
                    Ok(label) => label,
                    Err(err) => {
                        tracing::info!(
                            peer = %short_peer(&peer),
                            error = %err,
                            "enrollment token 兑换失败"
                        );
                        return ControlResponse::error("invalid-token");
                    }
                }
            };
            match context.allowed.enroll(peer) {
                Ok(newly) => {
                    tracing::info!(
                        peer = %short_peer(&peer),
                        label = %label,
                        newly,
                        "peer 已加入中继白名单"
                    );
                    let mut response = ControlResponse::ok();
                    response.enrolled = Some(true);
                    response.allowed = Some(true);
                    response
                }
                Err(err) => {
                    // 落盘失败不能回 ok：否则客户端以为开通了，重启后又没了
                    tracing::warn!(
                        peer = %short_peer(&peer),
                        error = %err,
                        "白名单落盘失败，enrollment 已回滚"
                    );
                    ControlResponse::error("enroll-failed")
                }
            }
        }
    }
}

/// 读一帧请求
pub async fn read_request<S>(stream: &mut S) -> Result<ControlRequest, ControlError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = decode_frame_len(header)?;
    let mut payload = vec![0u8; len.min(MAX_FRAME_BYTES)];
    stream.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

/// 写一帧响应
pub async fn write_response<S>(
    stream: &mut S,
    response: &ControlResponse,
) -> Result<(), ControlError>
where
    S: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(response)?;
    let frame = encode_frame(&body)?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use super::*;
    use crate::{access::AllowedPeers, tokens::TokenStore};

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    /// 内存流：预置输入字节，记录写出的字节
    ///
    /// 不用 `tokio::io::duplex` 的原因：libp2p 的流实现的是 `futures_io` 的
    /// AsyncRead/AsyncWrite，tokio 的 DuplexStream 不满足这组 trait 约束。
    struct MemStream {
        input: Vec<u8>,
        read_pos: usize,
        output: Vec<u8>,
    }

    impl MemStream {
        fn new(input: impl Into<Vec<u8>>) -> Self {
            Self {
                input: input.into(),
                read_pos: 0,
                output: Vec::new(),
            }
        }
    }

    impl AsyncRead for MemStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let remaining = this.input.len().saturating_sub(this.read_pos);
            if remaining == 0 {
                return Poll::Ready(Ok(0));
            }
            let take = remaining.min(buf.len());
            let start = this.read_pos;
            buf[..take].copy_from_slice(&this.input[start..start + take]);
            this.read_pos += take;
            Poll::Ready(Ok(take))
        }
    }

    impl AsyncWrite for MemStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.output.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        context: Arc<ControlContext>,
        allowed: AllowedPeers,
    }

    impl Fixture {
        fn new(mode: AccessMode, max_uses: u32) -> (Self, String) {
            let dir = tempfile::tempdir().expect("临时目录");
            let tokens_path = dir.path().join("tokens.json");
            let peers_path = dir.path().join("enrolled-peers.json");
            let mut store = TokenStore::load(&tokens_path).expect("token 表");
            let token = store.create("phone", max_uses).expect("创建 token");
            let allowed = AllowedPeers::new(mode, [], Some(peers_path)).expect("准入集合");
            let context = Arc::new(ControlContext {
                allowed: allowed.clone(),
                tokens: Mutex::new(store),
                relay_version: crate::RELAY_VERSION,
                peer_id: peer(),
            });
            (
                Self {
                    _dir: dir,
                    context,
                    allowed,
                },
                token,
            )
        }
    }

    #[test]
    fn hello_回带版本_模式与是否可预留() {
        let (fixture, _token) = Fixture::new(AccessMode::Allowlist, 1);
        let peer = peer();
        let response = handle_request(
            &fixture.context,
            peer,
            ControlRequest::Hello {
                v: CONTROL_PROTOCOL_VERSION,
            },
        );
        assert!(response.ok);
        assert_eq!(response.access.as_deref(), Some("allowlist"));
        assert_eq!(response.allowed, Some(false), "未 enrollment 应报不可用");
        assert_eq!(
            response.relay_version.as_deref(),
            Some(crate::RELAY_VERSION)
        );
        assert_eq!(
            response.peer_id.as_deref(),
            Some(fixture.context.peer_id.to_base58().as_str())
        );
    }

    #[test]
    fn 协议版本不符回_unsupported_version() {
        let (fixture, _token) = Fixture::new(AccessMode::Open, 1);
        let response = handle_request(&fixture.context, peer(), ControlRequest::Hello { v: 99 });
        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("unsupported-version"));
    }

    #[test]
    fn 有效_token_兑换后立即进入白名单并落盘() {
        let (fixture, token) = Fixture::new(AccessMode::Allowlist, 1);
        let target = peer();
        let response = handle_request(
            &fixture.context,
            target,
            ControlRequest::Enroll {
                v: CONTROL_PROTOCOL_VERSION,
                token,
            },
        );
        assert!(response.ok, "{response:?}");
        assert_eq!(response.enrolled, Some(true));
        assert!(fixture.allowed.contains(&target), "应写入白名单");
        assert!(fixture.allowed.admits(&target));
    }

    #[test]
    fn 一次性_token_不能被第二个_peer_复用() {
        let (fixture, token) = Fixture::new(AccessMode::Allowlist, 1);
        let first = peer();
        let second = peer();

        let ok = handle_request(
            &fixture.context,
            first,
            ControlRequest::Enroll {
                v: CONTROL_PROTOCOL_VERSION,
                token: token.clone(),
            },
        );
        assert!(ok.ok);

        let reused = handle_request(
            &fixture.context,
            second,
            ControlRequest::Enroll {
                v: CONTROL_PROTOCOL_VERSION,
                token,
            },
        );
        assert!(!reused.ok);
        assert_eq!(reused.error.as_deref(), Some("invalid-token"));
        assert!(
            !fixture.allowed.contains(&second),
            "复用的 peer 不应入白名单"
        );
    }

    #[test]
    fn 无效_token_不入白名单() {
        let (fixture, _token) = Fixture::new(AccessMode::Allowlist, 1);
        let target = peer();
        let response = handle_request(
            &fixture.context,
            target,
            ControlRequest::Enroll {
                v: CONTROL_PROTOCOL_VERSION,
                token: "0".repeat(32),
            },
        );
        assert_eq!(response.error.as_deref(), Some("invalid-token"));
        assert!(!fixture.allowed.contains(&target));
    }

    #[test]
    fn 开放模式兑换不消耗_token_并如实回报已可用() {
        let (fixture, token) = Fixture::new(AccessMode::Open, 1);
        let target = peer();
        let response = handle_request(
            &fixture.context,
            target,
            ControlRequest::Enroll {
                v: CONTROL_PROTOCOL_VERSION,
                token,
            },
        );
        assert!(response.ok);
        assert_eq!(response.enrolled, Some(false), "开放模式不声称兑换成功");
        assert_eq!(response.allowed, Some(true));
        // token 未被消耗：用量仍为 0
        let tokens = fixture.context.tokens.lock().expect("锁");
        assert_eq!(tokens.summary(), vec![("phone".to_string(), 0, 1)]);
    }

    #[tokio::test]
    async fn 分帧写出的响应可被解析回同一内容() {
        let response = ControlResponse::error("invalid-token");
        let mut stream = MemStream::new(Vec::new());
        write_response(&mut stream, &response)
            .await
            .expect("写响应");

        let written = stream.output;
        assert!(written.len() > 4, "应写出长度头 + 载荷");
        let len = decode_frame_len([written[0], written[1], written[2], written[3]]).expect("帧长");
        assert_eq!(len, written.len() - 4);
        let decoded: ControlResponse = serde_json::from_slice(&written[4..]).expect("解析");
        assert_eq!(decoded, response);
    }

    #[tokio::test]
    async fn 读回请求帧() {
        let request = ControlRequest::Hello {
            v: CONTROL_PROTOCOL_VERSION,
        };
        let body = serde_json::to_vec(&request).expect("序列化");
        let frame = encode_frame(&body).expect("编码");
        let mut stream = MemStream::new(frame);
        let decoded = read_request(&mut stream).await.expect("读请求");
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn 非法载荷回_invalid_request_且返回错误() {
        let (fixture, _token) = Fixture::new(AccessMode::Open, 1);
        let frame = encode_frame(b"not json").expect("编码");
        let mut stream = MemStream::new(frame);

        let err = handle_stream(&mut stream, peer(), fixture.context)
            .await
            .expect_err("非法载荷应报错");
        assert!(matches!(err, ControlError::Json(_)), "{err:?}");

        let written = stream.output;
        let len = decode_frame_len([written[0], written[1], written[2], written[3]]).expect("帧长");
        let response: ControlResponse = serde_json::from_slice(&written[4..4 + len]).expect("解析");
        assert_eq!(response.error.as_deref(), Some("invalid-request"));
    }
}
