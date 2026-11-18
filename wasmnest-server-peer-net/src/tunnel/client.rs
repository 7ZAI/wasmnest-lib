//! 隧道客户端：开流写首帧、校验响应，并把结果接回回环本地代理。
//!
//! 响应只认服务端回的形状：`ok=true` + `caller="peer"` + 服务端给过的
//! `peerNodeId`（可选）。非 peer caller 一律拒绝（不变量 3），拒绝响应按错误码
//! 上抛（fail-visible），绝不在失败后继续把本地字节写到裸连接上。

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::base::identity::NodeId;
use crate::tunnel::frame::{read_reply, TunnelHello, CALLER_PEER};
use crate::tunnel::proxy::TunnelConnector;
use crate::tunnel::{
    Result, TunnelError, TunnelIo, CODE_INVALID_FRAME, CODE_NOT_MATCHED, CODE_PEER_OFFLINE, CODE_PORT_NOT_EXPOSED,
    CODE_TICKET_EXPIRED, CODE_TUNNEL_LIMIT,
};

/// 拨号并开一条 tunnel 子流的注入点（宿主实现：引擎 `open_stream` + compat）
#[async_trait]
pub trait TunnelStreamOpener: Send + Sync {
    async fn open(&self) -> Result<TunnelIo>;
}

/// 把「每条本地连接开一条流」的 proxy 契约接到本模块的首帧握手
pub struct ClientConnector {
    pub hello: TunnelHello,
    pub opener: Arc<dyn TunnelStreamOpener>,
}

impl ClientConnector {
    pub fn new(hello: TunnelHello, opener: Arc<dyn TunnelStreamOpener>) -> Self {
        Self { hello, opener }
    }
}

#[async_trait]
impl TunnelConnector for ClientConnector {
    async fn open(&self, _local_addr: SocketAddr) -> Result<TunnelIo> {
        let mut io = self.opener.open().await?;
        open_tunnel_stream(&mut io, &self.hello).await?;
        Ok(io)
    }
}

/// 服务端错误码 → 本地静态错误码；服务端给的任何未知码都收敛为 `peer-offline`，
/// 不允许把远端字符串原样当成本地错误类型
fn reply_error_code(code: Option<&str>) -> &'static str {
    match code {
        Some(c) if c == CODE_NOT_MATCHED => CODE_NOT_MATCHED,
        Some(c) if c == CODE_TICKET_EXPIRED => CODE_TICKET_EXPIRED,
        Some(c) if c == CODE_PORT_NOT_EXPOSED => CODE_PORT_NOT_EXPOSED,
        Some(c) if c == CODE_TUNNEL_LIMIT => CODE_TUNNEL_LIMIT,
        _ => CODE_PEER_OFFLINE,
    }
}

pub async fn open_tunnel_stream<S>(io: &mut S, hello: &TunnelHello) -> Result<Option<String>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    hello.validate()?;
    io.write_all(&hello.encode()?)
        .await
        .map_err(|e| TunnelError::new(CODE_INVALID_FRAME, format!("写首帧失败：{:?}", e.kind())))?;

    let reply = read_reply(io).await?;
    if reply.caller != CALLER_PEER {
        return Err(TunnelError::new(
            CODE_NOT_MATCHED,
            "服务端响应 caller 不是 peer，拒绝把隧道流量当本机",
        ));
    }
    if !reply.ok {
        return Err(TunnelError::new(
            reply_error_code(reply.error.as_deref()),
            "服务端拒绝建立隧道",
        ));
    }
    if let Some(node_id) = &reply.peer_node_id {
        if NodeId::parse(node_id).is_err() {
            return Err(TunnelError::new(CODE_INVALID_FRAME, "服务端响应 peerNodeId 形状非法"));
        }
    }
    Ok(reply.peer_node_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::frame::{read_frame, TunnelKind, TunnelReply};
    use crate::tunnel::proxy::{bind_loopback_proxy, run_proxy};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::watch;

    const NODE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ReplyMode {
        Accept,
        Reject,
        WrongCaller,
        BadNodeId,
    }

    struct FakeOpener {
        calls: AtomicUsize,
        mode: ReplyMode,
    }

    #[async_trait]
    impl TunnelStreamOpener for FakeOpener {
        async fn open(&self) -> Result<TunnelIo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (client_side, mut server_side) = tokio::io::duplex(4096);
            let mode = self.mode;
            tokio::spawn(async move {
                let payload = read_frame(&mut server_side).await.unwrap();
                let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(&payload);
                let hello = TunnelHello::decode(&frame).unwrap();
                assert_eq!(hello.port, 8765);
                let reply = match mode {
                    ReplyMode::Accept => TunnelReply::accepted(Some(NODE_A.into())),
                    ReplyMode::Reject => TunnelReply::rejected(CODE_TICKET_EXPIRED),
                    ReplyMode::WrongCaller => TunnelReply {
                        ok: true,
                        caller: "localhost".into(),
                        peer_node_id: Some(NODE_A.into()),
                        error: None,
                    },
                    ReplyMode::BadNodeId => TunnelReply::accepted(Some("forged".into())),
                };
                server_side.write_all(&reply.encode().unwrap()).await.unwrap();
                if mode == ReplyMode::Accept {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = server_side.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        server_side.write_all(&buf[..n]).await.unwrap();
                    }
                }
            });
            Ok(Box::new(client_side))
        }
    }

    fn opener(mode: ReplyMode) -> Arc<FakeOpener> {
        Arc::new(FakeOpener {
            calls: AtomicUsize::new(0),
            mode,
        })
    }

    fn hello() -> TunnelHello {
        TunnelHello::new(8765, TunnelKind::Http, None)
    }

    #[tokio::test]
    async fn accepted_peer_reply_returns_verified_node_id() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let payload = read_frame(&mut server).await.unwrap();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&payload);
            assert_eq!(TunnelHello::decode(&frame).unwrap(), hello());
            server
                .write_all(&TunnelReply::accepted(Some(NODE_A.into())).encode().unwrap())
                .await
                .unwrap();
        });
        let node_id = open_tunnel_stream(&mut client, &hello()).await.unwrap();
        assert_eq!(node_id.as_deref(), Some(NODE_A));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn connector_handshake_then_pipe() {
        let opener = opener(ReplyMode::Accept);
        let connector = ClientConnector::new(hello(), opener.clone());
        let mut io = connector.open(SocketAddr::from(([127, 0, 0, 1], 1))).await.unwrap();
        assert_eq!(opener.calls.load(Ordering::SeqCst), 1);
        io.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn rejected_and_malformed_replies_are_fail_visible() {
        for (mode, expected) in [
            (ReplyMode::Reject, CODE_TICKET_EXPIRED),
            (ReplyMode::WrongCaller, CODE_NOT_MATCHED),
            (ReplyMode::BadNodeId, CODE_INVALID_FRAME),
        ] {
            let connector = ClientConnector::new(hello(), opener(mode));
            let err = match connector.open(SocketAddr::from(([127, 0, 0, 1], 1))).await {
                Err(e) => e,
                Ok(_) => panic!("响应形状非法时必须拒绝建立隧道"),
            };
            assert_eq!(err.code, expected);
        }
    }

    /// 本地代理 → ClientConnector → 服务端：一条 TCP 连接恰好一次首帧握手
    #[tokio::test]
    async fn proxy_integration_opens_one_handshake_per_connection() {
        let opener = opener(ReplyMode::Accept);
        let connector = Arc::new(ClientConnector::new(hello(), opener.clone()));
        let (listener, addr) = bind_loopback_proxy().await.unwrap();
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(run_proxy(listener, connector, rx));
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(opener.calls.load(Ordering::SeqCst), 1);
        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        drop(client);
    }
}
