//! 隧道服务端：单条 `/wasmnest/tunnel/1` 流的完整裁决与生命周期。
//!
//! 顺序固定：读首帧 → **只读校验续票** → `TunnelPolicy` 准入（规则 / 端口 /
//! kind / 已匹配 / allowedPeers / 配额）→ 消费票据 → 连后端 → **在把第一个
//! 客户端字节写进后端之前**登记配对连接面标记 → 回 `{ok:true, caller:"peer"}` →
//! 裸字节 pipe → 清理注册表条目。任何一步失败都回点名错误码并关闭流，绝不静默
//! 连 8765 或把 peer 面当本机。
//!
//! 票据顺序：先 `validate`（不摘除条目）再准入，准入通过后才 `consume`——端口 /
//! kind 填错的尝试不得把一次性票据白白作废（用户还能用同一张票重试）。
//!
//! 宿主接线（T06）：`IncomingStreams::next()` 得到 `InboundStream` 后，把
//! `inbound.stream.compat()` 交给 [`TunnelServer::handle_stream`]，并用
//! `InboundStream.node_id` 与信任表填 `TunnelStreamContext`。接收器必须以
//! `require_admitted = false` 注册，否则未匹配 peer 的配对票据送不到这里。

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::tunnel::frame::{write_reply, TunnelHello, TunnelReply};
use crate::tunnel::pipe::{pipe_with_limits, PipeLimits, PipeStats};
use crate::tunnel::policy::{AdmissionContext, Backend, TunnelPolicy};
use crate::tunnel::registry::PairingRegistry;
use crate::tunnel::ticket::{AccessPath, TicketIssuer};
use crate::tunnel::{Result, TunnelError, TunnelIo};

/// 后端连接工厂：由宿主实现（对等 HTTP/WS 面或回环 TCP）。
///
/// 返回值第二个元素是**本端连接的四元组**（dial 对等面时的本地地址），用作配对
/// 连接注册表的键。实现必须只连 `Backend` 给定的地址，不做任何端口「回退」。
#[async_trait]
pub trait BackendConnector: Send + Sync {
    async fn connect(&self, backend: &Backend) -> Result<(TunnelIo, SocketAddr)>;
}

/// 单条入站流的宿主侧上下文（值必须来自隧道层 / 信任表，不读请求头）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelStreamContext {
    /// 隧道层已验证的对端 node id
    pub peer_node_id: Option<String>,
    /// 应用配对 + 传输信任两层同时成立
    pub matched: bool,
    pub active_streams: usize,
    /// 接入路径只作记录，票据不绑定路径
    pub access_path: AccessPath,
}

pub struct TunnelServer {
    policy: Arc<TunnelPolicy>,
    tickets: Arc<TicketIssuer>,
    registry: Arc<PairingRegistry>,
    backend: Arc<dyn BackendConnector>,
}

impl TunnelServer {
    pub fn new(
        policy: Arc<TunnelPolicy>,
        tickets: Arc<TicketIssuer>,
        registry: Arc<PairingRegistry>,
        backend: Arc<dyn BackendConnector>,
    ) -> Self {
        Self {
            policy,
            tickets,
            registry,
            backend,
        }
    }

    /// 处理一条流；返回 pipe 统计（只含字节数与 WS 标记）
    pub async fn handle_stream<S>(&self, io: &mut S, ctx: &TunnelStreamContext) -> Result<PipeStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let hello = match TunnelHello::read_from(io).await {
            Ok(hello) => hello,
            Err(e) => {
                reject(io, &e).await;
                return Err(e);
            }
        };

        // 票据只读校验：准入失败（端口 / kind 不在规则内、超出配额等）不得烧票；
        // 真正的单次消费在准入通过后（下方）。
        let mut ticket_error = None;
        let ticket_valid = match &hello.ticket {
            Some(ticket) => match self.tickets.validate(ticket, hello.port, ctx.access_path) {
                Ok(()) => true,
                Err(e) => {
                    ticket_error = Some(e);
                    false
                }
            },
            None => false,
        };
        // 未匹配且票据无效时优先回票据错误码（过期 / 二次使用 / 端口不符），
        // 而不是笼统的 not-matched，用户才知道要重新生成二维码。
        if !ctx.matched {
            if let Some(e) = ticket_error {
                reject(io, &e).await;
                return Err(e);
            }
        }

        let admission = match self.policy.admit(
            &hello,
            &AdmissionContext {
                peer_node_id: ctx.peer_node_id.clone(),
                matched: ctx.matched,
                ticket_valid,
                active_streams: ctx.active_streams,
            },
        ) {
            Ok(admission) => admission,
            Err(e) => {
                reject(io, &e).await;
                return Err(e);
            }
        };

        // 准入通过：此时才消费票据。已匹配连接不依赖票据，但携带的票据同样
        // 按一次性处理（防重放）；配对窗口必须消费成功，否则按票据错误拒绝。
        if let Some(ticket) = hello.ticket.as_deref() {
            let consumed = self.tickets.consume(ticket, hello.port, ctx.access_path);
            if let Err(e) = consumed {
                if !ctx.matched {
                    reject(io, &e).await;
                    return Err(e);
                }
            }
        }

        let (mut backend_io, conn_key) = match self.backend.connect(&admission.backend).await {
            Ok(connected) => connected,
            Err(e) => {
                reject(io, &e).await;
                return Err(e);
            }
        };

        // 配对窗口 / 已匹配面标记必须在任何请求字节到达后端之前登记；否则
        // 第一个 HTTP 请求会因注册表查不到而退化成无身份 peer 面。
        let registered = if admission.pairing {
            self.registry.register_pairing(conn_key, admission.peer_node_id.clone())
        } else if let Some(node_id) = &admission.peer_node_id {
            self.registry.register_matched(conn_key, node_id.clone())
        } else {
            Ok(())
        };
        if let Err(e) = registered {
            reject(io, &e).await;
            return Err(e);
        }
        // 流被取消 / 任务被中止时也要清掉面标记：Drop 守卫保证任何退出路径都
        // 消费条目（否则四元组复用时旧身份会泄漏到新连接）。
        let _registry_guard = RegistryEntryGuard::new(Arc::clone(&self.registry), conn_key);

        if let Err(e) = write_reply(io, &TunnelReply::accepted(admission.peer_node_id.clone())).await {
            return Err(e);
        }

        pipe_with_limits(io, &mut backend_io, PipeLimits::for_kind(hello.kind)).await
    }
}

/// 注册表条目的生命期守卫：正常结束、pipe 报错、任务中止（drop future）三条
/// 路径都会消费条目，不依赖 `pipe_with_limits` 之后的显式清理。
struct RegistryEntryGuard {
    registry: Arc<PairingRegistry>,
    key: SocketAddr,
}

impl RegistryEntryGuard {
    fn new(registry: Arc<PairingRegistry>, key: SocketAddr) -> Self {
        Self { registry, key }
    }
}

impl Drop for RegistryEntryGuard {
    fn drop(&mut self) {
        self.registry.consume(&self.key);
    }
}

async fn reject<S: AsyncWrite + Unpin>(io: &mut S, err: &TunnelError) {
    let reply = TunnelReply::rejected(err.code);
    if let Ok(frame) = reply.encode() {
        let _ = io.write_all(&frame).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::frame::{read_reply, TunnelKind};
    use crate::tunnel::policy::{ExposeConfig, PolicyConfig};
    use crate::tunnel::{CODE_PEER_OFFLINE, CODE_TICKET_EXPIRED};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const NODE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct FakeBackend {
        calls: AtomicUsize,
        last: Mutex<Option<Backend>>,
        conn_key: SocketAddr,
        fail: bool,
    }

    impl FakeBackend {
        fn new(conn_key: SocketAddr) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                last: Mutex::new(None),
                conn_key,
                fail: false,
            }
        }

        fn failing(conn_key: SocketAddr) -> Self {
            let mut backend = Self::new(conn_key);
            backend.fail = true;
            backend
        }
    }

    #[async_trait]
    impl BackendConnector for FakeBackend {
        async fn connect(&self, backend: &Backend) -> Result<(TunnelIo, SocketAddr)> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(TunnelError::new(CODE_PEER_OFFLINE, "对端不在线"));
            }
            *self.last.lock().unwrap() = Some(backend.clone());
            let (pipe_side, mut echo_side) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = echo_side.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    echo_side.write_all(&buf[..n]).await.unwrap();
                }
            });
            Ok((Box::new(pipe_side), self.conn_key))
        }
    }

    struct Fixture {
        server: Arc<TunnelServer>,
        tickets: Arc<TicketIssuer>,
        registry: Arc<PairingRegistry>,
        backend: Arc<FakeBackend>,
        peer_face: SocketAddr,
        conn_key: SocketAddr,
    }

    fn fixture(failing: bool) -> Fixture {
        let peer_face = SocketAddr::from(([127, 0, 0, 1], 39001));
        let conn_key = SocketAddr::from(([127, 0, 0, 1], 45001));
        let policy = Arc::new(TunnelPolicy::new(PolicyConfig::new(peer_face, 47613, 4001).unwrap()));
        for (port, kind) in [(8765, TunnelKind::Http), (39002, TunnelKind::Tcp)] {
            policy
                .expose(ExposeConfig {
                    port,
                    kind,
                    label: "test".into(),
                    allowed_peers: vec![],
                })
                .unwrap();
        }
        let tickets = Arc::new(TicketIssuer::new());
        let registry = Arc::new(PairingRegistry::new());
        let backend = Arc::new(if failing {
            FakeBackend::failing(conn_key)
        } else {
            FakeBackend::new(conn_key)
        });
        let server = Arc::new(TunnelServer::new(
            Arc::clone(&policy),
            Arc::clone(&tickets),
            Arc::clone(&registry),
            backend.clone(),
        ));
        Fixture {
            server,
            tickets,
            registry,
            backend,
            peer_face,
            conn_key,
        }
    }

    fn unmatched_ctx() -> TunnelStreamContext {
        TunnelStreamContext {
            peer_node_id: None,
            matched: false,
            active_streams: 0,
            access_path: AccessPath::LanDirect,
        }
    }

    async fn send_hello_then_read_reply<C: AsyncRead + AsyncWrite + Unpin>(
        client: &mut C,
        hello: &TunnelHello,
    ) -> TunnelReply {
        client.write_all(&hello.encode().unwrap()).await.unwrap();
        read_reply(client).await.unwrap()
    }

    /// 不变量 8 / 16：未匹配且无票据，后端连接一次都不发生
    #[tokio::test]
    async fn unmatched_peer_is_rejected_before_any_backend_connection() {
        let f = fixture(false);
        let (mut client, mut server_io) = tokio::io::duplex(4096);
        let server = Arc::clone(&f.server);
        let task = tokio::spawn(async move { server.handle_stream(&mut server_io, &unmatched_ctx()).await });
        let reply = send_hello_then_read_reply(&mut client, &TunnelHello::new(8765, TunnelKind::Http, None)).await;
        assert!(!reply.ok);
        assert_eq!(reply.error.as_deref(), Some(crate::tunnel::CODE_NOT_MATCHED));
        assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0);
        assert!(f.registry.is_empty());
        assert!(task.await.unwrap().is_err());
    }

    /// 不变量 4 / 2：票据只开配对窗口，后端恒为对等面，窗口随流结束清除
    #[tokio::test]
    async fn valid_ticket_opens_pairing_window_on_peer_face_and_clears_after_stream() {
        let f = fixture(false);
        let ticket = f.tickets.issue(8765, 120).unwrap();
        let (mut client, mut server_io) = tokio::io::duplex(4096);
        let server = Arc::clone(&f.server);
        let task = tokio::spawn(async move { server.handle_stream(&mut server_io, &unmatched_ctx()).await });
        let reply = send_hello_then_read_reply(
            &mut client,
            &TunnelHello::new(8765, TunnelKind::Http, Some(ticket.clone())),
        )
        .await;
        assert!(reply.ok, "配对窗口必须放行");
        assert_eq!(reply.caller, "peer");
        assert!(reply.peer_node_id.is_none());

        let face = f.registry.resolve(&f.conn_key);
        assert!(face.is_peer());
        assert!(face.is_pairing(), "配对态必须注入对等面");
        assert_eq!(*f.backend.last.lock().unwrap(), Some(Backend::PeerFace(f.peer_face)));

        let request = b"POST /api/auth/pair HTTP/1.1\r\n\r\n";
        client.write_all(request).await.unwrap();
        let mut echoed = vec![0u8; request.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed.as_slice(), request, "pipe 必须双向可用");
        drop(client);
        let stats = task.await.unwrap().unwrap();
        assert!(stats.total_bytes > 0);
        assert!(f.registry.is_empty(), "流结束即清窗口");

        // 票据二次使用（换一条中继路径也不行）
        let (mut client2, mut server_io2) = tokio::io::duplex(4096);
        let server2 = Arc::clone(&f.server);
        let mut ctx = unmatched_ctx();
        ctx.access_path = AccessPath::WanRelay;
        let task2 = tokio::spawn(async move { server2.handle_stream(&mut server_io2, &ctx).await });
        let reply2 =
            send_hello_then_read_reply(&mut client2, &TunnelHello::new(8765, TunnelKind::Http, Some(ticket))).await;
        assert!(!reply2.ok);
        assert_eq!(reply2.error.as_deref(), Some(CODE_TICKET_EXPIRED));
        assert!(task2.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn wrong_port_does_not_burn_the_ticket() {
        let f = fixture(false);
        let ticket = f.tickets.issue(8765, 120).unwrap();
        let (mut client, mut server_io) = tokio::io::duplex(4096);
        let server = Arc::clone(&f.server);
        let task = tokio::spawn(async move { server.handle_stream(&mut server_io, &unmatched_ctx()).await });

        // 端口对但 kind 不在规则内（8765 只 expose 了 http）：准入失败，票据必须还在
        let reply = send_hello_then_read_reply(
            &mut client,
            &TunnelHello::new(8765, TunnelKind::Tcp, Some(ticket.clone())),
        )
        .await;
        assert!(!reply.ok);
        assert_eq!(reply.error.as_deref(), Some(crate::tunnel::CODE_PORT_NOT_EXPOSED));
        assert_eq!(f.tickets.len(), 1, "端口 / kind 失败不得消耗一次性票据");
        assert!(task.await.unwrap().is_err());

        // 同一张票仍可在正确端口开配对窗口
        let (mut client2, mut server_io2) = tokio::io::duplex(4096);
        let server2 = Arc::clone(&f.server);
        let task2 = tokio::spawn(async move { server2.handle_stream(&mut server_io2, &unmatched_ctx()).await });
        let reply2 =
            send_hello_then_read_reply(&mut client2, &TunnelHello::new(8765, TunnelKind::Http, Some(ticket))).await;
        assert!(reply2.ok);
        assert!(f.tickets.is_empty());
        drop(client2);
        assert!(task2.await.unwrap().is_ok());
    }

    /// 配对窗口只开配对端点：kind=tcp 的规则即使存在也不能凭票据直连（准入失败不烧票）
    #[tokio::test]
    async fn pairing_window_rejects_tcp_kind() {
        let f = fixture(false);
        let ticket = f.tickets.issue(39002, 120).unwrap();
        let (mut client, mut server_io) = tokio::io::duplex(4096);
        let server = Arc::clone(&f.server);
        let task = tokio::spawn(async move { server.handle_stream(&mut server_io, &unmatched_ctx()).await });
        let reply =
            send_hello_then_read_reply(&mut client, &TunnelHello::new(39002, TunnelKind::Tcp, Some(ticket))).await;
        assert!(!reply.ok);
        assert_eq!(reply.error.as_deref(), Some(crate::tunnel::CODE_NOT_MATCHED));
        assert_eq!(f.backend.calls.load(Ordering::SeqCst), 0, "配对窗口不得连业务回环端口");
        assert_eq!(f.tickets.len(), 1);
        assert!(task.await.unwrap().is_err());
    }

    /// 已匹配流：响应带已验证 nodeId，注册表为已匹配面；tcp 只连回环
    #[tokio::test]
    async fn matched_stream_registers_verified_peer_and_tcp_uses_loopback() {
        let f = fixture(false);
        let (mut client, mut server_io) = tokio::io::duplex(4096);
        let mut ctx = unmatched_ctx();
        ctx.matched = true;
        ctx.peer_node_id = Some(NODE_A.into());
        let server = Arc::clone(&f.server);
        let task = tokio::spawn(async move { server.handle_stream(&mut server_io, &ctx).await });
        let reply = send_hello_then_read_reply(&mut client, &TunnelHello::new(39002, TunnelKind::Tcp, None)).await;
        assert!(reply.ok);
        assert_eq!(reply.peer_node_id.as_deref(), Some(NODE_A));
        let face = f.registry.resolve(&f.conn_key);
        assert!(face.is_peer() && !face.is_pairing());
        assert_eq!(face.peer_node_id.as_deref(), Some(NODE_A));
        assert_eq!(
            *f.backend.last.lock().unwrap(),
            Some(Backend::Loopback(SocketAddr::from(([127, 0, 0, 1], 39002))))
        );
        drop(client);
        assert!(task.await.unwrap().is_ok());
        assert!(f.registry.is_empty());
    }

    #[tokio::test]
    async fn backend_failure_is_fail_visible_and_leaves_no_registry_entry() {
        let f = fixture(true);
        let (mut client, mut server_io) = tokio::io::duplex(4096);
        let mut ctx = unmatched_ctx();
        ctx.matched = true;
        ctx.peer_node_id = Some(NODE_A.into());
        let server = Arc::clone(&f.server);
        let task = tokio::spawn(async move { server.handle_stream(&mut server_io, &ctx).await });
        let reply = send_hello_then_read_reply(&mut client, &TunnelHello::new(8765, TunnelKind::Http, None)).await;
        assert!(!reply.ok);
        assert_eq!(reply.error.as_deref(), Some(CODE_PEER_OFFLINE));
        assert!(f.registry.is_empty());
        assert!(task.await.unwrap().is_err());
    }
}
