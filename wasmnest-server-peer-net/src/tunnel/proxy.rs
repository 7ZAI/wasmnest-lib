//! 客户端回环本地代理（不变量 1）。
//!
//! 宿主在 `127.0.0.1:0` 起 listener，把返回的临时端口交给应用；**每条 accept
//! 的 TCP 连接开一条新的 tunnel 流**（不在流内再做多路复用），连接关闭即流关闭。
//! `shutdown` 触发时 listener 停止接受、全部在飞流任务被中止，句柄失效后不得静默
//! 重试（错误码 `tunnel-closed`，由宿主在 WIT 层给出）。
//!
//! 具体实现（引擎拨号 / 首帧 / pipe 到 libp2p 子流）由宿主经 [`TunnelConnector`]
//! 注入；本模块不依赖引擎类型，便于用内存双工流验证「一连接一流」与关停语义。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::tunnel::{Result, TunnelError, CODE_PROXY_BIND_FAILED};

/// 隧道流只需读写能力；boxed 让宿主可注入 libp2p 子流的 compat 适配层
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type TunnelIo = Box<dyn AsyncStream>;

/// 每条本地连接开一条流的注入点（宿主实现：拨号 → 首帧 → 响应校验 → 返回子流）
#[async_trait]
pub trait TunnelConnector: Send + Sync + 'static {
    async fn open(&self, local_addr: SocketAddr) -> Result<TunnelIo>;
}

/// 只绑 loopback 的临时端口；返回 listener 与实际地址
pub async fn bind_loopback_proxy() -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| TunnelError::new(CODE_PROXY_BIND_FAILED, format!("绑定回环失败：{}", e.kind())))?;
    let addr = listener
        .local_addr()
        .map_err(|e| TunnelError::new(CODE_PROXY_BIND_FAILED, format!("读取监听地址失败：{}", e.kind())))?;
    if addr.ip() != Ipv4Addr::LOCALHOST || addr.port() == 0 {
        return Err(TunnelError::new(
            CODE_PROXY_BIND_FAILED,
            "listener 必须绑 127.0.0.1 且端口非零",
        ));
    }
    Ok((listener, addr))
}

/// 代理主循环：`shutdown` 收到 `true` 即停止接受并中止全部在飞流
pub async fn run_proxy<C>(listener: TcpListener, connector: Arc<C>, shutdown: watch::Receiver<bool>) -> Result<()>
where
    C: TunnelConnector,
{
    let mut tasks = JoinSet::new();
    loop {
        let mut closed = shutdown.clone();
        tokio::select! {
            _ = closed.changed() => {
                if *closed.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut local, peer_addr) = accepted.map_err(|e| {
                    TunnelError::new(CODE_PROXY_BIND_FAILED, format!("接受连接失败：{}", e.kind()))
                })?;
                let conn = Arc::clone(&connector);
                let mut task_shutdown = closed.clone();
                tasks.spawn(async move {
                    let mut remote = match conn.open(peer_addr).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            // 开流失败必须显性：日志点名错误码，并关闭本地连接，
                            // 不把失败伪装成「对端返回空响应」。
                            tracing::warn!(code = e.code, "tunnel stream open failed: {}", e.detail);
                            let _ = local.shutdown().await;
                            return;
                        }
                    };
                    tokio::select! {
                        copied = tokio::io::copy_bidirectional(&mut local, &mut remote) => {
                            if let Err(e) = copied {
                                tracing::debug!("tunnel pipe closed: {}", e.kind());
                            }
                        }
                        _ = task_shutdown.changed() => {}
                    }
                    let _ = local.shutdown().await;
                    let _ = remote.shutdown().await;
                });
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    tasks.abort_all();
    Ok(())
}

/// 单条本地连接的 pipe（供宿主自行管理 listener 时复用）
pub async fn pipe_connection(mut local: TcpStream, mut remote: TunnelIo) {
    if let Err(e) = tokio::io::copy_bidirectional(&mut local, &mut remote).await {
        tracing::debug!("tunnel pipe closed: {}", e.kind());
    }
    let _ = local.shutdown().await;
    let _ = remote.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct EchoConnector {
        calls: AtomicUsize,
    }

    impl EchoConnector {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl TunnelConnector for EchoConnector {
        async fn open(&self, _local_addr: SocketAddr) -> Result<TunnelIo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (client_side, mut echo_side) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let n = echo_side.read(&mut buf).await.unwrap();
                echo_side.write_all(&buf[..n]).await.unwrap();
            });
            Ok(Box::new(client_side))
        }
    }

    /// 不变量 1：listener 只绑 127.0.0.1，端口由系统分配
    #[tokio::test]
    async fn listener_binds_loopback_only() {
        let (listener, addr) = bind_loopback_proxy().await.unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);
        drop(listener);
    }

    /// 每条本地连接恰好开一条流；关停后在飞任务被中止
    #[tokio::test]
    async fn each_connection_opens_exactly_one_stream_and_close_stops_proxy() {
        let (listener, addr) = bind_loopback_proxy().await.unwrap();
        let connector = Arc::new(EchoConnector::new());
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(run_proxy(listener, Arc::clone(&connector), rx));

        for payload in [b"ping".as_slice(), b"pong".as_slice()] {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(payload).await.unwrap();
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, payload);
        }
        assert_eq!(connector.calls.load(Ordering::SeqCst), 2);

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        assert!(TcpStream::connect(addr).await.is_err(), "close 后不得静默接受新连接");
    }

    #[tokio::test]
    async fn connector_failure_closes_local_connection() {
        struct FailingConnector;
        #[async_trait]
        impl TunnelConnector for FailingConnector {
            async fn open(&self, _: SocketAddr) -> Result<TunnelIo> {
                Err(TunnelError::new(crate::tunnel::CODE_PEER_OFFLINE, "对端不在线"))
            }
        }

        let (listener, addr) = bind_loopback_proxy().await.unwrap();
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(run_proxy(listener, Arc::new(FailingConnector), rx));
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0, "开流失败即关闭本地连接");
        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
