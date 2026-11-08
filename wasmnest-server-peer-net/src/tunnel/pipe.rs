//! 通道建立后的裸字节双向 pipe：字节配额、空闲回收与 WS 长连接保活。
//!
//! 设计 §4.4 要求「空闲超时只回收短连接 HTTP 流；WS 升级后的流按长连接处理，
//! 不得杀静默终端 WS」。判据只能来自**第一条客户端字节里的 HTTP `Upgrade` 头**，
//! 不能按端口或源 IP 猜：隧道流量在两端都呈现为 loopback。
//!
//! 指标只累计字节数，不记录 payload / 路径 / 文件名；读到的首块内容只用于匹配
//! 头字面量，用完即弃。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tunnel::frame::TunnelKind;
use crate::tunnel::{Result, TunnelError, CODE_TUNNEL_CLOSED, CODE_TUNNEL_IDLE, CODE_TUNNEL_LIMIT};

pub const DEFAULT_MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_HTTP_IDLE_TIMEOUT_SECS: u64 = 60;
const BUFFER_BYTES: usize = 8192;
/// 首块 header 累积上限（防内存放大；正常 WS 请求只有几百字节）
const MAX_PREFACE_BYTES: usize = 64 * 1024;
/// 首块后等待 header 收完的短窗口（分片 / 大 header；超时按非 WS 继续）
const PREFACE_READ_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeLimits {
    /// 单流双向总字节上限（两个方向共用同一计数）
    pub max_bytes: u64,
    /// `None` = 长连接，不按空闲回收
    pub idle_timeout: Option<Duration>,
}

impl PipeLimits {
    /// `http` 默认按短连接回收，遇到 WS 升级会在 pipe 内自动取消；`tcp` 按长连接处理
    pub fn for_kind(kind: TunnelKind) -> Self {
        Self {
            max_bytes: DEFAULT_MAX_STREAM_BYTES,
            idle_timeout: match kind {
                TunnelKind::Http => Some(Duration::from_secs(DEFAULT_HTTP_IDLE_TIMEOUT_SECS)),
                TunnelKind::Tcp => None,
            },
        }
    }

    pub fn long_lived() -> Self {
        Self {
            max_bytes: u64::MAX,
            idle_timeout: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PipeStats {
    pub total_bytes: u64,
    pub websocket_upgrade: bool,
}

/// 只认请求头字面量；不解析、不缓存、不落日志
pub fn is_websocket_upgrade(head: &[u8]) -> bool {
    let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
    lower
        .windows(b"upgrade: websocket".len())
        .any(|w| w == b"upgrade: websocket")
        || lower
            .windows(b"upgrade:websocket".len())
            .any(|w| w == b"upgrade:websocket")
}

/// 首块是否看起来像 HTTP 请求行（只对这类流继续等 header 结束）
fn looks_like_http_request(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE",
    ];
    METHODS
        .iter()
        .any(|method| buf.starts_with(method) && buf.get(method.len()) == Some(&b' '))
}

/// HTTP 头结束标记（`\r\n\r\n`）
fn contains_header_end(buf: &[u8]) -> bool {
    buf.windows(4).any(|window| window == b"\r\n\r\n")
}

async fn read_first<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    idle: Option<Duration>,
    idle_message: &str,
) -> Result<usize> {
    match idle {
        Some(d) => match tokio::time::timeout(d, reader.read(buf)).await {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(io_error(e)),
            Err(_) => Err(TunnelError::new(CODE_TUNNEL_IDLE, idle_message)),
        },
        None => reader.read(buf).await.map_err(io_error),
    }
}

fn io_error(e: std::io::Error) -> TunnelError {
    TunnelError::new(CODE_TUNNEL_CLOSED, format!("通道 IO 结束：{:?}", e.kind()))
}

fn count_bytes(total: &Arc<AtomicU64>, n: u64, max_bytes: u64) -> Result<()> {
    let before = total.fetch_add(n, Ordering::SeqCst);
    if before.saturating_add(n) > max_bytes {
        return Err(TunnelError::new(CODE_TUNNEL_LIMIT, "单流字节配额超限"));
    }
    Ok(())
}

async fn pump<R, W>(reader: &mut R, writer: &mut W, limits: &PipeLimits, total: Arc<AtomicU64>) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; BUFFER_BYTES];
    loop {
        let n = match limits.idle_timeout {
            Some(d) => match tokio::time::timeout(d, reader.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(io_error(e)),
                Err(_) => return Err(TunnelError::new(CODE_TUNNEL_IDLE, "短连接 HTTP 流空闲回收")),
            },
            None => reader.read(&mut buf).await.map_err(io_error)?,
        };
        if n == 0 {
            return Ok(());
        }
        count_bytes(&total, n as u64, limits.max_bytes)?;
        writer.write_all(&buf[..n]).await.map_err(io_error)?;
        writer.flush().await.map_err(io_error)?;
    }
}

/// 首块字节判定 WS 升级 → 取消空闲超时；随后双向 pipe，任一方向结束即回收整条流
///
/// 首块可能只是 header 的一部分（TCP 分片 / 大 header）：对看起来像 HTTP 请求的
/// 流继续累积到 `\r\n\r\n`（上限 [`MAX_PREFACE_BYTES`]）再判定，避免把一块就跨
/// 分片的 WS 升级当成短连接，60s 后误杀终端长连接。
pub async fn pipe_with_limits<L, R>(local: &mut L, remote: &mut R, limits: PipeLimits) -> Result<PipeStats>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let total = Arc::new(AtomicU64::new(0));
    let mut first = vec![0u8; BUFFER_BYTES];
    let mut n = read_first(local, &mut first, limits.idle_timeout, "短连接 HTTP 流空闲回收").await?;

    if n > 0 && looks_like_http_request(&first[..n]) && !contains_header_end(&first[..n]) {
        // 只取已读前缀（`first` 的 Vec 尾部是未填充的 0，不能整块计数）
        let mut preface = first[..n].to_vec();
        while preface.len() < MAX_PREFACE_BYTES {
            let mut chunk = [0u8; BUFFER_BYTES];
            match read_first(local, &mut chunk, Some(PREFACE_READ_TIMEOUT), "首块 header 读取超时").await {
                Ok(0) => break,
                Ok(k) => {
                    preface.extend_from_slice(&chunk[..k]);
                    if contains_header_end(&preface) {
                        break;
                    }
                }
                // 判据不明确：按非 WS 继续（已读字节不漏），交给后续 pipe
                Err(e) if e.code == CODE_TUNNEL_IDLE => break,
                Err(e) => return Err(e),
            }
        }
        n = preface.len();
        first = preface;
    }

    let mut effective = limits.clone();
    let websocket_upgrade = n > 0 && is_websocket_upgrade(&first[..n]);
    if websocket_upgrade {
        effective.idle_timeout = None;
    }
    if n > 0 {
        count_bytes(&total, n as u64, effective.max_bytes)?;
        remote.write_all(&first[..n]).await.map_err(io_error)?;
        remote.flush().await.map_err(io_error)?;
    }

    let (mut local_r, mut local_w) = tokio::io::split(local);
    let (mut remote_r, mut remote_w) = tokio::io::split(remote);
    let client_to_backend = pump(&mut local_r, &mut remote_w, &effective, Arc::clone(&total));
    let backend_to_client = pump(&mut remote_r, &mut local_w, &effective, Arc::clone(&total));
    tokio::select! {
        result = client_to_backend => result?,
        result = backend_to_client => result?,
    }
    Ok(PipeStats {
        total_bytes: total.load(Ordering::SeqCst),
        websocket_upgrade,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const WS_HANDSHAKE: &[u8] =
        b"GET /ws/plugin/terminal HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    const PLAIN_HTTP: &[u8] = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n";

    fn fast_limits(max_bytes: u64) -> PipeLimits {
        PipeLimits {
            max_bytes,
            idle_timeout: Some(Duration::from_millis(20)),
        }
    }

    #[test]
    fn upgrade_detection_is_header_based() {
        assert!(is_websocket_upgrade(WS_HANDSHAKE));
        assert!(is_websocket_upgrade(b"upgrade:websocket\r\n"));
        assert!(!is_websocket_upgrade(PLAIN_HTTP));
        assert!(!is_websocket_upgrade(b"websocket mentioned in body"));
        assert_eq!(
            PipeLimits::for_kind(TunnelKind::Http).idle_timeout,
            Some(Duration::from_secs(DEFAULT_HTTP_IDLE_TIMEOUT_SECS))
        );
        assert_eq!(PipeLimits::for_kind(TunnelKind::Tcp).idle_timeout, None);
    }

    /// WS 升级后即使静默超过空闲阈值也不得被杀（不变量：终端 WS 保活）
    #[tokio::test]
    async fn websocket_upgrade_disables_idle_reaping() {
        let (mut local, mut client) = tokio::io::duplex(2048);
        let (mut backend, mut echo) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok(n) = echo.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                echo.write_all(&buf[..n]).await.unwrap();
            }
        });

        let pipe = tokio::spawn(async move { pipe_with_limits(&mut local, &mut backend, fast_limits(4096)).await });
        client.write_all(WS_HANDSHAKE).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        client.write_all(b"still-alive").await.unwrap();
        drop(client);

        let stats = pipe.await.unwrap().unwrap();
        assert!(stats.websocket_upgrade);
        assert!(stats.total_bytes >= (WS_HANDSHAKE.len() + b"still-alive".len()) as u64);
    }

    /// 分片到达的 Upgrade 头（首块只有半截 header）也要识别成 WS：否则短连接
    /// 空闲回收会在 60s 后误杀终端长连接（R15）。
    #[tokio::test]
    async fn fragmented_websocket_upgrade_still_disables_idle_reaping() {
        let (mut local, mut client) = tokio::io::duplex(2048);
        let (mut backend, mut echo) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok(n) = echo.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                echo.write_all(&buf[..n]).await.unwrap();
            }
        });

        let pipe = tokio::spawn(async move { pipe_with_limits(&mut local, &mut backend, fast_limits(4096)).await });
        let (head, tail) = WS_HANDSHAKE.split_at(40);
        assert!(!contains_header_end(head), "首块必须不含 header 结束标记");
        client.write_all(head).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        client.write_all(tail).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        client.write_all(b"still-alive").await.unwrap();
        drop(client);

        let stats = pipe.await.unwrap().unwrap();
        assert!(stats.websocket_upgrade, "分片到达的 Upgrade 头也要识别");
        assert!(stats.total_bytes >= (WS_HANDSHAKE.len() + b"still-alive".len()) as u64);
    }

    #[tokio::test]
    async fn plain_http_stream_is_reaped_when_idle() {
        let (mut local, mut client) = tokio::io::duplex(2048);
        let (mut backend, mut sink) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = sink.read(&mut buf).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let pipe = tokio::spawn(async move { pipe_with_limits(&mut local, &mut backend, fast_limits(4096)).await });
        client.write_all(PLAIN_HTTP).await.unwrap();
        let err = pipe.await.unwrap().unwrap_err();
        assert_eq!(err.code, CODE_TUNNEL_IDLE);
    }

    #[tokio::test]
    async fn byte_quota_is_enforced_across_both_directions() {
        let (mut local, mut client) = tokio::io::duplex(2048);
        let (mut backend, mut sink) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = sink.read(&mut buf).await;
        });
        let pipe = tokio::spawn(async move { pipe_with_limits(&mut local, &mut backend, fast_limits(4)).await });
        client.write_all(b"0123456789").await.unwrap();
        let err = pipe.await.unwrap().unwrap_err();
        assert_eq!(err.code, CODE_TUNNEL_LIMIT);
    }
}
