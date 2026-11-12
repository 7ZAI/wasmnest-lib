//! 指标 / 健康端点（默认 `127.0.0.1:9090`）。
//!
//! 刻意手写最小 HTTP/1.1 —— 只为两个只读端点引一整套 web 框架（actix / axum）会
//! 把守护进程的依赖面和攻击面一起放大。这里只支持 `GET`、只读、`connection: close`，
//! 请求体一律不看。
//!
//! 暴露纪律：默认只绑回环（配置层校验）；要公网暴露必须显式 `expose_public = true`
//! 并自行加反代 TLS 或 token——健康端点会给出 PeerId 与监听地址，不是秘密但也不
//! 该无条件公开。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

use crate::{
    error::{RelayError, Result},
    metrics::Metrics,
};

/// 单次请求的最大读取字节（足够容纳请求行 + 少量头）
pub const MAX_REQUEST_BYTES: usize = 2048;
/// 读取请求的超时（慢连接不占任务）
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// `/healthz` 响应体
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthInfo {
    /// 固定 `ok`（进程活着且配置已通过校验才会起这个端点）
    pub status: String,
    /// 中继版本
    pub version: String,
    /// 中继 PeerId（base58）
    pub peer_id: String,
    /// PeerId 指纹（`sha256(ed25519 公钥)` 十六进制）
    pub peer_id_sha256: String,
    /// 准入模式
    pub access: String,
    /// 控制协议名（客户端据此判断是否支持兑换/查询）
    pub control_protocol: String,
    /// 实际绑定成功的监听地址
    pub listen_addrs: Vec<String>,
    /// 对外通告地址（客户端导入的形态，含 `/p2p/<peerId>`）
    pub advertise_addrs: Vec<String>,
}

/// 起端点（收到 shutdown 后返回）
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    health: Arc<HealthInfo>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        // 每条连接独立任务：一个慢客户端不能卡住指标采集
                        let metrics = Arc::clone(&metrics);
                        let health = Arc::clone(&health);
                        tokio::spawn(async move {
                            let _ = handle_connection(stream, metrics, health).await;
                        });
                    }
                    Err(err) => return Err(RelayError::Io(err)),
                }
            }
        }
    }
}

/// 处理一条连接（读一次请求 → 写一次响应 → 关闭）
pub async fn handle_connection(
    mut stream: TcpStream,
    metrics: Arc<Metrics>,
    health: Arc<HealthInfo>,
) -> std::io::Result<()> {
    let mut buffer = vec![0u8; MAX_REQUEST_BYTES];
    let read = match timeout(REQUEST_TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(read)) => read,
        Ok(Err(err)) => return Err(err),
        // 超时视为客户端问题，直接关连接（不打印错误刷日志）
        Err(_) => return Ok(()),
    };
    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
    let (status, content_type, body) = route(&request, &metrics, &health);
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// 路由（纯函数，便于不起端口直接测）
pub fn route(
    request: &str,
    metrics: &Metrics,
    health: &HealthInfo,
) -> (String, &'static str, String) {
    let Some(request_line) = request.lines().next() else {
        return bad_request();
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return bad_request();
    };
    if method != "GET" {
        return (
            "405 Method Not Allowed".to_string(),
            "text/plain; charset=utf-8",
            "只支持 GET\n".to_string(),
        );
    }
    let path = target.split('?').next().unwrap_or(target);
    match path {
        "/healthz" => (
            "200 OK".to_string(),
            "application/json",
            serde_json::to_string_pretty(health).unwrap_or_else(|_| "{}".to_string()),
        ),
        "/metrics" => (
            "200 OK".to_string(),
            "text/plain; version=0.0.4",
            metrics.render(),
        ),
        _ => (
            "404 Not Found".to_string(),
            "text/plain; charset=utf-8",
            "未知路径（只提供 /healthz 与 /metrics）\n".to_string(),
        ),
    }
}

fn bad_request() -> (String, &'static str, String) {
    (
        "400 Bad Request".to_string(),
        "text/plain; charset=utf-8",
        "请求行非法\n".to_string(),
    )
}

/// 绑定监听地址（端口 0 时由内核分配，用于测试）
pub async fn bind(listen: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(listen)
        .await
        .map_err(|e| RelayError::Swarm(format!("指标端点无法监听 {listen}：{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> HealthInfo {
        HealthInfo {
            status: "ok".to_string(),
            version: "0.0.1".to_string(),
            peer_id: "12D3KooWTest".to_string(),
            peer_id_sha256: "ab".repeat(32),
            access: "open".to_string(),
            control_protocol: "/wasmnest/relay-control/1".to_string(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            advertise_addrs: vec!["/dns4/relay.example.com/tcp/4001/p2p/12D3KooWTest".to_string()],
        }
    }

    #[test]
    fn 健康端点返回_json() {
        let metrics = Metrics::new();
        let (status, content_type, body) = route(
            "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n",
            &metrics,
            &health(),
        );
        assert_eq!(status, "200 OK");
        assert_eq!(content_type, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("应可解析");
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["peer_id"], "12D3KooWTest");
        assert_eq!(parsed["control_protocol"], "/wasmnest/relay-control/1");
    }

    #[test]
    fn 指标端点返回计数文本() {
        let metrics = Metrics::new();
        metrics.reservation_accepted(false);
        let (status, content_type, body) =
            route("GET /metrics HTTP/1.1\r\n\r\n", &metrics, &health());
        assert_eq!(status, "200 OK");
        assert!(content_type.starts_with("text/plain"));
        assert!(
            body.contains("wasmnest_relay_reservations_active 1"),
            "{body}"
        );
    }

    #[test]
    fn 查询串不影响路由() {
        let metrics = Metrics::new();
        let (status, _, _) = route("GET /metrics?x=1 HTTP/1.1\r\n\r\n", &metrics, &health());
        assert_eq!(status, "200 OK");
    }

    #[test]
    fn 未知路径_404_非_get_405_坏请求行_400() {
        let metrics = Metrics::new();
        let health = health();
        assert_eq!(
            route("GET /secret HTTP/1.1\r\n\r\n", &metrics, &health).0,
            "404 Not Found"
        );
        assert_eq!(
            route("POST /healthz HTTP/1.1\r\n\r\n", &metrics, &health).0,
            "405 Method Not Allowed"
        );
        assert_eq!(route("", &metrics, &health).0, "400 Bad Request");
        assert_eq!(route("garbage", &metrics, &health).0, "400 Bad Request");
    }

    #[tokio::test]
    async fn 端点可真实请求并在_shutdown_后退出() {
        let listener = bind("127.0.0.1:0".parse().expect("地址"))
            .await
            .expect("绑定");
        let addr = listener.local_addr().expect("本地地址");
        let metrics = Arc::new(Metrics::new());
        let health = Arc::new(health());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(serve(listener, Arc::clone(&metrics), health, shutdown_rx));

        let mut stream = TcpStream::connect(addr).await.expect("连接");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("写请求");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("读响应");
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(text.contains("wasmnest_relay_circuits_total"), "{text}");

        shutdown_tx.send(true).expect("发停止信号");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("端点应在收到停止信号后退出")
            .expect("任务不应 panic")
            .expect("serve 应返回 Ok");
    }
}
