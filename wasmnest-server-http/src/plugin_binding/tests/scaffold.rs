//! `plugin_binding` 的跨分组测试脚手架（用例文件经 `use super::scaffold::*` 引用）
//!
//! **为什么自带假端口**：本域的端口实现属宿主（桌面端见宿主 adapter `src-tauri/src/plugin/http.rs`），
//! crate 内不能引用宿主 bin crate ⇒ 单测必须在 crate 内造一份假实现。
//! 假端口同时是「机制自持」的可测性证据：权限门、出站授权三态、事件通道缺席、
//! 响应体上限、跳转裁决、SSE 切分、端点属主仲裁的断言全在本域内闭环，不经宿主上下文。
//!
//! **假端口与迁移前的差**：出站授权的**裁决来源**从宿主的真实授权记录库换成本文件
//! 的白名单脚本（[`AuthScript`]）——被断言的行为契约（授权门位置在任何网络动作之前、
//! 流式与非流式同门、错误串只带 origin 不带 query、授权放行放不了 SSRF 闸门）逐条保留。

use std::any::Any;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::plugin_binding::ports::{BoxedBlocked, HttpEventSink, HttpPorts, OutboundAuth};

// ==================== 插件 id ====================

/// 唯一插件 id（注册表按属主隔离，并行用例互不干扰）
pub(super) fn test_plugin(seed: &str) -> String {
    format!("test-http-{seed}")
}

// ==================== 出站授权脚本 ====================

/// 出站授权裁决的脚本（宿主侧那套真实授权记录库在本 crate 不可见，见模块头说明）
#[derive(Clone)]
pub(super) enum AuthScript {
    /// 一律放行（origin 回显，供 SSRF 闸门用例造「授权层放行」的前置）
    Allow,
    /// 一律拒绝（reason 固定——池线程未记录场景用 `no-record`）
    Deny(&'static str),
    /// 按归一化 origin 白名单放行，其余按 reason 拒绝
    AllowOrigins { allowed: Vec<String>, reason: &'static str },
    /// 授权检查自身失败（与「拒绝」是不同错误分类）
    CheckFailed(String),
}

/// 归一化 origin（`scheme://host:port`，缺端口补协议默认端口）
///
/// 与宿主授权层同一口径（缺端口补默认、只取 origin 不含 path / query），
/// 本 crate 用 `reqwest::Url` 直接算——错误串的字面断言依赖它。
pub(super) fn normalize_origin(url: &str) -> String {
    let parsed = reqwest::Url::parse(url).expect("test url must parse");
    format!(
        "{}://{}:{}",
        parsed.scheme(),
        parsed.host_str().expect("test url must have host"),
        parsed.port_or_known_default().expect("http(s) url must have a port")
    )
}

// ==================== 事件通道 ====================

/// 假事件通道：捕获 `(事件名, 载荷)` 序列
pub(super) struct RecordingEventSink {
    events: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
}

impl RecordingEventSink {
    pub(super) fn new() -> Arc<RecordingEventSink> {
        Arc::new(RecordingEventSink {
            events: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// 捕获到的事件（按到达序）
    pub(super) fn events(&self) -> Vec<(String, serde_json::Value)> {
        self.events.lock().expect("event sink poisoned").clone()
    }

    /// 该事件名下按序拼接的 `chunk` 载荷（流式断言用）
    pub(super) fn chunks(&self, event: &str) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|(name, _)| name == event)
            .filter_map(|(_, payload)| payload.get("chunk")?.as_str().map(str::to_string))
            .collect()
    }

    /// 是否出现过 `done: true` 的终止事件
    pub(super) fn saw_done(&self, event: &str) -> bool {
        self.events().into_iter().any(|(name, payload)| {
            name == event && payload.get("done").and_then(serde_json::Value::as_bool) == Some(true)
        })
    }
}

impl HttpEventSink for RecordingEventSink {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        self.events
            .lock()
            .expect("event sink poisoned")
            .push((event.to_string(), payload));
    }
}

// ==================== 假端口 ====================

/// 假端口：权限授予开关 + 出站授权脚本 + 事件通道（`None` = 无头）
pub(super) struct FakePorts {
    /// 是否授予 `network:http`（关 = 声明门拒绝一切原语）
    permission_granted: bool,
    /// 出站授权裁决脚本
    auth: AuthScript,
    /// 流式事件通道；`None` = 无头上下文（`streaming requires app_handle` 口径）
    event_sink: Option<Arc<RecordingEventSink>>,
}

impl FakePorts {
    /// 只授予 `network:http`，未记录 origin 一律 `no-record` 拒绝
    #[allow(non_snake_case)]
    pub(super) fn granting() -> Arc<FakePorts> {
        Arc::new(FakePorts {
            permission_granted: true,
            auth: AuthScript::Deny("no-record"),
            event_sink: None,
        })
    }

    /// 未授予 `network:http`（声明门在一律拒绝）
    #[allow(non_snake_case)]
    pub(super) fn denying_permission() -> Arc<FakePorts> {
        Arc::new(FakePorts {
            permission_granted: false,
            auth: AuthScript::Allow,
            event_sink: None,
        })
    }

    /// 覆盖出站授权脚本
    pub(super) fn with_auth(self: Arc<Self>, auth: AuthScript) -> Arc<Self> {
        Arc::new(FakePorts {
            permission_granted: self.permission_granted,
            auth,
            event_sink: self.event_sink.clone(),
        })
    }

    /// 装配事件通道（有头形态）
    pub(super) fn with_event_sink(self: Arc<Self>, sink: Arc<RecordingEventSink>) -> Arc<Self> {
        Arc::new(FakePorts {
            permission_granted: self.permission_granted,
            auth: self.auth.clone(),
            event_sink: Some(sink),
        })
    }
}

/// 只授予 `network:http` 的端口（自由函数形态——用例里最常用）
pub(super) fn granting() -> Arc<FakePorts> {
    FakePorts::granting()
}

/// 未授予 `network:http` 的端口（自由函数形态）
pub(super) fn denying_permission() -> Arc<FakePorts> {
    FakePorts::denying_permission()
}

impl HttpPorts for FakePorts {
    fn check_permission(&self, _plugin_id: &str, _permission: &str, _api: &str) -> bool {
        self.permission_granted
    }

    fn authorize_outbound(&self, _plugin_id: &str, url: &str, _may_prompt: bool) -> OutboundAuth {
        let origin = normalize_origin(url);
        match &self.auth {
            AuthScript::Allow => OutboundAuth::Allowed { origin },
            AuthScript::Deny(reason) => OutboundAuth::Denied {
                reason: (*reason).to_string(),
                origin,
            },
            AuthScript::AllowOrigins { allowed, reason } => {
                if allowed.contains(&origin) {
                    OutboundAuth::Allowed { origin }
                } else {
                    OutboundAuth::Denied {
                        reason: (*reason).to_string(),
                        origin,
                    }
                }
            }
            AuthScript::CheckFailed(e) => OutboundAuth::CheckFailed(e.clone()),
        }
    }

    fn event_sink(&self) -> Option<Arc<dyn HttpEventSink>> {
        self.event_sink.clone().map(|sink| sink as Arc<dyn HttpEventSink>)
    }

    fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send> {
        // 测试替身桥：与宿主那份唯一实现同策略的两条路——多线程运行时走
        // `block_in_place`（不阻塞 worker 池），current_thread / 无句柄线程走
        // 新线程 ambient 兜底（测试里那些会真实触网的用例标 multi_thread，
        // 原因与生产面同款：夹具服务要与被阻塞的调用线程分处不同执行上下文）。
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(fut))
            }
            _ => std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("fresh runtime for test bridge");
                rt.block_on(fut)
            })
            .join()
            .expect("test bridge thread panicked"),
        }
    }
}

/// 端口别名助手（域函数收 `&Arc<dyn HttpPorts>`；测试多数直接拿 `Arc<FakePorts>` 传）
pub(super) fn as_ports(ports: &Arc<FakePorts>) -> Arc<dyn HttpPorts> {
    Arc::clone(ports) as Arc<dyn HttpPorts>
}

// ==================== 本地 HTTP 夹具 ====================

/// 禁用系统代理对 loopback 的干扰（Windows 全局代理可能拦截测试请求）
pub(super) fn disable_proxy_for_loopback() {
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
}

/// 极简 mock HTTP 服务器：返回固定 body，响应后关闭连接
pub(super) async fn spawn_mock_server(body: Vec<u8>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            // 读完请求头即可响应（忽略 body）
            let _ = sock.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
        }
    });
    addr
}

/// 计数型 mock 服务器：每接受一条连接 +1（用来证明「被拒的请求没触达网络」）
pub(super) async fn spawn_counting_server(
    body: Vec<u8>,
) -> (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    disable_proxy_for_loopback();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            });
        }
    });
    (addr, hits)
}

/// 302 跳转服务器：跳到给定 `Location`（公网 → 私网 SSRF 场景的夹具）
///
/// 绑在 127.0.0.1 上但**用例用 `http://localhost:<port>` 访问**：`is_private_target`
/// 按 host 能否解析成 IP 判定私网，`localhost` 解析失败即判为「公网」——正是
/// 公网首跳 + 私网跳转目标这一 SSRF 形态的可达替身（`NO_PROXY` 已含 localhost）。
pub(super) async fn spawn_redirect_server(location: &str) -> std::net::SocketAddr {
    disable_proxy_for_loopback();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let head = Arc::new(format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let head = std::sync::Arc::clone(&head);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(head.as_bytes()).await;
            });
        }
    });
    addr
}

/// 流式夹具：按 `chunks` 逐块吐出，末块后关闭（验证 chunk 逐条到达而非末尾一次性到达）
pub(super) async fn spawn_chunked_server(chunks: Vec<Vec<u8>>) -> std::net::SocketAddr {
    disable_proxy_for_loopback();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                .await;
            for chunk in chunks {
                let _ = sock.write_all(&chunk).await;
                let _ = sock.flush().await;
            }
        }
    });
    addr
}
