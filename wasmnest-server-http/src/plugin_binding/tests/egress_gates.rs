//! 出站原语的闸门用例组：声明门 → 出站授权门 → 执行（迁移前同属一个内联 `mod tests`）

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::scaffold::*;
use crate::plugin_binding::egress::{execute_http_request, http_fetch};
use crate::plugin_binding::ports::{HttpEventSink, HttpPorts, OutboundAuth};

// ==================== jwtAuth 代注（2026-10-10 票 05：移动侧能力上移到本 crate） ====================

/// 只覆写 [`HttpPorts::jwt_auth_token`] 的端口包装器（其余方法委托给内层端口）
///
/// 为什么包一层而不是改 `FakePorts`：代注是**可选能力**（默认实现 `Ok(None)`），
/// 用例要覆盖的是「宿主给了 token / 宿主当下无 token」两种宿主态，而不是把这份
/// 开关焊进通用夹具（会让别的用例读到无关状态）。
struct JwtPorts {
    inner: Arc<dyn HttpPorts>,
    token: Result<Option<String>, String>,
}

impl HttpPorts for JwtPorts {
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool {
        self.inner.check_permission(plugin_id, permission, api)
    }
    fn authorize_outbound(&self, plugin_id: &str, url: &str, may_prompt: bool) -> OutboundAuth {
        self.inner.authorize_outbound(plugin_id, url, may_prompt)
    }
    fn event_sink(&self) -> Option<Arc<dyn HttpEventSink>> {
        self.inner.event_sink()
    }
    fn block_on_any(
        &self,
        fut: crate::plugin_binding::ports::BoxedBlocked,
    ) -> Box<dyn std::any::Any + Send> {
        self.inner.block_on_any(fut)
    }
    fn jwt_auth_token(&self, _plugin_id: &str) -> Result<Option<String>, String> {
        self.token.clone()
    }
}

/// 回显请求头的夹具服务器（`spawn_*` 家族没有这个形态：验证 Bearer 注入要看请求头）
async fn spawn_echo_server() -> SocketAddr {
    disable_proxy_for_loopback();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", head.len(), head);
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    addr
}

/// 宿主给了 token ⇒ 调用方不带 Authorization 也能拿到 Bearer（token 不落插件，C4）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwt_auth_injects_host_managed_bearer() {
    let addr = spawn_echo_server().await;
    let ports: Arc<dyn HttpPorts> = Arc::new(JwtPorts {
        // 授权层一律放行：本条用例锁的是代注语义（授权三态另有专门用例组），
        // 且夹具服务绑在 loopback——授权放行后仍要过执行期的私网跳转闸门，不冲突
        inner: as_ports(&granting().with_auth(AuthScript::Allow)),
        token: Ok(Some("tok-13".to_string())),
    });
    let response = http_fetch(
        &ports,
        "p1",
        &json!({"method": "GET", "url": format!("http://{}/x", addr), "jwtAuth": true}).to_string(),
        true,
    )
    .expect("jwtAuth 请求必须放行")
    .expect("fetch returns payload");
    let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
    let echo_body = parsed["body"].as_str().unwrap().to_ascii_lowercase();
    assert!(
        echo_body.contains("authorization: bearer tok-13"),
        "宿主代注的 Bearer 必须出现在请求头里，got: {echo_body}"
    );
}

/// 开关关 ⇒ 不得注入 Authorization（C4：token 只在显式请求时代注，避免把会话凭据
/// 撒到插件自己都不知道的外部目标上）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwt_auth_off_sends_no_authorization() {
    let addr = spawn_echo_server().await;
    let ports: Arc<dyn HttpPorts> = Arc::new(JwtPorts {
        // 授权层一律放行：本条用例锁的是代注语义（授权三态另有专门用例组），
        // 且夹具服务绑在 loopback——授权放行后仍要过执行期的私网跳转闸门，不冲突
        inner: as_ports(&granting().with_auth(AuthScript::Allow)),
        token: Ok(Some("tok-13".to_string())),
    });
    let response = http_fetch(
        &ports,
        "p1",
        &json!({"method": "GET", "url": format!("http://{}/x", addr), "jwtAuth": false}).to_string(),
        true,
    )
    .expect("未开 jwtAuth 的请求照常放行")
    .expect("fetch returns payload");
    let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
    let echo_body = parsed["body"].as_str().unwrap().to_ascii_lowercase();
    assert!(!echo_body.contains("authorization:"), "got: {echo_body}");
}

/// 要求代注但宿主无 token ⇒ **触达网络之前**拒绝（fail-visible：匿名在对端必 401，
/// 晚失败不如早失败，禁止静默降级为匿名）
#[tokio::test]
async fn jwt_auth_without_token_is_rejected_before_network() {
    let (addr, hits) = spawn_counting_server(b"{\"ok\":true}".to_vec()).await;
    let ports: Arc<dyn HttpPorts> = Arc::new(JwtPorts {
        // 授权层一律放行：本条用例锁的是代注语义（授权三态另有专门用例组），
        // 且夹具服务绑在 loopback——授权放行后仍要过执行期的私网跳转闸门，不冲突
        inner: as_ports(&granting().with_auth(AuthScript::Allow)),
        token: Err("jwtAuth requested but no global token available (not authenticated)".to_string()),
    });
    let err = http_fetch(
        &ports,
        "p1",
        &json!({"method": "GET", "url": format!("http://{}/x", addr), "jwtAuth": true}).to_string(),
        true,
    )
    .expect_err("无 token 的 jwtAuth 请求必须被拒");
    assert!(err.contains("no global token available"), "got: {err}");
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "缺 token 的请求不得触达网络（代注裁决必须在执行之前）"
    );
}

/// 正常小响应体：完整返回，不受上限影响
#[tokio::test]
async fn http_fetch_small_response_ok() {
    disable_proxy_for_loopback();
    let addr = spawn_mock_server(b"{\"ok\":true}".to_vec()).await;
    let resp = execute_http_request(
        &json!({
            "method": "GET",
            "url": format!("http://{}/small", addr),
        }),
        None,
    )
    .await
    .expect("small response must succeed");
    assert_eq!(resp["status"], 200);
    assert_eq!(resp["body"], "{\"ok\":true}");
}

/// 未声明 network:http 的插件调用 fetch：宿主侧直接拒绝（Rust 端最终仲裁）。
/// 错误消息含明确原因，与请求类错误可区分。
#[test]
fn http_fetch_permission_denied_rejected() {
    let ports = denying_permission();
    let err = http_fetch(&as_ports(&ports), "p1", r#"{"url":"http://127.0.0.1:1/x"}"#, true)
        .expect_err("unpermissioned fetch must be rejected");
    assert!(
        err.contains("permission denied") && err.contains("network:http"),
        "error should state permission reason, got: {}",
        err
    );
}

/// 声明 network:http 后放行：请求进入执行阶段（此处以缺 url 的请求 JSON 验证
/// 错误从「权限拒绝」变为「请求错误」，证明权限检查通过且未碰网络）。
///
/// **变异判据**：把声明门挪到授权门之后 ⇒ 未授权插件的拒绝原因会变成授权拒绝，
/// 本条转红。
#[test]
fn http_fetch_permission_granted_passes() {
    let ports = granting();
    let err =
        http_fetch(&as_ports(&ports), "p1", r#"{"method":"GET"}"#, true).expect_err("missing url is a request error");
    assert!(
        err.contains("Missing 'url'") || err.contains("http error"),
        "after permission, error should be request-level, got: {}",
        err
    );
    assert!(
        !err.contains("permission denied"),
        "permissioned plugin should not hit permission denial, got: {}",
        err
    );
}

/// 非法请求 JSON：权限放行后仍是解析错误（错误分类保持：权限拒绝 ≠ 请求错误）
#[test]
fn http_fetch_invalid_json_is_request_error_not_permission() {
    let ports = granting();
    let err = http_fetch(&as_ports(&ports), "p1", "not-json", true).expect_err("invalid JSON is a request error");
    assert!(
        err.contains("invalid request JSON"),
        "error should be parse-level, got: {}",
        err
    );
}

/// 超限响应体：立即拒绝并报错引导 stream:true，绝不把大载荷交给 guest
/// （保证 guest 侧 serde 解析工作量有界 → 不可能耗尽 fuel 预算被 trap）
#[tokio::test]
async fn http_fetch_oversized_response_rejected() {
    disable_proxy_for_loopback();
    let addr = spawn_mock_server(vec![
        0u8;
        wasmnest_server_base::constants::PLUGIN_HTTP_RESPONSE_BODY_LIMIT_BYTES
            + 1
    ])
    .await;
    let err = execute_http_request(
        &json!({
            "method": "GET",
            "url": format!("http://{}/big", addr),
        }),
        None,
    )
    .await
    .expect_err("oversized response must be rejected");
    assert!(
        err.to_string().contains("exceeds"),
        "error should mention size limit, got: {}",
        err
    );
    assert!(
        err.to_string().contains("stream:true"),
        "error should guide to streaming mode, got: {}",
        err
    );
}

/// 未记录的目标在**触达网络之前**被拒（变异判据：把授权检查挪到执行之后、或只门
/// 非流式分支 ⇒ 夹具服务器会收到连接，命中数从 0 变 1）。
#[tokio::test]
async fn unrecorded_origin_is_denied_before_any_network_io() {
    let ports = granting();
    let (addr, hits) = spawn_counting_server(b"{\"ok\":true}".to_vec()).await;

    let err = http_fetch(
        &as_ports(&ports),
        "p1",
        &json!({"method": "GET", "url": format!("http://{}/x", addr)}).to_string(),
        true,
    )
    .expect_err("未记录的目标必须被拒");

    assert!(
        err.contains("network authorization denied"),
        "错误须是授权拒绝而非请求错误: {err}"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "被拒的请求不得触达网络（授权检查必须在执行之前）"
    );
}

/// 正例：授权命中的 origin 真正放行（请求到达对端并拿到响应）
///
/// **必须 multi_thread**：出站原语是同步函数，内部经端口的桥阻塞调用线程；
/// 单线程测试运行时下夹具服务的 accept 任务被一同卡死（表现为连接超时）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_record_releases_the_request() {
    let (addr, hits) = spawn_counting_server(b"{\"ok\":true}".to_vec()).await;
    let ports = granting().with_auth(AuthScript::AllowOrigins {
        allowed: vec![normalize_origin(&format!("http://{addr}"))],
        reason: "no-record",
    });

    let response = http_fetch(
        &as_ports(&ports),
        "p1",
        &json!({"method": "GET", "url": format!("http://{}/x", addr)}).to_string(),
        true,
    )
    .expect("记录命中的 origin 必须放行")
    .expect("fetch returns payload");
    // 返回值是响应对象的 JSON 文本（body 字段仍是被转义的原文）
    let parsed: serde_json::Value = serde_json::from_str(&response).expect("响应是合法 JSON");
    assert_eq!(parsed["status"], 200);
    assert_eq!(parsed["body"], "{\"ok\":true}", "响应体应原样返回");
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "放行的请求应真实到达对端"
    );
}

/// 凭据红线（AGENTS §8）：拒绝错误串带 origin，**不带 path / query 里的 token**
#[tokio::test]
async fn denial_error_carries_origin_but_never_query() {
    let ports = granting();
    let err = http_fetch(
        &as_ports(&ports),
        "p1",
        r#"{"method":"GET","url":"https://api.example.com/v1?access_token=SECRET_TOKEN"}"#,
        true,
    )
    .expect_err("未记录 origin 必须被拒");

    assert!(
        err.contains("https://api.example.com:443"),
        "错误须点明被拒的 origin: {err}"
    );
    assert!(!err.contains("SECRET_TOKEN"), "token 不得进错误串: {err}");
    assert!(!err.contains("/v1"), "path 不得进错误串: {err}");
}

/// 任务单元（池线程）路径：may_prompt=false ⇒ 只能靠记录，未记录即拒
///
/// 变异判据：把两个路径写反（或池线程也去弹窗）时 reason 会变，本条转红。
#[tokio::test]
async fn task_unit_path_denies_unrecorded_origin_with_no_record_reason() {
    let ports = granting();
    let (addr, hits) = spawn_counting_server(b"{}".to_vec()).await;

    let err = http_fetch(
        &as_ports(&ports),
        "p1",
        &json!({"method": "GET", "url": format!("http://{}/x", addr)}).to_string(),
        false,
    )
    .expect_err("池线程不得弹窗，未记录目标必须被拒");

    assert!(
        err.contains("no-record"),
        "池线程拒绝原因应为 no-record（而非询问侧的 user-denied）: {err}"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "被拒的请求不得触达网络"
    );
}

/// 流式分支同样在授权之后：未记录目标不得拿到 streamId（变异：只门非流式）
#[tokio::test]
async fn streaming_mode_is_gated_too() {
    let ports = granting();
    let err = http_fetch(
        &as_ports(&ports),
        "p1",
        r#"{"method":"POST","url":"https://api.example.com/v1/chat","stream":true,"streamEvent":"x:y"}"#,
        true,
    )
    .expect_err("流式请求同样要过授权门");
    assert!(
        err.contains("network authorization denied"),
        "流式分支必须被同一道门拦住: {err}"
    );
}

/// 授权检查自身失败：错误分类与「拒绝」不同（不得被调用方当成策略拒绝吞掉）
#[tokio::test]
async fn authorization_check_failure_is_its_own_error_class() {
    let ports = granting().with_auth(AuthScript::CheckFailed("store unavailable".to_string()));
    let err = http_fetch(
        &as_ports(&ports),
        "p1",
        r#"{"method":"GET","url":"https://api.example.com/v1"}"#,
        true,
    )
    .expect_err("检查失败必须报错");
    assert!(
        err.contains("network authorization check failed") && err.contains("store unavailable"),
        "错误须点明检查失败而非策略拒绝: {err}"
    );
}

/// 缺 `url` 的请求不在授权门拦（归执行层的错误分类，保持不变）：授权脚本即使
/// 一律放行，错误仍应是 `Missing 'url'` 而不是授权相关文案。
#[tokio::test]
async fn missing_url_is_execution_error_not_authorization_error() {
    let ports = granting().with_auth(AuthScript::Deny("no-record"));
    let err = http_fetch(&as_ports(&ports), "p1", r#"{"method":"GET"}"#, true).expect_err("缺 url 是请求错误");
    assert!(err.contains("Missing 'url'"), "错误须归执行层: {err}");
    assert!(!err.contains("authorization"), "缺 url 不该被归类成授权错误: {err}");
}
