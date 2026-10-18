//! 跳转裁决（SSRF 闸门）用例组：私网判定 + 纯函数裁决 + 「授权放行放不了闸门」的实测

use serde_json::json;

use super::scaffold::*;
use crate::plugin_binding::egress::{http_fetch, is_private_target, redirect_decision};

/// 私网目标判定：局域网/回环/链路本地 → 直连（不走系统代理）
///
/// 文件服务对端通常是局域网 IP（RFC1918），标准库 is_private 动态判定，
/// 不硬编码网段；域名（外网 API）→ false 走系统代理
#[test]
fn is_private_target_classifies_correctly() {
    // RFC1918：10/8、172.16/12、192.168/16
    assert!(is_private_target(
        "http://10.60.74.97:43145/com.wasmnest.file-transfer/files/list"
    ));
    assert!(is_private_target("http://192.168.1.5:8080/"));
    assert!(is_private_target("http://172.16.0.1/"));
    // loopback 与链路本地
    assert!(is_private_target("http://127.0.0.1:5173/"));
    assert!(is_private_target("http://169.254.1.1/"));
    // 外网域名/IP → 走代理
    assert!(!is_private_target("https://api.example.com/v1/chat"));
    assert!(!is_private_target("http://8.8.8.8/"));
    // 无 host 的畸形 URL → false（默认走代理，行为保守）
    assert!(!is_private_target("not a url"));
}

/// 跳转裁决：公网→私网阻断（无系统代理环境直连即 SSRF）；私网→私网放行
#[test]
fn redirect_decision_blocks_public_to_private() {
    // 公网跳转：跟随
    assert!(redirect_decision(
        "https://cdn.example.com/file",
        &["https://api.github.com/x"],
    ));
    // 外网 302 → 内网 / 回环 / 云元数据：Stop
    assert!(!redirect_decision(
        "http://192.168.1.5:8080/x",
        &["https://api.example.com/y"],
    ));
    assert!(!redirect_decision(
        "http://127.0.0.1:8000/meta",
        &["https://api.example.com/y"],
    ));
    assert!(!redirect_decision(
        "http://169.254.169.254/latest/meta-data",
        &["https://api.example.com/y"],
    ));
    // 私网→私网（局域网文件服务站内跳转）：跟随
    assert!(redirect_decision(
        "http://192.168.1.9/x",
        &["http://192.168.1.5:8080/a"],
    ));
    // 混合链（私网前序 + 公网）跳私网：Stop
    assert!(!redirect_decision(
        "http://192.168.1.9/x",
        &["http://192.168.1.5:8080/a", "https://api.example.com/y"],
    ));
}

/// **授权层的放行放不了 SSRF 闸门**（spec §4.2 / §6.4 / §12.2）
///
/// 授权层只回答「这个地址要不要问用户」，而公网 → 私网（云元数据 `169.254.169.254`）
/// 的跳转阻断是**执行期**的安全裁决，与档位正交。若某天把策略层的判定结果喂给
/// `redirect_decision`（=「SSRF 闸门放到策略之后」这个变异），本条转红。
///
/// 断言形态：跳转**未被跟随** ⇒ 拿到的就是首跳的 302 本身；一旦被跟随，请求会打到
/// 链路本地元数据地址（多半超时或非 302）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn granted_origin_does_not_open_public_to_private_redirects() {
    let addr = spawn_redirect_server("http://169.254.169.254/latest/meta-data").await;
    let origin = format!("http://localhost:{}", addr.port());
    // 授权层「放行」（等价于用户记录命中 / 「始终允许」档免询问放行，两者同形）
    let ports = granting().with_auth(AuthScript::AllowOrigins {
        allowed: vec![normalize_origin(&origin)],
        reason: "no-record",
    });

    let response = http_fetch(
        &as_ports(&ports),
        "p1",
        &json!({"method": "GET", "url": format!("{origin}/x")}).to_string(),
        true,
    )
    .expect("记录命中的 origin 本身应放行")
    .expect("fetch returns payload");
    let parsed: serde_json::Value = serde_json::from_str(&response).expect("响应是合法 JSON");
    assert_eq!(
        parsed["status"], 302,
        "记录命中不得放行公网 → 链路本地元数据的重定向（SSRF 闸门在授权之外）"
    );
}

/// 变体：授权层「一律放行」（等价于「始终允许」档）同样不得打开公网 → 私网跳转
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blanket_allow_does_not_open_public_to_private_redirects() {
    let addr = spawn_redirect_server("http://169.254.169.254/latest/meta-data").await;
    let origin = format!("http://localhost:{}", addr.port());
    let ports = granting().with_auth(AuthScript::Allow);

    let response = http_fetch(
        &as_ports(&ports),
        "p1",
        &json!({"method": "GET", "url": format!("{origin}/x")}).to_string(),
        true,
    )
    .expect("始终允许档应放行该 origin")
    .expect("fetch returns payload");
    let parsed: serde_json::Value = serde_json::from_str(&response).expect("响应是合法 JSON");
    assert_eq!(
        parsed["status"], 302,
        "始终允许档同样不得放行公网 → 私网重定向（档位是「不问」，不是「越闸」）"
    );
}
