//! 权限门与判定顺序（自宿主迁入的 `gates` 组）

use super::scaffold::{denied, drop_handle, mint, FakePorts};
use super::*;

/// 权限门：未授予 `peer` 即拒绝，且不触碰句柄表/引擎
#[test]
fn peer_denied_without_permission() {
    let ports = FakePorts::with(&[]);
    assert_eq!(
        super::peer_dial(&ports, "com.wasmnest.no-peer", "{}").unwrap_err(),
        denied()
    );
    assert_eq!(
        super::peer_close(&ports, "com.wasmnest.no-peer", "sess-nonexistent").unwrap_err(),
        denied()
    );
}

/// 正例（防「恒拒绝」假绿）：授予后越过权限门，报的是无头上下文不可用而非权限
#[test]
fn peer_granted_passes_permission_gate() {
    let ports = FakePorts::with(&[("com.wasmnest.peer-ok", PERMISSION_PEER)]);
    let err = super::peer_close(&ports, "com.wasmnest.peer-ok", "sess-nonexistent").expect_err("无头上下文不应可断开");
    assert!(!err.contains("permission denied"), "已授予 peer 仍被权限门拒绝: {err}");
    assert!(err.contains("headless"), "预期无头上下文错误: {err}");
    // 无头文案是插件可见的 wire 事实：逐字保留（含「无 app_handle」的判定依据）
    assert_eq!(err, ports::HEADLESS_UNAVAILABLE);
}

/// 无头文案与迁移前逐字一致（防重写文案打断已发布插件的错误匹配）
#[test]
fn headless_wording_is_verbatim() {
    assert_eq!(
        ports::HEADLESS_UNAVAILABLE,
        "peer-net unavailable in headless context (no app_handle)"
    );
}

/// 域函数面（红测）：非属主调 `peer_close` 拿到的就是属主拒绝，
/// 而不是先撞上「无头上下文不可用」——判定顺序本身也是被断言的行为
#[test]
fn peer_close_by_non_owner_is_denied_before_app_check() {
    let ports = FakePorts::with(&[("com.wasmnest.intruder-b", PERMISSION_PEER)]);
    let h = mint("victim-session");
    let err = super::peer_close(&ports, "com.wasmnest.intruder-b", &h).unwrap_err();
    assert_eq!(err, format!("{NOT_OWNER}: {h}"), "got: {err}");
    // 句柄未被摘走，属主仍可解析
    assert_eq!(
        super::with_handles(|t| t.resolve_session(&h)).map(|e| e.node_id),
        Some("victim-session".to_string())
    );
    drop_handle(&h);
}

/// 非属主 close 的零副作用同形断言（函数面 + 表状态两处都验过才算锁住）
#[test]
fn peer_close_by_non_owner_keeps_handle_registered() {
    let ports = FakePorts::with(&[("com.wasmnest.intruder-b", PERMISSION_PEER)]);
    let h = mint("keep-me");
    super::peer_close(&ports, "com.wasmnest.intruder-b", &h).expect_err("非属主必须被拒");
    assert!(
        super::with_handles(|t| t.resolve_session(&h)).is_some(),
        "非属主的一次 close 试探不得把别人的连接摘走"
    );
    drop_handle(&h);
}

/// 属主可继续操作（正例）：同一个句柄，属主拿到的是引擎侧错误而非属主拒绝
#[test]
fn peer_close_by_owner_reaches_engine_side() {
    let ports = FakePorts::with(&[("com.wasmnest.owner-a", PERMISSION_PEER)]);
    let h = mint("owned-session");
    let err = super::peer_close(&ports, "com.wasmnest.owner-a", &h).expect_err("无头上下文取不到引擎");
    assert!(!err.starts_with(NOT_OWNER), "属主不应撞属主拒绝: {err}");
    assert_eq!(err, ports::HEADLESS_UNAVAILABLE);
    drop_handle(&h);
}

/// T21：`node-info` 同受 `peer` 权限门；未授予时不得触碰引擎上下文
#[test]
fn peer_node_info_denied_without_permission() {
    let ports = FakePorts::with(&[]);
    assert_eq!(
        super::peer_node_info(&ports, "com.wasmnest.no-peer").unwrap_err(),
        denied()
    );
}

/// T21：授予后越过权限门，报无头上下文（与既有原语同口径，不伪造空身份）
#[test]
fn peer_node_info_granted_reaches_headless_gate() {
    let ports = FakePorts::with(&[("com.wasmnest.peer-ok", PERMISSION_PEER)]);
    assert_eq!(
        super::peer_node_info(&ports, "com.wasmnest.peer-ok").unwrap_err(),
        ports::HEADLESS_UNAVAILABLE
    );
}

/// T21：`enable=true` + 空地址是调用方错误，先于引擎上下文报出
#[test]
fn configure_relay_rejects_empty_addrs_before_context() {
    let ports = FakePorts::with(&[("com.wasmnest.peer-ok", PERMISSION_PEER)]);
    let err = super::peer_configure_relay(&ports, "com.wasmnest.peer-ok", "[]", true).expect_err("空地址必须显性失败");
    assert!(err.contains("must not be empty"), "got: {err}");
}

/// T21：坏 JSON 同样先于引擎上下文报出（不静默当 LAN-only）
#[test]
fn configure_relay_rejects_bad_json_before_context() {
    let ports = FakePorts::with(&[("com.wasmnest.peer-ok", PERMISSION_PEER)]);
    let err = super::peer_configure_relay(&ports, "com.wasmnest.peer-ok", "not-json", true)
        .expect_err("坏 JSON 必须显性失败");
    assert!(err.contains("invalid relay addrs json"), "got: {err}");
}

/// T21：释放路径（enable=false）允许空地址，越过权限门后报无头上下文
#[test]
fn configure_relay_disable_passes_to_context_gate() {
    let ports = FakePorts::with(&[("com.wasmnest.peer-ok", PERMISSION_PEER)]);
    assert_eq!(
        super::peer_configure_relay(&ports, "com.wasmnest.peer-ok", "[]", false).unwrap_err(),
        ports::HEADLESS_UNAVAILABLE
    );
}
