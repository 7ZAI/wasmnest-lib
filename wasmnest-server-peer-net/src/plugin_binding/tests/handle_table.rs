//! 句柄表与属主仲裁（自宿主迁入的 `handle_table` 组）

use super::scaffold::{entry, RELAY_DIAL_ADDR};
use super::*;

/// 属主登记与判定（票 04）：句柄只有拨号方可继续操作
#[test]
fn session_handle_is_owner_scoped() {
    let mut t = PeerHandleTable::default();
    let h = t.mint_session(entry("own"));
    let got = t.resolve_session(&h).expect("resolved");
    assert_eq!(got.owner, "com.wasmnest.owner-a", "拨号方即属主");
    assert!(ensure_handle_owner(&got, "com.wasmnest.owner-a", &h).is_ok());
    let err = ensure_handle_owner(&got, "com.wasmnest.intruder-b", &h).unwrap_err();
    assert_eq!(err, format!("not owner of peer handle: {h}"));
    // 错误文案不回带真实属主身份
    assert!(!err.contains("owner-a"), "拒绝文案不得泄露属主插件 id: {err}");
}

/// 非属主 close 的拒绝路径零副作用：句柄仍在册，别人仍可用
#[test]
fn rejected_close_restores_handle() {
    let mut t = PeerHandleTable::default();
    let h = t.mint_session(entry("keep"));
    let taken = t.take_session(&h).expect("taken");
    assert!(ensure_handle_owner(&taken, "intruder", &h).is_err());
    t.restore_session(&h, taken);
    assert_eq!(t.resolve_session(&h).expect("still registered").node_id, "keep");
}

#[test]
fn mint_and_resolve_roundtrip_keeps_endpoint() {
    let mut t = PeerHandleTable::default();
    let h = t.mint_session(entry("aa"));
    assert!(h.starts_with("sess-"));
    let got = t.resolve_session(&h).expect("resolved");
    assert_eq!(got.node_id, "aa");
    assert_eq!(got.addrs, vec!["/ip4/192.168.1.5/tcp/47821".to_string()]);
}

/// T11：句柄记忆**全部**候选地址且保持调用方顺序（断线重拨按同序复用）
#[test]
fn session_handle_remembers_all_candidate_addrs_in_order() {
    let mut t = PeerHandleTable::default();
    let mut e = entry("multi");
    e.addrs = vec!["/ip4/192.168.1.5/tcp/47821".to_string(), RELAY_DIAL_ADDR.to_string()];
    let h = t.mint_session(e.clone());
    let got = t.resolve_session(&h).expect("resolved");
    assert_eq!(got.addrs, e.addrs, "候选表不得去重/重排");
}

#[test]
fn take_session_removes_entry() {
    let mut t = PeerHandleTable::default();
    let h = t.mint_session(entry("n1"));
    assert_eq!(t.take_session(&h).unwrap().node_id, "n1");
    assert!(t.take_session(&h).is_none());
    assert!(t.resolve_session(&h).is_none());
}

#[test]
fn unknown_handle_is_error_not_passthrough() {
    // Phase 4 收紧：非句柄入参不再透传为 node-id（双态寻址退役）
    let t = PeerHandleTable::default();
    assert!(t.resolve_session("some-node-id").is_none());
}

#[test]
fn minted_handles_are_unique() {
    let mut t = PeerHandleTable::default();
    let h1 = t.mint_session(entry("n1"));
    let h2 = t.mint_session(entry("n1"));
    assert_ne!(h1, h2);
}
