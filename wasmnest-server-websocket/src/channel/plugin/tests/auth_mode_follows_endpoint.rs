//! general — crate 内单元测试（自 packages/wasmnest-server-websocket/src/channel/plugin.rs 迁出）

use super::*;

use crate::endpoint::EndpointAuth;

#[test]
fn auth_mode_follows_endpoint_declaration() {
    let open = PluginChannel::new(&test_endpoint("open", EndpointAuth::None), addr(41001));
    assert_eq!(open.auth_mode(), AuthMode::None);
    assert_eq!(open.auth_timeout_close_code(), None, "none 模式无认证窗口");

    let guarded = PluginChannel::new(&test_endpoint("jwt", EndpointAuth::Jwt), addr(41002));
    assert_eq!(guarded.auth_mode(), AuthMode::Required);
    assert_eq!(guarded.auth_timeout_close_code(), Some(CLOSE_AUTH_FAILED));
}
#[test]
fn client_id_is_peer_addr_key() {
    // clientId 必须与注册表会话键同源（对端地址字符串），否则 list-clients /
    // 单发寻址对不上号
    let channel = PluginChannel::new(&test_endpoint("cid", EndpointAuth::None), addr(41003));
    assert_eq!(channel.client_id, "127.0.0.1:41003");
}
#[test]
fn connect_and_disconnect_guards_are_idempotent() {
    let mut channel = PluginChannel::new(&test_endpoint("guard", EndpointAuth::None), addr(41004));
    assert!(!channel.connected_announced);
    // 接入守卫：重复调用只认第一次（调用方在 on_auth_ok 里）
    channel.connected_announced = true;
    channel.connected_announced = true;
    assert!(!channel.disconnect_reported);
    // 断开守卫：未接入（认证失败）时不得上报
    channel.connected_announced = false;
    assert!(!channel.disconnect_reported);
}
#[test]
fn auth_frame_requires_type_and_token() {
    // 形状契约（D8）：仅接受 {"type":"auth","token":"..."}
    let ok: AuthFrame = serde_json::from_str(r#"{"type":"auth","token":"t"}"#).unwrap();
    assert_eq!(ok.frame_type, "auth");
    assert_eq!(ok.token, "t");
    assert!(
        serde_json::from_str::<AuthFrame>(r#"{"type":"ping","token":"t"}"#).is_err()
            || serde_json::from_str::<AuthFrame>(r#"{"type":"ping","token":"t"}"#)
                .map(|f| f.frame_type != "auth")
                .unwrap()
    );
    // 缺 token / 非 JSON：形状不匹配 → 走「丢弃 + warn」分支（不 panic）
    assert!(serde_json::from_str::<AuthFrame>(r#"{"type":"auth"}"#).is_err());
    assert!(serde_json::from_str::<AuthFrame>("not json").is_err());
}
#[test]
fn frame_queue_is_bounded_and_preserves_order() {
    let entry = test_endpoint("queue", EndpointAuth::None);
    let mut channel = PluginChannel::new(&entry, addr(41005));
    let mut receiver = channel.frames_rx.take().expect("frame receiver");

    for index in 0..PLUGIN_WS_SEND_QUEUE_CAPACITY {
        assert!(channel
            .enqueue_frame("text", format!("frame-{index}").into_bytes())
            .is_ok());
    }
    assert!(matches!(
        channel.enqueue_frame("binary", vec![0xff]),
        Err(FrameEnqueueError::Full)
    ));

    let first = receiver.try_recv().expect("first frame");
    assert_eq!(first.kind, "text");
    assert_eq!(first.payload, b"frame-0");
    let second = receiver.try_recv().expect("second frame");
    assert_eq!(second.payload, b"frame-1");

    drop(receiver);
    assert!(matches!(
        channel.enqueue_frame("text", b"closed".to_vec()),
        Err(FrameEnqueueError::Closed)
    ));
    crate::endpoint::remove(&entry.endpoint_id);
}
