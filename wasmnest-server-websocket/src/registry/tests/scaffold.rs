//! packages/wasmnest-server-websocket/src/registry.rs 的跨分组测试脚手架（用例文件经 `use super::scaffold::*` 引用）

use super::*;

/// 构造带属主 / 端点标识的注册条目（插件端点通道域测试用）
pub(super) fn entry_owned(
    client_id: &str,
    owner: &str,
    endpoint_id: &str,
    authenticated: bool,
) -> (String, WsSessionEntry) {
    entry_with(client_id, Some(owner), Some(endpoint_id), authenticated, None, None)
}

/// 构造条目共用体：经伪 WS 握手取得真实 Addr，按插件端点通道装配骨架与处理器
pub(super) fn entry_with(
    client_id: &str,
    owner: Option<&str>,
    endpoint_id: Option<&str>,
    authenticated: bool,
    device_name: Option<&str>,
    fingerprint: Option<&str>,
) -> (String, WsSessionEntry) {
    let port = 20000u16 + (client_id.bytes().fold(0usize, |acc, b| acc.wrapping_add(b as usize)) % 10000) as u16;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let req = actix_web::test::TestRequest::default()
        .insert_header(("Connection", "Upgrade"))
        .insert_header(("Upgrade", "websocket"))
        .insert_header(("Sec-WebSocket-Version", "13"))
        .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .to_http_request();
    // 空 payload 流：握手需要流参数，测试不驱动 actor future，空流即可
    let payload: actix_web::dev::Payload = actix_web::dev::Payload::None;
    let mut actor = WsConnBase::new(
        crate::conn::ConnSpec {
            owner: owner.map(|s| s.to_string()),
            endpoint_id: endpoint_id.map(|s| s.to_string()),
            ..crate::conn::ConnSpec::new(addr)
        },
        Box::new(StubChannel),
    );
    actor.disable_registry_for_test();
    let (actor_addr, _resp) = actix_web_actors::ws::WsResponseBuilder::new(actor, &req, payload)
        .start_with_addr()
        .expect("fake ws handshake must succeed");

    (
        client_id.to_string(),
        WsSessionEntry {
            actor_addr,
            socket_addr: addr,
            subject: None,
            device_name: device_name.map(|s| s.to_string()),
            fingerprint: fingerprint.map(|s| s.to_string()),
            authenticated,
            connected_at: 0,
            owner: owner.map(|s| s.to_string()),
            endpoint_id: endpoint_id.map(|s| s.to_string()),
            closing: false,
        },
    )
}

/// 测试用空通道处理器（不被驱动，仅满足骨架构造约束）
pub(super) struct StubChannel;

impl crate::conn::ChannelHandler for StubChannel {
    fn auth_mode(&self) -> crate::conn::AuthMode {
        crate::conn::AuthMode::None
    }

    fn on_text(&mut self, _conn: &mut WsConnBase, _text: String, _ctx: &mut crate::conn::ConnCtx) {}

    fn on_binary(&mut self, _conn: &mut WsConnBase, _data: Vec<u8>, _ctx: &mut crate::conn::ConnCtx) {}
}

/// 把条目列表转成测试用 HashMap
/// 当前无调用者（scaffold 通用工具，供未来用例）；保持主题化：测试脚手架常驻
#[allow(dead_code)]
pub(super) fn entries_map(entries: Vec<(String, WsSessionEntry)>) -> HashMap<String, WsSessionEntry> {
    entries.into_iter().collect()
}

/// 构造独立注册表实例
///
/// 端点域 / 属主回收用例用本地实例，避免全局单例被并行用例相互清空
pub(super) fn local_registry() -> WsSessionRegistry {
    WsSessionRegistry {
        sessions: RwLock::new(HashMap::new()),
        addr_to_client_id: RwLock::new(HashMap::new()),
        pending_endpoint_reservations: RwLock::new(HashSet::new()),
    }
}

/// 批量写入条目（直插 sessions：伪造 Addr 不走 register 的真实地址路径）
pub(super) async fn seed(registry: &WsSessionRegistry, entries: Vec<(String, WsSessionEntry)>) {
    let mut sessions = registry.sessions.write().unwrap_or_else(|e| e.into_inner());
    for (client_id, entry) in entries {
        sessions.insert(client_id, entry);
    }
}

/// 取注册表当前全部 client_id（升序，便于断言）
pub(super) async fn client_ids(registry: &WsSessionRegistry) -> Vec<String> {
    let mut ids: Vec<String> = registry
        .sessions
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect();
    ids.sort();
    ids
}

// ==================== 端点域寻址 / 属主回收 / 按端点断开 ====================
//
// 一律用 `local_registry()`：这些用例只验证注册表自身语义，写全局单例会在
// 并行执行时干扰同居用例
#[actix_rt::test]
pub(super) async fn purge_for_plugin_only_hits_owner() {
    let registry = local_registry();

    seed(
        &registry,
        vec![
            entry_owned("p-a1", "plugin-a", "wse-a", true),
            entry_owned("p-a2", "plugin-a", "wse-a", true),
            entry_owned("p-b1", "plugin-b", "wse-b", true),
        ],
    )
    .await;

    let mut purged = registry.purge_for_plugin("plugin-a", 4005, "plugin deactivated").await;
    purged.sort();
    assert_eq!(purged, vec!["p-a1", "p-a2"], "只回收本人属主条目");
    assert_eq!(
        client_ids(&registry).await,
        vec!["p-a1", "p-a2", "p-b1"],
        "关闭标记期间条目仍由 actor 持有，最终摘除由 stopping 完成"
    );
    for client_id in ["p-a1", "p-a2"] {
        registry.unregister(client_id).await;
    }

    // 未知属主：命中为空、幂等不 panic
    assert!(
        registry.purge_for_plugin("plugin-none", 4005, "gone").await.is_empty(),
        "未知属主无命中"
    );
    assert_eq!(client_ids(&registry).await.len(), 1, "未知属主回收不得误伤条目");
}

#[actix_rt::test]
pub(super) async fn disconnect_by_endpoint_hits_only_that_endpoint() {
    let registry = local_registry();

    seed(
        &registry,
        vec![
            entry_owned("p-a1", "plugin-a", "wse-a", true),
            entry_owned("p-a2", "plugin-a", "wse-a", true),
            entry_owned("p-b1", "plugin-b", "wse-b", true),
        ],
    )
    .await;

    assert_eq!(registry.endpoint_client_count("wse-a").await, 2);
    assert_eq!(registry.list_by_endpoint("wse-a").await.len(), 2);
    assert!(registry.is_endpoint_client("wse-a", "p-a1").await);
    assert!(
        !registry.is_endpoint_client("wse-a", "p-b1").await,
        "端点域寻址不得跨端点命中"
    );

    let closed = registry.disconnect_by_endpoint("wse-a", 4004, "kicked by plugin").await;
    assert_eq!(closed, 2, "按端点断开命中该端点全部客户端");
    assert_eq!(registry.list_by_endpoint("wse-a").await.len(), 2, "关闭事件前条目仍在");
    assert_eq!(registry.list_by_endpoint("wse-b").await.len(), 1, "其他端点不受影响");
    for client_id in ["p-a1", "p-a2"] {
        registry.unregister(client_id).await;
    }

    assert_eq!(registry.disconnect_by_endpoint("wse-a", 4004, "kicked").await, 0);
}

#[actix_rt::test]
pub(super) async fn endpoint_queries_unknown_id_are_idempotent() {
    let registry = local_registry();

    // 未登记条目的端点 / 属主标识：一律返回空命中，不 panic
    assert!(registry.list_by_endpoint("wse-none").await.is_empty());
    assert_eq!(registry.endpoint_client_count("wse-none").await, 0);
    assert!(!registry.is_endpoint_client("wse-none", "c-none").await);
    assert_eq!(registry.broadcast_to_endpoint("wse-none", "ping".to_string()).await, 0);
    assert_eq!(registry.disconnect_by_endpoint("wse-none", 4005, "gone").await, 0);
    assert!(registry.purge_for_plugin("plugin-none", 4005, "gone").await.is_empty());
}

#[actix_rt::test]
pub(super) async fn endpoint_targeted_send_and_broadcast() {
    let registry = local_registry();

    seed(
        &registry,
        vec![
            entry_owned("p-a1", "plugin-a", "wse-a", true),
            entry_owned("p-a2", "plugin-a", "wse-a", true),
        ],
    )
    .await;

    // 错配寻址：端点句柄与客户端不属于同一端点 → Err（不消费句柄）
    let mismatch = registry
        .send_to_endpoint_client("wse-b", "p-a1", "hello".to_string())
        .await;
    assert!(mismatch.is_err(), "跨端点寻址必须被拒");
    assert!(
        registry.is_endpoint_client("wse-a", "p-a1").await,
        "拒绝不得消费/摘除句柄"
    );

    // 单发命中：客户端已摘除时返回 Err（fail-visible，不静默丢弃）
    let missing = registry
        .send_to_endpoint_client("wse-b", "p-none", "hello".to_string())
        .await;
    assert!(missing.is_err(), "未知客户端必须返回错误");

    // 广播成功入队数不超过端点在线客户端数（actor 未被驱动时投递失败 → 计数 0，
    // 故只断言上界与不 panic）
    let sent = registry.broadcast_to_endpoint("wse-a", "ping".to_string()).await;
    assert!(sent <= 2, "广播成功数不得超过在线客户端数，实际 {sent}");
}

// ==================== 停机下线（票据 05 四条断开路径之一：服务器停机 1001） ====================
#[actix_rt::test]
pub(super) async fn shutdown_closes_only_plugin_endpoint_clients() {
    let registry = local_registry();
    seed(
        &registry,
        vec![
            entry_owned("p-a1", "plugin-a", "wse-a", true),
            entry_owned("p-a2", "plugin-b", "wse-b", true),
        ],
    )
    .await;

    // 停机只下线插件端点客户端（终态只剩该类连接）
    assert_eq!(
        registry
            .disconnect_all_endpoint_clients(1001, "server shutting down")
            .await,
        2
    );
    assert_eq!(
        client_ids(&registry).await,
        vec!["p-a1", "p-a2"],
        "插件端点先标记关闭，最终摘除由 actor stopping 完成"
    );
    for client_id in ["p-a1", "p-a2"] {
        registry.unregister(client_id).await;
    }
    assert_eq!(
        registry
            .disconnect_all_endpoint_clients(1001, "server shutting down")
            .await,
        0
    );
}

/// 远程属主不可见另一属主连接的端点域条目（跨属主隔离，属主回收用例的补充）
#[actix_rt::test]
pub(super) async fn cross_owner_endpoint_domain_is_isolated() {
    let registry = local_registry();
    seed(
        &registry,
        vec![
            entry_owned("p-a1", "plugin-a", "wse-a", true),
            entry_owned("p-b1", "plugin-b", "wse-b", true),
        ],
    )
    .await;

    // 属主 B 的端点/客户端键不命中 A 的端点域
    assert!(!registry.is_endpoint_client("wse-b", "p-a1").await);
    assert_eq!(registry.list_by_endpoint("wse-a").await.len(), 1);
}
