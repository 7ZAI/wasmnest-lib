//! 中继会合客户端（跨 NAT 设备发现）。
//!
//! ## 解决什么
//!
//! mDNS 只在同一二层网络可见；两台设备跨 NAT 时，即使都连上同一个中继，也
//! 互相不知道对方的 PeerId。本模块在 relay 预留生效后，周期性向中继控制面
//! `/wasmnest/relay-control/1` 发送 `announce`，拿回同房间的其它设备，拼出
//! `<relay>/p2p-circuit/p2p/<peer>` 候选地址，经总线 `peer:relay-devices`
//! 推给插件前端。
//!
//! ## 边界
//!
//! - **只做发现，不做授权**：中继会合表不是信任表。拨号仍走引擎的 node-id
//!   绑定校验与宿主首连确认；发现到 ≠ 能访问。
//! - **只在中继预留生效后工作**：没有 `relay-reserved` 时既没有可拨的 circuit
//!   地址，也没有必要向中继登记。预留丢失即推空快照，界面上的「外网设备」随之
//!   消失（不保留陈旧条目）。
//! - **房间边界**：默认房间键 = [`DEFAULT_ROOM`]（同一台中继 = 同一个私有网络）；
//!   插件可经 `peer:relay-room` 发布**空间码**，宿主用 SHA-256 派生房间键后发给
//!   中继——中继只看到哈希，看不到空间码。
//! - **失败 fail-visible**：控制流超时 / 中继回错只记 warn 并保留上一份快照；
//!   不把「查不到」伪装成「没有设备」——增量由下一轮心跳纠正。
//!
//! ## 事件形状
//!
//! `peer:relay-devices`（host 发布；插件订阅后转 `plugin:<id>:relay-devices`）：
//! `{ devices: [...], status, error, relay, updatedAtMs }`。全量快照，前端按
//! nodeId 与 mDNS 缓存归并；空数组 = 当前没有中继可见设备。
//!
//! `status` 词表：`ok | disabled | relay-unavailable | unsupported | denied | error`。
//! 失败时保留上一份 `devices`（查不到 ≠ 没设备），只更新 status / error；
//! `updatedAtMs` 是宿主发布时刻（前端据此判断「状态可能过期」）。

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use wasmnest_p2p_engine::engine::RunningNode;
use wasmnest_p2p_engine::relay::RelayEndpoint;
use wasmnest_p2p_engine::{Multiaddr, PeerId};

use crate::PeerCtx;

/// 中继控制协议名（与 relay crate `wire::CONTROL_PROTOCOL` 同字面）
const CONTROL_PROTOCOL: &str = "/wasmnest/relay-control/1";
/// 未设置空间码时的房间键（同一台中继 = 同一个私有网络；见模块文档）
pub(crate) const DEFAULT_ROOM: &str = "nest";
/// 插件发布空间码的总线 topic（`{ room: "<raw code>" }`）
pub(crate) const ROOM_TOPIC: &str = "peer:relay-room";
/// 宿主静态订阅者注册名
const ROOM_SUBSCRIBER: &str = "host-peer-relay-room";
/// 心跳间隔：中继侧 TTL 90s，允许丢两次
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(25);
/// 单次控制请求超时（开流协商 + 往返）
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
/// 响应帧上限（中继侧 `MAX_FRAME_BYTES` 同值；64 台设备的名单约 14 KiB）
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// 总线 topic（host 发布）
pub(crate) const RELAY_DEVICES_TOPIC: &str = "peer:relay-devices";

/// 推给前端的单台设备
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayDevice {
    /// 64 位小写 hex 节点 ID（对端自报；拨号握手复核）
    pub node_id: String,
    /// libp2p PeerId（base58；circuit 地址末段）
    pub peer_id: String,
    /// 展示名（空 = 对端未命名）
    pub device_name: String,
    /// 可拨地址（当前恒为 `<relay>/p2p-circuit/p2p/<peer>`）
    pub addrs: Vec<String>,
    /// 中继侧最近登记时刻（Unix 毫秒）
    pub last_seen_ms: u64,
}

/// 全量快照（总线载荷）
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelaySnapshot {
    devices: Vec<RelayDevice>,
    /// 发现状态词表（ok = 本轮查询成功；其余见模块文档）
    status: &'static str,
    /// 失败分类 token 或截断后的错误原文（成功时 null）
    error: Option<String>,
    /// 当前使用的中继端点（未配置时 null）
    relay: Option<String>,
    /// 发布时刻（Unix 毫秒）；前端据此判断状态是否过期
    updated_at_ms: u64,
}

/// 发布去重键：devices + status + error + relay。
///
/// 刻意**不含** `updated_at_ms`：心跳每 25s 刷新时间戳会让前端每轮重渲染，
/// 而「状态没变」时前端的时间戳仍会停在上一次变化点——超过 60s 显示
/// 「状态可能过期」是预期行为（提示用户刷新，而不是假装实时）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SnapshotKey {
    devices: Vec<RelayDevice>,
    status: &'static str,
    error: Option<String>,
    relay: Option<String>,
}

impl SnapshotKey {
    fn new(devices: Vec<RelayDevice>, status: &'static str, error: Option<String>, relay: Option<String>) -> Self {
        Self {
            devices,
            status,
            error,
            relay,
        }
    }

    /// 失败 / 未就绪：保留上一份设备列表，只更新状态与错误
    fn keep_devices(
        last: Option<&SnapshotKey>,
        status: &'static str,
        error: Option<String>,
        relay: Option<String>,
    ) -> Self {
        Self::new(
            last.map(|key| key.devices.clone()).unwrap_or_default(),
            status,
            error,
            relay,
        )
    }
}

/// 是否发布：force（唤醒 / 首帧）或键变化才发
fn should_publish(last: Option<&SnapshotKey>, next: &SnapshotKey, force: bool) -> bool {
    force || last != Some(next)
}

/// 失败分类：旧中继 / allowlist / 其它原文。
///
/// 错误文本来自 [`announce`] 的 `relay rejected announce: <code>`；只认两个
/// 稳定 token，其余保留截断原文（不猜成因）。
fn classify_failure(error: &str) -> (&'static str, String) {
    if error.contains("invalid-request") {
        ("unsupported", "invalid-request".to_string())
    } else if error.contains("not-allowed") {
        ("denied", "not-allowed".to_string())
    } else {
        ("error", truncate_detail(error, 240))
    }
}

/// 错误摘要截断（字符边界安全；前端另有 120 字符展示上限）
fn truncate_detail(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push('…');
    out
}

/// 发布时刻（Unix 毫秒）
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 中继回执里的单条记录（本地最小镜像；不引 relay crate）
#[derive(Debug, Deserialize)]
struct WirePeer {
    peer_id: String,
    node_id: String,
    #[serde(default)]
    name: String,
    last_seen_ms: u64,
}

/// 中继回执（只取本模块需要的字段；`deny_unknown_fields` 不启用——
/// 旧 / 新中继多带字段不应让发现整批失败）
#[derive(Debug, Deserialize)]
struct ControlResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    peers: Option<Vec<WirePeer>>,
}

#[derive(Debug, Serialize)]
struct AnnounceRequest<'a> {
    op: &'static str,
    v: u32,
    room: &'a str,
    node_id: &'a str,
    name: &'a str,
}

/// 派生任务：随节点生命周期启停（`stop_locked` abort）。
pub(crate) fn spawn(ctx: std::sync::Arc<PeerCtx>) -> tokio::task::JoinHandle<()> {
    wasmnest_server_base::error_boundary::spawn_with_error_boundary("peer_net_relay_rendezvous", run(ctx))
}

async fn run(ctx: std::sync::Arc<PeerCtx>) {
    let mut last: Option<SnapshotKey> = None;
    let mut timer = tokio::time::interval(ANNOUNCE_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 首 tick 立即执行：节点启动 / 配置变更后不必等满一个心跳
    timer.tick().await;

    // 「预留刚配置好、还在 connecting」时用 2s 短轮询，别让首帧等满 25s 心跳
    let mut retry_soon = false;
    loop {
        // 定时心跳是「保持登记」；唤醒是「有人要现在看」（配置变更 / 前端刷新）。
        // 唤醒必须强制重发：前端可能在上一份快照发布之后才订阅，去重发布会让它
        // 永远等不到首帧（直到设备集合发生变化）。
        let force = if retry_soon {
            retry_soon = false;
            tokio::time::sleep(Duration::from_secs(2)).await;
            false
        } else {
            tokio::select! {
                _ = timer.tick() => false,
                _ = ctx.state.rendezvous_wakeup.notified() => true,
            }
        };

        let relay_hint = current_relay(&ctx);

        if !current_enabled(&ctx) {
            let key = SnapshotKey::new(Vec::new(), "disabled", None, relay_hint);
            publish(&ctx, &mut last, key, force);
            continue;
        }

        let Some((engine, node_id, device_name)) = current_runtime(&ctx).await else {
            // 节点未启动：清空上一份快照（重启后由新节点重新登记）
            let key = SnapshotKey::new(
                Vec::new(),
                "relay-unavailable",
                Some("node not running".to_string()),
                relay_hint,
            );
            publish(&ctx, &mut last, key, force);
            continue;
        };

        let relays = ctx.state.relay.desired();
        if relays.is_empty() || engine.relay_status().state.as_str() != "relay-reserved" {
            let key = SnapshotKey::new(Vec::new(), "relay-unavailable", None, relay_hint);
            publish(&ctx, &mut last, key, force);
            // 有中继但还没 reserved：2s 后再看；没有中继就等正常心跳
            retry_soon = !relays.is_empty();
            continue;
        }

        let mut devices = Vec::<RelayDevice>::new();
        let mut succeeded = 0usize;
        let mut ok_relay = None::<String>;
        let mut failures = Vec::<String>::new();
        for relay in relays {
            let endpoint = match RelayEndpoint::parse(&relay, None) {
                Ok(endpoint) => endpoint,
                Err(e) => {
                    tracing::warn!(relay = %relay, error = %e, "relay rendezvous: invalid relay endpoint");
                    continue;
                }
            };
            let room = current_room(&ctx);
            match announce(&engine, &endpoint, &node_id, &device_name, &room).await {
                Ok(peers) => {
                    succeeded += 1;
                    if ok_relay.is_none() {
                        ok_relay = Some(endpoint.base().to_string());
                    }
                    merge_peers(&mut devices, &endpoint, peers);
                }
                Err(e) => {
                    // 保留上一份快照（fail-visible：查不到 ≠ 没设备），下一轮重试
                    tracing::warn!(
                        relay = %endpoint.base(),
                        error = %e,
                        "relay rendezvous announce failed"
                    );
                    failures.push(e);
                }
            }
        }
        // 全部中继都查询失败：保留上一份 devices，只更新 status / error
        // （fail-visible 的「查不到 ≠ 没设备」；中继真正不可达时 relay_status
        // 会转 Lost，走上面的清空分支）
        if succeeded == 0 {
            let (status, error) = classify_failure(&failures.join("; "));
            let key = SnapshotKey::keep_devices(last.as_ref(), status, Some(error), relay_hint);
            publish(&ctx, &mut last, key, force);
            continue;
        }
        // 顺序稳定，避免 HashMap / 中继返回顺序造成无意义的重发
        devices.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        devices.dedup_by(|a, b| a.node_id == b.node_id);
        publish(&ctx, &mut last, SnapshotKey::new(devices, "ok", None, ok_relay), force);
    }
}

/// 当前配置的第一台中继端点（状态卡展示用；未配置返回 None）
fn current_relay(ctx: &PeerCtx) -> Option<String> {
    ctx.state
        .relay
        .desired()
        .into_iter()
        .next()
        .map(|addr| addr.to_string())
}

/// 当前运行节点投影（节点未启动返回 None；锁只在取值期间持有）
async fn current_runtime(ctx: &PeerCtx) -> Option<(RunningNode, String, String)> {
    let runtime = ctx.state.runtime.lock().await;
    let runtime = runtime.as_ref()?;
    Some((
        runtime.running.p2p_handle(),
        runtime.node_id.clone(),
        runtime.device_name.clone(),
    ))
}

/// 向一台中继登记并取回同房间设备。
async fn announce(
    engine: &RunningNode,
    endpoint: &RelayEndpoint,
    node_id: &str,
    device_name: &str,
    room: &str,
) -> Result<Vec<WirePeer>, String> {
    let request = AnnounceRequest {
        op: "announce",
        v: 1,
        room,
        node_id,
        name: device_name,
    };
    let body = serde_json::to_vec(&request).map_err(|e| format!("encode announce: {e}"))?;
    if body.len() > 4096 {
        return Err(format!("announce frame too large: {} bytes", body.len()));
    }

    let exchange = async {
        let stream = engine
            .open_stream_to_peer(endpoint.peer_id(), CONTROL_PROTOCOL)
            .await
            .map_err(|e| format!("open relay control stream: {e}"))?;
        let mut io = stream.compat();
        io.write_all(&(body.len() as u32).to_be_bytes())
            .await
            .map_err(|e| format!("write frame header: {e}"))?;
        io.write_all(&body)
            .await
            .map_err(|e| format!("write frame body: {e}"))?;
        io.flush().await.map_err(|e| format!("flush frame: {e}"))?;

        let mut header = [0u8; 4];
        io.read_exact(&mut header)
            .await
            .map_err(|e| format!("read frame header: {e}"))?;
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > MAX_RESPONSE_BYTES {
            return Err(format!("invalid response frame length: {len}"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf)
            .await
            .map_err(|e| format!("read frame body: {e}"))?;
        let response: ControlResponse = serde_json::from_slice(&buf).map_err(|e| format!("decode response: {e}"))?;
        if !response.ok {
            return Err(format!(
                "relay rejected announce: {}",
                response.error.as_deref().unwrap_or("unknown")
            ));
        }
        Ok(response.peers.unwrap_or_default())
    };

    tokio::time::timeout(REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("relay announce timed out after {REQUEST_TIMEOUT:?}"))?
}

/// 把中继记录拼成 circuit 候选并入快照（跳过自己 / 非法 PeerId 只留痕）。
fn merge_peers(devices: &mut Vec<RelayDevice>, endpoint: &RelayEndpoint, peers: Vec<WirePeer>) {
    for peer in peers {
        let node_id = peer.node_id.trim().to_lowercase();
        if node_id.len() != 64 || !node_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            tracing::warn!(node_id = %peer.node_id, "relay rendezvous: invalid node id");
            continue;
        }
        let peer_id = match peer.peer_id.parse::<PeerId>() {
            Ok(peer_id) => peer_id,
            Err(e) => {
                tracing::warn!(peer_id = %peer.peer_id, error = %e, "relay rendezvous: invalid peer id");
                continue;
            }
        };
        let addr = circuit_addr(endpoint.base(), peer_id);
        devices.push(RelayDevice {
            node_id,
            peer_id: peer_id.to_base58(),
            device_name: peer.name,
            addrs: vec![addr.to_string()],
            last_seen_ms: peer.last_seen_ms,
        });
    }
}

/// `<relay base>/p2p-circuit/p2p/<peer>`
fn circuit_addr(base: &Multiaddr, peer: PeerId) -> Multiaddr {
    format!("{base}/p2p-circuit/p2p/{peer}")
        .parse()
        .expect("relay base + fixed segments is always a valid multiaddr")
}

/// 发布快照：`force` 或键变化才发（避免 25s 心跳刷前端）
fn publish(ctx: &PeerCtx, last: &mut Option<SnapshotKey>, next: SnapshotKey, force: bool) {
    if !should_publish(last.as_ref(), &next, force) {
        return;
    }
    let snapshot = RelaySnapshot {
        devices: next.devices.clone(),
        status: next.status,
        error: next.error.clone(),
        relay: next.relay.clone(),
        updated_at_ms: now_ms(),
    };
    let payload = serde_json::to_value(snapshot).unwrap_or_else(|_| {
        serde_json::json!({
            "devices": [],
            "status": "error",
            "error": "snapshot encode failed",
            "relay": null,
            "updatedAtMs": now_ms(),
        })
    });
    ctx.ports.bus.publish(RELAY_DEVICES_TOPIC, "host", payload);
    tracing::info!(
        count = next.devices.len(),
        status = next.status,
        "relay rendezvous snapshot published"
    );
    *last = Some(next);
}

/// 会合是否由活跃插件启用（插件停用即关，避免「应用已关仍被中继发现」）
fn current_enabled(ctx: &PeerCtx) -> bool {
    ctx.state.rendezvous_enabled.load(std::sync::atomic::Ordering::Relaxed)
}

/// 读取当前房间键（宿主默认 `nest`；插件设置空间码后为 SHA-256 派生值）
fn current_room(ctx: &PeerCtx) -> String {
    ctx.state
        .rendezvous_room
        .lock()
        .expect("relay room lock poisoned")
        .clone()
}

/// 空间码原文 → 房间键。空 = 默认房间；非空 = `hex(sha256("wasmnest-relay-room\0" + code))`。
///
/// 中继只看到哈希；两端用同一个码才能算出同一个键。截 64 位 hex 与中继的
/// `[A-Za-z0-9_-]{1,64}` 房间语法兼容。
pub(crate) fn derive_room(raw: &str) -> String {
    let code = raw.trim();
    if code.is_empty() {
        return DEFAULT_ROOM.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"wasmnest-relay-room\0");
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

/// 设置空间码（总线消息入口）：非法码只留痕、保留旧值（fail-visible，
/// 不静默清空成 relay-wide 扩大可见范围）。
pub(crate) fn set_room(ctx: &PeerCtx, raw: &str, enabled: Option<bool>) {
    if let Some(enabled) = enabled {
        ctx.state
            .rendezvous_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }
    let code = raw.trim();
    if !code.is_empty()
        && (code.len() > 64
            || !code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    {
        tracing::warn!("relay room rejected: must be 1-64 chars of [A-Za-z0-9_-]");
        return;
    }
    let room = derive_room(code);
    *ctx.state.rendezvous_room.lock().expect("relay room lock poisoned") = room;
    ctx.state.rendezvous_wakeup.notify_one();
}

/// 房间码静态订阅（与发现刷新订阅读同一套就绪等待；进程内只挂一次）
struct RelayRoomHandler {
    ctx: std::sync::Arc<PeerCtx>,
}

impl wasmnest_server_base::ports::BusMessageHandler for RelayRoomHandler {
    fn on_message(&self, msg: &wasmnest_server_base::wire::BusMessage) -> anyhow::Result<()> {
        let room = msg.payload.get("room").and_then(|v| v.as_str()).unwrap_or("");
        // 缺省 = 只同步房间码，保留当前开关（刷新路径 / 兼容只发 room 的调用方）
        let enabled = msg.payload.get("enabled").and_then(|v| v.as_bool());
        set_room(&self.ctx, room, enabled);
        Ok(())
    }
}

static ROOM_SUBSCRIBED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn spawn_room_subscriber(ctx: std::sync::Arc<PeerCtx>) {
    use std::sync::atomic::Ordering;
    if ROOM_SUBSCRIBED.swap(true, Ordering::SeqCst) {
        return;
    }
    wasmnest_server_base::error_boundary::spawn_with_error_boundary("peer_net_relay_room_subscriber", async move {
        loop {
            if ctx.ports.bus.is_ready() {
                ctx.ports
                    .bus
                    .subscribe_static(
                        ROOM_SUBSCRIBER,
                        ROOM_TOPIC,
                        Box::new(RelayRoomHandler { ctx: ctx.clone() }),
                    )
                    .await;
                tracing::info!("peer relay room subscriber registered");
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> RelayEndpoint {
        RelayEndpoint::parse(
            &"/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"
                .parse()
                .expect("relay addr"),
            None,
        )
        .expect("relay endpoint")
    }

    fn peer() -> PeerId {
        "12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA"
            .parse()
            .expect("peer id")
    }

    #[test]
    fn circuit_addr_拼出中继路径且可解析() {
        let addr = circuit_addr(relay().base(), peer());
        let text = addr.to_string();
        assert!(text.ends_with("/p2p-circuit/p2p/12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA"));
        assert!(text.starts_with("/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"));
    }

    #[test]
    fn merge_peers_跳过非法_peer_id_并保留其余() {
        let mut devices = Vec::new();
        merge_peers(
            &mut devices,
            &relay(),
            vec![
                WirePeer {
                    peer_id: "not-a-peer-id".into(),
                    node_id: "a".repeat(64),
                    name: "bad".into(),
                    last_seen_ms: 1,
                },
                WirePeer {
                    peer_id: peer().to_base58(),
                    node_id: "B".repeat(64),
                    name: "phone".into(),
                    last_seen_ms: 2,
                },
            ],
        );
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].node_id, "b".repeat(64), "node id 统一小写");
        assert_eq!(devices[0].device_name, "phone");
        assert_eq!(devices[0].addrs.len(), 1);
        assert!(devices[0].addrs[0].contains("/p2p-circuit/p2p/"));
    }

    #[test]
    fn 空间码派生稳定且不同码不同房间() {
        assert_eq!(derive_room(""), "nest");
        assert_eq!(derive_room("   "), "nest");
        let a = derive_room("my-home");
        let b = derive_room("my-home");
        let c = derive_room("my-office");
        assert_eq!(a, b, "同一码必须派生出同一房间键");
        assert_ne!(a, c, "不同码必须隔离");
        assert_eq!(a.len(), 64, "房间键是 64 位 hex，兼容中继房间语法");
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn classify_failure_只认旧中继与_allowlist_两个稳定_token() {
        assert_eq!(
            classify_failure("relay rejected announce: invalid-request"),
            ("unsupported", "invalid-request".to_string())
        );
        assert_eq!(
            classify_failure("relay rejected announce: not-allowed"),
            ("denied", "not-allowed".to_string())
        );
        let (status, detail) = classify_failure("relay announce timed out after 8s");
        assert_eq!(status, "error");
        assert!(detail.contains("timed out"));
    }

    #[test]
    fn truncate_detail_保留字符边界() {
        assert_eq!(truncate_detail("short", 10), "short");
        let long = "中".repeat(300);
        let cut = truncate_detail(&long, 240);
        assert_eq!(cut.chars().count(), 241, "240 字符 + 省略号");
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn should_publish_忽略时间戳且_force_总是发布() {
        let a = SnapshotKey::new(vec![], "ok", None, None);
        let b = SnapshotKey::new(vec![], "ok", None, None);
        assert!(!should_publish(Some(&a), &b, false), "内容相同不重发");
        assert!(should_publish(None, &b, false), "首帧必须发布");
        assert!(should_publish(Some(&a), &b, true), "唤醒强制发布");
        let c = SnapshotKey::new(vec![], "error", Some("x".into()), None);
        assert!(should_publish(Some(&a), &c, false), "status 变化必须发布");
    }

    #[test]
    fn 失败状态保留上一份设备() {
        let mut devices = Vec::new();
        merge_peers(
            &mut devices,
            &relay(),
            vec![WirePeer {
                peer_id: peer().to_base58(),
                node_id: "c".repeat(64),
                name: "phone".into(),
                last_seen_ms: 1,
            }],
        );
        let last = SnapshotKey::new(devices.clone(), "ok", None, None);
        let failed = SnapshotKey::keep_devices(
            Some(&last),
            "error",
            Some("timeout".into()),
            Some(relay().base().to_string()),
        );
        assert_eq!(failed.devices, devices, "查询失败不得清空设备列表");
        assert_eq!(failed.status, "error");
        assert!(failed.relay.is_some());
    }

    #[test]
    fn 快照序列化包含_status_error_relay_与时间戳() {
        let key = SnapshotKey::new(vec![], "unsupported", Some("invalid-request".into()), None);
        let snapshot = RelaySnapshot {
            devices: key.devices.clone(),
            status: key.status,
            error: key.error.clone(),
            relay: key.relay.clone(),
            updated_at_ms: 1_730_000_000_000,
        };
        let value = serde_json::to_value(snapshot).expect("serialize");
        assert_eq!(value["status"], "unsupported");
        assert_eq!(value["error"], "invalid-request");
        assert!(value["relay"].is_null());
        assert_eq!(value["updatedAtMs"], 1_730_000_000_000u64);
        assert_eq!(value["devices"], serde_json::json!([]));
    }

    #[test]
    fn 同名设备去重由调用方负责_排序稳定() {
        let mut devices = vec![
            RelayDevice {
                node_id: "b".repeat(64),
                peer_id: peer().to_base58(),
                device_name: "b".into(),
                addrs: vec![],
                last_seen_ms: 1,
            },
            RelayDevice {
                node_id: "a".repeat(64),
                peer_id: peer().to_base58(),
                device_name: "a".into(),
                addrs: vec![],
                last_seen_ms: 1,
            },
        ];
        devices.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        devices.dedup_by(|a, b| a.node_id == b.node_id);
        assert_eq!(devices[0].node_id, "a".repeat(64));
    }
}
