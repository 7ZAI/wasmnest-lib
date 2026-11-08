//! T06 隧道管理器单测：单一引用计数、属主仲裁、`allowWan` 门控、生命周期清场。
//!
//! 引擎与对等面都用替身（不启动网络）；首帧 / 票据 / 准入等判定属 T05 单测，
//! 这里只断言「谁在什么时候建立 / 释放 reservation」与「句柄 / 规则只允许属主操作」。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasmnest_p2p_engine::Multiaddr;
use wasmnest_server_base::face::PeerFaceResolver;

use crate::tunnel::frame::read_reply;
use crate::tunnel::server::{BackendConnector, TunnelServer};

use super::*;
use crate::tunnel::mode::Subnet;

const RELAY: &str = "/ip4/127.0.0.1/tcp/4001";
const LAN: &str = "/ip4/127.0.0.1/tcp/47613";
/// 合法 relay PeerId（multiaddr 解析要求 `/p2p/<peer-id>` 是真正的 base58 multihash）
const RELAY_PEER: &str = "12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA";
/// 合法目标 PeerId（经 relay 的拨号地址末段）
const TARGET_PEER: &str = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

#[derive(Default)]
struct FakeState {
    node_started: bool,
    reserve_calls: usize,
    release_calls: usize,
    /// 每次 reserve 的地址集合（R11/R13：地址变化要重建、域名先解析）
    reserve_addrs: Vec<Vec<String>>,
    dials: Vec<(String, Vec<String>)>,
    dial_fails: bool,
    /// `Some(kind)` = 所有拨号按该成因失败（分类判据用）
    fail_kind: Option<LanFailure>,
    /// `Some(causes)` = 逐候选成因（多地址混合失败；优先于 `fail_kind`）
    fail_causes: Option<Vec<LanFailure>>,
    /// 传输层信任（R07 锁：`matched` 只认这个）
    trusted: bool,
    /// 待消费的入站流（隧道接收循环测试用）
    inbound: Vec<(NodeId, AccessPath, TunnelIo)>,
    inbound_calls: usize,
    /// 模拟接收器结束：接下来 N 次 `next_inbound` 返回 `None`
    inbound_none_left: usize,
    facts: NetworkFacts,
    events: Vec<(String, serde_json::Value)>,
}

struct FakeEngine {
    state: Mutex<FakeState>,
    /// 入站流队列变更通知（空队列时 `next_inbound` 必须能被后续 push 唤醒）
    inbound_notify: tokio::sync::Notify,
}

impl FakeEngine {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FakeState::default()),
            inbound_notify: tokio::sync::Notify::new(),
        })
    }

    fn reserve_calls(&self) -> usize {
        self.state.lock().unwrap().reserve_calls
    }

    fn release_calls(&self) -> usize {
        self.state.lock().unwrap().release_calls
    }

    fn dials(&self) -> Vec<(String, Vec<String>)> {
        self.state.lock().unwrap().dials.clone()
    }

    fn set_dial_fails(&self) {
        self.state.lock().unwrap().dial_fails = true;
    }

    fn set_failure(&self, kind: LanFailure) {
        self.state.lock().unwrap().fail_kind = Some(kind);
    }

    fn set_failure_causes(&self, causes: Vec<LanFailure>) {
        self.state.lock().unwrap().fail_causes = Some(causes);
    }

    fn set_trusted(&self, trusted: bool) {
        self.state.lock().unwrap().trusted = trusted;
    }

    fn push_inbound(&self, node: &str, io: TunnelIo) {
        let node = NodeId::parse(node).unwrap();
        self.state
            .lock()
            .unwrap()
            .inbound
            .push((node, AccessPath::LanDirect, io));
        self.inbound_notify.notify_one();
    }

    fn inbound_calls(&self) -> usize {
        self.state.lock().unwrap().inbound_calls
    }

    /// 模拟接收器结束（节点重启 / 流控制面重建）
    fn end_inbound_streams(&self, times: usize) {
        self.state.lock().unwrap().inbound_none_left = times;
    }

    fn reserve_addrs(&self) -> Vec<Vec<String>> {
        self.state.lock().unwrap().reserve_addrs.clone()
    }

    fn set_facts(&self, facts: NetworkFacts) {
        self.state.lock().unwrap().facts = facts;
    }

    fn events(&self) -> Vec<(String, serde_json::Value)> {
        self.state.lock().unwrap().events.clone()
    }

    fn event_modes(&self) -> Vec<String> {
        self.events()
            .iter()
            .filter(|(event, _)| event == "peer-mode")
            .filter_map(|(_, payload)| payload.get("mode").and_then(|v| v.as_str()).map(str::to_string))
            .collect()
    }
}

/// 单网段事实（192.168.1.0/24，非蜂窝）——判据表的默认输入
fn wifi_facts() -> NetworkFacts {
    NetworkFacts {
        known: true,
        cellular: false,
        local_subnets: vec![Subnet::new("192.168.1.0".parse().unwrap(), 24).unwrap()],
        mdns_known: false,
    }
}

#[async_trait]
impl TunnelEngine for FakeEngine {
    async fn ensure_node(&self) -> Result<()> {
        self.state.lock().unwrap().node_started = true;
        Ok(())
    }

    async fn dial(&self, node_id: &NodeId, addrs: &[Multiaddr]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.dials.push((
            node_id.as_str().to_string(),
            addrs.iter().map(|a| a.to_string()).collect(),
        ));
        if state.dial_fails {
            return Err(TunnelError::new(CODE_PEER_OFFLINE, "fake dial failure"));
        }
        Ok(())
    }

    async fn dial_classified(&self, node_id: &NodeId, addrs: &[Multiaddr]) -> std::result::Result<(), DialFailure> {
        let mut state = self.state.lock().unwrap();
        state.dials.push((
            node_id.as_str().to_string(),
            addrs.iter().map(|a| a.to_string()).collect(),
        ));
        // `fail_causes` 优先：用来模拟「多候选混合失败」的逐条成因
        if let Some(causes) = state.fail_causes.clone() {
            return Err(DialFailure::from_causes(causes, "fake mixed failure"));
        }
        // `fail_kind` 只作用于 LAN 候选：用来模拟「LAN 失败、relay 可用」
        let relay_dial = addrs.iter().any(|addr| addr.to_string().contains("/p2p-circuit"));
        if let Some(kind) = state.fail_kind {
            if !relay_dial {
                return Err(DialFailure::new(kind, "fake dial failure"));
            }
        }
        if state.dial_fails {
            return Err(DialFailure::new(LanFailure::Other, "fake dial failure"));
        }
        Ok(())
    }

    async fn network_facts(&self) -> NetworkFacts {
        self.state.lock().unwrap().facts.clone()
    }

    fn emit(&self, event: &str, payload: serde_json::Value) {
        self.state.lock().unwrap().events.push((event.to_string(), payload));
    }

    async fn open_tunnel(&self, _node_id: &NodeId) -> Result<TunnelIo> {
        Err(TunnelError::new(CODE_PEER_OFFLINE, "fake opener 不用"))
    }

    async fn next_inbound(&self) -> Option<(NodeId, AccessPath, TunnelIo)> {
        loop {
            {
                let mut state = self.state.lock().unwrap();
                state.inbound_calls += 1;
                if state.inbound_none_left > 0 {
                    state.inbound_none_left -= 1;
                    return None;
                }
                if !state.inbound.is_empty() {
                    return Some(state.inbound.remove(0));
                }
            }
            self.inbound_notify.notified().await;
        }
    }

    async fn trust_contains(&self, _node_id: &NodeId) -> bool {
        self.state.lock().unwrap().trusted
    }

    async fn reserve_relay(&self, addrs: &[Multiaddr]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.reserve_calls += 1;
        state.reserve_addrs.push(addrs.iter().map(|a| a.to_string()).collect());
        Ok(())
    }

    async fn release_relay(&self) -> Result<()> {
        self.state.lock().unwrap().release_calls += 1;
        Ok(())
    }

    async fn relay_snapshot(&self) -> RelaySnapshot {
        RelaySnapshot {
            state: "relay-reserved".into(),
            relay_addr: Some(RELAY.into()),
            detail: String::new(),
        }
    }

    async fn node_snapshot(&self) -> NodeSnapshot {
        NodeSnapshot {
            started: self.state.lock().unwrap().node_started,
            node_id: Some(NODE.into()),
            addrs: Vec::new(),
        }
    }
}

const NODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_NODE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct FakeStarter {
    calls: AtomicUsize,
}

#[async_trait]
impl PeerFaceStarter for FakeStarter {
    async fn start(&self, _resolver: PeerFaceResolver) -> Result<PeerFaceListener> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PeerFaceListener::new(SocketAddr::from(([127, 0, 0, 1], 39001)), || {}))
    }
}

fn manager(engine: Arc<FakeEngine>) -> (Arc<TunnelManager>, Arc<FakeStarter>) {
    let starter = Arc::new(FakeStarter {
        calls: AtomicUsize::new(0),
    });
    let manager = Arc::new(TunnelManager::new(engine, starter.clone(), 47613, 4001).unwrap());
    (manager, starter)
}

fn relay_config() -> TunnelConfig {
    TunnelConfig {
        allow_wan: true,
        relay_addrs: vec![RELAY.into()],
    }
}

fn expose_http(port: u16) -> ExposeConfig {
    ExposeConfig {
        port,
        kind: TunnelKind::Http,
        label: "test".into(),
        allowed_peers: vec![],
    }
}

#[tokio::test]
async fn configure_rejects_allow_wan_without_relay_addrs() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine);
    let err = manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: true,
                relay_addrs: vec![],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_WAN_DISABLED);
}

#[tokio::test]
async fn configure_rejects_invalid_relay_addr() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine);
    let err = manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: true,
                relay_addrs: vec!["not-a-multiaddr".into()],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, CODE_WAN_DISABLED);
}

/// 0→1 建立、1→0 释放；多条 expose 规则共享同一 reservation
#[tokio::test]
async fn expose_rules_share_one_reference_counted_reservation() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let rule_a = manager.expose("p", expose_http(8765)).await.unwrap();
    assert_eq!(engine.reserve_calls(), 1);
    let rule_b = manager
        .expose(
            "p",
            ExposeConfig {
                port: 39002,
                kind: TunnelKind::Tcp,
                label: "tcp".into(),
                allowed_peers: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(engine.reserve_calls(), 1, "同一引用计数只能建立一次 reservation");

    assert!(manager.unexpose("p", &rule_a).await.unwrap());
    assert!(manager.unexpose("p", &rule_b).await.unwrap());
    assert_eq!(engine.release_calls(), 1, "最后一份规则归还才释放 reservation");
}

/// allowWan=false：expose 照常生效（LAN 入口不受影响），但绝不建立 reservation
#[tokio::test]
async fn allow_wan_false_keeps_lan_entry_without_reservation() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: false,
                relay_addrs: vec![RELAY.into()],
            },
        )
        .await
        .unwrap();
    let rule = manager.expose("p", expose_http(8765)).await.unwrap();
    assert_eq!(engine.reserve_calls(), 0);
    let status = manager.status("p").await;
    assert!(status.peer_face.is_some());
    assert!(!status.reservation);
    assert!(manager.unexpose("p", &rule).await.unwrap());
    assert_eq!(engine.release_calls(), 0);
}

/// 属主仲裁：非属主 unexpose / close 一律拒绝，未命中句柄 `tunnel-closed`
#[tokio::test]
async fn rules_and_handles_are_owner_scoped() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager.configure("a", relay_config()).await.unwrap();
    let rule = manager.expose("a", expose_http(8765)).await.unwrap();
    assert_eq!(manager.unexpose("b", &rule).await.unwrap_err().code, CODE_NOT_OWNER);

    let entry = manager
        .connect("a", NODE, 8765, "http", &format!("[\"{LAN}\"]"), None)
        .await
        .unwrap();
    assert_eq!(entry.address, "127.0.0.1", "回执 address 只能是 IP 字面量（不含端口）");
    assert!(
        !entry.address.contains(':'),
        "拼接 `ws://{{address}}:{{port}}` 时不得双端口"
    );
    assert!(entry.port > 0);
    assert_eq!(
        manager.close("b", &entry.handle).await.unwrap_err().code,
        CODE_NOT_OWNER
    );
    assert!(manager.close("a", &entry.handle).await.unwrap());
    assert_eq!(
        manager.close("a", &entry.handle).await.unwrap_err().code,
        CODE_TUNNEL_CLOSED
    );
}

/// WAN 拨号：allowWan=false 直接拒绝；打开时先建立 reservation 再拨号，
/// 关闭句柄归还计数并释放 reservation。
#[tokio::test]
async fn wan_connect_requires_allow_wan_and_counts_in_flight_dials() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: false,
                relay_addrs: vec![RELAY.into()],
            },
        )
        .await
        .unwrap();
    let relay_dial = format!("[\"{RELAY}/p2p/{RELAY_PEER}/p2p-circuit/p2p/{TARGET_PEER}\"]");
    assert_eq!(
        manager
            .connect("p", OTHER_NODE, 8765, "http", &relay_dial, None)
            .await
            .unwrap_err()
            .code,
        CODE_WAN_DISABLED
    );
    assert_eq!(engine.reserve_calls(), 0);

    manager.configure("p", relay_config()).await.unwrap();
    let entry = manager
        .connect("p", OTHER_NODE, 8765, "http", &relay_dial, None)
        .await
        .unwrap();
    assert_eq!(engine.reserve_calls(), 1);
    assert_eq!(engine.dials().len(), 1);
    assert_eq!(engine.dials()[0].0, OTHER_NODE);

    assert!(manager.close("p", &entry.handle).await.unwrap());
    assert_eq!(engine.release_calls(), 1);
}

/// 拨号失败必须回滚在飞计数（不留下永不释放的 reservation）
#[tokio::test]
async fn failed_wan_dial_rolls_back_reference_count() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();
    engine.set_dial_fails();
    let relay_dial = format!("[\"{RELAY}/p2p/{RELAY_PEER}/p2p-circuit/p2p/{TARGET_PEER}\"]");
    let err = manager
        .connect("p", OTHER_NODE, 8765, "http", &relay_dial, None)
        .await
        .unwrap_err();
    assert_eq!(
        err.code, CODE_RELAY_UNREACHABLE,
        "relay 拨号失败要给中继成因，不外溢成 peer-offline"
    );
    assert_eq!(engine.reserve_calls(), 1);
    assert_eq!(engine.release_calls(), 1, "拨号失败后计数归零即释放");
}

/// 属主仲裁必须先于 ACL 刷新：非属主幂等重登记不得改掉别人的规则
#[tokio::test]
async fn non_owner_cannot_refresh_existing_rule_acl() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine);
    manager.expose("a", expose_http(8765)).await.unwrap();

    let err = manager
        .expose(
            "b",
            ExposeConfig {
                port: 8765,
                kind: TunnelKind::Http,
                label: "hijack".into(),
                allowed_peers: vec![OTHER_NODE.into()],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, crate::tunnel::CODE_PORT_NOT_EXPOSED);
    let rules = manager.policy().rules();
    assert_eq!(rules[0].label, "test", "非属主不得改标签");
    assert!(rules[0].allowed_peers.is_empty(), "非属主不得改 ACL");
}

/// 服务租约 stop：停对等面 / 释放 reservation / 清空规则与句柄
#[tokio::test]
async fn stop_releases_reservation_and_clears_state() {
    let engine = FakeEngine::new();
    let (manager, starter) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();
    manager.expose("p", expose_http(8765)).await.unwrap();
    manager
        .connect("p", NODE, 8765, "http", &format!("[\"{LAN}\"]"), None)
        .await
        .unwrap();
    assert_eq!(starter.calls.load(Ordering::SeqCst), 1);

    manager.stop().await.unwrap();
    assert_eq!(engine.release_calls(), 1);
    assert!(!manager.has_open_resources("p"));
    assert!(manager.status("p").await.peer_face.is_none());
}

/// 令牌票据：需要本端对等面（T06 的 `tunnel-unavailable` 是移动端的显性出路）
#[tokio::test]
async fn ticket_issues_only_after_peer_face_is_ready() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine);
    let ticket = manager.issue_pairing_ticket(8765, 60).await.unwrap();
    assert_eq!(ticket.len(), 64);
    assert!(manager
        .issue_pairing_ticket(8765, crate::tunnel::ticket::MAX_TICKET_TTL_SECS + 1)
        .await
        .is_err());
}

// ==================== §4.9 传输模式判定（判据表 + 状态机接线）====================

/// 落在 [`wifi_facts`] 子网内的对端 LAN 候选
const LAN_ADDR: &str = "192.168.1.20";

fn lan_addrs() -> String {
    format!("[\"/ip4/{LAN_ADDR}/tcp/47613\"]")
}

fn lan_and_relay_addrs() -> String {
    format!("[\"/ip4/{LAN_ADDR}/tcp/47613\", \"{RELAY}/p2p/{RELAY_PEER}/p2p-circuit/p2p/{TARGET_PEER}\"]")
}

/// LAN 可通：只拨 LAN，不建立 reservation，模式 lan-active
#[tokio::test]
async fn lan_first_succeeds_without_touching_relay() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap();

    let dials = engine.dials();
    assert_eq!(dials.len(), 1, "LAN 打通后不得再拨 relay");
    assert!(dials[0].1[0].contains(LAN_ADDR));
    assert_eq!(engine.reserve_calls(), 0, "lan-active 不产生中继流量");

    let status = manager.status("p").await;
    assert_eq!(status.modes.len(), 1);
    assert_eq!(status.modes[0].mode.as_str(), "lan-active");
    assert!(engine
        .events()
        .iter()
        .any(|(event, payload)| event == "peer-transport" && payload["transport"] == "lan-direct"));

    manager.close("p", &entry.handle).await.unwrap();
}

/// 同网段 timeout：判据不明确 → 保持 LAN、`lan-unreachable`，绝不自动烧中继
#[tokio::test]
async fn same_subnet_timeout_never_switches_to_relay() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    engine.set_failure(LanFailure::Timeout);
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let err = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap_err();

    assert_eq!(err.code, CODE_LAN_UNREACHABLE);
    assert_eq!(engine.dials().len(), 1, "同网段 timeout 不触发自动切外网");
    assert_eq!(engine.reserve_calls(), 0);
    let status = manager.status("p").await;
    assert_eq!(status.modes[0].mode.as_str(), "lan-unreachable");
    assert!(status.modes[0].mode.needs_manual_entry(), "要留手动「尝试外网」入口");
}

/// 认证 / Noise 失败：安全错误码，不得伪装成「内网不可达」，更不得切 relay
#[tokio::test]
async fn auth_failure_never_switches_to_relay() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    engine.set_failure(LanFailure::Auth);
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let err = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap_err();

    assert_eq!(
        err.code, CODE_NOT_MATCHED,
        "认证失败必须报安全错误，不是 lan-unreachable"
    );
    assert_eq!(engine.dials().len(), 1, "认证失败不得切中继");
    assert_eq!(engine.reserve_calls(), 0);
    assert_ne!(
        manager.status("p").await.modes[0].mode,
        TransferMode::LanUnreachable,
        "安全错误不得标记为「内网不可达」"
    );
}

/// 全部 LAN 候选 EHOSTUNREACH：判据明确 → 进 wan，模式与事件同步
#[tokio::test]
async fn host_unreachable_lan_switches_to_relay() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    engine.set_failure(LanFailure::Unreachable);
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap();

    let dials = engine.dials();
    assert_eq!(dials.len(), 2, "先 LAN（失败）再 relay");
    assert!(dials[1].1[0].contains("p2p-circuit"));
    assert_eq!(engine.reserve_calls(), 1);
    let status = manager.status("p").await;
    assert_eq!(status.modes[0].mode.as_str(), "wan-active");
    assert_eq!(status.modes[0].reason, Some(ModeReason::HostUnreachable));
    assert!(manager.close("p", &entry.handle).await.unwrap());
    assert_eq!(engine.release_calls(), 1);
}

/// 蜂窝：直接进 wan（不先拨 LAN）
#[tokio::test]
async fn cellular_goes_straight_to_relay() {
    let engine = FakeEngine::new();
    engine.set_facts(NetworkFacts {
        known: true,
        cellular: true,
        local_subnets: vec![],
        mdns_known: false,
    });
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap();

    let dials = engine.dials();
    assert_eq!(dials.len(), 1, "蜂窝直切 wan，不浪费 LAN 探测时间");
    assert!(dials[0].1[0].contains("p2p-circuit"));
    let status = manager.status("p").await;
    assert_eq!(status.modes[0].mode.as_str(), "wan-active");
    assert_eq!(status.modes[0].reason, Some(ModeReason::Cellular));
    manager.close("p", &entry.handle).await.unwrap();
}

/// 候选不在本机任何子网且无 mDNS：判据明确 → 直接进 wan
#[tokio::test]
async fn different_subnet_goes_straight_to_relay() {
    let engine = FakeEngine::new();
    engine.set_facts(NetworkFacts {
        known: true,
        cellular: false,
        local_subnets: vec![Subnet::new("10.0.0.0".parse().unwrap(), 24).unwrap()],
        mdns_known: false,
    });
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap();

    assert_eq!(engine.dials().len(), 1);
    let status = manager.status("p").await;
    assert_eq!(status.modes[0].reason, Some(ModeReason::DifferentSubnet));
    manager.close("p", &entry.handle).await.unwrap();
}

/// 网络事实未知：判据不明确 → 先试 LAN，认不出的失败也保持 LAN
#[tokio::test]
async fn unknown_network_facts_keep_lan_first() {
    let engine = FakeEngine::new();
    engine.set_failure(LanFailure::Other);
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let err = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap_err();

    assert_eq!(err.code, CODE_LAN_UNREACHABLE);
    assert_eq!(engine.dials().len(), 1);
}

/// 用户手动「尝试外网」：本次网络会话内保持，跳过 LAN 探测
#[tokio::test]
async fn manual_wan_skips_lan_probe() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();
    manager.set_manual_wan(NODE, true);

    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap();

    let dials = engine.dials();
    assert_eq!(dials.len(), 1);
    assert!(dials[0].1[0].contains("p2p-circuit"), "手动入口直接走 wan");
    let status = manager.status("p").await;
    assert_eq!(status.modes[0].reason, Some(ModeReason::User));
    assert!(status.modes[0].manual_wan);
    manager.close("p", &entry.handle).await.unwrap();
}

/// wan-active 回切需要连续两次 LAN 探测成功（防抖）
#[tokio::test]
async fn wan_restore_requires_two_lan_probe_successes() {
    let engine = FakeEngine::new();
    engine.set_facts(NetworkFacts {
        known: true,
        cellular: true,
        local_subnets: vec![],
        mdns_known: false,
    });
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();
    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap();

    assert!(manager.on_lan_probe_result(NODE, true).is_none(), "第一次成功不回切");
    let view = manager.on_lan_probe_result(NODE, true).expect("第二次成功回切");
    assert_eq!(view.mode, TransferMode::LanActive);
    assert_eq!(view.reason, Some(ModeReason::LanRestored));
    manager.close("p", &entry.handle).await.unwrap();
}

/// 换网：清手动指令并回到 lan-probing（自动策略）
#[tokio::test]
async fn network_change_resets_manual_wan() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    let (manager, _) = manager(engine);
    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_addrs(), None)
        .await
        .unwrap();
    manager.set_manual_wan(NODE, true);

    let changed = manager.on_network_changed();
    assert!(changed.iter().any(|view| view.mode == TransferMode::LanProbing));
    assert_eq!(changed[0].reason, Some(ModeReason::NetworkChanged));
    assert!(manager.status("p").await.modes.iter().all(|view| !view.manual_wan));
    manager.close("p", &entry.handle).await.unwrap();
}

/// 句柄全关：显性 offline + `tunnel:state:closed`（不退化成 30s 超时）
#[tokio::test]
async fn closing_last_handle_marks_peer_offline() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    let (manager, _) = manager(engine.clone());
    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_addrs(), None)
        .await
        .unwrap();
    assert_eq!(manager.status("p").await.modes[0].mode, TransferMode::LanActive);

    manager.close("p", &entry.handle).await.unwrap();
    assert_eq!(manager.status("p").await.modes[0].mode, TransferMode::Offline);
    assert!(engine
        .events()
        .iter()
        .any(|(event, payload)| event == "tunnel-state" && payload["state"] == "closed"));
}

/// 可拨地址投影：通配监听展开为接口 IP、环回丢弃、relay circuit 追加在最后
#[test]
fn dialable_addrs_expand_wildcard_and_append_relay_circuit() {
    let wildcard: std::net::SocketAddr = "0.0.0.0:39000".parse().unwrap();
    let loopback: std::net::SocketAddr = "127.0.0.1:39000".parse().unwrap();
    let local = vec!["192.168.1.7".parse::<std::net::IpAddr>().unwrap()];
    let addrs = dialable_addrs(
        &[wildcard, loopback],
        &local,
        Some(&format!("/ip4/203.0.113.9/tcp/4001/p2p/{RELAY_PEER}")),
        TARGET_PEER,
    );
    assert_eq!(
        addrs,
        vec![
            // 通配地址展开成本机 IPv4（`/ip4/0.0.0.0` 不可拨）
            format!("/ip4/192.168.1.7/tcp/39000/p2p/{TARGET_PEER}"),
            // relay circuit 是本节点经中继的地址，排在 LAN 候选之后
            format!("/ip4/203.0.113.9/tcp/4001/p2p/{RELAY_PEER}/p2p-circuit/p2p/{TARGET_PEER}"),
        ],
        "环回监听地址不外发；relay 候选追加在 LAN 之后"
    );
}

/// 无 relay 预留 / 端口未就绪 / 无 LAN 事实时不得产出伪造地址
#[test]
fn dialable_addrs_never_invents_addresses() {
    let pending: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    assert!(
        dialable_addrs(&[pending], &[], None, TARGET_PEER).is_empty(),
        "端口 0（系统尚未分配）与空接口事实 → 空列表，不猜"
    );

    let concrete: std::net::SocketAddr = "10.0.0.5:39000".parse().unwrap();
    assert_eq!(
        dialable_addrs(&[concrete], &[], None, TARGET_PEER),
        vec![format!("/ip4/10.0.0.5/tcp/39000/p2p/{TARGET_PEER}")],
        "非通配监听地址原样外发"
    );
}

/// 全局事件名 → 插件总线 topic 的映射锁（设计 §7.2 四个事件）
#[test]
fn tunnel_events_map_to_bus_topics() {
    assert_eq!(crate::bus_topic_for("peer-mode"), Some("peer:mode"));
    assert_eq!(crate::bus_topic_for("peer-transport"), Some("peer:transport"));
    assert_eq!(crate::bus_topic_for("tunnel-state"), Some("tunnel:state"));
    assert_eq!(crate::bus_topic_for("tunnel-error"), Some("tunnel:error"));
}

// ==================== R03–R15 回归锁 ====================

/// R03：`allowWan=false` 只关外网，LAN 候选照常拨（QR v2 载荷固定 LAN+relay）
#[tokio::test]
async fn allow_wan_false_still_dials_lan() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    let (manager, _) = manager(engine.clone());
    manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: false,
                relay_addrs: vec![RELAY.into()],
            },
        )
        .await
        .unwrap();

    let entry = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .expect("关闭外网后 LAN 仍必须可用");

    let dials = engine.dials();
    assert_eq!(dials.len(), 1);
    assert!(!dials[0].1[0].contains("p2p-circuit"), "relay 候选必须被过滤掉");
    assert_eq!(engine.reserve_calls(), 0);
    manager.close("p", &entry.handle).await.unwrap();
}

/// R04：混合候选（unreachable + timeout）不得因为其中一条是 EHOSTUNREACH 就切 WAN
#[tokio::test]
async fn mixed_candidate_failure_stays_lan() {
    let engine = FakeEngine::new();
    engine.set_facts(wifi_facts());
    engine.set_failure_causes(vec![LanFailure::Unreachable, LanFailure::Timeout]);
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let err = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap_err();

    assert_eq!(err.code, CODE_LAN_UNREACHABLE);
    assert_eq!(engine.dials().len(), 1, "混合候选保守保持 LAN");
    assert_eq!(engine.reserve_calls(), 0);
}

/// R05：stop 清空准入规则与票据（stop → start 后旧端口不得仍可准入）
#[tokio::test]
async fn stop_clears_expose_rules_and_tickets() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();
    manager.expose("p", expose_http(8765)).await.unwrap();
    manager.issue_pairing_ticket(8765, 60).await.unwrap();
    assert_eq!(manager.tickets.len(), 1);

    manager.stop().await.unwrap();
    assert!(manager.policy.rules().is_empty(), "stop 必须清空 TunnelPolicy 规则");
    assert!(manager.tickets.is_empty(), "stop 必须清空票据（TTL 内也不得跨租约）");

    // stop → start 后旧端口不得仍可准入（规则真源在 policy，不只是计数表）
    manager.start().await.unwrap();
    let mut ctx = crate::tunnel::policy::AdmissionContext {
        peer_node_id: Some(NODE.into()),
        matched: true,
        ticket_valid: false,
        active_streams: 1,
    };
    let hello = TunnelHello::new(8765, TunnelKind::Http, None);
    assert_eq!(
        manager.policy().admit(&hello, &ctx).unwrap_err().code,
        crate::tunnel::CODE_PORT_NOT_EXPOSED
    );
    // 未匹配 + 无票据同样拒绝（窗口不会因 stop/start 残留）
    ctx.matched = false;
    ctx.peer_node_id = None;
    assert_eq!(
        manager.policy().admit(&hello, &ctx).unwrap_err().code,
        crate::tunnel::CODE_PORT_NOT_EXPOSED
    );
}

/// R05：unexpose 按端口撤销票据（TTL 内的旧票不得继续开配对窗口）
#[tokio::test]
async fn unexpose_revokes_tickets_for_the_port() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine);
    let rule = manager.expose("p", expose_http(8765)).await.unwrap();
    manager.issue_pairing_ticket(8765, 60).await.unwrap();
    assert!(manager.unexpose("p", &rule).await.unwrap());
    assert!(manager.tickets.is_empty());
}

/// R05：stop 必须终止已 spawn 的在飞流任务（只 abort 接收循环不够）
#[tokio::test]
async fn stop_cancels_inflight_stream_tasks() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager.start().await.unwrap();

    let (mut client, server_io) = tokio::io::duplex(4096);
    engine.push_inbound(NODE, Box::new(server_io));
    // 不写 hello：handle_stream 阻塞在首帧读取，验证 stop 能取消它
    tokio::time::sleep(Duration::from_millis(100)).await;
    manager.stop().await.unwrap();

    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_millis(500), client.read(&mut buf))
        .await
        .expect("stop 后 500ms 内流必须关闭")
        .unwrap();
    assert_eq!(n, 0, "取消后在飞流应 EOF");
}

/// R08：接收器返回 None 后必须重建，不能让人站隧道永久失效
#[tokio::test]
async fn inbound_loop_retries_when_receiver_returns_none() {
    let engine = FakeEngine::new();
    engine.end_inbound_streams(1);
    let (manager, _) = manager(engine.clone());
    manager.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        engine.inbound_calls() >= 2,
        "None 后必须重建接收器（旧实现 break 永久失效）"
    );
    manager.stop().await.unwrap();
}

/// R10：kind=tcp 只需要回环，不启动对等面（无头 / 移动宿主也能暴露 tcp）
#[tokio::test]
async fn tcp_expose_does_not_require_peer_face() {
    let engine = FakeEngine::new();
    let (manager, starter) = manager(engine);
    manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: false,
                relay_addrs: vec![],
            },
        )
        .await
        .unwrap();
    manager
        .expose(
            "p",
            ExposeConfig {
                port: 39002,
                kind: TunnelKind::Tcp,
                label: "tcp".into(),
                allowed_peers: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(starter.calls.load(Ordering::SeqCst), 0, "kind=tcp 不启动对等面");
}

/// R11：relay 地址变化且仍有引用时以新地址重建 reservation
#[tokio::test]
async fn relay_addr_change_rebuilds_reservation() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();
    manager.expose("p", expose_http(8765)).await.unwrap();
    assert_eq!(engine.reserve_calls(), 1);

    manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: true,
                relay_addrs: vec!["/ip4/127.0.0.1/tcp/4101".into()],
            },
        )
        .await
        .unwrap();
    assert_eq!(engine.reserve_calls(), 2, "地址变化必须重建 reservation");
    assert!(engine.reserve_addrs()[1][0].contains("4101"));
    manager.stop().await.unwrap();
}

/// R04：WAN 拨号认证失败不是「中继不可达」——不标 wan-unavailable、不误导排查 relay
#[tokio::test]
async fn wan_auth_failure_is_security_error_not_relay_unavailable() {
    let engine = FakeEngine::new();
    engine.set_facts(NetworkFacts {
        known: true,
        cellular: true,
        local_subnets: vec![],
        mdns_known: false,
    });
    // 蜂窝直切 WAN：用逐候选成因让 relay 拨号也回 Auth（`fail_kind` 只作用于 LAN）
    engine.set_failure_causes(vec![LanFailure::Auth]);
    let (manager, _) = manager(engine.clone());
    manager.configure("p", relay_config()).await.unwrap();

    let err = manager
        .connect("p", NODE, 8765, "http", &lan_and_relay_addrs(), None)
        .await
        .unwrap_err();

    assert_eq!(err.code, CODE_NOT_MATCHED);
    let status = manager.status("p").await;
    assert_ne!(status.modes[0].mode, TransferMode::WanUnavailable);
    assert_eq!(engine.release_calls(), 1, "失败后计数归零并释放 reservation");
}

/// R13：域名 relay 在宿主层解析成 IP 再交给引擎（不拖到 reserve 才失败）
#[tokio::test]
async fn domain_relay_is_resolved_before_reserve() {
    let engine = FakeEngine::new();
    let (manager, _) = manager(engine.clone());
    let dns = format!("/dns4/localhost/tcp/4001/p2p/{RELAY_PEER}");
    manager
        .configure(
            "p",
            TunnelConfig {
                allow_wan: true,
                relay_addrs: vec![dns],
            },
        )
        .await
        .unwrap();
    manager.expose("p", expose_http(8765)).await.unwrap();

    let addrs = engine.reserve_addrs();
    assert_eq!(addrs.len(), 1);
    assert!(
        addrs[0][0].starts_with("/ip4/127.0.0.1/tcp/4001/p2p/"),
        "域名必须先解析成 IP multiaddr：{addrs:?}"
    );
}

/// R12：relay 处于 Connecting / Lost 时 circuit 地址不可宣告（QR 只能带可拨地址）
#[test]
fn relay_lost_is_not_advertised_as_dialable() {
    let addr: Multiaddr = format!("{RELAY}/p2p/{RELAY_PEER}").parse().unwrap();
    assert!(advertised_relay_addr(RelayState::Reserved, Some(&addr)).is_some());
    assert!(advertised_relay_addr(RelayState::Connecting, Some(&addr)).is_none());
    assert!(advertised_relay_addr(RelayState::Lost, Some(&addr)).is_none());
    assert!(advertised_relay_addr(RelayState::Idle, None).is_none());
}

/// R07（口径 A，spec §9.2#2 默认）：`matched` 只认传输层信任；
/// 未信任且无票据时不得走到后端。
#[tokio::test]
async fn matched_comes_from_transport_trust_only() {
    let engine = FakeEngine::new();
    let backend = Arc::new(RecordingBackend {
        calls: AtomicUsize::new(0),
    });
    let policy = policy_with_http_rule();
    let tickets = Arc::new(TicketIssuer::new());
    let registry = Arc::new(PairingRegistry::new());
    let manager = manager_with(engine.clone(), policy, backend.clone(), registry, tickets);
    manager.start().await.unwrap();

    // 未信任：not-matched，后端一次都不连
    let (mut client, server_io) = tokio::io::duplex(4096);
    engine.push_inbound(NODE, Box::new(server_io));
    client
        .write_all(&TunnelHello::new(8765, TunnelKind::Http, None).encode().unwrap())
        .await
        .unwrap();
    let reply = read_reply(&mut client).await.unwrap();
    assert_eq!(reply.error.as_deref(), Some(CODE_NOT_MATCHED));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);

    // 传输信任成立 = 已匹配（当前口径）：走到后端
    engine.set_trusted(true);
    let (mut client2, server_io2) = tokio::io::duplex(4096);
    engine.push_inbound(NODE, Box::new(server_io2));
    client2
        .write_all(&TunnelHello::new(8765, TunnelKind::Http, None).encode().unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "传输信任即 matched");
    manager.stop().await.unwrap();
}

/// 记录后端调用次数的替身（不连真网络）
struct RecordingBackend {
    calls: AtomicUsize,
}

#[async_trait]
impl BackendConnector for RecordingBackend {
    async fn connect(&self, _backend: &Backend) -> Result<(TunnelIo, SocketAddr)> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(TunnelError::new(CODE_PEER_OFFLINE, "backend sentinel"))
    }
}

fn policy_with_http_rule() -> Arc<TunnelPolicy> {
    let policy = Arc::new(TunnelPolicy::new(
        PolicyConfig::new(SocketAddr::from(([127, 0, 0, 1], 39001)), 47613, 4001).unwrap(),
    ));
    policy.expose(expose_http(8765)).unwrap();
    policy
}

fn manager_with(
    engine: Arc<FakeEngine>,
    policy: Arc<TunnelPolicy>,
    backend: Arc<dyn BackendConnector>,
    registry: Arc<PairingRegistry>,
    tickets: Arc<TicketIssuer>,
) -> Arc<TunnelManager> {
    let server = Arc::new(TunnelServer::new(
        Arc::clone(&policy),
        Arc::clone(&tickets),
        Arc::clone(&registry),
        backend,
    ));
    Arc::new(TunnelManager {
        engine,
        peer_face_starter: Arc::new(FakeStarter {
            calls: AtomicUsize::new(0),
        }),
        policy,
        tickets,
        registry,
        server,
        peer_face: tokio::sync::Mutex::new(None),
        inbound_task: Mutex::new(None),
        inbound_cancel: Mutex::new(None),
        state: Mutex::new(ManagerState::default()),
        start_gate: tokio::sync::Mutex::new(()),
        recount_gate: tokio::sync::Mutex::new(()),
    })
}
