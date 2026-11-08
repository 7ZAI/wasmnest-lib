//! T06 隧道管理器单测：单一引用计数、属主仲裁、`allowWan` 门控、生命周期清场。
//!
//! 引擎与对等面都用替身（不启动网络）；首帧 / 票据 / 准入等判定属 T05 单测，
//! 这里只断言「谁在什么时候建立 / 释放 reservation」与「句柄 / 规则只允许属主操作」。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use wasmnest_p2p_engine::Multiaddr;
use wasmnest_server_base::face::PeerFaceResolver;

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
    dials: Vec<(String, Vec<String>)>,
    dial_fails: bool,
    /// `Some(kind)` = 所有拨号按该成因失败（分类判据用）
    fail_kind: Option<LanFailure>,
    facts: NetworkFacts,
    events: Vec<(String, serde_json::Value)>,
}

struct FakeEngine {
    state: Mutex<FakeState>,
}

impl FakeEngine {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FakeState::default()),
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
        std::future::pending().await
    }

    async fn trust_contains(&self, _node_id: &NodeId) -> bool {
        false
    }

    async fn reserve_relay(&self, _addrs: &[Multiaddr]) -> Result<()> {
        self.state.lock().unwrap().reserve_calls += 1;
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
    assert!(entry.address.starts_with("127.0.0.1:"));
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

/// 认证 / Noise 失败：安全错误，绝不为了绕过失败切 relay（不变量 9）
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

    assert_eq!(err.code, CODE_LAN_UNREACHABLE);
    assert_eq!(engine.dials().len(), 1, "认证失败不得切中继");
    assert_eq!(engine.reserve_calls(), 0);
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

/// 全局事件名 → 插件总线 topic 的映射锁（设计 §7.2 四个事件）
#[test]
fn tunnel_events_map_to_bus_topics() {
    assert_eq!(crate::bus_topic_for("peer-mode"), Some("peer:mode"));
    assert_eq!(crate::bus_topic_for("peer-transport"), Some("peer:transport"));
    assert_eq!(crate::bus_topic_for("tunnel-state"), Some("tunnel:state"));
    assert_eq!(crate::bus_topic_for("tunnel-error"), Some("tunnel:error"));
}
