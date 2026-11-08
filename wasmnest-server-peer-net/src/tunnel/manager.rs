//! 宿主隧道管理器（T06）：**单一引用计数**、客户端句柄表、对等面生命周期与状态投影。
//!
//! ## 单一所有权
//!
//! `expose` / `unexpose` / `configure`（`allowWan` 开关）/ 服务租约都**只改计数**；
//! 真正的 relay reservation 只在本模块的 [`TunnelManager::recount`] 里 0→1 建立、
//! 1→0 释放。计数来源（设计 §4.8，两条缺一不可）：
//!
//! 1. 生效 expose 规则（且该插件的 `allowWan=true` 且配置了 relay 地址）；
//! 2. 客户端在飞 WAN 通道（`connect` 的地址里含 `/p2p-circuit`，`close` 时归还）。
//!
//! `allowWan=false` 时即使有 expose 规则也不建立 / 保留 reservation（LAN 入口不受
//! 影响）；`connect` 携带 relay 地址时只把它们从候选里滤掉（LAN 候选仍可拨），
//! 只有在「没有 LAN 候选可用」时才 `wan-disabled` 失败——关闭外网不等于关闭内网。
//!
//! ## 生命周期
//!
//! `net.tunnel` 服务租约（[`crate::tunnel::service`]）0→1 时启动节点与入站流接收器；
//! 对等 HTTP/WS 面由宿主注入的 [`PeerFaceStarter`] 在第一次需要时启动（移动端可以
//! 不提供，`expose` / `issue-pairing-ticket` 显性 `tunnel-unavailable`，`connect`
//! 不受影响）。1→0 时停 listener、中止接收器、释放 reservation、清空全部状态。
//!
//! ## 与 T05 机制的分工
//!
//! 首帧裁决 / 票据 / 准入 / 本地代理 / 面登记的**判定**全在 T05 模块；本模块只做
//! 装配与记账，不重复实现安全判据，也不把失败降级成「没有对端就返回空」。

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wasmnest_p2p_engine::error::{DialCause, P2pError};
use wasmnest_p2p_engine::relay::RelayState;
use wasmnest_p2p_engine::Multiaddr;
use wasmnest_server_base::face::PeerFaceResolver;

use crate::base::identity::NodeId;
use crate::tunnel::client::{ClientConnector, TunnelStreamOpener};
use crate::tunnel::frame::{TunnelHello, TunnelKind};
use crate::tunnel::mode::{
    self, DialFailure, LanCandidateSource, LanFailure, LanFailureVerdict, LanVerdict, ModeMachine, ModeReason,
    NetworkFacts, PeerModeView, TransferMode, WanAvailability,
};
use crate::tunnel::policy::{Backend, ExposeConfig, PolicyConfig, TunnelPolicy};
use crate::tunnel::proxy::{bind_loopback_proxy, run_proxy, TunnelIo};
use crate::tunnel::registry::PairingRegistry;
use crate::tunnel::server::{BackendConnector, TunnelServer, TunnelStreamContext};
use crate::tunnel::ticket::{AccessPath, TicketIssuer};
use crate::tunnel::{
    Result, TunnelError, CODE_LAN_UNREACHABLE, CODE_NOT_MATCHED, CODE_NOT_OWNER, CODE_PEER_OFFLINE,
    CODE_PROXY_BIND_FAILED, CODE_RELAY_UNREACHABLE, CODE_TUNNEL_CLOSED, CODE_WAN_DISABLED,
};

/// 单次拨号候选的短超时（LAN 2~3s 口径，设计 §4.9）；relay 候选由引擎按同一窗口结算。
const DIAL_PER_ADDR_TIMEOUT: Duration = Duration::from_secs(3);

// ==================== 引擎端口（宿主注入 / 测试替身） ====================

/// 引擎侧需要隧道管理器驱动的全部机制（开流 / 收流 / 拨号 / 信任 / relay 预留）。
///
/// 端口存在只为让管理器**可测**：生产实现 [`PeerCtxEngine`] 直接接
/// `wasmnest-server-peer-net` 的引擎上下文，测试替身不启动任何网络。
#[async_trait]
pub trait TunnelEngine: Send + Sync {
    /// 幂等启动对等网络节点（已运行直接返回）
    async fn ensure_node(&self) -> Result<()>;
    /// 按 multiaddr 候选顺序拨号（经 relay 的候选由引擎先做形状校验）
    async fn dial(&self, node_id: &NodeId, addrs: &[Multiaddr]) -> Result<()>;
    /// 拨号一组候选并**分类失败成因**（设计 §4.9 判据表需要区分
    /// timeout / ECONNREFUSED / EHOSTUNREACH / 认证失败）。
    ///
    /// 默认实现把失败一律归为 [`LanFailure::Other`]——保守语义：判据不明确
    /// 时保持 LAN，绝不因为「没分类」而自动切外网。生产实现覆盖它以给出
    /// 真实分类；无头测试替身可继续用默认实现。
    async fn dial_classified(&self, node_id: &NodeId, addrs: &[Multiaddr]) -> std::result::Result<(), DialFailure> {
        self.dial(node_id, addrs)
            .await
            .map_err(|e| DialFailure::new(LanFailure::Other, e.detail))
    }
    /// §4.9 宿主侧网络事实（蜂窝 / 接口子网 / mDNS 发现态）。
    ///
    /// 默认未知 = 判据不明确 → 先试 LAN、不自动切 wan（不猜、不静默降级）。
    async fn network_facts(&self) -> NetworkFacts {
        NetworkFacts::unknown()
    }
    /// 事件出口（`peer:mode` / `peer:transport` / `tunnel:state` / `tunnel:error`）。
    /// fire-and-forget：默认丢弃（无头上下文 / 未接总线的测试替身）。
    fn emit(&self, _event: &str, _payload: serde_json::Value) {}
    /// 向已准入对端开一条 `/wasmnest/tunnel/1` 流
    async fn open_tunnel(&self, node_id: &NodeId) -> Result<TunnelIo>;
    /// 取下一条入站隧道流（未注册 / 节点未运行时挂起）
    async fn next_inbound(&self) -> Option<(NodeId, AccessPath, TunnelIo)>;
    /// 传输层信任（应用层配对由账户域另行判定，本层不代替）
    async fn trust_contains(&self, node_id: &NodeId) -> bool;
    /// relay 预留（0→1）
    async fn reserve_relay(&self, addrs: &[Multiaddr]) -> Result<()>;
    /// relay 预留释放（1→0，幂等）
    async fn release_relay(&self) -> Result<()>;
    /// 控制面状态快照（`status` 投影用，不含秘密）
    async fn relay_snapshot(&self) -> RelaySnapshot;
    /// 节点状态（是否运行 / 本机 node id）
    async fn node_snapshot(&self) -> NodeSnapshot;
}

/// relay 控制面快照（`RelayState::as_str()` 为词表字面）
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySnapshot {
    pub state: String,
    pub relay_addr: Option<String>,
    pub detail: String,
}

/// 节点状态快照
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSnapshot {
    pub started: bool,
    pub node_id: Option<String>,
    /// 本节点**可拨** multiaddr（LAN 直连在前、relay circuit 在后，去重保序）
    ///
    /// 为什么状态里要有它：应用把「怎么找到我」写进配对载荷（QR v2 的
    /// `peer.addrs`，T08），这是唯一一处宿主知道真实监听端口的出口。
    /// 通配监听地址（`0.0.0.0` / `::`）必须展开成本机可用 IPv4——
    /// `/ip4/0.0.0.0` 在 multiaddr 里不是可拨地址，直接外发会让对端永远拨不通。
    pub addrs: Vec<String>,
}

// ==================== 对等面启动端口 ====================

/// 对等 HTTP/WS 面 listener（只绑 127.0.0.1；端口由宿主实现选择）
pub struct PeerFaceListener {
    pub addr: SocketAddr,
    stop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl PeerFaceListener {
    pub fn new(addr: SocketAddr, stop: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            addr,
            stop: Some(Box::new(stop)),
        }
    }

    /// 停止 listener（幂等；drop 时也会尝试）
    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
    }
}

impl Drop for PeerFaceListener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 宿主注入的对等面启动器（桌面 = 真实 Actix listener；移动端可以不支持）
#[async_trait]
pub trait PeerFaceStarter: Send + Sync {
    async fn start(&self, resolver: PeerFaceResolver) -> Result<PeerFaceListener>;
}

// ==================== 配置 / 状态 ====================

/// 应用自持的通道配置（WIT `tunnel-config` 的宿主存储形状）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelConfig {
    /// 允许外网中继（关闭 ≠ 关闭加密；只关闭外网通道）
    pub allow_wan: bool,
    /// multiaddr 字符串数组（空 = 未配置中继）
    #[serde(default)]
    pub relay_addrs: Vec<String>,
}

impl TunnelConfig {
    /// 解析 relay 地址；空项 / 非法 multiaddr 一律显性拒绝
    pub fn parse_relay_addrs(&self) -> Result<Vec<Multiaddr>> {
        let mut out = Vec::with_capacity(self.relay_addrs.len());
        for raw in &self.relay_addrs {
            let addr: Multiaddr = raw
                .parse()
                .map_err(|e| TunnelError::new(CODE_WAN_DISABLED, format!("relay 地址非法：{e}")))?;
            out.push(addr);
        }
        Ok(out)
    }

    /// 解析 + **域名解析**：`/dns4|dns6|dns` 组件经宿主层 `lookup_host` 展开成
    /// `/ip4|ip6` 候选（引擎不启用 dns feature，T02 明确要求宿主层解析）。
    ///
    /// 解析失败点名原始地址（fail-visible）：不把配置错误拖到 reserve 时才暴露。
    pub async fn resolved_relay_addrs(&self) -> Result<Vec<Multiaddr>> {
        let mut out = Vec::new();
        for raw in &self.relay_addrs {
            let resolved = wasmnest_p2p_engine::relay::resolve_relay_addr(raw)
                .await
                .map_err(|e| TunnelError::new(CODE_WAN_DISABLED, format!("relay 地址解析失败（{raw}）：{e}")))?;
            for addr in resolved {
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
        Ok(out)
    }
}

/// `connect` 成功返回给应用的句柄信息
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectEntry {
    pub handle: String,
    /// 本地回环代理地址（只可能是 127.0.0.1）
    pub address: String,
    pub port: u16,
}

/// `status` 投影（应用只读；不含票据 / 令牌明文）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    pub node: NodeSnapshot,
    pub peer_face: Option<String>,
    pub allow_wan: bool,
    pub relay_addrs_configured: usize,
    pub reservation: bool,
    pub relay: RelaySnapshot,
    pub expose_rules: usize,
    pub connects: usize,
    /// 每对端传输模式（设计 §4.9；`lan-active` / `wan-active` / `lan-unreachable` …）
    pub modes: Vec<PeerModeView>,
}

struct RuleEntry {
    owner: String,
}

struct ConnectHandle {
    owner: String,
    /// 每对端模式归因用：最后一个句柄关闭才把该对端置 `offline`
    node_id: String,
    #[allow(dead_code)]
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    wan: bool,
}

#[derive(Default)]
struct ManagerState {
    configs: HashMap<String, TunnelConfig>,
    rules: HashMap<String, RuleEntry>,
    connects: HashMap<String, ConnectHandle>,
    /// 客户端在飞 WAN 通道计数（按插件）
    inbound_wan: HashMap<String, usize>,
    reserved: bool,
    /// 当前 reservation 实际使用的 relay 地址（`configure` 改地址时必须重建）
    reserved_addrs: Vec<Multiaddr>,
    /// 每对端模式表（§4.9；模式是每对端的，不是全局开关）
    modes: ModeMachine,
}

// ==================== 管理器 ====================

pub struct TunnelManager {
    engine: Arc<dyn TunnelEngine>,
    peer_face_starter: Arc<dyn PeerFaceStarter>,
    policy: Arc<TunnelPolicy>,
    tickets: Arc<TicketIssuer>,
    registry: Arc<PairingRegistry>,
    server: Arc<TunnelServer>,
    peer_face: tokio::sync::Mutex<Option<PeerFaceListener>>,
    inbound_task: Mutex<Option<JoinHandle<()>>>,
    /// 入站循环与在飞流共用的取消令牌：`stop` 时一并取消（在飞配对 / 业务流必须关）
    inbound_cancel: Mutex<Option<CancellationToken>>,
    state: Mutex<ManagerState>,
    start_gate: tokio::sync::Mutex<()>,
    recount_gate: tokio::sync::Mutex<()>,
}

impl TunnelManager {
    /// `peer_node_port` / `relay_control_port` 必须是实际监听端口（管理面黑名单）
    pub fn new(
        engine: Arc<dyn TunnelEngine>,
        peer_face_starter: Arc<dyn PeerFaceStarter>,
        peer_node_port: u16,
        relay_control_port: u16,
    ) -> Result<Self> {
        let policy = Arc::new(TunnelPolicy::new(PolicyConfig::unbound(
            peer_node_port,
            relay_control_port,
        )?));
        let tickets = Arc::new(TicketIssuer::new());
        let registry = Arc::new(PairingRegistry::new());
        let server = Arc::new(TunnelServer::new(
            Arc::clone(&policy),
            Arc::clone(&tickets),
            Arc::clone(&registry),
            Arc::new(TcpBackendConnector),
        ));
        Ok(Self {
            engine,
            peer_face_starter,
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

    pub fn registry(&self) -> Arc<PairingRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn policy(&self) -> Arc<TunnelPolicy> {
        Arc::clone(&self.policy)
    }

    /// 服务租约 start：节点 + 入站流接收器（**不**启动对等面）
    pub async fn start(&self) -> Result<()> {
        self.ensure_running().await
    }

    /// 服务租约 stop：停对等面 / 取消在飞流 / 清 expose 规则与票据 / 释放 reservation
    pub async fn stop(&self) -> Result<()> {
        let _gate = self.start_gate.lock().await;
        if let Some(mut listener) = self.peer_face.lock().await.take() {
            listener.stop();
        }
        self.policy.clear_peer_face();
        // 在飞流与接收循环一起取消：只 abort 接收循环不会终止已 spawn 的
        // `TunnelServer::handle_stream` 任务（配对窗口 / 业务 pipe 会继续存活）。
        if let Some(cancel) = self.inbound_cancel.lock().expect("inbound cancel lock poisoned").take() {
            cancel.cancel();
        }
        if let Some(task) = self.inbound_task.lock().expect("inbound task lock poisoned").take() {
            task.abort();
        }
        // 规则不只在计数表里清：`TunnelPolicy` 是准入真源，stop 后旧端口不得仍可准入
        // （stop → start 后 `port-not-exposed`）。
        for rule in self.policy.rules() {
            self.policy.unexpose(&rule.id);
        }
        // 票据不跨租约：TTL 内的旧票据不得在 stop → start 后仍然有效。
        self.tickets.clear();
        let held = {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            let held = state.reserved;
            state.reserved = false;
            state.reserved_addrs.clear();
            for handle in state.connects.values() {
                let _ = handle.shutdown.send(true);
            }
            state.connects.clear();
            state.rules.clear();
            state.configs.clear();
            state.inbound_wan.clear();
            state.modes = ModeMachine::new();
            held
        };
        self.registry.clear_all();
        if held {
            self.engine.release_relay().await?;
        }
        Ok(())
    }

    /// 写入（全量替换）某插件的通道配置；只改计数，不直接管理 reservation
    pub async fn configure(&self, plugin_id: &str, config: TunnelConfig) -> Result<()> {
        // 语法先判（空项 / 非法 multiaddr），再对域名做宿主层解析：域名 relay 不得
        // 拖到 reserve 时才失败（T02 的 `resolve_relay_addr` 在宿主侧消费）。
        let addrs = config.parse_relay_addrs()?;
        if config.allow_wan {
            if addrs.is_empty() {
                return Err(TunnelError::new(
                    CODE_WAN_DISABLED,
                    "allowWan=true 但未配置 relay 地址（外网通道不可用）",
                ));
            }
            config.resolved_relay_addrs().await?;
        }
        {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            state.configs.insert(plugin_id.to_string(), config);
        }
        self.recount().await
    }

    /// 登记暴露规则（幂等：同 port + kind 返回既有 id 并刷新 ACL；同端口跨应用拒绝）
    pub async fn expose(&self, plugin_id: &str, config: ExposeConfig) -> Result<String> {
        let allow_wan = self.config_of(plugin_id).allow_wan;
        if allow_wan {
            // allowWan 打开时先校验 relay 配置，避免「规则生效了但外网永远不可用」
            let addrs = self.config_of(plugin_id).parse_relay_addrs()?;
            if addrs.is_empty() {
                return Err(TunnelError::new(CODE_WAN_DISABLED, "allowWan=true 但未配置 relay 地址"));
            }
        }
        // 只有 `kind=http` 的后端恒为对等面；`kind=tcp` 只需节点 + 入站接收器。
        // 无对等面能力的宿主（无头 / 部分移动环境）也应能暴露回环 tcp 端口。
        if config.kind == TunnelKind::Http {
            self.ensure_peer_face().await?;
        } else {
            self.ensure_running().await?;
        }

        let expose_port = config.port;
        // 属主仲裁必须先于 `policy.expose`：幂等重登记会刷新 ACL / 标签，若先写
        // 再拒绝，非属主就能改掉别人的 `allowedPeers`（旧实现因「幂等不更新」掩盖了）。
        if let Some(existing) = self.policy.rule_id_for(expose_port, config.kind) {
            let state = self.state.lock().expect("tunnel state poisoned");
            if state.rules.get(&existing).is_some_and(|entry| entry.owner != plugin_id) {
                return Err(TunnelError::new(
                    crate::tunnel::CODE_PORT_NOT_EXPOSED,
                    "该端口已被其他应用暴露（先 unexpose 再重试）",
                ));
            }
        }
        let rule_id = self.policy.expose(config)?;
        {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            match state.rules.get(&rule_id) {
                Some(existing) if existing.owner != plugin_id => {
                    return Err(TunnelError::new(
                        crate::tunnel::CODE_PORT_NOT_EXPOSED,
                        "该端口已被其他应用暴露（先 unexpose 再重试）",
                    ));
                }
                Some(_) => {}
                None => {
                    state.rules.insert(
                        rule_id.clone(),
                        RuleEntry {
                            owner: plugin_id.to_string(),
                        },
                    );
                }
            }
        }
        if let Err(e) = self.recount().await {
            // 规则已登记（LAN 可用）；reservation 失败必须可见但不回滚 LAN 入口
            tracing::warn!(plugin_id = %plugin_id, code = e.code, "tunnel reservation failed after expose: {}", e.detail);
        }
        self.emit(
            "tunnel-state",
            serde_json::json!({ "state": "exposed", "ruleId": rule_id, "port": expose_port }),
        );
        Ok(rule_id)
    }

    /// 撤销暴露规则（只允许属主；未知 / 非属主返回 false）
    pub async fn unexpose(&self, plugin_id: &str, rule_id: &str) -> Result<bool> {
        let (removed, port) = {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            match state.rules.get(rule_id) {
                Some(entry) if entry.owner != plugin_id => {
                    return Err(TunnelError::new(CODE_NOT_OWNER, format!("不是规则属主：{rule_id}")));
                }
                Some(_) => {
                    state.rules.remove(rule_id);
                    (true, self.policy.rule_port(rule_id))
                }
                None => (false, None),
            }
        };
        if removed {
            self.policy.unexpose(rule_id);
            // 端口撤销即票据失效：否则 TTL 内的旧票据仍能开配对窗口
            if let Some(port) = port {
                self.tickets.revoke_port(port);
            }
            self.recount().await?;
            self.emit(
                "tunnel-state",
                serde_json::json!({ "state": "closed", "ruleId": rule_id }),
            );
        }
        Ok(removed)
    }

    /// 签发一次性配对票据（需要本端对等面在场）
    pub async fn issue_pairing_ticket(&self, port: u16, ttl_secs: u32) -> Result<String> {
        self.ensure_peer_face().await?;
        self.tickets.issue(port, ttl_secs)
    }

    /// 建立本地回环代理并返回句柄（每条本地连接开一条隧道流）
    ///
    /// 拨号顺序按设计 §4.9：**先 LAN**，只有判据表明确「不在内网」才进 wan；
    /// 同网段 timeout / `ECONNREFUSED` / 认证失败**保持 LAN** 并显性
    /// `lan-unreachable`（给手动「尝试外网」出路，不自动烧中继流量）。
    pub async fn connect(
        &self,
        plugin_id: &str,
        node_id: &str,
        port: u16,
        kind: &str,
        addrs_json: &str,
        pairing_ticket: Option<String>,
    ) -> Result<ConnectEntry> {
        let node_id =
            NodeId::parse(node_id).map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("非法 node id：{e}")))?;
        let node_key = node_id.as_str().to_string();
        let kind = parse_kind(kind)?;
        if port == 0 {
            return Err(TunnelError::new(CODE_PEER_OFFLINE, "目标端口为 0"));
        }
        let addrs = parse_addrs(addrs_json)?;
        let (lan_addrs, wan_candidates) = split_addrs(&addrs);
        // `allowWan=false` / 未配置 relay = 关闭外网通道，但**不关闭内网**：把 relay
        // 候选过滤掉继续拨 LAN；只有连一条 LAN 候选都没有时才显性失败。
        // （旧实现只要候选里带 relay 就整体拒绝，QR v2 的 LAN+relay 载荷在关闭
        // 远程访问的手机上连同一 Wi-Fi 也连不上。）
        let config = self.config_of(plugin_id);
        let wan_configured = !config.parse_relay_addrs()?.is_empty();
        let wan_addrs: Vec<Multiaddr> = if config.allow_wan && wan_configured {
            wan_candidates
        } else {
            Vec::new()
        };
        if lan_addrs.is_empty() && wan_addrs.is_empty() {
            let detail = if !config.allow_wan {
                "allowWan=false 且没有可用的 LAN 候选（外网访问已关闭）"
            } else if !wan_configured {
                "未配置 relay 地址，且没有可用的 LAN 候选"
            } else {
                "候选里没有可用的 LAN / relay 地址"
            };
            return Err(TunnelError::new(CODE_WAN_DISABLED, detail));
        }
        let wan = !wan_addrs.is_empty();

        let plan = self.plan_mode(plugin_id, &node_key, &lan_addrs, &wan_addrs).await?;
        self.ensure_running().await?;

        // ---------- 先 LAN：只有判据明确「不在内网」才进 wan ----------
        let (path, reason) = match plan {
            Plan::Lan => {
                if lan_addrs.is_empty() {
                    return Err(TunnelError::new(CODE_PEER_OFFLINE, "没有可用的 LAN 候选地址"));
                }
                self.mode_transition(|modes| modes.set(&node_key, TransferMode::LanProbing, None));
                match self.engine.dial_classified(&node_id, &lan_addrs).await {
                    Ok(()) => (Path::Lan, None),
                    Err(failure) => {
                        // 认证 / 未匹配 / Noise 失败：安全错误，保持当前模式并显性
                        // 报错——绝不为了绕过失败切 relay，也不误报成「内网不可达」。
                        if failure.kind == LanFailure::Auth {
                            self.emit_tunnel_error(&node_key, CODE_NOT_MATCHED, &failure.detail);
                            return Err(TunnelError::new(
                                CODE_NOT_MATCHED,
                                format!("认证 / 匹配校验失败：{}", failure.detail),
                            ));
                        }
                        match mode::judge_after_lan_failure(failure.kind) {
                            LanFailureVerdict::SwitchWan(switch_reason) if wan => (Path::Wan, Some(switch_reason)),
                            _ => {
                                // 判据不明确：保持 LAN，显性报错并留手动出口
                                self.mode_transition(|modes| modes.mark_lan_unreachable(&node_key));
                                self.emit_tunnel_error(&node_key, CODE_LAN_UNREACHABLE, &failure.detail);
                                return Err(TunnelError::new(
                                    CODE_LAN_UNREACHABLE,
                                    format!(
                                        "内网不可达（{}）：{}；可手动「尝试外网」",
                                        failure_word(failure.kind),
                                        failure.detail
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
            Plan::Wan(reason) => (Path::Wan, Some(reason)),
        };

        // ---------- WAN：先按引用计数建立 reservation，再拨 relay 候选 ----------
        let wan_used = matches!(path, Path::Wan);
        if wan_used {
            let reason = reason.unwrap_or(ModeReason::User);
            self.mode_transition(|modes| modes.mark_wan_connecting(&node_key, reason));
            self.acquire_wan(plugin_id).await?;
            if let Err(failure) = self.engine.dial_classified(&node_id, &wan_addrs).await {
                self.release_wan(plugin_id).await;
                // 认证 / 未匹配失败不是「中继不可达」：不标 wan-unavailable、不把
                // 安全错误混成网络错误（否则用户被引导去排查 relay）。
                if failure.kind == LanFailure::Auth {
                    self.emit_tunnel_error(&node_key, CODE_NOT_MATCHED, &failure.detail);
                    return Err(TunnelError::new(
                        CODE_NOT_MATCHED,
                        format!("中继链路认证 / 匹配校验失败：{}", failure.detail),
                    ));
                }
                self.mode_transition(|modes| modes.mark_wan_unavailable(&node_key, ModeReason::RelayUnavailable));
                self.emit_tunnel_error(&node_key, CODE_RELAY_UNREACHABLE, &failure.detail);
                return Err(TunnelError::new(
                    CODE_RELAY_UNREACHABLE,
                    format!("中继拨号失败（{}）：{}", failure_word(failure.kind), failure.detail),
                ));
            }
            self.mode_transition(|modes| modes.mark_wan_active(&node_key, reason));
            self.emit_transport(&node_key, "wan-relay", true);
        } else {
            self.mode_transition(|modes| modes.mark_lan_active(&node_key));
            self.emit_transport(&node_key, "lan-direct", false);
        }

        let opener = Arc::new(EngineOpener {
            engine: Arc::clone(&self.engine),
            node_id: node_id.clone(),
        });
        let connector = Arc::new(ClientConnector::new(
            TunnelHello::new(port, kind, pairing_ticket),
            opener,
        ));
        let (listener, addr) = match bind_loopback_proxy().await {
            Ok(bound) => bound,
            Err(e) => {
                if wan_used {
                    self.release_wan(plugin_id).await;
                }
                self.emit_tunnel_error(&node_key, e.code, &e.detail);
                return Err(e);
            }
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let event_engine = Arc::clone(&self.engine);
        let event_node = node_key.clone();
        tokio::spawn(async move {
            if let Err(e) = run_proxy(listener, connector, shutdown_rx).await {
                // 代理退出必须可见：否则应用只看到本地端口「连上又断」而不知道原因，
                // 状态栏还会继续显示「已连接」。事件与状态回落都发。
                tracing::warn!(code = e.code, "tunnel proxy exited: {}", e.detail);
                event_engine.emit(
                    "tunnel-error",
                    serde_json::json!({
                        "nodeId": event_node,
                        "code": e.code,
                        "detail": e.detail,
                        "atMs": mode::now_ms(),
                    }),
                );
                event_engine.emit(
                    "tunnel-state",
                    serde_json::json!({ "nodeId": event_node, "state": "error" }),
                );
            }
        });

        let handle = format!("tunnel-{}", uuid::Uuid::new_v4());
        {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            state.connects.insert(
                handle.clone(),
                ConnectHandle {
                    owner: plugin_id.to_string(),
                    node_id: node_key.clone(),
                    address: addr,
                    shutdown: shutdown_tx,
                    wan: wan_used,
                },
            );
        }
        self.emit(
            "tunnel-state",
            serde_json::json!({
                "nodeId": node_key,
                "handle": handle,
                "state": "connected",
                "transport": if wan_used { "wan-relay" } else { "lan-direct" },
            }),
        );
        Ok(ConnectEntry {
            handle,
            // 只回 IP 字面量：`TunnelStatus` / 应用会把 `address` 与 `port` 拼 URL
            // （`ws://{address}:{port}`）；回 `"127.0.0.1:5000"` 会拼成双端口。
            address: addr.ip().to_string(),
            port: addr.port(),
        })
    }

    /// §4.9 决策：先看用户手动「尝试外网」，再按判据表决定 LAN / WAN
    async fn plan_mode(
        &self,
        plugin_id: &str,
        node_key: &str,
        lan_addrs: &[Multiaddr],
        wan_addrs: &[Multiaddr],
    ) -> Result<Plan> {
        if wan_addrs.is_empty() {
            return Ok(Plan::Lan);
        }
        let config = self.config_of(plugin_id);
        let availability = WanAvailability::new(config.allow_wan, !config.relay_addrs.is_empty());
        let manual = {
            let state = self.state.lock().expect("tunnel state poisoned");
            state.modes.manual_wan(node_key)
        };
        if manual && availability.is_ready() {
            return Ok(Plan::Wan(ModeReason::User));
        }
        let facts = self.engine.network_facts().await;
        let lan_ips = collect_lan_ips(lan_addrs);
        match mode::judge_before_lan(&facts, &lan_ips, LanCandidateSource::Explicit, availability) {
            LanVerdict::SwitchWan(reason) => Ok(Plan::Wan(reason)),
            LanVerdict::Blocked(reason) => Err(TunnelError::new(
                CODE_WAN_DISABLED,
                format!("外网通道不可用（{}）：且没有可用的 LAN 候选", reason.as_str()),
            )),
            // `WaitDiscovery` 只对 mDNS 候选成立；`connect` 的候选由调用方显式给出
            LanVerdict::WaitDiscovery | LanVerdict::TryLan => Ok(Plan::Lan),
        }
    }

    /// 用户手动「尝试外网」（设计 §4.9 判据表最后一行）：本次网络会话内保持，
    /// 换网由宿主调 [`Self::on_network_changed`] 回到自动策略。
    pub fn set_manual_wan(&self, node_id: &str, enabled: bool) -> Option<PeerModeView> {
        self.mode_transition(|modes| modes.set_manual_wan(node_id, enabled))
    }

    /// 宿主检测到换网：清手动指令与探测计数，非 `offline` 对端回到 `lan-probing`
    pub fn on_network_changed(&self) -> Vec<PeerModeView> {
        let changed = {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            state.modes.on_network_changed()
        };
        for view in &changed {
            self.emit("peer-mode", mode_event(view));
        }
        changed
    }

    /// `wan-active` 期间 LAN 探测结果（连续两次成功才回切；探测循环由消费端驱动）
    ///
    /// **探测方式由调用方决定**（例如对 LAN 候选做一次短超时拨号探活）——本层只
    /// 记账与防抖，不在这里重复拨号：wan-active 期间重新 `dial` 会按引擎语义断开
    /// 现役链路，代价高于收益。
    pub fn on_lan_probe_result(&self, node_id: &str, reachable: bool) -> Option<PeerModeView> {
        if reachable {
            self.mode_transition(|modes| modes.on_lan_probe_success(node_id))
        } else {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            state.modes.on_lan_probe_failure(node_id);
            None
        }
    }

    /// 模式迁移 + `peer:mode` 事件（只在确实变化时发；同一事件名走宿主事件 + 插件总线）
    fn mode_transition(&self, f: impl FnOnce(&mut ModeMachine) -> Option<PeerModeView>) -> Option<PeerModeView> {
        let changed = {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            f(&mut state.modes)
        };
        if let Some(view) = &changed {
            self.emit("peer-mode", mode_event(view));
        }
        changed
    }

    /// 事件出口（转发给引擎注入的事件端口；无头上下文丢弃）
    fn emit(&self, event: &str, payload: serde_json::Value) {
        self.engine.emit(event, payload);
    }

    fn emit_transport(&self, node_key: &str, transport: &str, wan: bool) {
        self.emit(
            "peer-transport",
            serde_json::json!({
                "nodeId": node_key,
                "transport": transport,
                "wan": wan,
                "atMs": mode::now_ms(),
            }),
        );
    }

    fn emit_tunnel_error(&self, node_key: &str, code: &str, detail: &str) {
        self.emit(
            "tunnel-error",
            serde_json::json!({
                "nodeId": node_key,
                "code": code,
                "detail": detail,
                "atMs": mode::now_ms(),
            }),
        );
    }

    /// 关闭句柄（listener + 在飞流一起停；只允许属主）
    pub async fn close(&self, plugin_id: &str, handle: &str) -> Result<bool> {
        let entry = {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            match state.connects.get(handle) {
                Some(entry) if entry.owner != plugin_id => {
                    return Err(TunnelError::new(CODE_NOT_OWNER, format!("不是句柄属主：{handle}")));
                }
                Some(_) => state.connects.remove(handle),
                None => None,
            }
        };
        let Some(entry) = entry else {
            return Err(TunnelError::new(CODE_TUNNEL_CLOSED, format!("句柄已关闭：{handle}")));
        };
        let _ = entry.shutdown.send(true);
        if entry.wan {
            self.release_wan(plugin_id).await;
        }
        // 句柄已出表、shutdown 已发：这里是「释放 relay 失败」而非「关闭失败」。
        // `has_open_resources` 已为 false（服务租约可回落），reservation 由下次
        // recount 重试；不回滚句柄（回滚会让已关闭的代理重新出现在句柄表里）。
        // 失败仍要可见（事件 + 日志），不静默吞掉。
        if let Err(e) = self.recount().await {
            tracing::warn!(
                code = e.code,
                "tunnel reservation release failed after close: {}",
                e.detail
            );
            self.emit_tunnel_error(&entry.node_id, e.code, &e.detail);
        }
        let still_connected = {
            let state = self.state.lock().expect("tunnel state poisoned");
            state.connects.values().any(|c| c.node_id == entry.node_id)
        };
        if !still_connected {
            // 对端已无本地句柄：显性 offline（应用据此渲染「离线」，不退化成 30s 超时）
            self.mode_transition(|modes| modes.mark_offline(&entry.node_id));
        }
        self.emit(
            "tunnel-state",
            serde_json::json!({ "nodeId": entry.node_id, "handle": handle, "state": "closed" }),
        );
        Ok(true)
    }

    /// 应用只读状态投影（应用维度的规则 / 句柄计数 + 全局节点 / relay 状态 + 每对端模式）
    pub async fn status(&self, plugin_id: &str) -> TunnelStatus {
        let (config, expose_rules, connects, reservation, modes) = {
            let state = self.state.lock().expect("tunnel state poisoned");
            let config = state.configs.get(plugin_id).cloned().unwrap_or_default();
            let expose_rules = state.rules.values().filter(|r| r.owner == plugin_id).count();
            let connects = state.connects.values().filter(|c| c.owner == plugin_id).count();
            (config, expose_rules, connects, state.reserved, state.modes.views())
        };
        TunnelStatus {
            node: self.engine.node_snapshot().await,
            peer_face: self.policy.peer_face().map(|a| a.to_string()),
            allow_wan: config.allow_wan,
            relay_addrs_configured: config.relay_addrs.len(),
            reservation,
            relay: self.engine.relay_snapshot().await,
            expose_rules,
            connects,
            modes,
        }
    }

    // ==================== 内部 ====================

    /// 该插件是否仍持有隧道资源（expose 规则或客户端句柄）——
    /// 服务租约的释放判据（最后一份资源归还时才 release `net.tunnel`）
    pub fn has_open_resources(&self, plugin_id: &str) -> bool {
        let state = self.state.lock().expect("tunnel state poisoned");
        state.rules.values().any(|r| r.owner == plugin_id) || state.connects.values().any(|c| c.owner == plugin_id)
    }

    fn config_of(&self, plugin_id: &str) -> TunnelConfig {
        self.state
            .lock()
            .expect("tunnel state poisoned")
            .configs
            .get(plugin_id)
            .cloned()
            .unwrap_or_default()
    }

    async fn ensure_running(&self) -> Result<()> {
        let _gate = self.start_gate.lock().await;
        self.engine.ensure_node().await?;
        let mut task = self.inbound_task.lock().expect("inbound task lock poisoned");
        // 接收循环异常退出后必须能重启（节点重启 / 接收器失效）：旧实现只看
        // `is_none()`，任务结束后句柄仍在，入站隧道会永久失效。
        let restart = task.as_ref().is_none_or(JoinHandle::is_finished);
        if restart {
            if let Some(old) = task.take() {
                old.abort();
            }
            let cancel = CancellationToken::new();
            {
                let mut slot = self.inbound_cancel.lock().expect("inbound cancel lock poisoned");
                if let Some(old) = slot.take() {
                    old.cancel();
                }
                *slot = Some(cancel.clone());
            }
            let engine = Arc::clone(&self.engine);
            let server = Arc::clone(&self.server);
            *task = Some(tokio::spawn(run_inbound_loop(engine, server, cancel)));
        }
        Ok(())
    }

    async fn ensure_peer_face(&self) -> Result<SocketAddr> {
        self.ensure_running().await?;
        let mut guard = self.peer_face.lock().await;
        if let Some(listener) = guard.as_ref() {
            return Ok(listener.addr);
        }
        let listener = self.peer_face_starter.start(self.registry.resolver()).await?;
        self.policy.set_peer_face(listener.addr)?;
        let addr = listener.addr;
        *guard = Some(listener);
        Ok(addr)
    }

    /// WAN 通道计数 +1：先建立 reservation 再允许拨号（失败回滚计数）
    async fn acquire_wan(&self, plugin_id: &str) -> Result<()> {
        {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            *state.inbound_wan.entry(plugin_id.to_string()).or_insert(0) += 1;
        }
        if let Err(e) = self.recount().await {
            self.release_wan(plugin_id).await;
            return Err(e);
        }
        Ok(())
    }

    async fn release_wan(&self, plugin_id: &str) {
        {
            let mut state = self.state.lock().expect("tunnel state poisoned");
            if let Some(count) = state.inbound_wan.get_mut(plugin_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.inbound_wan.remove(plugin_id);
                }
            }
        }
        if let Err(e) = self.recount().await {
            tracing::warn!(code = e.code, "tunnel reservation release failed: {}", e.detail);
        }
    }

    /// 单一引用计数：0→1 建立 reservation，1→0 释放。
    ///
    /// 计数 = 生效 expose 规则（其属主 `allowWan=true` 且配置了 relay 地址）+ 在飞
    /// WAN 通道（同样只在 `allowWan=true` 时计入——关闭外网立即停止 WAN 入口，
    /// 不保留 reservation）；地址取所有相关插件配置的并集（去重，保持声明顺序）。
    ///
    /// 地址变化且 `desired>0` 时以新地址重建 reservation（T02 的 reserve 幂等替换）；
    /// 重建失败保留旧 reservation 并显性告警，不把已生效的入口打死。
    async fn recount(&self) -> Result<()> {
        let _gate = self.recount_gate.lock().await;
        // 锁内只做纯计算；域名解析是 I/O（`lookup_host`），必须在锁外。
        let (desired, configs, reserved, reserved_addrs) = {
            let state = self.state.lock().expect("tunnel state poisoned");
            let eligible = |plugin: &str| {
                state
                    .configs
                    .get(plugin)
                    .map(|c| c.allow_wan && !c.relay_addrs.is_empty())
                    .unwrap_or(false)
            };
            let mut plugins: BTreeSet<String> = BTreeSet::new();
            let mut rule_count = 0usize;
            for entry in state.rules.values() {
                if eligible(&entry.owner) {
                    rule_count += 1;
                    plugins.insert(entry.owner.clone());
                }
            }
            let mut wan_count = 0usize;
            for (plugin, count) in &state.inbound_wan {
                if eligible(plugin) {
                    wan_count += count;
                    plugins.insert(plugin.clone());
                }
            }
            let configs: Vec<TunnelConfig> = plugins
                .iter()
                .filter_map(|plugin| state.configs.get(plugin).cloned())
                .collect();
            (
                rule_count + wan_count,
                configs,
                state.reserved,
                state.reserved_addrs.clone(),
            )
        };

        let mut addrs: Vec<Multiaddr> = Vec::new();
        for config in &configs {
            for addr in config.resolved_relay_addrs().await? {
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
        }

        let need_release = desired == 0 && reserved;
        let need_reserve = desired > 0 && !addrs.is_empty() && (!reserved || reserved_addrs != addrs);
        if need_reserve {
            match self.engine.reserve_relay(&addrs).await {
                Ok(()) => {
                    let mut state = self.state.lock().expect("tunnel state poisoned");
                    state.reserved = true;
                    state.reserved_addrs = addrs;
                    tracing::info!(desired, "tunnel relay reservation established");
                }
                Err(e) if reserved => {
                    // 地址切换失败：旧 reservation 仍可用（旧地址集合继续生效）；
                    // 显性告警（下一次 recount 会重试），不回滚 LAN / 旧 WAN 入口。
                    tracing::warn!(
                        code = e.code,
                        "tunnel relay reservation refresh failed; keeping previous: {}",
                        e.detail
                    );
                }
                Err(e) => return Err(e),
            }
        } else if need_release {
            self.engine.release_relay().await?;
            let mut state = self.state.lock().expect("tunnel state poisoned");
            state.reserved = false;
            state.reserved_addrs.clear();
            tracing::info!("tunnel relay reservation released");
        } else if desired > 0 && addrs.is_empty() {
            // 需要外网但没有可用地址：显性告警（status 里 reservation=false 可见），
            // 不回滚已经生效的 LAN 入口。
            tracing::warn!(
                desired,
                "tunnel relay reservation required but no relay address configured"
            );
        }
        Ok(())
    }
}

// ==================== 入站流接收 ====================

async fn run_inbound_loop(engine: Arc<dyn TunnelEngine>, server: Arc<TunnelServer>, cancel: CancellationToken) {
    // 单 peer 并发流计数：任务结束时归还（配额上限由 `TunnelPolicy` 判定）
    let active: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let next = tokio::select! {
            _ = cancel.cancelled() => break,
            next = engine.next_inbound() => next,
        };
        let Some((node_id, access_path, mut io)) = next else {
            // 接收器结束（节点重启 / `accept_streams` 短暂失败）：不能 `break`
            // 让入站永久失效；稍等后重新拉接收器（下次 `next_inbound` 自建）。
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        };
        // `matched` 的当前口径（spec §9.2#2 默认 = A：宿主全局传输信任）：
        // 「应用配对 + 传输信任两层」在信任表层面已合并——auth-center 配对成功、
        // file-transfer 首连确认都写同一张 peer 信任表；因此这里只查传输信任。
        // 若将来改 per-app 隔离口径（B），必须在此注入应用配对端口，不要在前端补判。
        let matched = engine.trust_contains(&node_id).await;
        let key = node_id.as_str().to_string();
        let streams = {
            let mut table = active.lock().expect("tunnel stream counter poisoned");
            let counter = table.entry(key.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        let ctx = TunnelStreamContext {
            peer_node_id: Some(key.clone()),
            matched,
            active_streams: streams,
            access_path,
        };
        let server = Arc::clone(&server);
        let active = Arc::clone(&active);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            // `stop` 取消：在飞配对 / 业务流必须关（只 abort 接收循环杀不掉已 spawn 的流）
            tokio::select! {
                _ = cancel.cancelled() => {}
                result = server.handle_stream(&mut io, &ctx) => {
                    if let Err(e) = result {
                        tracing::debug!(code = e.code, "tunnel stream rejected: {}", e.detail);
                    }
                }
            }
            let mut table = active.lock().expect("tunnel stream counter poisoned");
            if let Some(counter) = table.get_mut(&key) {
                *counter = counter.saturating_sub(1);
                if *counter == 0 {
                    table.remove(&key);
                }
            }
        });
    }
}

// ==================== 可拨地址投影 ====================

/// 本节点可拨 multiaddr 列表（LAN 直连在前、relay circuit 在后；去重保序）
///
/// 判据：
/// - 通配监听地址（`0.0.0.0` / `::`）→ 展开为 `local_ipv4` 里的每个地址（同端口）；
/// - 环回 / 链路本地 / 组播 / 未指定端口 → 丢弃（对端拨不到，只会增加无效候选）；
/// - `relay_addr`（对端可达的中继 multiaddr）→ 追加 `<relay>/p2p-circuit/p2p/<self>`，
///   这是跨网唯一可达路径。
///
/// 纯函数：接口枚举在调用方（[`crate::tunnel::netinfo`]），便于单测锁定判据。
pub fn dialable_addrs(
    listen: &[std::net::SocketAddr],
    local_ipv4: &[std::net::IpAddr],
    relay_addr: Option<&str>,
    peer_id: &str,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |addr: String| {
        if !out.contains(&addr) {
            out.push(addr);
        }
    };

    for addr in listen {
        let port = addr.port();
        if port == 0 {
            continue;
        }
        let ip = addr.ip();
        if ip.is_unspecified() {
            for local in local_ipv4 {
                push(format!("/ip4/{local}/tcp/{port}/p2p/{peer_id}"));
            }
            continue;
        }
        if ip.is_loopback() || ip.is_multicast() || is_link_local_ip(ip) {
            continue;
        }
        match ip {
            std::net::IpAddr::V4(v4) => push(format!("/ip4/{v4}/tcp/{port}/p2p/{peer_id}")),
            std::net::IpAddr::V6(v6) => push(format!("/ip6/{v6}/tcp/{port}/p2p/{peer_id}")),
        }
    }

    if let Some(relay) = relay_addr.map(str::trim).filter(|a| !a.is_empty()) {
        push(format!("{relay}/p2p-circuit/p2p/{peer_id}"));
    }
    out
}

fn is_link_local_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

// ==================== 生产引擎适配 ====================

/// 直接接 `PeerCtx` 的引擎实现（桌面 / 移动同一份；无宿主类型）
pub struct PeerCtxEngine {
    ctx: Arc<crate::PeerCtx>,
    inbound: tokio::sync::Mutex<Option<wasmnest_p2p_engine::IncomingStreams>>,
}

impl PeerCtxEngine {
    pub fn new(ctx: Arc<crate::PeerCtx>) -> Self {
        Self {
            ctx,
            inbound: tokio::sync::Mutex::new(None),
        }
    }

    /// 取启动期预注册的 TUNNEL 接收器（`RunningNode` 持有；取走后由管理器消费）
    async fn take_pre_registered_tunnel(&self) -> Option<wasmnest_p2p_engine::links::IncomingStreams> {
        let mut guard = self.ctx.state.runtime.lock().await;
        guard.as_mut()?.take_tunnel_streams()
    }

    async fn running(&self) -> Result<wasmnest_p2p_engine::engine::RunningNode> {
        let guard = self.ctx.state.runtime.lock().await;
        guard
            .as_ref()
            .map(|runtime| runtime.running.p2p_handle())
            .ok_or_else(|| TunnelError::new(CODE_PEER_OFFLINE, "对等网络节点未启动"))
    }

    fn to_engine_node(node_id: &NodeId) -> Result<wasmnest_p2p_engine::identity_bridge::NodeId> {
        wasmnest_p2p_engine::identity_bridge::NodeId::parse(node_id.as_str())
            .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("node id 转换失败：{e}")))
    }
}

#[async_trait]
impl TunnelEngine for PeerCtxEngine {
    async fn ensure_node(&self) -> Result<()> {
        crate::start_peer_node(Arc::clone(&self.ctx))
            .await
            .map(|_| ())
            .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("节点启动失败：{e}")))
    }

    async fn dial(&self, node_id: &NodeId, addrs: &[Multiaddr]) -> Result<()> {
        let running = self.running().await?;
        let expected = Self::to_engine_node(node_id)?;
        running
            .dial_addrs(addrs, expected, DIAL_PER_ADDR_TIMEOUT)
            .await
            .map(|_| ())
            .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("隧道拨号失败：{e}")))
    }

    /// §4.9：把引擎的拨号错误分类成判据层能消费的成因（认不出 = 保守 `Other`）
    async fn dial_classified(&self, node_id: &NodeId, addrs: &[Multiaddr]) -> std::result::Result<(), DialFailure> {
        let running = self
            .running()
            .await
            .map_err(|e| DialFailure::new(LanFailure::Other, e.detail))?;
        let expected = Self::to_engine_node(node_id).map_err(|e| DialFailure::new(LanFailure::Auth, e.detail))?;
        running
            .dial_addrs(addrs, expected, DIAL_PER_ADDR_TIMEOUT)
            .await
            .map(|_| ())
            .map_err(|e| classify_p2p_dial(&e))
    }

    /// §4.9：宿主侧网络事实（接口子网 + 蜂窝判定；应用 JS 不可见）
    async fn network_facts(&self) -> NetworkFacts {
        crate::tunnel::netinfo::system_network_facts()
    }

    /// 事件出口：宿主事件面 + 插件总线（`peer:*` / `tunnel:*` topic 映射见 crate 根）
    fn emit(&self, event: &str, payload: serde_json::Value) {
        crate::emit_json(&self.ctx, event, payload);
    }

    async fn open_tunnel(&self, node_id: &NodeId) -> Result<TunnelIo> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let running = self.running().await?;
        let expected = Self::to_engine_node(node_id)?;
        let stream = running
            .open_stream(&expected, wasmnest_p2p_engine::stream_proto::TUNNEL)
            .await
            .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("开隧道流失败：{e}")))?;
        Ok(Box::new(stream.compat()))
    }

    async fn next_inbound(&self) -> Option<(NodeId, AccessPath, TunnelIo)> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let mut guard = self.inbound.lock().await;
        loop {
            if guard.is_none() {
                // 优先取启动期预注册的接收器（T05：监听开始前已注册 TUNNEL，
                // `require_admitted=false`）——消除「节点已监听、接收器未注册」
                // 窗口；仅旧节点 / 测试无预注册时回退到懒注册。
                let mut pre_registered = self.take_pre_registered_tunnel().await;
                if pre_registered.is_none() {
                    if let Ok(running) = self.running().await {
                        pre_registered = running
                            .accept_streams(wasmnest_p2p_engine::stream_proto::TUNNEL, false)
                            .await
                            .ok();
                    }
                }
                match pre_registered {
                    Some(incoming) => *guard = Some(incoming),
                    None => {
                        // 节点未启动 / 注册失败：短退避后重试，不让接收循环退出
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            }
            let inbound = guard.as_mut()?.next().await;
            let Some(inbound) = inbound else {
                // 接收器结束（节点重启 / 流控制面重建）：丢掉旧引用，下一轮重建
                *guard = None;
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };
            let node_id = NodeId::parse(inbound.node_id.as_str()).ok()?;
            let access_path = {
                let running = self.running().await.ok()?;
                match running.peer_link(&inbound.node_id) {
                    Some(link) if link.transport == wasmnest_p2p_engine::relay::Transport::WanRelay => {
                        AccessPath::WanRelay
                    }
                    _ => AccessPath::LanDirect,
                }
            };
            return Some((node_id, access_path, Box::new(inbound.stream.compat())));
        }
    }

    async fn trust_contains(&self, node_id: &NodeId) -> bool {
        let guard = self.ctx.state.trust.lock().await;
        guard.as_ref().map(|trust| trust.contains(node_id)).unwrap_or(false)
    }

    async fn reserve_relay(&self, addrs: &[Multiaddr]) -> Result<()> {
        let running = self.running().await?;
        running
            .reserve_relay(addrs.to_vec())
            .await
            .map(|_| ())
            .map_err(|e| TunnelError::new(crate::tunnel::CODE_WAN_DISABLED, format!("relay 预留失败：{e}")))
    }

    async fn release_relay(&self) -> Result<()> {
        let running = self.running().await?;
        running
            .release_relay()
            .await
            .map(|_| ())
            .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("relay 释放失败：{e}")))
    }

    async fn relay_snapshot(&self) -> RelaySnapshot {
        let guard = self.ctx.state.runtime.lock().await;
        match guard.as_ref() {
            Some(runtime) => {
                let status = runtime.running.p2p_handle().relay_status();
                RelaySnapshot {
                    state: status.state.as_str().to_string(),
                    relay_addr: status.relay_addr.map(|a| a.to_string()),
                    detail: status.detail,
                }
            }
            None => RelaySnapshot {
                state: "relay-idle".to_string(),
                relay_addr: None,
                detail: "节点未启动".to_string(),
            },
        }
    }

    async fn node_snapshot(&self) -> NodeSnapshot {
        let guard = self.ctx.state.runtime.lock().await;
        match guard.as_ref() {
            Some(runtime) => {
                let running = runtime.running.p2p_handle();
                // 只有预留生效（`Reserved`）时 circuit 地址对本节点才可达；
                // `Connecting` / `Lost` 的 endpoint 只是「最近一次尝试的地址」，
                // 写进 QR 会让对端拨一个不可用地址（T08 `peer.addrs` 必须可拨）。
                let status = running.relay_status();
                let relay_addr = advertised_relay_addr(status.state, status.relay_addr.as_ref());
                NodeSnapshot {
                    started: true,
                    node_id: Some(runtime.node_id.clone()),
                    addrs: dialable_addrs(
                        &running.listen_addresses(),
                        &crate::tunnel::netinfo::dialable_ipv4_addrs(),
                        relay_addr.as_deref(),
                        &running.peer_id().to_string(),
                    ),
                }
            }
            None => NodeSnapshot::default(),
        }
    }
}

/// 可对外宣告的 relay circuit 地址：只有预留已建立时才有值。
///
/// `relay_status().relay_addr` 在 `Connecting` / `Lost` 也会保留最近端点；
/// 直接外发会让 QR / 连接串带上拨不通的候选（T08 要求 `peer.addrs` 可拨）。
fn advertised_relay_addr(state: RelayState, addr: Option<&Multiaddr>) -> Option<String> {
    (state == RelayState::Reserved)
        .then(|| addr.map(|a| a.to_string()))
        .flatten()
}

struct EngineOpener {
    engine: Arc<dyn TunnelEngine>,
    node_id: NodeId,
}

#[async_trait]
impl TunnelStreamOpener for EngineOpener {
    async fn open(&self) -> Result<TunnelIo> {
        self.engine.open_tunnel(&self.node_id).await
    }
}

/// 隧道后端连接：对等面与回环都只连注入地址，不做任何端口回退
struct TcpBackendConnector;

#[async_trait]
impl BackendConnector for TcpBackendConnector {
    async fn connect(&self, backend: &Backend) -> Result<(TunnelIo, SocketAddr)> {
        let addr = match backend {
            Backend::PeerFace(addr) | Backend::Loopback(addr) => *addr,
        };
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| TunnelError::new(CODE_PROXY_BIND_FAILED, format!("隧道后端连接失败：{}", e.kind())))?;
        let local = stream
            .local_addr()
            .map_err(|e| TunnelError::new(CODE_PROXY_BIND_FAILED, format!("读取本地地址失败：{}", e.kind())))?;
        Ok((Box::new(stream), local))
    }
}

// ==================== §4.9 拨号计划小工具 ====================

/// 本次 `connect` 的计划路径（拨号前确定）
enum Plan {
    /// 先拨 LAN（默认）
    Lan,
    /// 判据明确 / 用户手动：直接进 wan
    Wan(ModeReason),
}

/// 实际走通的路径（拨号后确定）
enum Path {
    Lan,
    Wan,
}

/// 候选地址按「是否经 relay」分成 LAN / relay 两组（保持调用方给的相对顺序）
fn split_addrs(addrs: &[Multiaddr]) -> (Vec<Multiaddr>, Vec<Multiaddr>) {
    addrs.iter().cloned().partition(|addr| !is_relay_dial_addr(addr))
}

fn collect_lan_ips(addrs: &[Multiaddr]) -> Vec<IpAddr> {
    addrs.iter().filter_map(host_ip).collect()
}

/// 从 multiaddr 取主机 IP（`/ip4/…` / `/ip6/…`）；域名候选不参与子网判定
fn host_ip(addr: &Multiaddr) -> Option<IpAddr> {
    let text = addr.to_string();
    let mut parts = text.split('/');
    while let Some(part) = parts.next() {
        if part == "ip4" || part == "ip6" {
            return parts.next().and_then(|raw| raw.parse().ok());
        }
    }
    None
}

/// 失败成因 → 可展示词（只回原因类别，不回显票据 / 请求内容）
fn failure_word(kind: LanFailure) -> &'static str {
    match kind {
        LanFailure::Timeout => "timeout",
        LanFailure::Refused => "connection-refused",
        LanFailure::ServiceMissing => "service-missing",
        LanFailure::Unreachable => "host-unreachable",
        LanFailure::Auth => "auth-failed",
        LanFailure::Other => "dial-failed",
    }
}

/// 引擎拨号错误 → §4.9 失败成因（逐候选结构化；**不解析聚合文本**）。
///
/// 保守口径：认不出的成因归 [`LanFailure::Other`]（= 判据不明确 → 保持 LAN），
/// 绝不因为「没分类」把流量推给中继；混合候选由 [`DialFailure::from_causes`]
/// 归并为「判据不明确」，仍保持 LAN。
fn classify_p2p_dial(error: &P2pError) -> DialFailure {
    let causes: Vec<LanFailure> = match error {
        P2pError::DialAllFailed { failures, .. } if !failures.is_empty() => {
            failures.iter().map(|failure| map_dial_cause(failure.cause)).collect()
        }
        P2pError::DialTimeout => vec![LanFailure::Timeout],
        P2pError::NotAdmitted(_) | P2pError::NodeIdMismatch { .. } | P2pError::UnsupportedPeerIdentity(_) => {
            vec![LanFailure::Auth]
        }
        P2pError::Dial(text) => vec![classify_dial_text(text)],
        _ => vec![LanFailure::Other],
    };
    DialFailure::from_causes(causes, error.to_string())
}

/// engine 的中性成因 → tunnel 的判据类别
fn map_dial_cause(cause: DialCause) -> LanFailure {
    match cause {
        DialCause::Timeout => LanFailure::Timeout,
        DialCause::Unreachable => LanFailure::Unreachable,
        DialCause::Refused => LanFailure::Refused,
        DialCause::NotAdmitted | DialCause::IdentityMismatch => LanFailure::Auth,
        DialCause::Relay | DialCause::Other => LanFailure::Other,
    }
}

/// 传输层成因文本 → 类别（`io::Error` 的 Display，Linux / Android 同源）
///
/// 只有 `no route to host` / `network is unreachable` 属于「明确不在内网」判据；
/// `connection refused` / timeout 一律「判据不明确」。
fn classify_dial_text(text: &str) -> LanFailure {
    let lower = text.to_ascii_lowercase();
    if lower.contains("no route to host")
        || lower.contains("network is unreachable")
        || lower.contains("host is unreachable")
    {
        LanFailure::Unreachable
    } else if lower.contains("connection refused") {
        LanFailure::Refused
    } else if lower.contains("timed out") || lower.contains("timeout") {
        LanFailure::Timeout
    } else {
        LanFailure::Other
    }
}

/// `peer:mode` 事件载荷（词表字面 + 归因 + 时刻）
fn mode_event(view: &PeerModeView) -> serde_json::Value {
    serde_json::json!({
        "nodeId": view.node_id,
        "mode": view.mode.as_str(),
        "reason": view.reason.map(|reason| reason.as_str()),
        "lanProbeWins": view.lan_probe_wins,
        "manualWan": view.manual_wan,
        "atMs": view.updated_at_ms,
    })
}

// ==================== 小工具 ====================

fn parse_kind(kind: &str) -> Result<TunnelKind> {
    TunnelKind::parse(kind).ok_or_else(|| {
        TunnelError::new(
            CODE_PEER_OFFLINE,
            format!("未知通道 kind `{kind}`（只支持 http / tcp）"),
        )
    })
}

fn parse_addrs(addrs_json: &str) -> Result<Vec<Multiaddr>> {
    let raw: Vec<String> = serde_json::from_str(addrs_json)
        .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("addrs 不是字符串数组：{e}")))?;
    if raw.is_empty() {
        return Err(TunnelError::new(CODE_PEER_OFFLINE, "候选地址为空"));
    }
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let addr: Multiaddr = item
            .parse()
            .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("multiaddr 非法：{e}")))?;
        out.push(addr);
    }
    Ok(out)
}

/// 经 relay 的拨号地址形状：`.../p2p-circuit/p2p/<target>`
///
/// 用 multiaddr 的规范文本判定（能力仓不直接依赖 libp2p 类型；`/p2p-circuit`
/// 是协议名，不会被误判为普通地址段）。
fn is_relay_dial_addr(addr: &Multiaddr) -> bool {
    addr.to_string().contains("/p2p-circuit")
}

#[cfg(test)]
mod tests;
