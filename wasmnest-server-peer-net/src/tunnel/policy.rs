//! 暴露规则与隧道准入（不变量 2 / 8 / 16）。
//!
//! 判定顺序固定：首帧形状 → 规则（port + kind）→ 配额 → 已匹配校验 →
//! `allowedPeers` → 后端选择。任何一步失败都以点名错误码拒绝，绝不静默降级到
//! 「直接连 8765」或「按回环当本机」。
//!
//! `matched` 由宿主按「应用配对 + 传输层信任」两层同时成立后给出；本模块不自行
//! 查信任表、不采信客户端自报的 `peerNodeId`（值必须来自隧道层已验证上下文）。

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::RwLock;

use uuid::Uuid;
use wasmnest_server_base::constants::DEFAULT_SERVER_PORT;

use crate::base::identity::NodeId;
use crate::tunnel::frame::TunnelKind;
use crate::tunnel::Result;
use crate::tunnel::{TunnelError, TunnelHello, CODE_NOT_MATCHED, CODE_PORT_NOT_EXPOSED, CODE_TUNNEL_LIMIT};

pub const DEFAULT_MAX_STREAMS_PER_PEER: usize = 32;

/// 通道后端：`Http` 恒指向对等 HTTP/WS 面；`Tcp` 只指向回环
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    PeerFace(SocketAddr),
    Loopback(SocketAddr),
}

/// `expose` 的调用形状（与契约分片 `expose-config` 对齐）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeConfig {
    pub port: u16,
    pub kind: TunnelKind,
    pub label: String,
    pub allowed_peers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeRule {
    pub id: String,
    pub port: u16,
    pub kind: TunnelKind,
    pub label: String,
    /// 空 = 所有已匹配 peer
    pub allowed_peers: Vec<String>,
}

/// 一次入站流的裁决输入（全部由宿主 / 隧道层给出，不读请求头）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionContext {
    /// 隧道层已验证的对端 node id
    pub peer_node_id: Option<String>,
    /// 应用层配对 + 传输层信任两层是否同时成立
    pub matched: bool,
    /// 本条流的配对票据是否通过一次性消费校验
    pub ticket_valid: bool,
    pub active_streams: usize,
}

/// 裁决结果：`pairing=true` 时宿主必须把连接登记进配对注册表，由对等面执行
/// 路径白名单；配对窗口连接不得复用于业务访问
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub backend: Backend,
    pub pairing: bool,
    pub peer_node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    /// 对等 HTTP/WS 面的实际监听地址；`None` = 本端尚未（或不会）启动对等面
    pub peer_face: Option<SocketAddr>,
    pub management_ports: BTreeSet<u16>,
    pub max_streams_per_peer: usize,
}

impl PolicyConfig {
    /// 宿主必须注入**实际**监听端口（不是 0 / 默认值），否则拒绝装配
    pub fn new(peer_face: SocketAddr, peer_node_port: u16, relay_control_port: u16) -> Result<Self> {
        if peer_face.port() == 0 || peer_node_port == 0 || relay_control_port == 0 {
            return Err(TunnelError::new(
                CODE_PORT_NOT_EXPOSED,
                "必须注入对等面 / 节点 / 中继控制的实际监听端口",
            ));
        }
        validate_peer_face(peer_face)?;
        let management_ports = BTreeSet::from([
            DEFAULT_SERVER_PORT,
            peer_node_port,
            peer_face.port(),
            relay_control_port,
        ]);
        Ok(Self {
            peer_face: Some(peer_face),
            management_ports,
            max_streams_per_peer: DEFAULT_MAX_STREAMS_PER_PEER,
        })
    }

    /// 先装配、后绑定对等面（宿主 listener 端口由系统分配时使用）：
    /// 管理端口先只含网关 / 节点 / 中继控制三项，对等面就绪后经
    /// [`TunnelPolicy::set_peer_face`] 补入。
    pub fn unbound(peer_node_port: u16, relay_control_port: u16) -> Result<Self> {
        if peer_node_port == 0 || relay_control_port == 0 {
            return Err(TunnelError::new(
                CODE_PORT_NOT_EXPOSED,
                "必须注入节点 / 中继控制的实际监听端口",
            ));
        }
        Ok(Self {
            peer_face: None,
            management_ports: BTreeSet::from([DEFAULT_SERVER_PORT, peer_node_port, relay_control_port]),
            max_streams_per_peer: DEFAULT_MAX_STREAMS_PER_PEER,
        })
    }
}

fn validate_peer_face(addr: SocketAddr) -> Result<()> {
    if addr.port() == 0 {
        return Err(TunnelError::new(CODE_PORT_NOT_EXPOSED, "对等面端口为 0"));
    }
    if !addr.ip().is_loopback() || addr.port() == DEFAULT_SERVER_PORT {
        return Err(TunnelError::new(
            CODE_PORT_NOT_EXPOSED,
            "对等面只能绑回环且不得复用网关端口",
        ));
    }
    Ok(())
}

pub struct TunnelPolicy {
    rules: RwLock<HashMap<String, ExposeRule>>,
    cfg: RwLock<PolicyConfig>,
}

impl TunnelPolicy {
    pub fn new(cfg: PolicyConfig) -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
            cfg: RwLock::new(cfg),
        }
    }

    pub fn config(&self) -> PolicyConfig {
        self.cfg.read().expect("tunnel policy config poisoned").clone()
    }

    /// 绑定对等面实际监听地址（只允许 loopback、不得复用网关端口）；
    /// 重复绑定到同一地址幂等，换地址则同步更新管理端口黑名单。
    pub fn set_peer_face(&self, addr: SocketAddr) -> Result<()> {
        validate_peer_face(addr)?;
        let mut cfg = self.cfg.write().expect("tunnel policy config poisoned");
        if let Some(previous) = cfg.peer_face {
            cfg.management_ports.remove(&previous.port());
        }
        cfg.peer_face = Some(addr);
        cfg.management_ports.insert(addr.port());
        Ok(())
    }

    pub fn peer_face(&self) -> Option<SocketAddr> {
        self.cfg.read().expect("tunnel policy config poisoned").peer_face
    }

    /// 服务租约 1→0：对等面已停，后续 kind=http 的准入显性 `tunnel-unavailable`
    pub fn clear_peer_face(&self) {
        let mut cfg = self.cfg.write().expect("tunnel policy config poisoned");
        if let Some(previous) = cfg.peer_face.take() {
            cfg.management_ports.remove(&previous.port());
        }
    }

    /// 登记规则；同 `(port, kind)` 重复登记返回既有 id（幂等，默认不暴露任何端口）
    pub fn expose(&self, config: ExposeConfig) -> Result<String> {
        if config.port == 0 {
            return Err(TunnelError::new(CODE_PORT_NOT_EXPOSED, "目标端口为 0"));
        }
        let management_ports = self
            .cfg
            .read()
            .expect("tunnel policy config poisoned")
            .management_ports
            .clone();
        if config.kind == TunnelKind::Tcp && management_ports.contains(&config.port) {
            return Err(TunnelError::new(
                CODE_PORT_NOT_EXPOSED,
                format!("端口 {} 属于宿主管理面，禁止以 kind=tcp 裸暴露", config.port),
            ));
        }
        for node_id in &config.allowed_peers {
            NodeId::parse(node_id)
                .map_err(|_| TunnelError::new(CODE_NOT_MATCHED, "allowedPeers 含非法 node id（须 64 位小写 hex）"))?;
        }
        let mut rules = self.rules.write().expect("expose rules poisoned");
        if let Some(existing) = rules.values().find(|r| r.port == config.port && r.kind == config.kind) {
            return Ok(existing.id.clone());
        }
        let id = format!("tunnel-rule-{}", Uuid::new_v4());
        rules.insert(
            id.clone(),
            ExposeRule {
                id: id.clone(),
                port: config.port,
                kind: config.kind,
                label: config.label,
                allowed_peers: config.allowed_peers,
            },
        );
        Ok(id)
    }

    pub fn unexpose(&self, rule_id: &str) -> bool {
        self.rules
            .write()
            .expect("expose rules poisoned")
            .remove(rule_id)
            .is_some()
    }

    pub fn rules(&self) -> Vec<ExposeRule> {
        let mut rules: Vec<_> = self
            .rules
            .read()
            .expect("expose rules poisoned")
            .values()
            .cloned()
            .collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        rules
    }

    pub fn admit(&self, hello: &TunnelHello, ctx: &AdmissionContext) -> Result<Admission> {
        hello.validate()?;
        let cfg = self.cfg.read().expect("tunnel policy config poisoned").clone();
        let rule = self
            .rules
            .read()
            .expect("expose rules poisoned")
            .values()
            .find(|r| r.port == hello.port && r.kind == hello.kind)
            .cloned()
            .ok_or_else(|| {
                TunnelError::new(
                    CODE_PORT_NOT_EXPOSED,
                    format!("端口 {} / kind {} 未暴露", hello.port, hello.kind.as_str()),
                )
            })?;

        if ctx.active_streams >= cfg.max_streams_per_peer {
            return Err(TunnelError::new(
                CODE_TUNNEL_LIMIT,
                format!("单 peer 并发流达上限 {}", cfg.max_streams_per_peer),
            ));
        }

        // 未匹配 peer 只有配对票据这一条例外；缺校验过的 node id 的已匹配声明
        // 同样拒绝（不变量 16：不得由客户端自报身份补齐）。
        let pairing = if ctx.matched {
            false
        } else if ctx.ticket_valid {
            true
        } else {
            return Err(TunnelError::new(
                CODE_NOT_MATCHED,
                "应用配对或传输信任不成立，且无有效配对票据",
            ));
        };
        if ctx.matched && ctx.peer_node_id.is_none() {
            return Err(TunnelError::new(
                CODE_NOT_MATCHED,
                "已匹配声明缺少隧道层验证过的 peerNodeId",
            ));
        }
        if !rule.allowed_peers.is_empty() {
            let allowed = ctx
                .peer_node_id
                .as_deref()
                .is_some_and(|id| rule.allowed_peers.iter().any(|p| p == id));
            if !allowed {
                return Err(TunnelError::new(CODE_NOT_MATCHED, "对端不在该端口的 allowedPeers 内"));
            }
        }

        // kind=tcp 的端口黑名单在 expose 已查一次，这里再查：规则可能来自旧
        // 版本配置或宿主注入了变化后的管理端口，纵深防御不许在这里漏过。
        if hello.kind == TunnelKind::Tcp && cfg.management_ports.contains(&hello.port) {
            return Err(TunnelError::new(
                CODE_PORT_NOT_EXPOSED,
                format!("端口 {} 属于宿主管理面", hello.port),
            ));
        }

        let backend = match hello.kind {
            TunnelKind::Http => Backend::PeerFace(cfg.peer_face.ok_or_else(|| {
                TunnelError::new(
                    crate::tunnel::CODE_TUNNEL_UNAVAILABLE,
                    "本端对等 HTTP/WS 面尚未启动，拒绝对 kind=http 的后端连接",
                )
            })?),
            TunnelKind::Tcp => Backend::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), hello.port)),
        };
        Ok(Admission {
            backend,
            pairing,
            peer_node_id: ctx.peer_node_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NODE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Fixture {
        policy: TunnelPolicy,
        peer_face: SocketAddr,
        peer_port: u16,
        relay_port: u16,
    }

    fn fixture() -> Fixture {
        let peer_face = SocketAddr::from(([127, 0, 0, 1], 39001));
        let peer_port = 47613;
        let relay_port = 4001;
        let cfg = PolicyConfig::new(peer_face, peer_port, relay_port).unwrap();
        Fixture {
            policy: TunnelPolicy::new(cfg),
            peer_face,
            peer_port,
            relay_port,
        }
    }

    fn expose(policy: &TunnelPolicy, port: u16, kind: TunnelKind, allowed: Vec<String>) {
        policy
            .expose(ExposeConfig {
                port,
                kind,
                label: "test".into(),
                allowed_peers: allowed,
            })
            .unwrap();
    }

    fn matched_ctx() -> AdmissionContext {
        AdmissionContext {
            peer_node_id: Some(NODE_A.into()),
            matched: true,
            ticket_valid: false,
            active_streams: 0,
        }
    }

    #[test]
    fn policy_requires_real_management_ports() {
        assert!(PolicyConfig::new(SocketAddr::from(([127, 0, 0, 1], 39001)), 0, 4001).is_err());
        assert!(PolicyConfig::new(SocketAddr::from(([0, 0, 0, 0], 39001)), 47613, 4001).is_err());
        assert!(PolicyConfig::new(SocketAddr::from(([127, 0, 0, 1], 8765)), 47613, 4001).is_err());
        let cfg = PolicyConfig::new(SocketAddr::from(([127, 0, 0, 1], 39001)), 47613, 4001).unwrap();
        assert_eq!(cfg.management_ports, BTreeSet::from([8765, 47613, 39001, 4001]));
    }

    /// 不变量 2：`kind=http` 的 8765 只是逻辑端口，后端恒为对等面
    #[test]
    fn http_kind_never_forwards_to_gateway_port() {
        let f = fixture();
        expose(&f.policy, DEFAULT_SERVER_PORT, TunnelKind::Http, vec![]);
        let admission = f
            .policy
            .admit(
                &TunnelHello::new(DEFAULT_SERVER_PORT, TunnelKind::Http, None),
                &matched_ctx(),
            )
            .unwrap();
        assert_eq!(admission.backend, Backend::PeerFace(f.peer_face));
        assert_ne!(
            admission.backend,
            Backend::Loopback(SocketAddr::from(([127, 0, 0, 1], 8765)))
        );
    }

    /// 不变量 2：`kind=tcp` 拒绝四类宿主管理端口
    #[test]
    fn tcp_kind_rejects_all_management_ports() {
        let f = fixture();
        for port in [DEFAULT_SERVER_PORT, f.peer_port, f.peer_face.port(), f.relay_port] {
            let err = f
                .policy
                .expose(ExposeConfig {
                    port,
                    kind: TunnelKind::Tcp,
                    label: "test".into(),
                    allowed_peers: vec![],
                })
                .unwrap_err();
            assert_eq!(err.code, CODE_PORT_NOT_EXPOSED, "端口 {port} 必须拒绝");
        }
        expose(&f.policy, 39002, TunnelKind::Tcp, vec![]);
        let admission = f
            .policy
            .admit(&TunnelHello::new(39002, TunnelKind::Tcp, None), &matched_ctx())
            .unwrap();
        assert_eq!(
            admission.backend,
            Backend::Loopback(SocketAddr::from(([127, 0, 0, 1], 39002)))
        );
    }

    /// 不变量 8 / 16：未匹配无票据拒绝；有票据只开配对窗口
    #[test]
    fn unmatched_peer_is_rejected_except_for_valid_ticket_window() {
        let f = fixture();
        expose(&f.policy, DEFAULT_SERVER_PORT, TunnelKind::Http, vec![]);
        let mut unmatched = matched_ctx();
        unmatched.matched = false;
        unmatched.peer_node_id = None;
        assert_eq!(
            f.policy
                .admit(&TunnelHello::new(8765, TunnelKind::Http, None), &unmatched)
                .unwrap_err()
                .code,
            CODE_NOT_MATCHED
        );
        unmatched.ticket_valid = true;
        let window = f
            .policy
            .admit(
                &TunnelHello::new(8765, TunnelKind::Http, Some("tk-1".into())),
                &unmatched,
            )
            .unwrap();
        assert!(window.pairing, "配对窗口必须显式标记给面标记注册表");
        assert!(window.peer_node_id.is_none());
    }

    #[test]
    fn matched_declaration_without_verified_node_id_is_rejected() {
        let f = fixture();
        expose(&f.policy, DEFAULT_SERVER_PORT, TunnelKind::Http, vec![]);
        let mut ctx = matched_ctx();
        ctx.peer_node_id = None;
        assert_eq!(
            f.policy
                .admit(&TunnelHello::new(8765, TunnelKind::Http, None), &ctx)
                .unwrap_err()
                .code,
            CODE_NOT_MATCHED
        );
    }

    #[test]
    fn allowed_peers_narrows_and_invalid_node_ids_are_rejected() {
        let f = fixture();
        assert_eq!(
            f.policy
                .expose(ExposeConfig {
                    port: 39002,
                    kind: TunnelKind::Tcp,
                    label: "test".into(),
                    allowed_peers: vec!["not-a-node-id".into()],
                })
                .unwrap_err()
                .code,
            CODE_NOT_MATCHED
        );
        expose(&f.policy, 39002, TunnelKind::Tcp, vec![NODE_A.into()]);
        assert!(f
            .policy
            .admit(&TunnelHello::new(39002, TunnelKind::Tcp, None), &matched_ctx())
            .is_ok());
        let mut other = matched_ctx();
        other.peer_node_id = Some(NODE_B.into());
        assert_eq!(
            f.policy
                .admit(&TunnelHello::new(39002, TunnelKind::Tcp, None), &other)
                .unwrap_err()
                .code,
            CODE_NOT_MATCHED
        );
    }

    #[test]
    fn rules_are_idempotent_and_unknown_rule_fails_visible() {
        let f = fixture();
        let a = f
            .policy
            .expose(ExposeConfig {
                port: 39002,
                kind: TunnelKind::Tcp,
                label: "one".into(),
                allowed_peers: vec![],
            })
            .unwrap();
        let b = f
            .policy
            .expose(ExposeConfig {
                port: 39002,
                kind: TunnelKind::Tcp,
                label: "two".into(),
                allowed_peers: vec![],
            })
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(f.policy.rules().len(), 1);
        assert_eq!(
            f.policy
                .admit(&TunnelHello::new(39003, TunnelKind::Tcp, None), &matched_ctx())
                .unwrap_err()
                .code,
            CODE_PORT_NOT_EXPOSED
        );
        assert!(f.policy.unexpose(&a));
        assert_eq!(
            f.policy
                .admit(&TunnelHello::new(39002, TunnelKind::Tcp, None), &matched_ctx())
                .unwrap_err()
                .code,
            CODE_PORT_NOT_EXPOSED
        );
    }

    #[test]
    fn stream_quota_is_enforced() {
        let f = fixture();
        expose(&f.policy, DEFAULT_SERVER_PORT, TunnelKind::Http, vec![]);
        let mut ctx = matched_ctx();
        ctx.active_streams = DEFAULT_MAX_STREAMS_PER_PEER;
        assert_eq!(
            f.policy
                .admit(&TunnelHello::new(8765, TunnelKind::Http, None), &ctx)
                .unwrap_err()
                .code,
            CODE_TUNNEL_LIMIT
        );
    }

    /// T06：对等面端口由宿主 listener 实际分配，装配可先于绑定；
    /// 未绑定前 kind=http 显性失败，绝不回落到任何默认端口。
    #[test]
    fn unbound_peer_face_fails_visible_until_set() {
        let cfg = PolicyConfig::unbound(47613, 4001).unwrap();
        let policy = TunnelPolicy::new(cfg);
        policy
            .expose(ExposeConfig {
                port: DEFAULT_SERVER_PORT,
                kind: TunnelKind::Http,
                label: "test".into(),
                allowed_peers: vec![],
            })
            .unwrap();
        assert_eq!(
            policy
                .admit(&TunnelHello::new(8765, TunnelKind::Http, None), &matched_ctx())
                .unwrap_err()
                .code,
            crate::tunnel::CODE_TUNNEL_UNAVAILABLE
        );

        let addr = SocketAddr::from(([127, 0, 0, 1], 39011));
        policy.set_peer_face(addr).unwrap();
        assert_eq!(policy.peer_face(), Some(addr));
        assert!(policy.config().management_ports.contains(&39011));
        let admission = policy
            .admit(&TunnelHello::new(8765, TunnelKind::Http, None), &matched_ctx())
            .unwrap();
        assert_eq!(admission.backend, Backend::PeerFace(addr));

        // 换地址：旧端口必须从管理端口黑名单里摘除（不留下误伤）
        let moved = SocketAddr::from(([127, 0, 0, 1], 39012));
        policy.set_peer_face(moved).unwrap();
        let ports = policy.config().management_ports;
        assert!(!ports.contains(&39011));
        assert!(ports.contains(&39012));
    }

    /// 对等面地址约束：非回环 / 端口 0 / 复用网关端口一律拒绝
    #[test]
    fn peer_face_must_be_loopback_and_never_gateway_port() {
        let policy = TunnelPolicy::new(PolicyConfig::unbound(47613, 4001).unwrap());
        assert!(policy.set_peer_face(SocketAddr::from(([0, 0, 0, 0], 39011))).is_err());
        assert!(policy.set_peer_face(SocketAddr::from(([127, 0, 0, 1], 0))).is_err());
        assert!(policy
            .set_peer_face(SocketAddr::from(([127, 0, 0, 1], DEFAULT_SERVER_PORT)))
            .is_err());
    }
}
