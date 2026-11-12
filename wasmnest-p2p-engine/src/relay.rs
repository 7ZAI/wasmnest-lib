//! Circuit Relay v2 客户端地址面（T01/T02）：地址解析、PeerId 钉住、传输形态与预留状态。
//!
//! ## 分层
//!
//! - **地址面（本模块，始终编译）**：relay multiaddr 的校验/拆分、域名→IP 的宿主侧解析、
//!   传输形态分类（`lan-direct` / `wan-relay`）、预留状态快照。纯字符串/多址运算，
//!   不依赖 `relay` feature——宿主可以先校验地址、再决定是否启用 relay。
//! - **运行时（`engine` + `relay` feature）**：`libp2p-relay` 客户端行为、circuit 监听
//!   （= 预留）、预留失败退避重试。feature 关闭时 [`crate::engine::RunningNode::reserve_relay`]
//!   显性返回 [`P2pError::RelayDisabled`]，不静默降级。
//!
//! ## 地址形状（设计 §4.2）
//!
//! ```text
//! relay 端点（钉住 PeerId）: /ip4/203.0.113.10/tcp/4001/p2p/12D3KooWRelay...
//! 本机预留（监听）        : /ip4/203.0.113.10/tcp/4001/p2p/12D3KooWRelay.../p2p-circuit
//! 拨号目标（经 relay）    : /ip4/203.0.113.10/tcp/4001/p2p/12D3KooWRelay.../p2p-circuit/p2p/12D3KooWTarget...
//! ```
//!
//! **域名不启用引擎 `dns` feature**（Android feature 面纪律，T02）：`/dns4|dns6|dns`
//! 地址由宿主层调用 [`resolve_relay_addr`] 用 `tokio::net::lookup_host` 解析成 IP
//! 后再进入引擎；[`RelayEndpoint::parse`] 见到 DNS 组件一律显性拒绝，避免静默失败。

use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use crate::error::P2pError;

/// 一次连接的底层传输形态（设计 §7.2 `peer:transport` 词表）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// LAN 直连（不经 relay 数据面）
    LanDirect,
    /// 经 relay 转发（地址含 `/p2p-circuit`）
    WanRelay,
}

impl Transport {
    /// 按 multiaddr 判定传输形态：含 `/p2p-circuit` 即 relayed
    pub fn from_multiaddr(addr: &Multiaddr) -> Self {
        if addr.iter().any(|p| p == Protocol::P2pCircuit) {
            Self::WanRelay
        } else {
            Self::LanDirect
        }
    }

    /// 设计 §7.2 的事件词表字面（日志/事件桥使用）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LanDirect => "lan-direct",
            Self::WanRelay => "wan-relay",
        }
    }
}

/// relay 预留（reservation）生命周期状态
///
/// 词汇对齐设计 §7.2：`relay-reserved`（[`Self::Reserved`]）/ `relay-lost`
/// （[`Self::Lost`]）。`Connecting` 是引擎内部的「预留请求在飞」，让宿主状态栏
/// 能区分「还没连上」与「真丢了」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayState {
    /// 未启用（未配置 relay，或已显式释放）
    #[default]
    Idle,
    /// 预留请求在飞（含退避重试等待）
    Connecting,
    /// 预留已建立（控制面可用；不代表有数据流量——lan-active 时不产生 relay 数据）
    Reserved,
    /// 预留丢失 / relay 不可达，引擎按指数退避重试
    Lost,
}

impl RelayState {
    /// 事件词表字面（`peer:transport` 的 relay 半边）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "relay-idle",
            Self::Connecting => "relay-connecting",
            Self::Reserved => "relay-reserved",
            Self::Lost => "relay-lost",
        }
    }
}

/// relay 控制面状态快照（`host-tunnel.status` / `peer:transport` 的取数面）
#[derive(Debug, Clone, Default)]
pub struct RelayStatus {
    /// 当前状态
    pub state: RelayState,
    /// 当前（或最近一次尝试的）relay 端点 multiaddr（含 `/p2p/<relay>`，不含 `/p2p-circuit`）
    pub relay_addr: Option<Multiaddr>,
    /// 细节：失败原因 / 退避倒计时 / 成功时间等（人读，不承载秘密）
    pub detail: String,
}

/// 已钉住 PeerId 的 relay 端点
///
/// 钉住是安全判据（设计 §4.10）：relay 身份在 multiaddr 中固定，**不接受**
/// 「同 IP 不同 PeerId」的替换——否则同名 relay 被中间人顶替后 Noise 只保护到
/// 假 relay，端到端语义被削弱。
#[derive(Debug, Clone)]
pub struct RelayEndpoint {
    /// 基础地址：`.../p2p/<relay>`（不含 `/p2p-circuit`）
    base: Multiaddr,
    /// 钉住的 relay PeerId（也是 `base` 最后的 `/p2p` 组件）
    peer_id: PeerId,
}

impl RelayEndpoint {
    /// 解析并校验 relay 端点地址
    ///
    /// 判据：
    /// 1. 必须是 `.../tcp/<port>/p2p/<relay-id>` 形状（v1 只支持 TCP，QUIC 属 P3）；
    /// 2. 不得含 `/p2p-circuit`（那是预留/拨号地址，不是端点地址）；
    /// 3. 不允许 DNS 组件（宿主先 `resolve_relay_addr`，引擎不启用 dns feature）；
    /// 4. `expected_relay` 非空时必须与地址里的 PeerId 逐字一致（钉住校验）。
    pub fn parse(addr: &Multiaddr, expected_relay: Option<PeerId>) -> Result<Self, P2pError> {
        let mut seen_tcp = false;
        let mut seen_dns = false;
        let mut peer: Option<PeerId> = None;
        let mut last_is_peer = false;
        for p in addr.iter() {
            match p {
                Protocol::P2pCircuit => {
                    return Err(P2pError::Relay(format!(
                        "relay 端点地址不得包含 /p2p-circuit（{addr}）；预留地址由引擎自行拼装"
                    )));
                }
                Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                    seen_dns = true;
                }
                Protocol::Tcp(_) => seen_tcp = true,
                Protocol::P2p(id) => {
                    peer = Some(id);
                    last_is_peer = true;
                    continue;
                }
                _ => {}
            }
            last_is_peer = false;
        }
        if seen_dns {
            return Err(P2pError::Relay(format!(
                "relay 端点地址含域名（{addr}）：先经 resolve_relay_addr 解析为 IP 再交给引擎（不启用 dns feature）"
            )));
        }
        if !seen_tcp {
            return Err(P2pError::Relay(format!(
                "relay 端点地址缺少 /tcp/<port>（{addr}）；v1 只支持 TCP relay"
            )));
        }
        let peer = peer.ok_or_else(|| {
            P2pError::Relay(format!(
                "relay 端点地址缺少 /p2p/<relay-peer-id>（{addr}）——必须钉住 relay 身份"
            ))
        })?;
        if !last_is_peer {
            return Err(P2pError::Relay(format!(
                "relay 端点地址的 /p2p 必须是最后一个组件（{addr}）"
            )));
        }
        if let Some(expected) = expected_relay {
            if expected != peer {
                return Err(P2pError::RelayPeerMismatch {
                    expected: expected.to_string(),
                    actual: peer.to_string(),
                });
            }
        }
        Ok(Self {
            base: addr.clone(),
            peer_id: peer,
        })
    }

    /// 钉住的 relay PeerId
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// 端点基础地址（`.../p2p/<relay>`，不含 `/p2p-circuit`）
    pub fn base(&self) -> &Multiaddr {
        &self.base
    }

    /// 本机在该 relay 上的预留地址（`.../p2p/<relay>/p2p-circuit`）
    pub fn reservation_addr(&self) -> Multiaddr {
        self.base.clone().with(Protocol::P2pCircuit)
    }

    /// 经该 relay 拨号对端的完整地址（`.../p2p-circuit/p2p/<target>`）
    pub fn dial_addr(&self, target: PeerId) -> Multiaddr {
        self.reservation_addr().with(Protocol::P2p(target))
    }
}

/// 经 relay 拨号地址里的 relay PeerId（`/p2p-circuit` 之前最后一个 `/p2p`）
///
/// 用于把「到 relay 的直接控制连接」与「经 relay 的业务连接」区分开：前者是
/// 基础设施连接（不登记为业务对端 / 不发 `peer_connected`），后者才是业务链路。
/// 直连地址返回 `None`。
pub fn relay_peer_of_dial_addr(addr: &Multiaddr) -> Option<PeerId> {
    let mut last_p2p = None;
    for p in addr.iter() {
        match p {
            Protocol::P2pCircuit => return last_p2p,
            Protocol::P2p(id) => last_p2p = Some(id),
            _ => {}
        }
    }
    None
}

/// 校验经 relay 拨号地址的形状：必须 `.../p2p-circuit/p2p/<target>` 收尾
///
/// 返回目标 PeerId。非 relayed 地址返回 `None`（直连地址不归本判据管）。
pub fn relayed_dial_target(addr: &Multiaddr) -> Result<Option<PeerId>, P2pError> {
    let mut after_circuit = false;
    let mut target = None;
    for p in addr.iter() {
        if after_circuit {
            match p {
                Protocol::P2p(id) => target = Some(id),
                _ => {
                    return Err(P2pError::Relay(format!(
                        "经 relay 的拨号地址在 /p2p-circuit 后只允许 /p2p/<target>（{addr}）"
                    )));
                }
            }
        } else if p == Protocol::P2pCircuit {
            after_circuit = true;
        }
    }
    if !after_circuit {
        return Ok(None);
    }
    match target {
        Some(id) => Ok(Some(id)),
        None => Err(P2pError::Relay(format!(
            "经 relay 的拨号地址缺少目标 /p2p/<target>（{addr}）——libp2p 无法路由"
        ))),
    }
}

/// 把 relay 地址里的域名解析成 IP multiaddr 候选（宿主层调用；引擎不启用 dns feature）
///
/// - 无 DNS 组件：原样返回一条；
/// - 有 DNS 组件：`tokio::net::lookup_host` 解析，IPv4 在前、IPv6 在后（去重）；
/// - 解析失败 / 无地址：显性错误（不静默回退空列表）。
///
/// 解析结果仍保留 `.../p2p/<relay>` 尾部，可直接交给 [`RelayEndpoint::parse`]。
pub async fn resolve_relay_addr(input: &str) -> Result<Vec<Multiaddr>, P2pError> {
    let addr: Multiaddr = input
        .trim()
        .parse()
        .map_err(|e| P2pError::Relay(format!("relay 地址无法解析（{input}）：{e}")))?;

    // 拆成「DNS 之前的固定前缀」+「DNS 主机」+「TCP 端口及之后的尾部」
    let mut head = Multiaddr::empty();
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut tail = Multiaddr::empty();
    let mut seen_tcp = false;
    for p in addr.iter() {
        if seen_tcp {
            tail = tail.with(p);
            continue;
        }
        match p {
            Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => {
                if host.replace(h.to_string()).is_some() {
                    return Err(P2pError::Relay(format!(
                        "relay 地址含多个 DNS 组件（{addr}），无法确定主机"
                    )));
                }
            }
            Protocol::Tcp(p) => {
                port = Some(p);
                seen_tcp = true;
            }
            other => head = head.with(other),
        }
    }
    let Some(host) = host else {
        return Ok(vec![addr]);
    };
    let port = port
        .ok_or_else(|| P2pError::Relay(format!("relay 地址含域名但缺少 /tcp/<port>（{addr}）")))?;

    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| P2pError::Relay(format!("relay 域名解析失败（{host}:{port}）：{e}")))?;

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for sa in resolved {
        let mut ma = head.clone();
        match sa.ip() {
            std::net::IpAddr::V4(ip) => {
                ma = ma.with(Protocol::Ip4(ip)).with(Protocol::Tcp(port));
                if !v4.contains(&ma) {
                    v4.push(ma);
                }
            }
            std::net::IpAddr::V6(ip) => {
                ma = ma.with(Protocol::Ip6(ip)).with(Protocol::Tcp(port));
                if !v6.contains(&ma) {
                    v6.push(ma);
                }
            }
        }
    }
    v4.extend(v6);
    for ma in &mut v4 {
        *ma = ma.clone().with_p2p_tail(&tail);
    }
    if v4.is_empty() {
        return Err(P2pError::Relay(format!(
            "relay 域名无可用地址（{host}:{port}）"
        )));
    }
    Ok(v4)
}

/// 在 IP/TCP 地址后追加尾部组件（`/p2p/<relay>` 等）
trait WithP2pTail {
    fn with_p2p_tail(self, tail: &Multiaddr) -> Multiaddr;
}

impl WithP2pTail for Multiaddr {
    fn with_p2p_tail(self, tail: &Multiaddr) -> Multiaddr {
        let mut out = self;
        for p in tail.iter() {
            out = out.with(p);
        }
        out
    }
}

/// 预留请求的硬超时：超过即视为失败并进入退避（relay 不可达 / 拒绝都不该挂死）
pub const RESERVATION_TIMEOUT: Duration = Duration::from_secs(10);

/// 退避参数：1s 起，逐次翻倍，封顶 60s（沿用设计 §4.8「指数退避」）
pub const RETRY_BASE: Duration = Duration::from_secs(1);
/// 退避封顶
pub const RETRY_MAX: Duration = Duration::from_secs(60);

/// 第 `attempt` 次失败后的等待时长（attempt 从 0 起）
pub fn retry_delay(attempt: u32) -> Duration {
    let factor = 1u64.checked_shl(attempt.min(16)).unwrap_or(u64::MAX);
    RETRY_BASE.saturating_mul(factor as u32).min(RETRY_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_addr() -> Multiaddr {
        "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"
            .parse()
            .expect("测试用 relay 地址")
    }

    #[test]
    fn 端点解析_预留与拨号地址拼装() {
        let ep = RelayEndpoint::parse(&relay_addr(), None).expect("合法端点");
        assert_eq!(
            ep.reservation_addr().to_string(),
            format!("{}/p2p-circuit", relay_addr())
        );
        let target = PeerId::random();
        assert!(ep
            .dial_addr(target)
            .to_string()
            .ends_with(&format!("/p2p-circuit/p2p/{target}")));
    }

    #[test]
    fn 端点解析_拒绝_circuit_与域名_与缺_peer() {
        let with_circuit: Multiaddr = "/ip4/203.0.113.10/tcp/4001/p2p-circuit".parse().unwrap();
        assert!(
            RelayEndpoint::parse(&with_circuit, None).is_err(),
            "含 /p2p-circuit 应拒绝"
        );

        let dns: Multiaddr = "/dns4/relay.example.com/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"
            .parse()
            .unwrap();
        assert!(
            RelayEndpoint::parse(&dns, None).is_err(),
            "域名端点应要求先解析"
        );

        let no_peer: Multiaddr = "/ip4/203.0.113.10/tcp/4001".parse().unwrap();
        assert!(
            RelayEndpoint::parse(&no_peer, None).is_err(),
            "缺 /p2p 应拒绝"
        );
    }

    #[test]
    fn 端点解析_钉住_peer_id_不一致即拒绝() {
        let ep = RelayEndpoint::parse(&relay_addr(), None).expect("合法端点");
        let other = PeerId::random();
        assert!(matches!(
            RelayEndpoint::parse(&relay_addr(), Some(other)),
            Err(P2pError::RelayPeerMismatch { .. })
        ));
        assert!(RelayEndpoint::parse(&relay_addr(), Some(ep.peer_id())).is_ok());
    }

    #[test]
    fn 拨号地址形状_经_relay_必须有目标_peer() {
        let base = format!("{}/p2p-circuit", relay_addr());
        let missing: Multiaddr = base.parse().unwrap();
        assert!(relayed_dial_target(&missing).is_err(), "缺目标 /p2p 应拒绝");

        let target = PeerId::random();
        let ok: Multiaddr = format!("{base}/p2p/{target}").parse().unwrap();
        assert_eq!(relayed_dial_target(&ok).unwrap(), Some(target));

        let direct: Multiaddr = "/ip4/192.168.1.5/tcp/47613".parse().unwrap();
        assert_eq!(relayed_dial_target(&direct).unwrap(), None);
    }

    #[test]
    fn 传输形态_与_退避梯度() {
        assert_eq!(
            Transport::from_multiaddr(&relay_addr()),
            Transport::LanDirect
        );
        let relayed: Multiaddr = format!("{}/p2p-circuit", relay_addr()).parse().unwrap();
        assert_eq!(Transport::from_multiaddr(&relayed), Transport::WanRelay);
        assert_eq!(Transport::WanRelay.as_str(), "wan-relay");

        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(2), Duration::from_secs(4));
        assert_eq!(retry_delay(30), RETRY_MAX);
    }

    #[tokio::test]
    async fn 域名解析_保留_p2p_尾部且_ipv4_在前() {
        let out = resolve_relay_addr(
            "/dns4/localhost/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA",
        )
        .await
        .expect("localhost 应可解析");
        assert!(!out.is_empty());
        assert!(out
            .iter()
            .all(|ma| ma.iter().any(|p| matches!(p, Protocol::P2p(_)))));
        assert!(out
            .iter()
            .all(|ma| ma.iter().any(|p| matches!(p, Protocol::Tcp(4001)))));
        assert!(matches!(
            out.first().map(|ma| ma.iter().next()),
            Some(Some(Protocol::Ip4(_)))
        ));
    }
}
