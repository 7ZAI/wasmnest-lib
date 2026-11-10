//! relay 连通性探测（T19）：一次性临时 swarm 拨号 + 握手身份校验 + ping 往返。
//!
//! ## 为什么不用主 swarm
//!
//! 主引擎的连接会进链路表、跑准入闸门、发 `peer-connected`。探测连接一旦走那条路，
//! 会污染信任状态机，还要处理「探测连接与已有 relay 预留连接」的拆除竞态（拆错就断
//! 掉真实预留）。本模块因此**每次探测新建一个最小 swarm**：`tcp + noise + yamux + ping`，
//! 无 listener、无业务协议、无 relay 客户端行为，用一次性随机 ed25519 身份，结束即 drop。
//!
//! 随机身份的理由：不触达宿主私钥；`allowlist` 模式下探测仍能完成 TCP / Noise / 控制面
//! （v1 不报告准入结果），`open` 模式下无任何影响。
//!
//! ## 零持久副作用（不变量 P1 / P2）
//!
//! 本函数不建立 reservation、不登记 expose 规则、不写信任、不发任何 `peer:*` 事件
//! （没有 `P2pPorts` 可发）；返回后 swarm 被 drop，TCP 连接随之关闭。
//!
//! ## 身份校验（不变量 P3）
//!
//! 拨号时**剥掉地址尾部的 `/p2p/<relay>`**，只用传输地址拨——这样握手得到的 PeerId
//! 由 Noise 从对端公钥实测得出，再与地址里钉住的值比对。若带着 `/p2p/` 拨号，
//! libp2p 自身会拒绝身份不符的连接，错误退化成笼统的「拨号失败」，无法区分
//! 「端口不通」与「同 IP 换了身份」——那正是要显性报告的安全事件。
//!
//! ## 时间预算
//!
//! `timeout` 是**整次探测的总预算**（多地址按入参顺序逐个尝试，首个成功即返回）；
//! 超时后不再开始新候选，全失败时逐条汇总 `addr → 原因`，不截断到只剩最后一条。

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use libp2p::identity::PublicKey;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{noise, ping, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
use sha2::{Digest, Sha256};

use crate::relay::RelayEndpoint;

/// ping 间隔：连接建立后 handler 会立即发首包，此值只影响后续保活节奏
pub const PROBE_PING_INTERVAL: Duration = Duration::from_secs(1);
/// 单次 ping 往返的等待上限（超过即判 `rttMs = null`，可达性仍成立）
pub const PROBE_PING_TIMEOUT: Duration = Duration::from_secs(5);
/// 探测连接的空闲超时（探测是短命连接，远小于主引擎的一天）
const PROBE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 探测失败（逐类点名成因；域层按变体映射 `code: detail`）
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// 地址形状非法（空 / 非法 multiaddr / 含 `/p2p-circuit` / 残留域名 / 跨 PeerId）
    #[error("relay 地址非法：{0}")]
    AddressInvalid(String),
    /// 握手实测身份与地址钉住的身份不符（安全事件：不再尝试其它候选）
    #[error("relay 身份不符：{0}")]
    IdentityMismatch(String),
    /// 全部候选不可达（`addr → 原因`，分号分隔；含超时）
    #[error("relay 不可达：{0}")]
    Unreachable(String),
    /// 本机无法装配探测 swarm（传输栈 / 运行时不可用）
    #[error("本机对等网络无法启动：{0}")]
    NodeUnavailable(String),
}

/// 一次成功探测的结果（域层负责序列化成 WIT 报告的 JSON 形状）
#[derive(Debug, Clone)]
pub struct ProbeReport {
    /// 实际探测成功的地址（多地址时是首个成功项，含 `/p2p/<relay>`）
    pub addr: Multiaddr,
    /// 地址里钉住的 relay PeerId（握手已校验）
    pub peer_id: PeerId,
    /// `sha256(ed25519 原始公钥)` 十六进制——与 `wasmnest-relay` 的
    /// `peer_id_sha256` 同一派生口径，客户端可独立复算
    pub peer_id_sha256: String,
    /// dial → `ConnectionEstablished` 耗时
    pub handshake: Duration,
    /// 首次 ping 往返；ping 超时 / 对端不支持 ping 时为 `None`（可达性仍成立）
    pub rtt: Option<Duration>,
}

/// 探测的最小行为面：只有 ping（无 relay 客户端、无业务流协议）
#[derive(NetworkBehaviour)]
struct ProbeBehaviour {
    ping: ping::Behaviour,
}

/// 对一组 relay 端点做一次只读探测
///
/// - `addrs` 必须全部是同一 relay 的端点形状（`.../tcp/<port>/p2p/<relay>`），
///   不含 `/p2p-circuit`、不含域名（宿主先解析）；
/// - 按顺序逐个拨号，首个成功即返回；身份不符立即终止（不再尝试其它候选）；
/// - 调用返回后连接与 swarm 均已销毁，无任何持久资源。
pub async fn probe_relay(
    addrs: &[Multiaddr],
    timeout: Duration,
) -> Result<ProbeReport, ProbeError> {
    if addrs.is_empty() {
        return Err(ProbeError::AddressInvalid("relay 地址列表为空".to_string()));
    }

    // 纯校验（不触网）：端点形状 + 全候选同一 PeerId
    let mut expected: Option<PeerId> = None;
    for addr in addrs {
        let endpoint = RelayEndpoint::parse(addr, expected)
            .map_err(|e| ProbeError::AddressInvalid(format!("{addr}：{e}")))?;
        expected = Some(endpoint.peer_id());
    }
    let expected = expected.expect("非空地址列表必有首项");

    let deadline = tokio::time::Instant::now() + timeout.max(Duration::from_millis(1));
    let mut swarm = build_probe_swarm()?;
    let mut failures: Vec<String> = Vec::new();

    for addr in addrs {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            failures.push(format!("{addr} → timeout（总预算已耗尽）"));
            break;
        }
        if let Err(e) = swarm.dial(transport_addr(addr)) {
            failures.push(format!("{addr} → 拨号被拒绝：{e}"));
            continue;
        }
        match await_handshake_and_ping(&mut swarm, addr, &expected, deadline).await {
            Ok(report) => {
                let _ = swarm.disconnect_peer_id(report.peer_id);
                return Ok(report);
            }
            Err(ProbeError::IdentityMismatch(detail)) => {
                return Err(ProbeError::IdentityMismatch(format!("{addr}：{detail}")));
            }
            Err(ProbeError::Unreachable(detail)) => failures.push(format!("{addr} → {detail}")),
            Err(e) => return Err(e),
        }
    }

    Err(ProbeError::Unreachable(failures.join("；")))
}

/// 装配一次性探测 swarm：随机身份、无 listener、只挂 ping
fn build_probe_swarm() -> Result<Swarm<ProbeBehaviour>, ProbeError> {
    let builder = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| ProbeError::NodeUnavailable(format!("TCP/noise/yamux 传输栈装配失败：{e}")))?;
    Ok(builder
        .with_behaviour(|_key| ProbeBehaviour {
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(PROBE_PING_INTERVAL)
                    .with_timeout(PROBE_PING_TIMEOUT),
            ),
        })
        .map_err(|e| ProbeError::NodeUnavailable(format!("ping 行为面装配失败：{e}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(PROBE_IDLE_TIMEOUT))
        .build())
}

/// 剥掉端点地址尾部的 `/p2p/<relay>`：只用传输地址拨号，让 Noise 实测对端身份
fn transport_addr(addr: &Multiaddr) -> Multiaddr {
    let mut out = addr.clone();
    if matches!(out.iter().last(), Some(Protocol::P2p(_))) {
        out.pop();
    }
    out
}

/// 等握手 → 校验身份 → 等首个 ping
///
/// - 握手前超时 / 拨号错误 → `Unreachable`（交给下一个候选）
/// - 握手身份不符 → `IdentityMismatch`（安全事件，调用方立即终止）
/// - 握手成功但 ping 未在预算内回来 → `rtt = None`（可达性已成立）
async fn await_handshake_and_ping(
    swarm: &mut Swarm<ProbeBehaviour>,
    addr: &Multiaddr,
    expected: &PeerId,
    deadline: tokio::time::Instant,
) -> Result<ProbeReport, ProbeError> {
    let started = Instant::now();
    let mut handshake: Option<(PeerId, Duration)> = None;

    loop {
        let event = match tokio::time::timeout_at(deadline, swarm.select_next_some()).await {
            Ok(event) => event,
            Err(_) => {
                return match handshake {
                    Some((peer_id, handshake)) => report(addr, peer_id, handshake, None),
                    None => Err(ProbeError::Unreachable("握手超时".to_string())),
                };
            }
        };

        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if handshake.is_none() {
                    if peer_id != *expected {
                        return Err(ProbeError::IdentityMismatch(format!(
                            "地址钉住 {expected}，握手实测 {peer_id}"
                        )));
                    }
                    handshake = Some((peer_id, started.elapsed()));
                }
            }
            SwarmEvent::OutgoingConnectionError { error, .. } if handshake.is_none() => {
                return Err(ProbeError::Unreachable(format!("拨号失败：{error}")));
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                if let Some((established, handshake)) = handshake {
                    if established == peer_id {
                        return report(addr, established, handshake, None);
                    }
                }
            }
            SwarmEvent::Behaviour(ProbeBehaviourEvent::Ping(event)) => {
                if let Some((peer_id, handshake)) = handshake {
                    if event.peer != peer_id {
                        continue;
                    }
                    match event.result {
                        Ok(rtt) => return report(addr, peer_id, handshake, Some(rtt)),
                        // 对端不支持 ping / 单次超时：可达性与身份已成立，RTT 留空
                        Err(_) => return report(addr, peer_id, handshake, None),
                    }
                }
            }
            _ => {}
        }
    }
}

/// 组装报告（指纹派生失败 = 对端不是 ed25519，按身份问题显性拒绝）
fn report(
    addr: &Multiaddr,
    peer_id: PeerId,
    handshake: Duration,
    rtt: Option<Duration>,
) -> Result<ProbeReport, ProbeError> {
    let peer_id_sha256 = fingerprint(&peer_id).ok_or_else(|| {
        ProbeError::IdentityMismatch(format!(
            "对端 {peer_id} 不是 ed25519 身份密钥，无法计算 PeerId 指纹"
        ))
    })?;
    Ok(ProbeReport {
        addr: addr.clone(),
        peer_id,
        peer_id_sha256,
        handshake,
        rtt,
    })
}

/// `sha256(ed25519 原始公钥)` 十六进制（与 `wasmnest-relay::identity::fingerprint` 同口径）
fn fingerprint(peer_id: &PeerId) -> Option<String> {
    // ed25519 的 PeerId 是 identity multihash，digest 即 protobuf 编码的公钥
    let public = PublicKey::try_decode_protobuf(peer_id.as_ref().digest()).ok()?;
    let ed25519 = public.try_into_ed25519().ok()?;
    Some(hex::encode(Sha256::digest(ed25519.to_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn relay_addr(peer: PeerId, port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
            .parse()
            .expect("测试用 relay 地址")
    }

    #[test]
    fn 指纹_与_ed25519_公钥派生一致() {
        let key = Keypair::generate_ed25519();
        let peer = key.public().to_peer_id();
        let raw = key
            .public()
            .try_into_ed25519()
            .expect("ed25519 公钥")
            .to_bytes();
        assert_eq!(
            fingerprint(&peer).expect("ed25519 必有指纹"),
            hex::encode(Sha256::digest(raw))
        );
    }

    #[test]
    fn 拨号地址剥掉_p2p_尾部() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let addr = relay_addr(peer, 4001);
        assert_eq!(transport_addr(&addr).to_string(), "/ip4/127.0.0.1/tcp/4001");
        let bare: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert_eq!(transport_addr(&bare), bare, "无 /p2p 尾部时原样返回");
    }

    #[tokio::test]
    async fn 空列表与非法地址在校验期拒绝() {
        assert!(matches!(
            probe_relay(&[], Duration::from_secs(1)).await,
            Err(ProbeError::AddressInvalid(_))
        ));

        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let with_circuit: Multiaddr = format!("{}/p2p-circuit", relay_addr(peer, 4001))
            .parse()
            .unwrap();
        assert!(matches!(
            probe_relay(&[with_circuit], Duration::from_secs(1)).await,
            Err(ProbeError::AddressInvalid(_))
        ));

        let other = Keypair::generate_ed25519().public().to_peer_id();
        assert!(
            matches!(
                probe_relay(
                    &[relay_addr(peer, 4001), relay_addr(other, 4001)],
                    Duration::from_secs(1)
                )
                .await,
                Err(ProbeError::AddressInvalid(_))
            ),
            "跨 PeerId 的多地址必须拒绝（否则报告指代不明）"
        );
    }

    #[tokio::test]
    async fn 关闭端口_返回不可达且受超时约束() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("取空闲端口");
            listener.local_addr().expect("读端口").port()
        };
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let started = Instant::now();
        let err = probe_relay(&[relay_addr(peer, port)], Duration::from_secs(3))
            .await
            .expect_err("没有 relay 监听时必须失败");
        assert!(
            matches!(err, ProbeError::Unreachable(_)),
            "关闭端口应归为不可达：{err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3) + Duration::from_secs(2),
            "总预算应约束探测耗时，实得 {:?}",
            started.elapsed()
        );
        assert!(
            err.to_string().contains(&port.to_string()),
            "失败明细应逐候选点名地址：{err}"
        );
    }
}
