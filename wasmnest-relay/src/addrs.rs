//! `print-addrs` 导入载荷：应用侧「导入 relay 地址」的产出方契约。
//!
//! 桌面端的「中转服务器」卡片只认这一份 JSON（`print-addrs --json`）与 multiaddr
//! 纯文本两种形态。因此这里的字段一旦发布就是**跨端契约**：新增字段向后兼容，
//! 改名/删除等于让旧客户端解析失败，必须升 [`IMPORT_PAYLOAD_VERSION`] 并同步消费方。
//!
//! 载荷里**没有**任何凭据：enrollment token 属于一次性凭据，只经带外渠道发给设备，
//! 不进 JSON、不进日志、不进二维码以外的任何持久化面。

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use libp2p::{
    multiaddr::{Multiaddr, Protocol},
    PeerId,
};
use serde::Serialize;

use crate::{
    access::AccessMode,
    config::{self, RelayConfig},
    error::{RelayError, Result},
    identity::RelayIdentity,
    wire::CONTROL_PROTOCOL,
    RELAY_VERSION,
};

/// 导入载荷版本（应用侧据此拒绝不认识的未来版本）
pub const IMPORT_PAYLOAD_VERSION: u32 = 1;
/// 载荷类型标识（与应用内其它导入面区分）
pub const IMPORT_PAYLOAD_KIND: &str = "wasmnest-relay";

/// 应用导入的中继描述
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportPayload {
    /// 载荷版本
    pub v: u32,
    /// 载荷类型（固定 [`IMPORT_PAYLOAD_KIND`]）
    pub kind: String,
    /// 中继版本（应用据此提示升级）
    pub relay_version: String,
    /// 中继 PeerId（base58）
    pub peer_id: String,
    /// PeerId 指纹：`sha256(ed25519 公钥)` 十六进制，客户端可独立复算
    pub peer_id_sha256: String,
    /// 控制协议名（客户端据此判断能否查询/兑换）
    pub control_protocol: String,
    /// 可拨地址（已含 `/p2p/<peerId>`）
    pub addrs: Vec<String>,
    /// 准入模式（只读提示：客户端据此决定是否提示输入 token）
    pub access: AccessSummary,
    /// 配额摘要（客户端可据此提示「单次传输上限」）
    pub quota: QuotaSummary,
}

/// 准入摘要
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessSummary {
    /// `open` / `allowlist`
    pub mode: String,
}

/// 配额摘要（只放客户端需要知道的字段）
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuotaSummary {
    /// 单 circuit 字节上限（0 = 不限）
    pub max_circuit_bytes: u64,
    /// 单 circuit 最长存活时间（秒）
    pub max_circuit_duration_secs: u64,
}

/// 构建导入载荷
pub fn build(config: &RelayConfig, identity: &RelayIdentity) -> Result<ImportPayload> {
    let peer = identity.peer_id();
    let addrs = config
        .advertise_addrs()?
        .iter()
        .map(|addr| with_peer_id(addr, &peer).to_string())
        .collect();
    Ok(ImportPayload {
        v: IMPORT_PAYLOAD_VERSION,
        kind: IMPORT_PAYLOAD_KIND.to_string(),
        relay_version: RELAY_VERSION.to_string(),
        peer_id: peer.to_base58(),
        peer_id_sha256: identity.fingerprint(),
        control_protocol: CONTROL_PROTOCOL.to_string(),
        addrs,
        access: AccessSummary {
            mode: config.access.mode.as_str().to_string(),
        },
        quota: QuotaSummary {
            max_circuit_bytes: config.quota.max_circuit_bytes,
            max_circuit_duration_secs: config.quota.max_circuit_duration_secs,
        },
    })
}

/// 给地址追加 `/p2p/<peerId>`（已有则跳过，避免重复段）
pub fn with_peer_id(addr: &Multiaddr, peer: &PeerId) -> Multiaddr {
    let already: Vec<PeerId> = addr
        .iter()
        .filter_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .collect();
    if already.contains(peer) {
        return addr.clone();
    }
    let mut out = addr.clone();
    out.push(Protocol::P2p(*peer));
    out
}

/// 文本形态：每行一个可拨地址 + 指纹（可直接粘贴给应用）
pub fn render_text(payload: &ImportPayload) -> String {
    let mut out = String::new();
    for addr in &payload.addrs {
        out.push_str(addr);
        out.push('\n');
    }
    out.push_str(&format!("peerId: {}\n", payload.peer_id));
    out.push_str(&format!("peerIdSha256: {}\n", payload.peer_id_sha256));
    out.push_str(&format!("access: {}\n", payload.access.mode));
    out.push_str(&format!("controlProtocol: {}\n", payload.control_protocol));
    out
}

/// 把 `--advertise` 的「主机 + 端口」变成通告 multiaddr
///
/// IP 字面量走 `/ip4|ip6`，其余按域名走 `/dns4`（v1 不做 `/dns6`：IPv6 字面量已由
/// 前一条覆盖，纯 IPv6 域名解析属于客户端侧的事）。
pub fn describe_host(host: &str, port: u16) -> Result<Multiaddr> {
    let host = host.trim();
    if host.is_empty() {
        return Err(RelayError::args("--advertise 的主机名不能为空"));
    }
    if port == 0 {
        return Err(RelayError::args(
            "--port 不能为 0（客户端需要一个确定可拨的端口）",
        ));
    }
    if let Ok(ip) = IpAddr::from_str(host) {
        let base = match ip {
            IpAddr::V4(v4) => Multiaddr::empty().with(Protocol::Ip4(v4)),
            IpAddr::V6(v6) => Multiaddr::empty().with(Protocol::Ip6(v6)),
        };
        return Ok(base.with(Protocol::Tcp(port)));
    }
    if host.contains('/') || host.contains(char::is_whitespace) {
        return Err(RelayError::args(format!(
            "--advertise 主机名非法（{host}）：只接受域名或 IP 字面量，不含路径与空格"
        )));
    }
    Ok(Multiaddr::empty()
        .with(Protocol::Dns4(host.to_string().into()))
        .with(Protocol::Tcp(port)))
}

/// 从 multiaddr 取 IP（每 IP 配额统计用）
pub fn addr_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(Ipv4Addr::from(ip.octets()))),
        Protocol::Ip6(ip) => Some(IpAddr::V6(Ipv6Addr::from(ip.octets()))),
        _ => None,
    })
}

/// 默认端口（配置默认值）
pub fn default_port() -> u16 {
    config::DEFAULT_RELAY_PORT
}

/// 应用侧导入时的模式词表（供测试断言）
pub fn access_mode_word(mode: AccessMode) -> &'static str {
    mode.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RelayIdentity {
        RelayIdentity::generate()
    }

    fn config_with_advertise(addr: &str) -> RelayConfig {
        let mut config = RelayConfig::default();
        config.advertise.addrs = vec![addr.to_string()];
        config
    }

    #[test]
    fn 载荷字段稳定且地址带_peer_id() {
        let identity = identity();
        let config = config_with_advertise("/dns4/relay.example.com/tcp/4001");
        let payload = build(&config, &identity).expect("构建");

        assert_eq!(payload.v, IMPORT_PAYLOAD_VERSION);
        assert_eq!(payload.kind, "wasmnest-relay");
        assert_eq!(payload.relay_version, RELAY_VERSION);
        assert_eq!(payload.peer_id, identity.peer_id().to_base58());
        assert_eq!(payload.peer_id_sha256, identity.fingerprint());
        assert_eq!(payload.control_protocol, CONTROL_PROTOCOL);
        assert_eq!(
            payload.addrs,
            vec![format!(
                "/dns4/relay.example.com/tcp/4001/p2p/{}",
                identity.peer_id()
            )]
        );
        assert_eq!(payload.access.mode, "open");
        assert_eq!(
            payload.quota.max_circuit_bytes,
            config::DEFAULT_MAX_CIRCUIT_BYTES
        );
    }

    #[test]
    fn 载荷不含任何凭据字段() {
        let identity = identity();
        let payload = build(
            &config_with_advertise("/dns4/relay.example.com/tcp/4001"),
            &identity,
        )
        .expect("构建");
        let json = serde_json::to_string(&payload).expect("序列化");
        for forbidden in ["token", "secret", "password", "key"] {
            assert!(
                !json.to_lowercase().contains(forbidden),
                "导入载荷不应包含 {forbidden}：{json}"
            );
        }
    }

    #[test]
    fn 重复调用不重复追加_peer_id() {
        let identity = identity();
        let peer = identity.peer_id();
        let addr: Multiaddr = "/ip4/203.0.113.10/tcp/4001".parse().expect("地址");
        let once = with_peer_id(&addr, &peer);
        let twice = with_peer_id(&once, &peer);
        assert_eq!(once, twice);
        assert_eq!(
            once.to_string().matches("/p2p/").count(),
            1,
            "只应有一个 /p2p 段：{once}"
        );
    }

    #[test]
    fn 文本形态每行一个地址() {
        let identity = identity();
        let mut config = RelayConfig::default();
        config.advertise.addrs = vec![
            "/dns4/relay.example.com/tcp/4001".to_string(),
            "/ip4/203.0.113.10/tcp/4001".to_string(),
        ];
        let payload = build(&config, &identity).expect("构建");
        let text = render_text(&payload);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], payload.addrs[0]);
        assert_eq!(lines[1], payload.addrs[1]);
        assert!(text.contains("peerId: "));
        assert!(text.contains("peerIdSha256: "));
    }

    #[test]
    fn 主机描述支持_ipv4_ipv6_域名() {
        assert_eq!(
            describe_host("203.0.113.10", 4001)
                .expect("ipv4")
                .to_string(),
            "/ip4/203.0.113.10/tcp/4001"
        );
        assert_eq!(
            describe_host("2001:db8::1", 4001)
                .expect("ipv6")
                .to_string(),
            "/ip6/2001:db8::1/tcp/4001"
        );
        assert_eq!(
            describe_host("relay.example.com", 4001)
                .expect("域名")
                .to_string(),
            "/dns4/relay.example.com/tcp/4001"
        );
    }

    #[test]
    fn 非法主机与零端口报参数错误() {
        assert!(describe_host("", 4001).is_err());
        assert!(describe_host("relay.example.com", 0).is_err());
        assert!(describe_host("has space", 4001).is_err());
        assert!(describe_host("relay/example", 4001).is_err());
        assert!(describe_host("relay.example.com", 4001)
            .expect("合法")
            .to_string()
            .contains("/tcp/4001"));
    }

    #[test]
    fn 缓存端口为默认_4001() {
        assert_eq!(default_port(), 4001);
        assert_eq!(access_mode_word(AccessMode::Allowlist), "allowlist");
    }

    #[test]
    fn 地址解析出_ip() {
        let addr: Multiaddr = "/ip4/198.51.100.7/tcp/4001".parse().expect("地址");
        assert_eq!(
            addr_ip(&addr),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
        let addr: Multiaddr = "/dns4/relay.example.com/tcp/4001".parse().expect("地址");
        assert_eq!(addr_ip(&addr), None, "域名地址不含 IP");
    }
}
