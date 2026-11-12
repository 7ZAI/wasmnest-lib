//! 配置文件（TOML）与校验。
//!
//! 配置是**运维面契约**：手改是常态，因此两件事必须硬：未知字段直接报错（拼错的
//! 字段被静默忽略 = 运维以为改了配额其实没改），以及敏感默认值往「不暴露」方向
//! 收紧（指标端点默认只绑回环）。
//!
//! 数据目录约定：身份密钥、token 表、enrollment 白名单**都跟配置文件同目录**，
//! 于是 Docker 只需挂一个卷（`/data`）就能保证重启不换 PeerId。

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use libp2p::{
    multiaddr::{Multiaddr, Protocol},
    PeerId,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::AccessMode,
    error::{RelayError, Result},
    fsutil,
};

/// 配置格式版本（与 [`RelayConfig::config_version`] 比对；不匹配即拒載）
pub const CONFIG_VERSION: u32 = 1;
/// 配置文件名（数据目录内）
pub const CONFIG_FILE_NAME: &str = "config.toml";
/// 身份密钥默认文件名
pub const IDENTITY_FILE_NAME: &str = "identity.key";
/// enrollment token 表文件名
pub const TOKENS_FILE_NAME: &str = "tokens.json";
/// 已 enrollment 的 peer 白名单文件名
pub const PEERS_FILE_NAME: &str = "enrolled-peers.json";
/// 默认监听地址（对外 4001/tcp；v1 不启用 UDP）
pub const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/4001";
/// 默认中继端口
pub const DEFAULT_RELAY_PORT: u16 = 4001;
/// 默认指标/健康端点（只绑回环，不默认对公网暴露）
pub const DEFAULT_METRICS_LISTEN: &str = "127.0.0.1:9090";
/// 默认单 circuit 字节上限：1 GiB（对齐「跨 NAT 传 1GB」验收；太小会把大文件掐断）
pub const DEFAULT_MAX_CIRCUIT_BYTES: u64 = 1024 * 1024 * 1024;

/// 中继配置根
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// 配置格式版本（必须等于 [`CONFIG_VERSION`]）
    pub config_version: u32,
    /// 身份密钥位置
    #[serde(default)]
    pub identity: IdentityConfig,
    /// 监听地址（libp2p multiaddr 列表）
    #[serde(default)]
    pub listen: ListenConfig,
    /// 对外通告地址（客户端据此拼 `/p2p-circuit`；空 = 回退监听地址）
    #[serde(default)]
    pub advertise: AdvertiseConfig,
    /// 配额
    #[serde(default)]
    pub quota: QuotaConfig,
    /// 准入模式与静态白名单
    #[serde(default)]
    pub access: AccessConfig,
    /// 指标/健康端点
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// 身份密钥配置
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// ed25519 身份密钥路径（相对路径以配置文件所在目录为基准）
    pub key_file: PathBuf,
}

/// 监听地址配置
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// 监听 multiaddr 列表（不含 `/p2p`；libp2p 自行追加）
    pub addrs: Vec<String>,
}

/// 对外通告地址配置
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertiseConfig {
    /// 对外通告 multiaddr 列表（`/dns4/relay.example.com/tcp/4001` 或 IP 字面量）
    pub addrs: Vec<String>,
}

/// 配额配置
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    /// 同时存在的 reservation 上限
    pub max_reservations: usize,
    /// 单个 peer 的 reservation 上限
    pub max_reservations_per_peer: usize,
    /// reservation 有效期（秒）
    pub reservation_ttl_secs: u64,
    /// 同时存在的 circuit 上限
    pub max_circuits: usize,
    /// 单个 peer 的并发 circuit 上限
    pub max_circuits_per_peer: usize,
    /// 单条 circuit 最长存活时间（秒）
    pub max_circuit_duration_secs: u64,
    /// 单条 circuit 字节上限（0 = 不限；默认 1 GiB）
    pub max_circuit_bytes: u64,
    /// 单 IP 入站连接上限（超出即关闭新连接）
    pub max_connections_per_ip: usize,
}

/// 准入配置
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    /// `open`（默认：任何人可预留，靠配额防滥用）或 `allowlist`（只认白名单/已 enrollment 的 peer）
    pub mode: AccessMode,
    /// 静态白名单（allowlist 模式的初始集合；enrollment 会追加并持久化）
    pub allowlist: Vec<String>,
}

/// 指标端点配置
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// 监听地址（`GET /healthz`、`GET /metrics`）
    pub listen: String,
    /// 是否允许绑非回环地址（公网暴露必须显式开启，见部署文档的 token/反代要求）
    pub expose_public: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            config_version: CONFIG_VERSION,
            identity: IdentityConfig::default(),
            listen: ListenConfig::default(),
            advertise: AdvertiseConfig::default(),
            quota: QuotaConfig::default(),
            access: AccessConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            key_file: PathBuf::from(IDENTITY_FILE_NAME),
        }
    }
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            addrs: vec![DEFAULT_LISTEN_ADDR.to_string()],
        }
    }
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_reservations: 1024,
            max_reservations_per_peer: 4,
            reservation_ttl_secs: 3600,
            max_circuits: 512,
            max_circuits_per_peer: 64,
            max_circuit_duration_secs: 3600,
            max_circuit_bytes: DEFAULT_MAX_CIRCUIT_BYTES,
            // 一个 NAT 后的家庭网络可能有很多设备，32 足够；再高就成了单 IP DoS 面
            max_connections_per_ip: 32,
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_METRICS_LISTEN.to_string(),
            expose_public: false,
        }
    }
}

impl RelayConfig {
    /// 从 TOML 文件加载（解析失败点名路径）
    pub fn load(path: &Path) -> Result<Self> {
        let text = fsutil::read_to_string(path)?;
        let config: Self = toml::from_str(&text).map_err(|source| RelayError::TomlParse {
            path: path.display().to_string(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// 序列化为带说明头的 TOML（`init` 写盘用）
    pub fn to_toml(&self) -> Result<String> {
        let body = toml::to_string_pretty(self)?;
        Ok(format!(
            "{header}\n{body}",
            header = TOML_HEADER,
            body = body
        ))
    }

    /// 全量校验（配置非法一律拒載，不允许「跑起来再说」）
    pub fn validate(&self) -> Result<()> {
        if self.config_version != CONFIG_VERSION {
            return Err(RelayError::config(format!(
                "配置版本 {} 不受支持（本版本只认 {CONFIG_VERSION}）；请按 deploy/relay/config.example.toml 迁移",
                self.config_version
            )));
        }
        if self.identity.key_file.as_os_str().is_empty() {
            return Err(RelayError::config("identity.key_file 不能为空"));
        }

        let listen = self.listen_addrs()?;
        if listen.is_empty() {
            return Err(RelayError::config(
                "listen.addrs 不能为空（至少要有一个 TCP 监听地址）",
            ));
        }
        // 配好的通告地址必须能被解析（但回退结果不参与「是否缺通告」判定）
        let _advertise = self.advertise_addrs()?;
        let all_unspecified = listen.iter().all(addr_is_unspecified);
        // 注意：判断依据是**配置里有没有写** advertise，而不是回退结果——回退永远
        // 能给出一份地址（监听的 0.0.0.0），但那个地址客户端拨不动
        if all_unspecified && self.advertise.addrs.is_empty() {
            return Err(RelayError::config(
                "对外通告地址缺失：监听在 0.0.0.0/:: 时必须配置 advertise.addrs（公网域名或 IP），\
                 否则客户端拿到的是不可拨地址。用 `init --advertise <域名|IP>` 或手改配置。",
            ));
        }

        self.quota.validate()?;
        self.access.validate()?;
        self.metrics.validate()?;
        Ok(())
    }

    /// 解析监听地址列表
    pub fn listen_addrs(&self) -> Result<Vec<Multiaddr>> {
        self.listen
            .addrs
            .iter()
            .map(|text| {
                let addr = parse_multiaddr(text)?;
                validate_listen_addr(&addr)?;
                Ok(addr)
            })
            .collect()
    }

    /// 解析对外通告地址列表（空 = 回退监听地址）
    pub fn advertise_addrs(&self) -> Result<Vec<Multiaddr>> {
        let mut addrs = Vec::new();
        for text in &self.advertise.addrs {
            let addr = parse_multiaddr(text)?;
            validate_advertise_addr(&addr)?;
            addrs.push(addr);
        }
        if addrs.is_empty() {
            return self.listen_addrs();
        }
        Ok(addrs)
    }

    /// 解析静态白名单
    pub fn allowlist_peers(&self) -> Result<Vec<PeerId>> {
        self.access
            .allowlist
            .iter()
            .map(|text| {
                PeerId::from_str(text.trim()).map_err(|e| {
                    RelayError::config(format!("access.allowlist 中的 PeerId 非法（{text}）：{e}"))
                })
            })
            .collect()
    }

    /// 指标端点地址
    pub fn metrics_socket_addr(&self) -> Result<SocketAddr> {
        self.metrics.validate()?;
        self.metrics.listen.parse::<SocketAddr>().map_err(|e| {
            RelayError::config(format!(
                "metrics.listen 非法（{}）：{e}",
                self.metrics.listen
            ))
        })
    }

    /// 身份密钥的绝对路径（相对路径以配置文件所在目录为基准）
    pub fn identity_path(&self, config_path: &Path) -> PathBuf {
        resolve_against(config_path, &self.identity.key_file)
    }

    /// token 表路径（配置文件同目录）
    pub fn tokens_path(config_path: &Path) -> PathBuf {
        sibling(config_path, TOKENS_FILE_NAME)
    }

    /// enrollment 白名单路径（配置文件同目录）
    pub fn peers_path(config_path: &Path) -> PathBuf {
        sibling(config_path, PEERS_FILE_NAME)
    }

    /// `init` 生成配置：给定对外通告地址与端口
    pub fn for_init(advertise: Vec<String>, mode: AccessMode, allowlist: Vec<String>) -> Self {
        let mut config = Self::default();
        config.advertise.addrs = advertise;
        config.access.mode = mode;
        config.access.allowlist = allowlist;
        config
    }
}

impl QuotaConfig {
    fn validate(&self) -> Result<()> {
        let positive = [
            ("max_reservations", self.max_reservations as u64),
            (
                "max_reservations_per_peer",
                self.max_reservations_per_peer as u64,
            ),
            ("reservation_ttl_secs", self.reservation_ttl_secs),
            ("max_circuits", self.max_circuits as u64),
            ("max_circuits_per_peer", self.max_circuits_per_peer as u64),
            ("max_circuit_duration_secs", self.max_circuit_duration_secs),
            ("max_connections_per_ip", self.max_connections_per_ip as u64),
        ];
        for (name, value) in positive {
            if value == 0 {
                return Err(RelayError::config(format!("quota.{name} 必须 > 0")));
            }
        }
        if self.max_reservations_per_peer > self.max_reservations {
            return Err(RelayError::config(
                "quota.max_reservations_per_peer 不能大于 quota.max_reservations",
            ));
        }
        if self.max_circuits_per_peer > self.max_circuits {
            return Err(RelayError::config(
                "quota.max_circuits_per_peer 不能大于 quota.max_circuits",
            ));
        }
        // 单 circuit 至少要能跑一次真实文件块；上限过小会让所有传输立刻断
        if self.max_circuit_bytes != 0 && self.max_circuit_bytes < 1024 * 1024 {
            return Err(RelayError::config(
                "quota.max_circuit_bytes 过小（< 1 MiB 会让传输立刻被掐断）；0 表示不限",
            ));
        }
        Ok(())
    }
}

impl AccessConfig {
    fn validate(&self) -> Result<()> {
        // 白名单条目的 PeerId 形状必须当场校验，不能等到运行时「悄悄不匹配」
        let _ = RelayConfig {
            config_version: CONFIG_VERSION,
            identity: IdentityConfig::default(),
            listen: ListenConfig::default(),
            advertise: AdvertiseConfig::default(),
            quota: QuotaConfig::default(),
            access: self.clone(),
            metrics: MetricsConfig::default(),
        }
        .allowlist_peers()?;
        Ok(())
    }
}

impl MetricsConfig {
    fn validate(&self) -> Result<()> {
        let addr: SocketAddr = self.listen.parse().map_err(|e| {
            RelayError::config(format!("metrics.listen 非法（{}）：{e}", self.listen))
        })?;
        if !addr.ip().is_loopback() && !self.expose_public {
            return Err(RelayError::config(format!(
                "metrics.listen={} 不是回环地址；公网暴露健康/指标端点需要显式 \
                 `expose_public = true`，并自行加反代 TLS 或 token",
                self.listen
            )));
        }
        Ok(())
    }
}

/// `init` 写盘的配置说明头
const TOML_HEADER: &str = "\
# ==================== wasmnest-relay 配置（v1） ====================
# 数据目录内的所有文件都属于同一身份：identity.key（身份）/ tokens.json（enrollment）
# / enrolled-peers.json（已兑换 token 的 peer 白名单）。
#
# 重要：identity.key 丢失 = PeerId 变化 = 所有客户端必须重新导入 relay 地址。
# 修改配额后 `wasmnest-relay run` 重启即生效；改监听端口需同步客户端导入的地址。
#
# 字段说明见 deploy/relay/README.md 与 deploy/relay/config.example.toml。";

/// 解析 multiaddr（带可读错误）
pub fn parse_multiaddr(text: &str) -> Result<Multiaddr> {
    Multiaddr::from_str(text.trim())
        .map_err(|e| RelayError::config(format!("multiaddr 非法（{text}）：{e}")))
}

fn validate_listen_addr(addr: &Multiaddr) -> Result<()> {
    if has_protocol(addr, |p| matches!(p, Protocol::P2p(_))) {
        return Err(RelayError::config(format!(
            "监听地址不能包含 /p2p（libp2p 会自行追加本地 PeerId）：{addr}"
        )));
    }
    if has_protocol(addr, |p| matches!(p, Protocol::P2pCircuit)) {
        return Err(RelayError::config(format!(
            "中继节点不能监听在 /p2p-circuit 上：{addr}"
        )));
    }
    if tcp_port(addr).is_none() {
        return Err(RelayError::config(format!(
            "监听地址缺少 TCP 端口（v1 只启 TCP + Noise + Yamux，不启 UDP/QUIC）：{addr}"
        )));
    }
    Ok(())
}

fn validate_advertise_addr(addr: &Multiaddr) -> Result<()> {
    if has_protocol(addr, |p| matches!(p, Protocol::P2p(_))) {
        return Err(RelayError::config(format!(
            "通告地址不要手写 /p2p（`print-addrs` 会按本地 PeerId 追加，手写会导致重复）：{addr}"
        )));
    }
    if has_protocol(addr, |p| matches!(p, Protocol::P2pCircuit)) {
        return Err(RelayError::config(format!(
            "通告地址不能包含 /p2p-circuit：{addr}"
        )));
    }
    if tcp_port(addr).is_none() {
        return Err(RelayError::config(format!("通告地址缺少 TCP 端口：{addr}")));
    }
    Ok(())
}

/// 地址是否为「未指定」（0.0.0.0 / ::），这种地址不能直接给客户端拨
pub fn addr_is_unspecified(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}

/// 取出地址里的 TCP 端口
pub fn tcp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

fn has_protocol(addr: &Multiaddr, predicate: impl Fn(&Protocol<'_>) -> bool) -> bool {
    addr.iter().any(|p| predicate(&p))
}

fn sibling(config_path: &Path, name: &str) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

fn resolve_against(config_path: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        sibling(config_path, &candidate.to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_config() -> RelayConfig {
        let mut config = RelayConfig::default();
        config.listen.addrs = vec!["/ip4/127.0.0.1/tcp/0".to_string()];
        config.metrics.listen = "127.0.0.1:0".to_string();
        config
    }

    #[test]
    fn 默认配置合法且能_toml_往返() {
        let mut config = RelayConfig::default();
        // 默认监听 0.0.0.0，必须补通告地址才合法
        config.advertise.addrs = vec!["/dns4/relay.example.com/tcp/4001".to_string()];
        config.validate().expect("默认配置应合法");

        let text = config.to_toml().expect("序列化");
        assert!(text.contains("config_version = 1"), "{text}");
        let parsed: RelayConfig = toml::from_str(&text).expect("反序列化");
        assert_eq!(parsed, config);
    }

    #[test]
    fn 未知字段直接报错而不是静默忽略() {
        let text = r#"
config_version = 1
[listen]
addrs = ["/ip4/127.0.0.1/tcp/4001"]
[quota]
max_reservation = 10
"#;
        let err = toml::from_str::<RelayConfig>(text).expect_err("拼错字段必须报错");
        assert!(
            err.to_string().contains("max_reservation"),
            "错误应点名未知字段：{err}"
        );
    }

    #[test]
    fn 缺版本字段拒載() {
        let err = toml::from_str::<RelayConfig>("[listen]\naddrs = []\n")
            .expect_err("缺 config_version 必须报错");
        assert!(err.to_string().contains("config_version"), "{err}");
    }

    #[test]
    fn 版本不匹配拒載并给出迁移出路() {
        let mut config = loopback_config();
        config.config_version = 2;
        let err = config.validate().expect_err("版本不符应报错");
        let text = err.to_string();
        assert!(text.contains("配置版本 2"), "{text}");
        assert!(
            text.contains("config.example.toml"),
            "应给出手工迁移的指针：{text}"
        );
    }

    #[test]
    fn 监听地址缺_tcp_端口拒載() {
        let mut config = RelayConfig::default();
        config.listen.addrs = vec!["/ip4/0.0.0.0".to_string()];
        let err = config.validate().expect_err("缺端口应报错");
        assert!(err.to_string().contains("TCP 端口"), "{err}");
    }

    #[test]
    fn 监听地址含_p2p_或_circuit_拒載() {
        for addr in [
            "/ip4/0.0.0.0/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
            "/ip4/0.0.0.0/tcp/4001/p2p-circuit",
        ] {
            let mut config = RelayConfig::default();
            config.listen.addrs = vec![addr.to_string()];
            assert!(config.validate().is_err(), "非法监听地址应被拒绝：{addr}");
        }
    }

    #[test]
    fn 通告地址不得手写_p2p() {
        let mut config = loopback_config();
        config.advertise.addrs =
            vec!["/dns4/relay.example.com/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
                .to_string()];
        let err = config.validate().expect_err("应报错");
        assert!(err.to_string().contains("不要手写 /p2p"), "{err}");
    }

    #[test]
    fn 监听通配地址且无通告地址时拒載() {
        let config = RelayConfig::default();
        let err = config.validate().expect_err("0.0.0.0 + 无通告应报错");
        assert!(err.to_string().contains("对外通告地址缺失"), "{err}");
    }

    #[test]
    fn 通告地址为空时回退监听地址() {
        let config = loopback_config();
        let advertise = config.advertise_addrs().expect("回退");
        assert_eq!(advertise.len(), 1);
        assert_eq!(advertise[0].to_string(), "/ip4/127.0.0.1/tcp/0");
    }

    #[test]
    fn 配额零值与越界组合拒載() {
        let mut config = loopback_config();
        config.quota.max_reservations = 0;
        assert!(config.quota.validate().is_err(), "0 应被拒绝");

        let mut config = loopback_config();
        config.quota.max_reservations = 4;
        config.quota.max_reservations_per_peer = 8;
        assert!(
            config.quota.validate().is_err(),
            "单 peer 上限大于全局上限应被拒绝"
        );

        let mut config = loopback_config();
        config.quota.max_circuit_bytes = 1024;
        let err = config.quota.validate().expect_err("过小应拒绝");
        assert!(err.to_string().contains("max_circuit_bytes"), "{err}");

        let mut config = loopback_config();
        config.quota.max_circuit_bytes = 0;
        config.quota.validate().expect("0 表示不限，应允许");
    }

    #[test]
    fn 默认配额能覆盖_1gb_跨_nat_验收() {
        let quota = QuotaConfig::default();
        assert!(
            quota.max_circuit_bytes >= 1024 * 1024 * 1024,
            "默认单 circuit 上限必须能跑完 1GB 验收：{}",
            quota.max_circuit_bytes
        );
        assert!(
            quota.max_circuit_duration_secs >= 1800,
            "默认单 circuit 时长必须够传 1GB：{}s",
            quota.max_circuit_duration_secs
        );
    }

    #[test]
    fn 白名单_peer_id_形状在此处就校验() {
        let mut config = loopback_config();
        config.access.mode = AccessMode::Allowlist;
        config.access.allowlist = vec!["not-a-peer-id".to_string()];
        let err = config.validate().expect_err("非法 PeerId 应报错");
        assert!(err.to_string().contains("not-a-peer-id"), "{err}");
    }

    #[test]
    fn 指标端点非回环必须显式开启公网暴露() {
        let mut config = loopback_config();
        config.metrics.listen = "0.0.0.0:9090".to_string();
        let err = config.validate().expect_err("未显式开启应报错");
        assert!(err.to_string().contains("expose_public"), "{err}");

        config.metrics.expose_public = true;
        config.validate().expect("显式开启后允许");
    }

    #[test]
    fn 指标端点地址非法报错() {
        let mut config = loopback_config();
        config.metrics.listen = "9090".to_string();
        assert!(config.metrics.validate().is_err());
    }

    #[test]
    fn 身份路径相对配置文件目录解析() {
        let config = RelayConfig::default();
        let path = Path::new("/etc/wasmnest-relay/config.toml");
        assert_eq!(
            config.identity_path(path),
            PathBuf::from("/etc/wasmnest-relay/identity.key")
        );
        assert_eq!(
            RelayConfig::tokens_path(path),
            PathBuf::from("/etc/wasmnest-relay/tokens.json")
        );
        assert_eq!(
            RelayConfig::peers_path(path),
            PathBuf::from("/etc/wasmnest-relay/enrolled-peers.json")
        );
    }

    #[test]
    fn 身份路径绝对路径原样使用() {
        let mut config = RelayConfig::default();
        config.identity.key_file = PathBuf::from("/data/identity.key");
        assert_eq!(
            config.identity_path(Path::new("/etc/wasmnest-relay/config.toml")),
            PathBuf::from("/data/identity.key")
        );
    }

    #[test]
    fn 配置加载失败点名文件路径() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "config_version = ").expect("写坏配置");
        let err = RelayConfig::load(&path).expect_err("应报解析失败");
        assert!(err.to_string().contains("config.toml"), "{err}");
    }
}
