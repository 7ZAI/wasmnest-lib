//! 配额：把运维配置翻译成 `libp2p::relay::Config`，并提供每 IP 连接计数。
//!
//! 两条硬口径：
//!
//! 1. **默认值必须能跑完 1GB 跨 NAT 验收**——libp2p 的默认 `max_circuit_bytes`
//!    只有 128 KiB、`reservation_duration` 2 分钟，直接沿用会让大文件传输在中途
//!    被掐断，且表现为「传输随机失败」这种极难排查的形态。
//! 2. **默认的按 peer / 按 IP 速率限制要保留**（从 `Config::default()` 起改字段，
//!    而不是从零构造），否则任何人都能在几秒内刷满 reservation 表。
//!
//! 每 IP 连接上限不在 `libp2p::relay::Config` 里（那是 swarm 级配额），因此由事件
//! 循环调用 [`IpConnTracker`] 自行裁决：超限的连接被立刻关闭。

use std::{collections::HashMap, net::IpAddr, time::Duration};

use libp2p::relay;

use crate::{
    access::AccessLimiter,
    config::QuotaConfig,
    error::{RelayError, Result},
};

/// 解析后的配额（时间已转成 `Duration`，避免下游各自换算）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaPolicy {
    /// 全局 reservation 上限
    pub max_reservations: usize,
    /// 单 peer reservation 上限
    pub max_reservations_per_peer: usize,
    /// reservation 有效期
    pub reservation_ttl: Duration,
    /// 全局 circuit 上限
    pub max_circuits: usize,
    /// 单 peer 并发 circuit 上限
    pub max_circuits_per_peer: usize,
    /// 单 circuit 最长存活时间
    pub max_circuit_duration: Duration,
    /// 单 circuit 字节上限（0 = 不限）
    pub max_circuit_bytes: u64,
    /// 单 IP 入站连接上限
    pub max_connections_per_ip: usize,
}

impl QuotaPolicy {
    /// 从配置解析（配置层已校验，这里再做一次防御性检查，避免库调用方绕过 CLI）
    pub fn from_config(config: &QuotaConfig) -> Result<Self> {
        if config.max_reservations == 0
            || config.max_circuits == 0
            || config.max_connections_per_ip == 0
        {
            return Err(RelayError::config(
                "quota.max_reservations / max_circuits / max_connections_per_ip 必须 > 0",
            ));
        }
        Ok(Self {
            max_reservations: config.max_reservations,
            max_reservations_per_peer: config.max_reservations_per_peer,
            reservation_ttl: Duration::from_secs(config.reservation_ttl_secs),
            max_circuits: config.max_circuits,
            max_circuits_per_peer: config.max_circuits_per_peer,
            max_circuit_duration: Duration::from_secs(config.max_circuit_duration_secs),
            max_circuit_bytes: config.max_circuit_bytes,
            max_connections_per_ip: config.max_connections_per_ip,
        })
    }

    /// 组装 relay 行为面配置
    ///
    /// 准入限量器接在这里而不是连接层：被拒的 peer 仍能走控制协议兑换 token，
    /// 兑换后下一条 reservation 立刻放行。
    pub fn relay_config(
        &self,
        reservation_limiter: AccessLimiter,
        circuit_limiter: AccessLimiter,
    ) -> relay::Config {
        let mut config = relay::Config::default();
        config.max_reservations = self.max_reservations;
        config.max_reservations_per_peer = self.max_reservations_per_peer;
        config.reservation_duration = self.reservation_ttl;
        config.max_circuits = self.max_circuits;
        config.max_circuits_per_peer = self.max_circuits_per_peer;
        config.max_circuit_duration = self.max_circuit_duration;
        config.max_circuit_bytes = self.max_circuit_bytes;
        // 保留默认的按 peer / 按 IP 速率限制（防刷），再追加准入策略
        config
            .reservation_rate_limiters
            .push(Box::new(reservation_limiter));
        config
            .circuit_src_rate_limiters
            .push(Box::new(circuit_limiter));
        config
    }
}

/// 每 IP 入站连接计数
///
/// 统计口径是**已建立的入站连接**：连接建立时 +1、关闭时 -1；超限的连接不入账
/// （它会立刻被关闭，若仍计入会永久污染该 IP 的计数）。
#[derive(Debug)]
pub struct IpConnTracker {
    limit: usize,
    counts: HashMap<IpAddr, usize>,
}

impl IpConnTracker {
    /// 新建（`limit` 必须 > 0）
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            counts: HashMap::new(),
        }
    }

    /// 记录一条入站连接；返回 `false` 表示超过单 IP 上限（调用方应关闭该连接）
    pub fn on_connect(&mut self, ip: IpAddr) -> bool {
        let current = self.counts.get(&ip).copied().unwrap_or(0);
        if current >= self.limit {
            return false;
        }
        self.counts.insert(ip, current + 1);
        true
    }

    /// 记录一条入站连接关闭（未知 IP 不计数，避免多减）
    pub fn on_disconnect(&mut self, ip: IpAddr) {
        if let Some(current) = self.counts.get_mut(&ip) {
            *current = current.saturating_sub(1);
            if *current == 0 {
                self.counts.remove(&ip);
            }
        }
    }

    /// 当前活跃 IP 数（指标 / 自检）
    pub fn active_ips(&self) -> usize {
        self.counts.len()
    }

    /// 单 IP 上限
    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::config::QuotaConfig;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn relay_配置沿用默认速率限制并覆盖配额字段() {
        let policy = QuotaPolicy::from_config(&QuotaConfig::default()).expect("解析");
        let allowed = crate::access::AllowedPeers::new(crate::access::AccessMode::Open, [], None)
            .expect("准入集合");
        let (reservation_limiter, circuit_limiter) = allowed.limiters();
        let config = policy.relay_config(reservation_limiter, circuit_limiter);

        assert_eq!(config.max_reservations, 1024);
        assert_eq!(config.max_reservations_per_peer, 4);
        assert_eq!(config.reservation_duration, Duration::from_secs(3600));
        assert_eq!(config.max_circuits, 512);
        assert_eq!(config.max_circuits_per_peer, 64);
        assert_eq!(config.max_circuit_duration, Duration::from_secs(3600));
        assert_eq!(config.max_circuit_bytes, 1024 * 1024 * 1024);
        // 默认速率限制（按 peer / 按 IP）不能被准入限量器顶掉
        assert!(
            config.reservation_rate_limiters.len() >= 3,
            "应保留默认 reservation 速率限制并追加准入：{}",
            config.reservation_rate_limiters.len()
        );
        assert!(
            config.circuit_src_rate_limiters.len() >= 3,
            "应保留默认 circuit 速率限制并追加准入：{}",
            config.circuit_src_rate_limiters.len()
        );
    }

    #[test]
    fn 零连接上限被拒() {
        let mut config = QuotaConfig::default();
        config.max_connections_per_ip = 0;
        assert!(QuotaPolicy::from_config(&config).is_err());
    }

    #[test]
    fn 单_ip_计数在限额内放行_超限拒绝() {
        let mut tracker = IpConnTracker::new(2);
        assert!(tracker.on_connect(ip(1)));
        assert!(tracker.on_connect(ip(1)));
        assert!(!tracker.on_connect(ip(1)), "第 3 条应拒绝");
        assert!(tracker.on_connect(ip(2)), "其它 IP 不受影响");
    }

    #[test]
    fn 超限连接不入账_关闭后不产生负数() {
        let mut tracker = IpConnTracker::new(1);
        assert!(tracker.on_connect(ip(1)));
        assert!(!tracker.on_connect(ip(1)));

        tracker.on_disconnect(ip(1));
        assert_eq!(tracker.active_ips(), 0, "计数应归零并从表中移除");
        // 多余的 disconnect 不应产生负数或复活条目
        tracker.on_disconnect(ip(1));
        assert!(tracker.on_connect(ip(1)), "归零后应重新放行");
    }

    #[test]
    fn 计数按_ip_独立() {
        let mut tracker = IpConnTracker::new(2);
        assert!(tracker.on_connect(ip(1)));
        assert!(tracker.on_connect(ip(2)));
        tracker.on_disconnect(ip(1));
        assert_eq!(tracker.active_ips(), 1);
        // ip1 已归零：可以再建 2 条；ip2 仍占 1 条，只能再建 1 条
        assert!(tracker.on_connect(ip(1)));
        assert!(tracker.on_connect(ip(1)));
        assert!(!tracker.on_connect(ip(1)), "ip1 的第 3 条应被拒绝");
        assert!(tracker.on_connect(ip(2)), "ip2 的第 2 条应放行");
        assert!(!tracker.on_connect(ip(2)), "ip2 的第 3 条应被拒绝");
    }

    #[test]
    fn 上限为零时按_1_处理_不静默禁用限制() {
        let mut tracker = IpConnTracker::new(0);
        assert_eq!(tracker.limit(), 1);
        assert!(tracker.on_connect(ip(1)));
        assert!(!tracker.on_connect(ip(1)));
    }
}
