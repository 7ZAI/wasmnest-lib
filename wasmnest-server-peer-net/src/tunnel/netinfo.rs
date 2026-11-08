//! 宿主侧网络事实枚举（设计 §4.9）：接口子网 + 蜂窝判定。
//!
//! 判据本身在 [`super::mode`]；这里只负责「把操作系统的接口清单变成事实」。
//! 应用 JS 永远拿不到接口清单（`status` 只给模式归因），符合设计
//! 「网络类型与接口子网判定由宿主完成」。
//!
//! **未知优先**：枚举失败 / 只有环回接口 → `known = false`，判据层据此一律
//! 「先试 LAN、不自动切」。

use std::net::IpAddr;

use if_addrs::{get_if_addrs, IfAddr};

use super::mode::{NetworkFacts, Subnet};

/// 接口类型（按接口名判定；只用于「当前是否只走蜂窝」）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    Loopback,
    Wifi,
    Ethernet,
    Cellular,
    Virtual,
    Other,
}

/// 接口名 → 类型（Android 蜂窝：`rmnet_data*` / `ccmni*` / `pdp*` / `clat*` / `v4-*`）
pub fn classify_interface(name: &str) -> InterfaceKind {
    let name = name.trim_end_matches(':').to_ascii_lowercase();
    if name == "lo" || name.starts_with("lo0") || name.starts_with("loopback") {
        return InterfaceKind::Loopback;
    }
    const CELLULAR: [&str; 6] = ["rmnet", "ccmni", "pdp", "wwan", "clat", "v4-"];
    if CELLULAR.iter().any(|prefix| name.starts_with(prefix)) {
        return InterfaceKind::Cellular;
    }
    const WIFI: [&str; 4] = ["wlan", "wlp", "wlx", "swlan"];
    if WIFI.iter().any(|prefix| name.starts_with(prefix)) {
        return InterfaceKind::Wifi;
    }
    const ETHERNET: [&str; 6] = ["eth", "eno", "enp", "ens", "enx", "en"];
    if ETHERNET.iter().any(|prefix| name.starts_with(prefix)) {
        return InterfaceKind::Ethernet;
    }
    const VIRTUAL: [&str; 10] = [
        "docker",
        "veth",
        "br-",
        "virbr",
        "vmnet",
        "tun",
        "tap",
        "wg",
        "zt",
        "tailscale",
    ];
    if VIRTUAL.iter().any(|prefix| name.starts_with(prefix)) {
        return InterfaceKind::Virtual;
    }
    InterfaceKind::Other
}

/// 单条接口事实（枚举结果的最小可测形状）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceFact {
    pub name: String,
    pub addr: IpAddr,
    pub prefix: u8,
}

/// 接口清单 → 网络事实（纯函数，可测）
///
/// - 只收非环回 / 非链路本地地址（链路本地不构成「同网段判定」依据）；
/// - `known` = 至少一条可用接口事实——否则判据层按未知处理；
/// - `cellular` = 有蜂窝接口且**没有** Wi-Fi / Ethernet 接口（有线上行时不算蜂窝）。
pub fn facts_from(interfaces: &[InterfaceFact]) -> NetworkFacts {
    let mut subnets = Vec::new();
    let mut has_wifi_or_eth = false;
    let mut has_cellular = false;
    for item in interfaces {
        let kind = classify_interface(&item.name);
        if matches!(kind, InterfaceKind::Loopback) || is_link_local(item.addr) {
            continue;
        }
        if let Some(subnet) = Subnet::new(item.addr, item.prefix) {
            subnets.push(subnet);
        }
        match kind {
            InterfaceKind::Wifi | InterfaceKind::Ethernet => has_wifi_or_eth = true,
            InterfaceKind::Cellular => has_cellular = true,
            _ => {}
        }
    }
    NetworkFacts {
        known: !subnets.is_empty(),
        cellular: has_cellular && !has_wifi_or_eth,
        local_subnets: subnets,
        mdns_known: false,
    }
}

fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// 读取本机接口事实（失败 = 未知，不抛错：判据层会把未知当「不明确」）
pub fn system_network_facts() -> NetworkFacts {
    match get_if_addrs() {
        Ok(list) => {
            let facts: Vec<InterfaceFact> = list
                .into_iter()
                .filter_map(|interface| match interface.addr {
                    IfAddr::V4(v4) => Some(InterfaceFact {
                        name: interface.name,
                        addr: IpAddr::V4(v4.ip),
                        prefix: v4.prefixlen,
                    }),
                    IfAddr::V6(v6) => Some(InterfaceFact {
                        name: interface.name,
                        addr: IpAddr::V6(v6.ip),
                        prefix: v6.prefixlen,
                    }),
                })
                .collect();
            facts_from(&facts)
        }
        Err(e) => {
            tracing::warn!(error = %e, "interface enumeration failed; tunnel mode falls back to lan-first");
            NetworkFacts::unknown()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(name: &str, addr: &str, prefix: u8) -> InterfaceFact {
        InterfaceFact {
            name: name.into(),
            addr: addr.parse().unwrap(),
            prefix,
        }
    }

    #[test]
    fn interface_names_map_to_expected_kinds() {
        assert_eq!(classify_interface("lo"), InterfaceKind::Loopback);
        assert_eq!(classify_interface("wlan0"), InterfaceKind::Wifi);
        assert_eq!(classify_interface("eth0"), InterfaceKind::Ethernet);
        assert_eq!(classify_interface("enp3s0"), InterfaceKind::Ethernet);
        assert_eq!(classify_interface("rmnet_data0"), InterfaceKind::Cellular);
        assert_eq!(classify_interface("ccmni1"), InterfaceKind::Cellular);
        assert_eq!(classify_interface("docker0"), InterfaceKind::Virtual);
        assert_eq!(classify_interface("weird0"), InterfaceKind::Other);
    }

    #[test]
    fn wifi_home_network_is_not_cellular() {
        let facts = facts_from(&[fact("lo", "127.0.0.1", 8), fact("wlan0", "192.168.1.7", 24)]);
        assert!(facts.known);
        assert!(!facts.cellular, "存在 Wi-Fi 接口时不得判成蜂窝");
        assert_eq!(facts.local_subnets.len(), 1);
    }

    #[test]
    fn cellular_only_device_is_cellular() {
        let facts = facts_from(&[fact("lo", "127.0.0.1", 8), fact("rmnet_data0", "10.42.0.9", 30)]);
        assert!(facts.known);
        assert!(facts.cellular);
    }

    #[test]
    fn link_local_and_loopback_do_not_form_subnets() {
        let facts = facts_from(&[
            fact("lo", "127.0.0.1", 8),
            fact("wlan0", "169.254.10.3", 16),
            fact("wlan0", "fe80::1", 64),
        ]);
        assert!(!facts.known, "只有环回 / 链路本地 = 事实未知");
        assert!(facts.local_subnets.is_empty());
        assert!(!facts.cellular);
    }

    #[test]
    fn virtual_interfaces_do_not_mask_cellular() {
        let facts = facts_from(&[fact("rmnet_data0", "10.42.0.9", 30), fact("tun0", "172.19.0.1", 16)]);
        assert!(facts.cellular, "VPN 接口不改变「只有蜂窝上行」的事实");
    }
}
