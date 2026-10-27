//! System Information
//!
//! 全局系统基本信息（OS / 设备名称 / IP 地址），启动时采集一次，
//! 挂载到 AppContext 供全局引用（AppContext::global().system_info()）

use serde::Serialize;

/// 系统基本信息
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    /// OS 名称（std::env::consts::OS：windows / linux / macos）
    pub os_name: String,
    /// OS 版本（如 Windows "10.0.22631"），获取失败为空串
    pub os_version: String,
    /// 用户设置的设备名称（Windows 电脑名 COMPUTERNAME，其余平台取 hostname）
    pub device_name: String,
    /// 主机名
    pub hostname: String,
    /// 本地 IPv4 地址（排除回环与链路本地）
    pub local_ips: Vec<String>,
    /// 应用版本
    pub app_version: String,
}

impl SystemInfo {
    /// 采集当前系统信息
    ///
    /// 进程生命周期内基本不变（设备名/IP 变更需重启生效），启动时调用一次
    pub fn collect() -> Self {
        Self {
            os_name: std::env::consts::OS.to_string(),
            os_version: sysinfo::System::os_version().unwrap_or_default(),
            device_name: desktop_device_name(),
            hostname: sysinfo::System::host_name().unwrap_or_default(),
            local_ips: local_ipv4_addresses(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// 用户设置的设备名称
///
/// Windows 读 COMPUTERNAME 环境变量（即控制面板中的电脑名，用户可修改）；
/// 其余平台取系统 hostname（macOS/Linux 系统设置中可修改）；
/// 均获取不到时回退 `{os}-{ip}` 组合名
fn desktop_device_name() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(name) = std::env::var("COMPUTERNAME") {
            if !name.trim().is_empty() {
                return name;
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(name) = sysinfo::System::host_name() {
            if !name.trim().is_empty() {
                return name;
            }
        }
    }
    fallback_os_ip_name()
}

/// 兜底设备名：`{os}-{首个IPv4}`，无可用 IP 时回退默认常量
fn fallback_os_ip_name() -> String {
    let ips = local_ipv4_addresses();
    match ips.first() {
        Some(ip) => format!("{}-{}", std::env::consts::OS, ip),
        None => crate::constants::DEFAULT_HOSTNAME.to_string(),
    }
}

/// 本地 IPv4 地址列表（排除回环与链路本地）——**引擎事实**
///
/// 宿主命令面 `get_local_ip_addresses` 已注销（产品面归 `com.wasmnest.bedcode`
/// 的 `session.network.info`，其下是 ABI v19 原语 `host-platform.local-ipv4-addresses`）；
/// 本函数只服务宿主引擎自身：设备名兜底、启动提示与 [`SystemInfo`] 采集。
/// 口径与 `host_impl/platform.rs::platform_local_ipv4_addresses` 一致。
pub fn local_ipv4_addresses() -> Vec<String> {
    local_ip_address::list_afinet_netifas()
        .map(|interfaces| {
            interfaces
                .into_iter()
                .filter(|(_, ip)| match ip {
                    std::net::IpAddr::V4(ipv4) => !ipv4.is_loopback() && !ipv4.is_link_local(),
                    std::net::IpAddr::V6(_) => false,
                })
                .map(|(_, ip)| ip.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_info_collect() {
        let info = SystemInfo::collect();
        assert!(!info.os_name.is_empty(), "os_name 不应为空");
        assert!(!info.device_name.is_empty(), "device_name 不应为空");
        assert_eq!(info.app_version, env!("CARGO_PKG_VERSION"));
        // local_ips 在无网环境下可为空，不断言
    }
}
