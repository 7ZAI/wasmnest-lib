//! `doctor` 自检：把「能不能跑」拆成可行动的逐项判据。
//!
//! 设计口径：**本机能检查的一律实检**（身份可解析、配置合法、端口可绑、目录可写、
//! 时钟合理），**本机无法自证的明确标成 `unknown` 并给出验证路径**——绝不用一个
//! 假的 ✓ 冒充「公网可达」。公网可达性只能由外部视角证明（应用侧的「检测连通性」
//! 或另一台机器的实际拨号）。

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use libp2p::multiaddr::{Multiaddr, Protocol};
use serde::Serialize;

use crate::{
    access::{AccessMode, AllowedPeers},
    config::RelayConfig,
    error::Result,
    fsutil,
    identity::RelayIdentity,
    tokens::TokenStore,
    wire::CONTROL_PROTOCOL,
    RELAY_VERSION,
};

/// 时钟合理下界（unix 秒，2025-01-01）：早于它说明系统时间明显错误
pub const MIN_SANE_UNIX: u64 = 1_735_689_600;

/// 单项检查结果
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckState {
    /// 通过
    Pass,
    /// 可疑但可继续（如端口已被运行中的中继占用）
    Warn,
    /// 不可用（`run` 会失败）
    Fail,
    /// 本机无法自证，需外部验证
    Unknown,
}

/// 一条检查
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// 稳定 id（脚本 / 文档引用）
    pub id: String,
    /// 人类可读标题
    pub title: String,
    /// 结论
    pub state: CheckState,
    /// 细节（成功给实测值，失败给原因与出路）
    pub detail: String,
}

impl Check {
    fn new(id: &str, title: &str, state: CheckState, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            state,
            detail: detail.into(),
        }
    }
}

/// 全量自检
///
/// 不返回 `Result`：**配置本身坏了也要作为一条 `Fail` 出现在报告里**，否则用户只会
/// 看到一句「加载配置失败」而不知道其余项的状态。
pub fn run(config_path: &Path) -> Vec<Check> {
    let mut checks = Vec::new();
    checks.push(check_data_dir(config_path));
    checks.push(check_clock());

    let config = match RelayConfig::load(config_path) {
        Ok(config) => {
            checks.push(Check::new(
                "config",
                "配置",
                CheckState::Pass,
                format!(
                    "{}：config_version=1，准入 {}，单 circuit 上限 {} 字节 / {} 秒",
                    config_path.display(),
                    config.access.mode.as_str(),
                    config.quota.max_circuit_bytes,
                    config.quota.max_circuit_duration_secs
                ),
            ));
            Some(config)
        }
        Err(err) => {
            checks.push(Check::new(
                "config",
                "配置",
                CheckState::Fail,
                format!("{err}；可对照 deploy/relay/config.example.toml 修正"),
            ));
            None
        }
    };

    checks.push(check_identity(config_path, config.as_ref()));
    let Some(config) = config else {
        // 配置不可用时其余检查没有意义：明确写出来，不留空洞
        checks.push(Check::new(
            "listen",
            "监听端口",
            CheckState::Unknown,
            "配置不可用，跳过端口检查",
        ));
        checks.push(Check::new(
            "tokens",
            "enrollment token",
            CheckState::Unknown,
            "配置不可用，跳过 token 检查",
        ));
        checks.push(Check::new(
            "reachability",
            "公网可达",
            CheckState::Unknown,
            "配置不可用，无法给出通告地址",
        ));
        return checks;
    };

    checks.push(check_listen(&config));
    checks.push(check_metrics(&config));
    checks.push(check_tokens(config_path, &config));
    checks.push(check_reachability(&config));
    checks.push(check_version(&config));
    checks
}

/// 存在 `Fail` 时返回 1
pub fn exit_code(checks: &[Check]) -> i32 {
    if checks.iter().any(|c| c.state == CheckState::Fail) {
        1
    } else {
        0
    }
}

/// 文本报告
pub fn render_text(checks: &[Check]) -> String {
    let mut out = String::new();
    for check in checks {
        let mark = match check.state {
            CheckState::Pass => "✓",
            CheckState::Warn => "!",
            CheckState::Fail => "✗",
            CheckState::Unknown => "?",
        };
        out.push_str(&format!(
            "[{mark}] {title}（{id}）：{detail}\n",
            title = check.title,
            id = check.id,
            detail = check.detail
        ));
    }
    let fails = checks
        .iter()
        .filter(|c| c.state == CheckState::Fail)
        .count();
    let warns = checks
        .iter()
        .filter(|c| c.state == CheckState::Warn)
        .count();
    out.push_str(&format!(
        "\n结果：{} 项通过，{warns} 项警告，{fails} 项失败\n",
        checks
            .iter()
            .filter(|c| c.state == CheckState::Pass)
            .count()
    ));
    out
}

/// JSON 报告（`{"checks":[…],"fail":n}`）
pub fn render_json(checks: &[Check]) -> Result<String> {
    #[derive(Serialize)]
    struct Report<'a> {
        checks: &'a [Check],
        fail: usize,
        warn: usize,
        version: &'a str,
    }
    let report = Report {
        checks,
        fail: checks
            .iter()
            .filter(|c| c.state == CheckState::Fail)
            .count(),
        warn: checks
            .iter()
            .filter(|c| c.state == CheckState::Warn)
            .count(),
        version: RELAY_VERSION,
    };
    Ok(serde_json::to_string_pretty(&report)?)
}

fn check_data_dir(config_path: &Path) -> Check {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    match fsutil::writable_probe(dir) {
        Ok(()) => Check::new(
            "data_dir",
            "数据目录",
            CheckState::Pass,
            format!("{} 可写", dir.display()),
        ),
        Err(err) => Check::new(
            "data_dir",
            "数据目录",
            CheckState::Fail,
            format!(
                "{} 不可写：{err}（容器里检查卷挂载与只读标记）",
                dir.display()
            ),
        ),
    }
}

fn check_clock() -> Check {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now < MIN_SANE_UNIX {
        Check::new(
            "clock",
            "系统时钟",
            CheckState::Fail,
            format!(
                "当前时间戳 {now} 早于 2025-01-01：时钟明显错误，reservation/票据有效期会算错；请启用 NTP"
            ),
        )
    } else {
        Check::new("clock", "系统时钟", CheckState::Pass, format!("unix {now}"))
    }
}

fn check_identity(config_path: &Path, config: Option<&RelayConfig>) -> Check {
    let Some(config) = config else {
        return Check::new(
            "identity",
            "身份",
            CheckState::Unknown,
            "配置不可用，无法解析身份路径",
        );
    };
    let path = config.identity_path(config_path);
    match RelayIdentity::load(&path) {
        Ok(identity) => {
            let mut detail = format!(
                "{}：PeerId {}，指纹 {}",
                path.display(),
                identity.peer_id(),
                identity.fingerprint()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::metadata(&path) {
                    Ok(meta) => {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode & 0o077 != 0 {
                            return Check::new(
                                "identity",
                                "身份",
                                CheckState::Warn,
                                format!("{detail}；权限 {mode:o} 过宽（建议 600）"),
                            );
                        }
                        detail.push_str(&format!("，权限 {mode:o}"));
                    }
                    Err(err) => {
                        return Check::new(
                            "identity",
                            "身份",
                            CheckState::Warn,
                            format!("{detail}；无法读取权限位：{err}"),
                        )
                    }
                }
            }
            Check::new("identity", "身份", CheckState::Pass, detail)
        }
        Err(err) => Check::new("identity", "身份", CheckState::Fail, format!("{err}")),
    }
}

fn check_listen(config: &RelayConfig) -> Check {
    let addrs = match config.listen_addrs() {
        Ok(addrs) => addrs,
        Err(err) => {
            return Check::new("listen", "监听端口", CheckState::Fail, format!("{err}"));
        }
    };
    let mut details = Vec::new();
    let mut state = CheckState::Pass;
    for addr in &addrs {
        let Some(socket) = socket_addr(&addr) else {
            details.push(format!("{addr}：无法转换为 SocketAddr，跳过"));
            state = worst(state, CheckState::Warn);
            continue;
        };
        match TcpListener::bind(socket) {
            Ok(listener) => {
                // 立刻释放，避免 doctor 自己占着端口
                drop(listener);
                details.push(format!("{socket} 可绑定"));
            }
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                details.push(format!(
                    "{socket} 已被占用（若本机 relay 正在运行属正常）：{err}"
                ));
                state = worst(state, CheckState::Warn);
            }
            Err(err) => {
                details.push(format!("{socket} 无法绑定：{err}"));
                state = CheckState::Fail;
            }
        }
    }
    Check::new("listen", "监听端口", state, details.join("；"))
}

fn check_metrics(config: &RelayConfig) -> Check {
    match config.metrics_socket_addr() {
        Ok(addr) if addr.ip().is_loopback() => Check::new(
            "metrics",
            "指标端点",
            CheckState::Pass,
            format!("{addr}（只绑回环）"),
        ),
        Ok(addr) => Check::new(
            "metrics",
            "指标端点",
            CheckState::Warn,
            format!(
                "{addr} 非回环且已显式开启公网暴露：请用反代 TLS 或额外 token 保护 /healthz 与 /metrics"
            ),
        ),
        Err(err) => Check::new("metrics", "指标端点", CheckState::Fail, format!("{err}")),
    }
}

fn check_tokens(config_path: &Path, config: &RelayConfig) -> Check {
    let path = RelayConfig::tokens_path(config_path);
    match TokenStore::load(&path) {
        Ok(store) => {
            let summary = store.summary();
            let remaining: u32 = summary.iter().map(|(_, uses, max)| max - uses).sum();
            let peers_path = RelayConfig::peers_path(config_path);
            let peers = AllowedPeers::new(config.access.mode, Vec::new(), Some(peers_path.clone()))
                .map(|allowed| allowed.snapshot().len())
                .unwrap_or(0);
            let detail = format!(
                "{} 条 token（剩余可用 {remaining} 次）；已 enrollment 的 peer：{peers}；准入模式 {}",
                summary.len(),
                config.access.mode.as_str()
            );
            let state = if config.access.mode == AccessMode::Allowlist
                && summary.is_empty()
                && config.access.allowlist.is_empty()
                && peers == 0
            {
                CheckState::Warn
            } else {
                CheckState::Pass
            };
            Check::new(
                "tokens",
                "enrollment token",
                state,
                if state == CheckState::Warn {
                    format!(
                        "{detail}；allowlist 模式下白名单为空且没有 token：\n                   除配置文件里手写的 PeerId 外没人能通过。用 `token create --label <名字>` 发一个"
                    )
                } else {
                    detail
                },
            )
        }
        Err(err) => Check::new(
            "tokens",
            "enrollment token",
            CheckState::Fail,
            format!("{err}"),
        ),
    }
}

fn check_reachability(config: &RelayConfig) -> Check {
    let addrs = match config.advertise_addrs() {
        Ok(addrs) => addrs,
        Err(err) => {
            return Check::new(
                "reachability",
                "公网可达",
                CheckState::Fail,
                format!("{err}"),
            );
        }
    };
    let private: Vec<String> = addrs
        .iter()
        .filter(|addr| addr_is_private(addr))
        .map(|addr| addr.to_string())
        .collect();
    if !private.is_empty() {
        return Check::new(
            "reachability",
            "公网可达",
            CheckState::Warn,
            format!(
                "通告地址是私网/回环地址（{}）：只有同网段能连。公网部署请把 advertise.addrs 改成公网域名或 IP",
                private.join(", ")
            ),
        );
    }
    Check::new(
        "reachability",
        "公网可达",
        CheckState::Unknown,
        format!(
            "通告地址 {}；本机无法自证公网可达——请从外部机器实际拨号，或在应用侧用「检测连通性」（需放行 TCP {}）",
            addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            addrs
                .iter()
                .find_map(|a| crate::config::tcp_port(a))
                .unwrap_or(crate::config::DEFAULT_RELAY_PORT)
        ),
    )
}

fn check_version(config: &RelayConfig) -> Check {
    let quota_ok =
        config.quota.max_circuit_bytes == 0 || config.quota.max_circuit_bytes >= 1024 * 1024 * 1024;
    let mut check = Check::new(
        "version",
        "版本",
        CheckState::Pass,
        format!(
            "relay {RELAY_VERSION}，config_version {}，控制协议 {CONTROL_PROTOCOL}",
            config.config_version
        ),
    );
    if !quota_ok {
        check.state = CheckState::Warn;
        check.detail.push_str(&format!(
            "；单 circuit 字节上限 {} < 1 GiB，跨 NAT 传大文件会被掐断",
            config.quota.max_circuit_bytes
        ));
    }
    check
}

fn worst(current: CheckState, next: CheckState) -> CheckState {
    match (current, next) {
        (CheckState::Fail, _) | (_, CheckState::Fail) => CheckState::Fail,
        (CheckState::Warn, _) | (_, CheckState::Warn) => CheckState::Warn,
        _ => CheckState::Pass,
    }
}

fn socket_addr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut ip: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(value) => ip = Some(IpAddr::V4(Ipv4Addr::from(value.octets()))),
            Protocol::Ip6(value) => ip = Some(IpAddr::V6(Ipv6Addr::from(value.octets()))),
            Protocol::Tcp(value) => port = Some(value),
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?))
}

fn addr_is_private(addr: &Multiaddr) -> bool {
    addr.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                // CGNAT 100.64.0.0/10：不是公网，也不是 RFC1918
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
        }
        Protocol::Ip6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
        _ => false,
    })
}

/// 默认配置路径候选（`doctor` / `print-addrs` 未显式给 `--config` 时）
pub const DEFAULT_CONFIG_CANDIDATES: &[&str] =
    &["/data/config.toml", "/etc/wasmnest-relay/config.toml"];

/// 解析默认配置路径（显式 → 环境变量 → 候选中第一个存在的 → 报错并列出全部候选）
pub fn resolve_config_path(explicit: Option<std::path::PathBuf>) -> Result<std::path::PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os("WASMNEST_RELAY_CONFIG") {
        return Ok(std::path::PathBuf::from(path));
    }
    for candidate in DEFAULT_CONFIG_CANDIDATES {
        let path = std::path::PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }
    Err(crate::error::RelayError::args(format!(
        "找不到配置文件：请用 `--config <路径>` 指定，或设置 WASMNEST_RELAY_CONFIG（已尝试：{}）",
        DEFAULT_CONFIG_CANDIDATES.join("、")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_valid_config(dir: &Path) -> std::path::PathBuf {
        let mut config = RelayConfig::default();
        config.listen.addrs = vec!["/ip4/127.0.0.1/tcp/0".to_string()];
        config.advertise.addrs = vec!["/ip4/203.0.113.10/tcp/4001".to_string()];
        config.metrics.listen = "127.0.0.1:0".to_string();
        let path = dir.join("config.toml");
        std::fs::write(&path, config.to_toml().expect("序列化")).expect("写配置");
        RelayIdentity::create(&config.identity_path(&path), false).expect("身份");
        path
    }

    #[test]
    fn 合法部署除公网可达外全部通过() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = write_valid_config(dir.path());
        let checks = run(&path);
        assert_eq!(exit_code(&checks), 0, "不应有失败项：{checks:#?}");
        let reachability = checks
            .iter()
            .find(|c| c.id == "reachability")
            .expect("应有公网可达项");
        assert_eq!(
            reachability.state,
            CheckState::Unknown,
            "本机无法自证公网可达，必须如实标 unknown"
        );
        let identity = checks.iter().find(|c| c.id == "identity").expect("身份项");
        assert_eq!(identity.state, CheckState::Pass, "{identity:?}");
        assert!(identity.detail.contains("PeerId"), "{}", identity.detail);
    }

    #[test]
    fn 缺身份时该项失败且退出码非零() {
        let dir = tempfile::tempdir().expect("临时目录");
        let mut config = RelayConfig::default();
        config.advertise.addrs = vec!["/ip4/203.0.113.10/tcp/4001".to_string()];
        let path = dir.path().join("config.toml");
        std::fs::write(&path, config.to_toml().expect("序列化")).expect("写配置");

        let checks = run(&path);
        let identity = checks.iter().find(|c| c.id == "identity").expect("身份项");
        assert_eq!(identity.state, CheckState::Fail);
        assert!(identity.detail.contains("init"), "{}", identity.detail);
        assert_eq!(exit_code(&checks), 1);
    }

    #[test]
    fn 配置损坏时其余项标为跳过而不是假装通过() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "config_version = ").expect("写坏配置");
        let checks = run(&path);
        assert_eq!(
            checks
                .iter()
                .filter(|c| c.state == CheckState::Fail)
                .count(),
            1
        );
        for id in ["listen", "tokens", "reachability"] {
            let check = checks.iter().find(|c| c.id == id).expect(id);
            assert_eq!(check.state, CheckState::Unknown, "{check:?}");
        }
    }

    #[test]
    fn 私网通告地址给出警告并指出去处() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = write_valid_config(dir.path());
        let mut config = RelayConfig::load(&path).expect("加载");
        config.advertise.addrs = vec!["/ip4/192.168.1.10/tcp/4001".to_string()];
        std::fs::write(&path, config.to_toml().expect("序列化")).expect("改写");

        let checks = run(&path);
        let reachability = checks.iter().find(|c| c.id == "reachability").expect("项");
        assert_eq!(reachability.state, CheckState::Warn, "{reachability:?}");
        assert!(
            reachability.detail.contains("私网"),
            "{}",
            reachability.detail
        );
    }

    #[test]
    fn 白名单模式无令牌无白名单时给出警告() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = write_valid_config(dir.path());
        let mut config = RelayConfig::load(&path).expect("加载");
        config.access.mode = AccessMode::Allowlist;
        std::fs::write(&path, config.to_toml().expect("序列化")).expect("改写");

        let checks = run(&path);
        let tokens = checks.iter().find(|c| c.id == "tokens").expect("项");
        assert_eq!(tokens.state, CheckState::Warn, "{tokens:?}");
        assert!(tokens.detail.contains("token create"), "{}", tokens.detail);
    }

    #[test]
    fn 小_circuit_上限在版本项给出警告() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = write_valid_config(dir.path());
        let mut config = RelayConfig::load(&path).expect("加载");
        config.quota.max_circuit_bytes = 8 * 1024 * 1024;
        std::fs::write(&path, config.to_toml().expect("序列化")).expect("改写");

        let checks = run(&path);
        let version = checks.iter().find(|c| c.id == "version").expect("项");
        assert_eq!(version.state, CheckState::Warn, "{version:?}");
        assert!(version.detail.contains("1 GiB"), "{}", version.detail);
    }

    #[test]
    fn 文本与_json_报告可读且含全部项() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = write_valid_config(dir.path());
        let checks = run(&path);

        let text = render_text(&checks);
        for check in &checks {
            assert!(
                text.contains(&check.id),
                "文本报告缺少 {}：{text}",
                check.id
            );
        }
        assert!(text.contains("结果："));

        let json = render_json(&checks).expect("JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("解析");
        assert_eq!(parsed["fail"], 0);
        assert_eq!(
            parsed["checks"].as_array().expect("数组").len(),
            checks.len()
        );
        assert_eq!(parsed["version"], RELAY_VERSION);
    }

    #[test]
    fn 私网_ip_判定覆盖_rfc1918_与_cgnat() {
        for text in [
            "/ip4/10.0.0.1/tcp/4001",
            "/ip4/172.16.5.4/tcp/4001",
            "/ip4/192.168.1.1/tcp/4001",
            "/ip4/127.0.0.1/tcp/4001",
            "/ip4/100.64.3.2/tcp/4001",
            "/ip6/::1/tcp/4001",
            "/ip6/fd00::1/tcp/4001",
        ] {
            let addr: Multiaddr = text.parse().expect("地址");
            assert!(addr_is_private(&addr), "应判为私网：{text}");
        }
        for text in [
            "/ip4/203.0.113.10/tcp/4001",
            "/dns4/relay.example.com/tcp/4001",
        ] {
            let addr: Multiaddr = text.parse().expect("地址");
            assert!(!addr_is_private(&addr), "不应判为私网：{text}");
        }
    }

    #[test]
    fn socket_addr_转换只认_ip_加_tcp() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("地址");
        assert_eq!(
            socket_addr(&addr),
            Some("127.0.0.1:4001".parse().expect("SocketAddr"))
        );
        let addr: Multiaddr = "/dns4/relay.example.com/tcp/4001".parse().expect("地址");
        assert!(socket_addr(&addr).is_none(), "域名地址无法本地绑定检查");
    }

    #[test]
    fn 未给_config_且候选都不存在时报参数错误() {
        // 清除环境变量干扰（测试进程可能与开发终端共享）
        let previous = std::env::var_os("WASMNEST_RELAY_CONFIG");
        std::env::remove_var("WASMNEST_RELAY_CONFIG");
        let result = resolve_config_path(None);
        if let Some(previous) = previous {
            std::env::set_var("WASMNEST_RELAY_CONFIG", previous);
        }
        // 本机可能真的存在 /data/config.toml：那种情况下返回 Ok 也是正确行为
        match result {
            Ok(path) => assert!(path.exists(), "解析出的路径应存在：{}", path.display()),
            Err(err) => {
                let text = err.to_string();
                assert!(text.contains("--config"), "{text}");
                assert!(text.contains("/data/config.toml"), "{text}");
            }
        }
    }
}
