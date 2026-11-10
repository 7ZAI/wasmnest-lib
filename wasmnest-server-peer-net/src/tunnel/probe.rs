//! `host-tunnel.probe-relay` 域函数（T19）：relay 连通性探测。
//!
//! ## 分层
//!
//! ```text
//! 本文件            权限门 + 地址校验 / 域名解析 + 限流 + 错误码映射 + report 序列化
//! p2p-engine::probe 一次性临时 swarm 拨号 + 握手身份校验 + ping（无宿主依赖）
//! ```
//!
//! ## 零持久副作用（不变量 P1）
//!
//! 探测**不**登记 expose 规则、**不**建立 / 释放 reservation、**不**写信任、
//! **不** acquire `net.tunnel` 服务租约、**不**发任何事件。因此本函数不碰
//! [`TunnelManager`](super::TunnelManager)：它不持有任何隧道资源，管理器是否装配
//! 与「能不能测一下」无关（旧宿主 / 移动宿主没有该原语时，缺的是 WIT 导出，
//! 由 `tunnel-unavailable` 在宿主侧显性表达）。
//!
//! ## 只探测已保存的地址（不变量 P4）
//!
//! 命令签名不接受前端任意地址的理由就在应用仓：地址真源是中心 KV，若允许前端
//! 传地址，这个按钮会变成「任意 multiaddr 拨号器」。域层仍做形状校验（防 KV 被
//! 手改成畸形数据）。
//!
//! ## 限流（进程级，按插件）
//!
//! 同插件只允许 1 个探测在飞；结束后 2s 冷却内重复调用返回 `probe-rate-limited`
//! （不排队——界面提示「正在检测」，避免连点打爆公网 relay）。

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use wasmnest_p2p_engine::relay::{resolve_relay_addr, RelayEndpoint};
use wasmnest_p2p_engine::{Multiaddr, PeerId};

use super::plugin_binding::{block_on, TunnelPorts};
use super::{
    TunnelError, CODE_PEER_OFFLINE, CODE_PROBE_RATE_LIMITED, CODE_RELAY_ADDRESS_INVALID, CODE_RELAY_IDENTITY_MISMATCH,
    CODE_RELAY_UNREACHABLE,
};

/// 超时缺省值（`timeout_ms == 0`）：公网 relay 的 TCP + Noise 握手留足余量
pub const PROBE_DEFAULT_TIMEOUT_MS: u32 = 8_000;
/// 超时上限：界面等待上限，超过即截断（不让按钮无限转）
pub const PROBE_MAX_TIMEOUT_MS: u32 = 15_000;
/// 超时下限：低于此值环回都可能误判，直接抬到 1s
pub const PROBE_MIN_TIMEOUT_MS: u32 = 1_000;
/// 一次探测最多接受的地址条数（同一 relay 的多传输地址）
pub const PROBE_MAX_ADDRS: usize = 16;
/// 探测结束后的冷却窗口
pub const PROBE_COOLDOWN: Duration = Duration::from_secs(2);

// ==================== 限流 ====================

#[derive(Default)]
struct ProbeSlot {
    in_flight: bool,
    finished_at: Option<Instant>,
}

static PROBE_SLOTS: LazyLock<Mutex<HashMap<String, ProbeSlot>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// 在飞租约：drop 即结算（成功 / 失败 / panic 都释放，不会把插件永久卡在「正在检测」）
///
/// 只有**真正发起过拨号**（[`Self::spent`]）才进入冷却：地址形状 / 域名解析这类
/// 本地校验失败若也记冷却，用户改完配置立刻重试会被「冷却中」误导。
struct ProbeGuard {
    plugin_id: String,
    spent: bool,
}

impl ProbeGuard {
    /// 标记「已进入拨号阶段」——此后的失败与成功都算一次真实探测，进入冷却
    fn spent(&mut self) {
        self.spent = true;
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        let mut slots = PROBE_SLOTS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = slots.get_mut(&self.plugin_id) {
            slot.in_flight = false;
            if self.spent {
                slot.finished_at = Some(Instant::now());
            }
        }
    }
}

fn acquire_probe_slot(plugin_id: &str) -> Result<ProbeGuard, TunnelError> {
    let mut slots = PROBE_SLOTS.lock().unwrap_or_else(|e| e.into_inner());
    let slot = slots.entry(plugin_id.to_string()).or_default();
    if slot.in_flight {
        return Err(TunnelError::new(
            CODE_PROBE_RATE_LIMITED,
            "该插件已有探测在飞，本次不排队",
        ));
    }
    if let Some(finished) = slot.finished_at {
        let elapsed = finished.elapsed();
        if elapsed < PROBE_COOLDOWN {
            return Err(TunnelError::new(
                CODE_PROBE_RATE_LIMITED,
                format!(
                    "冷却中（剩余 {} ms）",
                    PROBE_COOLDOWN.saturating_sub(elapsed).as_millis()
                ),
            ));
        }
    }
    slot.in_flight = true;
    slot.finished_at = None;
    Ok(ProbeGuard {
        plugin_id: plugin_id.to_string(),
        spent: false,
    })
}

// ==================== 域函数 ====================

/// `tunnel.probe-relay`：对已保存的 relay 地址做一次只读探测，返回 report JSON
pub fn probe_relay(
    ports: &Arc<dyn TunnelPorts>,
    plugin_id: &str,
    addrs_json: &str,
    timeout_ms: u32,
) -> Result<String, String> {
    require_probe(ports, plugin_id)?;
    let input = parse_input(addrs_json).map_err(|e| e.as_wire_error())?;
    let timeout = clamp_timeout(timeout_ms);
    let mut slot = acquire_probe_slot(plugin_id).map_err(|e| e.as_wire_error())?;

    let resolved = block_on(ports, resolve_and_validate(input)).map_err(|e| e.as_wire_error())?;
    slot.spent();
    let call = Arc::clone(ports);
    let report =
        block_on(ports, call.probe_relay(resolved, timeout)).map_err(|e| map_probe_error(e).as_wire_error())?;
    serde_json::to_string(&ProbeReportDto::from_report(&report))
        .map_err(|e| TunnelError::new(CODE_PEER_OFFLINE, format!("探测报告序列化失败：{e}")).as_wire_error())
}

fn require_probe(ports: &Arc<dyn TunnelPorts>, plugin_id: &str) -> Result<(), String> {
    if ports.check_permission(
        plugin_id,
        crate::wire::PERMISSION_TUNNEL_PROBE,
        "host_tunnel_probe_relay",
    ) {
        Ok(())
    } else {
        Err("permission denied: tunnel:probe".to_string())
    }
}

fn clamp_timeout(timeout_ms: u32) -> Duration {
    let ms = match timeout_ms {
        0 => PROBE_DEFAULT_TIMEOUT_MS,
        ms => ms.clamp(PROBE_MIN_TIMEOUT_MS, PROBE_MAX_TIMEOUT_MS),
    };
    Duration::from_millis(u64::from(ms))
}

/// JSON 数组 → multiaddr 列表（只做语法 / 条数校验；域名解析与形状校验在下一步）
fn parse_input(addrs_json: &str) -> Result<Vec<Multiaddr>, TunnelError> {
    let raw: Vec<String> =
        serde_json::from_str(addrs_json).map_err(|e| invalid(format!("relay-addrs-json 不是字符串数组：{e}")))?;
    if raw.is_empty() {
        return Err(invalid("relay 地址列表为空（先导入 relay 地址）"));
    }
    if raw.len() > PROBE_MAX_ADDRS {
        return Err(invalid(format!(
            "一次最多探测 {PROBE_MAX_ADDRS} 条地址（实得 {}）",
            raw.len()
        )));
    }
    let mut out = Vec::with_capacity(raw.len());
    for text in raw {
        let addr: Multiaddr = text
            .trim()
            .parse()
            .map_err(|e| invalid(format!("`{text}` 不是合法 multiaddr：{e}")))?;
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

/// 域名 → IP（宿主层 `lookup_host`）并校验端点形状 / 全候选同一 PeerId
///
/// - 端点形状：`.../tcp/<port>/p2p/<relay>`，不得含 `/p2p-circuit`；
/// - 跨 PeerId 的多地址一律拒绝：报告里的 `addr` / `peerId` 会指代不明；
/// - 解析后去重、保持声明顺序（首个成功即返回，顺序就是优先级）。
async fn resolve_and_validate(input: Vec<Multiaddr>) -> Result<Vec<Multiaddr>, TunnelError> {
    let mut resolved: Vec<Multiaddr> = Vec::new();
    let mut expected: Option<PeerId> = None;
    for addr in input {
        let candidates = resolve_relay_addr(&addr.to_string())
            .await
            .map_err(|e| invalid(format!("relay 地址解析失败（{addr}）：{e}")))?;
        for candidate in candidates {
            let endpoint =
                RelayEndpoint::parse(&candidate, expected).map_err(|e| invalid(format!("{candidate}：{e}")))?;
            expected = Some(endpoint.peer_id());
            if !resolved.contains(&candidate) {
                resolved.push(candidate);
            }
        }
    }
    if resolved.is_empty() {
        return Err(invalid("relay 地址列表解析后为空"));
    }
    Ok(resolved)
}

fn invalid(detail: impl Into<String>) -> TunnelError {
    TunnelError::new(CODE_RELAY_ADDRESS_INVALID, detail)
}

fn map_probe_error(e: wasmnest_p2p_engine::probe::ProbeError) -> TunnelError {
    use wasmnest_p2p_engine::probe::ProbeError;
    match e {
        ProbeError::AddressInvalid(detail) => TunnelError::new(CODE_RELAY_ADDRESS_INVALID, detail),
        ProbeError::IdentityMismatch(detail) => TunnelError::new(CODE_RELAY_IDENTITY_MISMATCH, detail),
        ProbeError::Unreachable(detail) => TunnelError::new(CODE_RELAY_UNREACHABLE, detail),
        ProbeError::NodeUnavailable(detail) => TunnelError::new(CODE_PEER_OFFLINE, detail),
    }
}

// ==================== report 形状（§4.2） ====================

/// WIT 返回的 JSON 形状（camelCase，`v` 为形状版本）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeReportDto {
    v: u32,
    addr: String,
    peer_id: String,
    peer_id_sha256: String,
    handshake_ms: u64,
    rtt_ms: Option<u64>,
    checked_at: String,
}

impl ProbeReportDto {
    fn from_report(report: &wasmnest_p2p_engine::probe::ProbeReport) -> Self {
        Self {
            v: 1,
            addr: report.addr.to_string(),
            peer_id: report.peer_id.to_string(),
            peer_id_sha256: report.peer_id_sha256.clone(),
            handshake_ms: ms(report.handshake),
            rtt_ms: report.rtt.map(ms),
            checked_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }
}

fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use wasmnest_p2p_engine::probe::{ProbeError, ProbeReport};

    use super::*;
    use crate::tunnel::manager::TunnelManager;
    use crate::tunnel::plugin_binding::{BoxedBlocked, BoxedProbe};
    use crate::wire::PERMISSION_TUNNEL_PROBE;

    const RELAY: &str = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA";
    const OTHER_RELAY: &str = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

    #[derive(Clone, Copy)]
    enum Canned {
        Ok,
        Unreachable,
        IdentityMismatch,
        NodeUnavailable,
    }

    struct FakePorts {
        granted: Vec<&'static str>,
        canned: Canned,
        probes: Arc<AtomicUsize>,
    }

    impl TunnelPorts for FakePorts {
        fn check_permission(&self, _plugin_id: &str, permission: &str, _api: &str) -> bool {
            self.granted.contains(&permission)
        }

        fn tunnel_manager(&self) -> Option<Arc<TunnelManager>> {
            None
        }

        fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send> {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("测试运行时")
                .block_on(fut)
        }

        fn probe_relay(&self, addrs: Vec<Multiaddr>, _timeout: Duration) -> BoxedProbe {
            self.probes.fetch_add(1, Ordering::SeqCst);
            let canned = self.canned;
            let addr = addrs.first().cloned().expect("被测地址非空");
            Box::pin(async move {
                match canned {
                    Canned::Ok => Ok(ProbeReport {
                        addr,
                        peer_id: "12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA".parse().unwrap(),
                        peer_id_sha256: "bc1420f7".to_string(),
                        handshake: Duration::from_millis(62),
                        rtt: Some(Duration::from_millis(65)),
                    }),
                    Canned::Unreachable => Err(ProbeError::Unreachable("127.0.0.1:4001 → 拒绝连接".into())),
                    Canned::IdentityMismatch => Err(ProbeError::IdentityMismatch("地址钉住 A，握手实测 B".into())),
                    Canned::NodeUnavailable => Err(ProbeError::NodeUnavailable("无运行时".into())),
                }
            })
        }
    }

    /// 返回（端口替身, 拨号计数）——计数留在外部，断言不必依赖类型擦除后的字段
    fn fake(granted: bool, canned: Canned) -> (Arc<dyn TunnelPorts>, Arc<AtomicUsize>) {
        let probes = Arc::new(AtomicUsize::new(0));
        let ports = Arc::new(FakePorts {
            granted: if granted { vec![PERMISSION_TUNNEL_PROBE] } else { vec![] },
            canned,
            probes: Arc::clone(&probes),
        });
        (ports as Arc<dyn TunnelPorts>, probes)
    }

    fn addrs_json(list: &[&str]) -> String {
        serde_json::to_string(list).expect("JSON 序列化")
    }

    #[test]
    fn 未声明权限_fail_closed() {
        let (ports, _probes) = fake(false, Canned::Ok);
        let err = probe_relay(&ports, "plugin.a", &addrs_json(&[RELAY]), 0).unwrap_err();
        assert_eq!(err, "permission denied: tunnel:probe");
    }

    #[test]
    fn 地址形状非法_在拨号前拒绝() {
        let (ports, probes) = fake(true, Canned::Ok);
        for bad in [
            addrs_json(&[]),
            addrs_json(&["not-a-multiaddr"]),
            addrs_json(&[RELAY, OTHER_RELAY]),
            addrs_json(&["/ip4/127.0.0.1/tcp/4001/p2p-circuit"]),
        ] {
            let err = probe_relay(&ports, "plugin.shape", &bad, 0).unwrap_err();
            assert!(
                err.starts_with("relay-address-invalid:"),
                "非法地址应归入 relay-address-invalid：{err}"
            );
        }
        assert_eq!(probes.load(Ordering::SeqCst), 0, "形状非法不得进入拨号");
    }

    #[test]
    fn 成功报告_字段齐全且为_camel_case() {
        let (ports, _probes) = fake(true, Canned::Ok);
        let json = probe_relay(&ports, "plugin.ok", &addrs_json(&[RELAY]), 0).expect("探测成功");
        let value: serde_json::Value = serde_json::from_str(&json).expect("合法 JSON");
        assert_eq!(value["v"], 1);
        assert_eq!(value["addr"], RELAY);
        assert_eq!(value["peerId"], "12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA");
        assert_eq!(value["peerIdSha256"], "bc1420f7");
        assert_eq!(value["handshakeMs"], 62);
        assert_eq!(value["rttMs"], 65);
        assert!(
            value["checkedAt"].as_str().is_some_and(|s| s.ends_with('Z')),
            "checkedAt 应为 RFC3339 UTC：{json}"
        );
    }

    #[test]
    fn 引擎错误映射到契约错误码() {
        let cases = [
            (Canned::Unreachable, "relay-unreachable:"),
            (Canned::IdentityMismatch, "relay-identity-mismatch:"),
            (Canned::NodeUnavailable, "peer-offline:"),
        ];
        for (canned, prefix) in cases {
            let (ports, _probes) = fake(true, canned);
            let err = probe_relay(&ports, &format!("plugin.{prefix}"), &addrs_json(&[RELAY]), 5_000).unwrap_err();
            assert!(err.starts_with(prefix), "错误码映射漂移：{err}");
        }
    }

    #[test]
    fn 超时参数_按上下限夹取() {
        assert_eq!(clamp_timeout(0), Duration::from_millis(8_000));
        assert_eq!(clamp_timeout(10), Duration::from_millis(1_000));
        assert_eq!(clamp_timeout(5_000), Duration::from_millis(5_000));
        assert_eq!(clamp_timeout(60_000), Duration::from_millis(15_000));
    }

    #[test]
    fn 连点_冷却期内返回限流_冷却后可再测() {
        let (ports, probes) = fake(true, Canned::Ok);
        probe_relay(&ports, "plugin.rate", &addrs_json(&[RELAY]), 0).expect("首次探测");
        let err = probe_relay(&ports, "plugin.rate", &addrs_json(&[RELAY]), 0).unwrap_err();
        assert!(err.starts_with("probe-rate-limited:"), "冷却期内应限流：{err}");
        assert_eq!(probes.load(Ordering::SeqCst), 1, "限流不得拨号");

        std::thread::sleep(PROBE_COOLDOWN + Duration::from_millis(50));
        probe_relay(&ports, "plugin.rate", &addrs_json(&[RELAY]), 0).expect("冷却后可再测");
        assert_eq!(probes.load(Ordering::SeqCst), 2);
    }

    /// 在飞探测期间第二次调用：**立即**限流（不排队、不并发拨号）
    #[test]
    fn 在飞探测_第二次调用立即限流() {
        use std::sync::atomic::AtomicBool;

        struct BlockingHost {
            entered: Arc<AtomicBool>,
            release: Arc<AtomicBool>,
        }

        impl TunnelPorts for BlockingHost {
            fn check_permission(&self, _plugin_id: &str, permission: &str, _api: &str) -> bool {
                permission == PERMISSION_TUNNEL_PROBE
            }

            fn tunnel_manager(&self) -> Option<Arc<TunnelManager>> {
                None
            }

            fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send> {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("测试运行时")
                    .block_on(fut)
            }

            fn probe_relay(&self, addrs: Vec<Multiaddr>, _timeout: Duration) -> BoxedProbe {
                let entered = Arc::clone(&self.entered);
                let release = Arc::clone(&self.release);
                let addr = addrs.first().cloned().expect("被测地址非空");
                Box::pin(async move {
                    entered.store(true, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Ok(ProbeReport {
                        addr,
                        peer_id: "12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA".parse().unwrap(),
                        peer_id_sha256: "bc1420f7".to_string(),
                        handshake: Duration::from_millis(10),
                        rtt: Some(Duration::from_millis(12)),
                    })
                })
            }
        }

        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let ports: Arc<dyn TunnelPorts> = Arc::new(BlockingHost {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });

        let first_ports = Arc::clone(&ports);
        let first = std::thread::spawn(move || probe_relay(&first_ports, "plugin.inflight", &addrs_json(&[RELAY]), 0));
        // 等第一轮真的进入探测阶段（已持锁）
        while !entered.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }

        let err = probe_relay(&ports, "plugin.inflight", &addrs_json(&[RELAY]), 0).unwrap_err();
        assert!(
            err.starts_with("probe-rate-limited:"),
            "在飞期间第二次调用必须立即限流：{err}"
        );

        release.store(true, Ordering::SeqCst);
        first.join().expect("首轮线程不应 panic").expect("首轮探测应成功");
    }
}
