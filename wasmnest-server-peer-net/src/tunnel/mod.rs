//! 内网穿透通道机制（T05）：首帧线协议、暴露规则与准入、一次性配对票据、
//! 配对连接注册表、回环本地代理。
//!
//! **本模块不持有网络 I/O 的所有权**：流接收器由引擎注册、对等 HTTP/WS 面由宿主
//! 启动、`expose`/`connect` 的 WIT 绑定与节点生命周期由宿主装配（T06）。这里只提供
//! 「给出判据 + 可测机制」，宿主按本模块导出的类型接线，不重复实现安全判定。
//!
//! ## 安全口径
//!
//! - 默认不暴露任何端口；`kind=http` 的后端恒为对等 HTTP/WS 面，`kind=tcp` 只连
//!   回环且拒绝宿主管理端口。
//! - 未匹配 peer 一律拒绝（不变量 8）；唯一例外是有效配对票据开启的配对窗口，
//!   窗口内的路径白名单由对等面的面标记闸门执行（不变量 16）。
//! - 票据一次性、TTL ≤ 120s、绑定目标端口、不绑定接入路径（LAN / 中继均可）。
//! - 本地代理 listener 只绑 `127.0.0.1:0`（不变量 1）。

pub mod client;
pub mod frame;
pub mod manager;
pub mod mode;
pub mod netinfo;
pub mod pipe;
pub mod plugin_binding;
pub mod policy;
pub mod proxy;
pub mod registry;
pub mod server;
pub mod service;
pub mod ticket;

pub use client::{open_tunnel_stream, ClientConnector, TunnelStreamOpener};
pub use frame::{TunnelHello, TunnelKind, TunnelReply};
pub use manager::{
    ConnectEntry, NodeSnapshot, PeerCtxEngine, PeerFaceListener, PeerFaceStarter, RelaySnapshot, TunnelConfig,
    TunnelEngine, TunnelManager, TunnelStatus,
};
pub use mode::{
    DialFailure, LanCandidateSource, LanFailure, LanFailureVerdict, LanVerdict, ModeMachine, ModeReason, NetworkFacts,
    PeerModeView, Subnet, TransferMode, WanAvailability, LAN_RESTORE_PROBES,
};
pub use netinfo::{classify_interface, facts_from, system_network_facts, InterfaceFact, InterfaceKind};
pub use pipe::{pipe_with_limits, PipeLimits, PipeStats};
pub use policy::{Admission, AdmissionContext, Backend, ExposeConfig, ExposeRule, PolicyConfig, TunnelPolicy};
pub use proxy::{bind_loopback_proxy, run_proxy, AsyncStream, TunnelConnector, TunnelIo};
pub use registry::PairingRegistry;
pub use server::{BackendConnector, TunnelServer, TunnelStreamContext};
pub use service::{TunnelService, NET_TUNNEL_SERVICE_KEY};
pub use ticket::{AccessPath, TicketIssuer};

/// relay 控制面默认端口（`wasmnest-relay` 一键包，T13）：作为宿主管理端口
/// 进入 `kind=tcp` 黑名单，禁止应用把中继控制面当业务端口裸暴露。
pub const DEFAULT_RELAY_CONTROL_PORT: u16 = 4001;

/// `host-tunnel` 的原语集合（WIT 形状锁的对照面，顺序与契约分片一致）
pub const HOST_TUNNEL_FUNCTIONS: &[&str] = &[
    "configure",
    "expose",
    "unexpose",
    "connect",
    "close",
    "issue-pairing-ticket",
    "status",
];

// ==================== 错误码词表（设计 §7.1，通道层子集） ====================
//
// `invalid-frame` / `proxy-bind-failed` / `tunnel-idle` 是通道层新增的实现侧错误码：
// 分别拒绝畸形首帧 / 回环代理绑定失败 / 短连接 HTTP 流空闲回收。三者只回原因
// 类别，不回显票据或请求内容。设计 §7.1 的词表不是封闭集，新增项在应用仓 T05
// 实施记录里登记。

/// 应用配对或传输信任任一不成立，且无有效票据
pub const CODE_NOT_MATCHED: &str = "not-matched";
/// 配对票据过期 / 已使用 / 端口不符
pub const CODE_TICKET_EXPIRED: &str = "ticket-expired";
/// 端口未 expose、kind 不匹配、端口属于宿主管理面
pub const CODE_PORT_NOT_EXPOSED: &str = "port-not-exposed";
/// 并发 / 字节配额超限
pub const CODE_TUNNEL_LIMIT: &str = "tunnel-limit";
/// 本地代理句柄已关闭
pub const CODE_TUNNEL_CLOSED: &str = "tunnel-closed";
/// 短连接 HTTP 流空闲回收
pub const CODE_TUNNEL_IDLE: &str = "tunnel-idle";
/// 对端不在线 / 拨号失败
pub const CODE_PEER_OFFLINE: &str = "peer-offline";
/// 首帧 / 响应帧畸形
pub const CODE_INVALID_FRAME: &str = "invalid-frame";
/// 回环代理绑定失败
pub const CODE_PROXY_BIND_FAILED: &str = "proxy-bind-failed";
/// `allowWan=false` / 未配置 relay 地址，外网通道不可用（不变量 9 / 设计 §7.1）
pub const CODE_WAN_DISABLED: &str = "wan-disabled";
/// 同网段 LAN 不可达 / 服务未启动，判据不明确（设计 §7.1；带手动「尝试外网」出路）
pub const CODE_LAN_UNREACHABLE: &str = "lan-unreachable";
/// relay 连接失败 / 超时（设计 §7.1；不外溢成明文直连）
pub const CODE_RELAY_UNREACHABLE: &str = "relay-unreachable";
/// 本端不提供该通道形态（移动端无对等 HTTP/WS 面时 `expose` 显性失败）
pub const CODE_TUNNEL_UNAVAILABLE: &str = "tunnel-unavailable";
/// 非句柄属主的探测请求
pub const CODE_NOT_OWNER: &str = "not-owner";

/// 通道层错误：错误码 + 可展示原因（不含票据 / token 明文）
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct TunnelError {
    pub code: &'static str,
    pub detail: String,
}

impl TunnelError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// WIT `result<_, string>` 的错误形状：错误码在前，原因在后，便于宿主按码分派
    pub fn as_wire_error(&self) -> String {
        format!("{}: {}", self.code, self.detail)
    }
}

pub type Result<T> = std::result::Result<T, TunnelError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// 契约分片形状锁：独立包、六条原语、单 world，且不混进主插件包
    const WIT: &str = include_str!("../../wit/tunnel.wit");

    #[test]
    fn wit_shard_is_independent_package() {
        assert!(
            WIT.starts_with("package wasmnest:tunnel@0.0.1;"),
            "通道契约必须自持独立包与版本轴"
        );
        assert!(!WIT.contains("wasmnest:plugin"), "不得混进主插件包");
        assert!(WIT.contains("world cap-tunnel {"));
        assert_eq!(WIT.matches("interface ").count(), 1, "只声明一个 interface");
    }

    #[test]
    fn every_declared_primitive_has_a_wit_function() {
        for name in HOST_TUNNEL_FUNCTIONS {
            assert!(
                WIT.contains(&format!("{name}: func")),
                "WIT 缺原语 {name}，契约与实现登记表漂移"
            );
        }
        assert_eq!(HOST_TUNNEL_FUNCTIONS.len(), 7);
        assert!(WIT.contains("record expose-config"));
        assert!(WIT.contains("record tunnel-config"));
        assert!(WIT.contains("allow-wan: bool"));
        assert!(WIT.contains("relay-addrs-json: string"));
        assert!(WIT.contains("pairing-ticket: option<string>"));
    }

    /// `configure` 必须在 `expose` / `connect` 之前可独立调用（T06 的
    /// allowWan / relay 地址入口），且仍属 0.0.1 预发布线。
    #[test]
    fn configure_is_declared_before_any_service_primitive() {
        let configure = WIT.find("configure: func").expect("WIT 缺 configure");
        let expose = WIT.find("expose: func").expect("WIT 缺 expose");
        assert!(configure < expose, "configure 应声明在 expose 之前（契约阅读顺序）");
        assert!(WIT.contains("package wasmnest:tunnel@0.0.1;"));
    }

    #[test]
    fn wire_error_carries_code_without_echoing_secrets() {
        let err = TunnelError::new(CODE_TICKET_EXPIRED, "票据已使用");
        assert!(err.as_wire_error().starts_with("ticket-expired:"));
        assert_eq!(err.code, "ticket-expired");
    }
}
