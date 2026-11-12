//! 传输面标记（内网穿透 T03/T04 共用底座）
//!
//! 隧道流量在两端都呈现为 loopback：桌面经对等 HTTP/WS 面入站、移动经本地
//! 回环代理出站。任何按「源 IP / 目标环回」下信任判决的逻辑都会把远端误判
//! 成本机，故由 listener 在请求上下文注入 [`RequestFace`]，下游只认这个标记。
//! 标记只能由宿主写入 extensions，客户端自报的请求头一律不采信。

use std::net::SocketAddr;
use std::sync::Arc;

/// 一次请求所属的传输面（listener 级注入，进程内可读）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestFace {
    /// 是否来自对等 HTTP/WS 面（第二个 listener，只绑 loopback）
    pub peer: bool,
    /// 隧道层已验证的对端 node id；`None` = 未验证（不伪造、不写线协议字段）
    pub peer_node_id: Option<String>,
    /// 配对窗口：只放行配对端点，业务路径一律拒绝
    pub pairing: bool,
}

impl RequestFace {
    /// 普通面（既有 0.0.0.0 网关）：保持原来的环回 / 匿名语义
    pub const fn local() -> Self {
        Self {
            peer: false,
            peer_node_id: None,
            pairing: false,
        }
    }

    /// 对等面：`peer_node_id` 必须由隧道层验证后给出
    pub fn peer_face(peer_node_id: Option<String>, pairing: bool) -> Self {
        Self {
            peer: true,
            peer_node_id,
            pairing,
        }
    }

    pub fn is_peer(&self) -> bool {
        self.peer
    }

    pub fn is_pairing(&self) -> bool {
        self.pairing
    }
}

/// 对等面按连接四元组解析面上下文的注入点。
///
/// 配对连接注册表、已验证 node id 由宿主实现（T05 接线）；无解析器时退化为
/// 「peer 面但无 node id」，绝不因缺上下文而把请求升级为本机身份。
pub type PeerFaceResolver = Arc<dyn Fn(&SocketAddr) -> RequestFace + Send + Sync>;
