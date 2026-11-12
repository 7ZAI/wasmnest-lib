//! 配对连接注册表：把「哪条连接属于哪个已验证 peer / 是否处于配对窗口」
//! 交给对等 HTTP/WS 面的 [`PeerFaceResolver`]（T03 注入点）。
//!
//! 键是连接四元组（`SocketAddr`）。T03 的面标记注入在**每个请求**上调用解析器，
//! 故解析默认走非消费读；`consume` / `clear` 是连接关闭、配对成功或票据失效时的
//! 显式清理入口（由宿主按连接生命周期调用，不能按请求调用，否则 keep-alive
//! 的第二个请求会丢掉 face）。
//!
//! **安全默认**：查不到条目的连接返回「peer 面但无 nodeId」，绝不返回普通面——
//! 缺上下文不能把隧道流量升级为本机身份。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use wasmnest_server_base::face::{PeerFaceResolver, RequestFace};

use crate::base::identity::NodeId;
use crate::tunnel::{Result, TunnelError, CODE_NOT_MATCHED};

#[derive(Default)]
pub struct PairingRegistry {
    entries: Mutex<HashMap<SocketAddr, RequestFace>>,
}

impl PairingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记配对窗口连接：`pairing=true` 触发对等面路径白名单
    pub fn register_pairing(&self, key: SocketAddr, node_id: Option<String>) -> Result<()> {
        self.register(key, RequestFace::peer_face(node_id, true))
    }

    /// 配对成功提升为已匹配：立即去掉 `pairing` 标记，窗口不再限制该连接
    pub fn register_matched(&self, key: SocketAddr, node_id: String) -> Result<()> {
        if NodeId::parse(&node_id).is_err() {
            return Err(TunnelError::new(
                CODE_NOT_MATCHED,
                "已匹配 face 的 nodeId 必须是 64 位小写 hex",
            ));
        }
        self.register(key, RequestFace::peer_face(Some(node_id), false))
    }

    fn register(&self, key: SocketAddr, face: RequestFace) -> Result<()> {
        if !face.is_peer() {
            return Err(TunnelError::new(CODE_NOT_MATCHED, "隧道连接只能登记为 peer 面"));
        }
        if let Some(id) = face.peer_node_id.as_deref() {
            if NodeId::parse(id).is_err() {
                return Err(TunnelError::new(
                    CODE_NOT_MATCHED,
                    "face 的 nodeId 必须是 64 位小写 hex",
                ));
            }
        }
        self.entries
            .lock()
            .expect("pairing registry poisoned")
            .insert(key, face);
        Ok(())
    }

    /// 每请求解析：无条目时保持 peer 面但无身份 / 非配对态
    pub fn resolve(&self, key: &SocketAddr) -> RequestFace {
        self.entries
            .lock()
            .expect("pairing registry poisoned")
            .get(key)
            .cloned()
            .unwrap_or_else(|| RequestFace::peer_face(None, false))
    }

    /// 连接结束 / 窗口终止时消费条目
    pub fn consume(&self, key: &SocketAddr) -> Option<RequestFace> {
        self.entries.lock().expect("pairing registry poisoned").remove(key)
    }

    pub fn clear(&self, key: &SocketAddr) -> bool {
        self.consume(key).is_some()
    }

    pub fn clear_all(&self) {
        self.entries.lock().expect("pairing registry poisoned").clear();
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("pairing registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 供 `serve_peer_face(port, config, faces, Some(resolver))` 使用的闭包
    pub fn resolver(self: &Arc<Self>) -> PeerFaceResolver {
        let registry = Arc::clone(self);
        Arc::new(move |addr| registry.resolve(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn key(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// 安全锁：登记缺失绝不能回落到普通面（否则隧道流量会被当成本机）
    #[test]
    fn unknown_connection_stays_on_peer_face() {
        let registry = Arc::new(PairingRegistry::new());
        let resolver = registry.resolver();
        let face = resolver(&key(50001));
        assert!(face.is_peer());
        assert!(!face.is_pairing());
        assert!(face.peer_node_id.is_none());
        assert_ne!(face, RequestFace::local());
    }

    #[test]
    fn pairing_window_is_visible_to_resolver_and_clears_immediately() {
        let registry = Arc::new(PairingRegistry::new());
        let resolver = registry.resolver();
        let conn = key(50002);
        registry.register_pairing(conn, None).unwrap();

        let face = resolver(&conn);
        assert!(face.is_peer());
        assert!(face.is_pairing());
        assert!(face.peer_node_id.is_none());

        // 每请求解析不消费：同一连接的后续请求仍带面标记
        assert_eq!(resolver(&conn), face, "keep-alive 连接不得丢 face");

        assert!(registry.clear(&conn), "票据失效即清窗口");
        assert_eq!(resolver(&conn), RequestFace::peer_face(None, false));
        assert!(!registry.consume(&conn).map(|f| f.is_pairing()).unwrap_or(false));
    }

    #[test]
    fn promotion_to_matched_drops_pairing_restriction() {
        let registry = Arc::new(PairingRegistry::new());
        let resolver = registry.resolver();
        let conn = key(50003);
        registry.register_pairing(conn, None).unwrap();
        assert!(resolver(&conn).is_pairing());
        registry.register_matched(conn, NODE_A.into()).unwrap();
        let face = resolver(&conn);
        assert!(!face.is_pairing());
        assert_eq!(face.peer_node_id.as_deref(), Some(NODE_A));
        assert_eq!(registry.len(), 1);
        registry.clear_all();
        assert!(registry.is_empty());
    }

    #[test]
    fn forged_node_id_is_rejected() {
        let registry = PairingRegistry::new();
        assert!(registry.register_pairing(key(50004), Some("node-1".into())).is_err());
        assert!(registry.register_matched(key(50004), "NODE_A".into()).is_err());
        assert!(registry.is_empty(), "非法登记不得写入条目");
    }
}
