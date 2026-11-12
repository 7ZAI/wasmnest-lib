//! 本机 peer 节点投影（`host-peer.node-info` / `configure-relay` 返回面，T21）。
//!
//! 与隧道管理器的 `NodeSnapshot` 同口径：**只有 relay 预留真正生效
//! （`RelayState::Reserved`）时才把 circuit 地址放进 `addrs`**——`Connecting` /
//! `Lost` 的端点只是「最近一次尝试的地址」，写进连接串会让对端拨一个不可用地址。
//!
//! 身份 / 监听地址来自共享 `PeerCtx` 的 runtime（单节点语义，与 tunnel 同源）；
//! 不返回任何票据、长期密钥或中继控制面细节。

use serde::Serialize;
use wasmnest_p2p_engine::Multiaddr;

use crate::PeerCtx;

/// 本机节点只读投影（WIT `peer-node-info` 的 Rust 侧形状，camelCase 序列化）
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeInfo {
    /// 本机节点 id（64 位小写 hex）
    pub node_id: String,
    /// 生效的设备名（空 = 宿主未命名）
    pub device_name: String,
    /// 可拨 multiaddr（LAN 在前；仅 `Reserved` 时追加 circuit）
    pub addrs: Vec<String>,
    /// relay-idle / relay-connecting / relay-reserved / relay-lost
    pub relay_state: String,
}

/// 读当前节点投影；节点未启动时显性报错（不返回空身份冒充「未命名设备」）。
///
/// # Errors
/// - 节点未启动；
/// - 节点运行时状态锁中毒（进程级不变量被破坏）。
pub(crate) async fn snapshot(ctx: &PeerCtx) -> Result<NodeInfo, String> {
    let runtime = ctx.state.runtime.lock().await;
    let runtime = runtime.as_ref().ok_or_else(|| "peer node not running".to_string())?;
    let engine = runtime.running.p2p_handle();
    let status = engine.relay_status();
    let relay_addr = crate::tunnel::manager::advertised_relay_addr(status.state, status.relay_addr.as_ref());
    let addrs = crate::tunnel::manager::dialable_addrs(
        &engine.listen_addresses(),
        &crate::tunnel::netinfo::dialable_ipv4_addrs(),
        relay_addr.as_deref(),
        &engine.peer_id().to_string(),
    );
    Ok(NodeInfo {
        node_id: runtime.node_id.clone(),
        device_name: runtime.device_name.clone(),
        addrs,
        relay_state: status.state.as_str().to_string(),
    })
}

/// 解析 / 校验 / 去重 relay 端点列表（`configure-relay` 入参）。
///
/// 与隧道管理器同一判据：`resolve_relay_addr`（域名 → IP）+ `RelayEndpoint::parse`
/// （钉住 `/p2p/<relay>`，拒绝 `/p2p-circuit`）。空列表合法（调用方决定语义）。
///
/// # Errors
/// 任一条地址非法 / 域名解析失败时整批拒绝并点名——静默丢弃会让「保存了但没生效」
/// 变成不可归因的假故障。
pub(crate) async fn resolve_relay_endpoints(raw: &[String]) -> Result<Vec<Multiaddr>, String> {
    let mut out: Vec<Multiaddr> = Vec::new();
    for item in raw {
        let text = item.trim();
        if text.is_empty() {
            return Err("relay address must not be empty".to_string());
        }
        let resolved = wasmnest_p2p_engine::relay::resolve_relay_addr(text)
            .await
            .map_err(|e| format!("relay address resolve failed ({text}): {e}"))?;
        for addr in resolved {
            wasmnest_p2p_engine::relay::RelayEndpoint::parse(&addr, None)
                .map_err(|e| format!("invalid relay endpoint ({addr}): {e}"))?;
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_keeps_ip_literals_and_deduplicates() {
        let raw = vec![
            "/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA".to_string(),
            "/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA".to_string(),
        ];
        let addrs = resolve_relay_endpoints(&raw).await.expect("valid relay");
        assert_eq!(addrs.len(), 1, "重复端点必须去重");
        assert_eq!(addrs[0].to_string(), raw[0]);
    }

    #[tokio::test]
    async fn resolve_rejects_circuit_targets() {
        let raw = vec![
            "/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA/p2p-circuit/p2p/12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA".to_string(),
        ];
        let err = resolve_relay_endpoints(&raw)
            .await
            .expect_err("circuit 目标不是中继端点");
        assert!(err.contains("p2p-circuit"), "got: {err}");
    }

    #[tokio::test]
    async fn resolve_rejects_empty_and_malformed() {
        assert!(resolve_relay_endpoints(&["".to_string()]).await.is_err());
        assert!(resolve_relay_endpoints(&["not-a-multiaddr".to_string()]).await.is_err());
    }

    #[tokio::test]
    async fn resolve_accepts_empty_list() {
        assert_eq!(
            resolve_relay_endpoints(&[])
                .await
                .expect("empty list is caller's policy"),
            Vec::<Multiaddr>::new()
        );
    }
}
