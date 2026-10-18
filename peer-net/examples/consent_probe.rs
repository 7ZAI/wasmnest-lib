//! 信任门实机探针：以指定身份直拨目标节点
//!
//! 用途一（默认临时身份）：验证 acceptor 侧「未知节点入站 → peer-consent-
//! requested 弹窗」链路——对端应弹首连确认框并在超时后自动拒绝。
//! 用途二（`--identity <dir>` 借用既有身份）：验证受信入站快速路径——对端
//! 直通接受并发出 peer-connected（入站连接事件桥验证）。
//!
//! 用法：`cargo run --example consent_probe -- <对端 addr:port> <对端完整
//! node_id> [--identity <身份目录>]`（对端 node_id 用于拨号侧证书钉扎；crate
//! 未开 rt-multi-thread，手动建 runtime）

use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:47613".to_string());
    let peer_node_id = args.get(2).cloned().unwrap_or_default();
    let identity_dir = args
        .iter()
        .position(|a| a == "--identity")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("wasmnest-consent-probe-{}", std::process::id()))
        });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    rt.block_on(async move {
        let identity = wasmnest_peer_net::NodeIdentity::load_or_create(&identity_dir)
            .expect("identity");
        let own = identity.node_id();
        println!(
            "[probe] own node_id={} (short {}), dialing {addr}",
            own.as_str(),
            own.short_fingerprint()
        );
        let node = wasmnest_peer_net::PeerNetNode::new(wasmnest_peer_net::PeerNetNodeConfig {
            bind_addr: "0.0.0.0:0".parse().expect("bind addr"),
            identity,
            static_peers: Vec::new(),
        })
        .expect("node");
        let peer_addr: std::net::SocketAddr = addr.parse().expect("peer addr");
        let record = wasmnest_peer_net::StaticPeerRecord {
            node_id: wasmnest_peer_net::NodeId::parse(&peer_node_id)
                .expect("valid peer node id"),
            addr: peer_addr,
        };
        println!("[probe] dialing...");
        match tokio::time::timeout(Duration::from_secs(70), node.dial(&record)).await {
            Ok(Ok(conn)) => {
                println!("[probe] CONNECTED (对端未弹确认或已信任)");
                // --hold <秒>：保持连接存活供对端 UI 连接态观察（默认立即关闭）
                let hold = std::env::args()
                    .position(|a| a == "--hold")
                    .and_then(|i| std::env::args().nth(i + 1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                if hold > 0 {
                    println!("[probe] holding connection for {hold}s...");
                    tokio::time::sleep(Duration::from_secs(hold)).await;
                }
                drop(conn);
            }
            Ok(Err(wasmnest_peer_net::PeerNetError::DialDeniedByPeer { .. })) => {
                println!("[probe] DENIED — 对端确认框超时拒绝（consent 弹窗已触发）")
            }
            Ok(Err(e)) => println!("[probe] dial error: {e}"),
            Err(_) => println!("[probe] 70s 超时——对端确认框仍等待人工应答（弹窗已触发）"),
        }
    });
}
