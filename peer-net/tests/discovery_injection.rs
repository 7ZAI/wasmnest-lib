//! 发现注入缝集成测试（issue 03 AC#1）：手工构造的 [`DiscoveredPeerRecord`] 经
//! [`DiscoveryCache::observe`] 喂入——与 mDNS 守护回调完全同一入口——产物经
//! [`DiscoveredPeerRecord::to_static_peer_record`] 直接拨号成功，证明注入缝的
//! 产物端到端可用于建立可信连接。
//!
//! 以 harness.rs 为模板的最小独立副本：本票只需双节点 + 恒接受闸门 + 回声
//! handler，闸门策略矩阵已在 harness.rs 覆盖，不在此重复。

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use wasmnest_peer_net::{
    CAP_FILE_TRANSFER, Connection, ConnectionHandler, DISCOVERY_PROTOCOL_VERSION,
    DiscoveryCache, DiscoveredPeerRecord, HandlerFuture, NodeIdentity, PeerNetNode,
    PeerNetNodeConfig, RunningNode, TrustEvent, TrustStore,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// 单次拨号看门狗：协议卡死快速失败而非挂死 CI
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

// ==================== Harness ====================

/// 进程内测试节点：数据目录存活期覆盖整个断言期
struct TestNode {
    /// 身份与可信列表文件的所在目录（TempDir drop 即清理）
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    node: PeerNetNode,
    /// 运行句柄：暴露真实监听地址；测试结束随 runtime 销毁全部任务
    running: RunningNode,
    gate_task: tokio::task::JoinHandle<()>,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        // gate 任务显式收尾；accept 循环无法在 Drop 中 async shutdown，
        // 随 #[tokio::test] 运行时结束统一销毁
        self.gate_task.abort();
    }
}

impl TestNode {
    fn addr(&self) -> SocketAddr {
        self.running.local_addr()
    }
}

/// 起两个测试节点：A 挂载发现缓存（被喂入方），B 为被发现方
async fn spawn_pair() -> (TestNode, TestNode) {
    // 先完成身份生成与端口占位，再统一组网（与 harness.rs 相同的防竞态次序）
    let mut dirs = Vec::with_capacity(2);
    let mut identities = Vec::with_capacity(2);
    let mut listeners = Vec::with_capacity(2);
    for _ in 0..2 {
        let dir = tempfile::tempdir().expect("create tempdir");
        let identity = NodeIdentity::load_or_create(dir.path()).expect("load_or_create identity");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback ephemeral port");
        dirs.push(dir);
        identities.push(identity);
        listeners.push(listener);
    }

    // 逐项消费预置向量：身份/目录/端口一一对应，i==0 即 A（挂缓存方）
    let nodes: Vec<TestNode> = dirs
        .into_iter()
        .zip(identities)
        .zip(listeners)
        .enumerate()
        .map(|(i, ((dir, identity), listener))| {
            let bind_addr = listener.local_addr().expect("read local addr");
            let trust =
                Arc::new(TrustStore::load_or_create(dir.path()).expect("load_or_create trust"));
            let mut node = PeerNetNode::new(PeerNetNodeConfig {
                bind_addr,
                identity,
                // 静态列表留空：本票的对端记录全部走发现注入缝
                static_peers: Vec::new(),
            })
            .expect("construct peer-net test node")
            .with_trust_store(trust);
            if i == 0 {
                // 仅 A 挂载缓存：注入缝的被喂入方
                node = node.with_discovery(Arc::new(DiscoveryCache::new()));
            }

            let (events_tx, events_rx) = mpsc::channel::<TrustEvent>(16);
            let gate_task = tokio::spawn(drive_gate_accept_all(events_rx));
            let running = node
                .start_with_listener(listener, events_tx, Arc::new(EchoHandler))
                .expect("start peer-net test node");

            TestNode {
                dir,
                node,
                running,
                gate_task,
            }
        })
        .collect();
    // 恰好两节点且 A 在前、B 在后（TestNode 无 Debug，不能用 expect 展示错误侧）
    let [a, b]: [TestNode; 2] = match nodes.try_into() {
        Ok(pair) => pair,
        Err(_) => panic!("expected exactly two nodes"),
    };
    (a, b)
}

// ==================== 测试助手 ====================

/// 回声 handler：把收到的字节原样写回直到连接关闭——证明信任放行后连通
struct EchoHandler;

impl ConnectionHandler for EchoHandler {
    fn handle(&self, conn: Connection) -> HandlerFuture {
        Box::pin(async move {
            let (mut rd, mut wr) = tokio::io::split(conn);
            // 对端关闭导致的 EOF/Reset 是回声循环的正常终点，无需上报
            tokio::io::copy(&mut rd, &mut wr).await.ok();
        })
    }
}

/// 恒接受闸门：本票聚焦「发现→拨号」链路而非确认策略（策略矩阵见 harness.rs）
async fn drive_gate_accept_all(mut events: mpsc::Receiver<TrustEvent>) {
    while let Some(event) = events.recv().await {
        match event {
            TrustEvent::ConfirmRequested { reply, .. } => {
                // 请求方已超时/关停时发送失败属预期：无后续动作可做
                if reply.send(true).is_err() {
                    // 对端已不再等待应答
                }
            }
        }
    }
}

// ==================== AC#1 端到端 ====================

/// 注入缝产物端到端可用：observe 进缓存且字段完整 → to_static_peer_record →
/// mTLS 拨号 → 回声往返。守护回调与单测走的是同一个 observe 入口。
#[tokio::test]
async fn injected_record_flows_through_cache_into_trusted_dial() {
    let (a, b) = spawn_pair().await;
    let cache = a.node.discovery().expect("A must have discovery cache attached");

    // 注入前缓存为空：记录确实来自本次喂入而非其他来源
    assert!(cache.list().is_empty(), "cache starts empty");

    // 手工构造指向 B 的发现记录——与守护回调在 ServiceResolved 时构造的形态完全一致
    let injected = DiscoveredPeerRecord {
        node_id: b.node.node_id().clone(),
        addr: b.addr(),
        device_name: "smoke-device-b".to_string(),
        protocol_version: DISCOVERY_PROTOCOL_VERSION,
        capabilities: CAP_FILE_TRANSFER,
        last_seen: std::time::Instant::now(),
    };
    cache.observe(injected);

    // 缓存可见且字段完整（AC#1 断言点：名称/版本/能力位随记录进入缓存）
    let cached = cache.get(b.node.node_id()).expect("injected record visible");
    assert_eq!(cached.device_name, "smoke-device-b");
    assert_eq!(cached.protocol_version, DISCOVERY_PROTOCOL_VERSION);
    assert_eq!(cached.capabilities, CAP_FILE_TRANSFER);
    assert_eq!(cached.addr, b.addr());

    // 注入缝产物直接可用于拨号：mTLS 握手 + 首连确认 + 双向落库全链路走通
    let record = cached.to_static_peer_record();
    let mut conn = match tokio::time::timeout(DIAL_TIMEOUT, a.node.dial(&record)).await {
        Ok(result) => result.expect("dial via discovered record must succeed"),
        Err(_) => panic!("dial did not finish within {DIAL_TIMEOUT:?}"),
    };

    // 字节级回声往返：连接真实可用而非仅握手成功
    conn.write_all(b"discovered and trusted").await.expect("echo write");
    conn.flush().await.expect("echo flush");
    let mut echoed = vec![0u8; b"discovered and trusted".len()];
    tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut echoed))
        .await
        .expect("echo within timeout")
        .expect("echo read_exact");
    assert_eq!(echoed, b"discovered and trusted");

    // 双向落库：发现驱动的首连同样建立持久信任
    assert!(a.node.trust().contains(b.node.node_id()), "initiator must persist peer");
    assert!(b.node.trust().contains(a.node.node_id()), "acceptor must persist peer");
}
