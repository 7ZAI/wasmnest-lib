//! 双节点测试 harness：进程内多实例、回环端口互指、真实 mTLS 直连。
//!
//! ticket 02 起本 harness 是对等网络行为票的主验证缝：
//!
//! - 占位 listener 经 [`PeerNetNode::start_with_listener`] 移交给节点（Decision 4），
//!   端口防竞态设计保留但不再由 TestNode 持有到断言结束；
//! - 内置 recording 闸门（计数确认回调 + 按脚本应答，默认拒绝）与
//!   [`EchoHandler`]（证明连通性的最小上层协议）；
//! - 可信存储注入文件版实例：AC#4/#5 的持久化语义在真实目录上验证。
//!
//! 后续行为票只需把静态列表换成发现回调喂入（同一 `StaticPeerRecord` 入口）。

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wasmnest_peer_net::{
    Connection, ConnectionHandler, HandlerFuture, NodeId, NodeIdentity, PeerNetError, PeerNetNode,
    PeerNetNodeConfig, RunningNode, StaticPeerRecord, TrustEvent, TrustStore,
    verify_cert_matches_node_id,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// 单次拨号的看门狗：协议卡死时快速失败而非挂死 CI（确认应答本身是即时的）
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

// ==================== Harness ====================

/// 进程内测试节点：数据目录存活期覆盖整个断言期
struct TestNode {
    /// 身份与可信列表文件的所在目录（TempDir drop 即清理）
    dir: tempfile::TempDir,
    node: PeerNetNode,
    /// 运行句柄：暴露真实监听地址；测试结束随 runtime 销毁全部任务
    #[allow(dead_code)]
    running: RunningNode,
    /// 录制型闸门：本节点的首连确认回调计数与脚本
    gate: RecordingGate,
    gate_task: tokio::task::JoinHandle<()>,
}

impl TestNode {
    fn id(&self) -> &NodeId {
        self.node.node_id()
    }

    fn addr(&self) -> SocketAddr {
        self.running.local_addr()
    }

    /// 指向本节点的一条发现记录（供他方拨入）
    fn record(&self) -> StaticPeerRecord {
        StaticPeerRecord {
            node_id: self.id().clone(),
            addr: self.addr(),
        }
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        // gate 任务显式收尾；accept 循环与连接任务无法在 Drop 中 async shutdown，
        // 随 #[tokio::test] 运行时结束统一销毁
        self.gate_task.abort();
    }
}

/// 起 n 个进程内测试节点，互相以 [`StaticPeerRecord`] 全互联注入（回环互指）
async fn spawn_test_nodes(n: usize) -> Vec<TestNode> {
    // 先完成全部身份生成与端口占位，再统一组网：
    // 保证注入的 addr 互不冲突，且对端身份在注入时已存在
    let mut dirs = Vec::with_capacity(n);
    let mut identities = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let dir = tempfile::tempdir().expect("create tempdir");
        let identity = NodeIdentity::load_or_create(dir.path()).expect("load_or_create identity");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback ephemeral port");
        dirs.push(dir);
        identities.push(identity);
        listeners.push(listener);
    }
    let addrs: Vec<_> = listeners
        .iter()
        .map(|l| l.local_addr().expect("read local addr"))
        .collect();
    let node_ids: Vec<_> = identities.iter().map(|i| i.node_id().clone()).collect();

    dirs.into_iter()
        .zip(identities)
        .zip(listeners)
        .enumerate()
        .map(|(i, ((dir, identity), listener))| {
            let bind_addr = listener.local_addr().expect("read local addr");
            let static_peers: Vec<StaticPeerRecord> = (0..n)
                .filter(|&j| j != i)
                .map(|j| StaticPeerRecord {
                    node_id: node_ids[j].clone(),
                    addr: addrs[j],
                })
                .collect();
            // 注入文件版可信存储：与身份同目录，撤销/落库跨实例可见
            let trust =
                Arc::new(TrustStore::load_or_create(dir.path()).expect("load_or_create trust"));
            let node = PeerNetNode::new(PeerNetNodeConfig {
                bind_addr,
                identity,
                static_peers,
            })
            .expect("construct peer-net test node")
            .with_trust_store(trust);

            let gate = RecordingGate::default();
            let (events_tx, events_rx) = mpsc::channel(16);
            let gate_task = tokio::spawn(drive_gate(events_rx, gate.clone()));
            // 占位 listener 移交给节点进入 accept 循环
            let running = node
                .start_with_listener(listener, events_tx, Arc::new(EchoHandler))
                .expect("start peer-net test node");

            TestNode {
                dir,
                node,
                running,
                gate,
                gate_task,
            }
        })
        .collect()
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

/// 录制型确认闸门：统计回调次数 + 按脚本应答（空脚本默认拒绝）
#[derive(Clone, Default)]
struct RecordingGate {
    requests: Arc<AtomicUsize>,
    decisions: Arc<Mutex<VecDeque<bool>>>,
}

impl RecordingGate {
    /// 预置下一次确认回调的应答；不预置则默认拒绝
    fn push_decision(&self, accept: bool) {
        self.decisions
            .lock()
            .expect("gate decisions lock poisoned")
            .push_back(accept);
    }

    /// 已收到的首连确认回调次数
    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// 消费宿主事件通道：每次确认回调计数一次并按脚本应答
///
/// 这是对宿主「弹窗后点接受/拒绝」的测试替身：真实宿主在此处唤起 UI。
async fn drive_gate(mut events: mpsc::Receiver<TrustEvent>, gate: RecordingGate) {
    while let Some(event) = events.recv().await {
        match event {
            TrustEvent::ConfirmRequested { node_id: _, reply } => {
                gate.requests.fetch_add(1, Ordering::SeqCst);
                let decision = gate
                    .decisions
                    .lock()
                    .expect("gate decisions lock poisoned")
                    .pop_front()
                    .unwrap_or(false);
                // 请求方已超时/关停时发送失败属预期：无后续动作可做
                if reply.send(decision).is_err() {
                    // 对端已不再等待应答
                }
            }
        }
    }
}

/// 带看门狗的拨号：超时即 panic 并指明卡死位置
async fn dial_with_timeout(
    dialer: &TestNode,
    record: &StaticPeerRecord,
) -> Result<Connection, PeerNetError> {
    match tokio::time::timeout(DIAL_TIMEOUT, dialer.node.dial(record)).await {
        Ok(result) => result,
        Err(_) => panic!("dial to {} did not finish within {DIAL_TIMEOUT:?}", record.addr),
    }
}

/// 断言一次字节级回声往返（写多少读回多少）
async fn assert_echo_roundtrip(conn: &mut Connection, payload: &[u8]) {
    conn.write_all(payload).await.expect("echo write");
    conn.flush().await.expect("echo flush");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut echoed))
        .await
        .expect("echo within timeout")
        .expect("echo read_exact");
    assert_eq!(echoed, payload, "echoed bytes must round-trip exactly");
}

// ==================== 既有测试（ticket 01 骨架，机械转 async）====================

#[tokio::test]
async fn two_nodes_hold_distinct_ids_with_mutual_peer_records() {
    let nodes = spawn_test_nodes(2).await;
    let [a, b] = nodes.as_slice() else {
        panic!("expected exactly two nodes");
    };

    // 各持身份且互不相同
    assert_ne!(a.node.node_id(), b.node.node_id());

    // 回环互指：a 的静态记录精确指向 b，反之亦然
    assert_eq!(
        a.node.static_peers(),
        &[StaticPeerRecord {
            node_id: b.node.node_id().clone(),
            addr: b.node.bind_addr(),
        }]
    );
    assert_eq!(
        b.node.static_peers(),
        &[StaticPeerRecord {
            node_id: a.node.node_id().clone(),
            addr: a.node.bind_addr(),
        }]
    );
}

#[tokio::test]
async fn every_node_certificate_passes_binding_check() {
    let nodes = spawn_test_nodes(2).await;

    for node in &nodes {
        assert!(
            verify_cert_matches_node_id(node.node.certificate(), node.node.node_id()),
            "node {} certificate must match its own node_id",
            node.node.node_id()
        );
    }
}

#[tokio::test]
async fn restarted_node_keeps_identity_stable_across_reload() {
    let dir = tempfile::tempdir().expect("create tempdir");

    // 第一次启动：生成并持久化身份
    let first = NodeIdentity::load_or_create(dir.path()).expect("first start");
    let expected_id = first.node_id().clone();
    let expected_pk = first.public_key_raw();

    // 「重启」：内存态销毁后仅凭持久化目录恢复
    drop(first);
    let restarted = NodeIdentity::load_or_create(dir.path()).expect("restart reload");

    assert_eq!(restarted.node_id(), &expected_id);
    assert_eq!(restarted.public_key_raw(), expected_pk);
}

// ==================== AC 测试（issue 02 验收标准对照）====================

/// AC#1 拒绝分支：未信任 A 拨 B → B 收到确认回调 → 拒绝 → A 失败、双方零落库；
/// 再次拨入再次触发回调（可重试语义）
#[tokio::test]
async fn untrusted_dial_denied_by_peer_and_can_retry() {
    let nodes = spawn_test_nodes(2).await;
    let [a, b] = nodes.as_slice() else {
        panic!("expected exactly two nodes");
    };
    let record = b.record();

    // 未预置决策 → 默认 Deny
    let err = dial_with_timeout(a, &record)
        .await
        .expect_err("default-deny must fail the dial");
    assert!(
        matches!(err, PeerNetError::DialDeniedByPeer { .. }),
        "expected DialDeniedByPeer, got: {err}"
    );
    assert_eq!(b.gate.request_count(), 1, "B must receive one confirm callback");

    // 双方均未落库（拒绝不产生信任）
    assert!(!a.node.trust().contains(b.id()));
    assert!(!b.node.trust().contains(a.id()));

    // 重试：新连接重新走闸门，回调再次触发
    let err_again = dial_with_timeout(a, &record)
        .await
        .expect_err("retry without approval must fail again");
    assert!(matches!(err_again, PeerNetError::DialDeniedByPeer { .. }));
    assert_eq!(b.gate.request_count(), 2, "retry must re-trigger the callback");
}

/// AC#1 接受分支：接受 → 连通且双方信任双向落库
#[tokio::test]
async fn accepted_first_connect_establishes_mutual_trust_and_connectivity() {
    let nodes = spawn_test_nodes(2).await;
    let [a, b] = nodes.as_slice() else {
        panic!("expected exactly two nodes");
    };
    b.gate.push_decision(true);

    let mut conn = dial_with_timeout(a, &b.record())
        .await
        .expect("approved first connect must succeed");

    // 连通性证明：字节级回声往返
    assert_echo_roundtrip(&mut conn, b"hello over mtls").await;

    // 双向落库：A 侧在收到 Accepted 帧后落库，B 侧在写 Accepted 帧前落库
    assert!(a.node.trust().contains(b.id()), "initiator must persist peer");
    assert!(b.node.trust().contains(a.id()), "acceptor must persist peer");
}

/// AC#2：已信任对端重连全程无确认回调（静默快路径）
#[tokio::test]
async fn trusted_peer_reconnects_silently_without_callback() {
    let nodes = spawn_test_nodes(2).await;
    let [a, b] = nodes.as_slice() else {
        panic!("expected exactly two nodes");
    };
    b.gate.push_decision(true);

    // 首连建立信任（触发过一次回调）
    let first = dial_with_timeout(a, &b.record()).await.expect("first connect");
    assert_eq!(b.gate.request_count(), 1);
    drop(first);

    // 重连：快路径直通，回调计数不变且连通
    let mut second = dial_with_timeout(a, &b.record())
        .await
        .expect("trusted reconnect must succeed silently");
    assert_eq!(
        b.gate.request_count(),
        1,
        "reconnect must not trigger any confirm callback"
    );
    assert_echo_roundtrip(&mut second, b"second round").await;
}

/// AC#3：证书指纹与期望身份不符 → TLS 层拒绝，应用层零感知
#[tokio::test]
async fn forged_identity_record_is_rejected_at_tls_layer_without_callbacks() {
    let nodes = spawn_test_nodes(3).await;
    let [a, b, c] = nodes.as_slice() else {
        panic!("expected exactly three nodes");
    };

    // 伪造发现记录：声称 C 的身份在 B 的地址上（地址劫持场景）
    let forged = StaticPeerRecord {
        node_id: c.id().clone(),
        addr: b.addr(),
    };
    let err = dial_with_timeout(a, &forged)
        .await
        .expect_err("pinned verifier must reject identity/address mismatch");
    assert!(
        matches!(err, PeerNetError::TlsBindingMismatch { .. }),
        "expected TlsBindingMismatch, got: {err}"
    );

    // TLS 层拒绝不得产生任何应用层事件或信任落库
    assert_eq!(b.gate.request_count(), 0, "B must stay unaware of the rejected dial");
    assert_eq!(c.gate.request_count(), 0);
    assert!(!a.node.trust().contains(c.id()));
    assert!(!b.node.trust().contains(a.id()));
}

/// AC#4：撤销信任后重连必须重新走首连确认
#[tokio::test]
async fn revoked_trust_requires_confirmation_again() {
    let nodes = spawn_test_nodes(2).await;
    let [a, b] = nodes.as_slice() else {
        panic!("expected exactly two nodes");
    };
    b.gate.push_decision(true);

    let first = dial_with_timeout(a, &b.record()).await.expect("initial connect");
    assert_eq!(b.gate.request_count(), 1);
    drop(first);

    // B 撤销 A（AC#5 的 API 面）
    let removed = b.node.trust().remove(a.id()).expect("revoke must not fail on disk");
    assert!(removed, "revoked id was trusted before");

    // 重连：B 不再静默放行，闸门重新介入；预置接受 → 二次确认后连通
    b.gate.push_decision(true);
    let mut reconfirmed = dial_with_timeout(a, &b.record())
        .await
        .expect("re-confirmation with approval must succeed");
    assert_eq!(
        b.gate.request_count(),
        2,
        "revoked peer must re-trigger the confirmation callback"
    );
    assert_echo_roundtrip(&mut reconfirmed, b"re-confirmed").await;
    assert!(b.node.trust().contains(a.id()), "re-approval must restore trust");
}

/// AC#5：撤销动作有 API 且落库持久——同目录重载反映 add/remove
#[tokio::test]
async fn trust_changes_persist_across_store_reload() {
    let nodes = spawn_test_nodes(2).await;
    let [a, b] = nodes.as_slice() else {
        panic!("expected exactly two nodes");
    };
    b.gate.push_decision(true);

    // 经真实连接流建立信任后：B 目录重载仍含 A（落库持久）
    let _conn = dial_with_timeout(a, &b.record()).await.expect("connect");
    let reloaded_b = TrustStore::load_or_create(b.dir.path()).expect("reload B store");
    assert!(reloaded_b.contains(a.id()), "accepted peer must survive reload");

    // 撤销后：新建实例同目录重载不含该 ID
    b.node.trust().remove(a.id()).expect("revoke");
    let after_revoke = TrustStore::load_or_create(b.dir.path()).expect("reload after revoke");
    assert!(
        !after_revoke.contains(a.id()),
        "revoked id must be absent from persisted store"
    );

    // A 侧对称验证：其发起侧落库同样持久
    let reloaded_a = TrustStore::load_or_create(a.dir.path()).expect("reload A store");
    assert!(reloaded_a.contains(b.id()), "initiator-side entry must persist");
}
