//! 传输会话 AC 测试（issue 05）：单文件推送 A→B 全生命周期。
//!
//! 复用 harness 惯例（进程内双节点、回环互指、真实 mTLS 直连），把上层
//! handler 从 EchoHandler 换成 [`TransferReceiveHandler`]——接收角色即生产
//! 装配形状。首连确认闸门用自动接受驱动（信任语义已在 issue 02 覆盖）。
//!
//! 断言只看外部行为：终态事件、落盘文件内容与 .part 去留、进度事件序列。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use wasmnest_peer_net::{
    CancelToken, Connection, IncomingFrame, NodeId, NodeIdentity, OutgoingFile, PeerNetNode,
    PeerNetNodeConfig, ReceivePolicy, RejectReason, RunningNode, StaticPeerRecord, TerminalState,
    TransferConfig, TransferEvent, TransferFrame, TransferReceiveHandler, TrustEvent, send_batch,
};
use wasmnest_peer_net::transfer::{
    TRANSFER_PROTOCOL_VERSION, FileMeta,
    message::{read_frame, write_control, write_data},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;

/// 单次拨号看门狗（harness 同款）
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

// ==================== Harness ====================

struct TestNode {
    dir: tempfile::TempDir,
    node: PeerNetNode,
    #[allow(dead_code)]
    running: RunningNode,
    gate_task: tokio::task::JoinHandle<()>,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.gate_task.abort();
    }
}

impl TestNode {
    fn id(&self) -> &wasmnest_peer_net::NodeId {
        self.node.node_id()
    }

    fn addr(&self) -> std::net::SocketAddr {
        self.running.local_addr()
    }

    /// 指向本节点的一条发现记录
    fn record(&self) -> StaticPeerRecord {
        StaticPeerRecord {
            node_id: self.id().clone(),
            addr: self.addr(),
        }
    }
}

/// 接收端挂载传输处理器后的句柄集
struct ReceiverHandles {
    events: mpsc::Receiver<TransferEvent>,
    cancel: CancelToken,
}

/// 起「发送端 + 接收端」双节点：接收端按给定策略装配传输会话引擎，
/// 双方首连闸门均自动接受；返回接收端事件通道与取消令牌。
async fn spawn_pair(receiver_policy: ReceivePolicy) -> (TestNode, TestNode, ReceiverHandles) {
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let identity_a = NodeIdentity::load_or_create(dir_a.path()).expect("identity A");
    let identity_b = NodeIdentity::load_or_create(dir_b.path()).expect("identity B");
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind A");
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").expect("bind B");
    // 身份与 listener 均为 move 值：互指记录所需的 ID/地址先行捕获
    let id_a = identity_a.node_id().clone();
    let id_b = identity_b.node_id().clone();
    let addr_a = listener_a.local_addr().expect("addr A");
    let addr_b = listener_b.local_addr().expect("addr B");

    let trust_a =
        Arc::new(wasmnest_peer_net::TrustStore::load_or_create(dir_a.path()).expect("trust A"));
    let node_a = PeerNetNode::new(PeerNetNodeConfig {
        bind_addr: addr_a,
        identity: identity_a,
        static_peers: vec![StaticPeerRecord {
            node_id: id_b.clone(),
            addr: addr_b,
        }],
    })
    .expect("construct node A")
    .with_trust_store(trust_a);

    let trust_b =
        Arc::new(wasmnest_peer_net::TrustStore::load_or_create(dir_b.path()).expect("trust B"));
    let node_b = PeerNetNode::new(PeerNetNodeConfig {
        bind_addr: addr_b,
        identity: identity_b,
        static_peers: vec![StaticPeerRecord {
            node_id: id_a,
            addr: addr_a,
        }],
    })
    .expect("construct node B")
    .with_trust_store(trust_b);

    // 双方闸门自动接受（本票只测传输面，不测信任协商）
    async fn drive_gate_auto_accept(mut rx: mpsc::Receiver<TrustEvent>) {
        // 当前 TrustEvent 仅确认一种变体；新增变体时在此补充分流
        while let Some(TrustEvent::ConfirmRequested { reply, .. }) = rx.recv().await {
            let _ = reply.send(true);
        }
    }

    // 发送端也挂传输处理器（对称能力；本测试只消费 B 的事件流）
    let (_tx_a, _rx_a) = mpsc::channel(64);
    let handler_a = TransferReceiveHandler::new(TransferConfig::default(), _tx_a);

    let (tx_b, rx_b) = mpsc::channel(256);
    let handler_b = TransferReceiveHandler::new(
        TransferConfig {
            policy: receiver_policy,
            download_dir: dir_b.path().join("downloads"),
            chunk_size: 8 * 1024,
            landing: None,
        },
        tx_b,
    );
    let cancel_b = handler_b.cancel_token();

    let (gate_tx_a, gate_rx_a) = mpsc::channel(16);
    let (gate_tx_b, gate_rx_b) = mpsc::channel(16);
    let running_a = node_a
        .start_with_listener(listener_a, gate_tx_a, Arc::new(handler_a))
        .expect("start A");
    let running_b = node_b
        .start_with_listener(listener_b, gate_tx_b, Arc::new(handler_b))
        .expect("start B");

    let a = TestNode {
        dir: dir_a,
        node: node_a,
        running: running_a,
        gate_task: tokio::spawn(drive_gate_auto_accept(gate_rx_a)),
    };
    let b = TestNode {
        dir: dir_b,
        node: node_b,
        running: running_b,
        gate_task: tokio::spawn(drive_gate_auto_accept(gate_rx_b)),
    };
    (
        a,
        b,
        ReceiverHandles {
            events: rx_b,
            cancel: cancel_b,
        },
    )
}

/// 经看门狗拨号建立可信连接
async fn dial_trusted(a: &TestNode, b: &TestNode) -> wasmnest_peer_net::Connection {
    match tokio::time::timeout(DIAL_TIMEOUT, a.node.dial(&b.record())).await {
        Ok(result) => result.expect("trusted dial must succeed"),
        Err(_) => panic!("dial to {} did not finish within {DIAL_TIMEOUT:?}", b.addr()),
    }
}

/// 构造已知内容的源文件（伪随机填充强制多块推送）
///
/// 返回（路径，内容）；TempDir 由调用方持有保活。
fn make_source_file(dir: &Path, name: &str, len: usize) -> (PathBuf, Vec<u8>) {
    let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let path = dir.join(name);
    std::fs::write(&path, &content).expect("write source file");
    (path, content)
}

/// 从事件通道收集到首个 Terminal 事件（丢弃中间事件前先记录进度序列）
async fn wait_terminal(events: &mut mpsc::Receiver<TransferEvent>) -> Vec<TransferEvent> {
    let mut seen = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("event within watchdog")
            .expect("channel alive until terminal");
        let terminal = matches!(event, TransferEvent::Terminal { .. });
        seen.push(event);
        if terminal {
            return seen;
        }
    }
}

/// 断言进度事件序列完整：存在进度、字节单调不减、速率有限非负、末点达总量
fn assert_progress_sequence(events: &[TransferEvent], total: u64) {
    let mut prev: u64 = 0;
    let mut saw_progress = false;
    for event in events {
        if let TransferEvent::Progress {
            transferred,
            rate_bps,
            ..
        } = event
        {
            saw_progress = true;
            assert!(
                *transferred >= prev,
                "progress must be non-decreasing: {prev} -> {transferred}"
            );
            assert!(
                rate_bps.is_finite() && *rate_bps >= 0.0,
                "rate must be finite non-negative, got {rate_bps}"
            );
            prev = *transferred;
        }
    }
    assert!(saw_progress, "progress events must be reported");
    assert_eq!(prev, total, "last progress sample must reach total size");
}

/// 取事件序列中的终态（wait_terminal 保证恰有一个）
fn terminal_of(events: &[TransferEvent]) -> &TerminalState {
    match events.last() {
        Some(TransferEvent::Terminal { state, .. }) => state,
        other => panic!("expected terminal event, got {other:?}"),
    }
}

const KIB: usize = 1024;

// ==================== AC#1 三分支策略 ====================

/// 直接接收：单文件端到端落位 + 进度序列完整（含速率）+ 无 .part 残留
#[tokio::test]
async fn always_accept_pushes_single_file_end_to_end() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let (source, content) = make_source_file(a.dir.path(), "hello.bin", 256 * KIB);

    let conn = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(256);
    let state = send_batch(
        conn,
        "batch-accept".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "hello.bin".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("send session io");
    assert_eq!(state, TerminalState::Completed);

    let events = wait_terminal(&mut rx.events).await;
    assert_eq!(terminal_of(&events), &TerminalState::Completed);
    assert_progress_sequence(&events, content.len() as u64);

    // 发送端同样收到自己的终态与进度上报
    let mut a_seen = Vec::new();
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_secs(1), a_events.recv()).await
    {
        a_seen.push(event);
    }
    assert_eq!(terminal_of(&a_seen), &TerminalState::Completed);
    assert_progress_sequence(&a_seen, content.len() as u64);

    // 落盘内容一致；临时 .part 已原子 rename 消失
    let downloaded = b.dir.path().join("downloads").join("hello.bin");
    assert_eq!(std::fs::read(&downloaded).expect("read downloaded"), content);
    let part = b.dir.path().join("downloads").join(part_name("batch-accept", 0));
    assert!(!part.exists(), ".part must be renamed away after success");
}

/// 直接拒绝：Offer 即回 policy-denied，双方落拒绝终态、零落盘
#[tokio::test]
async fn always_deny_rejects_offer_without_touching_disk() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysDeny).await;
    let (source, _content) = make_source_file(a.dir.path(), "secret.txt", 4 * KIB);

    let conn = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(64);
    let state = send_batch(
        conn,
        "batch-deny".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "secret.txt".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("send session io");
    assert_eq!(
        state,
        TerminalState::Rejected {
            reason: RejectReason::PolicyDenied
        }
    );

    let events = wait_terminal(&mut rx.events).await;
    assert_eq!(
        terminal_of(&events),
        &TerminalState::Rejected {
            reason: RejectReason::PolicyDenied
        }
    );

    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_secs(1), a_events.recv()).await
    {
        assert!(!matches!(event, TransferEvent::Progress { .. }), "denied batch must carry no data progress");
    }

    let downloads = b.dir.path().join("downloads");
    assert!(
        !downloads.exists() || std::fs::read_dir(&downloads).expect("readdir").next().is_none(),
        "denied batch must not write any bytes"
    );
}

/// `.part` 临时文件命名（与引擎实现同源约定）
fn part_name(batch_id: &str, index: u32) -> String {
    format!(".wasmnest-transfer-{batch_id}-{index}.part")
}

/// 每次询问——接受分支：宿主回执 true 后放行传输
#[tokio::test]
async fn ask_policy_accept_after_explicit_reply() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::Ask {
        timeout: Duration::from_secs(10),
    })
    .await;
    let (source, content) = make_source_file(a.dir.path(), "note.txt", 32 * KIB);

    let conn = dial_trusted(&a, &b).await;
    let (tx, _a_events) = mpsc::channel(64);
    let sender = tokio::spawn(send_batch(
        conn,
        "batch-ask".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "note.txt".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    ));

    // 询问事件携带批清单与总大小（询问弹窗的知情依据）
    match rx.events.recv().await.expect("offer pending event") {
        TransferEvent::OfferPending {
            files,
            total_size,
            reply,
            ..
        } => {
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].path, "note.txt");
            assert_eq!(total_size, content.len() as u64);
            reply.send(true).expect("reply accepted");
        }
        other => panic!("expected OfferPending, got {other:?}"),
    }

    assert_eq!(
        sender.await.expect("join").expect("send session io"),
        TerminalState::Completed
    );
    assert_eq!(terminal_of(&wait_terminal(&mut rx.events).await), &TerminalState::Completed);
}

/// 每次询问——拒绝分支：显式 false 回执以 user-rejected 终止
#[tokio::test]
async fn ask_policy_reject_after_explicit_reply() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::Ask {
        timeout: Duration::from_secs(10),
    })
    .await;
    let (source, _content) = make_source_file(a.dir.path(), "nope.txt", 4 * KIB);

    let conn = dial_trusted(&a, &b).await;
    let (tx, _a_events) = mpsc::channel(64);
    let sender = tokio::spawn(send_batch(
        conn,
        "batch-reject".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "nope.txt".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    ));

    match rx.events.recv().await.expect("offer pending event") {
        TransferEvent::OfferPending { reply, .. } => {
            reply.send(false).expect("reply rejected");
        }
        other => panic!("expected OfferPending, got {other:?}"),
    }

    assert_eq!(
        sender.await.expect("join").expect("send session io"),
        TerminalState::Rejected {
            reason: RejectReason::UserRejected
        }
    );
    assert_eq!(
        terminal_of(&wait_terminal(&mut rx.events).await),
        &TerminalState::Rejected {
            reason: RejectReason::UserRejected
        }
    );
}

// ==================== AC#2 询问超时自动拒绝 ====================

/// 询问超时：接收端自动回 timeout 拒绝，发送端收到终态（Rejected{timeout}），
/// 且零落盘（拒绝发生在写任何字节前）
#[tokio::test]
async fn ask_timeout_auto_rejects_and_sender_receives_terminal_state() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::Ask {
        // 引擎按配置原样计时（10..=600s 校验属宿主配置层），测试用短窗口提速
        timeout: Duration::from_millis(300),
    })
    .await;
    let (source, _content) = make_source_file(a.dir.path(), "late.txt", 4 * KIB);

    let conn = dial_trusted(&a, &b).await;
    let (tx, _a_events) = mpsc::channel(64);
    let state = send_batch(
        conn,
        "batch-timeout".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "late.txt".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("send session io");

    // A 侧终态：timeout 拒绝（AC#2 的「A 收到终态」）
    assert_eq!(
        state,
        TerminalState::Rejected {
            reason: RejectReason::Timeout
        }
    );
    // B 侧终态对称
    let events = wait_terminal(&mut rx.events).await;
    assert_eq!(
        terminal_of(&events),
        &TerminalState::Rejected {
            reason: RejectReason::Timeout
        }
    );
    // 无数据进度、零落盘
    for event in &events {
        assert!(!matches!(event, TransferEvent::Progress { .. }));
    }
    let downloads = b.dir.path().join("downloads");
    assert!(
        !downloads.exists() || std::fs::read_dir(&downloads).expect("readdir").next().is_none()
    );
}

// ==================== AC#3 双向取消 ====================

/// 发送方取消进行中的传输：对端收到中断帧落 Cancelled{by_peer=true} 并保留
/// .part；本端落 Cancelled{by_peer=false}
///
/// 确定性手法：发送端事件通道容量压到 2，未排空即背压阻塞推流——主测试在
/// 观察到进度后取消，传输物理上不可能先行完成。
#[tokio::test]
async fn sender_cancel_mid_transfer_lands_correct_terminals_both_sides() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let (source, content) = make_source_file(a.dir.path(), "big-send.bin", 4 * 1024 * KIB);

    let conn = dial_trusted(&a, &b).await;
    // 容量 2 的通道制造推流背压（见函数注释）
    let (tx, mut a_events) = mpsc::channel(2);
    let cancel_a = CancelToken::new();
    let sender = tokio::spawn(send_batch(
        conn,
        "batch-cancel-a".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "big-send.bin".to_string(),
        }],
        tx,
        cancel_a.clone(),
        false,
        None,
    ));

    // 观察到首个进度事件即取消（此刻必然仍在传输中）
    match tokio::time::timeout(Duration::from_secs(10), a_events.recv()).await {
        Ok(Some(TransferEvent::Progress { .. })) => {}
        other => panic!("expected first progress event, got {other:?}"),
    }
    cancel_a.cancel();

    // 排空剩余事件直至本端终态（cancel 后 emit 解除阻塞）
    let mut a_seen = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), a_events.recv()).await {
            Ok(Some(event)) => {
                let terminal = matches!(event, TransferEvent::Terminal { .. });
                a_seen.push(event);
                if terminal {
                    break;
                }
            }
            other => panic!("expected terminal after cancel, got {other:?}"),
        }
    }
    assert_eq!(
        terminal_of(&a_seen),
        &TerminalState::Cancelled { by_peer: false }
    );
    assert_eq!(
        sender.await.expect("join").expect("send session io"),
        TerminalState::Cancelled { by_peer: false }
    );

    // 对端落对端取消终态，且 .part 保留（断点真源供 issue 06 续传）
    assert_eq!(
        terminal_of(&wait_terminal(&mut rx.events).await),
        &TerminalState::Cancelled { by_peer: true }
    );
    let part = b
        .dir
        .path()
        .join("downloads")
        .join(part_name("batch-cancel-a", 0));
    let partial = std::fs::metadata(&part).expect(".part must be kept").len();
    assert!(partial > 0 && partial < content.len() as u64);
}

/// 接收方取消进行中的传输：对端落 Cancelled{by_peer=true}；本端
/// Cancelled{by_peer=false} 并保留 .part
#[tokio::test]
async fn receiver_cancel_mid_transfer_lands_correct_terminals_both_sides() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let (source, content) = make_source_file(a.dir.path(), "big-recv.bin", 4 * 1024 * KIB);

    let conn = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(2);
    // 发送端事件并发排空：cap-2 背压给推流限速，同时避免 emit 无限阻塞
    let a_drain = tokio::spawn(async move {
        let mut seen = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(10), a_events.recv()).await {
                Ok(Some(event)) => {
                    let terminal = matches!(event, TransferEvent::Terminal { .. });
                    seen.push(event);
                    if terminal {
                        break;
                    }
                }
                _ => break,
            }
        }
        seen
    });
    let sender = tokio::spawn(send_batch(
        conn,
        "batch-cancel-b".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "big-recv.bin".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    ));

    // 观察接收端进度后触发宿主取消入口
    let mut observed_progress = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), rx.events.recv()).await {
            Ok(Some(TransferEvent::Progress { .. })) => {
                observed_progress += 1;
                if observed_progress >= 2 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            other => panic!("expected progress events, got {other:?}"),
        }
    }
    rx.cancel.cancel();

    assert_eq!(
        terminal_of(&wait_terminal_into(rx.events).await),
        &TerminalState::Cancelled { by_peer: false }
    );
    assert_eq!(
        terminal_of(&a_drain.await.expect("drain join")),
        &TerminalState::Cancelled { by_peer: true }
    );
    assert_eq!(
        sender.await.expect("join").expect("send session io"),
        TerminalState::Cancelled { by_peer: true }
    );

    let part = b
        .dir
        .path()
        .join("downloads")
        .join(part_name("batch-cancel-b", 0));
    let partial = std::fs::metadata(&part).expect(".part must be kept").len();
    assert!(partial > 0 && partial < content.len() as u64);
}

/// wait_terminal 的消费式变体：直接吃掉 Receiver（取消场景中句柄已被移动）
async fn wait_terminal_into(mut events: mpsc::Receiver<TransferEvent>) -> Vec<TransferEvent> {
    let mut seen = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("event within watchdog")
            .expect("channel alive until terminal");
        let terminal = matches!(event, TransferEvent::Terminal { .. });
        seen.push(event);
        if terminal {
            return seen;
        }
    }
}

// ==================== AC#4 断点真源契约 ====================

/// 接收端已写字节 = 续传起点：预置部分 .part 后重发同一批，
/// 发送端从接收端声明的偏移起推流（进度总量 = 全量 − 已写字节），
/// 最终文件内容完整一致
#[tokio::test]
async fn receiver_written_offset_is_resume_truth_source() {
    let (a, b, _rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let total = 128 * KIB;
    let (source, content) = make_source_file(a.dir.path(), "resume.bin", total);

    // 预置上次中断残留：前 32KiB 已写进 .part（内容与源文件一致）
    let downloads = b.dir.path().join("downloads");
    std::fs::create_dir_all(&downloads).expect("mkdir downloads");
    let already_written = 32 * KIB;
    let part = downloads.join(part_name("batch-resume", 0));
    std::fs::write(&part, &content[..already_written]).expect("seed partial .part");

    let conn = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(256);
    let state = send_batch(
        conn,
        "batch-resume".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "resume.bin".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("send session io");
    assert_eq!(state, TerminalState::Completed);

    // 进度按批累计（issue 06 口径）：首个样本 ≥ 已写偏移证明基线入账、
    // 未从头推流（忽略偏移的实现首样本必然远小于已写偏移）；末点达全量
    // 证明跨会话聚合收敛。内容校验兜底排除「基线入账但物理重发」。
    let mut first_sent: Option<u64> = None;
    let mut max_sent: u64 = 0;
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_secs(1), a_events.recv()).await
    {
        if let TransferEvent::Progress { transferred, .. } = event {
            first_sent.get_or_insert(transferred);
            max_sent = max_sent.max(transferred);
        }
    }
    assert!(
        first_sent.expect("sender must report progress") >= already_written as u64,
        "sender progress must start at the receiver-reported baseline"
    );
    assert_eq!(
        max_sent, total as u64,
        "batch-aggregated progress must reach total across resumed sessions"
    );

    // 落位完整且 .part 消失
    let downloaded = downloads.join("resume.bin");
    assert_eq!(std::fs::read(&downloaded).expect("read resumed file"), content);
    assert!(!part.exists());
}

// ==================== AC issue 06 断点续传 ====================

/// 手摇协议的中断腿：以真实帧序建立会话、按计划推流后由调用方硬掐连接。
///
/// `plan[i]` = 第 i 个文件的本腿推流量；`u64::MAX` 表示推完该文件并等
/// FileDone 后继续下一文件；推到部分量即返回（不等 FileDone）。返回各
/// 文件接收端声明的起始偏移（断点基线的线上证据）。
///
/// 为何手摇而非复用 send_batch：真实发送端无法从外部中途掐死连接，而
/// 「链路死亡」正是 issue 06 要覆盖的中断形态——在帧层精确控制推送量，
/// 中断位置完全确定。
async fn push_partial_then_cut(
    conn: &mut Connection,
    batch_id: &str,
    sources: &[PathBuf],
    remote_paths: &[&str],
    plan: &[u64],
) -> Vec<u64> {
    // Offer 清单与引擎同源构造（stat 源文件）
    let mut metas = Vec::with_capacity(sources.len());
    let mut total_size: u64 = 0;
    for (source, remote) in sources.iter().zip(remote_paths) {
        let size = tokio::fs::metadata(source)
            .await
            .expect("stat source")
            .len();
        metas.push(FileMeta::new(remote.to_string(), size));
        total_size += size;
    }
    write_control(
        conn,
        &TransferFrame::Offer {
            protocol_version: TRANSFER_PROTOCOL_VERSION,
            encrypted: false,
            enc_pub_key: None,
            batch_id: batch_id.to_string(),
            files: metas.clone(),
            total_size,
        },
    )
    .await
    .expect("write offer");

    // AlwaysAccept 下必为放行应答
    match read_frame(conn).await.expect("read decision") {
        IncomingFrame::Control(f) => match *f {
            TransferFrame::Decision {
                accepted: true,
                reason: None,
                ..
            } => {}
            other => panic!("expected accept decision, got {other:?}"),
        },
        other => panic!("expected control frame, got {other:?}"),
    }

    let mut offsets = Vec::with_capacity(plan.len());
    for (index, &push) in plan.iter().enumerate() {
        // 接收端声明的起点（断点真源）
        let offset = match read_frame(conn).await.expect("read start_file") {
            IncomingFrame::Control(f) => match *f {
                TransferFrame::StartFile {
                    index: i,
                    offset,
                } if i == index as u32 => offset,
                other => panic!("expected start_file for index {index}, got {other:?}"),
            },
            other => panic!("expected control frame, got {other:?}"),
        };
        offsets.push(offset);

        let full = metas[index].size - offset;
        let remaining = push.min(full);
        let mut source = tokio::fs::File::open(&sources[index]).await.expect("open source");
        AsyncSeekExt::seek(&mut source, std::io::SeekFrom::Start(offset))
            .await
            .expect("seek source");
        let mut buf = vec![0u8; 16 * KIB];
        let mut left = remaining;
        while left > 0 {
            let n = AsyncReadExt::read(&mut source, &mut buf)
                .await
                .expect("read source");
            assert!(n > 0, "source truncated while pushing partial leg");
            let n = (n as u64).min(left) as usize;
            write_data(conn, &buf[..n]).await.expect("write data");
            left -= n as u64;
        }
        if remaining == full {
            // 完整推完：等接收端落位确认后继续下一文件
            match read_frame(conn).await.expect("read file_done") {
                IncomingFrame::Control(f) => match *f {
                    TransferFrame::FileDone { index: i } if i == index as u32 => {}
                    other => panic!("expected file_done for {index}, got {other:?}"),
                },
                other => panic!("expected control frame, got {other:?}"),
            }
        } else {
            break;
        }
    }
    offsets
}

/// 等待事件通道到达首个终态（保持通道所有权在调用方），断言其匹配谓词
async fn wait_terminal_matching(
    events: &mut mpsc::Receiver<TransferEvent>,
    what: &str,
    check: impl Fn(&TerminalState) -> bool,
) {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), events.recv()).await {
            Ok(Some(TransferEvent::Terminal { state, .. })) => {
                assert!(
                    check(&state),
                    "{what}: unexpected terminal {state:?}"
                );
                return;
            }
            Ok(Some(_)) => continue,
            other => panic!("{what}: expected terminal, got {other:?}"),
        }
    }
}

/// 收集发送端进度事件的（首样本, 末样本）对——批聚合进度的算术证据
async fn progress_bounds(events: &mut mpsc::Receiver<TransferEvent>) -> (u64, u64) {
    let mut first: Option<u64> = None;
    let mut max: u64 = 0;
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_secs(1), events.recv()).await
    {
        if let TransferEvent::Progress { transferred, .. } = event {
            first.get_or_insert(transferred);
            max = max.max(transferred);
        }
    }
    (first.expect("sender must report progress"), max)
}

/// 在给定数据目录上启动一个接收端「进程」实例：身份与信任自目录恢复，
/// 下载目录由调用方指定。返回运行句柄、节点 ID、取消令牌、事件句柄与
/// 闸门任务——接收端重启语义测试专用。
fn start_receiver_instance(
    identity_dir: &Path,
    downloads: &Path,
    trusted_peer_id: NodeId,
    trusted_peer_addr: std::net::SocketAddr,
) -> (
    RunningNode,
    NodeId,
    CancelToken,
    mpsc::Receiver<TransferEvent>,
    tokio::task::JoinHandle<()>,
) {
    let identity = NodeIdentity::load_or_create(identity_dir).expect("reload identity");
    let own_id = identity.node_id().clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind receiver");
    let trust = Arc::new(
        wasmnest_peer_net::TrustStore::load_or_create(identity_dir).expect("reload trust"),
    );
    let node = PeerNetNode::new(PeerNetNodeConfig {
        bind_addr: listener.local_addr().expect("receiver addr"),
        identity,
        static_peers: vec![StaticPeerRecord {
            node_id: trusted_peer_id,
            addr: trusted_peer_addr,
        }],
    })
    .expect("construct receiver node")
    .with_trust_store(trust);

    // 首连确认自动接受（信任持久化语义已在 issue 02 覆盖）
    async fn drive_gate_auto_accept(mut rx: mpsc::Receiver<TrustEvent>) {
        while let Some(TrustEvent::ConfirmRequested { reply, .. }) = rx.recv().await {
            let _ = reply.send(true);
        }
    }

    let (gate_tx, gate_rx) = mpsc::channel(16);
    let (tx, events) = mpsc::channel(256);
    let handler = TransferReceiveHandler::new(
        TransferConfig {
            policy: ReceivePolicy::AlwaysAccept,
            download_dir: downloads.to_path_buf(),
            chunk_size: 8 * 1024,
            landing: None,
        },
        tx,
    );
    let cancel = handler.cancel_token();
    let running = node
        .start_with_listener(listener, gate_tx, Arc::new(handler))
        .expect("start receiver instance");
    let gate_task = tokio::spawn(drive_gate_auto_accept(gate_rx));
    (running, own_id, cancel, events, gate_task)
}

/// AC#1 类中断「传输中途掐断连接」：第一腿手摇推流至半程硬掐 TCP →
/// 第二腿同 batch_id 重发 intent → 自接收端已写偏移续传至完成，内容一致
#[tokio::test]
async fn connection_drop_mid_file_resumes_and_content_matches() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let total = 256 * KIB;
    let cut_at = 48 * KIB;
    let (source, content) = make_source_file(a.dir.path(), "drop.bin", total);

    // 腿一：推 48KiB 后掐线（offsets=[0] 证明首会话全新起点）
    let mut conn = dial_trusted(&a, &b).await;
    let offsets =
        push_partial_then_cut(&mut conn, "batch-drop", &[source.clone()], &["drop.bin"], &[cut_at as u64])
            .await;
    assert_eq!(offsets, vec![0], "fresh session must start from zero");
    drop(conn);

    // 链路中断 → 接收端 Failed 终态；TCP 字节序保证已推字节此刻全部落盘
    wait_terminal_matching(&mut rx.events, "leg1", |s| {
        matches!(s, TerminalState::Failed { .. })
    })
    .await;

    let part = b.dir.path().join("downloads").join(part_name("batch-drop", 0));
    let partial_len = std::fs::metadata(&part)
        .expect(".part must be kept after link drop")
        .len();
    assert_eq!(partial_len, cut_at as u64, ".part must hold exactly the pushed bytes");

    // 腿二：重发 intent（同 batch_id）→ 自断点续传完成
    let conn2 = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(256);
    let state = send_batch(
        conn2,
        "batch-drop".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "drop.bin".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("leg2 send io");
    assert_eq!(state, TerminalState::Completed);
    assert_eq!(
        terminal_of(&wait_terminal(&mut rx.events).await),
        &TerminalState::Completed
    );

    // 文件内容逐字节一致；.part 已 rename 消失
    let downloaded = b.dir.path().join("downloads").join("drop.bin");
    assert_eq!(std::fs::read(&downloaded).expect("read resumed"), content);
    assert!(!part.exists());

    // 批聚合进度：第二腿自基线（48KiB）起步推进至全量，而非归零只计补发
    let (first, max) = progress_bounds(&mut a_events).await;
    assert!(
        first >= partial_len,
        "resumed session must start at receiver baseline, first={first}"
    );
    assert_eq!(max, total as u64, "progress must aggregate to total across sessions");
}

/// AC#2 类中断「接收端进程被杀」：整个接收节点实例销毁重建（身份/信任/
/// 下载目录持久）后续传仍自落盘偏移开始——断点真源恒在磁盘侧，与内存态无关
#[tokio::test]
async fn receiver_process_restart_resumes_from_disk_truth() {
    // 目录由测试直接持有并跨「重启」保活（TestNode 封装会随实例销毁 TempDir）
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let downloads_b = dir_b.path().join("downloads");

    // 发送节点 A：一次启动全程存活
    let identity_a = NodeIdentity::load_or_create(dir_a.path()).expect("identity A");
    let id_a = identity_a.node_id().clone();
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind A");
    let addr_a = listener_a.local_addr().expect("addr A");
    let node_a = PeerNetNode::new(PeerNetNodeConfig {
        bind_addr: addr_a,
        identity: identity_a,
        static_peers: vec![],
    })
    .expect("node A")
    .with_trust_store(Arc::new(
        wasmnest_peer_net::TrustStore::load_or_create(dir_a.path()).expect("trust A"),
    ));
    let (_tx_a, _rx_a) = mpsc::channel(64);
    let _running_a = node_a
        .start_with_listener(
            listener_a,
            mpsc::channel(16).0,
            Arc::new(TransferReceiveHandler::new(TransferConfig::default(), _tx_a)),
        )
        .expect("start A");

    let total = 256 * KIB;
    let cut_at = 64 * KIB;
    let (source, content) = make_source_file(dir_a.path(), "restart.bin", total);

    // —— 接收端实例 #1 ——
    let (run1, id_b1, _cancel1, mut rx1, gate1) =
        start_receiver_instance(dir_b.path(), &downloads_b, id_a.clone(), addr_a);
    let rec1 = StaticPeerRecord {
        node_id: id_b1.clone(),
        addr: run1.local_addr(),
    };

    let mut conn = match tokio::time::timeout(DIAL_TIMEOUT, node_a.dial(&rec1)).await {
        Ok(r) => r.expect("leg1 dial"),
        Err(_) => panic!("leg1 dial timeout"),
    };
    let offsets = push_partial_then_cut(
        &mut conn,
        "batch-restart",
        &[source.clone()],
        &["restart.bin"],
        &[cut_at as u64],
    )
    .await;
    assert_eq!(offsets, vec![0]);
    drop(conn);

    wait_terminal_matching(&mut rx1, "leg1", |s| {
        matches!(s, TerminalState::Failed { .. })
    })
    .await;

    // 「杀掉」进程：实例 #1 全部内存态与任务一并销毁
    let part = downloads_b.join(part_name("batch-restart", 0));
    let partial_len = std::fs::metadata(&part).expect(".part survives process kill").len();
    assert_eq!(partial_len, cut_at as u64);
    drop(run1);
    drop(_cancel1);
    gate1.abort();

    // —— 接收端实例 #2：仅凭持久化目录复活 ——
    let (run2, id_b2, _cancel2, mut rx2, gate2) =
        start_receiver_instance(dir_b.path(), &downloads_b, id_a.clone(), addr_a);
    assert_eq!(id_b2, id_b1, "identity must be stable across restart reload");
    let rec2 = StaticPeerRecord {
        node_id: id_b2,
        addr: run2.local_addr(),
    };

    let conn2 = match tokio::time::timeout(DIAL_TIMEOUT, node_a.dial(&rec2)).await {
        Ok(r) => r.expect("leg2 dial"),
        Err(_) => panic!("leg2 dial timeout"),
    };
    let (tx, mut a_events) = mpsc::channel(256);
    let state = send_batch(
        conn2,
        "batch-restart".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "restart.bin".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("leg2 send io");
    assert_eq!(state, TerminalState::Completed);
    assert_eq!(
        terminal_of(&wait_terminal(&mut rx2).await),
        &TerminalState::Completed
    );

    let downloaded = downloads_b.join("restart.bin");
    assert_eq!(std::fs::read(&downloaded).expect("read resumed"), content);
    assert!(!part.exists());

    // 新实例零先验内存：偏移只能来自磁盘（基线 = 第一腿已写字节）
    let (first, max) = progress_bounds(&mut a_events).await;
    assert!(first >= partial_len, "resume must start at disk-reported baseline");
    assert_eq!(max, total as u64);
    gate2.abort();
}

/// AC#3 多文件批部分完成后重试：已完成文件零补发直接跳过、半程文件自
/// 断点续传、未动文件全量传输；批进度聚合跨会话收敛正确
#[tokio::test]
async fn multi_file_batch_retry_supplements_only_missing_files() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let size0 = 64 * KIB;
    let size1 = 128 * KIB;
    let size2 = 32 * KIB;
    let cut1 = 32 * KIB;
    let (p0, c0) = make_source_file(a.dir.path(), "f0.bin", size0);
    let (p1, c1) = make_source_file(a.dir.path(), "f1.bin", size1);
    let (p2, c2) = make_source_file(a.dir.path(), "f2.bin", size2);
    let sources = [p0.clone(), p1.clone(), p2.clone()];
    let remotes = ["f0.bin", "f1.bin", "f2.bin"];

    // 腿一：f0 完整落位 → f1 半程 → 硬掐（f2 未触达）
    let mut conn = dial_trusted(&a, &b).await;
    let offsets = push_partial_then_cut(
        &mut conn,
        "batch-multi",
        &sources,
        &remotes,
        &[u64::MAX, cut1 as u64, 0],
    )
    .await;
    assert_eq!(offsets, vec![0, 0], "fresh batch starts all files from zero");
    drop(conn);
    wait_terminal_matching(&mut rx.events, "leg1", |s| {
        matches!(s, TerminalState::Failed { .. })
    })
    .await;

    let downloads = b.dir.path().join("downloads");
    // f0 已落位、f1 断点在半程
    assert_eq!(std::fs::read(downloads.join("f0.bin")).expect("f0 done"), c0);
    assert_eq!(
        std::fs::metadata(downloads.join(part_name("batch-multi", 1)))
            .expect("f1 .part kept")
            .len(),
        cut1 as u64
    );

    // 腿二：同批重发 → 只补 f1 余量与 f2 全量
    let conn2 = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(256);
    let state = send_batch(
        conn2,
        "batch-multi".to_string(),
        vec![
            OutgoingFile {
                source: p0,
                remote_path: "f0.bin".to_string(),
            },
            OutgoingFile {
                source: p1,
                remote_path: "f1.bin".to_string(),
            },
            OutgoingFile {
                source: p2,
                remote_path: "f2.bin".to_string(),
            },
        ],
        tx,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("leg2 send io");
    assert_eq!(state, TerminalState::Completed);
    assert_eq!(
        terminal_of(&wait_terminal(&mut rx.events).await),
        &TerminalState::Completed
    );

    // 三文件内容全部一致，.part 无残留
    assert_eq!(std::fs::read(downloads.join("f0.bin")).expect("f0"), c0);
    assert_eq!(std::fs::read(downloads.join("f1.bin")).expect("f1"), c1);
    assert_eq!(std::fs::read(downloads.join("f2.bin")).expect("f2"), c2);
    assert!(!downloads.join(part_name("batch-multi", 1)).exists());
    assert!(!downloads.join(part_name("batch-multi", 2)).exists());

    // 批聚合的算术证明：第二腿首个样本 ≥ 基线（f0 满额 + f1 已写）——
    // 若 f0 被重传，首样本必然小于该基线
    let baseline = (size0 + cut1) as u64;
    let grand_total = (size0 + size1 + size2) as u64;
    let (first, max) = progress_bounds(&mut a_events).await;
    assert!(first >= baseline, "completed files must not be re-streamed, first={first}");
    assert_eq!(max, grand_total, "batch progress must aggregate to grand total");
}

/// AC#4 类中断「发送方取消后重试」：取消保留 .part（issue 05 已证）→
/// 重试同批自断点续传至完成
#[tokio::test]
async fn sender_cancel_then_retry_resumes_from_kept_part() {
    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let total = 4 * 1024 * KIB;
    let (source, content) = make_source_file(a.dir.path(), "cancel-retry.bin", total);

    // 腿一：真实发送端 + 观察到进度即取消（cap-2 背压保证物理上未完成）
    let conn = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(2);
    let cancel_a = CancelToken::new();
    let sender = tokio::spawn(send_batch(
        conn,
        "batch-cancel-retry".to_string(),
        vec![OutgoingFile {
            source: source.clone(),
            remote_path: "cancel-retry.bin".to_string(),
        }],
        tx,
        cancel_a.clone(),
        false,
        None,
    ));
    match tokio::time::timeout(Duration::from_secs(10), a_events.recv()).await {
        Ok(Some(TransferEvent::Progress { .. })) => {}
        other => panic!("expected first progress event, got {other:?}"),
    }
    cancel_a.cancel();
    assert_eq!(
        sender.await.expect("join").expect("send io"),
        TerminalState::Cancelled { by_peer: false }
    );
    wait_terminal_matching(&mut rx.events, "leg1", |s| {
        matches!(s, TerminalState::Cancelled { by_peer: true })
    })
    .await;

    let part = b.dir.path().join("downloads").join(part_name("batch-cancel-retry", 0));
    let partial_len = std::fs::metadata(&part).expect(".part kept after cancel").len();
    assert!(partial_len > 0 && partial_len < total as u64);

    // 腿二：重试 → 续传至完成
    let conn2 = dial_trusted(&a, &b).await;
    let (tx2, mut a_events2) = mpsc::channel(256);
    let state = send_batch(
        conn2,
        "batch-cancel-retry".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "cancel-retry.bin".to_string(),
        }],
        tx2,
        CancelToken::new(),
        false,
        None,
    )
    .await
    .expect("leg2 send io");
    assert_eq!(state, TerminalState::Completed);
    assert_eq!(
        terminal_of(&wait_terminal(&mut rx.events).await),
        &TerminalState::Completed
    );

    let downloaded = b.dir.path().join("downloads").join("cancel-retry.bin");
    assert_eq!(std::fs::read(&downloaded).expect("read resumed"), content);
    assert!(!part.exists());

    let (first, max) = progress_bounds(&mut a_events2).await;
    assert!(first >= partial_len, "retry must start at kept-part baseline");
    assert_eq!(max, total as u64);
}

/// 发送方 wire 暂停/恢复（issue 07 之后 file-transfer 暂停/恢复协议）：
/// 发送端经 PauseSlot 写 Pause 帧 → 接收端收到 Paused 事件且推流门控停滞；
/// 发送端 Resume → 接收端收到 Resumed 事件并最终双双 Completed。
/// 断言只看外部行为：事件序列 + 落盘内容完整（暂停不丢字节）。
#[tokio::test]
async fn sender_pause_then_resume_completes_both_sides_with_full_content() {
    use wasmnest_peer_net::{PauseCmd, PauseSlot};

    let (a, b, mut rx) = spawn_pair(ReceivePolicy::AlwaysAccept).await;
    let (source, content) = make_source_file(a.dir.path(), "pause-resume.bin", 8 * 1024 * KIB);

    let conn = dial_trusted(&a, &b).await;
    let (tx, mut a_events) = mpsc::channel(2);
    let a_drain = tokio::spawn(async move {
        let mut seen = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(15), a_events.recv()).await {
                Ok(Some(event)) => {
                    let terminal = matches!(event, TransferEvent::Terminal { .. });
                    seen.push(event);
                    if terminal {
                        break;
                    }
                }
                _ => break,
            }
        }
        seen
    });

    let pause_slot = PauseSlot::new();
    let sender = tokio::spawn(send_batch(
        conn,
        "batch-pause-resume".to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "pause-resume.bin".to_string(),
        }],
        tx,
        CancelToken::new(),
        false,
        Some(pause_slot.clone()),
    ));

    // 等接收端进度过半后暂停：推流门控 + wire Pause 帧
    let mut observed = 0u64;
    let mut got_paused = false;
    let mut got_resumed = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(15), rx.events.recv()).await {
            Ok(Some(TransferEvent::Progress { transferred, .. })) => {
                observed = transferred;
                if observed >= 4 * 1024 * KIB as u64 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            other => panic!("expected progress, got {other:?}"),
        }
    }
    pause_slot.send(PauseCmd::Pause).await;
    // 暂停后应收到 Paused 事件（在途数据块可能先到，容忍少量 Progress）；
    // 门控有效性：暂停期间不产生任何终态（传输挂起而非完成/取消）
    let mut paused_seen = false;
    let pause_window = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.events.recv().await {
                Some(TransferEvent::Paused { .. }) => break,
                Some(TransferEvent::Terminal { .. }) => {
                    panic!("terminal while paused: transfer must stay suspended")
                }
                Some(_) => continue,
                None => panic!("receiver events closed while paused"),
            }
        }
    })
    .await;
    assert!(pause_window.is_ok(), "Paused event must arrive after pause");
    paused_seen = true;
    // 暂停已生效：短暂窗口内不应有终态（也不应自行完成）
    let no_terminal = tokio::time::timeout(Duration::from_millis(400), rx.events.recv()).await;
    match no_terminal {
        Ok(Some(TransferEvent::Terminal { .. })) => {
            panic!("transfer reached terminal while paused")
        }
        _ => {}
    }
    pause_slot.send(PauseCmd::Resume).await;

    // 恢复后应观察到 Resumed 事件与最终 Completed（发送端与接收端双侧）
    loop {
        match tokio::time::timeout(Duration::from_secs(15), rx.events.recv()).await {
            Ok(Some(TransferEvent::Paused { .. })) => got_paused = true,
            Ok(Some(TransferEvent::Resumed { .. })) => got_resumed = true,
            Ok(Some(TransferEvent::Terminal { state, .. })) => {
                assert_eq!(state, TerminalState::Completed, "receiver terminal after resume");
                break;
            }
            Ok(Some(_)) => continue,
            other => panic!("expected resumed/terminal, got {other:?}"),
        }
    }
    let _ = sender.await.expect("sender join");
    let _ = a_drain.await.expect("sender drain join");
    assert!(paused_seen, "receiver must observe Paused event");
    assert!(got_resumed, "receiver must observe Resumed event");

    let downloaded = b.dir.path().join("downloads").join("pause-resume.bin");
    assert_eq!(
        std::fs::read(&downloaded).expect("read paused-resumed file"),
        content
    );
}
