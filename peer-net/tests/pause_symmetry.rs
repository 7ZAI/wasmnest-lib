//! 双端暂停/恢复/取消对称性集成测试（文件传输插件链路验收）。
//!
//! 功能设计：**同一个传输任务，任意一端都能立即暂停、恢复、取消**；暂停/恢复
//! 不掐断连接、不丢断点（对端恢复后按落盘偏移续流）。覆盖矩阵：
//!
//! | 方向 | 本端角色 | 能力 | 用例 |
//! | --- | --- | --- | --- |
//! | push（对端发给我） | 接收方 | 本地暂停/恢复（wire 帧门控对端推流） | `push_receiver_pause_stops_sender_and_resume_completes` |
//! | push | 发送方 | 本地暂停/恢复 + 对端任务状态同步 | `push_sender_pause_syncs_receiver_task_and_resume_completes` |
//! | pull（我拉对端） | 供流方 | 本地暂停/恢复 + 按批取消 | `pull_serve_side_pause_stops_stream_and_resume_completes` / `pull_serve_side_cancel_interrupts_puller_and_keeps_partial` |
//!
//! 装配形状与生产一致：两端都挂 [`SharedDirHandler`]（宿主 runtime 持有的复合
//! 处理器），经真实 mTLS 回环直连驱动。「暂停已生效」只看外部行为——落盘
//! `.part` 尺寸在宽限期内不再增长、期间不出现终态，恢复后内容逐字节一致。
//!
//! 拉取方本地暂停、发送方取消、接收方取消已由 `shared_dirs.rs` /
//! `transfer_session.rs` 覆盖，本套件不重复。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use wasmnest_peer_net::{
    pull_shared_file, send_batch, CancelToken, NodeIdentity, OutgoingFile, PauseCmd, PauseSlot,
    PeerNetNode, PeerNetNodeConfig, ReceivePolicy, SharedDirHandler, SharedDirRoot, SharedDirStore,
    StaticPeerRecord, TerminalState, TransferConfig, TransferEvent, TrustEvent,
};
use tokio::sync::mpsc;

const MIB: usize = 1024 * 1024;

/// 单次拨号看门狗（harness 同款）
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// 事件看门狗：会话卡死时快速失败而非挂死 CI
const EVENT_TIMEOUT: Duration = Duration::from_secs(15);
/// 暂停生效宽限：在途数据（socket 缓冲 + 帧通道）排空所需，宽限期后必须停滞
const STALL_GRACE: Duration = Duration::from_secs(5);
const STALL_SAMPLE: Duration = Duration::from_millis(200);

// ==================== Harness ====================

struct TestNode {
    dir: tempfile::TempDir,
    node: PeerNetNode,
    #[allow(dead_code)]
    running: wasmnest_peer_net::RunningNode,
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

    fn record(&self) -> StaticPeerRecord {
        StaticPeerRecord {
            node_id: self.id().clone(),
            addr: self.running.local_addr(),
        }
    }
}

/// B 端（被拨入方）的处理器与事件通道句柄：暂停/恢复/取消入口都在 handler 上
struct NodeBHandles {
    handler: Arc<SharedDirHandler>,
    /// push 接收事件（Progress/Paused/Resumed/Terminal）
    events: mpsc::Receiver<TransferEvent>,
    /// 服务侧拉取事件（PullServed/Progress/Terminal）
    serve_events: mpsc::Receiver<TransferEvent>,
    /// B 的接收落点（push 方向落盘位置）
    downloads: PathBuf,
}

/// 起双节点：两端均按生产装配挂 [`SharedDirHandler`]（B 带共享目录注册表）。
/// 双方首连闸门自动接受（信任语义由 harness 套件覆盖，本套件只测数据面）。
async fn spawn_pair(
    store_b: Arc<SharedDirStore>,
    downloads_b: PathBuf,
) -> (TestNode, TestNode, NodeBHandles) {
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let identity_a = NodeIdentity::load_or_create(dir_a.path()).expect("identity A");
    let identity_b = NodeIdentity::load_or_create(dir_b.path()).expect("identity B");
    let listener_a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind A");
    let listener_b = std::net::TcpListener::bind("127.0.0.1:0").expect("bind B");
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
            node_id: id_b,
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

    async fn drive_gate_auto_accept(mut rx: mpsc::Receiver<TrustEvent>) {
        while let Some(TrustEvent::ConfirmRequested { reply, .. }) = rx.recv().await {
            let _ = reply.send(true);
        }
    }

    // A（发送/拉取发起方）：空共享注册表占位——双端同构装配
    let (tx_a, _rx_a) = mpsc::channel(64);
    let (serve_tx_a, _serve_rx_a) = mpsc::channel(64);
    let handler_a = SharedDirHandler::new(
        Arc::new(SharedDirStore::in_memory()),
        None,
        TransferConfig::default(),
        tx_a,
        serve_tx_a,
    );

    // B（接收/供流方）：真实共享注册表 + 自动放行策略
    let (tx_b, rx_b) = mpsc::channel(512);
    let (serve_tx_b, serve_rx_b) = mpsc::channel(512);
    let handler_b = Arc::new(SharedDirHandler::new(
        store_b,
        None,
        TransferConfig {
            policy: ReceivePolicy::AlwaysAccept,
            download_dir: downloads_b.clone(),
            ..TransferConfig::default()
        },
        tx_b,
        serve_tx_b,
    ));

    let (gate_tx_a, gate_rx_a) = mpsc::channel(16);
    let (gate_tx_b, gate_rx_b) = mpsc::channel(16);
    let running_a = node_a
        .start_with_listener(listener_a, gate_tx_a, Arc::new(handler_a))
        .expect("start A");
    let running_b = node_b
        .start_with_listener(listener_b, gate_tx_b, Arc::clone(&handler_b) as Arc<_>)
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
        NodeBHandles {
            handler: handler_b,
            events: rx_b,
            serve_events: serve_rx_b,
            downloads: downloads_b,
        },
    )
}

/// 经看门狗拨号建立可信连接
async fn dial_trusted(a: &TestNode, b: &TestNode) -> wasmnest_peer_net::Connection {
    match tokio::time::timeout(DIAL_TIMEOUT, a.node.dial(&b.record())).await {
        Ok(result) => result.expect("trusted dial must succeed"),
        Err(_) => panic!("dial did not finish within {DIAL_TIMEOUT:?}"),
    }
}

/// 构造已知内容的源文件（内容确定性填充，强制多块推送）
fn make_source_file(dir: &Path, name: &str, len: usize) -> (PathBuf, Vec<u8>) {
    let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let path = dir.join(name);
    std::fs::write(&path, &content).expect("write source file");
    (path, content)
}

/// `.part` 临时文件名（引擎命名契约镜像：批 ID + 文件下标）
fn part_name(batch_id: &str, index: u32) -> String {
    format!(".wasmnest-transfer-{batch_id}-{index}.part")
}

fn part_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// 消费事件直到进度达到阈值（之前的非进度事件一并吞掉）
async fn wait_progress(events: &mut mpsc::Receiver<TransferEvent>, at_least: u64) -> u64 {
    loop {
        let event = tokio::time::timeout(EVENT_TIMEOUT, events.recv())
            .await
            .expect("progress event within watchdog")
            .expect("channel alive while transferring");
        match event {
            TransferEvent::Progress { transferred, .. } if transferred >= at_least => {
                return transferred
            }
            TransferEvent::Terminal { state, .. } => {
                panic!("transfer terminated before {at_least} bytes: {state:?}")
            }
            _ => continue,
        }
    }
}

/// 消费事件直到命中谓词（终态即失败：预期事件未到说明链路跑偏）
async fn wait_event<F>(events: &mut mpsc::Receiver<TransferEvent>, pred: F) -> TransferEvent
where
    F: Fn(&TransferEvent) -> bool,
{
    loop {
        let event = tokio::time::timeout(EVENT_TIMEOUT, events.recv())
            .await
            .expect("expected event within watchdog")
            .expect("channel alive while transferring");
        if pred(&event) {
            return event;
        }
        if matches!(event, TransferEvent::Terminal { .. }) {
            panic!("terminal reached before expected event: {event:?}");
        }
    }
}

/// 收集事件直至 Terminal（含），返回全部所见
async fn wait_terminal(events: &mut mpsc::Receiver<TransferEvent>) -> Vec<TransferEvent> {
    let mut seen = Vec::new();
    loop {
        let event = tokio::time::timeout(EVENT_TIMEOUT, events.recv())
            .await
            .expect("terminal within watchdog")
            .expect("channel alive until terminal");
        let terminal = matches!(event, TransferEvent::Terminal { .. });
        seen.push(event);
        if terminal {
            return seen;
        }
    }
}

fn terminal_of(events: &[TransferEvent]) -> &TerminalState {
    match events.last() {
        Some(TransferEvent::Terminal { state, .. }) => state,
        other => panic!("expected terminal event, got {other:?}"),
    }
}

/// 等数据面停滞（双采样相等即判定已停）；超时 panic 并带尺寸轨迹。
///
/// 「立即生效」的判据：暂停后允许在途数据（socket 缓冲 + 帧通道，百 KB 量级）
/// 继续落盘，但必须在 [`STALL_GRACE`] 内彻底停止——若数据供方未门控，GB 级
/// 文件会在宽限期内持续增长，本断言即失败。
async fn wait_stream_stalled(part: &Path) -> u64 {
    let deadline = std::time::Instant::now() + STALL_GRACE;
    let mut last = part_len(part);
    assert!(last > 0, "part file must exist before stall assertion");
    loop {
        tokio::time::sleep(STALL_SAMPLE).await;
        let now = part_len(part);
        if now == last {
            return now;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "数据面未在 {STALL_GRACE:?} 内停滞（仍在增长 {last} → {now}）"
        );
        last = now;
    }
}

/// 在给定窗口内确认无终态到达（窗口内其它事件消费掉）：暂停是挂起而非完成/取消
async fn assert_no_terminal(events: &mut mpsc::Receiver<TransferEvent>, window: Duration) {
    let deadline = std::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(TransferEvent::Terminal { state, .. })) => {
                panic!("暂停期间出现终态：{state:?}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("事件通道在暂停期间关闭"),
            Err(_elapsed) => return,
        }
    }
}

// ==================== push：接收方本地暂停/恢复 ====================

/// 接收方（B）本地暂停 push 批：经 wire Pause 帧门控对端发送会话推流——
/// 落盘停滞、无终态；恢复后按已写偏移续流至完成，内容逐字节一致。
///
/// 发送端刻意**不挂宿主暂停句柄**：对端帧仍必须门控推流（引擎自建兜底），
/// 回归「接收方按暂停、发送方没有门控落点 → 数据照传」的缺陷类。
#[tokio::test]
async fn push_receiver_pause_stops_sender_and_resume_completes() {
    let total = 8 * MIB;
    let downloads = tempfile::tempdir().expect("downloads tempdir");
    let (a, b, mut hb) = spawn_pair(
        Arc::new(SharedDirStore::in_memory()),
        downloads.path().into(),
    )
    .await;
    let (source, content) = make_source_file(a.dir.path(), "push-pause.bin", total);
    let conn = dial_trusted(&a, &b).await;
    let batch_id = "push-recv-pause-1";
    let b_downloads = hb.downloads.clone();

    let (tx_a, mut rx_a) = mpsc::channel(512);
    let drain = tokio::spawn(async move { while rx_a.recv().await.is_some() {} });
    let sender = tokio::spawn(send_batch(
        conn,
        batch_id.to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "push-pause.bin".to_string(),
        }],
        tx_a,
        CancelToken::new(),
        false,
        None,
    ));

    // 推到中途再暂停（保证仍在传输中）
    wait_progress(&mut hb.events, (total / 4) as u64).await;
    assert!(
        hb.handler.set_receive_paused(batch_id, true).await,
        "push 接收批必须命中接收侧暂停入口"
    );

    // 暂停立即生效：宽限期内落盘停滞，且暂停点必须落在传输中途
    let part = b_downloads.join(part_name(batch_id, 0));
    let stalled_at = wait_stream_stalled(&part).await;
    assert_no_terminal(&mut hb.events, Duration::from_millis(200)).await;
    assert!(
        stalled_at > 0 && stalled_at < total as u64,
        "暂停点必须落在传输中途（{stalled_at}/{total}）"
    );

    // 恢复：双端 Completed，落盘内容与源逐字节一致
    assert!(hb.handler.set_receive_paused(batch_id, false).await);
    let state = sender.await.expect("sender join").expect("send session io");
    assert_eq!(state, TerminalState::Completed, "发送端会话终态");
    assert_eq!(
        terminal_of(&wait_terminal(&mut hb.events).await),
        &TerminalState::Completed,
        "接收端终态"
    );
    assert_eq!(
        std::fs::read(b_downloads.join("push-pause.bin")).expect("read landed file"),
        content,
        "暂停/恢复不得丢字节"
    );
    drain.abort();
}

/// 发送方（A）本地暂停 push 批：本端门控停推流 + wire Pause 帧令对端任务
/// 同步为 paused（接收侧抬发 `Paused` 事件，宿主据此改任务状态）；恢复后
/// 对端收到 `Resumed` 并完整落盘。
#[tokio::test]
async fn push_sender_pause_syncs_receiver_task_and_resume_completes() {
    let total = 8 * MIB;
    let downloads = tempfile::tempdir().expect("downloads tempdir");
    let (a, b, mut hb) = spawn_pair(
        Arc::new(SharedDirStore::in_memory()),
        downloads.path().into(),
    )
    .await;
    let (source, content) = make_source_file(a.dir.path(), "push-sender-pause.bin", total);
    let conn = dial_trusted(&a, &b).await;
    let batch_id = "push-send-pause-1";

    let pause_slot = PauseSlot::new();
    let (tx_a, mut rx_a) = mpsc::channel(512);
    let drain = tokio::spawn(async move { while rx_a.recv().await.is_some() {} });
    let sender = tokio::spawn(send_batch(
        conn,
        batch_id.to_string(),
        vec![OutgoingFile {
            source,
            remote_path: "push-sender-pause.bin".to_string(),
        }],
        tx_a,
        CancelToken::new(),
        false,
        Some(Arc::clone(&pause_slot)),
    ));

    wait_progress(&mut hb.events, (total / 4) as u64).await;
    assert!(
        pause_slot.send(PauseCmd::Pause).await,
        "暂停命令必须送达会话"
    );
    // 对端任务同步：接收侧抬发 Paused 事件（宿主置任务 paused）
    wait_event(&mut hb.events, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;

    let part = downloads.path().join(part_name(batch_id, 0));
    let stalled_at = wait_stream_stalled(&part).await;
    assert_no_terminal(&mut hb.events, Duration::from_millis(200)).await;
    assert!(
        stalled_at > 0 && stalled_at < total as u64,
        "暂停点必须在传输中途"
    );

    assert!(
        pause_slot.send(PauseCmd::Resume).await,
        "恢复命令必须送达会话"
    );
    wait_event(&mut hb.events, |e| {
        matches!(e, TransferEvent::Resumed { .. })
    })
    .await;
    let state = sender.await.expect("sender join").expect("send session io");
    assert_eq!(state, TerminalState::Completed);
    assert_eq!(
        terminal_of(&wait_terminal(&mut hb.events).await),
        &TerminalState::Completed
    );
    assert_eq!(
        std::fs::read(downloads.path().join("push-sender-pause.bin")).expect("read landed file"),
        content
    );
    drain.abort();
}

// ==================== pull：供流侧本地暂停/恢复 + 按批取消 ====================

/// 从 `PullServed` 事件取服务侧批 ID（供流侧任务行的寻址键）
async fn wait_pull_served(events: &mut mpsc::Receiver<TransferEvent>) -> String {
    match wait_event(events, |e| matches!(e, TransferEvent::PullServed { .. })).await {
        TransferEvent::PullServed { batch_id, .. } => batch_id,
        other => panic!("expected PullServed, got {other:?}"),
    }
}

/// 建「B 暴露共享根 + A 拉取」的素材。
/// 返回（共享根 TempDir，拉取端落点 TempDir，注册表，共享根 ID，源内容）：
/// 两个 TempDir 由调用方持有保活（drop 即清理），根 ID 是拉取寻址键。
fn pull_fixture(
    total: usize,
) -> (
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<SharedDirStore>,
    String,
    Vec<u8>,
) {
    let shared_root = tempfile::tempdir().expect("shared root tempdir");
    let (_, content) = make_source_file(shared_root.path(), "big-pull.bin", total);
    let store = Arc::new(SharedDirStore::in_memory());
    let entry = store
        .add(
            "shared",
            SharedDirRoot::Fs {
                path: shared_root.path().to_path_buf(),
            },
        )
        .expect("register fs shared dir");
    let downloads_a = tempfile::tempdir().expect("puller downloads tempdir");
    (shared_root, downloads_a, store, entry.id, content)
}

/// 供流方（B）本地暂停 pull 批：serve 侧门控停供流 + wire Pause 帧令拉取方
/// 任务同步 paused（`Paused` 事件）；恢复后续流至完成，内容逐字节一致。
///
/// 这是「供流方也是同一任务的参与端」的对称能力：此前 pull 方向只有拉取
/// 发起方能暂停。
#[tokio::test]
async fn pull_serve_side_pause_stops_stream_and_resume_completes() {
    let total = 8 * MIB;
    let (_shared_root, downloads_a, store, dir_id, content) = pull_fixture(total);
    let b_downloads = tempfile::tempdir().expect("B downloads tempdir");
    let (a, b, mut hb) = spawn_pair(store, b_downloads.path().into()).await;
    let conn = dial_trusted(&a, &b).await;
    let batch_id = "pull-serve-pause-1";

    let (tx_a, mut rx_a) = mpsc::channel(512);
    let pull_downloads = downloads_a.path().to_path_buf();
    let puller = tokio::spawn(async move {
        pull_shared_file(
            conn,
            &dir_id,
            "big-pull.bin",
            batch_id,
            TransferConfig {
                policy: ReceivePolicy::AlwaysAccept,
                download_dir: pull_downloads,
                ..TransferConfig::default()
            },
            tx_a,
            CancelToken::new(),
            Some(PauseSlot::new()),
        )
        .await
    });

    let serve_batch = wait_pull_served(&mut hb.serve_events).await;
    wait_progress(&mut rx_a, (total / 4) as u64).await;
    assert!(
        hb.handler.set_serve_paused(&serve_batch, true).await,
        "供流批必须命中 serve 暂停入口"
    );

    let part = downloads_a.path().join(part_name(batch_id, 0));
    let stalled_at = wait_stream_stalled(&part).await;
    assert_no_terminal(&mut rx_a, Duration::from_millis(200)).await;
    assert!(
        stalled_at > 0 && stalled_at < total as u64,
        "暂停点必须落在传输中途（{stalled_at}/{total}）"
    );

    assert!(hb.handler.set_serve_paused(&serve_batch, false).await);
    let state = puller.await.expect("puller join").expect("pull session io");
    assert_eq!(state, TerminalState::Completed, "拉取方会话终态");
    assert_eq!(
        std::fs::read(downloads_a.path().join("big-pull.bin")).expect("read pulled file"),
        content
    );
    // 供流侧自身终态（双端记账：两侧各自结算一条任务）
    assert_eq!(
        terminal_of(&wait_terminal(&mut hb.serve_events).await),
        &TerminalState::Completed
    );
}

/// 供流方（B）按批取消 pull 批：会话写 Cancel 帧告知拉取方并停供流——
/// 拉取方落 `Cancelled{by_peer:true}`、供流方落 `Cancelled{by_peer:false}`，
/// 且拉取方 `.part` 保留（断点真源，重试即续传）。
#[tokio::test]
async fn pull_serve_side_cancel_interrupts_puller_and_keeps_partial() {
    let total = 16 * MIB;
    let (_shared_root, downloads_a, store, dir_id, _content) = pull_fixture(total);
    let b_downloads = tempfile::tempdir().expect("B downloads tempdir");
    let (a, b, mut hb) = spawn_pair(store, b_downloads.path().into()).await;
    let conn = dial_trusted(&a, &b).await;
    let batch_id = "pull-serve-cancel-1";

    let (tx_a, mut rx_a) = mpsc::channel(512);
    let pull_downloads = downloads_a.path().to_path_buf();
    let puller = tokio::spawn(async move {
        pull_shared_file(
            conn,
            &dir_id,
            "big-pull.bin",
            batch_id,
            TransferConfig {
                policy: ReceivePolicy::AlwaysAccept,
                download_dir: pull_downloads,
                ..TransferConfig::default()
            },
            tx_a,
            CancelToken::new(),
            Some(PauseSlot::new()),
        )
        .await
    });

    let serve_batch = wait_pull_served(&mut hb.serve_events).await;
    wait_progress(&mut rx_a, MIB as u64).await;
    // 同步调用、无 await 间隙：进度事件到手即取消，传输物理上不可能先行完成
    assert!(
        hb.handler.cancel_serve_transfer(&serve_batch),
        "供流批必须命中按批取消入口"
    );

    // 拉取方：对端取消 + .part 保留（断点真源）
    let state = puller.await.expect("puller join").expect("pull session io");
    assert_eq!(
        state,
        TerminalState::Cancelled { by_peer: true },
        "拉取方终态"
    );
    let part = downloads_a.path().join(part_name(batch_id, 0));
    let partial = part_len(&part);
    assert!(
        partial > 0 && partial < total as u64,
        ".part 必须保留为断点真源（{partial}/{total}）"
    );

    // 供流方：本端取消终态（双端各自结算一条任务）
    assert_eq!(
        terminal_of(&wait_terminal(&mut hb.serve_events).await),
        &TerminalState::Cancelled { by_peer: false }
    );
}
