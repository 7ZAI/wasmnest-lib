//! 共享目录浏览/拉取 AC 测试（issue 07）。
//!
//! 复用 harness 惯例（进程内双节点、回环互指、真实 mTLS 直连），暴露端挂载
//! [`SharedDirHandler`]，浏览端以 crate 客户端 API（[`browse_shared_dir`] /
//! [`pull_shared_file`]) 从节点公共 API 最高处驱动全部行为：
//!
//! - AC#1：B 暴露 Fs 目录 → A 列目录见条目（目录优先、按名排序）→ 拉取文件
//!   落入 A 的下载位置且内容一致；
//! - AC#1b：SAF 根经宿主缝（fake [`SharedSafAccess`]）全链路可列可拉；
//! - AC#2：未信任节点的拨入被首连闸门拒绝——列目录/拉取在结构上不可达；
//! - AC#3：只读约束——越界/绝对路径的拉取请求被拒且源目录零写入。
//!
//! Android SAF 授权条目重启后仍可读属真机冒烟项（持久化 URI 权限由系统承载，
//! 注册表条目落盘已由 registry 单测覆盖），不在本套件断言范围。

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use wasmnest_peer_net::{
    browse_shared_dir, list_shared_roots, CancelToken, DirEntry, NodeIdentity, PeerNetError,
    PeerNetNode, PeerNetNodeConfig, RejectReason, SeqReader, SharedDirHandler, SharedDirRoot,
    SharedSafAccess, SharedDirStore, TerminalState, TransferConfig, TransferEvent,
    TransferFrame, TrustEvent, pull_shared_file, resolve_rel_path,
};
use tokio::sync::mpsc;

/// 单次拨号看门狗（harness 同款）
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

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

    fn addr(&self) -> SocketAddr {
        self.running.local_addr()
    }

    fn record(&self) -> wasmnest_peer_net::StaticPeerRecord {
        wasmnest_peer_net::StaticPeerRecord {
            node_id: self.id().clone(),
            addr: self.addr(),
        }
    }
}

/// 起「浏览端 + 暴露端」双节点：暴露端按给定注册表/SAF 缝装配共享目录处理器，
/// 双方首连闸门均自动接受。返回暴露端的注册表句柄供用例注册条目。
struct ShareHandles {
    /// 暴露端事件通道（push 接收与拉取推流的终态断言用）
    events: mpsc::Receiver<TransferEvent>,
}

async fn spawn_pair(
    store_b: Arc<SharedDirStore>,
    saf_b: Option<Arc<dyn SharedSafAccess>>,
    config_b: TransferConfig,
) -> (TestNode, TestNode, ShareHandles) {
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let identity_a = NodeIdentity::load_or_create(dir_a.path()).expect("identity A");
    let identity_b = NodeIdentity::load_or_create(dir_b.path()).expect("identity B");
    let listener_a = TcpListener::bind("127.0.0.1:0").expect("bind A");
    let listener_b = TcpListener::bind("127.0.0.1:0").expect("bind B");
    let id_a = identity_a.node_id().clone();
    let id_b = identity_b.node_id().clone();
    let addr_a = listener_a.local_addr().expect("addr A");
    let addr_b = listener_b.local_addr().expect("addr B");

    let trust_a =
        Arc::new(wasmnest_peer_net::TrustStore::load_or_create(dir_a.path()).expect("trust A"));
    let node_a = PeerNetNode::new(PeerNetNodeConfig {
        bind_addr: addr_a,
        identity: identity_a,
        static_peers: vec![wasmnest_peer_net::StaticPeerRecord {
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
        static_peers: vec![wasmnest_peer_net::StaticPeerRecord {
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

    // 浏览端 A：回声 handler 占位（本测试无人拨入 A）
    let (_tx_a, _rx_a) = mpsc::channel(64);
    let handler_a = wasmnest_peer_net::TransferReceiveHandler::new(TransferConfig::default(), _tx_a);

    // 暴露端 B：共享目录复合处理器
    let (tx_b, rx_b) = mpsc::channel(256);
    // 服务侧拉取记账通道（双端记账）：测试无消费方，丢弃即可
    let (serve_tx_b, _serve_rx_b) = mpsc::channel(64);
    let handler_b = SharedDirHandler::new(store_b, saf_b, config_b, tx_b, serve_tx_b);

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
        ShareHandles { events: rx_b },
    )
}

async fn dial_trusted(a: &TestNode, b: &TestNode) -> wasmnest_peer_net::Connection {
    match tokio::time::timeout(DIAL_TIMEOUT, a.node.dial(&b.record())).await {
        Ok(result) => result.expect("trusted dial must succeed"),
        Err(_) => panic!("dial to {} did not finish within {DIAL_TIMEOUT:?}", b.addr()),
    }
}

/// 构造已知内容的源文件（内容确定性填充）
fn make_source_file(dir: &Path, name: &str, len: usize) -> (PathBuf, Vec<u8>) {
    let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir parent");
    std::fs::write(&path, &content).expect("write source file");
    (path, content)
}

/// 收集事件直至出现 Terminal（或超时）；返回全部所见
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

fn terminal_of(events: &[TransferEvent]) -> &TerminalState {
    match events.last() {
        Some(TransferEvent::Terminal { state, .. }) => state,
        other => panic!("expected terminal event, got {other:?}"),
    }
}

const KIB: usize = 1024;

// ==================== AC#1：Fs 根 列目录 + 拉取 ====================

#[tokio::test]
async fn fs_root_browse_lists_sorted_and_pull_lands_identical_content() {
    // ---- 暴露端素材：根下 docs/（目录）、a.txt、b.txt —— 排序断言素材 ----
    let shared_root = tempfile::tempdir().expect("shared root tempdir");
    std::fs::create_dir_all(shared_root.path().join("docs")).expect("mkdir docs");
    let (_, docs_content) =
        make_source_file(&shared_root.path().join("docs"), "inner.md", 16 * KIB);
    let (_, a_content) = make_source_file(shared_root.path(), "a.txt", 96 * KIB);
    let (_, _) = make_source_file(shared_root.path(), "b.txt", 4 * KIB);

    let store = Arc::new(SharedDirStore::in_memory());
    let entry = store
        .add(
            "shared",
            SharedDirRoot::Fs {
                path: shared_root.path().to_path_buf(),
            },
        )
        .expect("register fs shared dir");

    let (a, b, mut rx) = spawn_pair(store, None, TransferConfig::default()).await;

    // ---- 列根：目录优先、各自按名排序 ----
    let conn = dial_trusted(&a, &b).await;
    let listing = browse_shared_dir(conn, &entry.id, "").await.expect("browse root");
    assert!(!listing.filtered, "desktop fs root must not claim permission filtering");
    assert_eq!(
        listing.entries,
        vec![
            DirEntry::new("docs", true, 0),
            DirEntry::new("a.txt", false, a_content.len() as u64),
            DirEntry::new("b.txt", false, 4 * KIB as u64),
        ],
        "root listing must be dirs-first then name-sorted"
    );

    // ---- 下钻子目录（新连接；单连接单请求）----
    let conn = dial_trusted(&a, &b).await;
    let sub = browse_shared_dir(conn, &entry.id, "docs").await.expect("browse docs");
    assert_eq!(sub.entries, vec![DirEntry::new("inner.md", false, docs_content.len() as u64)]);

    // ---- 拉取子目录文件：落入本机下载目录且内容一致、.part 已消耗 ----
    let downloads = a.dir.path().join("downloads");
    let (conn_a_events_tx, _drop) = mpsc::channel::<TransferEvent>(64);
    let conn = dial_trusted(&a, &b).await;
    let state = pull_shared_file(
        conn,
        &entry.id,
        "docs/inner.md",
        "pull-test-fs-1",
        TransferConfig {
            policy: wasmnest_peer_net::ReceivePolicy::AlwaysAccept,
            download_dir: downloads.clone(),
            ..TransferConfig::default()
        },
        conn_a_events_tx,
        CancelToken::new(),
        None,
    )
    .await
    .expect("pull session io");
    assert_eq!(state, TerminalState::Completed);

    let pulled = downloads.join("docs").join("inner.md");
    assert_eq!(
        std::fs::read(&pulled).expect("read pulled file"),
        docs_content,
        "pulled content must be byte-identical"
    );

    // 暴露端事件流收到该次推流的完成终态
    assert_eq!(
        terminal_of(&wait_terminal(&mut rx.events).await),
        &TerminalState::Completed
    );
}

// ==================== AC#1b：SAF 缝全链路 ====================

/// fake SAF 访问缝：内存树（无头测试惯例，镜像 SafIo fake 注入模式）
struct FakeSaf {
    files: std::collections::HashMap<String, Vec<u8>>,
    dirs: Vec<String>,
}

impl FakeSaf {
    fn with_file(rel: &str, content: &[u8]) -> Self {
        let mut files = std::collections::HashMap::new();
        files.insert(rel.to_string(), content.to_vec());
        let dirs = rel
            .split('/')
            .take(rel.split('/').count().saturating_sub(1))
            .scan(String::new(), |acc, part| {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(part);
                Some(acc.clone())
            })
            .collect();
        Self { files, dirs }
    }
}

impl SharedSafAccess for FakeSaf {
    fn list_dir(
        &self,
        _tree_uri: &str,
        rel: &str,
    ) -> wasmnest_peer_net::Result<Vec<DirEntry>> {
        let prefix = if rel.is_empty() {
            String::new()
        } else {
            format!("{rel}/")
        };
        let mut out = Vec::new();
        for dir in &self.dirs {
            if let Some(name) = dir.strip_prefix(&prefix) {
                if !name.contains('/') && !name.is_empty() {
                    out.push(DirEntry::new(name.to_string(), true, 0));
                }
            }
        }
        for name in self.files.keys() {
            if let Some(base) = name.strip_prefix(&prefix) {
                if !base.contains('/') && !base.is_empty() {
                    out.push(DirEntry::new(
                        base.to_string(),
                        false,
                        self.files[name].len() as u64,
                    ));
                }
            }
        }
        Ok(out)
    }

    fn open_read(&self, _tree_uri: &str, rel: &str) -> wasmnest_peer_net::Result<Arc<dyn SeqReader>> {
        match self.files.get(rel) {
            Some(content) => Ok(Arc::new(MemReader {
                content: content.clone(),
            })),
            None => Err(wasmnest_peer_net::PeerNetError::TransferProtocol {
                role: "fake-saf",
                detail: format!("not-found: {rel}"),
            }),
        }
    }
}

struct MemReader {
    content: Vec<u8>,
}

impl SeqReader for MemReader {
    fn size(&self) -> u64 {
        self.content.len() as u64
    }

    fn read_at(&self, offset: u64, cap: usize) -> std::io::Result<Vec<u8>> {
        let start = (offset as usize).min(self.content.len());
        let end = (start + cap).min(self.content.len());
        Ok(self.content[start..end].to_vec())
    }
}

#[tokio::test]
async fn saf_root_flows_through_host_seam_for_browse_and_pull() {
    const TREE_URI: &str = "content://tree/test%3Adocs";
    let saf_content: Vec<u8> = (0..40 * KIB).map(|i| (i % 253) as u8).collect();

    let store = Arc::new(SharedDirStore::in_memory());
    let entry = store
        .add(
            "saf-shared",
            SharedDirRoot::Saf {
                tree_uri: TREE_URI.to_string(),
            },
        )
        .expect("register saf shared dir");

    let (a, b, _rx) = spawn_pair(
        store,
        Some(Arc::new(FakeSaf::with_file("reports/q3.bin", &saf_content))),
        TransferConfig::default(),
    )
    .await;

    // ---- 经 SAF 缝列子目录 ----
    let conn = dial_trusted(&a, &b).await;
    let listing = browse_shared_dir(conn, &entry.id, "reports").await.expect("browse saf subdir");
    assert_eq!(listing.entries, vec![DirEntry::new("q3.bin", false, saf_content.len() as u64)]);

    // ---- 经 SAF 缝拉取（spawn_blocking 定位读路径）----
    let downloads = a.dir.path().join("downloads");
    let (tx, _drop) = mpsc::channel::<TransferEvent>(64);
    let conn = dial_trusted(&a, &b).await;
    let state = pull_shared_file(
        conn,
        &entry.id,
        "reports/q3.bin",
        "pull-test-saf-1",
        TransferConfig {
            policy: wasmnest_peer_net::ReceivePolicy::AlwaysAccept,
            download_dir: downloads.clone(),
            ..TransferConfig::default()
        },
        tx,
        CancelToken::new(),
        None,
    )
    .await
    .expect("pull session io");
    assert_eq!(state, TerminalState::Completed);
    assert_eq!(
        std::fs::read(downloads.join("reports").join("q3.bin")).expect("read pulled"),
        saf_content,
        "saf-seam pulled content must be byte-identical"
    );
}

// ==================== AC#2：未信任节点不可达 ====================

/// 未信任节点拨入被首连闸门拒绝：确认弹窗触发、默认拒绝后无任何会话可能
/// （列目录/拉取必须先有可信连接——闸门即唯一入口，此处验证该结构性前提）
#[tokio::test]
async fn untrusted_dial_is_gated_before_any_share_session() {
    // 三节点组网：C 未被 B 预置接受决策
    let mut dirs: Vec<tempfile::TempDir> = (0..3)
        .map(|_| tempfile::tempdir().expect("tempdir"))
        .collect();
    let mut identities: Vec<NodeIdentity> = dirs
        .iter()
        .map(|d| NodeIdentity::load_or_create(d.path()).expect("identity"))
        .collect();
    let listeners: Vec<_> = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind"))
        .collect();
    let addrs: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
    let ids: Vec<_> = identities.iter().map(|i| i.node_id().clone()).collect();

    let store = Arc::new(SharedDirStore::in_memory());
    store
        .add(
            "secret",
            SharedDirRoot::Fs {
                path: dirs[1].path().to_path_buf(),
            },
        )
        .expect("register");

    async fn drive_gate_default_deny(mut rx: mpsc::Receiver<TrustEvent>) {
        while let Some(TrustEvent::ConfirmRequested { reply, .. }) = rx.recv().await {
            // 默认拒绝：模拟用户未确认
            let _ = reply.send(false);
        }
    }

    let mut nodes: Vec<TestNode> = Vec::new();
    for i in 0..3 {
        let dir = dirs.remove(0);
        let identity = identities.remove(0);
        let node = PeerNetNode::new(PeerNetNodeConfig {
            bind_addr: addrs[i],
            identity,
            static_peers: (0..3)
                .filter(|&j| j != i)
                .map(|j| wasmnest_peer_net::StaticPeerRecord {
                    node_id: ids[j].clone(),
                    addr: addrs[j],
                })
                .collect(),
        })
        .expect("node")
        .with_trust_store(Arc::new(
            wasmnest_peer_net::TrustStore::load_or_create(dir.path()).expect("trust"),
        ));

        let (gate_tx, gate_rx) = mpsc::channel(16);
        let running = if i == 1 {
            let (tx, _rx) = mpsc::channel(64);
            // 服务侧拉取记账通道（双端记账）：测试无消费方，丢弃即可
            let (serve_tx, _serve_rx) = mpsc::channel(64);
            let handler = SharedDirHandler::new(
                Arc::clone(&store),
                None,
                TransferConfig::default(),
                tx,
                serve_tx,
            );
            node.start_with_listener(listeners[i].try_clone().expect("clone"), gate_tx, Arc::new(handler))
                .expect("start B")
        } else {
            let (_tx, _rx) = mpsc::channel(64);
            let handler =
                wasmnest_peer_net::TransferReceiveHandler::new(TransferConfig::default(), _tx);
            node.start_with_listener(listeners[i].try_clone().expect("clone"), gate_tx, Arc::new(handler))
                .expect("start node")
        };
        nodes.push(TestNode {
            dir,
            node,
            running,
            gate_task: tokio::spawn(drive_gate_default_deny(gate_rx)),
        });
    }
    let [a, b, c] = nodes.as_slice() else {
        panic!("three nodes expected");
    };

    // 未信任 C → B：闸门拒绝，连接无法建立（列目录/拉取在结构上不可达）
    match tokio::time::timeout(DIAL_TIMEOUT, c.node.dial(&b.record())).await {
        Ok(Err(PeerNetError::DialDeniedByPeer { .. })) => {}
        other => panic!("expected DialDeniedByPeer, got {other:?}"),
    }
    assert!(!c.node.trust().contains(b.id()));
    assert!(!b.node.trust().contains(c.id()));

    // 可信 A → B 不受影响（闸门默认拒绝组里 A 也未获信任，同样被拒——
    // 证明拒绝来自闸门而非共享目录层故障）
    match tokio::time::timeout(DIAL_TIMEOUT, a.node.dial(&b.record())).await {
        Ok(Err(PeerNetError::DialDeniedByPeer { .. })) => {}
        other => panic!("expected DialDeniedByPeer for A too, got {other:?}"),
    }
}

// ==================== AC#3：只读约束 ====================

/// 浏览方先取共享根清单获得 dir_id（issue 11 前置）：含用户注册条目与内置
/// 免授权条目；随后以清单中的 id 正常下钻，证明寻址闭环
#[tokio::test]
async fn roots_listing_reports_registered_dirs_for_browse_addressing() {
    let shared_root = tempfile::tempdir().expect("shared root tempdir");
    let (_, marker) = make_source_file(shared_root.path(), "root.txt", 2 * KIB);

    let store = Arc::new(
        SharedDirStore::in_memory().with_builtin_download_dir("downloads", shared_root.path().join("dl")),
    );
    let entry = store
        .add(
            "shared",
            SharedDirRoot::Fs {
                path: shared_root.path().to_path_buf(),
            },
        )
        .expect("register");

    let (a, b, _rx) = spawn_pair(store, None, TransferConfig::default()).await;

    // ---- 列根：内置免授权条目在前、注册条目随后，id/name 齐备 ----
    let conn = dial_trusted(&a, &b).await;
    let roots = list_shared_roots(conn).await.expect("list roots");
    assert_eq!(roots.len(), 2, "builtin entry + user entries");
    assert_eq!(roots[0].id, wasmnest_peer_net::BUILTIN_DOWNLOADS_ID);
    assert_eq!(roots[0].name, "downloads");
    assert_eq!(roots[1].id, entry.id);
    assert_eq!(roots[1].name, "shared");

    // ---- 以根清单给出的 id 下钻，寻址闭环 ----
    let conn = dial_trusted(&a, &b).await;
    let listing = browse_shared_dir(conn, &roots[1].id, "").await.expect("browse via roots id");
    assert_eq!(listing.entries, vec![DirEntry::new("root.txt", false, marker.len() as u64)]);
}

/// 越界/绝对路径的拉取请求被服务端以 not-found 拒绝；源目录零写入
#[tokio::test]
async fn traversal_and_absolute_pull_requests_are_rejected_readonly() {
    let shared_root = tempfile::tempdir().expect("shared root tempdir");
    let (_, secret) = make_source_file(shared_root.path(), "keep.txt", 8 * KIB);

    let store = Arc::new(SharedDirStore::in_memory());
    let entry = store
        .add(
            "ro",
            SharedDirRoot::Fs {
                path: shared_root.path().to_path_buf(),
            },
        )
        .expect("register");

    let (a, b, _rx) = spawn_pair(store, None, TransferConfig::default()).await;

    for hostile_rel in ["../escaped.txt", "/abs/path.txt", "..", "a/../.."] {
        let conn = dial_trusted(&a, &b).await;
        let mut conn = conn;
        wasmnest_peer_net::transfer::message::write_control(
            &mut conn,
            &TransferFrame::PullRequest {
                protocol_version: 1,
                dir_id: entry.id.clone(),
                rel_path: hostile_rel.to_string(),
            },
        )
        .await
        .expect("send hostile pull request");

        let reply =
            wasmnest_peer_net::transfer::message::read_control(&mut conn).await.expect("reply");
        match reply {
            TransferFrame::Decision {
                accepted: false,
                reason: Some(reason),
                ..
            } => {
                assert_eq!(
                    reason,
                    RejectReason::NotFound,
                    "hostile rel '{hostile_rel}' must be rejected as not-found"
                );
            }
            other => panic!("hostile rel '{hostile_rel}' must get rejection decision, got {other:?}"),
        }
        drop(conn);
    }

    // 源目录零写入：仍只有原始文件
    let remaining: Vec<String> = std::fs::read_dir(shared_root.path())
        .expect("readdir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(remaining, vec!["keep.txt"]);
    assert_eq!(std::fs::read(shared_root.path().join("keep.txt")).expect("intact"), secret);

    // 路径清洗纯函数与线协议行为同源
    assert!(resolve_rel_path("../escaped.txt").is_none());
    assert!(resolve_rel_path("/abs/path.txt").is_none());
}

/// 拉取（pull serve）暂停/恢复：拉取方经 PauseSlot 门控数据供方推流，
/// serve 侧停滞且不落终态；恢复后完整落盘（暂停不丢字节）。
#[tokio::test]
async fn pull_pause_then_resume_serves_full_content() {
    use wasmnest_peer_net::{PauseCmd, PauseSlot};

    let shared_root = tempfile::tempdir().expect("shared root tempdir");
    let (source, content) = make_source_file(shared_root.path(), "big-pull.bin", 8 * 1024 * KIB);
    let file_name = "big-pull.bin".to_string();

    let store = Arc::new(SharedDirStore::in_memory());
    let entry = store
        .add(
            "shared",
            SharedDirRoot::Fs {
                path: shared_root.path().to_path_buf(),
            },
        )
        .expect("register fs shared dir");

    let (a, b, mut rx) = spawn_pair(store, None, TransferConfig::default()).await;
    let downloads = a.dir.path().join("downloads");
    let (conn_a_events_tx, mut conn_a_events) = mpsc::channel::<TransferEvent>(64);
    let conn = dial_trusted(&a, &b).await;
    let pause_slot = PauseSlot::new();
    let batch_id = "pull-pause-test-1";

    let puller = tokio::spawn({
        let downloads = downloads.clone();
        let pause_slot = pause_slot.clone();
        async move {
            wasmnest_peer_net::pull_shared_file(
                conn,
                &entry.id,
                &file_name,
                batch_id,
                TransferConfig {
                    policy: wasmnest_peer_net::ReceivePolicy::AlwaysAccept,
                    download_dir: downloads,
                    ..TransferConfig::default()
                },
                conn_a_events_tx,
                CancelToken::new(),
                Some(pause_slot),
            )
            .await
        }
    });

    // 等过半进度后暂停（事件通道 cap-64：过半后起后台排空，避免 puller emit 阻塞
    // 阻断暂停命令处理）
    loop {
        match tokio::time::timeout(Duration::from_secs(15), conn_a_events.recv()).await {
            Ok(Some(TransferEvent::Progress { transferred, .. })) => {
                if transferred >= 4 * 1024 * KIB as u64 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            other => panic!("expected pull progress, got {other:?}"),
        }
    }
    let drain = tokio::spawn(async move {
        let mut terminal_seen = false;
        loop {
            match conn_a_events.recv().await {
                Some(TransferEvent::Terminal { .. }) => {
                    terminal_seen = true;
                    break;
                }
                Some(_) => continue,
                None => break,
            }
        }
        terminal_seen
    });
    pause_slot.send(PauseCmd::Pause).await;
    // 暂停生效：serve 停滞——短暂窗口内不应出现终态（传输挂起而非完成/取消）
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!drain.is_finished(), "pull reached terminal while paused");

    pause_slot.send(PauseCmd::Resume).await;
    let state = puller.await.expect("puller join").expect("pull session io");
    assert_eq!(state, TerminalState::Completed, "pull must complete after resume");
    assert!(drain.await.expect("drain join"), "puller must report a terminal");

    let pulled = downloads.join("big-pull.bin");
    assert_eq!(
        std::fs::read(&pulled).expect("read pulled file"),
        content,
        "pulled content must be byte-identical after pause/resume"
    );
    assert!(
        source.exists(),
        "shared source must be untouched by pull pause"
    );
}
