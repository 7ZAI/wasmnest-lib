//! 传输会话引擎：控制面批协商 + 数据面流式推送 + 接收策略 + 进度/取消。
//!
//! 以 git 标签 v2.0.0 移动端 file_service 的传输语义为种子去 host 化改造
//! （issue 05）：upload session 契约收敛为「接收端已写字节 = 断点真源」——
//! 每个文件由接收端先发 [`TransferFrame::StartFile`] 声明起点偏移，发送端
//! 必须从该偏移起推流；`.part` 临时文件在取消/中断时保留（issue 06 续传
//! 在此契约上生长）。终端 WS 与 Announce token 依赖已剥离，信任放行后的
//! 已认证连接经 [`ConnectionHandler`] 缝挂载接收角色。
//!
//! ## 会话时序（单连接 = 单批，严格分相）
//!
//! ```text
//! A(发送端)                          B(接收端)
//!   | Offer{files,total_size} ────────▶ │ 按 ReceivePolicy 分流：
//!   |                                    │  AlwaysDeny → Decision{false}
//!   |                                    │  Ask → OfferPending 事件，
//!   |                                    │        超时自动 Decision{false,timeout}
//!   | ◀──────── Decision{accepted} ───── |
//!   | ◀──────── StartFile{i,offset} ──── | 创建 .part（已有则 offset=已写字节）
//!   | Data* ───────────────────────────▶ │ 顺序写盘，进度事件持续上报
//!   | ◀──────── FileDone{i} ──────────── | flush+sync 后原子 rename 落位
//!   |          （逐文件循环）            |
//!   | ◀──────── BatchDone{} ──────────── | 双方落 Completed 终态
//! ```
//!
//! 取消双向可用：任一端发 [`TransferFrame::Cancel`] 并关连接，对端落
//! `Cancelled{by_peer=true}`；本端落 `Cancelled{by_peer=false}`。
//!
//! 本票保持单活跃会话假设（一条连接一个批）；并发多批属后续票。中断续传
//! 已落地（issue 06）：以同 batch_id 重发 Offer 即从接收端落盘偏移续传，
//! 批内已完成文件零重传直接跳过，进度按批聚合跨会话单调推进。

pub mod batch;
pub mod crypto;
pub mod message;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::NodeId;
use tokio::sync::{mpsc, Notify};

pub use batch::{
    validate_batch_transition, BatchState, FileMeta, ReceivePolicy, RejectReason, TransferBatch,
    DEFAULT_ASK_TIMEOUT_SECS, MAX_ASK_TIMEOUT_SECS, MIN_ASK_TIMEOUT_SECS,
};
pub use message::{
    read_control, write_control, write_data, CancelOrigin, IncomingFrame, TransferFrame,
    TRANSFER_PROTOCOL_VERSION,
};

// ==================== 配置 ====================

/// 接收落位钩子：文件完整落位于 download_dir 后由引擎回调（issue 07）
///
/// 引擎只保证「rename 已完成、路径即最终位置」；钩子实现方自行决定后续动作
/// （如移动端把私有副本提升进 MediaStore.Downloads，失败保留私有副本即天然
/// 回退语义）。同步签名：实现方内部自行处理阻塞桥接（Kotlin 桥惯例），
/// 不让引擎感知平台细节。
pub trait FileLanding: Send + Sync {
    /// 单个文件落位完成回调
    ///
    /// `final_path` 为 download_dir 内的最终文件；`display_name` 为对外展示名
    /// （当前取相对路径末段）。回调失败不得影响会话终态（实现方自行兜底）。
    fn landed(&self, final_path: &std::path::Path, display_name: &str);
}

/// 传输会话配置
#[derive(Clone)]
pub struct TransferConfig {
    /// 全局接收策略（spec Decision 10：单开关粒度，不区分对端）
    pub policy: ReceivePolicy,
    /// 接收落点目录（桌面端缺省 `Downloads\WasmNest\` 由宿主注入）
    pub download_dir: PathBuf,
    /// 数据面分块大小（字节）
    pub chunk_size: usize,
    /// 落位钩子（None = 仅落盘，无后续动作；issue 07 移动端注入 MediaStore 提升）
    pub landing: Option<Arc<dyn FileLanding>>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            policy: ReceivePolicy::default(),
            download_dir: PathBuf::from("."),
            chunk_size: 64 * 1024,
            landing: None,
        }
    }
}

impl std::fmt::Debug for TransferConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferConfig")
            .field("policy", &self.policy)
            .field("download_dir", &self.download_dir)
            .field("chunk_size", &self.chunk_size)
            .field("landing", &self.landing.as_ref().map(|_| "<hook>"))
            .finish()
    }
}

/// 等待对端控制帧的空闲超时：协商/确认阶段对端无响应时快速失败而非挂死
const IDLE_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

/// 等待首批 Offer 的超时：信任放行后发送端应立即发起协商，久等即异常
const OFFER_TIMEOUT: Duration = Duration::from_secs(10);

// ==================== 取消令牌 ====================

/// 会话取消令牌（clone 共享给宿主；`cancel` 幂等、唤醒全部等待者）
///
/// flag + Notify 组合而非裸 Notify：`notify_waiters` 不留存许可，cancel 先于
/// wait 注册时会丢事件；flag 先落状态使后注册的等待者立即通过检查退出。
///
/// 父子层级（issue 10）：会话持有 `child(&global)` 令牌——宿主既能经全局
/// 令牌一键急停全部会话，也能按 batch_id 单独取消一条，互不牵连。
#[derive(Clone, Default)]
pub struct CancelToken {
    flag: Arc<Mutex<bool>>,
    notify: Arc<Notify>,
    /// 父令牌（None = 根）；任一层触发即视为已取消
    parent: Option<Arc<CancelToken>>,
}

impl CancelToken {
    /// 新建未取消令牌
    pub fn new() -> Self {
        Self::default()
    }

    /// 子令牌：父或自身任一触发即取消（自身 cancel 不影响父与兄弟）
    pub fn child(parent: &CancelToken) -> Self {
        Self {
            flag: Arc::new(Mutex::new(false)),
            notify: Arc::new(Notify::new()),
            parent: Some(Arc::new(parent.clone())),
        }
    }

    /// 触发取消（幂等）：置位并唤醒所有等待者
    pub fn cancel(&self) {
        if let Ok(mut flag) = self.flag.lock() {
            *flag = true;
        }
        self.notify.notify_waiters();
    }

    /// 是否已取消（非阻塞检查；含父链传递）
    pub fn is_cancelled(&self) -> bool {
        if self.flag.lock().map(|f| *f).unwrap_or(false) {
            return true;
        }
        match &self.parent {
            Some(parent) => parent.is_cancelled(),
            None => false,
        }
    }

    /// 等待取消触发（已取消则立即返回）
    pub(crate) async fn cancelled(&self) {
        // 先查标志再注册监听，消除「取消发生在注册前」的丢失窗口
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            match &self.parent {
                Some(parent) => {
                    // 装箱打断 async fn 递归（E0733）：父链深度为 1，开销可忽略
                    let parent = Arc::clone(parent);
                    tokio::select! {
                        _ = notified => {}
                        _ = Box::pin(async move { CancelToken::cancelled(&parent).await }) => {}
                    }
                }
                None => notified.await,
            }
        }
    }
}

// ==================== 暂停门控（wire Pause/Resume） ====================

/// 宿主 → 会话的数据面指令（经 [`PauseSlot`] 通道下发）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseCmd {
    /// 暂停：会话写 Pause 帧并（供方）停止推流
    Pause,
    /// 恢复：会话写 Resume 帧并（供方）继续推流
    Resume,
}

/// 会话暂停控制句柄：宿主创建后传入会话循环，宿主侧保留 Arc 供按 batch
/// 暂停/恢复（命令经有界通道下发，循环侧取走 Receiver）。
///
/// - 供方（发送端 / pull serve）收到命令后写 Pause/Resume 帧并门控自身推流；
/// - 消费方（接收端）收到命令后仅写 Pause/Resume 帧（数据面门控在对端，
///   本端读循环天然空闲故永不停止读——保证对端 Resume 帧可达）；
/// - 任一方向收到对端 Pause/Resume 帧：仅置位门控并抬发
///   [`TransferEvent::Paused`] / `Resumed`（宿主据以同步对端任务状态），不写回。
#[derive(Debug)]
pub struct PauseSlot {
    paused: Arc<std::sync::atomic::AtomicBool>,
    cmd_tx: mpsc::Sender<PauseCmd>,
    cmd_rx: tokio::sync::Mutex<Option<mpsc::Receiver<PauseCmd>>>,
}

impl PauseSlot {
    /// 新建句柄（通道容量 8；命令量极小，满则发送失败由宿主按返回 bool 处理）
    pub fn new() -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel::<PauseCmd>(8);
        Arc::new(Self {
            paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cmd_tx,
            cmd_rx: tokio::sync::Mutex::new(Some(cmd_rx)),
        })
    }

    /// 会话循环侧取走命令接收端（单次；无命令通道时返回 None）
    pub(crate) async fn take_receiver(&self) -> Option<mpsc::Receiver<PauseCmd>> {
        self.cmd_rx.lock().await.take()
    }

    /// 是否处于暂停态（供方数据面门控判据）
    pub fn is_paused(&self) -> bool {
        self.paused.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 本地指令：置门控位 + 下发命令（会话循环据此写 Pause/Resume 帧）
    pub async fn send(&self, cmd: PauseCmd) -> bool {
        match cmd {
            PauseCmd::Pause => self.paused.store(true, std::sync::atomic::Ordering::SeqCst),
            PauseCmd::Resume => self.paused.store(false, std::sync::atomic::Ordering::SeqCst),
        }
        self.cmd_tx.send(cmd).await.is_ok()
    }

    /// 对端帧置位（会话循环在收到对端 Pause/Resume 时调用；不写回）
    pub fn set_from_peer(&self, paused: bool) {
        self.paused.store(paused, std::sync::atomic::Ordering::SeqCst);
    }
}

/// 会话内部挂载的暂停上下文（候选编译期区分挂载与否）
pub(crate) enum SessionPause {
    /// 未挂暂停控制
    None,
    /// 已挂暂停控制（slot 供门控读取，cmd_rx 供 select 分支消费命令）
    Armed {
        slot: Arc<PauseSlot>,
        cmd_rx: mpsc::Receiver<PauseCmd>,
    },
}

impl SessionPause {
    /// 由宿主传入的可选句柄装配（取走命令接收端；会话循环单次消费）
    pub(crate) async fn from_optional(slot: Option<Arc<PauseSlot>>) -> Self {
        match slot {
            Some(slot) => match slot.take_receiver().await {
                Some(cmd_rx) => SessionPause::Armed {
                    slot: Arc::clone(&slot),
                    cmd_rx,
                },
                None => SessionPause::None,
            },
            None => SessionPause::None,
        }
    }
}

// ==================== 事件与终态 ====================

/// 会话终态（双端共用；宿主据此驱动 UI 与历史记录）
#[derive(Debug, Clone, PartialEq)]
pub enum TerminalState {
    /// 批内全部文件已完整落位
    Completed,
    /// 批被接收端拒绝
    Rejected { reason: RejectReason },
    /// 传输被取消；`by_peer` 标记取消来自对端还是本端操作
    Cancelled { by_peer: bool },
    /// 非终局失败（IO/协议错误/对端失联），detail 说明在哪一步失败
    Failed { detail: String },
}

/// 上报给宿主的传输事件（mpsc 通道消费；drop 接收端不阻断会话）
///
/// `remote` 为对端节点身份（接收方向 = 发送方，发送方向 = 接收方）：
/// 宿主据此在任务面展示「谁在发给我 / 发给了谁」，无需自建连接反查表。
#[derive(Debug)]
pub enum TransferEvent {
    /// 接收端收到 Offer 且策略为 Ask：等待宿主应答
    ///
    /// 宿主经 `reply` 回执 `true`=接受 / `false`=拒绝；弃置回执（drop
    /// Sender）等同拒绝。等待受策略 timeout 约束，逾期自动拒绝。
    OfferPending {
        /// 对端节点 ID
        remote: NodeId,
        /// 批 ID
        batch_id: String,
        /// 批内文件清单（供询问弹窗展示）
        files: Vec<FileMeta>,
        /// 批内总大小（字节）
        total_size: u64,
        /// 应答回执通道
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// 服务侧拉取会话开始（双端记账：供流方登记 send 任务）
    ///
    /// serve_pull 解析目标文件成功后上报；后续 Progress/Terminal 同 batch_id，
    /// 供流方据此登记/推进/结算一条 direction=send 的任务——拉取发起方（对端）
    /// 另有自己的 receive 任务，两端各自展示同一次传输。
    PullServed {
        /// 对端节点 ID（拉取发起方）
        remote: NodeId,
        /// 服务侧批 ID（"pull-{nanos}"，进度/终态同源）
        batch_id: String,
        /// 供流文件清单（单文件）
        files: Vec<FileMeta>,
        /// 批内总大小（字节）
        total_size: u64,
    },
    /// 进度：已传字节 / 总量 / 瞬时速率（B/s，滑动窗口）
    ///
    /// 发送端按「实际写入网络」计数，接收端按「实际落盘」计数——两侧
    /// 各自独立上报，互为校验。计数为批内累计口径（issue 06）：续传会话
    /// 把接收端已写偏移（含已完成文件的满额）计入基线，进度跨重试会话
    /// 单调推进至总量，不因重发归零。
    Progress {
        /// 对端节点 ID
        remote: NodeId,
        /// 批 ID
        batch_id: String,
        /// 本会话累计已传字节
        transferred: u64,
        /// 批内总大小（字节）
        total: u64,
        /// 瞬时速率（B/s；首个采样点为 0）
        rate_bps: f64,
    },
    /// 终态：每条会话恰好上报一次（成功/拒绝/取消/失败全覆盖）
    Terminal {
        /// 对端节点 ID
        remote: NodeId,
        /// 批 ID
        batch_id: String,
        /// 终态
        state: TerminalState,
    },
    /// 对端发来暂停帧：宿主据以把本端对应任务置 paused（数据面门控在对端）
    Paused {
        /// 对端节点 ID
        remote: NodeId,
        /// 批 ID
        batch_id: String,
    },
    /// 对端发来恢复帧：宿主据以把本端对应任务置回 running
    Resumed {
        /// 对端节点 ID
        remote: NodeId,
        /// 批 ID
        batch_id: String,
    },
}

// ==================== 内部辅助 ====================

/// 速率采样窗口（秒）：窗口内累计字节 / 窗口时长 = 窗口平均速率
///
/// 逐块采样（相邻两次采样之间只隔一个数据块）会在快网上产生亚毫秒窗口，
/// 把 64 KiB / 0.15 ms 放大成数百 MB/s 的假值；且两端各自采样时刻不同，
/// 屏幕上会出现「同一传输两侧速率差两个数量级」。窗口平均把采样抖动
/// 摊平到秒级，两端观测到的是同一段时间的同一批字节，数值自然对齐。
const RATE_WINDOW: Duration = Duration::from_millis(500);

/// 速率采样器：窗口平均速率（B/s）
#[derive(Debug)]
pub(crate) struct RateTracker {
    /// 本窗口起点（上次产出速率值的时刻）
    window_start: std::time::Instant,
    /// 本窗口起点时的累计字节
    window_bytes: u64,
    /// 上一次窗口速率（窗口未满时沿用，避免逐块返回 0 抖动）
    last_rate: f64,
    /// 最小窗口时长（测试可注入更短窗口）
    window: Duration,
}

impl RateTracker {
    pub(crate) fn new() -> Self {
        Self::with_window(RATE_WINDOW)
    }

    /// 指定窗口时长的采样器（测试专用：无需 sleep 即可驱动窗口边界）
    pub(crate) fn with_window(window: Duration) -> Self {
        Self {
            window_start: std::time::Instant::now(),
            window_bytes: 0,
            last_rate: 0.0,
            window,
        }
    }

    /// 采样当前累计字节数，返回窗口平均速率（B/s）
    ///
    /// 窗口未满时返回上次窗口速率（首个窗口返回 0）——累计字节持续喂入，
    /// 满窗后一次性产出「窗口增量 / 窗口时长」。
    pub(crate) fn sample(&mut self, total_bytes: u64) -> f64 {
        self.sample_at(total_bytes, std::time::Instant::now())
    }

    /// 带显式时刻的采样（纯函数式内核：单测以合成时刻驱动窗口边界）
    pub(crate) fn sample_at(&mut self, total_bytes: u64, now: std::time::Instant) -> f64 {
        let elapsed = now
            .saturating_duration_since(self.window_start)
            .as_secs_f64();
        if elapsed < self.window.as_secs_f64() {
            return self.last_rate;
        }
        let delta = total_bytes.saturating_sub(self.window_bytes);
        let rate = delta as f64 / elapsed;
        self.window_start = now;
        self.window_bytes = total_bytes;
        self.last_rate = rate;
        rate
    }

    /// 吸收续传基线跳变：把一次性入账的偏移并入窗口基线，
    /// 使后续窗口只度量本会话实际推流的增量（防速率尖峰失真）
    pub(crate) fn sync_base(&mut self, total_bytes: u64) {
        self.sync_base_at(total_bytes, std::time::Instant::now());
    }

    /// 带显式时刻的基线重置（纯函数式内核：单测以合成时刻驱动窗口边界）
    pub(crate) fn sync_base_at(&mut self, total_bytes: u64, now: std::time::Instant) {
        self.window_start = now;
        self.window_bytes = total_bytes;
        self.last_rate = 0.0;
    }
}

/// 纯函数：把发送方相对路径清洗为接收端落位的安全相对路径
///
/// 拒绝绝对路径、盘符/反斜杠（Windows 形状）、`..` 上溯与空结果——共享目录
/// 恒只读的对偶是「落位不越界」：恶意 Offer 不得把文件写到 download_dir 外。
fn sanitize_relative_path(path: &str) -> Option<PathBuf> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
        return None;
    }
    let mut out = PathBuf::new();
    for component in path.split('/') {
        match component {
            "" | "." => continue,
            ".." => return None,
            c if c.contains('\\') || c.contains(':') => return None,
            c => out.push(c),
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `.part` 临时文件名（与目标同目录，保证 rename 同卷原子；沿用 v2.0.0
/// upload session 的隐藏文件惯例并携带批 ID 与下标避免跨批碰撞）
fn part_file_name(batch_id: &str, index: u32) -> String {
    format!(".wasmnest-transfer-{batch_id}-{index}.part")
}

/// 上报一条事件；宿主已弃收通道时不阻断会话主流程
pub(crate) async fn emit(events: &mpsc::Sender<TransferEvent>, event: TransferEvent) {
    if events.send(event).await.is_err() {
        tracing::debug!("transfer event dropped: no host listener");
    }
}

// ==================== 接收角色 ====================

/// 接收端连接处理器：作为 [`ConnectionHandler`] 挂到节点上，信任放行后的
/// 连接进入接收会话（策略分流 → 落盘 → 终态上报）。
///
/// 单活跃会话假设（issue 05）：`cancel_token` 取消的是「当前活跃」的那条
/// 接收会话；并发多批属后续票。
pub struct TransferReceiveHandler {
    config: TransferConfig,
    events: mpsc::Sender<TransferEvent>,
    cancel: CancelToken,
}

impl TransferReceiveHandler {
    /// 构造接收处理器（config 决定策略与落点；events 为宿主事件通道）
    pub fn new(config: TransferConfig, events: mpsc::Sender<TransferEvent>) -> Self {
        Self {
            config,
            events,
            cancel: CancelToken::new(),
        }
    }

    /// 宿主取消入口的令牌句柄（clone 后可随时触发「取消进行中的接收」）
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }
}

impl crate::transport::ConnectionHandler for TransferReceiveHandler {
    fn handle(
        &self,
        conn: crate::transport::Connection,
    ) -> crate::transport::HandlerFuture {
        let config = self.config.clone();
        let events = self.events.clone();
        let cancel = self.cancel.clone();
        Box::pin(async move {
            let remote = conn.peer_node_id().clone();
            // batch_id 在 Offer 到达前未知：经槽位带回包装层供终态事件引用
            let mut batch_slot: Option<String> = None;
            let state = match run_receive(
                conn,
                &config,
                &events,
                &cancel,
                remote.clone(),
                &mut batch_slot,
                // 独立接收处理器无 batch 注册表：暂停入口由上层装配提供
                // （生产装配走 SharedDirHandler，见 crate::shared）
                None,
                None,
            )
            .await
            {
                    Ok(state) => state,
                    Err(e) => {
                        tracing::warn!("receive session failed: {e}");
                        TerminalState::Failed {
                            detail: e.to_string(),
                        }
                    }
                };
            emit(
                &events,
                TransferEvent::Terminal {
                    remote,
                    batch_id: batch_slot.unwrap_or_default(),
                    state,
                },
            )
            .await;
        })
    }
}

/// 错误构造辅助：会话层 IO/编解码失败
pub(crate) fn sess_io(role: &'static str, e: std::io::Error) -> crate::error::PeerNetError {
    crate::error::PeerNetError::TransferSession {
        role,
        detail: e.to_string(),
    }
}

/// 错误构造辅助：协议违规
pub(crate) fn proto_violation(role: &'static str, detail: impl Into<String>) -> crate::error::PeerNetError {
    crate::error::PeerNetError::TransferProtocol {
        role,
        detail: detail.into(),
    }
}

/// 取消收尾：发 Cancel 帧后排空对端仍在途的数据块（发送端收到 Cancel 即
/// 停发），最后优雅关闭。
///
/// 为何必须排空：「带未读数据关闭连接」会让内核回 RST，RST 会把对端尚未
/// 读取的缓冲（包括刚发出的 Cancel 帧）一并丢弃——对端因此误落 Failed 而
/// 不是 Cancelled{by_peer}。EOF 或宽限期到即停止等待。
///
/// 排空消费读半任务的帧通道（读半由独立任务持有，主循环不再直接读流）。
async fn send_cancel_then_drain_half<W>(
    wr: &mut W,
    frame_rx: &mut mpsc::Receiver<std::io::Result<IncomingFrame>>,
    by: CancelOrigin,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    let _ = message::write_control(wr, &TransferFrame::Cancel { by }).await;
    let _ = tokio::time::timeout(Duration::from_millis(200), async {
        // 数据块继续读掉（排空内核缓冲）；控制帧 / 通道关闭 / 读错误即停
        while let Some(Ok(IncomingFrame::Data(_))) = frame_rx.recv().await {}
    })
    .await;
    let _ = tokio::io::AsyncWriteExt::shutdown(wr).await;
}

/// 连接读半的帧转发通道容量（帧平均 64 KiB，16 帧 ≈ 1 MiB 在途上限；
/// 通道满即背压读半任务，不会无界缓存）
pub(crate) const FRAME_CHANNEL_CAP: usize = 16;

/// 启动读半转发任务：`read_frame` 内部是两个 `read_exact`，**不是取消安全的**
/// ——若被 `select!` 抢先取消，已从流中取走的半截帧字节会永久丢失，后续所有
/// 帧边界错位（对端随后读到 `unknown transfer frame kind 0xXX` 而整场失败）。
/// 故凡是「读帧要与其他分支竞速」的会话，都必须由本任务独占读半、只经通道
/// 向主循环交付**完整帧**；主循环侧的 `recv()` 是取消安全的。
pub(crate) fn spawn_frame_reader<R>(
    mut rd: R,
) -> (
    mpsc::Receiver<std::io::Result<IncomingFrame>>,
    tokio::task::JoinHandle<()>,
)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let (frame_tx, frame_rx) = mpsc::channel::<std::io::Result<IncomingFrame>>(FRAME_CHANNEL_CAP);
    let task = tokio::spawn(async move {
        loop {
            match message::read_frame(&mut rd).await {
                Ok(frame) => {
                    if frame_tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = frame_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });
    (frame_rx, task)
}

/// 读半任务守卫：会话函数任意出口（含 `?` 提前返回）都中止读半任务，
/// 避免会话结束后后台任务继续读已移交的连接
pub(crate) struct ReaderTaskGuard(tokio::task::JoinHandle<()>);

impl ReaderTaskGuard {
    /// 接管句柄（drop 即 abort）
    pub(crate) fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self(task)
    }
}

impl Drop for ReaderTaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 暂停命令分支：无暂停控制时永久挂起（select 分支自然失效）
pub(crate) async fn next_pause_cmd(pause: &mut SessionPause) -> Option<PauseCmd> {
    match pause {
        SessionPause::None => std::future::pending().await,
        SessionPause::Armed { cmd_rx, .. } => cmd_rx.recv().await,
    }
}

/// 写一条批协商应答（`enc_pub_key`：对加密 Offer 放行时携带的回执头，明文会话为 None）
pub(crate) async fn write_decision<W>(
    sink: &mut W,
    accepted: bool,
    reason: Option<RejectReason>,
    enc_pub_key: Option<String>,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    write_control(
        sink,
        &TransferFrame::Decision { accepted, reason, enc_pub_key },
    )
    .await
}

/// 接收会话核心流程：Offer → 策略分流 → 逐文件 StartFile/Data/FileDone →
/// BatchDone。终态事件由 [`TransferReceiveHandler`] 包装层统一上报，本函数
/// 只发 OfferPending / Progress 中间事件。
///
/// 断点契约（issue 06）：每个文件的续传起点 = `.part` 已落盘字节数，
/// 经 StartFile 告知发送端；取消/中断一律保留 `.part`；同 batch_id 重发
/// Offer 即续传，批内已完成文件跳过。
///
/// `pause`：接收侧本地暂停句柄（宿主按 batch_id 创建并登记）。挂载后本端作为
/// 数据消费方也能发起暂停/恢复——命令经会话循环写 Pause/Resume 帧请求对端
/// 发送会话门控推流（本端永不停止读，保证对端 Resume/Cancel 帧始终可达）。
/// 这补齐了「双端对同一传输任务对称暂停」：此前仅发送端/供流端能本地门控。
///
/// `pre_read`：上层分发器（issue 07 [`crate::shared::SharedDirHandler`]）已
/// 预读首帧做会话分流时传入该帧（必须为 Offer），独立接收端传 `None`。
pub(crate) async fn run_receive(
    mut conn: crate::transport::Connection,
    config: &TransferConfig,
    events: &mpsc::Sender<TransferEvent>,
    cancel: &CancelToken,
    remote: NodeId,
    batch_slot: &mut Option<String>,
    pause: Option<Arc<PauseSlot>>,
    pre_read: Option<IncomingFrame>,
) -> crate::Result<TerminalState> {
    const ROLE: &str = "receiver";

    // ---- Offer（信任放行后应立即到达）----
    let first = match pre_read {
        Some(frame) => frame,
        None => tokio::time::timeout(OFFER_TIMEOUT, message::read_frame(&mut conn))
            .await
            .map_err(|_| {
                proto_violation(ROLE, "timed out waiting for offer after trust gate")
            })?
            .map_err(|e| sess_io(ROLE, e))?,
    };
    let (batch_id, files, total_size, offer_encrypted, sender_enc_pub_key) =
        match *match first {
            IncomingFrame::Control(frame) => frame,
            IncomingFrame::Data(_) => {
                return Err(proto_violation(
                    ROLE,
                    "first transfer frame must be an offer, got data",
                ))
            }
        } {
            TransferFrame::Offer {
                protocol_version,
                batch_id,
                files,
                total_size,
                encrypted,
                enc_pub_key,
            } => {
                if protocol_version > TRANSFER_PROTOCOL_VERSION {
                    // 版本不识别：按拒绝回话并快速失败——静默错读未来协议更危险
                    let _ =
                        write_decision(&mut conn, false, Some(RejectReason::PolicyDenied), None)
                            .await;
                    return Err(proto_violation(
                        ROLE,
                        format!("offer protocol_version {protocol_version} is newer than supported"),
                    ));
                }
                // 加密请求头自洽性：声明加密却缺公钥即协议违规（fail-fast）
                if encrypted && enc_pub_key.is_none() {
                    return Err(proto_violation(
                        ROLE,
                        "offer declares encrypted=true but carries no enc_pub_key header",
                    ));
                }
                (batch_id, files, total_size, encrypted, enc_pub_key)
            }
            other => {
                return Err(proto_violation(
                    ROLE,
                    format!("first transfer frame must be an offer, got {other:?}"),
                ))
            }
        };
    *batch_slot = Some(batch_id.clone());

    // ---- 接收策略分流（spec Decision 10）----
    let mut batch = TransferBatch {
        batch_id: batch_id.clone(),
        files: files.clone(),
        total_size,
        state: BatchState::Pending,
        created_at: std::time::Instant::now(),
    };
    match &config.policy {
        ReceivePolicy::AlwaysDeny => {
            write_decision(&mut conn, false, Some(RejectReason::PolicyDenied), None)
                .await
                .map_err(|e| sess_io(ROLE, e))?;
            batch.state = BatchState::Rejected {
                reason: RejectReason::PolicyDenied,
            };
            return Ok(TerminalState::Rejected {
                reason: RejectReason::PolicyDenied,
            });
        }
        ReceivePolicy::AlwaysAccept => {}
        ReceivePolicy::Ask { timeout } => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            emit(
                events,
                TransferEvent::OfferPending {
                    remote: remote.clone(),
                    batch_id: batch_id.clone(),
                    files: files.clone(),
                    total_size,
                    reply: reply_tx,
                },
            )
            .await;

            // 应答语义分流：显式 false = 用户拒绝；弃置回执与超时同归为
            // 自动拒（无人应答即超时，安全姿态镜像首连闸门的「弃置等同拒绝」）
            enum AskOutcome {
                Accepted,
                Denied(RejectReason),
            }
            let outcome = match tokio::time::timeout(*timeout, reply_rx).await {
                Err(_elapsed) => AskOutcome::Denied(RejectReason::Timeout),
                Ok(Err(_dropped)) => AskOutcome::Denied(RejectReason::Timeout),
                Ok(Ok(true)) => AskOutcome::Accepted,
                Ok(Ok(false)) => AskOutcome::Denied(RejectReason::UserRejected),
            };
            match outcome {
                AskOutcome::Accepted => {}
                AskOutcome::Denied(reason) => {
                    write_decision(&mut conn, false, Some(reason), None)
                        .await
                        .map_err(|e| sess_io(ROLE, e))?;
                    batch.state = BatchState::Rejected { reason };
                    return Ok(TerminalState::Rejected { reason });
                }
            }
        }
    }

    // pending → approved 是唯一合法迁移（状态机纯函数在此消费）
    validate_batch_transition(&batch.state, &BatchState::Approved)
        .map_err(|detail| proto_violation(ROLE, detail))?;
    batch.state = BatchState::Approved;

    // ---- 加密协商结算（接收方自动解密契约）：对加密 Offer 生成本端临时密钥，
    // 放行应答携带公钥回执头；明文会话两值均为 None。派生失败即协商破裂 fail-fast
    let (cipher, enc_ack_key) = if offer_encrypted {
        let keys = crypto::EphemeralKeys::generate();
        let cipher = keys
            .derive_cipher(sender_enc_pub_key.as_deref().unwrap_or_default(), &batch_id)
            .map_err(|e| sess_io(ROLE, e))?;
        tracing::debug!(batch_id = %batch_id, "incoming batch requests encryption, acking with session key");
        (Some(cipher), Some(keys.public_hex().to_string()))
    } else {
        (None, None)
    };

    // ---- 放行：应答后进入逐文件数据面（与 pull 接收共用的下半程）----
    write_decision(&mut conn, true, None, enc_ack_key)
        .await
        .map_err(|e| sess_io(ROLE, e))?;
    receive_files_after_accept(
        conn,
        config,
        events,
        cancel,
        remote,
        &batch_id,
        &files,
        total_size,
        cipher,
        SessionPause::from_optional(pause).await,
    )
    .await
}

/// 放行后的逐文件接收数据面：建落点目录 → 逐文件 StartFile/Data/FileDone →
/// BatchDone。由 [`run_receive`]（push 批放行后）与 issue 07 的 pull 客户端
/// 流程共用——断点真源契约（issue 06）、取消语义与落位钩子在两条路径上
/// 天然一致。
///
/// 调用方负责已写 Decision{accepted=true}（push 协商放行）或按语义免协商
/// （pull 是用户主动获取，恒放行）。`cipher`：加密协商成立时由调用方传入的
/// 会话密码上下文——本函数只负责对每个数据帧自动解密后落盘。
pub(crate) async fn receive_files_after_accept(
    conn: crate::transport::Connection,
    config: &TransferConfig,
    events: &mpsc::Sender<TransferEvent>,
    cancel: &CancelToken,
    remote: NodeId,
    batch_id: &str,
    files: &[FileMeta],
    total_size: u64,
    cipher: Option<crypto::SessionCipher>,
    pause: SessionPause,
) -> crate::Result<TerminalState> {
    const ROLE: &str = "receiver";

    // ---- 建落点目录，进入数据面 ----
    tokio::fs::create_dir_all(&config.download_dir)
        .await
        .map_err(|e| sess_io(ROLE, e))?;

    // 暂停控制：拆读写两半——暂停命令分支需独立写半（与读半无借用冲突）。
    // 消费方（本端）永不停止读：对端门控推流后本循环天然空闲，保证对端
    // Resume/Cancel 帧始终可达；对端 Pause/Resume 帧仅置位门控并抬发事件。
    let mut pause = pause;
    let pause_slot = match &pause {
        SessionPause::Armed { slot, .. } => Some(Arc::clone(slot)),
        SessionPause::None => None,
    };
    let (rd, mut wr) = tokio::io::split(conn);
    // 读半由独立任务独占：read_frame 不是取消安全的，本循环的 select 若直接
    // 读流，暂停命令分支抢先时会吞掉半截帧 → 帧边界错位（对端报 unknown
    // transfer frame kind）。任务经通道只交付完整帧，通道接收取消安全。
    let (mut frame_rx, reader_task) = spawn_frame_reader(rd);
    let _reader_guard = ReaderTaskGuard::new(reader_task);

    let mut transferred_total: u64 = 0;
    // 会话内全局数据块序号：与发送端推流侧锁步计数一致，参与 nonce 构造
    let mut chunk_counter: u64 = 0;
    let mut rate = RateTracker::new();

    for (index, meta) in files.iter().enumerate() {
        let index = index as u32;

        // 落位安全：清洗相对路径，拒绝越界写（共享目录只读的对偶约束）
        let rel = sanitize_relative_path(&meta.path).ok_or_else(|| {
            proto_violation(
                ROLE,
                format!("offer carries unsafe relative path: {}", meta.path),
            )
        })?;
        let target = config.download_dir.join(&rel);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| sess_io(ROLE, e))?;
        }
        let tmp_dir = target.parent().unwrap_or(&config.download_dir).to_path_buf();
        let tmp = tmp_dir.join(part_file_name(batch_id, index));

        // ---- 断点扫描（issue 06）：三类起点，断点真源恒在落盘侧 ----
        // 1) target 已落位且尺寸与 Offer 一致 → 上次会话已完成：声明满偏移，
        //    发送端 remaining=0 零推流；本端不重写不 rename，直接 FileDone
        // 2) target 已存在但尺寸不符 → 名称冲突（沿用 v2.0.0 duplicate-name
        //    语义）整批失败——提前判定避免白白重传后 rename 才撞上
        // 3) 无 target：.part 已写字节即续传起点；超过声明大小的残留视为
        //    脏数据弃用（源文件变小场景）
        let target_meta = tokio::fs::metadata(&target).await;
        if let Ok(m) = &target_meta {
            if m.len() != meta.size {
                return Ok(TerminalState::Failed {
                    detail: format!(
                        "target already exists with different size (expected {}, got {}): {}",
                        meta.size,
                        m.len(),
                        target.display()
                    ),
                });
            }
        }
        let completed = target_meta.is_ok();
        let offset = if completed {
            meta.size
        } else {
            match tokio::fs::metadata(&tmp).await {
                Ok(m) if m.len() <= meta.size => m.len(),
                _ => 0,
            }
        };

        message::write_control(&mut wr, &TransferFrame::StartFile { index, offset })
            .await
            .map_err(|e| sess_io(ROLE, e))?;

        // 进度按批聚合：续传基线先入账（已完成文件以满额计入），本会话
        // 推流字节在其上累加——重试后进度从真实批位置继续而非归零
        transferred_total += offset;
        rate.sync_base(transferred_total);
        emit(
            events,
            TransferEvent::Progress {
                remote: remote.clone(),
                batch_id: batch_id.to_string(),
                transferred: transferred_total,
                total: total_size,
                rate_bps: rate.sample(transferred_total),
            },
        )
        .await;

        if completed {
            // 正常路径 rename 已消耗 .part；此处残留仅见于异常竞态，尽力清埋
            let _ = tokio::fs::remove_file(&tmp).await;
            message::write_control(&mut wr, &TransferFrame::FileDone { index })
                .await
                .map_err(|e| sess_io(ROLE, e))?;
            continue;
        }
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            // 全新起点截断打开：清掉脏 .part 可能遗留的尾部字节
            .truncate(offset == 0)
            .open(&tmp)
            .await
            .map_err(|e| sess_io(ROLE, e))?;
        tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| sess_io(ROLE, e))?;

        let mut remaining = meta.size - offset;
        while remaining > 0 {
            let frame = tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    // 接收方取消：告知对端并排空在途数据（防 RST 吞帧）、
                    // 保留 .part（断点真源）、落本端取消
                    send_cancel_then_drain_half(&mut wr, &mut frame_rx, CancelOrigin::Receiver).await;
                    return Ok(TerminalState::Cancelled { by_peer: false });
                }
                cmd = next_pause_cmd(&mut pause) => {
                    // 本端暂停/恢复：写 Pause/Resume 帧告知数据供方门控推流
                    match cmd {
                        Some(PauseCmd::Pause) => {
                            message::write_control(
                                &mut wr,
                                &TransferFrame::Pause { batch_id: batch_id.to_string() },
                            )
                            .await
                            .map_err(|e| sess_io(ROLE, e))?;
                        }
                        Some(PauseCmd::Resume) => {
                            message::write_control(
                                &mut wr,
                                &TransferFrame::Resume { batch_id: batch_id.to_string() },
                            )
                            .await
                            .map_err(|e| sess_io(ROLE, e))?;
                        }
                        None => {}
                    }
                    continue;
                }
                // 读半任务交付完整帧（通道接收取消安全）：暂停/取消分支抢先
                // 不会丢弃半截帧，帧边界恒对齐
                frame = frame_rx.recv() => match frame {
                    Some(Ok(frame)) => frame,
                    Some(Err(e)) => return Err(sess_io(ROLE, e)),
                    None => {
                        return Err(sess_io(
                            ROLE,
                            std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "peer closed connection mid-transfer",
                            ),
                        ))
                    }
                },
            };
            match frame {
                IncomingFrame::Data(bytes) => {
                    // 加密会话：先解密（含 GCM 认证），再按明文长度校验越界。
                    // 块序号与文件内偏移由本函数锁步推进，与发送端构造参数严格一致
                    let plaintext = match &cipher {
                        Some(c) => c
                            .decrypt_chunk(index, meta.size - remaining, chunk_counter, &bytes)
                            .map_err(|e| sess_io(ROLE, e))?,
                        None => bytes,
                    };
                    chunk_counter += 1;
                    if plaintext.len() as u64 > remaining {
                        return Err(proto_violation(
                            ROLE,
                            format!(
                                "data chunk {} bytes overruns remaining {remaining} of {}",
                                plaintext.len(),
                                meta.path
                            ),
                        ));
                    }
                    tokio::io::AsyncWriteExt::write_all(&mut file, &plaintext)
                        .await
                        .map_err(|e| sess_io(ROLE, e))?;
                    remaining -= plaintext.len() as u64;
                    transferred_total += plaintext.len() as u64;
                    emit(
                        events,
                        TransferEvent::Progress {
                            remote: remote.clone(),
                            batch_id: batch_id.to_string(),
                            transferred: transferred_total,
                            total: total_size,
                            rate_bps: rate.sample(transferred_total),
                        },
                    )
                    .await;
                }
                IncomingFrame::Control(boxed) => match *boxed {
                    TransferFrame::Cancel {
                        by: CancelOrigin::Sender,
                    } => {
                        // 发送方取消：保留 .part，落对端取消终态
                        return Ok(TerminalState::Cancelled { by_peer: true });
                    }
                    TransferFrame::Pause { .. } => {
                        // 数据供方暂停：本端任务同步 paused；门控在对端（不写回）
                        if let Some(slot) = &pause_slot {
                            slot.set_from_peer(true);
                        }
                        emit(
                            events,
                            TransferEvent::Paused {
                                remote: remote.clone(),
                                batch_id: batch_id.to_string(),
                            },
                        )
                        .await;
                    }
                    TransferFrame::Resume { .. } => {
                        if let Some(slot) = &pause_slot {
                            slot.set_from_peer(false);
                        }
                        emit(
                            events,
                            TransferEvent::Resumed {
                                remote: remote.clone(),
                                batch_id: batch_id.to_string(),
                            },
                        )
                        .await;
                    }
                    other => {
                        return Err(proto_violation(
                            ROLE,
                            format!("unexpected control frame during data phase: {other:?}"),
                        ))
                    }
                },
            }
        }

        // 单文件完整落位：flush + sync 保证断点真源可信，再同卷原子 rename；
        // 目标已存在 = 竞态失败（沿用 v2.0.0 duplicate-name 语义），保留 .part
        tokio::io::AsyncWriteExt::flush(&mut file)
            .await
            .map_err(|e| sess_io(ROLE, e))?;
        file.sync_all().await.map_err(|e| sess_io(ROLE, e))?;
        drop(file);
        if target.exists() {
            return Ok(TerminalState::Failed {
                detail: format!(
                    "target already exists: {} (partial kept at {})",
                    target.display(),
                    tmp.display()
                ),
            });
        }
        tokio::fs::rename(&tmp, &target)
            .await
            .map_err(|e| sess_io(ROLE, e))?;

        // 落位钩子（issue 07）：完整文件已就位；实现方自行兜底失败，
        // 引擎不因钩子结果改变会话终态（移动端在此提升 MediaStore）
        if let Some(landing) = &config.landing {
            let display_name = target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            landing.landed(&target, &display_name);
        }

        message::write_control(&mut wr, &TransferFrame::FileDone { index })
            .await
            .map_err(|e| sess_io(ROLE, e))?;
    }

    message::write_control(&mut wr, &TransferFrame::BatchDone {})
        .await
        .map_err(|e| sess_io(ROLE, e))?;
    tracing::info!(batch_id = %batch_id, "transfer batch received completely");
    Ok(TerminalState::Completed)
}

// ==================== 发送角色 ====================

/// 发送端待发文件（本机源路径 + 对外相对路径）
#[derive(Debug, Clone)]
pub struct OutgoingFile {
    /// 本机源文件
    pub source: PathBuf,
    /// 告知对端的相对路径（接收端落位形状，经对端清洗校验）
    pub remote_path: String,
}

impl OutgoingFile {
    /// 构造待发文件（remote_path 取源文件名）
    pub fn new(source: impl Into<PathBuf>) -> Self {
        let source = source.into();
        let remote_path = source
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            source,
            remote_path,
        }
    }
}

/// 在已拨号的可信连接上推送一批文件（发送角色会话主入口）
///
/// 终态同时经 `events` 上报与返回值给出；本地准备失败（源不可读等）返回
/// Err 并上报 Failed 终态。`cancel` 由宿主持有，随时可取消进行中的发送。
///
/// `encrypt`：应用层加密开关（宿主设置面持久化，默认关）。开启后本会话
/// 生成临时 X25519 密钥对、Offer 携带加密请求头；接收端未回加密回执头
/// （旧版不支持）则 fail-fast，禁止静默明文降级。
///
/// `pause`：暂停控制句柄（宿主创建）；暂停时门控本端推流（连接保持），
/// 对端暂停帧到达时同样置位门控并抬发 Paused/Resumed 事件。
pub async fn send_batch(
    conn: crate::transport::Connection,
    batch_id: String,
    files: Vec<OutgoingFile>,
    events: mpsc::Sender<TransferEvent>,
    cancel: CancelToken,
    encrypt: bool,
    pause: Option<Arc<PauseSlot>>,
) -> crate::Result<TerminalState> {
    let remote = conn.peer_node_id().clone();
    // 宿主未挂暂停句柄时会话内自建：对端（接收方）发来的 Pause/Resume 帧
    // 必须总能门控本端推流。句柄缺位曾被静默吞掉——接收方按暂停，发送方
    // 没有门控落点，数据照传（真机现象「一端显示已暂停、对端仍在传输」）。
    let session_pause = SessionPause::from_optional(Some(pause.unwrap_or_else(PauseSlot::new))).await;
    let state = match run_send(
        conn,
        &batch_id,
        files,
        &events,
        &cancel,
        remote.clone(),
        encrypt,
        session_pause,
    )
    .await
    {
        Ok(state) => state,
        Err(e) => {
            tracing::warn!("send session failed: {e}");
            TerminalState::Failed {
                detail: e.to_string(),
            }
        }
    };
    emit(
        &events,
        TransferEvent::Terminal {
            remote,
            batch_id,
            state: state.clone(),
        },
    )
    .await;
    Ok(state)
}

/// 读一帧或让位于取消：None 表示本端取消已触发
pub(crate) async fn next_frame_or_cancel(
    rx: &mut mpsc::Receiver<std::io::Result<IncomingFrame>>,
    cancel: &CancelToken,
) -> crate::Result<Option<IncomingFrame>> {
    const ROLE: &str = "sender";
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(None),
        frame = async {
            match tokio::time::timeout(IDLE_CONTROL_TIMEOUT, rx.recv()).await {
                // 空闲超时：对端协商/确认阶段无响应
                Err(_elapsed) => Err(proto_violation(ROLE, "timed out waiting for peer frame")),
                // 连接关闭：reader 任务退出且通道排空
                Ok(None) => Err(sess_io(
                    ROLE,
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "peer closed connection"),
                )),
                Ok(Some(result)) => result.map_err(|e| sess_io(ROLE, e)),
            }
        } => frame.map(Some),
    }
}

/// 控制相等待（会话级暂停面）：等待「本阶段期待的帧」的同时处理暂停面——
///
/// 1. **消费本地暂停命令**：暂停/恢复在任何阶段按下都要下发到对端（写
///    Pause/Resume 帧；本端数据面门控由 `PauseSlot::send` 先行置位）；
/// 2. **容忍并处理对端暂停帧**：置位门控 + 抬发 [`TransferEvent::Paused`] /
///    [`TransferEvent::Resumed`]，然后继续等本阶段真正期待的帧。
///
/// 为什么必须容忍：暂停是会话级信号，用户可能在「推流中」以外的任何时点按下
/// （等 StartFile / 等 FileDone / 等 BatchDone；对端拉取也可能恰好在数据块
/// 全推完、等 FileDone 时暂停）。历史实现把这些阶段收到的 Pause 帧判为协议
/// 违规并整场 Failed——真机现象「一端按暂停，对端会话直接失败」。
///
/// 返回值语义与 [`next_frame_or_cancel`] 一致（None = 本端取消）。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn next_frame_handling_pause<W>(
    wr: &mut W,
    frame_rx: &mut mpsc::Receiver<std::io::Result<IncomingFrame>>,
    cancel: &CancelToken,
    pause: &mut SessionPause,
    pause_slot: &Option<Arc<PauseSlot>>,
    events: &mpsc::Sender<TransferEvent>,
    remote: &NodeId,
    batch_id: &str,
) -> crate::Result<Option<IncomingFrame>>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(None),
            cmd = next_pause_cmd(pause) => {
                // 本地暂停/恢复：写帧告知对端（门控已由 slot 置位）
                match cmd {
                    Some(PauseCmd::Pause) => {
                        let _ = message::write_control(
                            wr,
                            &TransferFrame::Pause { batch_id: batch_id.to_string() },
                        )
                        .await;
                    }
                    Some(PauseCmd::Resume) => {
                        let _ = message::write_control(
                            wr,
                            &TransferFrame::Resume { batch_id: batch_id.to_string() },
                        )
                        .await;
                    }
                    None => {}
                }
                continue;
            }
            frame = next_frame_or_cancel(frame_rx, cancel) => {
                match frame? {
                    Some(IncomingFrame::Control(boxed)) => match *boxed {
                        TransferFrame::Pause { .. } => {
                            if let Some(slot) = pause_slot {
                                slot.set_from_peer(true);
                            }
                            emit(
                                events,
                                TransferEvent::Paused {
                                    remote: remote.clone(),
                                    batch_id: batch_id.to_string(),
                                },
                            )
                            .await;
                            continue;
                        }
                        TransferFrame::Resume { .. } => {
                            if let Some(slot) = pause_slot {
                                slot.set_from_peer(false);
                            }
                            emit(
                                events,
                                TransferEvent::Resumed {
                                    remote: remote.clone(),
                                    batch_id: batch_id.to_string(),
                                },
                            )
                            .await;
                            continue;
                        }
                        other => return Ok(Some(IncomingFrame::Control(Box::new(other)))),
                    },
                    other => return Ok(other),
                }
            }
        }
    }
}

/// 发送会话核心流程：Offer → Decision → 逐文件 StartFile/Data/FileDone →
/// BatchDone。连接拆读写两半：读半由独立任务持续收帧转发通道，写半在
/// 主循环推流——保证流式推送期间仍能即时感知对端取消。
async fn run_send(
    mut conn: crate::transport::Connection,
    batch_id: &str,
    files: Vec<OutgoingFile>,
    events: &mpsc::Sender<TransferEvent>,
    cancel: &CancelToken,
    remote: NodeId,
    encrypt: bool,
    pause: SessionPause,
) -> crate::Result<TerminalState> {
    const ROLE: &str = "sender";

    // ---- 本地准备：stat 源文件构造 Offer 清单 ----
    let mut metas = Vec::with_capacity(files.len());
    let mut total_size: u64 = 0;
    for file in &files {
        let size = tokio::fs::metadata(&file.source)
            .await
            .map_err(|e| sess_io(ROLE, e))?
            .len();
        metas.push(FileMeta::new(file.remote_path.clone(), size));
        total_size = total_size.saturating_add(size);
    }

    // ---- 加密请求头：开关开启即随 Offer 携带临时 X25519 公钥（每会话全新）----
    let ephemeral = if encrypt {
        Some(crypto::EphemeralKeys::generate())
    } else {
        None
    };
    message::write_control(
        &mut conn,
        &TransferFrame::Offer {
            protocol_version: TRANSFER_PROTOCOL_VERSION,
            batch_id: batch_id.to_string(),
            files: metas.clone(),
            total_size,
            encrypted: ephemeral.is_some(),
            enc_pub_key: ephemeral.as_ref().map(|k| k.public_hex().to_string()),
        },
    )
    .await
    .map_err(|e| sess_io(ROLE, e))?;

    // ---- 拆半 + 读半任务：控制帧即时可见，不被推流阻塞 ----
    let (mut rd, mut wr) = tokio::io::split(conn);
    let (frame_tx, mut frame_rx) = mpsc::channel::<std::io::Result<IncomingFrame>>(16);
    let reader_task = tokio::spawn(async move {
        loop {
            match read_frame_half(&mut rd).await {
                Ok(frame) => {
                    if frame_tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = frame_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    let outcome = drive_send(
        &mut wr,
        batch_id,
        &metas,
        total_size,
        files,
        events,
        cancel,
        remote,
        &mut frame_rx,
        ephemeral,
        pause,
    )
    .await;
    reader_task.abort();
    outcome
}

/// 读半任务的单帧读取（泛型收窄到 split 出的读半）
async fn read_frame_half<R>(stream: &mut R) -> std::io::Result<IncomingFrame>
where
    R: tokio::io::AsyncRead + Unpin,
{
    message::read_frame(stream).await
}

/// 发送主状态机：逐文件「等 StartFile → 推流 → 等 FileDone」，最后等 BatchDone
///
/// `ephemeral`：加密请求头协商上下文（None = 明文会话）。有值时 Decision
/// 回执必须携带对端临时公钥，缺头即旧版不支持 → fail-fast（静默明文降级
/// 比失败更危险）；协商成立则逐块 AES-256-GCM 加密推流。
#[allow(clippy::too_many_arguments)]
async fn drive_send(
    wr: &mut (impl tokio::io::AsyncWrite + Unpin + Send),
    batch_id: &str,
    metas: &[FileMeta],
    total_size: u64,
    files: Vec<OutgoingFile>,
    events: &mpsc::Sender<TransferEvent>,
    cancel: &CancelToken,
    remote: NodeId,
    frame_rx: &mut mpsc::Receiver<std::io::Result<IncomingFrame>>,
    ephemeral: Option<crate::transfer::crypto::EphemeralKeys>,
    mut pause: SessionPause,
) -> crate::Result<TerminalState> {
    const ROLE: &str = "sender";

    // 暂停门控：供方侧门控自身推流（暂停时不再读源写网络，连接保持，
    // 仍读对端帧——对端 Resume/Cancel 必须可达）；命令分支负责写帧。
    let pause_slot = match &pause {
        SessionPause::Armed { slot, .. } => Some(Arc::clone(slot)),
        SessionPause::None => None,
    };

    // ---- 批协商应答（含加密回执头结算）----
    // 协商应答等待同样处理暂停面：暂停在任一阶段按下都要下发给对端
    let decision = next_frame_handling_pause(
        wr,
        frame_rx,
        cancel,
        &mut pause,
        &pause_slot,
        events,
        &remote,
        batch_id,
    )
    .await?;
    let Some(IncomingFrame::Control(boxed)) = decision else {
        return Err(proto_violation(ROLE, "expected decision frame"));
    };
    let cipher = match *boxed {
        TransferFrame::Decision {
            accepted: true,
            reason: None,
            enc_pub_key,
        } => match ephemeral {
            None => None,
            Some(keys) => {
                let peer_key = enc_pub_key.ok_or_else(|| {
                    proto_violation(
                        ROLE,
                        "peer lacks transfer encryption support (no ack header on accept)",
                    )
                })?;
                let cipher = keys
                    .derive_cipher(&peer_key, batch_id)
                    .map_err(|e| sess_io(ROLE, e))?;
                tracing::debug!(batch_id = %batch_id, "transfer session encryption negotiated");
                Some(cipher)
            }
        },
        TransferFrame::Decision { accepted: false, reason, .. } => {
            // reason 缺省视为协议违规（拒绝必须带原因）
            let reason = reason.ok_or_else(|| {
                proto_violation(ROLE, "decision rejected without reason")
            })?;
            return Ok(TerminalState::Rejected { reason });
        }
        TransferFrame::Cancel { by: CancelOrigin::Receiver } => {
            return Ok(TerminalState::Cancelled { by_peer: true });
        }
        other => {
            return Err(proto_violation(
                ROLE,
                format!("expected decision after offer, got {other:?}"),
            ))
        }
    };

    let chunk_capacity = 64 * 1024usize; // 与缺省 chunk_size 一致；仅作读缓冲上限
    let mut buf = vec![0u8; chunk_capacity];
    let mut transferred_total: u64 = 0;
    // 会话内全局数据块序号（跨文件连续，与接收端按帧锁步计数一致）：
    // 参与 nonce 构造保证唯一；重试换新会话即新临时密钥，计数归零无碰撞
    let mut chunk_counter: u64 = 0;
    let mut rate = RateTracker::new();

    for (index, meta) in metas.iter().enumerate() {
        let index = index as u32;

        // ---- 等接收端声明起点（断点真源）----
        let start = next_frame_handling_pause(
            wr,
            frame_rx,
            cancel,
            &mut pause,
            &pause_slot,
            events,
            &remote,
            batch_id,
        )
        .await?;
        let Some(IncomingFrame::Control(boxed)) = start else {
            return Err(proto_violation(ROLE, "expected start_file frame"));
        };
        let offset = match *boxed {
            TransferFrame::StartFile {
                index: start_index,
                offset,
            } if start_index == index => offset,
            TransferFrame::Cancel {
                by: CancelOrigin::Receiver,
            } => return Ok(TerminalState::Cancelled { by_peer: true }),
            other => {
                return Err(proto_violation(
                    ROLE,
                    format!("expected start_file for index {index}, got {other:?}"),
                ))
            }
        };
        if offset > meta.size {
            return Err(proto_violation(
                ROLE,
                format!("peer reported offset {offset} beyond declared size {}", meta.size),
            ));
        }

        // 进度按批聚合（issue 06）：接收端声明的续传基线先入账——重试会话
        // 的进度从真实批位置继续推进至全量，而非每次归零只计补发字节
        transferred_total += offset;
        rate.sync_base(transferred_total);

        // ---- 从对端声明的偏移起推流（不允许自行从头开始）----
        let mut source = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&files[index as usize].source)
            .await
            .map_err(|e| sess_io(ROLE, e))?;
        tokio::io::AsyncSeekExt::seek(&mut source, std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| sess_io(ROLE, e))?;

        let mut remaining = meta.size - offset;
        while remaining > 0 {
            let paused = pause_slot.as_ref().map(|s| s.is_paused()).unwrap_or(false);
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    // 本端取消：告知对端后落本端取消终态；接收端保留 .part
                    let _ = message::write_control(
                        wr,
                        &TransferFrame::Cancel { by: CancelOrigin::Sender },
                    )
                    .await;
                    return Ok(TerminalState::Cancelled { by_peer: false });
                }
                cmd = next_pause_cmd(&mut pause) => {
                    // 本端暂停/恢复：写 Pause/Resume 帧并（供方）停/续推流
                    match cmd {
                        Some(PauseCmd::Pause) => {
                            let _ = message::write_control(
                                wr,
                                &TransferFrame::Pause { batch_id: batch_id.to_string() },
                            )
                            .await;
                        }
                        Some(PauseCmd::Resume) => {
                            let _ = message::write_control(
                                wr,
                                &TransferFrame::Resume { batch_id: batch_id.to_string() },
                            )
                            .await;
                        }
                        None => {}
                    }
                    continue;
                }
                frame = frame_rx.recv() => {
                    // 推流期间只接受对端取消/暂停/恢复；其余帧均为乱序违规
                    let incoming = match frame {
                        Some(result) => result.map_err(|e| sess_io(ROLE, e))?,
                        None => {
                            return Err(sess_io(
                                ROLE,
                                std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "peer closed connection mid-file",
                                ),
                            ))
                        }
                    };
                    match incoming {
                        IncomingFrame::Control(boxed) => match *boxed {
                            TransferFrame::Cancel { .. } => {
                                return Ok(TerminalState::Cancelled { by_peer: true });
                            }
                            TransferFrame::Pause { .. } => {
                                if let Some(slot) = &pause_slot {
                                    slot.set_from_peer(true);
                                }
                                emit(
                                    events,
                                    TransferEvent::Paused {
                                        remote: remote.clone(),
                                        batch_id: batch_id.to_string(),
                                    },
                                )
                                .await;
                            }
                            TransferFrame::Resume { .. } => {
                                if let Some(slot) = &pause_slot {
                                    slot.set_from_peer(false);
                                }
                                emit(
                                    events,
                                    TransferEvent::Resumed {
                                        remote: remote.clone(),
                                        batch_id: batch_id.to_string(),
                                    },
                                )
                                .await;
                            }
                            other => {
                                return Err(proto_violation(
                                    ROLE,
                                    format!("unexpected control frame while streaming: {other:?}"),
                                ))
                            }
                        },
                        IncomingFrame::Data(_) => {
                            return Err(proto_violation(ROLE, "data frame is receiver-to-sender only"))
                        }
                    }
                }
                read = tokio::io::AsyncReadExt::read(&mut source, &mut buf), if !paused => {
                    let n = read.map_err(|e| sess_io(ROLE, e))?;
                    if n == 0 {
                        return Err(sess_io(
                            ROLE,
                            std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                format!("source file truncated mid-transfer: {}", meta.path),
                            ),
                        ));
                    }
                    // 加密会话：本块在文件内的绝对偏移参与 AAD 位置绑定，
                    // 密文（含 GCM tag）经同一条数据帧通道推送
                    let payload = match &cipher {
                        Some(c) => {
                            c.encrypt_chunk(index, meta.size - remaining, chunk_counter, &buf[..n])
                        }
                        None => buf[..n].to_vec(),
                    };
                    chunk_counter += 1;
                    message::write_data(wr, &payload)
                        .await
                        .map_err(|e| sess_io(ROLE, e))?;
                    remaining -= n as u64;
                    transferred_total += n as u64;
                    emit(
                        events,
                        TransferEvent::Progress {
                            remote: remote.clone(),
                            batch_id: batch_id.to_string(),
                            transferred: transferred_total,
                            total: total_size,
                            rate_bps: rate.sample(transferred_total),
                        },
                    )
                    .await;
                }
            }
        }

        // ---- 等该文件落位确认 ----
        let done = next_frame_handling_pause(
            wr,
            frame_rx,
            cancel,
            &mut pause,
            &pause_slot,
            events,
            &remote,
            batch_id,
        )
        .await?;
        match done {
            None => {
                let _ = message::write_control(
                    wr,
                    &TransferFrame::Cancel { by: CancelOrigin::Sender },
                )
                .await;
                return Ok(TerminalState::Cancelled { by_peer: false });
            }
            Some(IncomingFrame::Control(boxed)) => match *boxed {
                TransferFrame::FileDone { index: done_index } if done_index == index => {}
                TransferFrame::Cancel { .. } => {
                    return Ok(TerminalState::Cancelled { by_peer: true });
                }
                other => {
                    return Err(proto_violation(
                        ROLE,
                        format!("expected file_done for index {index}, got {other:?}"),
                    ))
                }
            },
            Some(IncomingFrame::Data(_)) => {
                return Err(proto_violation(ROLE, "data frame is receiver-to-sender only"))
            }
        }
    }

    // ---- 批完成确认 ----
    let done = next_frame_handling_pause(
        wr,
        frame_rx,
        cancel,
        &mut pause,
        &pause_slot,
        events,
        &remote,
        batch_id,
    )
    .await?;
    match done {
        Some(IncomingFrame::Control(boxed)) if matches!(*boxed, TransferFrame::BatchDone {}) => {
            tracing::info!(batch_id = %batch_id, "transfer batch sent completely");
            Ok(TerminalState::Completed)
        }
        Some(other) => Err(proto_violation(
            ROLE,
            format!("expected batch_done after last file, got {other:?}"),
        )),
        None => {
            let _ = message::write_control(
                wr,
                &TransferFrame::Cancel { by: CancelOrigin::Sender },
            )
            .await;
            Ok(TerminalState::Cancelled { by_peer: false })
        }
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::io::AsyncRead;

    // ==================== 假流：按测试节奏喂字节（模拟真实链路分段到达） ====================

    #[derive(Default)]
    struct PipeState {
        data: Vec<u8>,
        pos: usize,
        waker: Option<std::task::Waker>,
        closed: bool,
    }

    /// 可增量喂入的假读流：无数据即挂起（不自行唤醒），由测试显式喂字节唤醒
    struct PipeReader {
        state: Arc<Mutex<PipeState>>,
    }

    impl PipeReader {
        fn new(state: Arc<Mutex<PipeState>>) -> Self {
            Self { state }
        }

        /// 追加字节并唤醒挂起的读（模拟对端继续推流）
        fn feed(state: &Arc<Mutex<PipeState>>, bytes: &[u8]) {
            let waker = {
                let mut guard = state.lock().expect("pipe state lock");
                guard.data.extend_from_slice(bytes);
                guard.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn close(state: &Arc<Mutex<PipeState>>) {
            let waker = {
                let mut guard = state.lock().expect("pipe state lock");
                guard.closed = true;
                guard.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    impl AsyncRead for PipeReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let mut guard = self.state.lock().expect("pipe state lock");
            if guard.pos >= guard.data.len() {
                if guard.closed {
                    return std::task::Poll::Ready(Ok(())); // EOF
                }
                guard.waker = Some(cx.waker().clone());
                return std::task::Poll::Pending;
            }
            let n = (guard.data.len() - guard.pos).min(buf.remaining());
            let (start, end) = (guard.pos, guard.pos + n);
            buf.put_slice(&guard.data[start..end]);
            guard.pos = end;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// 编码若干控制帧为线字节
    async fn encode_frames(frames: &[TransferFrame]) -> Vec<u8> {
        let mut buf = Vec::new();
        for frame in frames {
            message::write_control(&mut buf, frame).await.expect("encode frame");
        }
        buf
    }

    /// 取消安全的读帧前提（线上「unknown transfer frame kind 0xXX」的机制）：
    /// `read_frame` 内部是两个 `read_exact`——帧读到一半被取消（`select!` 分支
    /// 抢先 / 丢弃 future）时，已从流中取走的字节永久丢失，后续帧边界错位。
    /// 反例断言：取消后继续读，**不可能**再得到原本的下一帧。
    #[tokio::test]
    async fn direct_read_frame_cancelled_mid_frame_loses_bytes() {
        let first = TransferFrame::FileDone { index: 2 };
        let second = TransferFrame::BatchDone {};
        let bytes = encode_frames(&[first, second.clone()]).await;

        let state = Arc::new(Mutex::new(PipeState::default()));
        let mut stream = PipeReader::new(Arc::clone(&state));
        // 只喂前 3 字节（不足 u32 长度前缀）→ 读帧挂起在帧中
        PipeReader::feed(&state, &bytes[..3]);
        let cancelled =
            tokio::time::timeout(Duration::from_millis(50), message::read_frame(&mut stream)).await;
        assert!(cancelled.is_err(), "半截帧必须挂起，才能覆盖被取消的窗口");

        // 补齐剩余字节：被取消的读已吞掉前 3 字节 → 帧边界错位
        PipeReader::feed(&state, &bytes[3..]);
        let next =
            tokio::time::timeout(Duration::from_millis(200), message::read_frame(&mut stream))
                .await;
        match next {
            Ok(Err(_)) => {}
            Ok(Ok(frame)) => panic!("misaligned stream must not decode a frame, got {frame:?}"),
            Err(_elapsed) => panic!("misaligned stream must not hang"),
        }
    }

    /// 正例（本修复的契约）：读半任务交付**完整帧**，消费侧取消（暂停/恢复
    /// 命令分支抢先唤醒）不会丢失帧内字节，帧序与内容逐条保持。
    #[tokio::test]
    async fn frame_reader_keeps_frames_intact_across_consumer_cancellation() {
        let first = TransferFrame::FileDone { index: 2 };
        let second = TransferFrame::BatchDone {};
        let bytes = encode_frames(&[first.clone(), second.clone()]).await;
        let first_len = encode_frames(std::slice::from_ref(&first)).await.len();
        assert!(first_len > 2 && first_len < bytes.len());

        let state = Arc::new(Mutex::new(PipeState::default()));
        let (mut frame_rx, reader_task) = spawn_frame_reader(PipeReader::new(Arc::clone(&state)));
        let _guard = ReaderTaskGuard::new(reader_task);

        // 第一帧差 2 字节：读半任务挂在帧中
        PipeReader::feed(&state, &bytes[..first_len - 2]);
        // 消费侧「被取消」：短暂等待完整帧，超时即丢弃 recv（通道接收取消安全）
        let none_yet = tokio::time::timeout(Duration::from_millis(50), frame_rx.recv()).await;
        assert!(none_yet.is_err(), "半截帧不得提前交付");

        PipeReader::feed(&state, &bytes[first_len - 2..]);
        let got_first = tokio::time::timeout(Duration::from_millis(200), frame_rx.recv())
            .await
            .expect("first frame must arrive")
            .expect("channel open")
            .expect("frame decodes");
        assert_eq!(got_first, IncomingFrame::Control(Box::new(first)));

        PipeReader::close(&state);
        let got_second = tokio::time::timeout(Duration::from_millis(200), frame_rx.recv())
            .await
            .expect("second frame must arrive")
            .expect("channel open")
            .expect("frame decodes");
        assert_eq!(got_second, IncomingFrame::Control(Box::new(second)));
    }


    /// 会话级暂停面契约（回归：真机「一端按暂停，对端会话直接失败」）：
    /// 控制相等待期间必须同时做两件事——消费本端暂停命令（下发帧）与容忍
    /// 对端 Pause/Resume 帧（置位门控 + 抬发事件），且不得吞掉终态帧。
    #[tokio::test]
    async fn control_wait_handles_pause_plane_on_both_sides() {
        let state = Arc::new(Mutex::new(PipeState::default()));
        let (mut frame_rx, reader_task) = spawn_frame_reader(PipeReader::new(Arc::clone(&state)));
        let _guard = ReaderTaskGuard::new(reader_task);
        let cancel = CancelToken::new();
        let (events_tx, mut events_rx) = mpsc::channel::<TransferEvent>(8);
        let remote = NodeId::parse(&"a".repeat(64)).expect("node id");
        let slot = PauseSlot::new();
        let mut pause = SessionPause::from_optional(Some(Arc::clone(&slot))).await;
        let pause_slot = Some(Arc::clone(&slot));
        let mut out: Vec<u8> = Vec::new();

        // 本端暂停（在等待控制帧期间按下）+ 对端 Resume + 本阶段期待的 BatchDone
        slot.send(PauseCmd::Pause).await;
        let peer_resume = TransferFrame::Resume {
            batch_id: "b-1".to_string(),
        };
        let peer_pause = TransferFrame::Pause {
            batch_id: "b-1".to_string(),
        };
        let expected = TransferFrame::BatchDone {};
        PipeReader::feed(
            &state,
            &encode_frames(&[peer_resume, peer_pause, expected.clone()]).await,
        );

        let got = next_frame_handling_pause(
            &mut out,
            &mut frame_rx,
            &cancel,
            &mut pause,
            &pause_slot,
            &events_tx,
            &remote,
            "b-1",
        )
        .await
        .expect("wait must not fail")
        .expect("frame present");
        assert_eq!(got, IncomingFrame::Control(Box::new(expected)));

        // 本端暂停已即时下发（写半恰有一条 Pause 帧）
        let mut sink: &[u8] = &out;
        match message::read_frame(&mut sink).await.expect("decode outbound") {
            IncomingFrame::Control(boxed) => assert_eq!(
                *boxed,
                TransferFrame::Pause {
                    batch_id: "b-1".to_string()
                }
            ),
            other => panic!("expected outbound pause frame, got {other:?}"),
        }
        assert!(sink.is_empty(), "exactly one outbound frame expected");

        // 对端 Resume / Pause 均被消费：抬发 Resumed → Paused 事件，门控位随帧同步
        assert!(matches!(
            events_rx.try_recv().expect("resumed event"),
            TransferEvent::Resumed { .. }
        ));
        assert!(matches!(
            events_rx.try_recv().expect("paused event"),
            TransferEvent::Paused { .. }
        ));
        assert!(slot.is_paused(), "peer pause must set local gate");

        // 反例：终态帧不得被暂停面吞掉（调用方仍需按 Cancel 裁决）
        let peer_cancel = TransferFrame::Cancel {
            by: CancelOrigin::Sender,
        };
        PipeReader::feed(
            &state,
            &encode_frames(std::slice::from_ref(&peer_cancel)).await,
        );
        let got = next_frame_handling_pause(
            &mut out,
            &mut frame_rx,
            &cancel,
            &mut pause,
            &pause_slot,
            &events_tx,
            &remote,
            "b-1",
        )
        .await
        .expect("wait must not fail")
        .expect("frame present");
        assert_eq!(got, IncomingFrame::Control(Box::new(peer_cancel)));
    }

    /// 速率必须按窗口平均：单块到达不得立刻产出速率（线上 bug：64 KiB / 0.15 ms
    /// 被逐块采样放大成数百 MB/s，双端各自采样时刻不同 → 两侧速率差两个数量级）
    #[test]
    fn rate_is_window_averaged_not_per_chunk() {
        let mut rate = RateTracker::with_window(Duration::from_millis(500));
        let base = Instant::now();

        // 首块：窗口（500ms）远未满 → 不得产出速率（防首窗尖峰）
        assert_eq!(
            rate.sample_at(64 * 1024, base + Duration::from_micros(150)),
            0.0
        );
        // 同窗口内连续喂块（快网上一个窗口能喂进大量块）→ 仍不产出速率
        assert_eq!(
            rate.sample_at(8 * 1024 * 1024, base + Duration::from_millis(100)),
            0.0
        );
        // 窗口满：rate = 窗口增量 / 窗口时长，是平均而非瞬时
        let rate_1s = rate.sample_at(16 * 1024 * 1024, base + Duration::from_millis(500));
        assert!(
            (rate_1s - 32.0 * 1024.0 * 1024.0).abs() < 1024.0,
            "expected ~32 MiB/s window average, got {rate_1s}"
        );

        // 窗口重置：下一窗口只计窗口内增量（旧累计不重复计入）
        let rate_2s = rate.sample_at(24 * 1024 * 1024, base + Duration::from_millis(1000));
        assert!(
            (rate_2s - 16.0 * 1024.0 * 1024.0).abs() < 1024.0,
            "second window must count only its own delta, got {rate_2s}"
        );
    }

    /// 续传基线跳变（接收端声明的已写偏移一次性入账）不得被当成窗口内流量
    #[test]
    fn rate_sync_base_absorbs_resume_offset_jump() {
        let mut rate = RateTracker::with_window(Duration::from_millis(500));
        let base = Instant::now();
        rate.sample_at(1024, base + Duration::from_millis(600));

        // 续传：累计字节从 1 KiB 跳到 64 MiB，窗口基线随之重置
        rate.sync_base_at(64 * 1024 * 1024, base + Duration::from_millis(1100));
        assert_eq!(
            rate.sample_at(64 * 1024 * 1024, base + Duration::from_millis(1100)),
            0.0,
            "resume baseline jump must not become a rate spike"
        );
        let after = rate.sample_at(65 * 1024 * 1024, base + Duration::from_millis(1600));
        assert!(
            (after - (1024.0 * 1024.0 / 0.5)).abs() < 1024.0,
            "post-resume window counts only new bytes, got {after}"
        );
    }

    /// 窗口未满时沿用上次窗口速率（避免速率字段在窗口内反复跳 0/非 0）
    #[test]
    fn rate_holds_last_value_until_window_fills() {
        let mut rate = RateTracker::with_window(Duration::from_millis(500));
        let base = Instant::now();
        rate.sample_at(0, base);
        let first = rate.sample_at(1024 * 1024, base + Duration::from_millis(500));
        assert!(first > 0.0);
        // 窗口内：沿用上一窗口速率（非 0、非瞬时重算）
        assert_eq!(
            rate.sample_at(2 * 1024 * 1024, base + Duration::from_millis(600)),
            first
        );
    }
}
