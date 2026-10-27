//! 对等网络发送侧引擎接入（传输编排下沉票 3 终态：纯句柄表 + 引擎事件桥）。
//!
//! **口径（票 3 修正）**：本模块不再持有任何任务状态机——旧版所持的活跃任务
//! 表、并发闸门（1..=8 默认 3）、历史封顶（200）、peer_name 解析、原因码映射、
//! serve 供流记账与「两端各自展示同一次传输」的产品编排，已随传输编排整体
//! 下沉 `file-transfer` 插件（事件归约状态机，真源在其私有库）。宿主只保留
//! 「离宿主无法实现、且无业务语义」的引擎控制面：
//!
//! - **会话句柄表** `batch_id → SendSessionHandle`：CancelToken（取消）、
//!   PauseSlot（wire Pause/Resume 门控）、epoch（陈旧会话防护）、sources
//!   （redial 续传必需的源清单，spec §4.4）、寻址与加密参数、字节记账
//!   （active-transfers 投影用）；
//! - **send-files 收窄**：一次调用 = 一个会话立即发起（并发节流归调用方，
//!   插件侧闸门自控——见 `wasm-apps/file-transfer/rust/src/peer.rs`）；
//! - **引擎事件桥**：send 会话与 serve 供流通道的 TransferEvent 逐条直推
//!   `peer:transfer-event`（Progress 复用 150ms 节流窗口——纯性能无业务），
//!   不经任何状态机加工（原因码/终态判定归插件归约）。
//!
//! 防回接锁 `retired_peer_transfer_orchestration_is_not_reintroduced`
//! 钉住本口径：谁把任务状态表/并发闸门/封顶加回来，谁就要先推翻票 3 裁决。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::base::{
    CancelToken, Connection, DiscoveredPeerRecord, OutgoingFile, PauseCmd, PauseSlot, PeerNetNode, TerminalState,
    TransferEvent,
};
use tokio::sync::mpsc;
use wasmnest_server_base::error::AppError;
use wasmnest_server_base::error::Result as PeerResult;

use super::source_collect::{collect_outgoing_files, CollectedSources};
use super::PeerCtx;

// ==================== 常量 ====================

/// 进度事件最小发射间隔：引擎按 ≤64KiB chunk 发射 Progress，
/// 不加节流会在高速链路打爆 IPC；数值远低于人眼感知阈值
const PROGRESS_EMIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(150);

// ==================== 会话句柄表 ====================

/// 发送会话句柄（纯引擎控制面）：取消 / 暂停 / 代次 / 源清单 / 寻址。
/// `sources` 必须随句柄表保留——resume 的 redial 分支按它重拨续传
/// （spec §4.4：会话重启必需，非业务态）。
pub(crate) struct SendSessionHandle {
    pub cancel_token: CancelToken,
    pub epoch: u64,
    pub pause_slot: Arc<PauseSlot>,
    pub sources: Vec<OutgoingFile>,
    pub node_id: String,
    pub encrypt: bool,
    pub total_bytes: u64,
    /// 最新已传字节（事件循环记账；active-transfers 投影用，纯引擎进度事实）
    pub transferred_bytes: u64,
    /// 会话控制面状态：wire Pause 已写（resume 判据；对端 Paused/Resumed 帧
    /// 同步）。终态结算随句柄摘除
    pub paused: bool,
}

/// Tauri 托管的发送会话句柄表（旧 PeerTransferState 的任务状态机已删）。
/// 单把 Mutex 串行化读写——临界区均为内存短操作。
#[derive(Default)]
pub struct PeerTransferState {
    sessions: Mutex<HashMap<String, SendSessionHandle>>,
}

impl PeerTransferState {
    /// 登记新会话并返回代次（每批从 0 起；redial 递增）
    fn register_session(
        &self,
        batch_id: &str,
        sources: Vec<OutgoingFile>,
        node_id: String,
        encrypt: bool,
        total_bytes: u64,
    ) -> u64 {
        let mut guard = self.sessions.lock().expect("peer transfer sessions poisoned");
        let epoch = guard.get(batch_id).map(|h| h.epoch + 1).unwrap_or(0);
        guard.insert(
            batch_id.to_string(),
            SendSessionHandle {
                cancel_token: CancelToken::new(),
                epoch,
                pause_slot: PauseSlot::new(),
                sources,
                node_id,
                encrypt,
                total_bytes,
                transferred_bytes: 0,
                paused: false,
            },
        );
        epoch
    }

    /// 当前会话令牌（取消入口取用；不存在或已结算返回 None）
    fn cancel_token_of(&self, batch_id: &str) -> Option<CancelToken> {
        self.sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .get(batch_id)
            .map(|h| h.cancel_token.clone())
    }

    /// 取会话暂停句柄克隆（锁内 clone Arc，锁外使用）
    fn pause_slot_of(&self, batch_id: &str) -> Option<Arc<PauseSlot>> {
        self.sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .get(batch_id)
            .map(|h| Arc::clone(&h.pause_slot))
    }

    /// 会话是否在册（pause/resume 路由判据：send 会话 vs serve 供流批）
    fn has_session(&self, batch_id: &str) -> bool {
        self.sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .contains_key(batch_id)
    }

    /// wire Pause/Resume 控制面状态同步（对端帧 / 本端命令）
    fn set_paused(&self, batch_id: &str, paused: bool) {
        if let Some(handle) = self
            .sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .get_mut(batch_id)
        {
            handle.paused = paused;
        }
    }

    /// 进度记账（事件循环内调用；纯引擎字节事实）
    fn record_progress(&self, batch_id: &str, transferred: u64) {
        if let Some(handle) = self
            .sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .get_mut(batch_id)
        {
            handle.transferred_bytes = transferred;
        }
    }

    /// 会话结束/终态时摘除句柄
    fn unregister_session(&self, batch_id: &str) {
        self.sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .remove(batch_id);
    }
}

// ==================== 原语适配面 ====================

/// 活跃（非终态）发送会话投影（active-transfers 原语数据源）：句柄表在册条目
/// 即活跃会话（终态时摘除），status 取控制面 paused/running 事实
pub(crate) fn active_send_transfer_rows(ctx: &PeerCtx) -> Vec<serde_json::Value> {
    let state = &ctx.transfer;
    let guard = state.sessions.lock().expect("peer transfer sessions poisoned");
    guard
        .iter()
        .map(|(batch_id, handle)| send_handle_row(batch_id, handle))
        .collect()
}

/// 单条句柄 → 引擎事实投影行（纯函数，单测锚点：业务字段不得进投影）
fn send_handle_row(batch_id: &str, handle: &SendSessionHandle) -> serde_json::Value {
    serde_json::json!({
        "batchId": batch_id,
        "direction": "send",
        "status": if handle.paused { "paused" } else { "running" },
        "totalBytes": handle.total_bytes,
        "transferredBytes": handle.transferred_bytes,
        "rateBps": 0.0,
        "updatedAtMs": super::event_now_ms(),
    })
}

/// 发送源收集原语（host-peer `collect-outgoing`，票 1）：目录递归展开 + 批内
/// 同名去重 → `[{ path, size }]` JSON。纯文件系统事实枚举（仅元数据），
/// 潜在阻塞 IO 移出异步上下文；路径应来自 pick-* 用户选择（选择即授权）
pub(crate) async fn collect_outgoing_for_plugin(paths: Vec<String>) -> PeerResult<String> {
    let collected = tokio::task::spawn_blocking(move || collect_outgoing_files(&paths))
        .await
        .map_err(|e| AppError::Internal(format!("join source collection failed: {e}")))??;
    serde_json::to_string(&collected.files_json())
        .map_err(|e| AppError::Internal(format!("serialize collected sources failed: {e}")))
}

/// 取消进行中的发送会话（幂等：句柄不在册返回 false）。serve 供流批经
/// handler 按 serve batch_id 取消——会话写 Cancel 帧告知拉取方并停供流。
/// 任务行的 cancelled 落态由插件归约 terminal 事件完成（宿主无任务表）。
pub async fn cancel_peer_transfer(ctx: Arc<PeerCtx>, batch_id: String) -> PeerResult<bool> {
    let state = &ctx.transfer;
    if let Some(token) = state.cancel_token_of(&batch_id) {
        tracing::info!(batch_id = %batch_id, "peer transfer cancel requested");
        token.cancel();
        return Ok(true);
    }
    // 服务侧拉取供流批：经 handler 按 serve batch_id 取消
    Ok(cancel_serve_session(&ctx, &batch_id).await)
}

/// 显式暂停发送批（数据面门控）：本端发起的活跃会话查句柄表写 Pause 帧
/// （连接保持、供方停推流）；serve 供流批查 handler 注册表。任务行的
/// paused 落态由插件归约 Paused 事件完成。无命中返回 false。
pub async fn pause_peer_transfer(ctx: Arc<PeerCtx>, batch_id: String) -> PeerResult<bool> {
    let state = &ctx.transfer;
    if state.has_session(&batch_id) {
        let handled = match state.pause_slot_of(&batch_id) {
            Some(slot) => slot.send(PauseCmd::Pause).await,
            None => false,
        };
        state.set_paused(&batch_id, true);
        if !handled {
            // 会话已死（slot 命令通道关闭）：取消兜底，插件按 terminal 结算
            if let Some(token) = state.cancel_token_of(&batch_id) {
                token.cancel();
            }
        }
        tracing::info!(batch_id = %batch_id, "peer transfer paused");
        return Ok(true);
    }
    // serve 供流批：门控入口在 SharedDirHandler 的 serve 暂停注册表
    let hit = set_serve_paused(&ctx, &batch_id, true).await;
    if hit {
        tracing::info!(batch_id = %batch_id, "pull serve transfer paused");
    }
    Ok(hit)
}

/// serve 供流批的暂停/恢复门控入口（pause 与 resume 共用一张登记表——同一批
/// 在两个方向上是同一供流会话的两端视角，暂停态也共享）
///
/// 未命中（节点未起 / 无 handler / 该批不是本端供流的批）返回 `false` 而非
/// 报错：暂停与恢复都只按批 id 寻址，批 id 落在发送句柄表、serve 登记表、
/// pull 会话表、接收会话表中的哪一张由**传输方向**决定，本函数无从判别，
/// 方向回退由调用链的其余分支完成（见 [`pause_peer_transfer`] /
/// [`resume_peer_transfer`] 的路由说明与绑定层的接收侧回退）。
async fn set_serve_paused(ctx: &PeerCtx, batch_id: &str, paused: bool) -> bool {
    match super::peer_engine_receive::handler_and_config(ctx).await {
        Some((handler, _)) => handler.set_serve_paused(batch_id, paused).await,
        None => false,
    }
}

/// 恢复暂停的传输批：路由与 [`pause_peer_transfer`] 同款——发送句柄表 →
/// serve 供流登记表 → 两者皆未命中即返回 `false`，由绑定层回退接收侧路由。
///
/// - **发送会话**（本端在对端拉取中推流）：活跃会话写 Resume 帧续流；会话已
///   中断（重启/断线残留）的以句柄表记忆的源清单重新拨号续传（断点真源在
///   接收端落盘侧，保留已传字节——引擎 Progress 首帧会重设偏移）；
/// - **serve 供流批**（对端在本端拉取）：写 Resume 帧解除对端门控；
/// - **pull 会话 / push 接收批**（本端是接收方）：本函数无命中，由
///   `plugin_binding::peer_resume_transfer` 回退 `resume_peer_receiving`
///   按 pull / 接收会话表下发。
///
/// **为什么「不是发送会话」必须回退而不是报错**：四个方向共用一个
/// pause/resume 原语入口，批 id 归属哪张表由传输方向决定、入口无从判别。
/// 把「不在发送句柄表」报成 InvalidInput 会让错误直接上抛、**吃掉绑定层的
/// 接收侧回退分支**——结果是接收方向（手机端拉取下载、桌面端拉取手机文件）
/// 暂停后点恢复必然失败，真机事故原文即
/// `peer_resume_transfer: Invalid input: resume transfer: no send session
/// with that id (pull-…)`。已登记但确实无法恢复的发送会话（源清单为空、
/// 节点未起、对端离线）仍显性报错/结算失败，不在回退范围内。
pub async fn resume_peer_transfer(ctx: Arc<PeerCtx>, batch_id: String) -> PeerResult<bool> {
    let state = &ctx.transfer;
    if !state.has_session(&batch_id) {
        let hit = set_serve_paused(&ctx, &batch_id, false).await;
        if hit {
            tracing::info!(batch_id = %batch_id, "pull serve transfer resumed");
        }
        return Ok(hit);
    }
    let slot_sent = match state.pause_slot_of(&batch_id) {
        Some(slot) => slot.send(PauseCmd::Resume).await,
        None => false,
    };
    if slot_sent {
        state.set_paused(&batch_id, false);
        tracing::info!(batch_id = %batch_id, "peer transfer resumed (live session)");
        return Ok(true);
    }
    // 会话已死（slot 命令通道关闭）：以句柄表记忆的源清单重新拨号
    let (sources, node_id, encrypt, total_bytes) = {
        let mut guard = state.sessions.lock().expect("peer transfer sessions poisoned");
        let Some(handle) = guard.get_mut(&batch_id) else {
            return Ok(false);
        };
        handle.paused = false;
        (
            handle.sources.clone(),
            handle.node_id.clone(),
            handle.encrypt,
            handle.total_bytes,
        )
    };
    if sources.is_empty() {
        return Err(AppError::InvalidInput(format!(
            "resume transfer: batch {batch_id} has no remembered sources"
        )));
    }
    drive_redialed_session(ctx.clone(), batch_id, node_id, sources, encrypt, total_bytes).await;
    Ok(true)
}

/// 重新拨号恢复（resume 的会话已死分支）：登记新代次会话并立即发起——
/// 并发节流归调用方（插件逐批调 resume-transfer），宿主不再排队。
/// total_bytes 沿用句柄表记忆值（已传字节由引擎 Progress 首帧重设偏移）。
async fn drive_redialed_session(
    ctx: Arc<PeerCtx>,
    batch_id: String,
    node_id: String,
    sources: Vec<OutgoingFile>,
    encrypt: bool,
    total_bytes: u64,
) {
    let Some((node, cache)) = super::runtime_snapshot(&ctx).await else {
        settle_failed(&ctx, &batch_id, "peer transfer resume failed: node not started").await;
        return;
    };
    let parsed = match super::parse_node_id(&node_id) {
        Ok(p) => p,
        Err(e) => {
            settle_failed(&ctx, &batch_id, &format!("peer id invalid: {e}")).await;
            return;
        }
    };
    let Some(record) = cache.get(&parsed) else {
        settle_failed(
            &ctx,
            &batch_id,
            "peer transfer resume failed: peer not in discovery cache (offline or unknown)",
        )
        .await;
        return;
    };
    let state = &ctx.transfer;
    let _epoch = state.register_session(&batch_id, sources, node_id, encrypt, total_bytes);
    drive_send_session(ctx.clone(), node, record, batch_id.clone());
    tracing::debug!(batch_id = %batch_id, "peer transfer session redialed for resume");
}

/// 经 handler 取消服务侧拉取会话（本端在对端拉取中供流）：会话按 serve
/// batch_id（= 传输任务行 ID）寻址，命中即写 Cancel 帧并停供流。
async fn cancel_serve_session(ctx: &PeerCtx, batch_id: &str) -> bool {
    match super::peer_engine_receive::handler_and_config(ctx).await {
        Some((handler, _)) => handler.cancel_serve_transfer(batch_id),
        None => false,
    }
}

// ==================== 发送入口（v31 收窄：即发即会话） ====================

/// 发送入口（传输编排下沉票 3 收窄）：一次调用 = 一个会话立即发起——目录
/// 递归收集源清单后直接拨号启动，不再有宿主并发闸门排队（旧 pending 态
/// 删除）；发送方向并发节流由调用方在调用前自控。返回传输句柄（batch-id）。
///
/// `encrypt_override` 为 `Some(true)` 时本批强制加密（插件载荷元素级 flag
/// 聚合），`None` 不加密。
pub(crate) async fn send_files_to_peer(
    ctx: Arc<PeerCtx>,
    node_id: String,
    paths: Vec<String>,
    encrypt_override: Option<bool>,
) -> PeerResult<String> {
    let parsed = super::parse_node_id(&node_id)?;
    if paths.is_empty() || paths.iter().all(|p| p.trim().is_empty()) {
        return Err(AppError::InvalidInput(
            "send_files_to_peer: paths must not be empty".to_string(),
        ));
    }
    // `node` 仅用于确认节点已启动（runtime_snapshot 的可用性即启动判据）
    let Some((node, cache)) = super::runtime_snapshot(&ctx).await else {
        return Err(AppError::Internal(
            "peer transfer send failed: node not started".to_string(),
        ));
    };
    let record = cache.get(&parsed).ok_or_else(|| {
        AppError::Internal("peer transfer send failed: peer not in discovery cache (offline or unknown)".to_string())
    })?;

    // 目录递归是潜在阻塞 IO：移出异步上下文（上限保护在收集函数内）
    let trimmed = paths.into_iter().map(|p| p.trim().to_string()).collect::<Vec<_>>();
    let collected: CollectedSources = tokio::task::spawn_blocking(move || collect_outgoing_files(&trimmed))
        .await
        .map_err(|e| AppError::Internal(format!("join source collection failed: {e}")))??;

    let batch_id = uuid::Uuid::new_v4().to_string();
    let encrypt = encrypt_override.unwrap_or(false);
    let total_bytes = collected.total_bytes;
    let sources = collected.sources;
    let state = &ctx.transfer;
    let _epoch = state.register_session(&batch_id, sources, parsed.to_string(), encrypt, total_bytes);

    tracing::info!(
        batch_id = %batch_id,
        node_id = %node_id,
        total = total_bytes,
        "peer transfer send session started (no host-side queue, v31)"
    );
    drive_send_session(ctx.clone(), node, record, batch_id.clone());
    Ok(batch_id)
}

// ==================== 会话驱动（引擎事件桥） ====================

/// 后台发送会话：拨号 → `send_batch` → 事件直推（节流）/ 终态摘除句柄。
///
/// 会话句柄须已登记（send_files_to_peer / resume 的 redial 分支先行
/// register_session）。`epoch` 是陈旧会话防护：redial 递增代次，旧会话
/// 迟到的终态事件按代次丢弃，不直推（防止插件归约误结算新一轮）。
fn drive_send_session(ctx: Arc<PeerCtx>, node: PeerNetNode, record: DiscoveredPeerRecord, batch_id: String) {
    let state = &ctx.transfer;
    let Some((epoch, pause_slot)) = ({
        let guard = state.sessions.lock().expect("peer transfer sessions poisoned");
        guard.get(&batch_id).map(|h| (h.epoch, Arc::clone(&h.pause_slot)))
    }) else {
        tracing::warn!(batch_id = %batch_id, "drive_send_session: handle not registered, aborted");
        return;
    };

    tokio::spawn(async move {
        let (events_tx, mut events_rx) = mpsc::channel::<TransferEvent>(256);

        // 引擎会话主体：send_batch 消费连接并在终态经通道上报；
        // 通道随本闭包返回而关闭，转发循环随之自然退出
        let session_batch_id = batch_id.clone();
        let session_ctx = ctx.clone();
        let session = tokio::spawn(async move {
            let conn: Connection = match dial_for_send(&node, &record).await {
                Ok(conn) => conn,
                Err(detail) => {
                    // 拨号前置失败：直推 failed 终态事件（插件归约结算）；
                    // 句柄随终态摘除（见下方 Terminal 分支同路径）
                    settle_failed(&session_ctx, &session_batch_id, &detail).await;
                    return;
                }
            };
            let cancel = session_ctx
                .transfer
                .cancel_token_of(&session_batch_id)
                .unwrap_or_else(CancelToken::new);
            let sources = session_ctx.transfer.sources_of(&session_batch_id).unwrap_or_default();
            let encrypt = session_ctx.transfer.encrypt_of(&session_batch_id).unwrap_or(false);
            let _ = crate::base::send_batch(
                conn,
                session_batch_id,
                sources,
                events_tx,
                cancel,
                encrypt,
                Some(pause_slot),
            )
            .await;
        });

        // 事件直推循环：Progress 节流（纯性能），Terminal/Paused/Resumed 直推；
        // 宿主零状态机加工（原因码/终态判定归插件归约，票 3）
        let mut last_emit = tokio::time::Instant::now() - PROGRESS_EMIT_INTERVAL;
        while let Some(event) = events_rx.recv().await {
            match event {
                TransferEvent::OfferPending { .. } => {}
                // 服务侧拉取事件走独立 serve 通道（drive_serve_events），
                // 发起方会话通道收不到；防御性忽略
                TransferEvent::PullServed { .. } => {}
                TransferEvent::Progress {
                    batch_id: bid,
                    transferred,
                    total,
                    rate_bps,
                    ..
                } => {
                    ctx.transfer.record_progress(&bid, transferred);
                    if last_emit.elapsed() >= PROGRESS_EMIT_INTERVAL {
                        last_emit = tokio::time::Instant::now();
                        // 引擎原始事件直推（节流窗口内合并）
                        super::publish_engine_event(
                            &ctx,
                            super::TOPIC_TRANSFER_EVENT,
                            super::engine_progress_payload(&bid, transferred, total, rate_bps),
                        );
                    }
                }
                TransferEvent::Terminal {
                    batch_id: bid,
                    state: terminal,
                    remote: _,
                } => {
                    let payload = super::engine_terminal_payload(&bid, &terminal);
                    // 陈旧会话（redial 后旧代次迟到事件）：不直推、不摘新句柄
                    let stale = !ctx.transfer.session_is_current(&bid, epoch);
                    ctx.transfer.unregister_session(&bid);
                    if !stale {
                        super::publish_engine_event(&ctx, super::TOPIC_TRANSFER_EVENT, payload);
                    }
                    tracing::info!(batch_id = %bid, state = ?terminal, "peer transfer session ended");
                    break;
                }
                // 对端暂停/恢复帧：同步句柄控制面状态 + 直推（插件归约落态）
                TransferEvent::Paused { batch_id: bid, .. } => {
                    ctx.transfer.set_paused(&bid, true);
                    super::publish_engine_event(
                        &ctx,
                        super::TOPIC_TRANSFER_EVENT,
                        super::engine_pause_payload("paused", &bid),
                    );
                }
                TransferEvent::Resumed { batch_id: bid, .. } => {
                    ctx.transfer.set_paused(&bid, false);
                    super::publish_engine_event(
                        &ctx,
                        super::TOPIC_TRANSFER_EVENT,
                        super::engine_pause_payload("resumed", &bid),
                    );
                }
            }
        }
        session.abort();
    });
}

/// 对端取消发起方的陈旧终态防护：redial 后旧代次事件不得直推（错误结算
/// 新一轮会话）。session_is_current 即代次校验
impl PeerTransferState {
    fn session_is_current(&self, batch_id: &str, epoch: u64) -> bool {
        self.sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .get(batch_id)
            .map(|h| h.epoch == epoch)
            .unwrap_or(false)
    }

    fn sources_of(&self, batch_id: &str) -> Option<Vec<OutgoingFile>> {
        self.sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .get(batch_id)
            .map(|h| h.sources.clone())
    }

    fn encrypt_of(&self, batch_id: &str) -> Option<bool> {
        self.sessions
            .lock()
            .expect("peer transfer sessions poisoned")
            .get(batch_id)
            .map(|h| h.encrypt)
    }
}

/// 发送专用拨号（每次会话独立握手）：可信对端静默放行；拒绝/不可达归一为
/// 失败明细（业务文案由前端按状态渲染）
async fn dial_for_send(node: &PeerNetNode, record: &DiscoveredPeerRecord) -> Result<Connection, String> {
    match node.dial(&record.to_static_peer_record()).await {
        Ok(conn) => Ok(conn),
        Err(crate::base::PeerNetError::DialDeniedByPeer { .. }) => {
            Err("dial denied by peer (trust revoked or first-connect pending)".to_string())
        }
        Err(e) => Err(format!("dial unreachable: {e}")),
    }
}

/// 会话前置失败（拨号被拒/不可达/节点未起）：直推 failed 终态事件并摘除
/// 句柄——插件归约按 terminal 结算任务行，宿主无状态可写
async fn settle_failed(ctx: &PeerCtx, batch_id: &str, detail: &str) {
    let payload = super::engine_terminal_payload(
        batch_id,
        &TerminalState::Failed {
            detail: detail.to_string(),
        },
    );
    ctx.transfer.unregister_session(batch_id);
    super::publish_engine_event(&ctx, super::TOPIC_TRANSFER_EVENT, payload);
}

// ==================== 服务侧供流事件桥 ====================

/// 服务侧拉取会话事件消费（纯直推）：本端作为拉取源为对端供流时，引擎经
/// 独立 serve 通道上报 PullServed/Progress/Terminal——逐条直推
/// `peer:transfer-event`，供流记账任务行由插件收 `pull-served` 事件自建
/// （票 3：宿主不再代记 send 任务）。Progress 复用 150ms 节流窗口。
pub(crate) async fn drive_serve_events(ctx: Arc<PeerCtx>, mut rx: mpsc::Receiver<TransferEvent>) {
    let mut last_emit = tokio::time::Instant::now() - PROGRESS_EMIT_INTERVAL;
    while let Some(event) = rx.recv().await {
        match event {
            TransferEvent::PullServed {
                remote,
                batch_id,
                files,
                total_size,
            } => {
                let payload = super::engine_pull_served_payload(&remote, &batch_id, &files, total_size);
                super::publish_engine_event(&ctx, super::TOPIC_TRANSFER_EVENT, payload);
                tracing::info!(
                    batch_id = %batch_id,
                    remote = %remote,
                    "pull serve event bridged (accounting owned by plugin)"
                );
            }
            TransferEvent::Progress {
                batch_id,
                transferred,
                total,
                rate_bps,
                ..
            } => {
                if last_emit.elapsed() >= PROGRESS_EMIT_INTERVAL {
                    last_emit = tokio::time::Instant::now();
                    super::publish_engine_event(
                        &ctx,
                        super::TOPIC_TRANSFER_EVENT,
                        super::engine_progress_payload(&batch_id, transferred, total, rate_bps),
                    );
                }
            }
            TransferEvent::Terminal { batch_id, state, .. } => {
                let payload = super::engine_terminal_payload(&batch_id, &state);
                super::publish_engine_event(&ctx, super::TOPIC_TRANSFER_EVENT, payload);
                tracing::info!(batch_id = %batch_id, state = ?state, "pull serve session ended");
            }
            // 拉取方暂停/恢复：直推（插件归约同步记账行状态）
            TransferEvent::Paused { batch_id, .. } => {
                super::publish_engine_event(
                    &ctx,
                    super::TOPIC_TRANSFER_EVENT,
                    super::engine_pause_payload("paused", &batch_id),
                );
            }
            TransferEvent::Resumed { batch_id, .. } => {
                super::publish_engine_event(
                    &ctx,
                    super::TOPIC_TRANSFER_EVENT,
                    super::engine_pause_payload("resumed", &batch_id),
                );
            }
            TransferEvent::OfferPending { .. } => {}
        }
    }
}

// ==================== 发送源选择 ====================
//
// 选源对话框（pick-*）属 `host-platform`（与 peer 领域无关）；发送源目录
// 递归收集在 `source_collect` 模块（纯文件系统事实）。传输域不承载任何
// 平台交互或文件系统枚举编排。

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ctx::headless_ctx;

    fn sources(n: usize) -> Vec<OutgoingFile> {
        (0..n).map(|i| OutgoingFile::new(format!("C:/f-{i}.bin"))).collect()
    }

    // ==================== 暂停/恢复的四表路由（方向不可判时的回退契约） ====================
    //
    // 一个 pause/resume 原语入口管四个方向，批 id 落在哪张表由传输方向决定：
    // 发送句柄表（本端推流）/ serve 供流登记表（对端在本端拉取）/ pull 会话表
    // （本端拉取）/ 接收会话表（对端 push）。入口无从判别方向 ⇒「本表未命中」
    // **必须**是回退信号而不是错误，否则方向回退分支永远到不了（真机事故：
    // 手机端暂停下载后点恢复报 `no send session with that id (pull-…)`）。

    /// 反例（回归锁）：不在发送句柄表的批（pull / serve / 接收批 / 未知共用的
    /// 路由分支）必须返回 `Ok(false)` 让调用链继续回退，**不得**报错
    #[tokio::test]
    async fn resume_on_non_send_session_returns_false_instead_of_error() {
        let ctx = headless_ctx();
        let outcome = resume_peer_transfer(ctx, "pull-1792143196774125420".to_string()).await;
        assert_eq!(
            outcome.expect("非发送会话必须回退而不是报错"),
            false,
            "无 serve 供流会话可命中 ⇒ 交接收侧回退"
        );
    }

    /// 同分支对称性：暂停侧同一 miss 同样只回退（两侧路由形状不得再分叉）
    #[tokio::test]
    async fn pause_on_non_send_session_returns_false_instead_of_error() {
        let ctx = headless_ctx();
        let outcome = pause_peer_transfer(ctx, "pull-1792143196774125420".to_string()).await;
        assert_eq!(
            outcome.expect("非发送会话必须回退而不是报错"),
            false,
            "无 serve 供流会话可命中 ⇒ 交接收侧回退"
        );
    }

    /// 正例：在册发送会话——暂停置位数据面门控，恢复清门控 + 清控制面 paused
    /// （“恢复”不等于“返回 true”：门控位必须真被清掉，否则续流无从发生）
    #[tokio::test]
    async fn resume_live_send_session_clears_pause_gate() {
        let ctx = headless_ctx();
        ctx.transfer
            .register_session("send-1", sources(1), "n".into(), false, 8);
        let slot = ctx.transfer.pause_slot_of("send-1").expect("在册会话必有暂停句柄");

        assert!(pause_peer_transfer(ctx.clone(), "send-1".to_string())
            .await
            .expect("pause 发送会话"));
        assert!(slot.is_paused(), "暂停必须置位数据面门控");

        assert!(resume_peer_transfer(ctx.clone(), "send-1".to_string())
            .await
            .expect("resume 发送会话"));
        assert!(!slot.is_paused(), "恢复必须清除数据面门控");
        let handle_paused = ctx
            .transfer
            .sessions
            .lock()
            .expect("sessions lock")
            .get("send-1")
            .expect("在册会话")
            .paused;
        assert!(
            !handle_paused,
            "控制面 paused 事实必须随恢复清除（active-transfers 投影判据）"
        );
    }

    /// 反例（不得过度回退/报错）：已登记但**会话仍活**的发送会话一律走 live
    /// 分支写 Resume 帧并返回 `true`——即使句柄表里的源清单为空。源清单缺失
    /// 只在“会话已死需 redial”时才成立（该形态的判据是 Resume 帧下发失败，
    /// 只有真实会话循环取走命令通道后终结才会出现，单测夹具起不来），
    /// **不得**把那条报错提成无条件的入参校验（否则空清单会话连 live 恢复都失败）
    #[tokio::test]
    async fn resume_live_send_session_with_empty_remembered_sources_still_succeeds() {
        let ctx = headless_ctx();
        ctx.transfer
            .register_session("send-2", Vec::new(), "n".into(), false, 0);

        assert!(
            resume_peer_transfer(ctx.clone(), "send-2".to_string())
                .await
                .expect("会话仍活时不得报错"),
            "live 分支命中即成功"
        );
        let slot = ctx.transfer.pause_slot_of("send-2").expect("在册会话必有暂停句柄");
        assert!(!slot.is_paused(), "live 恢复清门控");
    }

    /// 反向销定：同一批 id 在**发送句柄表已登记**时，路由不得去看 serve 登记表
    /// （无 handler ⇒ 若误走 serve 分支会返回 false）——发送会话优先命中
    #[tokio::test]
    async fn registered_send_session_wins_over_serve_registry_lookup() {
        let ctx = headless_ctx();
        ctx.transfer
            .register_session("send-3", sources(1), "n".into(), false, 4);
        assert!(resume_peer_transfer(ctx, "send-3".to_string())
            .await
            .expect("发送会话优先命中"));
    }

    /// 设计不变量锁（非行为替身）：serve 供流登记表是**本端在对端拉取时**唯一的
    /// 暂停/恢复门控入口，pause 与 resume 必须经同一入口、两个方向都不得绕过它。
    ///
    /// **为什么需要源码锁**：serve 登记表在引擎 `SharedDirHandler` 内部，只在真实
    /// 供流会话存续期间有条目；单测夹具（无 handler、不起两节点）造不出“serve 批
    /// 在册”形态 ⇒ 行为用例区分不了「查了 serve 登记表」与「跳过它直接 false」
    /// （删掉 resume 的 serve 回退，全部行为用例仍全绿）。这里只钉结构不变量；
    /// serve 侧的 wire 语义（Pause/Resume 真能门控供流）由 `peer-net` 的
    /// `pause_symmetry` 集成套件覆盖。
    #[test]
    fn serve_registry_entry_is_shared_by_pause_and_resume() {
        let src = include_str!("peer_engine_transfer.rs");
        // 只统计**生产段**：`include_str!` 读的是本文件全文，不切分则本用例的匹配
        // 串也算进去（自指），删实现反而让计数对上
        let (production, _tests) = src
            .split_once("// ==================== 测试 ====================")
            .expect("生产代码与测试模块的分界注释必须保留");
        assert_eq!(
            production.matches("async fn set_serve_paused").count(),
            1,
            "serve 门控入口必须单一定义（pause/resume 共用）"
        );
        assert_eq!(
            production.matches("set_serve_paused(&ctx, &batch_id, true)").count(),
            1,
            "pause 必须经 serve 登记表门控"
        );
        assert_eq!(
            production.matches("set_serve_paused(&ctx, &batch_id, false)").count(),
            1,
            "resume 必须经同一 serve 登记表门控（删掉即回退：serve 批无法恢复）"
        );
    }

    // ==================== 会话句柄表（票 3 终态） ====================

    /// 登记与代次：同批重复登记递增 epoch（redial 陈旧事件防护）
    #[test]
    fn register_session_increments_epoch_per_batch() {
        let state = PeerTransferState::default();
        assert_eq!(state.register_session("b", sources(1), "n".into(), false, 1), 0);
        assert_eq!(state.register_session("b", sources(1), "n".into(), false, 1), 1);
        assert_eq!(state.register_session("other", sources(1), "n".into(), false, 1), 0);
        assert!(state.session_is_current("b", 1));
        assert!(!state.session_is_current("b", 0), "旧代次事件必须被判陈旧");
    }

    /// 取消/暂停/进度记账走句柄表；终态摘除后全部查询落空
    #[test]
    fn handle_table_lifecycle_register_to_unregister() {
        let state = PeerTransferState::default();
        state.register_session("b", sources(2), "n".into(), true, 10);
        assert!(state.has_session("b"));
        assert!(state.cancel_token_of("b").is_some());
        assert!(state.pause_slot_of("b").is_some());
        assert_eq!(state.sources_of("b").map(|s| s.len()), Some(2));
        assert_eq!(state.encrypt_of("b"), Some(true));

        state.record_progress("b", 7);
        state.set_paused("b", true);
        {
            let guard = state.sessions.lock().expect("lock");
            let handle = guard.get("b").expect("handle");
            assert_eq!(handle.transferred_bytes, 7);
            assert!(handle.paused);
        }

        state.unregister_session("b");
        assert!(!state.has_session("b"));
        assert!(state.cancel_token_of("b").is_none());
        assert!(state.pause_slot_of("b").is_none());
        assert!(!state.session_is_current("b", 0), "已摘除会话一切事件视为陈旧");

        // 未知批：句柄表一切查询落空（fail-safe——未知 ID 不得命中任何在册会话）
        assert!(!state.has_session("never-registered"));
        assert!(state.cancel_token_of("never-registered").is_none());
        assert!(state.pause_slot_of("never-registered").is_none());
        assert!(state.sources_of("never-registered").is_none());
        assert!(state.encrypt_of("never-registered").is_none());
        assert!(!state.session_is_current("never-registered", 0));
    }

    // ==================== 引擎事实投影（active-transfers） ====================

    /// 句柄表投影：仅引擎会话事实（batchId/direction/status/字节/时间），
    /// 业务字段（peerName/files/原因码）不得进投影（fail-visible 前置：
    /// 插件拿不到就自持，不会静默缺名）
    #[test]
    fn send_handle_row_carries_engine_facts_only() {
        let mut handle = SendSessionHandle {
            cancel_token: CancelToken::new(),
            epoch: 0,
            pause_slot: PauseSlot::new(),
            sources: sources(2),
            node_id: "n".to_string(),
            encrypt: true,
            total_bytes: 3,
            transferred_bytes: 3,
            paused: true,
        };
        let row = send_handle_row("b-1", &handle);
        assert_eq!(row["direction"], "send");
        assert_eq!(row["status"], "paused", "控制面 paused 事实入投影");
        assert_eq!(row["totalBytes"], 3);
        assert_eq!(row["transferredBytes"], 3);
        assert!(row.get("peerName").is_none(), "peerName 是业务字段，不得投影");
        assert!(row.get("files").is_none(), "files 是业务字段，不得投影");
        assert!(row.get("rejectReason").is_none(), "原因码是业务字段，不得投影");

        handle.paused = false;
        assert_eq!(send_handle_row("b-2", &handle)["status"], "running");
    }

    // ==================== 源收集（collect-outgoing 原语） ====================

    /// collect-outgoing 原语 JSON 形状：`[{ path, size }]`（相对落位形状 + 字节）
    #[tokio::test]
    async fn collect_outgoing_for_plugin_emits_path_size_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).expect("mkdir");
        std::fs::write(folder.join("a.txt"), vec![0u8; 4]).expect("write a");
        std::fs::write(folder.join("b.txt"), vec![0u8; 2]).expect("write b");

        let json = collect_outgoing_for_plugin(vec![folder.to_string_lossy().into_owned()])
            .await
            .expect("collect");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).expect("valid json array");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["path"], "docs/a.txt");
        assert_eq!(rows[0]["size"], 4);
        assert_eq!(rows[1]["path"], "docs/b.txt");
        assert_eq!(rows[1]["size"], 2);
    }

    /// 空选择显性报错（与 collect_outgoing_files 契约一致，不产空数组假成功）
    #[tokio::test]
    async fn collect_outgoing_for_plugin_rejects_empty_selection() {
        assert!(collect_outgoing_for_plugin(vec!["missing.bin".to_string()])
            .await
            .is_err());
    }
}
