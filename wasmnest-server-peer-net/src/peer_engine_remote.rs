//! 对等网络远端浏览/拉取（issue 11）：浏览可信对端共享目录 + 多文件拉取。
//!
//! 浏览为单请求会话——每次操作对对端新拨号（线协议「单连接单请求」契约），
//! 返回引擎排好序的条目与「可能被权限过滤」提示位；拉取按文件逐条独立会话
//! （免协商、断点续传复用 issue 05/06 数据面）。
//!
//! **口径（传输编排下沉票 3 修正）**：拉取的并发信号量（读设置并发上限）与
//! 任务行预登记（register_remote_pull / fail_task）属产品编排，已随编排整体
//! 下沉 `file-transfer` 插件——`pull-files` 收窄为「逐文件会话立即发起，
//! 并发节流归调用方分批调用自控」；每个拉取会话发起时直推 `pull-started`
//! 引擎事实事件（建行锚点同构：batchId/nodeId/files[]/totalSize/tsMs），
//! 任务行由插件事件归约自建。宿主只保留拉取会话句柄表
//! （batch_id → CancelToken/PauseSlot）——按批取消与 wire 暂停/恢复的引擎控制面。
//!
//! 只读约束：本模块只有列目录与拉取，无任何指向暴露端的写语义。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::base::{
    browse_shared_dir, list_shared_roots, pull_shared_file, CancelToken, NodeId, PauseCmd, PauseSlot, PeerNetError,
    TransferEvent,
};
use wasmnest_server_base::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{map_peer_net_error, parse_node_id, runtime_snapshot, PeerCtx};

// ==================== 数据模型 ====================

/// 远端目录条目（BrowseResponse DirEntry 的 camelCase 形态）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEntryDto {
    /// 条目名（不含路径分隔）
    pub name: String,
    /// 是否目录
    pub is_dir: bool,
    /// 文件字节数（目录恒 0）
    pub size: u64,
}

/// 远端目录浏览结果
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteBrowseDto {
    /// 子条目（已按「目录优先、按名排序」排好）
    pub entries: Vec<RemoteEntryDto>,
    /// 暴露端提示列表可能不全（Android 存储权限过滤，沿用既有 notice 语义）
    pub filtered: bool,
}

/// 拉取清单单项（前端递归枚举后的扁平文件列表）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemotePullFileDto {
    /// 暴露端共享目录内的相对路径（必须指向文件）
    pub rel_path: String,
    /// 文件字节数（浏览所得；供任务行进度分母）
    pub size: u64,
}

// ==================== 状态容器 ====================

/// 单个节点代际的拉取会话上下文（装配时建立，停止时取消）
struct SessionCtx {
    /// 接收侧事件通道发送端快照（拉取会话经它上报进度/终态）
    events: mpsc::Sender<TransferEvent>,
    /// 本代全部拉取令牌的父源：节点停止时 cancel 即中止所有在途/后续会话
    cancel_root: CancelToken,
}

/// 拉取会话句柄条目：取消令牌 + 暂停句柄（wire Pause/Resume 门控数据供方）
/// ——纯引擎控制面（票 3：并发编排归插件）
struct PullSession {
    /// 按批取消令牌（cancel_pull / 节点停止共用）
    token: CancelToken,
    /// 暂停句柄（pause_pull / resume_pull 经它写 Pause/Resume 帧）
    pause: Option<Arc<PauseSlot>>,
}

/// Tauri 托管的远端浏览/拉取状态容器
///
/// - `pulls`：进行中的客户端拉取会话（batch_id → 取消令牌 + 暂停句柄）；
///   std Mutex 与 consents/connections 同款瞬时临界区；
/// - `session`：当前节点代际上下文（None = 节点未启动）。
#[derive(Default)]
pub struct PeerRemoteState {
    pulls: Mutex<HashMap<String, PullSession>>,
    session: tokio::sync::Mutex<Option<SessionCtx>>,
}

/// 节点装配期登记拉取会话上下文（start_locked 调用）
pub(crate) async fn register_session(ctx: &PeerCtx, events: mpsc::Sender<TransferEvent>) {
    let state = &ctx.remote;
    *state.session.lock().await = Some(SessionCtx {
        events,
        cancel_root: CancelToken::new(),
    });
}

/// 节点停止时收尾：取消本代根令牌（中止在途与后续拉取）并摘除上下文
pub(crate) async fn clear_state(ctx: &PeerCtx) {
    let session = {
        let state = &ctx.remote;
        let mut guard = state.session.lock().await;
        guard.take()
    };
    if let Some(session) = session {
        session.cancel_root.cancel();
        let drained: Vec<String> = ctx
            .remote
            .pulls
            .lock()
            .expect("peer remote pulls lock poisoned")
            .drain()
            .map(|(id, _)| id)
            .collect();
        for batch_id in drained {
            tracing::debug!(batch_id = %batch_id, "remote pull dropped on node stop");
        }
    }
}

/// 取消进行中的拉取会话（返回是否命中）；由 [`super::peer_engine_receive::cancel_peer_receiving`]
/// 在服务端会话表未命中时兜底调用
pub(crate) fn cancel_pull(ctx: &PeerCtx, batch_id: &str) -> bool {
    let session = ctx
        .remote
        .pulls
        .lock()
        .expect("peer remote pulls lock poisoned")
        .remove(batch_id);
    match session {
        Some(session) => {
            tracing::info!(batch_id = %batch_id, "cancelling remote pull by host");
            session.token.cancel();
            true
        }
        None => false,
    }
}

/// 暂停进行中的拉取会话（返回是否命中）：写 Pause 帧门控数据供方推流
pub(crate) async fn pause_pull(ctx: &PeerCtx, batch_id: &str) -> bool {
    let slot = ctx
        .remote
        .pulls
        .lock()
        .expect("peer remote pulls lock poisoned")
        .get(batch_id)
        .and_then(|s| s.pause.clone());
    match slot {
        Some(slot) => {
            slot.send(PauseCmd::Pause).await;
            true
        }
        None => false,
    }
}

/// 恢复暂停的拉取会话（返回是否命中）：写 Resume 帧解除数据供方门控
pub(crate) async fn resume_pull(ctx: &PeerCtx, batch_id: &str) -> bool {
    let slot = ctx
        .remote
        .pulls
        .lock()
        .expect("peer remote pulls lock poisoned")
        .get(batch_id)
        .and_then(|s| s.pause.clone());
    match slot {
        Some(slot) => {
            slot.send(PauseCmd::Resume).await;
            true
        }
        None => false,
    }
}

/// 用例夹具：登记一条在册的 pull 会话（仅 `#[cfg(test)]`）
///
/// 生产路径的登记只在 [`run_pull_queue`] 里（每条会话先拨号再落表），单测不起
/// 两节点 ⇒ 路由用例经此入口装配一条“会话在册”的最小事实，返回该会话的暂停
/// 句柄供断言门控位变化（`pulls` 表是模块私有，生产面无直接登记原语）。
#[cfg(test)]
pub(crate) fn register_pull_for_test(ctx: &PeerCtx, batch_id: &str) -> Arc<PauseSlot> {
    let pause = PauseSlot::new();
    ctx.remote
        .pulls
        .lock()
        .expect("peer remote pulls lock poisoned")
        .insert(
            batch_id.to_string(),
            PullSession {
                token: CancelToken::new(),
                pause: Some(Arc::clone(&pause)),
            },
        );
    pause
}

// ==================== 内部辅助 ====================

/// 解析拨号记录并建立到对端的新连接（浏览/拉取共用前置）
///
/// denied/unreachable 以带上下文的错误上抛——入口仅在已连接态展示，
/// 到达此处仍被拒说明信任关系已变化，如实呈现给调用方。
async fn dial_peer(ctx: &PeerCtx, node_id: &NodeId, action: &str) -> Result<crate::base::Connection> {
    let (node, cache) = runtime_snapshot(ctx)
        .await
        .ok_or_else(|| AppError::Internal(format!("peer-net {action} failed: node not started")))?;
    let record = cache.get(node_id).ok_or_else(|| {
        AppError::Internal(format!(
            "peer-net {action} failed: peer {} not in discovery cache (offline or unknown)",
            node_id.as_str()
        ))
    })?;
    node.dial(&record.to_static_peer_record()).await.map_err(|e| match e {
        PeerNetError::DialDeniedByPeer { .. } => AppError::Internal(format!(
            "peer-net {action} failed: not trusted by peer {}",
            node_id.as_str()
        )),
        other => map_peer_net_error(other),
    })
}

// ==================== 命令面 ====================

/// 对端暴露中的共享根清单 DTO
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerSharedRootDto {
    /// 共享目录条目 ID（browse/pull 按此寻址）
    pub id: String,
    /// 展示名
    pub name: String,
}

/// 列可信对端暴露中的共享根（浏览入口：先取根清单再逐根下钻）
pub async fn list_peer_shared_roots(ctx: Arc<PeerCtx>, node_id: String) -> Result<Vec<PeerSharedRootDto>> {
    let parsed = parse_node_id(&node_id)?;
    let conn = dial_peer(&ctx, &parsed, "roots").await?;
    let roots = list_shared_roots(conn)
        .await
        .map_err(|e| AppError::Internal(format!("peer-net list shared roots failed: {e}")))?;
    // 诊断插桩：对端共享根可见性（排查移动端看不到桌面共享目录）
    tracing::info!(
        node_id = %parsed,
        count = roots.len(),
        "peer shared roots listed"
    );
    Ok(roots
        .into_iter()
        .map(|root| PeerSharedRootDto {
            id: root.id,
            name: root.name,
        })
        .collect())
}

/// 浏览可信对端的共享目录（单请求会话；每操作新拨号）
pub async fn browse_peer_directory(
    ctx: Arc<PeerCtx>,
    node_id: String,
    dir_id: String,
    rel_path: String,
) -> Result<RemoteBrowseDto> {
    let parsed = parse_node_id(&node_id)?;
    let conn = dial_peer(&ctx, &parsed, "browse").await?;
    let listing = browse_shared_dir(conn, &dir_id, &rel_path)
        .await
        .map_err(|e| AppError::Internal(format!("peer-net browse '{rel_path}' in dir '{dir_id}' failed: {e}")))?;
    // 诊断插桩：目录浏览结果可见性（dir_id 形状/条目数）
    tracing::info!(
        node_id = %parsed,
        dir_id = %dir_id,
        rel = %rel_path,
        entries = listing.entries.len(),
        "peer directory browsed"
    );
    Ok(RemoteBrowseDto {
        entries: listing
            .entries
            .into_iter()
            .map(|entry| RemoteEntryDto {
                name: entry.name,
                is_dir: entry.is_dir,
                size: entry.size,
            })
            .collect(),
        filtered: listing.filtered,
    })
}

/// 从可信对端拉取多个文件到本机下载目录（逐文件独立会话）
///
/// 免协商直取（用户主动获取即放行）。**票 3 收窄**：所有文件会话立即发起、
/// 无宿主并发信号量——并发节流由调用方分批调用自控（「多选下载逐条呈现」
/// 等编排语义归插件，经 `pull-started` 引擎事件自建任务行）；中断后重试
/// 同一文件自动断点续传。返回入队文件数。
pub async fn pull_peer_files(
    ctx: Arc<PeerCtx>,
    node_id: String,
    dir_id: String,
    files: Vec<RemotePullFileDto>,
) -> Result<usize> {
    if files.is_empty() {
        return Err(AppError::InvalidInput(
            "pull peer files: file list must not be empty".to_string(),
        ));
    }
    // 诊断插桩：拉取编排入口（逐文件会话另有 dial/serve 日志）
    tracing::info!(
        node_id = %node_id,
        dir_id = %dir_id,
        files = files.len(),
        "peer pull requested"
    );
    for file in &files {
        if file.rel_path.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "pull peer files: rel_path must not be empty".to_string(),
            ));
        }
    }

    let parsed = parse_node_id(&node_id)?;
    // 会话参数在锁外解析快照：拨号可达秒级，不阻塞 start/stop
    let (_, config) = super::peer_engine_receive::handler_and_config(&ctx)
        .await
        .ok_or_else(|| AppError::Internal("peer-net pull failed: node not started".to_string()))?;
    let (events, cancel_root) = {
        let state = &ctx.remote;
        let guard = state.session.lock().await;
        match guard.as_ref() {
            Some(ctx) => (ctx.events.clone(), ctx.cancel_root.clone()),
            None => return Err(AppError::Internal("peer-net pull failed: node not started".to_string())),
        }
    };
    let (node, cache) = runtime_snapshot(&ctx)
        .await
        .ok_or_else(|| AppError::Internal("peer-net pull failed: node not started".to_string()))?;
    let record = cache.get(&parsed).ok_or_else(|| {
        AppError::Internal(format!(
            "peer-net pull failed: peer {node_id} not in discovery cache (offline or unknown)"
        ))
    })?;

    let count = files.len();
    wasmnest_server_base::error_boundary::spawn_with_error_boundary(
        "peer_remote_pull",
        run_pull_queue(
            ctx.clone(),
            parsed,
            node,
            record.to_static_peer_record(),
            dir_id,
            files,
            config,
            cancel_root,
            events,
        ),
    );
    Ok(count)
}

/// 逐文件立即发起拉取会话：每文件独立 batch_id + 独立连接；会话发起即
/// 直推 `pull-started` 引擎事实事件（插件归约自建任务行）；单文件失败
/// 直推 failed 终态事件（任务行落态归插件归约），不阻断其余。
///
/// 取消令牌为本代会话根令牌的 child——节点停止（clear_state）时全部
/// 在途拉取一并中止。
#[allow(clippy::too_many_arguments)]
async fn run_pull_queue(
    ctx: Arc<PeerCtx>,
    peer: NodeId,
    node: crate::base::PeerNetNode,
    record: crate::base::StaticPeerRecord,
    dir_id: String,
    files: Vec<RemotePullFileDto>,
    config: crate::base::TransferConfig,
    cancel_root: crate::base::CancelToken,
    events: mpsc::Sender<TransferEvent>,
) {
    let state = &ctx.remote;
    for (index, file) in files.into_iter().enumerate() {
        if cancel_root.is_cancelled() {
            tracing::info!("remote pull queue aborted by node stop");
            break;
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let batch_id = format!("pull-{nanos}-{index}");
        let token = CancelToken::child(&cancel_root);
        let pause = PauseSlot::new();
        state.pulls.lock().expect("peer remote pulls lock poisoned").insert(
            batch_id.clone(),
            PullSession {
                token: token.clone(),
                pause: Some(Arc::clone(&pause)),
            },
        );

        // pull-started 引擎事实事件直推（票 3）：任务行由插件归约自建
        super::publish_engine_event(
            &ctx,
            super::TOPIC_RECEIVE_EVENT,
            super::engine_pull_started_payload(&peer, &batch_id, &file.rel_path, file.size),
        );

        let node = node.clone();
        let record = record.clone();
        let dir_id = dir_id.clone();
        let config = config.clone();
        let events = events.clone();
        let ctx = ctx.clone();
        let batch_id_spawn = batch_id.clone();
        let rel_path = file.rel_path.clone();
        let cancel_root = cancel_root.clone();
        tokio::spawn(async move {
            if cancel_root.is_cancelled() {
                return;
            }
            match node.dial(&record).await {
                Ok(conn) => {
                    let _ = pull_shared_file(
                        conn,
                        &dir_id,
                        &rel_path,
                        &batch_id_spawn,
                        config,
                        events,
                        token,
                        Some(pause),
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(batch_id = %batch_id_spawn, rel = %rel_path, "pull dial failed: {e}");
                    // 会话前置失败直推 failed 终态事件（插件归约结算任务行）
                    super::publish_engine_event(
                        &ctx,
                        super::TOPIC_RECEIVE_EVENT,
                        super::engine_terminal_payload(
                            &batch_id_spawn,
                            &crate::base::TerminalState::Failed {
                                detail: format!("dial failed: {e}"),
                            },
                        ),
                    );
                }
            }
            ctx.remote
                .pulls
                .lock()
                .expect("peer remote pulls lock poisoned")
                .remove(&batch_id_spawn);
        });
    }
}

// ==================== 活跃批投影（active-transfers） ====================

/// pull 会话投影（active-transfers 原语数据源）：句柄表在册条目即活跃会话
/// （纯引擎控制面事实；字节未知记 0——进度以 pull-started / progress 事件
/// 直推，归约态由插件自持）
pub(crate) fn active_pull_rows(ctx: &PeerCtx) -> Vec<serde_json::Value> {
    let state = &ctx.remote;
    let guard = state.pulls.lock().expect("peer remote pulls lock poisoned");
    guard
        .keys()
        .map(|batch_id| {
            serde_json::json!({
                "batchId": batch_id,
                "direction": "receive",
                "status": "running",
                "totalBytes": 0,
                "transferredBytes": 0,
                "rateBps": 0.0,
                "updatedAtMs": super::event_now_ms(),
            })
        })
        .collect()
}
