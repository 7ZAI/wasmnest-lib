//! 对等网络接收侧引擎接入（传输编排下沉票 3 终态：回执表 + 引擎事件桥）。
//!
//! **口径（票 3 修正）**：本模块不再持有任何任务状态机——旧版所持的接收
//! 任务表（活跃 + 会话内终态 100 封顶）、进度入账、终态结算、暂停/恢复状态
//! 同步、peer_name 解析、pull 任务行预登记与并发信号量，已随传输编排整体
//! 下沉 `file-transfer` 插件（事件归约状态机）。宿主只保留引擎控制面：
//!
//! - **询问回执表** `batch_id → PendingOffer`：OfferPending 的 oneshot 回执
//!   通道不可序列化，必须留宿主（spec §4.5）；条目附带询问事实（nodeId/
//!   totalSize/tsMs）供 active-transfers 投影；
//! - **原语面**：`respond-transfer`（应答回流）、收发两方向的暂停/恢复会话
//!   控制（wire Pause/Resume 帧）、`close` 接收侧分支（pending 即拒、running
//!   取消拉取/接收会话）；
//! - **策略面**：接收策略（ask/always_accept/always_deny）+ 询问超时 + 落点
//!   目录（`set-receive-policy` / `set-download-dir` 原语闸门；发送并发上限
//!   已随编排下沉删除——插件侧闸门自控）；
//! - **引擎事件桥**：接收通道 TransferEvent 逐条直推 `peer:receive-event`
//!   （Progress 复用 150ms 节流窗口——纯性能无业务），不经状态机加工。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use wasmnest_peer_net::transfer::batch::validate_ask_timeout_secs;
use wasmnest_peer_net::transfer::DEFAULT_ASK_TIMEOUT_SECS;
use wasmnest_peer_net::{NodeId, ReceivePolicy, SharedDirHandler, TransferConfig, TransferEvent};
use wasmnest_server_base::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::PeerCtx;

// ==================== 常量 ====================

/// 进度事件最小发射间隔（与发送侧转发层同值：低于人眼感知阈值）
const PROGRESS_EMIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(150);

// ==================== 数据模型 ====================

/// 接收策略模式（wire/持久化字符串；前端分段控件直用）
pub const POLICY_ASK: &str = "ask";
pub const POLICY_ALWAYS_ACCEPT: &str = "always_accept";
pub const POLICY_ALWAYS_DENY: &str = "always_deny";

/// 接收侧引擎配置（节点生命周期内的内存态；业务设置真源在 file-transfer
/// 插件私有库，经 set-receive-policy / set-download-dir 原语推送闸门）。
/// 发送方向并发上限字段已随编排下沉退役（票 3：插件侧闸门自控）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct PeerTransferSettings {
    /// `ask` | `always_accept` | `always_deny`
    policy_mode: String,
    /// ask 模式询问窗口（秒；crate 校验 10..=600）
    ask_timeout_secs: u64,
    /// 桌面端落点覆盖（None = 缺省 Downloads\WasmNest\；移动端恒 None）
    download_dir: Option<String>,
}

impl Default for PeerTransferSettings {
    fn default() -> Self {
        Self {
            policy_mode: POLICY_ASK.to_string(),
            ask_timeout_secs: DEFAULT_ASK_TIMEOUT_SECS,
            download_dir: None,
        }
    }
}

impl PeerTransferSettings {
    fn build_policy(&self) -> ReceivePolicy {
        match self.policy_mode.as_str() {
            POLICY_ALWAYS_ACCEPT => ReceivePolicy::AlwaysAccept,
            POLICY_ALWAYS_DENY => ReceivePolicy::AlwaysDeny,
            _ => ReceivePolicy::Ask {
                timeout: std::time::Duration::from_secs(self.ask_timeout_secs),
            },
        }
    }
}

// ==================== 状态容器 ====================

/// 等待应答的询问条目：oneshot 回执 + 投影所需询问事实（纯引擎事实）
pub(crate) struct PendingOffer {
    pub total_size: u64,
    pub ts_ms: u64,
    pub reply: tokio::sync::oneshot::Sender<bool>,
}
/// Tauri 托管的接收侧状态容器（票 3 终态：回执表 + 处理器句柄）
///
/// - `pending`：等待宿主应答的询问回执（batch_id → 引擎 oneshot + 询问事实）；
/// - `runtime`：节点运行时的复合处理器句柄与其配置快照——热更新以快照为
///   基底只替换策略/落点，保留 chunk_size 与落位钩子（移动端 MediaStore）；
/// - `last_emit`：进度节流基线（纯性能，无业务语义）；
/// - `settings`：本节点生命周期内的引擎闸门内存态（策略/超时/落点；业务
///   设置真源在插件，经原语推送覆盖）
#[derive(Default)]
pub struct PeerReceiveState {
    pending: Mutex<HashMap<String, PendingOffer>>,
    runtime: tokio::sync::Mutex<Option<(Arc<SharedDirHandler>, TransferConfig)>>,
    last_emit: Mutex<Option<tokio::time::Instant>>,
    settings: Mutex<Option<PeerTransferSettings>>,
}

// ==================== 引擎设置（节点生命周期内存态） ====================

/// 读当前引擎闸门设置（未推送过即缺省；跨 set-policy / set-download-dir
/// 调用互相保留现值）
fn current_settings(ctx: &PeerCtx) -> PeerTransferSettings {
    let state = &ctx.receive;
    let mut guard = state.settings.lock().expect("peer receive settings lock poisoned");
    guard.get_or_insert_with(PeerTransferSettings::default).clone()
}

/// 生效落点解析：覆盖值优先，否则桌面缺省 Downloads\WasmNest\
fn effective_download_dir(ctx: &PeerCtx, settings: &PeerTransferSettings) -> Result<PathBuf> {
    if let Some(dir) = settings
        .download_dir
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        return Ok(PathBuf::from(dir));
    }
    super::resolve_download_dir(ctx)
}

// ==================== 节点装配接缝（peer_net 调用）====================

/// 装配期登记：处理器句柄 + 配置快照（热更新基底）。start_locked 以缺省
/// Ask/60s 构造；用户设置由 file-transfer 插件激活后经 set-receive-policy /
/// set-download-dir 原语推送纠正
pub(crate) async fn register_handler(ctx: &PeerCtx, handler: Arc<SharedDirHandler>, mut config: TransferConfig) {
    let settings = default_settings(ctx);
    if let Ok(dir) = effective_download_dir(ctx, &settings) {
        config.download_dir = dir;
    }
    config.policy = settings.build_policy();
    handler.update_transfer_config(config.clone());
    let state = &ctx.receive;
    *state.runtime.lock().await = Some((handler, config));
}

/// 节点装配期缺省设置（无磁盘缓存——设置真源在插件，激活后推送纠正）
fn default_settings(_ctx: &PeerCtx) -> PeerTransferSettings {
    PeerTransferSettings::default()
}

/// 节点停止时摘除句柄（此后设置命令仅改内存态，下次启动重新装配）
pub(crate) async fn clear_handler(ctx: &PeerCtx) {
    let state = &ctx.receive;
    *state.runtime.lock().await = None;
}

/// 处理器与配置快照句柄（issue 11 远端拉取用：配置为落点/策略热更新基底）
pub(crate) async fn handler_and_config(ctx: &PeerCtx) -> Option<(Arc<SharedDirHandler>, TransferConfig)> {
    let snapshot = {
        let state = &ctx.receive;
        let guard = state.runtime.lock().await;
        guard.clone()
    };
    snapshot
}

/// 引擎事件消费主循环（票 3 终态：纯直推）：OfferPending 登记回执表后直推、
/// Progress 节流直推、Terminal/Paused/Resumed 直推。通道关闭（节点停止）时
/// 弃置 pending 回执——回执 drop 即自动拒（引擎 sweeper 兜底语义）。
pub(crate) async fn drive_receive_events(ctx: Arc<PeerCtx>, mut rx: mpsc::Receiver<TransferEvent>) {
    while let Some(event) = rx.recv().await {
        match event {
            TransferEvent::OfferPending {
                remote,
                batch_id,
                files,
                total_size,
                reply,
            } => {
                // 引擎原始事件先行构造（borrow），登记（move）后直推
                let payload = super::engine_offer_payload(&remote, &batch_id, &files, total_size);
                register_offer(&ctx, remote, batch_id, total_size, reply).await;
                super::publish_engine_event(&ctx, super::TOPIC_RECEIVE_EVENT, payload);
            }
            TransferEvent::Progress {
                batch_id,
                transferred,
                total,
                rate_bps,
                ..
            } => {
                // 节流窗口与直推共用：due 才直推引擎原始事件
                if throttle_due(&ctx) {
                    super::publish_engine_event(
                        &ctx,
                        super::TOPIC_RECEIVE_EVENT,
                        super::engine_progress_payload(&batch_id, transferred, total, rate_bps),
                    );
                }
            }
            TransferEvent::Terminal { batch_id, state, .. } => {
                let payload = super::engine_terminal_payload(&batch_id, &state);
                super::publish_engine_event(&ctx, super::TOPIC_RECEIVE_EVENT, payload);
                tracing::info!(batch_id = %batch_id, state = ?state, "peer receive session ended");
            }
            // 数据供方暂停/恢复：直推（插件归约同步任务行状态）
            TransferEvent::Paused { batch_id, .. } => {
                super::publish_engine_event(
                    &ctx,
                    super::TOPIC_RECEIVE_EVENT,
                    super::engine_pause_payload("paused", &batch_id),
                );
            }
            TransferEvent::Resumed { batch_id, .. } => {
                super::publish_engine_event(
                    &ctx,
                    super::TOPIC_RECEIVE_EVENT,
                    super::engine_pause_payload("resumed", &batch_id),
                );
            }
            // 服务侧拉取事件走独立 serve 通道，由发送侧模块消费，
            // 本接收通道理论上收不到；防御性忽略
            TransferEvent::PullServed { .. } => {}
        }
    }
    // 通道关闭 = 节点停止：pending 回执弃置即自动拒（回执 drop 触发引擎
    // 询问结算失败路径）；同时直推 `node-stopped` 事实——在途批已全部中止，
    // 插件据此把在册进行中条目标注 `interrupted`（共享核
    // `mark_active_interrupted`；宿主无任务表可写终态）
    discard_all_pending_offers(&ctx);
    super::publish_engine_event(&ctx, super::TOPIC_RECEIVE_EVENT, super::engine_node_stopped_payload());
    tracing::warn!("peer-net node stopped: receive event channel closed");
}

async fn register_offer(
    ctx: &PeerCtx,
    remote: NodeId,
    batch_id: String,
    total_size: u64,
    reply: tokio::sync::oneshot::Sender<bool>,
) {
    let state = &ctx.receive;
    state
        .pending
        .lock()
        .expect("peer receive pending lock poisoned")
        .insert(
            batch_id.clone(),
            PendingOffer {
                total_size,
                ts_ms: super::event_now_ms(),
                reply,
            },
        );
    tracing::info!(
        batch_id = %batch_id,
        remote = %remote,
        "incoming peer transfer offer pending user reply"
    );
}

/// 进度节流：距上次发射不足间隔则跳过（终态路径不经此函数即时推送）。
/// 返回本次是否发射。
fn throttle_due(ctx: &PeerCtx) -> bool {
    let state = &ctx.receive;
    let mut last = state.last_emit.lock().expect("peer receive throttle lock poisoned");
    let now = tokio::time::Instant::now();
    match *last {
        Some(t) if now.duration_since(t) < PROGRESS_EMIT_INTERVAL => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

/// 弃置全部 pending 回执（节点停止：回执 drop 即自动拒）
fn discard_all_pending_offers(ctx: &PeerCtx) {
    let state = &ctx.receive;
    let had = !state
        .pending
        .lock()
        .expect("peer receive pending lock poisoned")
        .is_empty();
    state
        .pending
        .lock()
        .expect("peer receive pending lock poisoned")
        .clear();
    if had {
        tracing::warn!("peer-net stopped with pending receive offers, replies dropped (auto-reject)");
    }
}

// ==================== 传输控制原语面 ====================

/// 应答传输询问（接受全部 / 拒绝全部；host-peer `respond-transfer` 原语）。
/// 返回是否成功送达回执——false 表示批已超时被引擎自动拒或 ID 未知。
///
/// 任务行的 running/rejected 落态由插件归约引擎后续事件完成（宿主无任务表）。
pub async fn respond_peer_transfer(ctx: Arc<PeerCtx>, batch_id: String, accepted: bool) -> Result<bool> {
    let state = &ctx.receive;
    let pending = state
        .pending
        .lock()
        .expect("peer receive pending lock poisoned")
        .remove(&batch_id);
    let Some(offer) = pending else {
        tracing::warn!(batch_id = %batch_id, "respond for unknown/expired receive offer");
        return Ok(false);
    };
    let delivered = offer.reply.send(accepted).is_ok();
    tracing::info!(batch_id = %batch_id, accepted, delivered, "peer transfer offer answered");
    Ok(delivered)
}

/// 取消接收批（host-peer `close` 原语的接收侧分支）：pending 视同用户拒绝
/// 并回执 false（引擎随后直推 rejected 终态，插件归约落态）；running 先查
/// 远端拉取会话（本端是拉取发起方），未命中再回退服务端会话表（push 接收批）。
/// 返回是否命中。
pub async fn cancel_peer_receiving(ctx: Arc<PeerCtx>, batch_id: String) -> Result<bool> {
    let state = &ctx.receive;
    if dismiss_pending_offer(&state, &batch_id) {
        tracing::info!(batch_id = %batch_id, "pending receive dismissed as rejected");
        return Ok(true);
    }
    let hit = match super::peer_engine_remote::cancel_pull(&ctx, &batch_id) {
        true => true,
        false => match state.runtime.lock().await.as_ref() {
            Some((handler, _)) => handler.cancel_transfer(&batch_id),
            None => false,
        },
    };
    tracing::debug!(batch_id = %batch_id, hit, "cancel receiving requested");
    Ok(hit)
}

/// 待决询问破除：pending 视同用户拒绝——移除回执通道并回执 `false`（送达失败 =
/// 引擎侧询问已先行结算）。命中返回 true。
fn dismiss_pending_offer(state: &PeerReceiveState, batch_id: &str) -> bool {
    let reply = state
        .pending
        .lock()
        .expect("peer receive pending lock poisoned")
        .remove(batch_id);
    match reply {
        None => false,
        Some(offer) => {
            // 回执送达失败 = 引擎侧询问已先行结算（超时/对端撤销）
            if offer.reply.send(false).is_err() {
                tracing::debug!(batch_id = %batch_id, "receive offer already settled by engine");
            }
            true
        }
    }
}

/// 暂停接收批：经 wire Pause 帧请求对端数据供方门控推流（连接保持、断点
/// 不丢）。两条路径：拉取会话（本端是拉取发起方，对端 serve 供流）经 pull
/// 暂停句柄下发；push 接收批（对端是发送方）经接收会话暂停句柄下发。
/// 任务行落态由插件归约（本端命令乐观 + 对端帧回流）。返回是否命中。
pub async fn pause_peer_receiving(ctx: Arc<PeerCtx>, batch_id: String) -> Result<bool> {
    let mut hit = super::peer_engine_remote::pause_pull(&ctx, &batch_id).await;
    if !hit {
        hit = pause_receive_session(&ctx, &batch_id, true).await;
    }
    tracing::debug!(batch_id = %batch_id, hit, "pause receiving requested");
    Ok(hit)
}

/// 恢复暂停的接收批：写 Resume 帧续流（对端数据供方解除门控）
pub async fn resume_peer_receiving(ctx: Arc<PeerCtx>, batch_id: String) -> Result<bool> {
    let mut hit = super::peer_engine_remote::resume_pull(&ctx, &batch_id).await;
    if !hit {
        hit = pause_receive_session(&ctx, &batch_id, false).await;
    }
    tracing::debug!(batch_id = %batch_id, hit, "resume receiving requested");
    Ok(hit)
}

/// 经接收会话暂停句柄下发暂停/恢复（push 接收批：本端写 Pause/Resume 帧
/// 请求对端发送会话门控推流）。
async fn pause_receive_session(ctx: &PeerCtx, batch_id: &str, paused: bool) -> bool {
    let handler = {
        let state = &ctx.receive;
        let guard = state.runtime.lock().await;
        guard.as_ref().map(|(handler, _)| Arc::clone(handler))
    };
    match handler {
        Some(handler) => handler.set_receive_paused(batch_id, paused).await,
        None => false,
    }
}

// ==================== 活跃批投影（active-transfers） ====================

/// pending 询问投影（active-transfers 原语数据源）：纯引擎询问事实——
/// batchId/direction/status=pending/totalSize/tsMs
pub(crate) fn active_receive_rows(ctx: &PeerCtx) -> Vec<serde_json::Value> {
    let state = &ctx.receive;
    let guard = state.pending.lock().expect("peer receive pending lock poisoned");
    guard
        .iter()
        .map(|(batch_id, offer)| {
            serde_json::json!({
                "batchId": batch_id,
                "direction": "receive",
                "status": "pending",
                "totalBytes": offer.total_size,
                "transferredBytes": 0,
                "rateBps": 0.0,
                "updatedAtMs": offer.ts_ms,
            })
        })
        .collect()
}

// ==================== 设置闸门 ====================

// 设置真源在 file-transfer 插件私有库，宿主只持有本次节点生命周期内的引擎闸门
// 内存态；查询/写入命令面与旧 `transfer_settings.json` 读写随票 06 退役，
// 以下入口只由 host-peer 原语（`peer_net::*_for_plugin`）调用。

/// 更新接收策略与询问超时（校验后运行中节点热生效）
pub async fn set_peer_receive_policy(ctx: Arc<PeerCtx>, mode: String, timeout_secs: u64) -> Result<()> {
    if !matches!(mode.as_str(), POLICY_ASK | POLICY_ALWAYS_ACCEPT | POLICY_ALWAYS_DENY) {
        return Err(AppError::InvalidInput(format!(
            "set receive policy: unknown mode '{mode}'"
        )));
    }
    validate_ask_timeout_secs(timeout_secs)
        .map_err(|detail| AppError::InvalidInput(format!("set receive policy: ask timeout {detail}")))?;
    let settings = PeerTransferSettings {
        policy_mode: mode,
        ask_timeout_secs: timeout_secs,
        download_dir: current_settings(&ctx).download_dir,
    };
    apply_settings(&ctx, &settings).await;
    tracing::info!(
        mode = %settings.policy_mode,
        timeout = settings.ask_timeout_secs,
        "receive policy updated"
    );
    Ok(())
}

/// 桌面端：更换接收落点目录（None = 恢复缺省 Downloads\WasmNest\）。
/// 目录即时创建；运行中节点热生效。
pub async fn set_peer_download_dir(ctx: Arc<PeerCtx>, path: Option<String>) -> Result<()> {
    let dir = match path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(d) => {
            tokio::fs::create_dir_all(d).await.map_err(|e| {
                AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("create download dir '{d}' failed: {e}"),
                ))
            })?;
            Some(d.to_string())
        }
        None => None,
    };
    let mut settings = current_settings(&ctx);
    settings.download_dir = dir;
    apply_settings(&ctx, &settings).await;
    tracing::info!(dir = ?settings.download_dir, "receive download dir updated (desktop)");
    Ok(())
}

/// 应用新设置：内存态替换 + 运行中处理器热更新（以装配快照为基底替换策略/落点）
async fn apply_settings(ctx: &PeerCtx, settings: &PeerTransferSettings) {
    let state = &ctx.receive;
    *state.settings.lock().expect("peer receive settings lock poisoned") = Some(settings.clone());

    let mut runtime = state.runtime.lock().await;
    if let Some((handler, base)) = runtime.as_ref() {
        let mut config = base.clone();
        config.policy = settings.build_policy();
        if let Ok(dir) = effective_download_dir(ctx, settings) {
            config.download_dir = dir;
        }
        handler.update_transfer_config(config.clone());
        *runtime = Some((Arc::clone(handler), config));
    }
}

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(mode: &str, timeout: u64) -> PeerTransferSettings {
        PeerTransferSettings {
            policy_mode: mode.to_string(),
            ask_timeout_secs: timeout,
            download_dir: None,
        }
    }

    #[test]
    fn settings_default_is_ask_with_default_window() {
        let settings = PeerTransferSettings::default();
        assert_eq!(settings.policy_mode, POLICY_ASK);
        assert_eq!(settings.ask_timeout_secs, DEFAULT_ASK_TIMEOUT_SECS);
        assert!(settings.download_dir.is_none());
        match settings.build_policy() {
            ReceivePolicy::Ask { timeout } => {
                assert_eq!(timeout, std::time::Duration::from_secs(DEFAULT_ASK_TIMEOUT_SECS))
            }
            other => panic!("default must build Ask, got {other:?}"),
        }
    }

    #[test]
    fn policy_modes_map_to_engine_variants() {
        assert!(matches!(
            settings(POLICY_ALWAYS_ACCEPT, 60).build_policy(),
            ReceivePolicy::AlwaysAccept
        ));
        assert!(matches!(
            settings(POLICY_ALWAYS_DENY, 60).build_policy(),
            ReceivePolicy::AlwaysDeny
        ));
        match settings(POLICY_ASK, 30).build_policy() {
            ReceivePolicy::Ask { timeout } => {
                assert_eq!(timeout, std::time::Duration::from_secs(30))
            }
            other => panic!("ask must build Ask, got {other:?}"),
        }
    }
}

/// ③ 回归：接收侧取消链路（票 06 改名时曾断链）。
///
/// 覆盖 `dismiss_pending_offer`：pending 询问视同拒绝并回执 false；无 pending
/// 返回 false。真实 mTLS loopback 属真实 wasm 闭环，本模块先锁 dead-code 级
/// 契约：pending 分支是「证明取消接收不是纯 shell」的入口。
#[cfg(test)]
mod cancel_regression_tests {
    use super::*;

    #[tokio::test]
    async fn dismiss_pending_offer_dismisses_as_reject_and_replies_false() {
        let state = PeerReceiveState::default();
        let (tx, rx) = tokio::sync::oneshot::channel();
        state.pending.lock().expect("lock").insert(
            "b1".to_string(),
            PendingOffer {
                total_size: 1,
                ts_ms: 1,
                reply: tx,
            },
        );

        assert!(dismiss_pending_offer(&state, "b1"), "pending offer 破除必须命中 true");
        assert_eq!(rx.await, Ok(false), "pending 询问必须回执 false（视同拒绝）");
        assert!(
            state.pending.lock().expect("lock").get("b1").is_none(),
            "pending 必须移除"
        );
    }

    #[test]
    fn dismiss_pending_offer_miss_returns_false_and_keeps_state() {
        let state = PeerReceiveState::default();
        assert!(
            !dismiss_pending_offer(&state, "unknown"),
            "无 pending → false（不是错误）"
        );
        assert!(state.pending.lock().expect("lock").is_empty());
    }
}
