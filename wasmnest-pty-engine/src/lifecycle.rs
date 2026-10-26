//! PTY Termination Gate
//!
//! 一条 PTY 会话的「结束」由两条互相独立的信号构成：
//!
//! ① **读线程关闭**——EOF / 读错误 / `running` 置位，此刻尾帧已全部投递；
//! ② **子进程被回收**——`Child::wait` 返回，此刻退出码才可用。
//!
//! 两者齐备才发出一条 [`PtyTerminated`]：只有 ① 时退出码还没拿到（业务链路历史上
//! 正是只等 EOF，所以从未带出退出码）；只有 ② 时消费方会在尾帧落环前翻到终态。
//! 恰好一次由 `emitted` 标志保证（broadcast 不去重，两条信号各自可能重入）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use portable_pty::Child as PtyChild;
use tokio::sync::broadcast;

use crate::pty_status::PtySessionStatus;

/// PTY 终态事件（生命周期广播载荷）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtyTerminated {
    /// 终止类别：读线程给出的 `Stopped`（EOF/主动停止）或 `Error`（读错误）
    pub status: PtySessionStatus,
    /// 进程退出码；回收失败或无子进程句柄时为 `None`
    pub exit_code: Option<i32>,
    /// 是否由本会话 `kill()` 主动终止
    ///
    /// portable-pty 的 `ExitStatus` 不暴露 signal（信号终止也报 `code=1`），
    /// 无法从退出码区分「被杀」与 `exit 1`，因此以宿主侧的 kill 请求为准。
    pub killed: bool,
}

/// 两路终止信号的汇聚门
pub struct PtyTerminationGate {
    session_id: String,
    lifecycle_tx: broadcast::Sender<PtyTerminated>,
    kill_requested: Arc<AtomicBool>,
    state: Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    /// 读线程给出的终止类别（`None` = 读线程尚未退出）
    reader_closed: Option<PtySessionStatus>,
    /// 回收结果（外层 `None` = 尚未回收；内层 `None` = 回收成功但无退出码）
    reaped: Option<Option<i32>>,
    /// 终态事件已发出
    emitted: bool,
}

impl PtyTerminationGate {
    pub fn new(
        session_id: String,
        lifecycle_tx: broadcast::Sender<PtyTerminated>,
        kill_requested: Arc<AtomicBool>,
    ) -> Self {
        Self {
            session_id,
            lifecycle_tx,
            kill_requested,
            state: Mutex::new(GateState::default()),
        }
    }

    /// 订阅终态事件（`PtySession::subscribe_lifecycle` 的实现基）
    pub fn subscribe(&self) -> broadcast::Receiver<PtyTerminated> {
        self.lifecycle_tx.subscribe()
    }

    /// 读线程是否已关闭（终态信号 ① 已到）
    ///
    /// 语义边界：**读线程读到 EOF / 读错误**，此刻尾帧已排入有序队列（投递由单消费者
    /// 任务按序完成）。对插件私有 PTY（`ReleaseOnSpawn`：spawn 后释放 slave fd），
    /// 这只可能在子进程已退出时发生——因此可作为「输出已终结」的存活判据；
    /// 业务线的 `Hold` 策略下自然退出读不到 EOF，本方法保持 false 直到 kill/销毁。
    pub fn reader_closed(&self) -> bool {
        self.lock_state().reader_closed.is_some()
    }

    /// 信号 ①：读线程退出（每条读线程生命周期只应到达一次，重复调用被忽略）
    pub fn mark_reader_closed(&self, status: PtySessionStatus) {
        let mut state = self.lock_state();
        if state.reader_closed.is_some() {
            return;
        }
        state.reader_closed = Some(status);
        self.try_complete(&mut state);
    }

    /// 信号 ②：子进程已回收，`exit_code` 为 `None` 表示回收失败/无句柄
    pub fn mark_reaped(&self, exit_code: Option<i32>) {
        let mut state = self.lock_state();
        if state.reaped.is_some() {
            return;
        }
        state.reaped = Some(exit_code);
        self.try_complete(&mut state);
    }

    /// 把子进程交给专属回收线程
    ///
    /// `Child::wait` 阻塞且要求 `&mut` 独占，只能落在非 async 的 OS 线程上——
    /// 这是「不轮询 `try_wait` 拿到退出码」的唯一形态。线程持有 `Child` 直到
    /// 进程被回收，随后把退出码汇入本门。
    pub fn spawn_reaper(self: &Arc<Self>, child: Box<dyn PtyChild + Send + Sync>) {
        let gate = self.clone();
        let session_id = self.session_id.clone();
        let pid = child.process_id();

        let spawned = std::thread::Builder::new()
            .name(format!("pty-reaper-{session_id}"))
            .spawn(move || {
                let mut child = child;
                match child.wait() {
                    Ok(status) => {
                        tracing::debug!(
                            session_id = %session_id,
                            pid = ?pid,
                            exit_code = status.exit_code(),
                            terminated_by = %status,
                            "PTY child reaped"
                        );
                        gate.mark_reaped(Some(status.exit_code() as i32));
                    }
                    Err(e) => {
                        tracing::warn!(
                            session_id = %session_id,
                            pid = ?pid,
                            error = %e,
                            "PTY 子进程回收失败，终态事件不带退出码"
                        );
                        gate.mark_reaped(None);
                    }
                }
            });

        if let Err(e) = spawned {
            tracing::error!(
                session_id = %self.session_id,
                error = %e,
                "PTY 回收线程启动失败，终态事件不带退出码"
            );
            self.mark_reaped(None);
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state.lock().expect("PTY 终态门锁被污染")
    }

    fn try_complete(&self, state: &mut GateState) {
        let (Some(status), Some(exit_code)) = (state.reader_closed, state.reaped) else {
            return;
        };
        if state.emitted {
            return;
        }
        state.emitted = true;

        let terminated = PtyTerminated {
            status,
            exit_code,
            killed: self.kill_requested.load(Ordering::SeqCst),
        };
        tracing::info!(
            session_id = %self.session_id,
            status = ?terminated.status,
            exit_code = ?terminated.exit_code,
            killed = terminated.killed,
            "PTY session terminated"
        );

        // 发送失败 = 无订阅者（业务会话已注销等），属正常终止路径
        if let Err(e) = self.lifecycle_tx.send(terminated) {
            tracing::warn!(session_id = %self.session_id, %e, "PTY lifecycle event dropped (no subscribers)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用门：`kill_requested` 由调用方给定，回收/读线程信号手动补
    fn fresh_gate(killed: bool) -> (Arc<PtyTerminationGate>, broadcast::Receiver<PtyTerminated>) {
        let (tx, rx) = broadcast::channel(8);
        let gate = Arc::new(PtyTerminationGate::new(
            "gate-test".to_string(),
            tx,
            Arc::new(AtomicBool::new(killed)),
        ));
        (gate, rx)
    }

    /// C-003 反例：只有读线程关闭 → 不发事件（此刻退出码尚不可用）
    #[test]
    fn reader_closed_alone_does_not_emit() {
        let (gate, mut rx) = fresh_gate(false);

        gate.mark_reader_closed(PtySessionStatus::Stopped);

        assert_eq!(
            rx.try_recv().unwrap_err(),
            broadcast::error::TryRecvError::Empty,
            "读线程单独关闭不得发出终态事件"
        );
    }

    /// C-003 配套：`reader_closed()` 访问器如实反映信号 ①（host-pty 的 `is-running` 判据）
    #[test]
    fn reader_closed_accessor_tracks_signal_one() {
        let (gate, _rx) = fresh_gate(false);
        assert!(!gate.reader_closed(), "未收到信号 ① 前不得报终结");

        gate.mark_reader_closed(PtySessionStatus::Error);
        assert!(
            gate.reader_closed(),
            "读线程关闭后必须报终结（EOF 即进程退出的可靠信号）"
        );

        // 重复信号不改判据（幂等）
        gate.mark_reader_closed(PtySessionStatus::Stopped);
        assert!(gate.reader_closed());
    }

    /// C-003 反例：只有子进程回收 → 不发事件（尾帧可能尚未投递完）
    #[test]
    fn reap_alone_does_not_emit() {
        let (gate, mut rx) = fresh_gate(false);

        gate.mark_reaped(Some(0));

        assert_eq!(
            rx.try_recv().unwrap_err(),
            broadcast::error::TryRecvError::Empty,
            "子进程单独回收不得发出终态事件（业务会话会在尾帧落环前翻到终态）"
        );
    }

    /// C-001/C-002 正例：两路信号齐备 → 恰好一条终态事件，退出码取自回收侧
    #[test]
    fn both_signals_emit_exactly_one_event_with_exit_code() {
        let (gate, mut rx) = fresh_gate(false);

        gate.mark_reaped(Some(7));
        gate.mark_reader_closed(PtySessionStatus::Stopped);
        // 重复信号（后到的回收结果/第二次关闭）不得产生第二条事件
        gate.mark_reaped(Some(9));
        gate.mark_reader_closed(PtySessionStatus::Error);

        assert_eq!(
            rx.try_recv().expect("两路信号齐备应发出终态事件"),
            PtyTerminated {
                status: PtySessionStatus::Stopped,
                exit_code: Some(7),
                killed: false,
            }
        );
        assert_eq!(
            rx.try_recv().unwrap_err(),
            broadcast::error::TryRecvError::Empty,
            "终态事件必须恰好一次"
        );
    }

    /// C-004 边界：信号到达顺序不影响结果（回收晚于读线程关闭同样带出退出码）
    #[test]
    fn reader_closed_before_reap_still_emits_exit_code() {
        let (gate, mut rx) = fresh_gate(false);

        gate.mark_reader_closed(PtySessionStatus::Error);
        gate.mark_reaped(Some(2));

        assert_eq!(
            rx.try_recv().expect("应发出终态事件"),
            PtyTerminated {
                status: PtySessionStatus::Error,
                exit_code: Some(2),
                killed: false,
            }
        );
    }

    /// C-005 异常：回收失败仍发事件（退出码缺省），不挂死消费方
    #[test]
    fn reap_failure_emits_without_exit_code() {
        let (gate, mut rx) = fresh_gate(false);

        gate.mark_reaped(None);
        gate.mark_reader_closed(PtySessionStatus::Stopped);

        let terminated = rx.try_recv().expect("回收失败仍应发出终态事件");
        assert_eq!(terminated.exit_code, None);
        assert_eq!(terminated.status, PtySessionStatus::Stopped);
    }

    /// C-006 正例：未发起 kill → killed=false（自然退出）
    #[test]
    fn emits_not_killed_when_kill_never_requested() {
        let (gate, mut rx) = fresh_gate(false);

        gate.mark_reaped(Some(1));
        gate.mark_reader_closed(PtySessionStatus::Stopped);

        assert!(!rx.try_recv().expect("应发出终态事件").killed);
    }

    /// C-006 反例：kill 请求位置位 → killed=true（与 `exit 1` 退出码相同仍可区分）
    #[test]
    fn emits_killed_when_kill_requested() {
        let (gate, mut rx) = fresh_gate(true);

        gate.mark_reaped(Some(1));
        gate.mark_reader_closed(PtySessionStatus::Stopped);

        assert!(rx.try_recv().expect("应发出终态事件").killed);
    }
}
