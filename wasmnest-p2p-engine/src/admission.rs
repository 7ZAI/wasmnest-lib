//! 入站准入闸门：首连确认的 pending 记账 + 上限 / 超时 / 去重拒绝结算。
//!
//! ## 语义孪生（P1 替换判据）
//!
//! 常量与拒绝语义对齐现役 peer-net base/transport.rs 的闸门：
//! - 确认超时 30s（`CONFIRM_TIMEOUT`）：留足用户读弹窗时间，超时按拒绝结算；
//! - pending 上限 8（`MAX_PENDING_CONFIRMATIONS`）：防同网恶意节点堆 pending
//!   耗尽内存；超限新连接立即拒绝；
//! - 同一 node_id 已有 pending 时重复拨入直接拒绝：避免弹窗风暴。
//!
//! 差异（刻意）：现役栈在 TLS 握手后、协议分发前拦截；本引擎在连接建立
//! （noise 握手完成、PeerId 已验证）后拦截——闸门放行前**零上层协议流量**
//! 的语义不变（P0 行为面只有 ping，见 engine 模块说明）。
//!
//! ## 任务形态
//!
//! 立时可判的拒绝（去重 / 超限）同步返回；需要问端口的确认派生独立任务
//! （select 端口应答 vs 超时），不阻塞引擎事件泵——闸门任务先撤 pending 记账
//! 再经 `settle` 通道回泵（泵再断开连接 / 发事件），与现役栈「accept 循环不
//! 等待闸门任务」同构。

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::PeerId;
use tokio::sync::mpsc;

use crate::identity_bridge::NodeId;
use crate::ports::{DenyCause, PeerAdmissionPort};

/// 确认超时默认值：孪生 peer-net `CONFIRM_TIMEOUT`（留足用户读弹窗时间）
pub const DEFAULT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);
/// pending 确认上限默认值：孪生 peer-net `MAX_PENDING_CONFIRMATIONS`
pub const DEFAULT_MAX_PENDING: usize = 8;

/// 准入闸门配置
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    /// 单次确认的等待窗口（超时按拒绝结算）
    pub confirm_timeout: Duration,
    /// 并发 pending 确认上限（超限立即拒绝）
    pub max_pending: usize,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            confirm_timeout: DEFAULT_CONFIRM_TIMEOUT,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }
}

/// 闸门对一次入站请求的即时判定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRequest {
    /// 已受理：端口应答或超时后经 settle 通道结算
    InProgress,
    /// 立即拒绝（不派生任务、不记账）
    Denied(DenyCause),
}

/// 闸门任务的结算回执（发出前 pending 记账已撤）
#[derive(Debug)]
pub struct AdmissionSettled {
    /// 请求确认的对端节点 ID
    pub node_id: NodeId,
    /// 对端 PeerId
    pub peer_id: PeerId,
    /// 结局：true = 放行
    pub admitted: bool,
    /// 拒绝成因（放行时无意义，恒 [`DenyCause::PortDenied`] 占位）
    pub cause: DenyCause,
}

/// 入站准入闸门（pending 记账 + 确认任务派生）
pub struct AdmissionGate {
    config: AdmissionConfig,
    pending: Arc<Mutex<HashSet<NodeId>>>,
}

impl AdmissionGate {
    /// 以给定配置构建
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            pending: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

impl Default for AdmissionGate {
    fn default() -> Self {
        Self::new(AdmissionConfig::default())
    }
}

impl AdmissionGate {
    /// 发起一次入站准入
    ///
    /// - 同 node_id 已 pending → [`GateRequest::Denied`]（`DuplicatePending`，
    ///   弹窗风暴防护——不覆盖在等请求）；
    /// - pending 已满 → [`GateRequest::Denied`]（`CapacityExceeded`，资源保护）；
    /// - 否则记账并派生确认任务（端口应答 vs 超时 select），任务先撤记账、
    ///   再经 `settle` 回泵。
    ///
    /// **须在 tokio 运行时上下文调用**（受理路径会派生任务）。
    pub fn request(
        &self,
        node_id: NodeId,
        peer_id: PeerId,
        port: Arc<dyn PeerAdmissionPort>,
        settle: mpsc::Sender<AdmissionSettled>,
    ) -> GateRequest {
        {
            let mut pending = self.pending.lock().expect("准入 pending 表中毒");
            if pending.contains(&node_id) {
                return GateRequest::Denied(DenyCause::DuplicatePending);
            }
            if pending.len() >= self.config.max_pending {
                return GateRequest::Denied(DenyCause::CapacityExceeded);
            }
            pending.insert(node_id.clone());
        }
        let timeout = self.config.confirm_timeout;
        let pending = Arc::clone(&self.pending);
        let settle = settle.clone();
        tokio::spawn(async move {
            let (admitted, cause) = tokio::select! {
                admitted = port.confirm_inbound(&node_id, &peer_id) => (admitted, DenyCause::PortDenied),
                _ = tokio::time::sleep(timeout) => (false, DenyCause::Timeout),
            };
            // 先撤记账再结算：拒绝后对端重拨可再走闸门；放行后同节点新连接不误判去重
            pending
                .lock()
                .expect("准入 pending 表中毒")
                .remove(&node_id);
            let _ = settle
                .send(AdmissionSettled {
                    node_id,
                    peer_id,
                    admitted,
                    cause,
                })
                .await;
        });
        GateRequest::InProgress
    }

    /// 撤销一笔 pending 记账（连接在结算前已断开时由泵调用，防记账滞留）
    pub fn withdraw(&self, node_id: &NodeId) {
        self.pending
            .lock()
            .expect("准入 pending 表中毒")
            .remove(node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 手动放行的桩端口：每笔确认等各自 oneshot 应答
    struct LatchPort {
        admits: Mutex<Vec<tokio::sync::oneshot::Sender<bool>>>,
    }

    #[async_trait::async_trait]
    impl PeerAdmissionPort for LatchPort {
        async fn confirm_inbound(&self, _node_id: &NodeId, _peer_id: &PeerId) -> bool {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.admits.lock().unwrap().push(tx);
            rx.await.unwrap_or(false)
        }
    }

    impl LatchPort {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                admits: Mutex::new(Vec::new()),
            })
        }

        /// 应答第 n 笔在等确认（等任务登记到位再取；越界/超时 panic = 测试自身装配错了）
        async fn answer(&self, n: usize, admitted: bool) {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if self.admits.lock().unwrap().len() > n {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "第 {n} 笔确认 2s 内未登记"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let tx = self.admits.lock().unwrap().remove(n);
            tx.send(admitted).unwrap();
        }
    }

    fn node_id(n: u8) -> NodeId {
        NodeId::parse(&hex::encode([n; 32])).unwrap()
    }

    #[tokio::test]
    async fn 受理_端口放行_结算_admitted() {
        let gate = AdmissionGate::default();
        let port = LatchPort::new();
        let (tx, mut rx) = mpsc::channel(8);
        assert_eq!(
            gate.request(node_id(1), PeerId::random(), port.clone(), tx),
            GateRequest::InProgress
        );
        port.answer(0, true).await;
        let settled = rx.recv().await.unwrap();
        assert!(settled.admitted);
        assert_eq!(settled.node_id, node_id(1));
    }

    #[tokio::test]
    async fn 受理_端口拒绝_结算_denied() {
        let gate = AdmissionGate::default();
        let port = LatchPort::new();
        let (tx, mut rx) = mpsc::channel(8);
        gate.request(node_id(2), PeerId::random(), port.clone(), tx);
        port.answer(0, false).await;
        let settled = rx.recv().await.unwrap();
        assert!(!settled.admitted);
        assert_eq!(settled.cause, DenyCause::PortDenied);
    }

    #[tokio::test]
    async fn 超时_按拒绝结算() {
        let gate = AdmissionGate::new(AdmissionConfig {
            confirm_timeout: Duration::from_millis(50),
            max_pending: 8,
        });
        let port = LatchPort::new();
        let (tx, mut rx) = mpsc::channel(8);
        gate.request(node_id(3), PeerId::random(), port.clone(), tx);
        let settled = rx.recv().await.unwrap();
        assert!(!settled.admitted);
        assert_eq!(settled.cause, DenyCause::Timeout);
    }

    #[tokio::test]
    async fn 同节点重复拨入_立即拒绝_不覆盖在等请求() {
        let gate = AdmissionGate::default();
        let port = LatchPort::new();
        let (tx, _rx) = mpsc::channel(8);
        assert_eq!(
            gate.request(node_id(4), PeerId::random(), port.clone(), tx.clone()),
            GateRequest::InProgress
        );
        assert_eq!(
            gate.request(node_id(4), PeerId::random(), port.clone(), tx),
            GateRequest::Denied(DenyCause::DuplicatePending)
        );
        // 第一笔仍在等（1 笔在等），结算后同节点可再来
        port.answer(0, true).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        assert_eq!(
            gate.request(node_id(4), PeerId::random(), port, tx2),
            GateRequest::InProgress
        );
        assert!(rx2.recv().await.is_some());
    }

    #[tokio::test]
    async fn pending_满额_立即拒绝() {
        let gate = AdmissionGate::new(AdmissionConfig {
            confirm_timeout: Duration::from_secs(30),
            max_pending: 2,
        });
        let port = LatchPort::new();
        let (tx, _rx) = mpsc::channel(8);
        for n in 1..=2u8 {
            assert_eq!(
                gate.request(node_id(n), PeerId::random(), port.clone(), tx.clone()),
                GateRequest::InProgress
            );
        }
        assert_eq!(
            gate.request(node_id(9), PeerId::random(), port.clone(), tx),
            GateRequest::Denied(DenyCause::CapacityExceeded)
        );
    }

    #[tokio::test]
    async fn withdraw_撤销在等记账() {
        let gate = AdmissionGate::default();
        let port = LatchPort::new();
        let (tx, _rx) = mpsc::channel(8);
        gate.request(node_id(5), PeerId::random(), port.clone(), tx);
        gate.withdraw(&node_id(5));
        // 撤销后同节点再入不受去重拦截
        let (tx2, _rx2) = mpsc::channel(8);
        assert_eq!(
            gate.request(node_id(5), PeerId::random(), port, tx2),
            GateRequest::InProgress
        );
    }
}
