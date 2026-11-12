//! 本机 relay 预留的共享协调器（T21 / issue #27）。
//!
//! ## 为什么需要协调器
//!
//! 宿主只有一个共享 peer 节点、一份 libp2p relay 预留；而预留的**需求方**有两类：
//!
//! 1. `host-tunnel` 的 `TunnelManager`（暴露规则 / 在飞 WAN 通道，按插件配置聚合）；
//! 2. `host-peer` 的 `configure-relay`（纯 peer 应用自持的接收面）。
//!
//! 引擎的 `reserve_relay(addrs)` 是**全量替换**（重复调用先释放旧预留）——两边各自
//! 直调会互相抹掉。本模块把「谁要哪些中继端点」收成一张 owner 表，取并集后
//! 串行下发给引擎，实现按插件引用计数：一个 owner 退出只回收自己那份。
//!
//! ## 状态口径
//!
//! - `owners`：owner → 期望端点（已解析为 IP multiaddr；空 = 该 owner 不预留）
//! - `applied`：最后一次成功下发给引擎的并集；`None` = 未知（节点重启 / 上次失败）
//! - `gate`：串行化「计算并集 → 调引擎 → 记账」，避免两个 owner 并发替换
//!
//! 失败时 `applied` 置 `None` 并保留 owners：引擎自身会按退避重试，下一次
//! `set` / `clear` / 节点重启后的 `reapply` 也会重新收敛——不静默丢弃需求。
//!
//! ## 可测性
//!
//! 引擎经 [`RelayEngine`] 注入（生产实现 [`NodeRelay`] 包一层 `RunningNode`），
//! native 单测用记录式假实现验证并集 / 释放 / 幂等 / 失败重试。

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use wasmnest_p2p_engine::engine::RunningNode as P2pRunningNode;
use wasmnest_p2p_engine::Multiaddr;

/// 隧道管理器的 owner 键（机制名，不得与 `peer:<plugin-id>` 冲突）
pub(crate) const TUNNEL_OWNER: &str = "tunnel";

/// 引擎侧最小能力面（生产 = [`NodeRelay`]；native 测试 = 记录式假实现）
#[async_trait]
pub(crate) trait RelayEngine: Send + Sync {
    /// 全量替换预留端点（空列表由协调器拦截，不会下发）
    async fn reserve(&self, addrs: Vec<Multiaddr>) -> Result<(), String>;
    /// 释放本节点全部预留（幂等）
    async fn release(&self) -> Result<(), String>;
}

/// `RunningNode` 适配（生产路径）
pub(crate) struct NodeRelay<'a>(pub(crate) &'a P2pRunningNode);

#[async_trait]
impl RelayEngine for NodeRelay<'_> {
    async fn reserve(&self, addrs: Vec<Multiaddr>) -> Result<(), String> {
        self.0.reserve_relay(addrs).await.map(|_| ()).map_err(|e| e.to_string())
    }

    async fn release(&self) -> Result<(), String> {
        self.0.release_relay().await.map(|_| ()).map_err(|e| e.to_string())
    }
}

/// owner 表 + 下发记账（进程级单例，挂在 `PeerNetState` 上）
#[derive(Default)]
pub(crate) struct RelayReservations {
    owners: Mutex<BTreeMap<String, Vec<Multiaddr>>>,
    applied: Mutex<Option<Vec<Multiaddr>>>,
    gate: tokio::sync::Mutex<()>,
}

impl RelayReservations {
    /// 设置某个 owner 的期望端点（全量替换；空列表 = 清除该 owner）
    ///
    /// # Errors
    /// 引擎下发失败时返回原因；owners 保留，等待下一次收敛。
    pub(crate) async fn set(&self, owner: &str, addrs: Vec<Multiaddr>, engine: &dyn RelayEngine) -> Result<(), String> {
        {
            let mut owners = self.owners.lock().expect("relay owners lock poisoned");
            if addrs.is_empty() {
                owners.remove(owner);
            } else {
                owners.insert(owner.to_string(), addrs);
            }
        }
        self.reconcile(engine).await
    }

    /// 清除某个 owner 的期望端点（幂等）
    ///
    /// # Errors
    /// 引擎下发失败时返回原因；owners 保留，等待下一次收敛。
    pub(crate) async fn clear(&self, owner: &str, engine: &dyn RelayEngine) -> Result<(), String> {
        self.owners.lock().expect("relay owners lock poisoned").remove(owner);
        self.reconcile(engine).await
    }

    /// 节点（重新）启动后重新下发当前并集（调用方先 [`Self::reset_applied`]）
    ///
    /// # Errors
    /// 引擎下发失败时返回原因；owners 保留。
    pub(crate) async fn reapply(&self, engine: &dyn RelayEngine) -> Result<(), String> {
        self.reset_applied();
        self.reconcile(engine).await
    }

    /// 引擎生命周期结束（节点关停）：清掉「已下发」记忆，owners 保留供重启重建
    pub(crate) fn reset_applied(&self) {
        *self.applied.lock().expect("relay applied lock poisoned") = None;
    }

    /// 当前并集快照（只读诊断 / 测试）
    pub(crate) fn desired(&self) -> Vec<Multiaddr> {
        let owners = self.owners.lock().expect("relay owners lock poisoned");
        let mut out = Vec::new();
        for addrs in owners.values() {
            for addr in addrs {
                if !out.contains(addr) {
                    out.push(addr.clone());
                }
            }
        }
        out
    }

    async fn reconcile(&self, engine: &dyn RelayEngine) -> Result<(), String> {
        let _gate = self.gate.lock().await;
        let desired = self.desired();
        {
            let applied = self.applied.lock().expect("relay applied lock poisoned");
            if applied.as_ref() == Some(&desired) {
                return Ok(());
            }
        }
        // 下发前先置未知：失败时不能把旧并集当成仍然生效
        self.reset_applied();
        if desired.is_empty() {
            engine.release().await?;
        } else {
            engine.reserve(desired.clone()).await?;
        }
        *self.applied.lock().expect("relay applied lock poisoned") = Some(desired);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    fn addr(text: &str) -> Multiaddr {
        text.parse().expect("test multiaddr")
    }

    fn relay_a() -> Multiaddr {
        addr("/ip4/203.0.113.9/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA")
    }

    fn relay_b() -> Multiaddr {
        addr("/ip4/198.51.100.7/tcp/4001/p2p/12D3KooWPbYEEfpRvnRKk2YLu43F28fLZgU22wic2M5m6Spkv9ZA")
    }

    #[derive(Default)]
    struct FakeEngine {
        calls: StdMutex<Vec<String>>,
        fail_next: StdMutex<bool>,
    }

    impl FakeEngine {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn fail_next(&self) {
            *self.fail_next.lock().unwrap() = true;
        }

        fn take_failure(&self) -> bool {
            let mut fail = self.fail_next.lock().unwrap();
            let value = *fail;
            *fail = false;
            value
        }
    }

    #[async_trait]
    impl RelayEngine for FakeEngine {
        async fn reserve(&self, addrs: Vec<Multiaddr>) -> Result<(), String> {
            if self.take_failure() {
                self.calls.lock().unwrap().push("reserve:failed".to_string());
                return Err("relay unreachable".to_string());
            }
            let list = addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
            self.calls.lock().unwrap().push(format!("reserve:{list}"));
            Ok(())
        }

        async fn release(&self) -> Result<(), String> {
            if self.take_failure() {
                self.calls.lock().unwrap().push("release:failed".to_string());
                return Err("release failed".to_string());
            }
            self.calls.lock().unwrap().push("release".to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn first_owner_reserves_its_endpoints() {
        let reservations = RelayReservations::default();
        let engine = FakeEngine::default();
        reservations
            .set("peer:a", vec![relay_a()], &engine)
            .await
            .expect("reserve");
        assert_eq!(engine.calls(), vec![format!("reserve:{}", relay_a())]);
    }

    #[tokio::test]
    async fn second_owner_extends_and_first_release_keeps_second() {
        let reservations = RelayReservations::default();
        let engine = FakeEngine::default();
        reservations.set("peer:a", vec![relay_a()], &engine).await.expect("a");
        reservations.set("peer:b", vec![relay_b()], &engine).await.expect("b");
        assert_eq!(reservations.desired(), vec![relay_a(), relay_b()]);

        reservations.clear("peer:a", &engine).await.expect("clear a");
        assert_eq!(reservations.desired(), vec![relay_b()]);
        assert_eq!(
            engine.calls().last().map(String::as_str),
            Some(format!("reserve:{}", relay_b()).as_str())
        );

        reservations.clear("peer:b", &engine).await.expect("clear b");
        assert_eq!(engine.calls().last().map(String::as_str), Some("release"));
    }

    #[tokio::test]
    async fn identical_set_is_idempotent_and_does_not_touch_engine() {
        let reservations = RelayReservations::default();
        let engine = FakeEngine::default();
        reservations
            .set("peer:a", vec![relay_a()], &engine)
            .await
            .expect("first");
        reservations
            .set("peer:a", vec![relay_a()], &engine)
            .await
            .expect("second");
        assert_eq!(engine.calls().len(), 1, "重复相同地址不应重建预留");
    }

    #[tokio::test]
    async fn duplicated_owner_endpoints_are_deduplicated_in_union() {
        let reservations = RelayReservations::default();
        let engine = FakeEngine::default();
        reservations.set("peer:a", vec![relay_a()], &engine).await.expect("a");
        reservations.set("peer:b", vec![relay_a()], &engine).await.expect("b");
        assert_eq!(reservations.desired(), vec![relay_a()]);
        assert_eq!(engine.calls().len(), 1);
    }

    #[tokio::test]
    async fn failure_keeps_owner_and_reapply_retries() {
        let reservations = RelayReservations::default();
        let engine = FakeEngine::default();
        engine.fail_next();
        reservations
            .set("peer:a", vec![relay_a()], &engine)
            .await
            .expect_err("first attempt must surface the failure");
        assert_eq!(reservations.desired(), vec![relay_a()], "owners 必须保留");

        reservations.reapply(&engine).await.expect("retry");
        assert_eq!(
            engine.calls(),
            vec!["reserve:failed".to_string(), format!("reserve:{}", relay_a())]
        );
    }

    #[tokio::test]
    async fn reset_applied_forces_reapply_after_engine_restart() {
        let reservations = RelayReservations::default();
        let engine = FakeEngine::default();
        reservations
            .set("peer:a", vec![relay_a()], &engine)
            .await
            .expect("reserve");
        reservations.reset_applied();
        reservations.reapply(&engine).await.expect("reapply");
        assert_eq!(engine.calls().len(), 2, "节点重启后必须重新下发");
    }

    #[tokio::test]
    async fn empty_owner_is_treated_as_clear() {
        let reservations = RelayReservations::default();
        let engine = FakeEngine::default();
        reservations
            .set("peer:a", vec![relay_a()], &engine)
            .await
            .expect("reserve");
        reservations
            .set("peer:a", Vec::new(), &engine)
            .await
            .expect("empty clears");
        assert!(reservations.desired().is_empty());
        assert_eq!(engine.calls().last().map(String::as_str), Some("release"));
    }
}
