//! `host-peer.start-node` / `stop-node` 的服务租约映射（service-leases §4.1 / §9.1）
//!
//! 用 fake registry + fake service 断言 outcome 映射，不启真实网络；
//! 无租约装配（None）走兼容路径时以 `HEADLESS_UNAVAILABLE` 收口。

use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use wasmnest_server_base::service::{ScopedService, ServiceRegistry};

use crate::plugin_binding::ports::{BoxedBlocked, PeerPorts, HEADLESS_UNAVAILABLE};

struct LeaseProbe {
    key: &'static str,
    starts: AtomicUsize,
    stops: AtomicUsize,
    fail_start: AtomicBool,
}

#[async_trait]
impl ScopedService for LeaseProbe {
    fn key(&self) -> &'static str {
        self.key
    }

    async fn start(&self) -> Result<(), String> {
        if self.fail_start.load(Ordering::SeqCst) {
            return Err("injected start failure".to_string());
        }
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), String> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// 只答权限门 + 可选注册表；引擎上下文恒无头（这些用例本就不该触引擎）
struct LeasePorts {
    registry: Option<Arc<ServiceRegistry>>,
}

impl PeerPorts for LeasePorts {
    fn check_permission(&self, _plugin_id: &str, permission: &str, _api: &str) -> bool {
        permission == crate::wire::PERMISSION_PEER
    }

    fn peer_ctx(&self) -> Result<Arc<crate::PeerCtx>, String> {
        Err(HEADLESS_UNAVAILABLE.to_string())
    }

    fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .expect("test bridge runtime")
                        .block_on(fut)
                })
                .join()
                .expect("test bridge driver thread must not panic")
        })
    }

    fn service_registry(&self) -> Option<Arc<ServiceRegistry>> {
        self.registry.clone()
    }
}

fn ports_with_registry(probe: &Arc<LeaseProbe>) -> Arc<dyn PeerPorts> {
    let registry = Arc::new(ServiceRegistry::new());
    registry.register(probe.clone() as Arc<dyn ScopedService>).unwrap();
    Arc::new(LeasePorts {
        registry: Some(registry),
    })
}

fn probe() -> Arc<LeaseProbe> {
    Arc::new(LeaseProbe {
        key: crate::service::PEER_NODE_SERVICE_KEY,
        starts: AtomicUsize::new(0),
        stops: AtomicUsize::new(0),
        fail_start: AtomicBool::new(false),
    })
}

/// 多应用共享：首引用启动一次，最后一个引用释放才关停；非持有者停止被拒。
#[test]
fn start_attaches_second_holder_and_stop_only_on_last_release() {
    let probe = probe();
    let ports = ports_with_registry(&probe);

    assert_eq!(super::super::peer_start_node(&ports, "app.a").unwrap(), true);
    assert_eq!(probe.starts.load(Ordering::SeqCst), 1);

    assert_eq!(super::super::peer_start_node(&ports, "app.b").unwrap(), false);
    assert_eq!(probe.starts.load(Ordering::SeqCst), 1, "他人持有时不得重复 start");

    assert_eq!(
        super::super::peer_start_node(&ports, "app.a").unwrap(),
        false,
        "同一 holder 重复 acquire 幂等"
    );

    assert_eq!(super::super::peer_stop_node(&ports, "app.a").unwrap(), true);
    assert_eq!(probe.stops.load(Ordering::SeqCst), 0, "app.b 仍持有，服务不得关停");

    assert_eq!(
        super::super::peer_stop_node(&ports, "app.a").unwrap_err(),
        "not owner of peer node",
        "未持有者停止必须被拒（保持旧「非属主拒绝」语义）"
    );

    assert_eq!(super::super::peer_stop_node(&ports, "app.b").unwrap(), true);
    assert_eq!(probe.stops.load(Ordering::SeqCst), 1, "最后一个引用释放才停");
}

/// 启动失败显性上抛，且不落 holder（下次可重试）。
#[test]
fn start_failure_is_visible_and_not_recorded() {
    let probe = probe();
    probe.fail_start.store(true, Ordering::SeqCst);
    let ports = ports_with_registry(&probe);

    let error = super::super::peer_start_node(&ports, "app.a").unwrap_err();
    assert!(error.contains("injected start failure"), "实际错误: {error}");
    assert_eq!(
        super::super::peer_start_node(&ports, "app.b").map(|_| ()),
        Err("service `net.peer-node` failed to start: injected start failure".to_string())
    );
    assert_eq!(probe.starts.load(Ordering::SeqCst), 0);
}

/// 无租约装配：退化为直连引擎；无头上下文仍以 HEADLESS_UNAVAILABLE 收口
/// （fallback 不制造假成功）。
#[test]
fn no_registry_falls_back_to_engine_and_stays_fail_visible() {
    let ports: Arc<dyn PeerPorts> = Arc::new(LeasePorts { registry: None });
    let error = super::super::peer_start_node(&ports, "app.a").unwrap_err();
    assert_eq!(error, HEADLESS_UNAVAILABLE);
    let error = super::super::peer_stop_node(&ports, "app.a").unwrap_err();
    assert_eq!(error, HEADLESS_UNAVAILABLE);
}
