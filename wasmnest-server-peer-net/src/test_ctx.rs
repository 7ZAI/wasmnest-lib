//! 无头 [`PeerCtx`] 夹具（仅 `#[cfg(test)]`）：传输控制面路由用例的最小宿主替身
//!
//! **为什么自带替身**：[`PeerCtx`] 的五个端口（bus / event_sink / paths /
//! system_info / mdns）的实现属宿主，crate 内单测不能引用宿主 bin crate。
//! 本夹具只保证「构造得出、不起节点、不连网」：四张会话表（发送句柄表 /
//! serve 供流登记表 / pull 会话表 / 接收会话表）与两个控制函数（`PeerTransferState`
//! 纯内存；后两张表的入口在 `SharedDirHandler` 内、本夹具不装配 handler ⇒ 未命中
//! 分支）都能被单测直接触达。
//!
//! **为什么 mDNS / 帧投递是 `unreachable!`**：被测的暂停/恢复路由不触发现守护、
//! 不经总线投递（事件直推发生在会话驱动侧，本夹具不起会话）。真触到即说明用例
//! 走到了夹具覆盖不到的面，此时应当**显式失败**而不是静默通过——与
//! `plugin_binding::tests::scaffold` 的无头端口同款纪律。

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use wasmnest_server_base::ports::{
    BusMessageHandler, BusPort, EventSink, MdnsPort, MdnsTypeSubscription, PathsPort, SystemInfoPort,
};

use std::sync::LazyLock;

use crate::base::{FileLanding, SharedSafAccess};
use crate::engine_ports::{PeerEnginePorts, PeerPlatformSeam};
use crate::peer_engine_receive::PeerReceiveState;
use crate::peer_engine_remote::PeerRemoteState;
use crate::peer_engine_transfer::PeerTransferState;
use crate::{PeerCtx, PeerNetState};

/// 构造一份无头引擎上下文：节点未启动、四张会话表全空、无 handler
pub(crate) fn headless_ctx() -> Arc<PeerCtx> {
    Arc::new(PeerCtx {
        ports: Arc::new(PeerEnginePorts {
            bus: Arc::new(NullBus),
            event_sink: Arc::new(NullEventSink),
            paths: Arc::new(FixedPaths),
            system_info: Arc::new(FixedSystemInfo),
            mdns: Arc::new(UnreachableMdns),
            platform: None,
        }),
        state: Arc::new(PeerNetState::default()),
        transfer: Arc::new(PeerTransferState::default()),
        receive: Arc::new(PeerReceiveState::default()),
        remote: Arc::new(PeerRemoteState::default()),
    })
}

/// 带平台默认共享目录的上下文变体（2026-10-22 peer-net-dissolve：验证平台目录
/// 不被插件 `set-shared-roots` 全量推送清掉；decorate 兜底回归用例用）
pub(crate) fn headless_ctx_with_platform_dir() -> Arc<PeerCtx> {
    // 固定临时目录一次创建（多用例共享同一路径 → decorate 同根去重跳过，幂等）
    static PLATFORM_DIR: LazyLock<std::path::PathBuf> = LazyLock::new(|| {
        let dir = std::env::temp_dir().join(format!("wasmnest-peer-platform-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create platform dir fixture");
        dir
    });
    let seam: Arc<dyn PeerPlatformSeam> = Arc::new(PlatformDirSeam(PLATFORM_DIR.clone()));
    Arc::new(PeerCtx {
        ports: Arc::new(PeerEnginePorts {
            bus: Arc::new(NullBus),
            event_sink: Arc::new(NullEventSink),
            // 共享注册表需要真实可落盘的数据目录（FixedPaths 的 `/nonexistent` 占位
            // 在 set_shared_roots 全量推送路径会 create_dir_all 失败）
            paths: Arc::new(TempPaths),
            system_info: Arc::new(FixedSystemInfo),
            mdns: Arc::new(UnreachableMdns),
            platform: Some(seam),
        }),
        state: Arc::new(PeerNetState::default()),
        transfer: Arc::new(PeerTransferState::default()),
        receive: Arc::new(PeerReceiveState::default()),
        remote: Arc::new(PeerRemoteState::default()),
    })
}

/// 真实临时数据目录 paths（注册表落盘用例用；LazyLock 单例，多用例共享）
struct TempPaths;

impl PathsPort for TempPaths {
    fn app_data_dir(&self) -> wasmnest_server_base::error::Result<std::path::PathBuf> {
        Ok(std::path::PathBuf::from(
            std::env::temp_dir().join(format!("wasmnest-peer-appdata-{}", std::process::id())),
        ))
    }

    fn download_dir(&self) -> wasmnest_server_base::error::Result<std::path::PathBuf> {
        Ok(std::path::PathBuf::from(
            std::env::temp_dir().join(format!("wasmnest-peer-downloads-{}", std::process::id())),
        ))
    }
}

/// 平台默认目录 seam 替身：`default_shared_dirs` 返回固定目录
struct PlatformDirSeam(std::path::PathBuf);

impl PeerPlatformSeam for PlatformDirSeam {
    fn shared_saf_access(&self) -> Option<Arc<dyn SharedSafAccess>> {
        None
    }

    fn file_landing(&self) -> Option<Arc<dyn FileLanding>> {
        None
    }

    fn default_shared_dirs(&self) -> Vec<(String, std::path::PathBuf)> {
        vec![("下载".to_string(), self.0.clone())]
    }
}

/// 总线替身：暂停/恢复路由不经总线（事件直推在会话驱动侧），被调即显式失败
struct NullBus;

#[async_trait]
impl BusPort for NullBus {
    fn publish(&self, topic: &str, _sender: &str, _payload: serde_json::Value) {
        unreachable!("夹具总线不应被发布：{topic}");
    }

    fn publish_binary(&self, topic: &str, _sender: &str, _payload: Vec<u8>) {
        unreachable!("夹具总线不应被发布：{topic}");
    }

    async fn subscribe_static(&self, _subscriber: &str, topic: &str, _handler: Box<dyn BusMessageHandler>) {
        unreachable!("夹具总线不应被订阅：{topic}");
    }

    async fn deliver_endpoint_frame(
        &self,
        _owner: &str,
        endpoint_id: &str,
        _client_id: &str,
        _kind: &str,
        _payload: Vec<u8>,
    ) {
        unreachable!("夹具总线不应投递端点帧：{endpoint_id}");
    }
}

/// 前端事件替身：路由用例不产生前端事件
struct NullEventSink;

impl EventSink for NullEventSink {
    fn emit(&self, event: &str, _payload: serde_json::Value) {
        unreachable!("夹具不应发前端事件：{event}");
    }
}

/// 路径替身：固定临时目录（控制面路由不读盘，但引擎状态构造要求非空语义）
struct FixedPaths;

impl PathsPort for FixedPaths {
    fn app_data_dir(&self) -> wasmnest_server_base::error::Result<PathBuf> {
        Ok(PathBuf::from("/nonexistent/wasmnest-test-data"))
    }

    fn download_dir(&self) -> wasmnest_server_base::error::Result<PathBuf> {
        Ok(PathBuf::from("/nonexistent/wasmnest-test-downloads"))
    }
}

/// 系统信息替身：固定中性值（无端知识，禁真实机器名）
struct FixedSystemInfo;

impl SystemInfoPort for FixedSystemInfo {
    fn device_name(&self) -> String {
        "wasmnest-test-node".to_string()
    }

    fn local_ipv4_addresses(&self) -> Vec<String> {
        Vec::new()
    }

    fn app_version(&self) -> String {
        "0.0.0-test".to_string()
    }
}

/// mDNS 替身：路由用例不触发现守护（真触到即夹具与被测面背离）
struct UnreachableMdns;

impl MdnsPort for UnreachableMdns {
    fn shared_daemon(&self) -> mdns_sd::ServiceDaemon {
        unreachable!("夹具不应取 mDNS 守护：控制面路由不触发现")
    }

    fn register_host_service(&self, service_type: &str, fullname: &str) -> std::result::Result<String, String> {
        unreachable!("夹具不应登记广播：{service_type} / {fullname}")
    }

    fn stop_host_service(&self, advertise_id: &str) -> std::result::Result<bool, String> {
        unreachable!("夹具不应注销广播：{advertise_id}")
    }

    fn subscribe_type(&self, service_type: &str) -> std::result::Result<MdnsTypeSubscription, String> {
        unreachable!("夹具不应订阅类型：{service_type}")
    }

    fn request_type_requery(&self, service_type: &str) {
        unreachable!("夹具不应请求重查：{service_type}")
    }
}
