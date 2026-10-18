//! peer 引擎端口面（窄聚合）：引擎实际消费的五个宿主能力端口
//!
//! ## 设计依据（对齐 `wasmnest-discovery-engine` 的 `DiscoveryPorts` 先例）
//!
//! 能力域 crate 只声明**自己真正要用的**宿主能力，宿主按需实现并按端装配
//! （AGENTS §5.1 判据：引擎实现进能力域、安全闸门留宿主）。本 crate 的引擎
//! （节点装配 / 传输 / 接收 / 远端浏览 / 事件翻译）只读五个端口：
//!
//! | 端口 | 用途 | 桌面实现 | 移动实现 |
//! | --- | --- | --- | --- |
//! | [`BusPort`] | 插件总线 publish（`peer:*` 事件与快照直推） | `ServerPorts::bus` | 宿主 message_bus |
//! | [`EventSink`] | 前端事件 emit（连接态 / 首连确认） | `ServerPorts::event_sink` | `app.emit` |
//! | [`PathsPort`] | 数据目录 + 下载目录解析 | `ServerPorts::paths` | app 数据目录 / 私有下载目录 |
//! | [`SystemInfoPort`] | 节点广播设备名 | `ServerPorts::system_info` | 宿主 SystemInfo |
//! | [`MdnsPort`] | mDNS 共享守护 + 宿主广播登记 + 浏览类型中枢订阅（`subscribe_type` / `request_type_requery`） | `ServerPorts::mdns` | `wasmnest-discovery-engine::engine` 与 `type_hub` 出口 |
//!
//! **为什么不直接用 `ServerPorts`（12 端口全量）**：那是桌面 server 族的聚合面，
//! 含 peer 引擎永不使用的端口（`plugin_invoker` / `auth_center` / `power` /
//! `mdns_advertiser` / `lifecycle` / `runtime` / `config`）。窄聚合让新增宿主
//! （移动端 / 无头测试宿主）只装配自己真正要实现的五个端口，并在**类型上**
//! 保证 peer 引擎引用不到无关端口。端口 trait 词汇全部复用
//! `wasmnest-server-base::ports`，不新造第二套。
//!
//! **mDNS 复用（用户指令「mdns 能力面尽量复用」）**：`mdns` 端口的实现方接
//! `wasmnest-discovery-engine` 的共享守护与类型中枢——桌面见
//! `server/ports_impl.rs` 的 `HostMdnsPort`；移动端实现即 `engine::shared_daemon` /
//! `engine::register_host_service` / `engine::stop_host_service` 三函数 + 中枢出口
//! `subscribe_type` / `request_type_requery`。本 crate 自身零 mDNS 依赖
//! （依赖方向锁保持，不引 discovery-engine）。

use std::sync::Arc;

use wasmnest_peer_net::{FileLanding, SharedDirStore, SharedSafAccess};
use wasmnest_server_base::ports::{BusPort, EventSink, MdnsPort, PathsPort, SystemInfoPort};

/// 对等网络引擎的宿主端口聚合（五个 + 一个可选平台缝；字段与安装对象的
/// `Arc` 同源，clone 廉价）
pub struct PeerEnginePorts {
    /// 插件消息总线（`peer:*` topic 直推）
    pub bus: Arc<dyn BusPort>,
    /// 前端事件出口（连接态 / 首连确认弹窗请求）
    pub event_sink: Arc<dyn EventSink>,
    /// 路径解析（身份/可信表/共享目录所在数据目录；接收落点目录）
    pub paths: Arc<dyn PathsPort>,
    /// 系统信息（节点 mDNS 广播设备名）
    pub system_info: Arc<dyn SystemInfoPort>,
    /// mDNS 共享守护接入 + 宿主身份广播登记（复用 discovery-engine）
    pub mdns: Arc<dyn MdnsPort>,
    /// 平台缝（可选）：SAF 共享访问 / 落点提升 / 内置共享条目。
    /// 桌面无平台缝传 `None`（行为与迁移前逐字一致）；移动端注入
    /// Android 实现（SAF 树 + MediaStore 提升 + app 私有下载目录内置条目）
    pub platform: Option<Arc<dyn PeerPlatformSeam>>,
}

/// 平台缝端口：各端注入「平台独有的共享/落点能力」，能力域自身零平台代码
///
/// 设计依据（对齐 AGENTS §5.1.3「引擎实现进能力域、平台缝经端口注入」）：
/// 三处差异面都只是**参数注入**（peer-net 引擎已预留接缝），不构成产品语义——
///
/// | 方法 | 消费点 | 桌面 | 移动 |
/// | --- | --- | --- | --- |
/// | [`PeerPlatformSeam::shared_saf_access`] | `SharedDirHandler::new` 的 SAF 参 | `None`（默认路径直读） | Android SAF 树桥 |
/// | [`PeerPlatformSeam::file_landing`] | `TransferConfig.landing` | `None`（不提升） | MediaStore.Downloads 尽力提升 |
/// | [`PeerPlatformSeam::builtin_shared_dirs`] | 装配期共享目录表 | 无 | app 私有下载目录（免授权内置条目） |
pub trait PeerPlatformSeam: Send + Sync + 'static {
    /// 平台 SAF 共享目录访问（Android SAF 树；无 SAF 平台返回 `None`）
    fn shared_saf_access(&self) -> Option<Arc<dyn SharedSafAccess>>;
    /// 落点提升钩子（Android MediaStore 尽力提升；无则 `None`）
    fn file_landing(&self) -> Option<Arc<dyn FileLanding>>;
    /// 内置免授权共享条目（名字 + 本地目录）；默认无（桌面）
    fn builtin_shared_dirs(&self) -> Vec<(String, std::path::PathBuf)> {
        Vec::new()
    }
}

/// 无平台缝占位（桌面 / 无头装配；行为 = 迁移前「crate 内零平台注入」逐字一致）
pub struct NoPlatformSeam;

impl PeerPlatformSeam for NoPlatformSeam {
    fn shared_saf_access(&self) -> Option<Arc<dyn SharedSafAccess>> {
        None
    }

    fn file_landing(&self) -> Option<Arc<dyn FileLanding>> {
        None
    }
}

/// 装配期共享目录表修饰：把平台内置条目挂到注册表（`peer-net` 的内置槽唯一，
/// 多条目取末次——当前两端的语义都是「一个内置下载目录」）
pub(crate) fn decorate_shared_store(
    store: SharedDirStore,
    seam: Option<&Arc<dyn PeerPlatformSeam>>,
) -> SharedDirStore {
    let mut store = store;
    if let Some(seam) = seam {
        for (name, dir) in seam.builtin_shared_dirs() {
            store = store.with_builtin_download_dir(name, dir);
        }
    }
    store
}
