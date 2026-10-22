//! Plugin Host
//!
//! 插件宿主 — 生命周期管理（加载/激活/停用）
//! 协调 loader、permission、registry、storage、wasm_runtime 五个子系统
//! 支持静态注册（Rust 插件 via inventory）、文件扫描（TS-only 插件）和 WASM 模块（Rust+TS 插件）

use crate::config::CallModel;
use crate::db::Database;
use crate::host_api::context::CapabilityTarget;
use crate::manager::loader::PluginLoader;
use crate::manager::registry::PluginRegistry;
use crate::manager::runtime::{InstanceMeta, LoadedWasmPlugin, WasmHostContext, WasmRuntime};
use crate::manager::types::{HostPluginInfo, LoadedPlugin, PluginSource};
use crate::manifest::{PluginKind, PluginState};
use crate::permission::PermissionManager;
use crate::storage::PluginStorage;
use crate::system::constants::{
    LIFECYCLE_SHUTDOWN, LIFECYCLE_STARTUP, PLUGIN_CALLBACK_TIMEOUT_SECS, PLUGIN_MANIFEST_FILE,
};
use chrono::Utc;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::Emitter;
use tokio::sync::{Mutex, RwLock};

use self::owner::{
    dispatch_mutex_op, spawn_owner, GuestCallFailure, OwnerFailureSink, OwnerHandle,
    OwnerStatsSnapshot, ShutdownReport,
};
// 属主任务调用面 re-export（票 05b）：lib 集成测试（system_component_test 的
// 能力转发断言）需要 GuestOp / GuestReply——`owner` 模块保持 pub(crate)（其
// 内部句柄/属主任务实现不外露），调用面经 host.rs 顶层公开。
pub use owner::{GuestOp, GuestReply};

/// WASM 插件 trap 自动重载最小间隔（秒）
///
/// wasmtime 同步引擎下任何一次 trap 都会污染整个 Store（`set_trapped`），
/// 之后该实例所有调用持续报 `CannotEnterComponent`，唯一恢复途径是整体重载。
/// 自动重载用最小间隔限频，防「重载后立刻再 trap」时无限重载风暴
/// （持久性 bug 时最多每间隔重试一次，期间插件保持 Error 态）。
const PLUGIN_AUTO_RELOAD_MIN_INTERVAL_SECS: u64 = 30;

/// 插件运行时异常前端提示最小间隔（秒）
///
/// 统一异常通道（`PLUGIN_RUNTIME_ERROR`）按插件合并提示：重载循环等
/// 连发异常场景下只弹一次 toast，日志始终记录全量错误。
const PLUGIN_RUNTIME_ERROR_NOTIFY_INTERVAL_SECS: u64 = 15;

// ==================== 装配条目（票 06 §5.1） ====================

/// 能力转发超时（票 03 §5.4 ③）
///
/// 能力转发 / 互调是「guest 栈内嵌套调另一实例」：目标实例若是环依赖的一端，
/// 嵌套等待**今天就会死锁**（双方各自占住自己的实例）。P1 给转发加超时兜底，
/// 把「永久死锁」降级为「有界失败」（根治 = 按需 async 化，P4 候选 ⑤）。
pub(crate) const CAPABILITY_FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// 装配条目：宿主侧持有插件实例的**唯一入口**（I1）
///
/// - `meta`：实例元数据（宿主侧只读投影；`event-loop` 模型下宿主不允许
///   「锁实例读元数据」——那就是第二个 Store 入口）
/// - `slot`：调用模型（`mutex` 现状 / `event-loop` 新）；两模型出口同构
///   （[`GuestReply`] / [`GuestCallFailure`]），调用方不需要知道模型
pub struct WasmInstanceEntry {
    meta: InstanceMeta,
    call_model: CallModel,
    slot: InstanceSlot,
}

/// 实例调用槽（唯一存放 Store 的地方）
pub(crate) enum InstanceSlot {
    /// 现状：每实例一把互斥锁（`Arc` 便于调用方在锁外共享句柄）
    Mutex(Arc<Mutex<LoadedWasmPlugin>>),
    /// 新：事件循环属主任务句柄（唯一持 `&mut Store`）
    Owner(OwnerHandle),
}

impl WasmInstanceEntry {
    /// 按调用模型装配（实例化期唯一入口：启动扫描 / zip 安装 / 重建共用）
    ///
    /// `event-loop` 分支把整个 `LoadedWasmPlugin`（Store + Instance）移进属主任务：
    /// 宿主侧此后只剩 [`InstanceMeta`] 副本与属主句柄（I1 by construction）。
    pub(crate) fn new(
        plugin: LoadedWasmPlugin,
        call_model: CallModel,
        sink: Arc<dyn OwnerFailureSink>,
    ) -> Self {
        let meta = plugin.meta().clone();
        let slot = match call_model {
            CallModel::Mutex => InstanceSlot::Mutex(Arc::new(Mutex::new(plugin))),
            CallModel::EventLoop => InstanceSlot::Owner(spawn_owner(plugin, sink)),
        };
        Self {
            meta,
            call_model,
            slot,
        }
    }

    /// 实例元数据（宿主侧只读投影，不进实例）
    pub(crate) fn meta(&self) -> &InstanceMeta {
        &self.meta
    }

    /// 调用模型（诊断 / 分派用）
    pub(crate) fn call_model(&self) -> CallModel {
        self.call_model
    }

    /// 属主是否已停（仅 `event-loop` 模型可能为 true；`mutex` 模型恒 false）
    ///
    /// 语义 = 「该实例的 Store 已不可用」：停用后重新激活必须先重建实例。
    pub(crate) fn owner_stopped(&self) -> bool {
        match &self.slot {
            InstanceSlot::Mutex(_) => false,
            InstanceSlot::Owner(owner) => !owner.is_alive(),
        }
    }

    /// 调用一次 guest 导出（**不含**宿主级失败恢复——那是 `PluginHost` 门面的职责）
    pub async fn call_guest(
        &self,
        op: GuestOp,
    ) -> std::result::Result<GuestReply, GuestCallFailure> {
        match &self.slot {
            InstanceSlot::Mutex(instance) => {
                call_mutex_blocking(self.meta.plugin_id.clone(), instance.clone(), op).await
            }
            // 属主模型：投递 + oneshot；实例级失败（trap/panic）由属主经
            // `OwnerFailureSink` 收敛，本处只透传单次调用结果
            InstanceSlot::Owner(owner) => owner.call(op).await.map_err(GuestCallFailure::new),
        }
    }

    /// 带超时兜底的 op 调用（能力转发专用；超时 = 有界失败，见
    /// [`CAPABILITY_FORWARD_TIMEOUT`]）
    fn call_op_with_timeout(&self, op: GuestOp) -> std::result::Result<GuestReply, String> {
        let entry = self;
        crate::runtime_util::block_on_async(async move {
            match tokio::time::timeout(CAPABILITY_FORWARD_TIMEOUT, entry.call_guest(op)).await {
                Ok(Ok(reply)) => Ok(reply),
                Ok(Err(failure)) => Err(failure.error.to_string()),
                Err(_elapsed) => Err(format!(
                    "capability forward timed out after {}ms (nested call did not finish; \
                     check for a circular capability dependency)",
                    CAPABILITY_FORWARD_TIMEOUT.as_millis()
                )),
            }
        })
    }

    /// 停止属主（`mutex` 模型 no-op 返回 `None`）：返回即 store 已不可达
    ///
    /// I3③/I6：停用、卸载、重建、进程退出前调用；此后做资源回收不会与在飞
    /// guest task 竞争。
    pub(crate) async fn shutdown(&self) -> Option<ShutdownReport> {
        match &self.slot {
            InstanceSlot::Mutex(_) => None,
            InstanceSlot::Owner(owner) => Some(owner.stop().await),
        }
    }

    /// 属主计数快照（诊断 / 测试；`mutex` 模型返回 `None`）
    pub(crate) fn owner_stats(&self) -> Option<OwnerStatsSnapshot> {
        match &self.slot {
            InstanceSlot::Mutex(_) => None,
            InstanceSlot::Owner(owner) => Some(owner.stats()),
        }
    }
}

/// 能力转发窄端口实现（host_api 只消费 trait，不接触装配类型）
///
/// `mutex` / `event-loop` 两模型同构：转发方不需要知道调用模型——差异全在
/// [`WasmInstanceEntry::call_guest`] 内部。
impl CapabilityTarget for WasmInstanceEntry {
    fn storage_get(
        &self,
        key: &str,
    ) -> std::result::Result<std::result::Result<Option<String>, String>, String> {
        match self.call_op_with_timeout(GuestOp::CapStorageGet {
            key: key.to_string(),
        }) {
            Ok(GuestReply::GuestOptional(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }

    fn storage_set(
        &self,
        key: &str,
        value: &str,
    ) -> std::result::Result<std::result::Result<(), String>, String> {
        match self.call_op_with_timeout(GuestOp::CapStorageSet {
            key: key.to_string(),
            value: value.to_string(),
        }) {
            Ok(GuestReply::GuestUnit(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }

    fn storage_delete(
        &self,
        key: &str,
    ) -> std::result::Result<std::result::Result<(), String>, String> {
        match self.call_op_with_timeout(GuestOp::CapStorageDelete {
            key: key.to_string(),
        }) {
            Ok(GuestReply::GuestUnit(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }

    fn mdns_browse(
        &self,
        service_type: &str,
    ) -> std::result::Result<std::result::Result<String, String>, String> {
        match self.call_op_with_timeout(GuestOp::CapMdnsBrowse {
            service_type: service_type.to_string(),
        }) {
            Ok(GuestReply::GuestStr(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }

    fn mdns_stop_browse(
        &self,
        browser_id: &str,
    ) -> std::result::Result<std::result::Result<bool, String>, String> {
        match self.call_op_with_timeout(GuestOp::CapMdnsStopBrowse {
            browser_id: browser_id.to_string(),
        }) {
            Ok(GuestReply::GuestBool(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }

    fn mdns_advertise(
        &self,
        config_json: &str,
    ) -> std::result::Result<std::result::Result<String, String>, String> {
        match self.call_op_with_timeout(GuestOp::CapMdnsAdvertise {
            config_json: config_json.to_string(),
        }) {
            Ok(GuestReply::GuestStr(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }

    fn mdns_stop_advertise(
        &self,
        advertise_id: &str,
    ) -> std::result::Result<std::result::Result<bool, String>, String> {
        match self.call_op_with_timeout(GuestOp::CapMdnsStopAdvertise {
            advertise_id: advertise_id.to_string(),
        }) {
            Ok(GuestReply::GuestBool(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }

    fn mdns_is_advertising(
        &self,
        advertise_id: &str,
    ) -> std::result::Result<std::result::Result<bool, String>, String> {
        match self.call_op_with_timeout(GuestOp::CapMdnsIsAdvertising {
            advertise_id: advertise_id.to_string(),
        }) {
            Ok(GuestReply::GuestBool(inner)) => Ok(inner),
            Ok(other) => Err(format!(
                "capability provider returned unexpected reply: {:?}",
                other
            )),
            Err(e) => Err(e),
        }
    }
}

/// `mutex` 模型的一次 guest 调用（原 `PluginHost` 的 mutex 调用面搬移，
/// 语义逐字不变）
///
/// WASI 预打开模式下，wasi 同步绑定（`in_tokio`）要求调用线程没有进入任何
/// tokio runtime——否则其内部 `handle.block_on` 会 panic（"Cannot start a
/// runtime from within a runtime"）。故 guest 调用统一搬到 `spawn_blocking`
/// 阻塞线程执行：该线程走 ambient runtime，宿主函数经
/// [`crate::runtime_util::block_on_async`] 的 ambient 兜底同样可阻塞执行。
async fn call_mutex_blocking(
    plugin_id: String,
    instance: Arc<Mutex<LoadedWasmPlugin>>,
    op: GuestOp,
) -> std::result::Result<GuestReply, GuestCallFailure> {
    let joined = tokio::task::spawn_blocking(move || {
        // 阻塞线程无 tokio handle：符合 wasi 同步绑定（in_tokio）要求；锁在
        // catch_unwind 后由 drop 释放（panic 不跨线程传播）
        let mut guard = crate::runtime_util::block_on_ambient(instance.lock());
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch_mutex_op(&mut guard, op)
        }))
    })
    .await;

    match joined {
        Ok(Ok(Ok(reply))) => Ok(reply),
        Ok(Ok(Err(app_error))) => Err(GuestCallFailure::new(app_error)),
        // dispatch 内 panic（catch_unwind 捕获的载荷）：与改造前同路径
        Ok(Err(payload)) => Err(GuestCallFailure::panicked(
            &plugin_id,
            crate::manager::runtime::panic_payload_to_string(&payload),
        )),
        // spawn_blocking 任务自身 panic（catch_unwind 未覆盖的极端路径）：
        // 与 mutex 模型既有路径同收敛（join 错误文本作为 panic 载荷）
        Err(join) => {
            let payload: Box<dyn std::any::Any + Send> = Box::new(join.to_string());
            Err(GuestCallFailure::panicked(
                &plugin_id,
                crate::manager::runtime::panic_payload_to_string(&payload),
            ))
        }
    }
}

/// 属主实例级失败回报端口（`event-loop` 模型，票 06 §5.5）
///
/// 持 `Weak<PluginHost>`（装配完成后经 [`HostOwnerFailureSink::bind`] 注入）：
/// 避免「PluginHost 持 `Arc<dyn OwnerFailureSink>`」构成自引用强环（宿主永不释放）。
/// 宿主已析构（进程退出路径）时只记日志——此时没有可通知的前端与可重载的宿主。
pub(crate) struct HostOwnerFailureSink {
    host: OnceLock<std::sync::Weak<PluginHost>>,
}

impl HostOwnerFailureSink {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            host: OnceLock::new(),
        })
    }

    /// 宿主装配完成后注入弱引用（`PluginHost::new` 中，先于任何实例化）
    fn bind(&self, host: &Arc<PluginHost>) {
        if self.host.set(Arc::downgrade(host)).is_err() {
            tracing::warn!(
                "[PluginHost] owner failure sink bound twice; keeping the first binding"
            );
        }
    }
}

impl OwnerFailureSink for HostOwnerFailureSink {
    fn on_owner_failed<'a>(
        &'a self,
        plugin_id: &'a str,
        kind: &'static str,
        detail: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(host) = self.host.get().and_then(|weak| weak.upgrade()) else {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    kind = %kind,
                    "plugin instance owner failed after host teardown; recovery skipped"
                );
                return;
            };
            // 与 mutex 模型同口径：统一异常通道通知前端（节流合并）+ 限频调度重载
            host.notify_plugin_runtime_error(plugin_id, kind, detail)
                .await;
            host.schedule_plugin_reload_after_trap(plugin_id);
        })
    }
}

/// 插件宿主
pub struct PluginHost {
    /// 已加载的插件
    plugins: Arc<RwLock<HashMap<String, LoadedPlugin>>>,
    /// 扩展点注册表
    registry: Arc<PluginRegistry>,
    /// 权限管理器
    permission: Arc<PermissionManager>,
    /// 插件存储
    storage: Arc<PluginStorage>,
    /// Rust 插件的 command handlers（运行时注册，inventory 静态注册插件使用）
    rust_command_handlers: Arc<RwLock<HashMap<String, wasmnest_plugin_api::PluginCommand>>>,
    /// Rust 插件的 terminal handlers（运行时注册，inventory 静态注册插件使用）
    rust_terminal_handlers: Arc<RwLock<Vec<Box<dyn wasmnest_plugin_api::TerminalHandler>>>>,
    /// WASM 运行时（全局共享）
    wasm_runtime: Arc<WasmRuntime>,
    /// WASM 插件实例装配表（plugin_id → 装配条目）
    ///
    /// 条目是宿主侧持有实例的**唯一入口**（I1）：`mutex` 模型条目内是实例锁，
    /// `event-loop` 模型条目内是属主任务句柄——两种形态都只能经
    /// [`PluginHost::call_guest`] 门面触达。map 锁只保护索引结构本身，取到
    /// 条目 Arc 后立即释放，插件间互不阻塞
    wasm_plugins: Arc<RwLock<HashMap<String, Arc<WasmInstanceEntry>>>>,
    /// 属主实例级失败回报端口（`event-loop` 模型；见 [`HostOwnerFailureSink`]）
    owner_sink: Arc<HostOwnerFailureSink>,
    /// 因属主先停而跳过的 guest 清理（`on_shutdown` / `deactivate`）计数
    ///
    /// I3③ 的 fail-visible 观测量：`event-loop` 实例停用即丢 store（不赌挂起
    /// task 放行），guest 清理无法执行——必须可见，不得静默跳过
    owner_cleanup_skipped: Arc<AtomicU64>,
    /// 宿主上下文工厂（供 WASM 插件激活时使用）
    wasm_host_ctx: Arc<WasmHostContext>,
    /// 消息总线
    message_bus: Arc<crate::bus::MessageBus>,
    /// 插件定时器（plugin_id → tokio 任务句柄，v6 ADR 0003）
    ///
    /// 重复注册替换旧句柄；插件停用/应用关闭时中止。
    /// 用 std Mutex：仅短时间的 map 操作，不跨 await 持锁
    plugin_timers: Arc<std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    /// WASM 插件 trap 自动重载限频表（plugin_id → 最近一次自动重载时刻）
    ///
    /// std Mutex：仅短时 map 操作，不跨 await 持锁
    wasm_reload_throttle: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    /// 插件运行时异常前端提示限频表（plugin_id → 最近一次 toast 时刻）
    ///
    /// 见 [`PLUGIN_RUNTIME_ERROR_NOTIFY_INTERVAL_SECS`]；std Mutex：短时 map 操作
    runtime_error_notify_throttle: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    /// 应用关闭标志：deactivate_all（应用退出）置位
    ///
    /// 插件 deactivate 内的卸载动作（如 CLI 安装清理）据此跳过：
    /// 应用正常退出 ≠ 用户停用插件，随包 CLI 应保留（下次启动 activate 幂等重装）
    shutting_down: Arc<std::sync::atomic::AtomicBool>,
    /// 用户插件目录（zip 安装目标，dev 合入）：卸载与 zip 安装均以此目录为落点
    user_plugins_dir: PathBuf,
    /// 前端插件通道身份（审计票 06 / P0-5）：loader 会话密钥 + 插件令牌 →
    /// 身份解析，堵住「前端 `plugin_*` 命令自报 plugin_id」这条通道
    frontend_channel: Arc<crate::security::frontend_channel::FrontendChannelRegistry>,
}

impl PluginHost {
    /// 创建 PluginHost 并加载所有插件（静态注册 + 文件扫描 + WASM）
    ///
    /// # Arguments
    /// * `db` - 主库连接
    /// * `plugins_dir` - 随包内置插件目录
    /// * `user_plugins_dir` - 用户安装插件目录（zip 安装目标，可卸载）
    /// * `app_handle` - Tauri AppHandle（无头/测试传 None，依赖前端事件的
    ///   宿主能力在调用处降级）
    /// * `peer_ctx_provider` - 对等网络上下文装配端口（无头/测试传 None）
    /// * `first_party_dirs` - 第一方免弹窗归属清单（宿主装配时注入）
    /// * `abi` - 组件形态规格（[`crate::manager::runtime::AbiPolicy`]，端事实：
    ///   桌面 `wasmnest_plugin_api::form::FORM_COMPONENT`；宿主装配时显式注入，
    ///   wasm-core 零端 ABI 知识。**只管 `abi-form`**，整数 ABI 版本协商已随
    ///   wit 包版本化退役——ADR 0051 D2）
    /// * `host_facts` - 宿主端事实（平台标识 / 入站服务器端口；
    ///   [`crate::host_api::ports::HostFactsPort`]）——端差异实现住各端宿主
    ///   （桌面 `plugin/host_facts.rs`），内核零端名；在实例化 / 激活**之前**
    ///   写入上下文，漏注入不 panic 但取值路径 fail-visible
    /// * `platform_picker` - 平台选择器端口（`host-platform.pick-*` 的实现；
    ///   [`crate::host_api::ports::PlatformPickerPort`]）——桌面传宿主实现
    ///   （`plugin/platform_picker.rs`，原生对话框），无头/测试传 `None`
    ///   （缺省 fail-visible）；与 `host_facts` 同处装配期写入（实例化 / 激活之前）
    /// 返回 `Arc<Self>`：宿主需要自身的弱引用注入属主失败回报端口
    /// （`event-loop` 模型的实例级失败收敛，见 [`HostOwnerFailureSink`]），
    /// 也便于调用方共享（原先由调用方各自 `Arc::new`）
    pub async fn new(
        db: Arc<std::sync::Mutex<Database>>,
        plugins_dir: &Path,
        // 用户插件目录（app_data_dir/plugins，zip 安装目标，可卸载；dev 合入）
        user_plugins_dir: &Path,
        // Option 化：无头/测试上下文无 AppHandle（与 WasmRuntime/WasmHostContext 同策略），
        // 依赖前端事件的宿主能力在调用处降级
        app_handle: Option<Arc<tauri::AppHandle>>,
        // 对等网络上下文装配端口（整核抽出 §3.3 唯一端口）：lib 实现
        // `peer_net_cmds::peer_ctx`，无头/测试传 None → HEADLESS_UNAVAILABLE 语义不变
        peer_ctx_provider: Option<Arc<crate::host_api::context::PeerCtxProvider>>,
        // 第一方免弹窗归属清单（票 08/P0-2：宿主装配时注入——产品数据出厂 lib，
        // 判定逻辑留 wasm-core；空表 = 无免弹窗项，无头/测试语义逐字不变）
        first_party_dirs: Vec<(&'static str, Vec<crate::security::fs_auth::TrustedDir>)>,
        // ABI 规格（端事实，宿主注入；见 [`crate::manager::runtime::AbiPolicy`]）
        abi: crate::manager::runtime::AbiPolicy,
        // 宿主端事实（平台标识 / 入站服务器端口；端实现住各端宿主，见
        // [`crate::host_api::ports::HostFactsPort`]——内核不得按端 `#[cfg]` 二选一）
        host_facts: Arc<dyn crate::host_api::ports::HostFactsPort>,
        // 平台选择器（同上：端差异实现住宿主；None = 未装配，插件调用点 fail-visible）
        platform_picker: Option<Arc<dyn crate::host_api::ports::PlatformPickerPort>>,
        // 应用作用域共享服务注册表（宿主机制；service-leases §4.3）：必须在
        // `new` 内**任何激活之前**写入——L1/L2 角色驱动组件在 `new` 内激活，
        // 激活期可能已注册端点并 acquire 传输面（例如 BedCode 的 activate 注册
        // HTTP 路由）。无头 / 测试传 None → 内核释放路径为 no-op。
        service_registry: Option<Arc<wasmnest_server_base::service::ServiceRegistry>>,
    ) -> Arc<Self> {
        tracing::info!(
            "[PluginHost] Initializing with plugins_dir: {:?}",
            plugins_dir
        );

        let permission = Arc::new(PermissionManager::new());
        let registry = Arc::new(PluginRegistry::new());
        let storage = Arc::new(PluginStorage::new(db.clone()));

        // 构建 WASM 运行时和宿主上下文（ABI 规格经 WasmRuntime::new 注入：wasm-core
        // 零端 ABI 知识，版本/形态要求是宿主事实；CoreConfig 仍按 app_handle 从
        // 配置文件加载——编译期默认 < 配置文件 < 运行时覆盖）
        let wasm_runtime = Arc::new(
            WasmRuntime::new(storage.clone(), app_handle.clone(), first_party_dirs, abi)
                .expect("Failed to initialize WASM runtime"),
        );

        // 创建消息总线（dispatcher 延迟注入，在 init_message_bus 中设置）
        let message_bus = Arc::new(crate::bus::MessageBus::new());

        let wasm_host_ctx = Arc::new(WasmHostContext::new(
            db.clone(),
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            storage.clone(),
            app_handle,
            permission.clone(),
            wasm_runtime.fs_auth().clone(),
            message_bus.clone(),
            Arc::new(crate::manager::capability::CapabilityRegistry::new()),
        ));
        // 运行监控出口（WIT `host-metrics`）：快照源 = 本运行时注册表。
        // 与 guest_events / host_facts 同款两阶段注入——实例化前写入，
        // 插件激活期即可调用（监控应用自身也走这条路径）。
        wasm_host_ctx.set_metrics_snapshot_source(wasm_runtime.monitor());

        // core-security × core-monitor：决策计数埋点两阶段注入
        // （monitor 生于 WasmRuntime，晚于宿主上下文构建）
        // 端事实在实例化 / 激活之前写入（file-transfer 等共享产物在激活期探测
        // `host-platform.platform()`；晚注入 = 激活失败）。选择器同批写入：
        // 插件激活期若调 `pick-*` 也必须拿到宿主实现（漏传 None 时保持
        // `UnimplementedPlatformPicker` fail-visible，不静默无选择器）
        wasm_host_ctx.set_host_facts(host_facts);
        if let Some(picker) = platform_picker {
            wasm_host_ctx.set_platform_picker(picker);
        }
        // 服务租约注册表：必须早于 `activate_role_driven_components`（L1/L2 在
        // `new` 内激活；激活期的端点注册会 acquire 传输面）
        wasm_host_ctx.set_service_registry(service_registry);
        wasm_host_ctx.security().set_monitor(wasm_runtime.monitor());
        // 授权记录容量丢弃计数（spec §8.2）：同一处两阶段注入（计数在落账点）
        wasm_runtime.fs_auth().set_monitor(wasm_runtime.monitor());
        // 网络侧同一机制（票 06：「始终允许」档下网络记录按 origin 累积）
        wasm_host_ctx.net_auth().set_monitor(wasm_runtime.monitor());
        // 对等网络上下文装配端口（整核抽出 §3.3）：与 monitor 同构的两阶段注入
        wasm_host_ctx.set_peer_ctx_provider(peer_ctx_provider);

        // 1. 收集静态注册的 Rust 插件
        let static_plugins: Vec<&'static wasmnest_plugin_api::WasmNestPluginEntry> =
            inventory::iter::<wasmnest_plugin_api::WasmNestPluginEntry>
                .into_iter()
                .collect();
        tracing::info!(
            "[PluginHost] Found {} static plugin(s) from inventory",
            static_plugins.len()
        );

        // 2. 扫描文件系统的 TS-only 和 WASM 插件：随包内置目录 + 用户插件目录
        // （zip 安装，可卸载），共用同一套加载与 WASM 实例化逻辑。**去重状态跨
        // 两次扫描共享**（内置先到先得）：同 id 的用户副本被拒绝，不得顶替内置
        // 条目——分开两次 load_all 各持一份 seen_ids，用户副本会静默覆盖内置记录，
        // 随包插件随即被降级为 UserInstalled 而卡在审批门禁（拒绝激活）
        let (file_plugins, user_plugins) =
            PluginLoader::load_builtin_and_user(plugins_dir, user_plugins_dir, &permission);
        tracing::info!(
            "[PluginHost] Found {} file-based plugin(s)",
            file_plugins.len()
        );
        tracing::info!(
            "[PluginHost] Found {} user-installed plugin(s)",
            user_plugins.len()
        );

        // 3. 合并所有插件
        let mut all_plugins: HashMap<String, LoadedPlugin> = HashMap::new();

        // 添加静态注册的 Rust 插件
        for entry in static_plugins {
            // 静态注册的 Rust 插件经 inventory 登记 SDK manifest（绑定面词汇）；
            // 进机制前 JSON 往返转中性形态（票 02 M4，from_sdk_json）
            let sdk_manifest = (entry.create_manifest)();
            let plugin_id = sdk_manifest.id.clone();

            // 授权结果只落在 PermissionManager（唯一真源）；LoadedPlugin 不再镜像
            // 一份 granted 列表（票 11 第 4 项：镜像字段只写不读）
            permission.grant_permissions(&plugin_id, &sdk_manifest.permissions);
            let manifest: crate::manifest::PluginManifest =
                crate::manifest::from_sdk_json(&sdk_manifest);

            // 内置常驻语义：随二进制分发、无独立启停，注册即激活。
            // 直接置 Activated 使 notify_startup 的 on_startup 回调与
            // invoke_rust_command 的身份门禁对其真实生效（此前停在 Loaded 态、
            // 永不激活，与 "Static plugin loaded" 日志自相矛盾）
            let loaded = LoadedPlugin {
                manifest,
                state: PluginState::Activated,
                extension_path: String::new(),
                activated_at: Some(Utc::now()),
                source: PluginSource::StaticRegistry,
            };

            tracing::info!(
                "Static plugin activated (builtin): {} v{}",
                loaded.manifest.id,
                loaded.manifest.version
            );
            all_plugins.insert(plugin_id, loaded);
        }

        // 添加文件扫描的插件（包含 TS-only 和 WASM 来源判定）：**记录**先入表；
        // WASM 实例化推迟到 `Arc<Self>` 构造之后——`event-loop` 模型的属主任务
        // 需要失败回报端口（`Weak<PluginHost>`），宿主必须先存在
        for (id, loaded) in file_plugins.into_iter().chain(user_plugins) {
            all_plugins.insert(id, loaded);
        }

        let host = Arc::new(Self {
            plugins: Arc::new(RwLock::new(all_plugins)),
            registry,
            permission,
            storage,
            rust_command_handlers: Arc::new(RwLock::new(HashMap::new())),
            rust_terminal_handlers: Arc::new(RwLock::new(Vec::new())),
            wasm_runtime,
            wasm_plugins: Arc::new(RwLock::new(HashMap::new())),
            owner_sink: HostOwnerFailureSink::new(),
            owner_cleanup_skipped: Arc::new(AtomicU64::new(0)),
            wasm_host_ctx,
            message_bus,
            plugin_timers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            wasm_reload_throttle: Arc::new(std::sync::Mutex::new(HashMap::new())),
            runtime_error_notify_throttle: Arc::new(std::sync::Mutex::new(HashMap::new())),
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            user_plugins_dir: user_plugins_dir.to_path_buf(),
            frontend_channel: Arc::new(
                crate::security::frontend_channel::FrontendChannelRegistry::new(),
            ),
        });

        // 属主失败回报端口绑定：必须早于任何实例化（属主任务在 trap 时回用它）
        host.owner_sink.bind(&host);

        // WASM 实例化收为一条路径（票 11 第 2 项）：声明了 `rust_library` 的插件
        // 按同一函数实例化，未声明的纯前端插件走它的空分支（无实例、原记录入表）；
        // 文件缺失 / 加载失败 → Error 态入表（manifest 仍注册，列表可见可诊断）
        host.instantiate_scanned_wasm_plugins().await;

        // 两阶段初始化：将 PluginHost（作为 PluginServices 实现）注入 WasmHostContext
        // 必须在 auto_activate 之前完成，否则 host_session_lifecycle_register 无法获取宿主服务
        host.wasm_host_ctx().set_services(host.clone()).await;

        // 两阶段注入：host-task 执行引擎（core-task）+ 单元执行器注册表（C3/C4）
        // host_api/task.rs 经 TaskEngine 接口调用 core-task；execute_unit 经 UnitExecutor
        // 注册表分发——manager::task 不再直调 host_api 域函数，host_api 不再依赖 manager
        host.wasm_host_ctx()
            .set_task_engine(Arc::new(crate::manager::task::CoreTaskEngine::new(
                host.wasm_host_ctx().clone(),
            )))
            .await;
        // 能力域端口装配（wasm-core-lib-split 票 03/04/05/06）：mDNS / WS / peer-net /
        // HTTP 四域的实现已迁进 `packages/` 能力 crate，其 `impl Host for WasmPluginState`
        // 经进程级端口反取宿主实现。**必须早于任何插件激活**——guest 一调该域原语就取
        // 端口，取不到直接 panic（fail-visible，不静默空转）。单一入口见
        // `host_api::install_capability_domain_ports`（两个测试夹具共用同一条链，
        // 免得再出现「只在生产装了」的漏装）。
        crate::host_api::install_capability_domain_ports(host.wasm_host_ctx());
        // 任务单元执行器（票 02 批次 05）：域实现 `submit_unit_executor!` 自报
        // （fs / http 在内核域文件，process 随 host-process 域住宿主
        // `src/plugin/process.rs`），装配点遍历注册——本处不点名任何执行器，
        // 宿主侧执行器迁入后零改动。幂等去重按具体类型（与测试装配共用注册表）。
        for entry in crate::host_api::unit_executor::collected_unit_executors() {
            crate::manager::task::register_unit_executor((entry.make)());
        }

        // 注册所有已加载插件的 manifest contributes 到 registry
        host.register_manifest_contributions().await;

        // 注册 Rust 插件的 command handlers（inventory 静态注册）
        host.register_rust_command_handlers().await;

        // 注册 Rust 插件的 terminal handlers（inventory 静态注册）
        host.register_rust_terminal_handlers().await;

        // 4. 角色驱动层优先激活（core-plugin-manager · ADR 0032）：L1 基础服务
        // → L2 内部统一业务应用，均由 manifest `type` 驱动、先于 L3 业务应用——
        // L1 的能力注册表装配必须先于消费方的依赖检查，L2 的裁决面须先于业务面就绪
        host.activate_role_driven_components().await;

        // 5. 根据持久化状态自动激活之前已激活的插件
        tracing::info!("[PluginHost] Starting auto-activation from persisted state...");
        host.auto_activate_from_persisted_state().await;

        let count = host.plugins.read().await.len();
        let wasm_count = host.wasm_plugins.read().await.len();
        // 汇总日志按真实状态分计数：degraded/error 不再隐没在 activated 里
        let mut activated_count = 0usize;
        let mut degraded_count = 0usize;
        let mut error_count = 0usize;
        for p in host.plugins.read().await.values() {
            match &p.state {
                PluginState::Activated => activated_count += 1,
                PluginState::Degraded { .. } => degraded_count += 1,
                PluginState::Error { .. } => error_count += 1,
                _ => {}
            }
        }
        tracing::info!(
            "[PluginHost] Initialization complete: {} plugin(s) total, {} wasm, {} activated, {} degraded, {} error",
            count,
            wasm_count,
            activated_count,
            degraded_count,
            error_count
        );
        host
    }

    /// 将所有已加载插件的 manifest contributes 注册到 registry

    /// 注册 Rust 插件的 command handlers 到运行时注册表（inventory 静态注册）

    /// 注册 Rust 插件的 terminal handlers 到运行时注册表（inventory 静态注册）

    // ==================== Accessors ====================

    /// 获取 WASM 宿主上下文引用
    pub fn wasm_host_ctx(&self) -> &Arc<WasmHostContext> {
        &self.wasm_host_ctx
    }

    // ==================== 统一 guest 调用门面（票 06 §5.4） ====================

    /// 取插件实例装配条目（宿主侧实例的唯一入口）
    pub async fn get_instance(&self, plugin_id: &str) -> Option<Arc<WasmInstanceEntry>> {
        self.wasm_plugins.read().await.get(plugin_id).cloned()
    }

    /// 统一 guest 调用门面：条目按调用模型分派，两模型出口同构
    ///
    /// - `mutex`：现状路径（实例锁 + 无 handle 阻塞线程）；失败时按
    ///   `OpKind::recovers_after_failure` 通知前端 + 限频调度重载（I5）
    /// - `event-loop`：投递属主队列 + oneshot 等待；实例级失败（trap / panic）
    ///   由属主任务经 [`OwnerFailureSink`] 收敛，本处只透传单次调用结果
    ///
    /// 实例缺失 → 立即显性 Err（不静默挂起）。
    pub(crate) async fn call_guest(
        &self,
        plugin_id: &str,
        op: GuestOp,
    ) -> std::result::Result<GuestReply, GuestCallFailure> {
        let Some(entry) = self.get_instance(plugin_id).await else {
            return Err(GuestCallFailure::new(crate::AppError::Plugin(format!(
                "WASM plugin {} not found in loaded instances",
                plugin_id
            ))));
        };
        let kind = op.kind();
        match entry.call_guest(op).await {
            Ok(reply) => Ok(reply),
            Err(failure) => {
                // `event-loop` 的实例级失败已由属主 sink 通知 + 调度重载，不重复；
                // `mutex` 模型在此补齐恢复动作（通知前端 + 调度重载）
                if entry.call_model() == CallModel::Mutex && kind.recovers_after_failure() {
                    let (kind_str, detail) = match &failure.panic_message {
                        Some(msg) => ("panic", msg.clone()),
                        None => ("trap", failure.error.to_string()),
                    };
                    self.notify_plugin_runtime_error(plugin_id, kind_str, &detail)
                        .await;
                    self.schedule_plugin_reload_after_trap(plugin_id);
                }
                Err(failure)
            }
        }
    }

    /// 同步门面（bus 投递 / process done / task event / 能力转发四处同步调用源）
    pub(crate) fn call_guest_blocking(
        &self,
        plugin_id: &str,
        op: GuestOp,
    ) -> std::result::Result<GuestReply, GuestCallFailure> {
        let host = self.clone();
        let plugin_id = plugin_id.to_string();
        crate::runtime_util::block_on_async(async move { host.call_guest(&plugin_id, op).await })
    }

    /// 停止某插件实例的属主（`event-loop` 模型；`mutex` / 不存在返回 `None`）
    ///
    /// 返回即该实例的 Store 已不可达（I3③ 的接线点：停用 / 卸载 / 重建 / 退出）。
    pub(crate) async fn stop_instance_owner(&self, plugin_id: &str) -> Option<ShutdownReport> {
        let entry = self.get_instance(plugin_id).await?;
        // 停机观测面：属主计数快照（启动/结算/放弃/队列满/在飞）落 debug 日志，
        // 排障时能看到「停用前还有多少在飞」而无需复现
        if let Some(stats) = entry.owner_stats() {
            tracing::debug!(
                plugin_id = %plugin_id,
                started = stats.started,
                settled = stats.settled,
                detached = stats.detached,
                queue_full = stats.queue_full,
                in_flight = stats.in_flight,
                traps = stats.traps,
                "plugin instance owner stats at stop"
            );
        }
        entry.shutdown().await
    }

    /// 停机兜底：停止全部残留属主（I6：进程退出前不留孤儿任务 / 持锁线程）
    pub(crate) async fn shutdown_all_owners(&self) {
        let entries: Vec<Arc<WasmInstanceEntry>> =
            self.wasm_plugins.read().await.values().cloned().collect();
        for entry in entries {
            if let Some(report) = entry.shutdown().await {
                if report.forced_abort || report.abandoned_requests > 0 {
                    tracing::warn!(
                        plugin_id = %entry.meta().plugin_id,
                        abandoned_requests = report.abandoned_requests,
                        forced_abort = report.forced_abort,
                        "plugin instance owner stopped during shutdown sweep"
                    );
                }
            }
        }
    }

    /// 因属主先停而跳过的 guest 清理次数（I3③ 的观测量）
    ///
    /// 当前消费者是两模型对照用例（生产侧无读点）。保留访问器而不删：它是
    /// 「停用即丢 store ⇒ guest 清理被跳过」这条语义差异唯一的可断言面
    /// （spec §8 A1 的 I3③ 证据）；写入点见 `deactivate_plugin_inner`。
    #[allow(dead_code)]
    pub(crate) fn owner_cleanup_skipped(&self) -> u64 {
        self.owner_cleanup_skipped.load(Ordering::Relaxed)
    }

    /// 调用认证中心插件的 `auth-policy.verify-device-token`（票 12 C3：宿主
    /// server 中间件取策略）
    ///
    /// 取代改造前的 `call_plugin_capability_export`（泛型直锁实例）：属主化后
    /// 实例只能经统一门面触达（I1）。前置校验：实例已加载且实例化时探测到该
    /// 能力导出；任一项缺失 → 外层 Err（调用方降级）。
    ///
    /// 外层 Err = 实例缺失 / 能力缺失 / 传输错误（trap 等）；内层 `Result` 含
    /// WIT `result<string, string>` 本体（guest 自报策略结果），两层语义分离。
    pub async fn call_auth_policy(
        &self,
        plugin_id: &str,
        token: String,
    ) -> crate::Result<std::result::Result<String, String>> {
        let Some(entry) = self.get_instance(plugin_id).await else {
            return Err(crate::AppError::Plugin(format!(
                "plugin '{}' not loaded (no wasm instance)",
                plugin_id
            )));
        };
        let capability = crate::manager::capability::CAP_AUTH_POLICY;
        if !entry
            .meta()
            .exported_capabilities
            .iter()
            .any(|c| c == capability)
        {
            return Err(crate::AppError::Plugin(format!(
                "plugin '{}' does not export capability '{}'",
                plugin_id, capability
            )));
        }
        match self
            .call_guest(plugin_id, GuestOp::CapAuthVerifyDeviceToken { token })
            .await
        {
            Ok(GuestReply::GuestStr(inner)) => Ok(inner),
            Ok(other) => Err(crate::AppError::Plugin(format!(
                "plugin '{}' auth-policy returned unexpected reply: {:?}",
                plugin_id, other
            ))),
            Err(failure) => Err(failure.error),
        }
    }

    /// 扫描导出 `auth-policy` 能力的激活插件（认证中心角色发现，HTTP 路由代码注册
    /// 下沉专项阶段 3，已删——v32 ADR 0031 起角色发现改查注册表，见
    /// `utils/auth/auth_center.rs::enforce_connection_policy`）。

    pub fn registry(&self) -> &Arc<PluginRegistry> {
        &self.registry
    }

    pub fn permission(&self) -> &Arc<PermissionManager> {
        &self.permission
    }

    pub fn storage(&self) -> &Arc<PluginStorage> {
        &self.storage
    }

    /// 已加载插件记录表（plugin_id → LoadedPlugin 记录）——测试装配便捷访问器
    ///
    /// pub（wasm-core 纯净性收口票 05b 迁移 system_component_test）：lib 集成
    /// 测试经此注入/改写 LoadedPlugin 记录（字段保持私有）；生产路径经
    /// `PluginHost::new` 的扫描装配写入同一张表。
    pub fn plugins(&self) -> &Arc<RwLock<HashMap<String, LoadedPlugin>>> {
        &self.plugins
    }

    /// WASM 实例装配表（plugin_id → 装配条目）——测试装配便捷访问器
    ///
    /// pub（票 05b）：lib 集成测试经此模拟实例消失（移除条目 = fail-closed
    /// 的 unavailable 分支）；字段保持私有。
    pub fn wasm_plugins(&self) -> &Arc<RwLock<HashMap<String, Arc<WasmInstanceEntry>>>> {
        &self.wasm_plugins
    }

    /// 前端插件通道身份注册表（loader 会话密钥 / 插件令牌）
    pub fn frontend_channel(
        &self,
    ) -> &Arc<crate::security::frontend_channel::FrontendChannelRegistry> {
        &self.frontend_channel
    }

    /// 重置**某个 webview** 的前端通道会话（该窗口新的一次页面加载）：其旧 loader 密钥
    /// 与全部插件令牌失效
    ///
    /// 由 Tauri `on_page_load` 钩子按发起加载的 webview label 调用（dev 下页面刷新需能重新
    /// 取得宿主面凭证）；也可在测试中显式调用以模拟某窗口前端重启。
    /// **只作用于该 label 的凭证域**——多窗口（主窗口 / 终端窗口）互不干扰：终端窗口加载
    /// 不再回收主窗口凭证（2026-09-26 修复，见 `security::frontend_channel` 模块注释）。
    pub fn reset_frontend_loader_session(&self, webview_label: &str, reason: &str) -> usize {
        let revoked = self.frontend_channel.reset(webview_label);
        tracing::info!(
            webview = %webview_label,
            reason = %reason,
            revoked_tokens = revoked,
            "[PluginChannel] 前端通道会话已重置"
        );
        revoked
    }

    /// 获取 WASM 运行时引用
    pub fn wasm_runtime(&self) -> &Arc<WasmRuntime> {
        &self.wasm_runtime
    }

    /// 获取消息总线引用
    pub fn message_bus(&self) -> &Arc<crate::bus::MessageBus> {
        &self.message_bus
    }

    /// 初始化消息总线 dispatcher（必须在 new() 之后调用）
    pub async fn init_message_bus(&self) {
        let dispatcher: Arc<dyn crate::bus::MessageDispatcher> = Arc::new(self.clone());
        self.message_bus.set_dispatcher(dispatcher).await;
        // v11：注入 core-monitor 注册表（订阅者队列满丢弃 / 格式不匹配拒绝计数）。
        // 必须在首次订阅（插件激活）之前完成——激活流程在 PluginHost::new 之后
        self.message_bus
            .set_monitor(self.wasm_runtime.monitor())
            .await;
        tracing::info!("[PluginHost] MessageBus dispatcher initialized");
    }

    // ==================== Lifecycle ====================

    /// 获取所有已加载插件的信息列表
    pub async fn list_plugins(&self) -> Vec<HostPluginInfo> {
        let plugins = self.plugins.read().await;
        let list: Vec<HostPluginInfo> = plugins.values().map(HostPluginInfo::from).collect();
        tracing::debug!(
            "[PluginHost] list_plugins() returning {} plugin(s)",
            list.len()
        );
        for info in &list {
            tracing::debug!(
                "[PluginHost]   - {} (state={:?}, type={:?})",
                info.id,
                info.state,
                info.plugin_type
            );
        }
        list
    }

    /// 获取单个插件信息
    pub async fn get_plugin(&self, plugin_id: &str) -> Option<HostPluginInfo> {
        let plugins = self.plugins.read().await;
        plugins.get(plugin_id).map(HostPluginInfo::from)
    }
}

// ==================== 子模块（自本文件拆分） ====================
// 职责面拆分（P2）：激活/停用、启动通知、注册、安装卸载、预授权、wasm 实例、错误上报
mod activation;
pub mod api_bridge;
mod app_cli;
mod boot;
mod commands;
mod errors;
mod install;
// 票 06 P1：插件实例属主任务（`event-loop` 调用模型）——装配条目
// （`WasmInstanceEntry`）在 `event-loop` 分支消费它
// （`pub(crate)`：属主测试在 `manager::runtime::tests::owner_e2e` 直接驱动句柄）
pub(crate) mod owner;
mod preauth;
mod register;
mod services;
mod wasm;
// 保持原导出路径（crate::manager::host::PluginLifecycleListener 等）
// 票 03：插件侧会话生命周期 / 输入行监听器实现（原 `listeners` 模块）已删除——
// 宿主不再派发这两类回调，注册面与派发点同批退役。
// preauth 域（P2 拆分后 re-export 保持 host:: 路径兼容）
pub use preauth::register_preauth_provider;
#[allow(unused_imports)] // 兼容 host:: 路径（测试经 super:: 引用；preauth.rs 内部自用）
pub(crate) use preauth::{
    collect_preauth_paths, preauth_providers, PreauthProvider, PREAUTH_PATHS_STORAGE_KEY,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{MessageBus, MessageDispatcher};
    use crate::manager::runtime::PluginServices;
    use crate::manifest::{PluginContributes, PluginManifest, PluginType};
    use crate::system::config::AppConfig;
    use serde_json::json;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use wasmnest_plugin_api::{PluginCommand, RustPluginContext, TerminalHandler};

    /// 测试用插件 ID（非 WASM 插件）
    const TEST_PLUGIN_ID: &str = "com.wasmnest.test";
    // 组件形态 WASM 夹具 id（`com.wasmnest.sdk-test`，原 TEST_WASM_PLUGIN_ID）随票 04
    // 夹具用例迁宿主一并删除——宿主 `src-tauri/tests/support/mod.rs` 自持同值常量。

    // 用例与脚手架按域拆分（票 11 第 7 项）：内联块只留 imports / 测试常量 / 子模块声明。
    // 模块树 `host::tests::<文件>` 与内联形态等价；各域文件经 `use super::*;` 拿到宿主项
    // 与测试常量，跨文件复用的脚手架另按需显式引入（顶层项已标 `pub(super)`）。
    mod approval_test;
    mod commands_test;
    mod contributions_test;
    mod host_api_test;
    mod instance_call_model_test;
    // l2_gating_test（L2 反向依赖红线锁）随票 08 批次三迁桌面宿主测试面
    // （`src-tauri/tests/l2_gating_lock.rs`）——它扫宿主源码，属平台侧判据。
    mod lifecycle_test;
    mod runtime_preauth_test;
    mod scaffold;
    mod scan_dedup_test;
    mod wasm_flow_test;
}
