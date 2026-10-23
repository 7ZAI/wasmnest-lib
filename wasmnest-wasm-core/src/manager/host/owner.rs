//! 插件实例属主任务（票 06：事件循环属主，P1）
//!
//! ## 为什么需要它
//!
//! 现状（`mutex` 模型）每个插件实例一把 `Arc<Mutex<LoadedWasmPlugin>>`，
//! 调用 = 「抢实例锁 + `spawn_blocking` + `block_on_async`」，锁全程持有到 guest
//! 返回 ⇒ **一次慢的 guest 调用会把该插件的全部交互一起堵死**（非流式
//! `host-http.fetch` 在 import 栈内等网络就是现实路径）。
//!
//! 本模块实现替代模型 `event-loop`：**每个实例一个常驻属主任务**，是唯一持有
//! `&mut Store` 的地方；调用方只把 [`GuestOp`] 投递进属主队列，属主用
//! `TypedFunc::start_call_concurrent` 启动 guest task（**不等待完成**），完成后再结算回
//! 请求方的 `oneshot`。
//!
//! ## 不变式（spec §3.2；每条都有测试或结构锁）
//!
//! - **I1** 同一实例至多一个属主：`LoadedWasmPlugin`（Store + Instance）整块移入属主
//!   任务，宿主侧不存在第二个 Store 入口（装配表只暴露 [`OwnerHandle`]）。
//! - **I2** 任何单次 guest 调用**不阻塞属主循环**：start 同步返回，慢调用挂起为 task。
//!   ⚠ 同实例后续调用会被 wasmtime 的实例级 `do_not_enter` 推迟（票 01 A2'：官方
//!   产物同样如此，推迟非死锁）⇒ 本模块只承诺「属主不占死、请求不丢、有界失败」，
//!   **不承诺「同实例并发执行」**。
//! - **I3** trap / panic = 整实例不可用（与 `mutex` 模型逐字等价：task trap 同样污染
//!   store）；发生时在等请求**逐条显式失败**（不排队、不静默重试），实例级收敛交给
//!   [`OwnerFailureSink`]（通知前端 + 限频调度重载）。
//! - **I4** 启动顺序 = 入队顺序：`select! { biased; }` + **单点 start**（只在收消息
//!   分支里 start），天然满足。
//! - **I6** 生命周期：属主任务随 [`OwnerHandle`] 结束；`stop()` 等属主退出
//!   （store 随任务结束 drop）后才返回。
//!
//! ## 已知边界（票 03 §8，不在 P1 解决）
//!
//! 嵌套等待（能力转发 / 互调：guest 栈内同步等另一实例）在 P1 仍占住**调用方属主**，
//! 与 `mutex` 模型逐字等价；P1 只加超时兜底（见 `manager/capability.rs`）。

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::FutureExt;
use tokio::sync::{mpsc, oneshot};
use wasmtime::component::{Accessor, ComponentNamedList, Instance, Lift, Lower};

use super::LoadedWasmPlugin;
use crate::manager::runtime::{OptionalExports, WasmPluginState};
use crate::monitor::{CallTimer, LifecycleEvent, PluginMetrics};
use crate::AppError;

// ==================== 导出名（ItemName 路径语法） ====================
//
// 组件的接口导出是嵌套实例形态，平名字符串（`iface#func`）无法被
// `Instance::get_typed_func` 命中（wasmtime 47 实证），必须用 `pkg:ns/iface.func` 路径。

/// 属主请求队列容量（入队满 = 显性错误，禁止无限缓冲与静默丢弃）
pub(crate) const OWNER_QUEUE_CAP: usize = 64;

/// 属主停止的默认宽限（等待属主退出；超时 abort 兜底）
pub(crate) const OWNER_STOP_GRACE: Duration = Duration::from_millis(500);

// ==================== 闭集 op / reply ====================

/// 宿主 → 属主的调用请求（**闭集**，不用泛型/闭包）
///
/// 闭集而非泛型的依据（票 03 §5.2）：`start_call_concurrent` 的 `Params/Return` 是
/// 编译期类型，泛型 erase 会退化成动态 `Val` 编解码（多一层手工 canonical ABI +
/// 丢掉类型检查）。现存调用面本就有限：世界导出 10 个 + 能力转发 4 个具体实例化。
/// **新增可路由能力时必须同步加 op**（`capability::routable_capabilities()` 对应关系；
/// 导出名的词汇真源在能力域自报侧，本文件的 `const EXPORT_*` 是编译期具名的调用面对偶，
/// 值相等由 `capability` 模块的单测钉住）。
#[derive(Debug)]
pub enum GuestOp {
    /// `command.invoke(name, args-json) -> string`（前端命令面 / HTTP `_http_endpoint` / 定时器 tick）
    InvokeCommand { name: String, args_json: String },
    /// `lifecycle.activate() -> result<_, string>`
    Activate,
    /// `lifecycle.deactivate() -> result<_, string>`
    Deactivate,
    /// `lifecycle.on-startup() -> result<_, string>`
    OnStartup,
    /// `lifecycle.on-shutdown() -> result<_, string>`
    OnShutdown,
    /// `events.on-message(topic, sender, payload-json) -> result<_, string>`
    OnMessage {
        topic: String,
        sender: String,
        payload_json: String,
    },
    /// `events-binary.on-message-binary(topic, sender, payload)`（可选导出）
    OnMessageBinary {
        topic: String,
        sender: String,
        payload: Vec<u8>,
    },
    /// `events.on-process-done(payload-json) -> result<_, string>`
    OnProcessDone { payload_json: String },
    /// `events-ws.on-message(handle, kind, payload)`（可选导出）
    WsClientMessage {
        handle: String,
        kind: String,
        payload: Vec<u8>,
    },
    /// `events-ws.on-client-message(endpoint-id, client-id, kind, payload)`（可选导出）
    WsEndpointMessage {
        endpoint_id: String,
        client_id: String,
        kind: String,
        payload: Vec<u8>,
    },
    /// `events-task.on-task-event(event-json)`（可选导出）
    OnTaskEvent { event_json: String },
    /// `host-storage.get(key) -> result<option<string>, string>`（能力转发）
    CapStorageGet { key: String },
    /// `host-storage.set(key, value) -> result<_, string>`（能力转发）
    CapStorageSet { key: String, value: String },
    /// `host-storage.delete(key) -> result<_, string>`（能力转发）
    CapStorageDelete { key: String },
    /// `host-mdns.browse(service-type) -> result<string, string>`（能力转发）
    CapMdnsBrowse { service_type: String },
    /// `host-mdns.stop-browse(browser-id) -> result<bool, string>`（能力转发）
    CapMdnsStopBrowse { browser_id: String },
    /// `host-mdns.advertise(config-json) -> result<string, string>`（能力转发）
    CapMdnsAdvertise { config_json: String },
    /// `host-mdns.stop-advertise(advertise-id) -> result<bool, string>`（能力转发）
    CapMdnsStopAdvertise { advertise_id: String },
    /// `host-mdns.is-advertising(advertise-id) -> result<bool, string>`（能力转发）
    CapMdnsIsAdvertising { advertise_id: String },
    /// `auth-policy.verify-device-token(token) -> result<string, string>`（宿主中间件直调）
    CapAuthVerifyDeviceToken { token: String },
}

impl GuestOp {
    /// op 种类（Copy；结算/日志用，避免在检查点重复 match 全字段）
    pub(crate) fn kind(&self) -> OpKind {
        match self {
            Self::InvokeCommand { .. } => OpKind::InvokeCommand,
            Self::Activate => OpKind::Activate,
            Self::Deactivate => OpKind::Deactivate,
            Self::OnStartup => OpKind::OnStartup,
            Self::OnShutdown => OpKind::OnShutdown,
            Self::OnMessage { .. } => OpKind::OnMessage,
            Self::OnMessageBinary { .. } => OpKind::OnMessageBinary,
            Self::OnProcessDone { .. } => OpKind::OnProcessDone,
            Self::WsClientMessage { .. } => OpKind::WsClientMessage,
            Self::WsEndpointMessage { .. } => OpKind::WsEndpointMessage,
            Self::OnTaskEvent { .. } => OpKind::OnTaskEvent,
            Self::CapStorageGet { .. } => OpKind::CapStorageGet,
            Self::CapStorageSet { .. } => OpKind::CapStorageSet,
            Self::CapStorageDelete { .. } => OpKind::CapStorageDelete,
            Self::CapMdnsBrowse { .. } => OpKind::CapMdnsBrowse,
            Self::CapMdnsStopBrowse { .. } => OpKind::CapMdnsStopBrowse,
            Self::CapMdnsAdvertise { .. } => OpKind::CapMdnsAdvertise,
            Self::CapMdnsStopAdvertise { .. } => OpKind::CapMdnsStopAdvertise,
            Self::CapMdnsIsAdvertising { .. } => OpKind::CapMdnsIsAdvertising,
            Self::CapAuthVerifyDeviceToken { .. } => OpKind::CapAuthVerifyDeviceToken,
        }
    }
}

/// op 种类（Copy；日志/记账口径的唯一来源）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpKind {
    InvokeCommand,
    Activate,
    Deactivate,
    OnStartup,
    OnShutdown,
    OnMessage,
    OnMessageBinary,
    OnProcessDone,
    WsClientMessage,
    WsEndpointMessage,
    OnTaskEvent,
    CapStorageGet,
    CapStorageSet,
    CapStorageDelete,
    CapMdnsBrowse,
    CapMdnsStopBrowse,
    CapMdnsAdvertise,
    CapMdnsStopAdvertise,
    CapMdnsIsAdvertising,
    CapAuthVerifyDeviceToken,
}

impl OpKind {
    /// WIT 导出路径（副作用：`log_trap` 的 `export=` 字段）
    pub(crate) fn export(self) -> &'static str {
        match self {
            Self::InvokeCommand => crate::contract::export_item("command", "invoke"),
            Self::Activate => crate::contract::export_item("lifecycle", "activate"),
            Self::Deactivate => crate::contract::export_item("lifecycle", "deactivate"),
            Self::OnStartup => crate::contract::export_item("lifecycle", "on-startup"),
            Self::OnShutdown => crate::contract::export_item("lifecycle", "on-shutdown"),
            Self::OnMessage => crate::contract::export_item("events", "on-message"),
            Self::OnMessageBinary => {
                crate::contract::export_item("events-binary", "on-message-binary")
            }
            Self::OnProcessDone => crate::contract::export_item("events", "on-process-done"),
            Self::WsClientMessage => crate::contract::export_item("events-ws", "on-message"),
            Self::WsEndpointMessage => {
                crate::contract::export_item("events-ws", "on-client-message")
            }
            Self::OnTaskEvent => crate::contract::export_item("events-task", "on-task-event"),
            Self::CapStorageGet => crate::contract::export_item("host-storage", "get"),
            Self::CapStorageSet => crate::contract::export_item("host-storage", "set"),
            Self::CapStorageDelete => crate::contract::export_item("host-storage", "delete"),
            Self::CapMdnsBrowse => crate::contract::export_item("host-mdns", "browse"),
            Self::CapMdnsStopBrowse => crate::contract::export_item("host-mdns", "stop-browse"),
            Self::CapMdnsAdvertise => crate::contract::export_item("host-mdns", "advertise"),
            Self::CapMdnsStopAdvertise => {
                crate::contract::export_item("host-mdns", "stop-advertise")
            }
            Self::CapMdnsIsAdvertising => {
                crate::contract::export_item("host-mdns", "is-advertising")
            }
            Self::CapAuthVerifyDeviceToken => {
                crate::contract::export_item("auth-policy", "verify-device-token")
            }
        }
    }

    /// mutex 模型错误文案里的导出函数名（`WASM <name>() call failed` 逐字对齐）
    fn fn_name(self) -> &'static str {
        match self {
            Self::InvokeCommand => "invoke_command",
            Self::Activate => "activate",
            Self::Deactivate => "deactivate",
            Self::OnStartup => "on_startup",
            Self::OnShutdown => "on_shutdown",
            Self::OnMessage => "on_message",
            Self::OnMessageBinary => "on_message_binary",
            Self::OnProcessDone => "on_process_done",
            Self::WsClientMessage => "on_ws_message",
            Self::WsEndpointMessage => "on_ws_client_message",
            Self::OnTaskEvent => "on_task_event",
            // 能力导出走 `capability call failed: <export> (<e>)` 文案（见 trap_error）
            Self::CapStorageDelete
            | Self::CapMdnsBrowse
            | Self::CapMdnsStopBrowse
            | Self::CapMdnsAdvertise
            | Self::CapMdnsStopAdvertise
            | Self::CapMdnsIsAdvertising
            | Self::CapStorageGet
            | Self::CapStorageSet
            | Self::CapAuthVerifyDeviceToken => self.export(),
        }
    }

    /// 是否能力转发导出（trap 文案分支判据）
    pub(crate) fn is_capability(self) -> bool {
        matches!(
            self,
            Self::CapStorageGet
                | Self::CapStorageSet
                | Self::CapStorageDelete
                | Self::CapMdnsBrowse
                | Self::CapMdnsStopBrowse
                | Self::CapMdnsAdvertise
                | Self::CapMdnsStopAdvertise
                | Self::CapMdnsIsAdvertising
                | Self::CapAuthVerifyDeviceToken
        )
    }

    /// 传输层失败（trap / 启动期错误）→ `AppError` 文案（与 mutex 模型逐字等价）
    pub(crate) fn trap_error(self, detail: &str) -> AppError {
        if self.is_capability() {
            AppError::Plugin(format!(
                "capability call failed: {} ({})",
                self.export(),
                detail
            ))
        } else {
            AppError::Plugin(format!("WASM {}() call failed: {}", self.fn_name(), detail))
        }
    }

    /// 失败后是否需要宿主统一恢复（通知前端 + 限频调度重载）
    ///
    /// 覆盖面与 mutex 模型的宿主侧调用面一致：命令面与事件 / WS 投递
    /// （这些调用点都走宿主统一恢复）。生命周期导出与能力转发的失败各自由
    /// 调用方处理（`mark_error` / Degraded / 能力回落宿主原语），在此重复
    /// 通知与重载调度会改变既有语义（I5）
    pub(crate) fn recovers_after_failure(self) -> bool {
        matches!(
            self,
            Self::InvokeCommand
                | Self::OnMessage
                | Self::OnMessageBinary
                | Self::OnProcessDone
                | Self::WsClientMessage
                | Self::WsEndpointMessage
                | Self::OnTaskEvent
        )
    }
}

// ==================== mutex 模型的 op 分派（I5 by construction） ====================

/// 把 [`GuestOp`] 分派到 `LoadedWasmPlugin` 的既有导出方法（`mutex` 模型分支）
///
/// 逐条委派（不做任何重新包装）⇒ 返回值、错误串与宿主侧 mutex 模型
/// 调用面（`PluginHost::call_guest` 的 Mutex 分支经 `call_mutex_blocking`
/// 直达本函数）逐字等价。`event-loop` 模型的同一批 op 由 [`start_op`]
/// 以类型化 `start_call_concurrent` 启动，两个分支共用 [`GuestReply`] 与
/// [`GuestCallFailure`] 出口。
pub(crate) fn dispatch_mutex_op(
    plugin: &mut LoadedWasmPlugin,
    op: GuestOp,
) -> crate::Result<GuestReply> {
    use crate::bus::WsFrameDispatch;

    match op {
        GuestOp::InvokeCommand { name, args_json } => plugin
            .invoke_command(&name, &args_json)
            .map(GuestReply::Str),
        GuestOp::Activate => plugin.activate().map(GuestReply::Code),
        GuestOp::Deactivate => plugin.deactivate().map(GuestReply::Code),
        GuestOp::OnStartup => plugin.on_startup().map(GuestReply::Lifecycle),
        GuestOp::OnShutdown => plugin.on_shutdown().map(GuestReply::Lifecycle),
        GuestOp::OnMessage {
            topic,
            sender,
            payload_json,
        } => {
            // 既有 mutex 调用点直传 `serde_json::Value`（导出方法内部再序列化）；
            // op 闭集统一携带 JSON 文本，此处解析回 Value——值往返确定，等价
            let payload: serde_json::Value = serde_json::from_str(&payload_json).map_err(|e| {
                AppError::Plugin(format!("invalid bus message payload JSON: {}", e))
            })?;
            plugin
                .on_message(&topic, &sender, &payload)
                .map(|()| GuestReply::Unit)
        }
        GuestOp::OnMessageBinary {
            topic,
            sender,
            payload,
        } => plugin
            .on_message_binary(&topic, &sender, &payload)
            .map(|()| GuestReply::Unit),
        GuestOp::OnProcessDone { payload_json } => plugin
            .on_process_done(&payload_json)
            .map(|()| GuestReply::Unit),
        GuestOp::WsClientMessage {
            handle,
            kind,
            payload,
        } => plugin
            .on_ws_frame(&WsFrameDispatch::Client {
                handle,
                kind,
                payload,
            })
            .map(GuestReply::Bool),
        GuestOp::WsEndpointMessage {
            endpoint_id,
            client_id,
            kind,
            payload,
        } => plugin
            .on_ws_frame(&WsFrameDispatch::EndpointClient {
                endpoint_id,
                client_id,
                kind,
                payload,
            })
            .map(GuestReply::Bool),
        GuestOp::OnTaskEvent { event_json } => {
            plugin.on_task_event(&event_json).map(GuestReply::Bool)
        }
        GuestOp::CapStorageGet { key } => plugin
            .call_capability_export::<(String,), (Result<Option<String>, String>,)>(
                crate::contract::export_item("host-storage", "get"),
                (key,),
            )
            .map(|(r,)| GuestReply::GuestOptional(r)),
        GuestOp::CapStorageSet { key, value } => plugin
            .call_capability_export::<(String, String), (Result<(), String>,)>(
                crate::contract::export_item("host-storage", "set"),
                (key, value),
            )
            .map(|(r,)| GuestReply::GuestUnit(r)),
        GuestOp::CapStorageDelete { key } => plugin
            .call_capability_export::<(String,), (Result<(), String>,)>(
                crate::contract::export_item("host-storage", "delete"),
                (key,),
            )
            .map(|(r,)| GuestReply::GuestUnit(r)),
        GuestOp::CapMdnsBrowse { service_type } => plugin
            .call_capability_export::<(String,), (Result<String, String>,)>(
                crate::contract::export_item("host-mdns", "browse"),
                (service_type,),
            )
            .map(|(r,)| GuestReply::GuestStr(r)),
        GuestOp::CapMdnsStopBrowse { browser_id } => plugin
            .call_capability_export::<(String,), (Result<bool, String>,)>(
                crate::contract::export_item("host-mdns", "stop-browse"),
                (browser_id,),
            )
            .map(|(r,)| GuestReply::GuestBool(r)),
        GuestOp::CapMdnsAdvertise { config_json } => plugin
            .call_capability_export::<(String,), (Result<String, String>,)>(
                crate::contract::export_item("host-mdns", "advertise"),
                (config_json,),
            )
            .map(|(r,)| GuestReply::GuestStr(r)),
        GuestOp::CapMdnsStopAdvertise { advertise_id } => plugin
            .call_capability_export::<(String,), (Result<bool, String>,)>(
                crate::contract::export_item("host-mdns", "stop-advertise"),
                (advertise_id,),
            )
            .map(|(r,)| GuestReply::GuestBool(r)),
        GuestOp::CapMdnsIsAdvertising { advertise_id } => plugin
            .call_capability_export::<(String,), (Result<bool, String>,)>(
                crate::contract::export_item("host-mdns", "is-advertising"),
                (advertise_id,),
            )
            .map(|(r,)| GuestReply::GuestBool(r)),
        GuestOp::CapAuthVerifyDeviceToken { token } => plugin
            .call_capability_export::<(String,), (Result<String, String>,)>(
                crate::contract::export_item("auth-policy", "verify-device-token"),
                (token,),
            )
            .map(|(r,)| GuestReply::GuestStr(r)),
    }
}

/// 属主结算回的 guest 层结果（**两层 Result 分层**：外层是 [`OwnerOutcome`]，
/// 内层是 WIT `result<T, string>` 本体）
#[derive(Debug)]
pub enum GuestReply {
    /// 无返回值导出（`on-message` / `on-message-binary` / `on-process-done`）
    Unit,
    /// 生命周期导出（`activate` / `deactivate`）：与 mutex 路径逐字等价地返回 0
    Code(i32),
    /// `invoke-command` 的 JSON 字符串返回值
    Str(String),
    /// 观察型回调的投递结果（`true` = 已投递；`false` = 该插件未导出该接口）
    Bool(bool),
    /// `on-startup` / `on-shutdown` 的 guest 自报结果（双层 Result 的内层）
    Lifecycle(Result<(), String>),
    /// 能力导出 `result<option<string>, string>`
    GuestOptional(Result<Option<String>, String>),
    /// 能力导出 `result<_, string>`
    GuestUnit(Result<(), String>),
    /// 能力导出 `result<string, string>`
    GuestStr(Result<String, String>),
    /// 能力导出 `result<bool, string>`（句柄存在性一类）
    GuestBool(Result<bool, String>),
}

/// 门面调用失败（`mutex` / `event-loop` 两模型同构，见 [`dispatch_mutex_op`]
/// 与 [`OwnerHandle::call`]）
///
/// - `error`：调用方可见错误（`mutex` 模型下与 `call_mutex_blocking` 路径
///   透传的 AppError 文案逐字等价；`event-loop` 模型下由 op 文案表生成）
/// - `panic_message`：宿主函数 panic 消息（`Some` 时生命周期调用点按既有
///   「xxx() panicked」文案分支，其余调用点忽略）
#[derive(Debug)]
pub struct GuestCallFailure {
    pub(crate) error: AppError,
    pub(crate) panic_message: Option<String>,
}

impl GuestCallFailure {
    /// 普通失败（guest 自报 / 传输错误 / trap）
    pub(crate) fn new(error: AppError) -> Self {
        Self {
            error,
            panic_message: None,
        }
    }

    /// 宿主函数 panic（mutex 模型的 catch_unwind 载荷槽位）：错误文案与
    /// mutex 模型的 panic 分支逐字等价
    pub(crate) fn panicked(plugin_id: &str, msg: String) -> Self {
        Self {
            error: AppError::Plugin(format!("WASM plugin {} call panicked: {}", plugin_id, msg)),
            panic_message: Some(msg),
        }
    }

    /// 宿主函数 panic 消息（`None` = 非 panic 失败；调用方可见文案见 `Display`）
    ///
    /// `pub` 只为宿主集成测试的「guest trap 不得被当成宿主 panic」断言（字段本身
    /// `pub(crate)`；本类型跨 crate 已可见，访问器不新增可见面）。
    pub fn panic_message(&self) -> Option<&str> {
        self.panic_message.as_deref()
    }
}

impl std::fmt::Display for GuestCallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for GuestCallFailure {}

/// 单次调用的完成态（传输层）
enum OwnerOutcome {
    /// 正常完成（含观察型导出的 guest 自报错误：与 mutex 路径一样只 warn 不失败）
    Done(GuestReply),
    /// 宿主层失败：guest 生命周期导出自报失败 / 导出缺失（该请求 Err，
    /// **不**触发实例级失败）
    Failed(String),
    /// 传输层 trap：wasmtime 错误全链文本（该请求 Err + **触发实例级失败**）
    Trap { trap: String, trap_detail: String },
}

// ==================== 属主统计与失败回报端口 ====================

/// 属主任务运行计数（纯原子；诊断面与测试断言共用）
#[derive(Default)]
pub(crate) struct OwnerStats {
    /// 已启动的 guest task 数（start 成功）
    started: AtomicU64,
    /// 已结算数（含 trap / 失败）
    settled: AtomicU64,
    /// 请求方放弃等待（应答通道已关闭）而丢弃返回值的次数（I3④：任务不取消）
    detached: AtomicU64,
    /// 队列满拒绝次数（有界失败，fail-visible）
    queue_full: AtomicU64,
    /// 当前在飞 task 数
    in_flight: AtomicU64,
    /// 属主退出时被放弃的在等请求数（I3② 的观测量）
    abandoned: AtomicU64,
    /// trap 次数（实例级失败）
    traps: AtomicU64,
    /// 属主未在宽限内退出、被 abort 兜底的次数（I6 观测量）
    forced_abort: AtomicU64,
    /// 自增请求 id（在等请求表的键）
    next_id: AtomicU64,
}

impl OwnerStats {
    /// 计数快照（诊断输出 / 测试断言）
    pub(crate) fn snapshot(&self) -> OwnerStatsSnapshot {
        OwnerStatsSnapshot {
            started: self.started.load(Ordering::Relaxed),
            settled: self.settled.load(Ordering::Relaxed),
            detached: self.detached.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            abandoned: self.abandoned.load(Ordering::Relaxed),
            traps: self.traps.load(Ordering::Relaxed),
            forced_abort: self.forced_abort.load(Ordering::Relaxed),
        }
    }
}

/// 属主计数快照
///
/// `pub` 但模块 `pub(crate)` ⇒ 生产跨 crate 不可达；宿主集成测试经
/// `crate::test_support::{TestOwnerHandle, OwnerStatsSnapshot}` 取快照断言属主不变式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerStatsSnapshot {
    pub started: u64,
    pub settled: u64,
    pub detached: u64,
    pub queue_full: u64,
    pub in_flight: u64,
    pub abandoned: u64,
    pub traps: u64,
    pub forced_abort: u64,
}

/// 实例级失败处理端口（宿主实现；属主任务在退出前 `await` 它）
///
/// 实现在 `PluginHost`：① 通知前端（统一异常通道，限频合并）；② 限频调度自动重载
/// （`schedule_plugin_reload_after_trap`）。**在等请求的显式失败由属主循环自己做**
/// （见 [`owner_body`]），本端口只做实例级收敛。
///
/// `pub` 但模块 `pub(crate)` ⇒ 生产跨 crate 不可达；宿主集成测试的实现方经
/// `crate::test_support::OwnerFailureSink` 取同一契约（单点定义，不另立副本）。
pub trait OwnerFailureSink: Send + Sync + 'static {
    /// `kind` ∈ {"trap", "panic"}；`detail` 为 wasmtime 错误全链文本 / panic 消息
    fn on_owner_failed<'a>(
        &'a self,
        plugin_id: &'a str,
        kind: &'static str,
        detail: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// 停止属主后的回报（fail-visible：放弃请求数 / 是否强制 abort）
///
/// `pub` 但模块 `pub(crate)` ⇒ 生产跨 crate 不可达；宿主集成测试经
/// `crate::test_support::TestOwnerHandle::stop` 返回本类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownReport {
    /// 属主退出时仍在等应答的请求数（已逐条显式失败）
    pub abandoned_requests: u64,
    /// 宽限内未退出、被 abort 兜底
    pub forced_abort: bool,
}

// ==================== 属主句柄 ====================

/// 属主消息（闭集）
enum OwnerMsg {
    /// 提交一次 guest 调用
    Call {
        op: GuestOp,
        reply: oneshot::Sender<crate::Result<GuestReply>>,
    },
    /// 停止属主（属主退出 ⇒ store 被 drop）
    Stop,
}

/// 属主任务句柄（装配表 `InstanceSlot::Owner` 的内容物；宿主侧唯一入口）
pub(crate) struct OwnerHandle {
    plugin_id: String,
    tx: mpsc::Sender<OwnerMsg>,
    /// 属主任务句柄（`stop()` 取走后 await；Drop 兜底 abort）
    join: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    alive: Arc<AtomicBool>,
    stats: Arc<OwnerStats>,
}

impl OwnerHandle {
    /// 属主是否仍在服务（false = 实例已不可用；调用方必须显性失败）
    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// 计数快照
    pub(crate) fn stats(&self) -> OwnerStatsSnapshot {
        self.stats.snapshot()
    }

    /// 异步门面：入队并等待结果
    ///
    /// 失败一律**立即显性 Err**（不静默挂起）：渠道关闭（属主已退出/任务 panic）、
    /// 队列满（有界失败）、应答通道被 drop（实例终止）。
    pub(crate) async fn call(&self, op: GuestOp) -> crate::Result<GuestReply> {
        let kind = op.kind();
        if !self.is_alive() {
            return Err(AppError::Plugin(format!(
                "plugin '{}' instance owner is not running (instance failed or stopped)",
                self.plugin_id
            )));
        }
        let (tx, rx) = oneshot::channel();
        match self.tx.try_send(OwnerMsg::Call { op, reply: tx }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.queue_full.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    plugin_id = %self.plugin_id,
                    export = kind.export(),
                    capacity = OWNER_QUEUE_CAP,
                    "plugin call rejected: owner queue is full"
                );
                return Err(AppError::Plugin(format!(
                    "plugin '{}' call queue is full (capacity {}, export {})",
                    self.plugin_id,
                    OWNER_QUEUE_CAP,
                    kind.export()
                )));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(AppError::Plugin(format!(
                    "plugin '{}' instance owner channel is closed (instance terminated)",
                    self.plugin_id
                )));
            }
        }
        rx.await.map_err(|_| {
            AppError::Plugin(format!(
                "plugin '{}' instance terminated while the call was in flight (export {})",
                self.plugin_id,
                kind.export()
            ))
        })?
    }

    /// 停止属主：发停止信号 → 等属主退出（store 已 drop）→ 超时 abort 兜底
    ///
    /// I3③/I6：调用方拿到返回值即代表**该实例的 Store 已不可达**，此后做资源回收
    /// （pty/ws/http/mdns/task purge）不会与在飞 guest task 竞争。
    pub(crate) async fn stop(&self) -> ShutdownReport {
        // 通道关闭 = 属主已死，无需再发信号
        let _ = self.tx.try_send(OwnerMsg::Stop);
        let deadline = Instant::now() + OWNER_STOP_GRACE;
        while self.is_alive() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut forced = false;
        let join = self.join.lock().unwrap_or_else(|e| e.into_inner()).take();
        if self.is_alive() {
            forced = true;
            self.stats.forced_abort.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                plugin_id = %self.plugin_id,
                grace_ms = OWNER_STOP_GRACE.as_millis() as u64,
                "plugin instance owner did not exit within grace, aborting"
            );
            if let Some(join) = &join {
                join.abort();
            }
        }
        if let Some(join) = join {
            // await 保证「store 已 drop」在返回前成立（abort 路径同样会结束任务）
            if let Err(e) = join.await {
                tracing::debug!(
                    plugin_id = %self.plugin_id,
                    error = %e,
                    "plugin instance owner task ended with error"
                );
            }
        }
        ShutdownReport {
            abandoned_requests: self.stats.abandoned.load(Ordering::Relaxed),
            forced_abort: forced,
        }
    }
}

impl Drop for OwnerHandle {
    /// 装配表条目被替换/移除（重载、卸载、退出）时的兜底：先发停止信号（属主自退，
    /// store 随任务 drop），再 abort 兜底防孤儿任务。
    fn drop(&mut self) {
        let _ = self.tx.try_send(OwnerMsg::Stop);
        if let Some(join) = self.join.lock().unwrap_or_else(|e| e.into_inner()).take() {
            join.abort();
        }
    }
}

// ==================== 属主任务 ====================

/// 属主退出原因
enum OwnerExit {
    /// 宿主主动停止（停用 / 卸载 / 重建 / 应用退出）：不触发实例级失败
    Shutdown,
    /// 实例级失败（trap / panic / 作用域退出即报错）：由 sink 收敛
    InstanceFailed { kind: &'static str, detail: String },
}

/// 启动属主任务（装配表在实例化期调用一次；零 WIT 改动）
pub(crate) fn spawn_owner(
    plugin: LoadedWasmPlugin,
    sink: Arc<dyn OwnerFailureSink>,
) -> OwnerHandle {
    let plugin_id = plugin.meta().plugin_id.clone();
    let (tx, rx) = mpsc::channel(OWNER_QUEUE_CAP);
    let stats = Arc::new(OwnerStats::default());
    let alive = Arc::new(AtomicBool::new(true));

    let task_stats = stats.clone();
    let task_alive = alive.clone();
    let task_plugin_id = plugin_id.clone();
    let join = crate::system::error_boundary::spawn_with_error_boundary(
        "plugin_instance_owner",
        async move {
            // panic 兜底：宿主函数 panic 会穿透 wasmtime 调用栈（mutex 模型靠
            // call_mutex_blocking 的 catch_unwind 捕获；属主模型必须包住整个任务体），
            // 收敛路径与 trap 一致（实例不可用 + 显式失败在等请求）
            let outcome = std::panic::AssertUnwindSafe(owner_body(plugin, rx, task_stats.clone()))
                .catch_unwind()
                .await;
            task_alive.store(false, Ordering::SeqCst);
            match outcome {
                Ok(OwnerExit::Shutdown) => {
                    tracing::debug!(plugin_id = %task_plugin_id, "plugin instance owner stopped");
                }
                Ok(OwnerExit::InstanceFailed { kind, detail }) => {
                    sink.on_owner_failed(&task_plugin_id, kind, &detail).await;
                }
                Err(panic) => {
                    let msg = crate::manager::runtime::panic_payload_to_string(&panic);
                    tracing::error!(
                        plugin_id = %task_plugin_id,
                        panic = %msg,
                        "plugin instance owner task panicked, instance is unusable"
                    );
                    sink.on_owner_failed(&task_plugin_id, "panic", &msg).await;
                }
            }
        },
    );

    OwnerHandle {
        plugin_id,
        tx,
        join: StdMutex::new(Some(join)),
        alive,
        stats,
    }
}

// ==================== 属主循环 ====================

/// 属主任务主体：常驻 `run_concurrent` 作用域内的调度循环
///
/// `run_concurrent` 作用域**必须常驻**（票 02 §6.1：作用域退出后表内任务停滞），
/// 故整个实例生命周期只进一次，循环在里面跑。
async fn owner_body(
    mut plugin: LoadedWasmPlugin,
    mut rx: mpsc::Receiver<OwnerMsg>,
    stats: Arc<OwnerStats>,
) -> OwnerExit {
    let plugin_id = plugin.meta().plugin_id.clone();
    // 进入作用域前取出（作用域内只有 &Accessor，无法再 &mut self）
    let instance = plugin.instance_handle();
    let metrics = plugin.metrics();
    let (fuel_enabled, fuel_budget) = plugin.fuel_spec();
    let optional = plugin.optional_exports();

    // 在等请求表（`id → 应答通道`）在作用域之外：实例级失败/停属主时必须能对
    // **仍在等**的请求逐条显式失败（I3②）。在飞 future 表在作用域之内——
    // 它们借用 `&Accessor`（wasmtime 不提供自持 accessor 的公开构造），
    // 且析构即取消（挂起的宿主 future 随 store 一起回收，票 02 A2.1）
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut exit = OwnerExit::Shutdown;

    let loop_result = plugin
        .store_mut()
        .run_concurrent(async |accessor| {
            let mut inflight: FuturesUnordered<BoxFuture<'_, Settled>> = FuturesUnordered::new();
            loop {
                tokio::select! {
                    // I4：先收请求再结算。单点 start（只在收消息分支里 start）+ 每轮
                    // 至多启动一个 task ⇒ 启动顺序严格等于入队顺序
                    biased;
                    msg = rx.recv() => match msg {
                        Some(OwnerMsg::Call { op, reply }) => {
                            let kind = op.kind();
                            let id = stats.next_id.fetch_add(1, Ordering::Relaxed);
                            // 计时起点 = start 时刻（task 生命周期，票 03 §3 口径）
                            let timer = metrics.start_call();
                            match start_op(accessor, &instance, &optional, op, timer, (fuel_enabled, fuel_budget), &metrics)
                            {
                                Ok(fut) => {
                                    pending.insert(id, Pending { kind, reply });
                                    stats.started.fetch_add(1, Ordering::Relaxed);
                                    stats.in_flight.fetch_add(1, Ordering::Relaxed);
                                    inflight.push(Box::pin(async move {
                                        Settled { id, outcome: fut.await }
                                    }));
                                }
                                Err(e) => {
                                    // start 期失败（导出缺失 / 燃料续费 / 非法导出名）：
                                    // 立即显性失败，不占在飞表
                                    if reply.send(Err(e)).is_err() {
                                        stats.detached.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        Some(OwnerMsg::Stop) | None => {
                            exit = OwnerExit::Shutdown;
                            break;
                        }
                    },
                    Some(settled) = inflight.next(), if !inflight.is_empty() => {
                        stats.in_flight.fetch_sub(1, Ordering::Relaxed);
                        stats.settled.fetch_add(1, Ordering::Relaxed);
                        if let Some(failure) = settle(settled, &mut pending, &stats, &metrics) {
                            exit = failure;
                            break;
                        }
                    }
                }
            }
        })
        .await;

    // `run_concurrent` 顶层 Err：guest task trap 会**从事件循环冒出**（而不是从
    // `finish_call_concurrent` 返回——那是短命作用域 `call_async` 的形态），
    // 按实例级失败收敛，并把 trap 文案归属到**最早的在飞请求**：
    // mutex 模型下调用串行（单在飞是常态），归属后错误串与 mutex 逐字等价（I5）
    let mut blamed: Option<(u64, String)> = None;
    if let Err(e) = loop_result {
        let trap = e.to_string();
        stats.traps.fetch_add(1, Ordering::Relaxed);
        if let Some(id) = pending.keys().min().copied() {
            blamed = Some((id, trap.clone()));
        }
        exit = OwnerExit::InstanceFailed {
            kind: "trap",
            detail: format!("run_concurrent failed: {}", trap),
        };
    }

    // 在等请求逐条显式失败（I3②：不排队等重载、不静默重试）
    let fail_msg = match &exit {
        OwnerExit::Shutdown => format!(
            "plugin '{}' instance stopped before the call completed",
            plugin_id
        ),
        OwnerExit::InstanceFailed { kind, detail } => {
            format!(
                "plugin '{}' instance failed ({}): {}",
                plugin_id, kind, detail
            )
        }
    };
    let abandoned = pending.len() as u64;
    for (id, entry) in pending.drain() {
        let err = match &blamed {
            Some((blame_id, trap)) if *blame_id == id => entry.kind.trap_error(trap),
            _ => AppError::Plugin(fail_msg.clone()),
        };
        if entry.reply.send(Err(err)).is_err() {
            stats.detached.fetch_add(1, Ordering::Relaxed);
        }
    }
    // 通道中尚未 start 的请求同样逐条显式失败（不留在队列里等一个不会来的属主）
    loop {
        match rx.try_recv() {
            Ok(OwnerMsg::Call { reply, .. }) => {
                if reply.send(Err(AppError::Plugin(fail_msg.clone()))).is_err() {
                    stats.detached.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(OwnerMsg::Stop) => {}
            Err(_) => break,
        }
    }
    if abandoned > 0 {
        stats.abandoned.fetch_add(abandoned, Ordering::Relaxed);
        tracing::warn!(
            plugin_id = %plugin_id,
            abandoned_requests = abandoned,
            "plugin instance owner exiting with requests still waiting (each failed explicitly)"
        );
    }

    exit
}

/// 在等请求条目
struct Pending {
    kind: OpKind,
    reply: oneshot::Sender<crate::Result<GuestReply>>,
}

/// 在飞条目的完成态
struct Settled {
    id: u64,
    outcome: OwnerOutcome,
}

/// 结算一条完成态：发送应答 + 记账；返回 `Some` 表示实例级失败（属主循环退出）
fn settle(
    settled: Settled,
    pending: &mut HashMap<u64, Pending>,
    stats: &OwnerStats,
    metrics: &Arc<PluginMetrics>,
) -> Option<OwnerExit> {
    let Settled { id, outcome } = settled;
    // 在等表条目缺失 = 内部一致性错误（已结算过 / id 漂移）：显性告警，不静默
    let Some(entry) = pending.remove(&id) else {
        tracing::error!(
            request_id = id,
            "plugin owner settlement without a matching pending request"
        );
        return None;
    };
    let kind = entry.kind;

    match outcome {
        OwnerOutcome::Done(reply) => {
            // 生命周期记账（口径与 mutex 路径的 LoadedWasmPlugin::activate/deactivate 一致）
            match kind {
                OpKind::Activate => metrics.record_lifecycle(LifecycleEvent::ActivateOk),
                OpKind::Deactivate => metrics.record_lifecycle(LifecycleEvent::Deactivate),
                _ => {}
            }
            send_reply(kind, stats, entry.reply, Ok(reply));
            None
        }
        OwnerOutcome::Failed(msg) => {
            if kind == OpKind::Activate {
                metrics.record_lifecycle(LifecycleEvent::ActivateFail);
            }
            // `Failed` 携带的已是完整文案（`start_op` 内按 mutex 路径逐字构造），
            // 不得再经 `trap_error` 裹一层（否则出现双前缀）
            send_reply(kind, stats, entry.reply, Err(AppError::Plugin(msg)));
            None
        }
        OwnerOutcome::Trap { trap, trap_detail } => {
            stats.traps.fetch_add(1, Ordering::Relaxed);
            // 与 mutex 路径 log_trap 同格式（trap_detail 打全链，Display 只有顶层 context）
            tracing::error!(
                export = kind.export(),
                trap = %trap,
                trap_detail = %trap_detail,
                "WASM plugin export call trapped"
            );
            send_reply(kind, stats, entry.reply, Err(kind.trap_error(&trap)));
            Some(OwnerExit::InstanceFailed {
                kind: "trap",
                detail: format!("{}: {}", kind.export(), trap),
            })
        }
    }
}

/// 应答发送（请求方放弃等待 = 计数 + debug 日志，**不取消任务**：I3④）
fn send_reply(
    kind: OpKind,
    stats: &OwnerStats,
    reply: oneshot::Sender<crate::Result<GuestReply>>,
    value: crate::Result<GuestReply>,
) {
    if reply.send(value).is_err() {
        stats.detached.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            export = kind.export(),
            "guest call result dropped: requester gave up waiting (task side effects already applied)"
        );
    }
}

// ==================== start 分派（闭集 op → 类型化 task） ====================

/// 启动一次 guest 调用：同步完成「燃料续费 + 取导出 + `start_call_concurrent`」，
/// 返回「完成时解释结果」的 future（属主循环 `await` 它）
fn start_op<'a>(
    accessor: &'a Accessor<WasmPluginState>,
    instance: &Instance,
    optional: &OptionalExports,
    op: GuestOp,
    timer: CallTimer,
    fuel: (bool, u64),
    metrics: &Arc<PluginMetrics>,
) -> crate::Result<BoxFuture<'a, OwnerOutcome>> {
    // 在飞 future 借用 `&Accessor`：wasmtime 未提供自持 accessor 的公开构造
    // （`clone_for_spawn` 私有），但属主循环与 start 同处一个常驻 `run_concurrent`
    // 作用域——start 在 `with` 内同步完成，finish 由属主循环 `await`，借用合法
    let owned = accessor;
    let (fuel_enabled, fuel_budget) = fuel;

    accessor.with(|mut access| -> crate::Result<BoxFuture<'a, OwnerOutcome>> {
        // 燃料续费在每次 start 前（实例级共享预算：并发 task 共享同一池，
        // 记账 = 各续费点差值之和，天然无干扰 —— 票 03 §3 口径）
        refill_fuel(&mut access, fuel_enabled, fuel_budget, metrics)?;

        let fut = match op {
            GuestOp::InvokeCommand { name, args_json } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("command", "invoke"),
                (name, args_json),
                owned,
                timer,
                |res| match res {
                    Ok((v,)) => OwnerOutcome::Done(GuestReply::Str(v)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::Activate => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("lifecycle", "activate"),
                (),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    Ok((Ok(()),)) => OwnerOutcome::Done(GuestReply::Code(0)),
                    Ok((Err(msg),)) => {
                        OwnerOutcome::Failed(format!("WASM activate() failed: {}", msg))
                    }
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::Deactivate => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("lifecycle", "deactivate"),
                (),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    Ok((Ok(()),)) => OwnerOutcome::Done(GuestReply::Code(0)),
                    Ok((Err(msg),)) => {
                        OwnerOutcome::Failed(format!("WASM deactivate() failed: {}", msg))
                    }
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::OnStartup => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("lifecycle", "on-startup"),
                (),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::Lifecycle(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::OnShutdown => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("lifecycle", "on-shutdown"),
                (),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::Lifecycle(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::OnMessage {
                topic,
                sender,
                payload_json,
            } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("events", "on-message"),
                (topic, sender, payload_json),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    // 观察型回调：guest 自报失败只 warn（与 mutex 路径一致）
                    Ok((Ok(()),)) => OwnerOutcome::Done(GuestReply::Unit),
                    Ok((Err(msg),)) => {
                        tracing::warn!("WASM on_message() failed: {}", msg);
                        OwnerOutcome::Done(GuestReply::Unit)
                    }
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::OnMessageBinary {
                topic,
                sender,
                payload,
            } => match optional.on_message_binary {
                Some(func) => start_typed_with_func(
                    &mut access,
                    func,
                    (topic, sender, payload),
                    owned,
                    timer,
                    |res: Result<(), wasmtime::Error>| match res {
                        Ok(()) => OwnerOutcome::Done(GuestReply::Unit),
                        Err(e) => trap_outcome(e),
                    },
                )?,
                // 与 mutex 路径同文案（总线已按订阅者格式偏好过滤，正常不会到达）
                None => ready(
                    timer,
                    OwnerOutcome::Failed(
                        "WASM plugin has no events-binary export (v11 required)".to_string(),
                    ),
                ),
            },
            GuestOp::OnProcessDone { payload_json } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("events", "on-process-done"),
                (payload_json,),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    Ok((Ok(()),)) => OwnerOutcome::Done(GuestReply::Unit),
                    Ok((Err(msg),)) => {
                        tracing::warn!("WASM on_process_done() failed: {}", msg);
                        OwnerOutcome::Done(GuestReply::Unit)
                    }
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::WsClientMessage {
                handle,
                kind,
                payload,
            } => match optional.on_ws_message {
                Some(func) => start_typed_with_func(
                    &mut access,
                    func,
                    (handle, kind, payload),
                    owned,
                    timer,
                    |res: Result<(), wasmtime::Error>| match res {
                        Ok(()) => OwnerOutcome::Done(GuestReply::Bool(true)),
                        Err(e) => trap_outcome(e),
                    },
                )?,
                // 未导出该接口：调用方按 spec §2.2 降级（丢弃 + 计数）
                None => ready(timer, OwnerOutcome::Done(GuestReply::Bool(false))),
            },
            GuestOp::WsEndpointMessage {
                endpoint_id,
                client_id,
                kind,
                payload,
            } => match optional.on_ws_client_message {
                Some(func) => start_typed_with_func(
                    &mut access,
                    func,
                    (endpoint_id, client_id, kind, payload),
                    owned,
                    timer,
                    |res: Result<(), wasmtime::Error>| match res {
                        Ok(()) => OwnerOutcome::Done(GuestReply::Bool(true)),
                        Err(e) => trap_outcome(e),
                    },
                )?,
                None => ready(timer, OwnerOutcome::Done(GuestReply::Bool(false))),
            },
            GuestOp::OnTaskEvent { event_json } => match optional.on_task_event {
                Some(func) => start_typed_with_func(
                    &mut access,
                    func,
                    (event_json,),
                    owned,
                    timer,
                    |res: Result<(), wasmtime::Error>| match res {
                        Ok(()) => OwnerOutcome::Done(GuestReply::Bool(true)),
                        Err(e) => trap_outcome(e),
                    },
                )?,
                None => ready(timer, OwnerOutcome::Done(GuestReply::Bool(false))),
            },
            GuestOp::CapStorageGet { key } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-storage", "get"),
                (key,),
                owned,
                timer,
                |res: Result<(Result<Option<String>, String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => {
                        OwnerOutcome::Done(GuestReply::GuestOptional(guest_result))
                    }
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapStorageSet { key, value } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-storage", "set"),
                (key, value),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestUnit(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapStorageDelete { key } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-storage", "delete"),
                (key,),
                owned,
                timer,
                |res: Result<(Result<(), String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestUnit(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapMdnsBrowse { service_type } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-mdns", "browse"),
                (service_type,),
                owned,
                timer,
                |res: Result<(Result<String, String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestStr(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapMdnsStopBrowse { browser_id } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-mdns", "stop-browse"),
                (browser_id,),
                owned,
                timer,
                |res: Result<(Result<bool, String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestBool(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapMdnsAdvertise { config_json } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-mdns", "advertise"),
                (config_json,),
                owned,
                timer,
                |res: Result<(Result<String, String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestStr(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapMdnsStopAdvertise { advertise_id } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-mdns", "stop-advertise"),
                (advertise_id,),
                owned,
                timer,
                |res: Result<(Result<bool, String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestBool(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapMdnsIsAdvertising { advertise_id } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("host-mdns", "is-advertising"),
                (advertise_id,),
                owned,
                timer,
                |res: Result<(Result<bool, String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestBool(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
            GuestOp::CapAuthVerifyDeviceToken { token } => start_typed(
                &mut access,
                instance,
                crate::contract::export_item("auth-policy", "verify-device-token"),
                (token,),
                owned,
                timer,
                |res: Result<(Result<String, String>,), wasmtime::Error>| match res {
                    Ok((guest_result,)) => OwnerOutcome::Done(GuestReply::GuestStr(guest_result)),
                    Err(e) => trap_outcome(e),
                },
            )?,
        };
        Ok(fut)
    })
}

/// trap（`wasmtime::Error`）→ 完成态：Display 与 Debug 双形态（Debug 含 `Caused by` 全链）
fn trap_outcome(e: wasmtime::Error) -> OwnerOutcome {
    OwnerOutcome::Trap {
        trap: e.to_string(),
        trap_detail: format!("{e:?}"),
    }
}

/// 无需启动的立即结算（可选导出缺失等降级分支）；计时器一并纳入 future 生命周期
fn ready<'a>(timer: CallTimer, outcome: OwnerOutcome) -> BoxFuture<'a, OwnerOutcome> {
    Box::pin(async move {
        drop(timer);
        outcome
    })
}

/// 类型化启动：取导出（`ItemName` 路径）→ `start_call_concurrent` → 包成解释型 future
fn start_typed<'a, Params, Return>(
    access: &mut impl wasmtime::AsContextMut<Data = WasmPluginState>,
    instance: &Instance,
    export: &str,
    params: Params,
    accessor: &'a Accessor<WasmPluginState>,
    timer: CallTimer,
    interpret: fn(std::result::Result<Return, wasmtime::Error>) -> OwnerOutcome,
) -> crate::Result<BoxFuture<'a, OwnerOutcome>>
where
    Params: ComponentNamedList + Lower + Send + 'static,
    Return: ComponentNamedList + Lift + Send + 'static,
{
    let item: wasmtime::component::wit_parser::ItemName = export
        .parse()
        .map_err(|e| AppError::Plugin(format!("invalid wasm export name: {} ({})", export, e)))?;
    let func = instance
        .get_typed_func::<Params, Return>(&mut *access, &item)
        .map_err(|e| AppError::Plugin(format!("WASM export '{}' not found: {}", export, e)))?;
    let call = func
        .start_call_concurrent(&mut *access, params)
        .map_err(|e| {
            AppError::Plugin(format!("WASM export '{}' start call failed: {}", export, e))
        })?;
    Ok(Box::pin(async move {
        let _timer = timer;
        interpret(func.finish_call_concurrent(accessor, call).await)
    }))
}

/// 同上但直接使用已探测到的可选导出句柄（`OptionalExports` 内为 `TypedFunc`）
fn start_typed_with_func<'a, Params, Return>(
    access: &mut impl wasmtime::AsContextMut<Data = WasmPluginState>,
    func: wasmtime::component::TypedFunc<Params, Return>,
    params: Params,
    accessor: &'a Accessor<WasmPluginState>,
    timer: CallTimer,
    interpret: fn(std::result::Result<Return, wasmtime::Error>) -> OwnerOutcome,
) -> crate::Result<BoxFuture<'a, OwnerOutcome>>
where
    Params: ComponentNamedList + Lower + Send + 'static,
    Return: ComponentNamedList + Lift + Send + 'static,
{
    let call = func
        .start_call_concurrent(&mut *access, params)
        .map_err(|e| AppError::Plugin(format!("WASM optional export start call failed: {}", e)))?;
    Ok(Box::pin(async move {
        let _timer = timer;
        interpret(func.finish_call_concurrent(accessor, call).await)
    }))
}

/// 单次调用燃料续费（与 `LoadedWasmPlugin::refill_call_fuel` 同口径）：
/// 续费前把上一区间消耗记入 core-monitor，再把预算重置为满额
fn refill_fuel(
    store: &mut impl wasmtime::AsContextMut<Data = WasmPluginState>,
    fuel_enabled: bool,
    fuel_budget: u64,
    metrics: &Arc<PluginMetrics>,
) -> crate::Result<()> {
    if !fuel_enabled {
        return Ok(());
    }
    let mut ctx = store.as_context_mut();
    if let Ok(remaining) = ctx.get_fuel() {
        if remaining <= fuel_budget {
            metrics.record_fuel_consumed(fuel_budget - remaining);
        }
    }
    ctx.set_fuel(fuel_budget)
        .map_err(|e| AppError::Plugin(format!("WASM fuel refill failed: {}", e)))
}
