//! Guest 事件导出派发契约面（票 03 / ADR 0022）
//!
//! ## 为什么这是「契约面」而非机制
//!
//! 事件循环机制（队列、属主化、背压、燃料续费、trap 记账、观察型失败不阻断投递链）
//! 是应用无关的引擎原语，**留在 wasm-core**；但「调用 guest 的哪个导出、什么签名」
//! 是 WIT 契约事实，且**双端不同**：
//!
//! | 端 | `events` 导出词汇 |
//! | --- | --- |
//! | 桌面 | `on-message` / `on-process-done` |
//! | 移动 | `on-bus-message` / `on-auth-success` / `on-disconnect` / `on-session-created` / `on-session-stopped` |
//!
//! 二者都不在 core.wit（内核机制面，ADR 0052 D1）内，绑进内核等于让内核对
//! 「哪端的 events」表态，并把某端 SDK 依赖钉进内核。
//!
//! ## 为什么不能用原生 `TypedFunc` 探测绕过绑定
//!
//! 两个导出返回 WIT `result<_, string>`，而 `Result<T, E>` **不实现
//! `ComponentNamedList`** —— `result` 返回是 bindgen 的特例处理，原生 TypedFunc
//! 层面无对应表达（ticket-03 §9.6 实测）。既有的可选导出探测能用原生形态，正因为
//! 它们返回 `()`。
//!
//! ## 裁决（用户 2026-10-11「按架构原则进行」）
//!
//! 按 ADR 0022 §5.1.3「机制留内核、契约面上移」：本 trait 是内核向宿主开的**窄缝**，
//! 由各端宿主用自己的 `bindgen!` 实现并注入（与 `HostModule` 自报同一范式）。

// `WasmPluginState` 从 host-kit 直取（机制内核的中性类型的唯一真源）——本文件
// 双端共用，不经过任何形态模块（原 `runtime::common` / `runtime::bare` 两壳已随
// 单形态 2026-10-13 合并为一份，本 trait 双端宿主各自实现并注入）
use wasmnest_host_kit::WasmPluginState;
use wasmtime::Store;

/// 端专属 guest 事件导出的派发器（各端宿主实现并注入）
///
/// **失败语义**（调用方不得放宽）：
/// - 返回 `Err` = 调用级失败（trap / 导出缺失）⇒ 宿主侧记 trap 并按机制处理；
/// - guest 自报的 `result` 失败由**实现方**就地消化（记 warn 后返回 `Ok`）——
///   事件投递是 fire-and-forget，一个处理失败的消息处理器不该让整条分发链失败。
pub trait GuestEventDispatcher: Send + Sync {
    /// 派发一条总线消息（桌面 `events.on-message`）
    ///
    /// `payload_json` 是已序列化的消息体：反序列化属于机制侧的事（宿主已在
    /// `owner.rs` 校验过 JSON），实现方不必再解一次。
    fn on_message(
        &self,
        store: &mut Store<WasmPluginState>,
        instance: wasmtime::component::Instance,
        topic: &str,
        sender: &str,
        payload_json: &str,
    ) -> crate::Result<()>;

    /// 派发「进程执行完成」（桌面 `events.on-process-done`）
    ///
    /// `payload_json` 形如 `{ run_id, exit_code, timed_out }`。
    fn on_process_done(
        &self,
        store: &mut Store<WasmPluginState>,
        instance: wasmtime::component::Instance,
        payload_json: &str,
    ) -> crate::Result<()>;

    // ==================== 移动词汇（桌面不覆写；缺省 fail-visible） ====================
    //
    // 移动 `events` 导出比桌面多 4 个生命周期回调（`cap-mobile.wit` 的
    // `interface events`）。它们与 `on_message` / `on_process_done` 同样是**契约面**，
    // 由移动宿主用自有绑定实现；桌面宿主不覆写 ⇒ 万一被误触发，缺省实现显性报错
    // 而不是静默丢弃（与构造期未注入派发器的 `UnwiredGuestEvents` 同款 fail-visible）。

    /// 派发认证成功（移动 `events.on-auth-success`）
    fn on_auth_success(
        &self,
        _store: &mut Store<WasmPluginState>,
        _instance: wasmtime::component::Instance,
    ) -> crate::Result<()> {
        Err(crate::AppError::Plugin(
            "WASM guest events: on-auth-success not wired by this host (mobile-only export)"
                .to_string(),
        ))
    }

    /// 派发连接断开（移动 `events.on-disconnect`，`reason` 为宿主侧断开原因）
    fn on_disconnect(
        &self,
        _store: &mut Store<WasmPluginState>,
        _instance: wasmtime::component::Instance,
        _reason: &str,
    ) -> crate::Result<()> {
        Err(crate::AppError::Plugin(
            "WASM guest events: on-disconnect not wired by this host (mobile-only export)"
                .to_string(),
        ))
    }

    /// 派发会话创建（移动 `events.on-session-created`）
    fn on_session_created(
        &self,
        _store: &mut Store<WasmPluginState>,
        _instance: wasmtime::component::Instance,
        _session_id: &str,
    ) -> crate::Result<()> {
        Err(crate::AppError::Plugin(
            "WASM guest events: on-session-created not wired by this host (mobile-only export)"
                .to_string(),
        ))
    }

    /// 派发会话停止（移动 `events.on-session-stopped`）
    fn on_session_stopped(
        &self,
        _store: &mut Store<WasmPluginState>,
        _instance: wasmtime::component::Instance,
        _session_id: &str,
    ) -> crate::Result<()> {
        Err(crate::AppError::Plugin(
            "WASM guest events: on-session-stopped not wired by this host (mobile-only export)"
                .to_string(),
        ))
    }
}

/// 未装配派发器时的占位（构造期到注入前、或无头上下文）
///
/// **fail-visible**：报「宿主未注入事件派发器」而非静默丢弃——静默丢弃会让宿主
/// 以为消息已被插件消费，表现为「插件收不到消息」这类极难定位的现象。
pub struct UnwiredGuestEvents;

impl GuestEventDispatcher for UnwiredGuestEvents {
    fn on_message(
        &self,
        _store: &mut Store<WasmPluginState>,
        _instance: wasmtime::component::Instance,
        topic: &str,
        _sender: &str,
        _payload_json: &str,
    ) -> crate::Result<()> {
        Err(crate::AppError::Plugin(format!(
            "WASM guest events unwired: host injected no dispatcher (topic {})",
            topic
        )))
    }

    fn on_process_done(
        &self,
        _store: &mut Store<WasmPluginState>,
        _instance: wasmtime::component::Instance,
        _payload_json: &str,
    ) -> crate::Result<()> {
        Err(crate::AppError::Plugin(
            "WASM guest events unwired: host injected no dispatcher (on-process-done)".to_string(),
        ))
    }
}
