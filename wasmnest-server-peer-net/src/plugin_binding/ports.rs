//! host-peer 能力域的宿主端口（边界层）
//!
//! ## 设计依据（ws 域的同名边界层同款，票 05 沿用票 04 在 ws 域跑通的形态）
//!
//! 消费方（本 crate）声明端口，宿主实现。本 crate **不依赖 tauri、不依赖宿主
//! bin crate**（由 [`crate::dependency_direction_lock`] 以依赖清单 + 源码前缀
//! 双锁钉死），故该域的机制面（句柄表 / 自动重拨 / 权限门位置 / 属性判定）自持，
//! 只把「宿主才有的三件事」经端口要过来。
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | [`PeerPorts::check_permission`] | 权限门（`peer`）是**宿主安全闸门**（AGENTS §5.1.3 四类薄壳之二），不该可插拔 ⇒ 留宿主，本域只问结果（拒绝文案与 warn 落宿主侧） |
//! | [`PeerPorts::peer_ctx`] | **本票要解除的反向耦合**：迁移前绑定层有 20 处靠「从宿主组装面取引擎上下文」拿引擎状态（宿主的引擎上下文装配函数），那要求本 crate 反向认识宿主 `AppHandle` 与宿主 state 表。经端口要「已装配好的 [`PeerCtx`]」后，绑定层对宿主组装面的引用降到 **0** |
//! | [`PeerPorts::block_on_any`] | 同步↔异步桥：WASM host function 是同步的，本域要驱动 async 引擎入口。**桥的实现在宿主**（含 ambient runtime 与 actix `current_thread` 自锁规避，见宿主 `runtime_util` 模块头），本域不复制第二份 |
//!
//! ## 为什么 `peer_ctx()` 返回 `Result` 而不是 `Option`
//!
//! 无头上下文（测试 / 无 GUI 运行时）拿不到引擎状态。迁移前的口径是
//! 「无头一律报错，不做静默降级」——对等网络能力依赖节点运行时，降级会产生
//! 「看似成功实则空列表」的假象。该口径由 [`HEADLESS_UNAVAILABLE`] 这个**逐字
//! 保留**的 wire 字符串承载：端口实现方在拿不到引擎状态时返回它，域内不做任何
//! 降级分支（拒绝文案是插件可见的事实，留在端口实现方但单一事实源在本模块）。
//!
//! ## 为什么 `block_on_any` 用类型擦除
//!
//! 端口 trait 必须 **dyn 兼容**（`Arc<dyn PeerPorts>` 存进进程级单例），而
//! `async fn`/泛型方法都会破坏 dyn 兼容。故入参出参都擦除成
//! `Box<dyn Any + Send>`，由本模块的泛型助手 [`block_on`] 还原成强类型返回值。

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::PeerCtx;

/// 类型擦除的「同步驱动异步」入参（[`PeerPorts::block_on_any`]）
pub type BoxedBlocked = Pin<Box<dyn Future<Output = Box<dyn Any + Send>> + Send>>;

/// 无头上下文的 wire 文案（逐字保留自迁移前的 `require_app`）
///
/// **插件可见**：该字符串出现在原语返回值里，属跨版本 wire 契约的一部分，
/// 故常量住在能力域（单一事实源），宿主端口实现方引用它而不另写一份。
pub const HEADLESS_UNAVAILABLE: &str = "peer-net unavailable in headless context (no app_handle)";

/// 宿主能力端口
///
/// 实现方是各端宿主的适配器（桌面端见宿主 host_api 域的 peer 适配器）。
pub trait PeerPorts: Send + Sync + 'static {
    /// 权限判定（`peer`）
    ///
    /// 返回 `false` 时**宿主侧**必须已按 AGENTS §8 落 `warn`（结构化字段
    /// `plugin_id` / `permission` / `api`）；本域不重复落日志。宿主侧也拿不到
    /// 权限管理器时（无头 / 测试）**必须返回 false**（fail-safe，与既有
    /// `host_api::check_permission` 同向）。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 取已装配的对等网络引擎上下文（端口 + 四个引擎状态句柄）
    ///
    /// 宿主侧的实现即迁移前那条「由 AppHandle 装配引擎上下文」的调用：
    /// **装配逻辑（从 Tauri managed state 取句柄）留在宿主**，本域只见结果。
    /// 拿不到（无头）时返回 [`HEADLESS_UNAVAILABLE`]，不做空转降级。
    fn peer_ctx(&self) -> Result<Arc<PeerCtx>, String>;

    /// 在宿主运行时上**同步驱动**一段异步计算（WASM host function 是同步的）
    ///
    /// 实现即宿主的 `runtime_util::block_on_async`：多线程运行时走
    /// `block_in_place`、current_thread / 无句柄线程走新线程 ambient 兜底。
    /// **必须复用宿主那份实现**，不得在本域复制第二份桥（重入自锁与 ambient
    /// runtime 语义是实测产物）。
    fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send>;
}

// ==================== 泛型助手 ====================

/// 强类型版同步驱动（端口方法的包装：擦除入参 → 驱动 → 还原类型）
///
/// 收 `&Arc<dyn PeerPorts>`（与本域域函数同一口径）——`Arc` 借用即可解引用成
/// `&dyn PeerPorts`，不需要克隆。
///
/// 类型不符是**装配期编程错误**（调用方传错了 future 的输出类型），直接 panic
/// 点名，不静默返回 `None` 之类的假值。
pub fn block_on<T: Send + 'static>(ports: &Arc<dyn PeerPorts>, fut: impl Future<Output = T> + Send + 'static) -> T {
    let erased: BoxedBlocked = Box::pin(async move { Box::new(fut.await) as Box<dyn Any + Send> });
    match ports.block_on_any(erased).downcast::<T>() {
        Ok(value) => *value,
        Err(_) => panic!(
            "peer ports block_on_any returned an unexpected result type (expected {})",
            std::any::type_name::<T>()
        ),
    }
}

// ==================== 端口装配（进程级单例） ====================

/// 进程级端口持有者
///
/// **为什么是全局**：`impl Host for WasmPluginState` 住在本 crate（它用本 crate
/// 的 `bindgen!` 生成的 `Host` trait），而**端口的具体实现属于宿主**，crate 之间
/// 无从互相指名——故用「宿主开机装一次、之后经本函数取」的单向装配，方向单一。
/// 与 ws 域的同名边界层同款。
static PORTS: std::sync::OnceLock<Arc<dyn PeerPorts>> = std::sync::OnceLock::new();

/// 装配宿主端口实现（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
///
/// 重复装配必须被忽略而不是替换：运行期换掉端口实现会让已建立的会话与在途
/// 传输继续持旧端口，属难以归因的不一致。首次装配者胜出。
pub fn install_ports(ports: Arc<dyn PeerPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的宿主端口
///
/// # Panics
/// 尚未装配时 panic 并点名——**fail-visible**：让一个未接宿主的能力域以
/// 「跑起来但什么都做不了」的面貌存在，比启动即炸难诊断得多。
pub fn ports() -> Arc<dyn PeerPorts> {
    PORTS
        .get()
        .cloned()
        .expect("peer plugin binding ports are not installed — the host must call `install_ports` during boot")
}
