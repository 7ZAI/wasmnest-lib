//! `host-database` / `host-plugin-database` / `host-storage` 三域的宿主端口（测试缝）
//!
//! **这不是架构边界，是可测性缝**：三段能力（权限门、库句柄、同步↔异步桥、kv
//! 存储与能力路由）全在宿主内，域代码与适配器同属 `wasm_core`——ADR 0036 明确
//! 它们**不拆 crate**。留这一层只为让域逻辑能在不构造完整 `WasmHostContext` 的前提
//! 下用假端口跑护栏 / 隔离 / 批次用例（[`super::sqlite_scaffold`]）。
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | [`SqlitePorts::check_permission`] | 权限门（`storage`——主库位 `database:main` 已随 2026-10-09 host-database 退役）是**宿主安全闸门**（AGENTS §5.1.3 四类薄壳之二），判定与拒绝 `warn` 只在宿主一处 ⇒ 域只问结果 |
//! | [`SqlitePorts::plugin_db`] | 插件私有库句柄（每插件独立库 / 独立连接，**懒创建**：目录根来自 `app_data_dir()/plugins/<id>` 或无头测试注入的根）。创建是 async 且属宿主策略，故经端口要 |
//! | [`SqlitePorts::block_on_any`] | 同步↔异步桥：guest 侧 host function 是同步的，而取句柄/加锁是 async。**桥的实现在宿主**（`runtime_util::block_on_async`，wasmtime-wasi ambient runtime 与 actix `current_thread` 自锁规避是实测产物），本域不复制第二份 |
//! | [`SqlitePorts::forward_storage_get`] / `_set` / `_delete` | 能力路由（core-plugin-manager）：`host-storage` 能力由系统组件提供时按调用方命名空间转发到它的同形导出，否则 `None` ⇒ 走宿主原语。**返回 `Option`** 是契约的一部分（`None` = 无提供者，不是错误） |
//! | [`SqlitePorts::storage_get`] / `_set` / `_delete` | 宿主键值存储（`plugin_storage` 表，`wasm_core::storage::PluginStorage`）。**同步端口方法**：内部 async，宿主用那份唯一的桥驱动完再交结果 |
//!
//! ## 为什么 kv 不经「给域一个 `PluginStorage` 句柄」
//!
//! `PluginStorage` 是**宿主服务对象**（15 处宿主调用方，含审批记录与预授权路径读取），
//! 它带一个 `pub(crate)` 的裸主库句柄访问器（R-10 纪律：只有 crate 内的安全/能力模块
//! 能摸）。把它整体交给域，那条访问器必须放宽成跨模块 `pub` ——为了三个原语而拆一道
//! 安全纪律，不划算。故 kv 经**窄端口方法**要，域拿不到裸句柄。
//!
//! ## dyn 兼容
//!
//! 端口 trait 必须 **dyn 兼容**（域函数收 `&Arc<dyn SqlitePorts>`，生产与假端口同形）。
//! 故异步出口一律擦除成 [`PluginDbFuture`] / [`BoxedBlocked`]（泛型方法会破坏 dyn
//! 兼容），由本模块的泛型助手 [`block_on`] 与各域函数还原成强类型。
//!
//! ## 端口从哪来
//!
//! 生产路径没有单例、没有装配期登记：域函数由 `component.rs` 的 `Host` impl 逐次
//! 调用，入参是**本次调用的上下文**（见 [`super::sqlite::ports_for`]）。能力域 crate
//! 形态下的进程级 `OnceLock` 单例 + 实例级 `domain_ports` 登记（能力域 crate 才需要的
//! 跨 crate 装配手段）随 crate 一并撤销。

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::db::Database;

/// 类型擦除的「同步驱动异步」入参（[`SqlitePorts::block_on_any`]）
///
/// **带生命周期参数**（不是 `'static`）：本域的驱动块普遍借用入参（`plugin_id` /
/// `sql`），强制 `'static` 会逼每个域函数把字符串克隆一遍才能过编译——那是搬迁带来的
/// 噪音，不是语义。宿主那份桥（`runtime_util::block_on_async`）**本来就只要求
/// `Future + Send`**（输出才要求 `'static`，因为要装进 `Box<dyn Any>`），本域的端口
/// 与宿主实现保持同一口径。
pub type BoxedBlocked<'a> = Pin<Box<dyn Future<Output = Box<dyn Any + Send>> + Send + 'a>>;

/// 插件私有库句柄的取用出口（[`SqlitePorts::plugin_db`]）
///
/// **带生命周期参数**（同 [`BoxedBlocked`]）：生产端口持宿主上下文的借用，懒创建
/// future 借用它（与 `DbScope::get_or_create_plugin_db` 同一形状，见
/// `host_api::context`）——无需为 `'static` 硬造一份 `Arc<WasmHostContext>`。
pub type PluginDbFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<std::sync::Mutex<Database>>, String>> + Send + 'a>>;

/// 宿主能力端口
///
/// 实现方有二：生产适配器 [`super::sqlite::HostSqlitePorts`]（包宿主上下文）与测试
/// 假端口 [`super::sqlite_scaffold::FakePorts`]。实现应尽量轻——每次原语调用都要经它。
/// 主库句柄访问器已随 host-database 退役删除（主库由内核直接管理，不进端口面）；
/// 本 trait 其余方法见文件头表格。
pub trait SqlitePorts: Send + Sync {
    /// 权限判定（`storage`；主库位 `database:main` 已随 host-database 退役）
    ///
    /// 返回 `false` 时**宿主侧**必须已按 AGENTS §8 落 `warn`（结构化字段
    /// `plugin_id` / `permission` / `api`）；本域不重复落日志。宿主侧也拿不到
    /// 权限管理器时（无头 / 测试）**必须返回 false**（fail-safe，与既有
    /// `host_api::check_permission` 同向）。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 取（或懒创建）某插件的私有库句柄
    ///
    /// 失败即 `Err(String)`（原样透传给 guest，不改写）；典型失败：无头上下文既无
    /// `app_handle` 也未注入私有库根目录。
    fn plugin_db<'a>(&'a self, plugin_id: String) -> PluginDbFuture<'a>;

    /// 在宿主运行时上**同步驱动**一段异步计算（WASM host function 是同步的）
    ///
    /// 实现即宿主的 `runtime_util::block_on_async`：多线程运行时走
    /// `block_in_place`、current_thread / 无句柄线程走新线程 ambient 兜底。
    /// **必须复用宿主那份实现**，不得在本域复制第二份桥（重入自锁与 ambient
    /// runtime 语义是实测产物）。
    fn block_on_any(&self, fut: BoxedBlocked<'_>) -> Box<dyn Any + Send>;

    /// 能力路由：`host-storage.get` 转给系统组件提供者；无提供者返回 `None`
    fn forward_storage_get(&self, plugin_id: &str, key: &str) -> Option<Result<Option<String>, String>>;

    /// 能力路由：`host-storage.set`（语义同 [`SqlitePorts::forward_storage_get`]）
    fn forward_storage_set(&self, plugin_id: &str, key: &str, value: &str) -> Option<Result<(), String>>;

    /// 能力路由：`host-storage.delete`（语义同 [`SqlitePorts::forward_storage_get`]）
    fn forward_storage_delete(&self, plugin_id: &str, key: &str) -> Option<Result<(), String>>;

    /// 宿主键值存储读（`plugin_storage` 表，按 `plugin_id` 隔离）
    fn storage_get(&self, plugin_id: &str, key: &str) -> Result<Option<serde_json::Value>, String>;

    /// 宿主键值存储写（upsert）
    fn storage_set(&self, plugin_id: &str, key: &str, value: serde_json::Value) -> Result<(), String>;

    /// 宿主键值存储删（幂等）
    fn storage_delete(&self, plugin_id: &str, key: &str) -> Result<(), String>;
}

// ==================== 泛型助手 ====================

/// 强类型版同步驱动（端口方法的包装：擦除入参 → 驱动 → 还原类型）
///
/// 入参 future 可借用调用方的数据（见 [`BoxedBlocked`] 的生命周期说明）；**返回值必须
/// `'static`**（要装进 `Box<dyn Any>`；本域的返回值都是 `u32` / `String` /
/// `serde_json::Value`，天然满足）。
///
/// 类型不符是**装配期编程错误**（调用方传错了 future 的输出类型），直接 panic
/// 点名，不静默返回 `None` 之类的假值。
pub fn block_on<'a, T: Send + 'static>(ports: &'a dyn SqlitePorts, fut: impl Future<Output = T> + Send + 'a) -> T {
    let erased: BoxedBlocked<'a> = Box::pin(async move { Box::new(fut.await) as Box<dyn Any + Send> });
    match ports.block_on_any(erased).downcast::<T>() {
        Ok(value) => *value,
        Err(_) => panic!(
            "sqlite ports block_on_any returned an unexpected result type (expected {})",
            std::any::type_name::<T>()
        ),
    }
}
