//! `host-database` / `host-plugin-database` / `host-storage` 三域的宿主端口实现
//!
//! 域代码（[`super::database`] / [`super::storage`]）与本适配器同属 `wasm_core`：
//! 权限门、主库与插件私有库句柄、唯一那份同步↔异步桥、kv 存储与能力路由全部在宿主
//! 一处。**不拆 crate**（ADR 0036，撤销 wasm-core-lib-split 票 07/08）。
//!
//! ## 每一段取值为何留在宿主（AGENTS §5.1.3 四类薄壳之二/之三）
//!
//! | 端口方法 | 留在宿主的原因 |
//! | --- | --- |
//! | `check_permission` | 权限判定是**安全闸门**：同一份 `PermissionManager`、同一条拒绝 `warn` 路径（结构化字段 `plugin_id` / `permission` / `api`），不另起一套判定 |
//! | `main_db` / `plugin_db` | 句柄的**持有与懒创建策略**：主库由内核直接管理（`main_db` 句柄方法已随 host-database 退役删除，主库不进端口面）；私有库的目录根来自 `app_data_dir()/plugins/<id>`（或无头测试注入的根），策略不进域 |
//! | `block_on_any` | 宿主那份唯一的同步↔异步桥（wasmtime-wasi ambient runtime + actix `current_thread` 自锁规避是实测产物），**不得复制第二份** |
//! | `forward_storage_*` | 能力路由（core-plugin-manager 的系统组件实例寻址与 trap 隔离）属宿主机制 |
//! | `storage_*` | 宿主 `PluginStorage` 是**宿主服务对象**（审批记录 / 预授权路径等 15 处消费方，且它带一条 `pub(crate)` 的裸主库句柄访问器纪律），不为三个原语把它交给域 |
//!
//! ## 没有装配期登记
//!
//! 能力域 crate 形态下这里曾是「开机 `install(ctx)` → 进程级 `OnceLock` 单例 +
//! 实例级 `domain_ports` 登记 + `inventory` 强制链接」。随 crate 撤销一并删除：
//! [`ports_for`] 按**本次调用**的上下文造一份端口视图（一个 `Arc` 分配，相对一次 DB
//! 往返可忽略），既没有「装了一半」的装配态，也不需要运行期换端口的不一致面。
//!
//! ## 插件停用
//!
//! 无 per-plugin 注册表，故无 `purge_for_plugin`：域只借用宿主的库句柄，不持有需要
//! 回收的资源（插件私有库的连接与目录始终归宿主生命周期）。

use std::any::Any;
use crate::host_api::context::{StorageScope, WasmHostContext};
use crate::host_api::sqlite_ports::{BoxedBlocked, PluginDbFuture, SqlitePorts};
use crate::manager::capability;
use crate::runtime_util::block_on_async;

/// 端口的宿主实现（生产路径：借用一份宿主上下文）
///
/// **借用而非持有 `Arc`**：调用点（`component.rs` 的 `Host` impl）手上只有
/// `&WasmHostContext`（经 `HostPorts::as_any` 取回），而 `plugin_db` 的懒创建 future
/// 本就借用上下文（同 `DbScope::get_or_create_plugin_db`）——不为了 `'static` 在调用点
/// 造一份 `Arc`。零分配，且端口永远与**本次调用**的上下文同形。
pub struct HostSqlitePorts<'a> {
    /// 宿主上下文（权限门 / 主库 / kv / 能力路由 / 异步桥的来源）
    ctx: &'a WasmHostContext,
}

impl<'a> HostSqlitePorts<'a> {
    /// 完整端口（生产）：权限门与全部能力都取自宿主上下文
    pub fn from_ctx(ctx: &'a WasmHostContext) -> Self {
        Self { ctx }
    }
}

/// 为某个上下文取一份端口视图（**不进任何单例**）
///
/// 生产与测试同形：域函数（[`super::database`] / [`super::storage`]）与 `component.rs`
/// 的 `Host` impl 都经它取端口，因此「测试里跑的路径」与「生产跑的路径」是同一条
/// trait 方法实现。
pub fn ports_for(ctx: &WasmHostContext) -> HostSqlitePorts<'_> {
    HostSqlitePorts::from_ctx(ctx)
}

impl SqlitePorts for HostSqlitePorts<'_> {
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool {
        // 权限门留宿主（AGENTS §5.1.3 四类薄壳之「安全闸门」——闸门不应可插拔）。
        // 复用既有 `host_api::check_permission`：同一份 PermissionManager、同一条
        // 拒绝 warn 路径（AGENTS §8 结构化字段），不另起一套判定。
        super::check_permission(self.ctx, plugin_id, permission, api)
    }

    fn plugin_db(&self, plugin_id: String) -> PluginDbFuture<'_> {
        // 懒创建策略（目录根二选一 + 缓存登记）整段留在宿主：域只拿到句柄。
        // future 借用上下文（`'a` 生命周期由端口 trait 传递），无需克隆任何东西。
        let ctx = self.ctx;
        Box::pin(async move { ctx.get_or_create_plugin_db(&plugin_id).await.map_err(|e| e.to_string()) })
    }

    fn block_on_any(&self, fut: BoxedBlocked<'_>) -> Box<dyn Any + Send> {
        // 复用宿主那份唯一的同步↔异步桥（ambient runtime + actix current_thread
        // 自锁规避都是实测产物，域不得复制第二份，见 sqlite_ports 模块文档）
        block_on_async(fut)
    }

    fn forward_storage_get(&self, plugin_id: &str, key: &str) -> Option<Result<Option<String>, String>> {
        capability::forward_storage_get(self.ctx, plugin_id, key)
    }

    fn forward_storage_set(&self, plugin_id: &str, key: &str, value: &str) -> Option<Result<(), String>> {
        capability::forward_storage_set(self.ctx, plugin_id, key, value)
    }

    fn forward_storage_delete(&self, plugin_id: &str, key: &str) -> Option<Result<(), String>> {
        capability::forward_storage_delete(self.ctx, plugin_id, key)
    }

    fn storage_get(&self, plugin_id: &str, key: &str) -> Result<Option<serde_json::Value>, String> {
        let storage = self.ctx.storage().clone();
        block_on_async(async move { storage.get(plugin_id, key).await }).map_err(|e| e.to_string())
    }

    fn storage_set(&self, plugin_id: &str, key: &str, value: serde_json::Value) -> Result<(), String> {
        let storage = self.ctx.storage().clone();
        block_on_async(async move { storage.set(plugin_id, key, value).await }).map_err(|e| e.to_string())
    }

    fn storage_delete(&self, plugin_id: &str, key: &str) -> Result<(), String> {
        let storage = self.ctx.storage().clone();
        block_on_async(async move { storage.delete(plugin_id, key).await }).map_err(|e| e.to_string())
    }
}
