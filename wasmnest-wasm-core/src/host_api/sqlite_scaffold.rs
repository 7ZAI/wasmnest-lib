//! SQLite 三域共用的**假端口**（`database::tests` / `storage::tests` 经
//! `use crate::host_api::sqlite_scaffold::*` 引用）
//!
//! 生产端口是 [`super::sqlite::HostSqlitePorts`]（包宿主上下文）；本替身让域逻辑在
//! **不构造完整 `WasmHostContext`** 的前提下可测：权限门三态、主库表名前缀纵深
//! （SQLite authorizer 引擎层边界）、语句超时 / 行数 / 字节护栏、批次事务语义、kv
//! 隔离与系统空间守卫的断言全在域内闭环。
//!
//! ## 与真实上下文的**形状差异**（刻意保持一致的部分才算证据）
//!
//! - **私有库默认缺席**：宿主那两条用例断言的是「无头上下文取不到私有库句柄」
//!   （宿主测试脚手架从不注入 `plugin_db_root`）。假端口保留同一形状与**同一条错误
//!   文案**，那两条用例断言的**错误归属**（被权限门拒 vs 被私有库缺席拒）逐字不变。
//! - **权限位是显式集合**而非 `PermissionManager`：域只问「放不放行」，判定与落
//!   日志在宿主那一侧，故脚本化授权即足。
//! - **kv 存储是内存 map**：真源是 `plugin_storage` 表（宿主 `PluginStorage`），单测
//!   只关心「按键 + 值 + 属主隔离」三条语义。

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};

use crate::db::Database;
use crate::host_api::sqlite_ports::{BoxedBlocked, PluginDbFuture, SqlitePorts};

/// 私有库缺席时的错误文案（与宿主 `WasmHostContext::get_or_create_plugin_db` 无头分支
/// 的 `AppError::Plugin(..).to_string()` 逐字一致——端口返回的就是那串文本）
const HEADLESS_NO_PLUGIN_DB: &str = "Plugin error: plugin database unavailable in headless context (no app_handle)";

/// 测试替身端口
pub(super) struct FakePorts {
    /// 主库（内存库，`init_schema` 跑过 ⇒ 表结构与生产一致）
    /// 随 host-database 退役（main_db 端口方法已删）字段只作 `new()` 表结构基建，
    /// 无读取方——保留不删（表结构一致性是既有测试依赖的隐性前提）
    #[allow(dead_code)]
    db: Arc<std::sync::Mutex<Database>>,
    /// 已授予的 (属主, 权限位)
    granted: StdMutex<HashSet<(String, String)>>,
    /// 宿主 kv 存储（`(plugin_id, key) -> value`）
    kv: StdMutex<HashMap<(String, String), serde_json::Value>>,
    /// 被「系统组件」代持 kv 能力的属主集合（能力路由用例用）
    kv_forwarded: StdMutex<HashSet<String>>,
    /// 「系统组件」侧的存储空间（**与 `kv` 分开**：两条路径必须可区分，否则
    /// 「命中转发」与「走宿主原语」在断言里长得一样）
    forwarded: StdMutex<HashMap<(String, String), serde_json::Value>>,
    /// 插件私有库（`plugin_db` 域函数测试注入；未登记 = 无头缺席形态）
    plugin_dbs: StdMutex<HashMap<String, Arc<std::sync::Mutex<Database>>>>,
}

impl FakePorts {
    /// 造一份新替身（主库已跑生产 `init_schema`）
    pub(super) fn new() -> Arc<Self> {
        let db = Database::new(std::path::Path::new(":memory:")).expect("open in-memory db");
        db.init_schema().expect("init schema");
        Arc::new(Self {
            db: Arc::new(std::sync::Mutex::new(db)),
            granted: StdMutex::new(HashSet::new()),
            kv: StdMutex::new(HashMap::new()),
            kv_forwarded: StdMutex::new(HashSet::new()),
            forwarded: StdMutex::new(HashMap::new()),
            plugin_dbs: StdMutex::new(HashMap::new()),
        })
    }

    /// 授予权限位（脚本化 `PermissionManager::grant_permissions`）
    pub(super) fn grant(&self, plugin_id: &str, permissions: &[&str]) {
        let mut granted = self.granted.lock().expect("granted lock");
        for permission in permissions {
            granted.insert((plugin_id.to_string(), (*permission).to_string()));
        }
    }

    /// 宿主原语空间里某键的当前值（能力路由用例断言「转发命中 ⇒ 原语未被碰」）
    pub(super) fn host_value(&self, plugin_id: &str, key: &str) -> Option<serde_json::Value> {
        self.kv
            .lock()
            .expect("kv lock")
            .get(&(plugin_id.to_string(), key.to_string()))
            .cloned()
    }

    /// 「系统组件」侧空间里某键的当前值（反向断言用）
    pub(super) fn forwarded_value(&self, plugin_id: &str, key: &str) -> Option<serde_json::Value> {
        self.forwarded
            .lock()
            .expect("forwarded lock")
            .get(&(plugin_id.to_string(), key.to_string()))
            .cloned()
    }

    /// 把某属主登记为「`host-storage` 由系统组件代持」（能力路由路径）
    pub(super) fn forward_kv_for(&self, plugin_id: &str) {
        self.kv_forwarded
            .lock()
            .expect("kv_forwarded lock")
            .insert(plugin_id.to_string());
    }

    /// 注入某插件的私有库（内存库；`host-plugin-database` 域函数测试用）。
    /// 未注入 = 无头上下文私有库缺席形态（与生产无 app_handle 一致）。
    pub(super) fn set_plugin_db(&self, plugin_id: &str) -> Arc<std::sync::Mutex<Database>> {
        let db = Database::new(std::path::Path::new(":memory:")).expect("open in-memory plugin db");
        let arc = Arc::new(std::sync::Mutex::new(db));
        self.plugin_dbs
            .lock()
            .expect("plugin_dbs lock")
            .insert(plugin_id.to_string(), Arc::clone(&arc));
        arc
    }
}

/// 端口别名助手（域函数收 `&dyn SqlitePorts`，替身是 `Arc<FakePorts>`）
pub(super) fn as_ports(ports: &Arc<FakePorts>) -> &dyn SqlitePorts {
    ports.as_ref()
}

/// 同步驱动异步的测试桥
///
/// 与宿主那份唯一实现（以及 http 域的假桥）同策略：不在当前线程起运行时，改起新线程
/// 跑一个 fresh current-thread 运行时。两个硬约束：
///
/// - **必须新线程**：kv 用例是 `#[tokio::test]`（已在运行时上下文内），此时在当前
///   线程 `Runtime::new()` / `block_on` 会 panic；
/// - **必须 scoped**：域函数的驱动块借用入参（`plugin_id` / `sql`），普通
///   `thread::spawn` 要求 `'static`，`thread::scope` 才接得住。
pub(super) fn drive<'a, T: Send + 'a>(fut: impl Future<Output = T> + Send + 'a) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("fresh runtime for test bridge")
                    .block_on(fut)
            })
            .join()
            .expect("test bridge thread panicked")
    })
}

impl SqlitePorts for FakePorts {
    fn check_permission(&self, plugin_id: &str, permission: &str, _api: &str) -> bool {
        self.granted
            .lock()
            .expect("granted lock")
            .contains(&(plugin_id.to_string(), permission.to_string()))
    }

    fn plugin_db<'a>(&'a self, plugin_id: String) -> PluginDbFuture<'a> {
        let hit = self
            .plugin_dbs
            .lock()
            .expect("plugin_dbs lock")
            .get(&plugin_id)
            .cloned();
        match hit {
            Some(arc) => Box::pin(async move { Ok(arc) }),
            None => Box::pin(async { Err(HEADLESS_NO_PLUGIN_DB.to_string()) }),
        }
    }

    fn block_on_any(&self, fut: BoxedBlocked<'_>) -> Box<dyn Any + Send> {
        drive(fut)
    }

    fn forward_storage_get(&self, plugin_id: &str, key: &str) -> Option<Result<Option<String>, String>> {
        if !self.kv_forwarded.lock().expect("kv_forwarded lock").contains(plugin_id) {
            return None;
        }
        let hit = self
            .forwarded
            .lock()
            .expect("forwarded lock")
            .get(&(plugin_id.to_string(), key.to_string()))
            .cloned();
        Some(Ok(hit.map(|v| v.to_string())))
    }

    fn forward_storage_set(&self, plugin_id: &str, key: &str, value: &str) -> Option<Result<(), String>> {
        if !self.kv_forwarded.lock().expect("kv_forwarded lock").contains(plugin_id) {
            return None;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(value).expect("forward payload must be JSON（域函数保证）");
        self.forwarded
            .lock()
            .expect("forwarded lock")
            .insert((plugin_id.to_string(), key.to_string()), parsed);
        Some(Ok(()))
    }

    fn forward_storage_delete(&self, plugin_id: &str, key: &str) -> Option<Result<(), String>> {
        if !self.kv_forwarded.lock().expect("kv_forwarded lock").contains(plugin_id) {
            return None;
        }
        self.forwarded
            .lock()
            .expect("forwarded lock")
            .remove(&(plugin_id.to_string(), key.to_string()));
        Some(Ok(()))
    }

    fn storage_get(&self, plugin_id: &str, key: &str) -> Result<Option<serde_json::Value>, String> {
        Ok(self
            .kv
            .lock()
            .expect("kv lock")
            .get(&(plugin_id.to_string(), key.to_string()))
            .cloned())
    }

    fn storage_set(&self, plugin_id: &str, key: &str, value: serde_json::Value) -> Result<(), String> {
        self.kv
            .lock()
            .expect("kv lock")
            .insert((plugin_id.to_string(), key.to_string()), value);
        Ok(())
    }

    fn storage_delete(&self, plugin_id: &str, key: &str) -> Result<(), String> {
        self.kv
            .lock()
            .expect("kv lock")
            .remove(&(plugin_id.to_string(), key.to_string()));
        Ok(())
    }
}
