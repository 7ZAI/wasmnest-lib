//! Plugin Storage（中立层）
//!
//! 插件持久化存储 — SQLite plugin_storage 表
//! 按 plugin_id 隔离，插件只能读写自己的空间
//! 同时存储系统级数据（如插件激活状态）
//!
//! **位置纪律（票 03：wasm_core 依赖单向化）**：原定义在
//! `crate::manager::storage`，使 `security` / `host_api` 只为用它就
//! 反向依赖 manager（见 `.scratch/2026-09-24-wasm-core-decouple/spec.md` C6）。
//! 归位到本中立层后只依赖 `crate::db`（SQLite 引擎，同在宿主内——ADR 0036 撤销
//! 票 07/08 的 crate 化），可被 `manager` / `host_api` / `security` 任意引用，
//! 自身不依赖任何 wasm_core 兄弟模块。

use crate::db::Database;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
// db 锁形态统一为 std Mutex（单形态票 02 M1）：方法体内锁获取后只有**同步**
// rusqlite 操作、无跨锁 await（guard 非 Send，编译器强制），std 锁免
// block_on 绕行（移动同步 host fn 直锁；桌面 async fn 内同步持锁同样安全）。
// 与 auth_policy.rs / context.rs / sqlite_ports 同款裁决（锁收敛为同步锁 +
// 短临界区）。
use std::sync::Mutex;

/// 系统级 plugin_id，用于存储非插件私有的全局数据
///
/// **真源随 host-storage 实现层上移共享核**（`wasmnest-host-api-core::storage`，
/// 票 18 起双端单点，fail-closed 消费方 `ensure_not_system_space` 同侧）；本模块仍是
/// 系统级数据的写入方（激活状态等），经再导出保既有路径（ADR 0037 垫片先例）。
pub(crate) use wasmnest_host_api_core::storage::SYSTEM_PLUGIN_ID;
/// 插件激活状态持久化 key
const ACTIVATION_STATE_KEY: &str = "activation_state";

/// 插件存储管理器
pub struct PluginStorage {
    db: Arc<Mutex<Database>>,
}

impl PluginStorage {
    pub fn new(db: Arc<Mutex<Database>>) -> Self {
        Self { db }
    }

    /// 测试构造（内存库 + 生产 schema 初始化）——跨模块测试共用夹具
    /// （迁移自宿主 plugin/storage.rs 同名函数；底库 = crate Database）。
    /// 可见性 = crate 测试 + 宿主 test-support feature（下游 dev-dependencies）。
    /// 常编译（单形态票 02）：共享测试夹具——`bare-host` / `common-host` 形态
    /// feature 已于 2026-10-13 收口退休，本夹具双端共用，不再有任何门控。
    pub fn test_storage() -> Arc<PluginStorage> {
        let db = Arc::new(Mutex::new({
            let db = Database::new(std::path::Path::new(":memory:")).expect("open in-memory db");
            db.init_schema().expect("init schema");
            db
        }));
        Arc::new(PluginStorage::new(db))
    }

    /// 共享底层数据库句柄（只给需要**直接查宿主主库表**的宿主组件用）
    ///
    /// 当前唯一消费者是授权策略与授权记录真源（`security::auth_policy`，表
    /// `plugin_auth_policies` / `plugin_auth_records` 不在 `plugin_storage` 里）：
    /// 它由 `FsAuthChecker` 从本模块取得句柄构造，避免 `WasmRuntime` 再多传一路 db。
    /// 插件可见面仍只有 `get` / `set` / `delete`——本访问器不进任何原语。
    ///
    /// `pub(crate)`（R-10）：全量 `Arc<Mutex<Database>>` 句柄暴露给任意持有者
    /// 会绕过窄存储隔离直读宿主每张表；本句柄只应在 crate 内（安全/能力模块）
    /// 出现，外部（SDK / 其它 crate）不得触达。
    pub(crate) fn db(&self) -> Arc<Mutex<Database>> {
        self.db.clone()
    }

    /// 获取插件存储值
    pub async fn get(
        &self,
        plugin_id: &str,
        key: &str,
    ) -> crate::Result<Option<serde_json::Value>> {
        let db = self.db.lock().expect("plugin storage db lock poisoned");
        let conn = db.conn();
        let mut stmt =
            conn.prepare("SELECT value FROM plugin_storage WHERE plugin_id = ?1 AND key = ?2")?;

        let result = stmt.query_row(rusqlite::params![plugin_id, key], |row| {
            row.get::<_, String>(0)
        });

        match result {
            Ok(json_str) => {
                let value: serde_json::Value = serde_json::from_str(&json_str)?;
                Ok(Some(value))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(crate::AppError::Database(e)),
        }
    }

    /// 设置插件存储值
    pub async fn set(
        &self,
        plugin_id: &str,
        key: &str,
        value: serde_json::Value,
    ) -> crate::Result<()> {
        let db = self.db.lock().expect("plugin storage db lock poisoned");
        let json_str = serde_json::to_string(&value)?;
        let now = Utc::now().to_rfc3339();

        db.conn().execute(
            "INSERT INTO plugin_storage (plugin_id, key, value, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(plugin_id, key) DO UPDATE SET value = ?3, updated_at = ?4",
            rusqlite::params![plugin_id, key, json_str, now],
        )?;

        Ok(())
    }

    /// 删除插件存储值
    pub async fn delete(&self, plugin_id: &str, key: &str) -> crate::Result<()> {
        let db = self.db.lock().expect("plugin storage db lock poisoned");
        db.conn().execute(
            "DELETE FROM plugin_storage WHERE plugin_id = ?1 AND key = ?2",
            rusqlite::params![plugin_id, key],
        )?;
        Ok(())
    }

    /// 原子读-改-写（同一 DB 锁内完成 get → f → set，跨调用窗口串行化同 key 并发修改）
    ///
    /// 现有 `get` / `set` 各自独立加锁，读-改-写跨锁：并发写同一 key 时后提交覆盖
    /// 先提交（lost update）。本原语把整段读写放进一次锁持有，读到的必是最近提交值、
    /// 写出的必落在下一个读者之前——比如审批记录的 approve/revoke
    /// （`security::approval`）两个实例并发时不再互相覆盖。
    ///
    /// `f` 返回写入的 value（始终 upsert）；实现内直接读写 conn，**不得**再调
    /// `get` / `set` / `delete`（它们会再抢同一把锁 → 自死锁）。
    pub async fn update<F>(&self, plugin_id: &str, key: &str, f: F) -> crate::Result<()>
    where
        F: FnOnce(Option<serde_json::Value>) -> crate::Result<serde_json::Value>,
    {
        let db = self.db.lock().expect("plugin storage db lock poisoned");
        let conn = db.conn();
        let previous = {
            let mut stmt =
                conn.prepare("SELECT value FROM plugin_storage WHERE plugin_id = ?1 AND key = ?2")?;
            match stmt.query_row(rusqlite::params![plugin_id, key], |row| {
                row.get::<_, String>(0)
            }) {
                Ok(json_str) => Some(serde_json::from_str::<serde_json::Value>(&json_str)?),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(crate::AppError::Database(e)),
            }
        };
        let next = f(previous)?;
        let json_str = serde_json::to_string(&next)?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO plugin_storage (plugin_id, key, value, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(plugin_id, key) DO UPDATE SET value = ?3, updated_at = ?4",
            rusqlite::params![plugin_id, key, json_str, now],
        )?;
        Ok(())
    }

    /// 清空插件所有存储（插件卸载时使用）
    pub async fn clear_all(&self, plugin_id: &str) -> crate::Result<()> {
        let db = self.db.lock().expect("plugin storage db lock poisoned");
        db.conn().execute(
            "DELETE FROM plugin_storage WHERE plugin_id = ?1",
            rusqlite::params![plugin_id],
        )?;
        Ok(())
    }

    // ==================== System-level: Activation State ====================

    /// 保存插件激活状态映射（plugin_id → is_activated）
    ///
    /// 使用系统级 plugin_id `__system__` 隔离，不与任何插件数据冲突
    pub async fn save_activated_plugins(
        &self,
        activated: &HashMap<String, bool>,
    ) -> crate::Result<()> {
        let value = serde_json::to_value(activated)?;
        self.set(SYSTEM_PLUGIN_ID, ACTIVATION_STATE_KEY, value)
            .await
    }

    /// 加载插件激活状态映射
    ///
    /// 首次启动或数据损坏时返回空 HashMap，**并真正清掉坏行**（R-06）——
    /// 旧实现损坏时返回 Err 且不重整：损坏行每次启动都失败，激活状态从此
    /// 永不恢复（与 approval S-10 同一 fail-visible 反面教材）。复位后下次
    /// 启动从干净状态继续。
    pub async fn load_activated_plugins(&self) -> crate::Result<HashMap<String, bool>> {
        match self.get(SYSTEM_PLUGIN_ID, ACTIVATION_STATE_KEY).await? {
            Some(value) => match serde_json::from_value::<HashMap<String, bool>>(value) {
                Ok(map) => Ok(map),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to parse activation state, resetting");
                    if let Err(clear_err) =
                        self.delete(SYSTEM_PLUGIN_ID, ACTIVATION_STATE_KEY).await
                    {
                        tracing::warn!(error = %clear_err, "Failed to clear corrupted activation state");
                    }
                    Ok(HashMap::new())
                }
            },
            None => Ok(HashMap::new()),
        }
    }
    // ==================== 旧 JSON 文件存储迁移（移动装配面，fork 迁入，票 06 批次 03） ====================
    //
    // 常编译（单形态票 02 M1）：移动宿主 lib.rs 启动迁移仍在消费（旧 JSON 文件存储
    // 存量数据 → 主库）；桌面宿主永不调用。绑定归位（T-05）时随移动宿主收口或退役。

    /// 旧版 JSON 文件存储 → 主库一次性迁移（批次 2b 自宿主 plugin/storage.rs 迁入；
    /// 旧 `app_data_dir/plugins/{plugin_id}.json` 导入 `plugin_storage` 表后删除，
    /// 旧读路径删除 = fail-visible 三形态①）
    ///
    /// - 幂等：逐 key `INSERT OR IGNORE`——DB 已有值优先（文件数据一律先于 DB
    ///   写入，绝不可能更新更新的值），重复执行无副作用；
    /// - 单文件全部成功导入后才删除 `.json`（中途失败不丢数据、不删文件）；
    /// - 只挑 `.json` 后缀（插件私有库 `plugins/<sanitized_id>.db` 不碰）；
    /// - 任一文件解析失败仅记日志跳过（best-effort，与 peer_migration 同款口径）。
    pub fn migrate_file_store_to_db(&self, app_data_dir: &std::path::Path) -> crate::Result<()> {
        let plugins_dir = app_data_dir.join(crate::system::constants::PLUGIN_STORAGE_DIR);
        if !plugins_dir.exists() {
            return Ok(());
        }
        let db = self.db.lock().expect("plugin storage db lock poisoned");
        let entries = match std::fs::read_dir(&plugins_dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(dir = %plugins_dir.display(), error = %e, "legacy plugin storage scan skipped");
                return Ok(());
            }
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let is_json = path
                .extension()
                .map(|ext| ext == std::ffi::OsStr::new("json"))
                .unwrap_or(false);
            if !is_json || !path.is_file() {
                continue;
            }
            let plugin_id = match path.file_stem().and_then(|s| s.to_str()) {
                Some(id) if !id.is_empty() => id.to_string(),
                _ => continue,
            };
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(plugin_id = %plugin_id, error = %e, "legacy storage file read skipped");
                    continue;
                }
            };
            let map: std::collections::HashMap<String, serde_json::Value> =
                match serde_json::from_str(&content) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(plugin_id = %plugin_id, error = %e, "legacy storage file parse skipped");
                        continue;
                    }
                };
            if map.is_empty() {
                continue;
            }
            let now = chrono::Utc::now().to_rfc3339();
            for (key, value) in &map {
                let json_str = serde_json::to_string(value)?;
                db.conn().execute(
                    "INSERT OR IGNORE INTO plugin_storage (plugin_id, key, value, updated_at) \
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![plugin_id, key, json_str, now],
                )?;
            }
            // 全部成功导入后才删除旧文件（旧读路径彻底移除，fail-visible ①）
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!(plugin_id = %plugin_id, error = %e, "legacy storage file removal failed");
            }
            tracing::info!(plugin_id = %plugin_id, count = map.len(), "legacy plugin storage file migrated to db");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Arc<Mutex<Database>> {
        let db = Database::new(&std::path::Path::new(":memory:")).unwrap();
        db.init_schema().unwrap();
        Arc::new(Mutex::new(db))
    }

    #[tokio::test]
    async fn test_storage_get_set_delete() {
        let db = test_db().await;
        let storage = PluginStorage::new(db);

        assert!(storage.get("plugin-1", "key1").await.unwrap().is_none());

        storage
            .set("plugin-1", "key1", serde_json::json!("hello"))
            .await
            .unwrap();
        let val = storage.get("plugin-1", "key1").await.unwrap();
        assert_eq!(val, Some(serde_json::json!("hello")));

        storage
            .set("plugin-1", "key1", serde_json::json!("world"))
            .await
            .unwrap();
        let val = storage.get("plugin-1", "key1").await.unwrap();
        assert_eq!(val, Some(serde_json::json!("world")));

        storage.delete("plugin-1", "key1").await.unwrap();
        assert!(storage.get("plugin-1", "key1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_storage_isolation() {
        let db = test_db().await;
        let storage = PluginStorage::new(db);

        storage
            .set("plugin-a", "key1", serde_json::json!("a"))
            .await
            .unwrap();
        storage
            .set("plugin-b", "key1", serde_json::json!("b"))
            .await
            .unwrap();

        assert_eq!(
            storage.get("plugin-a", "key1").await.unwrap(),
            Some(serde_json::json!("a"))
        );
        assert_eq!(
            storage.get("plugin-b", "key1").await.unwrap(),
            Some(serde_json::json!("b"))
        );

        storage.clear_all("plugin-a").await.unwrap();
        assert!(storage.get("plugin-a", "key1").await.unwrap().is_none());
        assert_eq!(
            storage.get("plugin-b", "key1").await.unwrap(),
            Some(serde_json::json!("b"))
        );
    }
}
