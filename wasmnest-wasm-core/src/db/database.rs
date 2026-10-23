//! Database wrapper
//!
//! 数据库连接管理

use rusqlite::Connection;
use std::path::Path;

/// Database wrapper
pub struct Database {
    conn: Connection,
}

/// 旧形状 `plugin_auth_records` 让路时的临时表名（事务内改名，提交前删除）
const LEGACY_AUTH_RECORDS_TABLE: &str = "plugin_auth_records__legacy_shape";

/// 库内 `plugin_auth_records` 的实际形状（[`Database::init_schema`] 的对账判据）
///
/// 只认「规范」与「已知旧形状」两类；其余一律 `Unrecognized` 交给调用点显性报错，
/// 不猜列映射（猜错 = 把用户裁决写成无意义行）。
enum AuthRecordsShape {
    /// 表不存在（新库 / 刚建过）
    Missing,
    /// 规范形状：含 `id`（`db/schema.sql` 建出的形状）
    Canonical,
    /// 往届宿主自持 schema 副本建出的旧形状：无 `id`、有 `decision`
    Legacy,
    /// 其它任何形状（附实际列名，供错误文案点名）
    Unrecognized(Vec<String>),
}

/// 列出一张表上的**显式**索引名（`CREATE INDEX` 产物）
///
/// 表级约束（PRIMARY KEY / UNIQUE）生成的自动索引（`origin` = `pk` / `u`）不可删、
/// 也不需要删（随表一起消失），故只收 `origin = 'c'`。
///
/// `table` 直接拼进 PRAGMA 语句：调用点只传本模块的常量表名，不接外部输入。
fn explicit_indexes(conn: &Connection, table: &str) -> crate::Result<Vec<String>> {
    let list_err =
        |e: rusqlite::Error| crate::AppError::Internal(format!("list indexes of {table}: {e}"));
    let mut stmt = conn
        .prepare(&format!("PRAGMA index_list({table})"))
        .map_err(list_err)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?, // name
                row.get::<_, String>(3)?, // origin
            ))
        })
        .map_err(list_err)?;
    let mut names = Vec::new();
    for row in rows {
        let (name, origin) = row.map_err(list_err)?;
        if origin == "c" {
            names.push(name);
        }
    }
    Ok(names)
}

impl Database {
    /// Create a new database connection
    pub fn new(path: &Path) -> crate::Result<Self> {
        let conn = Connection::open(path)?;
        Ok(Self { conn })
    }

    /// 从既有连接构造（常编译，票 02 M9 单形态化）：宿主主库连接由宿主侧打开
    /// （路径与锁归宿主），**建表与迁移真源在本 crate**——调用方开库后必须调
    /// [`Database::init_schema`]。宿主持有独立 DDL 副本会与 `db/schema.sql` 漂移：
    /// 2026-10-14 实证：宿主自持副本建出的旧 `plugin_auth_records` 缺 `id`，
    /// `security::fs_auth` 每次读取都报 `no such column: id`（按未命中处理 ⇒
    /// 授权记录面恒失败）。移动 host_domains/db 域消费；桌面宿主按需复用。
    pub fn from_connection(conn: Connection) -> Self {
        Self { conn }
    }

    /// Initialize database schema（单一事实源 = `db/schema.sql` + [`Self::run_migrations`]，幂等）
    ///
    /// 建表**之前**先做旧形状对账（[`Self::auth_records_shape`]）：`schema.sql` 的
    /// `CREATE TABLE IF NOT EXISTS` 对**已存在**的表零效果——若库里留着旧形状的
    /// `plugin_auth_records`（往届宿主自持 schema 副本建出的形状：无 `id` /
    /// `effect` / `ops` / `prefix_match` / `source` / `created_at`），不先让路就会
    /// 一直缺列，`security::fs_auth` 与 `security::auth_policy` 的读写全部失败。
    ///
    /// 对账 = 改名让路 → 由 `schema.sql` 建规范表 → 旧行按列语义搬回（`decision` →
    /// `effect`，来源标 `legacy`，`ops` / `prefix_match` 取规范缺省）→ 删让路表。
    /// 全程单事务：中途失败回滚，不留「旧表已改名、新表没行」的半迁移状态。
    /// 规范形状与新库零操作；无法识别的形状**显性报错**，不静默重建（会丢用户裁决）。
    pub fn init_schema(&self) -> crate::Result<()> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| crate::AppError::Internal(format!("begin schema transaction: {e}")))?;

        let legacy_set_aside = match self.auth_records_shape()? {
            AuthRecordsShape::Legacy => {
                tx.execute(
                    &format!(
                        "ALTER TABLE plugin_auth_records RENAME TO {LEGACY_AUTH_RECORDS_TABLE}"
                    ),
                    [],
                )
                .map_err(|e| {
                    crate::AppError::Internal(format!(
                        "set aside legacy-shaped plugin_auth_records: {e}"
                    ))
                })?;
                // 先摘掉挂在让路表上的**显式**索引：SQLite 改名会保留索引归属与名字，
                // 若库里已存在同名 `idx_auth_records_lookup`（旧表已被跑过一次内核
                // 初始化的状态——「拿旧库直接调 init_schema」就会留下它），`schema.sql`
                // 的 `CREATE INDEX IF NOT EXISTS` 会因同名索引仍在而跳过，随后
                // `DROP TABLE` 让路表又把索引一并带走 ⇒ 规范表永久缺查表索引
                // （静默降级：判定链能跑，只是每次查表都退化成全表扫）。
                for index in explicit_indexes(&tx, LEGACY_AUTH_RECORDS_TABLE)? {
                    tx.execute(&format!("DROP INDEX IF EXISTS \"{index}\""), [])
                        .map_err(|e| {
                            crate::AppError::Internal(format!(
                                "drop index {index} carried over by legacy plugin_auth_records: {e}"
                            ))
                        })?;
                }
                true
            }
            AuthRecordsShape::Unrecognized(cols) => {
                return Err(crate::AppError::Internal(format!(
                    "plugin_auth_records 形状无法识别（实际列：{cols:?}）：既非规范形状（含 id），\
                     也非旧宿主自持副本形状（无 id 但有 decision）。本表是授权记录真源，静默重建会丢\
                     用户已作出的允许/拒绝裁决——请人工迁移该表，或删除该库后重启以重建\
                     （重建后所有目标都会重新询问）"
                )));
            }
            AuthRecordsShape::Missing | AuthRecordsShape::Canonical => false,
        };

        tx.execute_batch(include_str!("schema.sql"))
            .map_err(|e| crate::AppError::Internal(format!("apply db/schema.sql: {e}")))?;

        if legacy_set_aside {
            tx.execute_batch(&format!(
                "INSERT INTO plugin_auth_records \
                   (plugin_id, resource, target, effect, ops, prefix_match, source, created_at) \
                 SELECT plugin_id, resource, target, decision, '[]', 0, 'legacy', updated_at \
                   FROM {LEGACY_AUTH_RECORDS_TABLE}; \
                 DROP TABLE {LEGACY_AUTH_RECORDS_TABLE};"
            ))
            .map_err(|e| {
                crate::AppError::Internal(format!(
                    "migrate legacy-shaped plugin_auth_records rows: {e}"
                ))
            })?;
        }

        tx.commit()
            .map_err(|e| crate::AppError::Internal(format!("commit schema transaction: {e}")))?;
        self.run_migrations()
    }

    /// 读库内 `plugin_auth_records` 的实际形状（对账判据；表不存在 = 空列集）
    fn auth_records_shape(&self) -> crate::Result<AuthRecordsShape> {
        let mut stmt = self
            .conn
            .prepare("PRAGMA table_info(plugin_auth_records)")
            .map_err(|e| {
                crate::AppError::Internal(format!("read plugin_auth_records shape: {e}"))
            })?;
        let cols = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<String>>>())
            .map_err(|e| {
                crate::AppError::Internal(format!("read plugin_auth_records shape: {e}"))
            })?;
        Ok(if cols.is_empty() {
            AuthRecordsShape::Missing
        } else if cols.iter().any(|c| c == "id") {
            AuthRecordsShape::Canonical
        } else if cols.iter().any(|c| c == "decision") {
            AuthRecordsShape::Legacy
        } else {
            AuthRecordsShape::Unrecognized(cols)
        })
    }

    /// Apply schema migrations for columns added after initial schema
    fn run_migrations(&self) -> crate::Result<()> {
        // v24（2026-09-22 认证记录下沉 + session_configs 删除）：主库
        // `pairings` / `connection_history` / `session_configs` 三表退役，
        // 其列级迁移（pairings 列追加 / session_configs CHECK 约束）随之删除。
        // 2026-09-23 用户裁定不再兼容旧版本存量用户：宿主侧 legacy 迁移链
        // （auth_records / quick_actions / session_db / task_data）整体退役，
        // 旧库滞留表不读不迁不清理（无残留迁移代码）。
        //
        // 2026-09-27 授权策略增强（票 01）：`plugin_auth_policies` /
        // `plugin_auth_records` 两表 + `idx_auth_records_lookup` 索引全由
        // `schema.sql` 的 `IF NOT EXISTS` 建出（单一事实源，见 AGENTS §9），
        // 无需列级迁移；幂等性由 `auth_tables_migration_is_idempotent` 与
        // `auth_tables_are_created_on_legacy_db` 两条锁覆盖。
        //
        // v33（2026-09-29 ADR 0033）：入场签发密钥的真源迁到认证中心，宿主不再
        // 读写入场密钥。`plugin_secrets` 里属主为 `host` 的那把 `jwt.key` 因此成为
        // 不可达的旧密钥材料——**清掉它**（幂等：不存在也视为成功）。
        //
        // 与「退役业务表不读不迁不清理」（v24 口径）的区别：那条针对的是**已退役的
        // 表**（留在那里无害、也不会被误读）；这里是**一张仍在用、仍会被插件读的
        // 表里的密钥行**——留着就是白给的攻击面（谁读到主库谁就拿到过期的入场密钥）。
        // 清理只按精确三元组（属主 `host` + 键名 `jwt.key`）删，不碰任何其它行。
        let purged = self
            .conn
            .execute(
                "DELETE FROM plugin_secrets WHERE plugin_id = 'host' AND key = 'jwt.key'",
                [],
            )
            .map_err(|e| crate::AppError::Internal(format!("purge retired host jwt key: {e}")))?;
        if purged > 0 {
            tracing::info!(
                purged_rows = purged,
                "db migration v33: purged retired host-owned entry-token signing key (ADR 0033)"
            );
        }

        // v34（2026-09-30 B-downsink）：生物凭证公钥真源迁到认证中心插件私有库
        // `auth_biometric_keys`（WASM 内 p256 验签），宿主不再读写信凭据材料。
        // 宿主 `plugin_secrets` 里形如 `biometric:<fingerprint>` 的旧行（v24–v33
        // 期间由宿主托管）因此成为不可达的死数据——**清掉**（v33 jwt.key 同款：
        // 在用的表里留死行 = 杂物）。幂等：按键名前缀 `biometric:` 精确删，不动
        // 其它任何行（含密钥环 `jwt.key` / `jwt.keyring`）。
        let bio_purged = self
            .conn
            .execute(
                "DELETE FROM plugin_secrets WHERE key LIKE 'biometric:%'",
                [],
            )
            .map_err(|e| crate::AppError::Internal(format!("purge retired biometric rows: {e}")))?;
        if bio_purged > 0 {
            tracing::info!(
                purged_rows = bio_purged,
                "db migration v34: purged retired host-hosted biometric public key rows (B-downsink)"
            );
        }
        Ok(())
    }

    /// Get a reference to the connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// 获取可变连接引用（事务/批量场景需要 `&mut Connection`）
    ///
    /// 调用方必须保证独占访问（宿主 DB 域持有全局 Mutex 锁时使用）
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 打开内存库并跑生产初始化（票据 21 修复：不再复制迁移逻辑，
    /// 直接调用 `init_schema`，使迁移被破坏时测试真实变红）
    fn open_in_memory_and_init() -> Database {
        let db = Database::new(Path::new(":memory:")).expect("open in-memory db");
        db.init_schema().expect("init schema");
        db
    }

    /// sqlite_master 里某类对象的同名条目数（建表 / 建索引幂等的唯一可观测面）
    fn master_count(db: &Database, kind: &str, name: &str) -> i64 {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
                rusqlite::params![kind, name],
                |row| row.get(0),
            )
            .expect("sqlite_master count query")
    }

    /// 授权两表 + 索引的建表语句幂等（spec §5.1 / C13 正例）：
    /// 同一库连跑两次生产初始化，结果一致，且已播种的授权数据不被清掉
    #[test]
    fn auth_tables_migration_is_idempotent() {
        let db = open_in_memory_and_init();
        db.conn()
            .execute(
                "INSERT INTO plugin_auth_policies (plugin_id, resource, strategy, updated_at) \
                 VALUES ('com.wasmnest.test', 'fs', 'always_ask', 1)",
                [],
            )
            .expect("seed policy");
        db.conn()
            .execute(
                "INSERT INTO plugin_auth_records \
                 (plugin_id, resource, target, effect, ops, prefix_match, source, created_at) \
                 VALUES ('com.wasmnest.test', 'fs', '/tmp/authed', 'allow', '[\"read\"]', 0, 'user', 1)",
                [],
            )
            .expect("seed record");

        db.init_schema().expect("second init_schema must succeed");

        assert_eq!(
            master_count(&db, "table", "plugin_auth_policies"),
            1,
            "建表语句必须幂等：不得重复建 / 不得消失"
        );
        assert_eq!(master_count(&db, "table", "plugin_auth_records"), 1);
        assert_eq!(
            master_count(&db, "index", "idx_auth_records_lookup"),
            1,
            "建索引语句必须幂等"
        );
        let policies: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM plugin_auth_policies", [], |r| {
                r.get(0)
            })
            .expect("count policies");
        let records: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM plugin_auth_records", [], |r| r.get(0))
            .expect("count records");
        assert_eq!(
            (policies, records),
            (1, 1),
            "重复初始化不得清掉已有授权数据"
        );
    }

    /// C13 反例：旧库（有 `fs_granted_paths`、无授权两表）跑一次生产初始化
    /// 即建表成功；旧记录原样保留（存量用户零感知，spec §5.2）
    ///
    /// 旧库形态用「生产初始化后删掉新表」构造：既得到真实的历史库形状
    /// （settings / plugin_storage / plugin_secrets + 旧 fs 授权数据），
    /// 又不必在测试里复制一份历史 DDL（复制即漂移源）。
    #[test]
    fn auth_tables_are_created_on_legacy_db() {
        let db = open_in_memory_and_init();
        db.conn()
            .execute(
                "INSERT INTO plugin_storage (plugin_id, key, value, updated_at) \
                 VALUES ('com.wasmnest.agent-hub', 'fs_granted_paths', '[\"/legacy/dir\"]', '2026-09-01T00:00:00Z')",
                [],
            )
            .expect("seed legacy fs grant");
        db.conn()
            .execute_batch("DROP TABLE plugin_auth_records; DROP TABLE plugin_auth_policies;")
            .expect("simulate legacy db without auth tables");
        assert_eq!(master_count(&db, "table", "plugin_auth_policies"), 0);
        assert_eq!(
            master_count(&db, "index", "idx_auth_records_lookup"),
            0,
            "索引随表一并删除，重新初始化必须重建它"
        );

        db.init_schema().expect("init on legacy db must succeed");

        assert_eq!(master_count(&db, "table", "plugin_auth_policies"), 1);
        assert_eq!(master_count(&db, "table", "plugin_auth_records"), 1);
        assert_eq!(master_count(&db, "index", "idx_auth_records_lookup"), 1);
        let legacy: String = db
            .conn()
            .query_row(
                "SELECT value FROM plugin_storage \
                 WHERE plugin_id = 'com.wasmnest.agent-hub' AND key = 'fs_granted_paths'",
                [],
                |r| r.get(0),
            )
            .expect("legacy grant must survive");
        assert_eq!(
            legacy, "[\"/legacy/dir\"]",
            "旧授权记录不得被迁移或清理（读路径回退才认它）"
        );
    }

    /// 往届宿主自持 schema 副本的旧 `plugin_auth_records` DDL（历史夹具，冻结不改）
    ///
    /// 生产代码已无这份 DDL（单一真源 = `db/schema.sql`），但已装设备上仍可能有
    /// 由它建出的表，故必须能在测试里原样重现。**只作为迁移输入**——改它等于把
    /// 迁移测试改成恒真。（源副本 2026-10-14 已随「宿主 schema 归位内核真源」整面退役。）
    const LEGACY_AUTH_RECORDS_DDL: &str = "\
CREATE TABLE plugin_auth_records (\n    plugin_id   TEXT NOT NULL,\n    target      TEXT NOT NULL,\n    resource    TEXT NOT NULL,\n    decision    TEXT NOT NULL,\n    updated_at  INTEGER NOT NULL,\n    PRIMARY KEY (plugin_id, target, resource)\n);";

    /// 建一张旧形状授权记录表并播种两条（fs allow / network deny）
    fn open_legacy_auth_records_db() -> Database {
        let db = Database::new(Path::new(":memory:")).expect("open in-memory db");
        db.conn()
            .execute_batch(LEGACY_AUTH_RECORDS_DDL)
            .expect("create legacy-shaped plugin_auth_records");
        db.conn()
            .execute(
                "INSERT INTO plugin_auth_records (plugin_id, target, resource, decision, updated_at) \
                 VALUES ('com.wasmnest.test', '/tmp/authed', 'fs', 'allow', 111), \
                        ('com.wasmnest.test', 'https://example.com', 'network', 'deny', 222)",
                [],
            )
            .expect("seed legacy rows");
        db
    }

    /// 全量授权记录快照（列序固定，便于整表比较）
    #[allow(
        clippy::type_complexity,
        reason = "测试内整表快照，内联元组比新建具名类型更直观"
    )]
    fn auth_record_rows(
        db: &Database,
    ) -> Vec<(String, String, String, String, String, i64, String, i64)> {
        let mut stmt = db
            .conn()
            .prepare(
                "SELECT plugin_id, resource, target, effect, ops, prefix_match, source, created_at \
                   FROM plugin_auth_records ORDER BY plugin_id, resource, target",
            )
            .expect("prepare auth records");
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .expect("query auth records");
        rows.map(|r| r.expect("row")).collect()
    }

    /// 旧形状授权记录（往届宿主自持副本建出的形状）对账到规范形状
    ///
    /// 判据：① 列补齐（`id` 在册）；② **行不丢且列语义映射正确**（`decision` →
    /// `effect`，`updated_at` → `created_at`，来源标 `legacy`，`ops` / `prefix_match`
    /// 取规范缺省）；③ 让路表不残留；④ 查表索引建出（判定链读模型依赖它）。
    #[test]
    fn legacy_shaped_auth_records_are_migrated() {
        let db = open_legacy_auth_records_db();

        db.init_schema().expect("init schema over legacy shape");

        let cols: Vec<String> = {
            let mut stmt = db
                .conn()
                .prepare("PRAGMA table_info(plugin_auth_records)")
                .expect("prepare table_info");
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .expect("query table_info");
            rows.map(|r| r.expect("row")).collect()
        };
        assert!(
            cols.iter().any(|c| c == "id"),
            "对账后必须是规范形状: {cols:?}"
        );

        assert_eq!(
            auth_record_rows(&db),
            vec![
                (
                    "com.wasmnest.test".into(),
                    "fs".into(),
                    "/tmp/authed".into(),
                    "allow".into(),
                    "[]".into(),
                    0,
                    "legacy".into(),
                    111,
                ),
                (
                    "com.wasmnest.test".into(),
                    "network".into(),
                    "https://example.com".into(),
                    "deny".into(),
                    "[]".into(),
                    0,
                    "legacy".into(),
                    222,
                ),
            ],
            "旧行必须按列语义搬进规范表（决策保留、来源标 legacy）"
        );
        assert_eq!(
            master_count(&db, "table", LEGACY_AUTH_RECORDS_TABLE),
            0,
            "让路表必须删除"
        );
        assert_eq!(
            master_count(&db, "index", "idx_auth_records_lookup"),
            1,
            "查表索引必须建出"
        );
    }

    /// 对账幂等：连跑两次 `init_schema` 结果一致（不多行、不重复改名、不报错）
    #[test]
    fn legacy_auth_records_migration_is_idempotent() {
        let db = open_legacy_auth_records_db();
        db.init_schema().expect("first init");
        let first = auth_record_rows(&db);
        assert_eq!(first.len(), 2, "首次对账必须搬回两行");

        db.init_schema().expect("second init (idempotent)");

        assert_eq!(auth_record_rows(&db), first, "重复初始化不得再迁移或丢行");
        assert_eq!(master_count(&db, "table", LEGACY_AUTH_RECORDS_TABLE), 0);
    }

    /// 让路前的陈旧索引清理：旧表上已挂着同名查表索引时（旧库被直接跑过一次内核
    /// 初始化的状态），对账后规范表必须仍拿到索引——否则 `CREATE INDEX IF NOT
    /// EXISTS` 被同名索引挡掉、`DROP TABLE` 让路表时又把索引一并带走，留下
    /// 「能跑但每次查表都全表扫」的静默降级。
    #[test]
    fn legacy_migration_rebuilds_lookup_index_when_name_is_taken() {
        let db = open_legacy_auth_records_db();
        db.conn()
            .execute_batch(
                "CREATE INDEX idx_auth_records_lookup \
                   ON plugin_auth_records(plugin_id, resource, target);",
            )
            .expect("plant stale lookup index on legacy table");

        db.init_schema()
            .expect("init schema over legacy shape carrying a stale index");

        assert_eq!(
            master_count(&db, "index", "idx_auth_records_lookup"),
            1,
            "规范表必须拿到查表索引（不得被让路表的同名索引挡掉）"
        );
        let indexed_cols: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pragma_index_info('idx_auth_records_lookup')",
                [],
                |r| r.get(0),
            )
            .expect("index column count");
        assert_eq!(
            indexed_cols, 3,
            "索引必须建在 (plugin_id, resource, target)"
        );
        assert_eq!(master_count(&db, "table", LEGACY_AUTH_RECORDS_TABLE), 0);
    }

    /// 反例（非恒真）：已是规范形状的库不被对账改写——`source` 保持 `user`，
    /// 已播种行不重复不重写（防对账条件写宽成「每次重建」）
    #[test]
    fn canonical_auth_records_are_left_untouched() {
        let db = open_in_memory_and_init();
        db.conn()
            .execute(
                "INSERT INTO plugin_auth_records \
                 (plugin_id, resource, target, effect, ops, prefix_match, source, created_at) \
                 VALUES ('com.wasmnest.test', 'fs', '/tmp/authed', 'allow', '[\"read\"]', 1, 'user', 7)",
                [],
            )
            .expect("seed canonical row");

        db.init_schema().expect("re-init over canonical shape");

        assert_eq!(
            auth_record_rows(&db),
            vec![(
                "com.wasmnest.test".into(),
                "fs".into(),
                "/tmp/authed".into(),
                "allow".into(),
                "[\"read\"]".into(),
                1,
                "user".into(),
                7,
            )],
            "规范数据必须原样保留（不改 source / ops / prefix_match）"
        );
        assert_eq!(
            master_count(&db, "table", LEGACY_AUTH_RECORDS_TABLE),
            0,
            "规范形状不得凭空让路"
        );
    }

    /// 未知形状 fail-visible：既不迁也不重建，报错点名表与实际列
    /// （静默重建 = 悄悄丢掉用户已作出的允许/拒绝裁决）
    #[test]
    fn unrecognized_auth_records_shape_fails_visible() {
        let db = Database::new(Path::new(":memory:")).expect("open in-memory db");
        db.conn()
            .execute_batch("CREATE TABLE plugin_auth_records (mystery_column TEXT NOT NULL);")
            .expect("create unrecognized-shaped table");

        let err = db
            .init_schema()
            .expect_err("未知形状必须报错，不得静默重建");

        let msg = format!("{err}");
        assert!(msg.contains("plugin_auth_records"), "错误必须点名表: {msg}");
        assert!(
            msg.contains("mystery_column"),
            "错误必须给出实际列名: {msg}"
        );
    }

    /// v24（2026-09-22）：session_configs / pairings / connection_history 三表退役，
    /// 新增表只读主库 schema；旧表不建（init_schema 零残留表断言）
    #[test]
    fn retired_tables_are_not_created() {
        let db = open_in_memory_and_init();
        for table in ["session_configs", "pairings", "connection_history"] {
            let count: i64 = db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    rusqlite::params![table],
                    |row| row.get(0),
                )
                .expect("count query");
            assert_eq!(count, 0, "退役表 {table} 不得被建出");
        }
    }

    /// v33（ADR 0033）+ v34（B-downsink）：宿主属主的入场签发密钥行与宿主托管
    /// 的生物公钥行被清掉，**且只清这两类**
    ///
    /// 判据：
    /// ① 旧库（有那些行）跑完迁移后不再有；
    /// ② 幂等（连跑两次结果一致，不报错）；
    /// ③ **不误伤**——密钥环（`jwt.key` / `jwt.keyring`，v33 后真源在插件
    ///    属主 / 中心密钥环）必须原样保留。
    #[test]
    fn retired_host_entry_token_key_is_purged_without_touching_others() {
        let dir = std::env::temp_dir().join(format!("db-purge-jwtkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let db_path = dir.join("wasmnest.db");
        // 造一个「旧库」：五条密钥行同表并存
        {
            let db = Database::new(&db_path).expect("open");
            db.init_schema().expect("init schema");
            for (owner, key, value) in [
                ("host", "jwt.key", "aa"),
                ("com.wasmnest.terminal-session", "jwt.key", "bb"),
                ("com.wasmnest.terminal-session", "jwt.keyring", "cc"),
                // B-downsink 前的宿主托管生物公钥（v24–v33 期间属主 = 插件）
                ("com.wasmnest.terminal-session", "biometric:fp-abc", "dd"),
                ("host", "biometric:fp-xyz", "ee"),
            ] {
                db.conn()
                    .execute(
                        "INSERT INTO plugin_secrets (plugin_id, key, value, updated_at) \
                         VALUES (?1, ?2, ?3, '2026-09-29')",
                        rusqlite::params![owner, key, value],
                    )
                    .expect("seed secret row");
            }
        }

        // 直接读 `plugin_secrets` 的 (属主, 键名) 清单
        fn secret_rows(db: &Database) -> Vec<(String, String)> {
            let mut stmt = db
                .conn()
                .prepare("SELECT plugin_id, key FROM plugin_secrets ORDER BY plugin_id, key")
                .expect("prepare");
            let mapped = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .expect("query");
            mapped.map(|r| r.expect("row")).collect()
        }

        {
            let db = Database::new(&db_path).expect("reopen");
            db.run_migrations().expect("first migration");
            let remaining = secret_rows(&db);
            assert!(
                !remaining.contains(&("host".to_string(), "jwt.key".to_string())),
                "宿主入场密钥行必须被清掉: {remaining:?}"
            );
            // v34：宿主托管的生物公钥行（不论属主）必须被清掉
            assert!(
                !remaining.contains(&(
                    "com.wasmnest.terminal-session".to_string(),
                    "biometric:fp-abc".to_string()
                )),
                "B-downsink 后宿主不得再托管生物公钥（插件属主行）: {remaining:?}"
            );
            assert!(
                !remaining.contains(&("host".to_string(), "biometric:fp-xyz".to_string())),
                "B-downsink 后宿主不得再托管生物公钥（host 属主行）: {remaining:?}"
            );
            for keep in [
                ("com.wasmnest.terminal-session", "jwt.key"),
                ("com.wasmnest.terminal-session", "jwt.keyring"),
            ] {
                assert!(
                    remaining.contains(&(keep.0.to_string(), keep.1.to_string())),
                    "不得误伤 {keep:?}: {remaining:?}"
                );
            }
            // 第二次迁移：幂等（不报错、不再删任何行）
            db.run_migrations().expect("second migration");
            assert_eq!(secret_rows(&db), remaining, "重复迁移必须幂等");
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
