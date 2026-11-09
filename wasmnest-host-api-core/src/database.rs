//! `host-plugin-database`（插件私有库 5 原语）实现层
//!
//! 自桌面 `packages/wasmnest-wasm-core/src/host_api/database.rs` 上移（票 18 批次 3），
//! **2026-10-09 双端机制决策（用户指令）收缩**：主库由 wasm-core 管理，**不给任何
//! wasm-app / 插件直接调用的方法**——`host-database`（主库）接口自双端 WIT 面移除，
//! 本层随之删除主库机制（authorizer 引擎层纵深 / 主库前缀校验 / 主库超时包裹），
//! 只保留**插件私有库面**（每插件属主分区的独立 SQLite 库）：
//!
//! 权限门（[`PermissionGate`] 参数化，`storage` 位）→ 语句超时护栏
//! （[`with_statement_timeout`]，progress handler 硬中断）→ 结果集护栏（行数 /
//! 字节双上限）→ 批次事务封装（[`execute_batch_on_conn`]，裸事务控制拒绝）。
//!
//! 插件自身需要数据库能力 = 声明 `storage` 权限（宿主私有库懒创建于
//! `app_data_dir/plugins/<id>.db`，整库归本插件、无前缀约束、停用回收）。
//!
//! ## 错误文本纪律
//!
//! guest 可见错误文本逐字保留：权限拒绝文案经 [`PermissionGate::deny_error`] 由
//! 各端传入；执行失败统一包 `database error: {e}`。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use crate::gate::PermissionGate;

// ==================== 执行护栏常量（真源已上移契约仓，本处保旧路径） ====================
//
// 2026-11-08（P0 默认形态依赖边界）：真源迁 `wasmnest-contract`——这四个常量不含机制
// 实现、不含平台判断，却把「叶子地基 `server-base`」反向拖进本实现层。本模块只做
// re-export，保 `wasmnest_host_api_core::database::*` 既有导入路径。

pub use wasmnest_contract::{
    PLUGIN_DB_EXECUTE_BATCH_MAX_STATEMENTS, PLUGIN_DB_QUERY_MAX_BYTES, PLUGIN_DB_QUERY_MAX_ROWS,
    PLUGIN_DB_STATEMENT_TIMEOUT_SECS,
};

// ==================== 参数绑定 ====================

/// 解析参数绑定 JSON 数组字符串（空串视为空数组）
pub fn parse_params_json(params_json: &str) -> Result<Vec<serde_json::Value>, String> {
    if params_json.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(params_json).map_err(|e| format!("invalid params JSON array: {}", e))
}

/// 解析 execute-batch 的 sqls-json（SQL 字符串数组）
pub fn parse_sqls_json(sqls_json: &str) -> Result<Vec<String>, String> {
    serde_json::from_str::<Vec<String>>(sqls_json)
        .map_err(|e| format!("invalid sqls JSON array: {}", e))
}

/// 参数无法无损绑定到 SQLite（不静默降级成 `0.0` / 空串）
#[derive(Debug)]
struct UnbindableJsonValue(&'static str);

impl std::fmt::Display for UnbindableJsonValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON value cannot be bound to SQLite: {}", self.0)
    }
}

impl std::error::Error for UnbindableJsonValue {}

/// 将 JSON 参数绑定到预编译语句（1-based 索引，rusqlite 真绑定，防注入）
///
/// 无法无损转换的输入（超出 f64 范围的数字 / 序列化失败的数组对象）**报错**，
/// 不落到 `0.0` / 空串——静默降级会让插件拿到看似成功却已丢数据的 round-trip。
pub fn bind_json_params(
    stmt: &mut rusqlite::Statement<'_>,
    params: &[serde_json::Value],
) -> rusqlite::Result<()> {
    for (i, p) in params.iter().enumerate() {
        let idx = i + 1;
        match p {
            serde_json::Value::Null => stmt.raw_bind_parameter(idx, rusqlite::types::Null)?,
            serde_json::Value::Bool(b) => stmt.raw_bind_parameter(idx, *b)?,
            serde_json::Value::Number(n) => {
                // 整数优先；非整数按浮点绑定
                if let Some(iv) = n.as_i64() {
                    stmt.raw_bind_parameter(idx, iv)?;
                } else if let Some(fv) = n.as_f64() {
                    stmt.raw_bind_parameter(idx, fv)?;
                } else {
                    return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
                        UnbindableJsonValue("number out of range"),
                    )));
                }
            }
            serde_json::Value::String(s) => stmt.raw_bind_parameter(idx, s.as_str())?,
            // 数组/对象 fallback：序列化为 JSON 字符串存储
            other => {
                let json = serde_json::to_string(other)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                stmt.raw_bind_parameter(idx, json)?;
            }
        }
    }
    Ok(())
}

/// 执行参数绑定 SQL，返回受影响行数
pub fn execute_with_params(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[serde_json::Value],
) -> Result<usize, String> {
    reject_unsafe_sql(sql)?;
    let mut stmt = conn.prepare(sql).map_err(|e| format!("prepare: {}", e))?;
    bind_json_params(&mut stmt, params).map_err(|e| format!("bind: {}", e))?;
    stmt.raw_execute().map_err(|e| format!("execute: {}", e))
}

// ==================== 结果集护栏 ====================

/// 结果集护栏：行数 / 序列化字节双上限逐行检查（安全边界，不可由插件调整）
///
/// 触发记结构化 warn!（plugin_id 字段），错误消息指明上限并引导插件加 LIMIT
/// 或分批。行数上限先于字节测量判断。
pub fn push_row_capped(
    plugin_id: &str,
    rows_out: &mut Vec<serde_json::Value>,
    total_bytes: &mut usize,
    row: serde_json::Value,
) -> Result<(), String> {
    if rows_out.len() >= PLUGIN_DB_QUERY_MAX_ROWS {
        tracing::warn!(
            plugin_id = %plugin_id,
            limit = PLUGIN_DB_QUERY_MAX_ROWS,
            "plugin query result exceeded row limit"
        );
        return Err(format!(
            "database error: query result exceeds {} rows limit (add LIMIT or batch)",
            PLUGIN_DB_QUERY_MAX_ROWS
        ));
    }
    *total_bytes += serde_json::to_vec(&row)
        .map_err(|e| format!("serialize row to measure size: {}", e))?
        .len();
    if *total_bytes > PLUGIN_DB_QUERY_MAX_BYTES {
        tracing::warn!(
            plugin_id = %plugin_id,
            limit = PLUGIN_DB_QUERY_MAX_BYTES,
            "plugin query result exceeded byte limit"
        );
        return Err(format!(
            "database error: query result exceeds {} bytes limit (add LIMIT or batch)",
            PLUGIN_DB_QUERY_MAX_BYTES
        ));
    }
    rows_out.push(row);
    Ok(())
}

/// 执行查询并将结果集转换为 JSON 行数组（含结果集护栏：行数/字节上限）
///
/// 逐行计数而非全量物化，超限立即截断报错。
pub fn query_to_json(
    plugin_id: &str,
    conn: &rusqlite::Connection,
    sql: &str,
) -> Result<serde_json::Value, String> {
    // prepare + step 能执行的文件边界语句（ATTACH / VACUUM INTO）必须在这里就拒：
    // 它们返回 0 行，旧实现会「成功」并把副作用留在缓存的连接上。
    reject_unsafe_sql(sql)?;
    let mut stmt = conn.prepare(sql).map_err(|e| format!("prepare: {}", e))?;

    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .map(|i| {
            stmt.column_name(i)
                .map(|s| s.to_string())
                .unwrap_or_else(|_| format!("col{}", i))
        })
        .collect();

    let mut rows_out: Vec<serde_json::Value> = Vec::new();
    let mut total_bytes: usize = 0;
    let rows = stmt
        .query_map([], |row| {
            let mut map = serde_json::Map::new();
            for (i, col_name) in column_names.iter().enumerate() {
                let value = column_to_json(row, i);
                map.insert(col_name.clone(), value);
            }
            Ok(map)
        })
        .map_err(|e| format!("query_map: {}", e))?;
    for row in rows {
        let map = row.map_err(|e| format!("row: {}", e))?;
        push_row_capped(
            plugin_id,
            &mut rows_out,
            &mut total_bytes,
            serde_json::Value::Object(map),
        )?;
    }

    Ok(serde_json::Value::Array(rows_out))
}

/// 参数绑定查询 → JSON 行数组（含结果集护栏：行数/字节上限）
pub fn query_with_params_to_json(
    plugin_id: &str,
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[serde_json::Value],
) -> Result<serde_json::Value, String> {
    reject_unsafe_sql(sql)?;
    let mut stmt = conn.prepare(sql).map_err(|e| format!("prepare: {}", e))?;
    bind_json_params(&mut stmt, params).map_err(|e| format!("bind: {}", e))?;

    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .map(|i| {
            stmt.column_name(i)
                .map(|s| s.to_string())
                .unwrap_or_else(|_| format!("col{}", i))
        })
        .collect();

    let mut rows_out: Vec<serde_json::Value> = Vec::new();
    let mut total_bytes: usize = 0;
    let mut rows = stmt.raw_query();
    while let Some(row) = rows.next().map_err(|e| format!("next: {}", e))? {
        let mut map = serde_json::Map::new();
        for (i, col_name) in column_names.iter().enumerate() {
            map.insert(col_name.clone(), column_to_json(row, i));
        }
        push_row_capped(
            plugin_id,
            &mut rows_out,
            &mut total_bytes,
            serde_json::Value::Object(map),
        )?;
    }

    Ok(serde_json::Value::Array(rows_out))
}

/// 将 rusqlite 行的指定列转换为 serde_json::Value
///
/// **按 SQLite 的存储类型分支**（`ValueRef`），不再「能读成 i64 就当整数」：
/// `1.0` / `SUM(...)` 这类 REAL 必须回浮点，否则插件 round-trip 后类型漂移
/// （WIT 面只给 `string`，错了也不报）。BLOB 转 hex 字符串，TEXT 按 UTF-8 读。
pub fn column_to_json(row: &rusqlite::Row<'_>, col_index: usize) -> serde_json::Value {
    use rusqlite::types::ValueRef;

    match row.get_ref(col_index) {
        Ok(ValueRef::Null) => serde_json::Value::Null,
        Ok(ValueRef::Integer(v)) => serde_json::Value::Number(serde_json::Number::from(v)),
        // 非有限值（±Inf / NaN）JSON 无法表达：显式字符串化，不伪装成合法数字 0
        Ok(ValueRef::Real(v)) => serde_json::Number::from_f64(v)
            .map(serde_json::Value::Number)
            .unwrap_or_else(|| {
                let label = if v.is_infinite() {
                    if v.is_sign_positive() {
                        "Infinity"
                    } else {
                        "-Infinity"
                    }
                } else {
                    "NaN"
                };
                serde_json::Value::String(label.to_string())
            }),
        Ok(ValueRef::Text(t)) => serde_json::Value::String(String::from_utf8_lossy(t).into_owned()),
        Ok(ValueRef::Blob(v)) => {
            use std::fmt::Write;
            let mut hex = String::with_capacity(v.len() * 2);
            for byte in v {
                write!(hex, "{:02x}", byte).unwrap();
            }
            serde_json::Value::String(hex)
        }
        // 读取失败（类型不可读 / 越界）不是可表达的值：按 NULL 处理（与旧行为同向）
        Err(_) => serde_json::Value::Null,
    }
}

// ==================== 语句超时护栏 ====================

/// SQL 执行超时护栏：连接上安装 SQLite progress handler，运行 `f` 后（含 panic 路径）
/// 经 Drop 守卫自动移除 handler。
///
/// SQLite progress handler 每 `num_ops`（1000）次虚拟机步回调一次；超时即返回 true
/// （中断），后续 `sqlite3_step` 返回 SQLITE_INTERRUPT → 映射为「查询超时」错误。
/// 超时上限不可由插件调整（安全边界）；触发记结构化 warn!（plugin_id 字段）。
pub fn with_statement_timeout<T>(
    plugin_id: &str,
    conn: &rusqlite::Connection,
    timeout: Duration,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    let timed_out = Arc::new(AtomicBool::new(false));
    let flag = timed_out.clone();
    conn.progress_handler(
        1000,
        Some(move || {
            if started.elapsed() > timeout {
                flag.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        }),
    );
    let _guard = ProgressHandlerGuard { conn };
    let result = f(conn);
    if timed_out.load(Ordering::Relaxed) {
        tracing::warn!(
            plugin_id = %plugin_id,
            timeout_secs = timeout.as_secs(),
            "plugin SQL statement timed out and was interrupted"
        );
        Err(format!(
            "database error: statement timed out after {}s (global limit: {}s)",
            timeout.as_secs(),
            PLUGIN_DB_STATEMENT_TIMEOUT_SECS
        ))
    } else {
        result
    }
}

/// progress handler 生命周期守卫：作用域结束（含 panic 展开）时移除 handler
struct ProgressHandlerGuard<'a> {
    conn: &'a rusqlite::Connection,
}

impl Drop for ProgressHandlerGuard<'_> {
    fn drop(&mut self) {
        self.conn.progress_handler(0, None::<fn() -> bool>);
    }
}

// ==================== 裸事务控制拒绝 + 批次事务 ====================

/// 事务控制语句白名单检测：拒绝以裸事务控制语句开头/结尾的 execute
///
/// 跨调用裸事务（BEGIN → 多次 execute → COMMIT）期间会留下未提交窗口（崩溃即
/// 丢数据、锁被长期持有）——execute-batch 是唯一受支持的事务入口（单次调用内
/// 持有事务）。
///
/// 尽力而为的检测：去除首尾空白与前导注释后取首/末 token 匹配白名单，
/// 覆盖 BEGIN/COMMIT/END/ROLLBACK/SAVEPOINT/RELEASE 常见形态，不做完整 SQL 解析。
pub fn reject_bare_transaction_control(sql: &str) -> Result<(), String> {
    let s = strip_leading_sql_comments(sql);
    let first = s.split_whitespace().next().map(normalize_sql_token);
    let last = s.split_whitespace().next_back().map(normalize_sql_token);
    let is_bare_transaction = matches!(
        first.as_deref(),
        Some("begin" | "commit" | "end" | "rollback" | "savepoint" | "release")
    ) || matches!(
        last.as_deref(),
        Some("commit" | "rollback" | "end" | "release")
    );
    if is_bare_transaction {
        return Err(
            "database error: bare transaction control statements are rejected at execute level \
             (use execute-batch for multi-statement transactions)"
                .to_string(),
        );
    }
    Ok(())
}

/// 剥掉前导空白与最多 8 层行/块注释（病态输入不无限剥）
fn strip_leading_sql_comments(sql: &str) -> &str {
    let mut s = sql.trim();
    for _ in 0..8 {
        if let Some(rest) = s.strip_prefix("--") {
            s = rest
                .split_once('\n')
                .map(|(_, after)| after)
                .unwrap_or("")
                .trim_start();
        } else if let Some(rest) = s.strip_prefix("/*") {
            s = rest
                .split_once("*/")
                .map(|(_, after)| after)
                .unwrap_or("")
                .trim_start();
        } else {
            break;
        }
    }
    s
}

/// 归一化 SQL token：去尾分号 + 小写（用于事务控制白名单匹配）
pub fn normalize_sql_token(t: &str) -> String {
    t.trim_end_matches(';').to_lowercase()
}

// ==================== 文件边界语句拒绝 ====================

/// 拒绝以文件为目标的 SQL 语句（`ATTACH` / `DETACH` / `VACUUM`）
///
/// `ATTACH DATABASE '<file>'` 在 `prepare` / `step` 期把任意 SQLite 文件挂到当前
/// 连接（返回 0 行，旧实现不报错，且挂载状态留在缓存的连接里）——绕过 `fs_auth`
/// 的文件授权模型，可读其它插件私有库与宿主主库；`VACUUM INTO '<file>'` 同样是
/// 「0 行语句 + 任意文件写」。
///
/// 纵深三层：
/// - 连接层（`wasmnest-wasm-core` 的 `Database::new`）：`SQLITE_LIMIT_ATTACHED = 0`
///   + authorizer 拒 Attach / Detach；
/// - 本函数（SQL 文本首 token）：覆盖 authorizer **不覆盖**的 `VACUUM INTO`，
///   并在语句还没到 SQLite 时就给出可读错误；
/// - 五个 WIT 原语入口全部经过本函数（`execute` / `execute_params` / `query` /
///   `query_params` / `execute_batch`）。
///
/// 检测是首 token 白名单（与 [`reject_bare_transaction_control`] 同粒度）：SQLite
/// 的 `prepare` 只执行第一条语句，`ATTACH` 只能出现在语句开头；前导注释会被剥掉。
pub fn reject_file_boundary_sql(sql: &str) -> Result<(), String> {
    let first = strip_leading_sql_comments(sql)
        .split_whitespace()
        .next()
        .map(normalize_sql_token);
    match first.as_deref() {
        Some(token @ ("attach" | "detach" | "vacuum")) => Err(format!(
            "database error: {token} is rejected (plugin databases are confined to their own file)"
        )),
        _ => Ok(()),
    }
}

/// 所有 execute / query 入口共用的 SQL 护栏（裸事务控制 + 文件边界语句）
///
/// # 单语句契约
/// 每个入口只执行**第一条**语句：`prepare` 编译后停在首条语句末尾，尾部语句
/// （`"A; B"` 的 `B`）既不执行也不报错——这是本护栏的前提（尾部若被执行，
/// ATTACH / VACUUM / 事务控制的文本检查就不再覆盖全部执行面）。批处理请走
/// [`execute_batch_on_conn`] / `execute-batch`（逐条传入，每条独立检查；且
/// rusqlite 的 `extra_check` 会让带尾部的单条元素直接报 `MultipleStatement`）。
pub fn reject_unsafe_sql(sql: &str) -> Result<(), String> {
    reject_bare_transaction_control(sql)?;
    reject_file_boundary_sql(sql)
}

/// 事务内顺序执行多语句：任一句失败整体回滚，返回受影响行数合计
///
/// 经 `unchecked_transaction`（rusqlite 0.32 安全 API，运行时检查嵌套，调用方持有
/// 数据库全局锁独占连接，无并发风险）在 `&Connection` 上开启事务；事务对象 Drop 时
/// 未提交自动回滚。超时护栏由外层 [`with_statement_timeout`] 覆盖整个批次。
///
/// 每语句先做裸事务控制 / 文件边界拒绝（batch 内部也不允许 BEGIN / ATTACH 等，
/// 提前拒绝给可读文案）。
pub fn execute_batch_on_conn(conn: &rusqlite::Connection, sqls: &[String]) -> Result<u32, String> {
    for sql in sqls {
        reject_unsafe_sql(sql)?;
    }
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("begin transaction: {}", e))?;
    let mut total_affected: u32 = 0;
    for sql in sqls {
        let affected = tx
            .execute(sql.as_str(), [])
            .map_err(|e| format!("execute '{}': {}", sql, e))?;
        // 与 adapter 同口径：WIT 返回 u32，超限饱和而不是回绕
        let affected = u32::try_from(affected).unwrap_or(u32::MAX);
        total_affected = total_affected.checked_add(affected).ok_or_else(|| {
            "database error: execute-batch affected row count overflow".to_string()
        })?;
    }
    tx.commit()
        .map_err(|e| format!("commit transaction: {}", e))?;
    Ok(total_affected)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 内存库夹具
    fn mem_conn() -> rusqlite::Connection {
        rusqlite::Connection::open_in_memory().expect("open in-memory db")
    }

    /// 参数化往返：绑定 → 查询回读（防注入真绑定）
    #[test]
    fn params_roundtrip() {
        let conn = mem_conn();
        conn.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)", [])
            .unwrap();
        let affected = execute_with_params(
            &conn,
            "INSERT INTO kv (k, v) VALUES (?1, ?2)",
            &[serde_json::json!("a"), serde_json::json!("hello")],
        )
        .expect("insert ok");
        assert_eq!(affected, 1);
        let out = query_with_params_to_json(
            "p1",
            &conn,
            "SELECT v FROM kv WHERE k = ?1",
            &[serde_json::json!("a")],
        )
        .expect("query ok");
        assert_eq!(out[0]["v"], "hello");
    }

    /// parse_params_json 空串视为空数组 + 非法 JSON 报错
    #[test]
    fn params_json_parse() {
        assert!(parse_params_json("").unwrap().is_empty());
        assert!(parse_params_json("[1, \"a\"]").unwrap().len() == 2);
        assert!(parse_params_json("not-json").is_err());
    }

    /// 结果集护栏：行上限纯函数（不查库）
    #[test]
    fn row_cap_enforced() {
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        for _ in 0..PLUGIN_DB_QUERY_MAX_ROWS - 1 {
            push_row_capped("p1", &mut rows, &mut bytes, serde_json::json!({"x": 1})).unwrap();
        }
        push_row_capped("p1", &mut rows, &mut bytes, serde_json::json!({"x": 1})).unwrap();
        let err =
            push_row_capped("p1", &mut rows, &mut bytes, serde_json::json!({"x": 1})).unwrap_err();
        assert!(err.contains("rows limit"), "got: {err}");
    }

    /// 结果集护栏：字节上限（构造超过 32MB 的行）
    #[test]
    fn byte_cap_enforced() {
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let big = serde_json::json!({ "pad": "x".repeat(PLUGIN_DB_QUERY_MAX_BYTES) });
        let err = push_row_capped("p1", &mut rows, &mut bytes, big).unwrap_err();
        assert!(err.contains("bytes limit"), "got: {err}");
    }

    /// 列转换：i64 / f64（非整 REAL 不被截断）/ 字符串 / 布尔 / blob hex / NULL
    #[test]
    fn column_conversion() {
        let conn = mem_conn();
        conn.execute(
            "CREATE TABLE t (i INTEGER, r REAL, s TEXT, b INTEGER, bl BLOB, n NULL)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO t VALUES (42, 3.5, 'hi', 1, x'00ff', NULL)", [])
            .unwrap();
        let out = query_to_json("p1", &conn, "SELECT * FROM t").unwrap();
        let row = &out[0];
        assert_eq!(row["i"], 42);
        assert_eq!(row["r"], 3.5);
        assert_eq!(row["s"], "hi");
        // SQLite 无真 bool 类型（BOOL 是 INTEGER 别名）：i64 优先 → Number
        assert_eq!(row["b"], 1);
        assert_eq!(row["bl"], "00ff");
        assert!(row["n"].is_null());
    }

    /// 裸事务控制拒绝正反例
    #[test]
    fn bare_transaction_rejected() {
        assert!(reject_bare_transaction_control("INSERT INTO t (x) VALUES ('begin')").is_ok());
        assert!(reject_bare_transaction_control("SELECT 1").is_ok());
        assert!(reject_bare_transaction_control("-- 注释\nBEGIN").is_err());
        assert!(reject_bare_transaction_control("INSERT INTO t VALUES (1); COMMIT").is_err());
        assert!(reject_bare_transaction_control("BEGIN").is_err());
        assert!(reject_bare_transaction_control("ROLLBACK").is_err());
    }

    /// REAL 列不得降级成整数：`1.0` / `SUM(...)` round-trip 后仍是浮点
    #[test]
    fn real_columns_stay_floats() {
        let conn = mem_conn();
        conn.execute("CREATE TABLE t (r REAL)", []).unwrap();
        conn.execute("INSERT INTO t (r) VALUES (1.0)", []).unwrap();
        let out = query_to_json("p1", &conn, "SELECT r, SUM(r) AS s FROM t").unwrap();
        for col in ["r", "s"] {
            let value = &out[0][col];
            assert_eq!(value.as_f64(), Some(1.0), "{col} must stay REAL: {value}");
            assert!(
                !value.is_i64(),
                "{col} must not be downgraded to integer: {value}"
            );
            assert_eq!(value.to_string(), "1.0");
        }
    }

    /// 非有限 REAL（`1e999` = +Inf）不得静默变 0：JSON 无法表达时显式字符串化
    #[test]
    fn non_finite_real_is_not_silently_zeroed() {
        let conn = mem_conn();
        let out = query_to_json("p1", &conn, "SELECT 1e999 AS inf, -1e999 AS neg").unwrap();
        assert_eq!(out[0]["inf"], serde_json::json!("Infinity"));
        assert_eq!(out[0]["neg"], serde_json::json!("-Infinity"));
        assert_ne!(out[0]["inf"], serde_json::json!(0));
    }

    /// 文件边界语句（ATTACH / DETACH / VACUUM）在五个入口均被拒；普通 SQL 不受影响
    #[test]
    fn file_boundary_statements_rejected() {
        let conn = mem_conn();
        for sql in [
            "ATTACH DATABASE '/tmp/wasmnest-attach.db' AS x",
            "-- 前导注释\nATTACH ':memory:' AS x",
            "/* block */ DETACH DATABASE x",
            "VACUUM INTO '/tmp/wasmnest-vacuum.db'",
            "vacuum;",
        ] {
            assert!(
                reject_file_boundary_sql(sql).is_err(),
                "{sql} must be rejected"
            );
        }
        assert!(reject_file_boundary_sql("SELECT 'attach' AS word").is_ok());
        assert!(reject_file_boundary_sql("INSERT INTO t (x) VALUES ('vacuum')").is_ok());

        assert!(query_to_json("p1", &conn, "ATTACH ':memory:' AS x").is_err());
        assert!(query_with_params_to_json("p1", &conn, "ATTACH ':memory:' AS x", &[]).is_err());
        assert!(execute_with_params(&conn, "VACUUM INTO '/tmp/y.db'", &[]).is_err());
        assert!(execute_batch_on_conn(&conn, &["ATTACH ':memory:' AS x".to_string()]).is_err());
    }

    /// 批次事务：全提交 / 冲突回滚 / 内部裸事务拒绝
    #[test]
    fn batch_transaction_semantics() {
        let conn = mem_conn();
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", [])
            .unwrap();
        let ok = execute_batch_on_conn(
            &conn,
            &[
                "INSERT INTO t (id, v) VALUES (1, 'a')".to_string(),
                "INSERT INTO t (id, v) VALUES (2, 'b')".to_string(),
            ],
        )
        .expect("batch ok");
        assert_eq!(ok, 2);
        // 冲突回滚
        let err = execute_batch_on_conn(
            &conn,
            &[
                "INSERT INTO t (id, v) VALUES (3, 'c')".to_string(),
                "INSERT INTO t (id, v) VALUES (1, 'dup')".to_string(),
            ],
        )
        .unwrap_err();
        assert!(
            err.contains("UNIQUE") || err.contains("duplicate"),
            "got: {err}"
        );
        assert_eq!(
            query_to_json("p1", &conn, "SELECT COUNT(*) AS n FROM t").unwrap()[0]["n"],
            2
        );
        // 内部裸事务拒绝
        assert!(execute_batch_on_conn(&conn, &["BEGIN".to_string()]).is_err());
        assert!(execute_batch_on_conn(
            &conn,
            &[
                "INSERT INTO t (id, v) VALUES (9, 'z')".to_string(),
                "COMMIT".to_string(),
            ]
        )
        .is_err());
        // 单条元素带尾部语句：extra_check 让 tx.execute 报 MultipleStatement，
        // 不得静默只执行第一条
        let err = execute_batch_on_conn(
            &conn,
            &[
                "INSERT INTO t (id, v) VALUES (10, 'x'); INSERT INTO t (id, v) VALUES (11, 'y')"
                    .to_string(),
            ],
        )
        .unwrap_err();
        assert!(
            err.to_lowercase().contains("multiple"),
            "尾部语句必须显性拒绝，got: {err}"
        );
        assert_eq!(
            query_to_json("p1", &conn, "SELECT COUNT(*) AS n FROM t").unwrap()[0]["n"],
            2,
            "被拒绝的批次不得部分落库"
        );
    }

    /// 超时护栏：零超时 + 大量 VM 步（递归 CTE，>1000 步必触发 progress handler
    /// 回调）验证「安装 handler 即判定超时」路径 + 卸载后不受残留影响
    #[test]
    fn statement_timeout_fires() {
        let conn = mem_conn();
        let err = with_statement_timeout("p1", &conn, Duration::ZERO, |c| {
            c.query_row(
                "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 100000) SELECT count(*) FROM cnt",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|v| v)
            .map_err(|e| e.to_string())
        })
        .unwrap_err();
        assert!(err.contains("timed out"), "got: {err}");
        // handler 已卸载：后续普通执行不受超时残留影响
        assert!(
            with_statement_timeout("p1", &conn, Duration::from_secs(60), |c| {
                c.query_row("SELECT 2", [], |row| row.get::<_, i64>(0))
                    .map(|v| v)
                    .map_err(|e| e.to_string())
            })
            .is_ok()
        );
    }
}
