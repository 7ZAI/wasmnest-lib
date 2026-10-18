//! 执行护栏（票据 05）：语句超时 / 结果行数上限 / 序列化字节上限 + 入口级全链路回归
//!
//! 护栏常量取自 `wasmnest-server-base::constants`（机制上限，不可由插件参数调整——
//! 安全边界）。迁移自宿主同名用例：超时错误与 SQL 错误**必须可区分**（分类混同会让
//! 插件无法判断该重试还是该改查询）。

use std::time::Duration;

use crate::system::constants::{PLUGIN_DB_QUERY_MAX_BYTES, PLUGIN_DB_QUERY_MAX_ROWS};
use crate::host_api::database::{
    plugin_db_execute, plugin_db_execute_params, plugin_db_query, plugin_db_query_params,
    query_to_json, with_statement_timeout,
};
use crate::host_api::sqlite_scaffold::*;
use crate::permission::PERMISSION_STORAGE;

// ==================== 执行护栏（票据 05）：超时 / 行数上限 / 字节上限 ====================

/// 内存连接 + n 行数据（事务内批量插入，测试用）
fn mem_conn_with_rows(n: usize) -> rusqlite::Connection {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (x INTEGER)").unwrap();
    {
        let tx = conn.transaction().unwrap();
        for i in 0..n {
            tx.execute("INSERT INTO t (x) VALUES (?1)", rusqlite::params![i as i64])
                .unwrap();
        }
        tx.commit().unwrap();
    }
    conn
}

/// 慢查询（大跨连）被超时护栏硬中断：超时错误与 SQL 错误可区分
#[test]
fn statement_timeout_interrupts_slow_query() {
    let conn = mem_conn_with_rows(5000);
    let err = with_statement_timeout("p1", &conn, Duration::from_millis(20), |c| {
        // 5000×5000 = 2500 万行结果，远超 20ms
        query_to_json("p1", c, "SELECT count(*) FROM t a CROSS JOIN t b")
    })
    .expect_err("slow query must be interrupted by timeout guard");
    assert!(
        err.contains("timed out"),
        "timeout error should be distinguishable, got: {}",
        err
    );
}

/// 约束/表缺失错误 ≠ 超时（错误分类保持：超时/超限 ≠ SQL 错误 ≠ 权限拒绝）
#[test]
fn sql_error_not_aliased_as_timeout() {
    let conn = mem_conn_with_rows(10);
    let err = with_statement_timeout("p1", &conn, Duration::from_secs(5), |c| {
        query_to_json("p1", c, "SELECT * FROM nope")
    })
    .expect_err("missing table must surface as SQL error");
    assert!(
        !err.contains("timed out") && err.contains("nope"),
        "SQL error should not be disguised as timeout, got: {}",
        err
    );
}

/// 快查询在超时窗口内放行；结果行数与字节均在上限内
#[test]
fn statement_within_timeout_and_limits_passes() {
    let conn = mem_conn_with_rows(100);
    let value = with_statement_timeout("p1", &conn, Duration::from_secs(5), |c| {
        query_to_json("p1", c, "SELECT x FROM t ORDER BY x")
    })
    .expect("fast small query must pass");
    assert_eq!(value.as_array().unwrap().len(), 100);
}

/// 结果集行数超上限：截断并报错（引导插件加 LIMIT 或分批）
#[test]
fn query_exceeding_row_limit_rejected() {
    let conn = mem_conn_with_rows(PLUGIN_DB_QUERY_MAX_ROWS + 1);
    let err = query_to_json("p1", &conn, "SELECT x FROM t").expect_err("result over row limit must be rejected");
    assert!(
        err.contains("rows limit") && err.contains("LIMIT"),
        "error should state row limit and guidance, got: {}",
        err
    );
}

/// 结果集序列化字节超上限（单行大字段）：截断并报错
#[test]
fn query_exceeding_byte_limit_rejected() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (x TEXT)").unwrap();
    let big = "a".repeat(PLUGIN_DB_QUERY_MAX_BYTES + 1);
    conn.execute("INSERT INTO t (x) VALUES (?1)", rusqlite::params![big.as_str()])
        .unwrap();
    let err = query_to_json("p1", &conn, "SELECT x FROM t").expect_err("oversized row must be rejected by byte guard");
    assert!(
        err.contains("bytes limit"),
        "error should state byte limit, got: {}",
        err
    );
}

/// 入口级回归：插件私有库 execute/query/参数绑定经护栏全链路（权限 + 超时/上限；
/// 私有库无前缀约束——整库属主）
#[test]
fn plugin_db_entry_execute_and_query_with_guards() {
    let fake = FakePorts::new();
    let ports = as_ports(&fake);
    fake.grant("p1", &[PERMISSION_STORAGE]);
    fake.set_plugin_db("p1");
    plugin_db_execute(ports, "p1", "CREATE TABLE t (x INTEGER)").expect("create table");
    for i in 0..3i64 {
        let params = format!("[{}]", i);
        plugin_db_execute_params(ports, "p1", "INSERT INTO t (x) VALUES (?1)", &params).expect("insert with params");
    }
    let out = plugin_db_query(ports, "p1", "SELECT x FROM t ORDER BY x")
        .expect("query")
        .expect("query result json");
    assert_eq!(out, "[{\"x\":0},{\"x\":1},{\"x\":2}]");
    let out_params = plugin_db_query_params(ports, "p1", "SELECT x FROM t WHERE x >= ?1 ORDER BY x", "[1]")
        .expect("query params")
        .expect("query params json");
    assert_eq!(out_params, "[{\"x\":1},{\"x\":2}]");
}
