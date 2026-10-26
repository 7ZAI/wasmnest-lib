//! `host-plugin-database` 能力域 **adapter**（实现层在共享核，票 18 批次 3）
//!
//! **2026-10-09 双端机制决策（用户指令）**：主库由 wasm-core 管理，**不给任何
//! wasm-app / 插件直接调用的方法**——`host-database`（主库）接口自双端 WIT 面
//! 移除（ABI 桌面 34→35 / 移动 18→19），本文件随之为**纯插件私有库 adapter**
//! （`host-plugin-database` 5 原语）：机制语义（权限门 `storage` / 语句超时护栏 /
//! 结果集护栏 / 批次事务）在 `wasmnest-host-api-core::database`（双端单点）。
//!
//! `component.rs` 绑定层零改动（`host_plugin_database::Host` impl 调用面不变）。

use crate::host_api::sqlite_ports::{block_on, SqlitePorts};
use crate::permission::PERMISSION_STORAGE;
use std::time::Duration;
use wasmnest_host_api_core::database as core_db;

// ==================== 机制面 re-export（真源 = 共享核；tests 既有路径保符号面） ====================

// tests（`tests/db_guards.rs` / `tests/db_batch.rs`）经本模块路径消费的符号面；
// 其余共享核符号生产路径一律走 `core_db::` 全限定，不在此 re-export。
// 非 test 构建无消费者 → cfg_attr 豁免（t 与既有注释「tests 既有路径保符号面」一致）
#[cfg_attr(not(test), allow(unused_imports))]
pub use wasmnest_host_api_core::database::{
    query_to_json, reject_bare_transaction_control, with_statement_timeout,
};

// ==================== 逻辑层（Component Model 绑定调用） ====================

/// 插件独立库执行 SQL（权限校验 + 超时护栏，无表名前缀校验）
pub fn plugin_db_execute(
    ports: &dyn SqlitePorts,
    plugin_id: &str,
    sql: &str,
) -> Result<u32, String> {
    if !ports.check_permission(plugin_id, PERMISSION_STORAGE, "host_plugin_db_execute") {
        return Err("permission denied".to_string());
    }
    core_db::reject_bare_transaction_control(sql)?;
    let timeout = Duration::from_secs(core_db::PLUGIN_DB_STATEMENT_TIMEOUT_SECS);
    block_on(ports, async {
        let db_arc = ports
            .plugin_db(plugin_id.to_string())
            .await
            .map_err(|e| e.to_string())?;
        let db = db_arc.lock().expect("plugin db lock poisoned");
        core_db::with_statement_timeout(plugin_id, db.conn(), timeout, |conn| {
            conn.execute(sql, [])
                .map(|n| n as u32)
                .map_err(|e| e.to_string())
        })
    })
    .map_err(|e| format!("database error: {}", e))
}

/// 插件独立库查询（权限校验 + 超时护栏，无表名前缀校验）
pub fn plugin_db_query(
    ports: &dyn SqlitePorts,
    plugin_id: &str,
    sql: &str,
) -> Result<Option<String>, String> {
    if !ports.check_permission(plugin_id, PERMISSION_STORAGE, "host_plugin_db_query") {
        return Err("permission denied".to_string());
    }
    let timeout = Duration::from_secs(core_db::PLUGIN_DB_STATEMENT_TIMEOUT_SECS);
    let value = block_on(ports, async {
        let db_arc = ports
            .plugin_db(plugin_id.to_string())
            .await
            .map_err(|e| e.to_string())?;
        let db = db_arc.lock().expect("plugin db lock poisoned");
        core_db::with_statement_timeout(plugin_id, db.conn(), timeout, |conn| {
            core_db::query_to_json(plugin_id, conn, sql)
        })
    })
    .map_err(|e| format!("database error: {}", e))?;
    serde_json::to_string(&value)
        .map(Some)
        .map_err(|e| format!("database error: JSON serialization failed: {}", e))
}

/// 插件独立库执行参数绑定 SQL（权限校验 + 超时护栏，无表名前缀校验）
pub fn plugin_db_execute_params(
    ports: &dyn SqlitePorts,
    plugin_id: &str,
    sql: &str,
    params_json: &str,
) -> Result<u32, String> {
    if !ports.check_permission(
        plugin_id,
        PERMISSION_STORAGE,
        "host_plugin_db_execute_params",
    ) {
        return Err("permission denied".to_string());
    }
    core_db::reject_bare_transaction_control(sql)?;
    let params = core_db::parse_params_json(params_json)?;
    let timeout = Duration::from_secs(core_db::PLUGIN_DB_STATEMENT_TIMEOUT_SECS);
    block_on(ports, async {
        let db_arc = ports
            .plugin_db(plugin_id.to_string())
            .await
            .map_err(|e| e.to_string())?;
        let db = db_arc.lock().expect("plugin db lock poisoned");
        core_db::with_statement_timeout(plugin_id, db.conn(), timeout, |conn| {
            core_db::execute_with_params(conn, sql, &params).map(|n| n as u32)
        })
    })
    .map_err(|e| format!("database error: {}", e))
}

/// 插件独立库参数绑定查询（权限校验 + 超时护栏，无表名前缀校验）
pub fn plugin_db_query_params(
    ports: &dyn SqlitePorts,
    plugin_id: &str,
    sql: &str,
    params_json: &str,
) -> Result<Option<String>, String> {
    if !ports.check_permission(plugin_id, PERMISSION_STORAGE, "host_plugin_db_query_params") {
        return Err("permission denied".to_string());
    }
    let params = core_db::parse_params_json(params_json)?;
    let timeout = Duration::from_secs(core_db::PLUGIN_DB_STATEMENT_TIMEOUT_SECS);
    let value = block_on(ports, async {
        let db_arc = ports
            .plugin_db(plugin_id.to_string())
            .await
            .map_err(|e| e.to_string())?;
        let db = db_arc.lock().expect("plugin db lock poisoned");
        core_db::with_statement_timeout(plugin_id, db.conn(), timeout, |conn| {
            core_db::query_with_params_to_json(plugin_id, conn, sql, &params)
        })
    })
    .map_err(|e| format!("database error: {}", e))?;
    serde_json::to_string(&value)
        .map(Some)
        .map_err(|e| format!("database error: JSON serialization failed: {}", e))
}

/// 插件独立库事务批次执行（权限 + 语句数上限 + 超时护栏，无表名前缀校验）
pub fn plugin_db_execute_batch(
    ports: &dyn SqlitePorts,
    plugin_id: &str,
    sqls_json: &str,
) -> Result<u32, String> {
    if !ports.check_permission(
        plugin_id,
        PERMISSION_STORAGE,
        "host_plugin_db_execute_batch",
    ) {
        return Err("permission denied".to_string());
    }
    let sqls = core_db::parse_sqls_json(sqls_json)?;
    if sqls.len() > core_db::PLUGIN_DB_EXECUTE_BATCH_MAX_STATEMENTS {
        return Err(format!(
            "database error: execute-batch exceeds {} statements limit",
            core_db::PLUGIN_DB_EXECUTE_BATCH_MAX_STATEMENTS
        ));
    }
    let timeout = Duration::from_secs(core_db::PLUGIN_DB_STATEMENT_TIMEOUT_SECS);
    block_on(ports, async {
        let db_arc = ports
            .plugin_db(plugin_id.to_string())
            .await
            .map_err(|e| e.to_string())?;
        let db = db_arc.lock().expect("plugin db lock poisoned");
        core_db::with_statement_timeout(plugin_id, db.conn(), timeout, |conn| {
            core_db::execute_batch_on_conn(conn, &sqls)
        })
    })
    .map_err(|e| format!("database error: {}", e))
}

#[cfg(test)]
mod tests;
