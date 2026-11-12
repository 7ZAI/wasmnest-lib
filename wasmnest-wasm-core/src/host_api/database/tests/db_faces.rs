//! 权限门：插件私有库（`host-plugin-database`）挂 `storage` 位——未授权拒；
//! 授权后进到执行（注入私有库）/ 无头私有库缺席
//!
//! **2026-10-09 双端机制决策**：主库面（`host-database` / `database:main`）已随
//! 「主库由 wasm-core 管理、不给插件直接调用方法」整体退役——插件数据库能力 =
//! 插件私有库（声明 `storage` 位）。

use crate::host_api::database::{plugin_db_execute, plugin_db_query};
use crate::host_api::sqlite_scaffold::*;
use crate::permission::PERMISSION_STORAGE;

/// 权限门：未授予 `storage` → 私有库面一律拒；授权后进到执行路径
#[test]
fn plugin_db_requires_storage_permission() {
    let fake = FakePorts::new();
    let ports = as_ports(&fake);
    let sql = "CREATE TABLE kv (k TEXT)";

    // ① 未授予：拒绝
    assert_eq!(
        plugin_db_execute(ports, "com.wasmnest.no-db", sql).unwrap_err(),
        "permission denied"
    );
    assert_eq!(
        plugin_db_query(ports, "com.wasmnest.no-db", "SELECT 1").unwrap_err(),
        "permission denied"
    );

    // ② 授予 storage 但未注入私有库：进到「私有库缺席」而非权限拒（无头形状）
    fake.grant("com.wasmnest.kv-only", &[PERMISSION_STORAGE]);
    let private_err = plugin_db_execute(ports, "com.wasmnest.kv-only", sql).unwrap_err();
    assert!(
        !private_err.contains("permission denied"),
        "持有 storage 的私有库面不应被权限门拒: {private_err}"
    );

    // ③ 授予 + 注入私有库：执行成功
    fake.set_plugin_db("com.wasmnest.full");
    fake.grant("com.wasmnest.full", &[PERMISSION_STORAGE]);
    plugin_db_execute(
        ports,
        "com.wasmnest.full",
        "CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)",
    )
    .expect("create ok");
}
