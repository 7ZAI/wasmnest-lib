//! `host-storage` 能力域 adapter（实现层已上移共享核，票 18）
//!
//! 机制语义（权限门 / 系统空间纵深守卫 / 能力路由 / 键值原语）在
//! `wasmnest-host-api-core::storage`（双端单点，机制修复一次生效）；本文件只剩
//! 「[`SqlitePorts`] → 共享核 [`StoragePorts`] 端口」的 adapter 与既有域函数签名
//! ——`component.rs` 绑定层与 `tests/kv.rs` 的调用面零改动（桌面零回归门禁）。
//!
//! 端口接线：权限判定委托 [`SqlitePorts::check_permission`]（PermissionManager
//! 单点）；键值委托宿主原语；能力路由（core-plugin-manager，桌面独有）委托
//! `forward_storage_*`——移动端同名端口走共享核默认实现（`None` = 无提供者）。
//!
//! 零业务代码红线（AGENTS §5.1）：本域只做「按属主分区的键值原语 + 路由」，
//! 不解释任何键的含义（激活状态、审批记录、预授权路径 …全归宿主/插件各自解释）。

use crate::host_api::sqlite_ports::SqlitePorts;
use crate::permission::PERMISSION_STORAGE;
use wasmnest_host_api_core::storage as core_storage;
use wasmnest_host_api_core::storage::{PermissionGate, StoragePorts};

/// 系统级 `plugin_id`：非插件私有的全局数据命名空间（真源在共享核
/// `wasmnest_host_api_core::storage`，经 `crate::storage` 再导出取同一个值）
///
/// 本再导出仅供 `tests/kv.rs` 既有路径消费（lib 代码不再直接引用——守卫已随
/// 实现层上移共享核），故 cfg(test) 门控。
#[cfg(test)]
pub(crate) use crate::storage::SYSTEM_PLUGIN_ID;

/// [`SqlitePorts`] → 共享核 [`StoragePorts`] 的桌面 adapter
struct SqliteStoragePorts<'a> {
    ports: &'a dyn SqlitePorts,
}

impl StoragePorts for SqliteStoragePorts<'_> {
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool {
        self.ports.check_permission(plugin_id, permission, api)
    }

    fn kv_get(&self, plugin_id: &str, key: &str) -> Result<Option<serde_json::Value>, String> {
        self.ports.storage_get(plugin_id, key)
    }

    fn kv_set(&self, plugin_id: &str, key: &str, value: serde_json::Value) -> Result<(), String> {
        self.ports.storage_set(plugin_id, key, value)
    }

    fn kv_delete(&self, plugin_id: &str, key: &str) -> Result<(), String> {
        self.ports.storage_delete(plugin_id, key)
    }

    fn forward_kv_get(&self, plugin_id: &str, key: &str) -> Option<Result<Option<String>, String>> {
        self.ports.forward_storage_get(plugin_id, key)
    }

    fn forward_kv_set(
        &self,
        plugin_id: &str,
        key: &str,
        value: &str,
    ) -> Option<Result<(), String>> {
        self.ports.forward_storage_set(plugin_id, key, value)
    }

    fn forward_kv_delete(&self, plugin_id: &str, key: &str) -> Option<Result<(), String>> {
        self.ports.forward_storage_delete(plugin_id, key)
    }
}

/// 获取值（实现层：权限门 → 系统空间守卫 → 能力路由 → 键值原语）
pub fn storage_get(
    ports: &dyn SqlitePorts,
    plugin_id: &str,
    key: &str,
) -> Result<Option<serde_json::Value>, String> {
    core_storage::storage_get(
        &SqliteStoragePorts { ports },
        plugin_id,
        key,
        &PermissionGate {
            permission: PERMISSION_STORAGE,
            api: "host_storage_get",
            deny_error: "permission denied",
        },
    )
}

/// 设置值（权限校验 + 服务调用）
pub fn storage_set(
    ports: &dyn SqlitePorts,
    plugin_id: &str,
    key: &str,
    value: serde_json::Value,
) -> Result<(), String> {
    core_storage::storage_set(
        &SqliteStoragePorts { ports },
        plugin_id,
        key,
        value,
        &PermissionGate {
            permission: PERMISSION_STORAGE,
            api: "host_storage_set",
            deny_error: "permission denied",
        },
    )
}

/// 删除值（权限校验 + 服务调用）
pub fn storage_delete(ports: &dyn SqlitePorts, plugin_id: &str, key: &str) -> Result<(), String> {
    core_storage::storage_delete(
        &SqliteStoragePorts { ports },
        plugin_id,
        key,
        &PermissionGate {
            permission: PERMISSION_STORAGE,
            api: "host_storage_delete",
            deny_error: "permission denied",
        },
    )
}

#[cfg(test)]
mod tests;
