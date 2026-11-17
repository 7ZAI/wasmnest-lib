//! host-stt 进程级引擎持有者与生命周期回收面
//!
//! 引擎单例（[`crate::hub::SttHub`]）由宿主开机期装一次；回收面（停用 / 关停）是
//! 宿主生命周期动作，**不经权限门、不取参数**——停用时插件已不可调用任何原语。

use std::sync::{Arc, OnceLock};

use crate::hub::SttHub;

static HUB: OnceLock<Arc<SttHub>> = OnceLock::new();

/// 装配引擎（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
pub fn install_hub(hub: Arc<SttHub>) {
    let _ = HUB.set(hub);
}

/// 取已装配的引擎
///
/// # Panics
/// 尚未装配时 panic 并点名（fail-visible）。
pub fn hub() -> Arc<SttHub> {
    hub_from(&HUB)
}

/// 取引擎的非 panicking 入口（guest 面与钩子用它把缺口变成错误串）
pub fn try_hub() -> Option<Arc<SttHub>> {
    HUB.get().cloned()
}

fn hub_from(cell: &OnceLock<Arc<SttHub>>) -> Arc<SttHub> {
    cell.get().cloned().expect(
        "stt engine is not installed — the host must call `plugin_binding::install_hub` during boot",
    )
}

/// 插件停用回收：丢弃会话、取消任务、移除任务历史，返回回收条数
pub fn purge_for_plugin(plugin_id: &str) -> usize {
    match try_hub() {
        Some(hub) => {
            let reclaimed = hub.purge(plugin_id);
            if reclaimed > 0 {
                tracing::info!(plugin_id = %plugin_id, reclaimed, "host-stt: 停用回收完成");
            }
            reclaimed
        }
        None => {
            tracing::warn!(
                plugin_id = %plugin_id,
                "host-stt: 停用回收跳过——引擎未装配（宿主接线缺口）"
            );
            0
        }
    }
}

/// 引擎层全量回收（系统关停路径）：取消全部任务并丢弃会话
pub fn close_all() -> usize {
    match try_hub() {
        Some(hub) => {
            let count = hub.close_all();
            if count > 0 {
                tracing::info!(count, "host-stt: 系统关停回收完成");
            }
            count
        }
        None => 0,
    }
}

/// 全进程在册会话数（诊断）
pub fn live_count() -> usize {
    try_hub().map_or(0, |hub| hub.session_count())
}

/// 全进程在册任务数（诊断）
pub fn job_count() -> usize {
    try_hub().map_or(0, |hub| hub.job_count())
}

/// 全进程在册会话 + 任务总数（诊断 / 关停守卫）
pub fn session_count() -> usize {
    live_count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::hub::SessionLimits;
    use crate::model_store::ModelStore;
    use std::path::PathBuf;

    fn hub() -> Arc<SttHub> {
        let dir = std::env::temp_dir().join(format!("wasmnest-stt-reg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store =
            Arc::new(ModelStore::new(dir, None, None).expect("store should open in temp dir"));
        Arc::new(SttHub::new(
            Arc::new(MockBackend::new("x")),
            store,
            SessionLimits::default(),
        ))
    }

    #[test]
    #[should_panic(expected = "stt engine is not installed")]
    fn hub_panics_when_host_never_installed() {
        let empty = OnceLock::new();
        let _ = hub_from(&empty);
    }

    #[test]
    fn installed_hub_is_shared() {
        let cell: OnceLock<Arc<SttHub>> = OnceLock::new();
        let hub = hub();
        let _ = cell.set(Arc::clone(&hub));
        assert!(Arc::ptr_eq(&hub_from(&cell), &hub));
    }

    #[test]
    fn reclaim_surface_is_inert_without_a_hub() {
        if try_hub().is_none() {
            assert_eq!(purge_for_plugin("stt-test.none"), 0);
            assert_eq!(close_all(), 0);
            assert_eq!(live_count(), 0);
            assert_eq!(job_count(), 0);
        }
    }

    #[test]
    fn unused_import_guard() {
        let _ = PathBuf::new();
    }
}
