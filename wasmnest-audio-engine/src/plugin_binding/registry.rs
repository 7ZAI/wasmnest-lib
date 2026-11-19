//! host-audio 进程级引擎持有者与生命周期回收面
//!
//! ## 本模块持有什么
//!
//! ① **引擎单例**（[`AudioHub`]）：会话表 + 配额表的唯一真源，由宿主开机期经
//! [`crate::plugin_binding::install_hub`] 装入一次（后端实现是宿主的选择：cpal / 自带 / 无头测试）。
//!
//! ② **回收面**（停用回收 / 关停全量回收 / 在册计数）：宿主生命周期动作，**不经权限门、
//! 不取参数**——停用时插件已不可调用任何原语。
//!
//! ## 为什么引擎而不是端口持有会话表
//!
//! 会话表必须与采集回调共享（引擎内 `StreamSink` 只认 `runtime`），而回调住在
//! 后端线程——把表放在宿主端口后面会让每次回调穿过一层 `dyn` 调用，且「谁能装表」变成
//! 宿主契约的一部分。表是机制，引擎自持；端口只留权限判定。
//!
//! ## 零业务语义
//!
//! 句柄表是**属主隔离的通用寻址表**：键是本域铸造的 `audio-<uuid>`，值是采集会话。
//! 「同时录几路」是插件的能力声明（`audioQuota`），本模块不替插件决定业务上该怎样。

use std::sync::{Arc, OnceLock};

use crate::engine::AudioHub;

/// 进程级引擎持有者
static HUB: OnceLock<Arc<AudioHub>> = OnceLock::new();

/// 装配引擎（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
///
/// 重复装配必须被忽略：在册会话已经绑定到旧引擎的回调与锁上，换掉会让它们变成
/// 收不到回调的孤儿。首次装配者胜出。
pub fn install_hub(hub: Arc<AudioHub>) {
    let _ = HUB.set(hub);
}

/// 取已装配的引擎
///
/// # Panics
/// 尚未装配时 panic 并点名（fail-visible，见 [`super`] 模块文档）。
pub fn hub() -> Arc<AudioHub> {
    hub_from(&HUB)
}

/// 取引擎的**非 panicking** 入口（guest 面与钩子用它把缺口变成错误串）
pub fn try_hub() -> Option<Arc<AudioHub>> {
    HUB.get().cloned()
}

/// `hub` 的可测入口（**参数化单例格**，理由同 `ports::ports_from`）
fn hub_from(cell: &OnceLock<Arc<AudioHub>>) -> Arc<AudioHub> {
    cell.get().cloned().expect(
        "audio engine is not installed — the host must call `plugin_binding::install_hub` during boot",
    )
}

// ==================== 回收面（宿主生命周期动作） ====================

/// 插件停用回收：停流 + 摘句柄 + 清配额登记，返回回收条数
///
/// **只碰本人**（同其它能力域的按属主回收）：其他插件在册采集流不受影响。引擎未装配
/// 时返回 0 并落 warn——停用回收是尽力而为的生命周期动作，不该在关停路径上 panic。
pub fn purge_for_plugin(plugin_id: &str) -> usize {
    match try_hub() {
        Some(hub) => {
            let reclaimed = hub.purge(plugin_id);
            if reclaimed > 0 {
                tracing::info!(plugin_id = %plugin_id, reclaimed, "host-audio: 停用回收完成");
            }
            reclaimed
        }
        None => {
            tracing::warn!(
                plugin_id = %plugin_id,
                "host-audio: 停用回收跳过——引擎未装配（宿主接线缺口）"
            );
            0
        }
    }
}

/// 引擎层**全量**回收（系统关停路径）：跨属主停流并摘除全部在册采集流
///
/// 必须由引擎自持：关机时插件可能已停用 / 超时 / trap，按属主回收依赖「停用流程被调到」；
/// 引擎自持回收保证不留下「宿主持着麦克风句柄退出」的窗口。
pub fn close_all() -> usize {
    match try_hub() {
        Some(hub) => {
            let closed = hub.close_all();
            if closed > 0 {
                tracing::info!(closed, "host-audio: 引擎层全量回收完成（系统关停）");
            }
            closed
        }
        None => 0,
    }
}

/// 全进程在册采集流条数（引擎事实：诊断 / 关停守卫；非 WIT 原语）
pub fn live_count() -> usize {
    try_hub().map_or(0, |hub| hub.live_count())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{PcmFormat, SampleFormat};
    use crate::test_util::ScriptedBackend;

    fn hub() -> Arc<AudioHub> {
        let backend = ScriptedBackend::new(PcmFormat::new(16_000, 1, SampleFormat::S16));
        Arc::new(AudioHub::new(
            Arc::new(backend),
            crate::AudioLimits::default(),
        ))
    }

    /// 未装配即取 ⇒ panic 点名（fail-visible）
    #[test]
    #[should_panic(expected = "audio engine is not installed")]
    fn hub_panics_when_host_never_installed() {
        let empty = OnceLock::new();
        let _ = hub_from(&empty);
    }

    /// 装配后取到同一份引擎（`Arc` 指针相等）；`try_hub` 与之一致
    #[test]
    fn installed_hub_is_shared() {
        let cell: OnceLock<Arc<AudioHub>> = OnceLock::new();
        let hub = hub();
        let _ = cell.set(Arc::clone(&hub));
        assert!(Arc::ptr_eq(&hub_from(&cell), &hub));
    }

    /// 引擎未装配时回收面不 panic、返回 0（关停路径的尽力语义）
    #[test]
    fn reclaim_surface_is_inert_without_a_hub() {
        // 本进程从未装配引擎（其它用例都用参数化单例格，不碰全局）
        if try_hub().is_none() {
            assert_eq!(purge_for_plugin("audio-test.none"), 0);
            assert_eq!(close_all(), 0);
            assert_eq!(live_count(), 0);
        }
    }
}
