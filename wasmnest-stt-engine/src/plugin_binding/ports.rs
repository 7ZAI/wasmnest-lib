//! host-stt 能力域的宿主端口（边界层）
//!
//! 消费方（本 crate）声明端口，宿主实现。本 crate 不依赖 tauri、不依赖宿主 bin
//! crate；出站域机制（引擎装配 / 会话表 / 任务表 / 模型目录）自持，只把
//! 「宿主才有的那两件事」经端口要过来：
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | `check_permission` | 权限门（`stt:infer` / `stt:model`）是宿主安全闸门，本域只问结果 |
//! | `authorize_import_path` | 本地模型导入要读插件选中的路径；路径授权链在宿主，本域只拿结论 |
//!
//! 权限判定返回 bool（与其它能力域同款）：拒绝文案与 warn 落宿主侧，本域只把
//! `false` 翻译成 `permission denied: …`。拿不到权限管理器时（无头 / 测试）宿主
//! 实现必须返回 false（fail-safe）。

use std::path::Path;
use std::sync::{Arc, OnceLock};

/// 宿主能力端口
pub trait SttPorts: Send + Sync + 'static {
    /// 权限判定（`stt:infer` / `stt:model`）
    ///
    /// 返回 false 时宿主侧必须已按统一口径落 warn（plugin_id / permission / api）。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 校验本地导入路径是否可读（`fs:pick` 选择结果或已授权目录）
    ///
    /// 返回 Err 即拒绝导入；错误文案由宿主给出（点名路径/授权缺口）。
    fn authorize_import_path(&self, plugin_id: &str, path: &Path) -> Result<(), String>;
}

// ==================== 端口装配（进程级单例） ====================

static PORTS: OnceLock<Arc<dyn SttPorts>> = OnceLock::new();

/// 装配宿主端口实现（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
pub fn install_ports(ports: Arc<dyn SttPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的宿主端口
///
/// # Panics
/// 尚未装配时 panic 并点名（fail-visible：让未接宿主的能力域以「跑起来但什么都
/// 做不了」的面貌存在，比启动即炸难诊断得多）。
pub fn ports() -> Arc<dyn SttPorts> {
    ports_from(&PORTS)
}

/// `ports` 的可测入口（参数化单例格）
fn ports_from(cell: &OnceLock<Arc<dyn SttPorts>>) -> Arc<dyn SttPorts> {
    cell.get().cloned().expect(
        "stt engine ports are not installed — the host must call `install_ports` during boot",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub;

    impl SttPorts for Stub {
        fn check_permission(&self, _: &str, _: &str, _: &str) -> bool {
            true
        }

        fn authorize_import_path(&self, _: &str, _: &Path) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    #[should_panic(expected = "stt engine ports are not installed")]
    fn ports_panics_when_host_never_installed() {
        let empty = OnceLock::new();
        let _ = ports_from(&empty);
    }

    #[test]
    fn installed_ports_are_shared() {
        let cell: OnceLock<Arc<dyn SttPorts>> = OnceLock::new();
        let stub: Arc<dyn SttPorts> = Arc::new(Stub);
        let _ = cell.set(Arc::clone(&stub));
        assert!(Arc::ptr_eq(&ports_from(&cell), &stub));
    }
}
