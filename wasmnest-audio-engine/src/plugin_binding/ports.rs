//! host-audio 能力域的宿主端口（边界层）
//!
//! ## 设计依据（能力域端口先例；http / ws / peer-net / mdns / pty 同款）
//!
//! 消费方（本 crate）声明端口，宿主实现。本 crate **不依赖 tauri、不依赖宿主 bin
//! crate**，故出站域机制（引擎装配 / 会话表 / 配额仲裁 / 属主校验）自持，只把
//! 「宿主才有的那件事」经端口要过来：
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | [`crate::plugin_binding::ports::AudioPorts::check_permission`] | 权限门（`audio:capture` / `audio:io`）是**宿主安全闸门**，不该可插拔 ⇒ 留宿主，本域只问结果（拒绝文案与 warn 落宿主侧） |
//!
//! 采集**后端**不是端口：引擎需要的是 `Arc<dyn CaptureBackend>`（可以来自本 crate 的
//! `backend-cpal`、宿主自带实现或无头测试替身），由宿主在 [`crate::plugin_binding::install_hub`] 时选定
//! ——它比端口少一层间接，且后端 trait 本身已在本 crate 定义。
//!
//! ## 为什么 [`crate::plugin_binding::ports::AudioPorts::check_permission`] 返回 bool 而不是 Result
//!
//! 与其它能力域同款：**拒绝文案与 warn 落宿主侧**（宿主才认得 PermissionManager 与结构化
//! 日志字段），本域只把 `false` 翻译成本域既有的 `permission denied: …` 串。拿不到权限
//! 管理器时（无头 / 测试）宿主实现**必须返回 false**（fail-safe）。

use std::sync::{Arc, OnceLock};

/// 宿主能力端口
///
/// 实现方是各端宿主的适配器（桌面端见宿主 `src-tauri/src/plugin/audio.rs` 的
/// `HostAudioPorts`）。
pub trait AudioPorts: Send + Sync + 'static {
    /// 权限判定（`audio:capture` / `audio:io`）
    ///
    /// 返回 `false` 时**宿主侧**必须已按 AGENTS §8 落 `warn`（结构化字段 `plugin_id` /
    /// `permission` / `api`）；本域不重复落日志。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;
}

// ==================== 端口装配（进程级单例） ====================

/// 进程级端口持有者
///
/// **为什么是全局**：`impl Host for WasmPluginState` 住在本 crate（它用本 crate 的
/// `bindgen!` 生成的 `Host` trait），而**端口的具体实现属于宿主**，crate 之间无从互相
/// 指名——故用「宿主开机装一次、之后经本函数取」的单向装配。
static PORTS: OnceLock<Arc<dyn AudioPorts>> = OnceLock::new();

/// 装配宿主端口实现（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
///
/// 首次装配者胜出：已在途的调用不应落到两套授权判定上。
pub fn install_ports(ports: Arc<dyn AudioPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的宿主端口
///
/// # Panics
/// 尚未装配时 panic 并点名——**fail-visible**：让一个未接宿主的能力域以「跑起来
/// 但什么都做不了」的面貌存在，比启动即炸难诊断得多。
pub fn ports() -> Arc<dyn AudioPorts> {
    ports_from(&PORTS)
}

/// `ports` 的可测入口（**参数化单例格**）
///
/// 为什么不直接测 [`ports`]：进程级单例一旦被同进程任一测试装配过，`#[should_panic]`
/// 用例就变成顺序依赖的假红。把格子作参数传入，「未装配 ⇒ 显性炸出」这条契约才能被
/// 确定性断言。
fn ports_from(cell: &OnceLock<Arc<dyn AudioPorts>>) -> Arc<dyn AudioPorts> {
    cell.get().cloned().expect(
        "audio engine ports are not installed — the host must call `install_ports` during boot",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub;

    impl AudioPorts for Stub {
        fn check_permission(&self, _: &str, _: &str, _: &str) -> bool {
            true
        }
    }

    /// 端口未装配即取 ⇒ panic 点名（fail-visible，不得静默给一份空实现）
    #[test]
    #[should_panic(expected = "audio engine ports are not installed")]
    fn ports_panics_when_host_never_installed() {
        let empty = OnceLock::new();
        let _ = ports_from(&empty);
    }

    /// 装配后取到同一份实现（`Arc` 指针相等，不是每次新建）
    #[test]
    fn installed_ports_are_shared() {
        let cell: OnceLock<Arc<dyn AudioPorts>> = OnceLock::new();
        let stub: Arc<dyn AudioPorts> = Arc::new(Stub);
        let _ = cell.set(Arc::clone(&stub));
        assert!(Arc::ptr_eq(&ports_from(&cell), &stub));
    }
}
