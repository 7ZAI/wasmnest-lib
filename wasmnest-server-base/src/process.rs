//! 进程创建工具（wasm-core 纯净性收口票 03 / E2-D4：`create_command` 下沉）
//!
//! 原住 `wasm_core::system::process`（Windows 专用进程创建包装）。下沉到基础层
//! 的原因：它被**两个 crate** 消费（`wasmnest-wasm-core` 的 `wsl_fs` / `wsl`
//! 引擎面 + `wasmnest-pty-engine` 的 Windows kill 路径），放任一侧都会造成跨 crate
//! 依赖（wasm-core 或 pty-engine 互相引用）。放本 crate 后双侧只向下依赖 base，
//! 归属唯一。

use std::process::Command;

/// 创建一个静默执行的外部命令
///
/// Windows 上自动添加 `CREATE_NO_WINDOW` 标志，避免控制台窗口闪现。
/// 其他平台等同于 `Command::new(program)`。
pub fn create_command(program: &str) -> Command {
    let cmd = Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW = 0x08000000
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}