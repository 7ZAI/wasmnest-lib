//! 能力仓自持夹具的**共享 target 目录**（单一事实来源）
//!
//! # 为什么存在
//!
//! 本仓库无根 workspace，`wasmnest-wasm-core/fixtures/` 下的夹具 crate 各自独立
//! workspace。`cargo build --manifest-path <夹具>/Cargo.toml` 未指定 target 目录时，
//! cargo 把产物写进**该夹具 crate 根下**的 `target/` —— 于是 SDK / wit-bindgen /
//! serde 这份相同依赖图被逐夹具重复编译。
//!
//! 改为共享本 crate 自己的 target 子目录（`<wasm-core>/target/fixtures`）后，同
//! triple + 同 profile 下 cargo 按产物指纹复用，依赖图只编译一次；同时与宿主
//! `cargo test` 的主 target 桶分开（防 `cargo clean` 互相牵连，也防把夹具产物
//! 混进宿主产物统计）。
//!
//! # 三仓拆分（票 08 批次三）的语义变化
//!
//! 拆分前本模块指向平台仓桌面宿主的 `target/fixtures`（夹具 crate 与 SDK
//! 都住平台仓）；批次三把「机制验证用夹具」收进能力仓自持后，夹具产物随能力仓
//! 自己的 target 桶走——能力仓单克隆 `cargo test` 不再读平台仓任何目录。
//!
//! # 安全性
//!
//! `cargo test` 运行测试期间**不持有** target 目录锁（2026-09-26 探针实测：测试
//! 睡眠期间并发 `cargo build` 真实重编译 0.04s 完成，无 `Blocking waiting for
//! file lock`），因此夹具构建与父 `cargo test` 共用目录不会死锁。

use std::path::PathBuf;

/// 夹具共享 target 根目录：`<wasm-core crate 根>/target/fixtures`
///
/// 由 `CARGO_MANIFEST_DIR` 定位，不依赖 cwd，因此测试以任意 cwd 启动都能命中
/// 同一目录；`cargo clean`（在 crate 根）会连带清掉，重建即可。
pub(crate) fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/fixtures")
}

/// 夹具产物路径：`<dir>/<target>/<profile>/<lib_name>.wasm`
///
/// `lib_name` 用 crate 名（`[lib] name` / `package.name` 的下划线形式），例如
/// `wasmnest_plugin_wasi_test`；`target` 与 `profile` 分别是 cargo 的 `--target`
/// 与 release/debug。
///
/// 共享目录后产物名仍由各夹具自己的 crate 名决定 → 不同夹具不会互相覆盖。
pub(crate) fn artifact(target: &str, profile: &str, lib_name: &str) -> PathBuf {
    dir()
        .join(target)
        .join(profile)
        .join(format!("{lib_name}.wasm"))
}
