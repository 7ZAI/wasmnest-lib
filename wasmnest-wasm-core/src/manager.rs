//! 插件管理模块（core-plugin-manager）——内核核心模块
//!
//! 插件加载、注册、生命周期与 WASM 运行时管理：
//! - [`loader`] / [`registry`] / [`watcher`]：插件包加载、注册表、dev 监听
//! - [`host`]：PluginHost 装配与命令面
//! - [`runtime`]：wasmtime Engine/Linker/Store/Instance 生命周期
//! - [`capability`]：能力注册表与系统组件装配（manifest type/dependencies、
//!   host-* 能力路由与 host-side 转发，票据 06）
//! - [`types`] / [`validation`]：类型与校验；
//! - [`task`]：host-task 执行引擎（core-task：专用 OS 线程池 + 任务注册表 + 事件管道）
//!
//! 宿主对外接口（host-* 原语实现与前端命令桥）已归位到 `crate::host_api`；
//! 插件存储（`PluginStorage`）中立化到 `crate::storage`（票 03）。

// 装配面（单形态 2026-10-13，runtime-single-form）：无 common/bare 分叉——桌面
// PluginHost 装配树（capability / host / task / watcher）随 `desktop-assembly`
// （桌面专属装配面，移动不开）；统一运行时壳（runtime.rs + component.rs）双端共用。
// 域实现真源在两端宿主 `src-tauri/src/plugin/host_domains/`。
// 机制面（downloader / loader / registry / types / validation）双端共享。
pub(crate) mod capability;
// 插件 zip 分发包解压安装：core-plugin-manager 的安装职责，已自 `plugin/downloader`
// 归位到此（票 11 第 5 项），引用方改为 `crate::manager::downloader`。
pub mod downloader;
#[cfg(feature = "desktop-assembly")]
pub mod host;
pub mod loader;
pub mod registry;
pub mod runtime;
#[cfg(feature = "desktop-assembly")]
pub(crate) mod task;
pub mod types;
pub mod validation;
#[cfg(all(debug_assertions, feature = "desktop-assembly"))]
pub mod watcher;
