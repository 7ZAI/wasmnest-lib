//! Plugin Dev Watcher
//!
//! 开发模式文件监听器 — 监听插件产物目录变化，触发热重载
//! 检测 .wasm 变化触发 Rust 端 WASM 热重载
//! 检测 .js 变化通过 Tauri 事件通知前端重新加载 TS 模块
//!
//! 仅在开发模式下启用（cfg!(debug_assertions)）

use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Emitter;

use crate::system::constants::PLUGIN_DEV_RELOAD;
use crate::system::constants::PLUGIN_RELOAD_DEBOUNCE_MS;

/// 插件开发文件监听器
///
/// 持有 notify::Watcher 实例，监听插件产物目录变化。
/// 检测到变化后通过 AppContext 获取 PluginHost 触发热重载。
pub struct PluginDevWatcher {
    // Watcher 必须 hold 住生命周期，drop 后停止监听；
    // None = 创建/开始监听失败（M-06：dev-only 工具失败不应崩 Tauri setup，记日志降级）
    _watcher: Option<Box<dyn Watcher + Send>>,
}

impl PluginDevWatcher {
    /// 启动插件开发文件监听
    ///
    /// 监听 plugins_dir 下的文件变化，对 .wasm/.js 变化触发热重载。
    /// 使用防抖机制避免短时间内多次触发（如 cargo build 连续写入多个文件）
    ///
    /// # Arguments
    /// * `plugins_dir` - 插件产物目录（resources/plugins/desktop/）
    /// * `runtime_handle` - Tokio 运行时 Handle（notify 回调在非 Tokio 线程，需通过 handle spawn）
    /// * `plugin_host` - 宿主 PluginHost 弱引用（整核抽出：不再经 lib `AppContext::global()`
    ///   取宿主——本 crate 内无 lib 组合根，改由调用方（lib bootstrap）注入；弱引用失效
    ///   时跳过触发，语义与「无 AppContext 降级」一致）
    ///
    /// 创建/监听失败（如 fresh checkout 无 plugins_dir）记 warn 降级返回，不崩 setup（M-06）。
    pub fn start(
        plugins_dir: PathBuf,
        runtime_handle: tokio::runtime::Handle,
        plugin_host: std::sync::Weak<crate::manager::host::PluginHost>,
    ) -> Self {
        // canonicalize（M-14）：watch 根与事件路径共用规范路径——macOS /private/var
        // symlink、`..` 组件会让 strip_prefix 失配 → 事件全量静默丢弃（热重载死亡无日志）。
        // 目录不存在时 canonicalize 失败，保留原路径（watch 会在下方报错降级）。
        let canonical = plugins_dir
            .canonicalize()
            .unwrap_or_else(|_| plugins_dir.clone());

        // 防抖状态：plugin_id → 最近一次触发时间（per-plugin 时间戳，M-05——
        // 共享单 (id, Instant) 对会让异插件事件交错覆盖彼此的防抖窗口）。
        // std Mutex 而非 tokio RwLock：WASM 分支在 spawn 内异步持有、JS 分支在
        // notify 回调线程同步持有，两种上下文都要能用。
        let pending: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

        let pd = canonical.clone();
        let plugin_host_weak = plugin_host;

        let mut watcher = match notify::recommended_watcher(
            move |res: Result<Event, notify::Error>| {
                let event = match res {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::debug!("Plugin watcher error: {}", e);
                        return;
                    }
                };

                // 只关注文件创建/修改事件
                if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    return;
                }

                for path in &event.paths {
                    let ext = path.extension().map(|e| e.to_string_lossy().to_string());

                    let plugin_id = match extract_plugin_id(path, &pd) {
                        Some(id) => id,
                        None => continue,
                    };

                    match ext.as_deref() {
                        // WASM 产物变化 → 触发 Rust 端热重载
                        Some("wasm") => {
                            tracing::info!(
                                plugin_id = %plugin_id,
                                "Plugin watcher: WASM changed: {}",
                                path.display()
                            );

                            let pending = pending.clone();
                            let plugin_id_clone = plugin_id.clone();
                            // FnMut 回调不能 move 捕获弱引用：在 spawn 前 clone（Weak 是 Clone）
                            let plugin_host_weak = plugin_host_weak.clone();
                            // notify 回调在非 Tokio 线程中运行，必须通过 Handle::spawn 而非 tokio::spawn
                            runtime_handle.spawn(async move {
                            // 防抖 check-and-set 全程持写锁（M-05）：并发两任务都看到空/过期
                            // pending 都调 reload 的窗口被原子化堵死；per-plugin 时间戳使
                            // 异插件事件互不干扰对方的防抖窗口
                            {
                                let mut p = pending.lock().unwrap_or_else(|e| e.into_inner());
                                if p.get(&plugin_id_clone)
                                    .is_some_and(|t| t.elapsed() < Duration::from_millis(PLUGIN_RELOAD_DEBOUNCE_MS))
                                {
                                    tracing::debug!(
                                        plugin_id = %plugin_id_clone,
                                        "Plugin watcher: debounced reload"
                                    );
                                    return;
                                }
                                p.insert(plugin_id_clone.clone(), Instant::now());
                            }

                            // 经注入的 PluginHost 弱引用取宿主（整核抽出：不再经
                            // lib `AppContext::global()`——本 crate 内无 lib 组合根）；
                            // 弱引用已失效（宿主已释放）→ 跳过本次触发
                            let Some(ph) = plugin_host_weak.upgrade() else {
                                return;
                            };
                            match ph.reload_wasm_plugin(&plugin_id_clone).await {
                                Ok(()) => {
                                    tracing::info!(plugin_id = %plugin_id_clone, "Plugin watcher: WASM hot-reloaded");
                                }
                                Err(e) => {
                                    tracing::error!(
                                        plugin_id = %plugin_id_clone,
                                        error = %e,
                                        "Plugin watcher: WASM hot-reload failed"
                                    );
                                }
                            }
                        });
                        }
                        // TS 产物变化 → 通知前端重新加载（M-09：打包器一次重建写多个 JS
                        // 文件会逐个触发 → 同样走防抖，否则前端收到 reload 洪泛）
                        Some("js") => {
                            tracing::info!(
                                plugin_id = %plugin_id,
                                "Plugin watcher: JS changed: {}",
                                path.display()
                            );

                            let mut p = pending.lock().unwrap_or_else(|e| e.into_inner());
                            if p.get(&plugin_id).is_some_and(|t| {
                                t.elapsed() < Duration::from_millis(PLUGIN_RELOAD_DEBOUNCE_MS)
                            }) {
                                tracing::debug!(plugin_id = %plugin_id, "Plugin watcher: debounced JS reload");
                                continue;
                            }
                            p.insert(plugin_id.clone(), Instant::now());
                            drop(p);

                            // 经注入的 PluginHost 弱引用取 app_handle（整核抽出：不再经
                            // lib `AppContext::global()`）；弱引用失效 → 跳过
                            let Some(ph) = plugin_host_weak.upgrade() else {
                                continue;
                            };
                            // 无头/测试上下文无 AppHandle：跳过前端重载通知
                            if let Some(handle) = ph.wasm_host_ctx().app_handle() {
                                let _ = handle.emit(
                                    PLUGIN_DEV_RELOAD,
                                    serde_json::json!({ "pluginId": plugin_id }),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            },
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create plugin file watcher; dev hot-reload disabled");
                return Self { _watcher: None };
            }
        };

        // 开始监听插件目录（用规范路径；fresh checkout 无目录时记 warn 降级）
        if let Err(e) = watcher.watch(&canonical, RecursiveMode::Recursive) {
            tracing::warn!(
                error = %e,
                dir = %canonical.display(),
                "Failed to start watching plugin directory; dev hot-reload disabled"
            );
            return Self { _watcher: None };
        }

        tracing::info!(
            "Plugin dev watcher started: watching '{}'",
            canonical.display()
        );

        Self {
            _watcher: Some(Box::new(watcher)),
        }
    }
}

/// 从变化文件路径提取插件 ID
///
/// 路径格式：plugins_dir/{plugin-id}/xxx
/// 例如：resources/plugins/desktop/com.wasmnest.ai-chatbox/wasmnest_plugin_ai_chatbox.wasm
///       → "com.wasmnest.ai-chatbox"
fn extract_plugin_id(path: &std::path::Path, plugins_dir: &std::path::Path) -> Option<String> {
    path.strip_prefix(plugins_dir)
        .ok()?
        .iter()
        .next()?
        .to_str()
        .map(String::from)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    // 可独立测试的面仅 extract_plugin_id（纯路径解析，不依赖文件系统）。
    // start() 的回调闭包强耦合 notify 事件循环、tokio runtime_handle 与全局
    // AppContext（触发热重载 / 前端 reload 事件），且防抖状态被闭包捕获，
    // 需重构为可注入的处理器才能单测；事件回调行为暂不覆盖。

    fn plugins_dir() -> std::path::PathBuf {
        std::path::PathBuf::from("/tmp/wasmnest-plugins")
    }

    /// 标准产物路径：plugins_dir/{plugin-id}/{filename} → 插件 ID
    #[test]
    fn test_extract_plugin_id_from_nested_file() {
        let dir = plugins_dir();
        let path = dir
            .join("com.wasmnest.ai-chatbox")
            .join("wasmnest_plugin_ai_chatbox.wasm");
        assert_eq!(
            extract_plugin_id(&path, &dir),
            Some("com.wasmnest.ai-chatbox".to_string())
        );
    }

    /// 路径不在 plugins_dir 下 → None（例如其他目录的产物）
    #[test]
    fn test_extract_plugin_id_path_outside_plugins_dir() {
        let dir = plugins_dir();
        let path = std::path::PathBuf::from("/other/plugin-a/x.wasm");
        assert_eq!(extract_plugin_id(&path, &dir), None);
    }

    /// 路径就是 plugins_dir 本身（无第一段子目录）→ None
    #[test]
    fn test_extract_plugin_id_plugins_dir_itself() {
        let dir = plugins_dir();
        assert_eq!(extract_plugin_id(&dir, &dir), None);
    }

    /// 深层目录（插件子目录下再嵌套目录）仍取第一段为插件 ID
    #[test]
    fn test_extract_plugin_id_deeply_nested_path() {
        let dir = plugins_dir();
        let path = dir
            .join("plugin-a")
            .join("dist")
            .join("assets")
            .join("main.js");
        assert_eq!(extract_plugin_id(&path, &dir), Some("plugin-a".to_string()));
    }

    /// 非 UTF-8 路径段返回 None（to_str 失败）
    #[cfg(unix)]
    #[test]
    fn test_extract_plugin_id_non_utf8_segment() {
        use std::os::unix::ffi::OsStrExt;
        let dir = plugins_dir();
        let plugin_dir = dir.join(std::ffi::OsStr::from_bytes(b"plugin-\xFF"));
        let path = plugin_dir.join("x.wasm");
        assert_eq!(extract_plugin_id(&path, &dir), None);
    }
}
