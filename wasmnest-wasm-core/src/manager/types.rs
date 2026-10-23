//! Plugin Types (Host)
//!
//! 桌面端插件类型 — 仅保留桌面端特有的内部模型
//! 共享类型（PluginManifest, PluginContributes, PluginState 等）迁移到 wasmnest-plugin-api

// 中性词汇（票 02 M4）：机制层不再按形态引用 SDK——清单/状态/类型词汇
// 统一取自 crate::manifest（超集；双端绑定层转换）
use crate::manifest::{PluginContributes, PluginKind, PluginManifest, PluginState, PluginType};
use chrono::{DateTime, Utc};
use std::path::Path;

/// 已加载插件的内部表示
#[derive(Clone)]
pub struct LoadedPlugin {
    pub manifest: PluginManifest,
    pub state: PluginState,
    pub extension_path: String,
    pub activated_at: Option<DateTime<Utc>>,
    /// 插件来源：静态注册或文件扫描
    pub source: PluginSource,
}

/// 插件来源
#[derive(Debug, Clone, PartialEq)]
pub enum PluginSource {
    /// 静态注册的 Rust 插件（通过 inventory::collect）
    StaticRegistry,
    /// 文件系统扫描的 TS-only 插件
    FileScan,
    /// WASM 模块加载的 Rust+TS 插件
    Wasm,
    /// 用户从 zip 安装的插件（位于 app_data_dir/plugins，可卸载）
    UserInstalled,
}

impl PluginSource {
    /// 序列化为前端友好字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StaticRegistry => "builtin",
            Self::FileScan => "scanned",
            Self::Wasm => "wasm",
            Self::UserInstalled => "user-installed",
        }
    }

    /// 插件是否携带 WASM 后端（需要执行 guest 生命周期回调）。
    ///
    /// 内置 wasm 插件恒真；用户 zip 安装（`UserInstalled`）仅当 manifest 声明
    /// `rust_library` 时有 wasm 实例。区分意义：激活/停用/热重载的 guest 调用
    /// 必须以「有实例」为准，否则用户安装的 rust-ts 插件会在**未运行 guest
    /// activate** 的实例上执行命令——guest 侧 OnceLock 激活态（数据目录等）
    /// 永不初始化，典型报错 `activate incomplete`（agent-hub 票据复现）。
    /// TS-only 用户插件无实例，维持原语义（跳过 guest 生命周期）。
    pub fn has_wasm_backend(&self, rust_library: &str) -> bool {
        match self {
            Self::Wasm => true,
            Self::UserInstalled => !rust_library.is_empty(),
            Self::StaticRegistry | Self::FileScan => false,
        }
    }
}

/// 插件信息（返回给前端的精简版本）
///
/// 从 wasmnest_plugin_api::PluginInfo 扩展，添加宿主特有字段
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostPluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub main: String,
    pub plugin_type: PluginType,
    /// 装配角色（L1 基础服务 / L2 内部业务 / L3 应用）；缺省 = L3
    #[serde(default)]
    pub kind: PluginKind,
    /// WASM 模块文件名（仅 rust-ts 类型插件使用）
    pub rust_library: String,
    pub permissions: Vec<String>,
    pub state: PluginState,
    pub extension_path: String,
    pub contributes: PluginContributes,
    /// 插件图标（manifest.icon 透传，可为空）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// 插件来源
    pub source: String,
    /// 插件目录总大小（字节）
    pub size_bytes: u64,
    /// 安装时间（unix 毫秒，plugin.json mtime）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<i64>,
}

impl From<&LoadedPlugin> for HostPluginInfo {
    fn from(p: &LoadedPlugin) -> Self {
        HostPluginInfo {
            id: p.manifest.id.clone(),
            name: p.manifest.name.clone(),
            version: p.manifest.version.clone(),
            description: p.manifest.description.clone(),
            author: p.manifest.author.clone(),
            main: p.manifest.main.clone(),
            plugin_type: p.manifest.plugin_type.clone(),
            kind: p.manifest.kind,
            rust_library: p.manifest.rust_library.clone(),
            permissions: p.manifest.permissions.clone(),
            state: p.state.clone(),
            extension_path: p.extension_path.clone(),
            contributes: p.manifest.contributes.clone(),
            icon: p.manifest.icon.clone(),
            source: p.source.as_str().to_string(),
            size_bytes: dir_size(Path::new(&p.extension_path)),
            installed_at: manifest_installed_at(&p.extension_path),
        }
    }
}

/// 递归计算目录总大小（字节），路径不存在或不可读时返回 0
fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(ft) if ft.is_file() => {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
                Ok(ft) if ft.is_dir() => {
                    total += dir_size(&entry.path());
                }
                _ => {}
            }
        }
    }
    total
}

/// 以 plugin.json 的 mtime 近似安装时间（unix 毫秒）
fn manifest_installed_at(extension_path: &str) -> Option<i64> {
    let manifest_path = Path::new(extension_path).join("plugin.json");
    std::fs::metadata(manifest_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as i64)
        })
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    // 中性词汇（票 02 M4）：测试段同机制层口径
    use crate::manifest::{PluginKind, PluginManifest, PluginState, PluginType};

    /// 构造带完整字段的测试 manifest
    ///
    /// 只列本用例真正断言的字段，其余走 `Default`——SDK 追加可选字段时不必回来补格子
    /// （会话引擎下沉票 14：`pty_quota` 追加时六处字面量漏了一处，宿主 `--lib` 红 6 项）。
    fn sample_manifest() -> PluginManifest {
        PluginManifest {
            id: "com.wasmnest.test".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.2.3".to_string(),
            description: "descriptive text".to_string(),
            author: "tester".to_string(),
            main: "index.ts".to_string(),
            permissions: vec!["broadcast".to_string(), "storage".to_string()],
            plugin_type: PluginType::RustTs,
            rust_library: "wasmnest_test.wasm".to_string(),
            ..Default::default()
        }
    }

    /// 构造测试 LoadedPlugin
    fn sample_loaded(source: PluginSource) -> LoadedPlugin {
        LoadedPlugin {
            manifest: sample_manifest(),
            state: PluginState::Activated,
            extension_path: "/nonexistent/plugins/com.wasmnest.test".to_string(),
            activated_at: Some(Utc::now()),
            source,
        }
    }

    /// PluginSource 序列化为前端友好字符串
    #[test]
    fn test_plugin_source_as_str() {
        assert_eq!(PluginSource::StaticRegistry.as_str(), "builtin");
        assert_eq!(PluginSource::FileScan.as_str(), "scanned");
        assert_eq!(PluginSource::Wasm.as_str(), "wasm");
    }

    /// LoadedPlugin → HostPluginInfo 字段一一映射（期望值为手写字面量）
    #[test]
    fn test_loaded_plugin_to_host_info_mapping() {
        let plugin = sample_loaded(PluginSource::Wasm);
        let info = HostPluginInfo::from(&plugin);

        assert_eq!(info.id, "com.wasmnest.test");
        assert_eq!(info.name, "Test Plugin");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.description, "descriptive text");
        assert_eq!(info.author, "tester");
        assert_eq!(info.main, "index.ts");
        assert_eq!(info.plugin_type, PluginType::RustTs);
        assert_eq!(info.kind, PluginKind::BusinessApp);
        assert_eq!(info.rust_library, "wasmnest_test.wasm");
        assert_eq!(info.permissions, vec!["broadcast", "storage"]);
        assert_eq!(info.state, PluginState::Activated);
        assert_eq!(info.extension_path, plugin.extension_path);
        assert_eq!(info.source, "wasm");
        // 扩展路径不存在时大小与安装时间均为缺省值
        assert_eq!(info.size_bytes, 0);
        assert!(info.installed_at.is_none());
    }

    /// icon 与 source 的序列化形态：icon=None 时省略字段，source 原样输出
    #[test]
    fn test_host_info_serialization_omit_icon() {
        let plugin = sample_loaded(PluginSource::FileScan);
        let info = HostPluginInfo::from(&plugin);
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["source"], "scanned");
        assert_eq!(
            json["pluginType"], "rust-ts",
            "PluginType 序列化为 kebab-case"
        );
        assert!(json.get("icon").is_none(), "icon=None 时应省略字段");
        assert!(json.get("installedAt").is_none());
    }

    /// 装配角色随清单透传，并按 kebab-case 序列化（监控页用它区分服务 / 应用）
    #[test]
    fn test_host_info_serializes_plugin_kind() {
        let mut plugin = sample_loaded(PluginSource::Wasm);
        plugin.manifest.kind = PluginKind::InternalBusiness;
        let info = HostPluginInfo::from(&plugin);

        assert_eq!(info.kind, PluginKind::InternalBusiness);
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["kind"], "internal-business");

        // 旧载荷缺 kind 时按缺省 L3 反序列化（向后兼容）
        let decoded: HostPluginInfo = serde_json::from_value(json).unwrap();
        let mut legacy = serde_json::to_value(&decoded).unwrap();
        legacy.as_object_mut().unwrap().remove("kind");
        let legacy_info: HostPluginInfo = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy_info.kind, PluginKind::BusinessApp);
    }

    /// icon 有值时透传并在序列化中保留
    #[test]
    fn test_host_info_serialization_with_icon() {
        let mut plugin = sample_loaded(PluginSource::StaticRegistry);
        plugin.manifest.icon = Some("icon.svg".to_string());
        let info = HostPluginInfo::from(&plugin);
        assert_eq!(info.icon.as_deref(), Some("icon.svg"));
        assert_eq!(info.source, "builtin");
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["icon"], "icon.svg");
    }

    /// size_bytes 递归统计目录内全部文件字节数（含嵌套目录）
    #[test]
    fn test_dir_size_counts_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        // 插件根：plugin.json 3 字节；嵌套子目录：a.bin 42 字节
        std::fs::write(dir.path().join("plugin.json"), b"{}").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("a.bin"), vec![0u8; 42]).unwrap();
        assert_eq!(dir_size(dir.path()), 44);
    }

    /// 不存在的路径统计为 0（不 panic）
    #[test]
    fn test_dir_size_missing_path_is_zero() {
        let missing = std::path::Path::new("/nonexistent-wasmnest-dir-xyz");
        assert_eq!(dir_size(missing), 0);
    }

    /// manifest_installed_at：扩展路径含 plugin.json 时返回其 mtime（unix 毫秒）
    #[test]
    fn test_manifest_installed_at_reads_mtime() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plugin.json"), b"{}").unwrap();
        let millis = manifest_installed_at(&dir.path().to_string_lossy()).expect("应返回安装时间");
        assert!(millis > 0);
    }

    /// manifest_installed_at：缺少 plugin.json 时返回 None
    #[test]
    fn test_manifest_installed_at_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(manifest_installed_at(&dir.path().to_string_lossy()).is_none());
    }

    /// From 转换在真实扩展目录上的端到端表现：size_bytes 与 installed_at 来自磁盘
    #[test]
    fn test_host_info_from_real_extension_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plugin.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("main.js"), vec![7u8; 100]).unwrap();

        let mut plugin = sample_loaded(PluginSource::Wasm);
        plugin.extension_path = dir.path().to_string_lossy().to_string();
        let info = HostPluginInfo::from(&plugin);

        assert_eq!(info.size_bytes, 102, "plugin.json(2) + main.js(100)");
        assert!(info.installed_at.is_some());
        assert_eq!(info.source, "wasm");
    }
}

// ==================== 移动装配面事件（fork 迁入，票 06 批次 03） ====================

/// 插件生命周期事件（票 02 M4 常编译：中性纯枚举——移动装配面
/// `dispatch_lifecycle_event` 消费；桌面无消费方但保持编译，不留形态分叉）
///
/// 统一的事件枚举，供 PluginManager::dispatch_lifecycle_event() 使用。
/// 每个变体携带触发点传入的上下文数据。
#[derive(Debug, Clone)]
pub enum PluginLifecycleEvent {
    AppStartup,
    AppShutdown,
    AuthSuccess,
    Disconnect { reason: String },
    SessionCreated { session_id: String },
    SessionStopped { session_id: String },
}

impl PluginLifecycleEvent {
    /// 返回声明字段名（用于 is_declared 检查）
    pub fn name(&self) -> &'static str {
        match self {
            Self::AppStartup => "onStartup",
            Self::AppShutdown => "onShutdown",
            Self::AuthSuccess => "onAuthSuccess",
            Self::Disconnect { .. } => "onDisconnect",
            Self::SessionCreated { .. } => "onSessionCreated",
            Self::SessionStopped { .. } => "onSessionStopped",
        }
    }

    /// 返回前端 Tauri 事件名（不含 plugin:lifecycle: 前缀）
    pub fn tauri_event_name(&self) -> &'static str {
        match self {
            Self::AppStartup => "appStartup",
            Self::AppShutdown => "appShutdown",
            Self::AuthSuccess => "authSuccess",
            Self::Disconnect { .. } => "disconnect",
            Self::SessionCreated { .. } => "sessionCreated",
            Self::SessionStopped { .. } => "sessionStopped",
        }
    }

    /// 转为前端 Tauri 事件 payload
    pub fn to_payload(&self) -> serde_json::Value {
        match self {
            Self::AppStartup | Self::AppShutdown | Self::AuthSuccess => {
                serde_json::json!({})
            }
            Self::Disconnect { reason } => {
                serde_json::json!({ "reason": reason })
            }
            Self::SessionCreated { session_id } | Self::SessionStopped { session_id } => {
                serde_json::json!({ "sessionId": session_id })
            }
        }
    }
}
