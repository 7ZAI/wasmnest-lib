//! Plugin Registry
//!
//! 扩展点注册表 — 管理 commands/views/terminal/http/file_handlers 的注册与查询
//! 前端 PluginContext 的注册调用通过 Tauri invoke 到达此注册表

// 中性词汇（票 02 M4）：贡献类型统一取自 crate::manifest（超集——含移动
// 无的 fileHandlers 声明面，机制保留，移动宿主不消费）
use crate::manifest::{CommandContribution, FileHandlerContribution, ViewContribution};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 已注册的命令条目
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandEntry {
    pub plugin_id: String,
    pub command_id: String,
    pub title: String,
    pub icon: Option<String>,
}

/// 已注册的视图条目
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewEntry {
    pub plugin_id: String,
    pub view_id: String,
    pub view_type: String,
    pub title: String,
    pub component: String,
}

/// 已注册的终端处理器
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalHandlers {
    pub plugin_id: String,
    pub input_handlers: Vec<String>,
    pub output_parsers: Vec<String>,
}

/// 已注册的文件处理器
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHandlerEntry {
    pub plugin_id: String,
    pub handler_id: String,
    pub extensions: Vec<String>,
    pub viewer: String,
    pub icon: Option<String>,
}

/// 扩展点注册表
pub struct PluginRegistry {
    commands: Arc<RwLock<HashMap<String, CommandEntry>>>,
    views: Arc<RwLock<HashMap<String, ViewEntry>>>,
    terminal_handlers: Arc<RwLock<HashMap<String, TerminalHandlers>>>,
    file_handlers: Arc<RwLock<HashMap<String, FileHandlerEntry>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            commands: Arc::new(RwLock::new(HashMap::new())),
            views: Arc::new(RwLock::new(HashMap::new())),
            terminal_handlers: Arc::new(RwLock::new(HashMap::new())),
            file_handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // ==================== Commands ====================

    /// 注册命令（从 manifest contributes.commands 批量注册）
    pub async fn register_commands(&self, plugin_id: &str, commands: &[CommandContribution]) {
        let mut map = self.commands.write().await;
        for cmd in commands {
            let entry = CommandEntry {
                plugin_id: plugin_id.to_string(),
                command_id: cmd.id.clone(),
                title: cmd.title.clone(),
                icon: cmd.icon.clone(),
            };
            map.insert(cmd.id.clone(), entry);
        }
    }

    /// 获取所有已注册的命令
    pub async fn list_commands(&self) -> Vec<CommandEntry> {
        self.commands.read().await.values().cloned().collect()
    }

    /// 获取指定插件的命令
    pub async fn get_plugin_commands(&self, plugin_id: &str) -> Vec<CommandEntry> {
        self.commands
            .read()
            .await
            .values()
            .filter(|e| e.plugin_id == plugin_id)
            .cloned()
            .collect()
    }

    // ==================== Views ====================

    /// 注册视图（从 manifest contributes.views 批量注册）
    pub async fn register_views(&self, plugin_id: &str, views: &[ViewContribution]) {
        let mut map = self.views.write().await;
        for view in views {
            let entry = ViewEntry {
                plugin_id: plugin_id.to_string(),
                view_id: view.id.clone(),
                view_type: view.view_type.clone(),
                title: view.title.clone(),
                component: view.component.clone(),
            };
            map.insert(view.id.clone(), entry);
        }
    }

    /// 获取指定类型的视图（sidebar/toolbox/statusbar）
    pub async fn get_views_by_type(&self, view_type: &str) -> Vec<ViewEntry> {
        self.views
            .read()
            .await
            .values()
            .filter(|e| e.view_type == view_type)
            .cloned()
            .collect()
    }

    /// 获取所有已注册的视图
    pub async fn list_views(&self) -> Vec<ViewEntry> {
        self.views.read().await.values().cloned().collect()
    }

    // ==================== Terminal ====================

    /// 注册终端处理器
    pub async fn register_terminal_handlers(
        &self,
        plugin_id: &str,
        input_handlers: &[String],
        output_parsers: &[String],
    ) {
        let mut map = self.terminal_handlers.write().await;
        map.insert(
            plugin_id.to_string(),
            TerminalHandlers {
                plugin_id: plugin_id.to_string(),
                input_handlers: input_handlers.to_vec(),
                output_parsers: output_parsers.to_vec(),
            },
        );
    }

    /// 获取所有终端处理器
    pub async fn list_terminal_handlers(&self) -> Vec<TerminalHandlers> {
        self.terminal_handlers
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    // ==================== File Handlers ====================

    /// 注册文件处理器（从 manifest contributes.fileHandlers 批量注册）
    pub async fn register_file_handlers(
        &self,
        plugin_id: &str,
        handlers: &[FileHandlerContribution],
    ) {
        let mut map = self.file_handlers.write().await;
        for handler in handlers {
            let entry = FileHandlerEntry {
                plugin_id: plugin_id.to_string(),
                handler_id: handler.id.clone(),
                extensions: handler.extensions.clone(),
                viewer: handler.viewer.clone(),
                icon: handler.icon.clone(),
            };
            map.insert(handler.id.clone(), entry);
        }
    }

    /// 根据文件扩展名查找匹配的处理器
    pub async fn find_file_handler(&self, extension: &str) -> Option<FileHandlerEntry> {
        let map = self.file_handlers.read().await;
        for entry in map.values() {
            if entry.extensions.iter().any(|e| e == extension) {
                return Some(entry.clone());
            }
        }
        None
    }

    /// 获取所有已注册的文件处理器
    pub async fn list_file_handlers(&self) -> Vec<FileHandlerEntry> {
        self.file_handlers.read().await.values().cloned().collect()
    }

    // ==================== Cleanup ====================

    /// 移除插件的所有注册（停用时调用）
    pub async fn unregister_plugin(&self, plugin_id: &str) {
        {
            let mut map = self.commands.write().await;
            map.retain(|_, v| v.plugin_id != plugin_id);
        }
        {
            let mut map = self.views.write().await;
            map.retain(|_, v| v.plugin_id != plugin_id);
        }
        {
            let mut map = self.terminal_handlers.write().await;
            map.remove(plugin_id);
        }
        {
            let mut map = self.file_handlers.write().await;
            map.retain(|_, v| v.plugin_id != plugin_id);
        }
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(id: &str, title: &str, icon: Option<&str>) -> CommandContribution {
        CommandContribution {
            id: id.to_string(),
            title: title.to_string(),
            icon: icon.map(|s| s.to_string()),
            cli: None,
        }
    }

    fn view(id: &str, view_type: &str, title: &str) -> ViewContribution {
        ViewContribution {
            id: id.to_string(),
            view_type: view_type.to_string(),
            title: title.to_string(),
            component: format!("{}.vue", id),
        }
    }

    fn file_handler(id: &str, extensions: &[&str], viewer: &str) -> FileHandlerContribution {
        FileHandlerContribution {
            id: id.to_string(),
            extensions: extensions.iter().map(|s| s.to_string()).collect(),
            viewer: viewer.to_string(),
            icon: None,
        }
    }

    /// 从列表按 command_id 取条目（HashMap 遍历无序，断言时先定位）
    fn find_command<'a>(entries: &'a [CommandEntry], command_id: &str) -> Option<&'a CommandEntry> {
        entries.iter().find(|e| e.command_id == command_id)
    }

    /// 新建注册表默认状态：所有扩展点均为空，查询不存在条目返回空/None
    #[tokio::test(flavor = "multi_thread")]
    async fn test_new_registry_is_empty() {
        let registry = PluginRegistry::new();
        assert!(registry.list_commands().await.is_empty());
        assert!(registry.get_plugin_commands("any").await.is_empty());
        assert!(registry.list_views().await.is_empty());
        assert!(registry.get_views_by_type("sidebar").await.is_empty());
        assert!(registry.list_terminal_handlers().await.is_empty());
        assert!(registry.find_file_handler("md").await.is_none());
        assert!(registry.list_file_handlers().await.is_empty());
    }

    /// 命令批量注册后可全量/按插件查询，字段原样保存
    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_commands_and_query_by_plugin() {
        let registry = PluginRegistry::new();
        registry
            .register_commands(
                "plugin-a",
                &[
                    cmd("cmd-1", "Command One", Some("icon1")),
                    cmd("cmd-2", "Command Two", None),
                ],
            )
            .await;
        registry
            .register_commands("plugin-b", &[cmd("cmd-3", "Command Three", None)])
            .await;

        assert_eq!(registry.list_commands().await.len(), 3);
        let plugin_a_cmds = registry.get_plugin_commands("plugin-a").await;
        assert_eq!(plugin_a_cmds.len(), 2);
        let c1 = find_command(&plugin_a_cmds, "cmd-1").expect("cmd-1 应存在");
        assert_eq!(c1.plugin_id, "plugin-a");
        assert_eq!(c1.title, "Command One");
        assert_eq!(c1.icon.as_deref(), Some("icon1"));
        assert_eq!(
            registry.get_plugin_commands("no-such-plugin").await.len(),
            0
        );
    }

    /// 相同 command_id 重复注册以最后一次为准（覆盖语义）
    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_commands_same_id_overwrites() {
        let registry = PluginRegistry::new();
        registry
            .register_commands("plugin-a", &[cmd("dup", "First Title", None)])
            .await;
        registry
            .register_commands("plugin-b", &[cmd("dup", "Second Title", None)])
            .await;

        let entries = registry.list_commands().await;
        assert_eq!(entries.len(), 1);
        let dup = find_command(&entries, "dup").expect("dup 应存在");
        assert_eq!(dup.title, "Second Title");
        assert_eq!(dup.plugin_id, "plugin-b");
    }

    /// 视图按 type 过滤与全量列举
    #[tokio::test(flavor = "multi_thread")]
    async fn test_views_get_by_type_and_list() {
        let registry = PluginRegistry::new();
        registry
            .register_views(
                "plugin-a",
                &[
                    view("v-side", "sidebar", "Side View"),
                    view("v-tool", "toolbox", "Tool View"),
                ],
            )
            .await;
        registry
            .register_views("plugin-b", &[view("v-status", "statusbar", "Status View")])
            .await;

        let sidebars = registry.get_views_by_type("sidebar").await;
        assert_eq!(sidebars.len(), 1);
        assert_eq!(sidebars[0].view_id, "v-side");
        assert_eq!(sidebars[0].plugin_id, "plugin-a");
        assert_eq!(sidebars[0].component, "v-side.vue");
        assert!(registry.get_views_by_type("unknown-type").await.is_empty());
        assert_eq!(registry.list_views().await.len(), 3);
    }

    /// 终端处理器按插件 ID 存储，重复注册覆盖旧值
    #[tokio::test(flavor = "multi_thread")]
    async fn test_terminal_handlers_reregister_overwrites() {
        let registry = PluginRegistry::new();
        registry
            .register_terminal_handlers("plugin-a", &["h1".to_string()], &["p1".to_string()])
            .await;
        // 同一插件再次注册 → 覆盖而非追加
        registry
            .register_terminal_handlers("plugin-a", &["h1".to_string(), "h2".to_string()], &[])
            .await;
        registry
            .register_terminal_handlers("plugin-b", &[], &["p9".to_string()])
            .await;

        let all = registry.list_terminal_handlers().await;
        assert_eq!(all.len(), 2);
        let a = all
            .iter()
            .find(|t| t.plugin_id == "plugin-a")
            .expect("plugin-a 应存在");
        assert_eq!(a.input_handlers, vec!["h1", "h2"]);
        assert!(a.output_parsers.is_empty());
    }

    /// 文件处理器按扩展名匹配；不支持的扩展名返回 None
    #[tokio::test(flavor = "multi_thread")]
    async fn test_file_handlers_find_by_extension_and_missing() {
        let registry = PluginRegistry::new();
        registry
            .register_file_handlers(
                "plugin-a",
                &[file_handler(
                    "md-viewer",
                    &["md", "markdown"],
                    "MarkdownPreview",
                )],
            )
            .await;
        registry
            .register_file_handlers(
                "plugin-b",
                &[file_handler("json-viewer", &["json"], "JsonView")],
            )
            .await;

        let md = registry.find_file_handler("md").await.expect("md 应命中");
        assert_eq!(md.plugin_id, "plugin-a");
        assert_eq!(md.handler_id, "md-viewer");
        assert_eq!(md.viewer, "MarkdownPreview");
        assert_eq!(md.extensions, vec!["md", "markdown"]);
        assert_eq!(
            registry
                .find_file_handler("json")
                .await
                .expect("json 应命中")
                .handler_id,
            "json-viewer"
        );
        assert!(registry.find_file_handler("rs").await.is_none());
        assert_eq!(registry.list_file_handlers().await.len(), 2);
    }

    /// unregister_plugin 移除该插件的全部扩展点注册，其他插件不受影响
    #[tokio::test(flavor = "multi_thread")]
    async fn test_unregister_plugin_removes_all_entries() {
        let registry = PluginRegistry::new();
        registry
            .register_commands("plugin-a", &[cmd("a1", "A1", None)])
            .await;
        registry
            .register_commands("plugin-b", &[cmd("b1", "B1", None)])
            .await;
        registry
            .register_views("plugin-a", &[view("va", "sidebar", "VA")])
            .await;
        registry
            .register_terminal_handlers("plugin-a", &["h".to_string()], &[])
            .await;
        registry
            .register_file_handlers("plugin-a", &[file_handler("fa", &["a"], "A")])
            .await;

        registry.unregister_plugin("plugin-a").await;

        assert_eq!(registry.get_plugin_commands("plugin-a").await.len(), 0);
        assert_eq!(registry.get_plugin_commands("plugin-b").await.len(), 1);
        assert!(registry.get_views_by_type("sidebar").await.is_empty());
        assert!(registry.list_terminal_handlers().await.is_empty());
        assert!(registry.find_file_handler("a").await.is_none());
        // 未注册过任何内容的插件调用 unregister 不应 panic
        registry.unregister_plugin("never-registered").await;
    }

    /// CommandEntry 序列化为 camelCase（前端 invoke 返回约定）
    #[tokio::test(flavor = "multi_thread")]
    async fn test_command_entry_serializes_camel_case() {
        let registry = PluginRegistry::new();
        registry
            .register_commands(
                "plugin-a",
                &[cmd("c1", "T", Some("i")), cmd("c2", "T2", None)],
            )
            .await;
        let json = serde_json::to_value(registry.list_commands().await).unwrap();
        let arr = json.as_array().expect("应为数组");
        assert_eq!(arr.len(), 2);
        for entry in arr {
            assert!(
                entry.get("commandId").is_some(),
                "字段应为 commandId 驼峰命名"
            );
            assert!(entry.get("pluginId").is_some());
            assert!(entry.get("command_id").is_none());
        }
    }
}
