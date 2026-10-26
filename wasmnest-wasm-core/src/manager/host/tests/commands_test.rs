//! Rust 命令分派与终端管道用例。

use super::scaffold::*;
use super::*;

// ==================== Rust Command Dispatch ====================

#[tokio::test(flavor = "multi_thread")]
async fn test_invoke_rust_command_gates() {
    let host = setup_host().await;
    // 未注册 / 未激活 → Err（调用者身份门禁）
    let err = host
        .invoke_rust_command("com.missing", "cmd", json!({}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not activated"));

    // TS-only 插件（FileScan）→ 拒绝 Rust command
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );
    let err = host
        .invoke_rust_command(TEST_PLUGIN_ID, "cmd", json!({}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("TS-only"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invoke_static_command_ok() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::StaticRegistry,
            PluginState::Activated,
        ),
    );
    // 运行时注册表直接注入 handler（等价于 register_rust_command_handlers 的产物）
    let cmd = PluginCommand::new("hello", |args| async move {
        Ok(serde_json::json!({ "echo": args }))
    });
    host.rust_command_handlers
        .write()
        .await
        .insert(format!("{}::hello", TEST_PLUGIN_ID), cmd);

    let result = host
        .invoke_rust_command(TEST_PLUGIN_ID, "hello", json!({"k": 1}))
        .await
        .unwrap();
    assert_eq!(result, json!({ "echo": { "k": 1 } }));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invoke_static_command_not_found() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::StaticRegistry,
            PluginState::Activated,
        ),
    );

    let err = host
        .invoke_rust_command(TEST_PLUGIN_ID, "missing", json!({}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Command not found"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invoke_static_command_handler_error() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::StaticRegistry,
            PluginState::Activated,
        ),
    );
    let cmd = PluginCommand::new("boom", |_args| async move {
        Err(anyhow::anyhow!("handler exploded"))
    });
    host.rust_command_handlers
        .write()
        .await
        .insert(format!("{}::boom", TEST_PLUGIN_ID), cmd);

    let err = host
        .invoke_rust_command(TEST_PLUGIN_ID, "boom", json!({}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Command execution error"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_list_rust_commands_parses_namespace() {
    let host = setup_host().await;
    for (pid, cmd_name, title) in [
        ("com.a", "cmd1", "One"),
        ("com.a", "cmd2", "Two"),
        ("com.b", "cmd3", "Three"),
    ] {
        let cmd = PluginCommand::new(cmd_name, |_args| async move { Ok(serde_json::json!(null)) })
            .with_title(title);
        host.rust_command_handlers
            .write()
            .await
            .insert(format!("{}::{}", pid, cmd_name), cmd);
    }

    let mut entries = host.list_rust_commands().await;
    // HashMap 迭代无序：按 (plugin_id, command_name) 排序后比较
    entries.sort_by(|a, b| {
        (a.plugin_id.clone(), a.command_name.clone())
            .cmp(&(b.plugin_id.clone(), b.command_name.clone()))
    });
    let pairs: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.plugin_id.clone(), e.command_name.clone()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("com.a".to_string(), "cmd1".to_string()),
            ("com.a".to_string(), "cmd2".to_string()),
            ("com.b".to_string(), "cmd3".to_string()),
        ]
    );
    // 全名 `plugin_id::command_name` 正确拆分
    assert_eq!(entries[0].title, "One");
}

// ==================== Terminal Handler Pipeline ====================

/// 转换输出的 mock 处理器
struct MockTerminalHandler;

impl TerminalHandler for MockTerminalHandler {
    fn on_output(&self, _session_id: &str, data: &str) -> Option<String> {
        Some(data.to_uppercase())
    }
}

/// 默认实现（全部透传）的处理器
struct PassthroughHandler;

impl TerminalHandler for PassthroughHandler {}

/// 输出管道：无 handler 原样透传；有 handler 依序生效（后一个的 None 不覆盖前一个结果）。
///
/// **票 03 起本用例只覆盖输出侧**：输入侧的逐帧修饰链（`process_terminal_input`）与
/// 提交行观察分发（`process_input_submitted`）已随宿主观察面退役——用户键入的字节
/// 现在由 `com.wasmnest.bedcode` 经 `host-pty.write` 原样写入，宿主不再介入。
#[tokio::test(flavor = "multi_thread")]
async fn test_terminal_output_pipeline() {
    let host = setup_host().await;
    // 无 handler：输出原样透传
    assert!(!host.has_terminal_handlers().await);
    assert_eq!(host.process_terminal_output("s1", "Hello").await, "Hello");

    host.rust_terminal_handlers
        .write()
        .await
        .push(Box::new(MockTerminalHandler));
    // 第二个 handler 不修改（验证 None 语义透传）
    host.rust_terminal_handlers
        .write()
        .await
        .push(Box::new(PassthroughHandler));

    assert!(host.has_terminal_handlers().await);
    assert_eq!(host.process_terminal_output("s1", "Hello").await, "HELLO");
}

// ==================== MessageDispatcher ====================

#[tokio::test(flavor = "multi_thread")]
async fn test_message_dispatcher_is_activated() {
    let host = setup_host().await;
    assert!(!MessageDispatcher::is_activated(&host, "com.missing"));

    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );
    assert!(MessageDispatcher::is_activated(&host, TEST_PLUGIN_ID));

    host.plugins.write().await.insert(
        "com.wasmnest.d".to_string(),
        make_plugin(
            "com.wasmnest.d",
            PluginSource::FileScan,
            PluginState::Deactivated,
        ),
    );
    assert!(!MessageDispatcher::is_activated(&host, "com.wasmnest.d"));
}
