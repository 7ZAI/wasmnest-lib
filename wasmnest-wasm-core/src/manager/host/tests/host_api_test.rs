//! PluginHost 状态与访问器用例（静态注册插件 + 状态机 + 懒激活判据）。

use super::scaffold::*;
use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_static_builtin_activated_notifies_startup() {
    let host = setup_host().await;
    // 未激活（Loaded）时 notify_startup 不得回调 —— 旧行为矛盾点：
    // 日志称 loaded 却永不激活、on_startup 永不执行
    host.plugins.write().await.insert(
        SYNTHETIC_STATIC_ID.to_string(),
        make_plugin(
            SYNTHETIC_STATIC_ID,
            PluginSource::StaticRegistry,
            PluginState::Loaded,
        ),
    );
    SYNTHETIC_ON_STARTUP_CALLED.store(false, Ordering::SeqCst);
    host.notify_startup().await;
    assert!(
        !SYNTHETIC_ON_STARTUP_CALLED.load(Ordering::SeqCst),
        "未激活的静态插件不应收到 on_startup 回调"
    );

    // 置 Activated（模拟 new() 的 builtin 常驻初始化产物）：回调真实发生
    host.plugins
        .write()
        .await
        .get_mut(SYNTHETIC_STATIC_ID)
        .unwrap()
        .state = PluginState::Activated;
    assert!(host.is_activated(SYNTHETIC_STATIC_ID).await);
    host.notify_startup().await;
    assert!(
        SYNTHETIC_ON_STARTUP_CALLED.load(Ordering::SeqCst),
        "notify_startup 应回调已激活静态插件的 on_startup"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_static_builtin_command_routed_after_activation() {
    let host = setup_host().await;
    // 经 register_rust_command_handlers 从合成 inventory 条目注册 handler
    host.register_rust_command_handlers().await;

    // 未激活：身份门禁拒绝
    host.plugins.write().await.insert(
        SYNTHETIC_STATIC_ID.to_string(),
        make_plugin(
            SYNTHETIC_STATIC_ID,
            PluginSource::StaticRegistry,
            PluginState::Loaded,
        ),
    );
    let err = host
        .invoke_rust_command(SYNTHETIC_STATIC_ID, "ping", json!({}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not activated"));

    // 置 Activated 后命令可达 handler
    host.plugins
        .write()
        .await
        .get_mut(SYNTHETIC_STATIC_ID)
        .unwrap()
        .state = PluginState::Activated;
    let result = host
        .invoke_rust_command(SYNTHETIC_STATIC_ID, "ping", json!({}))
        .await
        .unwrap();
    assert_eq!(result, json!({ "pong": true }));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_static_builtin_deactivate_and_reactivate() {
    let host = setup_host().await;
    host.register_rust_command_handlers().await;
    host.plugins.write().await.insert(
        SYNTHETIC_STATIC_ID.to_string(),
        make_plugin(
            SYNTHETIC_STATIC_ID,
            PluginSource::StaticRegistry,
            PluginState::Activated,
        ),
    );
    assert!(host
        .invoke_rust_command(SYNTHETIC_STATIC_ID, "ping", json!({}))
        .await
        .is_ok());

    // 停用：回落 Deactivated，命令门禁重新关闭
    host.deactivate_plugin(SYNTHETIC_STATIC_ID, false)
        .await
        .unwrap();
    assert!(!host.is_activated(SYNTHETIC_STATIC_ID).await);
    assert_eq!(
        host.get_plugin(SYNTHETIC_STATIC_ID).await.unwrap().state,
        PluginState::Deactivated
    );
    assert!(host
        .invoke_rust_command(SYNTHETIC_STATIC_ID, "ping", json!({}))
        .await
        .is_err());

    // 重启：activate_plugin 对 StaticRegistry 跳过 WASM phase 直接置回 Activated，命令恢复路由
    host.activate_plugin(SYNTHETIC_STATIC_ID, false)
        .await
        .unwrap();
    assert!(host.is_activated(SYNTHETIC_STATIC_ID).await);
    let result = host
        .invoke_rust_command(SYNTHETIC_STATIC_ID, "ping", json!({}))
        .await
        .unwrap();
    assert_eq!(result, json!({ "pong": true }));
}

// ==================== Accessors ====================

#[tokio::test(flavor = "multi_thread")]
async fn test_accessors_return_shared_arcs() {
    let host = setup_host().await;
    // getter 返回的是与字段共享的同一 Arc（Clone 语义）
    assert!(Arc::ptr_eq(host.registry(), &host.registry));
    assert!(Arc::ptr_eq(host.permission(), &host.permission));
    assert!(Arc::ptr_eq(host.storage(), &host.storage));
    assert!(Arc::ptr_eq(host.wasm_runtime(), &host.wasm_runtime));
    assert!(Arc::ptr_eq(host.message_bus(), &host.message_bus));
    assert!(Arc::ptr_eq(host.wasm_host_ctx(), &host.wasm_host_ctx));
}

// ==================== Plugins Map 查询 ====================

#[tokio::test(flavor = "multi_thread")]
async fn test_list_plugins_and_get_plugin() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );
    host.plugins.write().await.insert(
        "com.wasmnest.static".to_string(),
        make_plugin(
            "com.wasmnest.static",
            PluginSource::StaticRegistry,
            PluginState::Loaded,
        ),
    );

    let list = host.list_plugins().await;
    assert_eq!(list.len(), 2);
    // 来源映射到前端友好字符串
    let scanned = list.iter().find(|p| p.id == TEST_PLUGIN_ID).unwrap();
    assert_eq!(scanned.source, "scanned");
    assert_eq!(scanned.state, PluginState::Activated);
    let builtin = list.iter().find(|p| p.id == "com.wasmnest.static").unwrap();
    assert_eq!(builtin.source, "builtin");

    // get_plugin：命中与未命中
    assert!(host.get_plugin("com.missing").await.is_none());
    let info = host.get_plugin(TEST_PLUGIN_ID).await.unwrap();
    assert_eq!(info.id, TEST_PLUGIN_ID);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_is_activated_by_state() {
    let host = setup_host().await;
    // 未注册插件 → false
    assert!(!host.is_activated("com.missing").await);

    for (state, expected) in [
        (PluginState::Loaded, false),
        (PluginState::Activated, true),
        (PluginState::Deactivated, false),
        (
            PluginState::Error {
                error: "boom".into(),
            },
            false,
        ),
    ] {
        host.plugins.write().await.insert(
            TEST_PLUGIN_ID.to_string(),
            make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, state),
        );
        assert_eq!(host.is_activated(TEST_PLUGIN_ID).await, expected);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mark_error_updates_state() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );

    host.mark_error(TEST_PLUGIN_ID, "hooks install failed".to_string())
        .await;
    let info = host.get_plugin(TEST_PLUGIN_ID).await.unwrap();
    assert_eq!(
        info.state,
        PluginState::Error {
            error: "hooks install failed".to_string()
        }
    );

    // 未注册插件：静默 no-op，不 panic
    host.mark_error("com.missing", "x".to_string()).await;
    assert!(host.get_plugin("com.missing").await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_activated_state_excludes_static() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );
    host.plugins.write().await.insert(
        "com.wasmnest.ts".to_string(),
        make_plugin(
            "com.wasmnest.ts",
            PluginSource::FileScan,
            PluginState::Deactivated,
        ),
    );
    // 静态注册插件即使激活也不应进入持久化映射（由应用进程生命周期托管）
    host.plugins.write().await.insert(
        "com.wasmnest.static".to_string(),
        make_plugin(
            "com.wasmnest.static",
            PluginSource::StaticRegistry,
            PluginState::Activated,
        ),
    );

    let map = host.get_activated_state().await;
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(TEST_PLUGIN_ID), Some(&true));
    assert_eq!(map.get("com.wasmnest.ts"), Some(&false));
    assert!(!map.contains_key("com.wasmnest.static"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_should_lazy_activate_rules() {
    let host = setup_host().await;
    // 未注册 → false
    assert!(!host.should_lazy_activate("com.missing").await);

    // Loaded + 有命令贡献 → 需要按需激活
    let mut plugin = make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded);
    plugin.manifest.contributes = PluginContributes {
        commands: vec![crate::manifest::CommandContribution {
            id: "test.cmd".into(),
            title: "T".into(),
            icon: None,
            cli: None,
        }],
        ..Default::default()
    };
    host.plugins
        .write()
        .await
        .insert(TEST_PLUGIN_ID.to_string(), plugin);
    assert!(host.should_lazy_activate(TEST_PLUGIN_ID).await);

    // 无任何扩展点贡献 → false（激活无意义）
    host.plugins.write().await.insert(
        "com.wasmnest.empty".to_string(),
        make_plugin(
            "com.wasmnest.empty",
            PluginSource::FileScan,
            PluginState::Loaded,
        ),
    );
    assert!(!host.should_lazy_activate("com.wasmnest.empty").await);

    // 已激活/已停用/错误态 → false（仅 Loaded 态参与按需激活）
    host.plugins.write().await.insert(
        "com.wasmnest.act".to_string(),
        make_plugin(
            "com.wasmnest.act",
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );
    assert!(!host.should_lazy_activate("com.wasmnest.act").await);

    // 静态注册插件 → false（生命周期由 inventory 注册表托管）
    let mut static_p = make_plugin(
        "com.wasmnest.s",
        PluginSource::StaticRegistry,
        PluginState::Loaded,
    );
    static_p.manifest.contributes = PluginContributes {
        commands: vec![crate::manifest::CommandContribution {
            id: "test.cmd".into(),
            title: "T".into(),
            icon: None,
            cli: None,
        }],
        ..Default::default()
    };
    host.plugins
        .write()
        .await
        .insert("com.wasmnest.s".to_string(), static_p);
    assert!(!host.should_lazy_activate("com.wasmnest.s").await);
}
