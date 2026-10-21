//! 非 WASM 插件的激活 / 停用 / 持久化 / 启动期自动激活用例。

use super::scaffold::*;
use super::*;
use crate::monitor::LifecycleEvent;

// ==================== 激活 / 停用（非 WASM 插件） ====================

#[tokio::test(flavor = "multi_thread")]
async fn test_activate_plugin_file_scan_flow() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded),
    );

    // 未注册插件 → Err
    let err = host
        .activate_plugin("com.missing", false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"));

    host.activate_plugin(TEST_PLUGIN_ID, false).await.unwrap();

    let info = host.get_plugin(TEST_PLUGIN_ID).await.unwrap();
    assert_eq!(info.state, PluginState::Activated);
    // 激活时间被记录
    {
        let plugins_guard = host.plugins.read().await;
        let loaded = plugins_guard.get(TEST_PLUGIN_ID).unwrap();
        assert!(loaded.activated_at.is_some());
    }
    // 重新授权：manifest 声明的合法权限已授予（storage 恒默认授予）
    let granted = host.permission().get_granted(TEST_PLUGIN_ID);
    assert!(granted.contains("storage"));
    assert!(granted.contains("terminal:input"));
    assert!(host.permission().check(TEST_PLUGIN_ID, "terminal:input"));

    // 重复激活幂等（已激活 → Ok）
    host.activate_plugin(TEST_PLUGIN_ID, false).await.unwrap();
    assert_eq!(
        host.get_plugin(TEST_PLUGIN_ID).await.unwrap().state,
        PluginState::Activated
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_activate_plugin_recovers_from_error_state() {
    let host = setup_host().await;
    // Error 态插件可重新激活（如 WASM 缺失被标记后修复文件再激活）
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Error {
                error: "wasm load failed".into(),
            },
        ),
    );

    host.activate_plugin(TEST_PLUGIN_ID, false).await.unwrap();
    assert_eq!(
        host.get_plugin(TEST_PLUGIN_ID).await.unwrap().state,
        PluginState::Activated
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_activate_plugin_persists_state() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded),
    );

    host.activate_plugin(TEST_PLUGIN_ID, true).await.unwrap();

    let persisted = host.storage().load_activated_plugins().await.unwrap();
    assert_eq!(persisted.get(TEST_PLUGIN_ID), Some(&true));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_deactivate_plugin_flow() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );
    // 预注册一条命令贡献，验证停用时从 registry 摘除
    host.registry()
        .register_commands(
            TEST_PLUGIN_ID,
            &[crate::manifest::CommandContribution {
                id: "test.cmd".into(),
                title: "T".into(),
                icon: None,
            }],
        )
        .await;
    assert_eq!(host.registry().list_commands().await.len(), 1);

    host.deactivate_plugin(TEST_PLUGIN_ID, false).await.unwrap();

    let info = host.get_plugin(TEST_PLUGIN_ID).await.unwrap();
    assert_eq!(info.state, PluginState::Deactivated);
    assert!(!host.is_activated(TEST_PLUGIN_ID).await);
    // 激活时间被清除
    {
        let plugins_guard = host.plugins.read().await;
        let loaded = plugins_guard.get(TEST_PLUGIN_ID).unwrap();
        assert!(loaded.activated_at.is_none());
    }
    // 权限被撤销（重新激活时重新授权）
    assert!(host.permission().get_granted(TEST_PLUGIN_ID).is_empty());
    // registry 贡献被摘除
    assert!(host.registry().list_commands().await.is_empty());

    // 未注册插件 → Err
    let err = host
        .deactivate_plugin("com.missing", false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_deactivate_all() {
    let host = setup_host().await;
    for id in ["com.wasmnest.a", "com.wasmnest.b"] {
        host.plugins.write().await.insert(
            id.to_string(),
            make_plugin(id, PluginSource::FileScan, PluginState::Activated),
        );
    }

    host.deactivate_all().await.unwrap();

    for id in ["com.wasmnest.a", "com.wasmnest.b"] {
        assert_eq!(
            host.get_plugin(id).await.unwrap().state,
            PluginState::Deactivated
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_auto_activate_from_persisted_state() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded),
    );

    // 持久化激活 → 手动停用（不持久化）→ 从持久化状态恢复激活
    host.activate_plugin(TEST_PLUGIN_ID, true).await.unwrap();
    host.deactivate_plugin(TEST_PLUGIN_ID, false).await.unwrap();
    assert!(!host.is_activated(TEST_PLUGIN_ID).await);

    host.auto_activate_from_persisted_state().await;
    assert!(host.is_activated(TEST_PLUGIN_ID).await);

    // 幽灵 ID 清理：持久化映射中不存在的插件被剔除（map 整体替换语义：
    // 重新写入时保留现有条目再插入幽灵 ID）
    let mut stale = HashMap::new();
    stale.insert("com.ghost".to_string(), true);
    stale.insert(TEST_PLUGIN_ID.to_string(), true);
    host.storage().save_activated_plugins(&stale).await.unwrap();
    host.auto_activate_from_persisted_state().await;
    let persisted = host.storage().load_activated_plugins().await.unwrap();
    assert!(!persisted.contains_key("com.ghost"));
    // 已存在的插件条目保留
    assert_eq!(persisted.get(TEST_PLUGIN_ID), Some(&true));
}

/// 退出路径必须覆盖 Degraded 实例（审计票 09）：Degraded 是活实例（前端模块已加载、
/// 扩展点已注册、持久化态按「启用」计，见 `get_activated_state`），只收 Activated
/// 会让它在应用关闭时被静默跳过、收不到 `on_shutdown`。
#[tokio::test(flavor = "multi_thread")]
async fn test_deactivate_all_covers_degraded() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        "com.wasmnest.degraded".to_string(),
        make_plugin(
            "com.wasmnest.degraded",
            PluginSource::FileScan,
            PluginState::Degraded {
                error: "init failed".to_string(),
            },
        ),
    );
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );

    host.deactivate_all().await.unwrap();

    assert_eq!(
        host.get_plugin("com.wasmnest.degraded")
            .await
            .unwrap()
            .state,
        PluginState::Deactivated,
        "Degraded 实例必须在退出流程中被停用"
    );
    assert_eq!(
        host.get_plugin(TEST_PLUGIN_ID).await.unwrap().state,
        PluginState::Deactivated
    );
}

/// 重复激活去重（审计票 09）：`Activating` 是瞬时态，此时再请求激活必须**幂等返回**
/// 且不推进状态机——此前它落进 `_ =>` 分支，第二次调用会把 guest `activate()` 跑第二遍
/// （实例锁只保证串行、不保证去重）。
#[tokio::test(flavor = "multi_thread")]
async fn test_repeat_activation_during_activating_is_idempotent() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activating,
        ),
    );

    host.activate_plugin(TEST_PLUGIN_ID, false).await.unwrap();

    assert_eq!(
        host.get_plugin(TEST_PLUGIN_ID).await.unwrap().state,
        PluginState::Activating,
        "Activating 期间的重复激活必须原样返回，不得推进状态机"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn declared_ws_endpoint_follows_activation_lifecycle() {
    let host = setup_host().await;
    let plugin_id = "com.test.ws-endpoint-lifecycle";
    let mut plugin = make_plugin(plugin_id, PluginSource::FileScan, PluginState::Loaded);
    plugin.manifest.permissions.push("ws:server".to_string());
    plugin.manifest.contributes.ws_endpoints = vec![crate::manifest::WsEndpointContribution::Path(
        "echo".to_string(),
    )];
    host.plugins
        .write()
        .await
        .insert(plugin_id.to_string(), plugin);

    let mount = wasmnest_server_websocket::endpoint::mount_path(plugin_id, "echo");
    host.activate_plugin(plugin_id, false).await.unwrap();
    assert!(wasmnest_server_websocket::endpoint::find_by_mount(&mount).is_some());

    host.deactivate_plugin(plugin_id, false).await.unwrap();
    assert!(wasmnest_server_websocket::endpoint::find_by_mount(&mount).is_none());

    host.activate_plugin(plugin_id, false).await.unwrap();
    assert!(wasmnest_server_websocket::endpoint::find_by_mount(&mount).is_some());
    wasmnest_server_websocket::endpoint::purge_for_plugin(plugin_id);
}

// ==================== 授权记录 / 策略的生命周期（spec §8.3 · 票 09 防回接锁） ====================

/// 授权记录与策略的生命周期：**停用保留 / 卸载清空**（spec §8.3 防回接锁）
///
/// 两者语义不同，合并即错：
/// - **停用**是运行期开关，用户停了又开是常事。清授权记录等于让「停用」变成不可逆
///   操作——重启后所有目录/地址都要重新弹一遍窗。
/// - **卸载**清空（重装即全新授权，与 ADR 0020 内容哈希钉扎同调）。
///
/// 这条锁存在的理由就是「容易被后人顺手统一」：两处都是 `plugin_id` 维度的删除，
/// 看起来像同一件事。变异判据：① 停用路径加 purge ⇒ 后半段转红；② 卸载去掉 purge
/// ⇒ 前半段转红。
#[tokio::test(flavor = "multi_thread")]
async fn auth_records_survive_deactivate_and_are_purged_on_uninstall() {
    use crate::security::auth_policy::{
        AuthPolicyStore, AuthRecordSource, AuthResource, AuthStrategy,
    };

    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(
            TEST_PLUGIN_ID,
            PluginSource::FileScan,
            PluginState::Activated,
        ),
    );
    let store = AuthPolicyStore::new(host.storage().db());
    store
        .set_strategy(TEST_PLUGIN_ID, AuthResource::Fs, AuthStrategy::AlwaysAsk)
        .await
        .expect("seed strategy");
    store
        .grant(
            TEST_PLUGIN_ID,
            AuthResource::Fs,
            "/tmp/some-dir",
            &["read".to_string()],
            AuthRecordSource::User,
        )
        .await
        .expect("seed record");

    // 停用：记录与策略都在
    host.deactivate_plugin(TEST_PLUGIN_ID, false).await.unwrap();
    let after_deactivate = store
        .overview(TEST_PLUGIN_ID, "T", Vec::new())
        .await
        .unwrap();
    assert_eq!(
        after_deactivate.records.len(),
        1,
        "停用不得清授权记录（否则「停了再开」= 全部重新弹窗）"
    );
    assert_eq!(
        after_deactivate
            .strategies
            .iter()
            .find(|s| s.resource == AuthResource::Fs.as_str())
            .map(|s| s.strategy.as_str()),
        Some(AuthStrategy::AlwaysAsk.as_str()),
        "停用不得清策略档位"
    );

    // 卸载：清空（重装即全新授权）
    host.wasm_runtime()
        .monitor()
        .plugin(TEST_PLUGIN_ID)
        .record_lifecycle(LifecycleEvent::Instantiate);
    host.uninstall_plugin(TEST_PLUGIN_ID).await.unwrap();
    assert!(
        host.wasm_runtime().monitor().snapshot()["plugins"]
            .get(TEST_PLUGIN_ID)
            .is_none(),
        "卸载必须同步清掉指标注册表条目，避免监控快照残留幽灵插件"
    );
    let after_uninstall = store
        .overview(TEST_PLUGIN_ID, "T", Vec::new())
        .await
        .unwrap();
    assert!(
        after_uninstall.records.is_empty(),
        "卸载必须清空授权记录：重装不该继承前一任的授权"
    );
    assert!(
        after_uninstall
            .strategies
            .iter()
            .all(|s| s.strategy == AuthStrategy::Default.as_str()),
        "卸载必须清空策略档位（重装回到默认档）"
    );
}
