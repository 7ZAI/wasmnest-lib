//! guest 生命周期门回归用例（两道门：`has_wasm_backend` 后端门 + 状态短路门）。
//!
//! 无头宿主不建 wasm 实例，所以本文件断言的是「门的可见后果」而非 guest 调用本身：
//! - 后端门（`source.has_wasm_backend(rust_library)`）：有后端却拿不到实例时激活必须
//!   显性失败并落 `Error`，不得继续写 `Activated`——后者就是「宿主报已激活、guest
//!   从未初始化」的形态；
//! - 状态门（`guest_lifecycle_runnable`）：guest 从未初始化 / 已停用时清理钩子被短路，
//!   计数可见（`guest_lifecycle_skipped`），而宿主侧清扫逐项照跑。

use super::scaffold::*;
use super::*;

/// 带 `rustLibrary` 的用户安装 full 形态插件：激活不得再走「跳过 guest 直写 Activated」
///
/// 修复前该组合因 `source != Wasm` 整段跳过 guest `activate()` / `on_startup()`，
/// 终态仍写 `Activated` 且日志报 success（实测后果：file-transfer 24 个并发命令
/// 全 trap、bedcode `no such table: projects`）。无头宿主没有实例，修复后的正确
/// 形态是 fail-visible：激活失败 + `Error` 终态。
#[tokio::test(flavor = "multi_thread")]
async fn user_installed_full_form_activation_is_fail_visible() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-user-full";
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(
        tmp.path()
            .join(crate::system::constants::PLUGIN_MANIFEST_FILE),
        r#"{"id":"x"}"#,
    )
    .unwrap();
    register_user_installed(&host, id, tmp.path(), &["storage"]).await;
    // 先撞一次审批门禁（真实用户路径），再批准解除闸门
    assert!(host.activate_plugin(id, false).await.is_err());
    host.approve_plugin(id).await.expect("approve ok");

    host.plugins
        .write()
        .await
        .get_mut(id)
        .expect("plugin present")
        .manifest
        .rust_library = "wasmnest_test.wasm".to_string();

    let err = host
        .activate_plugin(id, false)
        .await
        .expect_err("有 wasm 后端却无实例，激活必须显性失败");
    assert!(
        err.to_string().contains("WASM module not loaded"),
        "失败原因必须点名「后端实例缺失」，实际: {err}"
    );
    let state = host.get_plugin(id).await.expect("plugin present").state;
    assert!(
        matches!(state, PluginState::Error { .. }),
        "失败路径要落 Error 终态，不得写 Activated，实际: {state:?}"
    );
}

/// 纯前端（`rustLibrary` 为空）用户插件：后端门仍判「无后端」，激活照常成功
///
/// 后端门收口的另一半——不能把用户插件一刀切成「都要 guest」，否则 frontend 形态
/// 装完就激活失败。
#[tokio::test(flavor = "multi_thread")]
async fn user_installed_frontend_form_still_skips_guest_lifecycle() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-user-frontend";
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(
        tmp.path()
            .join(crate::system::constants::PLUGIN_MANIFEST_FILE),
        r#"{"id":"x"}"#,
    )
    .unwrap();
    register_user_installed(&host, id, tmp.path(), &["storage"]).await;
    assert!(host.activate_plugin(id, false).await.is_err());
    host.approve_plugin(id).await.expect("approve ok");

    host.activate_plugin(id, false).await.expect("激活成功");
    assert_eq!(
        host.get_plugin(id).await.expect("plugin present").state,
        PluginState::Activated,
        "无 wasm 后端的用户插件维持原语义（跳过 guest 生命周期，不报错）"
    );
}

/// 启动重放卸载形态：从未激活（`Loaded`）的 wasm 插件被停用时跳过 guest 钩子
///
/// 宿主侧卸载墓碑重放会对刚创建的实例调 `deactivate`，修复前 guest 在无
/// `activate()` 上下文里执行清理并 `export=deactivate` trap。跳过 guest 的同时，
/// 宿主清扫（命令贡献摘除 / 撤权 / 定时器中止）必须逐项完成——「跳过 guest」
/// 不等于「跳过回收」。
#[tokio::test(flavor = "multi_thread")]
async fn deactivate_never_activated_plugin_skips_guest_but_keeps_host_cleanup() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-reap-unactivated";
    let mut plugin = make_plugin(id, PluginSource::Wasm, PluginState::Loaded);
    plugin.manifest.rust_library = "wasmnest_test.wasm".to_string();
    host.plugins.write().await.insert(id.to_string(), plugin);

    // 宿主侧登记：命令贡献 + 定时器，作为「清扫仍执行」的见证
    host.registry()
        .register_commands(
            id,
            &[crate::manifest::CommandContribution {
                id: "test.cmd".into(),
                title: "T".into(),
                icon: None,
                cli: None,
            }],
        )
        .await;
    PluginServices::register_plugin_timer(&host, id.to_string(), 3600, "tick".to_string());
    assert_eq!(host.registry().list_commands().await.len(), 1);

    host.deactivate_plugin(id, false).await.expect("停用成功");

    assert_eq!(
        host.guest_lifecycle_skipped.load(Ordering::Relaxed),
        1,
        "有后端但未激活 → guest 清理被短路，且必须留可见计数"
    );
    assert_eq!(
        host.get_plugin(id).await.expect("plugin present").state,
        PluginState::Deactivated
    );
    // 清扫未受影响
    assert!(
        host.registry().list_commands().await.is_empty(),
        "命令贡献应随停用摘除"
    );
    assert!(
        host.permission().get_granted(id).is_empty(),
        "权限应随停用撤销"
    );
    assert!(
        host.plugin_timers.lock().unwrap().is_empty(),
        "定时器应随停用中止"
    );
}

/// 撤权后重复停用：第二次 `deactivate` 仍不调 guest（幂等，计数逐次可见）
///
/// 修复前「先停用再卸载」会让 guest 清理跑在 `revoke_all` 之后，插件侧逐条报
/// `permission denied`（实测：`tunnel_unexpose` / `plugin_db_query`）。
#[tokio::test(flavor = "multi_thread")]
async fn repeated_deactivate_stays_out_of_guest_hooks() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-double-deactivate";
    let mut plugin = make_plugin(id, PluginSource::Wasm, PluginState::Activated);
    plugin.manifest.rust_library = "wasmnest_test.wasm".to_string();
    host.plugins.write().await.insert(id.to_string(), plugin);

    host.deactivate_plugin(id, false).await.expect("停用成功");
    // 无实例可达（无头宿主），guest 调用本身被 `get_instance` 分支静默跳过；
    // 关键判据是这一条没被记成「状态短路」
    assert_eq!(
        host.guest_lifecycle_skipped.load(Ordering::Relaxed),
        0,
        "Activated 状态的门必须打开（短路只针对未初始化 / 已停用）"
    );

    host.deactivate_plugin(id, false)
        .await
        .expect("重复停用幂等");
    assert_eq!(
        host.guest_lifecycle_skipped.load(Ordering::Relaxed),
        1,
        "已停用插件再次 deactivate 时 guest 清理被短路并计数"
    );
    assert_eq!(
        host.get_plugin(id).await.expect("plugin present").state,
        PluginState::Deactivated
    );
}

/// 免后端来源（随包扫描）永不被计入短路：门①先判，避免噪声计数
#[tokio::test(flavor = "multi_thread")]
async fn frontend_only_source_never_counts_as_skipped_guest_cleanup() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-frontend-only";
    host.plugins.write().await.insert(
        id.to_string(),
        make_plugin(id, PluginSource::FileScan, PluginState::Loaded),
    );

    host.deactivate_plugin(id, false).await.expect("停用成功");
    assert_eq!(
        host.guest_lifecycle_skipped.load(Ordering::Relaxed),
        0,
        "无 wasm 后端的插件本就没有 guest 钩子，不该计入短路观测"
    );
}
