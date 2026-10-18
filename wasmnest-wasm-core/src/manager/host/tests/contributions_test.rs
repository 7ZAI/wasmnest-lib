//! manifest contributes 注册用例（commands / views / terminal / http endpoints / file handlers）。

use super::scaffold::*;
use super::*;

// ==================== Manifest Contributions ====================

#[tokio::test(flavor = "multi_thread")]
async fn test_register_manifest_contributions() {
    let host = setup_host().await;
    let mut plugin = make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded);
    plugin.manifest.contributes = PluginContributes {
        commands: vec![crate::manifest::CommandContribution {
            id: "test.hello".into(),
            title: "Hello".into(),
            icon: None,
        }],
        views: vec![crate::manifest::ViewContribution {
            id: "test.view".into(),
            view_type: "sidebar".into(),
            title: "V".into(),
            component: "View.vue".into(),
        }],
        ..Default::default()
    };
    host.plugins.write().await.insert(TEST_PLUGIN_ID.to_string(), plugin);

    host.register_manifest_contributions().await;

    let commands = host.registry().list_commands().await;
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].plugin_id, TEST_PLUGIN_ID);
    let views = host.registry().list_views().await;
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].plugin_id, TEST_PLUGIN_ID);
    assert_eq!(views[0].view_type, "sidebar");
}

// ==================== 注册入口收敛（票 11 第 3 项） ====================

/// 六类 contributes 全填的 manifest（等价锁用）
fn all_contributions() -> PluginContributes {
    PluginContributes {
        commands: vec![crate::manifest::CommandContribution {
            id: "test.hello".into(),
            title: "Hello".into(),
            icon: None,
        }],
        views: vec![crate::manifest::ViewContribution {
            id: "test.view".into(),
            view_type: "sidebar".into(),
            title: "V".into(),
            component: "View.vue".into(),
        }],
        terminal: Some(crate::manifest::TerminalContribution {
            input_handlers: vec!["test.hook".into()],
            output_parsers: vec!["test.parser".into()],
        }),
        tool_providers: vec![crate::manifest::ToolProviderContribution {
            id: "test.tool".into(),
            name: "T".into(),
            endpoint: "test/tool".into(),
        }],
        http_endpoints: vec!["test/hello".into()],
        file_handlers: vec![crate::manifest::FileHandlerContribution {
            id: "test.file".into(),
            extensions: vec!["txt".into()],
            viewer: "Viewer.vue".into(),
            icon: None,
        }],
        ..Default::default()
    }
}

/// 注册面快照（manifest contributes 的对外可见投影；ABI v29 起 HTTP 路由面
/// 已退役出 manager 注册表——动态注册表在 `wasmnest-server-http::registry`）
async fn contributions_snapshot(host: &PluginHost) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let mut commands: Vec<String> = host
        .registry()
        .list_commands()
        .await
        .iter()
        .map(|c| format!("{}::{}", c.plugin_id, c.command_id))
        .collect();
    let mut views: Vec<String> = host
        .registry()
        .list_views()
        .await
        .iter()
        .map(|v| format!("{}::{}::{}", v.plugin_id, v.view_id, v.view_type))
        .collect();
    let mut terminals: Vec<String> = host
        .registry()
        .list_terminal_handlers()
        .await
        .iter()
        .map(|t| format!("{}::{:?}::{:?}", t.plugin_id, t.input_handlers, t.output_parsers))
        .collect();
    let mut files: Vec<String> = host
        .registry()
        .list_file_handlers()
        .await
        .iter()
        .map(|f| format!("{}::{}::{:?}", f.plugin_id, f.handler_id, f.extensions))
        .collect();
    commands.sort();
    views.sort();
    terminals.sort();
    files.sort();
    (commands, views, terminals, files)
}

/// 行为等价锁：启动期全量注册与安装/热重载走的单条注册必须产出**同一份注册面**，
/// 且重复注册幂等（票 11 第 3 项：三处手抄收敛为 `register_plugin_contributions`）。
#[tokio::test(flavor = "multi_thread")]
async fn contributions_identical_across_entry_points() {
    let mut plugin = make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded);
    plugin.manifest.contributes = all_contributions();

    // 入口 1：启动期全量（register_manifest_contributions → 委派单条）
    let host_all = setup_host().await;
    host_all
        .plugins
        .write()
        .await
        .insert(TEST_PLUGIN_ID.to_string(), plugin.clone());
    host_all.register_manifest_contributions().await;

    // 入口 2：单条（zip 安装 / 热重载路径）
    let host_one = setup_host().await;
    host_one
        .plugins
        .write()
        .await
        .insert(TEST_PLUGIN_ID.to_string(), plugin.clone());
    host_one.register_plugin_contributions(TEST_PLUGIN_ID).await;

    let snapshot_all = contributions_snapshot(&host_all).await;
    let snapshot_one = contributions_snapshot(&host_one).await;
    assert_eq!(
        snapshot_all, snapshot_one,
        "两条注册入口产出必须逐项一致（含 commands/views/terminal/file）"
    );
    // 断言注册面非空——否则「两条都空」也会相等，等价锁退化为恒真
    assert_eq!(snapshot_all.0.len(), 1, "commands 必须注册");
    assert_eq!(snapshot_all.1.len(), 1, "views 必须注册");
    assert_eq!(snapshot_all.2.len(), 1, "terminal handlers 必须注册");
    assert_eq!(snapshot_all.3.len(), 1, "file handlers 必须注册");
    // ABI v29：manifest httpEndpoints / toolProviders 静态声明面已退役（用户裁定 ④）——
    // 清单里即使还带这两类字段（老 manifest 解析容差），也不会产生 manager 注册面

    // 幂等：重复注册（全量与单条都会重复走到）不改变注册面
    host_one.register_plugin_contributions(TEST_PLUGIN_ID).await;
    host_one.register_manifest_contributions().await;
    assert_eq!(
        contributions_snapshot(&host_one).await,
        snapshot_all,
        "重复注册必须幂等"
    );

    // 未安装的 id：静默返回，不 panic（卸载竞态）
    host_one
        .register_plugin_contributions("com.wasmnest.not-installed")
        .await;
}

/// 票 09a：manifest 声明的 WS 端点经 `register_declared_ws_endpoints` 登记进
/// 宿主 WS 端点注册表（声明驱动静态路由，expand 阶段接口本身已存在）。
/// 锁三件事：①合法声明登记成功且路径完整（挂载 `/ws/plugin/<id>/<path>`）；
/// ②认证档位透传（缺省 = none，显式 jwt 原样）；③非法 path（含 `/`）与未声明
/// 不登记——渲染侧不可达（fail-visible，不静默）。
#[tokio::test(flavor = "multi_thread")]
async fn registered_manifest_declared_ws_endpoints() {
    use crate::manifest::WsEndpointContribution;

    let host = setup_host().await;
    let plugin_id = "com.test.ws-declared-positive";
    host.permission.grant_permissions(plugin_id, &["ws:server".to_string()]);
    let endpoints = vec![
        WsEndpointContribution::Path("echo".into()), // 缺省档 = none
        WsEndpointContribution::Declared {
            path: "chat".into(),
            auth: Some("jwt".into()),
        },
        WsEndpointContribution::Declared {
            path: "bad/path".into(), // 含 `/` → 不登记
            auth: None,
        },
    ];
    host.register_declared_ws_endpoints(plugin_id, &endpoints).await;

    use wasmnest_server_websocket::endpoint;
    // ws 域脱绑后（能力域脱绑 P3）端点认证档位为 `wire` 自持副本（与 SDK 漂移锁钉死）
    use wasmnest_server_websocket::wire::EndpointAuth;
    let echo = endpoint::find_by_mount(&endpoint::mount_path(plugin_id, "echo"));
    assert!(echo.is_some(), "declared echo endpoint must be registered");
    assert_eq!(echo.unwrap().auth, EndpointAuth::None, "缺省档 = none");

    let chat = endpoint::find_by_mount(&endpoint::mount_path(plugin_id, "chat"));
    assert!(chat.is_some(), "declared chat endpoint must be registered");
    assert_eq!(chat.unwrap().auth, EndpointAuth::Jwt, "显式 jwt 原样登记");

    let bad = endpoint::find_by_mount(&endpoint::mount_path(plugin_id, "bad/path"));
    assert!(bad.is_none(), "含 / 的声明不得登记（fail-visible）");

    // 清理（全局端点表在 test 进程内跨用例共享）
    endpoint::purge_for_plugin(plugin_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn declared_ws_endpoints_require_ws_server_permission() {
    let host = setup_host().await;
    let plugin_id = "com.test.ws-declared-permission";
    let endpoints = vec![crate::manifest::WsEndpointContribution::Path("guarded".into())];
    host.register_declared_ws_endpoints(plugin_id, &endpoints).await;
    assert!(
        wasmnest_server_websocket::endpoint::find_by_mount(&wasmnest_server_websocket::endpoint::mount_path(
            plugin_id, "guarded"
        ))
        .is_none()
    );

    host.permission.grant_permissions(plugin_id, &["ws:server".to_string()]);
    host.register_declared_ws_endpoints(plugin_id, &endpoints).await;
    assert!(
        wasmnest_server_websocket::endpoint::find_by_mount(&wasmnest_server_websocket::endpoint::mount_path(
            plugin_id, "guarded"
        ))
        .is_some()
    );
    wasmnest_server_websocket::endpoint::purge_for_plugin(plugin_id);
}

/// 源码漂移锁：registry 注册调用**只允许出现在 `register_plugin_contributions` 一处**。
/// 三份手抄的历史成因是「新 contributes 项要同改三处」，漏改即静默不注册。
///
/// ABI v29（HTTP 路由代码注册下沉）：`register_http_endpoints` / `register_tool_providers`
/// 已随静态声明面退役（用户裁定 ④：不通过声明配置路由），不在本锁清单内。
#[test]
fn registry_registration_has_single_call_site() {
    let sources = [
        include_str!("../register.rs"),
        include_str!("../wasm.rs"),
        include_str!("../install.rs"),
        include_str!("../../host.rs"),
    ];
    let joined = sources.join("\n");
    for call in [
        "register_commands(",
        "register_views(",
        "register_terminal_handlers(",
        "register_file_handlers(",
    ] {
        assert_eq!(
            joined.matches(call).count(),
            1,
            "`{call}` 必须只在 register_plugin_contributions 内出现一次（票 11 第 3 项）"
        );
    }
    // 退役面不得复燃：静态 HTTP 路由登记调用在源码中必须为零
    assert!(
        !joined.contains("register_http_endpoints("),
        "httpEndpoints 静态登记已退役"
    );
    assert!(
        !joined.contains("register_tool_providers("),
        "toolProviders 登记从未落地消费，已随退役"
    );
}

// ==================== 实例化入口收敛（票 11 第 2 项） ====================

/// 指定 `rust_library` 与安装目录的 LoadedPlugin（实例化分支用）
fn plugin_with_wasm(rust_library: &str, extension_path: &str) -> LoadedPlugin {
    let mut plugin = make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded);
    plugin.manifest.rust_library = rust_library.to_string();
    plugin.extension_path = extension_path.to_string();
    plugin
}

/// 两条入口（启动扫描 / zip 安装）共用 `instantiate_wasm_plugin`，行为归它裁决：
/// 无 wasm 声明 → 无实例且状态不变；声明了但产物缺失 → Error 态而非丢弃记录。
#[tokio::test(flavor = "multi_thread")]
async fn instantiate_wasm_plugin_covers_both_entries() {
    let host = setup_host().await;

    // 分支 1：未声明 rust_library（纯前端插件）→ 原记录入表、无实例
    let ts_only = plugin_with_wasm("", "/nonexistent/dir");
    let (entry, instance) = host.instantiate_wasm_plugin(&ts_only);
    assert!(instance.is_none(), "未声明 rust_library 不应产生 WASM 实例");
    assert!(
        matches!(entry.state, PluginState::Loaded),
        "无 wasm 声明时不改变加载状态"
    );

    // 分支 2：声明了 rust_library 但 wasm 产物缺失 → Error 态入表（列表可见可诊断）
    let missing = plugin_with_wasm("missing_module", "/nonexistent/plugin-dir");
    let (entry, instance) = host.instantiate_wasm_plugin(&missing);
    assert!(instance.is_none(), "产物缺失时没有可运行的实例");
    assert!(
        matches!(entry.state, PluginState::Error { .. }),
        "产物缺失必须降级 Error 而不是让插件从列表消失"
    );
}

/// 源码漂移锁：生产路径的 `load_plugin_from_file` **只允许两处**——两条入口共用的
/// `instantiate_wasm_plugin` 与热重载/授权重建的 `rebuild_wasm_instance`。
/// 第三处出现意味着有人绕过了共用入口，实例化策略又会开始分叉。
#[test]
fn wasm_instantiation_has_two_call_sites_only() {
    let sources = [
        include_str!("../wasm.rs"),
        include_str!("../install.rs"),
        include_str!("../register.rs"),
        include_str!("../../host.rs"),
    ];
    let joined = sources.join("\n");
    assert_eq!(
        joined.matches("load_plugin_from_file(").count(),
        2,
        "生产面 WASM 实例化只允许「共用入口 + 重建」两处调用"
    );
    // 反向锁：安装入口不得自己拼 wasm 路径（历史上 install 手写 format! 造成后缀漂移）
    assert!(
        !include_str!("../install.rs").contains("load_plugin_from_file("),
        "zip 安装入口必须走 instantiate_wasm_plugin"
    );
}
