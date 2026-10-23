//! host 测试共享脚手架（自 `manager/host.rs` 内联 `mod tests` 拆出，票 11 第 7 项）。
//!
//! 跨文件复用，故顶层项标 `pub(super)`（可见于 `host::tests` 及其后代）。

use super::*;
use std::sync::Mutex;

/// 本模块测试的不可测面说明：
///
/// - `PluginHost::new`：依赖 inventory 静态注册表与真实插件目录；app_handle 已
///   Option 化（None = 无头测试上下文），但集成测试在 crate 外无法访问私有字段,
///   仍需通过结构体字面量直接构造（tests 位于 host.rs 内部，可访问私有字段），
///   覆盖 new() 之后的全部宿主行为。
/// - `notify_startup` / `notify_shutdown` / `PluginServices::mark_plugin_error`：
///   无头测试上下文降级为纯日志跳过前端 emit（try_global None 分支），
///   静态插件回调链路由下方合成 inventory 条目测试覆盖。
/// - `dispatch_*_to_plugin` 的错误分支（WASM 实例缺失/调用失败）：仅有日志
///   副作用，无返回值可断言；成功路径由 `test_dispatch_lifecycle_and_input_to_wasm_plugin`
///   以「分发后 store 未被污染」间接验证。
/// - `invoke_wasm_command` 的非法 JSON 返回分支：需要构造返回坏 JSON 的恶意
///   WASM 插件，超出测试组件能力范围。

/// 构造无头测试宿主（app_handle = None）
///
/// 结构体字面量构造 PluginHost：字段私有但 tests 模块与 host.rs 同属一个
/// 模块树，可访问。所有子系统均用真实实现 + 内存 SQLite，仅 Tauri 相关
/// 能力降级（与 `test_support::setup_wasm_runtime` 测试同一策略）。
pub(super) async fn setup_host() -> PluginHost {
    // AppConfig 全局初始化（与 wasm_runtime 测试同策略；重复 init 幂等）
    static CONFIG_INIT: std::sync::Once = std::sync::Once::new();
    CONFIG_INIT.call_once(|| {
        let mut config = AppConfig::default();
        config.network.port = 8765;
        AppConfig::init(config);
    });

    let db = Arc::new(Mutex::new(
        Database::new(&PathBuf::from(":memory:")).unwrap(),
    ));
    db.lock().expect("db lock").init_schema().unwrap();
    let storage = Arc::new(PluginStorage::new(db.clone()));
    let permission = Arc::new(PermissionManager::new());
    let registry = Arc::new(PluginRegistry::new());
    let message_bus = Arc::new(MessageBus::new());

    let wasm_runtime = Arc::new(
        WasmRuntime::new(
            storage.clone(),
            None,
            Vec::new(),
            crate::manager::runtime::AbiPolicy::UNCONSTRAINED,
        )
        .unwrap(),
    );

    let wasm_host_ctx = Arc::new(WasmHostContext::new(
        db,
        Arc::new(Mutex::new(HashMap::new())),
        storage.clone(),
        None,
        permission.clone(),
        wasm_runtime.fs_auth().clone(),
        message_bus.clone(),
        Arc::new(crate::manager::capability::CapabilityRegistry::new()),
    ));

    wasm_host_ctx.security().set_monitor(wasm_runtime.monitor());
    // 与生产同形：授权记录容量丢弃计数（spec §8.2）也注入，无头用例可断言该计数
    wasm_runtime.fs_auth().set_monitor(wasm_runtime.monitor());
    // 网络侧同一机制（票 06）：与生产同形注入，无头用例可断言网络记录的容量计数
    wasm_host_ctx.net_auth().set_monitor(wasm_runtime.monitor());
    // v24 认证记录下沉：认证中心（terminal-session）配对/历史真源在插件私有库。
    // 无头测试无 AppHandle，注入进程级临时根使激活建表/播种/断言可达私有库
    // （auth-policy 闭环等依赖）
    wasm_host_ctx.set_plugin_db_root(Some(std::env::temp_dir().join(format!(
        "wasmnest-hosttest-pluginroot-{}",
        std::process::id()
    ))));

    // 能力域端口（wasm-core-lib-split 票 03 / 04 / 05 / 06）：迁出 `wasm_core` 的能力域
    // （mdns / ws / peer-net / http）经端口取宿主能力，生产在 `PluginHost::new` 的装配链里装；
    // 本 harness 直接拼 `PluginHost` 结构体字面量，**必须**做同一件事，否则停用
    // 路径上的属主回收（`activation.rs`）会因「端口未装配」而 panic（fail-visible
    // 的代价：无头用例里表现为测试红）。走与生产同一个入口，不在此处逐域 install——
    // 本文件曾逐域抄一份并漏掉 mdns，漏装只在「别的用例恰好先装过」时才看不出来。
    crate::host_api::install_capability_domain_ports(&wasm_host_ctx);

    PluginHost {
        plugins: Arc::new(RwLock::new(HashMap::new())),
        registry,
        permission,
        storage,
        rust_command_handlers: Arc::new(RwLock::new(HashMap::new())),
        rust_terminal_handlers: Arc::new(RwLock::new(Vec::new())),
        wasm_runtime,
        wasm_plugins: Arc::new(RwLock::new(HashMap::new())),
        owner_sink: HostOwnerFailureSink::new(),
        owner_cleanup_skipped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        wasm_host_ctx,
        message_bus,
        plugin_timers: Arc::new(std::sync::Mutex::new(HashMap::new())),
        wasm_reload_throttle: Arc::new(std::sync::Mutex::new(HashMap::new())),
        runtime_error_notify_throttle: Arc::new(std::sync::Mutex::new(HashMap::new())),
        shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        user_plugins_dir: std::env::temp_dir().join("wasmnest-test-user-plugins"),
        frontend_channel: Arc::new(
            crate::security::frontend_channel::FrontendChannelRegistry::new(),
        ),
    }
}

// `setup_host_shared`（`Arc<PluginHost>` + 手工 `owner_sink.bind`）随票 04 夹具用例
// 迁宿主一并删除：宿主侧经 `PluginHost::new` 真实装配路径构造（该路径本身已按生产
// 顺序绑定属主失败端口），不再需要结构体字面量 scaffold。

/// 构造一个最小 LoadedPlugin（manifest 含 storage + terminal:input 权限）
pub(super) fn make_plugin(id: &str, source: PluginSource, state: PluginState) -> LoadedPlugin {
    LoadedPlugin {
        manifest: PluginManifest {
            id: id.to_string(),
            name: format!("Test {}", id),
            version: "1.0.0".to_string(),
            main: "index.ts".to_string(),
            permissions: vec!["storage".to_string(), "terminal:input".to_string()],
            plugin_type: PluginType::TsOnly,
            // 余下字段取 Default，避免 SDK 追加可选字段时本夹具编译红（票 14）
            ..Default::default()
        },
        state,
        extension_path: String::new(),
        activated_at: None,
        source,
    }
}

// ==================== 静态注册插件（builtin 常驻语义） ====================

/// 合成静态插件 ID（inventory 条目仅编译进测试二进制，不影响产物）
pub(super) const SYNTHETIC_STATIC_ID: &str = "com.wasmnest.test-static";

/// 记录 on_startup 是否被宿主回调（inventory 条目进程级唯一，标志跨测试共享）
pub(super) static SYNTHETIC_ON_STARTUP_CALLED: AtomicBool = AtomicBool::new(false);

/// inventory 条目契约是**绑定层词汇**（`wasmnest_plugin_api::WasmNestPluginEntry` 的
/// `create_manifest` 返回 SDK 型 manifest）；进机制前的 SDK→中性 JSON 往返
/// 由生产装配链（`PluginHost::new` 的 `from_sdk_json`）负责，本夹具只构造 SDK 型
/// 以匹配条目签名——中性构造在 `make_plugin`（LoadedPlugin 直构）处另立。
fn synthetic_manifest() -> wasmnest_plugin_api::PluginManifest {
    wasmnest_plugin_api::PluginManifest {
        id: SYNTHETIC_STATIC_ID.to_string(),
        name: "Synthetic Static".to_string(),
        version: "0.1.0".to_string(),
        plugin_type: wasmnest_plugin_api::PluginType::Rust,
        // 余下字段取 Default，避免 SDK 追加可选字段时本夹具编译红（票 14）
        ..Default::default()
    }
}

fn synthetic_on_startup() -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
    Box::pin(async {
        SYNTHETIC_ON_STARTUP_CALLED.store(true, Ordering::SeqCst);
        Ok(())
    })
}

fn synthetic_on_shutdown() -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
    Box::pin(async { Ok(()) })
}

fn synthetic_noop_lifecycle(
    _ctx: RustPluginContext,
) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
    Box::pin(async { Ok(()) })
}

fn synthetic_commands() -> Vec<PluginCommand> {
    vec![PluginCommand::new("ping", |_args| async move {
        Ok(json!({ "pong": true }))
    })]
}

fn synthetic_terminal_handlers() -> Vec<Box<dyn TerminalHandler>> {
    Vec::new()
}

// 合成静态注册条目：等价 submit_plugin! 的 inventory 注册链路
inventory::submit! {
    wasmnest_plugin_api::WasmNestPluginEntry {
        id: SYNTHETIC_STATIC_ID,
        create_manifest: synthetic_manifest,
        activate: synthetic_noop_lifecycle,
        deactivate: synthetic_noop_lifecycle,
        register_commands: synthetic_commands,
        terminal_handlers: synthetic_terminal_handlers,
        on_startup: synthetic_on_startup,
        on_shutdown: synthetic_on_shutdown,
    }
}
