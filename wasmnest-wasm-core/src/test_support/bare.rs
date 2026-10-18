//! 移动宿主测试面（历史模块名 `bare`：fork 期的形态词；运行时单形态 2026-10-13
//! 收口后本模块只指「移动 `src-tauri` 测试消费的测试基建」，不持有第二份运行时壳）
//!
//! 编译门控：父模块 `test_support.rs` 的 `#[cfg(feature = "test-support")]`
//! （移动宿主 `[dev-dependencies]` 开启；wasm-core 自身默认 features 测试不编译）。
//! - 内部 `MockPorts` / mock_plugin_ws / build_component_state… 供移动宿主
//!   `src-tauri/tests/` 与宿主内 `#[cfg(test)]` 用例消费；
//! - 内部引用已改指统一运行时壳（`LoadedWasmPlugin` / 统一 `add_to_linker`）；
//!   共享符号（`TEST_PLUGIN_ID` / `plugin_raw_store`）单点定义在父模块。
//!
//! **夹具组件构建器已归位移动宿主测试面（票 08 批次三）**：
//! `build_test_component` / `build_terminal_session_component` 读移动夹具 crate
//! （`plugin-component-test`）与应用仓 bedcode 工程，随包夹具与产物均住平台仓；
//! 能力仓单克隆不再要求它们在场。移动宿主侧同名构建器住
//! `tests/support/fixtures.rs`（与 mock_plugin_ws 同型）。

// 共享符号单点定义在父模块（`test_support.rs`），本消费面不另存副本
use super::TEST_PLUGIN_ID;

pub mod mock_plugin_ws;

/// 构建测试引擎：燃料看门狗必须与生产配置一致（WasmRuntime::new）
pub fn test_engine() -> wasmtime::Engine {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    wasmtime::Engine::new(&config).expect("create test engine")
}

/// 构造最小宿主上下文（db 内存库 + 内存 storage；app_handle=None 无头形态；
/// 端口 = UnimplementedPorts 占位——夹具用例不触引擎调用）
pub fn build_host_ctx() -> std::sync::Arc<crate::host_api::WasmHostContext> {
    use std::sync::{Arc, Mutex};
    let db = std::sync::Arc::new(std::sync::Mutex::new(crate::db::Database::from_connection(
        rusqlite::Connection::open_in_memory().expect("open in-memory db"),
    )));
    let storage = crate::storage::PluginStorage::test_storage();
    // 无头/测试上下文：fs_auth 的 app_handle 亦为 None（桌面端 build_host_ctx 同形态）
    // first_party_dirs 空 = 移动形态（桌面 first-party 概念不启用）
    let fs_auth = Arc::new(crate::security::fs_auth::FsAuthChecker::new(
        storage.clone(),
        None,
        Vec::new(),
    ));
    let status_reporter: Arc<dyn Fn(&str, &str) + Send + Sync> = Arc::new(|_, _| {});
    Arc::new(crate::host_api::WasmHostContext::new_headless(
        db,
        storage,
        None,
        fs_auth,
        Arc::new(crate::bus::MessageBus::new()),
        status_reporter,
    ))
}

/// 统一运行时壳的无头构造（单形态 2026-10-13）
///
/// 无 storage / app_handle / first_party_dirs，形态规格 [`AbiPolicy::UNCONSTRAINED`]
/// （无头装配不设上限——夹具是桌面 SDK 产物）。供移动宿主集成测试构造
/// `WasmRuntime`（loader / manager / 终端会话夹具均需真实 Engine）。
pub fn setup_headless_runtime(
    aot_cache_dir: Option<std::path::PathBuf>,
) -> crate::Result<crate::manager::runtime::WasmRuntime> {
    setup_headless_runtime_with_abi(aot_cache_dir, crate::manager::runtime::AbiPolicy::UNCONSTRAINED)
}

/// 同 [`setup_headless_runtime`]，但显式注入形态规格（端事实）
///
/// 单形态（2026-10-13）：`abi-form` 要求是宿主注入的策略（wasm-core 零端 ABI
/// 知识）——端宿主测试要断言「形态不符的组件被拒绝」，必须注入端真实规格而非
/// 一律 `UNCONSTRAINED`。整数 ABI 版本上限检查已随 wit 包版本化退役
/// （ADR 0051 D2）：产物新旧由 linker 的 import 名逐字匹配裁决，无"高版本自报"
/// 形态可注入。
pub fn setup_headless_runtime_with_abi(
    aot_cache_dir: Option<std::path::PathBuf>,
    abi: crate::manager::runtime::AbiPolicy,
) -> crate::Result<crate::manager::runtime::WasmRuntime> {
    setup_headless_runtime_with_config(aot_cache_dir, abi, crate::config::CoreConfig::default())
}

/// 同 [`setup_headless_runtime_with_abi`]，但显式注入内核配置
///
/// 端宿主用例要按**生产引擎配置**装配才有代表性：例如移动端关掉信号式 trap
/// （`EngineTuning::signals_based_traps = Some(false)`，见 `mobile_core_config`）后，
/// 移动宿主的插件闭环用例必须用同一份配置跑——否则「trap 变成错误而非崩溃」这条
/// 产品性质在测试里根本没被装配到。
pub fn setup_headless_runtime_with_config(
    aot_cache_dir: Option<std::path::PathBuf>,
    abi: crate::manager::runtime::AbiPolicy,
    core_config: crate::config::CoreConfig,
) -> crate::Result<crate::manager::runtime::WasmRuntime> {
    let storage = crate::storage::PluginStorage::test_storage();
    let mut runtime = crate::manager::runtime::WasmRuntime::with_setup(
        storage,
        None,
        crate::manager::runtime::EngineSetup::new(core_config).with_abi(abi),
    )?;
    // AOT 缓存目录：无头装配注入（生产路径经 app_handle 取；测试用例断言
    // 缓存产物落点需要显式注入——aot_cache_dir 是 pub(crate)，crate 内可达）
    runtime.aot_cache_dir = aot_cache_dir;
    Ok(runtime)
}

/// 构造插件实例 state（统一 host-kit 形态，wasm-core-mobile-purity 票 04）
///
/// 取代旧自持 `WasmPluginState { plugin_id, host_ctx, runtime_handle,
/// granted_permissions, on_message_binary }` 字面量：权限真源 = 共享内核
/// `PermissionManager`（与生产激活路径 `grant_permissions` 同一条路），不再有
/// 逐实例 `granted_permissions` 副本（2026-10-14 桌面同构收口）；
/// `host` 槽是 host-kit state 的 `Arc<dyn HostPorts>`。
/// StoreSpec 取默认资源上限 + 关燃料（测试不设限、不注入燃料预算）。
pub fn build_component_state(plugin_id: &str, granted: &[&str]) -> crate::manager::runtime::WasmPluginState {
    let ctx = build_host_ctx();
    let requested: Vec<String> = granted.iter().map(|p| p.to_string()).collect();
    ctx.grant_permissions(plugin_id, &requested);
    build_component_state_with_ctx(plugin_id, ctx)
}

/// 同上，允许注入自定义宿主上下文（域测试需覆盖端口 / 构造无头上下文时用）
pub fn build_component_state_with_ctx(
    plugin_id: &str,
    ctx: std::sync::Arc<crate::host_api::WasmHostContext>,
) -> crate::manager::runtime::WasmPluginState {
    crate::manager::runtime::WasmPluginState::new(
        plugin_id.to_string(),
        ctx,
        // 移动测试夹具不 import WASI（wasm32-unknown-unknown）⇒ 空上下文即可
        crate::manager::runtime::wasi::empty_ctx(),
        crate::manager::runtime::StoreSpec {
            limits: wasmnest_host_kit::limits::StoreLimits::default(),
            fuel_enabled: false,
            metrics: std::sync::Arc::new(wasmnest_host_kit::metrics::PluginMetrics::default()),
        },
    )
}

// ==================== 组件实例观测面（宿主集成测试转发，票 05） ====================
//
// 宿主集成测试链的是**不带 cfg(test)** 的 lib（`#[cfg(test)]` 项等价于不可达），
// 而 fixture e2e 随绑定归位迁到移动宿主 `src-tauri/tests/`——它们需要的壳内私有面
// 经这两个转发函数消费（生产跨 crate 仍不可达：`raw_store` 是 `pub(crate)`、
// `core_binding` 是 `pub(crate) mod`）。

/// 系统存储空间属主 ID（`__system__`）
///
/// 内核 `storage::SYSTEM_PLUGIN_ID` 是 `pub(crate)`（属主分区细节不对外）；
/// 宿主域测试断言「系统空间纵深守卫对移动端同样生效」需要这个常量，经本转发面给出。
pub const SYSTEM_PLUGIN_ID: &str = crate::storage::SYSTEM_PLUGIN_ID;

/// linker 装配面（与生产同一函数：core 交集 + 宿主自报能力模块 + WASI 段）
///
/// 单形态（2026-10-13）起与桌面壳同一实现：`component::add_to_linker`——core
/// 交集 8 域（core_binding）+ `inventory` 自报能力模块 + WASI p2/p3。宿主集成
/// 测试据此断言 linker 装配契约（WASI 默认注册 / 配置关闭可重注册）。
pub fn build_component_linker(
    engine: &wasmtime::Engine,
    wasi_cfg: &crate::config::WasiConfig,
) -> crate::Result<wasmtime::component::Linker<crate::manager::runtime::WasmPluginState>> {
    let mut linker = wasmtime::component::Linker::new(engine);
    crate::manager::runtime::component::add_to_linker(&mut linker, wasi_cfg)?;
    Ok(linker)
}

/// 探针：对给定 linker 尝试再次注册 WASI p2
///
/// 返回 `Some(错误文本)` = 已注册过（重复注册被 wasmtime 以 "defined twice" 拒绝）；
/// `None` = 本次注册成功（即此前**未**注册）。让宿主测试不引入 `wasmtime-wasi` 依赖。
pub fn probe_wasi_p2_reregistration(
    linker: &mut wasmtime::component::Linker<crate::manager::runtime::WasmPluginState>,
) -> Option<String> {
    wasmtime_wasi::p2::add_to_linker_async(linker)
        .err()
        .map(|e| e.to_string())
}

// 实例 Store / Instance 裸面（燃料、limiter、原生导出调用等机制断言用）——
// `plugin_raw_store` 本体已上提父模块 `test_support.rs`（两消费面共享符号），
// 本面不再转存副本；移动宿主测试经 `test_support::plugin_raw_store` 引用。

// ==================== MockPorts：端口测试替身（builder 式 override） ====================

use crate::host_api::ports::{
    AuthEnginePort, ConnectionEnginePort, HostEnginePorts, PrimaryTarget, SafIoPort,
    UnimplementedPorts, WsReconnectPolicyPort,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// 端口测试替身：未 override 的方法复刻 UnimplementedPorts 的 fail-visible
/// 形态（Err/None/空值），override 过的方法返回测试注入值——域测试按需最小装配。
pub struct MockPorts {
    token: String,
    connection: Option<Arc<dyn ConnectionEnginePort>>,
    auth: Option<Arc<dyn AuthEnginePort>>,
    egress_allow: bool,
    reconnect: Option<Arc<dyn Fn(u32, u64, u64) -> Box<dyn WsReconnectPolicyPort> + Send + Sync>>,
    /// `host-config app.downloads_dir` 端事实（移动端专属键）：`Some` = 注入本端
    /// 下载目录（宿主集成测试要在无头上下文里驱动依赖该键的插件 activate 路径，
    /// 如 ai-chatbox 数据目录 `{downloads}/ai-chatbox`），`None` = 缺省 fail-visible
    app_downloads_dir: Option<String>,
    base: UnimplementedPorts,
}

impl Default for MockPorts {
    fn default() -> Self {
        Self::new()
    }
}

impl MockPorts {
    pub fn new() -> Self {
        Self {
            token: String::new(),
            connection: None,
            auth: None,
            egress_allow: false,
            reconnect: None,
            app_downloads_dir: None,
            base: UnimplementedPorts,
        }
    }

    /// 注入 `app.downloads_dir` 端事实（`host-config` 移动端专属键；见字段注释）
    pub fn with_app_downloads_dir(mut self, dir: &str) -> Self {
        self.app_downloads_dir = Some(dir.to_string());
        self
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = token.to_string();
        self
    }

    pub fn with_connection(mut self, engine: Arc<dyn ConnectionEnginePort>) -> Self {
        self.connection = Some(engine);
        self
    }

    pub fn with_auth(mut self, engine: Arc<dyn AuthEnginePort>) -> Self {
        self.auth = Some(engine);
        self
    }

    /// egress 一律放行（跳过宿主安全闸门——真源测试在宿主侧）
    pub fn with_egress_allow(mut self) -> Self {
        self.egress_allow = true;
        self
    }

    pub fn with_reconnect_policy(
        mut self,
        f: impl Fn(u32, u64, u64) -> Box<dyn WsReconnectPolicyPort> + Send + Sync + 'static,
    ) -> Self {
        self.reconnect = Some(Arc::new(f));
        self
    }
}

#[async_trait::async_trait]
impl HostEnginePorts for MockPorts {
    async fn egress_check(
        &self,
        app: &tauri::AppHandle,
        url: &str,
        source: &str,
    ) -> Result<(), String> {
        if self.egress_allow {
            Ok(())
        } else {
            self.base.egress_check(app, url, source).await
        }
    }

    fn egress_redirect_policy(&self) -> reqwest::redirect::Policy {
        reqwest::redirect::Policy::none()
    }

    fn auth_engine(&self) -> Option<Arc<dyn AuthEnginePort>> {
        self.auth.clone()
    }

    fn global_token(&self) -> String {
        self.token.clone()
    }

    fn connection_engine(&self) -> Arc<dyn ConnectionEnginePort> {
        self.connection
            .clone()
            .unwrap_or_else(|| Arc::new(NoTargetConn))
    }

    fn reconnect_policy(
        &self,
        max_retries: u32,
        base_ms: u64,
        max_ms: u64,
    ) -> Box<dyn WsReconnectPolicyPort> {
        match &self.reconnect {
            Some(f) => f(max_retries, base_ms, max_ms),
            None => Box::new(StaticBackoff::new(base_ms)),
        }
    }

    fn reconnect_bounds(&self) -> (u64, u64) {
        (1000, 60_000)
    }

    fn app_downloads_dir(&self) -> Option<String> {
        self.app_downloads_dir.clone()
    }

    fn current_node_id(&self, _app: &tauri::AppHandle) -> Option<String> {
        None
    }

    async fn peer_dial_endpoint(
        &self,
        app: &tauri::AppHandle,
        n: String,
        a: String,
        p: u16,
    ) -> crate::Result<String> {
        self.base.peer_dial_endpoint(app, n, a, p).await
    }
    async fn peer_disconnect(&self, app: &tauri::AppHandle, n: String) -> crate::Result<bool> {
        self.base.peer_disconnect(app, n).await
    }
    async fn peer_respond_consent(
        &self,
        app: &tauri::AppHandle,
        r: String,
        ok: bool,
    ) -> crate::Result<bool> {
        self.base.peer_respond_consent(app, r, ok).await
    }
    async fn peer_list_trusted(&self, app: &tauri::AppHandle) -> crate::Result<String> {
        self.base.peer_list_trusted(app).await
    }
    async fn peer_revoke_trusted(&self, app: &tauri::AppHandle, n: String) -> crate::Result<bool> {
        self.base.peer_revoke_trusted(app, n).await
    }
    async fn peer_set_shared_roots(&self, app: &tauri::AppHandle, j: String) -> crate::Result<()> {
        self.base.peer_set_shared_roots(app, j).await
    }
    async fn peer_start_node(&self, app: &tauri::AppHandle, c: &str) -> crate::Result<bool> {
        self.base.peer_start_node(app, c).await
    }
    async fn peer_stop_node(&self, app: &tauri::AppHandle, c: &str) -> crate::Result<bool> {
        self.base.peer_stop_node(app, c).await
    }
    async fn peer_cancel_transfer(&self, app: &tauri::AppHandle, b: String) -> crate::Result<bool> {
        self.base.peer_cancel_transfer(app, b).await
    }
    async fn peer_cancel_receiving(
        &self,
        app: &tauri::AppHandle,
        b: String,
    ) -> crate::Result<bool> {
        self.base.peer_cancel_receiving(app, b).await
    }
    async fn peer_send_files_with_policy(
        &self,
        app: &tauri::AppHandle,
        n: String,
        paths: Vec<String>,
        e: Option<bool>,
    ) -> crate::Result<String> {
        self.base
            .peer_send_files_with_policy(app, n, paths, e)
            .await
    }
    async fn peer_respond_transfer(
        &self,
        app: &tauri::AppHandle,
        b: String,
        ok: bool,
    ) -> crate::Result<()> {
        self.base.peer_respond_transfer(app, b, ok).await
    }
    async fn peer_set_receive_policy(
        &self,
        app: &tauri::AppHandle,
        m: String,
        t: u64,
    ) -> crate::Result<()> {
        self.base.peer_set_receive_policy(app, m, t).await
    }
    async fn peer_pause_transfer(&self, app: &tauri::AppHandle, b: String) -> crate::Result<bool> {
        self.base.peer_pause_transfer(app, b).await
    }
    async fn peer_resume_transfer(&self, app: &tauri::AppHandle, b: String) -> crate::Result<bool> {
        self.base.peer_resume_transfer(app, b).await
    }
    async fn peer_set_download_dir(
        &self,
        app: &tauri::AppHandle,
        p: Option<String>,
    ) -> crate::Result<()> {
        self.base.peer_set_download_dir(app, p).await
    }
    async fn peer_list_shared_roots(
        &self,
        app: &tauri::AppHandle,
        n: String,
    ) -> crate::Result<String> {
        self.base.peer_list_shared_roots(app, n).await
    }
    async fn peer_browse_directory(
        &self,
        app: &tauri::AppHandle,
        n: String,
        d: String,
        r: String,
    ) -> crate::Result<String> {
        self.base.peer_browse_directory(app, n, d, r).await
    }
    async fn peer_pull_files(
        &self,
        app: &tauri::AppHandle,
        n: String,
        d: String,
        f: String,
    ) -> crate::Result<u32> {
        self.base.peer_pull_files(app, n, d, f).await
    }
    async fn peer_active_transfers(&self, app: &tauri::AppHandle) -> crate::Result<String> {
        self.base.peer_active_transfers(app).await
    }
    async fn peer_collect_outgoing(&self, paths: Vec<String>) -> crate::Result<String> {
        self.base.peer_collect_outgoing(paths).await
    }
    async fn platform_pick_files(&self, app: &tauri::AppHandle) -> crate::Result<Vec<String>> {
        self.base.platform_pick_files(app).await
    }
    async fn platform_pick_shared_directory(
        &self,
    ) -> crate::Result<Option<(String, String, String)>> {
        self.base.platform_pick_shared_directory().await
    }
    async fn resolve_downloads_dir(&self, app: &tauri::AppHandle) -> crate::Result<String> {
        self.base.resolve_downloads_dir(app).await
    }
    async fn delete_file_android(&self, path: String) -> crate::Result<()> {
        self.base.delete_file_android(path).await
    }
    async fn is_within_app_downloads_dir(
        &self,
        app: &tauri::AppHandle,
        path: &str,
    ) -> crate::Result<bool> {
        self.base.is_within_app_downloads_dir(app, path).await
    }
    fn saf_io(&self, app: &tauri::AppHandle) -> Option<Arc<dyn SafIoPort>> {
        self.base.saf_io(app)
    }
    async fn app_data_dir(&self, app: &tauri::AppHandle) -> crate::Result<PathBuf> {
        self.base.app_data_dir(app).await
    }
    async fn notify_show(
        &self,
        plugin_id: &str,
        title: &str,
        body: &str,
        vibrate: bool,
        sound: bool,
    ) -> Result<(), String> {
        self.base
            .notify_show(plugin_id, title, body, vibrate, sound)
            .await
    }

    async fn notify_check_permission(&self) -> Result<bool, String> {
        self.base.notify_check_permission().await
    }

    async fn notify_request_permission(&self) -> Result<bool, String> {
        self.base.notify_request_permission().await
    }

    async fn notify_vibrate(&self, duration_ms: u32) -> Result<(), String> {
        self.base.notify_vibrate(duration_ms).await
    }

    async fn notify_play_sound(&self) -> Result<(), String> {
        self.base.notify_play_sound().await
    }
}

/// MockPorts 兜底连接引擎：无目标（Ok(None)）
struct NoTargetConn;

#[async_trait::async_trait]
impl ConnectionEnginePort for NoTargetConn {
    async fn primary_target(&self) -> crate::Result<Option<(PrimaryTarget, bool)>> {
        Ok(None)
    }
}

/// 固定退避策略（重连测试用：单轮固定延迟）
struct StaticBackoff {
    delay_ms: u64,
}

impl StaticBackoff {
    pub fn new(delay_ms: u64) -> Self {
        Self { delay_ms }
    }
}

#[async_trait::async_trait]
impl WsReconnectPolicyPort for StaticBackoff {
    async fn start(&self) -> Option<()> {
        Some(())
    }
    async fn get_delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms)
    }
    async fn on_success(&self) {}
}

/// 带自定义端口的宿主上下文构造（测试夹具）
pub fn build_host_ctx_with(
    ports: impl crate::host_api::HostEnginePorts + 'static,
) -> Arc<crate::host_api::WasmHostContext> {
    build_host_ctx_with_arc(Arc::new(ports))
}

/// [`build_host_ctx_with`] 的 Arc 形态（跨域测试共享同一端口替身实例；本文件内私有——
/// 外部消费面只经 `build_host_ctx_with`，多一层 Arc 入口是多余面）
fn build_host_ctx_with_arc(
    ports: Arc<dyn crate::host_api::HostEnginePorts>,
) -> Arc<crate::host_api::WasmHostContext> {
    use std::sync::Mutex;
    let db = Arc::new(Mutex::new(crate::db::Database::from_connection(
        rusqlite::Connection::open_in_memory().expect("open in-memory db"),
    )));
    let storage = crate::storage::PluginStorage::test_storage();
    let fs_auth = Arc::new(crate::security::fs_auth::FsAuthChecker::new(
        storage.clone(),
        None,
        Vec::new(),
    ));
    let status_reporter: Arc<dyn Fn(&str, &str) + Send + Sync> = Arc::new(|_, _| {});
    Arc::new(crate::host_api::WasmHostContext::new_with_ports(
        db,
        storage,
        None,
        fs_auth,
        Arc::new(crate::bus::MessageBus::new()),
        status_reporter,
        ports,
    ))
}
