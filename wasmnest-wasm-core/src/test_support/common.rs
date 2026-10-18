//! 桌面宿主测试面（共享符号定义见父模块 `test_support.rs`）
//!
//! 承载桌面宿主侧集成测试（`src-tauri/tests/*`，如 session_e2e）与本 crate
//! `#[cfg(test)]` 用例需要的全部脚手架：无头运行时装配、插件私有库根、会话中心
//! 私有库串行锁、认证中心注册表测试闸门。
//!
//! **常编译 pub（非 `#[cfg(test)]`）**：宿主集成测试链的是不带 `cfg(test)` 的 lib，
//! 必须经常编译面才能消费（按 `test_tokens` 常编译先例，ADR 0037 D7 同款裁决）。
//! 门控在父模块：本面随 `desktop-assembly`（桌面宿主开默认 features 时可见）；
//! 移动消费面见兄弟模块 `bare`（`test-support` feature）。
//!
//! 上提来源（wasm-core 纯净性收口票 05b，2026-10-06）：
//! - `manager/runtime.rs` mod tests：`setup_wasm_runtime(_with_config)` /
//!   `plugin_db_root` / `session_plugin_db_guard`（完整迁入，内部 `use crate::…`
//!   不变，同 crate 可直接引用）
//! - `host_api/auth_center.rs`：`registry_gate` / `hold_registry_desk` / `reset`
//!   （原位提为常编译 pub，本模块 re-export 统一入口）
//! - `manager/runtime/tests/session_e2e.rs`：`lock_auth_center_desk`（本地迁入）

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use tokio::sync::{Mutex, RwLock, SemaphorePermit};

// 共享符号单点定义在父模块（`test_support.rs`），本消费面不另存副本
use super::TEST_PLUGIN_ID;
use crate::bus::MessageBus;
use crate::config::{CallModel, CoreConfig};
use crate::db::Database;
use crate::host_api::context::WasmHostContext;
use crate::manager::capability::CapabilityRegistry;
use crate::manager::host::{GuestOp, GuestReply};
use crate::manager::runtime::{EngineSetup, LoadedWasmPlugin, WasmRuntime};
use crate::manager::task::{register_unit_executor, CoreTaskEngine};
use crate::permission::PermissionManager;
use crate::security::fs_auth::FsAuthChecker;
use crate::storage::PluginStorage;
use crate::system::config::AppConfig;

// ==================== 无头运行时装配 ====================

/// 创建 WasmRuntime + 宿主上下文（不实例化插件）
///
/// 供需要独立编译/实例化组件的测试复用。
/// 无头构建（app_handle = None）：tao 事件循环不允许在测试线程创建，
/// emit/数据目录类能力在测试中不被调用路径覆盖；
/// AOT 缓存目录注入到系统临时目录，保证 compile_component_from_file 走缓存路径。
pub fn setup_wasm_runtime() -> (WasmRuntime, Arc<WasmHostContext>) {
    setup_wasm_runtime_with_config(CoreConfig::default())
}

/// 以指定内核配置构建无头运行时（测试专用；`a03_probe` 的燃料禁用/紧内存探针用）
pub fn setup_wasm_runtime_with_config(
    core_config: CoreConfig,
) -> (WasmRuntime, Arc<WasmHostContext>) {
    setup_wasm_runtime_with_setup(EngineSetup::new(core_config))
}

/// 以完整引擎装配输入构建无头运行时（测试专用；引擎定制面 B 面钩子用例经此注入
/// `EngineSetup::with_customizer`，与生产 `PluginHost::new` → `WasmRuntime::with_setup`
/// 同一条装配路径）
pub fn setup_wasm_runtime_with_setup(setup: EngineSetup) -> (WasmRuntime, Arc<WasmHostContext>) {
    // AppConfig 初始化
    static CONFIG_INIT: std::sync::Once = std::sync::Once::new();
    CONFIG_INIT.call_once(|| {
        let mut config = AppConfig::default();
        config.network.port = 8765;
        AppConfig::init(config);
    });

    let all_permissions: &[&str] = &[
        "storage",
        "broadcast",
        "terminal:input",
        "terminal:output",
        "session:read",
        "fs:read",
        "fs:write",
        "ui:sidebar",
    ];

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let db = Database::new(&PathBuf::from(":memory:")).unwrap();
        db.init_schema().unwrap();
        let db = Arc::new(std::sync::Mutex::new(db));

        let storage = Arc::new(PluginStorage::new(db.clone()));

        // 配置管理器持一个建好 schema 的内核库：票 02 的 legacy 迁移通道经
        // `host-session.config-*` 读 `session_configs`，表不存在即报
        // `no such table`（票 07 的旧教训）。会话管理器自 v21 起无库依赖
        // （内核不再读配置表），故此处不再共库——变量保留仅为驱动
        // 建表副作用（init_schema），有意不读（下划线前缀）。
        let _kernel_db = Arc::new(std::sync::Mutex::new({
            let db = Database::new(&PathBuf::from(":memory:")).unwrap();
            db.init_schema().unwrap();
            db
        }));
        let permission = Arc::new(PermissionManager::new());
        permission.grant_permissions(
            TEST_PLUGIN_ID,
            &all_permissions
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        );

        let message_bus = Arc::new(MessageBus::new());

        // 无头构建：不创建 AppHandle（tao 事件循环不允许在测试线程初始化）
        let mut wasm_runtime = WasmRuntime::with_setup(storage.clone(), None, setup).unwrap();
        // guest 事件派发器（票 03 / 票 04）：缺省 `UnwiredGuestEvents`（派发即
        // fail-visible，不静默丢消息）——需要 `events` 导出投递的宿主集成测试自行
        // 注入 `DesktopGuestEvents`（见桌面 `tests/support/mod.rs` 的 setup_wasm_runtime）。
        // 注入 AOT 缓存目录（生产由 app_handle 派生，测试无头上下文手动注入）
        wasm_runtime.aot_cache_dir = Some(
            std::env::temp_dir().join(format!("wasmnest_aot_{}", std::process::id())),
        );

        let host_ctx = WasmHostContext::new(
            db,
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            storage,
            None,
            permission,
            wasm_runtime.fs_auth().clone(),
            message_bus,
            Arc::new(CapabilityRegistry::new()),
        );
        // 注入插件私有库根目录（无头上下文无 AppHandle，见字段文档）：
        // 票 08 的 S1 闭环需要真实私有库（host-plugin-database）
        host_ctx.set_plugin_db_root(Some(plugin_db_root()));
        let host_ctx = Arc::new(host_ctx);

        // 能力域端口（wasm-core-lib-split 票 03 / 04 / 05 / 06）：迁出 `wasm_core` 的
        // 能力域（mdns / ws / peer-net / http）经端口取宿主能力，使权限判定与引擎上下文的
        // 取法落在**本用例自己的**管理器/总线/库上（进程级只有一格，见
        // `wasmnest_host_kit::ports` 模块文档「两条通道」）。走与生产同一个装配入口
        // （`PluginHost::new` 装的就是它）——本夹具曾逐域抄一份且漏掉 mdns，于是依赖
        // mdns 的闭环用例只能在别的用例先装过时绿、单跑即崩（顺序依赖假绿）。
        crate::host_api::install_capability_domain_ports(&host_ctx);

        // 注入 host-task 执行引擎 + 单元执行器注册表（与 PluginHost 生产装配同构）：
        // host_api/task.rs 经 TaskEngine 接口调用 core-task；execute_unit 经
        // UnitExecutor 注册表分发域执行器（幂等去重，多测试共用进程级注册表）
        host_ctx
            .set_task_engine(Arc::new(CoreTaskEngine::new(host_ctx.clone())))
            .await;
        // 单元执行器注册表（与 PluginHost 生产装配同构，票 02 批次 05）：遍历域
        // 自报条目注册（幂等去重按具体类型，多测试共用进程级注册表）。内核测试
        // 二进制只含内核内自报的 fs / http 执行器；process 执行器随域住宿主。
        for entry in crate::host_api::unit_executor::collected_unit_executors() {
            register_unit_executor((entry.make)());
        }

        (wasm_runtime, host_ctx)
    })
}

// ==================== 轻量无头宿主上下文（域函数单测用） ====================

/// 构造轻量无头宿主上下文（**不建 WasmRuntime / 不 init AppConfig / 不装域端口**）
///
/// 与 [`setup_wasm_runtime`] 的差异：后者是「真实组件全链路」夹具（wasmtime 引擎 +
/// 域端口装配 + 单元执行器注册表），而**域函数单测**只需要窄 scope 面
/// （`DbScope` / `SecretsScope` / `PermissionScope`）——九件套里只有数据库需要可配。
///
/// `db_path`：`None` = 内存库（默认）；`Some(path)` = 文件后备库（持久化用例两代
/// 上下文指同一文件，模拟重启）。
///
/// **为什么放本模块**（常编译 pub）：迁宿主的域（票 02 批次 04 起路径 B）其单测随域
/// 住进宿主 `src/plugin/<domain>.rs`，而 `manager::capability` 注册表面不对外——宿主
/// 侧无法手工拼 `WasmHostContext::new` 的注册表参数，只能经本 crate 的公开测试基建
/// 拿上下文（`test_tokens` 常编译同款裁决）。
pub fn build_host_ctx_at(db_path: Option<&std::path::Path>) -> Arc<WasmHostContext> {
    let db = match db_path {
        Some(path) => Database::new(path).expect("open db"),
        None => Database::new(&PathBuf::from(":memory:")).expect("in-memory db"),
    };
    db.init_schema().expect("init schema");
    let db = Arc::new(std::sync::Mutex::new(db));
    let storage = Arc::new(PluginStorage::new(db.clone()));
    let permission = Arc::new(PermissionManager::new());
    let fs_auth = Arc::new(FsAuthChecker::new(storage.clone(), None, Vec::new()));
    let message_bus = Arc::new(MessageBus::new());
    Arc::new(WasmHostContext::new(
        db,
        Arc::new(std::sync::Mutex::new(HashMap::new())),
        storage,
        None,
        permission,
        fs_auth,
        message_bus,
        Arc::new(CapabilityRegistry::new()),
    ))
}

/// 无头测试的插件私有库根目录（`aot_cache_dir` 同模式：进程级固定路径，
/// 供需要用真实私有库的用例定位/清理 `com.wasmnest.terminal-session/plugin.db`）
pub fn plugin_db_root() -> PathBuf {
    std::env::temp_dir().join(format!("wasmnest_plugin_dbs_{}", std::process::id()))
}

/// 会话中心「插件私有库」用例串行锁：`plugin_db_root()` 是**进程级**路径
/// （`aot_cache_dir` 同模式），所有 `activate()` 会话中心的用例共用同一份
/// `com.wasmnest.terminal-session/plugin.db`，于是两类竞态都会把断言变成 flaky：
/// - 配置面用例先 `remove_dir_all` 清库再断言「legacy 两条全部迁入」，而任何一次
///   并发 `activate()` 都会写入 `config.migrated_at` marker → 本方读到 0 行；
/// - tick 按时间条件批量改行（超宽限的 pending → missed），并发用例注入的
///   `now_utc` 会提前推进另一方的定时任务。
/// 持锁即把「同一份私有库」上的写入排成一条序列（用例内仍各自清库）。
///
/// 覆盖范围是**全部**会话中心闭环用例（host-business-decarriage 收尾补全：此前
/// create-with-spec / actions / annotate / config-api / trust 五个用例未持锁，
/// 只要时序一变（如重启用例的完成信号从广播改为 Created 事件）就会让本用例
/// 读到空列表而翻红——新会话闭环用例必须同样持锁）。
pub fn session_plugin_db_guard() -> StdMutexGuard<'static, ()> {
    static SESSION_PLUGIN_DB_LOCK: StdMutex<()> = StdMutex::new(());
    SESSION_PLUGIN_DB_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// 认证中心注册表测试闸门 ====================

// `registry_gate` / `hold_registry_desk` / `reset` 原位提 pub（host_api/auth_center.rs），
// 经本模块 re-export 统一入口：lib 集成测试（session_e2e / system_component_test）与
// wasm-core 内部测试都走 `test_support::{registry_gate, hold_registry_desk, reset}`。

pub use crate::host_api::auth_center::{hold_registry_desk, registry_gate, reset};

/// 占用认证中心注册表的**测试闸门**（v32 / ADR 0031 K1 单中心 desk）
///
/// 注册表是**进程级单例**：桥接门 `session_active()` 查它，而走同一闸门的闭环用例
/// 会 `reset()` 清台。本文件用例会与它们**并行**执行——一旦被清台，本文件的桥接调用
/// 就瞬时变成「session plugin not active」（偶发红，且与被测行为无关）。
/// 故：每个用例在进入异步体时**持闸门到用例结束**（permit 跨 await 合法），
/// 并由 guest 的 `activate` 自行登记中心（产物含 `auth-center-register`）。
pub async fn lock_auth_center_desk() -> SemaphorePermit<'static> {
    registry_gate()
        .acquire()
        .await
        .expect("auth center registry test gate")
}

// ==================== 测试用总线消息投递器 ====================

/// 测试用消息投递器：总线消息按 plugin_id 路由到测试持有的插件实例
///
/// 生产环境由 PluginHost 实现 MessageDispatcher（经 `call_guest` 门面
/// 加锁调用 + trap 自动重载）；互调测试无 PluginHost，等价实现：查实例表
/// 加锁调用 on_message。is_activated 恒真（本测试全部实例均已 activate，
/// 「未激活订阅者不投递」的语义由门禁/注销断言覆盖）。
///
/// **票 05b 上提**（wasm-core 纯净性收口）：lib 集成测试（session_e2e）与
/// wasm-core 内部测试（ws_e2e / pty_e2e / sdk_e2e / ws_output_perf /
/// terminal_output_perf）共用；`instances` 字段 pub（lib 侧字面量构造）。
pub struct TestInstanceDispatcher {
    pub instances: Arc<RwLock<HashMap<String, Arc<Mutex<LoadedWasmPlugin>>>>>,
}

impl crate::bus::MessageDispatcher for TestInstanceDispatcher {
    fn dispatch_to_wasm(
        &self,
        plugin_id: &str,
        msg: &crate::bus::BusMessage,
    ) -> anyhow::Result<()> {
        let instances = self.instances.clone();
        let plugin_id = plugin_id.to_string();
        let msg = msg.clone();
        crate::runtime_util::block_on_async(async move {
            let instances = instances.read().await;
            let plugin = instances.get(&plugin_id).ok_or_else(|| {
                anyhow::anyhow!("TestInstanceDispatcher: no instance '{plugin_id}'")
            })?;
            let mut plugin = plugin.lock().await;
            // v11：按载荷格式路由（与生产 PluginHost 的 dispatch_to_wasm 同语义）
            if let Some(bytes) = &msg.payload_binary {
                plugin
                    .on_message_binary(&msg.topic, &msg.sender, bytes)
                    .map_err(|e| anyhow::Error::from(e))
            } else {
                plugin
                    .on_message(&msg.topic, &msg.sender, &msg.payload)
                    .map_err(|e| anyhow::Error::from(e))
            }
        })
    }

    /// ABI v14：WS 帧投递（`events-ws`）——与 `dispatch_to_wasm` 同桥，
    /// 生产环境由 PluginHost 实现（本实现等价：查实例表加锁调用）
    fn dispatch_ws_frame(
        &self,
        plugin_id: &str,
        frame: &crate::bus::WsFrameDispatch,
    ) -> anyhow::Result<bool> {
        let instances = self.instances.clone();
        let plugin_id = plugin_id.to_string();
        let frame = frame.clone();
        crate::runtime_util::block_on_async(async move {
            let instances = instances.read().await;
            let plugin = instances.get(&plugin_id).ok_or_else(|| {
                anyhow::anyhow!("TestInstanceDispatcher: no instance '{plugin_id}'")
            })?;
            let mut plugin = plugin.lock().await;
            plugin.on_ws_frame(&frame).map_err(anyhow::Error::from)
        })
    }

    fn is_activated(&self, _plugin_id: &str) -> bool {
        true
    }
}

// ==================== 互调 wire 捕获器 / 会话中心 api 清单 ====================

/// 互调 wire 捕获器（票 10 闭环）：静态订阅认证中心的请求 topic，记录
/// file-transfer → auth center 的 JSON-RPC 请求（含 params 原样）
///
/// **票 05b 上提**：lib 集成测试（session_e2e）与 wasm-core 内部测试共用；
/// `captures` 字段 pub（lib 侧字面量构造 + 断言读）。
pub struct AuthCenterCaptureHandler {
    pub captures: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
}

impl crate::bus::BusMessageHandler for AuthCenterCaptureHandler {
    fn on_message(&self, msg: &crate::bus::BusMessage) -> anyhow::Result<()> {
        // std Mutex 短临界区（总线消费任务内，禁止阻塞锁/await）
        self.captures
            .lock()
            .expect("capture lock")
            .push((msg.topic.clone(), msg.payload.clone()));
        Ok(())
    }
}

// ==================== 夹具产物读取面 / 应用仓读取面：已归位平台仓（票 08 批次三） ====================
//
// 曾在此的两类跨仓读取随消费者一并迁平台仓：
// - `session_apis`（读应用仓 bedcode 桌面 manifest）→ 桌面 `src-tauri/tests/support/`；
// - `sdk_fixture_artifact_bytes` / `system_test_artifact_bytes`（读平台仓
//   `target/fixtures`）→ 桌面 `src-tauri/tests/support/`（夹具 crate 与产物本来就住
//   平台仓；能力仓单克隆不再要求平台产物在场）。
// 能力仓自持夹具（`fixtures/*`）的产物经 `manager::runtime::fixture_target` 读取，
// 不经本模块。

// ==================== 内核私有机制的测试转发面（宿主集成测试用） ====================
//
// 为什么经这里转：`engine::aot_cache_key` 是内核私有（pub(crate)）——宿主集成测试
// 需要它定位 AOT 缓存产物，但生产面没有跨 crate 消费者。本模块是宿主测试的**唯一转
// 发点**（常编译 pub 测试基建），不为此放宽内核生产 API。
//
// `plugin_raw_store` / `TEST_PLUGIN_ID` 是两个消费面共享符号，单点定义在父模块
// `test_support.rs`（本面不再各持副本）。

/// AOT 缓存文件名 hash（宿主集成测试定位 `<cache_dir>/c<hash>.cwasm` 用）
///
/// 与内核 `compile_component_from_file` 同一 hash 真源——宿主测试不得另拼一份
/// 文件名规则（第二真源会在内核换算法时静默失配）。
pub fn aot_cache_key(path: &std::path::Path, source_len: u64) -> u64 {
    crate::manager::runtime::engine::aot_cache_key(path, source_len)
}

/// 日志捕获（引擎 / trap 证据链断言用：`capture(|| ...)` 收集 tracing 事件）
///
/// `host_api::log` 是 `pub(super)`（crate 内可见）——宿主测试经本 re-export 取用，
/// 不为测试把模块提为 pub。
pub use crate::host_api::log::capture;

// ==================== 属主模型（event-loop 调用模型）的测试转发面 ====================
//
// 为什么经这里转：`manager::host::owner` 是 pub(crate)（I1：宿主侧唯一入口是装配表
// `WasmInstanceEntry`，属主句柄不跨 crate 暴露）——但属主不变式（I3 trap 收敛 / I4
// 入队序 / I6 停止语义 / 有界失败）的宿主集成测试必须**直接**驱动属主（不经
// PluginHost，见 owner_e2e 用例主旨）。本段是那组测试的唯一转发面：暴露面收窄到
// 句柄四个方法与队列容量，生产 API 零变化。

/// 实例级失败处理端口（宿主测试实现方取同一契约——单点定义，不另立副本）
pub use crate::manager::host::owner::{OwnerFailureSink, OwnerStatsSnapshot, ShutdownReport};

/// 属主请求队列容量（有界失败断言的判据，与内核同一常量）
pub fn owner_queue_cap() -> usize {
    crate::manager::host::owner::OWNER_QUEUE_CAP
}

/// 直接启动属主任务（等价内核 `spawn_owner`）：把实例整块交给属主，不经装配表
/// ——宿主测试要观察的是属主模型自身的不变式，不是装配表门面
pub fn spawn_test_owner(plugin: LoadedWasmPlugin, sink: Arc<dyn OwnerFailureSink>) -> Arc<TestOwnerHandle> {
    Arc::new(TestOwnerHandle {
        inner: crate::manager::host::owner::spawn_owner(plugin, sink),
    })
}

/// 装配条目的调用模型（宿主测试断言「模型按装配参数生效」用）
pub fn instance_call_model(entry: &crate::manager::host::WasmInstanceEntry) -> CallModel {
    entry.call_model()
}

/// 停止装配条目上的属主（`mutex` 模型 no-op 返回 `None`）——宿主测试的
/// 「trap 后恢复路径 / store 随属主停止释放」断言用
pub async fn instance_shutdown(entry: &crate::manager::host::WasmInstanceEntry) -> Option<ShutdownReport> {
    entry.shutdown().await
}

/// 属主 guest 清理被跳过次数（`event-loop` 停用计数；`mutex` 模型恒 0）
pub fn host_owner_cleanup_skipped(host: &crate::manager::host::PluginHost) -> u64 {
    host.owner_cleanup_skipped()
}

/// 属主句柄的测试视图（薄转发：`call` / `stop` / `is_alive` / `stats`）
pub struct TestOwnerHandle {
    inner: crate::manager::host::owner::OwnerHandle,
}

impl TestOwnerHandle {
    /// 入队并等待结果（失败立即显性 Err：队列满 / 属主已停都点名原因）
    pub async fn call(&self, op: GuestOp) -> crate::Result<GuestReply> {
        self.inner.call(op).await
    }

    /// 停止属主（返回即 store 已 drop）
    pub async fn stop(&self) -> ShutdownReport {
        self.inner.stop().await
    }

    /// 属主是否仍在服务（false = 实例不可用）
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// 计数快照
    pub fn stats(&self) -> OwnerStatsSnapshot {
        self.inner.stats()
    }
}

// ==================== 内核测试二进制的域端口替身（仅 cfg(test)） ====================

/// **仅本 crate 的 lib 测试二进制编译**（cfg(test)）：宿主集成测试链的是**不带
/// cfg(test)** 的本 crate，此模块在那边不存在 ⇒ 不可能盖掉宿主装配的真端口
/// （域的 `install_ports` 是 `OnceLock`，首个装配者胜出）。
///
/// **为什么需要**（wasm-core 纯净性收口票 02 批次 03）：ws / http 的端口 adapter 已迁
/// 宿主 `src-tauri/src/plugin/{ws,http}.rs`，而**内核测试二进制不链宿主 lib** ⇒ 宿主
/// 自报的装配器不在场，两条通道（进程级 `install_ports` / 实例级 `set_domain_ports`）
/// 都无人装配 ⇒ 凡走真实组件全链路的用例（`manager::host` 的激活/停用/实例调用模型、
/// `manager::runtime` 的 http_e2e）会在域的 `ports()` 上 panic。
///
/// 替身按**宿主 adapter 的同一语义**实现：权限门走同一份 `host_api::check_permission`、
/// publish 走本实例总线（sender 恒 `host`）、桥走同一份 `runtime_util::block_on_async`、
/// `bus_port` 的帧投递侧用绑定到本总线的 `BusBoundWsPorts`。唯一差异是无头事实：
/// 测试上下文没有 `AppHandle` ⇒ `event_sink` 为 `None`（宿主 adapter 在同形上下文下
/// 取到的也是 `None`）。
#[cfg(test)]
pub(crate) mod kernel_test_domain_ports {
    use std::any::Any;
    use std::sync::Arc;

    use wasmnest_server_base::ports::BusPort;
    use wasmnest_server_http::plugin_binding::ports::{
        BoxedBlocked as HttpBoxedBlocked, HttpEventSink, HttpPorts, OutboundAuth,
    };
    use wasmnest_server_websocket::plugin_binding::ports::{
        BoxedBlocked as WsBoxedBlocked, FrameDispatch, WsFrameTarget, WsPorts,
    };

    use crate::bus::{BusBoundWsPorts, HostBusPort, MessageBus, WsFrameDispatch};
    use crate::host_api::check_permission;
    use crate::host_api::context::WasmHostContext;
    use crate::runtime_util::block_on_async;

    /// 装本 crate 测试二进制需要的迁出域端口替身（ws / http；两条通道都装，
    /// 与宿主 adapter 的 `install` 同形）
    pub(crate) fn install(host_ctx: &Arc<WasmHostContext>) {
        let ws: Arc<dyn WsPorts> = Arc::new(TestWsPorts::new(host_ctx.clone()));
        host_ctx.set_domain_ports(
            wasmnest_server_websocket::plugin_binding::DOMAIN,
            Arc::new(Arc::clone(&ws)) as Arc<dyn Any + Send + Sync>,
        );
        wasmnest_server_websocket::plugin_binding::install_ports(ws);

        let http: Arc<dyn HttpPorts> = Arc::new(TestHttpPorts { ctx: host_ctx.clone() });
        host_ctx.set_domain_ports(
            wasmnest_server_http::plugin_binding::DOMAIN,
            Arc::new(Arc::clone(&http)) as Arc<dyn Any + Send + Sync>,
        );
        wasmnest_server_http::plugin_binding::install_ports(http);
    }

    /// ws 端口替身（与宿主 `src/plugin/ws.rs` 的 `HostWsPorts` 同语义，仅测试）
    struct TestWsPorts {
        bus: Arc<MessageBus>,
        ctx: Arc<WasmHostContext>,
    }

    impl TestWsPorts {
        fn new(ctx: Arc<WasmHostContext>) -> Self {
            Self { bus: ctx.message_bus().clone(), ctx }
        }
    }

    impl WsPorts for TestWsPorts {
        fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool {
            // 与宿主 adapter 同一条判定路径（同一份 PermissionManager、同一条拒绝 warn）
            check_permission(self.ctx.as_ref(), plugin_id, permission, api)
        }

        fn publish(&self, topic: &str, payload: serde_json::Value) {
            // sender 恒为 `host`（与宿主 adapter / BusBoundWsPorts 一致）
            self.bus.publish(topic, "host", payload);
        }

        fn bus_port(&self) -> Arc<dyn BusPort> {
            // 端点登记的总线端口：帧投递侧用绑定到本总线的窄端口（与宿主 adapter 同形）
            Arc::new(HostBusPort::new(
                Arc::clone(&self.bus),
                Arc::new(BusBoundWsPorts::new(Arc::clone(&self.bus))),
            ))
        }

        fn dispatch_frame(
            &self,
            plugin_id: &str,
            target: WsFrameTarget<'_>,
            kind: &str,
            payload: Vec<u8>,
        ) -> FrameDispatch {
            // `events-ws` 帧回灌不经 topic 订阅，直接按属主寻址投给插件实例
            //（与宿主 adapter 逐字同语义）
            let Some(dispatcher) = block_on_async({
                let bus = Arc::clone(&self.bus);
                async move { bus.dispatcher().await }
            }) else {
                return FrameDispatch::Unavailable;
            };
            let frame = match target {
                WsFrameTarget::Client(handle) => WsFrameDispatch::Client {
                    handle: handle.to_string(),
                    kind: kind.to_string(),
                    payload,
                },
                WsFrameTarget::EndpointClient { endpoint_id, client_id } => {
                    WsFrameDispatch::EndpointClient {
                        endpoint_id: endpoint_id.to_string(),
                        client_id: client_id.to_string(),
                        kind: kind.to_string(),
                        payload,
                    }
                }
            };
            match dispatcher.dispatch_ws_frame(plugin_id, &frame) {
                Ok(true) => FrameDispatch::Delivered,
                Ok(false) => FrameDispatch::NotExported,
                Err(e) => FrameDispatch::Failed(e.to_string()),
            }
        }

        fn block_on_any(&self, fut: WsBoxedBlocked) -> Box<dyn Any + Send> {
            block_on_async(fut)
        }
    }

    /// http 端口替身（与宿主 `src/plugin/http.rs` 的 `HostHttpPorts` 同语义，仅测试）
    struct TestHttpPorts {
        ctx: Arc<WasmHostContext>,
    }

    impl HttpPorts for TestHttpPorts {
        fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool {
            check_permission(self.ctx.as_ref(), plugin_id, permission, api)
        }

        fn authorize_outbound(&self, plugin_id: &str, url: &str, may_prompt: bool) -> OutboundAuth {
            // 与宿主 adapter 同一条授权链（本实例的 net_auth；may_prompt=false 池线程不弹窗）
            let checker = self.ctx.net_auth();
            let verdict = block_on_async(async {
                if may_prompt {
                    checker.authorize_outbound(plugin_id, url).await
                } else {
                    checker.authorize_outbound_quiet(plugin_id, url).await
                }
            });
            match verdict {
                // origin 是归一化后的 origin（不含 path / query，AGENTS §8 凭据红线）
                Ok(verdict) if verdict.is_allowed() => OutboundAuth::Allowed {
                    origin: verdict.origin().to_string(),
                },
                Ok(verdict) => OutboundAuth::Denied {
                    reason: verdict.reason().to_string(),
                    origin: verdict.origin().to_string(),
                },
                Err(e) => OutboundAuth::CheckFailed(e.to_string()),
            }
        }

        fn event_sink(&self) -> Option<Arc<dyn HttpEventSink>> {
            // 无头测试上下文没有 AppHandle ⇒ None（能力域对 None 显性报错，不静默丢 chunk）
            debug_assert!(
                self.ctx.app_handle().is_none(),
                "内核测试上下文不应携带 AppHandle"
            );
            None
        }

        fn block_on_any(&self, fut: HttpBoxedBlocked) -> Box<dyn Any + Send> {
            block_on_async(fut)
        }
    }
}

