//! 宿主上下文（host-api 消费方家园，spec 票 04）
//!
//! `WasmHostContext`（宿主子系统引用聚合）、`PluginServices`（插件宿主服务抽象，
//! 两阶段注入解 PluginHost 互引）、`ProcessRegistry` / `kill_process_group`
//! （host-process 进程注册/终止，v8）原定义于 `crate::manager::runtime`，
//! 迁入本模块使 host_api 消费方不再反向 import manager（见
//! `.scratch/2026-09-24-wasm-core-decouple/spec.md` C1/C5）。
//!
//! **capability 端口（票 04）**：宿主上下文对 manager 的类型依赖经
//! [`CapabilityProvider`] + [`CapabilityTarget`] 两个 trait 消除——WasmHostContext
//! 持有 `Arc<dyn CapabilityProvider>`，host_api 只经 trait 消费能力路由；具体实现
//! （manager::capability 的注册表 / manager::host 的装配条目）在 manager 侧直连
//! （方向合法）。票 06 起本模块**不再引用任何 manager 类型**（原先的
//! `LoadedWasmPlugin` 引用随转发端口窄化消除）。
//!
//! **票 02 B5 上下文合一（单形态,已收敛）**：本模块是双端唯一宿主上下文（原移动
//! `bare_context::WasmHostContext` 已并入超集删除）。`fs_auth` 槽为**桌面原样
//! `Arc<FsAuthChecker>`**（用户新裁决 2026-10-11「wasm-core 机制全部以桌面端为准
//! 收敛一套」：fs 授权统一到桌面判定链，移动自实现已退役）——判定链 / 授权记录 /
//! 弹窗 / 策略档位单一实现在本 crate，双端共用。`first_party_dirs` 桌面由宿主
//! 注入、移动传空表（无 first-party 概念），其余语义逐字一致。
//!
//! `manager/runtime.rs` 保留 `pub use` 再导出（manager→host_api 合法方向），
//! 历史路径编译绿直至迭代清理。

use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use std::sync::Mutex;
use tokio::sync::RwLock;

use wasmnest_host_kit::state::WasmPluginState;

/// 对等网络上下文装配端口（整核抽出 §3.3 唯一端口）：lib 实现 `peer_ctx(&AppHandle)`
/// 构造 `Arc<PeerCtx>`（读 tauri managed state + server 端口装配）；无头/测试传 `None`
/// → `HEADLESS_UNAVAILABLE` 语义不变。
pub type PeerCtxProvider = dyn Fn(&tauri::AppHandle) -> Arc<wasmnest_server_peer_net::PeerCtx> + Send + Sync;

use crate::db::Database;
use crate::host_api::ports::{
    EnginePortsPlatformPicker, HostEnginePorts, HostFactsPort, PlatformPickerPort, UnimplementedHostFacts,
    UnimplementedPlatformPicker, UnimplementedPorts,
};
use crate::permission::PermissionManager;
use crate::security::fs_auth::FsAuthChecker;
use crate::security::network_auth::NetworkAuthChecker;
use crate::storage::PluginStorage;

// tauri::Manager：`AppHandle::path()` 扩展（get_or_create_plugin_db 数据目录派生）
use tauri::Manager;

/// 插件宿主服务抽象 — 解耦 WasmHostContext 与 PluginHost 的循环依赖
///
/// WasmHostContext 需要回调插件宿主（注册会话生命周期监听器），
/// 而 PluginHost 持有 WasmHostContext —— 通过 trait 对象 + 两阶段注入打破类型互引：
/// 本模块只依赖此 trait，`PluginHost` 在 `wasm_core::manager::host` 模块中实现它
pub trait PluginServices: Send + Sync + 'static {
    // 票 03 删除的两条注册面（`register_session_lifecycle_listener` /
    // `register_session_input_listener`）：宿主侧观察注册表与派发点一并退役，
    // 见 `session/session_manager.rs` 的「观察面（票 03 已退役）」节。

    /// 标记插件为错误状态
    ///
    /// 仅通知前端弹窗提示，不改变插件状态（保持激活，会话照常运行）。
    /// 由 `host_mark_plugin_error` Host Function 转发，插件自身检测到
    /// 配置失败（如 hooks 脚本拷贝失败）时调用。
    fn mark_plugin_error(&self, plugin_id: String, error: String);

    /// 为指定插件注册宿主周期定时器（v6，ADR 0003）
    ///
    /// 宿主按 interval_secs 到点调用插件的 command（附当前时间参数），
    /// 幂等判断归插件。重复注册替换该插件已有定时器。
    fn register_plugin_timer(&self, plugin_id: String, interval_secs: u64, command: String);

    /// 分发进程执行完成事件到插件（host-process，v8）
    ///
    /// 由宿主侧 process 域实现（桌面 `src-tauri/src/plugin/process.rs`，
    /// 移动 `host_domains/` 内）在进程结束时调用：经插件 export
    /// `on_process_done` 投递 `{ run_id, exit_code, timed_out }`。
    /// 插件未激活/已卸载时调用失败，仅记日志（尽力而为）。
    fn dispatch_process_done(&self, plugin_id: String, event: serde_json::Value);

    /// 分发宿主并发任务事件到插件（host-task，v20）
    ///
    /// 由 core-task 消费派发任务调用（每插件单线程串行，实例锁天然要求）：
    /// 经可选导出 `events-task#on-task-event` 投递 `{ jobId, phase, ... }`；
    /// 未导出（旧 SDK 产物）时降级 `Ok(false)` → 事件丢弃 + 计数（宿主不缓存，
    /// `status` / `list-jobs` 自愈）。插件未激活/已卸载时调用失败仅记日志
    /// （尽力而为，同 dispatch_process_done）。
    fn dispatch_task_event(&self, plugin_id: String, event: serde_json::Value);

    /// 安装插件随包 CLI（host-app，v8）：复制到用户 bin 目录 + 注册 PATH（幂等）
    ///
    /// 源 = 插件包目录 `cli/<file-name>`（Windows 自动补 .exe）；
    /// `bin_dir` 为空用平台默认。返回安装后的 bin 目录绝对路径。
    /// 由宿主侧 app 域实现（桌面 `src-tauri/src/plugin/app.rs`，移动
    /// `host_domains/` 内）经 block_on_async 驱动（宿主侧注册表/PATH 实现）。
    /// 返回 Box<dyn Future> 保持 trait dyn 兼容（async fn 会破坏 Arc<dyn>）。
    fn install_cli(
        &self,
        plugin_id: String,
        file_name: String,
        bin_dir: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>>;

    /// 卸载插件随包 CLI（host-app，v8）：删文件 + 移除仅本插件的 PATH 条目（幂等）
    ///
    /// 应用关闭流程（deactivate_all 置位 shutting_down）中调用时自动跳过，
    /// CLI 随下次激活重新安装。
    fn uninstall_cli(
        &self,
        plugin_id: String,
        file_name: String,
        bin_dir: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;

    /// 插件自身资源目录（host-app，v25 函数级追加，**无权限门**）：返回插件安装
    /// 目录绝对路径（`extension_path` 剥离 verbatim 前缀，与生命周期事件 payload
    /// 的 `resource_dir` 同值）。由宿主侧 app 域实现（桌面
    /// `src-tauri/src/plugin/app.rs`，移动 `host_domains/` 内）经 block_on_async
    /// 驱动。插件未加载 → `Err`（不静默返回空串，调用方据此显性失败）。
    fn plugin_resource_dir(
        &self,
        plugin_id: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>>;
}

/// 能力查询/路由端口（票 04 ISP 化）
///
/// host_api 侧只经本 trait 消费能力路由（`manager::capability::forward_*` 与宿主
/// 上下文访问器），不接触注册表具体类型；具体注册表在 manager 侧实现本 trait。
/// 系统组件装配（register_system_component 等）仍以具体注册表在 manager
/// 侧直连（方向合法）。
///
/// **转发目标经窄端口 [`CapabilityTarget`]**（票 06）：trait 签名不再引用任何
/// manager 类型——host_api 对 manager 的类型依赖至此清零（票 04 遗留的
/// `LoadedWasmPlugin` 引用随装配域下沉一并消除）。
pub trait CapabilityProvider: Send + Sync {
    /// 能力是否已有提供者（依赖检查用；未知能力名 = 无提供者）
    fn is_available(&self, name: &str) -> bool;
    /// 返回依赖清单中未装配的能力名（依赖缺失报错用）
    fn missing(&self, dependencies: &[String]) -> Vec<String>;
    /// 注册系统组件为能力提供者（替换宿主原语，二选一装配）
    fn register_system_component(
        &self,
        name: &str,
        plugin_id: &str,
        target: Arc<dyn CapabilityTarget>,
    ) -> crate::Result<()>;
    /// 能力回落宿主原语（仅当前提供者确为该插件时生效）
    fn revert_to_host(&self, name: &str, plugin_id: &str);
    /// 撤销某系统组件的全部能力提供（停用/重建前清理）
    fn revert_all_from(&self, plugin_id: &str);
    /// 查询路由目标：系统组件提供且调用方非提供者自身时返回（提供者 ID, 转发目标）
    fn system_component_instance(
        &self,
        name: &str,
        caller_plugin_id: &str,
    ) -> Option<(String, Arc<dyn CapabilityTarget>)>;
    /// 当前提供者类别（诊断/测试用）
    fn provider_kind(&self, name: &str) -> String;
}

/// 能力转发目标（系统组件实例句柄的**窄端口**，票 06）
///
/// 转发方（manager::capability）只经本 trait 触达提供者实例，**不知道调用模型**
/// ——`mutex`（实例锁）与 `event-loop`（属主队列）在实现内部分派。
/// 实现由 `manager::host::WasmInstanceEntry` 提供（超时兜底也在实现内）。
///
/// **闭表**：方法按能力分组，组名 = `manager::capability::routable_capabilities()`
/// 里的「路由方法前缀」（内建行内核自持；能力域行的词汇由该域自报，票 02 批次 03）。
/// 新增可路由能力时在此加一组方法（与那张表同步），
/// 漏加/多加由 `capability::tests::routable_capabilities_and_forward_methods_stay_in_sync`
/// 点名（该锁在两个方向都断言：表里有而此处没有 ⇒ 红；此处有而表里没有 ⇒ 红）。
///
/// 层次：外层 `Result` = **传输层**失败（trap / 超时 / 属主已停），
/// 内层 `Result` = guest 层 WIT `result<.., string>` 本体。
pub trait CapabilityTarget: Send + Sync + 'static {
    /// `host-storage.get`：`result<option<string>, string>`
    fn storage_get(&self, key: &str) -> std::result::Result<std::result::Result<Option<String>, String>, String>;
    /// `host-storage.set`（层次同 [`CapabilityTarget::storage_get`]）
    fn storage_set(&self, key: &str, value: &str) -> std::result::Result<std::result::Result<(), String>, String>;
    /// `host-storage.delete`（层次同 [`CapabilityTarget::storage_get`]）
    fn storage_delete(&self, key: &str) -> std::result::Result<std::result::Result<(), String>, String>;
    /// `host-mdns.browse`：`result<string, string>`（返回浏览句柄）
    fn mdns_browse(&self, service_type: &str) -> std::result::Result<std::result::Result<String, String>, String>;
    /// `host-mdns.stop-browse`：`result<bool, string>`（是否存在该句柄）
    fn mdns_stop_browse(&self, browser_id: &str) -> std::result::Result<std::result::Result<bool, String>, String>;
    /// `host-mdns.advertise`：`result<string, string>`（返回广播句柄）
    fn mdns_advertise(&self, config_json: &str) -> std::result::Result<std::result::Result<String, String>, String>;
    /// `host-mdns.stop-advertise`：`result<bool, string>`
    fn mdns_stop_advertise(&self, advertise_id: &str)
        -> std::result::Result<std::result::Result<bool, String>, String>;
    /// `host-mdns.is-advertising`：`result<bool, string>`
    fn mdns_is_advertising(&self, advertise_id: &str)
        -> std::result::Result<std::result::Result<bool, String>, String>;
}

/// host-task 执行引擎接口（消费方定义，两阶段注入，PluginServices 先例）
///
/// core-task（`manager::task`）实现本 trait；`WasmHostContext` 在 PluginHost
/// 构造完成后经 [`WasmHostContext::set_task_engine`] 注入。`host_api/task.rs`
/// 只依赖本接口做「权限门 + 解析/配额」，不再 import `manager::task`（依赖单向化 C3）。
pub trait TaskEngine: Send + Sync + 'static {
    /// 同步批（`execute-batch`）：扇出 → join → 一次性返回全部单元结果
    ///
    /// **不再收 `host_ctx`**（wasm-core-lib-split 票 03）：任务登记表需要**拥有**
    /// 一份宿主上下文强引用（任务在异步执行期间须独立于插件实例存活），而
    /// `WasmPluginState` 的宿主字段搬进机制内核后是 `Arc<dyn HostPorts>`，拿不回
    /// 具体 `Arc<WasmHostContext>`。改为**注入时捕获**——`set_task_engine` 本就是在
    /// 那一个 `Arc` 上调用的，捕获到的与调用方持有的是同一个对象，语义不变。
    fn execute_batch(&self, owner: &str, plan_json: &str) -> Result<String, String>;

    /// 异步任务（`submit`）：登记后立即返回 `task-<hex>` 句柄；终态经回调
    fn submit(&self, owner: &str, plan_json: &str) -> Result<String, String>;

    /// 任务状态自愈快照（事件丢失后查询）；`Ok(None)` = 不存在 / 非属主
    fn status(&self, owner: &str, job_id: &str) -> Result<Option<String>, String>;

    /// 协作式取消（正在执行的单元跑完或超时，未开始单元 skipped）；幂等
    fn cancel(&self, owner: &str, job_id: &str) -> Result<bool, String>;

    /// 本插件在册任务清单（自愈快照）
    fn list_jobs(&self, owner: &str) -> Result<String, String>;
}

/// 宿主上下文（注入到 WasmPluginState）
///
/// 持有宿主子系统引用，Host Functions 通过此上下文访问宿主能力
/// plugin_services 使用两阶段初始化：new() 时为 None，PluginHost 构造完成后通过 set_services() 注入
pub struct WasmHostContext {
    /// 主库连接（宿主侧域函数访问，host_api 迁移后 pub(crate)）
    pub(crate) db: Arc<Mutex<Database>>,
    /// 插件独立数据库池 — 每插件一个独立 .db 文件和连接
    ///
    /// `pub`：移动宿主 adapter（`plugin/host_domains/db.rs`，插件私有库按移动布局
    /// `plugins/<id 去点划>.db` 懒开 + 缓存）直读字段——票 05 绑定归位后域 adapter
    /// 住宿主，内核侧无第二读者（内核自己的 `get_or_create_plugin_db` 走另一布局）。
    pub plugin_dbs: Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>>,
    /// `pub`：移动宿主 adapter（`plugin/host_domains/storage.rs`）直读字段
    /// （票 05 绑定归位后域逻辑住宿主，与 `ports` / `plugin_dbs` 同侧先例）。
    pub storage: Arc<PluginStorage>,
    /// 密钥托管读缓存（v15 host-auth）：read-through（get 命中直接返回，
    /// set/delete 失效对应键）；真源为主库 plugin_secrets 表（重启后一致）
    pub(crate) secrets_cache: Arc<std::sync::RwLock<std::collections::HashMap<(String, String), String>>>,
    /// Tauri AppHandle（无头/测试上下文为 None，emit/路径类宿主能力降级）
    ///
    /// `pub`：移动宿主 adapter（`plugin/host_domains/{http,mdns,db,event,platform}.rs`）
    /// 直接克隆 `Option<Arc<AppHandle>>` 交给端口/任务持有（票 05 绑定归位后域逻辑
    /// 住宿主）；`app_handle()` 访问器只借出 `&AppHandle`，不满足「持有」场景。
    pub app_handle: Option<Arc<tauri::AppHandle>>,
    /// 插件私有库根目录覆盖（布局 `<root>/<plugin_id>/plugin.db`）
    ///
    /// 生产为 `None`：走 `app_handle` 的 `app_data_dir()/plugins/<plugin_id>`；
    /// 无头测试经 [`Self::set_plugin_db_root`] 注入（tao 事件循环不允许在测试
    /// 线程建 AppHandle，故测试只能经注入点拿到真实私有库——票 08 的 S1 闭环
    /// 需要它）。
    plugin_db_root: Arc<std::sync::RwLock<Option<PathBuf>>>,
    pub(crate) permission: Arc<PermissionManager>,
    /// 文件系统访问校验器（**桌面原样 `Arc<FsAuthChecker>`**，用户新裁决
    /// 2026-10-11「wasm-core 机制全部以桌面端为准收敛一套」）：判定链 / 授权记录 /
    /// 弹窗 / 策略档位单一实现在本 crate，双端共用同一实例类型。
    /// `first_party_dirs` 桌面由宿主注入、移动传空表（无 first-party 概念）。
    pub(crate) fs_auth: Arc<FsAuthChecker>,
    /// 网络出站授权校验器（票 05：`host-http.fetch` 的出站询问与网络授权记录）
    ///
    /// 与 `fs_auth` 同一形态（持 db 句柄 + AppHandle），判定入口分别是
    /// `authorize_outbound`（弹窗面）与 `is_granted`（任务单元无询问面）。
    /// 入站方向（`register-endpoint`）不归它管——「我要暴露什么接口」是业务编排。
    pub(crate) net_auth: Arc<NetworkAuthChecker>,
    pub message_bus: Arc<crate::bus::MessageBus>,
    /// 插件宿主服务（两阶段初始化，避免 PluginHost 与 WasmHostContext 类型互引）
    plugin_services: Arc<RwLock<Option<Arc<dyn PluginServices>>>>,
    /// host-task 执行引擎（两阶段注入：PluginHost 构造后经 [`Self::set_task_engine`] 注入；
    /// host_api/task.rs 只依赖 [`TaskEngine`] 接口，不依赖 manager::task 具体实现）
    task_engine: Arc<RwLock<Option<Arc<dyn TaskEngine>>>>,
    /// 运行中进程注册表（host-process，v8）：run_id → 进程句柄
    ///
    /// 宿主侧 process 域实现（桌面 `src-tauri/src/plugin/process.rs`，
    /// 移动 `host_domains/` 内）注册/移除；kill（超时/取消）经此查找句柄。
    process_registry: Arc<ProcessRegistry>,
    /// 插件互调 api 注册表（ADR-0017）：激活登记 / 停用注销，
    /// `bus_publish` 对 `wasmnest.api.*` 请求 topic 做目标校验
    api_registry: Arc<crate::security::api_registry::ApiRegistry>,
    /// 统一授权框架（core-security）：三段决策管线 + 仲裁器注册表
    ///
    /// 票 02 B5 改 `Arc`：宿主上下文（含历史逐插件派生，`for_plugin` 已于 2026-10-14 删）
    /// 需共享同一框架（注册表语义是宿主级，逐实例复制会丢 FsAuthorizer/ApiCallAuthorizer）。
    /// 访问器 [`Self::security`] 返回 `&SecurityFramework`（`Arc::as_ref`），消费点零改动。
    security: Arc<crate::security::SecurityFramework>,
    /// 能力注册表（core-plugin-manager 票据 06）：能力名 → 宿主原语/系统组件
    /// 实例（二选一装配）；宿主侧域函数内经此路由
    capabilities: Arc<dyn CapabilityProvider>,
    /// 实例级能力域端口表（域名 → 端口对象）
    ///
    /// wasm-core-lib-split 票 04：迁出 `wasm_core` 的能力域（ws 等）在自己的 crate 里
    /// 实现 `impl … Host for WasmPluginState`，拿不到本上下文，于是经
    /// [`wasmnest_host_kit::ports::HostPorts::domain_ports`] 从这里取回**与本实例同一份
    /// 上下文绑定**的端口（权限管理器 / 消息总线 / 异步桥都取自它）。
    ///
    /// 为什么要表而不是全局单例：一个进程可以有多份宿主上下文（无头测试每个用例一份、
    /// 多实例并行），各有各的权限与总线；全局只有一格 ⇒ 能力域会读到别的上下文的端口。
    /// 装配点：生产经 `PluginHost::new`、无头测试经 `setup_wasm_runtime`，都在持有
    /// `Arc<WasmHostContext>` 之后调 [`Self::set_domain_ports`]。
    domain_ports: Arc<std::sync::RwLock<std::collections::HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>>,
    /// 对等网络上下文装配端口（整核抽出 §3.3）：lib 注入 `peer_net_cmds::peer_ctx`，
    /// 无头/测试为 `None` → `HEADLESS_UNAVAILABLE` 语义不变。两阶段注入（同
    /// [`Self::set_task_engine`]），`PluginHost::new` 构造后写入。
    peer_ctx_provider: Arc<std::sync::RwLock<Option<Arc<PeerCtxProvider>>>>,
    /// 宿主引擎端口（移动装配面，票 02 B5 并入超集）：auth / egress / peer /
    /// mdns / 平台桥等「离宿主无法实现」的引擎调用唯一入口。桌面构造给
    /// [`UnimplementedPorts`] 占位（桌面引擎调用不经过端口，命中即 fail-visible）。
    ///
    /// `pub`：移动宿主（外部 crate）的域 adapter（`plugin/{auth,connection,fs_mobile}.rs`
    /// 等）直接读字段。
    pub ports: Arc<dyn HostEnginePorts>,
    /// 平台选择器（`host-platform.pick-files` / `pick-folders` 的端实现）
    ///
    /// 机制在 `host_api/platform.rs`（`fs:pick` 权限门 + `authorize_picked` 授权
    /// 校验 + JSON 形状），选择器本体是端差异（桌面原生对话框 / 移动 SAF），
    /// 经 [`PlatformPickerPort`] 注入（ADR 0052 D1）：
    ///
    /// - 桌面：`PluginHost::new` 末参注入宿主实现
    ///   （`桌面宿主 src-tauri/src/plugin/platform_picker.rs`）；
    /// - 移动：[`Self::new_with_ports`] 自动用 [`EnginePortsPlatformPicker`] 适配
    ///   已注入的 `ports`（SAF 端口）——与引擎端口同装配面，无需第二个构造参数；
    /// - 缺省 [`UnimplementedPlatformPicker`] fail-visible（无头 / 测试）。
    ///
    /// 槽位形态与 `host_facts` 同款（构造后才注入，读时 clone 一个 Arc）：桌面
    /// 注入发生在 `PluginHost::new` 内部、实例化之前。
    platform_picker: Arc<std::sync::RwLock<Arc<dyn PlatformPickerPort>>>,
    /// 宿主端事实（平台标识 / 入站服务器端口；见 [`HostFactsPort`]）
    ///
    /// 单形态收口（2026-10-13）后内核不再按 `desktop-assembly` 编译期二选一端值；
    /// 端差异实现住各端宿主，装配期经 [`Self::set_host_facts`] 注入。缺省
    /// [`UnimplementedHostFacts`] 是 fail-visible 占位（无头 / 测试上下文命中即显性
    /// 失败，不猜端值）。
    host_facts: Arc<std::sync::RwLock<Arc<dyn HostFactsPort>>>,
    /// 插件错误状态上报回调（移动装配面，票 02 B5 并入超集）：由
    /// `host_mark_plugin_error` 触发（置 Error + 持久化未启用 + 前端通知）。
    /// 桌面等价物是 `plugin_services.mark_plugin_error`，构造给 noop 缺省。
    pub status_reporter: Arc<dyn Fn(&str, &str) + Send + Sync>,
}

// ==================== 运行中的进程（记录 pid 供进程组 kill） ====================

/// Child 句柄由执行任务（宿主侧 process 域实现，桌面 `src-tauri/src/plugin/process.rs`，
/// 移动 `host_domains/` 内）独占持有：`Child::wait`
/// 在整个进程生命周期内独占 `&mut self`，注册表若同时持句柄，kill 路径
/// 将阻塞到进程自然退出（死锁）；按 pid 杀进程组则与 wait 无冲突。
struct RunningProcess {
    /// 发起执行的插件 ID（完成事件分发目标）
    plugin_id: String,
    /// 子进程 pid（process_group(0)/CREATE_NEW_PROCESS_GROUP 后为进程组组长）
    pid: u32,
}

/// 进程注册表（run_id → 运行中进程）
///
/// 生命周期：`process_run` 注册 → 进程结束/kill 后移除。
/// 应用退出时进程由 OS 回收（孤儿进程随宿主进程终止）。
pub struct ProcessRegistry {
    runs: std::sync::RwLock<HashMap<String, RunningProcess>>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self {
            runs: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// 注册运行中进程（run_id 由调用方预生成，UUID）
    ///
    /// 同步锁：临界区仅 map 操作（无 await），wasm host 调用栈内直接可用
    pub fn register(&self, run_id: String, plugin_id: String, pid: u32) {
        let mut runs = self.runs.write().unwrap_or_else(|e| e.into_inner());
        runs.insert(run_id, RunningProcess { plugin_id, pid });
    }

    /// 移除并返回进程的发起插件 ID（进程结束/kill 后调用）
    pub fn remove(&self, run_id: &str) -> Option<String> {
        let mut runs = self.runs.write().unwrap_or_else(|e| e.into_inner());
        runs.remove(run_id).map(|p| p.plugin_id)
    }

    /// 终止进程组（尽力而为）：找到记录则按 pid 杀进程组，返回是否找到
    pub async fn kill(&self, run_id: &str) -> bool {
        let pid = {
            let runs = self.runs.read().unwrap_or_else(|e| e.into_inner());
            match runs.get(run_id) {
                Some(proc) => proc.pid,
                None => return false,
            }
        };
        kill_process_group(pid).await;
        true
    }

    /// 运行中进程数（并发限制/诊断用）
    pub fn running_count(&self) -> usize {
        let runs = self.runs.read().unwrap_or_else(|e| e.into_inner());
        runs.len()
    }
}

/// 终止进程组（尽力而为，超时 kill 与插件取消共用）
///
/// - unix：`kill -9 -<pgid>`（`process_group(0)` 保证 pgid == pid）
/// - Windows：`taskkill /F /T /PID`（/T 连带子进程树）
///
/// 返回是否成功发起（进程已退出 / pid 无效返回 false，属预期内竞态）。
///
/// **pub（票 02 批次 05）**：host-process 域函数随域迁宿主
/// （`src-tauri/src/plugin/process.rs`）后经本公开面复用同一条终止路径——
/// 两份实现会让「杀整组」的语义漂移（与 `check_permission` 提公开同款理由）。
pub async fn kill_process_group(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        let mut cmd = tokio::process::Command::new("taskkill");
        cmd.args(["/F", "/T", "/PID", &pid.to_string()]);
        // CREATE_NO_WINDOW：taskkill 为控制台程序，避免超时杀进程时黑窗闪烁
        cmd.creation_flags(0x0800_0000);
        match cmd.output().await {
            Ok(o) if o.status.success() => true,
            Ok(o) => {
                tracing::warn!(
                    pid,
                    output = %String::from_utf8_lossy(&o.stderr),
                    "kill_process_group: taskkill reported failure"
                );
                false
            }
            Err(e) => {
                tracing::warn!(pid, error = %e, "kill_process_group: taskkill failed");
                false
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // 直接系统调用杀进程组（负 pgid = 组；process_group(0) 后组 id == 进程 pid）。
        // 不使用外部 kill 命令：命令进程是第二个 tokio child，在
        // current_thread（sh 的 wait）与 ambient multi_thread（kill 命令）双 runtime
        // 共享全局 SIGCHLD handler 的场景下，kill 命令退出与目标被杀同时发生时，
        // 两个 reaper 竞争 waitpid(-1) 回收 zombie，可能吞掉 sh 的退出通知导致
        // wait() 永久挂起（CI flaky：process_kill_terminates_process_group）。
        // 同步系统调用不产生 child，从根上消除该竞争。
        let rc = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        if rc == 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            pid,
            error = %err,
            "kill_process_group: kill(-pid) failed"
        );
        false
    }
}

impl WasmHostContext {
    /// 创建宿主上下文
    ///
    /// `app_handle` 为 None 时（无头/测试上下文）emit、数据目录等能力不可用。
    /// 第 8 参 `capabilities`（票 04 DIP 注入）：宿主上下文持 trait 对象，不依赖
    /// manager 具体注册表；重构为 Builder 留后续票。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<Mutex<Database>>,
        plugin_dbs: Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>>,
        storage: Arc<PluginStorage>,
        app_handle: Option<Arc<tauri::AppHandle>>,
        permission: Arc<PermissionManager>,
        fs_auth: Arc<FsAuthChecker>,
        message_bus: Arc<crate::bus::MessageBus>,
        capabilities: Arc<dyn CapabilityProvider>,
    ) -> Self {
        let api_registry = Arc::new(crate::security::api_registry::ApiRegistry::new());
        // 网络出站授权（票 05）：与 fs_auth 同形态——主库句柄 + AppHandle，
        // app_handle 需先 clone 再 move 进本结构
        let net_auth = Arc::new(NetworkAuthChecker::new(db.clone(), app_handle.clone()));
        // 统一授权框架：注册既有资源的仲裁器（fs 三层校验 / api-call 互调门）
        let security = Arc::new(crate::security::SecurityFramework::new());
        security.register(Arc::new(crate::security::framework::FsAuthorizer::new(
            permission.clone(),
            fs_auth.clone(),
        )));
        security.register(Arc::new(crate::security::framework::ApiCallAuthorizer::new(
            api_registry.clone(),
        )));
        Self {
            db,
            plugin_dbs,
            storage,
            secrets_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            app_handle,
            permission,
            fs_auth,
            net_auth,
            message_bus,
            plugin_services: Arc::new(RwLock::new(None)),
            task_engine: Arc::new(RwLock::new(None)),
            process_registry: Arc::new(ProcessRegistry::new()),
            api_registry,
            security,
            capabilities,
            // 私有库根目录覆盖：生产 None（走 app_handle 的 app_data_dir），
            // 无头测试在构造后经 `set_plugin_db_root` 注入（见 setup_wasm_runtime）
            plugin_db_root: Arc::new(std::sync::RwLock::new(None)),
            // 能力域端口表：构造时为空，由持有 `Arc<WasmHostContext>` 的装配点注入
            domain_ports: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            // 对等网络上下文装配端口：两阶段注入（PluginHost::new 写入），构造时 None
            peer_ctx_provider: Arc::new(std::sync::RwLock::new(None)),
            // 移动装配面三字段缺省（ports 命中即 fail-visible / granted 恒空 /
            // status_reporter noop）
            ports: Arc::new(UnimplementedPorts),
            // 选择器缺省 fail-visible（桌面在 `PluginHost::new` 注入宿主实现）
            platform_picker: Arc::new(std::sync::RwLock::new(Arc::new(UnimplementedPlatformPicker))),
            // 端事实缺省：未注入即 fail-visible（`set_host_facts` 装配期覆盖）
            host_facts: Arc::new(std::sync::RwLock::new(Arc::new(UnimplementedHostFacts))),
            status_reporter: Arc::new(|_, _| {}),
        }
    }

    /// 移动装配构造器（票 02 B5）：桌面全字段给缺省 + 注入移动需要面。
    ///
    /// 用户裁决 2026-10-11「wasm-core 机制全部以桌面为准收敛一套」：`fs_auth`
    /// 与桌面同型 `Arc<FsAuthChecker>`（移动不再自持闸门实现，白名单管理命令随
    /// 移动实现退役——路径白名单 / 插件白名单语义不进入统一机制）；`permission` /
    /// `capabilities` 给空缺省（权限判定走内核 `PermissionManager`、由激活路径授予，
    /// 能力路由无消费方；逐实例 `for_plugin` 派生已退役——调用方直接 `Arc::clone`
    /// 共享上下文）。    ///
    /// 平台选择器**从 `ports` 派生**（[`EnginePortsPlatformPicker`]）：移动的 SAF
    /// 选择器端口与引擎端口同住 `plugin/host_ports.rs`，本构造器把两者一次接线；
    /// 端口未装配时推选即 `port_err` fail-visible（与 `new_headless` 同口径）。
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ports(
        db: Arc<Mutex<Database>>,
        storage: Arc<PluginStorage>,
        app_handle: Option<Arc<tauri::AppHandle>>,
        fs_auth: Arc<FsAuthChecker>,
        message_bus: Arc<crate::bus::MessageBus>,
        status_reporter: Arc<dyn Fn(&str, &str) + Send + Sync>,
        ports: Arc<dyn HostEnginePorts>,
    ) -> Self {
        let net_auth = Arc::new(NetworkAuthChecker::new(db.clone(), app_handle.clone()));
        // 选择器从引擎端口派生（SAF 端口是选择器的移动实现）——适配器只接线，
        // 能力判断仍在端口方法内（未装配的端口推选即 fail-visible）。
        // AppHandle 在此一并捕获：`pick_files` 需要它，字段随后被移进上下文。
        let platform_picker: Arc<dyn PlatformPickerPort> = Arc::new(EnginePortsPlatformPicker::new(
            ports.clone(),
            app_handle.clone(),
        ));
        // 统一授权框架：**必须注册仲裁器**——`Framework::authorize` 对未注册资源
        // 直接 `Deny`（fail-closed），未注册即有 fs 原语全被拒的静默断链（
        // `host_api::fs` 的每条原语都经 `authorize_fs` 走本框架）。本构造器是
        // 移动装配面（生产 `PluginManager::init_wasm_runtime` 与 `new_headless`
        // 都经它），托盘 = `WasmHostContext::new`（桌面装配面）——两处注册同一批
        // 仲裁器，漏一处就是端间行为分叉。
        let permission = Arc::new(crate::permission::PermissionManager::new());
        let api_registry = Arc::new(crate::security::api_registry::ApiRegistry::new());
        let security = Arc::new(crate::security::SecurityFramework::new());
        security.register(Arc::new(crate::security::framework::FsAuthorizer::new(
            permission.clone(),
            fs_auth.clone(),
        )));
        security.register(Arc::new(crate::security::framework::ApiCallAuthorizer::new(
            api_registry.clone(),
        )));
        Self {
            db,
            plugin_dbs: Arc::new(Mutex::new(HashMap::new())),
            storage,
            secrets_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            app_handle,
            plugin_db_root: Arc::new(std::sync::RwLock::new(None)),
            permission,
            fs_auth,
            net_auth,
            message_bus,
            plugin_services: Arc::new(RwLock::new(None)),
            task_engine: Arc::new(RwLock::new(None)),
            process_registry: Arc::new(ProcessRegistry::new()),
            api_registry,
            security,
            capabilities: Arc::new(NoopCapabilityProvider),
            domain_ports: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            peer_ctx_provider: Arc::new(std::sync::RwLock::new(None)),
            ports,
            platform_picker: Arc::new(std::sync::RwLock::new(platform_picker)),
            // 端事实缺省：移动/桌面宿主装配后经 `set_host_facts` 注入本端实现
            host_facts: Arc::new(std::sync::RwLock::new(Arc::new(UnimplementedHostFacts))),
            status_reporter,
        }
    }

    /// 无头构造（移动测试夹具）：端口取 [`UnimplementedPorts`] 占位——
    /// 无头上下文命中引擎调用一律 fail-visible 拒绝
    pub fn new_headless(
        db: Arc<Mutex<Database>>,
        storage: Arc<PluginStorage>,
        app_handle: Option<Arc<tauri::AppHandle>>,
        fs_auth: Arc<FsAuthChecker>,
        message_bus: Arc<crate::bus::MessageBus>,
        status_reporter: Arc<dyn Fn(&str, &str) + Send + Sync>,
    ) -> Self {
        Self::new_with_ports(db, storage, app_handle, fs_auth, message_bus, status_reporter, Arc::new(UnimplementedPorts))
    }

    /// 为某能力域装配**实例级**端口（生产与无头测试共用此入口）
    ///
    /// 端口对象应是 `Arc<dyn 该域的端口 trait>`（擦除成 `Arc<dyn Any + Send + Sync>`
    /// 存表，能力域侧经 `downcast_domain_ports` 还原）。幂等：重复装配同一域时
    /// **后写覆盖**（与 `set_plugin_db_root` 同风格）——装配点只有一个，
    /// 重复调用是同形重放而非并存两套。
    pub fn set_domain_ports(&self, domain: &str, ports: Arc<dyn std::any::Any + Send + Sync>) {
        self.domain_ports
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(domain.to_string(), ports);
    }

    /// 插件私有库根目录覆盖：生产为 `None`（走 `app_handle` 的
    /// `app_data_dir()/plugins/<plugin_id>`）；无头/集成测试无 AppHandle
    /// （tao 事件循环不允许测试线程建 AppHandle），激活会话中心等插件前经此
    /// 注入临时根目录以获得真实私有库——认证记录下沉（v24）后配对/历史真源
    /// 在插件私有库，无私有库的无头上下文无法驱动认证链路。
    pub fn set_plugin_db_root(&self, root: Option<PathBuf>) {
        *self.plugin_db_root.write().unwrap_or_else(|e| e.into_inner()) = root;
    }

    /// 为插件授予权限（宿主激活路径入口；与桌面 `PluginHost::activate_plugin`
    /// 的 `PermissionManager::grant_permissions` 同一实现）
    ///
    /// pub（wasm-core 纯净性收口票 05b）：lib 集成测试（session_e2e）经此装配
    /// 权限——薄转发 `PermissionManager`（真源在 wasm-core `permission` 模块），
    /// 机制本体不变，`permission` 字段保持 pub(crate)。
    ///
    /// **双端唯一真源（2026-10-14）**：桌面与移动的权限面都只落本管理器；
    /// 移动宿主不再自持 `granted_permissions` 镜像/副本（已删）。
    pub fn grant_permissions(
        &self,
        plugin_id: &str,
        requested: &[String],
    ) -> std::collections::HashSet<String> {
        self.permission.grant_permissions(plugin_id, requested)
    }

    /// 插件是否持有指定权限（宿主侧重判定统一入口）
    ///
    /// 双端同源：桌面 `host_api::check_permission`、移动宿主 adapter
    /// （`plugin/bindings.rs` 与各 `host_domains` 端口）均经此判定。
    pub fn has_permission(&self, plugin_id: &str, permission: &str) -> bool {
        self.permission.check(plugin_id, permission)
    }

    /// 插件当前生效权限集快照（端口构造用；与 [`Self::has_permission`] 同源）
    pub fn granted_permissions(&self, plugin_id: &str) -> std::collections::HashSet<String> {
        self.permission.get_granted(plugin_id)
    }

    /// 撤销插件全部权限（停用路径；与桌面 `PluginHost::deactivate_plugin` 的
    /// `revoke_all` 同一实现）
    pub fn revoke_permissions(&self, plugin_id: &str) {
        self.permission.revoke_all(plugin_id)
    }

    /// 读取插件私有库根目录覆盖（None = 走 app_handle 派生）
    fn plugin_db_root_opt(&self) -> Option<PathBuf> {
        self.plugin_db_root
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// 文件系统访问校验器（三层判定链单一实现，双端共用同一实例类型，见字段文档）
    pub fn fs_auth(&self) -> &Arc<FsAuthChecker> {
        &self.fs_auth
    }

    /// 同 [`Self::fs_auth`]，供机制消费面（fs 单元预检 / WASI 预打开过滤 / 宿主
    /// `plugin/{fs,platform}.rs`）按名取具体闸门
    ///
    /// 单一实例类型收敛后不再有「下转型可能失败」的情形，故返回具体值而非
    /// `Option`——恒真的 `Option` 会把断链风险藏进 `.expect()` 的 panic 里。
    pub fn fs_auth_checker(&self) -> Arc<FsAuthChecker> {
        self.fs_auth.clone()
    }

    /// 网络出站授权校验器（票 05：host-http 出站面 / 应答命令的 Tauri State）
    pub fn net_auth(&self) -> &Arc<NetworkAuthChecker> {
        &self.net_auth
    }

    /// 权限管理器（core-task 单元预检读声明闸门用，见 `manager::task`）
    pub(crate) fn permission(&self) -> &Arc<crate::permission::PermissionManager> {
        &self.permission
    }

    /// 宿主引擎端口（`host-config` 端专属项的取数通道，票 03）
    ///
    /// 机制面常编译化后，`config_get` 这类**双端全等 interface** 的实现体不能再引
    /// 某端 SDK 类型，只能经端口取本端事实（网络端口 / 下载目录等）；端口未注入的
    /// 键在域内 fail-visible 报错。
    ///
    pub fn ports(&self) -> &Arc<dyn crate::host_api::ports::HostEnginePorts> {
        &self.ports
    }

    /// 取平台选择器端口（core 交集 `host-platform.pick-*` 的端实现）
    ///
    /// 消费方是 `manager::runtime::core_binding` 的 host-platform 绑定。
    /// 返回 clone 的 `Arc`（槽位见字段注释：桌面经 `set_platform_picker` 两阶段注入，
    /// 与 [`Self::host_facts`] 同款）。
    pub fn platform_picker(&self) -> Arc<dyn PlatformPickerPort> {
        self.platform_picker
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 装配期注入宿主平台选择器（桌面端；移动经 `new_with_ports` 自动派生）
    ///
    /// 与 [`Self::set_host_facts`] 同款两阶段注入：`PluginHost::new` 在实例化 /
    /// 激活**之前**写入——插件激活期的选择器调用（如果有）也必须拿到宿主实现，
    /// 不能只在运行期可用。宿主实现住 `plugin/platform_picker.rs`。
    pub fn set_platform_picker(&self, picker: Arc<dyn PlatformPickerPort>) {
        *self.platform_picker.write().unwrap_or_else(|e| e.into_inner()) = picker;
    }

    /// 装配期注入宿主端事实（平台标识 / 入站服务器端口）
    ///
    /// **必须在任何插件 `activate()` 之前调用**（与 [`Self::set_peer_ctx_provider`]
    /// 同款两阶段注入）：共享产物（file-transfer 单产物）在激活期经
    /// `host-platform.platform()` 探测端值，漏注入 = 激活失败（fail-visible，
    /// 不静默降级成某一端）。端实现住各端宿主（桌面
    /// `plugin/host_facts.rs` / 移动 `plugin/host_ports.rs`），内核零端名。
    pub fn set_host_facts(&self, facts: Arc<dyn HostFactsPort>) {
        *self.host_facts.write().unwrap_or_else(|e| e.into_inner()) = facts;
    }

    /// 取宿主端事实（缺省 [`UnimplementedHostFacts`]；热路径只 clone 一个 Arc）
    pub fn host_facts(&self) -> Arc<dyn HostFactsPort> {
        self.host_facts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn process_registry(&self) -> &Arc<ProcessRegistry> {
        &self.process_registry
    }

    /// 获取主库句柄（宿主侧读写内核表的入口）
    ///
    /// 生产路径经宿主侧各域函数访问（权限门 + 属主校验在域函数内）；
    /// 本访问器供宿主装配/测试直接读写内核真源（如 `pairings` 表播种与断言，
    /// 见 `host::tests::test_server_auth_policy_closed_loop`）。
    pub(crate) fn database(&self) -> &Arc<Mutex<Database>> {
        &self.db
    }

    /// 两阶段初始化：PluginHost 构造完成后注入宿主服务
    ///
    /// 必须在 PluginHost::new() 返回后、任何插件 activate 之前调用
    pub async fn set_services(&self, services: Arc<dyn PluginServices>) {
        *self.plugin_services.write().await = Some(services);
    }

    /// 获取宿主服务引用
    ///
    /// 在两阶段初始化完成前返回 None
    pub async fn services(&self) -> Option<Arc<dyn PluginServices>> {
        self.plugin_services.read().await.clone()
    }

    /// 两阶段初始化：PluginHost 构造完成后注入 host-task 执行引擎（core-task）
    ///
    /// 与 [`Self::set_services`] 同构：必须在任何插件 activate 之前调用，
    /// 否则 `host-task` 入口报「engine not available」fail-visible
    pub async fn set_task_engine(&self, engine: Arc<dyn TaskEngine>) {
        *self.task_engine.write().await = Some(engine);
    }

    /// 获取 host-task 执行引擎引用（注入完成前返回 None）
    pub async fn task_engine(&self) -> Option<Arc<dyn TaskEngine>> {
        self.task_engine.read().await.clone()
    }

    /// 获取消息总线引用
    pub fn message_bus(&self) -> &Arc<crate::bus::MessageBus> {
        &self.message_bus
    }

    /// 两阶段注入：`PluginHost::new` 构造后写入对等网络上下文装配端口
    /// （整核抽出 §3.3 唯一端口）。无头/测试传 `None` → `HEADLESS_UNAVAILABLE`
    /// 语义不变；重复写入覆盖（无头测试可在用例内替换提供者）。
    pub fn set_peer_ctx_provider(&self, provider: Option<Arc<PeerCtxProvider>>) {
        *self.peer_ctx_provider.write().unwrap_or_else(|e| e.into_inner()) = provider;
    }

    /// 取对等网络上下文装配端口（注入完成前返回 None）
    pub fn peer_ctx_provider(&self) -> Option<Arc<PeerCtxProvider>> {
        self.peer_ctx_provider
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 获取插件互调 api 注册表引用（ADR-0017 门禁）
    pub fn api_registry(&self) -> &Arc<crate::security::api_registry::ApiRegistry> {
        &self.api_registry
    }

    /// 获取统一授权框架引用（core-security 三段决策管线）
    /// 统一授权框架（core-security）：三段决策管线 + 仲裁器注册表
    ///
    /// 票 02 B5：字段改 `Arc<SecurityFramework>`（宿主上下文共享同一注册表；
    /// 历史逐实例派生 `for_plugin` 已于 2026-10-14 删），
    /// 访问器返回值不变（`Arc::as_ref` 解引用）。
    pub fn security(&self) -> &crate::security::SecurityFramework {
        self.security.as_ref()
    }

    /// 宿主侧互调调用（票 11 命令面桥接）：以宿主虚拟身份发布 JSON-RPC 请求到
    /// `wasmnest.api.<api>` topic 并等待回复。
    ///
    /// 与插件 mutual 调用的区别：调用方身份为
    /// [`crate::host_api::api::HOST_API_CALLER_ID`]
    /// （宿主不是插件，reply topic 路由 `wasmnest.api.reply.<caller>.<id>` 用）；
    /// 互调门禁（ADR 0017 层 1）只校验目标 api 已声明、不校验调用方——未激活
    /// 插件在注册表无登记 → 门禁拒绝 → 调用方降级宿主实现。
    ///
    /// **桌面装配面门控（`desktop-assembly`，票 02 B5 保留）**：`host_api::api`
    /// （回复道编排）是桌面 WIT 绑定域，随 T-03/04 迁宿主前保持桌面装配面门控——
    /// 单形态（2026-10-13）起统一上下文常编译，但本方法随 `desktop-assembly`
    /// （桌面专属装配面，移动不开——移动互调经宿主侧
    /// `移动宿主 src-tauri/src/plugin/host_domains/` 域实现，不经本入口）。
    #[cfg(feature = "desktop-assembly")]
    pub fn call_plugin_api_host(
        &self,
        request_topic: &str,
        payload_json: &str,
        timeout_ms: u64,
    ) -> Result<String, String> {
        crate::host_api::api::api_call(
            self,
            self,
            self,
            crate::host_api::api::HOST_API_CALLER_ID,
            request_topic,
            payload_json,
            timeout_ms,
        )
    }

    /// 获取能力注册表引用（core-plugin-manager：系统组件装配与能力路由）
    pub fn capabilities(&self) -> &Arc<dyn CapabilityProvider> {
        &self.capabilities
    }

    /// 丢弃插件独立数据库连接（卸载时调用，dev 合入的卸载完整性）
    ///
    /// 仅从连接池移除（不删库文件）：删除插件目录前须先释放文件句柄，
    /// 否则在部分平台（Windows）会因文件仍被占用而删不掉
    pub async fn drop_plugin_db(&self, plugin_id: &str) {
        let dropped = self.plugin_dbs.lock().expect("plugin dbs lock poisoned").remove(plugin_id).is_some();
        if dropped {
            tracing::debug!(plugin_id = %plugin_id, "Plugin database connection dropped");
        }
    }

    /// 应用句柄引用；无头 / 测试上下文为 None
    ///
    /// 存在的理由（审计票 12）：`app_handle` 字段是模块私有的，而 peer-net 节点的
    /// **属主清理钩子**在 `manager/host/activation.rs`——那里不是本模块的后代，读不到
    /// 字段。此前那条路走 `AppContext::try_global()`，但 boot 装配期全局尚未注册，
    /// 「插件在 activate 里起了节点、随后激活失败」这个窗口就拿不到句柄去收，
    /// 所以直接从上下文字段取（它在 `PluginHost::new` 之前就已就位）
    ///
    /// **常编译 pub（票 02 批次 03 起）**：宿主侧 adapter（`src/plugin/mdns.rs`
    /// 的 `local_node_id`——取对等网络上下文比对自播）经本访问器读句柄；同批次
    /// adapter 侧唯一的上下文句柄来源（旧 `host_context_registry` 已删除，见 `lib.rs`）。
    pub fn app_handle(&self) -> Option<&tauri::AppHandle> {
        self.app_handle.as_deref()
    }

    /// 获取或懒加载插件独立数据库
    ///
    /// 首次调用时创建目录 + 打开/创建 plugin.db + 缓存连接
    /// 后续调用直接返回缓存的连接
    pub async fn get_or_create_plugin_db(&self, plugin_id: &str) -> crate::Result<Arc<Mutex<Database>>> {
        // 快速路径：已缓存
        {
            let dbs = self.plugin_dbs.lock().expect("plugin dbs lock poisoned");
            if let Some(db) = dbs.get(plugin_id) {
                return Ok(db.clone());
            }
        }

        // 慢路径：创建数据库。数据目录来源二选一（`aot_cache_dir` 同模式）：
        // - 生产：`app_handle` 派生 `app_data_dir()/plugins/<plugin_id>`
        // - 无头测试：`plugin_db_root` 注入（tao 事件循环不允许在测试线程建
        //   AppHandle，故无头上下文必须显式给根目录才能测插件私有库）
        let plugin_dir = match (&self.app_handle, self.plugin_db_root_opt()) {
            (Some(app_handle), _) => {
                let app_data_dir = app_handle
                    .path()
                    .app_data_dir()
                    .map_err(|e| crate::AppError::Plugin(format!("Failed to get app data dir: {}", e)))?;
                app_data_dir.join("plugins").join(plugin_id)
            }
            (None, Some(root)) => root.join(plugin_id),
            (None, None) => {
                return Err(crate::AppError::Plugin(
                    "plugin database unavailable in headless context (no app_handle)".to_string(),
                ))
            }
        };

        // 创建插件数据目录
        if !plugin_dir.exists() {
            std::fs::create_dir_all(&plugin_dir).map_err(|e| {
                crate::AppError::Plugin(format!(
                    "Failed to create plugin data dir '{}': {}",
                    plugin_dir.display(),
                    e
                ))
            })?;
        }

        let db_path = plugin_dir.join("plugin.db");
        let db = Database::new(&db_path)?;

        // 缓存连接
        let db_arc = Arc::new(Mutex::new(db));
        {
            let mut dbs = self.plugin_dbs.lock().expect("plugin dbs lock poisoned");
            // 双重检查：另一个线程可能已插入
            if let Some(existing) = dbs.get(plugin_id) {
                return Ok(existing.clone());
            }
            dbs.insert(plugin_id.to_string(), db_arc.clone());
        }

        tracing::info!(plugin_id = %plugin_id, path = %db_path.display(), "Plugin database created/opened");
        Ok(db_arc)
    }
}

// ==================== 角色接口（ISP，票 05 接口隔离） ====================
// 域函数签名只收自己消费的窄角色视图（`&dyn XxxScope`），不再人手一个
// `&WasmHostContext` 上帝对象；`WasmHostContext` 实现全部角色接口，调用点
// `ctx.as_ref()`（&WasmHostContext）自动 unsize coerce 到任一 `&dyn` 角色。
// trait upcasting（1.86+）下域内互调满足被调者 scope 需求即可。

/// 主库 / 插件独立库访问视图
pub trait DbScope: Send + Sync {
    /// 主库句柄（宿主侧读写内核真源；域函数内访问经权限门 + 属主校验）
    fn database(&self) -> &Arc<Mutex<Database>>;
    /// 插件独立库连接池
    fn plugin_dbs(&self) -> &Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>>;
    /// 获取或懒加载插件独立数据库（无头上下文须先注入 plugin_db_root，否则报错）。
    /// async 方法经 Pin<Box<dyn Future>> 返回（async-fn-in-trait 在 1.98 仍非 dyn
    /// 兼容，返回 boxed future 保持 trait object 化，票 05）
    fn get_or_create_plugin_db<'a>(
        &'a self,
        plugin_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = crate::Result<Arc<Mutex<Database>>>> + Send + 'a>>;
}

/// 权限仲裁视图（`check_permission` 经此取 PermissionManager）
pub trait PermissionScope: Send + Sync {
    /// 权限管理器（SDK VALID_PERMISSIONS 授权面）
    fn permission(&self) -> &Arc<crate::permission::PermissionManager>;
}

/// 插件存储视图（StorageScope，票 03 中立层）
pub trait StorageScope: Send + Sync {
    /// 插件持久化存储（SQLite plugin_storage 表）
    fn storage(&self) -> &Arc<crate::storage::PluginStorage>;
}

/// 文件系统访问校验视图
pub trait FsAuthScope: Send + Sync {
    /// 三层 fs 校验器（已授权路径判据，绝不从池线程触发弹窗）
    fn fs_auth(&self) -> &Arc<FsAuthChecker>;

    /// 取具体闸门实例（机制方法消费面用）
    ///
    /// 默认实现克隆 `fs_auth()`——槽已收敛为单一具体类型，无下转型可言；本方法
    /// 让**窄接口消费方**（只拿得到 `&dyn FsAuthScope` 的域函数与宿主 adapter）
    /// 也能触达机制方法，而不必把整个上下文类型拖进签名。
    fn fs_auth_checker(&self) -> Arc<FsAuthChecker> {
        self.fs_auth().clone()
    }
}

/// 网络出站授权视图（票 05：`host-http.fetch` 的出站判定面）
pub trait NetworkAuthScope: Send + Sync {
    /// 出站授权校验器（`authorize_outbound` 弹窗面 / `is_granted` 无询问面）
    fn net_auth(&self) -> &Arc<crate::security::network_auth::NetworkAuthChecker>;
}

/// 消息总线视图
pub trait BusScope: Send + Sync {
    /// 内核消息总线（发布/订阅/事件广播）
    fn message_bus(&self) -> &Arc<crate::bus::MessageBus>;
}

/// Tauri AppHandle 视图（无头 / 测试上下文为 None，emit/路径类能力降级）
pub trait AppHandleScope: Send + Sync {
    /// 应用句柄；无头上下文 None
    fn app_handle(&self) -> Option<&tauri::AppHandle>;
}

/// 本上下文是机制内核的宿主能力端口实现（wasm-core-lib-split 票 03）
///
/// `WasmPluginState` 住在 `wasmnest-host-kit`，它的 `host` 字段是
/// `Arc<dyn HostPorts>`——kit 不能认识本类型，否则整个宿主（tauri / 数据库 /
/// 授权闸门）会被拖进机制内核。双向各走一条路：
///
/// - **kit → 宿主**：下面这个 impl（能力 crate 经 `Arc<dyn HostPorts>` 拿到的就是本类型）
/// - **宿主 → 具体类型**：[`HostCtxOf`] 扩展 trait 的向下转型
///
/// 新增能力域时**不要**在这里堆方法——迁出的能力域按 `wasmnest-server-base::ports`
/// 先例自声明窄端口 trait，宿主在 adapter 层实现它们。
impl wasmnest_host_kit::ports::HostPorts for WasmHostContext {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    /// 实例级能力域端口下发（票 04；未装配该域 ⇒ `None`，由能力域按自己的兜底口径处理）
    fn domain_ports(&self, domain: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        self.domain_ports
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(domain)
            .cloned()
    }
}

/// 从插件实例状态取回宿主上下文（core 域接口的向下转型出口）
///
/// 只给**留在宿主的** `impl … Host for WasmPluginState` 用（它们本来就住在
/// 宿主 crate 内，能直接指名 `WasmHostContext`）；迁出的能力域不碰本 trait，
/// 它们消费的是各自 crate 声明的窄端口。类型不符时 panic 并带出期望/实际类型名
/// （fail-visible：装配期编程错误，不静默降级为「拿不到宿主能力」）。
pub(crate) trait HostCtxOf {
    /// 宿主上下文引用
    fn host_ctx(&self) -> &WasmHostContext;
}

impl HostCtxOf for WasmPluginState {
    fn host_ctx(&self) -> &WasmHostContext {
        wasmnest_host_kit::ports::downcast_host(&*self.host)
    }
}

/// 插件宿主服务视图（两阶段注入的 PluginServices trait 对象）
pub trait ServicesScope: Send + Sync {
    /// 宿主服务引用（两阶段初始化完成前返回 None；async：内部 async RwLock；
    /// Pin<Box<dyn Future>> 返回保持 dyn 兼容，票 05）
    fn services<'a>(
        &'a self,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Option<Arc<dyn crate::host_api::context::PluginServices>>>
                + Send
                + 'a,
        >,
    >;
}

/// 进程注册表视图（host-process，v8）
pub trait ProcessScope: Send + Sync {
    /// 运行中进程注册表（run_id → 进程句柄）
    fn process_registry(&self) -> &Arc<crate::host_api::context::ProcessRegistry>;
}

/// 插件互调 api 注册表视图（ADR-0017 门禁）
pub trait ApiRegistryScope: Send + Sync {
    /// 激活登记 / 停用注销的 api 注册表
    fn api_registry(&self) -> &Arc<crate::security::api_registry::ApiRegistry>;
}

/// 统一授权框架视图（core-security 三段决策管线）
pub trait SecurityScope: Send + Sync {
    /// 授权框架（authorize 决策 + 仲裁器注册表 + monitor 埋点）
    fn security(&self) -> &crate::security::SecurityFramework;
}

/// 能力路由视图（票 04 trait 化端口，host_api 只经 &dyn 消费）
pub trait CapabilityScope: Send + Sync {
    /// 能力查询/路由端口
    fn capabilities(&self) -> &Arc<dyn CapabilityProvider>;
}

/// 密钥托管读缓存视图（v15 host-auth；set/delete 失效对应键）
pub trait SecretsScope: Send + Sync {
    /// read-through 缓存（真源为主库 plugin_secrets 表）
    fn secrets_cache(&self) -> &Arc<std::sync::RwLock<std::collections::HashMap<(String, String), String>>>;
}

// ==================== WasmHostContext 角色接口实现 ====================

impl DbScope for WasmHostContext {
    fn database(&self) -> &Arc<Mutex<Database>> {
        self.database()
    }
    fn plugin_dbs(&self) -> &Arc<Mutex<HashMap<String, Arc<Mutex<Database>>>>> {
        &self.plugin_dbs
    }
    fn get_or_create_plugin_db<'a>(
        &'a self,
        plugin_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = crate::Result<Arc<Mutex<Database>>>> + Send + 'a>> {
        Box::pin(self.get_or_create_plugin_db(plugin_id))
    }
}

impl PermissionScope for WasmHostContext {
    fn permission(&self) -> &Arc<crate::permission::PermissionManager> {
        self.permission()
    }
}

impl StorageScope for WasmHostContext {
    fn storage(&self) -> &Arc<crate::storage::PluginStorage> {
        &self.storage
    }
}

impl FsAuthScope for WasmHostContext {
    fn fs_auth(&self) -> &Arc<FsAuthChecker> {
        &self.fs_auth
    }
}

impl NetworkAuthScope for WasmHostContext {
    fn net_auth(&self) -> &Arc<crate::security::network_auth::NetworkAuthChecker> {
        self.net_auth()
    }
}

impl BusScope for WasmHostContext {
    fn message_bus(&self) -> &Arc<crate::bus::MessageBus> {
        self.message_bus()
    }
}

impl AppHandleScope for WasmHostContext {
    fn app_handle(&self) -> Option<&tauri::AppHandle> {
        self.app_handle()
    }
}

impl ServicesScope for WasmHostContext {
    fn services<'a>(
        &'a self,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Option<Arc<dyn crate::host_api::context::PluginServices>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(self.services())
    }
}

impl ProcessScope for WasmHostContext {
    fn process_registry(&self) -> &Arc<crate::host_api::context::ProcessRegistry> {
        self.process_registry()
    }
}

impl ApiRegistryScope for WasmHostContext {
    fn api_registry(&self) -> &Arc<crate::security::api_registry::ApiRegistry> {
        self.api_registry()
    }
}

impl SecurityScope for WasmHostContext {
    fn security(&self) -> &crate::security::SecurityFramework {
        self.security()
    }
}

impl CapabilityScope for WasmHostContext {
    fn capabilities(&self) -> &Arc<dyn CapabilityProvider> {
        self.capabilities()
    }
}

impl SecretsScope for WasmHostContext {
    fn secrets_cache(&self) -> &Arc<std::sync::RwLock<std::collections::HashMap<(String, String), String>>> {
        &self.secrets_cache
    }
}

/// 能力注册表缺失占位（移动 `new_with_ports` 缺省注入）——所有路由方法
/// fail-visible 拒绝（移动形态无能力路由消费方；若新增消费点须停下评估归属）。
pub(crate) struct NoopCapabilityProvider;

impl CapabilityProvider for NoopCapabilityProvider {
    fn is_available(&self, _name: &str) -> bool {
        false
    }
    fn missing(&self, dependencies: &[String]) -> Vec<String> {
        dependencies.to_vec()
    }
    fn register_system_component(
        &self,
        _name: &str,
        _plugin_id: &str,
        _target: Arc<dyn CapabilityTarget>,
    ) -> crate::Result<()> {
        Err(crate::AppError::Internal(
            "capability registry not wired in mobile headless context".to_string(),
        ))
    }
    fn revert_to_host(&self, _name: &str, _plugin_id: &str) {}
    fn revert_all_from(&self, _plugin_id: &str) {}
    fn system_component_instance(
        &self,
        _name: &str,
        _caller_plugin_id: &str,
    ) -> Option<(String, Arc<dyn CapabilityTarget>)> {
        None
    }
    fn provider_kind(&self, _name: &str) -> String {
        "noop".to_string()
    }
}
