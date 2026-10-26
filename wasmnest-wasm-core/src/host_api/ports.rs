//! 宿主引擎端口（批次 2 · 票 17 §6.2）——插件机制面与宿主引擎的唯一桥
//!
//! 运行时与 16 域迁入本 crate 后，所有「离宿主无法实现」的引擎调用不再直引
//! 宿主符号（`crate::state::get_auth_manager` / `crate::peer_net::*` /
//! `crate::egress::policy` / android_plugins 桥……），一律经本端口注入。
//!
//! **票 02 B5 起常编译（双端共享）**：统一 `WasmHostContext` 把 `ports` 槽并入
//! 超集后，本模块不再是移动 adapter 专属——桌面形态也编译（其上下文给
//! `UnimplementedPorts` 占位，桌面引擎调用不经过端口）。`FsAuthGate` 的
//! `Any` 超 trait 是下转型访问器（`WasmHostContext::fs_auth_checker`）的类型
//! 凭据：桌面把具体 `FsAuthChecker` 注入为 trait 对象后，具体方法消费面经
//! downcast 取回同一实例（移动宿主注入自己的闸门实现，无此需求）。
//!
//! - **引擎资产留宿主**：auth 引擎（C4 凭据）、egress 安全闸门（D5）、连接
//!   管理器、peer 四模块、mDNS 共享守护、WS 重连状态机、Android 平台桥
//!   （android_plugins / SAF）——端口只声明调用形状，实现由宿主装配
//!   （宿主 `plugin/host_ports.rs`）。
//! - **平台选择器独立窄端口**：[`PlatformPickerPort`]（`host-platform.pick-*` 的
//!   端实现）不并入本 trait——桌面宿主没有 `HostEnginePorts` 整体实现（见该
//!   trait 文档），两端按需各接一条。
//! - **机制随 crate**：句柄表、属主仲裁、权限门、事件定向投递——域文件内，
//!   不经端口。
//! - **DTO 以原始值 / JSON 过界**：宿主侧类型（DialEndpoint、RemotePullFileDto、
//!   ConsentRequest…）不出宿主，域内只传原始值或 JSON 串，反序列化责任在
//!   端口实现方——契约形状与 WIT 边界一致（JSON 字符串过界先例）。
//!
//! 无头 / 测试上下文用 [`UnimplementedPorts`]（fail-visible：所有方法返回
//! 显性错误或空值，禁 panic）。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::Result;

// ==================== 子 trait：引擎对象面 ====================

/// 设备入场认证引擎面（C4：密码学与凭据留宿主，域内只投影调用结果）
///
/// 形状对齐宿主 `auth::manager::AuthManager` 的插件消费面五方法；
/// `get_credentials` 只投影存在性（凭据零过境）。
#[async_trait]
pub trait AuthEnginePort: Send + Sync {
    async fn request_pairing(&self) -> Result<()>;
    async fn verify_pairing_code(&self, code: &str) -> Result<bool>;
    async fn authenticate_with_qr(&self, token: &str) -> Result<bool>;
    async fn authenticate_with_biometric(&self) -> Result<bool>;
    /// 宿主当前是否持有认证凭据（JWT）——只投影存在性
    async fn has_credentials(&self) -> bool;
}

/// 主连接事实面（票 12 `host-connection.primary-target` 的引擎读数）
///
/// `Ok(None)` = 从未配置目标；`Ok(Some((target, connected)))` = 传输事实。
#[async_trait]
pub trait ConnectionEnginePort: Send + Sync {
    async fn primary_target(&self) -> Result<Option<(PrimaryTarget, bool)>>;
}

/// 主连接目标（引擎事实：最后配置的目标地址 / 端口）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryTarget {
    pub address: String,
    pub port: u16,
}

/// SAF 桥面（Android MediaStore / 保存对话框；宿主 `saf_io::SafIo` 的窄投影）
pub trait SafIoPort: Send + Sync {
    fn write_media_downloads(
        &self,
        src: &str,
        display_name: &str,
        mime_type: &str,
    ) -> std::result::Result<(), String>;
    fn save_to_document(
        &self,
        src: &str,
        suggested_name: &str,
        mime_type: &str,
    ) -> std::result::Result<(), String>;
}

/// WS 自动重连策略面（票 12 R1：全局退避单一事实源 `connection::reconnect`
/// 留宿主；crate 侧按策略推进重连循环）
#[async_trait]
pub trait WsReconnectPolicyPort: Send + Sync {
    /// 推进一轮排期（无限重试下恒 `Some`；防御性保留放弃分支）
    async fn start(&self) -> Option<()>;
    /// 当前轮次的退避延迟
    async fn get_delay(&self) -> Duration;
    /// 重连成功回报（重置退避状态）
    async fn on_success(&self);
}

/// 文件授权操作（crate 自有枚举；宿主实现方映射到宿主 FsOp——形状解耦，
/// 宿主 fs_auth 白名单 / 弹窗 / 持久授权真源全部留宿主）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsAuthOp {
    Read,
    Write,
}

/// 文件授权闸门面（宿主 fs_auth 的窄投影）
///
/// crate 侧只问「这个插件能不能读/写这个路径」；授权判定链（路径白名单 →
/// 插件白名单 → 弹窗授权）是宿主安全闸门（ADR 0022 §5.1.3 ②），真源在宿主。
///
/// 窄授权判据（机制面消费的最小面）
///
/// 统一上下文的 `fs_auth` 槽已收敛为具体 `Arc<FsAuthChecker>`（用户裁决
/// 2026-10-11「机制以桌面端为准收敛一套」），本 trait 退化为**判据签名**：
/// `FsAuthChecker` 实现它，域函数按 trait 形态调用，第三方实现亦可只满足
/// `check` / `check_batch` 两个判定原语。桌面机制方法（`respond` /
/// `authorize_picked` / `is_granted` / `seed_legacy_granted_path`）不在本
/// trait 上，经 [`crate::host_api::context::WasmHostContext::fs_auth_checker`]
/// 取具体实例。
#[async_trait]
pub trait FsAuthGate: Send + Sync {
    async fn check(&self, plugin_id: &str, path: &str, op: FsAuthOp) -> bool;
    async fn check_batch(&self, plugin_id: &str, paths: &[String], op: FsAuthOp) -> bool;
}

// ==================== 端事实端口（单形态收口：端差异经宿主实现注入） ====================

/// 宿主端事实端口（内核零端分支，端值由各端宿主实现并注入）
///
/// 两个方法都是 **WIT 可见的端事实**：
/// - `platform_id` → `host-platform.platform`（跨端共享产物按它分支，如
///   file-transfer 单产物在**激活期**探测端值，未知值即激活失败）；
/// - `inbound_server_port` → `host-config.network.port`（桌面入站服务器运行态端口）。
///
/// 单形态（2026-10-13 裁决）之前这两处是内核里的
/// `#[cfg(feature = "desktop-assembly")]` 二选一：`"desktop"` / `"mobile"` 字面量
/// 与 `ServerSupervisor` 直读写死在内核——按 ADR 0049 D1 的判定口径（「桌面这样写、
/// 移动那样写」就不是机制）应属端宿主。现在内核只经本端口取端值，实现分别住
/// `桌面宿主 src-tauri/src/plugin/host_facts.rs` 与
/// `移动宿主 src-tauri/src/plugin/host_ports.rs`。
///
/// **注入点与时机**：`WasmHostContext::set_host_facts`，必须在任何插件
/// `activate()` 之前（桌面经 `PluginHost::new` 参数、移动在其上下文装配处）。
/// 漏注入不 panic，但两条取值路径都 fail-visible：`platform_id` 返回契约外取值
/// （guest 显性拒绝），`inbound_server_port` 返回 Err（不回落配置默认端口）。
pub trait HostFactsPort: Send + Sync {
    /// 宿主平台标识（契约取值：`"desktop"` / `"mobile"`；其余取值 guest 显性拒绝）
    fn platform_id(&self) -> String;

    /// 入站服务器实际端口（十进制字符串）；无入站服务器的宿主返回 Err
    fn inbound_server_port(&self) -> std::result::Result<String, String>;
}

/// 未注入端事实的占位（无头 / 测试上下文缺省；fail-visible，不猜端值）
pub struct UnimplementedHostFacts;

impl HostFactsPort for UnimplementedHostFacts {
    fn platform_id(&self) -> String {
        // 契约外取值：消费方（file-transfer 等共享产物）对未知端值显性失败——
        // "unknown" 是可见的断链信号，不猜默认平台
        "unknown".to_string()
    }

    fn inbound_server_port(&self) -> std::result::Result<String, String> {
        Err("network.port unavailable: this host has no inbound server".to_string())
    }
}

// ==================== 宿主引擎端口主 trait ====================

/// 宿主引擎端口（`WasmHostContext.ports` 注入；域函数唯一宿主调用面）
#[async_trait]
pub trait HostEnginePorts: Send + Sync {
    // ==================== egress（D5：授权策略整体留宿主） ====================

    /// 外网出口三层判定 + 需授权时弹窗回执，一次完成（decide + consent 编排
    /// 是宿主安全闸门的内聚实现，crate 侧只见「放行 / 拒绝（含错误码文本）」）
    async fn egress_check(
        &self,
        app: &tauri::AppHandle,
        url: &str,
        source: &str,
    ) -> std::result::Result<(), String>;

    /// 跳转重校验策略（302 → 内网 / 云元数据须过同源 / 桌面目标 / 私网链白名单）
    fn egress_redirect_policy(&self) -> reqwest::redirect::Policy;

    // ==================== auth / token（C4） ====================

    /// 认证引擎（None = 无头 / 未装配；域内 fail-visible 拒绝）
    fn auth_engine(&self) -> Option<Arc<dyn AuthEnginePort>>;

    /// 全局 JWT token（jwt-auth 首帧代发 / 宿主代注 Bearer；token 不落插件）
    fn global_token(&self) -> String;

    // ==================== host-config 端专属项（票 03） ====================
    //
    // `host-config` 是 core.wit 的双端全等 interface，白名单词汇由内核持并集
    // （见 `host_api/config.rs`）。并集里属**端专属事实**的一项是移动下载目录
    // （Android SAF 路径），由移动宿主经本端口注入；未注入 ⇒ 域内 fail-visible
    // 报错（不静默返回空值）。桌面侧无此需求（`network.port` 走桌面装配面
    // `desktop-assembly` 直读 supervisor，不经本端口）。

    /// 本端应用下载目录绝对路径（`app.downloads_dir`；移动 SAF 路径事实）
    ///
    /// 返回 `None` = 本端无对应物（桌面）或宿主未装配。
    fn app_downloads_dir(&self) -> Option<String> {
        None
    }

    // ==================== connection ====================

    /// 主连接事实读数
    fn connection_engine(&self) -> Arc<dyn ConnectionEnginePort>;

    // ==================== ws 重连 ====================

    /// 重连退避策略（参数钳制已在域内完成，宿主实现只出策略对象）
    fn reconnect_policy(
        &self,
        max_retries: u32,
        base_ms: u64,
        max_ms: u64,
    ) -> Box<dyn WsReconnectPolicyPort>;

    /// 重连退避钳制边界 `(min_delay_ms, max_delay_ms)`（宿主全局常量的投影）
    fn reconnect_bounds(&self) -> (u64, u64);

    // ==================== mdns ====================

    /// 本机 peer 节点 ID（自播回显过滤；未启动 None）
    fn current_node_id(&self, app: &tauri::AppHandle) -> Option<String>;

    // ==================== peer：peer_net 引擎 ====================

    /// 拨号建连（返回引擎应答的 `status` 字段：`"connected"` / 其他）
    async fn peer_dial_endpoint(
        &self,
        app: &tauri::AppHandle,
        node_id: String,
        addr: String,
        port: u16,
    ) -> Result<String>;

    /// 断开对端（返回是否命中；`close` 统一资源关闭的 session 路由）
    async fn peer_disconnect(&self, app: &tauri::AppHandle, node_id: String) -> Result<bool>;

    /// 首连应答
    async fn peer_respond_consent(
        &self,
        app: &tauri::AppHandle,
        request_id: String,
        accepted: bool,
    ) -> Result<bool>;

    /// 信任列表（JSON 序列化由实现方完成）
    async fn peer_list_trusted(&self, app: &tauri::AppHandle) -> Result<String>;

    /// 撤销信任
    async fn peer_revoke_trusted(&self, app: &tauri::AppHandle, node_id: String) -> Result<bool>;

    /// 全量幂等替换引擎广播源（`[{ id, name, safTreeUri }]` JSON，camelCase）
    async fn peer_set_shared_roots(
        &self,
        app: &tauri::AppHandle,
        entries_json: String,
    ) -> Result<()>;

    /// 按需启动本机节点（幂等；caller = 属主）
    async fn peer_start_node(&self, app: &tauri::AppHandle, caller: &str) -> Result<bool>;

    /// 属主插件让节点下线（非属主拒绝）
    async fn peer_stop_node(&self, app: &tauri::AppHandle, caller: &str) -> Result<bool>;

    // ==================== peer：transfer / receive / remote ====================

    /// 取消发送批
    async fn peer_cancel_transfer(&self, app: &tauri::AppHandle, batch_id: String) -> Result<bool>;

    /// 取消/拒绝接收批（pending 即拒；`close` 统一资源关闭的接收侧路由）
    async fn peer_cancel_receiving(&self, app: &tauri::AppHandle, batch_id: String)
        -> Result<bool>;

    /// 发送一批文件（paths 已由域内完成双形态解析与并发脉冲字段拒绝）
    async fn peer_send_files_with_policy(
        &self,
        app: &tauri::AppHandle,
        node_id: String,
        paths: Vec<String>,
        force_encrypt: Option<bool>,
    ) -> Result<String>;

    /// 接收批应答
    async fn peer_respond_transfer(
        &self,
        app: &tauri::AppHandle,
        batch_id: String,
        accept: bool,
    ) -> Result<()>;

    /// 接收策略
    async fn peer_set_receive_policy(
        &self,
        app: &tauri::AppHandle,
        mode: String,
        timeout_secs: u64,
    ) -> Result<()>;

    /// 暂停发送批（返回是否命中）
    async fn peer_pause_transfer(&self, app: &tauri::AppHandle, batch_id: String) -> Result<bool>;

    /// 恢复发送批（返回是否命中）
    async fn peer_resume_transfer(&self, app: &tauri::AppHandle, batch_id: String) -> Result<bool>;

    /// 设置接收落点（None = 恢复默认）
    async fn peer_set_download_dir(
        &self,
        app: &tauri::AppHandle,
        path: Option<String>,
    ) -> Result<()>;

    /// 远端共享根列表（JSON 由实现方序列化）
    async fn peer_list_shared_roots(
        &self,
        app: &tauri::AppHandle,
        node_id: String,
    ) -> Result<String>;

    /// 远端目录浏览（JSON 由实现方序列化）
    async fn peer_browse_directory(
        &self,
        app: &tauri::AppHandle,
        node_id: String,
        dir_id: String,
        rel_path: String,
    ) -> Result<String>;

    /// 拉取文件（files_json 契约归宿主实现解析）
    async fn peer_pull_files(
        &self,
        app: &tauri::AppHandle,
        node_id: String,
        dir_id: String,
        files_json: String,
    ) -> Result<u32>;

    /// 活跃传输批清单（send + receive pending + pull 三表聚合投影，JSON）
    async fn peer_active_transfers(&self, app: &tauri::AppHandle) -> Result<String>;

    /// 发送源收集（`[{ path, size }]` JSON；无 app 依赖——纯元数据面）
    async fn peer_collect_outgoing(&self, paths: Vec<String>) -> Result<String>;

    // ==================== platform / fs / config / db ====================

    /// 系统多文件选择器（返回路径列表；用户取消为空）
    async fn platform_pick_files(&self, app: &tauri::AppHandle) -> Result<Vec<String>>;

    /// SAF 共享目录树选择器（用户取消 None；`(uri, doc_id, display_name)`）
    async fn platform_pick_shared_directory(&self) -> Result<Option<(String, String, String)>>;

    /// 解析 app 下载目录（Kotlin 桥外部私有目录 → app_data 回退，惰性创建）
    async fn resolve_downloads_dir(&self, app: &tauri::AppHandle) -> Result<String>;

    /// Android 经 Kotlin FileDeletePlugin 删文件（仅 Android 分支调用）
    async fn delete_file_android(&self, path: String) -> Result<()>;

    /// 写入落点越界校验（src 必须在宿主解析的 app 下载目录内）
    async fn is_within_app_downloads_dir(&self, app: &tauri::AppHandle, path: &str)
        -> Result<bool>;

    /// SAF 桥句柄（None = 未装配）
    fn saf_io(&self, app: &tauri::AppHandle) -> Option<Arc<dyn SafIoPort>>;

    /// 应用数据目录（插件私有库落点解析）
    async fn app_data_dir(&self, app: &tauri::AppHandle) -> Result<PathBuf>;

    // ==================== notify（系统通知与提醒反馈，ABI v18） ====================
    //
    // 全部经 Kotlin TaskNotificationPlugin；非 Android 平台实现方返回 Err
    // （与退役前 host_notify 同语义）。权限门 `notify` 在域内（notify.rs），
    // 端口只承载平台调用形状。

    /// 发送系统通知（vibrate/sound 由域内 options 解析后传入）
    async fn notify_show(
        &self,
        plugin_id: &str,
        title: &str,
        body: &str,
        vibrate: bool,
        sound: bool,
    ) -> std::result::Result<(), String>;

    /// 通知权限是否已授予（POST_NOTIFICATIONS + 系统通知总开关）
    async fn notify_check_permission(&self) -> std::result::Result<bool, String>;

    /// 请求通知权限（弹系统授权框，阻塞至用户响应）
    async fn notify_request_permission(&self) -> std::result::Result<bool, String>;

    /// 立即震动一次（毫秒；域内已钳制 [1, 5000]）
    async fn notify_vibrate(&self, duration_ms: u32) -> std::result::Result<(), String>;

    /// 播放系统默认通知提示音
    async fn notify_play_sound(&self) -> std::result::Result<(), String>;
}

// ==================== 平台选择器端口（host-platform.pick-* 的端实现） ====================

/// 系统选择器端口（`host-platform` 的 `pick-files` / `pick-folders` 端实现）
///
/// 端差异落宿主（ADR 0052 D1「差异应该在各自的宿主侧」）：桌面 = 原生对话框
/// （宿主 `桌面宿主 src-tauri/src/plugin/platform_picker.rs`），移动 = SAF
/// 选择器（经 [`EnginePortsPlatformPicker`] 适配本模块 `HostEnginePorts` 已有的两条
/// SAF 端口）。内核只持共享机制——`fs:pick` 权限门 + 选择后 `authorize_picked`
/// 授权校验 + JSON 形状（`host_api/platform.rs`），选择器本身由宿主装配注入。
///
/// 为什么单独一条窄端口：桌面宿主不存在 `HostEnginePorts` 整体实现（桌面引擎调用
/// 不经端口，上下文持 [`UnimplementedPorts`] 占位），只为两条选择原语实现整条
/// 端口 trait 会给桌面造出第二份装配面；窄端口让两端各实现真正需要的东西。
#[async_trait]
pub trait PlatformPickerPort: Send + Sync {
    /// 选文件（用户取消为空数组；失败显性 `Err`，不得降级成空 = 静默丢选择）
    ///
    /// 无 `AppHandle` 参数：句柄在**装配期**由宿主实现捕获（桌面
    /// `DesktopPlatformPicker::new` / 移动适配器捕获 `Option<Arc<AppHandle>>`）——
    /// 无头/测试上下文因此也能构造选择器替身驱动域函数（不依赖 tao 事件循环
    /// 建 AppHandle，测试面直接断言「门→选择器→授权」全链）。
    async fn pick_files(&self) -> Result<Vec<String>>;

    /// 选目录（桌面 = 原生多选目录对话框；移动 = SAF 目录树单选，0/1 个树 URI）
    async fn pick_folders(&self) -> Result<Vec<String>>;
}

/// 未装配选择器（无头 / 测试上下文）：调用即 fail-visible
///
/// 与 [`UnimplementedPorts`] 同口径（禁 panic）：漏装配的宿主会在插件调用点拿到
/// 显性错误而非静默空数组。
pub struct UnimplementedPlatformPicker;

#[async_trait]
impl PlatformPickerPort for UnimplementedPlatformPicker {
    async fn pick_files(&self) -> Result<Vec<String>> {
        Err(port_err("platform_picker_pick_files"))
    }

    async fn pick_folders(&self) -> Result<Vec<String>> {
        Err(port_err("platform_picker_pick_folders"))
    }
}

/// 移动装配适配器：把 [`HostEnginePorts`] 的 SAF 选择器端口接到 [`PlatformPickerPort`]
///
/// 移动宿主的选择器实现本就住在 `HostEnginePorts`（`plugin/host_ports.rs`），
/// `WasmHostContext::new_with_ports` 装配上下文时经本适配器接线——移动宿主不必
/// 为选择器再造一个实现，构造器也不必为此再加参数。
pub struct EnginePortsPlatformPicker {
    ports: Arc<dyn HostEnginePorts>,
    /// 装配期捕获的应用句柄（None = 无头）：SAF 端口调用需要它，缺句柄时显性
    /// 报错（错误文案与旧 `platform.rs::require_app` 逐字一致，排障拼图不变）
    app_handle: Option<Arc<tauri::AppHandle>>,
}

impl EnginePortsPlatformPicker {
    /// 包装宿主引擎端口 + 应用句柄（构造器只做接线，不做能力判断）
    pub fn new(ports: Arc<dyn HostEnginePorts>, app_handle: Option<Arc<tauri::AppHandle>>) -> Self {
        Self { ports, app_handle }
    }
}

#[async_trait]
impl PlatformPickerPort for EnginePortsPlatformPicker {
    async fn pick_files(&self) -> Result<Vec<String>> {
        let app = self
            .app_handle
            .as_ref()
            .ok_or_else(|| crate::error::AppError::Internal(HEADLESS_PICKER_ERROR.to_string()))?;
        self.ports.platform_pick_files(app).await
    }

    /// SAF 目录树选择器为单选语义：`Some((uri, doc_id, display_name))` → 0/1 项
    /// （只交树 URI——doc-id / 展示名由共享目录注册表按 URI 自取）；用户取消 → 空数组
    ///
    /// 与 `pick_files` 不同，SAF 目录树端口无应用句柄参数（`run_mobile_plugin_async`
    /// 自持句柄）——但仍先过同一句柄检查：无头上下文不许假成功（取消与未装配
    /// 必须可区分），口径与 `pick_files` 一致。
    async fn pick_folders(&self) -> Result<Vec<String>> {
        if self.app_handle.is_none() {
            return Err(crate::error::AppError::Internal(
                HEADLESS_PICKER_ERROR.to_string(),
            ));
        }
        Ok(self
            .ports
            .platform_pick_shared_directory()
            .await?
            .map(|(uri, _doc_id, _display_name)| vec![uri])
            .unwrap_or_default())
    }
}

/// 无头上下文取不到 `AppHandle` 的选择器错误文案（原 `platform.rs::require_app` 原文）
const HEADLESS_PICKER_ERROR: &str = "platform unavailable in headless context (no app_handle)";

// ==================== 无头默认实现 ====================

/// 未装配端口的占位实现（无头 / 测试上下文；所有调用 fail-visible）
///
/// 全部方法返回显性错误或空值——**禁 panic**（wasmtime host fn 内 panic 会
/// 污染 Store 导致插件整体失效，见 `support::guarded_host_call` 注释）。
pub struct UnimplementedPorts;

#[async_trait]
impl HostEnginePorts for UnimplementedPorts {
    async fn egress_check(
        &self,
        _app: &tauri::AppHandle,
        _url: &str,
        _source: &str,
    ) -> std::result::Result<(), String> {
        Err(PORT_NOT_WIRED.to_string())
    }

    fn egress_redirect_policy(&self) -> reqwest::redirect::Policy {
        reqwest::redirect::Policy::none()
    }

    fn auth_engine(&self) -> Option<Arc<dyn AuthEnginePort>> {
        None
    }

    fn global_token(&self) -> String {
        String::new()
    }

    fn connection_engine(&self) -> Arc<dyn ConnectionEnginePort> {
        Arc::new(UnimplementedConnectionEngine)
    }

    fn reconnect_policy(
        &self,
        _max_retries: u32,
        _base_ms: u64,
        _max_ms: u64,
    ) -> Box<dyn WsReconnectPolicyPort> {
        Box::new(UnimplementedReconnectPolicy)
    }

    fn reconnect_bounds(&self) -> (u64, u64) {
        (1000, 60_000)
    }

    fn current_node_id(&self, _app: &tauri::AppHandle) -> Option<String> {
        None
    }

    async fn peer_dial_endpoint(
        &self,
        _app: &tauri::AppHandle,
        _node_id: String,
        _addr: String,
        _port: u16,
    ) -> Result<String> {
        Err(port_err("peer_dial_endpoint"))
    }

    async fn peer_disconnect(&self, _app: &tauri::AppHandle, _node_id: String) -> Result<bool> {
        Err(port_err("peer_disconnect"))
    }

    async fn peer_respond_consent(
        &self,
        _app: &tauri::AppHandle,
        _request_id: String,
        _accepted: bool,
    ) -> Result<bool> {
        Err(port_err("peer_respond_consent"))
    }

    async fn peer_list_trusted(&self, _app: &tauri::AppHandle) -> Result<String> {
        Err(port_err("peer_list_trusted"))
    }

    async fn peer_revoke_trusted(&self, _app: &tauri::AppHandle, _node_id: String) -> Result<bool> {
        Err(port_err("peer_revoke_trusted"))
    }

    async fn peer_set_shared_roots(
        &self,
        _app: &tauri::AppHandle,
        _entries_json: String,
    ) -> Result<()> {
        Err(port_err("peer_set_shared_roots"))
    }

    async fn peer_start_node(&self, _app: &tauri::AppHandle, _caller: &str) -> Result<bool> {
        Err(port_err("peer_start_node"))
    }

    async fn peer_stop_node(&self, _app: &tauri::AppHandle, _caller: &str) -> Result<bool> {
        Err(port_err("peer_stop_node"))
    }

    async fn peer_cancel_transfer(
        &self,
        _app: &tauri::AppHandle,
        _batch_id: String,
    ) -> Result<bool> {
        Err(port_err("peer_cancel_transfer"))
    }

    async fn peer_cancel_receiving(
        &self,
        _app: &tauri::AppHandle,
        _batch_id: String,
    ) -> Result<bool> {
        Err(port_err("peer_cancel_receiving"))
    }

    async fn peer_send_files_with_policy(
        &self,
        _app: &tauri::AppHandle,
        _node_id: String,
        _paths: Vec<String>,
        _force_encrypt: Option<bool>,
    ) -> Result<String> {
        Err(port_err("peer_send_files_with_policy"))
    }

    async fn peer_respond_transfer(
        &self,
        _app: &tauri::AppHandle,
        _batch_id: String,
        _accept: bool,
    ) -> Result<()> {
        Err(port_err("peer_respond_transfer"))
    }

    async fn peer_set_receive_policy(
        &self,
        _app: &tauri::AppHandle,
        _mode: String,
        _timeout_secs: u64,
    ) -> Result<()> {
        Err(port_err("peer_set_receive_policy"))
    }

    async fn peer_pause_transfer(
        &self,
        _app: &tauri::AppHandle,
        _batch_id: String,
    ) -> Result<bool> {
        Err(port_err("peer_pause_transfer"))
    }

    async fn peer_resume_transfer(
        &self,
        _app: &tauri::AppHandle,
        _batch_id: String,
    ) -> Result<bool> {
        Err(port_err("peer_resume_transfer"))
    }

    async fn peer_set_download_dir(
        &self,
        _app: &tauri::AppHandle,
        _path: Option<String>,
    ) -> Result<()> {
        Err(port_err("peer_set_download_dir"))
    }

    async fn peer_list_shared_roots(
        &self,
        _app: &tauri::AppHandle,
        _node_id: String,
    ) -> Result<String> {
        Err(port_err("peer_list_shared_roots"))
    }

    async fn peer_browse_directory(
        &self,
        _app: &tauri::AppHandle,
        _node_id: String,
        _dir_id: String,
        _rel_path: String,
    ) -> Result<String> {
        Err(port_err("peer_browse_directory"))
    }

    async fn peer_pull_files(
        &self,
        _app: &tauri::AppHandle,
        _node_id: String,
        _dir_id: String,
        _files_json: String,
    ) -> Result<u32> {
        Err(port_err("peer_pull_files"))
    }

    async fn peer_active_transfers(&self, _app: &tauri::AppHandle) -> Result<String> {
        Err(port_err("peer_active_transfers"))
    }

    async fn peer_collect_outgoing(&self, _paths: Vec<String>) -> Result<String> {
        Err(port_err("peer_collect_outgoing"))
    }

    async fn platform_pick_files(&self, _app: &tauri::AppHandle) -> Result<Vec<String>> {
        Err(port_err("platform_pick_files"))
    }

    async fn platform_pick_shared_directory(&self) -> Result<Option<(String, String, String)>> {
        Err(port_err("platform_pick_shared_directory"))
    }

    async fn resolve_downloads_dir(&self, _app: &tauri::AppHandle) -> Result<String> {
        Err(port_err("resolve_downloads_dir"))
    }

    async fn delete_file_android(&self, _path: String) -> Result<()> {
        Err(port_err("delete_file_android"))
    }

    async fn is_within_app_downloads_dir(
        &self,
        _app: &tauri::AppHandle,
        _path: &str,
    ) -> Result<bool> {
        Err(port_err("is_within_app_downloads_dir"))
    }

    fn saf_io(&self, _app: &tauri::AppHandle) -> Option<Arc<dyn SafIoPort>> {
        None
    }

    async fn app_data_dir(&self, _app: &tauri::AppHandle) -> Result<PathBuf> {
        Err(port_err("app_data_dir"))
    }

    async fn notify_show(
        &self,
        _plugin_id: &str,
        _title: &str,
        _body: &str,
        _vibrate: bool,
        _sound: bool,
    ) -> std::result::Result<(), String> {
        Err(PORT_NOT_WIRED.to_string())
    }

    async fn notify_check_permission(&self) -> std::result::Result<bool, String> {
        Err(PORT_NOT_WIRED.to_string())
    }

    async fn notify_request_permission(&self) -> std::result::Result<bool, String> {
        Err(PORT_NOT_WIRED.to_string())
    }

    async fn notify_vibrate(&self, _duration_ms: u32) -> std::result::Result<(), String> {
        Err(PORT_NOT_WIRED.to_string())
    }

    async fn notify_play_sound(&self) -> std::result::Result<(), String> {
        Err(PORT_NOT_WIRED.to_string())
    }
}

/// 端口未装配统一错误文案（fail-visible：无头上下文命中引擎调用即此文本）
pub const PORT_NOT_WIRED: &str = "host engine port not wired (headless/unimplemented)";

fn port_err(method: &str) -> crate::error::AppError {
    crate::error::AppError::Internal(format!("{PORT_NOT_WIRED}: {method}"))
}

/// [`UnimplementedPorts`] 伴随的连接引擎占位
struct UnimplementedConnectionEngine;

#[async_trait]
impl ConnectionEnginePort for UnimplementedConnectionEngine {
    async fn primary_target(&self) -> Result<Option<(PrimaryTarget, bool)>> {
        Err(port_err("connection_primary_target"))
    }
}

/// [`UnimplementedPorts`] 伴随的重连策略占位（单轮后放弃，零延迟）
struct UnimplementedReconnectPolicy;

#[async_trait]
impl WsReconnectPolicyPort for UnimplementedReconnectPolicy {
    async fn start(&self) -> Option<()> {
        Some(())
    }

    async fn get_delay(&self) -> Duration {
        Duration::from_millis(1000)
    }

    async fn on_success(&self) {}
}

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 无头端口占位面 fail-visible：无 app 参数的方法逐一断言（显性错误 / 空值）。
    ///
    /// 带 `&tauri::AppHandle` 参数的方法**不在本断言面**：无头上下文里域函数
    /// 在进端口前已被 `require_app` 拦截（"headless context"），占位实现运行时
    /// 不可达；真 app 路径由宿主集成测试覆盖。新增「无 app 参数」端口方法必须
    /// 在此同步补断言（防「占位实现静默成功」漂移）。
    #[tokio::test]
    async fn unimplemented_ports_fail_visibly() {
        let ports = UnimplementedPorts;
        assert!(ports.auth_engine().is_none());
        assert!(ports.global_token().is_empty());
        let (min_ms, max_ms) = ports.reconnect_bounds();
        assert!(min_ms > 0 && max_ms >= min_ms);
        assert!(ports
            .peer_collect_outgoing(vec!["/tmp/x".into()])
            .await
            .is_err());
        assert!(ports.platform_pick_shared_directory().await.is_err());
        assert!(ports.notify_show("t", "a", "b", true, true).await.is_err());
        // ABI v18：notify 域 4 个新增无 app 参数方法同属 fail-visible 断言面
        assert!(ports.notify_check_permission().await.is_err());
        assert!(ports.notify_request_permission().await.is_err());
        assert!(ports.notify_vibrate(100).await.is_err());
        assert!(ports.notify_play_sound().await.is_err());
    }
}
