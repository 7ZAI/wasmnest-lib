//! Plugin API Bridge
//!
//! Tauri commands — 前端 PluginContext 的每个 API 调用通过 Tauri invoke 到达此桥接层
//! Rust 端做权限校验后执行操作

use super::PluginHost;
use crate::manager::types::HostPluginInfo;
use crate::security::fs_auth::FsAuthChecker;
use std::sync::Arc;
use tauri::State;

// ==================== 前端通道身份（审计票 06 / P0-5） ====================
//
// 本桥的插件面命令**不再信任参数里的 plugin_id**：调用方必须带 `credential`，
// 身份由宿主解析（宿主面 loader 密钥 → 可操作任意目标；插件面令牌 → 目标必须是自己）。
// 机制与威胁模型见 `plugin/security/frontend_channel.rs`。
//
// **宿主面命令门（ADR 0058 方案 A，2026-10-24，issue #21）**：生命周期管理命令
// （plugin_preauthorize / plugin_activate / plugin_deactivate / plugin_approve /
// plugin_install_from_file / plugin_uninstall）已纳入宿主面凭证门——激活 / 停用 /
// 安装 / 卸载 / 审批是宿主职权，插件面令牌（即使目标是自己）也一律拒绝；前端调用点
// 必须经宿主面凭证（`ensureHostCredential`）。判据真源见
// `frontend_channel::require_host_identity`。
//
// **凭证域按 webview 分区**（2026-09-26）：每个 `plugin_*` 命令注入 `tauri::Webview`
// 参数（Tauri 保证是调用发起方所在窗口），label 决定用哪个凭证域解析——主窗口与终端
// 窗口互不干扰，跨窗口的凭证不可解析（比单一全局表更严）。

/// 宿主前端 bootstrap：取得**本窗口**本次页面加载的 loader 会话密钥（**域内首个调用者生效**）
///
/// 宿主前端在导入任何插件模块之前调用（`pluginLoader.loadAll()` 首行），插件代码开始运行时
/// 密钥已被占位。该窗口页面加载时由 `on_page_load` 钩子重置，dev 下刷新可重新取得。
#[tauri::command]
pub async fn plugin_frontend_loader_session(
    webview: tauri::Webview,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<String> {
    let session = plugin_host
        .frontend_channel()
        .issue_loader_session(webview.label())?;
    tracing::info!(webview = %webview.label(), "[API] plugin_frontend_loader_session: 宿主面凭证已签发");
    Ok(session)
}

/// 插件前端：为指定插件签发通道令牌（需同窗口的 loader 会话密钥 + 插件处于运行态）
///
/// 令牌随停用回收；同一窗口内重新签发会作废旧令牌。
#[tauri::command]
pub async fn plugin_channel_token(
    webview: tauri::Webview,
    plugin_id: String,
    loader_session: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<String> {
    if !plugin_host
        .frontend_channel()
        .verify_loader_session(webview.label(), &loader_session)
    {
        tracing::warn!(
            webview = %webview.label(),
            plugin_id = %plugin_id,
            "[API] plugin_channel_token: loader 会话凭证无效"
        );
        return Err(crate::AppError::Plugin(
            "invalid frontend loader session credential".to_string(),
        ));
    }
    // 运行态（Activated / Degraded）才签发：未激活插件没有 granted 集，令牌无意义
    if !plugin_host.is_running(&plugin_id).await {
        tracing::warn!(plugin_id = %plugin_id, "[API] plugin_channel_token: 插件未运行，拒绝签发");
        return Err(crate::AppError::Plugin(format!(
            "Plugin {} is not running, channel token refused",
            plugin_id
        )));
    }
    let token =
        plugin_host
            .frontend_channel()
            .issue_token(webview.label(), &loader_session, &plugin_id)?;
    tracing::info!(
        webview = %webview.label(),
        plugin_id = %plugin_id,
        "[API] plugin_channel_token: 插件面令牌已签发"
    );
    Ok(token)
}

/// 授权管理面命令的宿主面凭证门（读取 / 撤销 / 代答授权决定）
///
/// 授权记录是安全闸门的配给账：插件面凭证不得用它枚举其它应用的授权情况，
/// 更不能替用户撤销或同意。判据委托给
/// `frontend_channel::require_host_identity`（ADR 0058 方案 A 的真源，有单测），
/// 本层只负责把失败换成各命令自己的 denial 文案——既有调用点的拒绝文案逐字不变。
fn require_host_surface(
    plugin_host: &PluginHost,
    webview_label: &str,
    command: &str,
    credential: &str,
    denial: &str,
) -> crate::Result<()> {
    plugin_host
        .frontend_channel()
        .require_host_identity(webview_label, credential, command)
        .map_err(|_| crate::AppError::Plugin(denial.to_string()))
}

/// 插件面命令的统一身份校验（fail-closed 语义与裁决规则见 `frontend_channel::authorize`）
fn authorize_plugin_call(
    plugin_host: &PluginHost,
    webview_label: &str,
    plugin_id: &str,
    credential: &str,
) -> crate::Result<()> {
    plugin_host
        .frontend_channel()
        .authorize(webview_label, plugin_id, credential)
}

// ==================== Plugin Lifecycle ====================

/// 获取所有已加载插件列表
#[tauri::command]
pub async fn plugin_list_loaded(
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Vec<HostPluginInfo>> {
    tracing::debug!("[API] plugin_list_loaded called");
    let result = plugin_host.list_plugins().await;
    tracing::debug!(
        "[API] plugin_list_loaded returning {} plugin(s)",
        result.len()
    );
    Ok(result)
}

/// 获取单个插件信息
#[tauri::command]
pub async fn plugin_get_info(
    plugin_id: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Option<HostPluginInfo>> {
    tracing::debug!(plugin_id = %plugin_id, "[API] plugin_get_info");
    Ok(plugin_host.get_plugin(&plugin_id).await)
}

/// 预授权（启用前置，独立命令供前端先行调用）
///
/// 前端 toggle 时序：先调本命令（此阶段**不显示** loading 遮罩，授权弹窗
/// 可正常交互）→ 通过后再显示遮罩调 `plugin_activate`；拒绝则直接失败，
/// 不进入激活流程。`plugin_activate` 内部的 preauthorize 保留为兜底
/// （启动 auto-activate 无头场景 + 已授权路径短路无二次弹窗）。
#[tauri::command]
pub async fn plugin_preauthorize(
    webview: tauri::Webview,
    plugin_id: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_preauthorize",
        &credential,
        "plugin preauthorization must be requested by the host frontend",
    )?;
    tracing::info!(plugin_id = %plugin_id, "[API] plugin_preauthorize");
    let result = plugin_host.preauthorize_plugin(&plugin_id).await;
    if let Err(ref e) = result {
        tracing::error!(plugin_id = %plugin_id, error = %e, "[API] plugin_preauthorize failed");
    }
    result
}

/// 激活插件（用户操作，持久化状态）
#[tauri::command]
pub async fn plugin_activate(
    webview: tauri::Webview,
    plugin_id: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_activate",
        &credential,
        "plugin activation must be requested by the host frontend",
    )?;
    tracing::info!(plugin_id = %plugin_id, "[API] plugin_activate");
    let result = plugin_host.activate_plugin(&plugin_id, true).await;
    if let Err(ref e) = result {
        tracing::error!(plugin_id = %plugin_id, error = %e, "[API] plugin_activate failed");
    }
    result
}

/// 停用插件（用户操作，持久化状态）
#[tauri::command]
pub async fn plugin_deactivate(
    webview: tauri::Webview,
    plugin_id: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_deactivate",
        &credential,
        "plugin deactivation must be requested by the host frontend",
    )?;
    tracing::info!(plugin_id = %plugin_id, "[API] plugin_deactivate");
    let result = plugin_host.deactivate_plugin(&plugin_id, true).await;
    if let Err(ref e) = result {
        tracing::error!(plugin_id = %plugin_id, error = %e, "[API] plugin_deactivate failed");
    }
    result
}

/// 批准用户安装插件的权限清单（ADR 0020 审批门禁的放行操作）
///
/// 生效权限 = 批准 ∩ manifest 请求；批准与插件目录内容哈希绑定，
/// 目录内容在批准后变化 → 批准自动撤销并回到 NeedsApproval。
#[tauri::command]
pub async fn plugin_approve(
    webview: tauri::Webview,
    plugin_id: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Vec<String>> {
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_approve",
        &credential,
        "plugin permission approval must be granted by the host frontend",
    )?;
    tracing::info!(plugin_id = %plugin_id, "[API] plugin_approve");
    let result = plugin_host.approve_plugin(&plugin_id).await;
    if let Err(ref e) = result {
        tracing::error!(plugin_id = %plugin_id, error = %e, "[API] plugin_approve failed");
    }
    result
}

/// 标记插件错误
#[tauri::command]
pub async fn plugin_mark_error(
    plugin_id: String,
    error: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    plugin_host.mark_error(&plugin_id, error).await;
    Ok(())
}

/// 获取插件激活状态映射（plugin_id → is_activated）
#[tauri::command]
pub async fn plugin_get_activated_state(
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<std::collections::HashMap<String, bool>> {
    Ok(plugin_host.get_activated_state().await)
}

// ==================== Frontend Load Diagnostics ====================

/// 插件前端模块加载诊断上报（宿主内部诊断通道，spec §3.7 / issue 04）
///
/// 前端 PluginLoader 在 TS 模块导入/激活成败时调用，把结果写入 tracing 落盘日志
/// （runtime.*.log），使日志能看到插件加载「后端半程之外」的前端半程。仅写日志：
/// 不改插件状态机；也不做存在性/权限校验——诊断通道自身失败会丢日志行，
/// 门禁拒绝只会再丢一次。
///
/// 注意：这是宿主自身的启动期诊断命令，不是插件协议，不受「不加特殊上报 ABI」约束。
#[tauri::command]
pub async fn plugin_frontend_load_report(
    plugin_id: String,
    stage: String,
    ok: bool,
    detail: Option<String>,
) -> crate::Result<()> {
    if ok {
        tracing::info!(
            plugin_id = %plugin_id,
            stage = %stage,
            "[PluginLoader] frontend module load ok"
        );
    } else {
        tracing::error!(
            plugin_id = %plugin_id,
            stage = %stage,
            detail = detail.as_deref().unwrap_or("(no detail)"),
            "[PluginLoader] frontend module load FAILED"
        );
    }
    Ok(())
}

// ==================== Plugin Storage ====================

/// 插件存储：获取值
///
/// 身份：`credential` 决定调用方（宿主面 / 该插件自己）；`plugin_id` 只作目标。
/// 校验通过后再查激活态与 `storage` 权限（查的是**目标插件**的 granted 集）。
#[tauri::command]
pub async fn plugin_storage_get(
    webview: tauri::Webview,
    plugin_id: String,
    key: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Option<serde_json::Value>> {
    authorize_plugin_call(&plugin_host, webview.label(), &plugin_id, &credential)?;
    if !plugin_host.is_activated(&plugin_id).await {
        return Err(crate::AppError::Plugin(format!(
            "Plugin {} is not activated",
            plugin_id
        )));
    }
    if !plugin_host.permission().check(&plugin_id, "storage") {
        return Err(crate::AppError::Plugin(format!(
            "Plugin {} has no storage permission",
            plugin_id
        )));
    }
    plugin_host.storage().get(&plugin_id, &key).await
}

/// 插件存储：设置值
#[tauri::command]
pub async fn plugin_storage_set(
    webview: tauri::Webview,
    plugin_id: String,
    key: String,
    value: serde_json::Value,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    authorize_plugin_call(&plugin_host, webview.label(), &plugin_id, &credential)?;
    if !plugin_host.is_activated(&plugin_id).await {
        return Err(crate::AppError::Plugin(format!(
            "Plugin {} is not activated",
            plugin_id
        )));
    }
    if !plugin_host.permission().check(&plugin_id, "storage") {
        return Err(crate::AppError::Plugin(format!(
            "Plugin {} has no storage permission",
            plugin_id
        )));
    }
    plugin_host.storage().set(&plugin_id, &key, value).await
}

/// 插件存储：删除值
#[tauri::command]
pub async fn plugin_storage_delete(
    webview: tauri::Webview,
    plugin_id: String,
    key: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    authorize_plugin_call(&plugin_host, webview.label(), &plugin_id, &credential)?;
    if !plugin_host.is_activated(&plugin_id).await {
        return Err(crate::AppError::Plugin(format!(
            "Plugin {} is not activated",
            plugin_id
        )));
    }
    if !plugin_host.permission().check(&plugin_id, "storage") {
        return Err(crate::AppError::Plugin(format!(
            "Plugin {} has no storage permission",
            plugin_id
        )));
    }
    plugin_host.storage().delete(&plugin_id, &key).await
}

// ==================== Plugin Terminal（票 08 已注销） ====================

// `plugin_terminal_send_input` 随票 08 删除：它是「宿主替插件把终端输入导流到 PTY」
// 的桥，会话命令面注销后插件前端改走自家命令通道（`session.input` → 本插件
// `session::input_via_pty`），宿主不再有这条替插件写输入的路径。
//
// 门禁不是被放宽而是被**换掉载体**：插件命令通道（`plugin_invoke`）自带
// 「身份令牌 + 激活」两段，写入侧 `host-pty.write` 的 `pty:io` 权限门仍在
// WIT 层仲裁（插件的 manifest 声明面）。故本条删除不影响输入权限的有效性。

// ==================== Plugin Registry Queries ====================

/// 获取所有命令
#[tauri::command]
pub async fn plugin_list_commands(
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Vec<crate::manager::registry::CommandEntry>> {
    Ok(plugin_host.registry().list_commands().await)
}

/// 获取指定类型的视图
#[tauri::command]
pub async fn plugin_list_views(
    view_type: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Vec<crate::manager::registry::ViewEntry>> {
    Ok(plugin_host.registry().get_views_by_type(&view_type).await)
}

/// 查找文件处理器
#[tauri::command]
pub async fn plugin_find_file_handler(
    extension: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Option<crate::manager::registry::FileHandlerEntry>> {
    Ok(plugin_host.registry().find_file_handler(&extension).await)
}

// ==================== Rust Plugin Command Dispatch ====================

/// 调用 Rust 插件的自定义 command
///
/// 统一路由：前端通过 `invoke('plugin_invoke', { pluginId, command, args, credential })` 调用。
/// **身份由 `credential` 绑定**（审计票 06）：插件只能驱动自己的 command（目标必须等于令牌
/// 身份），宿主前端持 loader 会话密钥可驱动任意插件的 command（宿主职权）。
/// 此前该命令只查 `is_activated`，任何插件前端都能以他人 plugin_id 触发其命令副作用。
#[tauri::command]
pub async fn plugin_invoke(
    webview: tauri::Webview,
    plugin_id: String,
    command: String,
    args: serde_json::Value,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<serde_json::Value> {
    authorize_plugin_call(&plugin_host, webview.label(), &plugin_id, &credential)?;
    plugin_host
        .invoke_rust_command(&plugin_id, &command, args)
        .await
}

/// 获取所有 Rust 插件的 command 列表
#[tauri::command]
pub async fn plugin_list_rust_commands(
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<Vec<wasmnest_plugin_api::PluginCommandEntry>> {
    Ok(plugin_host.list_rust_commands().await)
}

// ==================== Dev Mode ====================

/// 热重载 WASM 插件（仅开发模式可用）
///
/// 执行完整的卸载-重载-激活循环，用于开发期间快速迭代。
/// 生产构建中调用此命令返回错误
#[tauri::command]
pub async fn plugin_dev_reload(
    plugin_id: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    #[cfg(debug_assertions)]
    {
        plugin_host.reload_wasm_plugin(&plugin_id).await
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (plugin_host, plugin_id);
        Err(crate::AppError::Plugin(
            "Hot reload only available in dev mode".to_string(),
        ))
    }
}

// ==================== File System Auth ====================

/// 回复文件系统授权请求（由前端弹窗调用）
///
/// 决定取值见 [`FsDecision`](crate::security::fs_auth::FsDecision)：
/// `allow_once` / `allow_remember` / `deny` / `deny_always`（票 03 固定；「记住」只在
/// 「默认」档成立，「总是询问」档的弹窗根本不提供它）。
/// 未知决定值**显性报错**，不兜底成放行（与 [`plugin_network_auth_respond`] 同一口径）。
///
/// **只接受宿主面凭证**（loader 会话密钥，审计票 06）：授权请求事件是广播的，插件前端也
/// 能 `listen` 到，若该命令不绑身份，插件就能替用户「同意」自己的文件访问请求——
/// 那是把授权弹窗变成摆设。宿主弹窗 `FsAuthDialog.vue` 持宿主面凭证，插件拿不到。
#[tauri::command]
pub async fn plugin_fs_auth_respond(
    webview: tauri::Webview,
    request_id: String,
    decision: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
    fs_auth: State<'_, Arc<FsAuthChecker>>,
) -> crate::Result<()> {
    use crate::security::fs_auth::FsDecision;
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_fs_auth_respond",
        &credential,
        "file system authorization must be answered by the host frontend",
    )?;
    let decision = FsDecision::parse(&decision).ok_or_else(|| {
        crate::AppError::InvalidInput(format!(
            "未知文件授权决定 '{decision}'（允许 allow_once / allow_remember / deny / deny_always）"
        ))
    })?;
    tracing::info!(
        "[API] plugin_fs_auth_respond: request_id={}, decision={}",
        request_id,
        decision.as_str()
    );
    fs_auth.respond(&request_id, decision).await;
    Ok(())
}

// ==================== Network Auth（票 05） ====================

/// 回复网络出站授权询问（由前端弹窗调用）
///
/// **不复用 fs 侧的双布尔签名**（票 05 固定三态）：网络侧的询问粒度就是 origin，
/// 用户点头的语义是「这个地址可以访问」——不存在「只这一次、别记」的中间档。
/// `allow_once` 落 allow 记录（`source='user'`）、`deny_always` 落 deny 记录、
/// `deny` 不落账。未知决定值**显性报错**，不得兜底成放行（AGENTS §8 fail-visible）。
///
/// **只接受宿主面凭证**（与 [`plugin_fs_auth_respond`] 同一判据）：询问事件是广播的，
/// 插件前端也能 `listen` 到；不绑身份的话插件就能替用户「同意」自己的出站访问。
#[tauri::command]
pub async fn plugin_network_auth_respond(
    webview: tauri::Webview,
    request_id: String,
    decision: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
    net_auth: State<'_, Arc<crate::security::network_auth::NetworkAuthChecker>>,
) -> crate::Result<()> {
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_network_auth_respond",
        &credential,
        "network authorization must be answered by the host frontend",
    )?;
    let decision =
        crate::security::network_auth::NetworkDecision::parse(&decision).ok_or_else(|| {
            crate::AppError::InvalidInput(format!(
                "未知网络授权决定 '{decision}'（允许 allow_once / deny / deny_always）"
            ))
        })?;
    tracing::info!(
        "[API] plugin_network_auth_respond: request_id={}, decision={}",
        request_id,
        decision.as_str()
    );
    net_auth.respond(&request_id, decision).await;
    Ok(())
}

// ==================== 应用授权读模型（授权策略增强 · 票 01） ====================

/// 应用授权读模型（spec §9.3）：策略 + 授权记录 + 第一方免询问项
///
/// 设置页「应用授权」总览与应用详情页「授权记录」区块共用本命令，不各写一套查询。
/// `plugin_id` 为空 = 总览（全部已安装 wasm 应用）；指定时只返回该应用——未安装 /
/// 未知 id 返回空列表而不是错误：调用方只按列表里的 id 取值，且卸载后残留的策略
/// 与记录不应把界面变成报错页。
///
/// **只接受宿主面凭证**（与 [`plugin_fs_auth_respond`] 同一判据）：授权记录是安全闸门
/// 的配给账，插件面凭证不得用它枚举其它应用的授权情况。
///
/// 只列携带 wasm 后端的应用（`pluginType` 为 backend / full）：授权策略与记录只对经 fs / http 原语的
/// 应用成立，纯宿主侧插件没有可管理的授权面。
#[tauri::command]
pub async fn plugin_auth_overview(
    webview: tauri::Webview,
    plugin_id: Option<String>,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
    db: State<'_, Arc<std::sync::Mutex<crate::db::Database>>>,
    // 票 08/P0-2：第一方免弹窗项的产品清单出厂 lib，读模型经宿主装配的校验器取
    // 只读投影（与 plugin_fs_auth_respond 同一 State，已注册）
    fs_auth: State<'_, Arc<FsAuthChecker>>,
) -> crate::Result<Vec<crate::security::auth_policy::PluginAuthOverview>> {
    use crate::security::auth_policy::AuthPolicyStore;
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_auth_overview",
        &credential,
        "plugin authorization overview must be requested by the host frontend",
    )?;

    let store = AuthPolicyStore::new(db.inner().clone());
    let first_party_projection = fs_auth.first_party_trusted_dirs();
    let mut apps: Vec<HostPluginInfo> = plugin_host
        .list_plugins()
        .await
        .into_iter()
        .filter(|info| info.plugin_type.has_backend())
        .collect();
    if let Some(target) = plugin_id.as_deref() {
        apps.retain(|info| info.id == target);
    }

    let mut out = Vec::with_capacity(apps.len());
    for info in &apps {
        out.push(
            store
                .overview(&info.id, &info.name, first_party_projection.clone())
                .await?,
        );
    }
    tracing::debug!(
        plugin_id = plugin_id.as_deref().unwrap_or("(all)"),
        app_count = out.len(),
        "[API] plugin_auth_overview：读模型已装配"
    );
    Ok(out)
}

/// 设置某应用在某资源上的授权策略档位（spec §4.1 三档；设置页策略控件的唯一写入口）
///
/// 管理面命令（宿主面凭证）：档位是安全闸门的松紧，插件面不得替用户改自己的档位。
/// 未知档位值**显性报错**——写面不猜档位：把 `always_allow` 手误写错却静默存成
/// `default`，用户会以为设置成功了（见 `AuthStrategy::parse_wire`）。
#[tauri::command]
pub async fn plugin_auth_set_strategy(
    webview: tauri::Webview,
    plugin_id: String,
    resource: String,
    strategy: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
    db: State<'_, Arc<std::sync::Mutex<crate::db::Database>>>,
) -> crate::Result<()> {
    use crate::security::auth_policy::{AuthPolicyStore, AuthResource, AuthStrategy};
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_auth_set_strategy",
        &credential,
        "authorization strategy must be set by the host frontend",
    )?;
    let resource = AuthResource::parse(&resource).ok_or_else(|| {
        crate::AppError::InvalidInput(format!("未知授权资源 '{resource}'（允许 fs / network）"))
    })?;
    let strategy = AuthStrategy::parse_wire(&strategy).ok_or_else(|| {
        crate::AppError::InvalidInput(format!(
            "未知授权档位 '{strategy}'（允许 always_ask / default / always_allow）"
        ))
    })?;

    AuthPolicyStore::new(db.inner().clone())
        .set_strategy(&plugin_id, resource, strategy)
        .await?;
    tracing::info!(
        plugin_id = %plugin_id,
        resource = resource.as_str(),
        strategy = strategy.as_str(),
        "[API] plugin_auth_set_strategy：策略档位已更新（判定侧实时读取）"
    );
    Ok(())
}

/// 撤销某目标的授权（spec §8.4：删除该目标的 allow 记录 + 落一条 `deny` 记录）
///
/// 管理面命令（宿主面凭证）：撤销是安全决策——插件面不得替用户撤掉或保留自己的授权。
/// 返回被删除的 allow 行数（0 表示该目标本就没有 allow 记录）。
#[tauri::command]
pub async fn plugin_auth_revoke(
    webview: tauri::Webview,
    plugin_id: String,
    resource: String,
    target: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
    db: State<'_, Arc<std::sync::Mutex<crate::db::Database>>>,
) -> crate::Result<usize> {
    use crate::security::auth_policy::{AuthPolicyStore, AuthResource};
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_auth_revoke",
        &credential,
        "authorization revoke must be requested by the host frontend",
    )?;
    let resource = AuthResource::parse(&resource).ok_or_else(|| {
        crate::AppError::InvalidInput(format!("未知授权资源 '{resource}'（允许 fs / network）"))
    })?;

    let removed = AuthPolicyStore::new(db.inner().clone())
        .revoke(&plugin_id, resource, &target)
        .await?;
    tracing::info!(
        plugin_id = %plugin_id,
        resource = resource.as_str(),
        target = %target,
        removed_records = removed,
        "[API] plugin_auth_revoke：已撤销授权并落 deny 记录"
    );
    Ok(removed)
}

/// 移除某目标的 deny 记录（spec §8.4 的恢复出口：只删 deny，回到未覆盖状态）
///
/// 管理面命令（宿主面凭证）。返回删除的 deny 行数（0 = 本就没有 deny 记录）。
#[tauri::command]
pub async fn plugin_auth_remove_record(
    webview: tauri::Webview,
    plugin_id: String,
    resource: String,
    target: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
    db: State<'_, Arc<std::sync::Mutex<crate::db::Database>>>,
) -> crate::Result<usize> {
    use crate::security::auth_policy::{AuthPolicyStore, AuthResource};
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_auth_remove_record",
        &credential,
        "authorization record removal must be requested by the host frontend",
    )?;
    let resource = AuthResource::parse(&resource).ok_or_else(|| {
        crate::AppError::InvalidInput(format!("未知授权资源 '{resource}'（允许 fs / network）"))
    })?;

    let removed = AuthPolicyStore::new(db.inner().clone())
        .remove_deny(&plugin_id, resource, &target)
        .await?;
    tracing::info!(
        plugin_id = %plugin_id,
        resource = resource.as_str(),
        target = %target,
        removed_records = removed,
        "[API] plugin_auth_remove_record：已移除拒绝记录"
    );
    Ok(removed)
}

// ==================== Tests ====================

/// 从本地 zip 分发包安装插件（dev 合入）
///
/// 仅接收已下载的本地文件路径：解压与身份/路径校验在 Rust 端完成。
/// `upgrade`（应用版本更新链路，缺省 false）：对同 id **用户安装**插件就地升级
/// （保数据换代码，运行中 / 非 user-installed 拒绝，见 `install.rs::install_from_zip`）。
#[tauri::command]
pub async fn plugin_install_from_file(
    webview: tauri::Webview,
    path: String,
    credential: String,
    upgrade: Option<bool>,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<String> {
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_install_from_file",
        &credential,
        "plugin installation must be requested by the host frontend",
    )?;
    let upgrade = upgrade.unwrap_or(false);
    tracing::info!(path = %path, upgrade, "[API] plugin_install_from_file");
    let result = plugin_host.install_from_zip(&path, upgrade).await;
    if let Err(ref e) = result {
        tracing::error!(error = %e, "[API] plugin_install_from_file failed");
    }
    result
}

/// 卸载插件（所有来源；要求插件未启用，dev 合入）
#[tauri::command]
pub async fn plugin_uninstall(
    webview: tauri::Webview,
    plugin_id: String,
    credential: String,
    plugin_host: State<'_, Arc<PluginHost>>,
) -> crate::Result<()> {
    require_host_surface(
        &plugin_host,
        webview.label(),
        "plugin_uninstall",
        &credential,
        "plugin uninstallation must be requested by the host frontend",
    )?;
    tracing::info!(plugin_id = %plugin_id, "[API] plugin_uninstall");
    let result = plugin_host.uninstall_plugin(&plugin_id).await;
    if let Err(ref e) = result {
        tracing::error!(plugin_id = %plugin_id, error = %e, "[API] plugin_uninstall failed");
    }
    result
}

#[cfg(test)]
mod tests {
    //! 本模块（Tauri commands 桥）大部分不可单测的原因：
    //!
    //! 1. 所有 command 函数的第一个/最后一个参数均为
    //!    `State<'_, Arc<PluginHost>>`（或 `State<'_, Arc<FsAuthChecker>>`），
    //!    Tauri 的 `State` 不实现 `From<T>`，且其 `CommandArg` 实现需要
    //!    Tauri 运行时上下文（`StateManager`）才能构造 —— 单元测试无法
    //!    直接调用这些函数。
    //! 2. 启用 `tauri` 的 `test` feature（`tauri::test::mock_builder`）可
    //!    模拟运行时，但需要修改 Cargo.toml（本任务约束：只加测试模块），
    //!    且桥接函数体全部是「权限门禁 + 委托给 PluginHost / FsAuthChecker」
    //!    的薄封装，无独立纯逻辑可提取。
    //! 3. 门禁逻辑（`is_activated` / `permission().check`）与委托目标
    //!    （`list_plugins` / `activate_plugin` / `invoke_rust_command` /
    //!    `storage()` 等）均已在 `host.rs` 测试中直接覆盖（含错误分支的
    //!    错误字符串断言），桥接层只是透传。
    //! 4. 宿主面门禁（ADR 0058 方案 A 起 `require_host_surface` 委托
    //!    `frontend_channel::require_host_identity`）：其可测逻辑（宿主面凭证放行、
    //!    插件面令牌即使目标是自己也拒绝、跨 webview 域隔离）已在该模块单测覆盖，
    //!    桥接层仍是薄委托（Err 时换用调用方传入的 denial 文案），不另测。
    //!
    //! 结论：不硬造测试；桥接层行为由 host.rs 的宿主测试 + 前端集成测试
    //! 覆盖。`plugin_terminal_send_input` 的写入委托目标（会话窄转发层
    //! `session_gateway::input` → 插件 `session-input`）由 `session_e2e` 闭环用例
    //! 覆盖，桥接层自身只剩门禁三段。
    //!
    //! 若未来启用 tauri test feature，可在此处为 `plugin_storage_*` /
    //! `plugin_terminal_send_input` 的门禁错误分支补测试。
    //!
    //! 例外：`plugin_frontend_load_report` 不依赖任何 State 参数（纯日志透传），
    //! 可直接调用测试。
    //!
    //! **已注销会话命令面的防回接锁**（扫宿主源码，票 08）已随票 08 批次三迁
    //! 桌面宿主测试面（`src-tauri/tests/retired_session_command_lock.rs`）——
    //! 它读宿主源码，属平台侧判据；内核测试面只剩 `plugin_frontend_load_report`
    //! 一条纯本地用例。

    /// 诊断上报命令：ok/error 两条路径都只写 tracing，恒返回 Ok（issue 04）
    #[tokio::test]
    async fn frontend_load_report_always_ok() {
        let ok_report = super::plugin_frontend_load_report(
            "com.wasmnest.demo".into(),
            "import".into(),
            true,
            None,
        )
        .await;
        let fail_report = super::plugin_frontend_load_report(
            "com.wasmnest.demo".into(),
            "activate".into(),
            false,
            Some("import timeout".into()),
        )
        .await;
        assert!(ok_report.is_ok());
        assert!(fail_report.is_ok());
    }
}
