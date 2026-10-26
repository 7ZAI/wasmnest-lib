//! HTTP 传输面路由装配：公开端点 + `/api` scope
//!
//! 从 `core/app.rs` 拆出（票 07）：两个公开 HTTP 端点（`health_check` /
//! `terminal_bg_image`）与 `/api` scope（含其 `wrap` 链）整块搬入——注册顺序与
//! `wrap` 相对次序**一字不改**（`Scope::wrap` 后注册者先执行，网关写在验签之前
//! 是硬约束，见 `configure_routes` 内注释）。此后 HTTP 面的路由改动只落在本文件。
//!
//! 常量语义分工：`API_HEALTH_PATH` 归本面（`/api/health` 健康检查路由）；
//! `WS_EVENT_PATH` 归 WS 面（`wasmnest-server-websocket` 的 `routes.rs`）——端点常量不留在
//! 组合物里，避免「内核知道具体路由」的错觉。
//!
//! 依赖方向（不变量 I2 / I1）：本文件只**向下**依赖 `wasmnest-server-core` 与系统常量，
//! 与 `websocket` 面零横向 import（I1，票 08 加锁）。

use actix_web::{web, HttpResponse};
use serde_json::json;

use crate::controllers::plugin_controller;
use wasmnest_server_base::constants::API_HEALTH_PATH;

/// 健康检查端点 — 移动端 WS 连接前探测桌面端是否可达
async fn health_check() -> HttpResponse {
    let supervisor = wasmnest_server_core::supervisor::ServerSupervisor::global();
    let status_info = supervisor.get_status_info().await;
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "port": status_info.port,
        "uptime_secs": status_info.uptime_secs,
    }))
}

/// 背景图片扩展名 → Content-Type 映射
fn terminal_bg_content_type(ext: &str) -> &'static str {
    match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    }
}

/// 终端背景图片静态端点 — 公开，无需 JWT（CSS background-image 无法携带认证头）
///
/// **ABI v29 下沉（HTTP 路由代码注册）**：URL 归属由插件注册声明（`/static/terminal-bg`，
/// auth:none），本路由按动态注册表门控——插件未注册 / 属主未激活 → 404（URL 生命周期
/// 归插件）。文件读取保留宿主（spec §7 待决已决）：背景图在宿主应用数据目录，而
/// host-fs 只有文本读取（`fs:read` 返回 String，图像二进制不可经插件读），故「宿主读
/// 文件」是二进制通道缺口下的引擎残留，渲染逻辑（URL 声明 / 档位 / 生命周期）归插件。
///
/// 返回应用数据目录中的 `terminal_bg.<ext>`；未设置时返回 404。
/// 仅扫描白名单扩展名的固定前缀文件，不接受任意路径参数，无目录穿越风险。
/// 图片为用户自选的壁纸，不含敏感信息，局域网可见可接受。
async fn terminal_bg_image() -> HttpResponse {
    use wasmnest_server_base::constants::{TERMINAL_BG_EXTENSIONS, TERMINAL_BG_FILE_PREFIX};

    // 注册表门控（ABI v29）：URL 由插件注册归属；未注册 / 属主未激活 → 404
    let Some(host_match) = crate::registry::find_by_host("/static/terminal-bg", "GET") else {
        return HttpResponse::NotFound().finish();
    };
    // 宿主壳注入的 PluginInvoker 端口；无端口（无头/测试上下文）→ 插件面不可判定
    // → 保守 404（与既有「无 AppContext → false」同语义）
    let activated = match wasmnest_server_base::ports::get() {
        Some(ports) => ports.plugin_invoker.is_activated(&host_match.entry.owner).await,
        None => false,
    };
    if !activated {
        return HttpResponse::NotFound().finish();
    }

    // 宿主壳注入的 PathsPort；无端口（无头/测试上下文无 AppHandle）→ 视为未设置背景图
    let data_dir = match wasmnest_server_base::ports::get() {
        Some(ports) => match ports.paths.app_data_dir() {
            Ok(dir) => dir,
            Err(e) => {
                tracing::error!("解析应用数据目录失败: {e}");
                return HttpResponse::InternalServerError().finish();
            }
        },
        None => return HttpResponse::NotFound().finish(),
    };

    // 扫描目录找到当前背景图片（扩展名在选图时可能变化，不能写死）
    let entries = match tokio::fs::read_dir(&data_dir).await {
        Ok(entries) => entries,
        Err(_) => return HttpResponse::NotFound().finish(),
    };

    let prefix = format!("{TERMINAL_BG_FILE_PREFIX}.");
    let mut found: Option<std::path::PathBuf> = None;
    let mut iter = entries;
    while let Ok(Some(entry)) = iter.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(ext) = name.strip_prefix(&prefix) {
            if TERMINAL_BG_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()) {
                found = Some(entry.path());
                break;
            }
        }
    }

    let Some(path) = found else {
        return HttpResponse::NotFound().finish();
    };

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match tokio::fs::read(&path).await {
        Ok(bytes) => HttpResponse::Ok()
            .content_type(terminal_bg_content_type(&ext))
            // 前端通过 ?t= 时间戳防缓存，服务端不额外下发长缓存头
            .insert_header(("Cache-Control", "no-cache"))
            .body(bytes),
        Err(e) => {
            tracing::error!("读取终端背景图片失败 {}: {e}", path.display());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 构建 HTTP 路由配置：两个公开端点 + `/api` scope
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    // 健康检查（公开，无需 JWT，供移动端探测连通性）
    cfg.route(API_HEALTH_PATH, web::get().to(health_check));

    // 终端背景图片（公开，无需 JWT；CSS background-image 无法携带认证头）——
    // ABI v29 起按动态注册表门控（URL 由插件注册归属）
    cfg.route("/static/terminal-bg", web::get().to(terminal_bg_image));

    // /api scope — 中间件顺序即请求顺序：JWT 验签 → HTTP 协议网关 → 路由
    // 顺序是硬约束（票 01）：网关只能在验签之后介入，业务 JWT 的验签执行点不下沉；
    // 由 server/gateway.rs 的 unverified_requests_never_reach_gateway 在真实 actix 栈上钉死
    cfg.service(
        web::scope("/api")
            // 注册顺序 = 由内到外（`Scope::wrap` 后注册者先执行），故业务网关在前、认证闸门在后。
            // 顺序语义由 server/gateway.rs 的中间件用例钉死；即便写反，业务网关的「已认证」
            // 前置也会把未认证的业务请求挡在插件之外（降级宿主，由认证闸门 401）。
            .wrap(actix_web::middleware::from_fn(crate::gateway::business_gateway))
            .wrap(actix_web::middleware::from_fn(
                crate::middleware::auth_gateway::auth_gateway,
            ))
            // ABI v29（HTTP 路由代码注册下沉）：/api/sessions* 七条与 /api/auth/* 七条
            // 已随终端插件 activate 期代码注册接管（host-http.register-endpoint 模板别名），
            // 宿主不再注册任何业务路由——网关查动态注册表转发；未注册 → 404
            // 插件动态 HTTP 端点代理 — 中间件允许 JWT 或 plugin token
            .route(
                "/plugin/{plugin_id}/{path:.*}",
                web::route().to(plugin_controller::plugin_http_endpoint),
            ),
    );
}
