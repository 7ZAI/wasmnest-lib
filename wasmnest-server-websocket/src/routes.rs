//! WebSocket 传输面路由装配：通用插件端点 + 帧上限
//!
//! 从 `core/app.rs` 拆出（票 07）：WS 握手 handler（`plugin_endpoint_ws`）、
//! 属主激活闸门（`endpoint_owner_activated`）与帧上限（`ws_frame_limit`）都是
//! 纯 WS 面语义，寄居单端口组合物是历史错位——此后 WS 面的路由改动只落在本文件。
//!
//! **终态（websocket 业务下沉票 08）**：业务路由 `/ws/event` 与
//! `/ws/terminal/session/{id}` 已删除，宿主只留 `/ws/plugin/{plugin_id}/{path}`
//! 一个握手端点；旧路径请求得到宿主通用 404，不提供 alias 或 fallback
//! （spec §2.1 / §8.2 结构锁：路由字符串只允许出现在迁移说明/测试反例）。
//!
//! 依赖方向（不变量 I2 / I1）：本文件只**向下**依赖 `wasmnest-server-core` 与系统常量，
//! 与 `http` 面零横向 import（I1，票 08 加锁）。

use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws as actix_ws;

use crate::channel::plugin::PluginChannel;
use crate::conn::{ConnSpec, WsConnBase};
use crate::registry::WsSessionRegistry;
use wasmnest_server_base::constants::PLACEHOLDER_PEER_ADDR;

/// WS 帧/消息大小上限（字节）
///
/// max_size 同时限制 frame 和 message 大小，取两者中较大的值；
/// host-websocket（ABI v14）客户端域/服务端域的帧上限与插件端点共用同一计算
/// （spec §4.4）
///
/// `pub`：宿主 `host-websocket` 原语（`wasm_core/host_api/ws.rs`）按同一上限做
/// 插件域/客户端域裁剪——上限只有一个真源，跨 crate 供读是刻意的。
pub fn ws_frame_limit() -> usize {
    // 宿主壳经 ConfigPort 注入（拆 lib 后 ws 面不反向引用宿主 AppConfig）；
    // 无端口（无头/单测）取缺省值
    let config = match wasmnest_server_base::ports::get() {
        Some(ports) => ports.config.network(),
        None => wasmnest_server_base::config::NetworkConfig::default(),
    };
    std::cmp::max(
        config.ws_max_frame_size_kb * 1024,
        config.ws_max_message_size_mb * 1024 * 1024,
    )
}

/// 插件端点 WS 握手端点 — `/ws/plugin/{plugin_id}/{path}`（spec D5）
///
/// 通配单点分发（不依赖 actix 动态加路由）：路径 → 端点表反查 → 未注册端点 /
/// 属主未激活 → 404；入站客户端数超上限 → 503（**协议升级前**拒绝，不产生
/// 连接事件，spec §4.4）。认证策略由端点声明（`auth: none | jwt`，spec D8）。
async fn plugin_endpoint_ws(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    stream: web::Payload,
) -> Result<HttpResponse, Error> {
    let (plugin_id, suffix) = path.into_inner();
    let mount = crate::endpoint::mount_path(&plugin_id, &suffix);
    let Some(entry) = crate::endpoint::find_by_mount(&mount) else {
        tracing::debug!(mount_path = %mount, "plugin ws endpoint not registered, rejecting 404");
        return Ok(HttpResponse::NotFound().finish());
    };

    // 属主未激活 → 404（停用流程已回收端点，此处为防御性门禁）
    if !endpoint_owner_activated(&plugin_id).await {
        tracing::debug!(
            plugin_id = %plugin_id,
            mount_path = %mount,
            "plugin ws endpoint owner is not activated, rejecting 404"
        );
        return Ok(HttpResponse::NotFound().finish());
    }

    let addr = req
        .peer_addr()
        .unwrap_or_else(|| PLACEHOLDER_PEER_ADDR.parse().unwrap());
    let client_id = addr.to_string();
    if !WsSessionRegistry::global().reserve_endpoint_client(&entry.endpoint_id, &client_id, entry.max_clients) {
        tracing::warn!(
            plugin_id = %plugin_id,
            endpoint_id = %entry.endpoint_id,
            limit = entry.max_clients,
            "plugin ws endpoint client limit reached, rejecting before upgrade (503)"
        );
        return Ok(HttpResponse::ServiceUnavailable().finish());
    }

    let channel = PluginChannel::new(&entry, addr);
    let ws_actor = WsConnBase::new(
        ConnSpec {
            owner: Some(entry.owner.clone()),
            endpoint_id: Some(entry.endpoint_id.clone()),
            ..ConnSpec::new(addr)
        },
        Box::new(channel),
    );
    match actix_ws::WsResponseBuilder::new(ws_actor, &req, stream)
        .frame_size(entry.max_message_bytes)
        .start()
    {
        Ok(response) => Ok(response),
        Err(error) => {
            WsSessionRegistry::global().release_endpoint_reservation(&entry.endpoint_id, &client_id);
            Err(error)
        }
    }
}

/// 属主插件是否处于激活态
///
/// 跳过闸门的两种情形（端点本身只可能由运行中的插件注册，端点表存在性已是
/// 最强证据；停用流程会 `purge_for_plugin` 回收端点，本闸门只是防御性兜底）：
/// - 端口注册表未注入的运行上下文（库级测试 / 初始化中间态）；
/// - 宿主对该 `plugin_id` **没有任何记录**——此时无从判定，且说明该 id 从未
///   在本进程注册过（测试替身宿主 / 外来壳注入的端口实现）。
///   仅当宿主有记录且状态非激活时否决。
async fn endpoint_owner_activated(plugin_id: &str) -> bool {
    // 宿主壳注入的 PluginInvoker 端口：无端口（无头/单测上下文）→ 无从判定 →
    // 放行（端点本身只可能由运行中的插件注册，端点表存在性已是最强证据；
    // 停用流程会 purge_for_plugin 回收端点，本闸门只是防御性兜底）
    let Some(ports) = wasmnest_server_base::ports::get() else {
        return true;
    };
    ports.plugin_invoker.is_activated(plugin_id).await
}

/// 构建 WS 路由配置
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    // 插件端点通配路由（spec D5）：命名空间段 `{plugin_id}` 由宿主注入，
    // 插件只给后缀；未注册 / 属主未激活 → 404，连接数超限 → 503。
    // 旧 `/ws/event` 与 `/ws/terminal/session/{id}` 已随 websocket 业务下沉
    // 票 08 删除——旧客户端不在兼容范围（spec §0.4）。
    cfg.route("/ws/plugin/{plugin_id}/{path:.*}", web::get().to(plugin_endpoint_ws));
}
