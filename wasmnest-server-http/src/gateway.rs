//! HTTP 协议网关 — 平台基础服务（HTTP 路由代码注册下沉专项，ABI v29）
//!
//! ## 它是什么
//!
//! 宿主 HTTP 传输面的路由**登记权**已整体移交插件（用户裁定 ④）：插件经
//! `host-http.register-endpoint` 在运行时注册自身路由（含对外 URL 别名、方法、
//! 认证档位），宿主只保留四件事——通用注册表（本 crate `registry`）、通用判定
//! （本文件 [`decide`]）、通用转发（复用 `plugin_controller::forward_to_plugin`）、
//! 认证闸门（`middleware/auth_gateway`，v33 起只问认证中心不本地验签）。本模块**零业务路由常量**：不再持有任何
//! 业务 URL 别名表 / 业务域枚举 / 硬编码插件 id。
//!
//! ## 三条不变量
//!
//! 1. **形状不变**：对外 URL、方法、响应 JSON 与迁移前逐字节一致。URL 别名由
//!    插件注册声明（含 `{id}` 模板段），网关按注册表精确/模板匹配，模板捕获值
//!    经 `params` 字段传给插件；响应形状契约锁在本文件测试段。
//! 2. **认证在网关之外**：认证裁决下沉认证中心插件（v33 / ADR 0033，宿主不再持有
//!    任何设备 JWT 密码学），网关只挂在认证闸门（`middleware/auth_gateway`）**之后**；
//!    转发只透传认证中心交回的连接身份派生的设备标识与 `caller` 三档调用方身份，
//!    **凭证本体与指纹不出宿主**。档位判定统一在网关（只有网关看得见注册表档位）：
//!    `jwt` 档要求已通过认证，`none` 档免认证转发。
//! 3. **不发明传输机制**：转发复用 `http/controllers/plugin_controller` 的同一内核
//!    （[`forward_to_plugin`]）与同一请求构造（headers 白名单 / status/contentType
//!    解析口径）。
//!
//! ## 未命中与降级
//!
//! - 未命中注册别名 → 原样放行交路由表（404 / 宿主自持端点照旧）；
//! - 命中但属主插件未激活（注册在册与停用之间的竞态）→ 明确报「插件未激活」
//!   （HTTP 200 + 业务码 1007，与 `/api/plugin/*` 面同口径）；
//! - 命中但档位 `jwt` 而本次未验签 → 401 + 业务码 1007（报「要认证」而非
//!   「插件未激活」，方向不能指错）。
//!
//! 停用回收：插件停用 → 宿主清空其全部注册路由（`registry::purge_for_plugin`），
//! 未激活插件的别名不再可达（404，fail-visible，不静默占用对外 URL 空间）。

use actix_web::body::MessageBody;
use actix_web::dev::{Payload, ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{web, Error, FromRequest, HttpResponse};
use serde_json::Value;

use crate::controllers::plugin_controller::{
    caller_identity, filter_plugin_request_headers, forward_to_plugin, HttpCaller, PluginHttpRequest,
};
use crate::dtos::{ApiResponse, CODE_INVALID_REQUEST, CODE_PLUGIN_AUTH_FAILED};
use crate::registry;
use crate::wire::EndpointAuth;

// ==================== 网关判定 ====================

/// 网关对一次请求的处置
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayDecision {
    /// 命中注册别名且判定通过 → 切插件路径
    Forward,
    /// 属主插件未激活（注册在册与停用之间的竞态）→ 明确报「插件未激活」
    PluginRequired,
    /// 端点档位要求已验签而本次请求没有 → 401
    ///
    /// 单独一档而不是回 [`GatewayDecision::PluginRequired`]：那会把「你没登录」报成
    /// 「插件未激活」，指错方向。
    AuthRequired,
    /// 未命中注册别名 / 插件面不可判定 → 原样放行交路由表
    PassThrough,
}

/// 降级判定（纯函数，转发条件的单一事实源）
///
/// - `entry_auth`：注册档位（`jwt` 要求宿主已验签；`none` 免验签转发）。
/// - `verified`：宿主 JWT 中间件是否已验签并注入 claims（[`caller_identity`] 的
///   device 档）。**需要验签时绝不转发**——这道守卫是网关自身的性质，不依赖
///   中间件注册顺序（顺序错乱时最多多拒一次，不会漏验签）。
/// - `activated`：属主插件是否激活。注册在册而属主停用（竞态）→ 明确报
///   「插件未激活」而非把请求交给不存在的插件。
pub fn decide(entry_auth: EndpointAuth, verified: bool, activated: bool) -> GatewayDecision {
    if !activated {
        return GatewayDecision::PluginRequired;
    }
    if entry_auth == EndpointAuth::Jwt && !verified {
        return GatewayDecision::AuthRequired;
    }
    GatewayDecision::Forward
}

/// 「插件未激活」响应：与 `/api/plugin/*` 路由的未激活响应同口径（HTTP 200 + 业务码 1007）
fn plugin_unavailable_response(entry: &registry::HttpRouteEntry) -> HttpResponse {
    tracing::warn!(
        plugin_id = %entry.owner,
        host_path = %entry.host_path.as_deref().unwrap_or("(internal)"),
        "业务端点不可用（属主插件未激活）"
    );
    HttpResponse::Ok().json(ApiResponse::<()>::error(
        CODE_PLUGIN_AUTH_FAILED,
        &format!("Plugin {} is not activated", entry.owner),
    ))
}

/// 转发失败时的显式错误响应（与宿主业务端点的错误口径一致：HTTP 200 + 业务码）
fn bad_request(message: &str) -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::<()>::error(CODE_INVALID_REQUEST, message))
}

/// 「调用方未验签」响应：HTTP 401 + 业务码 1007，与 JWT 中间件的 401 同一码
///
/// 这条分支生产链路正常走不到（中间件在网关之外已把无 JWT 的 `jwt` 档请求 401），
/// 它是「中间件顺序被改错」时的兜底，所以回 401 而不是回「插件未激活」。
fn unauthorized_response(path: &str) -> HttpResponse {
    HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
        CODE_PLUGIN_AUTH_FAILED,
        &format!("Authentication required for {}", path),
    ))
}

/// 查询串 → 转发用 JSON 对象
///
/// 复用 `web::Query<HashMap<String,String>>`——与 `/api/plugin/*` 路由同一个提取器，因此
/// 百分号转义、重复键（后者覆盖前者）、非 UTF-8 序列（lossy 替换）的口径与宿主逐字一致。
/// 该目标类型下提取实际不会失败，但错误仍走「显式拒绝」而非 `expect`：这条路对局域网
/// 可达（0.0.0.0），panic 即 DoS 面。
fn query_object(query_string: &str) -> Result<Value, String> {
    match web::Query::<std::collections::HashMap<String, String>>::from_query(query_string) {
        Ok(q) => Ok(Value::Object(
            q.into_inner().into_iter().map(|(k, v)| (k, Value::String(v))).collect(),
        )),
        Err(e) => {
            tracing::warn!(error = %e, query = %query_string, "业务端点查询串解析失败");
            Err(format!("Invalid query string: {e}"))
        }
    }
}

/// 请求体 → 转发用 JSON
///
/// 三种情形分开：
/// - 无载荷 → `Null`（与 `_http_endpoint` 的 `Option<Json>` 同口径，GET 端点即此分支）；
/// - 合法 JSON → 原样交给插件（不重新序列化宿主 DTO，避免未知字段被丢弃）；
/// - 有载荷但非 JSON → 显式失败（业务端点今天的宿主行为是拒绝，不许静默当空请求）。
async fn body_value(req: &actix_web::HttpRequest, payload: &mut Payload) -> Result<Value, String> {
    let bytes = match web::Bytes::from_request(req, payload).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "业务端点请求体读取失败");
            return Err(format!("Failed to read request body: {e}"));
        }
    };
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice::<Value>(&bytes).map_err(|e| format!("Invalid JSON body: {e}"))
}

/// 网关中间件：注册别名（精确 + 模板）→ 插件，其余请求原样放行
///
/// 挂在 `/api` scope 的 JWT 中间件**之后**（`Scope::wrap` 后注册者先执行，故本中间件注册在
/// 验签之前；顺序语义见 [`scope_wrap_registration_puts_jwt_outermost`]）。即便接线顺序被改错，
/// [`decide`] 的 `verified` 前置也会挡住未验签请求进插件。
pub(crate) async fn business_gateway<B>(req: ServiceRequest, next: Next<B>) -> Result<ServiceResponse, Error>
where
    B: MessageBody + 'static,
{
    let path = req.path().to_string();
    let method = req.method().as_str().to_string();
    // 未命中注册别名（精确匹配 + `{id}` 模板匹配）→ 原样放行交路由表
    let Some(host_match) = registry::find_by_host(&path, &method) else {
        return next.call(req).await.map(|res| res.map_into_boxed_body());
    };
    let entry = host_match.entry.clone();

    // 调用方身份（票 08）：device 档 = 宿主 JWT 中间件已验签并注入 claims。
    // 环回 / 匿名两档只在插件把该端点显式注册成 `auth: "none"` 时才可能走到转发。
    let (caller, device) = caller_identity(req.request());
    let verified = matches!(caller, HttpCaller::Device);
    // 无端口（无头 / 库级测试 / 初始化中间态）= 插件面不可判定 → 交回链条，
    // 绝不凭注册表就把请求递给不存在的插件
    let decision = match wasmnest_server_base::ports::get() {
        None => GatewayDecision::PassThrough,
        Some(ports) => {
            let activated = ports.plugin_invoker.is_activated(&entry.owner).await;
            decide(entry.auth, verified, activated)
        }
    };
    tracing::debug!(
        path = %path,
        plugin_id = %entry.owner,
        endpoint = %entry.path,
        caller = %caller.as_str(),
        forward = matches!(decision, GatewayDecision::Forward),
        "HTTP 协议网关判定"
    );

    match decision {
        GatewayDecision::PassThrough => next.call(req).await.map(|res| res.map_into_boxed_body()),
        GatewayDecision::PluginRequired => {
            let (http_req, _payload) = req.into_parts();
            Ok(ServiceResponse::new(http_req, plugin_unavailable_response(&entry)))
        }
        GatewayDecision::AuthRequired => {
            tracing::warn!(
                path = %path,
                plugin_id = %entry.owner,
                caller = %caller.as_str(),
                "业务端点要求已验签调用方，本次请求未通过宿主 JWT 验签"
            );
            let (http_req, _payload) = req.into_parts();
            Ok(ServiceResponse::new(http_req, unauthorized_response(&path)))
        }
        GatewayDecision::Forward => {
            // 判定完成才开始消费载荷：query / headers / claims 只读，body 走 payload
            let headers = filter_plugin_request_headers(req.headers());
            let query = match query_object(req.query_string()) {
                Ok(v) => v,
                Err(msg) => {
                    let (http_req, _payload) = req.into_parts();
                    return Ok(ServiceResponse::new(http_req, bad_request(&msg)));
                }
            };
            let (http_req, mut payload) = req.into_parts();
            let body = match body_value(&http_req, &mut payload).await {
                Ok(v) => v,
                Err(msg) => return Ok(ServiceResponse::new(http_req, bad_request(&msg))),
            };
            // 模板捕获参数（`{id}` 段）随请求注入插件；精确命中时为空对象
            let params = host_match
                .params
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
            let request = PluginHttpRequest {
                endpoint_path: &entry.path,
                method: &method,
                headers,
                body,
                query,
                params,
                caller,
                device,
            };
            let resp = forward_to_plugin(&entry.owner, &request).await;
            Ok(ServiceResponse::new(http_req, resp))
        }
    }
}

// ==================== Tests ====================

// ==================== Tests ====================

// 用例按功能拆至 `gateway/tests/`（本内联模块的子模块路径由 rustc
// 自动解析到该目录；模块树 `gateway::tests::<文件>` 与内联形态等价，私有项可见性不受影响）。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::controllers::plugin_controller::build_plugin_http_args;
    use crate::middleware::auth_gateway::auth_gateway;
    mod business_endpoint_shapes;
    mod decide_forwards_only_when;
    mod forwarded_request_shape;
    mod scaffold;
}
