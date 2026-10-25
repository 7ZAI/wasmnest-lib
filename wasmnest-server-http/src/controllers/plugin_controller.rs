//! Plugin Controller
//!
//! Routes:
//! - ANY /api/plugin/{plugin_id}/{path:.*} — 插件动态 HTTP 端点代理

use actix_web::{web, HttpRequest, HttpResponse};
use std::collections::HashMap;

use crate::wire::EndpointAuth;

use crate::dtos::{ApiResponse, CODE_INVALID_REQUEST, CODE_PLUGIN_AUTH_FAILED};
use crate::middleware::auth_gateway::get_authenticated_identity;

// ==================== 插件动态 HTTP 端点代理 ====================

/// 插件 HTTP 端点响应状态提取（纯函数，供测试）：`status` 字段缺失/非数字/越界
/// → 默认 200；仅接受 actix 合法区间 100..=999（原实现 `as u16` 截断在 >65535
/// 时会误放行截断后的合法码，此处用 try_from 拒绝截断）
pub(crate) fn plugin_http_status(response: &serde_json::Value) -> u16 {
    response
        .get("status")
        .and_then(|v| v.as_u64())
        .and_then(|s| u16::try_from(s).ok())
        .filter(|s| (100..=999).contains(s))
        .unwrap_or(200)
}

/// 调用方请求 headers 白名单（票据 04）：只透传业务相关头，
/// 避免透传全部请求头带来的凭据泄露与枚举面。
/// 凭据类头（authorization / cookie / proxy-authorization 等）一律不透传。
const PLUGIN_HEADER_WHITELIST: &[&str] = &["content-type", "accept", "x-request-id"];

/// 按白名单过滤调用方请求 headers（纯函数，供测试）
///
/// 返回插件可读的 headers 对象；白名单外（含全部凭据头）不进入结果。
pub(crate) fn filter_plugin_request_headers(
    headers: &actix_web::http::header::HeaderMap,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    for (key, value) in headers.iter() {
        let name = key.as_str().to_ascii_lowercase();
        if PLUGIN_HEADER_WHITELIST.contains(&name.as_str()) {
            if let Ok(v) = value.to_str() {
                out.insert(name, serde_json::Value::String(v.to_string()));
            }
        }
    }
    out
}

/// 插件响应 content-type 提取（票据 04）：`contentType` 字段指定响应类型；
/// 缺失/非法时返回 None（调用方保持默认 application/json）。
pub(crate) fn plugin_http_content_type(response: &serde_json::Value) -> Option<String> {
    response
        .get("contentType")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// 插件响应附加头提取（票 03）：`headers` 字段为 `{ "Header-Name": "value" }`
/// 字符串映射（如 file-tree-children 的 `Cache-Control`）；缺失/非法条目忽略。
/// 值只接受字符串——宿主不替插件解释或转换头值。
pub(crate) fn plugin_http_headers(response: &serde_json::Value) -> Vec<(String, String)> {
    let Some(headers) = response.get("headers").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    headers
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|value| (k.clone(), value.to_string())))
        .collect()
}

// ==================== 路由判定（纯函数，供测试固化） ====================

/// 端点认证判定（纯函数，票 08 / ABI v29）：登记档位 + 本次请求是否已过宿主验签 → 是否放行
///
/// `Jwt` 档要求 `verified`（宿主 JWT 中间件已注入 claims）；`None` 档免凭证，但仍
/// 携带 [`HttpCaller`] 身份，让插件自己按身份收紧（裁决 3）。
///
/// 路径声明判定（「只认登记、精确匹配」）已随 ABI v29 移交动态注册表
/// （本 crate `registry::find_by_internal`）——插件经 `host-http.register-endpoint`
/// 登记的内部路径即唯一可达面，未登记路径 404。
pub(crate) fn plugin_http_auth_allowed(auth: EndpointAuth, verified: bool) -> bool {
    match auth {
        EndpointAuth::Jwt => verified,
        EndpointAuth::None => true,
    }
}

/// 宿主判定的调用方身份（票 08 裁决 3）——转发给插件的 `caller` 字段取值
///
/// 三档互斥，按「已验签 > 环回 > 匿名」优先判定：
/// - [`HttpCaller::Device`]：JWT 验签通过的可信设备，`device` 字段带 claims 派生标识
/// - [`HttpCaller::Localhost`]：环回调用方（Claude Code / codex hook 脚本、本机工具），
///   无凭证可给，插件按「本机」这一固定标识区分
/// - [`HttpCaller::Anonymous`]：局域网内的匿名调用方（既未验签也非环回）
///
/// 凭据红线：任何一档都不带 JWT 本体与设备指纹（AGENTS.md §8）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpCaller {
    Device,
    Localhost,
    Anonymous,
}

impl HttpCaller {
    /// 转发字段取值（线协议字符串，插件侧按它分派）
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Localhost => "localhost",
            Self::Anonymous => "anonymous",
        }
    }

    /// 身份判定（纯函数，供测试）：`verified` = 宿主已验签注入 claims，
    /// `loopback` = TCP 对端是环回地址
    pub(crate) fn classify(verified: bool, loopback: bool) -> Self {
        match (verified, loopback) {
            (true, _) => Self::Device,
            (false, true) => Self::Localhost,
            (false, false) => Self::Anonymous,
        }
    }
}

/// 本次请求的调用方身份与可信设备上下文（`/api/plugin/*` 与业务网关共用一条判据）
///
/// 连接身份只在认证中心放行后注入（认证闸门 `auth_gateway`），因此 `device` 与
/// [`HttpCaller::Device`] 同源同步；设备上下文只取 claims 派生标识，
/// **JWT 本体与指纹不出宿主**（AGENTS.md §8 凭据红线）。
pub(crate) fn caller_identity(req: &actix_web::HttpRequest) -> (HttpCaller, Option<serde_json::Value>) {
    let identity = get_authenticated_identity(req);
    let loopback = req.peer_addr().is_some_and(|addr| addr.ip().is_loopback());
    let caller = HttpCaller::classify(identity.is_some(), loopback);
    let device = identity.map(|identity| {
        let mut device = serde_json::Map::new();
        device.insert("deviceId".to_string(), serde_json::Value::String(identity.device_id));
        if let Some(name) = identity.device_name {
            device.insert("deviceName".to_string(), serde_json::Value::String(name));
        }
        serde_json::Value::Object(device)
    });
    (caller, device)
}

/// 该由哪个插件应答本次请求（纯决策，供测试）
///
/// 只认请求前缀自身：已激活 → 本人应答；未激活 → None（「未激活」错误响应）。
pub(crate) fn resolve_http_owner<'a>(requested: &'a str, requested_activated: bool) -> Option<&'a str> {
    if requested_activated {
        Some(requested)
    } else {
        None
    }
}

// ==================== 转发内核（插件前缀路由与 HTTP 协议网关共用） ====================

/// 一次业务 HTTP 请求转发到插件 `_http_endpoint` 所需的全部入参
///
/// `pub(crate)`：`server/gateway.rs` 的业务 URL 别名走的是同一个内核——「新增传输机制」
/// 是票 01 明确禁止的形态，两条路径必须共用请求构造与响应映射（含 headers 白名单、
/// status/contentType 解析口径），否则同一请求经网关与经 `/api/plugin/*` 会答出两版。
pub(crate) struct PluginHttpRequest<'a> {
    /// 去掉 `/api/plugin/{plugin_id}/` 前缀后的端点段（网关路径取别名目标的端点段）
    pub endpoint_path: &'a str,
    pub method: &'a str,
    /// 已按 [`PLUGIN_HEADER_WHITELIST`] 过滤的请求头
    pub headers: serde_json::Map<String, serde_json::Value>,
    pub body: serde_json::Value,
    pub query: serde_json::Value,
    /// 模板段捕获参数（ABI v29 动态路由：host 别名 `{id}` 模板的捕获值；
    /// 精确命中 / 无模板时为空）
    pub params: serde_json::Map<String, serde_json::Value>,
    /// 宿主判定的调用方身份（票 08 裁决 3：`device` / `localhost` / `anonymous`）
    pub caller: HttpCaller,
    /// 宿主验签后的可信设备上下文（仅 [`HttpCaller::Device`] 时有值）
    ///
    /// 只给 claims 派生的标识字段，**JWT 本体与指纹一律不透传**（AGENTS.md §8 凭据红线）。
    pub device: Option<serde_json::Value>,
}

/// 插件 `_http_endpoint` 入参构造（纯函数，供双轨契约测试逐字段锁定）
///
/// `headers` 字段为票据 04 增量追加、`device` 为票 01 网关追加、`caller` 为票 08 追加
/// ——都是字段级追加，老插件忽略未知字段（协议增量原则）。
pub(crate) fn build_plugin_http_args(req: &PluginHttpRequest) -> serde_json::Value {
    let mut args = serde_json::json!({
        "method": req.method,
        "path": req.endpoint_path,
        "headers": serde_json::Value::Object(req.headers.clone()),
        "body": req.body,
        "query": req.query,
        // 免凭证调用方不再「没有身份」：三档固定取值让插件能区分本机 hook 与局域网匿名
        "caller": req.caller.as_str(),
    });
    // 模板捕获参数（ABI v29 动态路由）：命中 `{id}` 模板的 host 别名请求才携带；
    // 无模板的请求给空对象（老插件忽略未知字段，字段演进增量原则）
    args["params"] = serde_json::Value::Object(req.params.clone());
    if let Some(device) = &req.device {
        args["device"] = device.clone();
    }
    args
}

/// 转发内核：调插件 `_http_endpoint` 并把 `{ status, body, contentType }` 映射为 HTTP 响应
///
/// 调用方必须先完成属主解析与端点登记判定（本 crate `registry::find_by_internal`）——
/// 本函数只做「送进去 + 把回包翻译成 HTTP」，不掺任何路由策略。
pub(crate) async fn forward_to_plugin(owner: &str, req: &PluginHttpRequest<'_>) -> HttpResponse {
    let request_args = build_plugin_http_args(req);
    // 宿主壳注入的 PluginInvoker 端口：无端口（无头/单测上下文）即插件面
    // 不可达 → 显性报错（与「插件未激活」同 fail-visible 语义，不静默透传）
    let Some(ports) = wasmnest_server_base::ports::get() else {
        return HttpResponse::Ok().json(ApiResponse::<()>::error(
            CODE_INVALID_REQUEST,
            "Plugin endpoint unavailable: no runtime context",
        ));
    };
    let result = ports
        .plugin_invoker
        .invoke_rust_command(owner, "_http_endpoint", request_args)
        .await;

    match result {
        Ok(response) => {
            // 插件返回格式：{ status: number, body: any, contentType?: string }
            let status = plugin_http_status(&response);
            let response_body = response.get("body").cloned().unwrap_or(serde_json::Value::Null);

            // contentType 可选：插件可指定（如 text/plain / image/png），默认 application/json
            let mut builder = HttpResponse::build(
                actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK),
            );
            if let Some(content_type) = plugin_http_content_type(&response) {
                builder.insert_header((actix_web::http::header::CONTENT_TYPE, content_type));
            }
            // headers 可选（票 03）：插件透传附加响应头（如 Cache-Control）
            for (name, value) in plugin_http_headers(&response) {
                match actix_web::http::header::HeaderName::try_from(name.clone()) {
                    Ok(header_name) => {
                        builder.insert_header((header_name, value));
                    }
                    Err(_) => {
                        tracing::warn!(header = %name, "plugin http endpoint: invalid response header name, skipped");
                    }
                }
            }
            builder.json(response_body)
        }
        Err(e) => {
            tracing::error!(
                "Plugin HTTP endpoint error: plugin_id={}, path={}, error={}",
                owner,
                req.endpoint_path,
                e
            );
            HttpResponse::Ok().json(ApiResponse::<()>::error(
                CODE_INVALID_REQUEST,
                &format!("Plugin endpoint error: {}", e),
            ))
        }
    }
}

/// 「调用方未验签」响应（票 08）：HTTP 401 + 业务码 1007，与 JWT 中间件的 401 同一码
///
/// 文案同时点名两条出路（带合法 JWT / 在 manifest 逐条声明 `auth: "none"`）——
/// 收紧后打不通的调用方必须能从错误里读出该改哪一侧，而不是只看到「authentication failed」。
pub(crate) fn plugin_http_unauthenticated_response(full_path: &str) -> HttpResponse {
    HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
        CODE_PLUGIN_AUTH_FAILED,
        &format!(
            "Plugin endpoint '{}' requires auth \"jwt\"; present a valid JWT or declare auth: \"none\" in contributes.httpEndpoints",
            full_path
        ),
    ))
}

/// ANY /api/plugin/{plugin_id}/{path:.*}
///
/// 插件动态 HTTP 端点 — 请求到达后通过 PluginHost.invoke_rust_command 路由到插件 handler。
/// 仅支持已激活的 Rust / WASM 插件，TS-only 插件的 HTTP 端点通过前端 Tauri event 桥接。
///
/// 认证：`auth_gateway` 中间件先问认证中心（放行时注入连接身份），本 handler 按**属主端点
/// 声明的档位**决定是否要求已验签（票 08）：manifest 未声明 `auth` 即最严档 `jwt`，
/// 免凭证必须逐条显式声明 `auth: "none"`。服务监听 0.0.0.0，收紧前「插件端点对局域网
/// 无凭证可达」正是本票处置的风险。
pub async fn plugin_http_endpoint(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    body: Option<web::Json<serde_json::Value>>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let (plugin_id, endpoint_path) = path.into_inner();

    // 中间件只对带凭证的请求问认证中心；本路由无凭证的请求（环回 hook、局域网匿名）
    // 放行到这里，由下面的端点级档位判定决定是否真的到达插件。

    // 检查插件是否已激活：未激活 → 未激活错误响应（fail-closed，不把请求交给
    // 不存在的插件；宿主壳注入的 PluginInvoker 端口，无端口（无头/单测）→ 无从
    // 判定 → 视为未激活）
    let Some(ports) = wasmnest_server_base::ports::get() else {
        return HttpResponse::Ok().json(ApiResponse::<()>::error(
            CODE_PLUGIN_AUTH_FAILED,
            &format!("Plugin {} is not activated (no runtime context)", plugin_id),
        ));
    };
    let requested_activated = ports.plugin_invoker.is_activated(&plugin_id).await;
    let owner = match resolve_http_owner(&plugin_id, requested_activated) {
        Some(owner) => owner,
        None => {
            return HttpResponse::Ok().json(ApiResponse::<()>::error(
                CODE_PLUGIN_AUTH_FAILED,
                &format!("Plugin {} is not activated", plugin_id),
            ))
        }
    };

    // 端点注册治理（ABI v29 动态路由）：只认插件经 host-http.register-endpoint 登记
    // 的内部路径（含 manifest 声明面退役后由插件激活期代码注册的全部端点），未注册
    // 路径 404——「未声明清单 → 前缀内 ANY 放行」的过渡策略已退役，未登记的插件
    // 没有 HTTP 面。声明按**属主插件**查，full_path 同样按属主拼——插件侧收到
    // 的 `path` 字段保持请求原样。
    let full_path = format!("/api/plugin/{}/{}", owner, endpoint_path);
    let Some(entry) = crate::registry::find_by_internal(&full_path) else {
        tracing::warn!(
            plugin_id = %owner,
            requested_plugin_id = %plugin_id,
            path = %full_path,
            "plugin http endpoint not registered (exact match required)"
        );
        return HttpResponse::NotFound().json(ApiResponse::<()>::error(
            CODE_INVALID_REQUEST,
            &format!("Plugin endpoint '{}' is not registered", full_path),
        ));
    };

    // 认证档位（ABI v29）：按属主登记档位判定，未声明 auth 即要求宿主已验签
    let (caller, device) = caller_identity(&req);
    if !plugin_http_auth_allowed(entry.auth, matches!(caller, HttpCaller::Device)) {
        tracing::warn!(
            plugin_id = %owner,
            path = %full_path,
            caller = %caller.as_str(),
            auth = %entry.auth.as_str(),
            "plugin http endpoint requires an authenticated caller"
        );
        return plugin_http_unauthenticated_response(&full_path);
    }

    // 构造请求参数：method、path、白名单 headers、body、query、调用方身份
    // headers 字段为票据 04 增量追加，caller / device 为票 01 / 票 08 追加——
    // 老插件忽略未知字段（字段演进增量原则）
    let method = req.method().as_str();
    let request_headers = filter_plugin_request_headers(req.headers());
    let request = PluginHttpRequest {
        endpoint_path: &endpoint_path,
        method,
        headers: request_headers,
        body: body.map(|b| b.into_inner()).unwrap_or(serde_json::Value::Null),
        query: serde_json::Value::Object(
            query
                .into_inner()
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect(),
        ),
        // 内部路径精确命中：无模板捕获（模板只存在于 host 别名面）
        params: serde_json::Map::new(),
        caller,
        device,
    };
    forward_to_plugin(owner, &request).await
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use wasmnest_server_base::identity::AuthenticatedIdentity;

    #[test]
    fn plugin_http_status_accepts_valid_codes() {
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 200})), 200);
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 201})), 201);
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 599})), 599);
    }

    #[test]
    fn plugin_http_status_defaults_when_missing_or_invalid() {
        // 缺失 status / 非对象 → 默认 200
        assert_eq!(plugin_http_status(&serde_json::json!({})), 200);
        assert_eq!(plugin_http_status(&serde_json::json!({"body": 1})), 200);
        // 非数字 → 200
        assert_eq!(plugin_http_status(&serde_json::json!({"status": "abc"})), 200);
        // 小数 / 负数 → 200
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 200.5})), 200);
        assert_eq!(plugin_http_status(&serde_json::json!({"status": -1})), 200);
        // 低于 actix 合法区间（from_u16 失败回退）→ 200
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 50})), 200);
        // 超 u16 上限：原实现 `as u16` 截断可能误放行，try_from 拒绝 → 200
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 65536})), 200);
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 999999})), 200);
        // 超 actix 区间上限 → 200
        assert_eq!(plugin_http_status(&serde_json::json!({"status": 1000})), 200);
    }

    /// 请求头白名单（票据 04）：白名单内透传（小写），凭据/白名单外丢弃
    #[test]
    fn filter_plugin_request_headers_whitelist_only() {
        use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
        let mut headers = HeaderMap::new();
        // HeaderName 仅接受小写（http crate 规范）
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(HeaderName::from_static("accept"), HeaderValue::from_static("*/*"));
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("req-1"),
        );
        // 凭据与无关头：一律不透传
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("session=abc"),
        );
        headers.insert(HeaderName::from_static("x-custom"), HeaderValue::from_static("no"));

        let filtered = filter_plugin_request_headers(&headers);
        assert_eq!(
            filtered.get("content-type").and_then(|v| v.as_str()),
            Some("application/json")
        );
        assert_eq!(filtered.get("accept").and_then(|v| v.as_str()), Some("*/*"));
        assert_eq!(filtered.get("x-request-id").and_then(|v| v.as_str()), Some("req-1"));
        assert!(filtered.get("authorization").is_none(), "凭据头不得透传");
        assert!(filtered.get("cookie").is_none(), "Cookie 不得透传");
        assert!(filtered.get("x-custom").is_none(), "白名单外头不得透传");
    }

    /// 插件响应 contentType：缺失返回 None（默认 application/json），指定则原样返回
    #[test]
    fn plugin_http_content_type_extracted_or_default() {
        assert_eq!(plugin_http_content_type(&serde_json::json!({})), None);
        assert_eq!(plugin_http_content_type(&serde_json::json!({"body": 1})), None);
        assert_eq!(
            plugin_http_content_type(&serde_json::json!({"contentType": "text/plain"})),
            Some("text/plain".to_string())
        );
        // 非字符串 contentType → None（保持默认）
        assert_eq!(plugin_http_content_type(&serde_json::json!({"contentType": 123})), None);
    }

    /// 票 08：端点级认证判定只有「档位 × 是否已验签」两个输入，四格全覆盖
    #[test]
    fn auth_tier_judges_verification_state_only() {
        assert!(
            plugin_http_auth_allowed(EndpointAuth::Jwt, true),
            "已验签的可信设备可命中 jwt 档"
        );
        assert!(
            !plugin_http_auth_allowed(EndpointAuth::Jwt, false),
            "要验签的端点遇到未验签调用方（含环回 hook）必须拒——收紧的本体"
        );
        assert!(plugin_http_auth_allowed(EndpointAuth::None, true));
        assert!(
            plugin_http_auth_allowed(EndpointAuth::None, false),
            "显式声明 none 是免凭证可达的唯一形态"
        );
    }

    /// 票 08：身份判定的优先级与线协议取值
    ///
    /// 已验签压倒环回（本机带 token 的请求就是 device）；拿不到对端地址时按匿名处理
    /// （fail-closed：绝不因为「读不到地址」就升成本机身份）。
    #[test]
    fn caller_classification_priority_and_wire_values() {
        assert_eq!(HttpCaller::classify(true, true), HttpCaller::Device);
        assert_eq!(HttpCaller::classify(true, false), HttpCaller::Device);
        assert_eq!(HttpCaller::classify(false, true), HttpCaller::Localhost);
        assert_eq!(HttpCaller::classify(false, false), HttpCaller::Anonymous);
        // 线协议取值是插件侧的判据，改名即破坏契约
        assert_eq!(HttpCaller::Device.as_str(), "device");
        assert_eq!(HttpCaller::Localhost.as_str(), "localhost");
        assert_eq!(HttpCaller::Anonymous.as_str(), "anonymous");
    }

    /// 票 08 + 凭据红线：`caller_identity` 只给身份派生标识，凭证本体与指纹不外泄
    ///
    /// 认证中心交回的连接身份经中间件注入 extensions（ADR 0033：宿主不再自行验签，
    /// 也没有签发面，故本用例直接构造身份而不造 token）。断言：转发给插件的
    /// `device` 上下文只有 `deviceId` / `deviceName`，**不含指纹**。
    #[test]
    fn caller_identity_carries_only_host_derived_labels() {
        use actix_web::HttpMessage;

        // 无身份、无对端地址（TestRequest 默认）→ anonymous，且不带设备上下文
        let req = actix_web::test::TestRequest::get()
            .uri("/api/plugin/com.wasmnest.bedcode/task-status")
            .to_http_request();
        assert_eq!(
            caller_identity(&req),
            (HttpCaller::Anonymous, None),
            "未认证且取不到对端地址时按最弱身份处理"
        );

        // 无身份但对端是环回 → localhost（hook 脚本可被插件区分）
        let req = actix_web::test::TestRequest::get()
            .uri("/api/plugin/com.wasmnest.bedcode/task-status")
            .peer_addr("127.0.0.1:54321".parse().expect("loopback addr"))
            .to_http_request();
        assert_eq!(caller_identity(&req), (HttpCaller::Localhost, None));

        // 非环回对端同样落 anonymous（IPv6 环回则算本机）
        let req = actix_web::test::TestRequest::get()
            .uri("/api/plugin/com.wasmnest.bedcode/task-status")
            .peer_addr("192.168.1.7:54321".parse().expect("lan addr"))
            .to_http_request();
        assert_eq!(caller_identity(&req).0, HttpCaller::Anonymous);
        let req = actix_web::test::TestRequest::get()
            .uri("/api/plugin/com.wasmnest.bedcode/task-status")
            .peer_addr("[::1]:54321".parse().expect("ipv6 loopback addr"))
            .to_http_request();
        assert_eq!(caller_identity(&req).0, HttpCaller::Localhost);

        // 已认证 → device + 身份派生标识；指纹不得透传给插件
        let identity = AuthenticatedIdentity {
            device_id: "device-1".to_string(),
            device_name: Some("Pixel 9".to_string()),
            fingerprint: Some("fp-secret".to_string()),
        };
        let req = actix_web::test::TestRequest::get()
            .uri("/api/plugin/com.wasmnest.bedcode/task-status")
            .peer_addr("192.168.1.7:54321".parse().expect("lan addr"))
            .to_http_request();
        req.extensions_mut().insert(identity);
        let (caller, device) = caller_identity(&req);
        assert_eq!(caller, HttpCaller::Device, "已认证压倒对端地址判定");
        assert_eq!(
            device,
            Some(serde_json::json!({ "deviceId": "device-1", "deviceName": "Pixel 9" }))
        );
        let rendered = device.expect("device 上下文").to_string();
        assert!(
            !rendered.contains("fp-secret"),
            "指纹不得透传给插件（凭据红线）: {rendered}"
        );
    }

    /// 票 08：认证拒绝的响应形状是「401 + 1007 + 点名两条出路」，而不是 200 带业务码
    ///
    /// 走真实 actix body 读取（不是只看构造器），否则「忘了 `.Unauthorized()`」
    /// 这种最可能的写错方式不会被测到。
    #[actix_web::test]
    async fn unauthenticated_response_is_http_401_with_both_remedies_named() {
        let resp = plugin_http_unauthenticated_response("/api/plugin/com.wasmnest.bedcode/task-queue/add");
        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::UNAUTHORIZED,
            "免凭证拒绝必须是 HTTP 401，不能沿用宿主业务面的 200 + 业务码"
        );
        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], CODE_PLUGIN_AUTH_FAILED as u64);
        let message = json["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("/api/plugin/com.wasmnest.bedcode/task-queue/add"),
            "文案须点名被拒端点: {message}"
        );
        assert!(
            message.contains("jwt") && message.contains("contributes.httpEndpoints"),
            "文案须给出两条出路: {message}"
        );
    }

    /// 属主解析：只认前缀自身——已激活 → 本人应答；未激活 → None
    #[test]
    fn http_owner_only_serves_activated_prefix() {
        let plugin = "com.wasmnest.bedcode";
        assert_eq!(resolve_http_owner(plugin, true), Some(plugin));
        assert_eq!(resolve_http_owner(plugin, false), None);
        assert_eq!(
            resolve_http_owner("com.wasmnest.file-transfer", false),
            None,
            "未激活就是未激活，无兜底可走"
        );
    }
}
