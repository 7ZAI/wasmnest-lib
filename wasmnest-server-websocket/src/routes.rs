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

use actix_web::{web, Error, HttpMessage, HttpRequest, HttpResponse};
use actix_web_actors::ws as actix_ws;

use crate::channel::plugin::PluginChannel;
use crate::conn::{ConnSpec, WsConnBase};
use crate::registry::WsSessionRegistry;
use wasmnest_server_base::constants::PLACEHOLDER_PEER_ADDR;
use wasmnest_server_base::face::RequestFace;

/// 配对窗口不放行任何 WS 升级：配对端点只有 HTTP 的 `/api/auth/*`
/// （设计 §4.1）。peer 面标记由 listener 注入，终端端点仍按端点档位要求 JWT。
fn pairing_ws_upgrade_allowed(face: &RequestFace) -> bool {
    !face.is_pairing()
}
use wasmnest_server_core::link_crypto::{
    app_policy, coded_reason, derive_ws_session_ciphers, is_loopback_peer, parse_negotiation, ws_register_ciphers,
    ws_remove_ciphers, EncryptionPolicy, CODE_ENCRYPTION_REQUIRED, CODE_ENCRYPTION_UNSUPPORTED, ERROR_HEADER,
    NEGOTIATION_HEADER, PROTOCOL_VERSION, WS_POLICY_HEADER,
};

/// 链路加密协商拒绝（400 text/plain + 稳定码）
///
/// 头 `ERROR_HEADER` 与正文 `<code>: ` 前缀同源：客户端（移动宿主）按头把拒绝映射成
/// `encryption-unsupported`（对端不会协商 → 升级 / 先配对）或 `encryption-required`
/// （协商建不起来 → 检查链路身份 / 重新配对），不必从自由文本里猜（内网穿透 T07）。
fn reject_crypto(code: &'static str, detail: String) -> HttpResponse {
    HttpResponse::BadRequest()
        .content_type("text/plain; charset=utf-8")
        .insert_header((ERROR_HEADER, code))
        .body(coded_reason(code, detail))
}

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
    // 内网穿透 T03：面标记由 listener 注入；配对窗口不放行任何 WS 升级
    let face = req.extensions().get::<RequestFace>().cloned().unwrap_or_default();
    if !pairing_ws_upgrade_allowed(&face) {
        tracing::warn!(plugin_id = %plugin_id, "pairing window rejected WS upgrade");
        return Ok(HttpResponse::Forbidden().finish());
    }

    // ==================== 链路加密：升级期协商（应用策略裁决） ====================
    //
    // 握手放在协议升级阶段（HTTP 头），而不是升级后的首帧：
    // - 请求头 `X-WasmNest-Crypto: v1 <m_ek>` = 客户端提案（带上它的临时公钥）；
    // - 101 响应头 `X-WasmNest-Crypto-Policy` 恒下发应用策略；
    // - 101 响应头 `X-WasmNest-Crypto: v1 <s_ek>` 仅在服务端接受提案时下发。
    //
    // 这样 `required` 仍能在升级**之前**拒绝没有提案的连接（不建立一条随后必被
    // 帧过滤器断开的连接），而接受提案后的帧级加解密沿用既有密码表（按对端 addr
    // 索引），WS 连接建好后的帧语义 / 认证状态机零改动。
    //
    // 策略属于应用（owner）：`off` 时回绝提案（不注册密码、只回策略头）——移动端
    // 只有一个全局开关，无法预知各应用在桌面端的策略；客户端按 strict 开关自行
    // 决定「回绝即断开」还是「明文续跑」。
    let policy = app_policy(&entry.owner);
    let offer = match parse_ws_offer(&req) {
        Ok(offer) => offer,
        Err(reason) => {
            tracing::warn!(
                plugin_id = %plugin_id,
                endpoint_id = %entry.endpoint_id,
                peer = %client_id,
                %reason,
                "plugin ws endpoint rejected malformed link encryption offer"
            );
            // 带过头但格式非法 = 发起过协商、建不起来
            return Ok(reject_crypto(CODE_ENCRYPTION_REQUIRED, reason));
        }
    };
    // 环回与 HTTP 面同口径（本地豁免）：本机客户端不要求协商，也不接受协商——
    // 过滤器对环回流量不介入，注册了密码反而会把本机客户端的密文直投插件。
    // peer 面（隧道入口）虽来自 loopback，但代表远端设备，不得享受本地豁免
    let local_peer = !face.is_peer() && is_loopback_peer(&client_id);
    if policy == EncryptionPolicy::Required && !local_peer && offer.is_none() {
        tracing::warn!(
            plugin_id = %plugin_id,
            endpoint_id = %entry.endpoint_id,
            policy = policy.as_str(),
            peer = %client_id,
            "plugin ws endpoint requires link encryption but the upgrade request carries no offer, rejecting 400"
        );
        // 无提案 = 对端压根不会协商（旧客户端），或还没有 pin 信任锚（未配对）。
        // 宿主无法区分，文案把两条出路都点名；升级期就拒，不建立一条随后必被
        // 帧过滤器断开的连接。
        return Ok(reject_crypto(
            CODE_ENCRYPTION_UNSUPPORTED,
            format!(
                "link encryption required: endpoint '{}' of plugin '{}' has app policy 'required', but this \
                 connection carries no '{NEGOTIATION_HEADER}' negotiation header — the peer never started \
                 link-crypto negotiation (old client without link-crypto support, or a client with no pinned \
                 trust anchor); upgrade the peer or pair it first, plaintext is not accepted",
                entry.endpoint_id, entry.owner
            ),
        ));
    }

    // 所有可能在升级后失败的步骤都在 start 之前完成（派生 / 头值构造）；
    // 密码注册留在 `start()` 前一刻，失败路径统一回滚。
    let mut negotiated_ciphers = None;
    if local_peer && offer.is_some() {
        tracing::debug!(
            plugin_id = %plugin_id,
            endpoint_id = %entry.endpoint_id,
            peer = %client_id,
            "loopback ws client offered link encryption; local traffic is exempt and stays plaintext"
        );
    }
    let negotiated_offer = if local_peer { None } else { offer.as_deref() };
    let crypto_header = match negotiate_ws_offer(policy, negotiated_offer) {
        Ok(Some(handshake)) => {
            let value = format!("v{PROTOCOL_VERSION} {}", handshake.server_ek_b64);
            match actix_web::http::header::HeaderValue::from_str(&value) {
                Ok(value) => {
                    negotiated_ciphers = Some(handshake.ciphers);
                    Some(value)
                }
                Err(error) => {
                    tracing::error!(peer = %client_id, %error, "ws link crypto response header invalid");
                    return Ok(HttpResponse::InternalServerError().finish());
                }
            }
        }
        Ok(None) => {
            if offer.is_some() {
                // 应用策略 off：客户端提案被回绝（不注册密码），101 只带策略头。
                // 这不是静默降级——客户端能看到策略值并自行决定 strict 断开。
                tracing::info!(
                    plugin_id = %plugin_id,
                    endpoint_id = %entry.endpoint_id,
                    peer = %client_id,
                    "client offered link encryption but the app policy is 'off'; continuing plaintext"
                );
            }
            None
        }
        Err(error) => {
            tracing::warn!(
                plugin_id = %plugin_id,
                endpoint_id = %entry.endpoint_id,
                peer = %client_id,
                %error,
                "plugin ws endpoint rejected invalid link encryption offer"
            );
            return Ok(reject_crypto(
                CODE_ENCRYPTION_REQUIRED,
                format!(
                    "invalid link encryption offer on endpoint '{}' of plugin '{}': {error}",
                    entry.endpoint_id, entry.owner
                ),
            ));
        }
    };

    let crypto_header_name = actix_web::http::header::HeaderName::try_from(NEGOTIATION_HEADER)
        .expect("negotiation header name is a valid HTTP token");
    let policy_header_name = actix_web::http::header::HeaderName::try_from(WS_POLICY_HEADER)
        .expect("policy header name is a valid HTTP token");
    let policy_header =
        actix_web::http::header::HeaderValue::from_str(policy.as_str()).expect("policy wire literal is ASCII");

    if !WsSessionRegistry::global().reserve_endpoint_client(&entry.endpoint_id, &client_id, entry.max_clients) {
        tracing::warn!(
            plugin_id = %plugin_id,
            endpoint_id = %entry.endpoint_id,
            limit = entry.max_clients,
            "plugin ws endpoint client limit reached, rejecting before upgrade (503)"
        );
        return Ok(HttpResponse::ServiceUnavailable().finish());
    }

    // 先注册密码再启动 actor：升级响应一旦写出，首帧就可能到达，密码必须已就绪
    let registered_ciphers = match negotiated_ciphers.take() {
        Some(ciphers) => {
            ws_register_ciphers(&client_id, ciphers);
            true
        }
        None => false,
    };

    let channel = PluginChannel::new(&entry, addr);
    let ws_actor = WsConnBase::new(
        ConnSpec {
            owner: Some(entry.owner.clone()),
            endpoint_id: Some(entry.endpoint_id.clone()),
            face,
            ..ConnSpec::new(addr)
        },
        Box::new(channel),
    );
    match actix_ws::WsResponseBuilder::new(ws_actor, &req, stream)
        .frame_size(entry.max_message_bytes)
        .start()
    {
        Ok(mut response) => {
            response.headers_mut().insert(policy_header_name, policy_header);
            if let Some(value) = crypto_header {
                response.headers_mut().insert(crypto_header_name, value);
            }
            Ok(response)
        }
        Err(error) => {
            WsSessionRegistry::global().release_endpoint_reservation(&entry.endpoint_id, &client_id);
            if registered_ciphers {
                ws_remove_ciphers(&client_id);
            }
            Err(error)
        }
    }
}

/// 解析升级请求的链路加密提案
///
/// - `Ok(None)`：未带协商头（不提案）；
/// - `Ok(Some(ek_b64))`：合法提案（客户端临时公钥）；
/// - `Err(reason)`：带了头但格式非法——显性 400，不按「未提案」静默处理
///   （否则 `required` 会把一个拼错头的加密客户端伪装成「没开加密」）。
fn parse_ws_offer(req: &HttpRequest) -> Result<Option<String>, String> {
    let Some(raw) = req.headers().get(NEGOTIATION_HEADER) else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| format!("invalid '{NEGOTIATION_HEADER}' header: value is not valid ASCII/UTF-8"))?;
    match parse_negotiation(raw) {
        Some(ek_b64) => Ok(Some(ek_b64.to_string())),
        None => Err(format!(
            "invalid '{NEGOTIATION_HEADER}' header: expected 'v{PROTOCOL_VERSION} <base64 x25519 public key>'"
        )),
    }
}

/// 应用策略 × 客户端提案 → 是否接受（`Ok(Some(handshake))`）
///
/// - `off`：回绝提案（`Ok(None)`）——应用策略明文，不注册会话密码；
/// - `preferred` / `required`：按提案派生；提案缺失由调用方按策略裁决；
/// - 提案格式非法 / 身份不可用 → `Err`（fail-visible，不静默降级）。
fn negotiate_ws_offer(
    policy: EncryptionPolicy,
    offer: Option<&str>,
) -> Result<Option<wasmnest_server_core::link_crypto::WsHandshake>, String> {
    let Some(ek_b64) = offer else {
        return Ok(None);
    };
    if policy == EncryptionPolicy::Off {
        return Ok(None);
    }
    derive_ws_session_ciphers(ek_b64)
        .map(Some)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 触碰链路身份/策略全局态的用例必须串行
    static LINK_CRYPTO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn ready_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        wasmnest_server_core::link_crypto::init_identity(dir.path()).expect("link identity");
    }

    #[test]
    fn offer_parser_distinguishes_absent_and_malformed() {
        // 未带协商头 = 未提案（由 required 门禁裁决）
        let req = actix_web::test::TestRequest::get().to_http_request();
        assert_eq!(parse_ws_offer(&req), Ok(None));

        // 带合法提案
        let req = actix_web::test::TestRequest::get()
            .insert_header((NEGOTIATION_HEADER, "v1 QUJD"))
            .to_http_request();
        assert_eq!(parse_ws_offer(&req), Ok(Some("QUJD".to_string())));

        // 带头但版本/形状非法 = 错误，不得按「未提案」静默处理
        for bad in ["v2 QUJD", "v1", "v1 A B", "", "QUJD"] {
            let req = actix_web::test::TestRequest::get()
                .insert_header((NEGOTIATION_HEADER, bad))
                .to_http_request();
            let parsed = parse_ws_offer(&req);
            assert!(parsed.is_err(), "取值 {bad:?} 必须显性拒绝，got {parsed:?}");
        }
    }

    /// 升级期拒绝必须带稳定码（头 + 正文前缀同源）：旧客户端无提案 →
    /// `encryption-unsupported`，坏提案 / 坏协商 → `encryption-required`
    #[test]
    fn crypto_rejection_carries_code_in_header_and_body() {
        let unsupported = reject_crypto(CODE_ENCRYPTION_UNSUPPORTED, "no offer".to_string());
        assert_eq!(unsupported.status(), actix_web::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            unsupported.headers().get(ERROR_HEADER).and_then(|v| v.to_str().ok()),
            Some(CODE_ENCRYPTION_UNSUPPORTED),
            "旧客户端拒绝码必须进响应头（客户端按头分类，不从正文猜）"
        );

        let required = reject_crypto(CODE_ENCRYPTION_REQUIRED, "bad offer".to_string());
        let header = required
            .headers()
            .get(ERROR_HEADER)
            .and_then(|v| v.to_str().ok())
            .expect("坏协商也必须带码");
        assert_eq!(header, CODE_ENCRYPTION_REQUIRED);
        assert_ne!(header, CODE_ENCRYPTION_UNSUPPORTED, "两类拒绝不得混码");
    }

    #[test]
    fn negotiate_declines_offer_when_app_policy_is_off() {
        // off 不派生、也不需要身份：直接回绝
        assert!(matches!(
            negotiate_ws_offer(EncryptionPolicy::Off, Some("QUJD")),
            Ok(None)
        ));
        assert!(matches!(negotiate_ws_offer(EncryptionPolicy::Off, None), Ok(None)));
    }

    #[test]
    fn negotiate_derives_only_for_encrypting_policies() {
        let _guard = LINK_CRYPTO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ready_identity();

        let (private, public) = wasmnest_server_core::link_crypto::generate_ephemeral();
        let _ = private;
        let ek_b64 = wasmnest_server_core::link_crypto::b64_encode(&public);

        for policy in [EncryptionPolicy::Preferred, EncryptionPolicy::Required] {
            let handshake = negotiate_ws_offer(policy, Some(&ek_b64))
                .expect("valid offer must derive")
                .expect("encrypting policy accepts the offer");
            assert!(!handshake.server_ek_b64.is_empty());
        }

        // 非法提案 = 显性错误
        assert!(negotiate_ws_offer(EncryptionPolicy::Preferred, Some("v1 not-base64!")).is_err());
        assert!(negotiate_ws_offer(EncryptionPolicy::Required, Some("QUJD")).is_err());
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

// ==================== 内网穿透 T03 测试锁 ====================

#[cfg(test)]
mod tunnel_face_tests {
    use super::*;

    /// 内网穿透 T03：peer 面标记在 WS 握手请求上下文可读
    #[test]
    fn peer_face_marker_is_readable_at_ws_handshake() {
        let req = actix_web::test::TestRequest::get()
            .uri("/ws/plugin/com.wasmnest.bedcode/terminal")
            .to_http_request();
        req.extensions_mut()
            .insert(RequestFace::peer_face(Some("node-1".to_string()), false));
        let face = req.extensions().get::<RequestFace>().cloned().unwrap_or_default();
        assert!(face.is_peer());
        assert_eq!(face.peer_node_id.as_deref(), Some("node-1"));
    }

    /// 配对窗口不放行 WS 升级；普通面与已匹配 peer 面不受影响
    #[test]
    fn pairing_window_never_upgrades_ws() {
        assert!(pairing_ws_upgrade_allowed(&RequestFace::local()));
        assert!(pairing_ws_upgrade_allowed(&RequestFace::peer_face(
            Some("node-1".to_string()),
            false
        )));
        assert!(!pairing_ws_upgrade_allowed(&RequestFace::peer_face(None, true)));
    }
}
