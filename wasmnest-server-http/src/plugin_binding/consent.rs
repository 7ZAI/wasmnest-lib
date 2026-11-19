//! host-http 能力域的**出站批量授权询问**段
//!
//! 应用在发起一批已知请求前提交 URL 集合；宿主归一化到 origin、去重、过滤既有
//! allow / deny 记录后，把未决 origin 放进**一次**弹窗，用户一次裁决，宿主按
//! origin 逐条落账。本模块只做「JSON 形状校验 / 条数上限 / 可归一化前置校验 /
//! 逐项结果回填」，归一化、记录过滤、弹窗与落账全在宿主的授权端口背后完成。
//!
//! **不是通行证**：本入口不发请求、不在能力域留存放行状态；实际出站仍走
//! `fetch` 的判定链（声明门 → 硬拒绝 → 策略档 → 记录 → 询问）。
//!
//! 凭据红线：响应与错误串只出现归一化 origin / 入参索引 / 稳定错误码，
//! 原始 URL（含 path / query / fragment / userinfo）不落响应，也不进审计日志。
//!
//! 失败一律显性：请求形状非法、超量、权限缺失、策略不支持、无弹窗通道、
//! 记录读取失败、端口结果条数不符都返回稳定错误码，不静默放行、不静默降级。

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::plugin_binding::ports::{BatchOutboundAuth, BatchOutboundVerdict, HttpPorts};
use crate::wire::PERMISSION_NETWORK_HTTP;

/// 单次批量询问允许提交的最大 URL 条数
///
/// 上限约束弹窗长度与一次性落账量；应用候选集超过该值时自行分批提交。
pub const MAX_BATCH_URLS: usize = 50;

/// 请求 JSON 形状非法（非 JSON / `urls` 非字符串数组 / 含未知字段）
pub const CONSENT_INVALID_REQUEST: &str = "consent.invalid-request";
/// URL 条数超过 [`MAX_BATCH_URLS`]
pub const CONSENT_TOO_MANY: &str = "consent.too-many";
/// 插件未声明 `network:http`
pub const CONSENT_PERMISSION_DENIED: &str = "consent.permission-denied";
/// 当前策略为「总是询问」，批量语义不成立
pub const CONSENT_ALWAYS_ASK: &str = "consent.always-ask";
/// 当前端未实现批量询问（应用回退到逐个 `fetch`）
pub const CONSENT_UNSUPPORTED: &str = "consent.unsupported";
/// 无弹窗通道（无头 / 事件投递失败）
pub const CONSENT_UNAVAILABLE: &str = "consent.unavailable";
/// 授权记录读取失败，无法判定
pub const CONSENT_STORE_FAILED: &str = "consent.store-failed";
/// 其他宿主内部错误（含端口返回条数与入参不符）
pub const CONSENT_INTERNAL: &str = "consent.internal";

/// 请求形状：`{ "urls": [...] }`（严格解析，未知字段即非法）
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentRequest {
    urls: Vec<String>,
}

/// 响应形状：逐项结果 + 未落账条数
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConsentResponse {
    results: Vec<ConsentResult>,
    dropped_records: usize,
}

/// 单个入参 URL 的裁决结果
#[derive(Debug, Serialize)]
struct ConsentResult {
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'static str>,
}

/// 出站批量授权提前询问（WIT `host-http.request-egress-consent`）
///
/// 权限门与单 origin `fetch` 同权限位（`network:http`），位置在最前；随后校验
/// 请求形状与条数上限，逐项做可归一化前置校验（非 `http` / `https`、缺 host、
/// 不可解析一律记 `invalid`，不参与询问），只把合法 URL 交给宿主端口。
///
/// 空列表（以及全部项非法）不调用端口、不弹窗，直接返回成功结果。
///
/// # Errors
///
/// 返回稳定错误码字符串（见各 `CONSENT_*` 常量）；不带原始 URL。
pub fn request_egress_consent(
    ports: &Arc<dyn HttpPorts>,
    plugin_id: &str,
    request_json: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_NETWORK_HTTP, "host_http_request_egress_consent") {
        return Err(CONSENT_PERMISSION_DENIED.to_string());
    }

    let request: ConsentRequest =
        serde_json::from_str(request_json).map_err(|_| CONSENT_INVALID_REQUEST.to_string())?;

    if request.urls.len() > MAX_BATCH_URLS {
        tracing::warn!(
            plugin_id = %plugin_id,
            count = request.urls.len(),
            limit = MAX_BATCH_URLS,
            "host-http: 批量出站授权 URL 条数超限"
        );
        return Err(CONSENT_TOO_MANY.to_string());
    }

    let started = Instant::now();
    let mut eligible = Vec::with_capacity(request.urls.len());
    let mut urls = Vec::with_capacity(request.urls.len());
    for raw in request.urls {
        if is_consentable_url(&raw) {
            eligible.push(true);
            urls.push(raw);
        } else {
            eligible.push(false);
        }
    }
    let invalid = eligible.iter().filter(|eligible| !**eligible).count();

    if urls.is_empty() {
        let results = eligible
            .into_iter()
            .enumerate()
            .map(|(index, _)| invalid_result(index))
            .collect();
        return encode_response(ConsentResponse {
            results,
            dropped_records: 0,
        });
    }

    let (verdicts, dropped_records) = match ports.authorize_outbound_batch(plugin_id, &urls) {
        BatchOutboundAuth::Verdicts {
            verdicts,
            dropped_records,
        } => (verdicts, dropped_records),
        BatchOutboundAuth::AlwaysAsk => return Err(CONSENT_ALWAYS_ASK.to_string()),
        BatchOutboundAuth::Unsupported => return Err(CONSENT_UNSUPPORTED.to_string()),
        BatchOutboundAuth::Unavailable(detail) => {
            tracing::warn!(
                plugin_id = %plugin_id,
                code = CONSENT_UNAVAILABLE,
                "host-http: 批量出站授权无弹窗通道"
            );
            tracing::debug!(plugin_id = %plugin_id, detail = %detail, "host-http: 批量出站授权失败细节");
            return Err(CONSENT_UNAVAILABLE.to_string());
        }
        BatchOutboundAuth::StoreFailed(detail) => {
            tracing::warn!(
                plugin_id = %plugin_id,
                code = CONSENT_STORE_FAILED,
                "host-http: 批量出站授权记录读取失败"
            );
            tracing::debug!(plugin_id = %plugin_id, detail = %detail, "host-http: 批量出站授权失败细节");
            return Err(CONSENT_STORE_FAILED.to_string());
        }
        BatchOutboundAuth::Internal(detail) => {
            tracing::warn!(
                plugin_id = %plugin_id,
                code = CONSENT_INTERNAL,
                "host-http: 批量出站授权宿主内部错误"
            );
            tracing::debug!(plugin_id = %plugin_id, detail = %detail, "host-http: 批量出站授权失败细节");
            return Err(CONSENT_INTERNAL.to_string());
        }
    };

    if verdicts.len() != urls.len() {
        tracing::warn!(
            plugin_id = %plugin_id,
            urls = urls.len(),
            verdicts = verdicts.len(),
            "host-http: 批量出站授权端口返回条数与入参不符"
        );
        return Err(CONSENT_INTERNAL.to_string());
    }

    let mut results = Vec::with_capacity(eligible.len());
    let mut verdicts = verdicts.into_iter();
    let mut allowed = 0usize;
    let mut denied = 0usize;
    for (index, is_eligible) in eligible.into_iter().enumerate() {
        if !is_eligible {
            results.push(invalid_result(index));
            continue;
        }
        let verdict = verdicts.next().expect("verdict count is checked against input length");
        match verdict {
            BatchOutboundVerdict::Allowed { origin, source } => {
                allowed += 1;
                results.push(ConsentResult {
                    index,
                    origin: Some(origin),
                    decision: "allow",
                    source: Some(source.as_str()),
                });
            }
            BatchOutboundVerdict::Denied { origin, source } => {
                denied += 1;
                results.push(ConsentResult {
                    index,
                    origin: Some(origin),
                    decision: "deny",
                    source: Some(source.as_str()),
                });
            }
        }
    }

    tracing::debug!(
        plugin_id = %plugin_id,
        requested = results.len(),
        eligible = urls.len(),
        allowed,
        denied,
        invalid,
        dropped_records,
        elapsed_micros = started.elapsed().as_micros() as u64,
        "host-http: 批量出站授权完成"
    );

    encode_response(ConsentResponse {
        results,
        dropped_records,
    })
}

/// URL 是否可归一化为 `http` / `https` 的 origin
///
/// 只做前置校验，不复刻宿主的 origin 归一化（端口的归一化结果才是权威）：
/// 非法协议、缺 host、不可解析的字符串一律记为 `invalid`，不参与弹窗。
fn is_consentable_url(raw: &str) -> bool {
    match reqwest::Url::parse(raw) {
        Ok(url) => matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        Err(_) => false,
    }
}

/// 非法项结果：只回索引，不回显原始 URL（可能含 token）
fn invalid_result(index: usize) -> ConsentResult {
    ConsentResult {
        index,
        origin: None,
        decision: "invalid",
        source: None,
    }
}

/// 响应序列化（失败同样映射为稳定错误码，不返回半截 JSON）
fn encode_response(response: ConsentResponse) -> Result<String, String> {
    serde_json::to_string(&response).map_err(|error| {
        tracing::warn!(error = %error, "host-http: 批量出站授权响应序列化失败");
        CONSENT_INTERNAL.to_string()
    })
}
