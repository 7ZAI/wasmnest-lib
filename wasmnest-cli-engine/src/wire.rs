//! 本机 IPC wire 契约：CLI 前端 ↔ 宿主之间的帧类型与 JSON 行编解码
//!
//! 通道物理（装配侧决定：unix domain socket / Windows named pipe）与传输循环不在本
//! crate；本模块只钉**帧形状**与编解码纪律：
//!
//! - **JSON 行分帧**：一帧一行（[`encode`](fn encode.html) 保证输出不含裸换行，
//!   传输层按行切分即可）；
//! - `Request` 原样透传 argv（宿主侧用目录 + 解析器做权威解析——目录与解析的
//!   真源只有宿主一份，前端本地解析仅供帮助 / 补全呈现）；
//! - `Response` 的 `ok` / `error` 恰好其一（解码时校验，违例整行拒绝）；
//! - 人审经帧往返：宿主发 `ConfirmationRequest`，前端答 `ConfirmationResponse`
//!   （「触发通道承载确认」——GUI 触发的操作仍走 GUI 弹窗，不经本通道）；
//! - 错误信封只携带**语义码 + 消毒参数**，技术详情永不过线：`WireError` 是纯 wire
//!   类型（无任何宿主错误类型依赖）。宿主侧把域错误映射成语义码后经
//!   [`WireError::from_code`] / [`WireError::with_params`] 构造；没有语义码的失败落
//!   [`WireError::fallback`]（= 契约仓的 `DEFAULT_ERROR_CODE`）。**映射住宿主**——
//!   本 crate 是 argv / 帧解析骨架，不替任何一端的错误信封做决定。
//!
//! 信任边界：本机通道 = **系统用户**（socket 文件同用户权限，装配侧落地）；首期
//! 无 token、无加密——远程链路的加密协议不进本机通道。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasmnest_contract::DEFAULT_ERROR_CODE;

/// 请求操作
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestOp {
    /// 执行一条命令（argv 原样透传，宿主侧权威解析）
    Exec,
    /// 拉取命令目录（前端帮助 / 补全的刷新源）
    Catalog,
}

/// 人审决定（对齐装配侧既有权限授予语义：「记住」档落插件权限授予账本）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Allow,
    AllowRemember,
    Deny,
}

/// 过线错误信封（语义码 + 消毒参数；不含技术详情 / 堆栈 / 原始错误文本）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireError {
    pub code: String,
    /// 缺省 `null` 视作无参（与 server-base 信封口径一致）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl WireError {
    /// 以语义码构造（宿主侧把域错误映射成 code 后的唯一入口）
    pub fn from_code(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            params: None,
        }
    }

    /// 以语义码 + 已消毒具名参数构造（`Null` 视作无参，与信封口径一致）
    pub fn with_params(code: impl Into<String>, params: Value) -> Self {
        Self {
            code: code.into(),
            params: if params.is_null() { None } else { Some(params) },
        }
    }

    /// 兜底错误（没有语义码的失败）：code = 契约仓 [`DEFAULT_ERROR_CODE`]
    ///
    /// 兜底码是跨端 wire 契约的一部分（前端 i18n key 后缀），故真源在零依赖契约仓，
    /// 本 crate 只引用不复制。
    pub fn fallback() -> Self {
        Self::from_code(DEFAULT_ERROR_CODE)
    }
}

/// 单帧（tag = `type`，变体名 kebab-case，字段 camelCase）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Frame {
    /// 前端 → 宿主：请求
    #[serde(rename_all = "camelCase")]
    Request {
        op: RequestOp,
        op_id: String,
        argv: Vec<String>,
    },
    /// 宿主 → 前端：应答（ok / error 恰好其一，解码侧校验）
    #[serde(rename_all = "camelCase")]
    Response {
        op_id: String,
        ok: Option<Value>,
        error: Option<WireError>,
    },
    /// 宿主 → 前端：事件推送（总线观察 / 日志跟随）
    #[serde(rename_all = "camelCase")]
    Event { kind: String, payload: Value },
    /// 宿主 → 前端：人审请求（操作前确认 / 权限授予）
    #[serde(rename_all = "camelCase")]
    ConfirmationRequest {
        op_id: String,
        operation: String,
        reason: String,
        permissions: Vec<String>,
    },
    /// 前端 → 宿主：人审应答
    #[serde(rename_all = "camelCase")]
    ConfirmationResponse { op_id: String, decision: Decision },
}

/// 事件种类词汇（Event.kind 的合法值；装配侧按此路由）
pub const EVENT_KIND_BUS: &str = "bus";
pub const EVENT_KIND_LOGS: &str = "logs";

/// 编码为单行 JSON（不含结尾换行；serde_json 不产裸换行，可安全行分帧）
pub fn encode(frame: &Frame) -> Result<String, String> {
    serde_json::to_string(frame).map_err(|e| format!("帧编码失败：{}", e))
}

/// 解码单行 JSON（Response 的 ok/error 恰好其一在解码后显性校验）
pub fn decode(line: &str) -> Result<Frame, String> {
    let frame: Frame =
        serde_json::from_str(line).map_err(|e| format!("帧解码失败（整行拒绝）：{}", e))?;
    if let Frame::Response { op_id, ok, error } = &frame {
        match (ok.is_some(), error.is_some()) {
            (true, false) | (false, true) => {}
            _ => {
                return Err(format!(
                    "Response 帧 {} 的 ok/error 必须恰好其一（ok={} error={}）",
                    op_id,
                    ok.is_some(),
                    error.is_some()
                ))
            }
        }
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frame_kind_roundtrips() {
        let frames = vec![
            Frame::Request {
                op: RequestOp::Exec,
                op_id: "op-1".to_string(),
                argv: vec!["plugin".to_string(), "list".to_string()],
            },
            Frame::Request {
                op: RequestOp::Catalog,
                op_id: "op-2".to_string(),
                argv: vec![],
            },
            Frame::Response {
                op_id: "op-1".to_string(),
                ok: Some(serde_json::json!({"count": 0})),
                error: None,
            },
            Frame::Response {
                op_id: "op-3".to_string(),
                ok: None,
                error: Some(WireError {
                    code: "host.plugin.not-activated".to_string(),
                    params: Some(serde_json::json!({"pluginId": "com.example.demo"})),
                }),
            },
            Frame::Event {
                kind: EVENT_KIND_BUS.to_string(),
                payload: serde_json::json!({"topic": "task:started"}),
            },
            Frame::ConfirmationRequest {
                op_id: "op-4".to_string(),
                operation: "plugin install".to_string(),
                reason: "安装将加载新插件代码".to_string(),
                permissions: vec!["fs:read".to_string()],
            },
            Frame::ConfirmationResponse {
                op_id: "op-4".to_string(),
                decision: Decision::AllowRemember,
            },
        ];
        for frame in frames {
            let line = encode(&frame).unwrap();
            assert!(!line.contains('\n'), "帧必须单行：{}", line);
            assert_eq!(decode(&line).unwrap(), frame);
        }
    }

    #[test]
    fn wire_shape_uses_kebab_tag_and_camel_fields() {
        let line = encode(&Frame::ConfirmationResponse {
            op_id: "x".to_string(),
            decision: Decision::AllowRemember,
        })
        .unwrap();
        assert!(
            line.contains(r#""type":"confirmation-response""#),
            "{}",
            line
        );
        assert!(line.contains(r#""opId":"x""#), "{}", line);
        assert!(line.contains(r#""decision":"allow-remember""#), "{}", line);
    }

    #[test]
    fn malformed_lines_and_violating_responses_rejected() {
        assert!(decode("not json").is_err());
        assert!(decode("{}").is_err(), "缺 type tag 必须拒绝");
        // ok/error 双缺与双有都必须整行拒绝
        let neither = r#"{"type":"response","opId":"x"}"#;
        assert!(decode(neither).is_err());
        let both = r#"{"type":"response","opId":"x","ok":{},"error":{"code":"c"}}"#;
        assert!(decode(both).is_err());
    }

    #[test]
    fn wire_error_constructors_keep_shape_and_fallback_code() {
        // 语义码 + 消毒参数：wire 形状 `{ code, params? }`，无技术详情字段
        let wire = WireError::with_params(
            "host.plugin.not-activated",
            serde_json::json!({"pluginId": "com.example.demo"}),
        );
        assert_eq!(wire.code, "host.plugin.not-activated");
        assert_eq!(
            wire.params.as_ref().and_then(|p| p.get("pluginId")),
            Some(&serde_json::json!("com.example.demo"))
        );
        let json = serde_json::to_value(&wire).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "code": "host.plugin.not-activated",
                "params": { "pluginId": "com.example.demo" }
            })
        );

        // Null 参数 = 无参（字段省略，与信封口径一致）
        let bare = WireError::with_params("host.invoke.timeout", serde_json::Value::Null);
        assert!(bare.params.is_none());
        assert_eq!(
            serde_json::to_value(&bare).unwrap(),
            serde_json::json!({ "code": "host.invoke.timeout" })
        );

        // 兜底码是契约常量，不得在本 crate 复制字面量
        let fallback = WireError::fallback();
        assert_eq!(fallback.code, wasmnest_contract::DEFAULT_ERROR_CODE);
        assert_eq!(fallback.code, "host.internal");
        assert!(fallback.params.is_none());
    }
}
