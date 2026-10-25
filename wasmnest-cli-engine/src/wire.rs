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
//! - 错误信封复用 server-base 的 `AppError` 语义：`WireError` 只携带语义码与
//!   消毒参数（UserFacing 透传 code/params；其余落机制码兜底），技术详情永不过线。
//!
//! 信任边界：本机通道 = **系统用户**（socket 文件同用户权限，装配侧落地）；首期
//! 无 token、无加密——远程链路的加密协议不进本机通道。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasmnest_server_base::error::{AppError, DEFAULT_ERROR_CODE};

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
    /// 从宿主侧错误信封提取（UserFacing 的 code/params 透传，其余落机制码兜底）
    ///
    /// 不经 `AppError` 的 `Serialize` 边界取值——那个边界有副作用（生成追踪号并
    /// 落日志），wire 提取只做字段镜像。
    pub fn from_app_error(err: &AppError) -> Self {
        match err {
            AppError::UserFacing { code, params, .. } => WireError {
                code: code.clone(),
                params: Some(params.clone()),
            },
            _ => WireError {
                code: DEFAULT_ERROR_CODE.to_string(),
                params: None,
            },
        }
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
    fn wire_error_extracts_app_error_faithfully() {
        // UserFacing 的 code/params 透传（不经带副作用的 Serialize 边界）
        let user_facing = AppError::user_facing(
            "host.plugin.not-activated",
            serde_json::json!({"pluginId": "com.example.demo"}),
            "详情只进日志",
        );
        let wire = WireError::from_app_error(&user_facing);
        assert_eq!(wire.code, "host.plugin.not-activated");
        assert_eq!(
            wire.params.as_ref().and_then(|p| p.get("pluginId")),
            Some(&serde_json::json!("com.example.demo"))
        );
        // 非用户态错误落机制码兜底
        let other = AppError::Plugin("内部错误".to_string());
        let wire = WireError::from_app_error(&other);
        assert_eq!(wire.code, "host.internal");
        assert!(wire.params.is_none());
    }
}
