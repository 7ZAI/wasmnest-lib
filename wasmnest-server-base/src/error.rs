//! Error types for Claude Code Remote
//!
//! 共享错误类型 - 桌面端和移动端都可用
//!
//! 桌面端专属：错误信封（ADR 0030）——跨进程失败一律承载为 `{ code, request_id, params? }`，
//! 技术详情（原文 / anyhow 链 / 堆栈）**永不出产生方进程**；移动端不跟演（error.rs 独立副本）。

use rand::Rng;
use serde::{Serialize, Serializer};
use thiserror::Error;

/// 未显式映射的错误统一兜底到此语义码（ADR 0030 §3：默认兜底 + 显式覆盖）。
///
/// code 即前端 i18n key 的后半段（`errors.host.internal`），零映射层；改码 = 破坏性变更。
pub const DEFAULT_ERROR_CODE: &str = "host.internal";

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Session error: {0}")]
    Session(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Notification error: {0}")]
    Notification(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Internal error: {0}")]
    Internal(String),

    /// 出站策略闸门（egress）：移动 host_impl/conn 域的出站策略拒绝/失败
    /// （票 06 批次 03 超集化——fork 自持 error.rs 的唯一独有 variant 对齐共享真源，
    /// 桌面侧零消费零影响）
    #[error("Egress error: {0}")]
    Egress(String),

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[error("PTY error: {0}")]
    Pty(String),

    /// 显式友好错误（ADR 0030 §3）——需 UI 特定文案 / 参数的调用点在失败处显式构造。
    ///
    /// - `code`：机器可读稳定标识，= 前端 i18n key 后缀（`errors.<code>`）；改码 = 破坏性变更
    /// - `params`：已消毒具名参数（显示名 / 端口 / 秒数 / 文件名），禁止技术文案 / 堆栈 / 凭据
    /// - `detail`：技术详情，**只进产生方进程日志**（Serialize 时随同条 tracing 落盘），永不进信封
    ///
    /// Display = `detail`（日志 / 错误链照旧全量）；构造请用 `AppError::user_facing` 辅助。
    #[error("{detail}")]
    UserFacing {
        code: String,
        params: serde_json::Value,
        detail: String,
    },
}

impl AppError {
    /// 构造显式友好错误（ADR 0030 §3：默认兜底 + 显式覆盖的唯一入口）。
    ///
    /// `params` 应为 `serde_json::json!({...})`；序列化时为 `Null` 则省略，不进信封。
    /// `detail` 仅在产生方进程日志中可见（同条 tracing 带 `request_id` / `error` 字段）。
    pub fn user_facing(code: impl Into<String>, params: serde_json::Value, detail: impl Into<String>) -> Self {
        AppError::UserFacing {
            code: code.into(),
            params,
            detail: detail.into(),
        }
    }

    /// 无参版本的显式友好错误（信封省略 `params` 字段）。
    pub fn user_facing_simple(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::user_facing(code, serde_json::Value::Null, detail)
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

// Implement Serialize for Tauri IPC compatibility
//
// 实现说明（ADR 0030 §5）：`Serialize` 是跨进程边界的**唯一**转换点，且具有副作用：
// 1. 生成短随机 `request_id`（该次失败在产生方日志中的关联键，支持方可凭它 + 时间精确 grep）
// 2. 落同条 `tracing::error!` —— `request_id` 与 `error`（完整技术详情）结构化字段同条带出
// 3. 输出信封对象 `{ code, request_id, params? }`，**永不携带**错误原文 / 堆栈 / 任何 detail
//
// Tauri IPC 拒绝时恰好调用一次（见 tauri `From<T: Serialize> for InvokeError` →
// `InvokeResponse::Err(InvokeError)` → body 序列化）；同一次失败若被多次序列化会得到
// 不同的 request_id（每次失败独立关联），这是设计使然，非 bug。
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let request_id = new_request_id();
        let detail = self.to_string();
        tracing::error!(request_id = %request_id, error = %detail, "Tauri command failed");

        let (code, params) = match self {
            AppError::UserFacing { code, params, .. } => (code.clone(), Some(params.clone())),
            _ => (DEFAULT_ERROR_CODE.to_string(), None),
        };
        let mut envelope = serde_json::json!({ "code": code, "request_id": request_id });
        if let Some(p) = params {
            if !p.is_null() {
                envelope["params"] = p;
            }
        }
        envelope.serialize(serializer)
    }
}

/// 生成短随机 hex 请求 ID（8 位小写 hex，碰撞概率足够低）。
///
/// 跨边界失败（IPC 信封 / 事件信封）共用这一个生成器：同一形态便于按值 grep
pub fn new_request_id() -> String {
    let mut rng = rand::thread_rng();
    (0..8).map(|_| format!("{:x}", rng.gen_range(0..16u8))).collect()
}

/// 事件通道错误信封（ADR 0030 决定 7：事件与 IPC 同形状）
///
/// 事件不经 `Serialize` 边界，`request_id` 在此生成并随载荷下发；调用方负责把
/// 全量技术详情与同一个 `request_id` 打进**同一条** `tracing`，实现「用户提示 ↔ 详情」
/// 关联（用户面不展示 request_id，见 ADR 决定 9）。
///
/// 结构上**没有**存放详情的字段——与「详情不出产生方进程」是同一保证的第二道闸门。
pub struct EventEnvelope {
    /// 语义错误码（= 前端 i18n key 后缀 `errors.<code>`）
    pub code: String,
    /// 该次失败事件的追踪号（8 位小写 hex）
    pub request_id: String,
    /// 已消毒具名参数（应用显示名等）；`Null` 视作无参（`payload()` 省略该字段）
    pub params: Option<serde_json::Value>,
}

impl EventEnvelope {
    /// 构造事件信封（`params` 传 `json!(null)` 表示无参）
    pub fn new(code: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            code: code.into(),
            request_id: new_request_id(),
            params: if params.is_null() { None } else { Some(params) },
        }
    }

    /// 前端事件载荷：`{ code, request_id, params? }`（字段名与 IPC 信封完全一致）
    pub fn payload(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({ "code": self.code, "request_id": self.request_id });
        if let Some(p) = &self.params {
            obj["params"] = p.clone();
        }
        obj
    }
}

/// Tauri 框架错误 → `AppError::Internal`。
///
/// 受 `tauri-compat` feature 门控（见 manifest `[features]`）：本 impl 是本 crate 与
/// GUI 框架的**唯一**耦合点，关掉它，地基层就与框架彻底无关。孤儿规则要求它住在
/// 定义 `AppError` 的本 crate 内，下游无法自行补写 —— 故关闭该 feature 的调用方
/// 须在边界显式 `map_err`，不能靠 `?`。
#[cfg(feature = "tauri-compat")]
impl From<tauri::Error> for AppError {
    fn from(e: tauri::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

impl From<notify::Error> for AppError {
    fn from(e: notify::Error) -> Self {
        AppError::Internal(format!("File watcher error: {}", e))
    }
}

/// 允许在 crate::Result 函数中使用 anyhow::Context
///
/// 使用方式：在 Result<crate::AppError> 上调用 .context() / .with_context()
/// 后，通过 ? 运算符自动转换为 AppError::Internal（保留完整错误链）
impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

/// 链路加密共享 crate 错误 → AppError（issue 09：保留错误文案，
/// 过滤器 Reject 理由与既有测试断言的字节面不变）
impl From<wasmnest_link_crypto::LinkCryptoError> for AppError {
    fn from(e: wasmnest_link_crypto::LinkCryptoError) -> Self {
        AppError::Internal(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn envelope(err: &AppError) -> Value {
        serde_json::to_value(err).expect("AppError 必须可序列化为信封 JSON")
    }

    /// request_id 形状锁：8 位小写 hex。
    fn assert_request_id_shape(id: &Value) {
        let s = id.as_str().expect("request_id 必须是字符串");
        assert_eq!(s.len(), 8, "request_id 应为 8 hex，实际: {s}");
        assert!(
            s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "request_id 应全为小写 hex: {s}"
        );
    }

    #[test]
    fn non_user_facing_variants_default_to_host_internal() {
        for err in [
            AppError::Internal("database connection refused".into()),
            AppError::Database(rusqlite::Error::InvalidQuery),
            AppError::NotFound("file.txt".into()),
            AppError::InvalidInput("bad param".into()),
            AppError::Auth("expired".into()),
        ] {
            let v = envelope(&err);
            assert!(v.is_object(), "信封必须是对象，实际: {v:?}");
            assert_eq!(v["code"], json!(DEFAULT_ERROR_CODE), "未映射变体必须兜底 host.internal");
            assert_request_id_shape(&v["request_id"]);
        }
    }

    #[test]
    fn envelope_never_carries_technical_detail() {
        let err = AppError::Internal("secret detail: /root/key.pem failed at line 42".into());
        let v = serde_json::to_string(&err).expect("序列化");
        assert!(!v.contains("secret detail"), "信封携带技术详情: {v}");
        assert!(!v.contains("/root/key.pem"), "信封携带技术详情: {v}");
        assert!(!v.contains("line 42"), "信封携带技术详情: {v}");
        // 信封字段白名单：只有 code / request_id /（可选）params
        let obj = envelope(&err);
        let keys: Vec<&str> = obj.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        for key in &keys {
            assert!(
                matches!(*key, "code" | "request_id" | "params"),
                "信封出现白名单外字段: {key}"
            );
        }
    }

    #[test]
    fn user_facing_preserves_code_and_safe_params() {
        let err = AppError::user_facing(
            "host.plugin.trap",
            json!({ "name": "ai-chatbox" }),
            "wasm trap: unreachable at 0x1234",
        );
        let v = envelope(&err);
        assert_eq!(v["code"], json!("host.plugin.trap"));
        assert_eq!(v["params"], json!({ "name": "ai-chatbox" }));
        assert_request_id_shape(&v["request_id"]);
        // detail 永不出信封
        let s = serde_json::to_string(&err).unwrap();
        assert!(!s.contains("unreachable"), "信封携带 UserFacing.detail: {s}");
    }

    #[test]
    fn user_facing_null_params_omits_params_field() {
        let err = AppError::user_facing_simple("frontend.internal", "renderer crashed");
        let v = serde_json::to_value(&err).unwrap();
        assert!(
            v.as_object().unwrap().get("params").is_none(),
            "Null params 应省略: {v}"
        );
    }

    #[test]
    fn display_stays_unchanged_for_logging() {
        // Display 语义不变：日志 / 错误链照旧全量技术详情
        let internal = AppError::Internal("boom".into());
        assert_eq!(internal.to_string(), "Internal error: boom");
        let uf = AppError::user_facing("host.invoke.timeout", json!(null), "timed out after 30s");
        assert_eq!(uf.to_string(), "timed out after 30s");
    }

    #[test]
    fn request_id_is_renewed_per_serialization() {
        // 每次跨边界序列化都是独立失败事件：即使同一错误对象被序列化两次，
        // request_id 也必须不同（否则支持方无法区分两次失败）
        let err = AppError::Internal("boom".into());
        let a = serde_json::to_value(&err).unwrap();
        let b = serde_json::to_value(&err).unwrap();
        assert_ne!(a["request_id"], b["request_id"], "两次序列化必须生成不同 request_id");
        assert_eq!(a["code"], b["code"], "同一错误 code 必须稳定");
    }

    #[test]
    fn code_stability_registry_v0() {
        // ADR 0030 注册表 v0 宿主域基码：code 是公开契约，改码 = 破坏性变更
        assert_eq!(DEFAULT_ERROR_CODE, "host.internal");
        assert_eq!(
            AppError::user_facing_simple("host.invoke.timeout", "t").to_string(),
            "t"
        );
    }

    // ==================== 事件通道信封 ====================

    #[test]
    fn event_envelope_matches_ipc_envelope_shape() {
        let env = EventEnvelope::new("host.plugin.trap", json!({ "name": "ai-chatbox" }));
        let p = env.payload();
        assert_eq!(p["code"], json!("host.plugin.trap"));
        assert_eq!(p["params"], json!({ "name": "ai-chatbox" }));
        assert_request_id_shape(&p["request_id"]);
        // 字段白名单与 IPC 信封一致：事件侧不得多带字段（更不得带详情）
        let keys: Vec<&str> = p.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        for key in &keys {
            assert!(
                matches!(*key, "code" | "request_id" | "params"),
                "事件信封出现白名单外字段: {key}"
            );
        }
    }

    #[test]
    fn event_envelope_null_params_omits_params_field() {
        let p = EventEnvelope::new("host.internal", json!(null)).payload();
        assert!(
            p.as_object().unwrap().get("params").is_none(),
            "Null params 应省略: {p}"
        );
    }

    #[test]
    fn event_envelope_request_id_is_per_event() {
        let a = EventEnvelope::new("host.plugin.trap", json!(null));
        let b = EventEnvelope::new("host.plugin.trap", json!(null));
        assert_ne!(a.request_id, b.request_id, "两次失败事件必须各自生成追踪号");
        assert_eq!(a.payload()["code"], b.payload()["code"], "同一 code 必须稳定");
    }
}
