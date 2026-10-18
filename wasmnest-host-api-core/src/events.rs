//! 事件域实现层（载荷规范化语义，票 18 批次 4）
//!
//! 自桌面 `packages/wasmnest-wasm-core/src/host_api/events.rs` 提取的**机制语义**：
//! 事件载荷必须严格 JSON（fail-visible）——非法载荷直接拒绝（H-05），降级成
//! 字符串会让 guest 以为已投递、前端收到形状不同的载荷、监听方按原 schema
//! 解析运行时失败且无信号（静默降级的断链形态）。
//!
//! 双端差异点名（以桌面机制为准，2026-10-09 用户指令）：桌面 emit 走严格拒绝；
//! 移动此前把非法载荷降级为字符串 + warn——接入本层后**行为对齐**（Err 上抛，
//! 错误文案与桌面逐字一致）。
//!
//! ## 不抽的面（各端平台接入）
//!
//! - **投递通道**：tauri `Emitter`（宿主平台，共享核禁引）——桌面
//!   `host_api/events.rs` / 移动 `host_impl/event.rs` 各自保留；
//! - **notify**：桌面是前端事件（`plugin:notify` JSON 载荷），移动是 Android
//!   原生通知（Kotlin 桥）——两者语义不同，属各端平台能力，不抽。

/// 事件载荷严格解析：非法 JSON 即 Err（文案与桌面既有行为逐字一致）
pub fn parse_event_payload(payload_json: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(payload_json)
        .map_err(|e| format!("event emit failed: payload is not valid JSON: {e}"))
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 合法 JSON 通过，值原样返回
    #[test]
    fn valid_payload_parsed() {
        let v = parse_event_payload(r#"{"ok":true}"#).unwrap();
        assert_eq!(v, serde_json::json!({"ok": true}));
    }

    /// 非法 JSON：Err 且点名 JSON 解析失败（H-05 fail-visible 文案）
    #[test]
    fn invalid_payload_rejected() {
        let err = parse_event_payload("not-json").unwrap_err();
        assert!(err.contains("not valid JSON"), "错误须点名 JSON 解析失败: {err}");
    }
}
