//! 认证中心裁决后的**连接身份**（ADR 0033）
//!
//! v33 起宿主不再持有任何设备 JWT 密码学（`utils/auth/jwt.rs` 已退役），
//! 认证面的一切判定都来自认证中心：本类型就是中心放行时交回来的那份身份。
//!
//! **它不是产品类型**（ADR 0022 B1 不命中）：宿主拿到它不是为了「知道这个设备是谁」
//! 而是为了三件纯传输面的事——
//! ① HTTP 请求上下文里标记「已认证」并派生转发给插件的 `caller` 上下文
//! （线协议字段 `deviceId` / `deviceName`，ADR 0022 §5.1.3 的「零解析窄转发」
//! 与 `host-websocket.connection-context` 的 `authContext` 同族）；
//! ② WS 连接的认证态与脱敏身份（`device_id` / `device_name` / `fingerprint`）；
//! ③ 日志与 `deny_kind` 诊断的 `device_id` 字段。
//!
//! **字段集被 ADR 0033 修订后的 L2 锁钉死**（`l2_gating_test.rs`：
//! `l2_identity_payload_is_pinned_identity_only`）：恰好这三个字段。宿主**不得**
//! 从中心返回值里读配对记录 / 信任列表 / 设备档案 / 任何别的产品事实——那些留在
//! 中心私有库，通过别的面按需取。ADR 0022 §5.1.4「宿主侧回查」红线在此的具体形态。
//!
//! 中心返回的 claims JSON 里除这三个字段外还有 `iss` / `iat` / `exp` / `kid`
//! （签发元数据，宿主不需要解读）——本模块**只挑这三个字段**，其余一律不看，
//! 这样中心加字段不会渗进宿主的判断。

use serde::Deserialize;

/// 认证通过后的连接身份（宿主侧唯一持有的一份）
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthenticatedIdentity {
    /// 设备 id（中心 claims 的 `sub`）
    #[serde(rename = "sub")]
    pub device_id: String,
    /// 设备名（可选；claims `device_name`）
    #[serde(rename = "device_name", default)]
    pub device_name: Option<String>,
    /// 设备指纹（可选；claims `fingerprint`）
    #[serde(rename = "fingerprint", default)]
    pub fingerprint: Option<String>,
}

impl AuthenticatedIdentity {
    /// 从认证中心返回的 claims JSON 解析出连接身份
    ///
    /// 只认 `sub`（设备 id）必填；缺 `sub` 或 JSON 非法 → 错误（**不**回退成
    /// 「未认证但放行」：中心说放行却给不出身份，是中心侧的可观测性故障，
    /// 宿主这一侧必须显性失败而不是猜一个身份）。
    pub fn from_center_claims(claims_json: &str) -> Result<Self, String> {
        let identity: Self = serde_json::from_str(claims_json)
            .map_err(|e| format!("auth center claims unusable (no device identity): {e}"))?;
        if identity.device_id.is_empty() {
            return Err("auth center claims unusable (empty device subject)".to_string());
        }
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 正例：中心 claims 的三字段被完整取出，签发元数据被忽略
    #[test]
    fn parses_identity_and_ignores_issuing_metadata() {
        let identity = AuthenticatedIdentity::from_center_claims(
            r#"{"sub":"device-1","iss":"WasmNest","iat":1700000000,"exp":1700604800,
                "device_name":"Pixel 9","fingerprint":"fp-abc","kid":"g3"}"#,
        )
        .expect("identity");
        assert_eq!(identity.device_id, "device-1");
        assert_eq!(identity.device_name.as_deref(), Some("Pixel 9"));
        assert_eq!(identity.fingerprint.as_deref(), Some("fp-abc"));
    }

    /// 边界：可选字段缺省（中心不提供设备名 / 指纹时不得报错）
    #[test]
    fn optional_fields_default_to_none() {
        let identity = AuthenticatedIdentity::from_center_claims(r#"{"sub":"device-1"}"#).expect("identity");
        assert_eq!(identity.device_id, "device-1");
        assert_eq!(identity.device_name, None);
        assert_eq!(identity.fingerprint, None);
    }

    /// 反例：空串设备名 = 缺省（中心用空串表达「没有」）
    #[test]
    fn empty_device_name_is_kept_verbatim() {
        // 空串不是「缺字段」也不是 None——如实透传，由消费方决定语义
        let identity =
            AuthenticatedIdentity::from_center_claims(r#"{"sub":"device-1","device_name":""}"#).expect("identity");
        assert_eq!(identity.device_name.as_deref(), Some(""));
    }

    /// 反例：缺 `sub` / 空 `sub` / 非法 JSON → 显性错误（绝不猜身份）
    #[test]
    fn unusable_claims_fail_loudly() {
        for (raw, needle) in [
            (r#"{"iss":"WasmNest"}"#, "no device identity"),
            (r#"{"sub":""}"#, "empty device subject"),
            ("not json", "no device identity"),
            ("null", "no device identity"),
            (r#"{"sub":123}"#, "no device identity"),
        ] {
            let err = AuthenticatedIdentity::from_center_claims(raw).expect_err("必须报错");
            assert!(err.contains(needle), "形态 [{needle}] 报错不符: {err}");
        }
    }

    /// 中心加字段不得渗进宿主：claims 里出现未知字段仍能解析，且**不会**变成
    /// 宿主可见的结构（`deny_unknown_fields` 关闭时未知字段被丢弃）
    #[test]
    fn unknown_center_fields_do_not_leak_into_host_type() {
        let identity = AuthenticatedIdentity::from_center_claims(
            r#"{"sub":"device-1","pairingId":"p-1","trustLevel":"high","rotateCount":3}"#,
        )
        .expect("identity");
        // 宿主类型里没有这些字段——它们只留在中心的 JSON 里
        assert_eq!(
            identity,
            AuthenticatedIdentity {
                device_id: "device-1".to_string(),
                device_name: None,
                fingerprint: None,
            }
        );
    }
}
