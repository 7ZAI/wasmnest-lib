//! 传输批状态机与接收策略：纯数据模型 + 纯函数（无头单测惯例）。
//!
//! 移植自 git 标签 v2.0.0 的移动端 `file_service/transfer.rs` 批状态机并去
//! host 化：剥离 plugin_id / mount_path 宿主挂载概念与插件 API 类型依赖，
//! 只保留「一次发送动作的文件集合」这一领域内核。状态操作在会话引擎
//! （`super`）内实现；本模块不含任何 tokio / IO 依赖，独立单测。
//!
//! 核心安全规则（沿用种子约定）：
//! - pending → approved / rejected 是仅有的合法迁移；终态批重复应答一律拒绝；
//! - ask 超时由会话引擎执行自动拒绝（默认 60s，可配 10..=600s）；
//! - 批记录为内存态，不持久化（会话随连接生灭，无跨重启语义）。

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

// ==================== 常量 ====================

/// 默认询问超时（秒）：接收端「每次询问」策略等待宿主应答的窗口
pub const DEFAULT_ASK_TIMEOUT_SECS: u64 = 60;
/// 询问超时下限（秒）
pub const MIN_ASK_TIMEOUT_SECS: u64 = 10;
/// 询问超时上限（秒）
pub const MAX_ASK_TIMEOUT_SECS: u64 = 600;

// ==================== 数据模型 ====================

/// 批内单个文件的元数据（Offer 线载荷与批记录共用）
///
/// `path` 是发送方视角的相对路径（保留相对形状供接收端落位/展示），
/// 不含绝对路径——绝对路径既泄露目录结构，也使接收端无法安全落位。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    /// 发送方相对路径（`/` 分隔）
    pub path: String,
    /// 文件字节数
    pub size: u64,
}

impl FileMeta {
    /// 构造单文件元数据
    pub fn new(path: impl Into<String>, size: u64) -> Self {
        Self {
            path: path.into(),
            size,
        }
    }
}

/// 共享目录列目录返回的单条目（BrowseResponse 线载荷）
///
/// 与 [`FileMeta`] 刻意分离：浏览条目携带 `is_dir`（目录可继续下钻、文件可
/// 拉取），而传输清单恒为文件；两套形状独立演进互不牵制。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// 条目名（不含路径分隔）
    pub name: String,
    /// 是否目录
    pub is_dir: bool,
    /// 文件字节数（目录恒 0）
    pub size: u64,
}

impl DirEntry {
    /// 构造单条目
    pub fn new(name: impl Into<String>, is_dir: bool, size: u64) -> Self {
        Self {
            name: name.into(),
            is_dir,
            size,
        }
    }
}

/// 批状态（沿用种子三态；approved 由会话引擎即时消费，故无需 approved TTL 态）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchState {
    /// ask 后等待宿主应答（引擎按超时自动拒绝）
    Pending,
    /// 宿主接受 / 策略直接放行
    Approved,
    /// 拒绝（终态，不可再迁移）
    Rejected { reason: RejectReason },
}

/// 拒绝原因（wire kebab-case，显式 rename 锁死线上契约，两端逐字一致）
///
/// 相比种子新增 `policy-denied`：「直接拒绝」策略分支与「用户点拒」文案不同，
/// 发送端据此区分展示；wire 值互不冲突。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    /// 宿主点了拒绝
    #[serde(rename = "user-rejected")]
    UserRejected,
    /// 询问等待超时（引擎自动拒）
    #[serde(rename = "timeout")]
    Timeout,
    /// 接收策略为「直接拒绝」（非用户即时操作）
    #[serde(rename = "policy-denied")]
    PolicyDenied,
    /// 浏览/拉取目标在共享目录中不存在（含路径越界——只读暴露面不区分
    /// 「不存在」与「越界」，不向对端泄露目录结构信息）
    #[serde(rename = "not-found")]
    NotFound,
    /// 共享目录条目存在但读取失败（IO/授权失效等，issue 07 服务端读路径）
    #[serde(rename = "read-failed")]
    ReadFailed,
}

impl RejectReason {
    /// wire 字符串（事件上报 / 日志用，与 serde rename 保持同一契约源）
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::UserRejected => "user-rejected",
            RejectReason::Timeout => "timeout",
            RejectReason::PolicyDenied => "policy-denied",
            RejectReason::NotFound => "not-found",
            RejectReason::ReadFailed => "read-failed",
        }
    }
}

/// 传输批记录（会话内存态，不持久化）
///
/// 相比种子去掉 plugin_id / mount_path（宿主挂载概念）与 approved 24h TTL
/// （peer-net 会话中批被批准后立即在活连接上消费，不存在长驻等待窗口）。
#[derive(Debug, Clone)]
pub struct TransferBatch {
    /// 批 ID（发送方生成，跨端唯一标识一次「发送」动作）
    pub batch_id: String,
    /// 批内文件清单
    pub files: Vec<FileMeta>,
    /// 批内文件总大小（字节）
    pub total_size: u64,
    /// 当前状态
    pub state: BatchState,
    /// 创建时间（pending 超时计时基线）
    pub created_at: Instant,
}

/// 接收策略（spec Decision 10：全局单开关粒度，不区分对端；与信任层正交）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivePolicy {
    /// 每次询问（默认）：批进入 pending 等待宿主应答，超时自动拒
    Ask { timeout: Duration },
    /// 直接接收：不弹任何询问
    AlwaysAccept,
    /// 直接拒绝：Offer 一律回 policy-denied
    AlwaysDeny,
}

impl Default for ReceivePolicy {
    fn default() -> Self {
        ReceivePolicy::Ask {
            timeout: Duration::from_secs(DEFAULT_ASK_TIMEOUT_SECS),
        }
    }
}

// ==================== 纯函数 ====================

/// 纯函数：校验批状态迁移（应答命令与超时扫描共用）
///
/// 仅 pending → approved / rejected 合法；已终态批重复应答、approved 后再
/// 拒绝等一律拒绝。
pub fn validate_batch_transition(
    from: &BatchState,
    to: &BatchState,
) -> Result<(), &'static str> {
    match (from, to) {
        (BatchState::Pending, BatchState::Approved) => Ok(()),
        (BatchState::Pending, BatchState::Rejected { .. }) => Ok(()),
        _ => Err("invalid batch state transition"),
    }
}

/// 纯函数：批是否处于已批准状态
pub fn is_approved(batch: &TransferBatch) -> bool {
    matches!(batch.state, BatchState::Approved)
}

/// 纯函数：pending 批是否已超时（超时值来自接收策略而非批的固有属性，显式传入）
pub fn is_batch_expired(batch: &TransferBatch, ask_timeout: Duration) -> bool {
    matches!(batch.state, BatchState::Pending)
        && Instant::now().saturating_duration_since(batch.created_at) >= ask_timeout
}

/// 纯函数：校验询问超时值（10..=600 秒）
pub fn validate_ask_timeout_secs(secs: u64) -> Result<u64, &'static str> {
    if (MIN_ASK_TIMEOUT_SECS..=MAX_ASK_TIMEOUT_SECS).contains(&secs) {
        Ok(secs)
    } else {
        Err("ask timeout must be in 10..=600 seconds")
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_batch(total: u64) -> TransferBatch {
        TransferBatch {
            batch_id: "b-1".to_string(),
            files: vec![FileMeta::new("a.txt", total)],
            total_size: total,
            state: BatchState::Pending,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn pending_transitions_to_approved_and_rejected_only() {
        let approved = BatchState::Approved;
        let rejected = BatchState::Rejected {
            reason: RejectReason::UserRejected,
        };
        let done = BatchState::Approved;

        assert!(validate_batch_transition(&BatchState::Pending, &approved).is_ok());
        assert!(validate_batch_transition(&BatchState::Pending, &rejected).is_ok());
        // 终态不可再迁移
        assert!(validate_batch_transition(&approved, &rejected).is_err());
        assert!(validate_batch_transition(&rejected, &done).is_err());
    }

    #[test]
    fn reject_reason_wire_values_are_kebab_locked() {
        assert_eq!(RejectReason::UserRejected.as_str(), "user-rejected");
        assert_eq!(RejectReason::Timeout.as_str(), "timeout");
        assert_eq!(RejectReason::PolicyDenied.as_str(), "policy-denied");
        assert_eq!(RejectReason::NotFound.as_str(), "not-found");
        assert_eq!(RejectReason::ReadFailed.as_str(), "read-failed");

        // serde 往返保持 wire 契约
        for reason in [
            RejectReason::UserRejected,
            RejectReason::Timeout,
            RejectReason::PolicyDenied,
            RejectReason::NotFound,
            RejectReason::ReadFailed,
        ] {
            let json = serde_json::to_string(&reason).expect("serialize reason");
            let back: RejectReason = serde_json::from_str(&json).expect("deserialize reason");
            assert_eq!(back, reason);
        }
        assert_eq!(
            serde_json::to_string(&RejectReason::NotFound).expect("serde"),
            "\"not-found\""
        );
    }

    #[test]
    fn dir_entry_serializes_flat_for_wire() {
        let entry = DirEntry::new("docs", true, 0);
        let json = serde_json::to_string(&entry).expect("serialize dir entry");
        assert_eq!(json, r#"{"name":"docs","is_dir":true,"size":0}"#);
        let back: DirEntry = serde_json::from_str(&json).expect("deserialize dir entry");
        assert_eq!(back, entry);
    }

    #[test]
    fn expiry_applies_only_to_pending_with_explicit_timeout() {
        let ask_timeout = Duration::from_secs(1);
        let mut batch = pending_batch(10);

        // 刚创建未超时
        assert!(!is_batch_expired(&batch, ask_timeout));

        // 人为把创建时间拨回超时窗口之外
        batch.created_at = Instant::now() - ask_timeout - Duration::from_millis(50);
        assert!(is_batch_expired(&batch, ask_timeout));

        // 非 pending 批永不过期（approved 即时消费、rejected 已终态）
        batch.state = BatchState::Approved;
        assert!(!is_batch_expired(&batch, ask_timeout));
        batch.state = BatchState::Rejected {
            reason: RejectReason::Timeout,
        };
        assert!(!is_batch_expired(&batch, ask_timeout));
    }

    #[test]
    fn is_approved_reflects_state() {
        let mut batch = pending_batch(10);
        assert!(!is_approved(&batch));
        batch.state = BatchState::Approved;
        assert!(is_approved(&batch));
    }

    #[test]
    fn ask_timeout_bounds_are_enforced() {
        assert_eq!(validate_ask_timeout_secs(10), Ok(10));
        assert_eq!(validate_ask_timeout_secs(600), Ok(600));
        assert!(validate_ask_timeout_secs(9).is_err());
        assert!(validate_ask_timeout_secs(601).is_err());
    }

    #[test]
    fn default_policy_is_ask_with_default_window() {
        match ReceivePolicy::default() {
            ReceivePolicy::Ask { timeout } => {
                assert_eq!(timeout, Duration::from_secs(DEFAULT_ASK_TIMEOUT_SECS))
            }
            other => panic!("default policy must be Ask, got {other:?}"),
        }
    }

    #[test]
    fn file_meta_serializes_flat_for_wire() {
        let meta = FileMeta::new("docs/a b.txt", 42);
        let json = serde_json::to_string(&meta).expect("serialize file meta");
        assert_eq!(json, r#"{"path":"docs/a b.txt","size":42}"#);
        let back: FileMeta = serde_json::from_str(&json).expect("deserialize file meta");
        assert_eq!(back, meta);
    }
}
