//! PTY Session Status
//!
//! PTY 会话状态枚举

use serde::{Deserialize, Serialize};

/// PTY 会话状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtySessionStatus {
    Starting,
    Running,
    WaitingInput,
    Stopped,
    Error,
}
