//! Session DTOs

use serde::{Deserialize, Serialize};

/// GET /api/sessions response data
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionListResponseData {
    pub sessions: Vec<SessionItem>,
}

/// Single session item in list response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionItem {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub session_type: Option<String>,
    pub config_id: Option<String>,
    /// 任务执行状态
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_status: Option<String>,
    /// 任务状态原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_reason: Option<String>,
}

/// POST /api/sessions/start request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartSessionRequest {
    pub config_id: String,
    /// 启动端终端组件默认网格列数（与 rows 同时提供且 >0 才生效）
    #[serde(default)]
    pub cols: Option<u16>,
    /// 启动端终端组件默认网格行数
    #[serde(default)]
    pub rows: Option<u16>,
}

/// POST /api/sessions/start response data
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartSessionResponseData {
    pub session_id: String,
    pub status: String,
}

/// POST /api/sessions/{id}/resize request
#[derive(Debug, Clone, Deserialize)]
pub struct ResizeSessionRequest {
    pub cols: u16,
    pub rows: u16,
    /// 覆盖确认标志：服务端裁决返回 needsConfirmation 后，客户端弹窗确认以 force=true 重发
    #[serde(default)]
    pub force: bool,
}

/// POST /api/sessions/{id}/input request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInputRequest {
    /// 输入文本数据
    pub data: String,
    /// 特殊按键（如 "enter", "ctrl_c", "arrow_up" 等）
    #[serde(default)]
    pub special_key: Option<String>,
}

/// GET /api/sessions/{id}/history query（TB v3 字节锚点；缺省 from=0 = min_offset 起）
#[derive(Debug, Clone, Deserialize)]
pub struct SessionHistoryQuery {
    /// 起始字节偏移（历史一次性拉取的游标；旧于 min_offset 时收敛到 min_offset）
    #[serde(default)]
    pub from: Option<u64>,
}

/// GET /api/sessions/{id}/history response data（字节三件套 + 一次性历史字节）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHistoryData {
    /// 队列最早存续字节位置（环形淘汰后推进；客户端游标 < minOffset → 截断）
    pub min_offset: u64,
    /// 拉取时刻累计字节数（历史边界）
    pub snapshot_offset: u64,
    /// 驻留历史总字节数
    pub history_bytes: u64,
    /// `[from, snapshot_offset)` 字节（Base64；半块在 chunk 边界内精确切片）
    pub data_base64: String,
}
