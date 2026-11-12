//! File API DTOs
//!
//! 文件树、文件内容、Diff 树、文件 Diff 相关请求/响应类型

use serde::{Deserialize, Serialize};

// ==================== File Tree DTOs ====================

/// POST /api/file-tree request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTreeRequest {
    /// 会话 ID（优先使用）或配置 ID（会话未运行时使用）
    pub session_id: String,
    pub exclude_dirs: Vec<String>,
}

/// POST /api/file-tree response data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTreeResponseData {
    pub tree: Vec<FileTreeNode>,
}

/// File tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTreeNode {
    pub name: String,
    pub node_type: String,
    /// 相对于工作目录的路径（如 "src/main.rs"）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<FileTreeNode>>,
}

// ==================== File Tree Children DTOs ====================

/// GET /api/file-tree-children query params
#[derive(Debug, Clone, Deserialize)]
pub struct FileTreeChildrenQuery {
    /// 会话 ID 或配置 ID
    pub session_id: String,
    /// 相对于工作目录的路径，空或 "." 表示根目录
    pub dir_path: Option<String>,
    /// 逗号分隔的排除目录列表
    pub exclude_dirs: Option<String>,
}

/// GET /api/file-tree-children response data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTreeChildrenResponseData {
    pub children: Vec<FileTreeNode>,
}

// ==================== File Content DTOs ====================

/// POST /api/file-content request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileContentRequest {
    /// 会话 ID（优先使用）或配置 ID（会话未运行时使用）
    pub session_id: String,
    pub file_path: String,
}

/// POST /api/file-content response data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileContentResponseData {
    pub content: String,
    pub file_name: String,
}

// ==================== Diff Tree DTOs ====================

/// POST /api/diff-tree request
///
/// 与 FileTreeRequest 相同参数，返回仅包含 git 改动文件的树
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffTreeRequest {
    /// 会话 ID（优先使用）或配置 ID（会话未运行时使用）
    pub session_id: String,
    pub exclude_dirs: Vec<String>,
}

// ==================== File Diff DTOs ====================

/// POST /api/file-diff request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDiffRequest {
    /// 会话 ID（优先使用）或配置 ID（会话未运行时使用）
    pub session_id: String,
    pub file_path: String,
}

/// Diff 行类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDiffLine {
    /// "context" | "added" | "removed"
    #[serde(rename = "type")]
    pub line_type: String,
    /// 行内容（不含 +/- 前缀）
    pub content: String,
    /// 旧文件行号（removed 和 context 有值，added 为 null）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line_no: Option<u32>,
    /// 新文件行号（added 和 context 有值，removed 为 null）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line_no: Option<u32>,
}

/// POST /api/file-diff response data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDiffResponseData {
    pub file_name: String,
    pub lines: Vec<FileDiffLine>,
}
