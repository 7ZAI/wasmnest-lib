//! 形状契约锁（对外响应逐字节一致） — crate 内单元测试（自 packages/wasmnest-server-http/src/gateway.rs 迁出）

use super::scaffold::*;
use super::*;

/// 业务端点响应形状 golden：宿主侧当前输出即契约，插件面必须逐字段复刻。
///
/// 锁的是「JSON 形状」而不是「实现在哪」：DTO 的 serde 表示就是移动端看到的字节。
/// 票 02/03/04 的插件端点回包必须与本用例逐字段相同（含可选字段的缺席形态）。
#[test]
fn business_endpoint_shapes_are_locked() {
    use crate::dtos::config_dto::{ConfigItem, ConfigListResponseData, QuickActionItem, QuickActionListResponseData};
    use crate::dtos::file_dto::{
        FileContentResponseData, FileDiffLine, FileDiffResponseData, FileTreeNode, FileTreeResponseData,
    };
    use crate::dtos::git_dto::{GitBranchesResponseData, GitCheckoutResponseData, GitStatusResponseData};

    // GET /api/configs
    assert_shape(
        ApiResponse::ok_with_data(ConfigListResponseData {
            configs: vec![ConfigItem {
                id: "c1".into(),
                name: "工作台".into(),
                environment: "linux".into(),
                wsl_distro: None,
                working_dir: "/srv/app".into(),
                command: "bash".into(),
            }],
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "configs": [{
                "id": "c1", "name": "工作台", "environment": "linux", "wslDistro": null,
                "workingDir": "/srv/app", "command": "bash"
            }] }
        }),
    );
    // wslDistro 为 None 时是 **显式 null**（ConfigItem 没有 skip_serializing_if）
    assert_shape(
        ApiResponse::ok_with_data(ConfigListResponseData {
            configs: vec![ConfigItem {
                id: "c2".into(),
                name: "wsl".into(),
                environment: "wsl".into(),
                wsl_distro: Some("Ubuntu-24.04".into()),
                working_dir: "/home/u".into(),
                command: "claude".into(),
            }],
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "configs": [{
                "id": "c2", "name": "wsl", "environment": "wsl", "wslDistro": "Ubuntu-24.04",
                "workingDir": "/home/u", "command": "claude"
            }] }
        }),
    );

    // GET /api/quick-actions
    assert_shape(
        ApiResponse::ok_with_data(QuickActionListResponseData {
            actions: vec![
                QuickActionItem {
                    id: "a1".into(),
                    name: "提交".into(),
                    content: "git commit".into(),
                    icon: None,
                    color: None,
                },
                QuickActionItem {
                    id: "a2".into(),
                    name: "推送".into(),
                    content: "git push".into(),
                    icon: Some("upload".into()),
                    color: Some("#ff0000".into()),
                },
            ],
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "actions": [
                { "id": "a1", "name": "提交", "content": "git commit", "icon": null, "color": null },
                { "id": "a2", "name": "推送", "content": "git push", "icon": "upload", "color": "#ff0000" }
            ] }
        }),
    );

    // POST /api/file-tree 与 POST /api/diff-tree 共用同一树形状
    let tree = ApiResponse::ok_with_data(FileTreeResponseData {
        tree: vec![
            FileTreeNode {
                name: "src".into(),
                node_type: "directory".into(),
                path: Some("src".into()),
                children: Some(vec![FileTreeNode {
                    name: "main.rs".into(),
                    node_type: "file".into(),
                    path: Some("src/main.rs".into()),
                    children: None,
                }]),
            },
            FileTreeNode {
                name: ".git".into(),
                node_type: "directory".into(),
                path: None,
                children: None,
            },
        ],
    });
    assert_shape(
        tree.clone(),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "tree": [
                { "name": "src", "nodeType": "directory", "path": "src", "children": [
                    { "name": "main.rs", "nodeType": "file", "path": "src/main.rs" }
                ] },
                { "name": ".git", "nodeType": "directory" }
            ] }
        }),
    );

    // POST /api/file-content
    assert_shape(
        ApiResponse::ok_with_data(FileContentResponseData {
            content: "hello".into(),
            file_name: "b.txt".into(),
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "content": "hello", "fileName": "b.txt" }
        }),
    );

    // POST /api/file-diff
    assert_shape(
        ApiResponse::ok_with_data(FileDiffResponseData {
            file_name: "a.rs".into(),
            lines: vec![
                FileDiffLine {
                    line_type: "removed".into(),
                    content: "let a = 1;".into(),
                    old_line_no: Some(3),
                    new_line_no: None,
                },
                FileDiffLine {
                    line_type: "added".into(),
                    content: "let a = 2;".into(),
                    old_line_no: None,
                    new_line_no: Some(3),
                },
                FileDiffLine {
                    line_type: "context".into(),
                    content: "".into(),
                    old_line_no: Some(4),
                    new_line_no: Some(4),
                },
            ],
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "fileName": "a.rs", "lines": [
                { "type": "removed", "content": "let a = 1;", "oldLineNo": 3 },
                { "type": "added", "content": "let a = 2;", "newLineNo": 3 },
                { "type": "context", "content": "", "oldLineNo": 4, "newLineNo": 4 }
            ] }
        }),
    );

    // GET /api/git/branches：非 git 仓库与仓库两态
    assert_shape(
        ApiResponse::ok_with_data(GitBranchesResponseData {
            current_branch: None,
            branches: vec![],
            is_git_repo: false,
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "currentBranch": null, "branches": [], "isGitRepo": false }
        }),
    );
    assert_shape(
        ApiResponse::ok_with_data(GitBranchesResponseData {
            current_branch: Some("main".into()),
            branches: vec!["main".into(), "dev".into()],
            is_git_repo: true,
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "currentBranch": "main", "branches": ["main", "dev"], "isGitRepo": true }
        }),
    );

    // GET /api/git/status
    assert_shape(
        ApiResponse::ok_with_data(GitStatusResponseData {
            has_changes: true,
            changed_count: 2,
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "hasChanges": true, "changedCount": 2 }
        }),
    );

    // POST /api/git/checkout
    assert_shape(
        ApiResponse::ok_with_data(GitCheckoutResponseData { branch: "dev".into() }),
        serde_json::json!({ "code": 0, "message": "ok", "data": { "branch": "dev" } }),
    );

    // 错误信封：这些端点今天全部是 HTTP 200 + 业务码。插件面必须同口径
    assert_shape(
        ApiResponse::<()>::error(404, "Session not found"),
        serde_json::json!({ "code": 404, "message": "Session not found" }),
    );

    // ABI v29（sessions REST 下沉）：/api/sessions* 七条由插件 sessions_http 域
    // 复刻旧宿主控制器形状——SessionItem / StartSessionResponseData /
    // SessionHistoryData 的 serde 表示即移动端看到的字节，插件面必须逐字段同形
    use crate::dtos::session_dto::{
        SessionHistoryData, SessionItem, SessionListResponseData, StartSessionResponseData,
    };
    assert_shape(
        ApiResponse::ok_with_data(SessionListResponseData {
            sessions: vec![SessionItem {
                id: "s-1".into(),
                name: "工作台".into(),
                status: "Running".into(),
                created_at: "2026-09-25T00:00:00Z".into(),
                started_at: Some("2026-09-25T00:00:01Z".into()),
                session_type: Some("pty".into()),
                config_id: Some("c1".into()),
                task_status: Some("idle".into()),
                task_reason: None,
            }],
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "sessions": [{
                "id": "s-1", "name": "工作台", "status": "Running",
                "createdAt": "2026-09-25T00:00:00Z", "startedAt": "2026-09-25T00:00:01Z",
                "sessionType": "pty", "configId": "c1", "taskStatus": "idle"
            }] }
        }),
    );
    assert_shape(
        ApiResponse::ok_with_data(StartSessionResponseData {
            session_id: "s-2".into(),
            status: "running".into(),
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": { "sessionId": "s-2", "status": "running" }
        }),
    );
    assert_shape(
        ApiResponse::ok_with_data(SessionHistoryData {
            min_offset: 0,
            snapshot_offset: 1024,
            history_bytes: 2048,
            data_base64: "aGVsbG8=".into(),
        }),
        serde_json::json!({
            "code": 0, "message": "ok",
            "data": {
                "minOffset": 0, "snapshotOffset": 1024, "historyBytes": 2048,
                "dataBase64": "aGVsbG8="
            }
        }),
    );
}
