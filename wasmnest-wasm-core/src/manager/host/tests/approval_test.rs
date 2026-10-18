//! 审批门禁（ADR 0020 / 审计票 03）用例。

use super::scaffold::*;
use super::*;

// ==================== 审批门禁（ADR 0020 / 审计票 03） ====================

/// 注册一个「用户 zip 安装」的 TS-only 插件，安装目录指向 `dir`
async fn register_user_installed(host: &PluginHost, id: &str, dir: &Path, permissions: &[&str]) {
    let mut plugin = make_plugin(id, PluginSource::UserInstalled, PluginState::Loaded);
    plugin.manifest.permissions = permissions.iter().map(|p| p.to_string()).collect();
    plugin.extension_path = dir.to_string_lossy().to_string();
    host.plugins.write().await.insert(id.to_string(), plugin);
}

/// 无批准记录 → 拒绝激活、落 NeedsApproval、一位权限都不授予
#[tokio::test]
async fn user_installed_plugin_needs_approval_before_activation() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-needs-approval";
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join(PLUGIN_MANIFEST_FILE), r#"{"id":"x"}"#).unwrap();
    register_user_installed(&host, id, tmp.path(), &["storage", "terminal:input"]).await;

    let err = host.activate_plugin(id, false).await.unwrap_err();
    assert!(
        err.to_string().contains("requires user approval"),
        "必须显性报告「需人工批准」，实际: {err}"
    );
    assert!(!host.is_activated(id).await, "未批准的插件不得进入 Activated");
    assert_eq!(
        host.get_plugin(id).await.expect("plugin present").state,
        PluginState::NeedsApproval,
        "拒绝激活必须落 NeedsApproval（前端据此显示审批入口）"
    );
    assert!(
        host.permission().get_granted(id).is_empty(),
        "未批准路径不得授予任何权限（曾出现 storage 恒授予的旁路）"
    );
}

/// 批准后激活 → 生效权限 = 批准 ∩ 请求，且词汇表外的声明被丢弃
#[tokio::test]
async fn approve_then_activate_grants_only_effective_permissions() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-approve";
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join(PLUGIN_MANIFEST_FILE), r#"{"id":"x"}"#).unwrap();
    register_user_installed(
        &host,
        id,
        tmp.path(),
        &["storage", "not:a:permission", "terminal:input"],
    )
    .await;

    // 先撞一次门禁：状态落到待授权（真实用户路径）
    assert!(host.activate_plugin(id, false).await.is_err());

    let approved = host.approve_plugin(id).await.expect("approve ok");
    assert_eq!(
        approved,
        vec!["storage".to_string(), "terminal:input".to_string()],
        "批准清单只含词汇表内的声明位（保持声明顺序、丢弃装饰词汇）"
    );
    assert_eq!(
        host.get_plugin(id).await.expect("plugin present").state,
        PluginState::Deactivated,
        "批准只解除闸门：状态从待授权复位为未启用"
    );

    host.activate_plugin(id, false).await.expect("激活成功");
    assert_eq!(
        host.get_plugin(id).await.expect("plugin present").state,
        PluginState::Activated
    );
    let granted = host.permission().get_granted(id);
    assert!(granted.contains("storage"));
    assert!(granted.contains("terminal:input"));
    assert!(
        !granted.contains("not:a:permission"),
        "词汇表外的声明不得进入生效集，实际: {granted:?}"
    );
}

/// 批准集严格小于请求集 → 生效集跟着收窄（交集语义必须落到权限管理器）
#[tokio::test]
async fn activation_grants_only_approved_subset_of_declared() {
    use crate::security::approval::{compute_dir_hash, PluginApprovalStore};

    let host = setup_host().await;
    let id = "com.wasmnest.test-partial-approval";
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join(PLUGIN_MANIFEST_FILE), r#"{"id":"x"}"#).unwrap();
    register_user_installed(&host, id, tmp.path(), &["storage", "terminal:input", "process:run"]).await;

    // 只批准 storage（按位批准的记录形态：批准集是请求集的真子集）
    let hash = compute_dir_hash(tmp.path()).expect("hash ok");
    PluginApprovalStore::new(host.storage().clone())
        .approve(id, &["storage".to_string()], &hash, "1.0.0")
        .await
        .expect("seed approval");

    host.activate_plugin(id, false).await.expect("已批准 → 可激活");
    assert_eq!(
        host.permission().get_granted(id),
        HashSet::from(["storage".to_string()]),
        "生效集必须是批准 ∩ 请求，未批准的声明位不得因 manifest 声明而生效"
    );
}

/// 批准后目录内容变化 → 拒绝激活、撤销批准、回 NeedsApproval
#[tokio::test]
async fn approval_revoked_when_plugin_content_changes() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-hash-pin";
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join(PLUGIN_MANIFEST_FILE), r#"{"id":"x"}"#).unwrap();
    std::fs::write(tmp.path().join("index.js"), "console.log(1)").unwrap();
    register_user_installed(&host, id, tmp.path(), &["storage"]).await;

    host.approve_plugin(id).await.expect("approve ok");

    // 批准之后替换插件代码（在位冒名顶替）
    std::fs::write(tmp.path().join("index.js"), "console.log('evil')").unwrap();

    let err = host.activate_plugin(id, false).await.unwrap_err();
    assert!(err.to_string().contains("requires user approval"), "实际: {err}");
    assert_eq!(
        host.get_plugin(id).await.expect("plugin present").state,
        PluginState::NeedsApproval
    );
    let record = crate::security::approval::PluginApprovalStore::new(host.storage().clone())
        .get(id)
        .await
        .expect("read approvals");
    assert!(record.is_none(), "内容不匹配必须撤销批准记录");
    assert!(host.permission().get_granted(id).is_empty());
}

/// 私有库文件（plugin.db）运行期变化不得触发撤销：启用 → 停用 → 再启用仍可激活
#[tokio::test]
async fn runtime_private_db_does_not_invalidate_approval() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-private-db";
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join(PLUGIN_MANIFEST_FILE), r#"{"id":"x"}"#).unwrap();
    register_user_installed(&host, id, tmp.path(), &["storage"]).await;
    host.approve_plugin(id).await.expect("approve ok");

    // 首次启用会创建私有库；停用后再启用必须仍通过审批门禁
    host.activate_plugin(id, false).await.expect("首次激活");
    std::fs::write(tmp.path().join("plugin.db"), b"SQLite format 3").unwrap();
    host.deactivate_plugin(id, false).await.expect("停用");
    host.activate_plugin(id, false)
        .await
        .expect("再次激活不得被误判为内容被替换");
}

/// 信任分档：随包来源（内置 WASM / 文件扫描 / 静态注册）免审批
#[tokio::test]
async fn builtin_source_skips_approval_gate() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-builtin-scan";
    // 目录不存在也不触发哈希计算 —— 免审批来源根本不走审批门禁
    let mut plugin = make_plugin(id, PluginSource::FileScan, PluginState::Loaded);
    plugin.extension_path = "/nonexistent/plugins/com.wasmnest.test-builtin-scan".to_string();
    host.plugins.write().await.insert(id.to_string(), plugin);

    host.activate_plugin(id, false).await.expect("内置来源免审批");
    assert!(host.is_activated(id).await);
}

/// 对免审批来源调用批准 → 显性报错（不做无意义写入）
#[tokio::test]
async fn approve_rejects_trusted_source() {
    let host = setup_host().await;
    let id = "com.wasmnest.test-builtin-approve";
    host.plugins.write().await.insert(
        id.to_string(),
        make_plugin(id, PluginSource::FileScan, PluginState::Loaded),
    );

    let err = host.approve_plugin(id).await.unwrap_err();
    assert!(err.to_string().contains("approval is not required"), "实际: {err}");
}
