//! 目录扫描去重用例（内置目录 vs 用户安装目录）。
//!
//! 现场来源：随包插件（`resources/plugins/desktop`）与用户此前用文件安装的同 id
//! 副本（`app_data/plugins`）同时存在时，用户副本会顶替内置条目——插件信任档从
//! `Wasm`/`FileScan` 降级为 `UserInstalled`，激活被审批门禁拒绝，日志表现为
//! 「随包插件报 requires user approval」。根因是两次 `load_all` 各持一份
//! `seen_ids`，跨扫描去重缺失；本用例从宿主入口（`PluginHost::new`）锁住修复。

use super::*;

/// 同 id 同时存在于内置与用户目录：内置条目必须胜出，且激活不得被审批门禁拒绝
#[tokio::test]
async fn user_copy_must_not_shadow_builtin_scan_plugin() {
    // AppConfig 全局初始化（与 setup_host 同策略，重复 init 幂等）
    static CONFIG_INIT: std::sync::Once = std::sync::Once::new();
    CONFIG_INIT.call_once(|| {
        let mut config = AppConfig::default();
        config.network.port = 8765;
        AppConfig::init(config);
    });

    let tmp_dir = tempfile::TempDir::new().unwrap();
    let builtin_dir = tmp_dir.path().join("builtin");
    let user_dir = tmp_dir.path().join("user");
    let shadowed_id = "com.wasmnest.test-shadow-dup";

    // 两侧写同一 id 的最小 TS-only 插件（无 rust_library → 不需要 wasm 产物，
    // 排除「实例化失败」这一无关变量）
    for dir in [&builtin_dir, &user_dir] {
        let plugin_dir = dir.join(shadowed_id);
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join(PLUGIN_MANIFEST_FILE),
            format!(
                r#"{{"id": "{}", "name": "Shadow Test", "version": "1.0.0", "platform": "both", "main": "index.js", "permissions": ["storage"]}}"#,
                shadowed_id
            ),
        )
        .unwrap();
    }

    let db = Arc::new(std::sync::Mutex::new(
        Database::new(&std::path::PathBuf::from(":memory:")).unwrap(),
    ));
    db.lock().expect("db lock").init_schema().unwrap();
    let host = PluginHost::new(
        db,
        &builtin_dir,
        &user_dir,
        None,
        None,
        Vec::new(),
        crate::manager::runtime::AbiPolicy::UNCONSTRAINED,
        std::sync::Arc::new(crate::host_api::ports::UnimplementedHostFacts),
        None,
        None,
    )
    .await;

    let info = host.get_plugin(shadowed_id).await.expect("plugin present");
    assert_eq!(
        info.source, "scanned",
        "同 id 时内置（文件扫描）条目必须胜出，用户副本不得顶替（顶替即降级为 user-installed）"
    );
    assert_eq!(
        info.extension_path,
        builtin_dir.join(shadowed_id).to_string_lossy().to_string(),
        "扩展路径必须指向内置目录（用户副本的路径不得生效）"
    );

    // 现象级断言：随包插件不再因「用户副本顶替」被审批门禁拒绝激活
    host.activate_plugin(shadowed_id, false)
        .await
        .expect("内置来源免审批，激活不得被审批门禁拒绝");
    assert_eq!(
        host.get_plugin(shadowed_id)
            .await
            .expect("plugin present")
            .state,
        PluginState::Activated
    );
}
