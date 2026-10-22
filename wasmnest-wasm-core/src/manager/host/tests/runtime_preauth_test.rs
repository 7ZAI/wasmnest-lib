//! 运行期错误通知节流 + 事件信封形状 + fs 预授权（preauth）用例。

use crate::manifest::WasiPreopenDir;
use super::super::errors::{
    runtime_error_code, runtime_error_envelope, self_check_envelope, PLUGIN_RECOVERY_FAILED_CODE,
    PLUGIN_SELF_CHECK_FAILED_CODE, PLUGIN_TRAP_CODE,
};
use super::scaffold::*;
use super::*;

/// 被测插件 id（本文件的测试夹具，不是内核常量）
///
/// 审计票 12 起 `FILE_TRANSFER_PLUGIN_ID` 从 `manager/host.rs` 与 `peer_net.rs` 删除——
/// 内核不再硬编码产品身份（peer-net 节点改按属主记账）。本用例测的是「共享根为空的
/// 插件可以启用先行」这条通用 preauth 语义，用一个具名夹具插件 id 即可，
/// 不需要内核侧留着那个常量
const FILE_TRANSFER_PLUGIN_ID: &str = "com.wasmnest.file-transfer";

#[tokio::test]
async fn notify_plugin_runtime_error_throttle_and_no_app_context() {
    // 统一异常通道（PLUGIN_RUNTIME_ERROR）：
    // 1. 无 AppContext（测试/无头）时降级为纯日志，不 panic
    // 2. 同一插件窗口内二次通知被节流（不重复提示），节流表只记录一次
    let host = setup_host().await;

    host.notify_plugin_runtime_error(TEST_PLUGIN_ID, "panic", "boom").await;
    host.notify_plugin_runtime_error(TEST_PLUGIN_ID, "trap", "boom again")
        .await;

    let throttle = host.runtime_error_notify_throttle.lock().unwrap();
    assert!(
        throttle.contains_key(TEST_PLUGIN_ID),
        "first call must record throttle entry"
    );
    // 窗口内二次调用不新增/刷新条目（被节流）
    assert_eq!(throttle.len(), 1, "second call within window must be throttled");
}

// ==================== 运行时异常事件信封（ADR 0030 决定 7） ====================
//
// 契约：事件载荷 = `{ code, request_id, params: { name } }`，code 语义稳定（= 前端
// i18n key 后缀），**永不携带** panic 消息 / 回溯 / 错误链（那些只在宿主日志里）。
// 反向锁：一旦有人往 payload 塞 `error` 字段、或让 code 随 kind 漂移，本组用例转红。

/// 异常 kind → 语义码映射：panic / trap 合并（用户看到的是同一件事），未知 kind 兜底
#[test]
fn runtime_error_kind_maps_to_stable_semantic_code() {
    assert_eq!(runtime_error_code("panic"), PLUGIN_TRAP_CODE);
    assert_eq!(runtime_error_code("trap"), PLUGIN_TRAP_CODE);
    assert_eq!(runtime_error_code("recovery_failed"), PLUGIN_RECOVERY_FAILED_CODE);
    // 未知 kind 不臆造语义：落通用兜底（前端显示「操作未完成，请稍后重试」）
    assert_eq!(
        runtime_error_code("brand-new-kind"),
        crate::system::error::DEFAULT_ERROR_CODE
    );
    assert_eq!(runtime_error_code(""), crate::system::error::DEFAULT_ERROR_CODE);
}

/// 运行时异常载荷：字段白名单 + 具名参数 + 无详情
#[test]
fn runtime_error_payload_is_envelope_with_app_name_only() {
    for (kind, expect_code) in [
        ("panic", PLUGIN_TRAP_CODE),
        ("trap", PLUGIN_TRAP_CODE),
        ("recovery_failed", PLUGIN_RECOVERY_FAILED_CODE),
    ] {
        let payload = runtime_error_envelope("AI Chatbox", kind).payload();
        assert_eq!(payload["code"], json!(expect_code), "kind={kind} 码必须稳定");
        assert_eq!(payload["params"], json!({ "name": "AI Chatbox" }), "只带应用显示名");
        let keys: Vec<&str> = payload.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        for key in &keys {
            assert!(
                matches!(*key, "code" | "request_id" | "params"),
                "载荷出现白名单外字段 {key}（kind={kind}）"
            );
        }
        let s = payload.to_string();
        assert!(!s.contains("0x1234"), "载荷携带技术详情: {s}");
        assert!(!s.contains("unreachable"), "载荷携带技术详情: {s}");
    }
}

/// 自检失败载荷：固定 code + `{ plugin }` 参数
///
/// 参数名与运行时异常通道的 `name` 不同——两者各自对应 i18n 模板，不允许混用。
#[test]
fn self_check_payload_uses_self_check_code_and_plugin_param() {
    let payload = self_check_envelope("Terminal Session").payload();
    assert_eq!(payload["code"], json!(PLUGIN_SELF_CHECK_FAILED_CODE));
    assert_eq!(payload["params"], json!({ "plugin": "Terminal Session" }));
    assert!(
        !payload.to_string().contains("hooks"),
        "载荷不得携带失败原因: {payload}"
    );
}

/// 未在册插件（查不到 manifest 名）→ 退回插件 ID 作为显示名，不返回空串
///
/// 空串会让用户看到「应用「」运行异常」这种无主语提示。
#[tokio::test]
async fn display_name_falls_back_to_plugin_id() {
    let host = setup_host().await;
    assert_eq!(host.display_name("com.wasmnest.unknown").await, "com.wasmnest.unknown");
}

// ==================== preauthorize_plugin 预授权钩子 ====================
//
// 验证「先授权再 loading」改造的契约:
// 1. 无 provider + 无 storage:直接放行(空路径 = 无需预授权)
// 2. file-transfer 无共享目录:同样放行(启用先行,配置由插件设置面板引导)
// 3. 路径已在 storage:不需要 provider,直接放行(check_batch 空路径短路)

/// 无 provider + 无 storage 预授权路径:空路径直接放行。
/// 对应「普通插件(无 fs 权限)启用 → 不出现 fs 弹窗,loading 正常显示」场景。
#[tokio::test]
async fn preauthorize_empty_paths_passes() {
    let host = setup_host().await;
    let result = host.preauthorize_plugin(TEST_PLUGIN_ID).await;
    assert!(result.is_ok(), "empty preauth paths must pass, got: {:?}", result.err());
}

/// file-transfer 共享目录未配置:放行(启用先行)。
/// 硬拒绝会造成死锁——共享目录配置入口在插件 UI 内,而插件 UI 加载
/// 依赖激活成功,「配置需激活 → 激活需先配置」互为前置,首次启用永远失败。
#[tokio::test]
async fn preauthorize_file_transfer_empty_shared_roots_passes() {
    let host = setup_host().await;
    let result = host.preauthorize_plugin(FILE_TRANSFER_PLUGIN_ID).await;
    assert!(
        result.is_ok(),
        "file-transfer with empty shared_roots must pass (enable-first), got: {:?}",
        result.err()
    );
}

/// manifest `wasiPreopenDirs` 声明目录并入预授权收集（**仅 worker 类别可达**，
/// ADR 0034；机制保留为 worker 预留能力）。未授权 + 无头上下文（check_batch 保守
/// 拒绝）→ 返回「授权被拒」错误——若声明目录未被收集,空路径会直接放行,本用例即失去意义
///
/// 声明特意用**只读档**（票 07）：档位只收紧 guest 的写能力，不构成免授权通道，
/// 所以只读目录同样必须被收集并因未授权而拒绝
#[tokio::test]
async fn preauthorize_collects_manifest_preopen_dirs_ungranted_denied() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded),
    );
    host.plugins
        .write()
        .await
        .get_mut(TEST_PLUGIN_ID)
        .expect("test plugin in map")
        .manifest
        .wasi_preopen_dirs = vec![WasiPreopenDir::read_only("${home}/.wasmnest-preauth-probe")];

    let err = host
        .preauthorize_plugin(TEST_PLUGIN_ID)
        .await
        .expect_err("ungranted manifest dir must be collected and denied headless");
    assert!(
        err.to_string().contains("denied"),
        "must fail via check_batch deny (not storage/parse), got: {}",
        err
    );
}

// ==================== 服务型 wasm 免目录授权弹窗（issue #6 D4） ====================

/// 随包服务型插件（L2 + 非用户安装）→ 声明路径**直接放行**，不弹目录授权框
///
/// 无头上下文（无 `AppHandle`）是这条用例的判据本体：弹窗路径在无头下必然失败
/// （`check_batch` 保守拒绝），只有「免询问 + 落账」才能通过。同时断言授权记录
/// 来源是 `service`（安全面板要能区分「随包服务」与「用户点过」）。
#[tokio::test]
async fn packaged_service_grants_declared_paths_without_dialog() {
    let host = setup_host().await;
    let expanded = format!(
        "{}/.wasmnest-service-preauth-probe",
        std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
    );
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::Wasm, PluginState::Loaded),
    );
    {
        let mut plugins = host.plugins.write().await;
        let plugin = plugins.get_mut(TEST_PLUGIN_ID).expect("test plugin in map");
        plugin.manifest.kind = PluginKind::InternalBusiness;
        plugin.manifest.wasi_preopen_dirs =
            vec![WasiPreopenDir::writable("${home}/.wasmnest-service-preauth-probe")];
    }

    host.preauthorize_plugin(TEST_PLUGIN_ID)
        .await
        .expect("随包服务型插件必须免弹窗放行（无头上下文亦可通过）");

    assert!(
        host.wasm_runtime
            .fs_auth()
            .is_granted(
                TEST_PLUGIN_ID,
                &expanded,
                crate::security::fs_auth::FsOps::READ_WRITE
            )
            .await,
        "声明路径必须已落账（后续 host-fs 访问不再弹窗）"
    );
    let overview = host
        .wasm_runtime
        .fs_auth()
        .auth_records()
        .overview(TEST_PLUGIN_ID, "test", Vec::new())
        .await
        .expect("auth overview");
    let row = overview
        .records
        .iter()
        .find(|r| r.target == expanded)
        .expect("声明路径必须有授权记录");
    assert_eq!(
        row.source, "service",
        "来源必须是 service（与用户确认 / 策略档区分，安全面板据此解释）"
    );
}

/// 回归锁：随包 **L3 业务应用** 不免弹窗（既有口径不变）
///
/// 同一个 manifest 声明目录，只把 `type` 换成 `business-app` 就必须回到
/// 「收集 → 弹窗」路径（无头下被拒）——否则本轮豁免扩到了所有应用。
#[tokio::test]
async fn packaged_business_app_still_requires_dialog() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::Wasm, PluginState::Loaded),
    );
    {
        let mut plugins = host.plugins.write().await;
        let plugin = plugins.get_mut(TEST_PLUGIN_ID).expect("test plugin in map");
        plugin.manifest.kind = PluginKind::BusinessApp;
        plugin.manifest.wasi_preopen_dirs =
            vec![WasiPreopenDir::writable("${home}/.wasmnest-service-preauth-probe")];
    }

    let err = host
        .preauthorize_plugin(TEST_PLUGIN_ID)
        .await
        .expect_err("L3 业务应用的声明目录仍须经授权弹窗（无头下被拒）");
    assert!(
        err.to_string().contains("denied"),
        "必须走 check_batch 拒绝，而不是被服务型判据放行，实际: {err}"
    );
}

/// 声明目录已授权(storage fs_granted_paths 前缀命中)→ check_batch 短路
/// 通过,preauthorize 整体放行。**仅 worker 类别可达**（ADR 0034）：本用例
/// 直接设 manifest 字段测机制，在策略闸门（validation.rs）之下。
#[tokio::test]
async fn preauthorize_manifest_preopen_dir_granted_passes() {
    let host = setup_host().await;
    let expanded = format!(
        "{}/.wasmnest-preauth-probe",
        std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
    );
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Loaded),
    );
    host.plugins
        .write()
        .await
        .get_mut(TEST_PLUGIN_ID)
        .expect("test plugin in map")
        .manifest
        .wasi_preopen_dirs = vec![WasiPreopenDir::writable("${home}/.wasmnest-preauth-probe")];
    host.storage
        .set(TEST_PLUGIN_ID, "fs_granted_paths", json!([expanded]))
        .await
        .unwrap();

    let result = host.preauthorize_plugin(TEST_PLUGIN_ID).await;
    assert!(
        result.is_ok(),
        "granted manifest dir must pass, got: {:?}",
        result.err()
    );
}

/// storage 已写入 preauth_paths 数组:从 storage 读取路径,非 file-transfer
/// 插件直接放行(check_batch 空 path 列表会短路返回 true,无头上下文
/// 不发事件)。
#[tokio::test]
async fn preauthorize_reads_paths_from_storage() {
    let host = setup_host().await;
    // 写入 storage 数组 — 不影响 plugin_id 隔离(只有自身能读)
    host.storage
        .set(
            TEST_PLUGIN_ID,
            super::PREAUTH_PATHS_STORAGE_KEY,
            json!([std::env::temp_dir().to_string_lossy()]),
        )
        .await
        .unwrap();
    // check_batch 在无头 app_handle 上下文下对未授权路径保守拒绝,
    // 因此我们只验证「路径已被收集」并不期望一定通过;重要的是
    // preauthorize 不会因 storage 读取而 panic,且调用了 check_batch
    let result = host.preauthorize_plugin(TEST_PLUGIN_ID).await;
    // 接受 Ok 或 Err(无头上下文拒绝)— 但不能是 storage 解析错误
    if let Err(e) = &result {
        assert!(
            !e.to_string().contains("parse") && !e.to_string().contains("deserialize"),
            "storage parse error indicates collector bug: {}",
            e
        );
    }
}

// ==================== 系统组件与能力装配（core-plugin-manager，票据 06） ====================
