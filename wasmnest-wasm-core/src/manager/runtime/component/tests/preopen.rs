//! WASI 预打开目录解析与 build_ctx 装配（仅 worker 类别，ADR 0034）
//!
//! 自 `common/component.rs` 的 `mod tests` 拆出（共享脚手架在父 `mod tests`，
//! 经 `use super::*` 可见）；fixture 互斥与产物构建语义不变。
//!
//! **被测实现已迁核心模块** `manager::runtime::wasi`（用户裁决 2026-10-12：WASI
//! 面住核心、双端同源、默认全开、开/关由 `CoreConfig::wasi` 定）——文件留在原地
//! 只为复用父模块的测试脚手架，`use` 显式指向真源。

use super::*;
// 装配真源已迁核心模块（用户裁决 2026-10-12：WASI 面住核心、双端同源）
use crate::config::WasiConfig;
use crate::manager::runtime::wasi::{build_ctx, expand_preopen_declarations, resolve_preopen_dirs};

// ==================== WASI 预打开目录解析 ====================

/// 预打开解析测试基建：返回 (host_ctx, 已授权目录)
///
/// 目录真实存在（canonicalize 需要），测试结束时由 TempDir 自动清理。
async fn preopen_ctx(plugin_id: &str) -> (Arc<WasmHostContext>, tempfile::TempDir) {
    let ctx = build_host_ctx();
    grant_permissions(&ctx, plugin_id, &["storage"]);
    let dir = tempfile::tempdir().expect("tempdir");
    // 模拟激活时 fs_request_auth 同意后的持久化授权（storage key fs_granted_paths）
    crate::host_api::storage::storage_set(
        &crate::host_api::sqlite::ports_for(&ctx),
        plugin_id,
        "fs_granted_paths",
        serde_json::json!([dir.path().to_string_lossy()]),
    )
    .expect("seed granted path");
    (ctx, dir)
}

/// 预开声明的断言投影：`(主机路径, 挂载档)`
///
/// 所有解析类断言都走它，而不是只比路径——只比路径的话，「展开/过滤过程中
/// 把只读档丢掉」（实现退化成 `Vec<String>`）在内层链路上看不出来。
fn preopen_tiers(out: &[WasiPreopenDir]) -> Vec<(&str, bool)> {
    out.iter().map(|d| (d.path(), d.readonly())).collect()
}

#[tokio::test]
async fn resolve_preopen_dirs_empty_when_no_declaration() {
    let (ctx, _dir) = preopen_ctx("com.wasmnest.test").await;
    assert!(resolve_preopen_dirs(&ctx, "com.wasmnest.test", &[]).is_empty());
}

#[tokio::test]
async fn resolve_preopen_dirs_keeps_granted_and_trims() {
    let (ctx, dir) = preopen_ctx("com.wasmnest.test").await;
    let pid = "com.wasmnest.test";
    let granted = dir.path().to_string_lossy().to_string();

    // 已授权目录保留；头尾空白与多余分隔符被清理；裸路径档 = 可写
    let out = resolve_preopen_dirs(
        &ctx,
        pid,
        &[WasiPreopenDir::writable(format!(" {} /", granted))],
    );
    assert_eq!(preopen_tiers(&out), vec![(granted.as_str(), false)]);
}

#[tokio::test]
async fn resolve_preopen_dirs_filters_ungranted_and_blank() {
    let (ctx, _dir) = preopen_ctx("com.wasmnest.test").await;
    let pid = "com.wasmnest.test";

    // 未授权目录不得预打开（manifest 声明不能绕过授权机制）
    let rogue = std::env::temp_dir().join("wasi-rogue-not-authorized");
    std::fs::create_dir_all(&rogue).unwrap();
    // 授权根之外的不存在路径（canonicalize 回退父目录+名，不在授权前缀下）同样剔除
    let missing = rogue.join("missing-deep");

    let out = resolve_preopen_dirs(
        &ctx,
        pid,
        &[
            WasiPreopenDir::writable(rogue.to_string_lossy().to_string()),
            // 只读档同样要授权：声明 ~/.ssh 式的路径为 readonly 不得换来预打开
            // （票 07 裁决 3——档位收紧 guest 能力，不是免弹窗通道）
            WasiPreopenDir::read_only(missing.to_string_lossy().to_string()),
            WasiPreopenDir::writable("   ".to_string()),
            WasiPreopenDir::writable("/".to_string()),
        ],
    );
    assert!(out.is_empty(), "未授权/空白声明全部剔除，实际: {:?}", out);
}

#[tokio::test]
async fn resolve_preopen_dirs_expands_home_variable() {
    let Some(home) = dirs::home_dir() else {
        return; // 无主目录环境跳过
    };
    let (ctx, _dir) = preopen_ctx("com.wasmnest.test").await;
    let pid = "com.wasmnest.test";

    // 在主目录下建真实目录并授权，验证 ${home} 展开 + 授权过滤联合生效
    let probe = home.join(".wasmnest-wasi-preopen-test");
    std::fs::create_dir_all(&probe).unwrap();
    crate::host_api::storage::storage_set(
        &crate::host_api::sqlite::ports_for(&ctx),
        pid,
        "fs_granted_paths",
        serde_json::json!([probe.to_string_lossy()]),
    )
    .expect("seed granted path");

    let out = resolve_preopen_dirs(
        &ctx,
        pid,
        &[WasiPreopenDir::writable(
            "${home}/.wasmnest-wasi-preopen-test",
        )],
    );
    assert_eq!(out.len(), 1);
    assert!(out[0].path().ends_with(".wasmnest-wasi-preopen-test"));
    std::fs::remove_dir_all(&probe).ok();
}

/// expand_preopen_declarations：`${home}` 展开 + 尾分隔符清理 + 滤空，
/// 且**不过滤未授权项**——preauthorize 收集的恰恰是未授权候选（交由
/// check_batch 弹窗），与 resolve_preopen_dirs 的授权过滤形成对照
#[test]
fn expand_preopen_declarations_expands_and_keeps_ungranted() {
    let Some(home) = dirs::home_dir() else {
        return; // 无主目录环境跳过
    };
    let home_str = home.to_string_lossy().trim_end_matches('/').to_string();

    let out = expand_preopen_declarations(
        "com.wasmnest.test",
        &[
            WasiPreopenDir::writable("${home}/.wasmnest/ai-chatbox".to_string()),
            WasiPreopenDir::read_only(format!(" {}/readonly-trailing/ ", home_str)),
            WasiPreopenDir::writable(format!(" {}/trailing/ ", home_str)),
            WasiPreopenDir::writable("   ".to_string()),
            WasiPreopenDir::writable(String::new()),
        ],
    );
    assert_eq!(out.len(), 3, "实际: {:?}", out);
    assert!(
        out[0].path().ends_with("/.wasmnest/ai-chatbox"),
        "实际: {:?}",
        out
    );
    // 展开只换路径，档位逐条跟着自己的声明走（不得被相邻条目串档）
    assert!(
        out[1].path().ends_with("/readonly-trailing"),
        "实际: {:?}",
        out
    );
    assert!(out[2].path().ends_with("/trailing"), "实际: {:?}", out);
}

/// 展开后仍保留只读档（with_path 的档位粘性）——反例：展开实现自己重建条目、
/// 只带路径不带档位时，只读声明会在到达 preopen 之前退化成可写
#[test]
fn expand_preopen_declarations_keeps_read_only_tier() {
    let Some(_home) = dirs::home_dir() else {
        return; // 无主目录环境跳过
    };
    let out = expand_preopen_declarations(
        "com.wasmnest.test",
        &[WasiPreopenDir::read_only(
            "${home}/.wasmnest-ro-probe".to_string(),
        )],
    );
    assert_eq!(out.len(), 1, "实际: {:?}", out);
    assert!(
        out[0].path().ends_with("/.wasmnest-ro-probe"),
        "实际: {:?}",
        out
    );
    assert!(out[0].readonly(), "只读档必须在 ${{home}} 展开后仍然生效");
}

/// 已授权但目录尚不存在（首次启用场景）：build_ctx 先幂等创建再 preopen，
/// 并把实际挂载目录计入返回值——修复「授权只落库、目录不创建」导致的
/// WASI 预打开失败死循环（Bug B 方案 A）。
#[tokio::test]
async fn build_ctx_creates_missing_granted_dir_and_reports_preopened() {
    let (ctx, _dir) = preopen_ctx("com.wasmnest.test").await;
    let pid = "com.wasmnest.test";
    // 授权父路径（fs_auth save_granted_path 的存储语义即父目录前缀）；
    // 目标目录刻意不存在，模拟首次启用前数据目录未创建
    let base = std::env::temp_dir().join(format!("wasmnest-wasi-create-{}", std::process::id()));
    let missing = base.join("ai-chatbox");
    std::fs::create_dir_all(&base).unwrap();
    crate::host_api::storage::storage_set(
        &crate::host_api::sqlite::ports_for(&ctx),
        pid,
        "fs_granted_paths",
        serde_json::json!([base.to_string_lossy()]),
    )
    .expect("seed granted path");

    let (wasi_ctx, preopened) = build_ctx(
        &ctx,
        pid,
        &[WasiPreopenDir::writable(
            missing.to_string_lossy().to_string(),
        )],
        &WasiConfig::default(),
    );
    assert_eq!(preopened, vec![missing.to_string_lossy().to_string()]);
    assert!(missing.is_dir(), "host must create the missing preopen dir");
    drop(wasi_ctx);
    std::fs::remove_dir_all(&base).ok();
}

/// 只读档同样建目录并计入 preopened：宿主建空目录只是给 guest 一个可挂载的
/// 锚点，写能力在 WASI 层由 OpenMode 拒（guest 侧的实际拒绝见 preopen_e2e 闭环）；
/// 若把只读实现成「干脆不挂」，插件连读都读不到，是本票的反例
#[tokio::test]
async fn build_ctx_mounts_read_only_dir_and_reports_it() {
    let (ctx, _dir) = preopen_ctx("com.wasmnest.test").await;
    let pid = "com.wasmnest.test";
    let base = std::env::temp_dir().join(format!("wasmnest-wasi-ro-{}", std::process::id()));
    let missing = base.join("ro-child");
    std::fs::create_dir_all(&base).unwrap();
    crate::host_api::storage::storage_set(
        &crate::host_api::sqlite::ports_for(&ctx),
        pid,
        "fs_granted_paths",
        serde_json::json!([base.to_string_lossy()]),
    )
    .expect("seed granted path");

    let (wasi_ctx, preopened) = build_ctx(
        &ctx,
        pid,
        &[WasiPreopenDir::read_only(
            missing.to_string_lossy().to_string(),
        )],
        &WasiConfig::default(),
    );
    assert_eq!(preopened, vec![missing.to_string_lossy().to_string()]);
    assert!(missing.is_dir(), "只读档也要有可挂载的锚点目录");
    drop(wasi_ctx);
    std::fs::remove_dir_all(&base).ok();
}

/// 目录创建失败（不可写路径）不 panic：跳过该声明，其余声明仍正常挂载
#[tokio::test]
async fn build_ctx_skips_uncreatable_dir_without_panicking() {
    let (ctx, _dir) = preopen_ctx("com.wasmnest.test").await;
    let pid = "com.wasmnest.test";
    // 已授权目录（可创建）
    let base = std::env::temp_dir().join(format!("wasmnest-wasi-create2-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    crate::host_api::storage::storage_set(
        &crate::host_api::sqlite::ports_for(&ctx),
        pid,
        "fs_granted_paths",
        serde_json::json!([base.to_string_lossy()]),
    )
    .expect("seed granted path");
    let ok_dir = base.join("ok");
    // 不可创建路径：普通文件当父目录（create_dir_all 必然失败）
    let blocker = base.join("blocker");
    std::fs::write(&blocker, b"not a dir").unwrap();
    let bad_dir = blocker.join("child");

    let (wasi_ctx, preopened) = build_ctx(
        &ctx,
        pid,
        &[
            WasiPreopenDir::writable(bad_dir.to_string_lossy().to_string()),
            WasiPreopenDir::writable(ok_dir.to_string_lossy().to_string()),
        ],
        &WasiConfig::default(),
    );
    assert_eq!(preopened, vec![ok_dir.to_string_lossy().to_string()]);
    assert!(ok_dir.is_dir());
    drop(wasi_ctx);
    std::fs::remove_dir_all(&base).ok();
}

/// `wasi.enabled=false` ⇒ 即便声明了**已授权**目录也不预打开（空上下文）
///
/// 配置整体关闭 = 不给任何 WASI 能力：跳过预打开装配、`preopened` 为空。
/// 反例锁：只在 linker 注册分支读 cfg、装配面忽略（以为「没注册就没必要防空上下文」）
/// 会红本条——设备上真正的能力边界必须与配置一致，不能一处生效一处不生效。
#[tokio::test]
async fn build_ctx_yields_empty_context_when_wasi_disabled() {
    let (ctx, dir) = preopen_ctx("com.wasmnest.test").await;
    let pid = "com.wasmnest.test";
    let (wasi_ctx, preopened) = build_ctx(
        &ctx,
        pid,
        &[WasiPreopenDir::writable(dir.path().to_string_lossy().to_string())],
        &WasiConfig {
            enabled: false,
            ..WasiConfig::default()
        },
    );
    assert!(
        preopened.is_empty(),
        "关闭 WASI 面时不得预打开任何目录，实际: {:?}",
        preopened
    );
    drop(wasi_ctx);
}
