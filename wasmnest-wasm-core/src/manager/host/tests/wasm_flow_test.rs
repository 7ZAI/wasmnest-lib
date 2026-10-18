//! 定时器 / 重载限频用例 + 宿主退役面源码扫描锁。
//!
//! **票 04 迁移记录**：原文件的夹具功能态用例（degraded 激活与恢复 / 持久化意图 /
//! 激活-调用-停用闭环 / 热重载循环）与夹具脚手架（`build_test_component` /
//! `setup_wasm_plugin(_with_model)`）随「wasm-core 不再持全 world 绑定」迁桌面宿主
//! `src-tauri/tests/wasm_flow_e2e.rs`（判决性探针实测：本族是最后一批依赖内核测试
//! 替身的夹具用例）。留本文件的不实例化夹具（`make_plugin` 直造 LoadedPlugin），
//! 与四张退役面源码扫描锁同属内核机制面。

use super::scaffold::*;
use super::*;

// 票 03 删除的用例 `test_dispatch_lifecycle_and_input_to_wasm_plugin`：
// 它覆盖的「事件 → payload → dispatch → wasm 回调」链路随宿主观察面退役
// （派发点、监听器实现、注册表三处同批删除），无对象可测。
// 插件导出的 `on_session_lifecycle` / `on_input_submitted` 仍由 SDK 默认实现兜底，
// 其 WIT 面随票 10 整 interface 删除时收口。

// ==================== PluginServices（可测部分） ====================

#[tokio::test(flavor = "multi_thread")]
async fn test_plugin_timer_register_replace_abort() {
    let host = setup_host().await;
    host.plugins.write().await.insert(
        TEST_PLUGIN_ID.to_string(),
        make_plugin(TEST_PLUGIN_ID, PluginSource::FileScan, PluginState::Activated),
    );

    // 注册定时器（3600s 间隔：测试期间不会触发 tick 回调）
    PluginServices::register_plugin_timer(&host, TEST_PLUGIN_ID.to_string(), 3600, "tick".to_string());
    assert_eq!(host.plugin_timers.lock().unwrap().len(), 1);

    // 重复注册替换旧句柄（v6 ADR 0003：同一插件仅保留一个定时器）
    PluginServices::register_plugin_timer(&host, TEST_PLUGIN_ID.to_string(), 3600, "tick".to_string());
    assert_eq!(host.plugin_timers.lock().unwrap().len(), 1);

    // 停用中止定时器（不再到点回调）
    host.deactivate_plugin(TEST_PLUGIN_ID, false).await.unwrap();
    assert!(host.plugin_timers.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_schedule_plugin_reload_throttle() {
    let host = setup_host().await;
    // 未激活插件：调度后后台任务直接退出，仅验证限频表行为
    host.schedule_plugin_reload_after_trap(TEST_PLUGIN_ID);
    {
        let throttle = host.wasm_reload_throttle.lock().unwrap();
        assert!(throttle.contains_key(TEST_PLUGIN_ID));
    }
    // 30 秒窗口内再次调度被限频跳过：不新增条目
    host.schedule_plugin_reload_after_trap(TEST_PLUGIN_ID);
    {
        let throttle = host.wasm_reload_throttle.lock().unwrap();
        assert_eq!(throttle.len(), 1);
    }
}

// 票 03 删除的用例 `test_session_listener_registration_via_services`：
// `PluginServices` 的两条注册面（生命周期 / 输入）已随宿主观察面退役，
// 注册表与派发点不复存在，本用例无对象可测。

// ==================== 内核会话域防回接锁（票 11） ====================

/// 防回接锁的源码扫描面：宿主 `src` + **六个 server lib crate 的 `src`**
///
/// server-lib-split 票 07：面抽 crate 后只扫宿主 `src` 是不够的——退役面若被回接到
/// crate 里，宿主侧的锁一个也看不见。尤其 `wasmnest-server-peer-net`（传输编排下沉后
/// 引擎面正是最可能复归编排的地方）与 `wasmnest-server-websocket`（会话观察面）。
/// crate 清单的登记处是 `server::crate_boundary_lock::SERVER_LIB_CRATES`（单一事实源）。
fn retired_domain_scan_roots() -> Vec<std::path::PathBuf> {
    let mut roots = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    roots.extend(crate::crate_boundary_lock::server_lib_src_roots());
    roots
}

/// 递归收集扫描面下所有 `.rs` 文件（路径 + 相对宿主 crate 根的定位串）
fn collect_retired_domain_rs_files() -> Vec<(std::path::PathBuf, String)> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut stack = retired_domain_scan_roots();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((path, rel));
        }
    }
    out
}

/// 源码扫描锁：宿主侧不得再出现内核会话域的任何符号。
///
/// 票 11 删除了 `src/session/` 整个目录（`SessionManager` / `SessionConfigManager` /
/// `SessionOutputManager` / `GlobalOutputManager` / `SessionInfoRegistry` / 环与
/// 订阅者实现）。这不是「换了个位置放」——会话真源在 `com.wasmnest.terminal-session`
/// 登记域，宿主只剩 `host-pty`（引擎）+ `host-connection`（连接清单）+ `session_gateway`
/// （互调窄转发层）。谁把内核会话对象加回来，谁就要先推翻票 11 的裁定。
///
/// 与票 03 的锁同理：只扫**非注释行**（各模块里「为什么删」的说明段落是记账），
/// 且跳过两张锁自身（`sync_handler.rs` 与本文件——它们把标识符当字符串去匹配）。
#[test]
fn retired_kernel_session_domain_is_not_reintroduced() {
    let mut violations: Vec<String> = Vec::new();

    let forbidden: [&str; 8] = [
        "crate::session::",
        "SessionManager",
        "SessionConfigManager",
        "SessionOutputManager",
        "GlobalOutputManager",
        "SessionInfoRegistry",
        "SessionOutputSink",
        "UnifiedOutputQueue",
    ];

    for (path, rel) in collect_retired_domain_rs_files() {
        // 锁自身：它们以字符串形式携带这些标识符去匹配
        if rel.ends_with("wasm_flow_test.rs") || rel.ends_with("sync_handler.rs") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (idx, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim_start();
            if line.starts_with("//") || line.starts_with("///") {
                continue;
            }
            for needle in forbidden {
                if line.contains(needle) {
                    violations.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "内核会话域（票 11 已整目录删除）出现回接痕迹：\n{}",
        violations.join("\n")
    );
}

// ==================== 对等传输编排域防回接锁（传输编排下沉票 3） ====================

/// 源码扫描锁：宿主 peer 域不得再把传输任务编排状态机接回来。
///
/// 票 3 把发送/接收任务编排整体下沉 `file-transfer` 插件（事件归约状态机，
/// 真源在其私有库）：宿主 `peer_engine_*` 收敛为「会话句柄表 + 引擎事件桥」——
/// 旧版所持的任务 DTO 形状（`PeerTransferDto`）、并发闸门（`pick_pending_to_start`
/// / `pump_send_queue`）、历史封顶（`HISTORY_CAP` / `RECEIVE_TERMINAL_CAP`）、
/// serve 供流记账（`register_serve_task` / `settle_serve_terminal`）、pull 任务行
/// 预登记（`register_remote_pull`）、peer_name 解析（`resolve_peer_name`）、
/// 批量恢复编排（`peer_resume_all_transfers` / `resume_all_transfers_for_plugin`）
/// 与并发脉冲（`set_transfer_concurrency_for_plugin`）一并退役。谁把这些加回来，
/// 谁就要先推翻票 3 裁决。
///
/// 与票 11 的锁同理：只扫**非注释行**（模块头「为什么删」的说明段落是记账），
/// 且跳过锁自身。fail-visible 双保险之一——另一保险是 `send-files` 载荷
/// `concurrency` 字段检测（wasm-core-lib-split 票 05 起在
/// `wasmnest-server-peer-net::plugin_binding`，行为级）。
#[test]
fn retired_peer_transfer_orchestration_is_not_reintroduced() {
    let mut violations: Vec<String> = Vec::new();

    let forbidden: [&str; 15] = [
        "PeerTransferDto",
        "PeerTransferFileDto",
        "register_remote_pull",
        // 带冒号精确匹配常量名（避免误中 server 指标的 METRICS_HISTORY_CAPACITY）
        "HISTORY_CAP:",
        "RECEIVE_TERMINAL_CAP",
        "pick_pending_to_start",
        "pump_send_queue",
        "running_send_count_locked",
        "register_serve_task",
        "settle_serve_terminal",
        "set_serve_pause_status",
        "evict_history_cap_locked",
        "evict_terminal_cap_locked",
        "resume_all_transfers_for_plugin",
        "set_transfer_concurrency_for_plugin",
    ];

    for (path, rel) in collect_retired_domain_rs_files() {
        // 锁自身：以字符串形式携带这些标识符去匹配
        if rel.ends_with("wasm_flow_test.rs") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (idx, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim_start();
            if line.starts_with("//") || line.starts_with("///") {
                continue;
            }
            for needle in forbidden {
                if line.contains(needle) {
                    violations.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "对等传输编排域（票 3 已整体下沉插件）出现回接痕迹：\n{}",
        violations.join("\n")
    );
}

// ==================== 退役面防回接锁（票 03） ====================

/// 源码扫描锁：宿主侧不得再把「注册了就能收到会话回调」的观察面接回来。
///
/// 票 03 的裁决是**整体退役**（不换成总线 topic）：这两条通道在 P1-b 真源下沉后
/// 生产流量归零，留着「代码在、永远不触发」是下一处断链的种子。本锁把裁决变成
/// 可执行判据——谁把注册表 / 派发点 / 修饰链加回来，谁就要先推翻票 03 的裁定。
///
/// 只扫「宿主源码里的定义与调用」，不扫注释：本文件与各模块的说明段落里出现这些
/// 名字是**记账**（说清为什么删），不是回接。
#[test]
fn retired_session_observation_surface_is_not_reintroduced() {
    let mut violations: Vec<String> = Vec::new();

    // 逐条列出「退役面的形状」。命中即红。
    let forbidden: [&str; 6] = [
        "register_lifecycle_listener",
        "register_input_listener",
        "register_session_lifecycle_listener",
        "register_session_input_listener",
        "dispatch_lifecycle_to_plugin",
        "dispatch_input_to_plugin",
    ];

    for (path, rel) in collect_retired_domain_rs_files() {
        // 本文件是锁自身，跳过（避免自匹配）
        if rel.ends_with("wasm_flow_test.rs") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (idx, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim_start();
            if line.starts_with("//") {
                continue;
            }
            for needle in forbidden {
                if line.contains(needle) {
                    violations.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "会话观察面（票 03 已整体退役）出现回接痕迹：\n{}",
        violations.join("\n")
    );
}

// ==================== 认证中心发现路径防回接锁（ADR 0031 v32） ====================

/// 源码扫描锁：宿主侧不得再出现「能力探测 + 排序取首个」的认证中心发现路径。
///
/// v32（2026-09-29，ADR 0031）把认证中心角色发现从「扫描导出 auth-policy 的
/// 激活插件 + 按 id 取第一个」改为**注册表显式登记**（`auth-center-register` +
/// 唯一性仲裁）——旧路径在候选 > 1 时选中未实现策略的插件（2026-09-29 移动端
/// 4001 日志风暴事故根因），且与 api_registry 锚点形成**两套发现机制并存**的
/// 结构病灶。谁把这些符号加回宿主源码（函数 / 常量 / fail-open 降级），谁就要
/// 先推翻 ADR 0031 的裁定。
///
/// 只扫「宿主源码里的定义与调用」，不扫注释：本文件与各模块的说明段落里出现这些
/// 名字是**记账**（说清为什么删），不是回接。fail-visible 形态③（删即抛）。
#[test]
fn retired_auth_center_discovery_is_not_reintroduced() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations: Vec<String> = Vec::new();

    // 逐条列出「退役面的形状」。命中即红。
    let forbidden: [&str; 4] = [
        // 旧角色发现：扫描 + 排序取首个（v32 改查注册表）
        "auth_center_candidates",
        // 旧桥接锚点：api_registry 探活（v32 退役，改查注册表 is_registered）
        "SESSION_MARKER_API",
        // 旧 fail-open：插件不可用时记录降级并放行（v32 改 fail-closed 拒绝）
        "log_fallback",
        // 旧锚点查询辅助函数（随 SESSION_MARKER_API 一并退役）
        "fn api_registered",
    ];

    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            // 本文件是锁自身，跳过（避免自匹配）
            if path.ends_with("wasm_flow_test.rs") {
                continue;
            }
            for (idx, raw_line) in content.lines().enumerate() {
                let line = raw_line.trim_start();
                if line.starts_with("//") {
                    continue;
                }
                for needle in forbidden {
                    if line.contains(needle) {
                        violations.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "认证中心发现路径（v32 已整体退役，改注册表显式登记）出现回接痕迹：\n{}",
        violations.join("\n")
    );
}
