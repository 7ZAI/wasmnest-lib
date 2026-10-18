//! host-platform 逻辑层 —— 通用平台能力域（ADR 0022 v2，issue 13 Phase 2）
//!
//! 系统对话框等与领域无关的平台交互。
//!
//! ## 选源器（`pick-*`）的双段口径（2026-09-27）
//!
//! 1. **准入门**：manifest 必须**单独声明权限 `fs:pick`**。未声明 → 显性 `Err`，
//!    且**在弹选择器之前**返回（不给「没权限也能弹框看路径列表」留缝）。
//!    选器与 `fs:read` / `fs:write` 分域：它只交付「用户亲手选中的路径」这一层。
//! 2. **结果门**：选择器浏览面不设限（浏览由用户在系统选择器里驱动，宿主不读
//!    任何数据）；选择结束后对**选中项**做 [`FsAuthChecker::authorize_picked`]
//!    授权校验——命中已授权目录前缀则静默放行，未授权的弹一次授权框并按**所在
//!    目录**落账，拒绝 / 超时 / 无弹窗通道 → `Err` 且**不回传路径**（fail-visible：
//!    不得降级成空数组）。
//!
//! ## 选择器本体 = 宿主装配的端口（ADR 0052 D1，2026-10-13）
//!
//! 选择器机制本身是**端差异**（桌面原生对话框 Windows IFileDialog / Linux
//! xdg-desktop-portal；移动 SAF 目录树/文件选择器），落在
//! [`crate::host_api::ports::PlatformPickerPort`]：
//!
//! - 桌面：宿主实现（`桌面宿主 src-tauri/src/plugin/platform_picker.rs`）
//!   经 `PluginHost::new` 装配期注入；
//! - 移动：`WasmHostContext::new_with_ports` 用
//!   [`crate::host_api::ports::EnginePortsPlatformPicker`] 把既有 SAF 引擎端口
//!   适配成选择器端口；
//! - 本文件只持**共享机制**：`fs:pick` 权力门 + 选择后授权校验 + JSON 形状——
//!   两端同源，不按端分叉。
//!
//! 历史（host-business-decarriage 收尾）：选源器曾挂在 `peer_engine_transfer`
//! （对等传输域）下经 `peer_net` 转发——那是「peer 命令面复用」时期的错放
//! （ADR 0022 v2 已把 pick-* 判归 host-platform）。单形态收口（2026-10-13）
//! 合并 common（桌面对话框实现）/ bare（移动 SAF 端口）时只保留下桌面版，
//! 移动构建因此编不过（`pick_folders` 在 tauri-plugin-dialog 中是 desktop-only
//! API，Android 无此方法）——端口化后两端各自成立。

use crate::host_api::context::{FsAuthScope, PermissionScope};
use crate::host_api::ports::PlatformPickerPort;
use crate::permission::PERMISSION_FS_PICK;
use crate::runtime_util::block_on_async;
use crate::security::fs_auth::FsAuthChecker;
use std::sync::Arc;

/// 权限门（`fs:pick`）：未声明即拒绝，**且不弹对话框**
///
/// 文案点名缺失的权限位与补法（fail-visible）：插件拿到的错误必须能直接回答
/// 「我在 manifest 里加什么」——「permission denied」这种无信息文案在这里是
/// 把排障成本推给插件作者。
fn require_pick_permission(perm: &dyn PermissionScope, plugin_id: &str, api: &str) -> Result<(), String> {
    if super::check_permission(perm, plugin_id, PERMISSION_FS_PICK, api) {
        return Ok(());
    }
    Err(format!(
        "permission denied: manifest must declare '{PERMISSION_FS_PICK}' to use the system file picker ({api})"
    ))
}

/// 宿主平台标识（v38 `host-platform.platform`；无权限门——平台事实不是能力）
///
/// 端值**不由内核判定**：各端宿主实现 [`crate::host_api::ports::HostFactsPort`] 并
/// 装配期注入（桌面 `plugin/host_facts.rs` → `"desktop"`，移动
/// `plugin/host_ports.rs` → `"mobile"`），内核只透传端口取值——单形态收口
/// （2026-10-13，ADR 0049 D1「桌面这样写、移动那样写就不是机制」）前这里是
/// `#[cfg(feature = "desktop-assembly")]` 编译期二选一。
/// 消费方是双端共享 wasm 产物（file-transfer 单产物）：它在**激活期**经此探测端值
/// 并在同一 trait 的双实现间分支；guest 侧对空/未知取值 fail-visible（显性报错
/// 不猜默认平台，未注入端事实时取到 `"unknown"`）。
pub(crate) fn platform_id(facts: &dyn crate::host_api::ports::HostFactsPort) -> String {
    facts.platform_id()
}

/// 系统多文件选择器 → string[] JSON（用户取消为空数组）
///
/// 选择器本体经 [`PlatformPickerPort`] 注入（桌面原生对话框 / 移动 SAF）；
/// 本函数只做共享机制：`fs:pick` 准入 → 选择结果授权校验 → JSON 序列化。
pub(crate) fn platform_pick_files(
    perm: &dyn PermissionScope,
    fs: &dyn FsAuthScope,
    picker: &dyn PlatformPickerPort,
    plugin_id: &str,
) -> Result<String, String> {
    require_pick_permission(perm, plugin_id, "host_platform_pick_files")?;
    let picked = sync_result(block_on_async(picker.pick_files()))?;
    let picked = authorize_picked(fs, plugin_id, "host_platform_pick_files", picked)?;
    serde_json::to_string(&picked).map_err(|e| format!("serialize picked files failed: {e}"))
}

/// 系统文件夹选择器（多选）→ string[] JSON；用户取消为空数组
///
/// 2026-10-13 功能级统一（ADR 0052 D3）：原 `pick-folder`（单目录字符串）与桌面
/// `host-platform-desktop.pick-folders`（多目录 JSON）是同一功能的两种形状 →
/// 统一为本函数。移动端 SAF 目录树选择器为单选语义，返回 0/1 项。
/// 选择器本体同 [`platform_pick_files`]（端口注入，两端各自实现）。
pub(crate) fn platform_pick_folders(
    perm: &dyn PermissionScope,
    fs: &dyn FsAuthScope,
    picker: &dyn PlatformPickerPort,
    plugin_id: &str,
) -> Result<String, String> {
    require_pick_permission(perm, plugin_id, "host_platform_pick_folders")?;
    let picked = sync_result(block_on_async(picker.pick_folders()))?;
    let picked = authorize_picked(fs, plugin_id, "host_platform_pick_folders", picked)?;
    serde_json::to_string(&picked).map_err(|e| format!("serialize picked folders failed: {e}"))
}

/// 选择结果的授权校验（`fs:pick` 契约第二段）
///
/// - **空选择**（用户取消）→ 直接放行：取消不是「拒绝授权」，不该多弹一个框；
/// - **命中已授权目录** → 静默放行（`authorize_picked` 内部按第一、二层判）；
/// - **未授权** → 弹一次框；拒绝 / 超时 / 无弹窗通道 → `Err`，**一个路径都不回传**
///   （回传空数组会让插件把「被拒」读成「用户没选文件」，静默丢数据）。
fn authorize_picked(
    fs: &dyn FsAuthScope,
    plugin_id: &str,
    api: &str,
    picked: Vec<String>,
) -> Result<Vec<String>, String> {
    if picked.is_empty() {
        return Ok(picked);
    }
    let checker: Arc<FsAuthChecker> = fs
        .fs_auth_checker();
    if block_on_async(checker.authorize_picked(plugin_id, &picked)) {
        return Ok(picked);
    }
    tracing::warn!(
        plugin_id = %plugin_id,
        api = %api,
        picked_count = picked.len(),
        "platform pick: selection not authorized (denied or timed out)"
    );
    Err(format!(
        "{api}: picked paths were not authorized (user denied or the request timed out); no path returned"
    ))
}

fn sync_result<T>(r: crate::Result<T>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}

// 票 02 批次 06（v36 交集切片）：platform 桌面扩展三函数（wsl-distros /
// local-ipv4-addresses / reveal-in-dir）已拆入 `host-platform-desktop` 并迁宿主
// `src-tauri/src/plugin/platform.rs`（路径 B：域函数 + 单测随域走宿主；内核不再
// 持有桌面平台依赖 `local_ip_address` / `system::wsl`）。桌面原
// `host-platform-desktop.pick-folders` 已随 2026-10-13 功能级统一（ADR 0052 D3）
// 并入本文件 [`platform_pick_folders`]。**桌面对话框本体**同日起改由宿主
// `src-tauri/src/plugin/platform_picker.rs` 经 [`PlatformPickerPort`] 注入
// （内核不再持 `tauri-plugin-dialog` 用法）。

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_api::tests::build_host_ctx;
    use crate::host_api::grant_permissions;
    use crate::permission::PERMISSION_FS_PICK;

    const PLUGIN: &str = "com.test.pick";

    /// 选择器替身：把「用户在系统选择器里选了什么」变成测试可控输入
    ///
    /// 真选择器（桌面对话框 / 移动 SAF）需要真 AppHandle，单元测试造不出来；
    /// 端口把选择器与域机制隔开后，本替身直接驱动「门 → 选择器 → 授权 → JSON」
    /// 全链（选择器本体各自的用例住两端宿主）。
    struct FakePicker {
        files: Vec<String>,
        folders: Vec<String>,
    }

    #[async_trait::async_trait]
    impl PlatformPickerPort for FakePicker {
        async fn pick_files(&self) -> crate::Result<Vec<String>> {
            Ok(self.files.clone())
        }

        async fn pick_folders(&self) -> crate::Result<Vec<String>> {
            Ok(self.folders.clone())
        }
    }

    fn fake(files: Vec<String>, folders: Vec<String>) -> Arc<dyn PlatformPickerPort> {
        Arc::new(FakePicker { files, folders })
    }

    /// 未授权选择器的 fail-visible 错误（[`crate::host_api::ports::PORT_NOT_WIRED`]
    /// 的端口名前缀）——无头 / 测试上下文的缺省选择器命中它
    fn assert_picker_not_wired(err: &str) {
        assert!(
            err.contains("not wired") && err.contains("platform_picker_"),
            "缺省选择器必须 fail-visible（点名未装配的选择器端口）, got: {err}"
        );
    }

    // ==================== 权限门（`fs:pick`） ====================

    /// C-101 未声明 `fs:pick` → 显性拒绝，且**在弹选择器之前**（若顺序反了错误
    /// 会是选择器端口的 fail-visible 那条）
    #[test]
    fn pick_requires_fs_pick_permission() {
        let ctx = build_host_ctx();
        for perm in ["fs:read", "fs:write", "storage", "peer"] {
            grant_permissions(&ctx, PLUGIN, &[perm]);
            let picker = ctx.platform_picker();
            let err = platform_pick_files(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
                .expect_err("未声明 fs:pick 必须拒绝");
            assert!(
                err.contains(PERMISSION_FS_PICK),
                "错误必须点名缺失的权限位（插件作者据此知道 manifest 补什么），got: {err}"
            );
            assert!(
                !err.contains("not wired"),
                "权限门必须早于选择器：拿到了未装配报错说明顺序反了, got: {err}"
            );
        }
    }

    /// C-110 分域：`fs:read` / `fs:write` 都不隐含选择器位，反向也不成立
    #[test]
    fn pick_bit_is_independent_from_read_write() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_PICK]);
        // 声明了 fs:pick → 过得了权限门（下一步才会走到选择器端口；无头上下文
        // 缺省选择器 fail-visible，不是权限错误）
        let picker = ctx.platform_picker();
        let err = platform_pick_files(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect_err("无头上下文没有装配选择器");
        assert_picker_not_wired(&err);
        assert!(
            !err.contains(PERMISSION_FS_PICK),
            "已声明 fs:pick 不得再报权限缺失, got: {err}"
        );
    }

    /// `pick-folders`（2026-10-13 统一函数）与 `pick-files` 同门：未声明
    /// `fs:pick` 拒绝且早于选择器（防「多选变体绕过准入」的回接形态）
    #[test]
    fn pick_folders_requires_fs_pick_permission() {
        let ctx = build_host_ctx();
        let picker = ctx.platform_picker();
        let err = platform_pick_folders(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect_err("未声明 fs:pick 必须拒绝");
        assert!(
            err.contains(PERMISSION_FS_PICK),
            "错误必须点名缺失的权限位（插件作者据此知道 manifest 补什么），got: {err}"
        );
        assert!(!err.contains("not wired"), "权限门必须早于选择器, got: {err}");
    }

    // 权限位进 CLI 生成物的断言已随漂移锁迁平台仓（票 08）：
    // `cross-end-tests/tests/permission_vocabulary_lock.rs` 的「真源 ↔ 生成物
    // 集合相等」整体覆盖；本文件不再读平台 SDK 生成物。

    // ==================== 选择器端口到授权链路的全链 ====================
    //
    // 授权判据本身的用例（已授权目录静默放行 / 未授权保守拒 / 取消不弹框 /
    // 落账粒度）在 `security::fs_auth` 的测试模块——那里能读 `pending_requests`
    // 私有字段断言「没有多弹一个框」，本文件只锁宿主原语这一层的接线契约。

    /// 唯一临时夹具目录（带 pid + 名字后缀，避免并行用例互踩）
    fn fixture_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wasmnest-pick-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    /// 注入选择器的结果**必须过结果门**：未授权 → 拒且不回传；授权后 → 原样交付
    ///
    /// 反向断言（先拒）防「结果门被短路」的回接；正向断言（后放行）防把已授权
    /// 选择也一律拒掉的过度收紧。
    #[tokio::test]
    async fn picker_result_flows_through_authorization_gate() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_PICK]);
        let dir = fixture_dir("files");
        let file = dir.join("picked.txt");
        std::fs::write(&file, b"x").expect("fixture file");
        let file = file.to_string_lossy().to_string();
        let picker = fake(vec![file.clone()], Vec::new());

        let err = platform_pick_files(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect_err("未授权选择结果在无弹窗通道下必须拒绝，且不得回传路径");
        assert!(err.contains("not authorized"), "got: {err}");
        assert!(!err.contains(&file), "拒绝时不得把路径回传给插件, got: {err}");

        ctx.fs_auth_checker()
            .seed_legacy_granted_path(PLUGIN, &dir.to_string_lossy())
            .await
            .expect("seed granted dir");
        let json = platform_pick_files(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect("已授权选择结果必须放行");
        assert_eq!(serde_json::from_str::<Vec<String>>(&json).expect("json"), vec![file]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `pick-folders` 同链：移动 SAF 单选语义的 0/1 项也走同一结果门
    #[tokio::test]
    async fn folders_picker_result_flows_through_authorization_gate() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_PICK]);
        let dir = fixture_dir("folders");
        let dir_str = dir.to_string_lossy().to_string();
        let picker = fake(Vec::new(), vec![dir_str.clone()]);

        let err = platform_pick_folders(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect_err("未授权目录在无弹窗通道下必须拒绝");
        assert!(err.contains("not authorized"), "got: {err}");

        ctx.fs_auth_checker()
            .seed_legacy_granted_path(PLUGIN, &dir_str)
            .await
            .expect("seed granted dir");
        let json = platform_pick_folders(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect("已授权目录必须放行");
        assert_eq!(serde_json::from_str::<Vec<String>>(&json).expect("json"), vec![dir_str]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 取消（空选择）不等价于「被拒」：直接回空数组，不需要任何授权弹窗通道
    #[tokio::test]
    async fn cancelled_pick_returns_empty_without_authorization_prompt() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_PICK]);
        let picker = fake(Vec::new(), Vec::new());
        let json = platform_pick_files(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect("取消必须成功返回");
        assert_eq!(json, "[]");
        let json = platform_pick_folders(ctx.as_ref(), ctx.as_ref(), picker.as_ref(), PLUGIN)
            .expect("取消必须成功返回");
        assert_eq!(json, "[]");
    }

    // ==================== 既有域（本文件原有用例） ====================
    //
    // 桌面扩展原有用例（wsl_distro_names / wsl_distros_fail_loudly /
    // filter_ipv4 / collect_local_ipv4 一族）已随域函数迁宿主
    // `src-tauri/src/plugin/platform.rs`（票 02 批次 06：域函数 + 单测随域走），
    // 选择器本体用例同批随宿主实现走。本文件只留交集 pick-* 的机制用例（见上）。
}
