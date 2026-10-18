//! 文件系统域宿主实现（三层访问校验：权限 → 白名单 → 弹窗授权）
//!
//! 读写/复制均支持 WSL UNC 路径（`\\wsl.localhost\` / `\\wsl$\`）：
//! 发行版 Stopped 时 UNC 路径不可达，自动改用 wsl.exe 桥接访问。

use super::wsl_fs;
use crate::host_api::context::WasmHostContext;
use crate::host_api::unit_executor::UnitExecutor;
use crate::permission::{PERMISSION_FS_READ, PERMISSION_FS_WRITE};
use crate::runtime_util::block_on_async;
use crate::security::fs_auth::FsOps;
use std::sync::Arc;

// ==================== 任务单元执行器（C4：core-task 经注册表分发到域实现） ====================

/// 执行器自报（票 02 批次 05）：内核装配点经 `collected_unit_executors` 遍历注册
/// ——manager 不点名本域；执行器随 fs 域（核心子集）留内核，自报静态随之常编译。
fn make_fs_executor() -> Arc<dyn UnitExecutor> {
    Arc::new(FsUnitExecutor)
}

crate::submit_unit_executor!("fs.", make_fs_executor);

/// fs 单元执行器（kind 前缀 `fs.`）
///
/// 执行前按管线顺序预检声明闸门 + fs_auth 已授权（判据同源、**绝不从池线程触发
/// 弹窗**——spec §6：未授权 fail-visible 并指名 `host-fs.request-auth` 出路）；
/// 预检通过后再调用单路径 fs 原语，错误文案与同步链逐字一致。
pub(crate) struct FsUnitExecutor;

impl UnitExecutor for FsUnitExecutor {
    fn matches(&self, kind: &str) -> bool {
        kind.starts_with("fs.")
    }

    fn execute(
        &self,
        host_ctx: &Arc<WasmHostContext>,
        owner: &str,
        kind: &str,
        params: &serde_json::Value,
    ) -> Result<Option<String>, String> {
        ensure_unit_path_granted(host_ctx, owner, kind, params)?;
        match kind {
            "fs.read" => {
                let path = params.get("path").and_then(|v| v.as_str());
                match path {
                    Some(p) => {
                        fs_read(host_ctx.as_ref(), owner, p).map(|v| v.map(|c| serde_json::json!(c).to_string()))
                    }
                    None => Err("fs.read: missing path".to_string()),
                }
            }
            "fs.read-dir" => {
                let path = params.get("path").and_then(|v| v.as_str());
                match path {
                    Some(p) => fs_read_dir(host_ctx.as_ref(), owner, p).map(Some),
                    None => Err("fs.read-dir: missing path".to_string()),
                }
            }
            "fs.stat" => {
                let path = params.get("path").and_then(|v| v.as_str());
                match path {
                    Some(p) => fs_stat(host_ctx.as_ref(), owner, p),
                    None => Err("fs.stat: missing path".to_string()),
                }
            }
            "fs.exists" => {
                let path = params.get("path").and_then(|v| v.as_str());
                match path {
                    Some(p) => fs_exists(host_ctx.as_ref(), owner, p).map(|b| Some(serde_json::json!(b).to_string())),
                    None => Err("fs.exists: missing path".to_string()),
                }
            }
            "fs.write" => {
                let path = params.get("path").and_then(|v| v.as_str());
                let data = params.get("data").and_then(|v| v.as_str());
                match (path, data) {
                    (Some(p), Some(d)) => fs_write(host_ctx.as_ref(), owner, p, d).map(|_| Some("null".to_string())),
                    (Some(_), None) => Err("fs.write: missing data".to_string()),
                    _ => Err("fs.write: missing path".to_string()),
                }
            }
            other => Err(format!("task: unknown unit kind '{other}'")),
        }
    }
}

/// fs.* 单元执行的授权预检（按管线**同一顺序**预判，判据同源；只做已授权校验，
/// **绝不从池线程触发用户弹窗**——那会占池槽位 30s 并在错误时机打扰用户）：
///
/// 1. 声明闸门（`fs:read` / `fs:write`）——缺声明时返回与内层链逐字相同的
///    `"permission denied"`，否则单元错误会从「你没声明这个权限」变成「去申请目录」；
/// 2. 目录授权（与弹窗路径同一判据）——未授权 fail-visible 并指名
///    `host-fs.request-auth` 这条出路（缺 path 的单元由各 kind 自己报错，这里不替它判）。
fn ensure_unit_path_granted(
    host_ctx: &Arc<WasmHostContext>,
    owner: &str,
    kind: &str,
    params: &serde_json::Value,
) -> Result<(), String> {
    if !kind.starts_with("fs.") {
        return Ok(());
    }
    let needs_write = kind == "fs.write";
    let permission = if needs_write {
        PERMISSION_FS_WRITE
    } else {
        PERMISSION_FS_READ
    };
    if !host_ctx.permission().check(owner, permission) {
        return Err("permission denied".to_string());
    }
    let Some(path) = params.get("path").and_then(|v| v.as_str()) else {
        // 缺路径的单元由各 kind 自己报错（那才是它契约里的事），这里不替它判
        return Ok(());
    };
    // 所需能力按单元种类取（票 02 操作拆分）：写单元要写授权，其余要读授权——
    // 不带操作集的话「授权读」的目录能跑写单元，池线程这条无弹窗通道就成了绕过口
    let needed = if needs_write { FsOps::WRITE } else { FsOps::READ };
    // 票 02 B5：`is_granted` 是 FsAuthChecker 具体机制方法（不在窄 FsAuthGate trait
    // 上）——经下转型访问器取回（桌面装配形态恒 Some）
    let checker = host_ctx
        .fs_auth_checker();
    if block_on_async(checker.is_granted(owner, path, needed)) {
        return Ok(());
    }
    Err(format!(
        "fs unit path not authorized: {} — request it via host-fs.request-auth before submitting units",
        path
    ))
}

/// 读取文本文件（WSL UNC 路径走 wsl.exe 桥接）
fn read_text_file(path: &str) -> std::io::Result<String> {
    if let Some((distro, wsl_path)) = wsl_fs::parse_wsl_unc_path(path) {
        return wsl_fs::read_to_string_via_wsl(&distro, &wsl_path);
    }
    std::fs::read_to_string(path)
}

/// 写入文本文件（WSL UNC 路径走 wsl.exe 桥接，自动创建父目录）
fn write_text_file(path: &str, content: &str) -> std::io::Result<()> {
    if let Some((distro, wsl_path)) = wsl_fs::parse_wsl_unc_path(path) {
        return wsl_fs::write_bytes_via_wsl(&distro, &wsl_path, content.as_bytes());
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, content)
}

/// fs 资源授权：统一经 core-security 三段决策管线（wasm-core 票据 08）
///
/// 替代改造前的手工内联链（`super::check_permission` + `fs_auth.check`）：
/// 语义等价（声明 → 审批 → 强制，fs 三层校验为框架的 fs 资源实现），
/// 对外错误文案保持 `"permission denied"`（插件契约与既有用例锁定）。
///
/// 差异仅在可观测性：决策进 core-monitor `authz` 埋点——fs 是插件最活跃的
/// 资源路径，改造前不进监控（框架的唯一生产接入点是总线互调门）。
/// 授权拒绝属「可恢复异常/过滤拒绝」，按日志红线走 warn + 结构化字段。
fn authorize_fs(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
    operation: &str,
) -> Result<(), String> {
    let req = crate::security::AuthRequest {
        plugin_id,
        resource: crate::security::ResourceKind::Fs,
        operation,
        target: path,
    };
    let decision = sec.security().authorize(&req);
    if decision != crate::security::AuthDecision::Allow {
        // 拒绝原因结构化落日志：`AuthDecision::Deny` 带具体阶段原因（含「资源未注册
        // 仲裁器」这类装配漏配），只有笼统的 "permission denied" 文案会让真机排障
        // 卡在「到底哪一层拒的」上（2026-10-15 移动 fs 恒拒即此类）。
        tracing::warn!(
            plugin_id = %plugin_id,
            path = %path,
            operation = %operation,
            decision = ?decision,
            "fs: access denied by security framework"
        );
        return Err("permission denied".to_string());
    }
    Ok(())
}

/// 批量请求目录授权（权限 + fs_auth 批量弹窗校验）
///
/// 注：批量预授权（一次弹窗覆盖多路径，`check_batch` 语义）**不并入单路径
/// 授权函数**——管线 fs 资源实现的强制段是单路径 `check`，批量语义不同，
/// 强行合并会改变弹窗次数与用户交互，故保留原手工链（见票据 08）。
///
/// paths-json 为 JSON 字符串数组；返回是否全部同意（拒绝/超时均为 false）
pub(crate) fn fs_request_auth(
    fs_auth: &dyn crate::host_api::context::FsAuthScope,
    perm: &dyn crate::host_api::context::PermissionScope,
    plugin_id: &str,
    paths_json: &str,
) -> Result<bool, String> {
    if !super::check_permission(perm, plugin_id, PERMISSION_FS_READ, "host_fs_request_auth") {
        return Err("permission denied".to_string());
    }
    let paths: Vec<String> =
        serde_json::from_str(paths_json).map_err(|e| format!("fs error: invalid paths json: {}", e))?;
    if paths.is_empty() {
        return Ok(true);
    }
    let fs_auth = fs_auth
        .fs_auth_checker();
    // 操作集 = 读 + 写：`request-auth` 的 WIT 签名没有操作维度，插件的用途（fs 单元
    // 可读可写）决定这里要申请两种能力——与改造前「无操作维度 = 读写等价」逐字一致
    // （票 02 只做拆分与落账，不动这条原语的契约；将来要收窄需 WIT 加参）
    let allowed = block_on_async(fs_auth.check_batch(plugin_id, &paths, FsOps::READ_WRITE));
    if !allowed {
        tracing::warn!(
            plugin_id = %plugin_id,
            paths = ?paths,
            "fs_request_auth: denied by user"
        );
        return Ok(false);
    }
    Ok(true)
}

/// 读取文件原始字节（WSL UNC 路径走 wsl.exe 桥接）
fn read_file_bytes(path: &str) -> std::io::Result<Vec<u8>> {
    if let Some((distro, wsl_path)) = wsl_fs::parse_wsl_unc_path(path) {
        return wsl_fs::read_bytes_via_wsl(&distro, &wsl_path);
    }
    std::fs::read(path)
}

/// 写入文件原始字节（WSL UNC 路径走 wsl.exe 桥接，自动创建父目录）
fn write_file_bytes(path: &str, content: &[u8]) -> std::io::Result<()> {
    if let Some((distro, wsl_path)) = wsl_fs::parse_wsl_unc_path(path) {
        return wsl_fs::write_bytes_via_wsl(&distro, &wsl_path, content);
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, content)
}

/// 复制文件（源或目标为 WSL UNC 路径时拆为读源 + 写目标，支持跨域复制）
fn copy_file(src: &str, dst: &str) -> std::io::Result<()> {
    if wsl_fs::is_wsl_unc_path(src) || wsl_fs::is_wsl_unc_path(dst) {
        let data = read_file_bytes(src)?;
        return write_file_bytes(dst, &data);
    }
    if let Some(parent) = std::path::Path::new(dst).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::copy(src, dst).map(|_| ())
}

/// 删除文件（WSL UNC 路径走 wsl.exe 桥接；文件不存在视为成功，幂等）
fn delete_file(path: &str) -> std::io::Result<()> {
    if let Some((distro, wsl_path)) = wsl_fs::parse_wsl_unc_path(path) {
        return wsl_fs::delete_via_wsl(&distro, &wsl_path);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// 读取文本文件（权限 + 三层访问校验）
pub(crate) fn fs_read(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
) -> Result<Option<String>, String> {
    authorize_fs(sec, plugin_id, path, "read")?;
    read_text_file(path).map(Some).or_else(|e| {
        // SDK HostFs 契约：文件不存在返回 Ok(None)（store.rs 等插件依赖此语义处理新建文件）
        if e.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(format!("fs error: file read failed: {}", e))
        }
    })
}

/// 写入文本文件（权限 + 三层访问校验）
pub(crate) fn fs_write(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
    data: &str,
) -> Result<(), String> {
    authorize_fs(sec, plugin_id, path, "write")?;
    write_text_file(path, data).map_err(|e| format!("fs error: file write failed: {}", e))
}

/// 复制文件（读源 + 写目标双授权）
pub(crate) fn fs_copy(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    src: &str,
    dst: &str,
) -> Result<(), String> {
    // 双授权：源读 + 目标写（与改造前一致，逐路径经授权管线）
    authorize_fs(sec, plugin_id, src, "read")?;
    authorize_fs(sec, plugin_id, dst, "write")?;
    copy_file(src, dst).map_err(|e| format!("fs error: file copy failed: {}", e))
}

/// 删除文件（权限 + 三层访问校验；文件不存在视为成功，幂等）
pub(crate) fn fs_delete(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
) -> Result<(), String> {
    authorize_fs(sec, plugin_id, path, "write")?;
    delete_file(path).map_err(|e| format!("fs error: file delete failed: {}", e))
}

/// 检查文件是否存在（权限 + 三层访问校验，支持 WSL UNC 路径）
pub(crate) fn fs_exists(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
) -> Result<bool, String> {
    authorize_fs(sec, plugin_id, path, "read")?;
    // 支持 WSL UNC 路径
    if let Some((distro, wsl_path)) = wsl_fs::parse_wsl_unc_path(path) {
        return wsl_fs::exists_via_wsl(&distro, &wsl_path).map_err(|e| format!("fs error: WSL check failed: {}", e));
    }
    Ok(std::path::Path::new(path).exists())
}

// ==================== v19 追加（票 03 文件浏览域） ====================
//
// 票 02 批次 06（v36 交集切片）：三个函数拆入 `host-fs-desktop` interface，其
// **WIT impl 迁宿主**（`src-tauri/src/plugin/fs.rs` 路径 B）。实现本体留内核作
// **机制**（与 `check_permission` 提 pub 同款先例）：① 内核 `FsUnitExecutor`
// （`fs.read-dir` / `fs.stat` task 单元）仍消费同一条实现；② 宿主 WIT impl 经
// 公开面复用，行为逐字不变。函数签名（`SecurityScope` + 权限判据 + 错误文案）
// 不随迁改变。

/// 目录直读（v19 追加）：`[{name, nodeType}]`（JSON 字符串）
///
/// `nodeType` 由 `DirEntry::file_type` 判定：目录 → "folder"、文件 → "file"、
/// 其余（symlink / 特殊条目）→ "other"——与宿主 file_controller::scan_dir
/// 「跳过非目录非文件条目」的语义对齐（symlink 不进文件树）。
/// 权限 `fs:read` + fs_auth 三层校验；不支持 WSL UNC（与宿主 file_controller
/// 的 std::fs 语义一致，working_dir 是宿主路径）。
pub fn fs_read_dir(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
) -> Result<String, String> {
    authorize_fs(sec, plugin_id, path, "read")?;
    let read_dir = std::fs::read_dir(path).map_err(|e| format!("fs error: read dir '{}' failed: {}", path, e))?;
    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("fs error: read dir entry failed: {}", e))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("fs error: dir entry file type failed: {}", e))?;
        let node_type = if file_type.is_dir() {
            "folder"
        } else if file_type.is_file() {
            "file"
        } else {
            "other"
        };
        entries.push(serde_json::json!({ "name": name, "nodeType": node_type }));
    }
    serde_json::to_string(&entries).map_err(|e| format!("fs error: read dir serialize failed: {}", e))
}

/// canonicalize 绝对路径（v19 追加）；路径不存在返回 `Ok(None)`
///
/// 供 `../` 穿越与 symlink 逃逸的 containment 判定（宿主 file 控制器
/// 同语义：canonicalize 后校验前缀在根目录内）。
///
/// 消费方在桌面装配面（`host_api.rs` 再导出 → 桌面宿主 `plugin/fs.rs`）；移动形态
/// 经 fs_mobile 域直连实现，不消费本函数——单形态共享故保留 + 按形态豁免。
/// 防回接锁（lib.rs 锁测试）钉住源码文本 `pub fn fs_canonicalize`，不得删除。
#[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
pub fn fs_canonicalize(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
) -> Result<Option<String>, String> {
    authorize_fs(sec, plugin_id, path, "read")?;
    match std::fs::canonicalize(path) {
        Ok(canonical) => Ok(Some(canonical.to_string_lossy().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("fs error: canonicalize '{}' failed: {}", path, e)),
    }
}

/// 文件元数据（v19 追加）：`{size, isFile, isDir}`；路径不存在返回 `Ok(None)`
///
/// 供文件大小上限判定（与宿主 file 域的大小上限语义一致）。
pub fn fs_stat(
    sec: &dyn crate::host_api::context::SecurityScope,
    plugin_id: &str,
    path: &str,
) -> Result<Option<String>, String> {
    authorize_fs(sec, plugin_id, path, "read")?;
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(
            serde_json::json!({
                "size": meta.len(),
                "isFile": meta.is_file(),
                "isDir": meta.is_dir(),
            })
            .to_string(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("fs error: stat '{}' failed: {}", path, e)),
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_api::tests::build_host_ctx;
    use crate::host_api::grant_permissions;
    use crate::monitor::MetricsRegistry;
    use crate::permission::PERMISSION_FS_WRITE;
    use std::sync::Arc;

    const PLUGIN: &str = "test-plugin";

    /// fs.* 单元的授权预检按管线顺序判两件事，且**不弹窗**（票 07 C4：随
    /// FsUnitExecutor 自 manager::task 迁入本域；执行器经注册表由 core-task 分发）
    #[test]
    fn fs_unit_executor_gate_follows_pipeline_order_and_never_prompts() {
        let executor = FsUnitExecutor;
        let ctx = build_host_ctx();
        let dir = bare_temp_root("fs-unit-gate");
        let file = dir.1.join("f.txt");
        std::fs::write(&file, b"x").expect("write fixture");
        let path = file.to_string_lossy().to_string();
        let read_params = serde_json::json!({ "path": path.clone() });

        // ① 未声明 fs:read：文案必须与内层链逐字相同（否则把插件指向无关出路）
        assert_eq!(
            executor
                .execute(&ctx, "test-plugin", "fs.read", &read_params)
                .unwrap_err(),
            "permission denied",
            "缺声明时不得先报目录未授权"
        );

        // ② 声明了但目录未授权：给出可行动出路
        ctx.permission()
            .grant_permissions("test-plugin", &[PERMISSION_FS_READ.to_string()]);
        let err = executor
            .execute(&ctx, "test-plugin", "fs.read", &read_params)
            .expect_err("未授权路径必须被拒");
        assert!(err.contains(&path), "错误文案须点明是哪条路径: {err}");
        assert!(err.contains("request-auth"), "错误文案须给出出路: {err}");

        // ③ 预置持久化授权（= 用户在弹窗里点过「记住」）→ 放行并真实执行成功
        let checker = ctx
            .fs_auth_checker();
        block_on_async(checker.seed_legacy_granted_path("test-plugin", &path)).expect("seed grant");
        executor
            .execute(&ctx, "test-plugin", "fs.read", &read_params)
            .expect("已授权路径须放行");

        // ④ 授权不跨插件共享；写单元要的是 fs:write（读了授权也不许写）
        executor
            .execute(&ctx, "test-plugin.other", "fs.read", &read_params)
            .expect_err("授权不得跨插件共享");
        let write_params = serde_json::json!({ "path": path.clone(), "data": "x" });
        assert_eq!(
            executor
                .execute(&ctx, "test-plugin", "fs.write", &write_params)
                .unwrap_err(),
            "permission denied",
            "只授 fs:read 不得让写单元过闸"
        );
        ctx.permission().grant_permissions(
            "test-plugin",
            &[PERMISSION_FS_READ.to_string(), PERMISSION_FS_WRITE.to_string()],
        );
        executor
            .execute(&ctx, "test-plugin", "fs.write", &write_params)
            .expect("声明 fs:write 后写单元须过预检");

        // ⑤ 非 fs 单元不属于本执行器；缺 path 的 fs 单元由 kind 分支报错，预检不插手
        assert!(!executor.matches("process.run-sync"), "process 单元不属于 fs 执行器");
        let nopath = serde_json::json!({});
        let err = executor.execute(&ctx, "test-plugin", "fs.read", &nopath).unwrap_err();
        assert!(err.contains("missing path"), "缺 path 由 kind 契约报错: {err}");
    }

    /// 每个测试独立的临时目录根（纯文件辅助函数用，不经 fs_auth）
    fn bare_temp_root(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join(name);
        std::fs::create_dir_all(&root).expect("create root");
        (dir, root)
    }

    /// 临时目录根 + **持久化授权预置**（票 07 后无弹窗放行的唯一测试入口）
    ///
    /// 旧做法把目录塞进 `.claude` 段借路径白名单免检——那条白名单对**任何**插件都
    /// 放行，已随票 07 退役。这里改走生产同款通道：用户在弹窗里勾选「记住」后落的
    /// `fs_granted_paths` 前缀记录，测的仍然是 fs 原语本身而不是授权豁免的后门。
    fn granted_temp_root(name: &str, ctx: &WasmHostContext) -> (tempfile::TempDir, std::path::PathBuf) {
        let (dir, root) = bare_temp_root(name);
        let checker = ctx
            .fs_auth_checker();
        block_on_async(checker.seed_legacy_granted_path(PLUGIN, &root.to_string_lossy()))
            .expect("seed persisted grant");
        (dir, root)
    }

    // ==================== 私有纯文件操作辅助 ====================

    /// write_text_file 自动创建不存在的父目录 + 读写往返
    #[test]
    fn write_text_file_creates_parent_dirs_roundtrip() {
        let (_dir, root) = bare_temp_root("roundtrip");
        let path = root.join("a/b/c/roundtrip.txt");
        write_text_file(path.to_str().unwrap(), "hello").expect("write ok");
        assert_eq!(read_text_file(path.to_str().unwrap()).expect("read ok"), "hello");
    }

    /// read_text_file 不存在的文件返回 NotFound（与 std 语义一致，供上层翻译为 None）
    #[test]
    fn read_text_file_missing_returns_not_found() {
        let (_dir, root) = bare_temp_root("missing");
        let path = root.join("missing.txt");
        let err = read_text_file(path.to_str().unwrap()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// delete_file 幂等：不存在的文件视为成功
    #[test]
    fn delete_file_missing_idempotent() {
        let (_dir, root) = bare_temp_root("delete");
        let path = root.join("never-exists.txt");
        delete_file(path.to_str().unwrap()).expect("delete missing ok");
        // 写入后删除，再次删除仍 Ok
        write_text_file(path.to_str().unwrap(), "x").unwrap();
        delete_file(path.to_str().unwrap()).expect("delete ok");
        delete_file(path.to_str().unwrap()).expect("delete again ok");
    }

    /// copy_file 目标父目录不存在时自动创建
    #[test]
    fn copy_file_creates_parent_dirs() {
        let (_dir, root) = bare_temp_root("copy");
        let src = root.join("src.txt");
        let dst = root.join("deep/nested/dst.txt");
        write_text_file(src.to_str().unwrap(), "payload").unwrap();
        copy_file(src.to_str().unwrap(), dst.to_str().unwrap()).expect("copy ok");
        assert_eq!(read_text_file(dst.to_str().unwrap()).unwrap(), "payload");
    }

    /// write_file_bytes / read_file_bytes 二进制往返
    #[test]
    fn write_read_file_bytes_roundtrip() {
        let (_dir, root) = bare_temp_root("bytes");
        let path = root.join("data.bin");
        let bytes: Vec<u8> = (0..=255u8).collect();
        write_file_bytes(path.to_str().unwrap(), &bytes).expect("write ok");
        assert_eq!(read_file_bytes(path.to_str().unwrap()).unwrap(), bytes);
    }

    // ==================== 权限门禁 ====================

    /// 无 fs:read 权限：读被拒绝
    #[test]
    fn fs_read_permission_denied() {
        let ctx = build_host_ctx();
        let err = fs_read(ctx.as_ref(), PLUGIN, "/tmp/x").unwrap_err();
        assert_eq!(err, "permission denied");
    }

    /// 无 fs:write 权限：写被拒绝
    #[test]
    fn fs_write_permission_denied() {
        let ctx = build_host_ctx();
        let err = fs_write(ctx.as_ref(), PLUGIN, "/tmp/x", "data").unwrap_err();
        assert_eq!(err, "permission denied");
    }

    /// 无 fs:write 权限：删被拒绝
    #[test]
    fn fs_delete_permission_denied() {
        let ctx = build_host_ctx();
        let err = fs_delete(ctx.as_ref(), PLUGIN, "/tmp/x").unwrap_err();
        assert_eq!(err, "permission denied");
    }

    /// 无 fs:read 权限：存在性检查被拒绝
    #[test]
    fn fs_exists_permission_denied() {
        let ctx = build_host_ctx();
        let err = fs_exists(ctx.as_ref(), PLUGIN, "/tmp/x").unwrap_err();
        assert_eq!(err, "permission denied");
    }

    /// **移动装配面回归锁**：`new_headless`（= 移动 `PluginManager` 用的 `new_with_ports`）
    /// 必须和桌面构造器一样注册 fs 仲裁器
    ///
    /// 真机链路（2026-10-15 ai-chatbox SIGILL 崩溃）：移动上下文漏注册 ⇒
    /// `authorize_fs` 归到「资源 Fs 未注册仲裁器，默认拒绝」⇒ host-fs 全部原语恒拒
    /// ⇒插件 activate 在 `store::init` 失败 ⇒ 插件前端照常加载并调命令 ⇒
    /// guest 状态未初始化即 panic ⇒ 真机 trap 未被处理 ⇒ 进程 SIGILL。
    /// 授权面已预置（grant + 旧式前缀记录）——本用例只盯「仲裁器在不在」。
    #[test]
    fn ports_host_ctx_registers_fs_authorizer() {
        let ctx = crate::host_api::tests::build_ports_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let (_dir, root) = granted_temp_root("ports-ctx-fs", &ctx);
        let probe = root.join("probe.txt");
        // 未预先创建：存在性检查应得 Ok(false)，而不是「permission denied」
        assert!(
            !fs_exists(ctx.as_ref(), PLUGIN, probe.to_str().unwrap()).unwrap(),
            "移动装配面 fs 原语不得被拒（仲裁器未注册即恒拒）"
        );
    }

    /// fs_copy 需要读+写双权限：只授 fs:read 时在写校验处被拒绝
    #[test]
    fn fs_copy_requires_both_permissions() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let err = fs_copy(ctx.as_ref(), PLUGIN, "/tmp/a", "/tmp/b").unwrap_err();
        assert_eq!(err, "permission denied");
    }

    /// fs_request_auth 空路径数组：无需弹窗直接放行（批量请求约定）
    #[test]
    fn fs_request_auth_empty_paths_ok() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        assert!(fs_request_auth(ctx.as_ref(), ctx.as_ref(), PLUGIN, "[]").expect("empty paths ok"));
    }

    /// fs_request_auth 非法 JSON：解析失败
    #[test]
    fn fs_request_auth_invalid_json_rejected() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let err = fs_request_auth(ctx.as_ref(), ctx.as_ref(), PLUGIN, "not-json").unwrap_err();
        assert!(err.contains("invalid paths json"), "got: {}", err);
    }

    /// 无 fs:read 权限：批量授权请求被拒绝
    #[test]
    fn fs_request_auth_permission_denied() {
        let ctx = build_host_ctx();
        let err = fs_request_auth(ctx.as_ref(), ctx.as_ref(), PLUGIN, "[]").unwrap_err();
        assert_eq!(err, "permission denied");
    }

    // ==================== 端到端（已授权临时根 + 内存上下文） ====================

    /// 写→读往返（fs_write 自动建父目录；SDK 契约：文件不存在 fs_read 返回 Ok(None)）
    #[tokio::test]
    async fn fs_write_then_read_roundtrip() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ, PERMISSION_FS_WRITE]);
        let (_dir, root) = granted_temp_root("e2e-roundtrip", &ctx);
        let path = root.join("roundtrip.txt");

        fs_write(ctx.as_ref(), PLUGIN, path.to_str().unwrap(), "hello wasm").expect("write ok");
        let content = fs_read(ctx.as_ref(), PLUGIN, path.to_str().unwrap())
            .expect("read ok")
            .expect("value");
        assert_eq!(content, "hello wasm");
    }

    /// 不存在的文件：fs_read 返回 Ok(None)（store.rs 等插件依赖此语义处理新建文件）
    #[tokio::test]
    async fn fs_read_missing_file_returns_none() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let (_dir, root) = granted_temp_root("e2e-missing", &ctx);
        let path = root.join("missing.txt");
        assert!(fs_read(ctx.as_ref(), PLUGIN, path.to_str().unwrap())
            .expect("read ok")
            .is_none());
    }

    /// 存在性检查：写入后 true，删除后 false
    #[tokio::test]
    async fn fs_exists_tracks_file_lifecycle() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ, PERMISSION_FS_WRITE]);
        let (_dir, root) = granted_temp_root("e2e-exists", &ctx);
        let path = root.join("exists.txt");
        assert!(!fs_exists(ctx.as_ref(), PLUGIN, path.to_str().unwrap()).expect("missing false"));
        fs_write(ctx.as_ref(), PLUGIN, path.to_str().unwrap(), "x").unwrap();
        assert!(fs_exists(ctx.as_ref(), PLUGIN, path.to_str().unwrap()).expect("exists true"));
        fs_delete(ctx.as_ref(), PLUGIN, path.to_str().unwrap()).expect("delete ok");
        assert!(!fs_exists(ctx.as_ref(), PLUGIN, path.to_str().unwrap()).expect("deleted false"));
    }

    /// fs_delete 幂等：删除不存在的文件同样 Ok
    #[tokio::test]
    async fn fs_delete_missing_idempotent() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ, PERMISSION_FS_WRITE]);
        let (_dir, root) = granted_temp_root("e2e-delete", &ctx);
        let path = root.join("delete-missing.txt");
        fs_delete(ctx.as_ref(), PLUGIN, path.to_str().unwrap()).expect("delete missing ok");
    }

    /// fs_copy 端到端：源读授权 + 目标写授权 + 自动创建父目录
    #[tokio::test]
    async fn fs_copy_end_to_end() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ, PERMISSION_FS_WRITE]);
        let (_dir, root) = granted_temp_root("e2e-copy", &ctx);
        let src = root.join("copy-src.txt");
        let dst = root.join("nested/copy-dst.txt");
        fs_write(ctx.as_ref(), PLUGIN, src.to_str().unwrap(), "payload").unwrap();
        fs_copy(ctx.as_ref(), PLUGIN, src.to_str().unwrap(), dst.to_str().unwrap()).expect("copy ok");
        let content = fs_read(ctx.as_ref(), PLUGIN, dst.to_str().unwrap())
            .expect("read ok")
            .expect("value");
        assert_eq!(content, "payload");
    }

    // ==================== 票据 08：fs 授权经统一框架 + 决策埋点 ====================

    /// 埋点：无权限的 fs 访问被框架拒绝 → 决策进 `authz.deny` 计数
    /// （改造前 fs 走手工链、不进监控；这是本次的核心可观测性收益）
    #[tokio::test]
    async fn fs_denied_decision_counted_into_monitor() {
        let ctx = build_host_ctx();
        let monitor = Arc::new(MetricsRegistry::new());
        ctx.security().set_monitor(monitor.clone());

        let err = fs_read(ctx.as_ref(), PLUGIN, "/tmp/denied").unwrap_err();
        assert_eq!(err, "permission denied", "对外错误文案须保持不变");

        let authz = &monitor.snapshot()["plugins"][PLUGIN]["authz"];
        assert_eq!(authz["deny"], 1, "拒绝决策必须进监控埋点");
        assert_eq!(authz["allow"], 0);
    }

    /// 埋点：已授权路径放行 → 决策进 `authz.allow` 计数
    #[tokio::test]
    async fn fs_allowed_decision_counted_into_monitor() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let monitor = Arc::new(MetricsRegistry::new());
        ctx.security().set_monitor(monitor.clone());

        let (_dir, root) = granted_temp_root("fs-monitor-allow", &ctx);
        let path = root.join("f.txt");
        // 已授权路径放行（文件不存在按 SDK 契约返回 Ok(None)）
        assert!(fs_read(ctx.as_ref(), PLUGIN, path.to_str().unwrap())
            .expect("read ok")
            .is_none());

        let authz = &monitor.snapshot()["plugins"][PLUGIN]["authz"];
        assert_eq!(authz["allow"], 1, "放行决策必须进监控埋点");
        assert_eq!(authz["deny"], 0);
    }

    /// 等价性：operation 映射 —— 只授 fs:read 时 fs_write 仍被拒绝
    /// （框架 FsAuthorizer 的 read/write → 权限映射正确，无越权升格）
    #[tokio::test]
    async fn fs_write_denied_when_only_read_permission_granted() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let (_dir, root) = bare_temp_root("fs-write-gate");
        let path = root.join("f.txt");

        assert_eq!(
            fs_write(ctx.as_ref(), PLUGIN, path.to_str().unwrap(), "x").unwrap_err(),
            "permission denied",
            "read 权限不得用于写操作"
        );
    }

    /// 等价性：fs_copy 双路径双权限 —— 缺写权限时拒绝（即便源路径可读）
    #[tokio::test]
    async fn fs_copy_requires_read_and_write_permissions() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let (_dir, root) = bare_temp_root("fs-copy-gate");
        let src = root.join("a.txt");
        let dst = root.join("b.txt");

        assert_eq!(
            fs_copy(ctx.as_ref(), PLUGIN, src.to_str().unwrap(), dst.to_str().unwrap()).unwrap_err(),
            "permission denied",
            "copy 须同时具备源读与目标写授权"
        );
    }

    /// 等价性：已声明权限但路径未授权（无头无弹窗）→ 强制段拒绝且计数
    /// （改造未放宽安全边界：三层校验仍生效）
    #[tokio::test]
    async fn fs_ungranted_path_denied_by_enforce_stage() {
        let ctx = build_host_ctx();
        grant_permissions(&ctx, PLUGIN, &[PERMISSION_FS_READ]);
        let monitor = Arc::new(MetricsRegistry::new());
        ctx.security().set_monitor(monitor.clone());

        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("plain").join("f.txt");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "x").unwrap();

        assert_eq!(
            fs_read(ctx.as_ref(), PLUGIN, path.to_str().unwrap()).unwrap_err(),
            "permission denied",
            "非白名单且无授权的路径必须被拒绝"
        );
        assert_eq!(monitor.snapshot()["plugins"][PLUGIN]["authz"]["deny"], 1);
    }
}
