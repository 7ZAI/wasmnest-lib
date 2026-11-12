//! 插件随包 CLI 安装/卸载：bin 目录解析、PATH 条目维护、平台注册
//!
//! - PATH 条目增删为纯字符串函数（Windows 大小写不敏感），可单测
//! - Windows：`reg` 命令操作 HKCU\Environment（免管理员），
//!   `%VAR%` 原样保留（REG_EXPAND_SZ，直接 spawn reg 不经 cmd 防展开），
//!   完成后广播 WM_SETTINGCHANGE 让新终端/agent 进程生效
//! - unix：`~/.local/bin/<name>` symlink → bin 目录（通常已在 PATH 中）
//!
//! 幂等：add 已存在条目不重复；remove 仅移除精确匹配条目（大小写不敏感），
//! 保留用户原有项。

use std::path::{Path, PathBuf};

/// Windows 平台默认 bin 目录：%LOCALAPPDATA%/com.wasmnest.app/bin
/// unix 平台默认 bin 目录：~/.wasmnest/bin
pub fn default_bin_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir()
            .map(|d| d.join("com.wasmnest.app").join("bin"))
            .unwrap_or_else(|| PathBuf::from("."))
    }
    #[cfg(not(target_os = "windows"))]
    {
        dirs::home_dir()
            .map(|d| d.join(".wasmnest").join("bin"))
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

/// CLI 可执行文件名（Windows 补 .exe）
pub fn exe_name(file_name: &str) -> String {
    let base = if file_name.is_empty() {
        "bedtask"
    } else {
        file_name
    };
    #[cfg(target_os = "windows")]
    {
        if base.ends_with(".exe") {
            base.to_string()
        } else {
            format!("{}.exe", base)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        base.to_string()
    }
}

/// unix 用户 bin 目录（通常已在 PATH 中）：~/.local/bin
fn user_local_bin() -> PathBuf {
    dirs::home_dir()
        .map(|d| d.join(".local").join("bin"))
        .unwrap_or_else(|| PathBuf::from("."))
}

// ==================== 目录级 PATH 登记（register-path / unregister-path） ====================

/// 允许登记进**用户级 PATH** 的目录根（allowlist）
///
/// 只接受落在这些根之内的目录：
/// - `~/.wasmnest`——应用数据根（插件自有数据目录在它之下，如
///   `~/.wasmnest/agent-hub/runtime/node/v24.22.1/bin`）；
/// - `%LOCALAPPDATA%/com.wasmnest.app`（Windows 应用数据目录）；
/// - `~/.local`（unix 用户 bin 根，symlink 落点）。
///
/// **为什么必须 allowlist**：PATH 是**持久化**用户环境面——被登记的目录会在之后
/// 每个新开的终端/进程里生效。放开任意路径等于给插件一条持久化劫持通道
///（把 `/tmp/evil` 或 `C:\Windows` 塞进用户 PATH）。越界一律拒绝并点名实际路径。
pub fn allowed_path_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join(".wasmnest"));
        roots.push(home.join(".local"));
    }
    #[cfg(target_os = "windows")]
    if let Some(local) = dirs::data_local_dir() {
        roots.push(local.join("com.wasmnest.app"));
    }
    roots
}

/// 路径词法规范化（allowlist 比较用）：消解 `.` / `..`、去尾分隔符
///
/// **词法而非文件系统解析**：目录可能尚不存在（登记调用方先校验存在性），
/// 且 `..` 不能穿透 allowlist 根——`~/.wasmnest/../evil` 必须归一到 `~/evil`
/// 再判定，而不是字面比较骗过门。
fn normalize_for_compare(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir => out.push(comp.as_os_str()),
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// 路径分量相等（Windows 大小写不敏感，unix 敏感）
fn component_eq(a: &std::path::Component, b: &std::path::Component) -> bool {
    let (x, y) = (
        a.as_os_str().to_string_lossy(),
        b.as_os_str().to_string_lossy(),
    );
    if cfg!(target_os = "windows") {
        x.eq_ignore_ascii_case(&y)
    } else {
        x == y
    }
}

/// `dir` 是否位于 `root` 之内（分量级比较，Windows 大小写不敏感）
fn path_starts_with(dir: &Path, root: &Path) -> bool {
    let dir_parts: Vec<_> = dir.components().collect();
    let root_parts: Vec<_> = root.components().collect();
    if root_parts.len() > dir_parts.len() {
        return false;
    }
    root_parts
        .iter()
        .zip(dir_parts.iter())
        .all(|(r, d)| component_eq(r, d))
}

/// 目录是否在 allowlist 之内（纯函数，可单测）
///
/// 相对路径一律拒绝（绝对路径才谈得上「位于某根之内」）。
pub fn path_dir_allowed_in(dir: &Path, roots: &[PathBuf]) -> bool {
    if !dir.is_absolute() {
        return false;
    }
    let dir = normalize_for_compare(dir);
    roots
        .iter()
        .any(|root| path_starts_with(&dir, &normalize_for_compare(root)))
}

/// 目录是否在默认 allowlist 之内
pub fn path_dir_allowed(dir: &Path) -> bool {
    path_dir_allowed_in(dir, &allowed_path_roots())
}

/// 目录登记进用户 PATH（跨平台入口）
///
/// Windows：把目录本身追加进 `HKCU\Environment\Path`（保留 `REG_EXPAND_SZ`
/// 类型与用户原有项，写后广播 `WM_SETTINGCHANGE`）。
/// unix：为目录下每个可执行常规文件建 `~/.local/bin/<name>` symlink。
pub async fn register_path_dir(dir: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        register_path_windows(dir).await
    }
    #[cfg(not(target_os = "windows"))]
    {
        register_path_dir_unix(dir).map(|_| ())
    }
}

/// 目录从用户 PATH 摘除（跨平台入口，幂等）
pub async fn unregister_path_dir(dir: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        unregister_path_windows(dir).await
    }
    #[cfg(not(target_os = "windows"))]
    {
        unregister_path_dir_unix(dir).map(|_| ())
    }
}

/// unix：为目录下**每个可执行常规文件**建 `~/.local/bin/<name>` symlink
///
/// 覆盖式创建（先删旧链再建）→ 幂等；返回建链的文件名列表。
/// 只认**常规文件**（`DirEntry::file_type` 不跟随符号链接）：目录、软链、
/// 设备文件都不链。
#[cfg(not(target_os = "windows"))]
pub fn register_path_dir_unix(dir: &Path) -> Result<Vec<String>, String> {
    register_path_dir_unix_in(dir, &user_local_bin())
}

/// unix：建链实现（落点可注入——单测用临时目录，不写真实 `~/.local/bin`）
#[cfg(not(target_os = "windows"))]
pub fn register_path_dir_unix_in(dir: &Path, link_dir: &Path) -> Result<Vec<String>, String> {
    use std::os::unix::fs::{symlink, PermissionsExt};
    std::fs::create_dir_all(link_dir)
        .map_err(|e| format!("create {} failed: {}", link_dir.display(), e))?;
    let mut linked = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("read dir {} failed: {}", dir.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read dir entry failed: {}", e))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("stat {} failed: {}", entry.path().display(), e))?;
        if !file_type.is_file() {
            continue;
        }
        let meta = entry
            .metadata()
            .map_err(|e| format!("stat {} failed: {}", entry.path().display(), e))?;
        // 可执行位：无执行位的文件链进 PATH 不会被 shell 当命令跑
        if meta.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let name = entry.file_name();
        let link = link_dir.join(&name);
        let target = dir.join(&name);
        let _ = std::fs::remove_file(&link);
        symlink(&target, &link).map_err(|e| {
            format!(
                "symlink {} -> {} failed: {}",
                link.display(),
                target.display(),
                e
            )
        })?;
        linked.push(name.to_string_lossy().to_string());
    }
    tracing::info!(
        "[AppCli] PATH dir registered (unix symlinks): {} -> {} ({} entries)",
        dir.display(),
        link_dir.display(),
        linked.len()
    );
    Ok(linked)
}

/// unix：摘除 `~/.local/bin` 中**指向该目录内**的 symlink
///
/// 只删指向本目录的符号链接：其他链接与**真实文件**（同名用户自建文件）
/// 一律不碰。返回被摘除的链接名列表。
#[cfg(not(target_os = "windows"))]
pub fn unregister_path_dir_unix(dir: &Path) -> Result<Vec<String>, String> {
    unregister_path_dir_unix_in(dir, &user_local_bin())
}

/// unix：摘链实现（落点可注入——单测用临时目录，不动真实 `~/.local/bin`）
#[cfg(not(target_os = "windows"))]
pub fn unregister_path_dir_unix_in(dir: &Path, link_dir: &Path) -> Result<Vec<String>, String> {
    use std::fs::symlink_metadata;
    if !link_dir.exists() {
        return Ok(Vec::new());
    }
    let dir_norm = normalize_for_compare(dir);
    let mut removed = Vec::new();
    let entries = std::fs::read_dir(link_dir)
        .map_err(|e| format!("read dir {} failed: {}", link_dir.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read dir entry failed: {}", e))?;
        let path = entry.path();
        let Ok(meta) = symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_symlink() {
            // 同名真实文件：不是本机制建的，不动
            continue;
        }
        let Ok(target) = std::fs::read_link(&path) else {
            continue;
        };
        if !path_starts_with(&normalize_for_compare(&target), &dir_norm) {
            // 指向别处的链接：不动
            continue;
        }
        std::fs::remove_file(&path)
            .map_err(|e| format!("remove symlink {} failed: {}", path.display(), e))?;
        removed.push(entry.file_name().to_string_lossy().to_string());
    }
    tracing::info!(
        "[AppCli] PATH dir unregistered (unix symlinks): {} ({} entries)",
        dir.display(),
        removed.len()
    );
    Ok(removed)
}

// ==================== PATH 条目维护（纯函数） ====================

/// 追加 PATH 条目（去重，Windows 大小写不敏感），返回新 PATH 值
///
/// - 已存在（大小写不敏感相等）→ 原样返回
/// - 空条目（前后空格/连续分号）规范化去除
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn path_add(path: &str, entry: &str) -> String {
    let entry = entry.trim();
    if entry.is_empty() {
        return path.to_string();
    }
    let mut parts: Vec<String> = path
        .split(';')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    let eq = |a: &str, b: &str| -> bool {
        if cfg!(target_os = "windows") {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    };
    if parts.iter().any(|p| eq(p, entry)) {
        return parts.join(";");
    }
    parts.push(entry.to_string());
    parts.join(";")
}

/// 移除 PATH 条目（大小写不敏感），返回 (新 PATH, 是否发生变更)
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn path_remove(path: &str, entry: &str) -> (String, bool) {
    let entry = entry.trim();
    if entry.is_empty() {
        return (path.to_string(), false);
    }
    let eq = |a: &str, b: &str| -> bool {
        if cfg!(target_os = "windows") {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    };
    let kept: Vec<String> = path
        .split(';')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .filter(|p| !eq(p, entry))
        .map(str::to_string)
        .collect();
    let changed = kept.len()
        != path
            .split(';')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .count();
    (kept.join(";"), changed)
}

// ==================== Windows 注册表 PATH ====================

/// 读取 HKCU\Environment\Path（含类型），返回 (value, is_expand_sz)
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
async fn reg_query_path() -> Result<Option<(String, bool)>, String> {
    let mut cmd = tokio::process::Command::new("reg");
    cmd.args(["query", "HKCU\\Environment", "/v", "Path"]);
    // CREATE_NO_WINDOW：reg 为控制台程序，插件激活时静默注册 PATH，避免黑窗闪烁
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(0x0800_0000);
    }
    let output = cmd
        .output()
        .await
        .map_err(|e| format!("reg query failed: {}", e))?;
    if !output.status.success() {
        // 值不存在（首次安装）：reg 返回非零且输出 ERROR 提示
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    // 输出形如：
    //   HKEY_CURRENT_USER\Environment
    //       Path    REG_EXPAND_SZ    C:\foo;%USERPROFILE%\bar
    // 取含 "Path" 的值行：第 3 段起为类型，其后为值（值可含空格）
    let line = text.lines().find(|l| {
        let mut it = l.trim_start().split_whitespace();
        matches!(it.next(), Some("Path"))
    });
    let Some(line) = line else {
        return Ok(None);
    };
    let mut it = line.trim_start().splitn(3, char::is_whitespace);
    let _name = it.next().unwrap_or("");
    let reg_type = it.next().unwrap_or("");
    let value = it.next().unwrap_or("").trim().to_string();
    Ok(Some((
        value,
        reg_type.eq_ignore_ascii_case("REG_EXPAND_SZ"),
    )))
}

/// 写回 HKCU\Environment\Path（保留原 REG_EXPAND_SZ 类型）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
async fn reg_write_path(value: &str, is_expand_sz: bool) -> Result<(), String> {
    let reg_type = if is_expand_sz {
        "REG_EXPAND_SZ"
    } else {
        "REG_SZ"
    };
    let mut cmd = tokio::process::Command::new("reg");
    cmd.args([
        "add",
        "HKCU\\Environment",
        "/v",
        "Path",
        "/t",
        reg_type,
        "/d",
        value,
        "/f",
    ]);
    // CREATE_NO_WINDOW：reg 为控制台程序，静默写入，避免黑窗闪烁
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(0x0800_0000);
    }
    let output = cmd
        .output()
        .await
        .map_err(|e| format!("reg add failed: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "reg add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// 广播 WM_SETTINGCHANGE（Environment）：通知 Explorer/新进程刷新环境变量
#[cfg(target_os = "windows")]
fn broadcast_setting_change() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };
    let env: Vec<u16> = "Environment"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // 失败仅记日志：注册表已写入，新终端从注册表读取仍会生效
    let mut result: usize = 0;
    let _ = unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            env.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        )
    };
}

/// Windows：注册 PATH（幂等：已包含则跳过）
#[cfg(target_os = "windows")]
pub async fn register_path_windows(bin_dir: &Path) -> Result<(), String> {
    let bin_str = bin_dir.to_string_lossy().to_string();
    let (current, is_expand_sz) = match reg_query_path().await? {
        Some((v, t)) => (v, t),
        None => (String::new(), true), // 首次安装按 REG_EXPAND_SZ 写入（兼容 %VAR% 条目）
    };
    let updated = path_add(&current, &bin_str);
    if updated == current {
        return Ok(()); // 幂等：已注册
    }
    reg_write_path(&updated, is_expand_sz).await?;
    broadcast_setting_change();
    tracing::info!("[AppCli] PATH registered: {}", bin_str);
    Ok(())
}

/// Windows：移除 PATH 条目（仅精确匹配本 bin 目录，保留其他项）
#[cfg(target_os = "windows")]
pub async fn unregister_path_windows(bin_dir: &Path) -> Result<(), String> {
    let bin_str = bin_dir.to_string_lossy().to_string();
    let Some((current, is_expand_sz)) = reg_query_path().await? else {
        return Ok(()); // 从未注册
    };
    let (updated, changed) = path_remove(&current, &bin_str);
    if !changed {
        return Ok(()); // 幂等：本条目不存在
    }
    reg_write_path(&updated, is_expand_sz).await?;
    broadcast_setting_change();
    tracing::info!("[AppCli] PATH entry removed: {}", bin_str);
    Ok(())
}

// ==================== unix symlink ====================

/// unix：注册 ~/.local/bin/<exe> symlink → bin_dir/<exe>
#[cfg(not(target_os = "windows"))]
pub fn register_path_unix(bin_dir: &Path, exe: &str) -> Result<(), String> {
    use std::os::unix::fs::symlink;
    let link_dir = user_local_bin();
    std::fs::create_dir_all(&link_dir)
        .map_err(|e| format!("create {} failed: {}", link_dir.display(), e))?;
    let link = link_dir.join(exe);
    let target = bin_dir.join(exe);
    // 覆盖式创建：先删旧链（已存在则直接建会失败）
    let _ = std::fs::remove_file(&link);
    symlink(&target, &link).map_err(|e| {
        format!(
            "symlink {} -> {} failed: {}",
            link.display(),
            target.display(),
            e
        )
    })?;
    tracing::info!(
        "[AppCli] symlink registered: {} -> {}",
        link.display(),
        target.display()
    );
    Ok(())
}

/// unix：移除 ~/.local/bin/<exe> symlink（仅当指向本 bin 目录，避免误删同名用户文件）
#[cfg(not(target_os = "windows"))]
pub fn unregister_path_unix(bin_dir: &Path, exe: &str) -> Result<(), String> {
    use std::fs::symlink_metadata;
    let link = user_local_bin().join(exe);
    let Ok(meta) = symlink_metadata(&link) else {
        return Ok(()); // 不存在
    };
    if !meta.file_type().is_symlink() {
        // 同名但非本插件创建的链接：不动，仅记日志
        tracing::warn!(
            "[AppCli] {} exists but is not a symlink, left untouched",
            link.display()
        );
        return Ok(());
    }
    // 校验指向本 bin 目录（避免误删用户自建链接）
    if let Ok(target) = std::fs::read_link(&link) {
        let expected = bin_dir.join(exe);
        if target != expected {
            tracing::warn!(
                "[AppCli] {} points to {} (not {}), left untouched",
                link.display(),
                target.display(),
                expected.display()
            );
            return Ok(());
        }
    }
    std::fs::remove_file(&link)
        .map_err(|e| format!("remove symlink {} failed: {}", link.display(), e))?;
    tracing::info!("[AppCli] symlink removed: {}", link.display());
    Ok(())
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_add_is_idempotent_and_case_insensitive_on_windows() {
        // 新增
        let p = path_add("C:\\a;C:\\b", "C:\\new");
        assert_eq!(p, "C:\\a;C:\\b;C:\\new");
        // 重复（精确）
        assert_eq!(path_add(&p, "C:\\new"), "C:\\a;C:\\b;C:\\new");
        // Windows 大小写不敏感（测试在任意平台跑：cfg 下仅本机 windows 生效）
        #[cfg(target_os = "windows")]
        assert_eq!(path_add(&p, "c:\\NEW"), "C:\\a;C:\\b;C:\\new");
        // 空 PATH
        assert_eq!(path_add("", "C:\\x"), "C:\\x");
        // 规范化空条目（前后空格/连续分号）
        assert_eq!(path_add("C:\\a; ;C:\\b;;", "C:\\c"), "C:\\a;C:\\b;C:\\c");
    }

    #[test]
    fn path_remove_keeps_other_entries() {
        let path = "C:\\a;C:\\b;C:\\c";
        let (updated, changed) = path_remove(path, "C:\\b");
        assert!(changed);
        assert_eq!(updated, "C:\\a;C:\\c");
        // 再次移除：无变更
        let (_, changed) = path_remove(&updated, "C:\\b");
        assert!(!changed);
        // 移除不存在的条目：无变更
        let (_, changed) = path_remove(path, "C:\\zzz");
        assert!(!changed);
        // 空 PATH 移除：无变更
        let (_, changed) = path_remove("", "C:\\a");
        assert!(!changed);
        // Windows 大小写不敏感
        #[cfg(target_os = "windows")]
        {
            let (u2, c2) = path_remove(path, "c:\\B");
            assert!(c2);
            assert_eq!(u2, "C:\\a;C:\\c");
        }
    }

    #[test]
    fn exe_name_appends_exe_on_windows_only() {
        #[cfg(target_os = "windows")]
        {
            assert_eq!(exe_name("bedtask"), "bedtask.exe");
            assert_eq!(exe_name("bedtask.exe"), "bedtask.exe");
            assert_eq!(exe_name(""), "bedtask.exe");
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(exe_name("bedtask"), "bedtask");
            assert_eq!(exe_name(""), "bedtask");
        }
    }

    // ==================== 目录级登记：allowlist + unix symlink ====================

    /// allowlist：根之内放行、根之外拒绝、相对路径拒绝、`..` 不得穿透根
    #[test]
    fn path_dir_allowed_enforces_roots() {
        let roots = vec![
            PathBuf::from("/home/u/.wasmnest"),
            PathBuf::from("/home/u/.local"),
        ];
        // 根之内（含嵌套）
        assert!(path_dir_allowed_in(
            Path::new("/home/u/.wasmnest/agent-hub/runtime/node/v24.22.1/bin"),
            &roots
        ));
        assert!(path_dir_allowed_in(Path::new("/home/u/.local/bin"), &roots));
        // 根之外
        assert!(!path_dir_allowed_in(Path::new("/tmp/evil"), &roots));
        assert!(!path_dir_allowed_in(Path::new("/home/u/other"), &roots));
        assert!(!path_dir_allowed_in(Path::new("/etc"), &roots));
        // 相对路径一律拒绝
        assert!(!path_dir_allowed_in(Path::new("relative/dir"), &roots));
        // `..` 不得穿透根（词法归一后再判定）
        assert!(!path_dir_allowed_in(
            Path::new("/home/u/.wasmnest/../evil"),
            &roots
        ));
        // 根自身放行（等号边界）
        assert!(path_dir_allowed_in(Path::new("/home/u/.wasmnest"), &roots));
    }

    /// allowlist：`..` 归一后仍在根内则放行（不得误杀合法嵌套路径）
    #[test]
    fn path_dir_allowed_normalizes_dot_segments() {
        let roots = vec![PathBuf::from("/home/u/.wasmnest")];
        assert!(path_dir_allowed_in(
            Path::new("/home/u/.wasmnest/agent-hub/./runtime"),
            &roots
        ));
        assert!(path_dir_allowed_in(
            Path::new("/home/u/.wasmnest/agent-hub/runtime/../runtime"),
            &roots
        ));
    }

    /// 默认根含应用数据根与用户 bin 根（越界目录必被拒）
    #[test]
    fn default_roots_cover_app_data_and_local_bin() {
        let roots = allowed_path_roots();
        assert!(!roots.is_empty());
        let _home = dirs::home_dir().expect("home dir");
        assert!(roots.iter().any(|r| r.ends_with(".wasmnest")));
        assert!(roots.iter().any(|r| r.ends_with(".local")));
        assert!(!path_dir_allowed(Path::new("/tmp/evil")));
    }

    /// unix：为目录下每个可执行常规文件建链（无执行位 / 目录不链），幂等
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn register_path_dir_unix_links_executables_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("appcli-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        let links = base.join("links");
        std::fs::create_dir_all(&src).expect("src dir");

        let exe = src.join("node");
        std::fs::write(&exe, b"#!/bin/sh\n").expect("write exe");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let plain = src.join("README.md");
        std::fs::write(&plain, b"x").expect("write plain");
        std::fs::create_dir_all(src.join("subdir")).expect("subdir");

        let names = register_path_dir_unix_in(&src, &links).expect("register ok");
        // 只链「可执行常规文件」
        assert_eq!(names, vec!["node".to_string()]);
        assert!(links.join("node").exists());
        assert!(!links.join("README.md").exists());
        // 幂等：重复登记不报错，链接仍指向源文件
        let again = register_path_dir_unix_in(&src, &links).expect("register again ok");
        assert_eq!(again, vec!["node".to_string()]);
        assert_eq!(
            std::fs::read_link(links.join("node")).expect("read link"),
            exe
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// unix：摘除只删指向本目录的链接，同名真实文件与其他目录的链接不碰
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn unregister_path_dir_unix_only_removes_own_links() {
        let base = std::env::temp_dir().join(format!("appcli-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        let other = base.join("other");
        let links = base.join("links");
        std::fs::create_dir_all(&src).expect("src dir");
        std::fs::create_dir_all(&other).expect("other dir");
        std::fs::create_dir_all(&links).expect("links dir");

        // 指向本目录的链接 + 指向别处的链接 + 同名真实文件
        std::os::unix::fs::symlink(src.join("a"), links.join("a")).expect("symlink a");
        std::fs::write(other.join("b"), b"x").expect("write target b");
        std::os::unix::fs::symlink(other.join("b"), links.join("b")).expect("symlink b");
        std::fs::write(links.join("c"), b"real file").expect("write c");

        let removed = unregister_path_dir_unix_in(&src, &links).expect("unregister ok");
        assert_eq!(removed, vec!["a".to_string()]);
        assert!(!links.join("a").exists());
        // 别的目录的链接与真实文件都不动
        assert!(links.join("b").exists());
        assert!(links.join("c").exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
