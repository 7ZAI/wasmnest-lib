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
    let base = if file_name.is_empty() { "bedtask" } else { file_name };
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
    let changed = kept.len() != path.split(';').map(|p| p.trim()).filter(|p| !p.is_empty()).count();
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
    let output = cmd.output().await.map_err(|e| format!("reg query failed: {}", e))?;
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
    Ok(Some((value, reg_type.eq_ignore_ascii_case("REG_EXPAND_SZ"))))
}

/// 写回 HKCU\Environment\Path（保留原 REG_EXPAND_SZ 类型）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
async fn reg_write_path(value: &str, is_expand_sz: bool) -> Result<(), String> {
    let reg_type = if is_expand_sz { "REG_EXPAND_SZ" } else { "REG_SZ" };
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
    let output = cmd.output().await.map_err(|e| format!("reg add failed: {}", e))?;
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
    let env: Vec<u16> = "Environment".encode_utf16().chain(std::iter::once(0)).collect();
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
    std::fs::create_dir_all(&link_dir).map_err(|e| format!("create {} failed: {}", link_dir.display(), e))?;
    let link = link_dir.join(exe);
    let target = bin_dir.join(exe);
    // 覆盖式创建：先删旧链（已存在则直接建会失败）
    let _ = std::fs::remove_file(&link);
    symlink(&target, &link).map_err(|e| format!("symlink {} -> {} failed: {}", link.display(), target.display(), e))?;
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
    std::fs::remove_file(&link).map_err(|e| format!("remove symlink {} failed: {}", link.display(), e))?;
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
}
