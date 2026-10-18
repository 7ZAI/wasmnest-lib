//! 平台定位原语（引擎级）
//!
//! 「在系统文件管理器中打开所在目录并选中目标」的实现本体。两个消费方共用同一份
//! 平台实现（Windows Shell COM / macOS `open -R` / Linux `xdg-open`）：
//! - `commands/opener.rs::open_log_dir`（宿主设置页「打开日志目录」）
//! - `src-tauri/src/plugin/platform.rs::platform_reveal_in_dir`
//!   （插件原语 `host-platform.reveal-in-dir`，ABI v22；WIT 域迁宿主后经此复用）
//!
//! 平台细节与历史注释（Windows `\\?\` verbatim 前缀、`SHOpenFolderAndSelectItems`
//! 的 `ERROR_FILE_NOT_FOUND` 兜底）随 2026-09-21 从 `commands/opener.rs` 搬迁保留。
//! 落点从命令层移到 `system/` 是分层需要：该实现是**引擎原语**，命令层不该承载
//! 插件能力实现，而宿主侧域实现（`pub(super)`）对命令层不可见。

use std::path::{Path, PathBuf};

/// 校验并定位文件/目录（`host-platform.reveal-in-dir` 原语入口）
///
/// - 剥离历史 wasm 产物可能带上的 `\\?\` verbatim 前缀：旧版插件用 POSIX 语义
///   拼出 `\\?\D:\下载/file.mkv` 这类路径，Windows 下 `exists` / `canonicalize`
///   直接报 os error 123（纯正斜杠 / 混合分隔符均为宿主 API 接受）
/// - 路径不存在 → `AppError::NotFound("reveal: path not found: …")`
/// - 平台分发失败 → `AppError::Internal("reveal: failed to open '…': …")`
pub fn reveal_existing_in_dir(path: &str) -> crate::Result<()> {
    let path = PathBuf::from(strip_verbatim_prefix(path));
    if !path.exists() {
        return Err(crate::AppError::NotFound(format!(
            "reveal: path not found: {}",
            path.display()
        )));
    }
    reveal_in_dir(&path)
        .map_err(|e| crate::AppError::Internal(format!("reveal: failed to open '{}': {}", path.display(), e)))
}

/// 剥离 Windows `\\?\` verbatim 前缀（非 Windows 路径原样返回）
fn strip_verbatim_prefix(path: &str) -> &str {
    path.strip_prefix(r"\\?\").unwrap_or(path)
}

/// 平台分发：仅在目标平台编译对应分支（避免未使用函数告警）
///
/// - Windows：Shell COM API（`SHOpenFolderAndSelectItems`）定位选中文件；
///   不用 `explorer /select,<path>` 命令行：explorer 的参数解析器非标准
///   （逗号当分隔符、不识别 Command 序列化后的外层引号 + `\"` 转义），路径
///   解析失败会退化为打开默认位置（桌面/快速访问）并选中一个无关文件夹，
///   Win11 实测复现。COM 直接以 PIDL 操作 Shell，彻底绕开命令行解析。
/// - macOS：`open -R <path>`（Finder 定位选中）
/// - Linux：`xdg-open` 打开所在目录（无 reveal 语义，退化为打开目录）
pub fn reveal_in_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows_reveal(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let (program, args) = unix_reveal_command(std::env::consts::OS, path);
        std::process::Command::new(program).args(args).spawn().map(|_| ())
    }
}

/// 非 Windows 平台的定位命令构造（纯函数：便于跨平台钉住参数与分支选择）
///
/// macOS 走 `open -R <path>`（定位并选中目标）；其余（Linux 等）走
/// `xdg-open <父目录>`（无 reveal 语义，退化为打开所在目录）。
fn unix_reveal_command(os: &str, path: &Path) -> (&'static str, Vec<String>) {
    if os == "macos" {
        ("open", vec!["-R".to_string(), path.display().to_string()])
    } else {
        let dir = path.parent().unwrap_or(path);
        ("xdg-open", vec![dir.display().to_string()])
    }
}

// ==================== 外部 URL 打开（scheme 白名单闸门） ====================

/// 允许交系统浏览器打开的 URL scheme 白名单（fail-closed：不在表内一律拒绝）
///
/// 只放 http/https：`file://` 会变成任意本地文件读取入口，`javascript:` / `data:`
/// 会变成脚本执行入口，`smb://` / `ftp://` 等会把「打开链接」变成任意外部协议跳板。
const EXTERNAL_URL_ALLOWED_SCHEMES: [&str; 2] = ["http", "https"];

/// 校验待打开的外部 URL，只放行 http/https
///
/// 存在的理由：宿主外壳命令 `open_external_url` 是前端**唯一**合法的「打开外部链接」
/// 通路（`shell:allow-open` 权限已随前端零资源访问红线撤除，见
/// `capabilities/default.json` 与 `tests/capabilities_lock.rs` 的防回接锁），因此闸门必须
/// 落在宿主侧且**默认拒绝**。
///
/// 拒绝：空串 / 无 `:` / scheme 非法字符（非 `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`）
/// / scheme 不在白名单 / 冒号后为空 / 含 ASCII 控制字符（防走私）。
pub fn validate_external_url(url: &str) -> crate::Result<&str> {
    let err = |reason: &str| crate::AppError::InvalidInput(format!("open_external_url: {reason}: {url:?}"));

    if url.is_empty() {
        return Err(err("empty url"));
    }
    if url.chars().any(|c| c.is_control()) {
        return Err(err("url contains control characters"));
    }

    let Some((scheme, rest)) = url.split_once(':') else {
        return Err(err("missing scheme separator ':'"));
    };
    if rest.is_empty() {
        return Err(err("nothing after scheme separator"));
    }

    let mut chars = scheme.chars();
    let starts_with_alpha = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    let rest_is_legal = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !starts_with_alpha || !rest_is_legal {
        return Err(err("scheme is not a legal RFC 3986 scheme token"));
    }

    if !EXTERNAL_URL_ALLOWED_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()) {
        return Err(err("scheme not in allowlist (only http/https)"));
    }

    Ok(url)
}

// ==================== Windows：Shell COM 选中 ====================

/// Windows 平台分发：目录输入打开目录视图；文件输入走 Shell COM 选中
#[cfg(target_os = "windows")]
fn windows_reveal(path: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::{
        Foundation::ERROR_FILE_NOT_FOUND,
        System::Com::CoInitialize,
        UI::Shell::{Common::ITEMIDLIST, ILCreateFromPathW, ILFree, SHOpenFolderAndSelectItems},
    };

    // 目录输入：直接打开目录视图（explore verb），无选中语义
    if path.is_dir() {
        return shell_execute_explore(path);
    }

    unsafe {
        // 进程级 COM 初始化（幂等；与 tauri-plugin-opener 同款，不做 CoUninitialize
        // 配对——Shell API 在 Tauri 进程生命周期内反复使用，引用计数无碍）
        let _ = CoInitialize(std::ptr::null());

        // 父目录 + 目标文件的 ITEMIDLIST（以宽字符路径直接构造，规避一切
        // 命令行转义/编码问题，中文路径原生支持）
        let dir = path.parent().unwrap_or(path);
        let dir_wide = to_wide(dir);
        let file_wide = to_wide(path);
        let dir_item = ILCreateFromPathW(dir_wide.as_ptr());
        let file_item = ILCreateFromPathW(file_wide.as_ptr());

        let hr = if dir_item.is_null() || file_item.is_null() {
            if !dir_item.is_null() {
                ILFree(dir_item);
            }
            if !file_item.is_null() {
                ILFree(file_item);
            }
            // PIDL 构造失败（非常规文件系统路径）：直接退化为打开目录
            return shell_execute_explore(dir);
        } else {
            let hr = SHOpenFolderAndSelectItems(
                dir_item,
                1,
                std::ptr::addr_of!(file_item) as *const *const ITEMIDLIST,
                0,
            );
            ILFree(dir_item);
            ILFree(file_item);
            hr
        };

        // 已知坑（tauri-plugin-opener 同款注释）：部分系统 SHOpenFolderAndSelectItems
        // 对存在文件仍报 ERROR_FILE_NOT_FOUND，此时 ShellExecuteExW 打开目录兜底
        // （能进目录但不再选中文件）。HRESULT 为 0x8007xxxx 形态，低 16 位即 Win32 码
        if (hr & 0xFFFF) as u32 == ERROR_FILE_NOT_FOUND {
            return shell_execute_explore(dir);
        }
        if hr != 0 {
            return Err(std::io::Error::from_raw_os_error(hr));
        }
        Ok(())
    }
}

/// Windows：ShellExecuteExW 打开目录视图（explore verb）
#[cfg(target_os = "windows")]
fn shell_execute_explore(dir: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::UI::{
        Shell::{ShellExecuteExW, SHELLEXECUTEINFOW, SHELLEXECUTEINFOW_0},
        WindowsAndMessaging::SW_SHOWNORMAL,
    };

    let dir_wide = to_wide(dir);
    let verb: [u16; 8] = [0x65, 0x78, 0x70, 0x6c, 0x6f, 0x72, 0x65, 0]; // "explore\0"
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: 0,
        hwnd: std::ptr::null_mut(),
        lpVerb: verb.as_ptr(),
        lpFile: dir_wide.as_ptr(),
        lpParameters: std::ptr::null(),
        lpDirectory: std::ptr::null(),
        nShow: SW_SHOWNORMAL,
        hInstApp: std::ptr::null_mut(),
        lpIDList: std::ptr::null_mut(),
        lpClass: std::ptr::null(),
        hkeyClass: std::ptr::null_mut(),
        dwHotKey: 0,
        // hIcon / hMonitor 共用 union（windows-sys 0.61 以 Anonymous 呈现）
        Anonymous: SHELLEXECUTEINFOW_0 {
            hIcon: std::ptr::null_mut(),
        },
        hProcess: std::ptr::null_mut(),
    };
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// UTF-16 宽字符路径（NUL 结尾，供 *W Shell API 直接使用）
#[cfg(target_os = "windows")]
fn to_wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 契约：verbatim 前缀只在**开头**时剥离（历史 wasm 产物的 `\\?\D:\x/y` 形态）
    #[test]
    fn strip_verbatim_prefix_only_at_start() {
        assert_eq!(strip_verbatim_prefix(r"\\?\D:\下载\file.mkv"), r"D:\下载\file.mkv");
        assert_eq!(strip_verbatim_prefix(r"\\?\D:\下载/file.mkv"), r"D:\下载/file.mkv");
        assert_eq!(strip_verbatim_prefix("/tmp/a/b.txt"), "/tmp/a/b.txt");
        assert_eq!(
            strip_verbatim_prefix(r"D:\\?\nested.txt"),
            r"D:\\?\nested.txt",
            "非开头的同形字串不得被剥离"
        );
    }

    /// 反例：路径不存在 → NotFound（文案含操作上下文），且**不进入平台分发**
    /// （不会 spawn 任何进程——测试无副作用）
    #[test]
    fn reveal_existing_in_dir_reports_missing_path() {
        let err = reveal_existing_in_dir("/definitely/not/here/xyz.txt").expect_err("missing path must fail loudly");
        let msg = err.to_string();
        assert!(
            matches!(err, crate::AppError::NotFound(_)),
            "缺失路径必须走 NotFound 分支，got: {msg}"
        );
        assert!(msg.contains("reveal: path not found"), "got: {msg}");
    }

    /// 平台分支选择（纯函数钉住两端参数）：macOS 定位选中、其余平台退化为打开目录
    #[test]
    fn unix_reveal_command_pins_platform_arguments() {
        let file = Path::new("/home/u/downloads/movie.mkv");

        let (program, args) = unix_reveal_command("macos", file);
        assert_eq!(program, "open");
        assert_eq!(
            args,
            vec!["-R".to_string(), "/home/u/downloads/movie.mkv".to_string()],
            "macOS 必须定位选中目标本身"
        );

        let (program, args) = unix_reveal_command("linux", file);
        assert_eq!(program, "xdg-open");
        assert_eq!(
            args,
            vec!["/home/u/downloads".to_string()],
            "Linux 无 reveal 语义，打开父目录"
        );
    }

    /// 边界：无父目录的路径（根 / 单段）按自身打开，不 panic
    #[test]
    fn unix_reveal_command_falls_back_to_self_for_rootless_path() {
        let (program, args) = unix_reveal_command("linux", Path::new("/"));
        assert_eq!(program, "xdg-open");
        assert_eq!(args, vec!["/".to_string()]);
    }
}

#[cfg(test)]
mod external_url_tests {
    use super::validate_external_url;

    /// 正例：http / https 放行（含大写 scheme，RFC 3986 scheme 大小写无关）
    #[test]
    fn allows_http_and_https() {
        for url in [
            "https://github.com/7ZAI/BedCode",
            "http://example.com",
            "HTTPS://EXAMPLE.COM/Path",
            "HtTp://localhost:1420/x?y=1#z",
        ] {
            assert_eq!(validate_external_url(url).ok(), Some(url), "http/https 必须放行：{url}");
        }
    }

    /// 反例：白名单外的 scheme 一律拒绝——这些正是「打开链接」变成越权读取 / 执行的入口
    #[test]
    fn rejects_non_allowlisted_schemes() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "ftp://example.com/x",
            "smb://share/x",
            "tauri://localhost",
            "vscode://file/x",
            "intent://scan#Intent;scheme=zxing;end",
            "mailto:a@b.com",
            "tel:+100",
        ] {
            let err = validate_external_url(url)
                .expect_err("白名单外 scheme 必须拒绝")
                .to_string();
            assert!(err.contains("open_external_url"), "错误必须带操作上下文，got: {err}");
        }
    }

    /// 边界：非法 scheme 词法（缺首字符 / 非法字符 / 缺冒号 / 冒号后空 / 空串）全拒绝
    #[test]
    fn rejects_malformed_urls() {
        for url in [
            "",
            "example.com",
            "//example.com",
            "/local/path",
            "1http://example.com", // scheme 不能以数字开头
            "ht tp://example.com", // scheme 内含空格
            "ht+tp://example.com", // '+' 合法于 scheme，但不在白名单
            "http:",               // 冒号后为空
            "://example.com",      // scheme 为空
        ] {
            assert!(validate_external_url(url).is_err(), "非法 URL 必须拒绝：{url:?}");
        }
    }

    /// 反例：控制字符走私（含换行的 scheme 拼接攻击）必须拒绝
    #[test]
    fn rejects_control_character_smuggling() {
        for url in [
            "https://example.com\nX-Injected: 1",
            "java\0script:alert(1)",
            "https://example.com\rmalicious",
        ] {
            assert!(
                validate_external_url(url).is_err(),
                "含控制字符的 URL 必须拒绝：{url:?}"
            );
        }
    }

    /// 合法字符的 scheme 词法边界（首字符字母、其余可含数字与 + - .）确实走到白名单判定
    /// 而不是被词法检查误放行
    #[test]
    fn scheme_lexical_boundary_reaches_allowlist_check() {
        // 词法合法但不在白名单 → 报的是白名单错误（证明没被词法分支提前放过）
        let err = validate_external_url("a+1-b.c://x")
            .expect_err("应被白名单拒绝")
            .to_string();
        assert!(
            err.contains("allowlist"),
            "合法词法的未知 scheme 应命中白名单分支，got: {err}"
        );
    }
}
