//! WSL 文件系统桥接
//!
//! WSL2 发行版处于 Stopped 状态时，`\\wsl.localhost\<distro>\...` 与 `\\wsl$\<distro>\...`
//! UNC 路径在 Windows 侧不可访问（std::fs 返回 ERROR_FILE_NOT_FOUND）。
//!
//! 通过 `wsl.exe` 桥接读写可自动启动发行版（wsl.exe 会按需启动 Stopped 的发行版），
//! 保证任意状态下 WSL 文件可访问，同时支持 Windows 路径 ↔ WSL 路径的跨域复制
//! （hook 脚本安装场景：源为插件安装目录，目标为 WSL 项目 .claude/）。
//!
//! 所有 `wsl.exe` 子进程均带超时（`WSL_CMD_TIMEOUT`）：发行版冷启动或异常状态下
//! wsl.exe 可能长时间无响应，无超时的阻塞等待会悬挂调用方（如插件停用路径的
//! hooks 清理会逐项目 spawn wsl.exe）。超时后返回错误并终止子进程。

use crate::runtime_util::block_on_async;

/// wsl.exe 子进程超时：发行版冷启动（数秒）加桥接命令余量；超时即失败，避免调用方悬挂
const WSL_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// POSIX 单引号转义（H-02）：`wsl.exe` 会把 `--` 后的参数**重拼为单命令行**交给
/// 发行版默认 shell 执行——路径含空格 / `$()` / 反引号 / `;` / glob 会被二次解析
/// 成命令注入（`/home/user/$(cmd)` 会真的执行 cmd）。逐参数包单引号、内部 `'`
/// 转义为 `'\''` 后，参数作为单一字面量传给 shell，元字符不再被解释。
fn wsl_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// 构造 wsl.exe 命令（`-d <distro> -- <args>`；Windows 下隐藏窗口，与 create_command 一致）
///
/// `--` 后的全部参数经 [`wsl_quote`] 单引号转义——wsl.exe 侧 argv 数组原样
/// 送达，但发行版默认 shell 会重拼，所以必须在这里就交给它「已引号化」的参数。
fn wsl_command(distro: &str, args: &[&str]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("wsl.exe");
    cmd.arg("-d").arg(distro).arg("--");
    for arg in args {
        cmd.arg(wsl_quote(arg));
    }
    #[cfg(target_os = "windows")]
    {
        // CREATE_NO_WINDOW = 0x08000000（tokio::process::Command 固有方法）
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

/// 执行 wsl.exe 命令并等待完成；超时后终止子进程并返回错误（不悬挂调用方）
fn run_wsl_output(distro: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut cmd = wsl_command(distro, args);
    // stdin 置空：避免 wsl.exe 继承调用方 stdin 后在无输入时阻塞
    cmd.stdin(std::process::Stdio::null());
    let distro_owned = distro.to_string();
    block_on_async(async move {
        match tokio::time::timeout(WSL_CMD_TIMEOUT, cmd.output()).await {
            Ok(result) => result,
            // timeout 会 drop output() 未来，tokio 默认 KillOnDrop 终止子进程
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("wsl.exe timed out (distro={})", distro_owned),
            )),
        }
    })
}

/// 通过 wsl.exe 读取文件原始字节（等价于 std::fs::read）
pub fn read_bytes_via_wsl(distro: &str, wsl_path: &str) -> std::io::Result<Vec<u8>> {
    let output = run_wsl_output(distro, &["cat", wsl_path])?;

    if !output.status.success() {
        return Err(map_wsl_failure("wsl cat", distro, &output.stderr));
    }

    Ok(output.stdout)
}

/// 按 stderr 映射 wsl.exe 失败为可区分 io::Error（H-10）
///
/// 旧实现把所有失败都拍成 NotFound——权限拒绝 / 是目录 / 发行版错配也被调用方
/// 按「文件不存在 → 跳过或重建」处理，静默误判真实 I/O 错。按 stderr 关键字
/// 映射：文件缺席 → NotFound（既有语义不变），权限 → PermissionDenied，其余
/// → Other。
fn map_wsl_failure(action: &str, distro: &str, stderr: &[u8]) -> std::io::Error {
    let msg = String::from_utf8_lossy(stderr);
    let kind = if msg.contains("No such file") || msg.contains("cannot open") || msg.contains("not found") {
        std::io::ErrorKind::NotFound
    } else if msg.contains("Permission denied") {
        std::io::ErrorKind::PermissionDenied
    } else if msg.contains("Is a directory") {
        std::io::ErrorKind::IsADirectory
    } else {
        std::io::ErrorKind::Other
    };
    std::io::Error::new(kind, format!("{} failed (distro={}): {}", action, distro, msg.trim()))
}

/// 通过 wsl.exe 读取文本文件（等价于 std::fs::read_to_string）
pub fn read_to_string_via_wsl(distro: &str, wsl_path: &str) -> std::io::Result<String> {
    let bytes = read_bytes_via_wsl(distro, wsl_path)?;
    String::from_utf8(bytes).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("wsl cat output is not UTF-8 (distro={}): {}", distro, e),
        )
    })
}

/// 通过 wsl.exe 写入文件原始字节，自动创建父目录（等价于 std::fs::write + create_dir_all）
///
/// 使用 `mkdir -p` + `tee` 组合而非 shell 重定向：wsl.exe 对 `--` 后的参数会
/// 重新拼接，含引号/$ 的 shell 脚本会丢失语义，普通参数则原样传递。
pub fn write_bytes_via_wsl(distro: &str, wsl_path: &str, content: &[u8]) -> std::io::Result<()> {
    // 1. 创建父目录（Rust 侧计算 dirname，避免 shell 引号问题）
    if let Some(parent) = wsl_path.rsplit_once('/').map(|(d, _)| d) {
        if !parent.is_empty() {
            let mkdir = run_wsl_output(distro, &["mkdir", "-p", parent])?;
            if !mkdir.status.success() {
                let stderr = String::from_utf8_lossy(&mkdir.stderr);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("wsl mkdir failed (distro={}): {}", distro, stderr.trim()),
                ));
            }
        }
    }

    // 2. tee 从 stdin 写入目标文件（路径作为普通参数传递）
    let mut cmd = wsl_command(distro, &["tee", wsl_path]);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());

    let content_owned = content.to_vec();
    let distro_owned = distro.to_string();
    let wsl_path_owned = wsl_path.to_string();
    let result: std::io::Result<std::process::Output> = block_on_async(async move {
        let write_fut = async {
            let mut child = cmd.spawn()?;
            // 写入后显式 drop 关闭 stdin，让 tee 收到 EOF
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(&content_owned).await?;
                drop(stdin);
            }
            child.wait_with_output().await
        };
        match tokio::time::timeout(WSL_CMD_TIMEOUT, write_fut).await {
            Ok(result) => result,
            // 超时后 write_fut 被 drop，tokio 默认 KillOnDrop 终止子进程
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "wsl.exe write timed out (distro={}, path={})",
                    distro_owned, wsl_path_owned
                ),
            )),
        }
    });
    let output = result?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("wsl write failed (distro={}): {}", distro, stderr.trim()),
        ));
    }
    Ok(())
}

/// 通过 wsl.exe 删除文件（等价于 std::fs::remove_file，文件不存在视为成功）
pub fn delete_via_wsl(distro: &str, wsl_path: &str) -> std::io::Result<()> {
    // rm -f 对不存在的文件不报错，天然幂等
    let output = run_wsl_output(distro, &["rm", "-f", wsl_path])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("wsl rm failed (distro={}): {}", distro, stderr.trim()),
        ));
    }
    Ok(())
}

/// 通过 wsl.exe 检查文件是否存在（`test -e`）
///
/// `false` 只表示「明确不存在」；权限拒绝 / 其它非零退出按可区分错误传播
/// （H-11）——旧实现把「父目录无权限」也当「不存在」让调用方继续重建。
pub fn exists_via_wsl(distro: &str, wsl_path: &str) -> std::io::Result<bool> {
    let output = run_wsl_output(distro, &["test", "-e", wsl_path])?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such file") || stderr.contains("not found") {
        return Ok(false);
    }
    // 非「明确不存在」的失败（权限 / 发行版错配 / 其它）按错误传播，不做
    // 静默降级（fail-visible）
    Err(map_wsl_failure("wsl test", distro, &output.stderr))
}

/// 判断路径是否为 WSL UNC 路径（兼容 / 与 \ 分隔符混合）
pub fn is_wsl_unc_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\");
    normalized.starts_with("\\\\wsl.localhost\\") || normalized.starts_with("\\\\wsl$\\")
}

/// 从 WSL UNC 路径解析发行版名称与 WSL 内部路径
///
/// `\\wsl.localhost\Ubuntu\home\binblink\project\blink` → `("Ubuntu", "/home/binblink/project/blink")`
pub fn parse_wsl_unc_path(path: &str) -> Option<(String, String)> {
    let normalized = path.replace('/', "\\");
    let rest = if normalized.starts_with("\\\\wsl.localhost\\") {
        &normalized["\\\\wsl.localhost\\".len()..]
    } else if normalized.starts_with("\\\\wsl$\\") {
        &normalized["\\\\wsl$\\".len()..]
    } else {
        return None;
    };

    let (distro, inner) = rest.split_once('\\')?;
    if distro.is_empty() || inner.is_empty() {
        return None;
    }
    Some((distro.to_string(), format!("/{}", inner.replace('\\', "/"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wsl_unc_path() {
        assert!(is_wsl_unc_path("\\\\wsl.localhost\\Ubuntu\\home\\user"));
        assert!(is_wsl_unc_path("\\\\wsl$\\Ubuntu\\home\\user"));
        assert!(is_wsl_unc_path(
            "\\\\wsl.localhost\\Ubuntu\\home\\user/.claude/settings.json"
        ));
        assert!(!is_wsl_unc_path("C:\\Users\\test"));
        assert!(!is_wsl_unc_path("D:\\Projects\\my-app/.claude/settings.json"));
        assert!(!is_wsl_unc_path("/home/user"));
    }

    #[test]
    fn test_parse_wsl_unc_path() {
        // wsl.localhost 新格式
        let (distro, wsl_path) =
            parse_wsl_unc_path("\\\\wsl.localhost\\Ubuntu\\home\\binblink\\project\\blink").expect("parse failed");
        assert_eq!(distro, "Ubuntu");
        assert_eq!(wsl_path, "/home/binblink/project/blink");

        // 混合分隔符（Windows 前缀 + 正斜杠后续）
        let (distro, wsl_path) =
            parse_wsl_unc_path("\\\\wsl.localhost\\Ubuntu\\home\\binblink\\project\\blink/.claude/settings.json")
                .expect("parse failed");
        assert_eq!(distro, "Ubuntu");
        assert_eq!(wsl_path, "/home/binblink/project/blink/.claude/settings.json");

        // wsl$ 旧格式
        let (distro, wsl_path) = parse_wsl_unc_path("\\\\wsl$\\Ubuntu\\home\\user").expect("parse failed");
        assert_eq!(distro, "Ubuntu");
        assert_eq!(wsl_path, "/home/user");

        // 非 WSL 路径返回 None
        assert!(parse_wsl_unc_path("C:\\Users\\test").is_none());
        assert!(parse_wsl_unc_path("/home/user").is_none());
    }
}
