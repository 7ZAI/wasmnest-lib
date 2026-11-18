//! 私钥 / 身份文件的「只在不存在时发布」落盘原语（宿主无关）
//!
//! 一份身份密钥（peer-net `node_identity.json`、link-crypto
//! `link_crypto_identity.json`）在首启时必须同时满足两个约束：
//!
//! 1. **不覆盖既有文件**：两个并发首启各生成不同密钥时，后到者若覆盖盘、自己留在
//!    内存里，重启后指纹即变，对端 pin 与可信列表全部失效；
//! 2. **读者永远看不到半截内容**：进程在写入中途被杀，不能让下一次启动读到半截
//!    JSON 并把它当成「损坏」（那会把一次可恢复的失败升级成需要人工清理数据的
//!    故障）。
//!
//! ## 为什么发布步不是 `rename`
//!
//! `rename` 会无条件覆盖，违反约束 1（`wasmnest` 2026-11-09 的评审正是为此把
//! `rename` 换成 `hard_link`）。`hard_link` 在目标已存在时失败，天然是「只在不存在
//! 时可见」的原子发布，读者也只会看到完整的 tmp 内容。
//!
//! ## Android 上 `hard_link` 被 SELinux 拒绝
//!
//! `untrusted_app` 域**没有** `app_data_file:file link` 权限（Android M 起为防止
//! 应用借硬链接篡改自有数据文件而收紧），`hard_link(2)` 恒返回 `EACCES`：
//!
//! ```text
//! avc: denied { link } for name="node_identity.<pid>.<nanos>.tmp"
//!   scontext=u:r:untrusted_app:s0 tcontext=u:object_r:app_data_file:s0 tclass=file
//! ```
//!
//! 因此在 `hard_link` 被拒（EACCES/EPERM/ENOTSUP/ENOSYS/EMLINK/EXDEV）时回退到
//! 「`create_new` 直接占名 → 写入同一份内容」：`create_new` 仍是「已存在即失败」，
//! 所以约束 1 成立；代价是「占名」与「写完」不再是一步，故用进程内的发布互斥让
//! 并发首启的输家等赢家写完后才去加载（约束 2 在本进程内成立）。
//!
//! **契约边界**：跨进程并发首启不在本原语的承诺内（身份文件只由单个宿主进程写），
//! 且回退路径下进程若恰好被 SIGKILL 在写入中途，会留下截断文件——下一次启动按
//! 「损坏即报错」快速失败（[`crate::error`] 的上层语义），不会静默换身份。
//!
//! ## 用法
//!
//! ```ignore
//! match create_private_file_exclusive(&dir.join("node_identity.json"), json.as_bytes())? {
//!     CreateOutcome::Created => { /* 本次生成了身份，内存里的密钥即磁盘上的密钥 */ }
//!     CreateOutcome::AlreadyExisted => { /* 别人先建了身份，去加载既有文件 */ }
//! }
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 发布结果：调用方据此决定「用内存里刚生成的密钥」还是「加载既有文件」
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    /// 本次调用创建了文件，`contents` 已完整落盘
    Created,
    /// 目标已存在且**未被覆盖**，调用方应改为加载既有文件
    AlreadyExisted,
}

/// 进程内发布互斥
///
/// 只服务于 `hard_link` 回退路径：那条路径上「占名」与「写完」不是一步，输家若
/// 立刻读会看到半截内容。互斥使同进程的并发首启串行化（赢家写完并释放锁后，
/// 输家才会走到加载）。锁内没有可中毒的不变量，中毒也照常取用。
static PUBLISH_LOCK: Mutex<()> = Mutex::new(());

/// 把 `contents` 发布到 `path`（权限收紧为属主读写），目标已存在时绝不覆盖。
///
/// 语义与并发说明见模块文档。父目录必须已存在（本原语不创建目录：调用方持有目录
/// 语义，错误信息里的路径也才指向真实落点）。
pub fn create_private_file_exclusive(path: &Path, contents: &[u8]) -> io::Result<CreateOutcome> {
    let _guard = PUBLISH_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // 第一步：完整写入同目录唯一 tmp。内容先落盘，读者才不会看到半截文件。
    let tmp = unique_tmp_path(path);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| contextual(e, "create", &tmp))?;
    write_claimed(file, &tmp, contents)?;

    // 第二步：发布。「目标已存在」是正常结果而非错误；平台拒绝硬链接时回退。
    let published = match fs::hard_link(&tmp, path) {
        Ok(()) => Ok(CreateOutcome::Created),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(CreateOutcome::AlreadyExisted),
        Err(e) if is_link_refused(&e) => create_new_with_contents(path, contents),
        Err(e) => Err(contextual(e, "publish", path)),
    };

    // tmp 只是发布的中转，成功/失败都不该留在数据目录里
    let _ = fs::remove_file(&tmp);
    published
}

/// tmp 名：`<stem>.<pid>.<nanos>.tmp`（同目录 = 同一文件系统，硬链接不会跨设备）
fn unique_tmp_path(path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    path.with_extension(format!("{}.{nanos}.tmp", std::process::id()))
}

/// `hard_link` 的失败是否等同于「本平台不允许/不支持硬链接」（而非真故障）
///
/// EACCES/EPERM：SELinux（Android `untrusted_app`）/ 其他沙箱拒 `link`；
/// ENOTSUP/ENOSYS：文件系统或内核不支持；EMLINK/EXDEV：链接数上限 / 跨设备。
fn is_link_refused(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
    ) {
        return true;
    }
    // LINUX_EMLINK = 31 / LINUX_EXDEV = 18 在 std 上尚无稳定 ErrorKind
    #[cfg(unix)]
    {
        matches!(error.raw_os_error(), Some(18) | Some(31))
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// 回退发布：`create_new` 直接占名后写入同一份内容（`AlreadyExists` = 输家）
fn create_new_with_contents(path: &Path, contents: &[u8]) -> io::Result<CreateOutcome> {
    let file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(CreateOutcome::AlreadyExisted),
        Err(e) => return Err(contextual(e, "create", path)),
    };
    write_claimed(file, path, contents)?;
    Ok(CreateOutcome::Created)
}

/// 写入已占名的文件；失败时删掉占名文件（不让半截内容冒充身份文件）
fn write_claimed(mut file: File, path: &Path, contents: &[u8]) -> io::Result<()> {
    let result = write_and_restrict(&mut file, contents);
    drop(file);
    if let Err(e) = result {
        let _ = fs::remove_file(path);
        return Err(contextual(e, "write", path));
    }
    Ok(())
}

fn write_and_restrict(file: &mut File, contents: &[u8]) -> io::Result<()> {
    // unix 下收紧权限：私钥材料不应被同机其他用户读取（Windows ACL 由用户目录
    // 隔离兜底，无需等价处理）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    // sync 后才算「已落盘」：发布的是完整内容，不是页缓存里的半份
    file.sync_all()
}

/// 给底层 io 错误补上「哪一步、哪个路径」，调用方不必重复拼上下文
fn contextual(error: io::Error, action: &str, path: &Path) -> io::Error {
    io::Error::new(error.kind(), format!("{action} {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .expect("read dir")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn publishes_exact_contents_with_owner_only_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");

        let outcome = create_private_file_exclusive(&path, b"{\"v\":1}").expect("publish");
        assert_eq!(outcome, CreateOutcome::Created);
        assert_eq!(fs::read(&path).expect("read"), b"{\"v\":1}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "私钥文件必须 0600，实际 {mode:o}");
        }
        assert!(tmp_leftovers(dir.path()).is_empty(), "tmp 未清理");
    }

    #[test]
    fn existing_file_is_never_overwritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");

        assert_eq!(
            create_private_file_exclusive(&path, b"first").expect("first"),
            CreateOutcome::Created
        );
        assert_eq!(
            create_private_file_exclusive(&path, b"second").expect("second"),
            CreateOutcome::AlreadyExisted
        );
        assert_eq!(fs::read(&path).expect("read"), b"first", "既有身份不得被覆盖");
        assert!(tmp_leftovers(dir.path()).is_empty(), "tmp 未清理");
    }

    /// 并发首启：恰好一个赢家，所有调用方看到的内容一致且完整（不留半截文件）
    #[test]
    fn concurrent_publish_yields_one_writer_and_intact_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let contents = format!("{{\"writer\":{i}}}");
                    let outcome = create_private_file_exclusive(&path, contents.as_bytes()).expect("publish");
                    (outcome, fs::read(&path).expect("read"))
                })
            })
            .collect();

        let results: Vec<(CreateOutcome, Vec<u8>)> =
            handles.into_iter().map(|handle| handle.join().expect("join")).collect();

        let winners = results.iter().filter(|(o, _)| *o == CreateOutcome::Created).count();
        assert_eq!(winners, 1, "并发首启只能有一个赢家: {results:?}");
        let first = &results[0].1;
        assert!(
            results.iter().all(|(_, contents)| contents == first),
            "并发调用看到了不同内容"
        );
        // 内容必须完整：一定是某个写者的完整 JSON，而不是两个写者的拼接
        let text = String::from_utf8(first.clone()).expect("utf8");
        assert!(
            text.starts_with("{\"writer\":") && text.ends_with('}') && text.len() == "{\"writer\":0}".len(),
            "落盘内容被截断或拼接: {text:?}"
        );
        assert!(tmp_leftovers(dir.path()).is_empty(), "tmp 未清理");
    }

    /// Android 回退路径（`hard_link` 被拒时走的那条）：同样是「只在不存在时写入」
    #[test]
    fn create_new_fallback_claims_only_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");

        assert_eq!(
            create_new_with_contents(&path, b"winner").expect("first"),
            CreateOutcome::Created
        );
        assert_eq!(
            create_new_with_contents(&path, b"loser").expect("second"),
            CreateOutcome::AlreadyExisted
        );
        assert_eq!(fs::read(&path).expect("read"), b"winner");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn missing_parent_directory_is_an_error_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nope").join("identity.json");

        let err = create_private_file_exclusive(&path, b"x").expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("create"), "错误应点名失败步骤: {err}");
        assert!(tmp_leftovers(dir.path()).is_empty());
    }
}
