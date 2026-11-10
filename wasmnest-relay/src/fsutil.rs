//! 落盘小工具：目录创建、原子写、带模式的写。
//!
//! 身份密钥与 token 摘要都在这里落盘，因此写操作一律**原子**（临时文件 →
//! `rename`）：写一半掉电会留下不可解析的密钥文件，而密钥文件损坏 = PeerId 丢失
//! = 所有客户端需重新导入。临时文件与目标同目录，保证 `rename` 不跨文件系统。

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::error::{RelayError, Result};

/// 身份密钥与 token 文件的默认权限（仅属主可读写）
pub const SECRET_FILE_MODE: u32 = 0o600;
/// 配置目录的默认权限（仅属主可进入）
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// 创建目录（已存在不报错），并尽力收紧权限到 `0700`
pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| RelayError::file(path, e))?;
    set_dir_mode(path)?;
    Ok(())
}

/// 原子写文件（临时文件 → `rename`），并把权限设为 `mode`（unix）
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(dir)?;
    let tmp = temp_path(path);
    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options.open(&tmp).map_err(|e| RelayError::file(&tmp, e))?;
        file.write_all(bytes)
            .map_err(|e| RelayError::file(&tmp, e))?;
        // 落盘后再 rename：保证 rename 成功后内容已完成（否则掉电可能留下空文件）
        file.sync_all().map_err(|e| RelayError::file(&tmp, e))?;
    }
    #[cfg(unix)]
    set_file_mode(&tmp, mode)?;
    fs::rename(&tmp, path).map_err(|e| {
        // rename 失败时清掉临时文件，避免目录里堆积半成品
        let _ = fs::remove_file(&tmp);
        RelayError::file(path, e)
    })
}

/// 读文本文件
pub fn read_to_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| RelayError::file(path, e))
}

/// 读二进制文件
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| RelayError::file(path, e))
}

/// 文件是否存在
pub fn exists(path: &Path) -> bool {
    path.exists()
}

/// 数据目录可写探针：创建再删除一个临时文件
///
/// 用真实写入判断而不是只看权限位：容器里挂载的只读卷、磁盘满、SELinux 标签
/// 不匹配都表现为「权限位看着对，写却失败」。
pub fn writable_probe(dir: &Path) -> io::Result<()> {
    ensure_dir(dir).map_err(|e| match e {
        RelayError::File { source, .. } => source,
        other => io::Error::other(other.to_string()),
    })?;
    let probe = temp_path(&dir.join(".write-probe"));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        file.write_all(b"wasmnest-relay-probe")?;
    }
    fs::remove_file(&probe)
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}.tmp.{}", std::process::id()))
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| RelayError::file(path, e))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // 只在「新建后仍是默认 0o755」时收紧；用户刻意放宽的目录（如共享卷）不强行改回
    let meta = fs::metadata(path).map_err(|e| RelayError::file(path, e))?;
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
            .map_err(|e| RelayError::file(path, e))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 原子写覆盖既有文件且不留临时文件() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("config.toml");
        write_atomic(&path, b"first", SECRET_FILE_MODE).expect("首次写");
        write_atomic(&path, b"second", SECRET_FILE_MODE).expect("覆盖写");

        assert_eq!(read_to_string(&path).expect("读取"), "second");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("列目录")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "不应残留临时文件：{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn 密钥文件权限为仅属主可读写() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("identity.key");
        write_atomic(&path, b"secret", SECRET_FILE_MODE).expect("写密钥");
        let mode = fs::metadata(&path).expect("元数据").permissions().mode() & 0o777;
        assert_eq!(mode, SECRET_FILE_MODE, "密钥文件权限应为 0600");
    }

    #[test]
    fn 可写探针不留下文件() {
        let dir = tempfile::tempdir().expect("临时目录");
        let nested = dir.path().join("nested/data");
        writable_probe(&nested).expect("可写");
        assert!(nested.exists());
        assert_eq!(
            fs::read_dir(&nested).expect("列目录").count(),
            0,
            "探针文件应已删除"
        );
    }

    #[test]
    fn 读缺失文件报错并点名路径() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("missing.toml");
        let err = read_to_string(&path).expect_err("应报错");
        assert!(err.to_string().contains("missing.toml"), "{err}");
    }
}
