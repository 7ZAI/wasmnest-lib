//! 发送源收集（纯文件系统事实，传输编排下沉票 3 从 `peer_engine_transfer`
//! 剥离）：目录递归展开 + 批内同名去重。只读元数据不读内容，零业务语义——
//! 服务面两个消费方：`send-files` 原语的内部收集与 `collect-outgoing` 原语
//! 的显式枚举。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use wasmnest_server_base::error::{AppError, Result};

use wasmnest_peer_net::OutgoingFile;

/// 单批文件数上限：目录递归收集的失控保护
pub(crate) const MAX_FILES_PER_BATCH: usize = 512;

/// 收集结果：待发文件清单 + 各文件大小 + 总字节数
pub(crate) struct CollectedSources {
    pub sources: Vec<OutgoingFile>,
    pub sizes: Vec<u64>,
    pub total_bytes: u64,
}

impl CollectedSources {
    /// 批内文件 DTO（remote 相对落位形状 + 字节数；引擎事件与首屏快照同形状）
    pub(crate) fn files_json(&self) -> Vec<serde_json::Value> {
        self.sources
            .iter()
            .zip(self.sizes.iter())
            .map(|(f, size)| serde_json::json!({ "path": f.remote_path, "size": size }))
            .collect()
    }
}

/// 从用户选择路径构建待发清单：文件取名直推，目录递归展开保持相对形状
///
/// 同名 remote 目标以「名称 (2).ext」样式编号去重，避免接收端落位互踩；
/// 数量超上限或选不出任何可发文件均显式报错。
pub(crate) fn collect_outgoing_files(paths: &[String]) -> Result<CollectedSources> {
    let mut sources: Vec<OutgoingFile> = Vec::new();
    let mut sizes: Vec<u64> = Vec::new();
    let mut used: HashSet<String> = HashSet::new();

    for raw in paths {
        let path = PathBuf::from(raw.trim());
        let meta = std::fs::metadata(&path)
            .map_err(|e| AppError::InvalidInput(format!("send source '{}' unreadable: {e}", path.display())))?;
        if meta.is_dir() {
            let root_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string_lossy().into_owned());
            walk_directory(&path, &root_name, &mut sources, &mut sizes, &mut used)?;
        } else if meta.is_file() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            push_outgoing(
                path,
                unique_remote_path(name, &mut used),
                meta.len(),
                &mut sources,
                &mut sizes,
            );
        }
    }

    if sources.is_empty() {
        return Err(AppError::InvalidInput(
            "no sendable files found in selection".to_string(),
        ));
    }
    if sources.len() > MAX_FILES_PER_BATCH {
        return Err(AppError::InvalidInput(format!(
            "selection exceeds per-batch limit of {MAX_FILES_PER_BATCH} files"
        )));
    }
    let total_bytes = sizes.iter().sum();
    Ok(CollectedSources {
        sources,
        sizes,
        total_bytes,
    })
}

/// 递归展开目录（排序保证确定性；空目录跳过，非普通文件忽略）
fn walk_directory(
    dir: &Path,
    display_prefix: &str,
    sources: &mut Vec<OutgoingFile>,
    sizes: &mut Vec<u64>,
    used: &mut HashSet<String>,
) -> Result<()> {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)
        .map_err(|e| AppError::InvalidInput(format!("read directory '{}' failed: {e}", dir.display())))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        if sources.len() >= MAX_FILES_PER_BATCH {
            return Ok(());
        }
        let path = entry.path();
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_display = format!("{display_prefix}/{name}");
        if meta.is_dir() {
            walk_directory(&path, &child_display, sources, sizes, used)?;
        } else if meta.is_file() {
            push_outgoing(
                path,
                unique_remote_path(child_display, used),
                meta.len(),
                sources,
                sizes,
            );
        }
    }
    Ok(())
}

fn push_outgoing(
    source: PathBuf,
    remote_path: String,
    size: u64,
    sources: &mut Vec<OutgoingFile>,
    sizes: &mut Vec<u64>,
) {
    sources.push(OutgoingFile { source, remote_path });
    sizes.push(size);
}

/// 同名目标去重：首次原样保留，后续碰撞追加序号（保留扩展名）
fn unique_remote_path(requested: String, used: &mut HashSet<String>) -> String {
    if used.insert(requested.clone()) {
        return requested;
    }
    let (stem, ext) = match requested.rsplit_once('.') {
        // 点号出现在末段且两侧非空才视为扩展名分隔（路径分隔/隐藏文件不误判）
        Some((s, e)) if !s.is_empty() && !e.is_empty() && !e.contains('/') => (s.to_string(), e.to_string()),
        _ => (requested.clone(), String::new()),
    };
    for seq in 2..u32::MAX {
        let candidate = if ext.is_empty() {
            format!("{stem} ({seq})")
        } else {
            format!("{stem} ({seq}).{ext}")
        };
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("sequence space exhausted")
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_remote_path_keeps_first_and_numbers_collisions() {
        let mut used = HashSet::new();
        assert_eq!(unique_remote_path("a.txt".into(), &mut used), "a.txt");
        assert_eq!(unique_remote_path("a.txt".into(), &mut used), "a (2).txt");
        assert_eq!(unique_remote_path("a.txt".into(), &mut used), "a (3).txt");
        // 无扩展名与多点路径同样稳定
        assert_eq!(unique_remote_path("Makefile".into(), &mut used), "Makefile");
        assert_eq!(unique_remote_path("Makefile".into(), &mut used), "Makefile (2)");
        assert_eq!(
            unique_remote_path("docs/my.photo.png".into(), &mut used),
            "docs/my.photo.png"
        );
        assert_eq!(
            unique_remote_path("docs/my.photo.png".into(), &mut used),
            "docs/my.photo (2).png"
        );
    }

    #[test]
    fn collect_expands_directories_and_dedupes_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(folder.join("sub")).expect("mkdir");
        std::fs::write(folder.join("a.png"), vec![0u8; 10]).expect("write a");
        std::fs::write(folder.join("sub").join("b.png"), vec![0u8; 5]).expect("write b");
        let loose = dir.path().join("notes.txt");
        std::fs::write(&loose, vec![0u8; 3]).expect("write notes");

        let collected = collect_outgoing_files(&[
            folder.to_string_lossy().into_owned(),
            loose.to_string_lossy().into_owned(),
        ])
        .expect("collect");

        assert_eq!(collected.total_bytes, 18);
        assert_eq!(
            collected.files_json(),
            vec![
                serde_json::json!({"path": "photos/a.png", "size": 10}),
                serde_json::json!({"path": "photos/sub/b.png", "size": 5}),
                serde_json::json!({"path": "notes.txt", "size": 3}),
            ]
        );

        // 同名文件（不同目录来源）remote 目标自动编号
        let other = dir.path().join("elsewhere");
        std::fs::create_dir_all(&other).expect("mkdir elsewhere");
        std::fs::write(other.join("notes.txt"), vec![0u8; 1]).expect("write dup");
        let deduped = collect_outgoing_files(&[
            loose.to_string_lossy().into_owned(),
            other.join("notes.txt").to_string_lossy().into_owned(),
        ])
        .expect("collect dup")
        .files_json();
        assert_eq!(deduped[0]["path"], "notes.txt");
        assert_eq!(deduped[1]["path"], "notes (2).txt");
    }

    #[test]
    fn collect_rejects_empty_selection_and_missing_paths() {
        assert!(collect_outgoing_files(&[]).is_err());
        assert!(collect_outgoing_files(&["missing.bin".to_string()]).is_err());
    }
}
