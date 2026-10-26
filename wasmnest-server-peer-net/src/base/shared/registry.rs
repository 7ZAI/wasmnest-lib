//! 共享目录注册表：两端对称的「本机暴露面」登记与持久化（issue 07）。
//!
//! ## 形状（spec Decision 8）
//!
//! 条目只有两种根形态，与平台解耦：
//! - [`SharedDirRoot::Fs`]：真实文件系统目录——桌面端用户选择的文件夹、移动端
//!   app 私有下载目录（宿主平台缝注入的普通条目）都落在此形态；
//! - [`SharedDirRoot::Saf`]：Android SAF 树 URI（content://tree/...）——系统
//!   目录选择器产出、经 takePersistableUriPermission 持久授权，URI 本身即重启
//!   后仍有效的凭据；crate 不感知 ContentResolver，读取经宿主注入的
//!   [`crate::base::shared::SharedSafAccess`] 缝完成。
//!
//! ## 持久化模式完全照抄 trust_store.rs
//!
//! 同一威胁模型：进程中途被杀不得产生半截 JSON，同目录临时文件 + rename 原子
//! 落盘；文件损坏快速失败而非静默重建（静默清空等于「重启后暴露面消失」，对
//! 已依赖该暴露面的可信对端是语义回退）。
//!
//! 并发形态与 TrustStore 一致：同步 `RwLock` + 小集合 + 单个小文件落盘，
//! 实例经调用方 `Arc` 共享；禁止 unsafe impl Send/Sync。

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::base::error::{PeerNetError, Result};
use crate::base::transfer::batch::DirEntry;

/// 注册表文件名（位于宿主注入的数据目录下）
const SHARED_DIRS_FILE: &str = "shared_dirs.json";

/// 文件格式版本：演进只允许追加字段，加载端拒绝更大版本
const SHARED_DIRS_FORMAT_VERSION: u32 = 1;

// ==================== 数据模型 ====================

/// 共享目录根形态（wire internally tagged，`type` 字段即线上契约）
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SharedDirRoot {
    /// 真实文件系统目录
    Fs {
        /// 目录绝对路径
        path: PathBuf,
    },
    /// Android SAF 目录树（持久化授权 URI）
    Saf {
        /// 树 URI（content://tree/...）
        tree_uri: String,
    },
}

/// 一个共享目录条目：稳定 ID + 展示名 + 根形态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedDirEntry {
    /// 条目 ID（注册表生成，浏览/拉取请求按此寻址）
    pub id: String,
    /// 展示名（别名或末段目录名）
    pub name: String,
    /// 根形态
    pub root: SharedDirRoot,
}

/// 注册表文件的磁盘表示
#[derive(Debug, Serialize, Deserialize)]
struct SharedDirsFile {
    version: u32,
    dirs: Vec<SharedDirEntry>,
}

// ==================== 纯函数 ====================

/// 纯函数：把浏览相对路径清洗为分量列表（共享目录只读暴露面的路径安全根基）
///
/// 拒绝绝对路径形状（前导 `/`）、Windows 形状（反斜杠/盘符冒号）、`..` 上溯；
/// 空/`.` 分量跳过；空串 = 目录根本身。返回 `None` 即请求非法（服务端一律回
/// not-found，不区分「不存在」与「越界」，不向对端泄露结构信息）。
pub fn resolve_rel_path(rel: &str) -> Option<Vec<String>> {
    if rel.starts_with('/') || rel.contains('\\') || rel.contains(':') {
        return None;
    }
    let mut out = Vec::new();
    for component in rel.split('/') {
        match component {
            "" | "." => continue,
            ".." => return None,
            c => out.push(c.to_string()),
        }
    }
    Some(out)
}

/// 纯函数：列目录结果排序——目录优先、各自按名排序（大小写不敏感，稳定序）
///
/// 排序在服务端完成后上线（BrowseResponse 契约的一部分），客户端不再排：
/// 保证任意实现的两端展示顺序一致。
pub fn sort_entries(entries: &[DirEntry]) -> Vec<DirEntry> {
    let mut out = entries.to_vec();
    out.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

// ==================== 注册表 ====================

/// 本机共享目录注册表：内存集合 + 原子持久化文件的双写视图
#[derive(Debug)]
pub struct SharedDirStore {
    /// 持久化文件完整路径；内存态实例为 None（无落盘）
    path: Option<PathBuf>,
    /// 用户注册条目（插入序）
    dirs: RwLock<Vec<SharedDirEntry>>,
}

impl SharedDirStore {
    /// 加载或创建注册表——crate 管完整 load/create，宿主只注入目录
    ///
    /// 文件损坏快速失败不静默重建（理由见模块文档）。
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| PeerNetError::CreateDir {
            path: dir.to_path_buf(),
            source: e,
        })?;

        let path = dir.join(SHARED_DIRS_FILE);
        let dirs = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            // 首启显式落一个空表：让「存储已初始化」在磁盘上可见
            let store = Self {
                path: Some(path.clone()),
                dirs: RwLock::new(Vec::new()),
            };
            store.write_atomic(&SharedDirsFile {
                version: SHARED_DIRS_FORMAT_VERSION,
                dirs: Vec::new(),
            })?;
            tracing::debug!("created new shared dirs file at {}", path.display());
            return Ok(store);
        };

        Ok(Self {
            path: Some(path),
            dirs: RwLock::new(dirs),
        })
    }

    /// 内存态空表（测试用；无落盘）
    pub fn in_memory() -> Self {
        Self {
            path: None,
            dirs: RwLock::new(Vec::new()),
        }
    }

    /// 全部条目（按插入序）
    pub fn list(&self) -> Vec<SharedDirEntry> {
        self.dirs.read().expect("dirs lock poisoned").iter().cloned().collect()
    }

    /// 按 ID 取条目
    pub fn get(&self, id: &str) -> Option<SharedDirEntry> {
        self.dirs
            .read()
            .expect("dirs lock poisoned")
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    /// 新增用户条目并原子落盘
    ///
    /// 校验：名称非空限长；Fs 根必须存在且为目录；同根去重。
    /// 返回新条目（ID 由注册表分配）。
    pub fn add(&self, name: impl Into<String>, root: SharedDirRoot) -> Result<SharedDirEntry> {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 200 {
            return Err(PeerNetError::TransferSession {
                role: "registry",
                detail: format!("shared dir name must be 1..=200 bytes, got {}", trimmed.len()),
            });
        }

        match &root {
            SharedDirRoot::Fs { path } => {
                let meta = std::fs::metadata(path).map_err(|e| PeerNetError::TransferSession {
                    role: "registry",
                    detail: format!("shared dir root '{}' inaccessible: {e}", path.display()),
                })?;
                if !meta.is_dir() {
                    return Err(PeerNetError::TransferSession {
                        role: "registry",
                        detail: format!("shared dir root '{}' is not a directory", path.display()),
                    });
                }
            }
            SharedDirRoot::Saf { tree_uri } => {
                // 最小形状校验：SAF 树 URI 的权威判定（ContentResolver 可达性）
                // 属宿主适配层，这里只挡明显非 URI 的输入
                if !tree_uri.starts_with("content://") {
                    return Err(PeerNetError::TransferSession {
                        role: "registry",
                        detail: format!("shared dir saf root is not a content uri: {tree_uri}"),
                    });
                }
            }
        }

        let mut dirs = self.dirs.write().expect("dirs lock poisoned");
        if dirs.iter().any(|e| e.root == root) {
            return Err(PeerNetError::TransferSession {
                role: "registry",
                detail: "shared dir root already registered".to_string(),
            });
        }

        let entry = SharedDirEntry {
            id: generate_entry_id(trimmed, &root),
            name: trimmed.to_string(),
            root,
        };
        dirs.push(entry.clone());

        if let Err(e) = self.persist_locked(&dirs) {
            dirs.pop();
            return Err(e);
        }
        tracing::info!(dir_id = %entry.id, name = %entry.name, "shared dir added");
        Ok(entry)
    }

    /// 全量幂等替换用户条目（ADR 0022 v2：host-peer `set-shared-roots` 原语）
    ///
    /// 注册表 CRUD 真源在插件侧（host-plugin-database），引擎侧注册表退化为
    /// 广播/浏览服务面的镜像：插件每次变更后推送全量列表，本方法整体替换
    /// 用户条目并原子落盘。
    ///
    /// 校验与 [`Self::add`] 同尺逐条施加（名称限长、Fs 根存在且为目录、SAF
    /// URI 形状、同根去重），另加：ID 非空、ID 与根全表唯一。任一条目非法即整批拒绝（全量语义下部分成功无意义），原有
    /// 条目保持不变；落盘失败同样回滚内存态。
    pub fn replace_all(&self, entries: &[SharedDirEntry]) -> Result<()> {
        let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut seen_roots: std::collections::HashSet<&SharedDirRoot> = std::collections::HashSet::new();
        for entry in entries {
            let trimmed = entry.name.trim();
            if trimmed.is_empty() || trimmed.len() > 200 {
                return Err(PeerNetError::TransferSession {
                    role: "registry",
                    detail: format!(
                        "shared dir name must be 1..=200 bytes, got {} (id {})",
                        trimmed.len(),
                        entry.id
                    ),
                });
            }
            if entry.id.trim().is_empty() {
                return Err(PeerNetError::TransferSession {
                    role: "registry",
                    detail: format!("shared dir id '{}' is reserved or empty", entry.id),
                });
            }
            match &entry.root {
                SharedDirRoot::Fs { path } => {
                    let meta = std::fs::metadata(path).map_err(|e| PeerNetError::TransferSession {
                        role: "registry",
                        detail: format!("shared dir root '{}' inaccessible: {e}", path.display()),
                    })?;
                    if !meta.is_dir() {
                        return Err(PeerNetError::TransferSession {
                            role: "registry",
                            detail: format!("shared dir root '{}' is not a directory", path.display()),
                        });
                    }
                }
                SharedDirRoot::Saf { tree_uri } => {
                    if !tree_uri.starts_with("content://") {
                        return Err(PeerNetError::TransferSession {
                            role: "registry",
                            detail: format!("shared dir saf root is not a content uri: {tree_uri}"),
                        });
                    }
                }
            }
            if !seen_ids.insert(entry.id.as_str()) {
                return Err(PeerNetError::TransferSession {
                    role: "registry",
                    detail: format!("shared dir id duplicated in batch: {}", entry.id),
                });
            }
            if !seen_roots.insert(&entry.root) {
                return Err(PeerNetError::TransferSession {
                    role: "registry",
                    detail: "shared dir root duplicated in batch".to_string(),
                });
            }
        }

        // 规范化名称（trim 后回写）再整体换入；持久化失败回滚旧表
        let normalized: Vec<SharedDirEntry> = entries
            .iter()
            .map(|e| SharedDirEntry {
                name: e.name.trim().to_string(),
                ..e.clone()
            })
            .collect();
        let mut dirs = self.dirs.write().expect("dirs lock poisoned");
        let previous = std::mem::replace(&mut *dirs, normalized);
        if let Err(e) = self.persist_locked(&dirs) {
            *dirs = previous;
            return Err(e);
        }
        tracing::info!(count = entries.len(), "shared roots replaced wholesale");
        Ok(())
    }

    /// 移除用户条目并原子落盘；返回该 ID 原本是否存在
    ///
    pub fn remove(&self, id: &str) -> Result<bool> {
        let mut dirs = self.dirs.write().expect("dirs lock poisoned");
        let Some(pos) = dirs.iter().position(|e| e.id == id) else {
            return Ok(false);
        };
        let removed = dirs.remove(pos);
        if let Err(e) = self.persist_locked(&dirs) {
            dirs.insert(pos, removed);
            return Err(e);
        }
        tracing::info!(dir_id = %id, "shared dir removed");
        Ok(true)
    }

    // ---- 持久化内部 ----

    fn load_from_file(path: &Path) -> Result<Vec<SharedDirEntry>> {
        let raw = std::fs::read_to_string(path).map_err(|source| PeerNetError::SharedDirsRead {
            path: path.to_path_buf(),
            source,
        })?;
        let value: serde_json::Value = serde_json::from_str(&raw).map_err(|source| PeerNetError::SharedDirsParse {
            path: path.to_path_buf(),
            source,
        })?;
        let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if version > SHARED_DIRS_FORMAT_VERSION as u64 {
            // 更新格式：终局拒绝（静默降级读会丢字段，语义回退不可接受）
            return Err(PeerNetError::TransferSession {
                role: "registry",
                detail: format!(
                    "shared dirs file format v{version} is newer than supported v{SHARED_DIRS_FORMAT_VERSION}"
                ),
            });
        }
        let file: SharedDirsFile = serde_json::from_value(value).map_err(|source| PeerNetError::SharedDirsParse {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(file.dirs)
    }

    fn persist_locked(&self, dirs: &[SharedDirEntry]) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(()); // 内存态实例无落盘
        };
        self.write_atomic(&SharedDirsFile {
            version: SHARED_DIRS_FORMAT_VERSION,
            dirs: dirs.to_vec(),
        })
        .map_err(|e| {
            tracing::error!(path = %path.display(), "persist shared dirs failed: {e}");
            e
        })
    }

    /// 原子写：同目录临时文件 + rename（trust_store 同款两步）
    fn write_atomic(&self, file: &SharedDirsFile) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let payload = serde_json::to_vec_pretty(file).map_err(|source| PeerNetError::SharedDirsSerialize { source })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, payload).map_err(|source| PeerNetError::SharedDirsWriteTemp {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| PeerNetError::SharedDirsRename {
            from: tmp,
            to: path.clone(),
            source,
        })?;
        Ok(())
    }
}

/// 生成条目 ID：SHA-256(名称 + 根形态规范串 + 纳秒时钟) 前 16 hex
///
/// crate 无 uuid 依赖；sha2/hex 已在依赖树中（identity 同源）。纳秒时钟保证
/// 同名同根的「删除后重加」也得到不同 ID（旧浏览会话不会误命中新条目）。
/// 条目 id = SHA256(name ‖ 0 ‖ root) 前 8 字节（确定性——同 name/root 必同 id）。
///
/// 2026-10-22 peer-net-dissolve：原实现混入时间戳 nanos，导致「平台默认目录被
/// 插件全量推送清掉后重注册」得到**新 id**，对端缓存的 dir_id 失效（浏览 404）。
/// 注册表已对同 root 去重，条目集合极小（个位数），去掉随机分量后 id 稳定幂等、
/// 无实际碰撞窗口；remove 后重 add 同 root 也得到原 id（对端缓存继续有效）。
fn generate_entry_id(name: &str, root: &SharedDirRoot) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0]);
    match root {
        SharedDirRoot::Fs { path } => hasher.update(path.to_string_lossy().as_bytes()),
        SharedDirRoot::Saf { tree_uri } => hasher.update(tree_uri.as_bytes()),
    }
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_path_resolution_rejects_escape_shapes() {
        assert_eq!(resolve_rel_path(""), Some(vec![]));
        assert_eq!(resolve_rel_path("a/b.txt"), Some(vec!["a".into(), "b.txt".into()]));
        assert_eq!(resolve_rel_path("./a//b"), Some(vec!["a".into(), "b".into()]));
        assert_eq!(resolve_rel_path("/abs"), None);
        assert_eq!(resolve_rel_path("a/../b"), None);
        assert_eq!(resolve_rel_path(".."), None);
        assert_eq!(resolve_rel_path(r"a\b"), None);
        assert_eq!(resolve_rel_path("C:/x"), None);
    }

    #[test]
    fn entries_sort_dirs_first_then_by_name_case_insensitive() {
        let entries = vec![
            DirEntry::new("zeta.txt", false, 1),
            DirEntry::new("Beta", true, 0),
            DirEntry::new("apple.TXT", false, 2),
            DirEntry::new("alpha", true, 0),
        ];
        let sorted = sort_entries(&entries);
        let names: Vec<&str> = sorted.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "Beta", "apple.TXT", "zeta.txt"]);
    }

    #[test]
    fn store_roundtrips_through_disk_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SharedDirStore::load_or_create(dir.path()).expect("create store");
        let entry = store
            .add(
                "Movies",
                SharedDirRoot::Fs {
                    path: dir.path().to_path_buf(),
                },
            )
            .expect("add fs dir");
        assert!(!entry.id.is_empty());

        // 重载：磁盘条目仍在
        let reloaded = SharedDirStore::load_or_create(dir.path()).expect("reload store");
        assert_eq!(reloaded.list().len(), 1);
        assert_eq!(reloaded.get(&entry.id).expect("entry survives reload"), entry);

        // 移除后重载不含
        assert!(reloaded.remove(&entry.id).expect("remove"));
        let after = SharedDirStore::load_or_create(dir.path()).expect("reload after remove");
        assert!(after.get(&entry.id).is_none());
    }

    #[test]
    fn add_validates_name_root_and_dedupes_roots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SharedDirStore::in_memory();

        // 空名拒绝
        assert!(store
            .add(
                "  ",
                SharedDirRoot::Fs {
                    path: dir.path().to_path_buf()
                }
            )
            .is_err());

        // 不存在的路径拒绝
        assert!(store
            .add(
                "ghost",
                SharedDirRoot::Fs {
                    path: dir.path().join("nope")
                }
            )
            .is_err());

        // 非 content:// 的 SAF 根拒绝
        assert!(store
            .add(
                "bad-saf",
                SharedDirRoot::Saf {
                    tree_uri: "/storage/emulated/0".into()
                }
            )
            .is_err());

        // 合法新增 + 同根去重
        store
            .add(
                "docs",
                SharedDirRoot::Fs {
                    path: dir.path().to_path_buf(),
                },
            )
            .expect("first add");
        assert!(store
            .add(
                "docs-again",
                SharedDirRoot::Fs {
                    path: dir.path().to_path_buf()
                }
            )
            .is_err());
    }

    fn fs_entry(id: &str, name: &str, path: &Path) -> SharedDirEntry {
        SharedDirEntry {
            id: id.to_string(),
            name: name.to_string(),
            root: SharedDirRoot::Fs {
                path: path.to_path_buf(),
            },
        }
    }

    #[test]
    fn replace_all_swaps_wholesale_and_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SharedDirStore::load_or_create(dir.path()).expect("create store");
        let old = store
            .add(
                "old",
                SharedDirRoot::Fs {
                    path: dir.path().to_path_buf(),
                },
            )
            .expect("seed old entry");

        // 全量替换：旧条目消失，新条目（插件持有 ID）生效
        let seeds = vec![fs_entry("plugin-dir-1", "Docs", dir.path())];
        store.replace_all(&seeds).expect("replace");
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert!(store.get(&old.id).is_none());
        assert_eq!(store.get("plugin-dir-1").expect("new entry"), seeds[0]);

        // 空表替换 = 清空用户面（幂等）；重载后磁盘态一致
        store.replace_all(&[]).expect("clear via replace");
        let reloaded = SharedDirStore::load_or_create(dir.path()).expect("reload");
        assert!(reloaded.list().is_empty());
        assert!(reloaded.get("plugin-dir-1").is_none());
    }

    #[test]
    fn replace_all_rejects_invalid_batch_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SharedDirStore::in_memory();
        let good = fs_entry("a1", "A", dir.path());
        store.replace_all(std::slice::from_ref(&good)).expect("seed");

        // 幽灵路径拒绝
        let ghost = vec![
            fs_entry("ok", "Ok", dir.path()),
            fs_entry("g", "G", &dir.path().join("nope")),
        ];
        assert!(store.replace_all(&ghost).is_err());
        // 同批 ID / 根重复拒绝
        let dup_id = vec![good.clone(), fs_entry("a1", "B", dir.path())];
        assert!(store.replace_all(&dup_id).is_err());
        // 空名拒绝（trim 后）
        let blank = vec![fs_entry("b1", "   ", dir.path())];
        assert!(store.replace_all(&blank).is_err());

        // 整批原子性：任一非法 → 原有条目原封不动
        assert_eq!(store.get("a1"), Some(good));
    }
}
