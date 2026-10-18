//! 可信节点列表持久化：AC#4（撤销后重走确认）与 AC#5（撤销 API + 落库持久）的载体。
//!
//! ## 为什么完全照抄 identity.rs 的持久化模式
//!
//! 同一威胁模型：进程中途被杀不得产生半截 JSON（半截文件会永久锁死加载），
//! 故同目录临时文件 + rename 原子落盘；文件损坏快速失败而非静默重建——静默
//! 重建等于「重启即清空信任」，攻击者损坏该文件即可强制所有对端重走确认弹窗，
//! 属安全语义回退，宁可启动失败让人工介入。
//!
//! 并发形态：accept 循环的多个连接任务并发查询 [`contains`]，宿主/拨号侧经
//! [`add`] / [`remove`] 写入——内部 `RwLock<BTreeMap>` 支撑读多写少；临界区
//! 只含内存集合操作与单个小文件落盘（< 数 KB），用同步锁避免 tokio 异步锁的
//! 持有跨 await 复杂度。实例本身经调用方 `Arc` 共享，内部不再嵌套 Arc。
//!
//! ## 展示元数据（ticket 04）
//!
//! 设置面的可信对端列表需要「设备名 / 加入时间」，故 v2 格式在节点 ID 之外
//! 持久化可选展示名与加入时刻。transport 的 `add` 热路径不感知名称（握手层
//! 只有 ID），名称由宿主在确认放行前经 [`TrustStore::add_with_metadata`] 预写
//! ——先落库再回执，保证「连接建立时条目已带元数据」。v1 旧文件（纯 ID 列表）
//! 加载时原位迁移：名称留空、加入时间取文件修改时间，下次落盘自然升为 v2。
//!
//! 禁止 unsafe impl Send/Sync：RwLock<BTreeMap<NodeId, _>> 已天然 Send+Sync。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{PeerNetError, Result};
use crate::identity::NodeId;

/// 可信节点列表文件名（位于宿主注入的数据目录下）
const TRUSTED_NODES_FILE: &str = "trusted_nodes.json";

/// 文件格式版本：演进只允许追加字段，接收端拒绝更大版本
const TRUSTED_NODES_FORMAT_VERSION: u32 = 2;

// ==================== 公开类型 ====================

/// 一条可信对端的完整快照（设置面管理列表的数据形状）
#[derive(Debug, Clone, Serialize)]
pub struct TrustedPeerEntry {
    /// 对端节点 ID
    #[serde(serialize_with = "serialize_node_id_as_str")]
    pub node_id: NodeId,
    /// 展示名（mDNS 广播名；未注名为 `None` 时宿主可回退在线缓存解析）
    pub display_name: Option<String>,
    /// 加入可信列表的时刻
    pub added_at: DateTime<Utc>,
}

/// `NodeId` 的序列化辅助：输出 64 位小写 hex 字符串
///
/// 与 discovery.rs 同款模式：NodeId 刻意不派生 serde（identity.rs 禁止任何绕过
/// parse 校验的反序列化构造路径），序列化只读不构造，安全输出字符串形态。
fn serialize_node_id_as_str<S: serde::Serializer>(
    node_id: &NodeId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(node_id.as_str())
}

// ==================== 内部表示 ====================

/// 单条记录的内存元数据（ID 为 BTreeMap 键）
#[derive(Debug, Clone)]
struct PeerMeta {
    name: Option<String>,
    added_at: DateTime<Utc>,
}

/// 可信节点列表文件的磁盘表示（v2）
///
/// `version` 在加载路径经 serde_json::Value 预检后才进入本结构、在写入路径恒为
/// 当前常量，故 Rust 侧从不读取——allow 而非删除：字段是磁盘契约的一部分。
#[derive(Debug, Serialize, Deserialize)]
struct TrustedNodesFile {
    #[allow(dead_code)]
    version: u32,
    peers: Vec<TrustedPeerRecordFile>,
}

/// 单条磁盘记录：ID 必填，元数据可缺省（防御手改文件不炸加载）
#[derive(Debug, Serialize, Deserialize)]
struct TrustedPeerRecordFile {
    node_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    added_at: Option<DateTime<Utc>>,
}

/// v1 旧格式（纯 ID 列表）：仅用于一次性迁移读取，永不回写
///
/// `version` 同上：Value 预检已确认 =1，反序列化只为取 node_ids。
#[derive(Debug, Deserialize)]
struct TrustedNodesFileV1 {
    #[allow(dead_code)]
    version: u32,
    node_ids: Vec<String>,
}

// ==================== TrustStore ====================

/// 本地可信节点列表：内存集合 + 原子持久化文件的双写视图
///
/// 「信任」的唯一判定入口是 [`TrustStore::contains`]；撤销走 [`TrustStore::remove`]，
/// 落盘即时生效（下次 load_or_create 不含被撤条目，AC#5）。
#[derive(Debug)]
pub struct TrustStore {
    /// 持久化文件完整路径；内存态实例为 None（无落盘）
    path: Option<PathBuf>,
    peers: RwLock<BTreeMap<NodeId, PeerMeta>>,
}

impl TrustStore {
    /// 加载或创建可信节点列表——crate 管完整 load/create，宿主只注入目录
    ///
    /// - `{dir}/trusted_nodes.json` 存在 → 读出并逐项校验 ID 形状（v1 自动迁移）；
    /// - 不存在 → 创建空表并原子写入初始文件；
    /// - 文件损坏 → 快速失败不静默重建（理由见模块文档）。
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| PeerNetError::CreateDir {
            path: dir.to_path_buf(),
            source: e,
        })?;

        let path = dir.join(TRUSTED_NODES_FILE);
        if path.exists() {
            let peers = Self::load_from_file(&path)?;
            Ok(Self {
                path: Some(path),
                peers: RwLock::new(peers),
            })
        } else {
            let store = Self {
                path: Some(path.clone()),
                peers: RwLock::new(BTreeMap::new()),
            };
            // 首启显式落一个空表：让「存储已初始化」在磁盘上可见，排查时
            // 能区分「从未初始化」与「初始化后被清空」
            store.write_atomic(&TrustedNodesFile {
                version: TRUSTED_NODES_FORMAT_VERSION,
                peers: Vec::new(),
            })?;
            tracing::debug!("created new trusted nodes file at {}", path.display());
            Ok(store)
        }
    }

    /// 内存态空表：无目录上下文时的缺省（宿主后续可注入持久化实例替换）
    pub fn in_memory() -> Self {
        Self {
            path: None,
            peers: RwLock::new(BTreeMap::new()),
        }
    }

    /// 是否信任给定节点（accept 循环热路径，只取读锁）
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.peers.read().expect("trust store lock poisoned").contains_key(node_id)
    }

    /// 加入可信集（幂等：已存在时不重复落盘），返回是否为新加入
    ///
    /// 持久化失败如实上抛：内存与磁盘不一致的状态必须让调用方可见，
    /// 由其决定连接是否继续（见 transport 侧注释），禁止此处吞错。
    pub fn add(&self, node_id: &NodeId) -> Result<bool> {
        self.add_with_metadata(node_id, None)
    }

    /// 加入可信集并携带展示元数据；已存在且缺名时补注名称（幂等）
    ///
    /// 返回是否为新加入。两个写入方向都即时落盘：
    /// - 新插入：name + 当前时刻一并落库；
    /// - 补注：仅在既有条目缺名且本次带名时填充（已有名不覆盖——首次确认时
    ///   用户看到的名字即为准）。
    pub fn add_with_metadata(&self, node_id: &NodeId, display_name: Option<&str>) -> Result<bool> {
        let name = display_name.map(str::to_string).filter(|s| !s.is_empty());
        let mut inserted = false;
        let mut annotated = false;
        {
            let mut guard = self.peers.write().expect("trust store lock poisoned");
            match guard.get_mut(node_id) {
                Some(meta) => {
                    // 已存在：仅补缺名，不覆盖已有名；返回值保持「非新插入」语义
                    if name.is_some() && meta.name.is_none() {
                        meta.name = name;
                        annotated = true;
                    }
                }
                None => {
                    guard.insert(
                        node_id.clone(),
                        PeerMeta { name, added_at: Utc::now() },
                    );
                    inserted = true;
                }
            }
        }
        if inserted || annotated {
            if let Err(e) = self.persist_snapshot() {
                // 落盘失败则回滚内存变更，保证「contains 为真 ⇒ 已落库」不变量
                let mut guard = self.peers.write().expect("trust store lock poisoned");
                if inserted {
                    guard.remove(node_id);
                } else if let Some(meta) = guard.get_mut(node_id) {
                    // 回滚补注：恢复缺名态
                    meta.name = None;
                }
                return Err(e);
            }
            tracing::info!(node_id = %node_id, short = %node_id.short_fingerprint(), "peer added to trust store");
        }
        Ok(inserted)
    }

    /// 从可信集撤销指定节点（AC#5 的 API 面），返回该节点原本是否存在
    pub fn remove(&self, node_id: &NodeId) -> Result<bool> {
        let removed_meta = self
            .peers
            .write()
            .expect("trust store lock poisoned")
            .remove(node_id);
        let Some(meta) = removed_meta else {
            return Ok(false);
        };
        if let Err(e) = self.persist_snapshot() {
            // 与 add 对称：落盘失败原样放回，撤销不会「看似生效实则未落库」
            self.peers
                .write()
                .expect("trust store lock poisoned")
                .insert(node_id.clone(), meta);
            return Err(e);
        }
        tracing::info!(node_id = %node_id, short = %node_id.short_fingerprint(), "peer removed from trust store");
        Ok(true)
    }

    /// 当前可信节点快照（按 ID 排序）
    pub fn list(&self) -> Vec<NodeId> {
        self.peers.read().expect("trust store lock poisoned").keys().cloned().collect()
    }

    /// 完整元数据快照（按 ID 排序）：设置面管理列表的直接数据源
    pub fn list_entries(&self) -> Vec<TrustedPeerEntry> {
        self.peers
            .read()
            .expect("trust store lock poisoned")
            .iter()
            .map(|(node_id, meta)| TrustedPeerEntry {
                node_id: node_id.clone(),
                display_name: meta.name.clone(),
                added_at: meta.added_at,
            })
            .collect()
    }

    // ==================== 内部：加载与落盘 ====================

    /// 从磁盘加载并校验自洽（格式版本 + 每个 ID 形状合法；v1 原位迁移到 v2）
    fn load_from_file(path: &PathBuf) -> Result<BTreeMap<NodeId, PeerMeta>> {
        let content =
            std::fs::read_to_string(path).map_err(|e| PeerNetError::TrustStoreRead {
                path: path.clone(),
                source: e,
            })?;
        // 非 JSON 即损坏：快速失败，保留原文件供人工诊断
        let value: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| PeerNetError::TrustStoreParse {
                path: path.clone(),
                source: e,
            })?;
        let version = match value.get("version").and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => {
                return Err(PeerNetError::TrustStoreCorrupted {
                    path: path.clone(),
                    detail: "missing format version".to_string(),
                });
            }
        };

        let entries: Vec<(NodeId, PeerMeta)> = match version {
            1 => {
                let legacy: TrustedNodesFileV1 =
                    serde_json::from_value(value).map_err(|e| PeerNetError::TrustStoreParse {
                        path: path.clone(),
                        source: e,
                    })?;
                // v1 无逐条时间戳：以文件修改时间近似加入时刻（宁可近似也不虚构「现在」）
                let migrated_at = file_modified_utc(path);
                legacy
                    .node_ids
                    .into_iter()
                    .map(|raw| {
                        Ok((
                            parse_node_id_entry(&raw, path)?,
                            PeerMeta { name: None, added_at: migrated_at },
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            v if v == TRUSTED_NODES_FORMAT_VERSION as u64 => {
                let file: TrustedNodesFile =
                    serde_json::from_value(value).map_err(|e| PeerNetError::TrustStoreParse {
                        path: path.clone(),
                        source: e,
                    })?;
                file.peers
                    .into_iter()
                    .map(|record| {
                        Ok((
                            parse_node_id_entry(&record.node_id, path)?,
                            PeerMeta {
                                name: record.name,
                                added_at: record.added_at.unwrap_or_else(Utc::now),
                            },
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            other => {
                return Err(PeerNetError::TrustStoreCorrupted {
                    path: path.clone(),
                    detail: format!("unsupported format version {other}"),
                });
            }
        };

        let mut peers = BTreeMap::new();
        for (node_id, meta) in entries {
            peers.insert(node_id, meta);
        }
        tracing::debug!(
            count = peers.len(),
            "loaded trusted nodes from {}",
            path.display()
        );
        Ok(peers)
    }

    /// 把当前内存集合快照原子写入磁盘（调用方需已持有写锁或处于单线程变更点）
    fn persist_snapshot(&self) -> Result<()> {
        let guard = self.peers.read().expect("trust store lock poisoned");
        let file = TrustedNodesFile {
            version: TRUSTED_NODES_FORMAT_VERSION,
            peers: guard
                .iter()
                .map(|(node_id, meta)| TrustedPeerRecordFile {
                    node_id: node_id.as_str().to_string(),
                    name: meta.name.clone(),
                    added_at: Some(meta.added_at),
                })
                .collect(),
        };
        drop(guard);
        self.write_atomic(&file)
    }

    /// 原子写入：同目录临时文件 + rename
    fn write_atomic(&self, file: &TrustedNodesFile) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let content = serde_json::to_string_pretty(file)
            .map_err(|e| PeerNetError::TrustStoreSerialize { source: e })?;

        // 同目录保证 rename 在同一文件系统内原子生效
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, content).map_err(|e| PeerNetError::TrustStoreWriteTemp {
            path: tmp_path.clone(),
            source: e,
        })?;

        // unix 下收紧权限：可信名单泄露可被用于定向社工，非机密但也不必公开
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| PeerNetError::TrustStorePermissions {
                    path: tmp_path.clone(),
                    source: e,
                },
            )?;
        }

        std::fs::rename(&tmp_path, path).map_err(|e| PeerNetError::TrustStoreRename {
            from: tmp_path,
            to: path.clone(),
            source: e,
        })
    }
}

// ==================== 内部辅助 ====================

/// 解析并校验单条 ID 形状，非法即报 corrupted（快速失败约定）
fn parse_node_id_entry(raw: &str, path: &PathBuf) -> Result<NodeId> {
    NodeId::parse(raw).map_err(|_| PeerNetError::TrustStoreCorrupted {
        path: path.clone(),
        detail: format!("invalid node id entry: {raw}"),
    })
}

/// 文件修改时间的 UTC 形态（v1 迁移的加入时刻来源）；不可得则退回当前时刻
fn file_modified_utc(path: &Path) -> DateTime<Utc> {
    std::fs::metadata(path)
        .ok()
        .and_then(|meta| meta.modified().ok())
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(Utc::now)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn sample_node_id(byte0: u8) -> NodeId {
        let hex = format!("{byte0:02x}").repeat(32);
        NodeId::parse(&hex).expect("valid node id")
    }

    #[test]
    fn roundtrip_add_then_reload_keeps_entry() {
        let dir = fresh_dir();
        let a_id = sample_node_id(0x11);

        let first = TrustStore::load_or_create(dir.path()).expect("create store");
        assert!(!first.contains(&a_id));
        first.add(&a_id).expect("add");

        let reloaded = TrustStore::load_or_create(dir.path()).expect("reload store");
        assert!(reloaded.contains(&a_id));
        assert_eq!(reloaded.list(), vec![a_id]);
    }

    #[test]
    fn add_is_idempotent_and_remove_reports_presence_once() {
        let dir = fresh_dir();
        let store = TrustStore::load_or_create(dir.path()).expect("store");
        let id = sample_node_id(0x22);

        assert!(store.add(&id).expect("first add"), "first insert is new");
        assert!(!store.add(&id).expect("second add"), "second insert is noop");

        assert!(store.remove(&id).expect("first remove"), "present once");
        assert!(!store.remove(&id).expect("second remove"), "gone after first");
        assert!(!store.contains(&id));
    }

    #[test]
    fn removal_is_visible_across_instances_and_restarts() {
        let dir = fresh_dir();
        let keep = sample_node_id(0x31);
        let revoked = sample_node_id(0x32);

        let writer = TrustStore::load_or_create(dir.path()).expect("writer");
        writer.add(&keep).expect("add keep");
        writer.add(&revoked).expect("add revoked");

        // 另一实例读到相同内容（共享目录并发查询的前提）
        let reader = TrustStore::load_or_create(dir.path()).expect("reader");
        assert!(reader.contains(&revoked));

        // 撤销即时落库：新建实例重载不含被撤条目（AC#5 核心）
        writer.remove(&revoked).expect("revoke");
        let after = TrustStore::load_or_create(dir.path()).expect("after revoke");
        assert!(!after.contains(&revoked));
        assert!(after.contains(&keep));
    }

    #[test]
    fn corrupted_file_fails_fast_and_is_not_rebuilt() {
        let dir = fresh_dir();
        let path = dir.path().join(TRUSTED_NODES_FILE);
        std::fs::write(&path, "{ not valid json !!!").expect("corrupt file");

        let err = TrustStore::load_or_create(dir.path()).expect_err("must fail fast");
        assert!(
            matches!(err, PeerNetError::TrustStoreParse { .. }),
            "expected TrustStoreParse, got: {err}"
        );

        // 损坏文件原样保留：人工恢复/诊断的前提
        let still_corrupted = std::fs::read_to_string(&path).expect("file untouched");
        assert_eq!(still_corrupted, "{ not valid json !!!");
    }

    #[test]
    fn invalid_node_id_entry_is_reported_as_corrupted() {
        let dir = fresh_dir();
        let path = dir.path().join(TRUSTED_NODES_FILE);
        // 合法 JSON 但含非法 ID（大写 hex）：形状校验必须拦住
        let bad = r#"{"version":1,"node_ids":["ZZZZ"]}"#;
        std::fs::write(&path, bad).expect("seed bad file");

        let err = TrustStore::load_or_create(dir.path()).expect_err("must fail fast");
        assert!(matches!(err, PeerNetError::TrustStoreCorrupted { .. }));
    }

    #[test]
    fn in_memory_store_works_without_disk() {
        let store = TrustStore::in_memory();
        let id = sample_node_id(0x44);
        store.add(&id).expect("in-memory add");
        assert!(store.contains(&id));
        store.remove(&id).expect("in-memory remove");
        assert!(!store.contains(&id));
    }

    // ==================== ticket 04：元数据与迁移 ====================

    #[test]
    fn metadata_survives_reload_and_annotates_only_unnamed_entries() {
        let dir = fresh_dir();
        let named = sample_node_id(0x51);
        let unnamed = sample_node_id(0x52);
        let renamed_target = sample_node_id(0x53);

        let store = TrustStore::load_or_create(dir.path()).expect("store");
        assert!(
            store.add_with_metadata(&named, Some("张三的手机")).expect("add named"),
            "first insert is new"
        );
        store.add(&unnamed).expect("add unnamed");
        store.add(&renamed_target).expect("add target");

        // 缺名条目可被带名的重复 add 补注；已有名不被覆盖
        assert!(!store.add_with_metadata(&named, Some("改名")).expect("no-op"));
        assert!(!store.add_with_metadata(&renamed_target, Some("后到的名字")).expect("annotate"));

        let reloaded = TrustStore::load_or_create(dir.path()).expect("reload");
        let by_id = |id: &NodeId| {
            reloaded
                .list_entries()
                .into_iter()
                .find(|entry| entry.node_id == *id)
                .expect("entry present")
        };
        assert_eq!(by_id(&named).display_name.as_deref(), Some("张三的手机"));
        assert_eq!(by_id(&unnamed).display_name, None);
        assert_eq!(by_id(&renamed_target).display_name.as_deref(), Some("后到的名字"));
        // 加入时间已被持久化为合理近邻时刻（不早于 1 小时前、不晚于未来）
        let now = Utc::now();
        for entry in reloaded.list_entries() {
            assert!(entry.added_at <= now + chrono::Duration::minutes(1));
            assert!(entry.added_at > now - chrono::Duration::hours(1));
        }
    }

    #[test]
    fn v1_file_migrates_in_place_and_next_write_upgrades_format() {
        let dir = fresh_dir();
        let legacy_a = sample_node_id(0x61);
        let legacy_b = sample_node_id(0x62);
        let path = dir.path().join(TRUSTED_NODES_FILE);
        let legacy = format!(
            r#"{{"version":1,"node_ids":["{}","{}"]}}"#,
            legacy_a.as_str(),
            legacy_b.as_str()
        );
        std::fs::write(&path, legacy).expect("seed v1 file");

        let store = TrustStore::load_or_create(dir.path()).expect("load migrates");
        assert!(store.contains(&legacy_a) && store.contains(&legacy_b));
        // 迁移条目名称为空、时间取自文件 mtime（存在且合理即可，不做精确断言）
        for entry in store.list_entries() {
            assert_eq!(entry.display_name, None);
            assert!(entry.added_at <= Utc::now());
        }

        // 后续写入升级为 v2：重载仍兼容且新增条目带元数据
        let fresh = sample_node_id(0x63);
        store
            .add_with_metadata(&fresh, Some("新设备"))
            .expect("post-migration add");
        let reloaded = TrustStore::load_or_create(dir.path()).expect("reload upgraded");
        assert!(reloaded.contains(&legacy_a) && reloaded.contains(&legacy_b));
        let entry = reloaded
            .list_entries()
            .into_iter()
            .find(|entry| entry.node_id == fresh)
            .expect("fresh entry");
        assert_eq!(entry.display_name.as_deref(), Some("新设备"));
    }

    #[test]
    fn future_format_version_fails_fast() {
        let dir = fresh_dir();
        let path = dir.path().join(TRUSTED_NODES_FILE);
        std::fs::write(&path, r#"{"version":99,"peers":[]}"#).expect("seed future file");

        let err = TrustStore::load_or_create(dir.path()).expect_err("must fail fast");
        assert!(matches!(err, PeerNetError::TrustStoreCorrupted { .. }));
    }
}
