//! 节点身份：Ed25519 长效密钥与公钥指纹（node_id）。
//!
//! ## 为什么与 DeviceIdentity 彻底分离（决策 D2）
//!
//! 宿主 auth 域的设备身份（`device_identity.json`）由 ANDROID_ID 派生，让终端配对
//! 跨重装存活；节点身份方向刻意相反——**首启纯随机生成**（OsRng）、不做任何设备
//! 标识派生，落实「重装即新身份」。两条身份的关联映射属于未来信任层（ticket 10），
//! 本 crate 只管密钥材料：身份文件不内嵌设备名等展示字段，设备名由宿主提供。
//!
//! ## 为什么损坏即报错而非静默重建（决策 D3）
//!
//! 自身 node_id 变更会让对端可信列表里记录的 ID 全部失效（ticket 02 可信列表存的
//! 是对方 ID），因此文件损坏时返回 Err 快速失败，绝不悄悄换一个新身份。

use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{PeerNetError, Result};

/// 身份持久化文件名（与宿主 `device_identity.json` 并列、互不相干）
const IDENTITY_FILE: &str = "node_identity.json";

/// 身份文件格式版本（未来迁移判据；当前恒为 1）
const IDENTITY_FORMAT_VERSION: u32 = 1;

/// node_id 十六进制长度 = SHA-256 输出（32B）× 2
const NODE_ID_HEX_LEN: usize = 64;

/// 短指纹长度：node_id 前 8 字符（UI 展示用）
pub const SHORT_FINGERPRINT_LEN: usize = 8;

// ==================== NodeId ====================

/// 节点 ID newtype：`hex(SHA-256(raw ed25519 公钥 32B))`，小写全长 64 字符
///
/// 指纹算法选原始公钥哈希而非 DER SPKI 哈希——生成侧持有原始公钥、校验侧从
/// SPKI BIT STRING 直接取 32 字节原始钥再哈希，两侧计算路径都最短。
///
/// 刻意不派生 serde：所有反序列化入口都必须经 [`NodeId::parse`] 或由公钥重算，
/// 杜绝任何绕过格式校验的构造路径。
///
/// `Ord` 支撑可信列表的 `BTreeSet` 存储（稳定排序快照供 UI 列表复用）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    /// 从原始 Ed25519 公钥计算节点 ID
    pub fn from_public_key(public_key_raw: &[u8; 32]) -> Self {
        Self(hex::encode(Sha256::digest(public_key_raw)))
    }

    /// 从字符串解析并校验格式（64 位小写 hex）
    pub fn parse(value: &str) -> Result<Self> {
        if is_valid_node_id(value) {
            Ok(Self(value.to_string()))
        } else {
            Err(PeerNetError::InvalidNodeId {
                value: value.to_string(),
            })
        }
    }

    /// 节点 ID 字符串形式（小写 hex 64 字符）
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 短指纹：前 8 字符，供 UI 与日志并列展示
    ///
    /// 长度恒定（[`SHORT_FINGERPRINT_LEN`]），切片不会越界。
    pub fn short_fingerprint(&self) -> &str {
        &self.0[..SHORT_FINGERPRINT_LEN]
    }
}

impl Deref for NodeId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// node_id 格式校验：长度 64 且全为小写 hex 字符
fn is_valid_node_id(s: &str) -> bool {
    s.len() == NODE_ID_HEX_LEN
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ==================== NodeIdentity ====================

/// 节点身份：Ed25519 签名密钥 + 缓存的节点 ID
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    signing_key: SigningKey,
    node_id: NodeId,
}

impl NodeIdentity {
    /// 加载或创建节点身份——crate 管完整 load/generate/save，宿主只注入目录（决策 D3）
    ///
    /// - `{dir}/node_identity.json` 存在 → 读出种子重建密钥并校验自洽；
    /// - 不存在 → OsRng 纯随机生成并原子写入（unix 下收紧为 0600）；
    /// - 文件损坏 → 返回 [`PeerNetError`] 快速失败（理由见模块文档 D3 段）。
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| PeerNetError::CreateDir {
            path: dir.to_path_buf(),
            source: e,
        })?;

        let path = dir.join(IDENTITY_FILE);
        if path.exists() {
            Self::load_from_file(&path)
        } else {
            // 首启：纯随机生成——无任何设备标识输入是「重装即新身份」的核心（D2）
            let identity = Self::generate();
            identity.save_to_file(&path)?;
            tracing::info!(
                node_id = %identity.node_id,
                short_fingerprint = %identity.node_id.short_fingerprint(),
                "generated new peer-net node identity"
            );
            Ok(identity)
        }
    }

    /// 原始公钥（32 字节）——指纹计算与证书绑定校验的最短输入路径
    pub fn public_key_raw(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }

    /// 节点 ID（公钥指纹）
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// 签名密钥种子（32 字节）
    ///
    /// crate 内部供 cert.rs 构造 rcgen 密钥对；后续 TLS 栈（ticket 02）复用同一
    /// 密钥时再评估是否提升可见性，当前保持最小暴露面。
    pub(crate) fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// 纯随机生成新身份（首启专用；测试用它构造互相独立的身份）
    fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    /// 由签名密钥派生完整身份（node_id 由公钥重算，不信任外部输入）
    fn from_signing_key(signing_key: SigningKey) -> Self {
        let node_id = NodeId::from_public_key(signing_key.verifying_key().as_bytes());
        Self { signing_key, node_id }
    }

    /// 从磁盘加载身份并做自洽校验
    fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| PeerNetError::IdentityRead {
            path: path.clone(),
            source: e,
        })?;
        // 非 JSON 即损坏：按 D3 报错，不静默重新生成
        let file: IdentityFile =
            serde_json::from_str(&content).map_err(|e| PeerNetError::IdentityParse {
                path: path.clone(),
                source: e,
            })?;

        if file.version != IDENTITY_FORMAT_VERSION {
            return Err(PeerNetError::IdentityCorrupted {
                path: path.clone(),
                detail: format!("unsupported format version {}", file.version),
            });
        }

        let seed: [u8; 32] = hex::decode(&file.secret_seed_hex)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| PeerNetError::IdentityCorrupted {
                path: path.clone(),
                detail: "secret_seed_hex is not 32 bytes of hex".to_string(),
            })?;
        let signing_key = SigningKey::from_bytes(&seed);

        // 自洽校验：文件记录的 node_id 必须等于由密钥重算出的指纹——拦截手改/
        // 半写损坏，防止「密钥」与「对外身份」悄悄错位
        let derived = Self::from_signing_key(signing_key);
        if !is_valid_node_id(&file.node_id) || file.node_id != derived.node_id.as_str() {
            return Err(PeerNetError::IdentityCorrupted {
                path: path.clone(),
                detail: "stored node_id does not match key-derived fingerprint".to_string(),
            });
        }

        Ok(derived)
    }

    /// 原子写入身份文件：同目录临时文件 + rename
    ///
    /// 进程中途被杀只会留下完整的 tmp 或旧版正式文件，绝不产生半截 JSON——
    /// 半截文件按 D3 会永久锁死身份加载，宁可多一步也不能让它出现。
    fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let file = IdentityFile {
            version: IDENTITY_FORMAT_VERSION,
            secret_seed_hex: hex::encode(self.seed_bytes()),
            node_id: self.node_id.as_str().to_string(),
        };
        let content =
            serde_json::to_string_pretty(&file).map_err(|e| PeerNetError::IdentitySerialize {
                source: e,
            })?;

        // 同目录保证 rename 在同一文件系统内原子生效
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, content).map_err(|e| PeerNetError::IdentityWriteTemp {
            path: tmp_path.clone(),
            source: e,
        })?;

        // unix 下收紧权限：私钥材料不应被同机其他用户读取（Windows ACL 由用户
        // 目录隔离兜底，无需等价处理）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| PeerNetError::IdentityPermissions {
                    path: tmp_path.clone(),
                    source: e,
                },
            )?;
        }

        std::fs::rename(&tmp_path, path).map_err(|e| PeerNetError::IdentityRename {
            from: tmp_path,
            to: path.clone(),
            source: e,
        })?;
        tracing::debug!("saved peer-net node identity to {}", path.display());
        Ok(())
    }
}

// ==================== 磁盘表示 ====================

/// 身份文件的磁盘表示
///
/// 只存密钥材料，不内嵌设备名字段（D2）；node_id 冗余存储用于人读排查与
/// 加载自洽校验。
#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    /// Ed25519 种子（32 字节）的小写 hex
    secret_seed_hex: String,
    node_id: String,
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_save_then_load_keeps_same_id_and_public_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = NodeIdentity::load_or_create(dir.path()).expect("first load_or_create");

        let reloaded = NodeIdentity::load_or_create(dir.path()).expect("reload");
        assert_eq!(first.node_id(), reloaded.node_id());
        assert_eq!(first.public_key_raw(), reloaded.public_key_raw());

        // 文件确实落盘且内容自洽
        assert!(dir.path().join(IDENTITY_FILE).exists());
        assert!(!dir.path().join(IDENTITY_FILE).with_extension("tmp").exists());
    }

    #[test]
    fn fresh_instances_in_different_dirs_get_different_ids() {
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let dir_b = tempfile::tempdir().expect("tempdir b");

        let a = NodeIdentity::load_or_create(dir_a.path()).expect("a");
        let b = NodeIdentity::load_or_create(dir_b.path()).expect("b");

        assert_ne!(a.node_id(), b.node_id());
        assert_ne!(a.public_key_raw(), b.public_key_raw());
    }

    #[test]
    fn wiping_data_dir_yields_new_identity_reinstall_semantics() {
        let dir = tempfile::tempdir().expect("tempdir");
        let before = NodeIdentity::load_or_create(dir.path()).expect("first");
        let old_id = before.node_id().clone();

        // 「重装」的本质：数据目录被清掉（卸载删除应用数据）
        std::fs::remove_file(dir.path().join(IDENTITY_FILE)).expect("wipe identity file");

        let after = NodeIdentity::load_or_create(dir.path()).expect("regenerated");
        assert_ne!(old_id, *after.node_id());
    }

    #[test]
    fn corrupted_identity_file_errors_instead_of_regenerating() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = NodeIdentity::load_or_create(dir.path()).expect("first");
        let original_id = original.node_id().clone();
        let path = dir.path().join(IDENTITY_FILE);

        std::fs::write(&path, "{ not valid json !!!").expect("corrupt file");

        let err = NodeIdentity::load_or_create(dir.path()).expect_err("must fail fast on corruption");
        match err {
            PeerNetError::IdentityParse { .. } => {}
            other => panic!("expected IdentityParse, got: {other}"),
        }

        // 不静默重建：损坏文件原样保留（人工恢复/诊断的前提）
        let still_corrupted =
            std::fs::read_to_string(&path).expect("file untouched after failed load");
        assert_eq!(still_corrupted, "{ not valid json !!!");

        // 且没有偷偷生成新身份顶替旧 ID
        let err_again = NodeIdentity::load_or_create(dir.path()).expect_err("still failing");
        assert!(matches!(err_again, PeerNetError::IdentityParse { .. }));
        assert_eq!(original_id.len(), NODE_ID_HEX_LEN);
    }

    #[test]
    fn tampered_node_id_in_file_is_detected_as_inconsistent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = NodeIdentity::load_or_create(dir.path()).expect("first");
        let path = dir.path().join(IDENTITY_FILE);

        // 手改 node_id 字段（合法 hex 但与密钥不符）：自洽校验必须拒绝，
        // 否则「对外身份」可与「实际密钥」错位而不被发现
        let mut file: IdentityFile =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
        let mut tampered = file.node_id.clone().into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        file.node_id = String::from_utf8(tampered).expect("utf8");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&file).expect("serialize"),
        )
        .expect("write");

        let err = NodeIdentity::load_or_create(dir.path()).expect_err("inconsistency detected");
        assert!(matches!(err, PeerNetError::IdentityCorrupted { .. }));
        drop(original);
    }

    #[test]
    fn node_id_parse_rejects_invalid_formats() {
        let valid = "a".repeat(NODE_ID_HEX_LEN);
        assert!(NodeId::parse(&valid).is_ok());

        // 大写 hex 拒绝（约定小写全长）
        let uppercase = "A".repeat(NODE_ID_HEX_LEN);
        assert!(matches!(
            NodeId::parse(&uppercase),
            Err(PeerNetError::InvalidNodeId { .. })
        ));

        // 截断串拒绝
        let short = "a".repeat(NODE_ID_HEX_LEN - 1);
        assert!(matches!(
            NodeId::parse(&short),
            Err(PeerNetError::InvalidNodeId { .. })
        ));
    }

    #[test]
    fn short_fingerprint_is_first_8_chars() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = NodeIdentity::load_or_create(dir.path()).expect("first");
        let id = identity.node_id();
        assert_eq!(id.short_fingerprint().len(), SHORT_FINGERPRINT_LEN);
        assert!(id.as_str().starts_with(id.short_fingerprint()));
    }
}
