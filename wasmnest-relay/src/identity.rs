//! 中继身份（ed25519）。
//!
//! 身份密钥 = PeerId = 客户端导入地址里的 `/p2p/<id>`：**丢失即所有客户端必须重新
//! 导入**。因此这里的取舍是「保守覆盖」：
//!
//! - 已有密钥时 `init` 直接拒绝，必须显式 `--force`（并提示后果）；
//! - 只接受 ed25519（与对等栈「指纹即身份」口径一致，非 ed25519 显性拒绝）；
//! - 落盘原子 + `0600`，避免半写文件或全局可读的私钥。

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use libp2p::identity::Keypair;
use libp2p::PeerId;
use sha2::{Digest, Sha256};

use crate::{
    error::{RelayError, Result},
    fsutil::SECRET_FILE_MODE,
};

/// 中继身份：ed25519 密钥对 + 派生的 PeerId
#[derive(Clone)]
pub struct RelayIdentity {
    keypair: Keypair,
}

impl std::fmt::Debug for RelayIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不 Debug 出密钥材料：只暴露可比较的 PeerId
        f.debug_struct("RelayIdentity")
            .field("peer_id", &self.peer_id())
            .finish()
    }
}

impl RelayIdentity {
    /// 生成新身份（ed25519）
    pub fn generate() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
        }
    }

    /// 从磁盘加载；文件缺失显性失败并给 `init` 出路
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(RelayError::Identity(format!(
                "身份密钥不存在：{}；先运行 `wasmnest-relay init --dir <数据目录>` 生成，\
                 或从备份恢复该文件（丢失身份 = PeerId 变化 = 所有客户端需重新导入）",
                path.display()
            )));
        }
        let bytes = crate::fsutil::read_bytes(path)?;
        let keypair = Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
            RelayError::Identity(format!(
                "身份密钥无法解析（{}）：{e}；该文件由 `init` 生成，损坏请从备份恢复",
                path.display()
            ))
        })?;
        let identity = Self { keypair };
        identity.ensure_ed25519()?;
        Ok(identity)
    }

    /// 生成并落盘身份；已有文件时要求显式覆盖
    pub fn create(path: &Path, force: bool) -> Result<Self> {
        if path.exists() && !force {
            return Err(RelayError::Identity(format!(
                "身份密钥已存在：{}；覆盖会让 PeerId 变化、所有客户端需重新导入。\
                 确需覆盖请显式加 `--force`",
                path.display()
            )));
        }
        let identity = Self::generate();
        identity.save(path)?;
        Ok(identity)
    }

    /// 落盘（原子写 + `0600`）
    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = self
            .keypair
            .to_protobuf_encoding()
            .map_err(|e| RelayError::Identity(format!("身份密钥编码失败：{e}")))?;
        crate::fsutil::write_atomic(path, &bytes, SECRET_FILE_MODE)
    }

    /// 本节点 PeerId
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    /// PeerId 指纹：`sha256(ed25519 原始公钥)` 的十六进制
    ///
    /// 与对等栈的 `node_id = hex(SHA-256(raw ed25519 key))` 同一派生口径，因此客户端
    /// 侧可以直接用同一算法独立校验——不必相信中继自报的字符串。
    pub fn fingerprint(&self) -> String {
        let public = self
            .keypair
            .public()
            .try_into_ed25519()
            .expect("身份在加载/生成时已限定 ed25519");
        hex::encode(Sha256::digest(public.to_bytes()))
    }

    /// 供 swarm 装配消费的密钥对
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    fn ensure_ed25519(&self) -> Result<()> {
        if self.keypair.public().try_into_ed25519().is_err() {
            return Err(RelayError::Identity(
                "身份密钥不是 ed25519：对等栈按 ed25519 派生指纹与 PeerId，\
                 请用 `init` 重新生成（迁移其它算法需先评估客户端兼容性）"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// PeerId 短指纹（日志用）：`12D3KooW…7f3a`
pub fn short_peer(peer: &PeerId) -> String {
    let text = peer.to_base58();
    if text.len() <= 12 {
        return text;
    }
    format!("{}…{}", &text[..8], &text[text.len() - 4..])
}

/// 解析 PeerId 字符串（CLI / 白名单共用）
pub fn parse_peer_id(text: &str) -> Result<PeerId> {
    PeerId::from_str(text.trim())
        .map_err(|e| RelayError::args(format!("PeerId 非法（{text}）：{e}")))
}

/// 数据目录内身份密钥的默认路径
pub fn default_identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join(crate::config::IDENTITY_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 生成的身份是_ed25519_且指纹稳定() {
        let identity = RelayIdentity::generate();
        let first = identity.fingerprint();
        let second = identity.fingerprint();
        assert_eq!(first, second, "同一身份的指纹必须稳定");
        assert_eq!(first.len(), 64, "sha256 十六进制应为 64 字符");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn 落盘再加载后_peer_id_与指纹不变() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("identity.key");
        let created = RelayIdentity::create(&path, false).expect("创建");
        let loaded = RelayIdentity::load(&path).expect("加载");

        assert_eq!(created.peer_id(), loaded.peer_id(), "重启不换 PeerId");
        assert_eq!(created.fingerprint(), loaded.fingerprint());
    }

    #[test]
    fn 已存在身份时拒绝覆盖除非显式_force() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("identity.key");
        let first = RelayIdentity::create(&path, false).expect("首次创建");

        let err = RelayIdentity::create(&path, false).expect_err("应拒绝覆盖");
        assert!(err.to_string().contains("--force"), "{err}");

        let forced = RelayIdentity::create(&path, true).expect("显式覆盖");
        assert_ne!(
            first.peer_id(),
            forced.peer_id(),
            "覆盖 = 新身份（这正是需要 --force 的原因）"
        );
        let reloaded = RelayIdentity::load(&path).expect("重新加载");
        assert_eq!(reloaded.peer_id(), forced.peer_id());
    }

    #[test]
    fn 缺失身份报错并给出_init_出路() {
        let dir = tempfile::tempdir().expect("临时目录");
        let err = RelayIdentity::load(&dir.path().join("identity.key")).expect_err("应报错");
        let text = err.to_string();
        assert!(text.contains("init"), "{text}");
        assert!(text.contains("identity.key"), "{text}");
    }

    #[test]
    fn 损坏身份显性失败() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("identity.key");
        std::fs::write(&path, b"not-a-keypair").expect("写坏文件");
        let err = RelayIdentity::load(&path).expect_err("应报错");
        assert!(err.to_string().contains("无法解析"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn 身份文件权限仅属主可读写() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("identity.key");
        RelayIdentity::create(&path, false).expect("创建");
        let mode = std::fs::metadata(&path)
            .expect("元数据")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "私钥不能全局可读");
    }

    #[test]
    fn 短指纹保留首尾便于人工比对() {
        let identity = RelayIdentity::generate();
        let short = short_peer(&identity.peer_id());
        assert!(short.contains('…'), "{short}");
        assert!(short.starts_with(&identity.peer_id().to_base58()[..8]));
    }

    #[test]
    fn 非法_peer_id_报参数错误() {
        let err = parse_peer_id("not-a-peer").expect_err("应报错");
        assert!(err.to_string().starts_with("参数错误："), "{err}");
    }
}
