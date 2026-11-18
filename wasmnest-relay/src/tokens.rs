//! 私有 relay 的 enrollment token。
//!
//! 用途：`allowlist` 模式下给「还没进白名单」的设备一条自助开通路径——设备起来
//! 后连上控制协议，用运维发给它的 token 兑换一次白名单席位。token 的定位是
//! **防滥用凭证**，不是设备身份：兑换成功后真正的身份是 PeerId。
//!
//! 落盘纪律：只存 `sha256(token)`，明文只在 `token create` 那一次输出里出现，之后
//! 无法再取回；日志与指标一律不出现 token（含长度以外的任何形状）。

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{RelayError, Result},
    fsutil,
};

/// token 明文长度（32 个十六进制字符 = 128 bit）
pub const TOKEN_HEX_LEN: usize = 32;

/// 一条 token 记录
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    /// 人类可读标签（发给谁用；只用于运维识别）
    pub label: String,
    /// `sha256(明文)` 的十六进制
    pub sha256: String,
    /// 创建时间（unix 秒）
    pub created_at_unix: u64,
    /// 允许兑换次数
    pub max_uses: u32,
    /// 已兑换次数
    pub uses: u32,
}

/// token 表文件格式
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFile {
    tokens: Vec<TokenRecord>,
}

/// token 表（落盘 + 内存）
#[derive(Debug)]
pub struct TokenStore {
    path: PathBuf,
    file: TokenFile,
}

impl TokenStore {
    /// 加载 token 表；文件不存在 = 空表（私有 relay 尚未发过 token，不是错误）
    pub fn load(path: &Path) -> Result<Self> {
        let file = if path.exists() {
            let text = fsutil::read_to_string(path)?;
            let parsed: TokenFile =
                serde_json::from_str(&text).map_err(|source| RelayError::JsonParse {
                    path: path.display().to_string(),
                    source,
                })?;
            validate_records(path, &parsed.tokens)?;
            parsed
        } else {
            TokenFile::default()
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// 创建 token：返回明文（仅此一次）并落盘摘要
    pub fn create(&mut self, label: &str, max_uses: u32) -> Result<String> {
        let label = label.trim();
        if label.is_empty() {
            return Err(RelayError::args("token 标签不能为空（用于运维识别）"));
        }
        if max_uses == 0 {
            return Err(RelayError::args("token 兑换次数必须 ≥ 1"));
        }
        let token = generate_token();
        let record = TokenRecord {
            label: label.to_string(),
            sha256: hash_token(&token),
            created_at_unix: now_unix(),
            max_uses,
            uses: 0,
        };
        self.file.tokens.push(record);
        if let Err(err) = self.save() {
            // 落盘失败就别留下「内存里能兑换、重启后消失」的假开通
            self.file.tokens.pop();
            return Err(err);
        }
        Ok(token)
    }

    /// 兑换：校验摘要与剩余次数，成功后计数 +1 并落盘
    ///
    /// 返回 token 的标签（写日志用；不含 token 本身）。失败原因只区分「无效/用尽」，
    /// 不区分「不存在」与「格式错」——对外少泄一点信息。
    pub fn verify_and_consume(&mut self, presented: &str) -> Result<String> {
        let presented = presented.trim();
        if presented.len() != TOKEN_HEX_LEN || !presented.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RelayError::Token("invalid-token".to_string()));
        }
        let digest = hex::decode(hash_token(presented)).expect("sha256 十六进制");
        let index = self
            .file
            .tokens
            .iter()
            .position(|record| {
                // 定长摘要逐字节比较；token 是高熵 128 bit 随机值，且来自 Noise 加密
                // 通道，时序侧信道不构成现实威胁（真正的防重放靠次数与 PeerId 绑定）。
                let stored = hex::decode(&record.sha256).unwrap_or_default();
                stored.len() == digest.len()
                    && stored
                        .iter()
                        .zip(digest.iter())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0
                    && record.uses < record.max_uses
            })
            .ok_or_else(|| RelayError::Token("invalid-token".to_string()))?;

        let previous = self.file.tokens[index].uses;
        self.file.tokens[index].uses = previous.saturating_add(1);
        if let Err(err) = self.save() {
            self.file.tokens[index].uses = previous;
            return Err(err);
        }
        Ok(self.file.tokens[index].label.clone())
    }

    /// 记录数（自检用）
    pub fn len(&self) -> usize {
        self.file.tokens.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.file.tokens.is_empty()
    }

    /// 概览（标签 + 用量；不含摘要与明文，供 `doctor` 打印）
    pub fn summary(&self) -> Vec<(String, u32, u32)> {
        self.file
            .tokens
            .iter()
            .map(|r| (r.label.clone(), r.uses, r.max_uses))
            .collect()
    }

    /// 落盘路径
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&self) -> Result<()> {
        let body = serde_json::to_vec_pretty(&self.file)?;
        fsutil::write_atomic(&self.path, &body, 0o600)
    }
}

/// 生成 128 bit 随机 token（32 个十六进制字符）
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_HEX_LEN / 2];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// `sha256(明文)` 的十六进制
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn validate_records(path: &Path, records: &[TokenRecord]) -> Result<()> {
    let mut seen = HashSet::new();
    for record in records {
        if record.max_uses == 0 {
            return Err(RelayError::config(format!(
                "{} 中存在兑换次数为 0 的 token（label={}）",
                path.display(),
                record.label
            )));
        }
        if record.uses > record.max_uses {
            return Err(RelayError::config(format!(
                "{} 中 token 用量超过上限（label={}，uses={}，max_uses={}）",
                path.display(),
                record.label,
                record.uses,
                record.max_uses
            )));
        }
        if record.sha256.len() != 64 || !seen.insert(record.sha256.clone()) {
            return Err(RelayError::config(format!(
                "{} 中存在非法或重复的 token 摘要（label={}）",
                path.display(),
                record.label
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 生成的_token_为_32_位十六进制() {
        let token = generate_token();
        assert_eq!(token.len(), TOKEN_HEX_LEN);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(token, generate_token(), "每次生成应不同");
    }

    #[test]
    fn 创建后可兑换并返回标签() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        let mut store = TokenStore::load(&path).expect("加载");
        let token = store.create("phone", 1).expect("创建");

        let label = store.verify_and_consume(&token).expect("兑换");
        assert_eq!(label, "phone");
        assert!(path.exists(), "应落盘");
    }

    #[test]
    fn token_默认一次性() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        let mut store = TokenStore::load(&path).expect("加载");
        let token = store.create("phone", 1).expect("创建");

        store.verify_and_consume(&token).expect("首次");
        let err = store.verify_and_consume(&token).expect_err("二次应失败");
        assert!(err.to_string().contains("invalid-token"), "{err}");
    }

    #[test]
    fn 多次兑换按上限放行() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        let mut store = TokenStore::load(&path).expect("加载");
        let token = store.create("team", 2).expect("创建");

        store.verify_and_consume(&token).expect("第 1 次");
        store.verify_and_consume(&token).expect("第 2 次");
        assert!(store.verify_and_consume(&token).is_err(), "第 3 次应失败");
    }

    #[test]
    fn 兑换计数跨重启保持() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        let token = {
            let mut store = TokenStore::load(&path).expect("加载");
            store.create("phone", 1).expect("创建")
        };

        let mut reloaded = TokenStore::load(&path).expect("重新加载");
        reloaded.verify_and_consume(&token).expect("重启后仍可兑换");
        let mut again = TokenStore::load(&path).expect("再次加载");
        assert!(
            again.verify_and_consume(&token).is_err(),
            "已用尽的 token 重启后仍然是已用尽"
        );
    }

    #[test]
    fn 明文不落盘() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        let mut store = TokenStore::load(&path).expect("加载");
        let token = store.create("phone", 1).expect("创建");
        let text = std::fs::read_to_string(&path).expect("读取");
        assert!(!text.contains(&token), "落盘文件不应包含 token 明文");
        assert!(text.contains(&hash_token(&token)), "应包含摘要");
    }

    #[test]
    fn 非法形态的_token_直接拒绝且不消耗次数() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        let mut store = TokenStore::load(&path).expect("加载");
        let token = store.create("phone", 1).expect("创建");

        for malformed in ["", "zz", &"g".repeat(TOKEN_HEX_LEN), &"a".repeat(31)] {
            assert!(
                store.verify_and_consume(malformed).is_err(),
                "非法 token 应拒绝：{malformed}"
            );
        }
        // 非法尝试不能吃掉合法 token 的次数
        store.verify_and_consume(&token).expect("合法 token 仍可用");
    }

    #[test]
    fn 未知_token_报无效() {
        let dir = tempfile::tempdir().expect("临时目录");
        let mut store = TokenStore::load(&dir.path().join("tokens.json")).expect("加载");
        store.create("phone", 1).expect("创建");
        let err = store
            .verify_and_consume(&generate_token())
            .expect_err("未知 token 应失败");
        assert!(err.to_string().contains("invalid-token"), "{err}");
    }

    #[test]
    fn 空标签与零次数拒绝创建() {
        let dir = tempfile::tempdir().expect("临时目录");
        let mut store = TokenStore::load(&dir.path().join("tokens.json")).expect("加载");
        assert!(store.create("   ", 1).is_err());
        assert!(store.create("phone", 0).is_err());
        assert!(store.is_empty(), "失败创建不应留下记录");
    }

    #[test]
    fn 损坏的_token_表显性失败() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        std::fs::write(&path, "[]").expect("写坏文件");
        let err = TokenStore::load(&path).expect_err("应报错");
        assert!(err.to_string().contains("tokens.json"), "{err}");
    }

    #[test]
    fn 重复摘要或零次数的手改记录被拒绝() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tokens.json");
        let record = TokenRecord {
            label: "x".into(),
            sha256: "ab".repeat(32),
            created_at_unix: 0,
            max_uses: 1,
            uses: 0,
        };
        let file = TokenFile {
            tokens: vec![record.clone(), record],
        };
        std::fs::write(&path, serde_json::to_vec(&file).expect("序列化")).expect("写文件");
        let err = TokenStore::load(&path).expect_err("重复摘要应拒绝");
        assert!(err.to_string().contains("重复"), "{err}");
    }

    #[test]
    fn 概览只含标签与用量() {
        let dir = tempfile::tempdir().expect("临时目录");
        let mut store = TokenStore::load(&dir.path().join("tokens.json")).expect("加载");
        let token = store.create("phone", 2).expect("创建");
        store.verify_and_consume(&token).expect("兑换");
        assert_eq!(store.summary(), vec![("phone".to_string(), 1, 2)]);
        assert_eq!(store.len(), 1);
    }
}
