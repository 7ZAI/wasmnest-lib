//! 准入模式：`open`（默认）与 `allowlist`。
//!
//! **relay 不是授权点**：这里的白名单只防滥用（别人蹭你的带宽），不表达「哪些
//! 设备可以访问哪台桌面」——那件事的权威在目标宿主的配对校验。因此：
//!
//! - `open`：任何人可预留 + 配额兜底，是自建 relay 的默认上手形态；
//! - `allowlist`：只有静态白名单或已兑换 enrollment token 的 PeerId 能预留/开
//!   circuit，其余 peer 的请求被静默拒绝并计入指标（`rejected{reservation-denied}`）。
//!
//! 拒绝发生在 relay 行为面的限量器里而不是连接层：被拒的 peer 仍能连上来走控制
//! 协议兑换 token，兑换成功后立刻可预留——否则 token 永远用不上（先有鸡还是先有蛋）。

use std::{
    collections::BTreeSet,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Instant,
};

use libp2p::{multiaddr::Multiaddr, relay::RateLimiter, PeerId};
use serde::{Deserialize, Serialize};

use crate::{
    error::{RelayError, Result},
    fsutil,
};

/// 准入模式
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessMode {
    /// 开放（默认）：所有人可预留，靠配额防滥用
    #[default]
    Open,
    /// 白名单：只认静态白名单 + 已 enrollment 的 peer
    Allowlist,
}

impl AccessMode {
    /// 对外字符串（配置 / 指标 / 控制协议共用同一词汇）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Allowlist => "allowlist",
        }
    }
}

impl FromStr for AccessMode {
    type Err = RelayError;

    fn from_str(text: &str) -> Result<Self> {
        match text {
            "open" => Ok(Self::Open),
            "allowlist" => Ok(Self::Allowlist),
            other => Err(RelayError::args(format!(
                "未知准入模式 `{other}`（只认 open / allowlist）"
            ))),
        }
    }
}

/// enrollment 白名单落盘格式
#[derive(Debug, Default, Serialize, Deserialize)]
struct PeersFile {
    /// 已 enrollment 的 PeerId（base58）
    peers: Vec<String>,
}

/// 准入判定 + enrollment 持久化
///
/// 进程内共享（swarm 限量器与控制协议任务共用同一份集合）：enrollment 成功后
/// 下一条 reservation 立刻生效，无需重启。
#[derive(Debug, Clone)]
pub struct AllowedPeers {
    mode: AccessMode,
    peers: Arc<RwLock<BTreeSet<PeerId>>>,
    store: Option<PathBuf>,
}

impl AllowedPeers {
    /// 新建：静态白名单 ∪ 已落盘集合
    pub fn new(
        mode: AccessMode,
        seeded: impl IntoIterator<Item = PeerId>,
        store: Option<PathBuf>,
    ) -> Result<Self> {
        let mut peers: BTreeSet<PeerId> = seeded.into_iter().collect();
        if let Some(path) = &store {
            peers.extend(load_store(path)?);
        }
        Ok(Self {
            mode,
            peers: Arc::new(RwLock::new(peers)),
            store,
        })
    }

    /// 当前模式
    pub fn mode(&self) -> AccessMode {
        self.mode
    }

    /// 该 peer 是否可预留 / 开 circuit
    pub fn admits(&self, peer: &PeerId) -> bool {
        match self.mode {
            AccessMode::Open => true,
            AccessMode::Allowlist => self.contains(peer),
        }
    }

    /// 是否在集合内（与模式无关；`open` 模式下用于控制协议回报）
    pub fn contains(&self, peer: &PeerId) -> bool {
        self.read().contains(peer)
    }

    /// 当前集合快照（指标 / 自检用）
    pub fn snapshot(&self) -> Vec<PeerId> {
        self.read().iter().copied().collect()
    }

    /// enrollment：把 peer 加入集合并落盘
    ///
    /// 返回 `true` 表示新加入、`false` 表示已在集合内（幂等）。落盘失败会回滚内存改动：
    /// 不落盘的 enrollment 在重启后失效，等于骗客户端「已开通」。
    pub fn enroll(&self, peer: PeerId) -> Result<bool> {
        let newly = {
            let mut peers = self.write();
            peers.insert(peer)
        };
        if !newly {
            return Ok(false);
        }
        if let Some(path) = &self.store {
            if let Err(err) = persist_store(path, &self.snapshot()) {
                self.write().remove(&peer);
                return Err(err);
            }
        }
        Ok(true)
    }

    /// 生成 relay 限量器（reservation 与 circuit 各一个，共享同一份集合）
    pub fn limiters(&self) -> (AccessLimiter, AccessLimiter) {
        (
            AccessLimiter {
                mode: self.mode,
                peers: Arc::clone(&self.peers),
            },
            AccessLimiter {
                mode: self.mode,
                peers: Arc::clone(&self.peers),
            },
        )
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<PeerId>> {
        self.peers.read().expect("准入集合锁中毒")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeSet<PeerId>> {
        self.peers.write().expect("准入集合锁中毒")
    }
}

/// `libp2p-relay` 限量器：按准入模式放行 reservation / circuit
///
/// 用限量器而不是连接层拦截的原因见模块头注（enrollment 需要一个可连的控制面）。
pub struct AccessLimiter {
    mode: AccessMode,
    peers: Arc<RwLock<BTreeSet<PeerId>>>,
}

impl RateLimiter for AccessLimiter {
    fn try_next(&mut self, peer: PeerId, _addr: &Multiaddr, _now: Instant) -> bool {
        match self.mode {
            AccessMode::Open => true,
            // 注意：`Instant` 在非 wasm 目标上就是 `std::time::Instant`
            //（`web_time` 对 native 目标直接 re-export std），故此处无需额外依赖。
            AccessMode::Allowlist => self.peers.read().expect("准入集合锁中毒").contains(&peer),
        }
    }
}

fn load_store(path: &PathBuf) -> Result<Vec<PeerId>> {
    if !fsutil::exists(path) {
        // 还没 enrollment 过任何 peer：空集合是合法初始态，不是错误
        return Ok(Vec::new());
    }
    let text = fsutil::read_to_string(path)?;
    let file: PeersFile = serde_json::from_str(&text).map_err(|source| RelayError::JsonParse {
        path: path.display().to_string(),
        source,
    })?;
    file.peers
        .iter()
        .map(|text| {
            PeerId::from_str(text.trim()).map_err(|e| {
                RelayError::config(format!(
                    "{} 中的 PeerId 非法（{text}）：{e}；该文件由 enrollment 生成，\
                     手改后请修正或删除（删除 = 清空白名单，仅影响 allowlist 模式）",
                    path.display()
                ))
            })
        })
        .collect()
}

fn persist_store(path: &PathBuf, peers: &[PeerId]) -> Result<()> {
    let file = PeersFile {
        peers: peers.iter().map(|p| p.to_base58()).collect(),
    };
    let body = serde_json::to_vec_pretty(&file)?;
    fsutil::write_atomic(path, &body, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn limiter_admits(limiter: &mut AccessLimiter, peer: PeerId) -> bool {
        limiter.try_next(peer, &Multiaddr::empty(), Instant::now())
    }

    #[test]
    fn 开放模式放行任意_peer() {
        let allowed = AllowedPeers::new(AccessMode::Open, [], None).expect("构造");
        let (mut reservation, mut circuit) = allowed.limiters();
        assert!(limiter_admits(&mut reservation, peer()));
        assert!(limiter_admits(&mut circuit, peer()));
        assert!(allowed.admits(&peer()));
    }

    #[test]
    fn 白名单模式拒绝未登记_peer_放行已登记_peer() {
        let allowed_peer = peer();
        let denied = peer();
        let allowed = AllowedPeers::new(AccessMode::Allowlist, [allowed_peer], None).expect("构造");
        let (mut reservation, mut circuit) = allowed.limiters();

        assert!(limiter_admits(&mut reservation, allowed_peer));
        assert!(limiter_admits(&mut circuit, allowed_peer));
        assert!(!limiter_admits(&mut reservation, denied));
        assert!(!limiter_admits(&mut circuit, denied));
        assert!(!allowed.admits(&denied));
    }

    #[test]
    fn enrollment_立即对限量器生效() {
        let allowed = AllowedPeers::new(AccessMode::Allowlist, [], None).expect("构造");
        let (mut reservation, _circuit) = allowed.limiters();
        let target = peer();

        assert!(!limiter_admits(&mut reservation, target), "兑换前应拒绝");
        assert!(allowed.enroll(target).expect("enroll"));
        assert!(limiter_admits(&mut reservation, target), "兑换后立即可预留");
    }

    #[test]
    fn enrollment_落盘并在重启后仍生效() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = dir.path().join("enrolled-peers.json");
        let target = peer();

        let allowed =
            AllowedPeers::new(AccessMode::Allowlist, [], Some(store.clone())).expect("构造");
        assert!(allowed.enroll(target).expect("enroll"));
        assert!(store.exists(), "应落盘");

        // 模拟重启：重新从磁盘加载（静态白名单为空）
        let reloaded = AllowedPeers::new(AccessMode::Allowlist, [], Some(store)).expect("重新加载");
        assert!(reloaded.contains(&target), "重启后白名单应仍在");
        assert!(reloaded.admits(&target));
    }

    #[test]
    fn 重复_enrollment_幂等且不改写文件() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = dir.path().join("enrolled-peers.json");
        let allowed =
            AllowedPeers::new(AccessMode::Allowlist, [], Some(store.clone())).expect("构造");
        let target = peer();

        assert!(allowed.enroll(target).expect("首次"));
        let first_write = std::fs::metadata(&store)
            .expect("元数据")
            .modified()
            .expect("修改时间");
        assert!(!allowed.enroll(target).expect("重复"), "重复应返回 false");
        let second_write = std::fs::metadata(&store)
            .expect("元数据")
            .modified()
            .expect("修改时间");
        assert_eq!(first_write, second_write, "重复 enrollment 不应重写文件");
    }

    #[test]
    fn 静态白名单与落盘集合合并去重() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = dir.path().join("enrolled-peers.json");
        let static_peer = peer();
        let enrolled_peer = peer();

        let first = AllowedPeers::new(AccessMode::Allowlist, [static_peer], Some(store.clone()))
            .expect("构造");
        first.enroll(enrolled_peer).expect("enroll");

        let merged =
            AllowedPeers::new(AccessMode::Allowlist, [static_peer], Some(store)).expect("重新加载");
        let snapshot = merged.snapshot();
        assert_eq!(snapshot.len(), 2, "应合并去重：{snapshot:?}");
        assert!(merged.contains(&static_peer));
        assert!(merged.contains(&enrolled_peer));
    }

    #[test]
    fn 落盘文件损坏显性失败而不是清空白名单() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = dir.path().join("enrolled-peers.json");
        std::fs::write(&store, "{ not json").expect("写坏文件");
        let err =
            AllowedPeers::new(AccessMode::Allowlist, [], Some(store)).expect_err("损坏文件应报错");
        assert!(err.to_string().contains("enrolled-peers.json"), "{err}");
    }

    #[test]
    fn 模式字符串与配置词表一致() {
        assert_eq!(AccessMode::Open.as_str(), "open");
        assert_eq!(AccessMode::Allowlist.as_str(), "allowlist");
        assert_eq!(
            AccessMode::from_str("allowlist").expect("解析"),
            AccessMode::Allowlist
        );
        assert!(AccessMode::from_str("private").is_err());
    }
}
