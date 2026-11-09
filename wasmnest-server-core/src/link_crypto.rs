//! Link Crypto — 局域网链路报文加密（HTTP/WS 载荷）
//!
//! 规划文档：`.scratch/http-ws-payload-encryption/spec.md`。本模块是链路加密的
//! 宿主侧协议与执行中心，职责四块：
//!
//! 1. **应用策略域**（`APP_POLICIES`）：策略属于应用（plugin id），每个应用一个值
//!    （`off` / `preferred` / `required`），覆盖该应用全部 HTTP / WS 端点。应用
//!    在自己的设置页决定并经 app 通道令牌写入；宿主不设整机下限、不提供开关，
//!    未登记 = `off`（不要求加密，默认明文）。持久化于 DB settings 表 [`APP_POLICY_SETTING_KEY`]，
//!    仅供宿主重启后继续执行。
//! 2. **身份密钥 Kd** [`LinkIdentity`]：桌面端静态 X25519 密钥对，首启生成、
//!   落盘 `app_data_dir/link_crypto_identity.json`（与 peer-net node_identity.json
//!   同目录同模式）；指纹 = SHA-256(公钥) 前 16 hex，供移动端 pin 与人工核对。
//!   已存在但损坏时拒绝重建而非静默换钥——静默换钥会让移动端 pin 全部失效，
//!   与 peer-net 身份决策 D3 同理。
//! 3. **HKDF 方向分离派生**：ECDH 共享密钥 → 各方向独立 AES-256 会话密钥，
//!    info 常量是跨端兼容性表面（移动端 TS 实现必须逐字节一致）。
//! 4. **过滤器骨架** [`LinkEncryptionFilter`]：注册进 `TrafficFilterChain` 的
//!    转换型过滤器。本地豁免三分支与应用策略判定已完整实现；豁免外流量的
//!    真实加解密由 issue 02（HTTP 信封）/ issue 04（WS 帧）在本模块填充。
//!
//! 决策模型（spec §6）：应用声明自己的加密要求 → 接收方按线上信封自动识别 →
//! 响应绑定与降级检测两条强制安全耦合在 issue 02/04 落地。

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
#[cfg(test)]
use wasmnest_server_base::face::RequestFace;

use wasmnest_crypto_engine::provider::{
    AeadProvider, KdfProvider, KeyAgreementProvider, AEAD_AES_256_GCM, KDF_HKDF_SHA256, KEY_AGREEMENT_X25519,
};
use wasmnest_crypto_engine::registry::{resolve_aead, resolve_kdf, resolve_key_agreement};

use crate::filter::{Direction, FilterContext, TrafficChannel, TrafficFilter, TrafficFilterChain, Verdict};
use wasmnest_server_base::error::{AppError, Result};

// ==================== 错误边界映射（2026-11-08，P0 默认形态依赖边界） ====================
//
// `wasmnest-server-base` 不再为 `LinkCryptoError` / `CryptoError` 提供 `From` impl
// （那两条边把 link-crypto 与 crypto-engine 的归属钉在了地基层）。映射改在本边界显式
// 完成——**文案逐字不变**：`LinkCryptoError` 与 `CryptoError` 的 `Display` 已是旧文案
// 原文，映射后由 `AppError` 变体前缀补回 `Invalid input:` / `Internal error:`。
//
// 分派判据按**变体语义**而非字符串匹配：输入非法（密钥 / nonce 长度、未知算法、
// 其它非法输入）→ `InvalidInput`；算法执行失败 → `Internal`。

/// `CryptoError` → `AppError`（按变体语义分派）
fn crypto_to_app_error(err: wasmnest_crypto_engine::CryptoError) -> AppError {
    if err.is_invalid_input() {
        AppError::InvalidInput(err.detail().to_string())
    } else {
        AppError::Internal(err.detail().to_string())
    }
}

/// `LinkCryptoError` → `AppError::Internal`（协议核心错误一律视为内部失败，文案不变）
fn link_crypto_to_app_error(err: wasmnest_link_crypto::LinkCryptoError) -> AppError {
    AppError::Internal(err.to_string())
}

/// rusqlite 错误 → `AppError::Database`（`Database` 不再携带 `rusqlite::Error`）
fn db_error(err: rusqlite::Error) -> AppError {
    AppError::Database(err.to_string())
}

// ==================== 引擎注册表抽象（票 02：WS/HTTP 只留加密抽象层） ====================
// 生产运行时路径的算法调用一律经 crypto 引擎注册表按名解析，模块不再直接依赖具体
// 算法实现。先解析为模块级 lazy 引用，避免逐帧重复查表。
// 数据面固定选 AES-256-GCM / HKDF-SHA256 / X25519（与移动端线协议金样一致）；
// 协商套件参数化（票 05）将把这里涉及的算法名提升为可注入。
/// 数据面 AEAD：AES-256-GCM（应用内兔取模块级引用，避免逐帧查注册表）
static DATA_AEAD: LazyLock<&'static dyn AeadProvider> =
    LazyLock::new(|| resolve_aead(AEAD_AES_256_GCM).expect("crypto engine 必须注册 aes-256-gcm"));
/// 数据面 KDF：HKDF-SHA256
static DATA_KDF: LazyLock<&'static dyn KdfProvider> =
    LazyLock::new(|| resolve_kdf(KDF_HKDF_SHA256).expect("crypto engine 必须注册 hkdf-sha256"));
/// 数据面密钥交换：X25519（HTTP 入站 ECDH 共享密钥）
static DATA_ECDH: LazyLock<&'static dyn KeyAgreementProvider> =
    LazyLock::new(|| resolve_key_agreement(KEY_AGREEMENT_X25519).expect("crypto engine 必须注册 x25519"));

// ==================== 协议核心再导出（issue 09 共享 crate） ====================
// 字节级协议面已抽至 packages/link-crypto（桌面 server 与移动端 event WS
// 共同消费，消除第三份实现）；此处保持既有模块路径与测试可见性不变。
use wasmnest_link_crypto as proto;

pub use proto::{
    b64_decode, b64_encode, coded_reason, decrypt_http_body, encrypt_http_body, generate_ephemeral, parse_negotiation,
    reason_code, ClientWsCrypto, HttpEnvelope, WsDirectionCipher, WsTextEnvelope, CODE_ENCRYPTION_REQUIRED,
    CODE_ENCRYPTION_UNSUPPORTED, ERROR_HEADER, HTTP_INFO_REQUEST, HTTP_INFO_RESPONSE, NEGOTIATION_HEADER,
    ORIGIN_BINARY, ORIGIN_TEXT, PROTOCOL_VERSION, REJECTION_CODES, WS_BINARY_HEADER_LEN, WS_FRAME_VERSION,
    WS_INFO_CLIENT_TO_SERVER, WS_INFO_SERVER_TO_CLIENT, WS_PLUGIN_CHANNEL, WS_POLICY_HEADER, WS_TRANSCRIPT_PREFIX,
};

// ==================== 常量 ====================

/// 身份密钥落盘文件名（与 node_identity.json 并列同目录）
const IDENTITY_FILE: &str = "link_crypto_identity.json";

/// 身份文件格式版本：密钥语义变化时递增并走迁移/拒绝路径
const IDENTITY_FORMAT_VERSION: u32 = 1;

/// 过滤器注册名（注销与日志定位用）
pub const FILTER_NAME: &str = "link-crypto";

// HKDF info 常量——协议兼容性表面，issue 05 移动端 TS 实现必须逐字节一致
// （已抽至共享 crate，经上方 pub use 保持既有路径可见）

// ==================== 应用链路加密策略（应用拥有，宿主只执行） ====================
//
// 归属（2026-11-04 用户裁决，修正 2026-11-02 的宿主 floor 方案）：
// - **策略属于应用**：每个 plugin id 一个值（off / preferred / required），覆盖该
//   应用注册的全部 HTTP / WS 端点。应用在自己的设置页决定，经 app 通道令牌写入；
// - **宿主不设下限、不提供开关**：本模块只保存应用声明的当前值并交给过滤链执行；
//   未登记 = `off`（不要求加密，默认明文）。宿主设置页只读审计，不提供任何写入口；
// - **没有端点级声明**：同一应用的所有端点共用应用策略。若将来出现单端点例外，
//   仍由应用侧声明，宿主不做策略决策。
//
// 身份真源：`owner` 只来自端点注册表（HTTP 注册记录 / WS 端点表），过滤器不解析
// URL 猜属主，也不接受请求方自报。

/// 链路加密严格度（应用策略词表）
///
/// serde 只认小写字面量，未知取值解析失败——写错一个字母不允许静默当成明文。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionPolicy {
    /// 不要求加密：默认明文；客户端自愿加密时仍解密/回密（不是「禁止加密」）
    Off,
    /// 机会主义：对端支持就加密，不支持就放行明文（永不拒绝）
    Preferred,
    /// 强制：非环回对端没有有效协商/会话密钥 → 拒绝（fail-visible）
    Required,
}

impl EncryptionPolicy {
    /// 稳定字面量（日志 / 错误文案 / 设置页 wire 形状）
    pub fn as_str(self) -> &'static str {
        match self {
            EncryptionPolicy::Off => "off",
            EncryptionPolicy::Preferred => "preferred",
            EncryptionPolicy::Required => "required",
        }
    }

    /// 严格解析：只接受三个合法取值，未知取值点名合法取值后报错
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim() {
            "off" => Ok(EncryptionPolicy::Off),
            "preferred" => Ok(EncryptionPolicy::Preferred),
            "required" => Ok(EncryptionPolicy::Required),
            other => Err(AppError::InvalidInput(format!(
                "unknown encryption policy '{other}' (expected one of: off, preferred, required)"
            ))),
        }
    }

    /// 允许明文对端（`required` 不允许）
    pub fn allows_plaintext(self) -> bool {
        self != EncryptionPolicy::Required
    }
}

impl std::fmt::Display for EncryptionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DB settings 表中的应用策略键：JSON 对象 `{ "<plugin id>": "<policy>" }`
///
/// 旧 `trafficEncryption`（宿主 floor）记录不再读取，保留在库里不迁移——研发期
/// 直接换语义，避免把旧的整机下限静默翻译成某个应用的策略。
pub const APP_POLICY_SETTING_KEY: &str = "linkCryptoAppPolicies";

/// 应用策略表：plugin id → 策略（未登记 = `off`：不要求加密）
///
/// 宿主只保存应用声明的当前值（执行所需事实）；持久化同样只是让策略在宿主重启后
/// 继续生效，决策权仍在应用。应用卸载不主动删（同 id 重装沿用用户选择；无端点时
/// 不影响任何流量）。
static APP_POLICIES: LazyLock<RwLock<HashMap<String, EncryptionPolicy>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn policy_lock() -> std::sync::RwLockReadGuard<'static, HashMap<String, EncryptionPolicy>> {
    APP_POLICIES.read().unwrap_or_else(|e| e.into_inner())
}

/// 应用当前策略（未登记 / 空 owner = `off`）
pub fn app_policy(owner: &str) -> EncryptionPolicy {
    if owner.is_empty() {
        return EncryptionPolicy::Off;
    }
    policy_lock().get(owner).copied().unwrap_or(EncryptionPolicy::Off)
}

/// 策略合法性判据（纯函数：身份可用性由调用方给，便于逐条单测）
fn validate_app_policy(
    owner: &str,
    policy: EncryptionPolicy,
    identity_available: bool,
) -> std::result::Result<(), String> {
    if owner.trim().is_empty() {
        return Err("app link encryption policy rejected: plugin id must not be empty".to_string());
    }
    if policy == EncryptionPolicy::Required && !identity_available {
        return Err(format!(
            "app link encryption policy 'required' rejected: link identity unavailable on this host, plugin '{owner}' cannot be encrypted"
        ));
    }
    Ok(())
}

/// 写入应用策略（app 通道令牌门之后调用；`owner` 由宿主解析，不接受前端自报）
///
/// `required` 在本进程链路身份不可用时拒绝：否则策略显示 required 却根本无法
/// 加密（fail-visible，不静默降级成明文）。
pub fn set_app_policy(owner: &str, policy: EncryptionPolicy) -> std::result::Result<(), String> {
    validate_app_policy(owner, policy, IDENTITY.get().is_some())?;
    match APP_POLICIES.write() {
        Ok(mut map) => {
            map.insert(owner.to_string(), policy);
        }
        Err(_) => {
            return Err(format!(
                "app link encryption policy registry lock poisoned, plugin '{owner}' policy rejected"
            ))
        }
    }
    sync_registration();
    tracing::info!(plugin_id = %owner, policy = policy.as_str(), "app link encryption policy updated");
    Ok(())
}

/// 移除应用策略（卸载清理 / 测试隔离；未知键幂等）
pub fn remove_app_policy(owner: &str) -> bool {
    let removed = match APP_POLICIES.write() {
        Ok(mut map) => map.remove(owner).is_some(),
        Err(_) => false,
    };
    if removed {
        sync_registration();
        tracing::debug!(plugin_id = %owner, "app link encryption policy removed");
    }
    removed
}

/// 当前应用策略快照（DB 持久化 / 审计；按 plugin id 稳定排序）
pub fn app_policy_snapshot() -> std::collections::BTreeMap<String, EncryptionPolicy> {
    policy_lock()
        .iter()
        .map(|(owner, policy)| (owner.clone(), *policy))
        .collect()
}

/// 一条应用策略记录（宿主设置页只读审计）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPolicyRecord {
    /// 属主插件 id
    pub owner: String,
    /// 应用当前策略（未登记的应用不出现在本表；它们按 `off` 执行）
    pub policy: EncryptionPolicy,
}

/// 已登记的应用策略快照（宿主设置页 / 审计数据源；不含载荷与密钥）
pub fn app_policies() -> Vec<AppPolicyRecord> {
    let mut records: Vec<AppPolicyRecord> = policy_lock()
        .iter()
        .map(|(owner, policy)| AppPolicyRecord {
            owner: owner.clone(),
            policy: *policy,
        })
        .collect();
    records.sort_by(|a, b| a.owner.cmp(&b.owner));
    records
}

/// 从 DB settings 读取应用策略（启动期调用；表缺失 / 键缺失 / 损坏 → 空表 + 日志）
///
/// 逐条严格解析：未知策略值只跳过该条并 error 留痕（绝不把 required 静默当明文），
/// 其余有效条目照常加载。返回成功应用条数。
pub fn load_app_policies_from_db(conn: &rusqlite::Connection) -> usize {
    let json = match conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        rusqlite::params![APP_POLICY_SETTING_KEY],
        |row| row.get::<_, String>(0),
    ) {
        Ok(json) => json,
        Err(_) => return 0, // 首次启动 / 旧库：没有策略记录
    };
    let raw: HashMap<String, serde_json::Value> = match serde_json::from_str(&json) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::error!(
                key = APP_POLICY_SETTING_KEY,
                "app link encryption policies corrupt, no policy loaded this boot: {e}"
            );
            return 0;
        }
    };
    let mut loaded = 0;
    for (owner, value) in raw {
        let Some(text) = value.as_str() else {
            tracing::error!(plugin_id = %owner, "app link encryption policy is not a string, skipped");
            continue;
        };
        match EncryptionPolicy::parse(text) {
            Ok(policy) => match set_app_policy(&owner, policy) {
                Ok(()) => loaded += 1,
                Err(e) => {
                    // 典型：identity 不可用时 required 被拒。运行期按 off 执行，错误可见。
                    tracing::error!(plugin_id = %owner, error = %e, "app link encryption policy could not be applied")
                }
            },
            Err(e) => {
                tracing::error!(plugin_id = %owner, error = %e, "app link encryption policy invalid, skipped")
            }
        }
    }
    loaded
}

/// 持久化应用策略快照（宿主命令先更新运行态，落库失败由调用方回滚运行态）
pub fn persist_app_policies_to_db(
    conn: &rusqlite::Connection,
    policies: &std::collections::BTreeMap<String, EncryptionPolicy>,
) -> Result<()> {
    let json = serde_json::to_string(policies)?;
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![APP_POLICY_SETTING_KEY, json, now],
    )
    .map_err(db_error)?;
    Ok(())
}

/// 明文放行审计去重集（键 = (属主, 端点句柄)）
///
/// 审计要回答「哪些端点真的在被明文使用」，而不是逐请求刷日志：同一端点只记首次。
/// 集合有上限：端点数量本身受注册表上限约束，这里再兜一层，避免长期运行被
/// 「装/卸循环」产生的旧句柄撑大内存（超限后只放弃审计新端点，不影响裁决）。
const PLAINTEXT_AUDIT_CAP: usize = 1024;
static PLAINTEXT_AUDITED: LazyLock<RwLock<HashSet<(String, String)>>> = LazyLock::new(|| RwLock::new(HashSet::new()));

/// 记录一次明文放行；返回 true = 该端点首次（调用方据此记 info 审计日志）
pub fn note_plaintext_connection(owner: &str, endpoint: &str) -> bool {
    if owner.is_empty() || endpoint.is_empty() {
        return false;
    }
    let Ok(mut seen) = PLAINTEXT_AUDITED.write() else {
        return false;
    };
    let key = (owner.to_string(), endpoint.to_string());
    if seen.contains(&key) || seen.len() >= PLAINTEXT_AUDIT_CAP {
        return false;
    }
    seen.insert(key);
    true
}

/// 测试用：清空明文审计去重集
#[cfg(test)]
fn reset_plaintext_audit() {
    if let Ok(mut seen) = PLAINTEXT_AUDITED.write() {
        seen.clear();
    }
}

/// 能力查询（宿主 → 应用前端，只读）：应用在声明 `required` 前必须能确认本端
/// 支持按应用策略与对应密钥模型；旧宿主不支持时应用必须拒绝启用该业务。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkCryptoCapabilities {
    /// 是否支持按应用设置策略（本版恒 true；旧宿主缺此字段）
    pub app_scoped_policy: bool,
    /// 策略可取的全部取值（wire 字面量）
    pub policies: Vec<&'static str>,
    /// 链路身份指纹（未初始化 = None，此时 `required` 会被拒绝）
    pub identity_fingerprint: Option<String>,
    /// 可用密钥模型（配对设备的 HTTP 路径绑定）
    pub key_models: Vec<&'static str>,
    /// WS 帧级链路加密是否可用
    ///
    /// 自 2026-11-04 起为 `true`：升级期头协商（客户端提案 + 101 策略/密钥回执）
    /// 已接线，`required` 不再拒绝所有 WS 客户端。
    pub ws_session: bool,
}

/// 本进程的链路加密能力快照
pub fn capabilities() -> LinkCryptoCapabilities {
    LinkCryptoCapabilities {
        app_scoped_policy: true,
        policies: vec![
            EncryptionPolicy::Required.as_str(),
            EncryptionPolicy::Preferred.as_str(),
            EncryptionPolicy::Off.as_str(),
        ],
        identity_fingerprint: identity_fingerprint().map(|fp| fp.to_string()),
        key_models: vec!["paired-http-path-bound"],
        ws_session: true,
    }
}

// ==================== 身份密钥 Kd ====================

/// 身份密钥落盘结构
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    x25519_private_hex: String,
}

/// 桌面端链路加密静态身份密钥（X25519）
///
/// 手写 Debug：只暴露指纹，私钥材料绝不进日志/调试输出。
pub struct LinkIdentity {
    keypair: wasmnest_crypto_engine::x25519::X25519KeyPair,
    fingerprint: String,
}

impl std::fmt::Debug for LinkIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl LinkIdentity {
    /// 加载或生成身份密钥：
    /// - 目录下无文件 → 原子创建新密钥对并落盘（首次启动）；
    /// - 文件已存在（含并发首启的输家）→ 加载既有身份（弃用本次生成）；
    /// - 文件存在且损坏/版本不符 → 报错拒绝重建：静默换钥会让移动端 pin 全部
    ///   失效，宁可本次启动禁用加密并由用户显式处理。
    ///
    /// 生成路径先写同目录唯一 tmp，再 `hard_link` 发布到正式名（目标已存在即失败）：
    /// 并发的两个首启不会各写一份不同密钥（后到者回退加载既有身份，内存指纹与磁盘
    /// 密钥始终一致），读者也永远看不到半截 JSON（进程中途被杀只留下 tmp）。
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let path = dir.join(IDENTITY_FILE);
        if path.exists() {
            return Self::load(&path);
        }

        let keypair = wasmnest_crypto_engine::x25519::x25519_generate();
        let file = IdentityFile {
            version: IDENTITY_FORMAT_VERSION,
            x25519_private_hex: hex::encode(keypair.private()),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| AppError::Internal(format!("serialize link identity failed: {e}")))?;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let tmp = path.with_extension(format!("{}.{nanos}.tmp", std::process::id()));

        use std::io::Write;
        let mut opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| AppError::Internal(format!("create {}: {e}", tmp.display())))?;
        // 私钥文件限属主可读（与 peer-net 身份文件同模式）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            opened
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| AppError::Internal(format!("chmod {}: {e}", tmp.display())))?;
        }
        let written = opened
            .write_all(json.as_bytes())
            .and_then(|_| opened.sync_all())
            .map_err(|e| AppError::Internal(format!("write {}: {e}", tmp.display())));
        drop(opened);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }

        let published = match std::fs::hard_link(&tmp, &path) {
            Ok(()) => Ok(true),
            // 并发初始化已有人写盘：加载既有身份，丢弃本次生成
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(AppError::Internal(format!("publish {}: {e}", path.display()))),
        };
        let _ = std::fs::remove_file(&tmp);
        if !published? {
            return Self::load(&path);
        }
        tracing::info!(file = %path.display(), "link crypto identity generated");
        Self::from_keypair(keypair)
    }

    fn load(path: &Path) -> Result<Self> {
        let json =
            std::fs::read_to_string(path).map_err(|e| AppError::Internal(format!("read {}: {e}", path.display())))?;
        let file: IdentityFile = serde_json::from_str(&json).map_err(|e| {
            AppError::Internal(format!(
                "link identity {} is corrupt, refusing to regenerate (pins would break): {e}",
                path.display()
            ))
        })?;
        if file.version != IDENTITY_FORMAT_VERSION {
            return Err(AppError::Internal(format!(
                "link identity version mismatch: file v{}, expected v{}",
                file.version, IDENTITY_FORMAT_VERSION
            )));
        }
        let mut private = [0u8; wasmnest_crypto_engine::x25519::KEY_LEN];
        hex::decode_to_slice(&file.x25519_private_hex, &mut private)
            .map_err(|e| AppError::Internal(format!("link identity private key invalid hex: {e}")))?;
        let keypair = wasmnest_crypto_engine::x25519::X25519KeyPair::from_private(&private);
        Self::from_keypair(keypair)
    }

    fn from_keypair(keypair: wasmnest_crypto_engine::x25519::X25519KeyPair) -> Result<Self> {
        // 指纹先于 move 计算：keypair 随结构体构造被消费
        let fingerprint = fingerprint_of(keypair.public());
        Ok(Self { keypair, fingerprint })
    }

    /// 公钥（base64，配对响应下发用，issue 03 消费）
    pub fn public_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.keypair.public())
    }

    /// 私钥引用（请求解密 / WS 派生用，issue 02/04 消费）
    pub(crate) fn keypair(&self) -> &wasmnest_crypto_engine::x25519::X25519KeyPair {
        &self.keypair
    }

    /// 指纹：SHA-256(公钥) 前 16 hex 小写，设置页展示 + 移动端 pin 展示比对
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// 公钥指纹：SHA-256 前 16 hex 小写（实现在共享 crate）
fn fingerprint_of(public: &[u8; 32]) -> String {
    proto::fingerprint_of(public)
}

static IDENTITY: OnceLock<LinkIdentity> = OnceLock::new();

/// 进程内初始化身份密钥（幂等：已初始化则直接返回现有指纹）
///
/// 启动装配与命令懒初始化共用入口；失败不 panic——调用方记 error 后按
/// 「本进程加密不可用」处理（配置强制回退全关）。
pub fn init_identity(dir: &Path) -> Result<&'static str> {
    if let Some(existing) = IDENTITY.get() {
        return Ok(existing.fingerprint());
    }
    let identity = LinkIdentity::load_or_create(dir)?;
    // 竞争失败说明并发初始化已成功，取既有实例即可（两者内容一致：
    // load_or_create 对同一文件是确定性的）；set 成功后 get 必为 Some，
    // 理论不可达的 None 以显式错误收口（不得引用局部值充当 'static）
    let _ = IDENTITY.set(identity);
    IDENTITY
        .get()
        .map(|i| i.fingerprint())
        .ok_or_else(|| AppError::Internal("link identity registration lost".to_string()))
}

/// 已初始化的身份指纹（未初始化返回 None，命令层负责懒初始化）
pub fn identity_fingerprint() -> Option<&'static str> {
    IDENTITY.get().map(|i| i.fingerprint())
}

/// 身份密钥访问（03 下发公钥 / 测试消费）；未初始化返回 None
pub fn identity_parts() -> Option<(&'static str, String)> {
    IDENTITY.get().map(|i| (i.fingerprint(), i.public_b64()))
}

/// 身份私钥访问（02/04 内部派生用；未初始化返回 None，调用方 fail-closed）
#[allow(dead_code)] // 预留：ADR 02/04 内部派生路径尚未接入
pub(crate) fn identity_keypair() -> Option<&'static wasmnest_crypto_engine::x25519::X25519KeyPair> {
    IDENTITY.get().map(|i| i.keypair())
}

// ==================== HKDF 方向分离派生 ====================

/// HTTP 单发加密的两方向会话密钥
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTrafficKeys {
    /// 请求体加密密钥（发送方→桌面端）
    pub request: [u8; 32],
    /// 响应体加密密钥（桌面端→发送方），与请求密钥密码学隔离
    pub response: [u8; 32],
}

/// 由 ECDH 共享密钥派生 HTTP 两方向密钥
///
/// salt = 请求路径 ASCII 字节（路径绑定，防信封跨端点搬运）；
/// info 区分方向（request ≠ response，单向泄露不波及另一向）。
pub fn derive_http_traffic_keys(shared_ikm: &[u8], http_path: &str) -> Result<HttpTrafficKeys> {
    let salt = http_path.as_bytes();
    let req = DATA_KDF
        .derive(Some(salt), shared_ikm, HTTP_INFO_REQUEST, 32)
        .map_err(crypto_to_app_error)?;
    let resp = DATA_KDF
        .derive(Some(salt), shared_ikm, HTTP_INFO_RESPONSE, 32)
        .map_err(crypto_to_app_error)?;
    let to_arr = |v: Vec<u8>| {
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    };
    Ok(HttpTrafficKeys {
        request: to_arr(req),
        response: to_arr(resp),
    })
}

// 派生单个 WS 方向密码上下文（HKDF OKM 36B：32B key + 4B 随机前缀）——
// 实现已抽至共享 crate（proto 内部）；桌面侧经 derive_server_handshake 间接消费
// ==================== WS 会话加密（issue 04） ====================

// WS 帧常量与来源类型字节（WS_BINARY_HEADER_LEN / WS_FRAME_VERSION /
// WS_TRANSCRIPT_PREFIX / ORIGIN_TEXT / ORIGIN_BINARY）已抽至共享 crate，
// 经文件头 `pub use proto::{...}` 保持既有模块路径与测试可见性不变。

// ==================== 链路加密套件（票 05 套件参数化） ====================
// 「套件」= 一组合法的算法组合（密钥交换 + AEAD + KDF），按名字寻址。名字即
// 引擎词汇（三算法名都必须在 crypto/ 注册表白名单内，杜绝随手拼一个不存在的组合）。
// 当前线协议只实现**一套**（X25519 + AES-256-GCM + HKDF-SHA256，与移动端线协议
// 金样逐字节一致）；方案只是把「套件名」变成可注入参数 + 白名单校验，为后续
// 加入新套件留好入口——今天只接受默认名，未知名由宿主显式拒绝（fail-visible），
// 绝不在协商处静默降级到别的套件。

/// 链路加密套件：密钥交换 + AEAD + KDF 三次算法组合（字节级协议面搭档）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSuite {
    /// 稳定谜别名（wire 上承载的协商名）
    pub name: &'static str,
    /// 密钥交换（ECDH）算法名（引擎注册表词表）
    pub key_agreement: &'static str,
    /// AEAD 算法名（引擎注册表词表）
    pub aead: &'static str,
    /// KDF 算法名（引擎注册表词表）
    pub kdf: &'static str,
}

/// 默认套件：X25519 + AES-256-GCM + HKDF-SHA256（与移动端线协议金样一致；
/// 也是协商套件字段缺省时的选择——原 `CryptoProposal.suite` 缺省语义，该
/// wire 定义已随宿主认证 wire 退役删除（enums/auth.rs，2026-09-25），协商方
/// 形状归移动端线协议文档）。
pub const DEFAULT_LINK_SUITE: LinkSuite = LinkSuite {
    name: "x25519+aes-256-gcm+hkdf-sha256",
    key_agreement: KEY_AGREEMENT_X25519,
    aead: AEAD_AES_256_GCM,
    kdf: KDF_HKDF_SHA256,
};

/// 已知套件表（当前仅默认一套；加入新套件在此登记，并实现对应的握手派生）。
const KNOWN_LINK_SUITES: &[LinkSuite] = &[DEFAULT_LINK_SUITE];

/// 解析协商套件：`Some(名)` → 在已知套件表内命中才接受（且三算法名都必须在
/// 引擎白名单内），否则显式拒绝（fail-closed，不静默降级）；`None`（老客户端
/// 不携带）→ 默认套件。返回选中的套件供调用方审计。
pub fn resolve_link_suite(suite: Option<&str>) -> Result<&'static LinkSuite> {
    let name = match suite {
        Some(n) if !n.is_empty() => n,
        // 缺省 / 空串 → 默认套件（老客户端不断流）
        _ => return Ok(&DEFAULT_LINK_SUITE),
    };
    if name == DEFAULT_LINK_SUITE.name {
        return Ok(&DEFAULT_LINK_SUITE);
    }
    // 未知套件名：显式拒绝，绝不静默落到默认套件（协商是安全面，降级即旁路）
    let known = KNOWN_LINK_SUITES.iter().map(|s| s.name).collect::<Vec<_>>().join(", ");
    Err(AppError::InvalidInput(format!(
        "未知链路加密套件: '{name}'（当前支持: {known}）"
    )))
}

/// 单条 `LinkSuite` 选时的算法名都落在引擎注册表白名单（供测试断言
/// 套件与引擎词汇不漂移）。
/// 链路加密套件校验（供测试）：本函数先经引擎注册表解析三算法名，任一名不在
/// 白名单即 panic（套件与引擎词汇漂移应立即暴露）。仅测试使用，非生产路径。
#[cfg(test)]
fn assert_suite_algorithms_registered(s: &LinkSuite) {
    resolve_key_agreement(s.key_agreement).expect("套件密钥交换算法必须在引擎白名单");
    resolve_aead(s.aead).expect("套件 AEAD 算法必须在引擎白名单");
    resolve_kdf(s.kdf).expect("套件 KDF 算法必须在引擎白名单");
}

/// 一条 WS 连接的双向密码状态（服务端视角；发送/接收序号严格单调）
/// WsDirectionCipher 实现在共享 crate（文件头再导出，字段形状不变）；带序号
/// 计数器的 WsSessionCiphers 注册表类型留在桌面侧。
pub struct WsSessionCiphers {
    pub client_to_server: WsDirectionCipher,
    pub server_to_client: WsDirectionCipher,
    s2c_next_seq: u64,
    c2s_expected_seq: u64,
}

/// 握手产物：服务端临时公钥回执 + 注册用双向密码
pub struct WsHandshake {
    pub server_ek_b64: String,
    pub ciphers: WsSessionCiphers,
}

/// 双 ECDH 握手派生（spec §3）：服务端生成新鲜 s_eph，
/// IKM = ECDH(s_eph,m_eph) ‖ ECDH(Kd,m_eph)，salt = "bc-link-crypto/v1" ‖ m_ek_b64 ‖ s_ek_b64。
/// 字节拼接顺序是跨端兼容性表面，issue 05 移动端 TS 必须一致（金样互验钉死）。
/// 公式实现在共享 crate；本函数只负责身份私钥与临时密钥生命周期。
pub fn derive_ws_session_ciphers(client_ek_b64: &str) -> Result<WsHandshake> {
    let Some(identity) = IDENTITY.get() else {
        return Err(AppError::Internal("link identity unavailable".to_string()));
    };
    let (s_ephemeral_private, _s_public_unused) = proto::generate_ephemeral();
    let hs = proto::derive_server_handshake(client_ek_b64, identity.keypair().private(), &s_ephemeral_private)
        .map_err(link_crypto_to_app_error)?;

    Ok(WsHandshake {
        server_ek_b64: hs.server_ek_b64,
        ciphers: WsSessionCiphers {
            client_to_server: hs.client_to_server,
            server_to_client: hs.server_to_client,
            s2c_next_seq: 0,
            c2s_expected_seq: 0,
        },
    })
}

// ---------- 连接密码表（actor 注册 / 过滤器消费，keyed by 对端 addr） ----------

static WS_CIPHERS: LazyLock<Mutex<HashMap<String, WsSessionCiphers>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// 握手完成后注册连接密码（此后该连接所有帧进入加密模式）；重复注册覆盖
pub fn ws_register_ciphers(addr: &str, ciphers: WsSessionCiphers) {
    match WS_CIPHERS.lock() {
        Ok(mut map) => {
            map.insert(addr.to_string(), ciphers);
        }
        Err(_) => {
            tracing::error!(addr, "ws cipher registry lock poisoned, register dropped");
            return;
        }
    }
    // 应用策略可能在同一时刻降到 off：过滤器不能在有活跃密码会话时被摘掉，
    // 否则存量连接的帧会绕过滤链（Race 窗口：协商完成 → 策略切换）。
    sync_registration();
}

/// 断连清理（terminal_ws disconnected 调用）
pub fn ws_remove_ciphers(addr: &str) {
    let removed = match WS_CIPHERS.lock() {
        Ok(mut map) => map.remove(addr).is_some(),
        Err(_) => false,
    };
    if removed {
        // 最后一条密码会话消失后，若所有应用策略都是 off，过滤器可以摘除
        sync_registration();
    }
}

/// 是否有任何连接处于加密会话（过滤器不能把存量密文连接当明文处理）
fn ws_ciphers_present() -> bool {
    WS_CIPHERS.lock().map(|map| !map.is_empty()).unwrap_or(false)
}

/// 连接是否已处于加密模式（过滤器与 Close-4003 判定共用）
pub fn ws_has_ciphers(addr: &str) -> bool {
    WS_CIPHERS.lock().map(|map| map.contains_key(addr)).unwrap_or(false)
}

// nonce/AAD 构造已抽至共享 crate；AAD 的 Direction 经适配器映射
use proto::ws_nonce;

fn ws_aad(channel_str: &str, direction: Direction, origin: u8) -> Vec<u8> {
    proto::ws_aad(
        channel_str,
        match direction {
            Direction::Inbound => proto::Direction::Inbound,
            Direction::Outbound => proto::Direction::Outbound,
        },
        origin,
    )
}

// WS 文本帧信封（WsTextEnvelope）已抽至共享 crate，经文件头 `pub use proto::{...}`
// 保持既有模块路径可见；字段形状逐字节一致。

/// 加密一条出站文本帧（JSON → 信封 JSON 字符串），并推进发送序号
pub(crate) fn ws_encrypt_outbound_text(addr: &str, channel_str: &str, text: &str) -> Result<Vec<u8>> {
    let mut map = WS_CIPHERS
        .lock()
        .map_err(|_| AppError::Internal("ws cipher lock poisoned".into()))?;
    let c = map
        .get_mut(addr)
        .ok_or_else(|| AppError::Internal("no ws cipher for addr".into()))?;
    let seq = c.s2c_next_seq;
    let aad = ws_aad(channel_str, Direction::Outbound, ORIGIN_TEXT);
    let sealed = encrypt_ws_payload(&c.server_to_client, seq, text.as_bytes(), &aad)?;
    c.s2c_next_seq = seq
        .checked_add(1)
        .ok_or_else(|| AppError::Internal("ws seq overflow".into()))?;
    let envelope = WsTextEnvelope {
        v: WS_FRAME_VERSION,
        seq,
        n: b64_encode(&sealed.nonce),
        ct: b64_encode(&sealed.ciphertext),
    };
    Ok(serde_json::to_vec(&envelope)?)
}

/// 解密一条入站文本帧（信封 JSON → 原 JSON 字符串），严格校验接收序号
pub(crate) fn ws_decrypt_inbound_text(addr: &str, channel_str: &str, body: &[u8]) -> Result<String> {
    let envelope: WsTextEnvelope =
        serde_json::from_slice(body).map_err(|e| AppError::Internal(format!("ws text envelope malformed: {e}")))?;
    if envelope.v != WS_FRAME_VERSION {
        return Err(AppError::Internal(format!(
            "unsupported ws frame version {}",
            envelope.v
        )));
    }
    let nonce_v = b64_decode(&envelope.n).map_err(link_crypto_to_app_error)?;
    let nonce: [u8; 12] = nonce_v
        .try_into()
        .map_err(|v: Vec<u8>| AppError::Internal(format!("nonce length mismatch: {}", v.len())))?;
    let ciphertext = b64_decode(&envelope.ct).map_err(link_crypto_to_app_error)?;

    let mut map = WS_CIPHERS
        .lock()
        .map_err(|_| AppError::Internal("ws cipher lock poisoned".into()))?;
    let c = map
        .get_mut(addr)
        .ok_or_else(|| AppError::Internal("no ws cipher for addr".into()))?;
    if envelope.seq != c.c2s_expected_seq {
        return Err(AppError::Internal(format!(
            "ws seq mismatch: expected {}, got {}",
            c.c2s_expected_seq, envelope.seq
        )));
    }
    let plain = DATA_AEAD
        .decrypt(
            &c.client_to_server.key,
            &nonce,
            &ciphertext,
            Some(&ws_aad(channel_str, Direction::Inbound, ORIGIN_TEXT)),
        )
        .map_err(crypto_to_app_error)?;
    c.c2s_expected_seq += 1;
    String::from_utf8(plain).map_err(|e| AppError::Internal(format!("decrypted text not utf-8: {e}")))
}

struct SealedPayload {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

fn encrypt_ws_payload(cipher: &WsDirectionCipher, seq: u64, plaintext: &[u8], aad: &[u8]) -> Result<SealedPayload> {
    let nonce = ws_nonce(&cipher.nonce_prefix, seq);
    let ciphertext = DATA_AEAD
        .encrypt(&cipher.key, &nonce, plaintext, Some(aad))
        .map_err(crypto_to_app_error)?;
    Ok(SealedPayload { nonce, ciphertext })
}

/// 加密一条出站二进制帧（原帧 → ver+seq+ct），并推进发送序号
pub(crate) fn ws_encrypt_outbound_binary(addr: &str, channel_str: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut map = WS_CIPHERS
        .lock()
        .map_err(|_| AppError::Internal("ws cipher lock poisoned".into()))?;
    let c = map
        .get_mut(addr)
        .ok_or_else(|| AppError::Internal("no ws cipher for addr".into()))?;
    let seq = c.s2c_next_seq;
    let aad = ws_aad(channel_str, Direction::Outbound, ORIGIN_BINARY);
    let sealed = encrypt_ws_payload(&c.server_to_client, seq, data, &aad)?;
    c.s2c_next_seq = seq
        .checked_add(1)
        .ok_or_else(|| AppError::Internal("ws seq overflow".into()))?;
    let mut frame = Vec::with_capacity(WS_BINARY_HEADER_LEN + sealed.ciphertext.len());
    frame.push(WS_FRAME_VERSION);
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&sealed.ciphertext);
    Ok(frame)
}

/// 解密一条入站二进制帧（ver+seq+ct → 原帧），严格校验接收序号
pub(crate) fn ws_decrypt_inbound_binary(addr: &str, channel_str: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < WS_BINARY_HEADER_LEN {
        return Err(AppError::Internal(format!("ws binary frame too short: {}", data.len())));
    }
    if data[0] != WS_FRAME_VERSION {
        return Err(AppError::Internal(format!("unsupported ws frame version {}", data[0])));
    }
    let seq = u64::from_be_bytes(data[1..9].try_into().expect("seq slice is 8 bytes"));
    let ciphertext = &data[WS_BINARY_HEADER_LEN..];

    let mut map = WS_CIPHERS
        .lock()
        .map_err(|_| AppError::Internal("ws cipher lock poisoned".into()))?;
    let c = map
        .get_mut(addr)
        .ok_or_else(|| AppError::Internal("no ws cipher for addr".into()))?;
    if seq != c.c2s_expected_seq {
        return Err(AppError::Internal(format!(
            "ws seq mismatch: expected {}, got {}",
            c.c2s_expected_seq, seq
        )));
    }
    let plain = DATA_AEAD
        .decrypt(
            &c.client_to_server.key,
            &ws_nonce(&c.client_to_server.nonce_prefix, seq),
            ciphertext,
            Some(&ws_aad(channel_str, Direction::Inbound, ORIGIN_BINARY)),
        )
        .map_err(crypto_to_app_error)?;
    c.c2s_expected_seq += 1;
    Ok(plain)
}

/// 过滤器统一分发：按帧来源选择文本/二进制编解码路径
fn ws_decrypt_inbound_text_binary(addr: &str, channel_str: &str, origin: u8, data: &[u8]) -> Result<Vec<u8>> {
    if origin == ORIGIN_TEXT {
        ws_decrypt_inbound_text(addr, channel_str, data).map(String::into_bytes)
    } else {
        ws_decrypt_inbound_binary(addr, channel_str, data)
    }
}

fn ws_encrypt_outbound_text_binary(addr: &str, channel_str: &str, origin: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
    if origin == ORIGIN_TEXT {
        let text =
            std::str::from_utf8(plaintext).map_err(|e| AppError::Internal(format!("outbound text not utf-8: {e}")))?;
        ws_encrypt_outbound_text(addr, channel_str, text)
    } else {
        ws_encrypt_outbound_binary(addr, channel_str, plaintext)
    }
}

// ==================== HTTP 信封协议（issue 02） ====================

// 协商信号头与协议版本常量（NEGOTIATION_HEADER / PROTOCOL_VERSION）已抽至
// 共享 crate，经文件头 `pub use proto::{...}` 保持既有模块路径可见。

/// 请求级响应密钥缓存 TTL：同请求出入站间隔毫秒级，30s 已是数百倍冗余
const REQUEST_KEY_TTL: Duration = Duration::from_secs(30);

// HTTP 信封结构与编解码辅助（HttpEnvelope / b64_encode / b64_decode /
// parse_negotiation）已抽至共享 crate，经文件头 `pub use proto::{...}`
// 保持既有模块路径与测试可见性不变（错误转换经 AppError 的 From impl）。

/// HTTP AAD 绑定：b"v1" || direction || u32be(path_len) || path
///
/// 路径绑定防信封跨端点搬运；方向绑定防请求/响应载荷互换重放。
/// 实现在共享 crate，此处仅做 Direction 适配。
fn http_aad(direction: Direction, path: &str) -> Vec<u8> {
    proto::http_aad(
        match direction {
            Direction::Inbound => proto::Direction::Inbound,
            Direction::Outbound => proto::Direction::Outbound,
        },
        path,
    )
}

// 信封编解码（encrypt_http_body / decrypt_http_body）已抽至共享 crate，
// 经文件头 `pub use proto::{...}` 保持既有模块路径与测试可见性不变
//（错误经 AppError 的 From<LinkCryptoError> 自动转换，文案不变）。

// ---------- 请求级响应密钥缓存 ----------
//
// filter 是全局单例、出入站两次独立调用，而响应加密密钥只能从该次请求的
// 临时公钥派生（spec §3 实现要点）。入站成功解密时写入，出站命中即取走，
// 未命中（入站被拒/未协商）→ 响应保持明文。
/// 移动端每请求全新临时密钥对 → (peer, ek) 天然唯一，无并发覆盖问题。
/// 容量护栏：TTL（30s）已收敛缓存规模，但 GET 懒加载高频协商下极端流量仍可
/// 让 map 逼近窗口内唯一 (peer, ek) 数上界之外的增长——超限时逐出最早项
const HTTP_KEY_CACHE_MAX: usize = 1024;

struct CachedHttpKeys {
    keys: HttpTrafficKeys,
    inserted_at: Instant,
}

static HTTP_KEY_CACHE: LazyLock<Mutex<HashMap<String, CachedHttpKeys>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn cache_key(peer: &str, ek_b64: &str) -> String {
    // \u{1} 作分隔符：peer 与 ek 各自不含该控制字符，杜绝拼接歧义
    format!("{peer}\u{1}{ek_b64}")
}

fn entry_expired(entry: &CachedHttpKeys, now: Instant) -> bool {
    now.duration_since(entry.inserted_at) >= REQUEST_KEY_TTL
}

fn store_http_keys(peer: &str, ek_b64: &str, keys: HttpTrafficKeys) {
    let now = Instant::now();
    match HTTP_KEY_CACHE.lock() {
        Ok(mut map) => {
            map.retain(|_, entry| !entry_expired(entry, now)); // 插入时顺带清扫
            if map.len() >= HTTP_KEY_CACHE_MAX {
                // 逐出最早项：容量有界，防极端流量下 map 无界增长
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, entry)| entry.inserted_at)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
            map.insert(cache_key(peer, ek_b64), CachedHttpKeys { keys, inserted_at: now });
        }
        Err(_) => {
            tracing::error!("http key cache lock poisoned, response will stay plaintext");
        }
    }
}

fn take_http_keys(peer: &str, ek_b64: &str) -> Option<HttpTrafficKeys> {
    let now = Instant::now();
    match HTTP_KEY_CACHE.lock() {
        Ok(mut map) => {
            let key = cache_key(peer, ek_b64);
            match map.remove(&key) {
                Some(entry) if !entry_expired(&entry, now) => Some(entry.keys),
                Some(_) => None, // 存在但已过期：视作 miss
                None => None,
            }
        }
        Err(_) => None,
    }
}

// ==================== 过滤器骨架 ====================

/// 明文白名单路由（HTTP）：配对引导期端点——它们本身是 pinning 建立即刻，
/// 必须明文可达；健康检查供探活。豁免不受任何配置开关影响（spec §6 硬约束）。
fn is_plaintext_whitelisted(route: &str) -> bool {
    // 路径穿越不得以 `/api/auth/` 前缀骗取白名单豁免（配对窗口闸门同判据）
    if route.contains("..") || route.to_ascii_lowercase().contains("%2e%2e") {
        return false;
    }
    route.starts_with("/api/auth/") || route == "/health" || route == "/api/health"
}

/// 解析 FilterContext.peer 为 SocketAddr（HTTP = 客户端地址，WS = 连接对端地址）
fn parse_peer(peer: &str) -> Option<std::net::SocketAddr> {
    peer.parse().ok()
}

/// 对端是否环回（本地豁免判据；WS 升级门禁与过滤器共用同一口径）
///
/// 无法解析的 peer 一律视为远端（fail-safe：宁多过滤不放行）。
pub fn is_loopback_peer(peer: &str) -> bool {
    parse_peer(peer).is_some_and(|addr| addr.ip().is_loopback())
}

/// 本地豁免判定（spec §4 + 内网穿透 T04 不变量 15）：
/// ① 普通面的环回对端（hook 脚本调 /api/plugin/*、本机工具直连 REST）；
/// ② 配对引导白名单路由（HTTP；peer 面同样保留，Noise 内明文 HTTP 是有意设计）。
///
/// **面标记优先**：peer 面的 TCP 对端必然是 127.0.0.1（隧道入口），按源 IP
/// 判环回会把远端流量静默豁免，「required」被击穿。故 peer 面直接跳过环回
/// 分支，只保留路由白名单；peer 无法解析时按远端处理（fail-safe）。
fn is_exempt(ctx: &FilterContext<'_>) -> bool {
    if ctx.face.is_peer() {
        return matches!(ctx.channel, TrafficChannel::Http) && is_plaintext_whitelisted(ctx.route);
    }
    if is_loopback_peer(ctx.peer) {
        return true;
    }
    matches!(ctx.channel, TrafficChannel::Http) && is_plaintext_whitelisted(ctx.route)
}

impl LinkEncryptionFilter {
    /// 本流量的生效策略；`None` = 本地豁免（环回 / 宿主引导面，不受任何策略影响）
    ///
    /// 策略 = 应用策略（`app_policy(owner)`），未登记 = `off`。端点身份（属主）
    /// 由宿主注册表注入到 [`FilterContext`]，本函数不解析 URL 猜身份、不接受对端自报。
    pub fn policy_of(ctx: &FilterContext<'_>) -> Option<EncryptionPolicy> {
        if is_exempt(ctx) {
            return None;
        }
        Some(app_policy(ctx.owner))
    }

    /// 该流量是否应进入加解密处理（`off` / 本地豁免 = 不处理）
    pub fn should_process(ctx: &FilterContext<'_>) -> bool {
        Self::policy_of(ctx).is_some_and(|policy| policy != EncryptionPolicy::Off)
    }

    /// 端点身份提示串（错误文案统一格式：点名端点 / 属主 / 通道）
    fn endpoint_hint(ctx: &FilterContext<'_>) -> String {
        if ctx.endpoint.is_empty() {
            return format!("channel '{}' (no endpoint identity)", ctx.channel.as_str());
        }
        let owner = if ctx.owner.is_empty() { "(host)" } else { ctx.owner };
        format!(
            "endpoint '{}' of plugin '{owner}' (channel '{}')",
            ctx.endpoint,
            ctx.channel.as_str()
        )
    }

    /// WS 入站/出站统一入口：连接已注册密码 → 帧级加解密（fail-closed，
    /// Reject 由 WS 接线点升级为 Close 4003）；未注册（明文会话）→ 按应用策略裁决
    ///
    /// 拒绝原因带拒绝码（内网穿透 T07）：帧层只能观测到「会话没有密码」，分不出
    /// 「从未协商」与「协商后丢失」，因此**不**下 `encryption-unsupported`——
    /// 旧客户端由升级期（`routes.rs` 无提案门禁）判定，这里一律
    /// `encryption-required`。
    fn on_ws_frame(ctx: &mut FilterContext<'_>, policy: EncryptionPolicy) -> Verdict {
        if !ws_has_ciphers(ctx.peer) {
            return if policy.allows_plaintext() {
                Self::audit_plaintext(ctx, policy);
                Verdict::Continue
            } else {
                Verdict::Reject(coded_reason(
                    CODE_ENCRYPTION_REQUIRED,
                    format!(
                        "link encryption required (policy '{}') but this connection has no negotiated session cipher: {}; pair the client or change the app's encryption setting",
                        policy.as_str(),
                        Self::endpoint_hint(ctx)
                    ),
                ))
            };
        }
        let origin = if ctx.route == "binary" {
            ORIGIN_BINARY
        } else {
            ORIGIN_TEXT
        };
        let channel_str = ctx.channel.as_str();
        let result = match ctx.direction {
            Direction::Inbound => ws_decrypt_inbound_text_binary(ctx.peer, channel_str, origin, &ctx.data),
            Direction::Outbound => ws_encrypt_outbound_text_binary(ctx.peer, channel_str, origin, &ctx.data),
        };
        match result {
            Ok(sealed) => {
                crate::metrics::MetricsCollector::global().inc_encrypted_frame();
                ctx.data = sealed;
                Verdict::Continue
            }
            Err(e) => {
                crate::metrics::MetricsCollector::global().inc_decrypt_failure();
                Verdict::Reject(coded_reason(
                    CODE_ENCRYPTION_REQUIRED,
                    format!("ws frame crypto failed: {e}"),
                ))
            }
        }
    }

    /// HTTP 入站：协商 → ECDH(Kd, ek) 派生 → 解信封 → 缓存响应密钥。
    /// 任一步失败一律 Reject（fail-closed），错误详情进 400 响应体。
    /// 明文放行留痕（每端点首次）：注册日志说明端点存在，首连日志说明它真的被
    /// 明文使用（spec §7 审计要求）；只记端点与对端，不写载荷 / 密钥材料
    fn audit_plaintext(ctx: &FilterContext<'_>, policy: EncryptionPolicy) {
        if !note_plaintext_connection(ctx.owner, ctx.endpoint) {
            return;
        }
        tracing::info!(
            plugin_id = %ctx.owner,
            endpoint = %ctx.endpoint,
            channel = ctx.channel.as_str(),
            policy = policy.as_str(),
            peer = %ctx.peer,
            route = %ctx.route,
            "plaintext connection allowed by app policy"
        );
    }

    /// HTTP 入站：协商 → ECDH(Kd, ek) 派生 → 解信封 → 缓存响应密钥。
    /// 任一步失败一律 Reject（fail-closed），错误详情进 400 响应体。
    ///
    /// GET/HEAD 无请求体：协商头携带临时公钥即足以派生响应密钥，body
    /// 为空时跳过解信封（无载荷可解），仅缓存密钥供出站加密响应。
    /// 注：实际只有 GET 走此路径——HEAD 由 http_filter 在责任链之前按
    /// 快速路径短路（响应无 body 可加密），此处注释泛指无请求体语义
    fn on_http_inbound(ctx: &mut FilterContext<'_>, policy: EncryptionPolicy) -> Verdict {
        // `off` = 不要求加密，不是禁止加密：客户端自愿加密时照常解密（结
        // 果仍是插件收到明文）。真正危险的是「本端无法解密却放行密文」——
        // 那条由中间件的 fail-visible 分支处理（过滤器不在链上 → 400）。
        let Some(ek_b64) = parse_negotiation(ctx.negotiation) else {
            // 无协商：`preferred` 放行明文；`required` 必拒（不降级）。
            //
            // 拒绝码 = `encryption-unsupported`：对端**根本没有发起**协商。宿主无法
            // 区分「旧版本客户端（不会协商）」与「没有 pin 信任锚的客户端（筹不出
            // 密钥）」，所以文案把两条出路都点名，不假装知道是哪一种（T07 判据：
            // 显性失败 + 升级提示，无明文回退）。
            return if policy.allows_plaintext() {
                Self::audit_plaintext(ctx, policy);
                Verdict::Continue
            } else {
                Verdict::Reject(coded_reason(
                    CODE_ENCRYPTION_UNSUPPORTED,
                    format!(
                        "link encryption required (policy '{}') but the request carries no '{NEGOTIATION_HEADER}' negotiation header: {}; the peer never started link-crypto negotiation (old client without link-crypto support, or a client with no pinned trust anchor) — upgrade the peer or pair it first; plaintext is not accepted",
                        policy.as_str(),
                        Self::endpoint_hint(ctx)
                    ),
                ))
            };
        };
        let Some(identity) = IDENTITY.get() else {
            return Verdict::Reject(coded_reason(CODE_ENCRYPTION_REQUIRED, "link identity unavailable"));
        };

        // GET/HEAD 空 body：无载荷可解，协商仅用于响应加密（密钥派生已足以
        // 证明对端持有临时私钥）——空 body 直接通过，不尝试解信封。had_body
        // 须在闭包前捕获（闭包会把 ctx.data 替换为明文）
        let had_body = !ctx.data.is_empty();
        let result = (|| -> Result<()> {
            let ek_raw = b64_decode(ek_b64).map_err(link_crypto_to_app_error)?;
            let peer_public: [u8; 32] = ek_raw.try_into().map_err(|v: Vec<u8>| {
                AppError::Internal(format!("negotiation key length mismatch: expected 32, got {}", v.len()))
            })?;
            let shared = DATA_ECDH
                .compute_shared(identity.keypair().private(), &peer_public)
                .map_err(crypto_to_app_error)?;
            let keys = derive_http_traffic_keys(&shared, ctx.route)?;
            // GET/HEAD 空 body：无载荷可解，协商仅用于响应加密（密钥派生已足以
            // 证明对端持有临时私钥）——空 body 直接通过，不尝试解信封
            if had_body {
                let request_key = keys.request;
                let plaintext = decrypt_http_body(&request_key, &ctx.data, &http_aad(Direction::Inbound, ctx.route))
                    .map_err(link_crypto_to_app_error)?;
                ctx.data = plaintext;
            }
            store_http_keys(ctx.peer, ek_b64, keys);
            Ok(())
        })();

        match result {
            Ok(()) => {
                // 仅实际解封了请求体才计加密帧：空 body 协商只派生响应密钥，
                // 计帧会高估加密吞吐（指标语义：成功处理帧/请求）
                if had_body {
                    crate::metrics::MetricsCollector::global().inc_encrypted_frame();
                }
                Verdict::Continue
            }
            Err(e) => {
                crate::metrics::MetricsCollector::global().inc_decrypt_failure();
                Verdict::Reject(coded_reason(
                    CODE_ENCRYPTION_REQUIRED,
                    format!("http request decrypt failed: {e}"),
                ))
            }
        }
    }

    /// HTTP 出站：入站已成功协商的请求 → 用缓存的 k_resp 加密响应；
    /// 未命中（未协商/入站被拒）→ 明文端点保持明文；`required` 端点拒绝
    /// （否则就是对管理员承诺的加密静默降级）
    fn on_http_outbound(ctx: &mut FilterContext<'_>, policy: EncryptionPolicy) -> Verdict {
        // `off` 同理：没有协商/没有缓存密钥 → 明文；有协商且上行已缓存密钥 →
        // 回加密响应（客户端自愿加密时必须成对，否则客户端会判降级）。
        let Some(ek_b64) = parse_negotiation(ctx.negotiation) else {
            return Verdict::Continue;
        };
        let Some(keys) = take_http_keys(ctx.peer, ek_b64) else {
            crate::metrics::MetricsCollector::global().inc_response_key_miss();
            if policy == EncryptionPolicy::Required {
                return Verdict::Reject(coded_reason(
                    CODE_ENCRYPTION_REQUIRED,
                    format!(
                        "response encryption failed: no cached response key for a 'required' endpoint: {}; refusing to answer in plaintext",
                        Self::endpoint_hint(ctx)
                    ),
                ));
            }
            // 入站已协商但出站取 key 失败（TTL 竞态/锁毒化/密钥失配）→ 响应
            // 明文放行（错误信息需对端可读）。必须留痕：strict 客户端会据此
            // 断流报 LINK_ENCRYPTION_DOWNGRADE，服务端若无日志与计数将无从排查
            tracing::warn!(
                peer = ctx.peer,
                route = ctx.route,
                "http response key miss; response sent plaintext"
            );
            return Verdict::Continue;
        };
        match encrypt_http_body(&keys.response, &ctx.data, &http_aad(Direction::Outbound, ctx.route)) {
            Ok(envelope_json) => {
                crate::metrics::MetricsCollector::global().inc_encrypted_frame();
                ctx.data = envelope_json;
                // 响应加密标记（spec §4）：移动端据 `X-WasmNest-Crypto: v1`
                // 识别加密响应并解信封；值必须带 "v" 前缀（与请求侧
                // parse_negotiation 的 `format!("v{PROTOCOL_VERSION}")` 同源），
                // 裸 `1` 会被移动端 `respHeader === 'v1'` 判为不匹配 → 误报降级
                ctx.outbound_headers
                    .push((NEGOTIATION_HEADER.to_string(), format!("v{PROTOCOL_VERSION}")));
                Verdict::Continue
            }
            Err(e) => {
                crate::metrics::MetricsCollector::global().inc_decrypt_failure();
                Verdict::Reject(coded_reason(
                    CODE_ENCRYPTION_REQUIRED,
                    format!("http response encrypt failed: {e}"),
                ))
            }
        }
    }
}

/// 链路加密过滤器（转换型）
///
/// 注册进全局责任链后对所有通道的收发载荷生效；裁决按 `owner` 的应用策略
/// （`app_policy`，见模块头 §1），本地豁免流量零介入直通。
pub struct LinkEncryptionFilter;

impl TrafficFilter for LinkEncryptionFilter {
    fn name(&self) -> &str {
        FILTER_NAME
    }

    fn on_inbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
        let Some(policy) = Self::policy_of(ctx) else {
            return Verdict::Continue;
        };
        match ctx.channel {
            // HTTP 即便 `off` 也要看协商头：密文送进明文端点是必须显性拒绝的错误
            TrafficChannel::Http => Self::on_http_inbound(ctx, policy),
            TrafficChannel::WsTerminal | TrafficChannel::WsEvent | TrafficChannel::WsPlugin => {
                // 已协商会话密码的连接必须继续走加解密：应用把策略从 required /
                // preferred 降到 off 时，存量连接仍是密文——按 off 直通会把密文
                // 原样投给插件（或把明文回给期待密文的客户端）。
                if policy == EncryptionPolicy::Off && !ws_has_ciphers(ctx.peer) {
                    Self::audit_plaintext(ctx, policy);
                    return Verdict::Continue;
                }
                Self::on_ws_frame(ctx, policy)
            }
        }
    }

    fn on_outbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
        let Some(policy) = Self::policy_of(ctx) else {
            return Verdict::Continue;
        };
        match ctx.channel {
            TrafficChannel::Http => Self::on_http_outbound(ctx, policy),
            TrafficChannel::WsTerminal | TrafficChannel::WsEvent | TrafficChannel::WsPlugin => {
                // 已协商会话密码的连接必须继续走加解密：应用把策略从 required /
                // preferred 降到 off 时，存量连接仍是密文——按 off 直通会把密文
                // 原样投给插件（或把明文回给期待密文的客户端）。
                if policy == EncryptionPolicy::Off && !ws_has_ciphers(ctx.peer) {
                    Self::audit_plaintext(ctx, policy);
                    return Verdict::Continue;
                }
                Self::on_ws_frame(ctx, policy)
            }
        }
    }
}

// ==================== 注册与启动装配 ====================

/// 最近一次同步后的注册态（日志诊断用；裁决只认「链上有无同名节点」）
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// 按当前应用策略同步全局链注册状态（幂等；策略写入 / 启动装配共用）
///
/// 注册判据：
/// 1. 本进程必须有链路身份（没有密钥就不能加密；`required` 写入已在
///    [`set_app_policy`] 处显性拒绝，此处是防御）；
/// 2. 至少一个应用的策略非 `off`，或仍有存量 WS 密码会话——否则链上不应多一个
///    每帧都要跑的过滤器（全明文部署零影响）。注意：`off` 只表示「不要求加密」，
///    客户端自愿加密时本过滤器若因其他应用在链上，仍会解密/回密（见
///    `on_http_inbound` / `on_http_outbound`）。
pub fn sync_registration() {
    let chain = TrafficFilterChain::global();
    let wanted = IDENTITY.get().is_some() && crypto_wanted();
    // 以「链上是否已有同名节点」为唯一判据：同名重复注册会让同一帧被处理两次
    // （第一次解密成功、第二次把明文当信封再解一次 → 整条链路自伤）。不只看
    // 进程内标志位，因为外部 `chain.clear()`（测试隔离 / 宿主热重置）会让标志
    // 与链的真实状态脱节。
    let present = chain.contains(FILTER_NAME);
    if wanted && !present {
        chain.register(std::sync::Arc::new(LinkEncryptionFilter));
        REGISTERED.store(true, Ordering::SeqCst);
    } else if !wanted && present {
        chain.unregister(FILTER_NAME);
        REGISTERED.store(false, Ordering::SeqCst);
    }
}

/// 是否需要链路加密能力：至少一个应用要求非明文，或仍有存量密码会话
///
/// 后者是运行期降级的正确性约束：应用把策略降到 `off` 时，已协商的 WS 连接仍是
/// 密文，过滤器必须留在链上继续解密/加密，直到这些连接断开（`ws_remove_ciphers`）。
/// 该判据同时经 [`filter_active`] 暴露给 `/api/health`（移动端据此决定是否为
/// 应用发起的 HTTP 加信封——链上没有过滤器时加信封只会被 fail-visible 400）。
fn crypto_wanted() -> bool {
    policy_lock().values().any(|policy| *policy != EncryptionPolicy::Off) || ws_ciphers_present()
}

/// 本进程当前是否在流量链上装着链路加密过滤器（`/api/health` 只读能力位）
///
/// 移动端在感知到「对端参与链路加密」时才给应用发起的 HTTP 加信封；对方全
/// `off` 时加信封只会被中间件的 fail-visible 分支拒绝。以链上真实节点为判据
/// （而不是只看策略表）：外部 `chain.clear()` / 热重置后两者可能短暂脱节。
pub fn filter_active() -> bool {
    TrafficFilterChain::global().contains(FILTER_NAME)
}

/// 向指定链注册（测试隔离用：单元测试走独立链实例，不触碰全局单例）
pub fn register_into(chain: &TrafficFilterChain) {
    chain.register(std::sync::Arc::new(LinkEncryptionFilter));
}

/// 启动期装配：建身份 → 读库中的应用策略 → 同步注册
///
/// 必须在 supervisor.start 之前完成（服务器收到的第一条流量就要按应用策略裁决）。
/// 身份损坏时策略中的 `required` 无法应用（[`load_app_policies_from_db`] 逐条
/// error 留痕，该应用本启动期按 `off` 执行）——加密不可用是可接受的降级，
/// 静默换钥破坏 pin 是不可接受的错误。
///
/// server-lib-split：宿主壳负责解析应用数据目录与主库连接（`PathsPort` /
/// `app.state::<Database>`），本函数只接 `&Path` + `&rusqlite::Connection`。
/// 同步而非 `async`：`&Connection` 跨 `.await` 会让调用方的任务要求
/// `Connection: Sync`（rusqlite 连接是 Send !Sync），装配本身无等待点。
pub fn init_at_startup(data_dir: &std::path::Path, conn: &rusqlite::Connection) {
    match init_identity(data_dir) {
        Ok(fp) => tracing::info!(fingerprint = fp, "link crypto identity ready"),
        Err(e) => tracing::error!("link crypto identity init failed, encryption stays off: {e}"),
    }

    let loaded = load_app_policies_from_db(conn);
    sync_registration();
    tracing::info!(
        apps = loaded,
        filter_registered = REGISTERED.load(Ordering::SeqCst),
        "link crypto initialized"
    );
}

/// 命令层懒初始化：已初始化直接返指纹；否则从应用数据目录建身份后返回
pub fn ensure_identity_fingerprint(data_dir: &std::path::Path) -> Result<String> {
    if let Some(fp) = identity_fingerprint() {
        return Ok(fp.to_string());
    }
    Ok(init_identity(data_dir)?.to_string())
}

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::sync::Mutex;

    use crate::filter::Direction;

    /// 触碰全局应用策略表的测试必须持此锁串行执行：
    /// cargo test 同模块用例默认多线程并行，否则策略互踩产生偶发红
    static POLICY_LOCK: Mutex<()> = Mutex::new(());

    /// 在「指定应用使用某策略」的隔离状态下执行断言，结束后移除该应用策略
    fn with_app_policy<T>(owner: &str, policy: EncryptionPolicy, f: impl FnOnce() -> T) -> T {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_app_policy(owner, policy).expect("测试策略写入失败");
        let out = f();
        remove_app_policy(owner);
        out
    }

    /// 无属主身份的上下文（宿主自有面 / 未注册路径：没有应用策略 = 明文）
    fn mk_ctx<'a>(channel: TrafficChannel, peer: &'a str, route: &'a str) -> FilterContext<'a> {
        FilterContext {
            channel,
            direction: Direction::Inbound,
            peer,
            route,
            owner: "",
            endpoint: "",
            negotiation: "",
            data: b"payload".to_vec(),
            outbound_headers: Vec::new(),
            face: RequestFace::default(),
        }
    }

    /// 带属主身份的上下文（策略按应用策略裁决；endpoint 只用于日志/错误定位）
    fn mk_endpoint_ctx<'a>(
        channel: TrafficChannel,
        peer: &'a str,
        route: &'a str,
        owner: &'a str,
        endpoint: &'a str,
    ) -> FilterContext<'a> {
        FilterContext {
            owner,
            endpoint,
            ..mk_ctx(channel, peer, route)
        }
    }

    // ---------- 配置域 ----------

    // ---------- 应用策略域 ----------

    #[test]
    fn unregistered_app_defaults_to_off() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        remove_app_policy("test-default");
        assert_eq!(app_policy("test-default"), EncryptionPolicy::Off);
        assert_eq!(app_policy(""), EncryptionPolicy::Off, "宿主自有面没有应用策略");
    }

    #[test]
    fn app_policy_set_remove_and_snapshot() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let owner = "test-app-policy";
        set_app_policy(owner, EncryptionPolicy::Preferred).unwrap();
        assert_eq!(app_policy(owner), EncryptionPolicy::Preferred);

        let record = app_policies()
            .into_iter()
            .find(|r| r.owner == owner)
            .expect("已登记策略应出现在审计快照中");
        assert_eq!(record.policy, EncryptionPolicy::Preferred);
        // wire 形状是前端接口镜像真源：字段名必须 camelCase
        let json = serde_json::to_value(&record).unwrap();
        assert!(json.get("owner").is_some() && json.get("policy").is_some(), "{json}");

        assert!(remove_app_policy(owner));
        assert_eq!(app_policy(owner), EncryptionPolicy::Off);
        assert!(!remove_app_policy(owner), "未知键回收幂等");
    }

    #[test]
    fn policy_validation_rejects_empty_owner_and_required_without_identity() {
        assert!(validate_app_policy("  ", EncryptionPolicy::Off, true).is_err());
        let err = validate_app_policy("com.example.app", EncryptionPolicy::Required, false)
            .expect_err("无身份时 required 必须失败");
        assert!(err.contains("identity") && err.contains("com.example.app"), "{err}");
        // 无身份：preferred / off 不受阻（它们不要求本端必须能加密）
        assert!(validate_app_policy("p", EncryptionPolicy::Preferred, false).is_ok());
        assert!(validate_app_policy("p", EncryptionPolicy::Required, true).is_ok());
    }

    #[test]
    fn app_policies_db_roundtrip_and_corrupt_fallback() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("test.db")).unwrap();
        conn.execute_batch("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);")
            .unwrap();

        remove_app_policy("db-test-a");
        remove_app_policy("db-test-b");
        // 键不存在 → 不加载任何策略
        assert_eq!(load_app_policies_from_db(&conn), 0);

        set_app_policy("db-test-a", EncryptionPolicy::Preferred).unwrap();
        set_app_policy("db-test-b", EncryptionPolicy::Off).unwrap();
        let snapshot = app_policy_snapshot();
        persist_app_policies_to_db(&conn, &snapshot).unwrap();
        remove_app_policy("db-test-a");
        remove_app_policy("db-test-b");
        assert_eq!(load_app_policies_from_db(&conn), 2);
        assert_eq!(app_policy("db-test-a"), EncryptionPolicy::Preferred);
        assert_eq!(app_policy("db-test-b"), EncryptionPolicy::Off);

        // 损坏 JSON → 不加载、不 panic
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![APP_POLICY_SETTING_KEY, "{not-json", "now"],
        )
        .unwrap();
        assert_eq!(load_app_policies_from_db(&conn), 0);

        // 未知策略值只跳过该条，其余照常（绝不静默当成明文）
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                APP_POLICY_SETTING_KEY,
                r#"{"db-test-a":"preferred","db-test-b":"enabled"}"#,
                "now"
            ],
        )
        .unwrap();
        assert_eq!(load_app_policies_from_db(&conn), 1);
        assert_eq!(app_policy("db-test-a"), EncryptionPolicy::Preferred, "有效条目照常加载");
        assert_eq!(
            app_policy("db-test-b"),
            EncryptionPolicy::Off,
            "非法条目不得被当成明文以外的值"
        );

        remove_app_policy("db-test-a");
        remove_app_policy("db-test-b");
    }

    // ---------- 身份密钥 ----------

    #[test]
    fn identity_load_or_create_is_idempotent_and_stable() {
        let dir = tempfile::tempdir().unwrap();

        let first = LinkIdentity::load_or_create(dir.path()).unwrap();
        let fp1 = first.fingerprint().to_string();
        assert_eq!(fp1.len(), 16, "指纹 = SHA-256 前 16 hex");
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));
        // base64 公钥可解码为 32 字节
        let raw = base64::engine::general_purpose::STANDARD
            .decode(first.public_b64())
            .unwrap();
        assert_eq!(raw.len(), 32);

        // 重启模拟：重新加载指纹不变
        let second = LinkIdentity::load_or_create(dir.path()).unwrap();
        assert_eq!(second.fingerprint(), fp1);

        // 私钥文件限属主可读（与 peer-net 身份文件同模式）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(IDENTITY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "私钥文件必须 0600，实际 {mode:o}");
        }
        // 原子发布的 tmp 必须清理干净
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "遗留 tmp: {leftovers:?}");
    }

    /// 并发首启只产生一份身份：所有线程拿到同一指纹（不覆盖既有文件）
    #[test]
    fn identity_concurrent_first_start_converges() {
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let path = dir.path().to_path_buf();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                LinkIdentity::load_or_create(&path).unwrap().fingerprint().to_string()
            }));
        }
        let fps: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(fps.windows(2).all(|p| p[0] == p[1]), "并发首启出现了不同密钥: {fps:?}");
        assert_eq!(LinkIdentity::load_or_create(dir.path()).unwrap().fingerprint(), fps[0]);
    }

    #[test]
    fn identity_corrupt_file_refuses_regeneration() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IDENTITY_FILE), "{corrupt").unwrap();

        let err = LinkIdentity::load_or_create(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt") || msg.contains("refusing"),
            "应明确拒绝重建而非静默换钥: {msg}"
        );
    }

    #[test]
    fn init_identity_is_idempotent_in_process() {
        let dir = tempfile::tempdir().unwrap();
        let fp = init_identity(dir.path()).unwrap().to_string();
        // 同进程二次调用返回既有指纹（不因传入不同目录而换钥）
        let again = init_identity(tempfile::tempdir().unwrap().path()).unwrap();
        assert_eq!(again, fp);
    }

    // ---------- HKDF 派生 ----------

    #[test]
    fn http_keys_deterministic_and_direction_isolated() {
        let ikm = [7u8; 32];
        let a = derive_http_traffic_keys(&ikm, "/api/sessions").unwrap();
        let b = derive_http_traffic_keys(&ikm, "/api/sessions").unwrap();
        assert_eq!(a, b, "同输入必须确定（两端各自派生要一致）");
        assert_ne!(a.request, a.response, "方向 info 隔离");

        // salt 参与派生：不同路径不同密钥（防信封跨端点搬运）
        let other = derive_http_traffic_keys(&ikm, "/api/file-tree").unwrap();
        assert_ne!(a.request, other.request);
        assert_ne!(a.response, other.response);
    }

    /// HTTP 双方向密钥金样向量（票据 15 变异守卫）
    ///
    /// 固定 IKM `[7u8; 32]` + path `/api/sessions` 锁死派生输出字节：
    /// 任何 HKDF info 常量 / salt / 参数改动（如交换 HTTP_INFO_REQUEST ↔
    /// HTTP_INFO_RESPONSE）都会改变派生结果。roundtrip 自洽性无法捕获
    /// 「方向语义反转」变异（request≠response 仍成立），金样是唯一守卫。
    /// 移动端 TS 复刻（linkCrypto.ts）必须逐字节一致——协议兼容锚点。
    #[test]
    fn http_keys_gold_vector_locked() {
        let ikm = [7u8; 32];
        let keys = derive_http_traffic_keys(&ikm, "/api/sessions").unwrap();
        // 锁死精确字节（协议兼容锚点）
        assert_eq!(
            hex::encode(keys.request),
            "74e1f1abf39df6a1c213ac2b7894264742e7d5d2b9784abb650903807a1b56b2"
        );
        assert_eq!(
            hex::encode(keys.response),
            "1558166c6fcad0bfe92708ae62fbc5a702be7d5e582a2c3d442fdeaa32b83012"
        );
    }

    /// WS 方向密钥金样向量（票据 15）：锁死 c2s/s2c HKDF 派生输出
    ///
    /// 固定 ikm `[9u8; 64]` + salt，方向 info 常量被交换（变异）时断言失败。
    /// 移动端 TS 复刻必须逐字节一致——协议兼容锚点。
    #[test]
    fn ws_session_ciphers_gold_vector_locked() {
        use wasmnest_crypto_engine::kdf::hkdf_sha256;
        let ikm = [9u8; 64];
        let salt = b"wasmnest-ws-gold-vector".to_vec();
        let c2s = hkdf_sha256(Some(&salt), &ikm, WS_INFO_CLIENT_TO_SERVER, 36).unwrap();
        let s2c = hkdf_sha256(Some(&salt), &ikm, WS_INFO_SERVER_TO_CLIENT, 36).unwrap();
        // 锁死精确字节；c2s ≠ s2c（方向隔离）
        assert_eq!(
            hex::encode(&c2s[..]),
            "464d675c3b83780a77e03a4cc5ed773d396dd99abceb4d92c09b27ca47be86390138c9f1"
        );
        assert_eq!(
            hex::encode(&s2c[..]),
            "5af555217656841d5bf4191cba84710f1b405fd5776cf12a145d7347bf1aee3dddd47c32"
        );
    }

    // ---------- 链路加密套件解析（票 05 套件参数化） ----------

    /// 默认套件三算法名都在引擎注册表白名单内（套件与引擎词汇不漂移）
    #[test]
    fn default_link_suite_algorithms_registered() {
        assert_suite_algorithms_registered(&DEFAULT_LINK_SUITE);
    }

    /// 缺省（老客户端不携带 suite）→ 默认套件；显式传默认名 → 默认套件
    #[test]
    fn resolve_link_suite_default_when_absent_or_default_name() {
        // 老客户端不携带 / 空串 → 默认套件（不断流）
        assert_eq!(resolve_link_suite(None).unwrap().name, DEFAULT_LINK_SUITE.name);
        assert_eq!(resolve_link_suite(Some("")).unwrap().name, DEFAULT_LINK_SUITE.name);
        // 新客户端携带默认套件名 → 接受
        assert_eq!(
            resolve_link_suite(Some(DEFAULT_LINK_SUITE.name)).unwrap().name,
            DEFAULT_LINK_SUITE.name
        );
    }

    /// 未知套件名 → 显式拒绝（fail-visible，不静默降级到默认）
    #[test]
    fn resolve_link_suite_unknown_rejected() {
        match resolve_link_suite(Some("aes-128-gcm+rsa")) {
            Ok(s) => panic!("未知套件必须拒绝，实际选择: {}", s.name),
            Err(e) => {
                assert!(
                    matches!(e, AppError::InvalidInput(_)),
                    "未知套件必须 fail-visible，实际: {e}"
                );
                assert!(e.to_string().contains("aes-128-gcm+rsa"), "错误应含套件名: {e}");
            }
        }
    }

    // ---------- WS 会话加密（issue 04） ----------

    /// 移动端 TS 侧的派生复刻：相同字节序列必须得到相同密钥（跨端兼容锚点）
    #[test]
    fn ws_handshake_interop_with_client_replication() {
        init_identity(tempfile::tempdir().unwrap().path()).unwrap();
        use wasmnest_crypto_engine::x25519::{x25519_diffie_hellman, x25519_generate};

        let client_eph = x25519_generate();
        let m_ek_b64 = b64_encode(client_eph.public());
        let handshake = derive_ws_session_ciphers(&m_ek_b64).unwrap();

        // 客户端复算：eph-eph ‖ eph-Kd，transcript salt 相同
        let (_, kd_pub_b64) = identity_parts().unwrap();
        let kd_pub: [u8; 32] = b64_decode(&kd_pub_b64).unwrap().try_into().unwrap();
        let s_pub: [u8; 32] = b64_decode(&handshake.server_ek_b64).unwrap().try_into().unwrap();
        let eph_eph = x25519_diffie_hellman(&client_eph, &s_pub).unwrap();
        let auth = x25519_diffie_hellman(&client_eph, &kd_pub).unwrap();
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(eph_eph.as_bytes());
        ikm[32..].copy_from_slice(auth.as_bytes());
        let salt = [
            WS_TRANSCRIPT_PREFIX,
            m_ek_b64.as_bytes(),
            handshake.server_ek_b64.as_bytes(),
        ]
        .concat();
        let c2s = wasmnest_crypto_engine::kdf::hkdf_sha256(Some(&salt), &ikm, WS_INFO_CLIENT_TO_SERVER, 36).unwrap();
        let s2c = wasmnest_crypto_engine::kdf::hkdf_sha256(Some(&salt), &ikm, WS_INFO_SERVER_TO_CLIENT, 36).unwrap();

        assert_eq!(&c2s[..32], &handshake.ciphers.client_to_server.key);
        assert_eq!(&c2s[32..], &handshake.ciphers.client_to_server.nonce_prefix);
        assert_eq!(&s2c[..32], &handshake.ciphers.server_to_client.key);
        assert_eq!(&s2c[32..], &handshake.ciphers.server_to_client.nonce_prefix);
    }

    #[test]
    fn ws_frame_codec_roundtrip_and_seq_discipline() {
        init_identity(tempfile::tempdir().unwrap().path()).unwrap();
        let client_eph = wasmnest_crypto_engine::x25519::x25519_generate();
        let handshake = derive_ws_session_ciphers(&b64_encode(client_eph.public())).unwrap();

        // 注册前克隆客户端视角的两把方向密钥（容器含私有序号不可整体克隆）
        let c2s_cipher = handshake.ciphers.client_to_server.clone();
        let s2c_cipher = handshake.ciphers.server_to_client.clone();
        ws_register_ciphers("t:1", handshake.ciphers);
        assert!(ws_has_ciphers("t:1"));

        // 客户端侧封帧助手：与移动端 TS 公式一致（c2s 密钥 + Inbound AAD）。
        // 单机测试必须双端模拟：服务端入站解密只认 c2s，拿 s2c 加密的
        // 出站帧回灌必然 AEAD 失败（方向隔离本就是协议设计）。
        let seal_client_text = |seq: u64, channel: &str, text: &str| -> Vec<u8> {
            let sealed = encrypt_ws_payload(
                &c2s_cipher,
                seq,
                text.as_bytes(),
                &ws_aad(channel, Direction::Inbound, ORIGIN_TEXT),
            )
            .unwrap();
            serde_json::to_vec(&WsTextEnvelope {
                v: WS_FRAME_VERSION,
                seq,
                n: b64_encode(&sealed.nonce),
                ct: b64_encode(&sealed.ciphertext),
            })
            .unwrap()
        };

        // 文本往返（客户端 → 服务端）
        let control = r#"{"type":"subscribe"}"#;
        let sealed = seal_client_text(0, "ws-terminal", control);
        assert_eq!(ws_decrypt_inbound_text("t:1", "ws-terminal", &sealed).unwrap(), control);

        // 重放上一帧 → seq mismatch 拒绝
        assert!(ws_decrypt_inbound_text("t:1", "ws-terminal", &sealed).is_err());

        // 篡改密文 → 解密失败（合法新序号帧上翻转 ct 末字节）
        let mut tampered: WsTextEnvelope = serde_json::from_slice(&seal_client_text(1, "ws-event", "x")).unwrap();
        let mut ct = b64_decode(&tampered.ct).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        tampered.ct = b64_encode(&ct);
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert!(ws_decrypt_inbound_text("t:1", "ws-event", &tampered).is_err());

        // 二进制往返（客户端 → 服务端；TBv2 输出帧模拟。篡改帧解密失败不推进
        // 接收序号，故此处仍用 seq 1）
        let frame = vec![0xABu8; 37];
        let bin_seq = 1u64;
        let nonce = ws_nonce(&c2s_cipher.nonce_prefix, bin_seq);
        let ciphertext = wasmnest_crypto_engine::aes_gcm::encrypt(
            &c2s_cipher.key,
            &nonce,
            &frame,
            Some(&ws_aad("ws-terminal", Direction::Inbound, ORIGIN_BINARY)),
        )
        .unwrap();
        let mut enc = Vec::with_capacity(WS_BINARY_HEADER_LEN + ciphertext.len());
        enc.push(WS_FRAME_VERSION);
        enc.extend_from_slice(&bin_seq.to_be_bytes());
        enc.extend_from_slice(&ciphertext);
        assert_eq!(enc[0], 1, "帧头版本字节");
        assert_eq!(ws_decrypt_inbound_binary("t:1", "ws-terminal", &enc).unwrap(), frame);

        // 服务端出站帧可被持有 s2c 密钥的客户端解开（跨端兼容锚点）
        let outbound = ws_encrypt_outbound_binary("t:1", "ws-terminal", &frame).unwrap();
        let out_seq = u64::from_be_bytes(outbound[1..9].try_into().unwrap());
        let out_plain = wasmnest_crypto_engine::aes_gcm::decrypt(
            &s2c_cipher.key,
            &ws_nonce(&s2c_cipher.nonce_prefix, out_seq),
            &outbound[WS_BINARY_HEADER_LEN..],
            Some(&ws_aad("ws-terminal", Direction::Outbound, ORIGIN_BINARY)),
        )
        .unwrap();
        assert_eq!(out_plain, frame);

        ws_remove_ciphers("t:1");
        assert!(!ws_has_ciphers("t:1"), "断连清理后应无密码");
    }

    /// 应用策略降到 off 后，已协商的 WS 连接仍必须继续加解密
    ///
    /// 回归：过滤器曾按「policy == Off ⇒ 直接放行」短路，应用关闭链路加密后，
    /// 存量加密连接的下行密文会被原样投给插件、上行明文会被回给期待密文的客户端。
    #[test]
    fn encrypted_ws_connection_keeps_crypto_after_policy_off() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        init_identity(tempfile::tempdir().unwrap().path()).unwrap();
        let owner = "com.example.ws-downgrade";
        let peer = "192.168.1.90:9001";
        remove_app_policy(owner);
        ws_remove_ciphers(peer);

        let client_eph = wasmnest_crypto_engine::x25519::x25519_generate();
        let handshake = derive_ws_session_ciphers(&b64_encode(client_eph.public())).unwrap();
        let c2s = handshake.ciphers.client_to_server.clone();
        let s2c = handshake.ciphers.server_to_client.clone();
        ws_register_ciphers(peer, handshake.ciphers);

        // 客户端视角封一帧（c2s，seq 0）
        let sealed =
            encrypt_ws_payload(&c2s, 0, b"hello", &ws_aad("ws-plugin", Direction::Inbound, ORIGIN_TEXT)).unwrap();
        let envelope = serde_json::to_vec(&WsTextEnvelope {
            v: WS_FRAME_VERSION,
            seq: 0,
            n: b64_encode(&sealed.nonce),
            ct: b64_encode(&sealed.ciphertext),
        })
        .unwrap();

        let mut inbound = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", owner, "wse-1");
        inbound.data = envelope;
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut inbound), Verdict::Continue);
        assert_eq!(inbound.data, b"hello", "策略 off 不得把存量密文直通给插件");

        let mut outbound = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", owner, "wse-1");
        outbound.direction = Direction::Outbound;
        outbound.data = b"pong".to_vec();
        assert_eq!(LinkEncryptionFilter.on_outbound(&mut outbound), Verdict::Continue);
        assert_ne!(outbound.data, b"pong", "存量加密连接的出站帧仍须加密");
        let out_env: WsTextEnvelope = serde_json::from_slice(&outbound.data).unwrap();
        let opened = wasmnest_crypto_engine::aes_gcm::decrypt(
            &s2c.key,
            &ws_nonce(&s2c.nonce_prefix, out_env.seq),
            &b64_decode(&out_env.ct).unwrap(),
            Some(&ws_aad("ws-plugin", Direction::Outbound, ORIGIN_TEXT)),
        )
        .unwrap();
        assert_eq!(opened, b"pong");

        ws_remove_ciphers(peer);
    }

    // ---------- 过滤器豁免与开关判定 ----------

    /// WS AAD 通道字面量只有一份真源（桌面过滤器 ↔ 移动客户端共享常量）
    #[test]
    fn ws_plugin_channel_literal_matches_filter_channel() {
        assert_eq!(TrafficChannel::WsPlugin.as_str(), WS_PLUGIN_CHANNEL);
    }

    #[test]
    fn loopback_peer_always_exempt() {
        let mut ctx = mk_ctx(TrafficChannel::Http, "127.0.0.1:5000", "/api/plugin/foo");
        assert!(!LinkEncryptionFilter::should_process(&ctx));
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut ctx), Verdict::Continue);
        assert_eq!(ctx.data, b"payload", "豁免流量不得改写");
    }

    #[test]
    fn loopback_peers_exempt_ipv4_and_ipv6() {
        for peer in ["127.0.0.1:51000", "[::1]:51000"] {
            let ctx = mk_ctx(TrafficChannel::Http, peer, "/api/sessions");
            assert!(!LinkEncryptionFilter::should_process(&ctx), "环回 {peer} 应豁免");
            assert!(is_loopback_peer(peer), "WS 升级门禁与过滤器必须同口径");
        }
        assert!(!is_loopback_peer("192.168.1.42:51000"));
        assert!(!is_loopback_peer("unknown"), "无法解析一律按远端（fail-safe）");
    }

    /// 插件端点通道按应用策略裁决：未登记 = 明文，登记后进入加解密
    #[test]
    fn ws_plugin_channel_follows_app_policy() {
        let ctx = mk_endpoint_ctx(
            TrafficChannel::WsPlugin,
            "192.168.1.42:5001",
            "text",
            "com.example.plugin",
            "wse-any",
        );
        assert!(!LinkEncryptionFilter::should_process(&ctx), "未设置策略的应用默认明文");
        with_app_policy("com.example.plugin", EncryptionPolicy::Preferred, || {
            assert!(LinkEncryptionFilter::should_process(&ctx));
        });
    }

    #[test]
    fn unparseable_peer_treated_as_remote_fail_safe() {
        with_app_policy("com.example.peer", EncryptionPolicy::Preferred, || {
            let ctx = mk_endpoint_ctx(
                TrafficChannel::Http,
                "unknown",
                "/api/sessions",
                "com.example.peer",
                "http-1",
            );
            assert!(LinkEncryptionFilter::should_process(&ctx));
        });
    }

    #[test]
    fn ws_frame_no_ciphers_fallback_branch() {
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let owner = "com.example.fallback";
        let peer = "192.168.1.60:5555";
        ws_remove_ciphers(peer);

        // preferred：无密码连接 → 明文放行且不改写
        set_app_policy(owner, EncryptionPolicy::Preferred).unwrap();
        let mut ctx = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", owner, "wse-fallback");
        assert!(LinkEncryptionFilter::should_process(&ctx));
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut ctx), Verdict::Continue);
        assert_eq!(ctx.data, b"payload", "明文 fallback 不得改写载荷");
        let mut ctx2 = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", owner, "wse-fallback");
        assert_eq!(LinkEncryptionFilter.on_outbound(&mut ctx2), Verdict::Continue);

        // required：无密码连接 → 双向 fail-closed
        set_app_policy(owner, EncryptionPolicy::Required).unwrap();
        let mut ctx3 = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "binary", owner, "wse-fallback");
        match LinkEncryptionFilter.on_inbound(&mut ctx3) {
            Verdict::Reject(msg) => assert!(
                msg.contains("required") && msg.contains("no negotiated session cipher"),
                "拒绝消息应点名策略与缺口: {msg}"
            ),
            other => panic!("期望 Reject，实际: {other:?}"),
        }
        let mut ctx4 = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", owner, "wse-fallback");
        assert!(matches!(
            LinkEncryptionFilter.on_outbound(&mut ctx4),
            Verdict::Reject(_)
        ));

        remove_app_policy(owner);
    }

    #[test]
    fn auth_and_health_routes_whitelisted_for_http_only() {
        with_app_policy("com.example.whitelist", EncryptionPolicy::Preferred, || {
            for route in ["/api/auth/pairing", "/api/auth/qr-connect", "/health", "/api/health"] {
                let ctx = mk_endpoint_ctx(
                    TrafficChannel::Http,
                    "192.168.1.50:4444",
                    route,
                    "com.example.whitelist",
                    "http-1",
                );
                assert!(!LinkEncryptionFilter::should_process(&ctx), "白名单路由 {route} 应豁免");
            }
            // 白名单只对 HTTP 生效；WS 帧类别叫 "text"/"binary"，天然不命中前缀
            let ws_ctx = mk_endpoint_ctx(
                TrafficChannel::WsPlugin,
                "192.168.1.50:4444",
                "text",
                "com.example.whitelist",
                "wse-1",
            );
            assert!(LinkEncryptionFilter::should_process(&ws_ctx));
        });
    }

    #[test]
    fn remote_non_whitelisted_processed_when_app_encrypts() {
        with_app_policy("com.example.remote", EncryptionPolicy::Preferred, || {
            let mut http = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.50:4444",
                "/api/sessions",
                "com.example.remote",
                "http-1",
            );
            assert!(LinkEncryptionFilter::should_process(&http));
            assert_eq!(LinkEncryptionFilter.on_inbound(&mut http), Verdict::Continue);
            assert_eq!(http.data, b"payload");

            let ws = mk_endpoint_ctx(
                TrafficChannel::WsPlugin,
                "192.168.1.50:4444",
                "text",
                "com.example.remote",
                "wse-1",
            );
            assert!(LinkEncryptionFilter::should_process(&ws));
        });
    }

    #[test]
    fn unconfigured_app_serves_plaintext() {
        let owner = "com.example.unconfigured";
        remove_app_policy(owner);
        let ctx = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.50:4444",
            "/api/sessions",
            owner,
            "http-1",
        );
        assert!(!LinkEncryptionFilter::should_process(&ctx));
        // 宿主自有面（无属主）同样没有应用策略 → 明文
        let host_ctx = mk_ctx(TrafficChannel::Http, "192.168.1.50:4444", "/api/sessions");
        assert!(!LinkEncryptionFilter::should_process(&host_ctx));
    }

    #[test]
    fn registration_into_fresh_chain_is_named_and_idempotent_per_instance() {
        // 持锁：防止并行执行的其他用例（sync_registration / update_config 系列）
        // 在同一时刻改动全局链，把本用例的「独立实例不妨碍全局」断言搅黄；
        // 全局链基线读两次做差分断言（而非「不得包含本过滤器」）——并行套件里
        // 兄弟用例可能已把过滤器注册进全局链，绝对断言会误红（flaky：单跑绿、
        // 全量并发红，2026-09-27 全量回归实测）
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let global_names_before = TrafficFilterChain::global().list_names();
        let chain = TrafficFilterChain::new();
        register_into(&chain);
        assert_eq!(chain.list_names(), vec![FILTER_NAME.to_string()]);
        // 独立实例互不干扰：注册入新链不得改动全局链（含此前的并行注册态）
        let global_names_after = TrafficFilterChain::global().list_names();
        assert_eq!(
            global_names_after, global_names_before,
            "register_into 只作用于自建链，不得触碰全局链"
        );
    }

    #[test]
    fn sync_registration_is_idempotent() {
        // 同名节点重复注册会让链上出现重复项；sync 防护保证幂等
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let owner = "com.example.sync";
        set_app_policy(owner, EncryptionPolicy::Preferred).unwrap();
        let global = TrafficFilterChain::global();
        let before = global.list_names().len();
        sync_registration();
        sync_registration();
        sync_registration();
        let after = global.list_names().len();
        assert!(
            after <= before + 1,
            "重复 sync_registration 不得累积重复节点: {before} -> {after}"
        );
        remove_app_policy(owner);
    }

    #[test]
    fn identity_corrupt_file_refuses_regeneration_and_keeps_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IDENTITY_FILE), "{corrupt").unwrap();

        let err = LinkIdentity::load_or_create(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt") || msg.contains("refusing"),
            "应明确拒绝重建而非静默换钥: {msg}"
        );
        // 拒绝重建后文件内容必须保持原样（未被覆盖为新身份）
        let now = std::fs::read_to_string(dir.path().join(IDENTITY_FILE)).unwrap();
        assert_eq!(now, "{corrupt", "拒绝路径不得改写损坏的身份文件");
    }

    // ---------- HTTP 协议层（issue 02） ----------

    #[test]
    fn negotiation_parsing_accepts_only_v1_pair() {
        assert_eq!(parse_negotiation("v1 QUJD"), Some("QUJD"));
        assert_eq!(parse_negotiation("  v1   QUJD  "), Some("QUJD"), "容忍多余空白");
        assert_eq!(parse_negotiation("v2 QUJD"), None, "未知版本视作未协商");
        assert_eq!(parse_negotiation("v1"), None);
        assert_eq!(parse_negotiation("v1 A B"), None, "多段非法");
        assert_eq!(parse_negotiation("v1 "), None, "空公钥拒绝");
        assert_eq!(parse_negotiation(""), None);
    }

    #[test]
    fn http_codec_roundtrip_and_tamper_rejection() {
        let key = [5u8; 32];
        let aad = http_aad(Direction::Inbound, "/api/sessions");
        let plain = br#"{"ok":true,"n":42}"#.to_vec();

        let sealed = encrypt_http_body(&key, &plain, &aad).unwrap();
        assert_eq!(decrypt_http_body(&key, &sealed, &aad).unwrap(), plain);

        // 篡改密文任一字节 → GCM 校验失败
        let mut tampered = sealed.clone();
        let last = sealed.len() - 2; // 收尾引号前的 base64 字符必属 ct 字段
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(decrypt_http_body(&key, &tampered, &aad).is_err());

        // AAD 不匹配（换路径）→ 拒绝：防信封跨端点搬运
        assert!(decrypt_http_body(&key, &sealed, &http_aad(Direction::Inbound, "/other")).is_err());
        // 方向互换 → 拒绝
        assert!(decrypt_http_body(&key, &sealed, &http_aad(Direction::Outbound, "/api/sessions")).is_err());

        // 版本不符 / nonce 长度不符
        let bad_version = br#"{"v":9,"n":"QUJD","ct":"QUJD"}"#;
        assert!(decrypt_http_body(&key, bad_version, &aad).is_err());
        let bad_nonce = br#"{"v":1,"n":"AAAA","ct":"AAAA"}"#;
        assert!(decrypt_http_body(&key, bad_nonce, &aad).is_err());
        // 非信封 JSON
        assert!(decrypt_http_body(&key, b"plain text", &aad).is_err());
    }

    #[test]
    fn request_key_cache_is_take_once_and_ttl_bounded() {
        let keys = HttpTrafficKeys {
            request: [1u8; 32],
            response: [2u8; 32],
        };
        store_http_keys("peer-a", "EK==", keys.clone());
        // 命中即取走
        assert_eq!(take_http_keys("peer-a", "EK=="), Some(keys.clone()));
        // 二次 miss（一次性）
        assert_eq!(take_http_keys("peer-a", "EK=="), None);

        // TTL 判定纯函数
        let now = Instant::now();
        let fresh = CachedHttpKeys {
            keys: keys.clone(),
            inserted_at: now,
        };
        let stale = CachedHttpKeys {
            keys,
            inserted_at: now - REQUEST_KEY_TTL,
        };
        assert!(!entry_expired(&fresh, now));
        assert!(entry_expired(&stale, now));
    }

    #[test]
    fn request_key_cache_capacity_eviction_guard() {
        // 容量护栏：超 HTTP_KEY_CACHE_MAX 时逐出最早项，map 保持有界
        let keys = HttpTrafficKeys {
            request: [1u8; 32],
            response: [2u8; 32],
        };
        // 逐个写入超过上限的条目（peer 唯一、ek 唯一 → 全命中不同 key）
        for i in 0..(HTTP_KEY_CACHE_MAX + 8) {
            store_http_keys("cap-peer", &format!("EK{i:04}"), keys.clone());
        }
        let size = HTTP_KEY_CACHE.lock().unwrap().len();
        assert!(
            size <= HTTP_KEY_CACHE_MAX,
            "容量护栏失效: {size} > {HTTP_KEY_CACHE_MAX}"
        );
        // 最早写入的条目应已被逐出，最新条目可命中
        assert_eq!(take_http_keys("cap-peer", "EK0000"), None, "最早项应被逐出");
        let last = format!("EK{:04}", HTTP_KEY_CACHE_MAX + 7);
        assert!(take_http_keys("cap-peer", &last).is_some(), "最新条目应可命中");
        // 只清理本测试写入的 key（全表 clear 会污染并行测试，票据 14 同类问题）
        {
            let mut map = HTTP_KEY_CACHE.lock().unwrap();
            for i in 0..(HTTP_KEY_CACHE_MAX + 8) {
                map.remove(&cache_key("cap-peer", &format!("EK{i:04}")));
            }
        }
    }

    #[test]
    fn request_key_cache_ttl_sweep_on_store() {
        // store 时顺带清扫过期项（插入时 retain）：先塞一条过期条目，再 store 新条目，
        // 过期条目应被清掉而非占据容量
        let keys = HttpTrafficKeys {
            request: [3u8; 32],
            response: [4u8; 32],
        };
        {
            let mut map = HTTP_KEY_CACHE.lock().unwrap();
            // 只移除本测试可能残留的 key，不动其它测试条目
            map.remove(&cache_key("sweep-peer", "STALE=="));
            map.remove(&cache_key("sweep-peer", "FRESH=="));
            // 手工塞一条已过期条目（inserted_at 回溯超过 TTL）
            map.insert(
                cache_key("sweep-peer", "STALE=="),
                CachedHttpKeys {
                    keys: keys.clone(),
                    inserted_at: Instant::now() - REQUEST_KEY_TTL - Duration::from_secs(1),
                },
            );
        }
        // store 新条目触发清扫
        store_http_keys("sweep-peer", "FRESH==", keys);
        {
            let mut map = HTTP_KEY_CACHE.lock().unwrap();
            assert!(
                !map.contains_key(&cache_key("sweep-peer", "STALE==")),
                "过期条目应在 store 时被清扫"
            );
            assert!(map.contains_key(&cache_key("sweep-peer", "FRESH==")), "新条目应保留");
            // 只清理本测试写入的 key（全表 clear 会污染并行测试，票据 14 同类问题）
            map.remove(&cache_key("sweep-peer", "STALE=="));
            map.remove(&cache_key("sweep-peer", "FRESH=="));
        }
    }

    #[test]
    fn http_full_request_response_cycle_through_filter() {
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let owner = "com.example.cycle";

        with_app_policy(owner, EncryptionPolicy::Preferred, || {
            use wasmnest_crypto_engine::x25519::{x25519_diffie_hellman, x25519_generate};

            // 客户端侧模拟：临时密钥对 + 对 Kd 公钥 ECDH 派生两方向密钥
            let client_eph = x25519_generate();
            let (_, kd_pub_b64) = identity_parts().unwrap();
            let kd_pub: [u8; 32] = b64_decode(&kd_pub_b64).unwrap().try_into().unwrap();
            let shared = x25519_diffie_hellman(&client_eph, &kd_pub).unwrap();
            let keys = derive_http_traffic_keys(shared.as_bytes(), "/api/sessions").unwrap();
            let negotiation = format!("v1 {}", b64_encode(client_eph.public()));

            // ---- 入站：加密请求体 → 过滤器解密为明文 ----
            let req_plain = br#"{"q":"list sessions"}"#.to_vec();
            let req_sealed = encrypt_http_body(
                &keys.request,
                &req_plain,
                &http_aad(Direction::Inbound, "/api/sessions"),
            )
            .unwrap();
            let mut inbound = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.9:55001",
                "/api/sessions",
                owner,
                "http-1",
            );
            inbound.negotiation = &negotiation;
            inbound.data = req_sealed;
            assert_eq!(LinkEncryptionFilter.on_inbound(&mut inbound), Verdict::Continue);
            assert_eq!(inbound.data, req_plain, "handler 应收到明文");

            // ---- 出站：明文响应 → 过滤器加密 → 客户端用 k_resp 解回 ----
            let resp_plain = br#"{"code":0,"data":[1,2]}"#.to_vec();
            let mut outbound = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.9:55001",
                "/api/sessions",
                owner,
                "http-1",
            );
            outbound.direction = Direction::Outbound;
            outbound.negotiation = &negotiation;
            outbound.data = resp_plain.clone();
            assert_eq!(LinkEncryptionFilter.on_outbound(&mut outbound), Verdict::Continue);
            assert_ne!(outbound.data, resp_plain, "响应应已加密");
            // 加密响应必须回协商头标记（spec §4）：客户端据 `X-WasmNest-Crypto: v1`
            // 识别并解密，缺失/值不符会导致客户端误判明文降级（值必须是 "v1"）
            assert_eq!(
                outbound.outbound_headers,
                vec![(NEGOTIATION_HEADER.to_string(), format!("v{PROTOCOL_VERSION}"))],
                "加密响应应注入 X-WasmNest-Crypto: v1 标记头"
            );
            let decrypted = decrypt_http_body(
                &keys.response,
                &outbound.data,
                &http_aad(Direction::Outbound, "/api/sessions"),
            )
            .unwrap();
            assert_eq!(decrypted, resp_plain);

            // ---- 缓存一次性：第二个同 peer/ek 响应无密钥可取 → 明文直通 ----
            let mut second = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.9:55001",
                "/api/sessions",
                owner,
                "http-1",
            );
            second.direction = Direction::Outbound;
            second.negotiation = &negotiation;
            second.data = b"late".to_vec();
            assert_eq!(LinkEncryptionFilter.on_outbound(&mut second), Verdict::Continue);
            assert_eq!(second.data, b"late");
        });
    }

    /// `off` = 不要求加密，不是禁止加密：客户端自愿加密时过滤器仍解密/回密
    ///
    /// 移动端只有一个全局链路加密开关，无法预知每个应用在对端宿主的策略；若
    /// `off` 拒绝加密请求，开着全局开关的用户会打不开任何 `off` 应用的 HTTP。
    /// 这里锁定「自愿加密被接受且成对回密」，同时保留「过滤器不在链上 → 中间件
    /// fail-visible 400」那条真正的危险路径。
    #[test]
    fn http_off_accepts_client_initiated_encryption() {
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let owner = "com.example.off-voluntary";

        with_app_policy(owner, EncryptionPolicy::Off, || {
            use wasmnest_crypto_engine::x25519::{x25519_diffie_hellman, x25519_generate};

            let client_eph = x25519_generate();
            let (_, kd_pub_b64) = identity_parts().unwrap();
            let kd_pub: [u8; 32] = b64_decode(&kd_pub_b64).unwrap().try_into().unwrap();
            let shared = x25519_diffie_hellman(&client_eph, &kd_pub).unwrap();
            let keys = derive_http_traffic_keys(shared.as_bytes(), "/api/sessions").unwrap();
            let negotiation = format!("v1 {}", b64_encode(client_eph.public()));

            let plain = br#"{"q":"off-app"}"#.to_vec();
            let sealed =
                encrypt_http_body(&keys.request, &plain, &http_aad(Direction::Inbound, "/api/sessions")).unwrap();
            let mut inbound = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.77:55002",
                "/api/sessions",
                owner,
                "http-1",
            );
            inbound.negotiation = &negotiation;
            inbound.data = sealed;
            assert_eq!(LinkEncryptionFilter.on_inbound(&mut inbound), Verdict::Continue);
            assert_eq!(inbound.data, plain, "off 应用的加密请求仍应解出明文");

            let mut outbound = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.77:55002",
                "/api/sessions",
                owner,
                "http-1",
            );
            outbound.direction = Direction::Outbound;
            outbound.negotiation = &negotiation;
            outbound.data = br#"{"code":0}"#.to_vec();
            assert_eq!(LinkEncryptionFilter.on_outbound(&mut outbound), Verdict::Continue);
            assert_eq!(
                outbound.outbound_headers,
                vec![(NEGOTIATION_HEADER.to_string(), format!("v{PROTOCOL_VERSION}"))],
                "自愿加密的请求必须成对回密（否则客户端判降级）"
            );
            let decrypted = decrypt_http_body(
                &keys.response,
                &outbound.data,
                &http_aad(Direction::Outbound, "/api/sessions"),
            )
            .unwrap();
            assert_eq!(decrypted, br#"{"code":0}"#);
        });
    }

    #[test]
    fn http_fail_closed_paths() {
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();

        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let owner = "com.example.failclosed";
        set_app_policy(owner, EncryptionPolicy::Required).unwrap();

        // ① required：未协商请求直接拒绝
        let mut no_neg = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:55002",
            "/api/sessions",
            owner,
            "http-req",
        );
        assert!(matches!(
            LinkEncryptionFilter.on_inbound(&mut no_neg),
            Verdict::Reject(msg) if msg.contains("required")
        ));

        // ② 已协商但载荷损坏 → Reject 且原因含 decrypt failed
        let client_eph = wasmnest_crypto_engine::x25519::x25519_generate();
        let negotiation = format!("v1 {}", b64_encode(client_eph.public()));
        let mut garbage = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:55003",
            "/api/sessions",
            owner,
            "http-req",
        );
        garbage.negotiation = &negotiation;
        garbage.data = b"definitely-not-an-envelope".to_vec();
        assert!(matches!(
            LinkEncryptionFilter.on_inbound(&mut garbage),
            Verdict::Reject(msg) if msg.contains("decrypt failed")
        ));

        // ③ 非法公钥（非 base64/长度错）→ Reject
        let mut bad_key = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:55004",
            "/api/sessions",
            owner,
            "http-req",
        );
        bad_key.negotiation = "v1 !!!not-base64!!!";
        bad_key.data = vec![0u8; 16];
        assert!(matches!(
            LinkEncryptionFilter.on_inbound(&mut bad_key),
            Verdict::Reject(_)
        ));

        remove_app_policy(owner);
    }

    /// GET/HEAD 无请求体协商：空 body + 协商头 → 直接通过并缓存响应密钥，
    /// 出站时响应以 k_resp 加密并回标记头（修复：移动端 GET 请求此前无 body
    /// 可加密但协商必须成立，否则响应密钥缓存缺失、响应加密失效）
    #[test]
    fn http_get_with_empty_body_negotiates_and_encrypts_response() {
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let owner = "com.example.get";

        with_app_policy(owner, EncryptionPolicy::Preferred, || {
            use wasmnest_crypto_engine::x25519::{x25519_diffie_hellman, x25519_generate};

            let client_eph = x25519_generate();
            let (_, kd_pub_b64) = identity_parts().unwrap();
            let kd_pub: [u8; 32] = b64_decode(&kd_pub_b64).unwrap().try_into().unwrap();
            let shared = x25519_diffie_hellman(&client_eph, &kd_pub).unwrap();
            let keys = derive_http_traffic_keys(shared.as_bytes(), "/api/sessions").unwrap();
            let negotiation = format!("v1 {}", b64_encode(client_eph.public()));

            // 入站：空 body（GET）→ 通过，不解信封（无载荷可解）
            let mut inbound = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.9:55005",
                "/api/sessions",
                owner,
                "http-1",
            );
            inbound.negotiation = &negotiation;
            inbound.data = Vec::new();
            assert_eq!(LinkEncryptionFilter.on_inbound(&mut inbound), Verdict::Continue);
            assert!(inbound.data.is_empty(), "空 body 应原样透传");

            // 出站：响应加密 + 标记头（客户端据头解密）
            let resp_plain = br#"{"code":0,"data":[]}"#.to_vec();
            let mut outbound = mk_endpoint_ctx(
                TrafficChannel::Http,
                "192.168.1.9:55005",
                "/api/sessions",
                owner,
                "http-1",
            );
            outbound.direction = Direction::Outbound;
            outbound.negotiation = &negotiation;
            outbound.data = resp_plain.clone();
            assert_eq!(LinkEncryptionFilter.on_outbound(&mut outbound), Verdict::Continue);
            assert_ne!(outbound.data, resp_plain, "GET 响应应加密");
            assert_eq!(
                outbound.outbound_headers,
                vec![(NEGOTIATION_HEADER.to_string(), format!("v{PROTOCOL_VERSION}"))]
            );
            let decrypted = decrypt_http_body(
                &keys.response,
                &outbound.data,
                &http_aad(Direction::Outbound, "/api/sessions"),
            )
            .unwrap();
            assert_eq!(decrypted, resp_plain);
        });
    }

    // ---------- 加密策略域（宿主下限 + 按应用/端点声明） ----------

    /// 策略词表：wire 只认小写字面量，大小写 / 拼写错一律失败（不得静默当明文）
    #[test]
    fn encryption_policy_parsing_is_strict_and_ordered() {
        assert_eq!(
            serde_json::to_string(&EncryptionPolicy::Required).unwrap(),
            "\"required\""
        );
        assert_eq!(
            serde_json::from_str::<EncryptionPolicy>("\"off\"").unwrap(),
            EncryptionPolicy::Off
        );
        assert!(
            serde_json::from_str::<EncryptionPolicy>("\"REQUIRED\"").is_err(),
            "大小写拼错不得静默通过"
        );
        assert!(serde_json::from_str::<EncryptionPolicy>("\"enabled\"").is_err());

        let err = EncryptionPolicy::parse("plain").unwrap_err().to_string();
        assert!(
            err.contains("plain") && err.contains("required") && err.contains("preferred") && err.contains("off"),
            "错误应点名非法取值与合法取值: {err}"
        );
        assert_eq!(
            EncryptionPolicy::parse(" required ").unwrap(),
            EncryptionPolicy::Required
        );
        // 严格度序：off < preferred < required（日志/展示排序基础）
        assert!(EncryptionPolicy::Off < EncryptionPolicy::Preferred);
        assert!(EncryptionPolicy::Preferred < EncryptionPolicy::Required);
        assert!(!EncryptionPolicy::Required.allows_plaintext());
        assert!(EncryptionPolicy::Preferred.allows_plaintext());
        assert!(EncryptionPolicy::Off.allows_plaintext());
    }

    /// 应用策略表：登记 / 审计快照 / 回收（全局表，本用例自清）
    #[test]
    fn app_policy_table_roundtrip_and_purge() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();

        remove_app_policy("policy-test");
        remove_app_policy("policy-other");
        set_app_policy("policy-test", EncryptionPolicy::Required).expect("required 允许（身份已就绪）");
        assert_eq!(app_policy("policy-test"), EncryptionPolicy::Required);
        set_app_policy("policy-other", EncryptionPolicy::Preferred).unwrap();
        assert_eq!(app_policy("policy-other"), EncryptionPolicy::Preferred);

        // 审计快照：排序稳定、wire camelCase、每条带 owner/policy
        let records = app_policies();
        let record = records
            .iter()
            .find(|r| r.owner == "policy-test")
            .expect("策略快照缺 policy-test");
        assert_eq!(record.policy, EncryptionPolicy::Required);
        let json = serde_json::to_value(record).expect("策略快照必须可序列化");
        for key in ["owner", "policy"] {
            assert!(json.get(key).is_some(), "策略 wire 缺字段 {key}: {json}");
        }
        assert!(
            records.windows(2).all(|w| w[0].owner <= w[1].owner),
            "快照须按属主稳定排序"
        );

        // 回收只命中本人
        assert!(remove_app_policy("policy-test"));
        assert_eq!(app_policy("policy-test"), EncryptionPolicy::Off);
        assert_eq!(app_policy("policy-other"), EncryptionPolicy::Preferred);
        remove_app_policy("policy-other");
    }

    /// A/B 共存：同一宿主上 A 应用 required 拒绝明文、B 应用未设置（off）保持明文
    #[test]
    fn app_required_and_plaintext_traffic_coexist() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let owner_a = "com.example.a";
        let owner_b = "com.example.b";
        set_app_policy(owner_a, EncryptionPolicy::Required).expect("required 策略");
        remove_app_policy(owner_b);

        // A：未协商 → 拒绝，文案点名端点 / 属主 / 策略 / 协商头
        let mut a = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:6001",
            "/api/plugin/com.example.a/secret",
            owner_a,
            "http-req",
        );
        match LinkEncryptionFilter.on_inbound(&mut a) {
            Verdict::Reject(msg) => assert!(
                msg.contains("http-req")
                    && msg.contains(owner_a)
                    && msg.contains("required")
                    && msg.contains(NEGOTIATION_HEADER),
                "拒绝文案须点名端点/属主/策略/协商头: {msg}"
            ),
            other => panic!("required 应用未协商时必须拒绝，实际: {other:?}"),
        }

        // B：off 端点接受明文；客户端自愿加密时照常解密（off = 不要求，不是禁止）
        let mut b = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:6002",
            "/api/plugin/com.example.b/status",
            owner_b,
            "http-plain",
        );
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut b), Verdict::Continue);
        assert_eq!(b.data, b"payload", "off 端点明文字节不得改写");

        use wasmnest_crypto_engine::x25519::{x25519_diffie_hellman, x25519_generate};
        let client_eph = x25519_generate();
        let (_, kd_pub_b64) = identity_parts().unwrap();
        let kd_pub: [u8; 32] = b64_decode(&kd_pub_b64).unwrap().try_into().unwrap();
        let shared = x25519_diffie_hellman(&client_eph, &kd_pub).unwrap();
        let route = "/api/plugin/com.example.b/status";
        let keys = derive_http_traffic_keys(shared.as_bytes(), route).unwrap();
        let negotiation = format!("v1 {}", b64_encode(client_eph.public()));
        let voluntary = b"off-voluntary".to_vec();
        b.negotiation = &negotiation;
        b.data = encrypt_http_body(&keys.request, &voluntary, &http_aad(Direction::Inbound, route)).unwrap();
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut b), Verdict::Continue);
        assert_eq!(b.data, voluntary, "off 应用的加密请求仍应解出明文");

        // 出站：上行已缓存响应密钥 → 成对回密（不回密会让客户端判降级）
        let mut b_out = mk_endpoint_ctx(TrafficChannel::Http, "192.168.1.9:6002", route, owner_b, "http-plain");
        b_out.direction = Direction::Outbound;
        b_out.negotiation = &negotiation;
        b_out.data = b"payload".to_vec();
        assert_eq!(LinkEncryptionFilter.on_outbound(&mut b_out), Verdict::Continue);
        assert_eq!(
            b_out.outbound_headers,
            vec![(NEGOTIATION_HEADER.to_string(), format!("v{PROTOCOL_VERSION}"))],
            "自愿加密必须成对回密"
        );
        let decrypted = decrypt_http_body(&keys.response, &b_out.data, &http_aad(Direction::Outbound, route)).unwrap();
        assert_eq!(decrypted, b"payload");

        remove_app_policy(owner_a);
        remove_app_policy(owner_b);
    }

    /// WS 应用 required + 未协商连接 → Reject（fail-visible，不降级成明文）
    #[test]
    fn ws_required_endpoint_rejects_unpaired_connection() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let owner = "com.example.ws";
        let peer = "192.168.1.70:7001";
        ws_remove_ciphers(peer);

        set_app_policy(owner, EncryptionPolicy::Required).expect("required 策略");
        let mut inbound = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", owner, "wse-req");
        match LinkEncryptionFilter.on_inbound(&mut inbound) {
            Verdict::Reject(msg) => assert!(
                msg.contains("wse-req") && msg.contains("required") && msg.contains("no negotiated session cipher"),
                "拒绝文案须点名端点/策略/缺口: {msg}"
            ),
            other => panic!("required 端点无会话密码时必须拒绝，实际: {other:?}"),
        }
        let mut outbound = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "binary", owner, "wse-req");
        outbound.direction = Direction::Outbound;
        assert!(matches!(
            LinkEncryptionFilter.on_outbound(&mut outbound),
            Verdict::Reject(_)
        ));

        // 同一应用改为 preferred：无密码连接仍然放行（机会主义）
        set_app_policy(owner, EncryptionPolicy::Preferred).unwrap();
        let mut opt = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", owner, "wse-req");
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut opt), Verdict::Continue);
        assert_eq!(opt.data, b"payload");

        remove_app_policy(owner);
    }

    /// 明文放行审计：同一端点只记首次（其余去重），无身份不记
    #[test]
    fn plaintext_audit_records_first_connection_per_endpoint() {
        assert!(
            note_plaintext_connection("com.example.audit-first", "http-first"),
            "首次明文放行应留痕"
        );
        assert!(
            !note_plaintext_connection("com.example.audit-first", "http-first"),
            "同一端点重复放行应去重（否则逐请求刷日志）"
        );
        assert!(
            note_plaintext_connection("com.example.audit-first", "wse-second"),
            "同一应用的另一端点独立计数"
        );
        assert!(
            !note_plaintext_connection("", "http-first"),
            "无属主身份（宿主自有面）不记端点审计"
        );
        assert!(
            !note_plaintext_connection("com.example.audit-first", ""),
            "无端点身份不记端点审计"
        );
        reset_plaintext_audit();
    }

    /// 能力查询：按应用策略已支持、身份如实上报
    #[test]
    fn capabilities_report_supported_policy_surface() {
        let caps = capabilities();
        assert!(caps.app_scoped_policy, "本版本支持按应用设置策略");
        assert_eq!(caps.policies, vec!["required", "preferred", "off"]);
        assert!(caps.key_models.contains(&"paired-http-path-bound"));
        assert!(caps.ws_session, "WS 升级期链路加密已接线，能力查询必须如实上报");
        // 身份可用时指纹随能力一起下发（应用声明 required 前用于确认）
        if let Some(fp) = identity_fingerprint() {
            assert_eq!(caps.identity_fingerprint.as_deref(), Some(fp));
        }
        // wire 形状（serde camelCase）是前端接口镜像真源：多单词字段必须驼峰，
        // 否则前端读 undefined 会误判「宿主不支持按应用策略」
        let json = serde_json::to_value(&caps).expect("能力查询必须可序列化");
        for key in [
            "appScopedPolicy",
            "policies",
            "identityFingerprint",
            "keyModels",
            "wsSession",
        ] {
            assert!(json.get(key).is_some(), "能力查询 wire 缺字段 {key}: {json}");
        }
    }

    // ---------- 错误边界映射（P0：crypto-engine / link-crypto 错误归域后） ----------

    /// 输入非法类 `CryptoError` 落 `AppError::InvalidInput`，文案逐字保留
    /// （`Display` = 变体前缀 + detail 原文；改造前 detail 直接就是 `InvalidInput` 载荷）
    #[test]
    fn crypto_error_maps_to_app_error_by_variant_semantics() {
        let invalid_input_cases = [
            wasmnest_crypto_engine::CryptoError::invalid_key_length("aes-256-gcm: 密钥长度必须为 32 字节，收到 5"),
            wasmnest_crypto_engine::CryptoError::invalid_nonce_length("aes-256-gcm: nonce 长度必须为 12 字节，收到 3"),
            wasmnest_crypto_engine::CryptoError::unsupported_algorithm("未知 AEAD 算法: 'toy'（不在白名单）"),
            wasmnest_crypto_engine::CryptoError::invalid_input("base64 解码失败: invalid symbol"),
        ];
        for err in invalid_input_cases {
            let detail = err.detail().to_string();
            let mapped = crypto_to_app_error(err);
            assert!(
                matches!(mapped, AppError::InvalidInput(_)),
                "输入非法类必须映射到 InvalidInput: {mapped}"
            );
            // 逐字：变体前缀 + 原文 detail（与改造前 AppError::InvalidInput 的 Display 一致）
            assert_eq!(mapped.to_string(), format!("Invalid input: {detail}"));
        }

        let detail = "AES-256-GCM 解密失败: aead::Error";
        let mapped = crypto_to_app_error(wasmnest_crypto_engine::CryptoError::operation_failed(detail));
        assert!(
            matches!(mapped, AppError::Internal(_)),
            "算法执行失败必须映射到 Internal"
        );
        assert_eq!(mapped.to_string(), format!("Internal error: {detail}"));
    }

    /// `LinkCryptoError` 落 `AppError::Internal`，文案逐字保留
    #[test]
    fn link_crypto_error_maps_to_app_error_internal_verbatim() {
        // 用协议核心真实错误路径构造（非法 base64 是最稳定的输入侧失败）
        let err = b64_decode("!!!not-base64!!!").expect_err("非法 base64 必须失败");
        let detail = err.to_string();
        let mapped = link_crypto_to_app_error(err);
        assert!(matches!(mapped, AppError::Internal(_)));
        assert_eq!(mapped.to_string(), format!("Internal error: {detail}"));
    }

    /// rusqlite 错误 → `AppError::Database(String)`：信封语义不变（仍落 host.internal 兜底码）
    #[test]
    fn db_error_maps_to_string_variant_without_envelope_change() {
        let mapped = db_error(rusqlite::Error::InvalidQuery);
        match &mapped {
            AppError::Database(msg) => assert!(!msg.is_empty(), "Database 必须携带非空文案"),
            other => panic!("rusqlite 错误必须落 Database: {other}"),
        }
        let envelope = serde_json::to_value(&mapped).expect("AppError 必须可序列化");
        assert_eq!(envelope["code"], serde_json::json!("host.internal"));
    }

    // ---------- 面标记（peer 面加密裁决，T04） ----------

    /// 不变量 15（桌面侧测试锁）：peer 面 loopback 流量不得被环回豁免
    #[test]
    fn peer_face_loopback_is_never_exempt() {
        let mut ctx = mk_ctx(TrafficChannel::Http, "127.0.0.1:54321", "/api/sessions");
        ctx.face = RequestFace::peer_face(Some("node-1".to_string()), false);
        assert!(
            LinkEncryptionFilter::policy_of(&ctx).is_some(),
            "peer 面即使源地址为 loopback 也必须进入加密裁决"
        );
    }

    /// T07 测试锁：旧客户端（不发起协商）在 `required` 下被显性判为
    /// `encryption-unsupported`，且**没有明文回退**。
    ///
    /// 判据三层同时断言：① 拒绝码是 `encryption-unsupported`（不是笼统的
    /// `encryption-required`，也不是无码自由文本）；② 文案点名升级 / 配对出路；
    /// ③ 请求体没有被替换成「放行」——`Reject` 而不是 `Continue`。
    #[test]
    fn required_without_any_negotiation_is_encryption_unsupported() {
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let owner = "com.example.legacy-client";
        set_app_policy(owner, EncryptionPolicy::Required).unwrap();

        // ① 普通面（LAN 旧客户端直连）：无协商头
        let mut lan = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.40:55002",
            "/api/sessions",
            owner,
            "http-req",
        );
        let lan_verdict = LinkEncryptionFilter.on_inbound(&mut lan);
        assert_eq!(
            reason_code(match &lan_verdict {
                Verdict::Reject(reason) => reason,
                other => panic!("required + 无协商必须拒绝，实际 {other:?}"),
            }),
            Some(CODE_ENCRYPTION_UNSUPPORTED),
            "无协商头 = 对端不具备协商能力，拒绝码必须是 encryption-unsupported"
        );

        // ② peer 面（隧道入口的旧客户端）：同样无协商头，同样不得豁免
        let mut peer = mk_endpoint_ctx(
            TrafficChannel::Http,
            "127.0.0.1:54322",
            "/api/sessions",
            owner,
            "http-req",
        );
        peer.face = RequestFace::peer_face(Some("node-legacy".to_string()), false);
        let peer_verdict = LinkEncryptionFilter.on_inbound(&mut peer);
        let peer_reason = match &peer_verdict {
            Verdict::Reject(reason) => reason,
            other => panic!("peer 面 required + 无协商必须拒绝，实际 {other:?}"),
        };
        assert_eq!(reason_code(peer_reason), Some(CODE_ENCRYPTION_UNSUPPORTED));
        // 文案给出路：升级对端 / 先配对（宿主不知道是哪一种，不假装知道）
        let text = peer_reason.to_ascii_lowercase();
        assert!(text.contains("upgrade the peer"), "必须给升级提示: {peer_reason}");
        assert!(text.contains("pair it first"), "未配对客户端也要有出路: {peer_reason}");
        assert!(
            text.contains("plaintext is not accepted"),
            "不得让用户以为可降级: {peer_reason}"
        );
        assert_eq!(peer.data, b"payload".to_vec(), "拒绝路径不得把载荷当明文放行");

        remove_app_policy(owner);
    }

    /// T07 测试锁（对照）：**发起过**协商但链路建不起来 → `encryption-required`
    ///
    /// 两类必须分开：旧客户端（无协商）给升级提示，坏协商给「检查链路身份 / 重新
    /// 配对」——否则用户会被告知去升级一个已经升级过的对端。
    #[test]
    fn required_with_broken_negotiation_is_encryption_required() {
        use wasmnest_crypto_engine::x25519::x25519_generate;

        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();

        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let owner = "com.example.broken-negotiation";
        set_app_policy(owner, EncryptionPolicy::Required).unwrap();

        // 协商头合法、密钥正常，但信封载荷损坏（对端僵实现 / 中间件改写）
        let client_eph = x25519_generate();
        let negotiation = format!("v1 {}", b64_encode(client_eph.public()));
        let mut ctx = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.41:55003",
            "/api/sessions",
            owner,
            "http-req",
        );
        ctx.negotiation = &negotiation;
        ctx.data = b"definitely-not-an-envelope".to_vec();
        let verdict = LinkEncryptionFilter.on_inbound(&mut ctx);
        match verdict {
            Verdict::Reject(reason) => assert_eq!(
                reason_code(&reason),
                Some(CODE_ENCRYPTION_REQUIRED),
                "协商已发起但解密失败应归 encryption-required: {reason}"
            ),
            other => panic!("坏协商必须拒绝，实际 {other:?}"),
        }

        remove_app_policy(owner);
    }

    /// 不变量 15：peer 面仅保留配对引导白名单，路径穿越不得骗豁免
    #[test]
    fn peer_face_exempts_pairing_endpoint_only() {
        let face = RequestFace::peer_face(None, true);
        let mut pairing = mk_ctx(TrafficChannel::Http, "127.0.0.1:54321", "/api/auth/pairing");
        pairing.face = face.clone();
        assert!(LinkEncryptionFilter::policy_of(&pairing).is_none());

        for route in ["/api/auth/../plugin/bedcode/task-status", "/api/sessions"] {
            let mut ctx = mk_ctx(TrafficChannel::Http, "127.0.0.1:54321", route);
            ctx.face = face.clone();
            assert!(
                LinkEncryptionFilter::policy_of(&ctx).is_some(),
                "peer 面路径 {route} 不得豁免"
            );
        }
    }

    /// 回归保护：普通面的 loopback 本地豁免不受面标记改动影响
    #[test]
    fn ordinary_face_loopback_remains_exempt() {
        let ctx = mk_ctx(TrafficChannel::Http, "127.0.0.1:54321", "/api/sessions");
        assert!(LinkEncryptionFilter::policy_of(&ctx).is_none());
    }
}
