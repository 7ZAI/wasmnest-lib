//! Link Crypto — 局域网链路报文加密（HTTP/WS 载荷）
//!
//! 规划文档：`.scratch/http-ws-payload-encryption/spec.md`。本模块是链路加密的
//! 宿主侧协议与开关中心，职责四块：
//!
//! 1. **配置域** [`LinkCryptoConfig`]：全部默认关闭（opt-in），持久化于 DB
//!    settings 表单键 [`SETTING_KEY`]；运行期经 [`current_config`] /
//!    [`update_config`] 快照热更新，过滤器逐流量读取、不做注册/注销抖动。
//! 2. **身份密钥 Kd** [`LinkIdentity`]：桌面端静态 X25519 密钥对，首启生成、
//!   落盘 `app_data_dir/link_crypto_identity.json`（与 peer-net node_identity.json
//!   同目录同模式）；指纹 = SHA-256(公钥) 前 16 hex，供移动端 pin 与人工核对。
//!   已存在但损坏时拒绝重建而非静默换钥——静默换钥会让移动端 pin 全部失效，
//!   与 peer-net 身份决策 D3 同理。
//! 3. **HKDF 方向分离派生**：ECDH 共享密钥 → 各方向独立 AES-256 会话密钥，
//!    info 常量是跨端兼容性表面（移动端 TS 实现必须逐字节一致）。
//! 4. **过滤器骨架** [`LinkEncryptionFilter`]：注册进 `TrafficFilterChain` 的
//!    转换型过滤器。本地豁免三分支与通道子开关判定已完整实现；豁免外流量的
//!    真实加解密由 issue 02（HTTP 信封）/ issue 04（WS 帧）在本模块填充。
//!
//! 决策模型（spec §6）：发送方配置决定参与意愿 → 接收方按线上信封自动识别 →
//! 响应绑定与降级检测两条强制安全耦合在 issue 02/04 落地。

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use wasmnest_crypto_engine::provider::{
    AeadProvider, KdfProvider, KeyAgreementProvider, AEAD_AES_256_GCM, KDF_HKDF_SHA256, KEY_AGREEMENT_X25519,
};
use wasmnest_crypto_engine::registry::{resolve_aead, resolve_kdf, resolve_key_agreement};

use crate::filter::{Direction, FilterContext, TrafficChannel, TrafficFilter, TrafficFilterChain, Verdict};
use wasmnest_server_base::error::{AppError, Result};

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
    b64_decode, b64_encode, decrypt_http_body, encrypt_http_body, parse_negotiation, HttpEnvelope, WsDirectionCipher,
    WsTextEnvelope, HTTP_INFO_REQUEST, HTTP_INFO_RESPONSE, NEGOTIATION_HEADER, ORIGIN_BINARY, ORIGIN_TEXT,
    PROTOCOL_VERSION, WS_BINARY_HEADER_LEN, WS_FRAME_VERSION, WS_INFO_CLIENT_TO_SERVER, WS_INFO_SERVER_TO_CLIENT,
    WS_TRANSCRIPT_PREFIX,
};

// ==================== 常量 ====================

/// DB settings 表中的配置键（值为 LinkCryptoConfig 的 JSON 序列化）
pub const SETTING_KEY: &str = "trafficEncryption";

/// 身份密钥落盘文件名（与 node_identity.json 并列同目录）
const IDENTITY_FILE: &str = "link_crypto_identity.json";

/// 身份文件格式版本：密钥语义变化时递增并走迁移/拒绝路径
const IDENTITY_FORMAT_VERSION: u32 = 1;

/// 过滤器注册名（注销与日志定位用）
pub const FILTER_NAME: &str = "link-crypto";

// HKDF info 常量——协议兼容性表面，issue 05 移动端 TS 实现必须逐字节一致
// （已抽至共享 crate，经上方 pub use 保持既有路径可见）

// ==================== 配置域 ====================

/// 链路加密配置域（spec §6）
///
/// 默认值即「功能整体关闭」：`enabled=false` 时过滤器不注册，其余字段不生效；
/// 子通道开关默认 true 是有意设计——用户只需打开主开关即获全通道覆盖，
/// 粒度收窄是显式动作。未知字段一律拒绝（防前端拼写错误的开关被静默吞掉）。
///
/// **`floor` 与旧字段的关系**：`floor` 是权威的宿主下限；旧字段
/// （`enabled` / `encrypt_*` / `allow_plaintext_fallback`）保留为**迁移输入**——
/// 旧配置记录没有 `floor` 时按 [`LinkCryptoConfig::host_floor`] 的映射推导，
/// 一旦写入 `floor`，旧子开关不再参与裁决（[`LinkCryptoConfig::channel_floor`]）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkCryptoConfig {
    /// 主开关：false 时过滤器不注册，全服务明文（与现状一致）
    ///
    /// 迁移态下与 `floor` 同源；写 `floor` 时本字段由
    /// [`LinkCryptoConfig::from_floor`] 同步（floor != off ⇒ true）。
    #[serde(default)]
    pub enabled: bool,
    /// HTTP REST 载荷加解密（迁移输入：仅在无 `floor` 的旧记录里生效）
    #[serde(default = "default_true")]
    pub encrypt_http: bool,
    /// WS 终端通道帧加解密（迁移输入，同上）
    #[serde(default = "default_true")]
    pub encrypt_ws_terminal: bool,
    /// WS 事件通道帧加解密（迁移输入，同上）
    #[serde(default = "default_true")]
    pub encrypt_ws_event: bool,
    /// 服务端对未协商的老客户端放行明文（迁移输入，同上）
    #[serde(default = "default_true")]
    pub allow_plaintext_fallback: bool,
    /// 宿主下限（`required` / `preferred` / `off`）
    ///
    /// `None` = 迁移态：按 `enabled` + `allow_plaintext_fallback` 推导（见
    /// [`LinkCryptoConfig::host_floor`]）。宿主设置页写入口一律写 `Some(..)`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<EncryptionPolicy>,
}

fn default_true() -> bool {
    true
}

impl Default for LinkCryptoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            encrypt_http: true,
            encrypt_ws_terminal: true,
            encrypt_ws_event: true,
            allow_plaintext_fallback: true,
            floor: None,
        }
    }
}

impl LinkCryptoConfig {
    /// 宿主下限（含迁移推导；spec §6 迁移映射）
    ///
    /// - `enabled=false` → `off`（保持现状：默认明文，应用可主动 `required`）
    /// - `enabled=true` + `allow_plaintext_fallback=true` → `preferred`
    /// - `enabled=true` + `allow_plaintext_fallback=false` → `required`
    pub fn host_floor(&self) -> EncryptionPolicy {
        match self.floor {
            Some(floor) => floor,
            None if !self.enabled => EncryptionPolicy::Off,
            None if self.allow_plaintext_fallback => EncryptionPolicy::Preferred,
            None => EncryptionPolicy::Required,
        }
    }

    /// 某通道的下限
    ///
    /// 显式 `floor` 是权威（旧逐通道子开关不再参与裁决——它们无法表达
    /// 「required」，留着会让 `required` 被一个旧开关静默降级）。
    /// 迁移态沿用逐通道子开关；插件 WS 端点（`WsPlugin`）在迁移态恒 `off`——
    /// 它在旧模型里从未参与链路加密，迁移必须保持这一事实（不静默改变姿态）。
    pub fn channel_floor(&self, channel: TrafficChannel) -> EncryptionPolicy {
        if self.floor.is_some() {
            return self.host_floor();
        }
        if !self.enabled {
            return EncryptionPolicy::Off;
        }
        let channel_enabled = match channel {
            TrafficChannel::Http => self.encrypt_http,
            TrafficChannel::WsTerminal => self.encrypt_ws_terminal,
            TrafficChannel::WsEvent => self.encrypt_ws_event,
            TrafficChannel::WsPlugin => false,
        };
        if !channel_enabled {
            return EncryptionPolicy::Off;
        }
        if self.allow_plaintext_fallback {
            EncryptionPolicy::Preferred
        } else {
            EncryptionPolicy::Required
        }
    }

    /// 由宿主下限构造配置（设置页写入口的唯一构造点：`floor` 与 `enabled` 同源，
    /// 避免「floor=required 但 enabled=false」这种自相矛盾的落库值）
    pub fn from_floor(floor: EncryptionPolicy) -> Self {
        Self {
            enabled: floor != EncryptionPolicy::Off,
            floor: Some(floor),
            ..Self::default()
        }
    }
}

/// 运行期配置快照（单例）：过滤器热路径只做一次读锁克隆，无注册/注销抖动
static CONFIG_SNAPSHOT: LazyLock<RwLock<LinkCryptoConfig>> = LazyLock::new(|| RwLock::new(LinkCryptoConfig::default()));

/// 读取当前配置快照
pub fn current_config() -> LinkCryptoConfig {
    CONFIG_SNAPSHOT.read().map(|guard| guard.clone()).unwrap_or_else(|_| {
        // 锁中毒退化为默认值（全关），可用性优先；中毒方已记 error
        tracing::error!("link crypto config snapshot lock poisoned, using default");
        LinkCryptoConfig::default()
    })
}

/// 更新配置快照（调用方负责先持久化成功再更新内存态）
pub fn update_config(config: LinkCryptoConfig) {
    match CONFIG_SNAPSHOT.write() {
        Ok(mut guard) => *guard = config,
        Err(_) => tracing::error!("link crypto config snapshot lock poisoned, update dropped"),
    }
}

/// 从 DB settings 表加载配置；键不存在或 JSON 非法均回退默认值（全关）
///
/// 非法 JSON 只 warn 不报错：配置损坏不应阻断启动，用户重存一次即可修复。
pub fn load_config_from_db(conn: &rusqlite::Connection) -> LinkCryptoConfig {
    let json = match conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        rusqlite::params![SETTING_KEY],
        |row| row.get::<_, String>(0),
    ) {
        Ok(json) => json,
        Err(e) => {
            // 表不存在 / 键缺失 / 读失败：一律回退默认（全关），不 panic
            tracing::warn!(
                key = SETTING_KEY,
                "read traffic encryption config failed, falling back to default (all off): {e}"
            );
            return LinkCryptoConfig::default();
        }
    };
    serde_json::from_str(&json).unwrap_or_else(|e| {
        tracing::warn!(
            key = SETTING_KEY,
            "traffic encryption config corrupt, falling back to default (all off): {e}"
        );
        LinkCryptoConfig::default()
    })
}

/// 持久化配置到 DB settings 表（JSON 序列化失败属程序错误，上抛）
pub fn persist_config_to_db(conn: &rusqlite::Connection, config: &LinkCryptoConfig) -> Result<()> {
    let json = serde_json::to_string(config)?;
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![SETTING_KEY, json, now],
    )?;
    Ok(())
}

// ==================== 加密策略域（宿主下限 + 按应用/端点声明） ====================
//
// 三层模型（spec §1）：宿主下限（本模块配置域）▸ 端点声明（本段）▸ 逐连接协商
// （过滤器）。应用只能提高严格度，不能降低下限：把声明登记在**宿主侧表**里，
// 过滤器按 `(owner, endpoint)` 查 `effective = strictest(floor, declared)`。
//
// 身份真源：`owner` / `endpoint` 只来自端点注册表（HTTP 注册记录 / WS 端点表），
// 过滤器不解析 URL 猜属主，也不接受请求方自报（spec §3 / 安全不变量 4）。

/// 链路加密严格度（端点声明与宿主下限共用词表）
///
/// `Ord` 顺序 `Off < Preferred < Required` 即严格度顺序，「取更严者」用
/// [`strictest`]（内部就是 `max`）。serde 只认小写字面量，未知取值解析失败——
/// 端点注册配置里写错一个字母不允许静默当成明文。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionPolicy {
    /// 明文：不进入加解密（宿主下限更严时，注册阶段即失败——fail-visible）
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

    /// 可选字段解析：缺省/空串 → 默认值（端点注册未声明 = `preferred`）
    pub fn parse_opt(raw: Option<&str>, default: EncryptionPolicy) -> Result<Self> {
        match raw {
            Some(value) if !value.trim().is_empty() => Self::parse(value),
            _ => Ok(default),
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

/// 取更严者：`effective = strictest(host_floor, endpoint_policy)`
pub fn strictest(a: EncryptionPolicy, b: EncryptionPolicy) -> EncryptionPolicy {
    a.max(b)
}

/// 一条已登记的端点策略（宿主设置页 / 审计面数据源；不含载荷与密钥）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointPolicyRecord {
    /// 属主插件 id
    pub owner: String,
    /// 端点句柄（`http-*` / `wse-*`）
    pub endpoint: String,
    /// 端点声明的策略（未声明的端点不在本表——它们跟随宿主下限）
    pub policy: EncryptionPolicy,
}

/// 端点策略表：键 = (属主插件 id, 端点句柄)
///
/// 端点句柄由宿主注册表铸造（UUID），插件无法伪造他端点的身份。
static ENDPOINT_POLICIES: LazyLock<RwLock<HashMap<(String, String), EncryptionPolicy>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn policy_lock() -> std::sync::RwLockReadGuard<'static, HashMap<(String, String), EncryptionPolicy>> {
    ENDPOINT_POLICIES.read().unwrap_or_else(|e| e.into_inner())
}

/// 登记端点策略（端点注册表在挂牌前调用；返回 Err = 端点注册应整体失败）
///
/// 两条拒绝判据（fail-visible，不静默改档）：
/// 1. 声明 `off` 而宿主下限更严 → 拒绝（否则就是「管理员要求加密、应用偷偷明文」）；
/// 2. 声明 `required` 而本进程链路身份不可用 → 拒绝（否则注册成功却根本无法加密）。
///
/// `channel` 决定用哪条通道下限做判据（HTTP / 插件 WS 各自的下限可能不同）。
pub fn declare_endpoint_policy(
    owner: &str,
    endpoint: &str,
    policy: Option<EncryptionPolicy>,
    channel: TrafficChannel,
) -> std::result::Result<(), String> {
    let floor = current_config().channel_floor(channel);
    // 未声明 = 跟随宿主下限：没有需要登记/校验的声明（也无需为自己的端点背书）
    let Some(policy) = policy else {
        withdraw_endpoint_policy(owner, endpoint);
        return Ok(());
    };
    check_declaration(owner, endpoint, policy, floor, channel, IDENTITY.get().is_some())?;

    match ENDPOINT_POLICIES.write() {
        Ok(mut map) => {
            map.insert((owner.to_string(), endpoint.to_string()), policy);
        }
        Err(_) => {
            return Err(format!(
                "endpoint policy registry lock poisoned, endpoint '{endpoint}' of plugin '{owner}' rejected"
            ))
        }
    }

    // 明文端点必须可见、可审计（spec §7 / 安全不变量 5）：注册即留痕，
    // 但不写载荷 / 密钥材料
    if policy == EncryptionPolicy::Off {
        tracing::info!(
            plugin_id = %owner,
            endpoint = %endpoint,
            channel = channel.as_str(),
            floor = %floor,
            "plaintext endpoint registered (encryption off)"
        );
    } else {
        tracing::debug!(
            plugin_id = %owner,
            endpoint = %endpoint,
            channel = channel.as_str(),
            policy = %policy,
            floor = %floor,
            "endpoint encryption policy registered"
        );
    }

    // 端点声明可能把「全关」的下限抬高（off floor + required 端点），
    // 过滤器注册状态要跟着走
    sync_registration();
    Ok(())
}

/// 声明合法性判据（纯函数：身份可用性由调用方给，便于逐条单测）
fn check_declaration(
    owner: &str,
    endpoint: &str,
    policy: EncryptionPolicy,
    floor: EncryptionPolicy,
    channel: TrafficChannel,
    identity_available: bool,
) -> std::result::Result<(), String> {
    if policy == EncryptionPolicy::Off && floor != EncryptionPolicy::Off {
        return Err(format!(
            "encryption policy 'off' rejected: host floor is '{floor}' ({}), endpoint '{endpoint}' of plugin '{owner}' may not serve plaintext",
            channel.as_str()
        ));
    }
    if policy == EncryptionPolicy::Required && !identity_available {
        return Err(format!(
            "encryption policy 'required' rejected: link identity unavailable on this host, endpoint '{endpoint}' of plugin '{owner}' cannot be encrypted"
        ));
    }
    Ok(())
}

/// 注销单个端点策略（端点注销 / 回收时调用；未知键幂等）
pub fn withdraw_endpoint_policy(owner: &str, endpoint: &str) {
    if let Ok(mut map) = ENDPOINT_POLICIES.write() {
        map.remove(&(owner.to_string(), endpoint.to_string()));
    }
    sync_registration();
}

/// 回收属主的全部端点策略（插件停用 / 卸载；只碰本人）
pub fn withdraw_endpoint_policies(owner: &str) -> usize {
    let removed = match ENDPOINT_POLICIES.write() {
        Ok(mut map) => {
            let before = map.len();
            map.retain(|(key_owner, _), _| key_owner != owner);
            before - map.len()
        }
        Err(_) => 0,
    };
    if removed > 0 {
        tracing::debug!(plugin_id = %owner, count = removed, "endpoint encryption policies withdrawn");
        sync_registration();
    }
    removed
}

/// 端点声明的策略（未声明 = `None`；调用方按 `preferred` 缺省）
pub fn endpoint_policy(owner: &str, endpoint: &str) -> Option<EncryptionPolicy> {
    policy_lock().get(&(owner.to_string(), endpoint.to_string())).copied()
}

/// 生效策略 = `strictest(channel_floor, declared)`
///
/// - 端点**未声明** → 完全跟随通道下限（spec §2「缺省跟随 floor」）；
/// - 端点**有声明** → 取更严者（只升不降）；
/// - `owner` / `endpoint` 为空（宿主自有面 / 未注册路径）→ 没有端点维度，按通道
///   下限执行。
pub fn effective_endpoint_policy(owner: &str, endpoint: &str, channel: TrafficChannel) -> EncryptionPolicy {
    let floor = current_config().channel_floor(channel);
    if owner.is_empty() || endpoint.is_empty() {
        return floor;
    }
    match endpoint_policy(owner, endpoint) {
        Some(declared) => strictest(floor, declared),
        None => floor,
    }
}

/// 当前已登记的端点策略快照（宿主设置页「明文端点清单」数据源）
pub fn declared_endpoint_policies() -> Vec<EndpointPolicyRecord> {
    let mut records: Vec<EndpointPolicyRecord> = policy_lock()
        .iter()
        .map(|((owner, endpoint), policy)| EndpointPolicyRecord {
            owner: owner.clone(),
            endpoint: endpoint.clone(),
            policy: *policy,
        })
        .collect();
    records.sort_by(|a, b| (&a.owner, &a.endpoint).cmp(&(&b.owner, &b.endpoint)));
    records
}

/// 能力查询（宿主 → 本模块）：应用注册 `required` 端点前必须能确认本端支持
/// per-endpoint 策略与对应密钥模型，旧宿主不支持时应用必须拒绝启用该业务
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkCryptoCapabilities {
    /// 是否支持按端点声明加密策略（旧宿主缺此能力）
    pub per_endpoint_policy: bool,
    /// 端点策略可取的全部取值（wire 字面量）
    pub endpoint_policies: Vec<&'static str>,
    /// 当前宿主下限
    pub floor: EncryptionPolicy,
    /// 链路身份指纹（未初始化 = None，此时 `required` 端点注册会被拒绝）
    pub identity_fingerprint: Option<String>,
    /// 可用密钥模型（配对设备的 HTTP 路径绑定 / 配对设备的 WS 会话密码）
    pub key_models: Vec<&'static str>,
}

/// 本进程的链路加密能力快照
pub fn capabilities() -> LinkCryptoCapabilities {
    LinkCryptoCapabilities {
        per_endpoint_policy: true,
        endpoint_policies: vec![
            EncryptionPolicy::Required.as_str(),
            EncryptionPolicy::Preferred.as_str(),
            EncryptionPolicy::Off.as_str(),
        ],
        floor: current_config().host_floor(),
        identity_fingerprint: identity_fingerprint().map(|fp| fp.to_string()),
        key_models: vec!["paired-http-path-bound", "paired-ws-session"],
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
    /// - 目录下无文件 → 生成新密钥对并落盘（首次启动）；
    /// - 文件存在且合法 → 加载（重启后指纹不变，pin 不失效）；
    /// - 文件存在但损坏/版本不符 → 报错拒绝重建：静默换钥会让移动端 pin 全部
    ///   失效，宁可本次启动禁用加密并由用户显式处理。
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
        std::fs::write(&path, json).map_err(|e| AppError::Internal(format!("write {}: {e}", path.display())))?;
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
    let req = DATA_KDF.derive(Some(salt), shared_ikm, HTTP_INFO_REQUEST, 32)?;
    let resp = DATA_KDF.derive(Some(salt), shared_ikm, HTTP_INFO_RESPONSE, 32)?;
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
    let hs = proto::derive_server_handshake(client_ek_b64, identity.keypair().private(), &s_ephemeral_private)?;

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
        Err(_) => tracing::error!(addr, "ws cipher registry lock poisoned, register dropped"),
    }
}

/// 断连清理（terminal_ws disconnected 调用）
pub fn ws_remove_ciphers(addr: &str) {
    if let Ok(mut map) = WS_CIPHERS.lock() {
        map.remove(addr);
    }
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
    let nonce_v = b64_decode(&envelope.n)?;
    let nonce: [u8; 12] = nonce_v
        .try_into()
        .map_err(|v: Vec<u8>| AppError::Internal(format!("nonce length mismatch: {}", v.len())))?;
    let ciphertext = b64_decode(&envelope.ct)?;

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
    let plain = DATA_AEAD.decrypt(
        &c.client_to_server.key,
        &nonce,
        &ciphertext,
        Some(&ws_aad(channel_str, Direction::Inbound, ORIGIN_TEXT)),
    )?;
    c.c2s_expected_seq += 1;
    String::from_utf8(plain).map_err(|e| AppError::Internal(format!("decrypted text not utf-8: {e}")))
}

struct SealedPayload {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

fn encrypt_ws_payload(cipher: &WsDirectionCipher, seq: u64, plaintext: &[u8], aad: &[u8]) -> Result<SealedPayload> {
    let nonce = ws_nonce(&cipher.nonce_prefix, seq);
    let ciphertext = DATA_AEAD.encrypt(&cipher.key, &nonce, plaintext, Some(aad))?;
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
    let plain = DATA_AEAD.decrypt(
        &c.client_to_server.key,
        &ws_nonce(&c.client_to_server.nonce_prefix, seq),
        ciphertext,
        Some(&ws_aad(channel_str, Direction::Inbound, ORIGIN_BINARY)),
    )?;
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
    route.starts_with("/api/auth/") || route == "/health" || route == "/api/health"
}

/// 解析 FilterContext.peer 为 SocketAddr（HTTP = 客户端地址，WS = 连接对端地址）
fn parse_peer(peer: &str) -> Option<std::net::SocketAddr> {
    peer.parse().ok()
}

/// 本地豁免判定（spec §4，硬约束不受开关影响）：
/// ① 环回对端（hook 脚本调 /api/plugin/*、本机工具直连 REST）；
/// ② 配对引导白名单路由。
/// peer 无法解析时视为远端（fail-safe：宁多过滤不放行）。
fn is_exempt(ctx: &FilterContext<'_>) -> bool {
    if parse_peer(ctx.peer).is_some_and(|addr| addr.ip().is_loopback()) {
        return true;
    }
    matches!(ctx.channel, TrafficChannel::Http) && is_plaintext_whitelisted(ctx.route)
}

impl LinkEncryptionFilter {
    /// 本流量的生效策略；`None` = 本地豁免（环回 / 宿主引导面，不受任何策略影响）
    ///
    /// 策略 = `strictest(通道下限, 端点声明)`。端点身份（属主 / 端点句柄）由宿主
    /// 注册表注入到 [`FilterContext`]，本函数不解析 URL 猜身份、不接受对端自报。
    pub fn policy_of(ctx: &FilterContext<'_>) -> Option<EncryptionPolicy> {
        if is_exempt(ctx) {
            return None;
        }
        Some(effective_endpoint_policy(ctx.owner, ctx.endpoint, ctx.channel))
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
    /// Reject 由 WS 接线点升级为 Close 4003）；未注册（明文会话）→ 按端点策略裁决
    fn on_ws_frame(ctx: &mut FilterContext<'_>, policy: EncryptionPolicy) -> Verdict {
        if !ws_has_ciphers(ctx.peer) {
            return if policy.allows_plaintext() {
                Verdict::Continue
            } else {
                Verdict::Reject(format!(
                    "link encryption required (policy '{}') but this connection has no negotiated session cipher: {}; pair the client or lower the endpoint policy",
                    policy.as_str(),
                    Self::endpoint_hint(ctx)
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
                Verdict::Reject(format!("ws frame crypto failed: {e}"))
            }
        }
    }

    /// HTTP 入站：协商 → ECDH(Kd, ek) 派生 → 解信封 → 缓存响应密钥。
    /// 任一步失败一律 Reject（fail-closed），错误详情进 400 响应体。
    ///
    /// GET/HEAD 无请求体：协商头携带临时公钥即足以派生响应密钥，body
    /// 为空时跳过解信封（无载荷可解），仅缓存密钥供出站加密响应。
    /// 注：实际只有 GET 走此路径——HEAD 由 http_filter 在责任链之前按
    /// 快速路径短路（响应无 body 可加密），此处注释泛指无请求体语义
    fn on_http_inbound(ctx: &mut FilterContext<'_>, policy: EncryptionPolicy) -> Verdict {
        // 明文端点（off）不接受加密信封：静默放行密文会让下游插件把密文当 JSON
        // 解析，回出误导性业务码（比直接拒绝更难排查）
        if policy == EncryptionPolicy::Off {
            return if ctx.negotiation.trim().is_empty() {
                Verdict::Continue
            } else {
                Verdict::Reject(format!(
                    "request negotiated link encryption but the target is a plaintext endpoint (policy 'off'): {}; disable encryption on the peer or raise the endpoint policy",
                    Self::endpoint_hint(ctx)
                ))
            };
        }
        let Some(ek_b64) = parse_negotiation(ctx.negotiation) else {
            // 无协商：`preferred` 放行明文；`required` 必拒（不降级）
            return if policy.allows_plaintext() {
                Verdict::Continue
            } else {
                Verdict::Reject(format!(
                    "link encryption required (policy '{}') but the request carries no '{NEGOTIATION_HEADER}' negotiation header: {}; upgrade the peer or lower the endpoint policy",
                    policy.as_str(),
                    Self::endpoint_hint(ctx)
                ))
            };
        };
        let Some(identity) = IDENTITY.get() else {
            return Verdict::Reject("link identity unavailable".to_string());
        };

        // GET/HEAD 空 body：无载荷可解，协商仅用于响应加密（密钥派生已足以
        // 证明对端持有临时私钥）——空 body 直接通过，不尝试解信封。had_body
        // 须在闭包前捕获（闭包会把 ctx.data 替换为明文）
        let had_body = !ctx.data.is_empty();
        let result = (|| -> Result<()> {
            let ek_raw = b64_decode(ek_b64)?;
            let peer_public: [u8; 32] = ek_raw.try_into().map_err(|v: Vec<u8>| {
                AppError::Internal(format!("negotiation key length mismatch: expected 32, got {}", v.len()))
            })?;
            let shared = DATA_ECDH.compute_shared(identity.keypair().private(), &peer_public)?;
            let keys = derive_http_traffic_keys(&shared, ctx.route)?;
            // GET/HEAD 空 body：无载荷可解，协商仅用于响应加密（密钥派生已足以
            // 证明对端持有临时私钥）——空 body 直接通过，不尝试解信封
            if had_body {
                let request_key = keys.request;
                let plaintext = decrypt_http_body(&request_key, &ctx.data, &http_aad(Direction::Inbound, ctx.route))?;
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
                Verdict::Reject(format!("http request decrypt failed: {e}"))
            }
        }
    }

    /// HTTP 出站：入站已成功协商的请求 → 用缓存的 k_resp 加密响应；
    /// 未命中（未协商/入站被拒）→ 明文端点保持明文；`required` 端点拒绝
    /// （否则就是对管理员承诺的加密静默降级）
    fn on_http_outbound(ctx: &mut FilterContext<'_>, policy: EncryptionPolicy) -> Verdict {
        if policy == EncryptionPolicy::Off {
            // 明文端点：不回加密信封（对端即便带了协商头也已在上行被显式拒绝）
            return Verdict::Continue;
        }
        let Some(ek_b64) = parse_negotiation(ctx.negotiation) else {
            return Verdict::Continue;
        };
        let Some(keys) = take_http_keys(ctx.peer, ek_b64) else {
            crate::metrics::MetricsCollector::global().inc_response_key_miss();
            if policy == EncryptionPolicy::Required {
                return Verdict::Reject(format!(
                    "response encryption failed: no cached response key for a 'required' endpoint: {}; refusing to answer in plaintext",
                    Self::endpoint_hint(ctx)
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
                Verdict::Reject(format!("http response encrypt failed: {e}"))
            }
        }
    }
}

/// 链路加密过滤器（转换型）
///
/// 注册进全局责任链后对所有通道的收发载荷生效；裁决按 `(owner, endpoint)` 的
/// 生效策略（宿主下限 ▸ 端点声明），本地豁免流量零介入直通。
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
                if policy == EncryptionPolicy::Off {
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
                if policy == EncryptionPolicy::Off {
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

/// 按当前快照同步全局链注册状态（幂等；配置写入、端点策略登记/回收、启动装配共用）
///
/// 注册判据（按优先级）：
/// 1. 本进程必须有链路身份（没有密钥就不能加密；`required` 端点注册已在
///    [`declare_endpoint_policy`] 处显性拒绝，此处是防御）；
/// 2. 要么某通道下限非 `off`，要么有端点声明非 `off`——否则链上不应多一个
///    每帧都要跑的过滤器（全明文部署零影响）。
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

/// 是否有任何流量需要加密能力（通道下限或端点声明非 `off`）
fn crypto_wanted() -> bool {
    let config = current_config();
    let channel_wants = [
        TrafficChannel::Http,
        TrafficChannel::WsTerminal,
        TrafficChannel::WsEvent,
        TrafficChannel::WsPlugin,
    ]
    .iter()
    .any(|channel| config.channel_floor(*channel) != EncryptionPolicy::Off);
    if channel_wants {
        return true;
    }
    // 端点可把「全关」的宿主机抬高（应用声明 required）
    policy_lock().values().any(|policy| *policy != EncryptionPolicy::Off)
}

/// 向指定链注册（测试隔离用：单元测试走独立链实例，不触碰全局单例）
pub fn register_into(chain: &TrafficFilterChain) {
    chain.register(std::sync::Arc::new(LinkEncryptionFilter));
}

/// 启动期装配：懒建身份 → 读 DB 配置进快照 → 同步注册
///
/// 必须在 supervisor.start 之前完成（服务器收到的第一条流量就要被开关裁决）。
/// 身份损坏时强制回退全关并 error 日志——加密不可用是可接受的降级，
/// 静默换钥破坏 pin 是不可接受的错误。
///
/// server-lib-split：宿主壳负责解析应用数据目录与主库连接（`PathsPort` /
/// `app.state::<Database>`），本函数只接 `&Path` + `&rusqlite::Connection`。
/// 同步而非 `async`：`&Connection` 跨 `.await` 会让调用方的任务要求
/// `Connection: Sync`（rusqlite 连接是 Send !Sync），装配本身无等待点。
pub fn init_at_startup(data_dir: &std::path::Path, conn: &rusqlite::Connection) {
    let mut identity_ready = false;
    match init_identity(data_dir) {
        Ok(fp) => {
            tracing::info!(fingerprint = fp, "link crypto identity ready");
            identity_ready = true;
        }
        Err(e) => {
            tracing::error!("link crypto identity init failed, encryption stays off: {e}")
        }
    }

    let mut config = load_config_from_db(conn);
    if !identity_ready && config.host_floor() != EncryptionPolicy::Off {
        // 加密不可用时把下限降到 off，且启用态同步（避免「floor=required 但
        // 过滤器不在链上」的自相矛盾状态）；静默换钥破坏 pin 仍是不可接受的错误
        tracing::warn!(
            floor = %config.host_floor(),
            "trafficEncryption active in settings but identity unavailable, forcing floor=off this boot"
        );
        config.floor = Some(EncryptionPolicy::Off);
        config.enabled = false;
    }

    update_config(config);
    sync_registration();
    tracing::info!(
        floor = %current_config().host_floor(),
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

    /// 触碰全局配置快照的测试必须持此锁串行执行：
    /// cargo test 同模块用例默认多线程并行，否则 enabled 开关互踩产生偶发红
    static SNAPSHOT_LOCK: Mutex<()> = Mutex::new(());

    /// 在「迁移态主开关开 + 子通道全开」的隔离快照下执行断言，结束后还原
    ///
    /// 注意：迁移态下 `WsPlugin` 通道下限恒为 `off`（它历史上从未参与链路
    /// 加密）——插件端点的策略必须由端点声明抬高。
    fn with_all_enabled<T>(f: impl FnOnce() -> T) -> T {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = current_config();
        update_config(LinkCryptoConfig {
            enabled: true,
            ..LinkCryptoConfig::default()
        });
        let out = f();
        update_config(original);
        out
    }

    /// 无端点身份的上下文（宿主自有面 / 未注册路径：按通道下限裁决）
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
        }
    }

    /// 带端点身份的上下文（策略按 `strictest(floor, declared)` 裁决）
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

    #[test]
    fn default_config_is_off_with_channels_on() {
        let cfg = LinkCryptoConfig::default();
        assert!(!cfg.enabled, "主开关必须默认关闭（opt-in 设计）");
        assert!(cfg.encrypt_http && cfg.encrypt_ws_terminal && cfg.encrypt_ws_event);
        assert!(cfg.allow_plaintext_fallback);
    }

    #[test]
    fn config_serde_roundtrip_and_unknown_field_rejection() {
        let cfg = LinkCryptoConfig {
            enabled: true,
            ..LinkCryptoConfig::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(serde_json::from_str::<LinkCryptoConfig>(&json).unwrap(), cfg);

        // 未知字段拒绝：前端拼错开关名不允许被静默吞掉
        let bad = r#"{"enabled":true,"encryptHttp":false}"#;
        assert!(serde_json::from_str::<LinkCryptoConfig>(bad).is_err());

        // 部分字段省略走 serde default
        let partial = r#"{"enabled":true}"#;
        let parsed = serde_json::from_str::<LinkCryptoConfig>(partial).unwrap();
        assert!(parsed.enabled && parsed.encrypt_http);
    }

    #[test]
    fn config_db_roundtrip_and_corrupt_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("test.db")).unwrap();
        conn.execute_batch("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);")
            .unwrap();

        // 键不存在 → 默认全关
        assert!(!load_config_from_db(&conn).enabled);

        let cfg = LinkCryptoConfig {
            enabled: true,
            encrypt_http: false,
            ..LinkCryptoConfig::default()
        };
        persist_config_to_db(&conn, &cfg).unwrap();
        assert_eq!(load_config_from_db(&conn), cfg);

        // 损坏 JSON → 回退默认不报错
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![SETTING_KEY, "{not-json", "now"],
        )
        .unwrap();
        assert!(!load_config_from_db(&conn).enabled);
    }

    #[test]
    fn snapshot_update_visible_to_readers() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = current_config();
        let mut cfg = original.clone();
        cfg.enabled = !cfg.enabled;
        update_config(cfg);
        assert_eq!(current_config().enabled, !original.enabled);
        // 还原，避免污染其他测试
        update_config(original);
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

    // ---------- 过滤器豁免与开关判定 ----------

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
        }
    }

    /// 插件端点通道在迁移态仍不参与链路加密（旧行为保持），但端点一经声明
    /// 策略就进入裁决（blanket「永不加密」已解除，spec §4）
    #[test]
    fn ws_plugin_channel_follows_floor_then_endpoint_declaration() {
        with_all_enabled(|| {
            // 无声明 / 无端点身份 → 跟随迁移态通道下限（历史 = 不加密）
            let ctx = mk_ctx(TrafficChannel::WsPlugin, "192.168.1.42:5001", "text");
            assert!(
                !LinkEncryptionFilter::should_process(&ctx),
                "迁移态下插件端点通道下限为 off（旧行为）"
            );

            // 端点声明 preferred → 生效策略 preferred → 进入链路加密协商
            let declared = mk_endpoint_ctx(
                TrafficChannel::WsPlugin,
                "192.168.1.42:5001",
                "text",
                "com.example.plugin",
                "wse-declared",
            );
            declare_endpoint_policy(
                "com.example.plugin",
                "wse-declared",
                Some(EncryptionPolicy::Preferred),
                TrafficChannel::WsPlugin,
            )
            .expect("preferred 不受下限约束");
            assert!(LinkEncryptionFilter::should_process(&declared));
            withdraw_endpoint_policy("com.example.plugin", "wse-declared");
        });
    }

    #[test]
    fn unparseable_peer_treated_as_remote_fail_safe() {
        // peer 解析失败（如 "unknown"）不能当环回放行；需主开关开才进入处理判定
        with_all_enabled(|| {
            let ctx = mk_ctx(TrafficChannel::Http, "unknown", "/api/sessions");
            assert!(LinkEncryptionFilter::should_process(&ctx));
        });
    }

    /// WS 帧在 peer 未注册 ciphers 时的明文 fallback 分支（票据 11 盲区）：
    /// 生产代码仅 on_inbound/on_outbound 内部触达，此前从未被测试覆盖。
    #[test]
    fn ws_frame_no_ciphers_fallback_branch() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = current_config();
        // 确保该 peer 无 ciphers（每个测试进程独立，但防御性清理）
        ws_remove_ciphers("192.168.1.60:5555");

        // 正向：allow_plaintext_fallback=true → Continue 且数据不变
        update_config(LinkCryptoConfig {
            enabled: true,
            allow_plaintext_fallback: true,
            ..LinkCryptoConfig::default()
        });
        let mut ctx = mk_ctx(TrafficChannel::WsTerminal, "192.168.1.60:5555", "text");
        assert!(LinkEncryptionFilter::should_process(&ctx));
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut ctx), Verdict::Continue);
        assert_eq!(ctx.data, b"payload", "明文 fallback 不得改写载荷");
        let mut ctx2 = mk_ctx(TrafficChannel::WsEvent, "192.168.1.60:5555", "text");
        assert_eq!(LinkEncryptionFilter.on_outbound(&mut ctx2), Verdict::Continue);

        // 负向：迁移态 allow_plaintext_fallback=false → 通道下限 required → Reject
        update_config(LinkCryptoConfig {
            enabled: true,
            allow_plaintext_fallback: false,
            ..LinkCryptoConfig::default()
        });
        let mut ctx3 = mk_ctx(TrafficChannel::WsTerminal, "192.168.1.60:5555", "binary");
        let verdict = LinkEncryptionFilter.on_inbound(&mut ctx3);
        match verdict {
            Verdict::Reject(msg) => {
                assert!(
                    msg.contains("required") && msg.contains("no negotiated session cipher"),
                    "拒绝消息应点名策略与缺口: {msg}"
                )
            }
            other => panic!("期望 Reject，实际: {other:?}"),
        }
        // 出站同样 fail-closed
        let mut ctx4 = mk_ctx(TrafficChannel::WsEvent, "192.168.1.60:5555", "text");
        assert!(matches!(
            LinkEncryptionFilter.on_outbound(&mut ctx4),
            Verdict::Reject(_)
        ));

        update_config(original);
    }

    #[test]
    fn auth_and_health_routes_whitelisted_for_http_only() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for route in ["/api/auth/pairing", "/api/auth/qr-connect", "/health", "/api/health"] {
            let ctx = mk_ctx(TrafficChannel::Http, "192.168.1.50:4444", route);
            assert!(!LinkEncryptionFilter::should_process(&ctx), "白名单路由 {route} 应豁免");
        }
        // 白名单只对 HTTP 生效；WS 帧类别叫 "text"/"binary"，天然不命中前缀。
        // WS 非豁免路径会读快照，先临时开启避免依赖其它用例留下的状态
        update_config(LinkCryptoConfig {
            enabled: true,
            ..LinkCryptoConfig::default()
        });
        let ws_ctx = mk_ctx(TrafficChannel::WsTerminal, "192.168.1.50:4444", "text");
        assert!(LinkEncryptionFilter::should_process(&ws_ctx));
        update_config(LinkCryptoConfig::default());
    }

    #[test]
    fn remote_non_whitelisted_processed_when_enabled() {
        with_all_enabled(|| {
            let ctx = mk_ctx(TrafficChannel::Http, "192.168.1.50:4444", "/api/sessions");
            assert!(LinkEncryptionFilter::should_process(&ctx));
            // 骨架期直通不改数据
            let mut mutable = ctx;
            assert_eq!(LinkEncryptionFilter.on_inbound(&mut mutable), Verdict::Continue);
            assert_eq!(mutable.data, b"payload");

            let term = mk_ctx(TrafficChannel::WsTerminal, "192.168.1.50:4444", "binary");
            assert!(LinkEncryptionFilter::should_process(&term));
            let event = mk_ctx(TrafficChannel::WsEvent, "192.168.1.50:4444", "text");
            assert!(LinkEncryptionFilter::should_process(&event));
        });
    }

    #[test]
    fn master_switch_off_blocks_everything() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        update_config(LinkCryptoConfig::default()); // enabled=false
        let ctx = mk_ctx(TrafficChannel::Http, "192.168.1.50:4444", "/api/sessions");
        assert!(!LinkEncryptionFilter::should_process(&ctx));
    }

    #[test]
    fn per_channel_switch_gates_individually() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = current_config();
        update_config(LinkCryptoConfig {
            enabled: true,
            encrypt_http: false,
            ..LinkCryptoConfig::default()
        });
        let http = mk_ctx(TrafficChannel::Http, "192.168.1.50:4444", "/api/sessions");
        assert!(!LinkEncryptionFilter::should_process(&http), "子开关关应跳过该通道");
        let term = mk_ctx(TrafficChannel::WsTerminal, "192.168.1.50:4444", "text");
        assert!(LinkEncryptionFilter::should_process(&term), "其余通道不受影响");
        update_config(original);
    }

    #[test]
    fn registration_into_fresh_chain_is_named_and_idempotent_per_instance() {
        // 持锁：防止并行执行的其他用例（sync_registration / update_config 系列）
        // 在同一时刻改动全局链，把本用例的「独立实例不妨碍全局」断言搅黄；
        // 全局链基线读两次做差分断言（而非「不得包含本过滤器」）——并行套件里
        // 兄弟用例可能已把过滤器注册进全局链，绝对断言会误红（flaky：单跑绿、
        // 全量并发红，2026-09-27 全量回归实测）
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        // 同名节点重复注册会让链上出现重复项；swap 防护保证幂等
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = current_config();
        // 用一个独立链替代全局链的注册目标不可行（sync_registration 固定用 global），
        // 此处验证幂等机制本身：同一配置下重复同步不改变全局链节点数
        update_config(LinkCryptoConfig {
            enabled: true,
            ..LinkCryptoConfig::default()
        });
        let global = TrafficFilterChain::global();
        let before = global.list_names().len();
        sync_registration();
        sync_registration();
        sync_registration();
        let after = global.list_names().len();
        // 幂等：三次同步后节点数相对基线仅增加 1（首次注册），不重复累积
        assert!(
            after <= before + 1,
            "重复 sync_registration 不得累积重复节点: {before} -> {after}"
        );
        sync_registration();
        update_config(original);
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

        with_all_enabled(|| {
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
            let mut inbound = FilterContext {
                channel: TrafficChannel::Http,
                direction: Direction::Inbound,
                peer: "192.168.1.9:55001",
                route: "/api/sessions",
                owner: "",
                endpoint: "",
                negotiation: &negotiation,
                data: req_sealed,
                outbound_headers: Vec::new(),
            };
            assert_eq!(LinkEncryptionFilter.on_inbound(&mut inbound), Verdict::Continue);
            assert_eq!(inbound.data, req_plain, "handler 应收到明文");

            // ---- 出站：明文响应 → 过滤器加密 → 客户端用 k_resp 解回 ----
            let resp_plain = br#"{"code":0,"data":[1,2]}"#.to_vec();
            let mut outbound = FilterContext {
                channel: TrafficChannel::Http,
                direction: Direction::Outbound,
                peer: "192.168.1.9:55001",
                route: "/api/sessions",
                owner: "",
                endpoint: "",
                negotiation: &negotiation,
                data: resp_plain.clone(),
                outbound_headers: Vec::new(),
            };
            assert_eq!(LinkEncryptionFilter.on_outbound(&mut outbound), Verdict::Continue);
            assert_ne!(outbound.data, resp_plain, "响应应已加密");
            // 加密响应必须回协商头标记（spec §4）：客户端据 `X-WasmNest-Crypto: v1`
            // 识别并解密，缺失/值不符会导致客户端误判明文降级（值必须是 "v1"，
            // 与移动端 `respHeader === 'v1'` 判定一致，非裸 "1"）
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
            let mut second = FilterContext {
                channel: TrafficChannel::Http,
                direction: Direction::Outbound,
                peer: "192.168.1.9:55001",
                route: "/api/sessions",
                owner: "",
                endpoint: "",
                negotiation: &negotiation,
                data: b"late".to_vec(),
                outbound_headers: Vec::new(),
            };
            assert_eq!(LinkEncryptionFilter.on_outbound(&mut second), Verdict::Continue);
            assert_eq!(second.data, b"late");
        });
    }

    #[test]
    fn http_fail_closed_paths() {
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();

        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = current_config();

        // ① 强加密模式（fallback=false）：未协商请求直接拒绝
        update_config(LinkCryptoConfig {
            enabled: true,
            allow_plaintext_fallback: false,
            ..LinkCryptoConfig::default()
        });
        let mut no_neg = mk_ctx(TrafficChannel::Http, "192.168.1.9:55002", "/api/sessions");
        assert!(matches!(
            LinkEncryptionFilter.on_inbound(&mut no_neg),
            Verdict::Reject(msg) if msg.contains("required")
        ));

        // ② 已协商但载荷损坏 → Reject 且原因含 decrypt failed
        update_config(LinkCryptoConfig {
            enabled: true,
            ..LinkCryptoConfig::default()
        });
        let client_eph = wasmnest_crypto_engine::x25519::x25519_generate();
        let negotiation = format!("v1 {}", b64_encode(client_eph.public()));
        let mut garbage = FilterContext {
            channel: TrafficChannel::Http,
            direction: Direction::Inbound,
            peer: "192.168.1.9:55003",
            route: "/api/sessions",
            owner: "",
            endpoint: "",
            negotiation: &negotiation,
            data: b"definitely-not-an-envelope".to_vec(),
            outbound_headers: Vec::new(),
        };
        assert!(matches!(
            LinkEncryptionFilter.on_inbound(&mut garbage),
            Verdict::Reject(msg) if msg.contains("decrypt failed")
        ));

        // ③ 非法公钥（非 base64/长度错）→ Reject
        let mut bad_key = FilterContext {
            channel: TrafficChannel::Http,
            direction: Direction::Inbound,
            peer: "192.168.1.9:55004",
            route: "/api/sessions",
            owner: "",
            endpoint: "",
            negotiation: "v1 !!!not-base64!!!",
            data: vec![0u8; 16],
            outbound_headers: Vec::new(),
        };
        assert!(matches!(
            LinkEncryptionFilter.on_inbound(&mut bad_key),
            Verdict::Reject(_)
        ));

        update_config(original);
    }

    /// GET/HEAD 无请求体协商：空 body + 协商头 → 直接通过并缓存响应密钥，
    /// 出站时响应以 k_resp 加密并回标记头（修复：移动端 GET 请求此前无 body
    /// 可加密但协商必须成立，否则响应密钥缓存缺失、响应加密失效）
    #[test]
    fn http_get_with_empty_body_negotiates_and_encrypts_response() {
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();

        with_all_enabled(|| {
            use wasmnest_crypto_engine::x25519::{x25519_diffie_hellman, x25519_generate};

            let client_eph = x25519_generate();
            let (_, kd_pub_b64) = identity_parts().unwrap();
            let kd_pub: [u8; 32] = b64_decode(&kd_pub_b64).unwrap().try_into().unwrap();
            let shared = x25519_diffie_hellman(&client_eph, &kd_pub).unwrap();
            let keys = derive_http_traffic_keys(shared.as_bytes(), "/api/sessions").unwrap();
            let negotiation = format!("v1 {}", b64_encode(client_eph.public()));

            // 入站：空 body（GET）→ 通过，不解信封（无载荷可解）
            let mut inbound = FilterContext {
                channel: TrafficChannel::Http,
                direction: Direction::Inbound,
                peer: "192.168.1.9:55005",
                route: "/api/sessions",
                owner: "",
                endpoint: "",
                negotiation: &negotiation,
                data: Vec::new(),
                outbound_headers: Vec::new(),
            };
            assert_eq!(LinkEncryptionFilter.on_inbound(&mut inbound), Verdict::Continue);
            assert!(inbound.data.is_empty(), "空 body 应原样透传");

            // 出站：响应加密 + 标记头（客户端据头解密）
            let resp_plain = br#"{"code":0,"data":[]}"#.to_vec();
            let mut outbound = FilterContext {
                channel: TrafficChannel::Http,
                direction: Direction::Outbound,
                peer: "192.168.1.9:55005",
                route: "/api/sessions",
                owner: "",
                endpoint: "",
                negotiation: &negotiation,
                data: resp_plain.clone(),
                outbound_headers: Vec::new(),
            };
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
        assert_eq!(
            EncryptionPolicy::parse_opt(None, EncryptionPolicy::Preferred).unwrap(),
            EncryptionPolicy::Preferred
        );
        assert_eq!(
            EncryptionPolicy::parse_opt(Some("  "), EncryptionPolicy::Preferred).unwrap(),
            EncryptionPolicy::Preferred
        );

        // 严格度序：off < preferred < required（「只升不降」的实现基础）
        assert!(EncryptionPolicy::Off < EncryptionPolicy::Preferred);
        assert!(EncryptionPolicy::Preferred < EncryptionPolicy::Required);
        assert_eq!(
            strictest(EncryptionPolicy::Off, EncryptionPolicy::Preferred),
            EncryptionPolicy::Preferred
        );
        assert_eq!(
            strictest(EncryptionPolicy::Required, EncryptionPolicy::Off),
            EncryptionPolicy::Required
        );
        assert!(!EncryptionPolicy::Required.allows_plaintext());
        assert!(EncryptionPolicy::Preferred.allows_plaintext());
        assert!(EncryptionPolicy::Off.allows_plaintext());
    }

    /// 旧字段 → 下限的一次性迁移映射（spec §6）：映射必须可预测、可逆
    #[test]
    fn legacy_config_maps_to_floor() {
        let off = LinkCryptoConfig {
            enabled: false,
            ..LinkCryptoConfig::default()
        };
        assert_eq!(off.host_floor(), EncryptionPolicy::Off);

        let preferred = LinkCryptoConfig {
            enabled: true,
            allow_plaintext_fallback: true,
            ..LinkCryptoConfig::default()
        };
        assert_eq!(preferred.host_floor(), EncryptionPolicy::Preferred);

        let required = LinkCryptoConfig {
            enabled: true,
            allow_plaintext_fallback: false,
            ..LinkCryptoConfig::default()
        };
        assert_eq!(required.host_floor(), EncryptionPolicy::Required);

        // 迁移态逐通道子开关仍然生效；插件端点通道历史从未加密 → 恒 off
        let http_off = LinkCryptoConfig {
            enabled: true,
            encrypt_http: false,
            ..LinkCryptoConfig::default()
        };
        assert_eq!(http_off.channel_floor(TrafficChannel::Http), EncryptionPolicy::Off);
        assert_eq!(
            http_off.channel_floor(TrafficChannel::WsTerminal),
            EncryptionPolicy::Preferred
        );
        assert_eq!(http_off.channel_floor(TrafficChannel::WsPlugin), EncryptionPolicy::Off);

        // 显式 floor 为权威：旧子开关不再能把 required 降级成明文
        let explicit = LinkCryptoConfig {
            enabled: false,
            encrypt_http: false,
            floor: Some(EncryptionPolicy::Required),
            ..LinkCryptoConfig::default()
        };
        assert_eq!(explicit.host_floor(), EncryptionPolicy::Required);
        assert_eq!(explicit.channel_floor(TrafficChannel::Http), EncryptionPolicy::Required);
        assert_eq!(
            explicit.channel_floor(TrafficChannel::WsPlugin),
            EncryptionPolicy::Required
        );

        // 写入口构造：floor 与 enabled 同源（不允许 floor=required + enabled=false）
        let written = LinkCryptoConfig::from_floor(EncryptionPolicy::Preferred);
        assert!(written.enabled && written.floor == Some(EncryptionPolicy::Preferred));
        assert!(!LinkCryptoConfig::from_floor(EncryptionPolicy::Off).enabled);

        // 落库往返：floor 保留（重启后姿态不变）
        let json = serde_json::to_string(&written).unwrap();
        assert_eq!(serde_json::from_str::<LinkCryptoConfig>(&json).unwrap(), written);
        assert!(!json.contains("\"floor\":null"), "floor 缺省不序列化，旧读者仍可解析");
    }

    /// 声明判据（纯函数）：只能往上加、不能往下压；无身份不得声明 required
    #[test]
    fn declaration_checks_enforce_floor_and_identity() {
        use TrafficChannel::Http;
        // 下限 off：可声明 off / preferred / required（向上提）
        for policy in [
            EncryptionPolicy::Off,
            EncryptionPolicy::Preferred,
            EncryptionPolicy::Required,
        ] {
            assert!(
                check_declaration("p", "http-1", policy, EncryptionPolicy::Off, Http, true).is_ok(),
                "floor=off 时 {policy} 应允许"
            );
        }
        // 下限 required：声明 off 拒绝，且文案点名端点 / 属主 / 通道 / 下限
        let err = check_declaration(
            "com.example.app",
            "http-2",
            EncryptionPolicy::Off,
            EncryptionPolicy::Required,
            Http,
            true,
        )
        .expect_err("floor=required 时 off 必须失败");
        assert!(
            err.contains("off")
                && err.contains("required")
                && err.contains("http-2")
                && err.contains("com.example.app")
                && err.contains("http"),
            "拒绝文案须点名端点/属主/通道/下限: {err}"
        );
        // 下限 required：preferred 允许（生效仍是 required）
        assert!(check_declaration(
            "p",
            "http-3",
            EncryptionPolicy::Preferred,
            EncryptionPolicy::Required,
            Http,
            true
        )
        .is_ok());
        // 无身份：required 拒绝（否则注册成功却无法加密）
        let err = check_declaration(
            "p",
            "http-4",
            EncryptionPolicy::Required,
            EncryptionPolicy::Off,
            Http,
            false,
        )
        .expect_err("无身份时 required 必须失败");
        assert!(err.contains("identity") && err.contains("http-4"), "{err}");
        // 无身份：preferred / off 不受阻（它们不要求本端必须能加密）
        assert!(check_declaration(
            "p",
            "http-5",
            EncryptionPolicy::Preferred,
            EncryptionPolicy::Off,
            Http,
            false
        )
        .is_ok());
    }

    /// 端点策略表：登记 / 生效值 / 回收（全局表，本用例自清）
    #[test]
    fn endpoint_policy_table_roundtrip_and_purge() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let original = current_config();

        update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Off));
        declare_endpoint_policy(
            "policy-test",
            "http-a",
            Some(EncryptionPolicy::Required),
            TrafficChannel::Http,
        )
        .expect("抬高下限必须允许");
        assert_eq!(
            effective_endpoint_policy("policy-test", "http-a", TrafficChannel::Http),
            EncryptionPolicy::Required
        );
        declare_endpoint_policy(
            "policy-test",
            "http-b",
            Some(EncryptionPolicy::Off),
            TrafficChannel::Http,
        )
        .expect("floor=off 时 off 允许");
        assert_eq!(
            effective_endpoint_policy("policy-test", "http-b", TrafficChannel::Http),
            EncryptionPolicy::Off
        );
        // 未登记端点跟随通道下限
        assert_eq!(
            effective_endpoint_policy("policy-test", "http-unknown", TrafficChannel::Http),
            EncryptionPolicy::Off
        );
        // 无端点身份（宿主自有面）跟随通道下限
        assert_eq!(
            effective_endpoint_policy("", "", TrafficChannel::Http),
            EncryptionPolicy::Off
        );

        // 下限变严：声明 off 的端点不会因此被静默降级（已有声明保留，但生效值取更严者）
        update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Required));
        assert_eq!(
            effective_endpoint_policy("policy-test", "http-b", TrafficChannel::Http),
            EncryptionPolicy::Required,
            "下限变严后旧 off 声明的生效值必须跟着变严"
        );
        assert_eq!(endpoint_policy("policy-test", "http-b"), Some(EncryptionPolicy::Off));

        // 清单快照（排序稳定，供宿主设置页展示）
        let records = declared_endpoint_policies();
        assert!(records
            .iter()
            .any(|r| r.owner == "policy-test" && r.endpoint == "http-a"));

        // 回收只命中本人
        declare_endpoint_policy(
            "policy-other",
            "http-c",
            Some(EncryptionPolicy::Preferred),
            TrafficChannel::Http,
        )
        .expect("floor=required 时 preferred 声明允许");
        assert_eq!(withdraw_endpoint_policies("policy-test"), 2);
        assert!(endpoint_policy("policy-test", "http-a").is_none());
        assert!(endpoint_policy("policy-other", "http-c").is_some());
        withdraw_endpoint_policies("policy-other");

        update_config(original);
    }

    /// A/B 共存：同一宿主上 A 端点 required 拒绝明文、B 端点 off 保持明文
    #[test]
    fn http_required_and_off_endpoints_coexist() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let original = current_config();
        // floor=off（这台机器最低要求就是明文）：A 主动抬高到 required，B 显式 off
        update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Off));

        declare_endpoint_policy(
            "com.example.a",
            "http-req",
            Some(EncryptionPolicy::Required),
            TrafficChannel::Http,
        )
        .expect("required 声明");
        declare_endpoint_policy(
            "com.example.b",
            "http-plain",
            Some(EncryptionPolicy::Off),
            TrafficChannel::Http,
        )
        .expect("floor=off 时 off 声明允许");

        // A：未协商 → 拒绝，文案点名端点 / 属主 / 策略 / 协商头
        let mut a = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:6001",
            "/api/plugin/com.example.a/secret",
            "com.example.a",
            "http-req",
        );
        match LinkEncryptionFilter.on_inbound(&mut a) {
            Verdict::Reject(msg) => assert!(
                msg.contains("http-req")
                    && msg.contains("com.example.a")
                    && msg.contains("required")
                    && msg.contains(NEGOTIATION_HEADER),
                "拒绝文案须点名端点/属主/策略/协商头: {msg}"
            ),
            other => panic!("required 端点未协商时必须拒绝，实际: {other:?}"),
        }

        // B：明文端点不接受加密信封（密文会被下游当 JSON 解析，回出误导性业务码）
        let mut b = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:6002",
            "/api/plugin/com.example.b/status",
            "com.example.b",
            "http-plain",
        );
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut b), Verdict::Continue);
        assert_eq!(b.data, b"payload", "off 端点明文字节不得改写");
        b.negotiation = "v1 AAA=";
        match LinkEncryptionFilter.on_inbound(&mut b) {
            Verdict::Reject(msg) => assert!(
                msg.contains("off") && msg.contains("plaintext") && msg.contains("http-plain"),
                "off 端点收到密文必须显性拒绝: {msg}"
            ),
            other => panic!("off 端点收到协商必须拒绝，实际: {other:?}"),
        }
        // 出站：off 端点不回加密信封
        let mut b_out = mk_endpoint_ctx(
            TrafficChannel::Http,
            "192.168.1.9:6002",
            "/api/plugin/com.example.b/status",
            "com.example.b",
            "http-plain",
        );
        b_out.direction = Direction::Outbound;
        assert_eq!(LinkEncryptionFilter.on_outbound(&mut b_out), Verdict::Continue);
        assert!(b_out.outbound_headers.is_empty(), "明文端点不得回加密标记头");
        assert_eq!(b_out.data, b"payload");

        withdraw_endpoint_policies("com.example.a");
        withdraw_endpoint_policies("com.example.b");
        update_config(original);
    }

    /// WS 端点 required + 未协商连接 → Reject（fail-visible，不降级成明文）
    #[test]
    fn ws_required_endpoint_rejects_unpaired_connection() {
        let _guard = SNAPSHOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        init_identity(dir.path()).unwrap();
        let original = current_config();
        update_config(LinkCryptoConfig::from_floor(EncryptionPolicy::Preferred));
        declare_endpoint_policy(
            "com.example.ws",
            "wse-req",
            Some(EncryptionPolicy::Required),
            TrafficChannel::WsPlugin,
        )
        .expect("required 声明");
        let peer = "192.168.1.70:7001";
        ws_remove_ciphers(peer);

        let mut inbound = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", "com.example.ws", "wse-req");
        match LinkEncryptionFilter.on_inbound(&mut inbound) {
            Verdict::Reject(msg) => assert!(
                msg.contains("wse-req") && msg.contains("required") && msg.contains("no negotiated session cipher"),
                "拒绝文案须点名端点/策略/缺口: {msg}"
            ),
            other => panic!("required 端点无会话密码时必须拒绝，实际: {other:?}"),
        }
        let mut outbound = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "binary", "com.example.ws", "wse-req");
        outbound.direction = Direction::Outbound;
        assert!(matches!(
            LinkEncryptionFilter.on_outbound(&mut outbound),
            Verdict::Reject(_)
        ));

        // 同宿主上声明 preferred 的 WS 端点：无密码连接仍然放行（机会主义）
        declare_endpoint_policy(
            "com.example.ws",
            "wse-opt",
            Some(EncryptionPolicy::Preferred),
            TrafficChannel::WsPlugin,
        )
        .unwrap();
        let mut opt = mk_endpoint_ctx(TrafficChannel::WsPlugin, peer, "text", "com.example.ws", "wse-opt");
        assert_eq!(LinkEncryptionFilter.on_inbound(&mut opt), Verdict::Continue);
        assert_eq!(opt.data, b"payload");

        withdraw_endpoint_policies("com.example.ws");
        update_config(original);
    }

    /// 能力查询：per-endpoint 策略已支持、下限与身份如实上报
    #[test]
    fn capabilities_report_supported_policy_surface() {
        let caps = capabilities();
        assert!(caps.per_endpoint_policy, "本版本支持按端点声明策略");
        assert_eq!(caps.endpoint_policies, vec!["required", "preferred", "off"]);
        assert!(caps.key_models.contains(&"paired-http-path-bound"));
        // 下限与配置快照同源
        assert_eq!(caps.floor, current_config().host_floor());
        // 身份可用时指纹随能力一起下发（应用注册 required 前用于确认）
        if let Some(fp) = identity_fingerprint() {
            assert_eq!(caps.identity_fingerprint.as_deref(), Some(fp));
        }
    }
}
