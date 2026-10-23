//! 对等网络专用 mDNS 节点发现（ticket 03）：
//! 独立服务类型广播 + 浏览并存、TXT 携带设备名/协议版本/能力位图、带 TTL 的在线缓存。
//!
//! ## 与终端链路旧 mDNS 的关系
//!
//! 服务类型 `_wasmnest-peer._tcp.local.` 与旧 `_wasmnest._tcp.local.` 刻意错开：
//! 两套发现靠**服务类型**隔离，彼此不会收到对方的 browse 结果。但它们**不是**
//! 各自独立的守护进程——mDNS 基础能力服务收敛（spec v2 / ticket 04）后，守护句柄
//! 由宿主壳经 `MdnsPort` 端口层**注入**本模块（[`spawn_peer_mdns_daemon`] 的
//! `daemon` 参数），本模块不再自建 `ServiceDaemon`（端口 trait 定义见
//! `wasmnest-server-base` 的 `MdnsPort`）。因此「多实例共存」不是本模块可依赖的
//! 性质：新增发现服务必须走同一个共享守护，否则会出现两个守护争抢同一组播端口。
//! 本模块不触碰旧链路与 file_service announce（冻结区）。
//!
//! ## 浏览面走类型中枢订阅（ADR 0054）
//!
//! mdns-sd 对每个服务类型只保留**一个** listener，重复 `browse` 会静默覆盖前一个
//! （旧 listener 既不收事件也不断开），因此同进程内多方各自 `daemon.browse` 必然
//! 互相杀死事件流。「全进程同类型只允许一次 browse / stop_browse」的机制收敛在
//! 宿主发现引擎的**类型中枢**里，本模块据此改造：
//!
//! - 浏览面收宿主注入的值形态 [`PeerMdnsBrowse`]（fan-out receiver + 退订守卫 +
//!   重查闭包）：本模块**不再** `daemon.browse` / `stop_browse`，也不再自建
//!   receiver 换绑机器；退订随句柄释放（守卫 Drop ⇒ 中枢移除发送端 ⇒ 通道断开）
//!   即完成，事件循环据此退出；
//! - 重查（30s 周期 + 即时刷新）只经 [`DiscoveryDaemon::request_requery`]（转调
//!   闭包）请求中枢统一执行：中枢重发唯一 browse + 缓存重放 fan-out 给全部订阅者，
//!   节奏仍由本模块掌握（业务节奏属消费方，机制归中枢）；
//! - 广播面（register / unregister / 周期 re-announce）不受影响，仍用注入的
//!   `daemon`。
//!
//! 另：`spawn_peer_mdns_advertiser`（仅广告、无浏览）曾是本模块内**仍自建**
//! `ServiceDaemon` 的那一个，且无生产调用方——已随双端共享 lib spec M4（2026-10-09）
//! 删除：广告面由宿主自播（owner=host）/ 插件 `host-mdns` advertise 覆盖。
//! ## 「同一通路」注入缝（issue 03 核心验收点）
//!
//! mDNS 事件（经中枢 fan-out 的浏览订阅）与单测喂入统一收敛到
//! [`DiscoveryCache::observe`]：守护任务在
//! `ServiceResolved` 时构造 [`DiscoveredPeerRecord`] 后调用 `observe()`，单测以
//! 完全相同的调用形态注入手工记录——不存在守护专属的第二条插入路径。
//! 产物经 [`DiscoveredPeerRecord::to_static_peer_record`] 即可直接拨号。
//!
//! ## 「在线」语义与 TTL 三层机制
//!
//! 「在线」= 缓存中存在记录，与是否维持连接无关（ADR 0028：未信任节点也可见）。
//! ① 每次 `ServiceResolved` 盖章续期；② `ServiceRemoved`（goodbye）立即移除；
//! ③ 守护任务每 [`SWEEP_INTERVAL`] 清扫一次超时项——崩溃进程没有 goodbye，
//! 只能靠 TTL 兜底（[`PEER_DISCOVERY_TTL`]）。过期判定抽成接受显式 `now` 的
//! 纯逻辑入口，inline 单测直接构造过去时间戳，全程不用 sleep（CI 无 flake）。
//!
//! ## 平台边界（决策 D2）
//!
//! crate 层保持平台无关：MulticastLock 是 Android 宿主职责，由移动端在启动
//! 守护前经 Kotlin 插件 acquire；本模块不做平台开关。

use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use mdns_sd::{ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Serialize;
use tokio::sync::watch;

use crate::base::error::{PeerNetError, Result};
use crate::base::identity::NodeId;
use crate::base::node::{PeerNetNode, StaticPeerRecord};
use crate::base::transport::RunningNode;

// ==================== 常量 ====================

/// 对等网络专用服务类型：与终端链路 `_wasmnest._tcp.local.` 错开（AC#4）
pub const SERVICE_TYPE: &str = "_wasmnest-peer._tcp.local.";

/// 发现通告协议版本
///
/// 刻意独立于 `frame.rs` 的 [`crate::base::frame::PROTOCOL_VERSION`]：帧格式是 TLS
/// 层契约、发现广播是通告契约，二者演进节奏不同，版本号不得互相牵制。
pub const DISCOVERY_PROTOCOL_VERSION: u32 = 1;

/// 能力位图 bit0：文件传输（首个能力位，后续能力按位追加）
pub const CAP_FILE_TRANSFER: u64 = 1 << 0;

/// 在线记录 TTL：超过该时长未续期即视为离线
///
/// 大于 [`SWEEP_INTERVAL`] 数倍，保证崩溃节点的残留记录在一个清扫周期粒度内
/// 被移除的同时，不会因单次丢包误删活节点（解析事件本身会持续盖章续期）。
/// 120s：mDNS 周期广播间隔随网络抖动可达 30-60s+（多网卡环境更甚），30s TTL
/// 会形成「过期清扫→再发现」循环——发现推送把空/非空列表交替推给前端，
/// 设备面板表现为反复闪空（2026-08-26 双端互不可见排查实证）；TTL 取广播
/// 间隔的 2 倍以上余量，异常离线由 goodbye 包即时移除兜底，不依赖超时。
pub const PEER_DISCOVERY_TTL: Duration = Duration::from_secs(120);

/// 守护任务的过期清扫周期
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// 周期 re-announce 间隔：mdns-sd 注册服务后只做启动 announce，不主动周期
/// 广播；而 browse 的查询按 RFC 6762 指数退避（上限 1 小时），远超
/// [`PEER_DISCOVERY_TTL`]，会造成「启动互见 → 记录过期 → 互不可见」
/// （2026-09-06 双端实测）。守护每此间隔重复 register 触发 unsolicited
/// announce（register 幂等：同名覆盖，不 probe、不发 goodbye）。
pub const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(45);

/// 周期主动重查间隔：重新 browse 一次服务类型，触发查询突发 + mdns-sd
/// 内部缓存重放，刷新本端记录续期。
///
/// 被动 announce 在真机 WiFi 环境双向丢失率极高（2026-09-06 实证：手机
/// 30 分钟内未收到桌面端任一 re-announce，桌面端 40 次中也只收到 2-3 次），
/// 而「查询 → 应答」路径始终秒级可达。本间隔同时规避 browse 指数退避
/// （上限 1 小时）远超 [`PEER_DISCOVERY_TTL`] 导致的记录静默过期。
pub const REQUERY_INTERVAL: Duration = Duration::from_secs(30);

/// 设备名截断上限（字节）
///
/// mdns-sd 要求单条 TXT 键值 ≤255 字节，200 留足余量；按 UTF-8 字符边界截断。
pub(crate) const DEVICE_NAME_MAX_BYTES: usize = 200;

/// 实例名前缀：实例名绑定短指纹而非设备名——设备改名不会引发 remove/found
/// 抖动（D5）；人类可读名走 TXT `name`
pub(crate) const INSTANCE_PREFIX: &str = "wasmnest-peer-";

// ---- TXT keys（全小写：mdns-sd 按 RFC 6763 规范化键名）----

/// TXT key：完整节点 ID（64 位小写 hex）
///
/// 必要补充（D4 未列出）：实例名只含 8 位短指纹，而拨号侧 TLS 身份钉扎需要
/// 完整 NodeId 比对证书指纹——不带全量 ID 的记录根本无法用于建立可信连接。
pub(crate) const TXT_KEY_ID: &str = "id";
/// TXT key：设备名（UTF-8，截断至 [`DEVICE_NAME_MAX_BYTES`]）
pub(crate) const TXT_KEY_NAME: &str = "name";
/// TXT key：协议版本（十进制 u32 字符串）
pub(crate) const TXT_KEY_VER: &str = "ver";
/// TXT key：能力位图（小写 hex u64；与 NodeId 小写风格一致且 >32 bit 时紧凑稳定）
pub(crate) const TXT_KEY_CAP: &str = "cap";

// ==================== 发现记录 ====================

/// 一条通过 mDNS 发现的对端记录：拨号所需最小信息 + 展示/门控元数据
///
/// `last_seen` 由 [`DiscoveryCache::observe`] 盖章维护，是缓存簿记元数据而非
/// 载荷数据，序列化时跳过（`Instant` 无 serde 表示且跨进程无意义，前端列表
/// 只需可见性与名称/能力）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveredPeerRecord {
    /// 对端节点 ID（公钥指纹，来自 TXT `id`；序列化为 64 位小写 hex 字符串）
    #[serde(serialize_with = "serialize_node_id_as_str")]
    pub node_id: NodeId,
    /// 对端监听地址（mDNS 解析的 IP:port，优先 IPv4）
    pub addr: SocketAddr,
    /// 设备名（来自 TXT `name`，缺失时回退实例名）
    pub device_name: String,
    /// 对端通告的协议版本（来自 TXT `ver`，缺失/损坏记 0；仅供未来门控参考）
    pub protocol_version: u32,
    /// 能力位图（来自 TXT `cap` 小写 hex，损坏记 0）
    pub capabilities: u64,
    /// 最近一次被发现/续期时刻（见结构体文档的序列化说明）
    #[serde(skip)]
    pub last_seen: Instant,
}

impl DiscoveredPeerRecord {
    /// 转为拨号入口所需的静态对端记录（发现元数据不污染拨号通路，D1）
    pub fn to_static_peer_record(&self) -> StaticPeerRecord {
        StaticPeerRecord {
            node_id: self.node_id.clone(),
            addr: self.addr,
        }
    }
}

/// `NodeId` 的序列化辅助：输出 64 位小写 hex 字符串
///
/// 不给 [`NodeId`] 派生 serde（identity.rs 明确禁止任何绕过 parse 校验的
/// 反序列化构造路径）；序列化只读不构造，安全输出字符串形态。
fn serialize_node_id_as_str<S: serde::Serializer>(
    node_id: &NodeId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(node_id.as_str())
}

// ==================== TXT 编解码（纯函数） ====================

/// 编码广播用 TXT 载荷（编码/解码为纯函数，D4）
pub(crate) fn encode_txt_properties(
    node_id: &NodeId,
    device_name: &str,
    protocol_version: u32,
    capabilities: u64,
) -> HashMap<String, String> {
    HashMap::from([
        (TXT_KEY_ID.to_string(), node_id.as_str().to_string()),
        (
            TXT_KEY_NAME.to_string(),
            truncate_utf8(device_name, DEVICE_NAME_MAX_BYTES),
        ),
        (TXT_KEY_VER.to_string(), protocol_version.to_string()),
        // 小写 hex：与 NodeId 小写风格一致，且能力位超过 32 bit 时比二进制紧凑稳定
        (TXT_KEY_CAP.to_string(), format!("{capabilities:x}")),
    ])
}

/// 从 TXT 载荷解码发现记录（容忍降级，D4）
///
/// - `id` 缺失或非法 → 返回 `None`（整条记录跳过）：无法钉扎身份的记录不可拨号；
/// - `name` 缺失 → 回退实例名；`ver` 缺失/坏 → 0；`cap` 坏 → 0；
/// - 广播载荷解析失败不应产生错误传播链，调用方 warn 后跳过即可。
///
/// 返回值中的 `last_seen` 仅为占位（调用方 [`DiscoveryCache::observe`] 统一盖章）。
pub(crate) fn decode_txt_properties(
    instance_name: &str,
    addr: SocketAddr,
    properties: &HashMap<String, String>,
) -> Option<DiscoveredPeerRecord> {
    let node_id = NodeId::parse(properties.get(TXT_KEY_ID)?).ok()?;
    let device_name = properties
        .get(TXT_KEY_NAME)
        .cloned()
        .unwrap_or_else(|| instance_name.to_string());
    let protocol_version = properties
        .get(TXT_KEY_VER)
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let capabilities = properties
        .get(TXT_KEY_CAP)
        .and_then(|v| u64::from_str_radix(v, 16).ok())
        .unwrap_or(0);
    Some(DiscoveredPeerRecord {
        node_id,
        addr,
        device_name,
        protocol_version,
        capabilities,
        last_seen: Instant::now(),
    })
}

/// 按字符边界安全截断 UTF-8 字符串（防 TXT 超 255 上限被 mdns-sd 拒注）
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// 从服务全名提取实例名段：`wasmnest-peer-<指纹>.<SERVICE_TYPE>` → `wasmnest-peer-<指纹>`
fn instance_from_fullname(fullname: &str) -> Option<&str> {
    let instance = fullname.strip_suffix(&format!(".{SERVICE_TYPE}"))?;
    instance.starts_with(INSTANCE_PREFIX).then_some(instance)
}

/// 从实例名提取短指纹段：`wasmnest-peer-<指纹>` → `<指纹>`
fn fingerprint_of_instance(instance: &str) -> Option<&str> {
    instance.strip_prefix(INSTANCE_PREFIX).filter(|s| !s.is_empty())
}

// ==================== 在线缓存 ====================

/// 发现结果的在线缓存：「在线」的唯一判定来源（存在记录即可见，与连接无关）
///
/// 同步 `std::sync::RwLock` + `Arc` 共享（禁 unsafe impl Send/Sync 的替代）：
/// 所有方法瞬时完成、无跨 await 持锁，同步锁足够且免去异步锁的生命周期负担。
#[derive(Debug, Default)]
pub struct DiscoveryCache {
    peers: RwLock<HashMap<NodeId, DiscoveredPeerRecord>>,
}

impl DiscoveryCache {
    /// 空缓存
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一条发现结果并盖章当前时刻（mDNS 守护回调与单测喂入的同一入口）
    ///
    /// 同一 node_id 重复发现即覆盖更新（携带最新地址/元数据），天然完成续期。
    pub fn observe(&self, mut record: DiscoveredPeerRecord) {
        record.last_seen = Instant::now();
        self.peers
            .write()
            .expect("discovery cache lock poisoned")
            .insert(record.node_id.clone(), record);
    }

    /// 立即移除指定节点（`ServiceRemoved`/goodbye 语义的直接形态）
    pub fn remove(&self, node_id: &NodeId) -> Option<DiscoveredPeerRecord> {
        self.peers
            .write()
            .expect("discovery cache lock poisoned")
            .remove(node_id)
    }

    /// 按短指纹移除并返回被移除记录
    ///
    /// goodbye 事件（`ServiceRemoved`）只携带实例名，而实例名内嵌短指纹（D5），
    /// 据此反查缓存条目。LAN 规模下线性扫描成本可忽略。
    pub(crate) fn remove_by_fingerprint(&self, short: &str) -> Option<DiscoveredPeerRecord> {
        let mut peers = self.peers.write().expect("discovery cache lock poisoned");
        let victim = peers
            .iter()
            .find(|(_, record)| record.node_id.short_fingerprint() == short)
            .map(|(id, _)| id.clone())?;
        peers.remove(&victim)
    }

    /// 移除所有超过 TTL 未续期的记录，返回移除数量（显式时间的纯逻辑核心，D3）
    pub fn sweep_expired_at(&self, now: Instant) -> usize {
        let mut peers = self.peers.write().expect("discovery cache lock poisoned");
        let before = peers.len();
        peers.retain(|_, record| !is_expired(record.last_seen, now));
        before - peers.len()
    }

    /// 以真实时钟执行过期清扫（守护任务的便捷包装）
    pub fn sweep_expired(&self) -> usize {
        self.sweep_expired_at(Instant::now())
    }

    /// 读取单条记录（快照克隆，不暴露内部锁）
    pub fn get(&self, node_id: &NodeId) -> Option<DiscoveredPeerRecord> {
        self.peers
            .read()
            .expect("discovery cache lock poisoned")
            .get(node_id)
            .cloned()
    }

    /// 当前全部在线记录（按 node_id 稳定排序，供命令面/UI 复用）
    pub fn list(&self) -> Vec<DiscoveredPeerRecord> {
        let mut records: Vec<_> = self
            .peers
            .read()
            .expect("discovery cache lock poisoned")
            .values()
            .cloned()
            .collect();
        records.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        records
    }

    /// 以指定时间戳直接插入（绕过盖章）
    ///
    /// 仅 inline 测试使用：构造「过去发现、现已过期」的时间线而无需 sleep。
    #[cfg(test)]
    pub(crate) fn insert_with_last_seen(&mut self, record: DiscoveredPeerRecord, last_seen: Instant) {
        let mut stamped = record;
        stamped.last_seen = last_seen;
        self.peers
            .write()
            .expect("discovery cache lock poisoned")
            .insert(stamped.node_id.clone(), stamped);
    }
}

/// TTL 过期判定（唯一判定函数，`sweep_expired_at` 与单测共用）
///
/// 时钟倒退（last_seen 晚于 now）时 `duration_since` 饱和为零，判为未过期：
/// 宁可晚删也不误删，符合「在线」语义的保守取向。
fn is_expired(last_seen: Instant, now: Instant) -> bool {
    now.duration_since(last_seen) > PEER_DISCOVERY_TTL
}

// ==================== 守护任务 ====================

/// 发现守护配置：广播自身时携带的本机元数据
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// 本机设备名（写入 TXT `name`，供对端展示）
    pub device_name: String,
    /// 本机能力位图（写入 TXT `cap`）
    pub capabilities: u64,
}

/// mDNS 发现守护句柄：持有优雅关闭的全部凭据
///
/// 由 [`spawn_peer_mdns_daemon`] 产出；drop 句柄**不会**停止守护（任务已移交
/// 运行时），显式关停必须调用 [`DiscoveryDaemon::stop`]（Graceful Shutdown
/// 架构决策：退订浏览订阅 → 注销广播 → join 事件循环；共享守护归 MdnsService，
/// 本句柄不 shutdown——见 stop() 文档）。
pub struct DiscoveryDaemon {
    /// 底层 mdns-sd 守护句柄；stop 中 take 掉，drop 最终触发守护线程退出
    daemon: Option<ServiceDaemon>,
    /// 自身服务的完整实例名（注销必需：unregister 按全名寻址）
    fullname: String,
    /// 事件循环停机标志（退订未即时生效时的兜底退出通道）
    shutdown_tx: watch::Sender<bool>,
    /// 事件循环任务句柄（join 用）
    event_task: Option<tokio::task::JoinHandle<()>>,
    /// 周期 re-announce 任务句柄（join 用）
    reannounce_task: Option<tokio::task::JoinHandle<()>>,
    /// 周期 requery 任务句柄（join 用）
    requery_task: Option<tokio::task::JoinHandle<()>>,
    /// 浏览订阅退订守卫：本模块**不解释**其内容（中枢实现细节），只在句柄存续期
    /// 持有、在 [`DiscoveryDaemon::stop`] 中释放——释放即退订（事件循环随之断连）
    browse_guard: Option<Box<dyn Any + Send + Sync>>,
    /// 中枢类型级重查闭包（即时刷新转调它；周期任务持同一闭包的克隆）
    request_requery: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for DiscoveryDaemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryDaemon")
            .field("fullname", &self.fullname)
            .finish_non_exhaustive()
    }
}

impl DiscoveryDaemon {
    /// 本机广播的完整实例名（宿主登记 owner=host 用）
    pub fn service_fullname(&self) -> &str {
        &self.fullname
    }

    /// 优雅关停：退订浏览订阅 → 注销广播（让对端即时移除本机）→ join
    ///
    /// 共享守护收敛后（spec v2 / ticket 04）守护线程归 MdnsService 所有，
    /// 本句柄**不** shutdown 共享 daemon——只退订自己的浏览订阅、注销自己的
    /// 广播，其余插件浏览/广播不受影响。
    ///
    /// 清理中途遇到的首个错误会延迟到最后返回：半关闭状态下泄漏一个 mDNS
    /// 守护线程比返回部分错误更难排查，剩余清理步骤必须继续执行完。
    pub async fn stop(mut self) -> Result<()> {
        // ① 请求事件循环退出：正常路径由 ② 释放订阅守卫（通道断开）触发；
        //    此标志保证退订未即时生效时循环仍能在至多一个 SWEEP_INTERVAL 内收尾
        if self.shutdown_tx.send(true).is_err() {
            tracing::debug!("peer discovery event loop already exited before stop");
        }

        let mut first_err: Option<PeerNetError> = None;
        // ② 释放浏览订阅守卫：中枢据 Drop 退订本订阅者 → fan-out 发送端移除 →
        //    通道关闭 → 事件循环的 recv_async 断连退出（与旧 stop_browse 断联同形）。
        //    只释放本订阅者，同类型的其他订阅者（插件 host-mdns）不受影响
        drop(self.browse_guard.take());
        // 共享守护克隆（不 shutdown；drop 后仅释放本句柄对 daemon 的引用）
        if let Some(daemon) = self.daemon.take() {
            // ③ 注销自身广播：对端收到 goodbye 即时移除本机（不等 TTL 过期）；
            //    NotFound 属幂等重入，视为成功
            match daemon.unregister(&self.fullname) {
                Ok(status) => match status.recv_async().await {
                    Ok(status) => {
                        tracing::debug!(status = ?status, "peer mDNS service unregistered")
                    }
                    Err(e) => tracing::warn!("unregister status channel closed before reply: {e}"),
                },
                Err(source) => {
                    first_err.get_or_insert(PeerNetError::MdnsUnregister { source });
                }
            }
        }
        // ⑤ join 事件循环：JoinError 如实分级记录，panic 不得静默
        if let Some(task) = self.event_task.take() {
            match task.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("peer discovery event loop cancelled")
                }
                Err(e) => tracing::error!("peer discovery event loop panicked: {e}"),
            }
        }
        // ⑥ join 周期 re-announce 任务：停机标志已置位，至多一个 tick 内退出
        if let Some(task) = self.reannounce_task.take() {
            match task.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("peer discovery re-announce loop cancelled")
                }
                Err(e) => tracing::error!("peer discovery re-announce loop panicked: {e}"),
            }
        }
        // ⑦ join 周期 requery 任务：同上
        if let Some(task) = self.requery_task.take() {
            match task.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("peer discovery requery loop cancelled")
                }
                Err(e) => tracing::error!("peer discovery requery loop panicked: {e}"),
            }
        }
        tracing::info!(service = %self.fullname, "peer mDNS discovery daemon stopped");
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 请求立即重查：转调中枢重查闭包（对端设备列表手动刷新用，不等下一个
    /// [`REQUERY_INTERVAL`] 周期）。
    ///
    /// 重查机制（重发唯一 browse + receiver 缓存重放 + 广播给全部订阅者）归类型
    /// 中枢，本模块只投递请求；闭包必须是非阻塞同步调用（中枢内部按合并窗吞并
    /// 突发请求）——调用方可能持宿主状态锁，禁止在此 await
    pub fn request_requery(&self) {
        (self.request_requery)();
    }
}

/// 宿主注入的浏览订阅（纯值形态）：类型中枢 fan-out 的接收端 + 退订守卫 + 重查闭包
///
/// 三字段同源同生命周期，必须整份移交（不存在「只要 receiver 或只要守卫」的用法）：
/// - `receiver`：中枢 fan-out 的事件通道（flume，容量由中枢定），移交事件循环消费；
/// - `guard`：退订守卫。本模块**不解释**其内容（中枢实现细节，可能含 receiver 的
///   发送端、订阅 id 等），只随 [`DiscoveryDaemon`] 生命周期持有，
///   [`DiscoveryDaemon::stop`] 中释放——释放即退订（通道断开，事件循环退出）；
/// - `request_requery`：绑到中枢 `request_type_requery(SERVICE_TYPE)` 的闭包，
///   周期/即时重查都转调它（中枢按合并窗统一重发唯一 browse + 缓存重放 fan-out）。
///
/// 本模块据此**不再** `daemon.browse` / `stop_browse`：全进程同类型 browse 唯一性
/// 由中枢保证（ADR 0054），peer-net 的旧「重查换绑 receiver」机制随之删除。
pub struct PeerMdnsBrowse {
    /// 中枢 fan-out 接收端（移交事件循环）
    pub receiver: flume::Receiver<ServiceEvent>,
    /// 退订守卫：持有期间订阅有效，Drop 即退订（本模块不解释其内容）
    pub guard: Box<dyn Any + Send + Sync>,
    /// 中枢类型级重查闭包（同步非阻塞：内部只投递控制消息）
    pub request_requery: Arc<dyn Fn() + Send + Sync>,
}

/// 启动对等网络 mDNS 发现守护：注册自身广播 + 消费中枢浏览订阅 + 事件循环入缓存
///
/// 必须在 tokio 运行时上下文中调用（内部 spawn 依赖 Handle::current）：生产侧
/// 为宿主异步环境，测试侧为 `#[tokio::test]`。节点必须已通过
/// [`PeerNetNode::with_discovery`] 挂载缓存——守护回调与外部喂入共用该实例。
///
/// 广播端口取宿主移交 listener 的实际端口（`running`），广播地址走 addr_auto
/// 由 mdns-sd 枚举本机全部接口（多网卡/IP 变化免手工维护）。
///
/// 浏览面由宿主壳铸造 [`PeerMdnsBrowse`]（中枢订阅）后注入：本函数**不**发起
/// `daemon.browse`——subscribe 时中枢已建立该类型唯一浏览（新订阅者享中枢的
/// 「加入触发后缘重查」缓存重放），本模块只消费 fan-out 事件。
pub fn spawn_peer_mdns_daemon(
    node: &PeerNetNode,
    running: &RunningNode,
    config: DiscoveryConfig,
    daemon: ServiceDaemon,
    browse: PeerMdnsBrowse,
) -> Result<DiscoveryDaemon> {
    let own_node_id = node.node_id().clone();
    let short = own_node_id.short_fingerprint();
    let instance_name = format!("{INSTANCE_PREFIX}{short}");
    // 全名格式由 mdns-sd 固定为 "{escaped_instance}.{service_type}"（见 ServiceInfo::new）
    let fullname = format!("{instance_name}.{SERVICE_TYPE}");
    let listen_port = running.local_addr().port();

    let cache = node.discovery().ok_or(PeerNetError::DiscoveryNotAttached)?;

    // 浏览订阅三字段同一生命周期：receiver 给事件循环，守卫与闭包留本句柄
    let PeerMdnsBrowse {
        receiver,
        guard,
        request_requery,
    } = browse;

    // mDNS 基础能力服务收敛（spec v2 / ticket 04）：不再自建 ServiceDaemon，
    // 使用宿主 MdnsService 的全局共享守护（register / re-announce 广播面不动；
    // 虚拟网卡禁用由 discovery-engine 的共享守护初始化执行一次，此处不重复）
    let properties = encode_txt_properties(
        &own_node_id,
        &config.device_name,
        DISCOVERY_PROTOCOL_VERSION,
        config.capabilities,
    );
    // ip 参数传空串 = 启用 addr_auto 的库约定（AsIpAddrs 对空串返回空集合）
    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &format!("{instance_name}.local."),
        "",
        listen_port,
        properties,
    )
    .map_err(|source| PeerNetError::MdnsServiceInfo { source })?
    .enable_addr_auto();

    daemon
        .register(service_info.clone())
        .map_err(|source| PeerNetError::MdnsRegister { source })?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let event_task = tokio::spawn(run_discovery_loop(receiver, cache, own_node_id, shutdown_rx.clone()));
    // 周期 re-announce：mdns-sd 注册后不主动周期广播，须手动续期（见常量注释）
    let reannounce_task = tokio::spawn(run_reannounce_loop(daemon.clone(), service_info, shutdown_rx.clone()));
    // 周期主动重查：被动 announce 真机环境不可靠，查询→应答是唯一稳定刷新路径；
    // 重查本身由中枢统一执行，本任务只按节奏转调闭包（同一个闭包即时刷新也用）
    let requery_task = tokio::spawn(run_requery_loop(Arc::clone(&request_requery), shutdown_rx));
    tracing::info!(
        service = %fullname,
        port = listen_port,
        device = %config.device_name,
        "peer mDNS discovery daemon started (shared daemon, type-hub subscription)"
    );
    Ok(DiscoveryDaemon {
        daemon: Some(daemon),
        fullname,
        shutdown_tx,
        event_task: Some(event_task),
        reannounce_task: Some(reannounce_task),
        requery_task: Some(requery_task),
        browse_guard: Some(guard),
        request_requery,
    })
}

/// 周期 re-announce 任务：每隔 [`REANNOUNCE_INTERVAL`] 重复 register 自身服务
///
/// mdns-sd 的 `register` 幂等（同名覆盖），重复调用直接触发 unsolicited
/// announce（RFC 6762 §8.3 自动补发第二条），不 probe、不发 goodbye——对端
/// 不会误判离线，又能持续收到续期广播，规避 browse 查询指数退避（上限 1 小时）
/// 超过缓存 TTL 导致的「启动互见、随后互不可见」。
async fn run_reannounce_loop(daemon: ServiceDaemon, service_info: ServiceInfo, mut shutdown_rx: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(REANNOUNCE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // 首个 tick 立即到期：跳过（调用方启动时已 register 过一次）
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            r = shutdown_rx.changed() => {
                // changed() 在 Sender 被 drop（未 send true 的异常停机路径）时
                // 返回 Err(Closed) 立即就绪：若只查 borrow() 不 break，本循环
                // 会在 biased 首分支上空转（busy-loop 100% CPU）
                if r.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                if *shutdown_rx.borrow() {
                    break;
                }
                match daemon.register(service_info.clone()) {
                    Ok(()) => tracing::debug!("peer mDNS re-announce sent"),
                    Err(e) => tracing::warn!(error = %e, "peer mDNS re-announce register failed"),
                }
            }
        }
    }
    tracing::debug!("peer mDNS re-announce loop exited");
}

/// 守护事件循环：消费中枢 fan-out 事件 + 周期性过期清扫
///
/// 退出条件（任一）：① 中枢退订致通道断开（守卫释放路径：`recv_async` 返回
/// Disconnected）；② 停机标志置位（退订未即时生效时的兜底，最迟一个
/// SWEEP_INTERVAL 后生效）。
///
/// receiver 由宿主注入的中枢订阅移交（[`PeerMdnsBrowse::receiver`]），本模块不再
/// 自己 browse、也没有 receiver 换绑——重查换绑与缓存重放都在中枢内部完成，事件
/// 按订阅者 fan-out 过来（同类型其他订阅者各收一份，互不影响）。
///
/// 事件只进引擎内部 DiscoveryCache（spec v2 D1：面向插件的全局发现桥接
/// 已退役——插件改经 host-mdns 自建 browse 收定向事件）
async fn run_discovery_loop(
    receiver: flume::Receiver<ServiceEvent>,
    cache: Arc<DiscoveryCache>,
    own_node_id: NodeId,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut last_sweep = Instant::now();
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        tokio::select! {
            biased;
            r = shutdown_rx.changed() => {
                // Sender 被 drop → Err(Closed)：同 reannounce 循环，视为停机
                if r.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            // flume 0.12 无 recv_async_timeout：用 tokio 超时包裹 recv_async 同义实现
            event = tokio::time::timeout(SWEEP_INTERVAL, receiver.recv_async()) => {
                match event {
                    Ok(Ok(event)) => {
                        handle_browse_event(&cache, &own_node_id, event);
                        // 高频事件流下 Timeout 分支可能长期不触发，清扫按墙钟到期兜底
                        let now = Instant::now();
                        if now.duration_since(last_sweep) >= SWEEP_INTERVAL {
                            sweep_and_log(&cache);
                            last_sweep = now;
                        }
                    }
                    // 断连 = 中枢退订本订阅者（守卫释放 / 归属者退出）
                    Ok(Err(_recv_err)) => break,
                    // 超时 = 本周期无事件，正好执行周期性过期清扫
                    Err(_elapsed) => {
                        sweep_and_log(&cache);
                        last_sweep = Instant::now();
                    }
                }
            }
        }
    }
    tracing::debug!("peer mDNS discovery event loop exited");
}

/// 周期主动重查任务：每 [`REQUERY_INTERVAL`] 转调中枢重查闭包一次
///
/// 被动 announce 在真机 WiFi 环境不可靠（见 [`REQUERY_INTERVAL`]），主动查询是
/// 唯一稳定的对端刷新路径；重查机制（重发唯一 browse + receiver 换绑 + 缓存重放
/// fan-out）全在类型中枢，本任务只负责节奏——业务节奏属消费方，机制归中枢。
/// 宿主可经 [`DiscoveryDaemon::request_requery`] 发起即时重查（设备列表手动刷新），
/// 与周期路径转调同一闭包，突发由中枢的合并窗吞并。
async fn run_requery_loop(request_requery: Arc<dyn Fn() + Send + Sync>, mut shutdown_rx: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(REQUERY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // 首个 tick 立即到期：跳过（订阅建立时中枢已 browse 并触发缓存重放，
    // 启动即重查属重复请求）
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            r = shutdown_rx.changed() => {
                // Sender 被 drop → Err(Closed)：同 reannounce 循环，视为停机
                if r.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {}
        }
        if *shutdown_rx.borrow() {
            break;
        }
        (request_requery)();
        tracing::debug!("peer mDNS periodic requery issued");
    }
    tracing::debug!("peer mDNS requery loop exited");
}

/// 单次清扫并按移除数量分级记录
fn sweep_and_log(cache: &DiscoveryCache) {
    let removed = cache.sweep_expired();
    if removed > 0 {
        tracing::debug!(count = removed, "peer discovery cache swept expired records");
    }
}

/// 处理单个浏览事件：found/resolved 进缓存（含自播过滤）、removed 即时移除。
/// 返回供宿主桥接插件总线的 wire 事件（自播/无地址/无 id 等被过滤场景返回 None）。
fn handle_browse_event(cache: &DiscoveryCache, own_node_id: &NodeId, event: ServiceEvent) {
    match event {
        ServiceEvent::SearchStarted(ty) => {
            tracing::debug!(service_type = %ty, "peer mDNS search started");
        }
        ServiceEvent::SearchStopped(ty) => {
            tracing::debug!(service_type = %ty, "peer mDNS search stopped");
        }
        ServiceEvent::ServiceFound(_, fullname) => {
            tracing::debug!(instance = %fullname, "peer mDNS instance found, waiting for resolve");
        }
        ServiceEvent::ServiceResolved(info) => {
            let Some(ip) = info
                .get_addresses()
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| info.get_addresses().iter().next())
                .map(ScopedIp::to_ip_addr)
            else {
                tracing::warn!(
                    instance = %info.get_fullname(),
                    "resolved peer record carries no address, skipped"
                );
                return;
            };
            let addr = SocketAddr::new(ip, info.get_port());
            let Some(instance) = instance_from_fullname(info.get_fullname()) else {
                tracing::warn!(fullname = %info.get_fullname(), "unexpected peer mDNS fullname shape, skipped");
                return;
            };
            let properties: HashMap<String, String> = info
                .get_properties()
                .iter()
                .map(|p| (p.key().to_string(), p.val_str().to_string()))
                .collect();
            match decode_txt_properties(instance, addr, &properties) {
                Some(record) => {
                    // 自播回显过滤：本机的广播也会被自己的浏览收到
                    if record.node_id == *own_node_id {
                        return;
                    }
                    tracing::info!(
                        name = %record.device_name,
                        cap = format!("{:#x}", record.capabilities),
                        ver = record.protocol_version,
                        peer = %record.addr,
                        short = %record.node_id.short_fingerprint(),
                        "peer discovered"
                    );
                    cache.observe(record);
                }
                None => {
                    tracing::warn!(
                        instance = %info.get_fullname(),
                        "peer TXT payload lacks valid node id, record skipped"
                    );
                }
            }
        }
        ServiceEvent::ServiceRemoved(_, fullname) => {
            let removed = instance_from_fullname(&fullname)
                .and_then(fingerprint_of_instance)
                .and_then(|fp| cache.remove_by_fingerprint(fp));
            match removed {
                Some(record) => tracing::info!(
                    name = %record.device_name,
                    short = %record.node_id.short_fingerprint(),
                    "peer removed (mDNS goodbye)"
                ),
                None => tracing::debug!(
                    instance = %fullname,
                    "goodbye for unknown or already swept instance"
                ),
            }
        }
        // ServiceEvent 标记 #[non_exhaustive]：上游新增变体时先忽略并留痕，
        // 避免未来版本升级在事件热路径上 panic
        other => {
            tracing::debug!(event = ?other, "unhandled peer mDNS event variant");
        }
    }
}

// ==================== inline 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 合法 64 位 hex NodeId 构造助手
    fn test_node_id(seed: u8) -> NodeId {
        NodeId::parse(&hex::encode([seed; 32])).expect("valid node id")
    }

    // ---- TXT codec ----

    #[test]
    fn txt_roundtrip_preserves_all_fields() {
        let node_id = test_node_id(0x2a);
        let properties = encode_txt_properties(&node_id, "开发机 Dev", 1, CAP_FILE_TRANSFER | (1 << 3));
        let addr: SocketAddr = "192.168.1.10:47613".parse().expect("valid addr");

        let decoded =
            decode_txt_properties("wasmnest-peer-deadbeef", addr, &properties).expect("round-trip must decode");

        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.addr, addr);
        assert_eq!(decoded.device_name, "开发机 Dev");
        assert_eq!(decoded.protocol_version, DISCOVERY_PROTOCOL_VERSION);
        assert_eq!(decoded.capabilities, CAP_FILE_TRANSFER | (1 << 3));
    }

    #[test]
    fn txt_decode_tolerates_missing_and_broken_fields() {
        let addr: SocketAddr = "192.168.1.20:1".parse().expect("valid addr");
        let node_id = test_node_id(0x11);

        // 缺 name → 回退实例名；缺 ver/cap → 0
        let minimal = HashMap::from([(TXT_KEY_ID.to_string(), node_id.as_str().to_string())]);
        let decoded =
            decode_txt_properties("wasmnest-peer-feedface", addr, &minimal).expect("minimal payload still decodes");
        assert_eq!(decoded.device_name, "wasmnest-peer-feedface");
        assert_eq!(decoded.protocol_version, 0);
        assert_eq!(decoded.capabilities, 0);

        // 坏 cap / 坏 ver → 记 0，不产生错误
        let broken = HashMap::from([
            (TXT_KEY_ID.to_string(), node_id.as_str().to_string()),
            (TXT_KEY_VER.to_string(), "not-a-number".to_string()),
            (TXT_KEY_CAP.to_string(), "zzz".to_string()),
        ]);
        let decoded =
            decode_txt_properties("wasmnest-peer-feedface", addr, &broken).expect("broken ver/cap degrade to zero");
        assert_eq!(decoded.protocol_version, 0);
        assert_eq!(decoded.capabilities, 0);

        // 缺 id / 坏 id → 整条跳过（None）：无法钉扎身份的记录不可拨号
        assert!(decode_txt_properties("x", addr, &HashMap::new()).is_none());
        let bad_id = HashMap::from([(TXT_KEY_ID.to_string(), "nothex".to_string())]);
        assert!(decode_txt_properties("x", addr, &bad_id).is_none());
    }

    #[test]
    fn txt_encode_truncates_long_device_name_on_char_boundary() {
        let node_id = test_node_id(0x33);
        // 100 个三字节汉字 = 300 字节 > 200 上限
        let long_name = "测".repeat(100);
        let properties = encode_txt_properties(&node_id, &long_name, 1, 0);
        let encoded_name = &properties[TXT_KEY_NAME];
        assert!(encoded_name.len() <= DEVICE_NAME_MAX_BYTES);
        // 截断必须落在字符边界上（String 切片本身保证 UTF-8 合法性，此处断言未丢整字）
        assert_eq!(encoded_name.chars().count(), DEVICE_NAME_MAX_BYTES / 3);

        // mdns-sd 的硬约束：键 + 值总长 ≤255
        for (key, value) in &properties {
            assert!(
                key.len() + value.len() <= u8::MAX as usize,
                "TXT property {key} exceeds 255-byte limit"
            );
        }
    }

    #[test]
    fn fullname_helpers_extract_instance_and_fingerprint() {
        let fullname = format!("{INSTANCE_PREFIX}deadbeef.{SERVICE_TYPE}");
        let instance = instance_from_fullname(&fullname).expect("well-shaped fullname");
        assert_eq!(instance, "wasmnest-peer-deadbeef");
        assert_eq!(fingerprint_of_instance(instance), Some("deadbeef"));

        // 外域服务 / 非本应用实例 → None
        assert!(instance_from_fullname("other._wasmnest._tcp.local.").is_none());
        assert!(fingerprint_of_instance("not-our-prefix").is_none());
    }

    // ---- 在线缓存（显式时间戳，无 sleep）----

    fn sample_record(seed: u8, last_octet: u8) -> DiscoveredPeerRecord {
        DiscoveredPeerRecord {
            node_id: test_node_id(seed),
            addr: format!("192.168.1.{last_octet}:476{last_octet:02}")
                .parse()
                .expect("valid addr"),
            device_name: format!("device-{seed}"),
            protocol_version: DISCOVERY_PROTOCOL_VERSION,
            capabilities: CAP_FILE_TRANSFER,
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn observe_enters_cache_with_full_metadata() {
        let cache = DiscoveryCache::new();
        let record = sample_record(1, 11);

        cache.observe(record.clone());

        let cached = cache.get(&record.node_id).expect("observed record visible");
        // 字段完整性：AC#1 断言点（名称/版本/能力位随记录进入缓存）
        assert_eq!(cached.device_name, "device-1");
        assert_eq!(cached.protocol_version, DISCOVERY_PROTOCOL_VERSION);
        assert_eq!(cached.capabilities, CAP_FILE_TRANSFER);
        assert_eq!(cached.addr, record.addr);
        // observe 盖章真实时刻：last_seen 不早于 observe 调用点
        assert!(cached.last_seen >= record.last_seen);
        assert_eq!(cache.list().len(), 1);
    }

    #[test]
    fn sweep_expired_at_removes_stale_records_only() {
        let mut cache = DiscoveryCache::new();
        let fresh = sample_record(2, 22);
        let stale = sample_record(3, 33);

        // fresh 走公开 observe（盖章 now）；stale 回填「TTL+1s 前」的过去时间戳
        let now = Instant::now();
        cache.observe(fresh.clone());
        let past = now
            .checked_sub(PEER_DISCOVERY_TTL + Duration::from_secs(1))
            .expect("backwards instant");
        cache.insert_with_last_seen(stale.clone(), past);

        let removed = cache.sweep_expired_at(now);
        assert_eq!(removed, 1, "only the stale record expires");
        assert!(cache.get(&fresh.node_id).is_some(), "fresh record survives");
        assert!(cache.get(&stale.node_id).is_none());

        // 边界：恰好等于 TTL 不算过期（严格大于才移除）
        let boundary = sample_record(4, 44);
        let at_ttl = now.checked_sub(PEER_DISCOVERY_TTL).expect("backwards instant");
        cache.insert_with_last_seen(boundary.clone(), at_ttl);
        assert_eq!(cache.sweep_expired_at(now), 0, "age == TTL stays online");
    }

    #[test]
    fn remove_is_immediate_goodbye_semantics() {
        let cache = DiscoveryCache::new();
        let record = sample_record(5, 55);
        cache.observe(record.clone());

        // 移除返回的是缓存中的盖章副本：last_seen 已被 observe 续期到不早于原值
        let removed = cache.remove(&record.node_id).expect("record removed");
        assert_eq!(removed.node_id, record.node_id);
        assert_eq!(removed.addr, record.addr);
        assert!(removed.last_seen >= record.last_seen, "observe must have stamped");
        assert!(cache.get(&record.node_id).is_none(), "gone immediately");
        assert!(cache.list().is_empty());

        // remove_by_fingerprint：goodbye 只带实例名时的反查路径
        cache.observe(record.clone());
        let short = record.node_id.short_fingerprint();
        assert!(cache.remove_by_fingerprint(short).is_some());
        assert!(
            cache.remove_by_fingerprint(short).is_none(),
            "second goodbye idempotent"
        );
    }

    #[test]
    fn discovered_record_converts_to_static_peer_record() {
        let record = sample_record(6, 66);
        let converted = record.to_static_peer_record();
        // 拨号通路只需要 node_id + addr：发现元数据不随之流动（D1）
        assert_eq!(converted.node_id, record.node_id);
        assert_eq!(converted.addr, record.addr);
    }

    /// 序列化形状守卫：`last_seen` 跳过、其余字段齐全（list_discovered_peers 响应契约）
    #[test]
    fn serialization_skips_runtime_bookkeeping_field() {
        let record = sample_record(7, 77);
        let json = serde_json::to_value(&record).expect("serializable");
        let obj = json.as_object().expect("object shape");
        assert!(!obj.contains_key("last_seen"), "bookkeeping field must be skipped");
        for key in ["node_id", "addr", "device_name", "protocol_version", "capabilities"] {
            assert!(obj.contains_key(key), "payload field {key} must serialize");
        }
    }

    // ---- 中枢订阅形态（ADR 0054：浏览面注入 + 事件循环 / 停机语义）----

    /// 有界轮询等待异步条件成立（无固定 sleep；超时即失败并给出定位信息）
    async fn wait_for(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::task::yield_now().await;
        }
    }

    /// 中枢 fan-out 可注入的「对端已解析服务」事件（事件形状与 mdns-sd 投递一致：
    /// `ServiceResolved` 内为 ResolvedService）
    fn synthetic_resolved_event(node_id: &NodeId, ip: &str, port: u16) -> ServiceEvent {
        let instance = format!("{INSTANCE_PREFIX}{}", node_id.short_fingerprint());
        let properties = encode_txt_properties(node_id, "对端设备", DISCOVERY_PROTOCOL_VERSION, CAP_FILE_TRANSFER);
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            ip,
            port,
            properties,
        )
        .expect("synthetic service info builds");
        ServiceEvent::ServiceResolved(Box::new(info.as_resolved_service()))
    }

    /// goodbye 事件（只带服务类型 + 全名的形状）
    fn synthetic_removed_event(node_id: &NodeId) -> ServiceEvent {
        ServiceEvent::ServiceRemoved(
            SERVICE_TYPE.to_string(),
            format!("{INSTANCE_PREFIX}{}.{SERVICE_TYPE}", node_id.short_fingerprint()),
        )
    }

    /// 单测夹具：不带真实守护 / 后台任务的空句柄，字段由各用例按需补齐
    /// （真实守护只经 [`spawn_peer_mdns_daemon`]，单测一律不触网）
    fn daemon_fixture() -> DiscoveryDaemon {
        let (shutdown_tx, _) = watch::channel(false);
        DiscoveryDaemon {
            daemon: None,
            fullname: format!("{INSTANCE_PREFIX}00000000.{SERVICE_TYPE}"),
            shutdown_tx,
            event_task: None,
            reannounce_task: None,
            requery_task: None,
            browse_guard: None,
            request_requery: Arc::new(|| {}),
        }
    }

    /// 退订探针：模拟中枢订阅守卫（Drop = 退订，同时释放内部持有的发送端）
    struct SubscriptionProbe {
        /// 持有 fan-out 发送端：守卫存活期间通道不断开（与中枢行为同形）
        _tx: flume::Sender<ServiceEvent>,
        releases: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for SubscriptionProbe {
        fn drop(&mut self) {
            self.releases.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 契约：`request_requery` 每次调用都转调注入的中枢重查闭包
    /// （合并窗吞并突发请求是中枢职责，peer-net 侧不得自行节流或丢弃）
    #[test]
    fn request_requery_forwards_every_call_to_hub_closure() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let mut daemon = daemon_fixture();
        daemon.request_requery = Arc::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });

        daemon.request_requery();
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "即时重查必须转调中枢闭包"
        );
        daemon.request_requery();
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "连续请求逐次转调（不自行吞并）"
        );
    }

    /// 契约：事件循环消费宿主注入的中枢 fan-out 事件——自播过滤、goodbye 即时移除、
    /// 通道断开（= 中枢退订）即退出
    ///
    /// 多线程运行时：事件循环在独立 worker 上跑，断言侧的超时/轮询永远不会被
    /// 「循环空转不 yield」这类回归拖成悬挂（回归表现为确定的超时失败）
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_loop_consumes_hub_fanin_events_and_exits_on_disconnect() {
        let cache = Arc::new(DiscoveryCache::new());
        let own = test_node_id(0x10);
        let peer = test_node_id(0x20);

        let (tx, rx) = flume::bounded::<ServiceEvent>(8);
        // 停机通道全程存活（Sender 一旦 drop，事件循环会视为停机立即退出）
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let loop_task = tokio::spawn(run_discovery_loop(rx, Arc::clone(&cache), own.clone(), shutdown_rx));

        // ① 自播回显与对端事件同走一条 FIFO 通道：等到对端记录出现，即可断定
        //    自播那条已被处理并过滤（无需 sleep）
        tx.send(synthetic_resolved_event(&own, "192.168.1.9", 40000))
            .expect("send self-broadcast event");
        tx.send(synthetic_resolved_event(&peer, "192.168.1.20", 40001))
            .expect("send peer event");
        wait_for("peer record cached", || cache.list().len() == 1).await;
        let cached = cache.list();
        assert_eq!(cached[0].node_id, peer, "自播回显不得入缓存");
        assert_eq!(cached[0].device_name, "对端设备");
        assert_eq!(
            cached[0].addr,
            "192.168.1.20:40001".parse::<SocketAddr>().expect("addr")
        );

        // ② goodbye：经同一 fan-out 通道抵达 → 缓存即时移除（不等 TTL 清扫）
        tx.send(synthetic_removed_event(&peer)).expect("send goodbye event");
        wait_for("peer record removed", || cache.list().is_empty()).await;

        // ③ 通道断开（守卫释放 / 中枢停机）⇒ 事件循环退出，无需停机标志
        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .expect("event loop must exit when subscription channel disconnects")
            .expect("event loop must not panic");
        drop(shutdown_tx);
    }

    /// 契约：停机标志（退订未即时生效时的兜底通道）能立即终止事件循环
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_loop_exits_on_shutdown_flag() {
        let cache = Arc::new(DiscoveryCache::new());
        let (_tx, rx) = flume::bounded::<ServiceEvent>(4);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let loop_task = tokio::spawn(run_discovery_loop(rx, cache, test_node_id(0x11), shutdown_rx));

        shutdown_tx.send(true).expect("receiver alive");
        // 4s < SWEEP_INTERVAL(5s)：正确实现立即（微秒级）退出，而「丢掉停机分支」
        // 的变异只能靠兜底超时脱离，必超 4s → 必红
        tokio::time::timeout(Duration::from_secs(4), loop_task)
            .await
            .expect("event loop must exit on shutdown flag")
            .expect("event loop must not panic");
    }

    /// 契约：订阅守卫随句柄生命周期——`stop()` 释放守卫恰一次（释放即退订），
    /// 并在同一调用内 join 掉事件循环（不悬挂、不重复释放）
    #[tokio::test]
    async fn stop_releases_subscription_guard_once_and_joins_event_loop() {
        let releases = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cache = Arc::new(DiscoveryCache::new());
        let (tx, rx) = flume::bounded::<ServiceEvent>(4);
        // 探针：本测试另持一个发送端克隆，事件循环退出（receiver 释放）后即断连
        let probe_tx = tx.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let event_task = tokio::spawn(run_discovery_loop(rx, cache, test_node_id(0x30), shutdown_rx));

        let mut daemon = daemon_fixture();
        daemon.browse_guard = Some(Box::new(SubscriptionProbe {
            _tx: tx,
            releases: Arc::clone(&releases),
        }));
        daemon.shutdown_tx = shutdown_tx;
        daemon.event_task = Some(event_task);

        assert_eq!(
            releases.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "守卫在句柄存续期保持持有（订阅未提前释放）"
        );
        tokio::time::timeout(Duration::from_secs(5), daemon.stop())
            .await
            .expect("stop must not hang on event loop join")
            .expect("stop succeeds without a shared-daemon handle");
        assert_eq!(
            releases.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "守卫在 stop 中释放恰一次（无二次释放）"
        );
        // stop 返回时事件循环必须已被 join：receiver 随之释放，探针发送端断连
        assert!(
            probe_tx.is_disconnected(),
            "stop 必须 join 掉事件循环（receiver 已释放）"
        );
    }
}
