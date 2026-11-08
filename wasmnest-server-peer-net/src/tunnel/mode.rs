//! 传输模式判定（设计 §4.9）：内网默认，**明确不在内网**才切外网。
//!
//! 本模块是**纯判据层**：不做 I/O、不建连接、不读时钟以外的环境；输入 = 宿主侧
//! 网络事实 + LAN 尝试结果 + 用户手动指令，输出 = 模式与下一步动作。拨号顺序、
//! reservation 计数、事件投递都在 [`super::manager`] 里按这里的结论执行。
//!
//! ## 安全口径（不变量 9）
//!
//! - 只有判据表里标「是」的情形允许自动切 wan；表外情形一律保持 lan；
//! - 同网段 timeout / `ECONNREFUSED` / 服务未启动 / 认证失败 / 未匹配 /
//!   Noise 握手失败**永不**触发自动切换（否则阻断 LAN 就能把流量逼进中继）；
//! - 网络事实未知（接口枚举失败 / 无任何非环回接口）按「判据不明确」处理——
//!   先试 LAN，不猜、不静默切；
//! - `wan-active` 回切 `lan-active` 需要**连续两次** LAN 探测成功（防抖）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

// ==================== 状态与原因词表 ====================

/// 传输模式（8 态，设计 §4.9 状态机）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferMode {
    /// 仅未匹配 + 有效票据时进入
    Pairing,
    /// 拨 LAN 候选（默认路径）
    LanProbing,
    /// 直连对端 LAN 地址，数据不经 relay
    LanActive,
    /// 同网段但不可达 / 服务未启动：判据不明确，保持 lan 并给手动入口
    LanUnreachable,
    /// 经 relay 建通道中
    WanConnecting,
    /// 通道已建立并承载业务数据
    WanActive,
    /// 无 relay 配置 / relay 不可达 / 用户关闭外网
    WanUnavailable,
    /// 无可用通道（未启动 / 已断开 / 票据失败）
    Offline,
}

impl TransferMode {
    /// 词表字面（`peer:mode` 事件与 `status` 投影共用）
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::LanProbing => "lan-probing",
            Self::LanActive => "lan-active",
            Self::LanUnreachable => "lan-unreachable",
            Self::WanConnecting => "wan-connecting",
            Self::WanActive => "wan-active",
            Self::WanUnavailable => "wan-unavailable",
            Self::Offline => "offline",
        }
    }

    /// 该模式是否要求「内网不可达」的手动「尝试外网」入口
    pub fn needs_manual_entry(&self) -> bool {
        matches!(self, Self::LanUnreachable)
    }
}

/// 模式归因（`mode.wan.selected reason=…` 日志与 `peer:mode` 事件字段）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModeReason {
    /// 移动端网络类型为蜂窝（无 Wi-Fi / Ethernet）
    Cellular,
    /// 对端 LAN 候选不在本机任何接口子网内，且 mDNS 无记录
    DifferentSubnet,
    /// 没有任何 LAN 候选（无 mDNS、无上次 LAN 地址、连接串不含 LAN 提示）
    NoLanCandidate,
    /// 全部 LAN 候选返回 EHOSTUNREACH / ENETUNREACH（不是 timeout）
    HostUnreachable,
    /// 用户手动「尝试外网」
    User,
    /// `allowWan=false`：外网通道被用户关闭（不是加密开关）
    WanDisabled,
    /// 未配置 relay 地址
    RelayUnavailable,
    /// wan-active 期间周期探测 LAN 成功（连续两次）后回切
    LanRestored,
    /// 换网：手动指令与探测窗口重置，回到自动策略
    NetworkChanged,
}

impl ModeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cellular => "cellular",
            Self::DifferentSubnet => "different-subnet",
            Self::NoLanCandidate => "no-lan-candidate",
            Self::HostUnreachable => "host-unreachable",
            Self::User => "user",
            Self::WanDisabled => "wan-disabled",
            Self::RelayUnavailable => "relay-unavailable",
            Self::LanRestored => "lan-restored",
            Self::NetworkChanged => "network-changed",
        }
    }
}

/// 对外可见的模式快照（`host-tunnel.status` 的 `modes` 字段 / `peer:mode` 事件载荷）
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerModeView {
    pub node_id: String,
    pub mode: TransferMode,
    pub reason: Option<ModeReason>,
    /// wan-active 期间连续 LAN 探测成功次数（0/1，第 2 次回切）
    pub lan_probe_wins: u8,
    /// 用户手动「尝试外网」在本网络会话内保持
    pub manual_wan: bool,
    pub updated_at_ms: u64,
}

// ==================== 网络事实（宿主机侧枚举）====================

/// 接口子网（`ip/prefix`）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    addr: IpAddr,
    prefix: u8,
}

impl Subnet {
    /// 前缀越界（v4 > 32 / v6 > 128）返回 `None`——非法事实不得参与判定
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { addr, prefix })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// 地址是否落在本子网（v4/v6 不互判）
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

fn v6_mask(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p if p >= 128 => u128::MAX,
        p => u128::MAX << (128 - p),
    }
}

/// 宿主侧网络事实（应用 JS 不可见；只进本层判定与 `status` 归因）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkFacts {
    /// 枚举是否可信（false = 未知：一律不自动切 wan）
    pub known: bool,
    /// 当前只走蜂窝（无 Wi-Fi / Ethernet 接口）
    pub cellular: bool,
    /// 本机非环回接口子网
    pub local_subnets: Vec<Subnet>,
    /// mDNS 是否已发现该对端
    pub mdns_known: bool,
}

impl NetworkFacts {
    /// 未知事实：判据不明 → 先试 LAN（不猜、不切）
    pub fn unknown() -> Self {
        Self::default()
    }

    /// 候选是否至少有一个落在本机任一接口子网内
    pub fn any_in_local_subnet(&self, candidates: &[IpAddr]) -> bool {
        candidates
            .iter()
            .any(|ip| self.local_subnets.iter().any(|subnet| subnet.contains(*ip)))
    }
}

/// LAN 候选来源（决定「没有候选」是否算「明确不在内网」）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanCandidateSource {
    /// 连接串 / QR / 上次 LAN 地址：候选由调用方显式给出
    Explicit,
    /// mDNS 发现：没有候选可能只是发现窗口未结束
    Mdns,
}

/// 外网可用性（`allowWan` + relay 配置；不可用时给显性原因）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanAvailability {
    Ready,
    Blocked(ModeReason),
}

impl WanAvailability {
    /// `allow_wan` / relay 地址是否配置 → 可用性（关闭优先于未配置）
    pub fn new(allow_wan: bool, relay_addrs_configured: bool) -> Self {
        if !allow_wan {
            Self::Blocked(ModeReason::WanDisabled)
        } else if !relay_addrs_configured {
            Self::Blocked(ModeReason::RelayUnavailable)
        } else {
            Self::Ready
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// LAN 尝试失败的成因分类（**只有** `Unreachable` 属于「明确不在内网」）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanFailure {
    /// 拨号超时：判据不明确
    Timeout,
    /// `ECONNREFUSED`：服务未启动 / 端口未暴露，判据不明确
    Refused,
    /// 服务未启动（对端可达但端口无监听的其他表现），判据不明确
    ServiceMissing,
    /// `EHOSTUNREACH` / `ENETUNREACH`：明确不在内网
    Unreachable,
    /// 认证 / 未匹配 / Noise 握手失败：安全错误，**不得**为了绕过失败切 relay
    Auth,
    /// 其他未分类失败：保守按「判据不明确」处理
    Other,
}

/// 拨号失败详情（成因分类 + 可展示原因 + 逐候选成因）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialFailure {
    /// 整体类别（由 [`Self::from_causes`] 按判据表归并；事件 / 错误码只看这个）
    pub kind: LanFailure,
    pub detail: String,
    /// 逐候选成因（「全部 `Unreachable`」只能在这个列表上判，**不得**解析 detail）
    pub causes: Vec<LanFailure>,
}

impl DialFailure {
    /// 单一成因（非多地址拨号的路径 / 测试替身）
    pub fn new(kind: LanFailure, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            causes: vec![kind],
        }
    }

    /// 按逐候选成因归并整体类别：
    ///
    /// - **全部** `Unreachable` → `Unreachable`（§4.9 唯一允许自动切 wan 的明确判据）；
    /// - 任一 `Auth` → `Auth`（安全错误优先，绝不为了绕过失败切 relay）；
    /// - 单候选 → 原样；
    /// - 其余混合（timeout/refused/unreachable 等）→ `Other`（保守保持 LAN）。
    pub fn from_causes(causes: Vec<LanFailure>, detail: impl Into<String>) -> Self {
        let kind = if !causes.is_empty() && causes.iter().all(|c| *c == LanFailure::Unreachable) {
            LanFailure::Unreachable
        } else if causes.contains(&LanFailure::Auth) {
            LanFailure::Auth
        } else if causes.len() == 1 {
            causes[0]
        } else {
            LanFailure::Other
        };
        Self {
            kind,
            detail: detail.into(),
            causes,
        }
    }

    /// 全部候选都是 `EHOSTUNREACH` / `ENETUNREACH`（明确不在内网）
    pub fn all_unreachable(&self) -> bool {
        !self.causes.is_empty() && self.causes.iter().all(|c| *c == LanFailure::Unreachable)
    }
}

// ==================== 判据表 ====================

/// LAN 前置判据结论：这一步决定「还没拨号要不要直接进 wan」
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanVerdict {
    /// 默认路径：拨 LAN 候选
    TryLan,
    /// 判据明确：直接进 wan（原因进事件与日志）
    SwitchWan(ModeReason),
    /// mDNS 刚启动 / 刚换网：等发现窗口（不拨、不切）
    WaitDiscovery,
    /// 判据明确但外网不可用：显性 `lan-unreachable`（带 wan 不可用原因）
    Blocked(ModeReason),
}

/// 拨号前判据（设计 §4.9 判据表前三行 + 「mDNS 尚未发现」行）
pub fn judge_before_lan(
    facts: &NetworkFacts,
    candidates: &[IpAddr],
    source: LanCandidateSource,
    wan: WanAvailability,
) -> LanVerdict {
    // 行：没有任何 LAN 候选（没有内网路径）——明确
    if candidates.is_empty() {
        return match source {
            LanCandidateSource::Explicit => switch_or_block(wan, ModeReason::NoLanCandidate),
            // mDNS 尚无候选 ≠ 不在内网：先等一个发现窗口
            LanCandidateSource::Mdns => LanVerdict::WaitDiscovery,
        };
    }

    // 事实未知：判据不明确 → 先试 LAN（绝不凭「不知道」切外网）
    if !facts.known {
        return LanVerdict::TryLan;
    }

    // 行：移动端网络类型为蜂窝（无 Wi-Fi / Ethernet）——明确
    if facts.cellular {
        return switch_or_block(wan, ModeReason::Cellular);
    }

    // 有候选落在本机子网内 → 内网路径存在，先拨 LAN
    if facts.any_in_local_subnet(candidates) {
        return LanVerdict::TryLan;
    }

    // 行：候选都不在本机子网内，且 mDNS 无对端记录——明确
    if !facts.mdns_known {
        return switch_or_block(wan, ModeReason::DifferentSubnet);
    }

    // mDNS 有记录却不属于本机子网（地址陈旧 / 跨子网）：先试 LAN，不轻易切
    LanVerdict::TryLan
}

fn switch_or_block(wan: WanAvailability, reason: ModeReason) -> LanVerdict {
    match wan {
        WanAvailability::Ready => LanVerdict::SwitchWan(reason),
        WanAvailability::Blocked(blocked) => LanVerdict::Blocked(blocked),
    }
}

/// LAN 尝试失败后的结论（判据表后四行）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanFailureVerdict {
    /// 明确不在内网：允许进 wan
    SwitchWan(ModeReason),
    /// 判据不明确 / 安全错误：保持 lan，显性报错 + 手动「尝试外网」入口
    StayLanUnreachable,
}

pub fn judge_after_lan_failure(failure: LanFailure) -> LanFailureVerdict {
    match failure {
        // 行：全部候选 EHOSTUNREACH / ENETUNREACH——明确
        LanFailure::Unreachable => LanFailureVerdict::SwitchWan(ModeReason::HostUnreachable),
        // 行：同网段 timeout / ECONNREFUSED / 服务未启动——不明确
        LanFailure::Timeout | LanFailure::Refused | LanFailure::ServiceMissing => LanFailureVerdict::StayLanUnreachable,
        // 行：认证 / 未匹配 / Noise 失败——安全错误，绝不切 relay
        LanFailure::Auth => LanFailureVerdict::StayLanUnreachable,
        LanFailure::Other => LanFailureVerdict::StayLanUnreachable,
    }
}

// ==================== 每对端状态机 ====================

/// `wan-active` 回切 `lan-active` 需要的连续 LAN 探测成功次数（设计 §4.9 防抖）
pub const LAN_RESTORE_PROBES: u8 = 2;

#[derive(Debug, Clone)]
struct PeerState {
    mode: TransferMode,
    reason: Option<ModeReason>,
    lan_probe_wins: u8,
    /// 用户手动「尝试外网」：本次网络会话内保持，换网重置
    manual_wan: bool,
    updated_at_ms: u64,
}

impl Default for PeerState {
    fn default() -> Self {
        Self {
            mode: TransferMode::Offline,
            reason: None,
            lan_probe_wins: 0,
            manual_wan: false,
            updated_at_ms: 0,
        }
    }
}

/// 每对端模式表（模式是**每对端**的，不是全局开关）
#[derive(Debug, Default)]
pub struct ModeMachine {
    peers: HashMap<String, PeerState>,
}

impl ModeMachine {
    pub fn new() -> Self {
        Self::default()
    }

    /// 单个对端视图（未登记过 = `None`）
    pub fn view(&self, node_id: &str) -> Option<PeerModeView> {
        self.peers.get(node_id).map(|state| PeerModeView {
            node_id: node_id.to_string(),
            mode: state.mode,
            reason: state.reason,
            lan_probe_wins: state.lan_probe_wins,
            manual_wan: state.manual_wan,
            updated_at_ms: state.updated_at_ms,
        })
    }

    /// 全量视图（`status` 投影；按 node id 排序保证可复现）
    pub fn views(&self) -> Vec<PeerModeView> {
        let mut views: Vec<PeerModeView> = self.peers.keys().filter_map(|node| self.view(node)).collect();
        views.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        views
    }

    pub fn manual_wan(&self, node_id: &str) -> bool {
        self.peers.get(node_id).map(|s| s.manual_wan).unwrap_or(false)
    }

    /// 模式迁移原语：返回 `Some(view)` = 确实变了（调用方据此发 `peer:mode`）
    pub fn set(&mut self, node_id: &str, mode: TransferMode, reason: Option<ModeReason>) -> Option<PeerModeView> {
        let state = self.peers.entry(node_id.to_string()).or_default();
        if state.mode == mode && state.reason == reason {
            return None;
        }
        state.mode = mode;
        state.reason = reason;
        if mode != TransferMode::WanActive {
            state.lan_probe_wins = 0;
        }
        state.updated_at_ms = now_ms();
        self.view(node_id)
    }

    /// `connect` 开始：先试 LAN（手动「尝试外网」则直接进 wan-connecting）
    pub fn begin(&mut self, node_id: &str, wan: WanAvailability) -> (TransferMode, Option<PeerModeView>) {
        if self.manual_wan(node_id) && wan.is_ready() {
            let changed = self.set(node_id, TransferMode::WanConnecting, Some(ModeReason::User));
            return (TransferMode::WanConnecting, changed);
        }
        let changed = self.set(node_id, TransferMode::LanProbing, None);
        (TransferMode::LanProbing, changed)
    }

    /// LAN 打通
    pub fn mark_lan_active(&mut self, node_id: &str) -> Option<PeerModeView> {
        self.set(node_id, TransferMode::LanActive, None)
    }

    /// 判据不明确：保持 lan，显性「内网不可达」
    pub fn mark_lan_unreachable(&mut self, node_id: &str) -> Option<PeerModeView> {
        self.set(node_id, TransferMode::LanUnreachable, None)
    }

    /// 判据明确：进 wan
    pub fn mark_wan_connecting(&mut self, node_id: &str, reason: ModeReason) -> Option<PeerModeView> {
        self.set(node_id, TransferMode::WanConnecting, Some(reason))
    }

    pub fn mark_wan_active(&mut self, node_id: &str, reason: ModeReason) -> Option<PeerModeView> {
        self.set(node_id, TransferMode::WanActive, Some(reason))
    }

    pub fn mark_wan_unavailable(&mut self, node_id: &str, reason: ModeReason) -> Option<PeerModeView> {
        self.set(node_id, TransferMode::WanUnavailable, Some(reason))
    }

    pub fn mark_offline(&mut self, node_id: &str) -> Option<PeerModeView> {
        self.set(node_id, TransferMode::Offline, None)
    }

    /// 用户手动「尝试外网」开关（本次网络会话内保持）
    pub fn set_manual_wan(&mut self, node_id: &str, enabled: bool) -> Option<PeerModeView> {
        let state = self.peers.entry(node_id.to_string()).or_default();
        if state.manual_wan == enabled {
            return None;
        }
        state.manual_wan = enabled;
        state.updated_at_ms = now_ms();
        self.view(node_id)
    }

    /// 换网：清手动指令与探测计数，非 `offline` 对端回到 `lan-probing`（自动策略）
    pub fn on_network_changed(&mut self) -> Vec<PeerModeView> {
        let mut changed = Vec::new();
        for (node, state) in self.peers.iter_mut() {
            state.manual_wan = false;
            state.lan_probe_wins = 0;
            if state.mode != TransferMode::Offline {
                state.mode = TransferMode::LanProbing;
                state.reason = Some(ModeReason::NetworkChanged);
                state.updated_at_ms = now_ms();
                changed.push(PeerModeView {
                    node_id: node.clone(),
                    mode: state.mode,
                    reason: state.reason,
                    lan_probe_wins: state.lan_probe_wins,
                    manual_wan: state.manual_wan,
                    updated_at_ms: state.updated_at_ms,
                });
            }
        }
        changed.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        changed
    }

    /// `wan-active` 期间的一次 LAN 探测结果记账（**不改模式**）
    ///
    /// 返回 `true` = 连续成功已达回切阈值（[`LAN_RESTORE_PROBES`]）。调用方负责先做
    /// **真实 LAN 拨号**，成功后才改 `lan-active`——不让「探测通了但链路仍在 relay」
    /// 的中间态出现在 `status` / `peer:mode` 里。
    ///
    /// 非 `wan-active` 对端不记账（探测只在 wan-active 有意义）；失败一律清零。
    pub fn record_lan_probe(&mut self, node_id: &str, success: bool) -> bool {
        let state = self.peers.entry(node_id.to_string()).or_default();
        if state.mode != TransferMode::WanActive {
            return false;
        }
        state.updated_at_ms = now_ms();
        if !success {
            state.lan_probe_wins = 0;
            return false;
        }
        state.lan_probe_wins = state.lan_probe_wins.saturating_add(1);
        state.lan_probe_wins >= LAN_RESTORE_PROBES
    }

    /// 处于指定模式的对端 node id（探测循环枚举 `wan-active` 目标用；排序保证可复现）
    pub fn nodes_in(&self, mode: TransferMode) -> Vec<String> {
        let mut nodes: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, state)| state.mode == mode)
            .map(|(node, _)| node.clone())
            .collect();
        nodes.sort();
        nodes
    }

    /// `wan-active` 期间周期 / 换网探测 LAN 成功：连续两次才回切（防抖）
    ///
    /// 返回 `Some(view)` = 已回切 `lan-active`；未到次数返回 `None`。
    ///
    /// 生产路径不用本方法直接回切（探测循环要先真实拨号成功再改模式），
    /// 保留它是为了「调用方已自行完成链路切换」的场景与既有语义。
    pub fn on_lan_probe_success(&mut self, node_id: &str) -> Option<PeerModeView> {
        if !self.record_lan_probe(node_id, true) {
            return None;
        }
        self.set(node_id, TransferMode::LanActive, Some(ModeReason::LanRestored))
    }

    /// LAN 探测失败：计数归零（不因单次失败改变当前 wan 模式）
    pub fn on_lan_probe_failure(&mut self, node_id: &str) {
        self.record_lan_probe(node_id, false);
    }
}

/// 事件 / 视图时刻（Unix 毫秒；插件 wasm32 无时钟，时刻由宿主提供）
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_IP: &str = "192.168.1.20";

    fn facts(subnets: &[(&str, u8)], cellular: bool) -> NetworkFacts {
        NetworkFacts {
            known: true,
            cellular,
            local_subnets: subnets
                .iter()
                .map(|(ip, prefix)| Subnet::new(ip.parse().unwrap(), *prefix).unwrap())
                .collect(),
            mdns_known: false,
        }
    }

    fn explicit() -> LanCandidateSource {
        LanCandidateSource::Explicit
    }

    // ==================== 判据表（设计 §4.9）====================

    #[test]
    fn cellular_switches_to_wan_without_probing_lan() {
        let facts = facts(&[], true);
        let verdict = judge_before_lan(&facts, &[PEER_IP.parse().unwrap()], explicit(), WanAvailability::Ready);
        assert_eq!(verdict, LanVerdict::SwitchWan(ModeReason::Cellular));
    }

    #[test]
    fn cellular_without_wan_is_blocked_visibly() {
        let facts = facts(&[], true);
        let verdict = judge_before_lan(
            &facts,
            &[PEER_IP.parse().unwrap()],
            explicit(),
            WanAvailability::new(false, true),
        );
        assert_eq!(verdict, LanVerdict::Blocked(ModeReason::WanDisabled));
    }

    #[test]
    fn no_lan_candidate_is_explicit_not_in_lan() {
        let verdict = judge_before_lan(
            &facts(&[("192.168.1.5", 24)], false),
            &[],
            explicit(),
            WanAvailability::Ready,
        );
        assert_eq!(verdict, LanVerdict::SwitchWan(ModeReason::NoLanCandidate));
    }

    #[test]
    fn mdns_without_candidate_waits_for_discovery_window() {
        let verdict = judge_before_lan(
            &facts(&[("192.168.1.5", 24)], false),
            &[],
            LanCandidateSource::Mdns,
            WanAvailability::Ready,
        );
        assert_eq!(verdict, LanVerdict::WaitDiscovery);
    }

    #[test]
    fn candidate_outside_every_subnet_without_mdns_switches() {
        let verdict = judge_before_lan(
            &facts(&[("10.0.0.5", 24)], false),
            &[PEER_IP.parse().unwrap()],
            explicit(),
            WanAvailability::Ready,
        );
        assert_eq!(verdict, LanVerdict::SwitchWan(ModeReason::DifferentSubnet));
    }

    #[test]
    fn candidate_inside_subnet_tries_lan_first() {
        let verdict = judge_before_lan(
            &facts(&[("192.168.1.0", 24)], false),
            &[PEER_IP.parse().unwrap()],
            explicit(),
            WanAvailability::Ready,
        );
        assert_eq!(verdict, LanVerdict::TryLan);
    }

    #[test]
    fn mdns_record_keeps_lan_even_outside_subnet() {
        let mut facts = facts(&[("10.0.0.5", 24)], false);
        facts.mdns_known = true;
        let verdict = judge_before_lan(&facts, &[PEER_IP.parse().unwrap()], explicit(), WanAvailability::Ready);
        assert_eq!(verdict, LanVerdict::TryLan, "mDNS 有记录时不轻易切外网");
    }

    #[test]
    fn unknown_facts_never_trigger_auto_switch() {
        let verdict = judge_before_lan(
            &NetworkFacts::unknown(),
            &[PEER_IP.parse().unwrap()],
            explicit(),
            WanAvailability::Ready,
        );
        assert_eq!(verdict, LanVerdict::TryLan, "事实未知 = 判据不明确，先试 LAN");
    }

    #[test]
    fn timeout_and_refused_never_switch_but_unreachable_does() {
        assert_eq!(
            judge_after_lan_failure(LanFailure::Timeout),
            LanFailureVerdict::StayLanUnreachable
        );
        assert_eq!(
            judge_after_lan_failure(LanFailure::Refused),
            LanFailureVerdict::StayLanUnreachable
        );
        assert_eq!(
            judge_after_lan_failure(LanFailure::ServiceMissing),
            LanFailureVerdict::StayLanUnreachable
        );
        assert_eq!(
            judge_after_lan_failure(LanFailure::Unreachable),
            LanFailureVerdict::SwitchWan(ModeReason::HostUnreachable)
        );
    }

    #[test]
    fn auth_failure_never_switches_to_relay() {
        // 攻击者阻断 LAN 不能把流量逼进 relay；认证失败是安全错误
        assert_eq!(
            judge_after_lan_failure(LanFailure::Auth),
            LanFailureVerdict::StayLanUnreachable
        );
        assert_eq!(
            judge_after_lan_failure(LanFailure::Other),
            LanFailureVerdict::StayLanUnreachable
        );
    }

    /// R04：多候选失败必须按逐候选成因归并——混合 timeout/refused/unreachable
    /// 不得因为「其中一条是 EHOSTUNREACH」而切 WAN；任一 Auth 优先安全错误。
    #[test]
    fn multi_candidate_failure_is_classified_by_all_causes() {
        let all_unreachable = DialFailure::from_causes(
            vec![LanFailure::Unreachable, LanFailure::Unreachable],
            "two unreachable",
        );
        assert_eq!(all_unreachable.kind, LanFailure::Unreachable);
        assert!(all_unreachable.all_unreachable());
        assert!(matches!(
            judge_after_lan_failure(all_unreachable.kind),
            LanFailureVerdict::SwitchWan(ModeReason::HostUnreachable)
        ));

        let mixed = DialFailure::from_causes(
            vec![LanFailure::Unreachable, LanFailure::Timeout],
            "unreachable + timeout",
        );
        assert_eq!(mixed.kind, LanFailure::Other, "混合候选保守保持 LAN");
        assert_eq!(
            judge_after_lan_failure(mixed.kind),
            LanFailureVerdict::StayLanUnreachable
        );

        let auth = DialFailure::from_causes(vec![LanFailure::Unreachable, LanFailure::Auth], "unreachable + auth");
        assert_eq!(auth.kind, LanFailure::Auth, "任一认证失败优先安全错误");
        assert_eq!(
            judge_after_lan_failure(auth.kind),
            LanFailureVerdict::StayLanUnreachable
        );

        let single = DialFailure::new(LanFailure::Refused, "refused");
        assert_eq!(single.kind, LanFailure::Refused);
        assert!(!single.all_unreachable());
    }

    #[test]
    fn subnet_mask_membership_is_prefix_aware() {
        let subnet = Subnet::new("192.168.1.0".parse().unwrap(), 25).unwrap();
        assert!(subnet.contains("192.168.1.100".parse().unwrap()));
        assert!(!subnet.contains("192.168.1.200".parse().unwrap()));
        let v6 = Subnet::new("fd00::".parse().unwrap(), 64).unwrap();
        assert!(v6.contains("fd00::1".parse().unwrap()));
        assert!(!v6.contains("fd01::1".parse().unwrap()));
        assert!(!v6.contains("192.168.1.1".parse().unwrap()), "v4/v6 不互判");
        assert!(Subnet::new("0.0.0.0".parse().unwrap(), 0)
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
        assert!(Subnet::new("192.168.1.1".parse().unwrap(), 32)
            .unwrap()
            .contains("192.168.1.1".parse().unwrap()));
        assert!(
            Subnet::new("::".parse().unwrap(), 129).is_none(),
            "前缀越界不得进入判定"
        );
    }

    // ==================== 状态机 ====================

    #[test]
    fn eight_modes_have_stable_vocabulary() {
        let all = [
            (TransferMode::Pairing, "pairing"),
            (TransferMode::LanProbing, "lan-probing"),
            (TransferMode::LanActive, "lan-active"),
            (TransferMode::LanUnreachable, "lan-unreachable"),
            (TransferMode::WanConnecting, "wan-connecting"),
            (TransferMode::WanActive, "wan-active"),
            (TransferMode::WanUnavailable, "wan-unavailable"),
            (TransferMode::Offline, "offline"),
        ];
        for (mode, literal) in all {
            assert_eq!(mode.as_str(), literal);
        }
        assert_eq!(ModeReason::DifferentSubnet.as_str(), "different-subnet");
        assert_eq!(ModeReason::HostUnreachable.as_str(), "host-unreachable");
        assert_eq!(ModeReason::User.as_str(), "user");
        assert_eq!(ModeReason::Cellular.as_str(), "cellular");
    }

    #[test]
    fn lan_path_reaches_lan_active_and_reports_change_once() {
        let mut machine = ModeMachine::new();
        let (mode, changed) = machine.begin("n1", WanAvailability::Ready);
        assert_eq!(mode, TransferMode::LanProbing);
        assert!(changed.is_some(), "首次进入也要发事件（应用据此渲染状态栏）");
        assert!(machine.mark_lan_active("n1").is_some());
        assert!(machine.mark_lan_active("n1").is_none(), "同态重复不发事件");
        assert_eq!(machine.view("n1").unwrap().mode.as_str(), "lan-active");
    }

    #[test]
    fn unclear_lan_failure_lands_on_lan_unreachable_with_manual_entry() {
        let mut machine = ModeMachine::new();
        machine.begin("n1", WanAvailability::Ready);
        let view = machine.mark_lan_unreachable("n1").unwrap();
        assert_eq!(view.mode, TransferMode::LanUnreachable);
        assert!(view.mode.needs_manual_entry());
        assert!(view.reason.is_none(), "内网不可达不是「明确不在内网」，不带切换归因");
    }

    #[test]
    fn wan_active_restores_lan_only_after_two_consecutive_successes() {
        let mut machine = ModeMachine::new();
        machine.begin("n1", WanAvailability::Ready);
        machine.mark_wan_connecting("n1", ModeReason::Cellular);
        machine.mark_wan_active("n1", ModeReason::Cellular);

        assert!(machine.on_lan_probe_success("n1").is_none(), "第一次成功不回切");
        machine.on_lan_probe_failure("n1");
        assert!(machine.on_lan_probe_success("n1").is_none(), "失败后计数归零");
        let view = machine.on_lan_probe_success("n1").unwrap();
        assert_eq!(view.mode, TransferMode::LanActive);
        assert_eq!(view.reason, Some(ModeReason::LanRestored));
    }

    /// `record_lan_probe` 只记账不改模式（生产路径先真实拨号，成功才改模式）
    #[test]
    fn record_lan_probe_counts_without_switching_mode() {
        let mut machine = ModeMachine::new();
        machine.begin("n1", WanAvailability::Ready);
        machine.mark_wan_connecting("n1", ModeReason::Cellular);
        machine.mark_wan_active("n1", ModeReason::Cellular);

        assert!(!machine.record_lan_probe("n1", true));
        assert_eq!(
            machine.view("n1").unwrap().mode,
            TransferMode::WanActive,
            "未达阀值不切模式"
        );
        assert!(!machine.record_lan_probe("n1", false), "失败立即清零");
        assert_eq!(machine.view("n1").unwrap().lan_probe_wins, 0);
        assert!(!machine.record_lan_probe("n1", true));
        assert!(machine.record_lan_probe("n1", true), "连续两次才达阀值");
        assert_eq!(machine.view("n1").unwrap().mode, TransferMode::WanActive);
    }

    /// 非 `wan-active` 对端不记账（探测只在 wan-active 有意义）
    #[test]
    fn record_lan_probe_ignores_non_wan_active_peers() {
        let mut machine = ModeMachine::new();
        machine.mark_lan_active("n1");
        assert!(!machine.record_lan_probe("n1", true));
        assert_eq!(machine.view("n1").unwrap().lan_probe_wins, 0);
    }

    /// `nodes_in` 只枚举目标模式的对端（探测循环的候选来源）
    #[test]
    fn nodes_in_filters_by_mode() {
        let mut machine = ModeMachine::new();
        machine.mark_wan_connecting("n1", ModeReason::Cellular);
        machine.mark_wan_active("n1", ModeReason::Cellular);
        machine.mark_lan_active("n2");

        assert_eq!(machine.nodes_in(TransferMode::WanActive), vec!["n1".to_string()]);
        assert!(machine.nodes_in(TransferMode::Pairing).is_empty());
    }

    #[test]
    fn manual_wan_persists_in_session_and_resets_on_network_change() {
        let mut machine = ModeMachine::new();
        machine.set_manual_wan("n1", true);
        assert!(machine.manual_wan("n1"));
        let (mode, changed) = machine.begin("n1", WanAvailability::Ready);
        assert_eq!(mode, TransferMode::WanConnecting, "手动尝试外网直接进 wan");
        assert_eq!(changed.unwrap().reason, Some(ModeReason::User));

        let changed = machine.on_network_changed();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].mode, TransferMode::LanProbing);
        assert_eq!(changed[0].reason, Some(ModeReason::NetworkChanged));
        assert!(!machine.manual_wan("n1"), "换网回到自动策略");
    }

    #[test]
    fn manual_wan_is_ignored_when_wan_is_blocked() {
        let mut machine = ModeMachine::new();
        machine.set_manual_wan("n1", true);
        let (mode, _) = machine.begin("n1", WanAvailability::new(false, true));
        assert_eq!(mode, TransferMode::LanProbing, "外网关闭时手动入口也不得绕过");
    }

    #[test]
    fn modes_are_per_peer_not_global() {
        let mut machine = ModeMachine::new();
        machine.mark_lan_active("a");
        machine.mark_wan_connecting("b", ModeReason::Cellular);
        machine.mark_wan_active("b", ModeReason::Cellular);
        assert_eq!(machine.view("a").unwrap().mode, TransferMode::LanActive);
        assert_eq!(machine.view("b").unwrap().mode, TransferMode::WanActive);
        let views = machine.views();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].node_id, "a", "视图按 node id 排序，投影可复现");
        assert_eq!(views[1].node_id, "b");
    }

    #[test]
    fn offline_peers_are_not_resurrected_by_network_change() {
        let mut machine = ModeMachine::new();
        machine.mark_wan_active("gone", ModeReason::Cellular);
        machine.mark_offline("gone");
        assert!(machine.on_network_changed().is_empty());
        assert_eq!(machine.view("gone").unwrap().mode, TransferMode::Offline);
    }

    #[test]
    fn wan_unavailable_carries_blocking_reason() {
        let mut machine = ModeMachine::new();
        let view = machine
            .mark_wan_unavailable("n1", ModeReason::RelayUnavailable)
            .unwrap();
        assert_eq!(view.mode, TransferMode::WanUnavailable);
        assert_eq!(view.reason, Some(ModeReason::RelayUnavailable));
    }
}
