//! host-peer 能力域 —— 对等网络基础能力（ADR 0022 v2 终态 19 原语）
//!
//! spec：`.scratch/2026-10-04-wasm-core-lib-split/spec.md` §3.1；票 05（自宿主
//! host_api 域的 peer 适配器整体迁入本 crate，并解除其对宿主组装面的 20 处
//! 反向耦合）。
//!
//! **零业务代码红线**：本模块只做引擎原语——句柄铸造与属主仲裁、数据面自动
//! 重拨、权限门位置、载荷校验；传输任务 / 策略 / 历史 / 展示名等**产品业务真源
//! 全在 file-transfer 插件**（见 [`crate`] 模块文档「定位」段）。DTO 一律以 JSON
//! 字符串过界，本域不新增任何业务字段。
//!
//! ## 分层
//!
//! ```text
//!   本文件        机制 + WIT 接线（19 条原语的宿主实现 + 能力模块自报）
//!   ports.rs      边界：宿主能力端口（权限门 / 引擎上下文 / 异步桥）
//! ```
//!
//! 宿主侧只剩一个 adapter（宿主 host_api 域的 peer 适配器）与一次开机装配调用。
//!
//! ## 本票解除的反向耦合（票 05 的第二交付）
//!
//! 迁移前本域有 20 处「从宿主组装面取引擎状态」的调用（宿主 peer 命令壳里那个
//! 「由 AppHandle 装配引擎上下文」的函数）——它要求本 crate 反向认识宿主的
//! `AppHandle` 与宿主的 managed state 表，也正是本 crate 依赖方向锁禁的那两种
//! 形态（锁自身携带这两个前缀字面量，故此处刻意不写）。现在改经
//! [`ports::PeerPorts::peer_ctx`] 要「已装配好的 [`PeerCtx`]」：本文件对宿主
//! 组装面的引用为 **0**，且**不动对等网络引擎自身**。

use std::sync::{Arc, LazyLock};

use crate::plugin_binding::ports::{block_on, PeerPorts};
use crate::wire::PERMISSION_PEER;

/// 宿主能力端口（边界层；见 [`ports`] 模块文档）
pub mod ports;

// ==================== v2 句柄路由（ADR 0022）====================

/// session 句柄路由表条目：拨号时铸造 `sess-<uuid>` 并记忆 endpoint 三元组，
/// 数据面断线自动重拨的寻址依据。
#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub node_id: String,
    pub addr: String,
    pub port: u16,
    /// 拨号方插件 id（票 04）：句柄只有属主可继续操作
    ///
    /// 此前句柄表没有 owner 列——`sess-<uuid>` 虽是随机不可猜，但一旦泄露给另一插件
    /// （日志、事件、互调参数），持有者即可断开他人连接、以他人身份读写传输。
    /// 与 pty / ws / mdns 的 owner 列同形，判定统一在本域。
    pub owner: String,
}

/// 进程级单例（与引擎连接生命周期对齐：宿主重启即清空，插件重拨即可）。
/// 传输句柄不进表——send/pull 返回的 batch-id 本身即唯一句柄
/// （peer:transfer / peer:receive 事件也以它寻址），close 按「session 表 →
/// 发送取消 → 接收取消」顺序路由，命中即停。
#[derive(Default)]
pub struct PeerHandleTable {
    sessions: std::collections::HashMap<String, SessionEntry>,
}

impl PeerHandleTable {
    /// 铸造新 session 句柄并绑定 endpoint
    fn mint_session(&mut self, entry: SessionEntry) -> String {
        let handle = format!("sess-{}", uuid::Uuid::new_v4());
        self.sessions.insert(handle.clone(), entry);
        handle
    }

    /// 解析句柄 → endpoint 条目（不移除；数据面函数按句柄寻址时用）
    fn resolve_session(&self, handle: &str) -> Option<SessionEntry> {
        self.sessions.get(handle).cloned()
    }

    /// 取出句柄（close 时用）
    fn take_session(&mut self, handle: &str) -> Option<SessionEntry> {
        self.sessions.remove(handle)
    }

    /// 放回句柄（属主判定拒绝时回滚，非属主的探测不得改变注册表状态）
    fn restore_session(&mut self, handle: &str, entry: SessionEntry) {
        self.sessions.insert(handle.to_string(), entry);
    }
}

static PEER_HANDLES: LazyLock<std::sync::Mutex<PeerHandleTable>> =
    LazyLock::new(|| std::sync::Mutex::new(PeerHandleTable::default()));

fn with_handles<T>(f: impl FnOnce(&mut PeerHandleTable) -> T) -> T {
    let mut guard = PEER_HANDLES.lock().expect("peer handle table lock poisoned");
    f(&mut guard)
}

/// 属主判定（票 04）：非属主统一拒绝，文案与 pty / mdns 同形
const NOT_OWNER: &str = "not owner of peer handle";

fn ensure_handle_owner(entry: &SessionEntry, plugin_id: &str, handle: &str) -> Result<(), String> {
    if entry.owner == plugin_id {
        return Ok(());
    }
    tracing::warn!(plugin_id = %plugin_id, handle = %handle, "host-peer 属主校验拒绝");
    Err(format!("{NOT_OWNER}: {handle}"))
}

fn denied() -> String {
    "permission denied: peer".to_string()
}

/// 引擎函数返回 `wasmnest_server_base::Result<T>`（AppError）——WASM 边界统一转可读字符串
fn sync_result<T>(r: crate::Result<T>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}

/// 数据面自动重拨包装：仅接受 session 句柄；操作报错且命中引擎「发现缓存
/// 缺失」字样（连接已断/缓存被 TTL 清扫）时，以句柄记忆的 endpoint 重走
/// 引擎握手后重试一次。denied/unreachable 等其他错误原样上抛。
fn with_auto_redial<T>(
    ports: &Arc<dyn PeerPorts>,
    plugin_id: &str,
    handle: &str,
    op: impl Fn(&str) -> Result<T, String>,
) -> Result<T, String> {
    let entry =
        with_handles(|t| t.resolve_session(handle)).ok_or_else(|| format!("invalid session handle: {handle}"))?;
    ensure_handle_owner(&entry, plugin_id, handle)?;
    match op(&entry.node_id) {
        Ok(v) => Ok(v),
        Err(e) if e.contains("discovery cache") || e.contains("not in discovery cache") => {
            let ctx = ports.peer_ctx()?;
            let endpoint = crate::DialEndpoint {
                node_id: entry.node_id.clone(),
                addr: entry.addr.clone(),
                port: entry.port,
            };
            tracing::info!(
                node_id = %entry.node_id,
                "peer data-plane auto-redial (handle-remembered endpoint)"
            );
            sync_result(block_on(ports, crate::dial_peer_endpoint(ctx, endpoint)))?;
            op(&entry.node_id)
        }
        Err(e) => Err(e),
    }
}

pub fn peer_dial(ports: &Arc<dyn PeerPorts>, plugin_id: &str, endpoint_json: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_dial") {
        return Err(denied());
    }
    let endpoint: crate::DialEndpoint =
        serde_json::from_str(endpoint_json).map_err(|e| format!("dial endpoint: invalid json: {e}"))?;
    let ctx = ports.peer_ctx()?;
    // 注意：node_id 必须 clone 而非 take——take 会把 endpoint.node_id 置空，
    // dial_peer_endpoint 对空 node_id 报 "invalid node id ''" 静默失败
    // （2026-09-07 实机实证：桌面点连接无拨号、无任何日志）。移动端同函数因
    // take 后重新构造 endpoint 无此 bug，两端口径保持 clone 语义对齐。
    let node_id = endpoint.node_id.clone();
    let addr = endpoint.addr.clone();
    let port = endpoint.port;
    let dto = sync_result(block_on(ports, crate::dial_peer_endpoint(ctx, endpoint)))?;
    match dto.status.as_str() {
        "connected" => Ok(with_handles(|t| {
            t.mint_session(SessionEntry {
                node_id,
                addr,
                port,
                owner: plugin_id.to_string(),
            })
        })),
        other => Err(format!("dial endpoint failed: peer {other}")),
    }
}

pub fn peer_close(ports: &Arc<dyn PeerPorts>, plugin_id: &str, handle: &str) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_close") {
        return Err(denied());
    }
    // ① session 句柄 → 先判属主再谈断开：属主判定刻意排在取引擎上下文之前，
    //    越权探测在无头/引擎未就绪的环境下也得到同一个答案（不因先报 headless 而掩盖）
    if let Some(entry) = with_handles(|t| t.take_session(handle)) {
        if let Err(e) = ensure_handle_owner(&entry, plugin_id, handle) {
            // 拒绝即放回句柄：非属主的一次 close 试探不得把别人的连接摘走
            with_handles(|t| t.restore_session(handle, entry));
            return Err(e);
        }
        let ctx = ports.peer_ctx()?;
        return sync_result(block_on(ports, crate::disconnect_peer(ctx, entry.node_id)));
    }
    let ctx = ports.peer_ctx()?;
    // ② 发送传输句柄（batch-id）→ 取消发送批
    let cancelled = sync_result(block_on(
        ports,
        crate::cancel_transfer_for_plugin(ctx.clone(), handle.to_string()),
    ));
    if matches!(&cancelled, Ok(true)) {
        return cancelled;
    }
    // ③ 接收侧句柄（batch-id）→ 取消/拒绝接收批（pending 即拒）
    sync_result(block_on(
        ports,
        crate::cancel_receiving_for_plugin(ctx, handle.to_string()),
    ))
}

pub fn peer_respond_consent(
    ports: &Arc<dyn PeerPorts>,
    plugin_id: &str,
    request_id: &str,
    accepted: bool,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_respond_consent") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let request_id = request_id.to_string();
    sync_result(block_on(ports, crate::respond_peer_consent(ctx, request_id, accepted)))
}

pub fn peer_list_trusted(ports: &Arc<dyn PeerPorts>, plugin_id: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_list_trusted") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let dtos = sync_result(block_on(ports, crate::list_trusted_peers(ctx)))?;
    serde_json::to_string(&dtos).map_err(|e| format!("serialize trusted peers failed: {e}"))
}

pub fn peer_revoke_trusted(ports: &Arc<dyn PeerPorts>, plugin_id: &str, node_id: &str) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_revoke_trusted") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let node_id = node_id.to_string();
    sync_result(block_on(ports, crate::revoke_trusted_peer(ctx, node_id)))
}

pub fn peer_send_files(
    ports: &Arc<dyn PeerPorts>,
    plugin_id: &str,
    session: &str,
    paths_json: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_send_files") {
        return Err(denied());
    }
    // 载荷双形态（issue 13 Phase 3 步骤 5）：纯 string 兼容保留；对象元素
    // `{ path, encrypt? }` 携带逐文件加密意图，任一 true → 批量强制加密
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum SendPathEntry {
        Plain(String),
        Detailed { path: String, encrypt: Option<bool> },
    }
    // v31 fail-visible（传输编排下沉票 3）：旧产物载荷携带的 `concurrency`
    // 并发脉冲字段已随宿主并发闸门退役——serde 未知字段默认忽略，必须
    // 显式检测并显性报错（点名 v31 重建），否则旧产物静默超并发
    let raw: serde_json::Value =
        serde_json::from_str(paths_json).map_err(|e| format!("send files: invalid paths json: {e}"))?;
    if raw.as_array().is_some_and(|arr| {
        arr.iter()
            .any(|e| e.as_object().is_some_and(|o| o.contains_key("concurrency")))
    }) {
        // 文案不点名版本号（两端 ABI 序列编号不同——两端同集单点实现下不误导任一端）
        return Err(
            "send files: payload field 'concurrency' retired (host-side concurrency gate removed; \
             concurrency is caller-controlled): rebuild plugin artifact with current SDK"
                .to_string(),
        );
    }
    let entries: Vec<SendPathEntry> =
        serde_json::from_value(raw).map_err(|e| format!("send files: invalid paths json: {e}"))?;
    let mut paths = Vec::with_capacity(entries.len());
    let mut force_encrypt = false;
    for entry in entries {
        match entry {
            SendPathEntry::Plain(path) => paths.push(path),
            SendPathEntry::Detailed { path, encrypt } => {
                if encrypt == Some(true) {
                    force_encrypt = true;
                }
                paths.push(path);
            }
        }
    }
    // 返回值已收窄为传输句柄（batch-id）；v31 起一次调用 = 一个会话立即发起
    // （宿主并发闸门删除）。断线场景由 with_auto_redial 以记忆 endpoint 重拨
    let batch_id = with_auto_redial(ports, plugin_id, session, |node_id| {
        let ctx = ports.peer_ctx()?;
        sync_result(block_on(
            ports,
            crate::send_files_for_plugin(
                ctx,
                node_id.to_string(),
                paths.clone(),
                if force_encrypt { Some(true) } else { None },
            ),
        ))
    })?;
    Ok(batch_id)
}

pub fn peer_respond_transfer(
    ports: &Arc<dyn PeerPorts>,
    plugin_id: &str,
    batch_id: &str,
    accept: bool,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_respond_transfer") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let batch_id = batch_id.to_string();
    let _hit = sync_result(block_on(
        ports,
        crate::respond_transfer_for_plugin(ctx, batch_id, accept),
    ))?;
    Ok(())
}

pub fn peer_set_receive_policy(
    ports: &Arc<dyn PeerPorts>,
    plugin_id: &str,
    mode: &str,
    timeout_secs: u64,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_set_receive_policy") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let mode = mode.to_string();
    sync_result(block_on(
        ports,
        crate::set_receive_policy_for_plugin(ctx, mode, timeout_secs),
    ))
}

/// 显式暂停进行中的发送批：会话数据面门控（wire Pause 帧 + 供方停推流），
/// 任务保留（含已传字节）不落历史。本端发起的活跃会话查句柄表、serve 供流
/// 批查 handler 注册表。**发送批未命中回落接收方向**（拉取会话 / push 接收批
/// 的 Pause 帧下发）——两端同集 19 原语下「单一原语管双向」的统一语义
/// （移动端历史组合语义由 crate 单点承载）；两向都未命中返回错误。
pub fn peer_pause_transfer(ports: &Arc<dyn PeerPorts>, plugin_id: &str, batch_id: &str) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_pause_transfer") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let batch_id = batch_id.to_string();
    if sync_result(block_on(
        ports,
        crate::pause_transfer_for_plugin(ctx.clone(), batch_id.clone()),
    ))? {
        return Ok(());
    }
    let hit = sync_result(block_on(
        ports,
        crate::peer_engine_receive::pause_peer_receiving(ctx, batch_id),
    ))?;
    if !hit {
        return Err("pause transfer: no running transfer with that id".to_string());
    }
    Ok(())
}

/// 恢复暂停的传输批：活跃发送会话写 Resume 帧续流；会话已中断的以句柄表记忆
/// 的源清单重新拨号续传（v31：批量恢复编排归插件，resume-all-transfers
/// 已退役）。**发送批未命中回落接收方向**（同 pause 的统一语义）；两向都
/// 未命中返回错误（WIT 契约「无命中返回错误」）——文案不点方向：批 id 归属
/// 哪张会话表由传输方向决定，此时四个方向都已排除。
pub fn peer_resume_transfer(ports: &Arc<dyn PeerPorts>, plugin_id: &str, batch_id: &str) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_resume_transfer") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let batch_id = batch_id.to_string();
    if sync_result(block_on(
        ports,
        crate::resume_transfer_for_plugin(ctx.clone(), batch_id.clone()),
    ))? {
        return Ok(());
    }
    let hit = sync_result(block_on(
        ports,
        crate::peer_engine_receive::resume_peer_receiving(ctx, batch_id),
    ))?;
    if !hit {
        return Err("resume transfer: no paused transfer with that id".to_string());
    }
    Ok(())
}

pub fn peer_set_shared_roots(ports: &Arc<dyn PeerPorts>, plugin_id: &str, dirs_json: &str) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_set_shared_roots") {
        return Err(denied());
    }
    // 双形态条目（WIT 注释承诺的形状）：桌面 `{ id, name, path }`（本地文件系统
    // 路径 → Fs 根）；移动 `{ id, name, safTreeUri }`（SAF 树 URI → Saf 根）。
    // 两端同集 19 原语下由本域单点解析；两条目形态互斥，`path` 缺席时才认
    // `safTreeUri`（首见非空者胜）。
    #[derive(serde::Deserialize)]
    struct SharedRootSeed {
        id: String,
        name: String,
        #[serde(default)]
        path: Option<String>,
        #[serde(default, rename = "safTreeUri")]
        saf_tree_uri: Option<String>,
    }
    let seeds: Vec<SharedRootSeed> =
        serde_json::from_str(dirs_json).map_err(|e| format!("set shared roots: invalid dirs json: {e}"))?;
    let mut entries = Vec::with_capacity(seeds.len());
    for s in seeds {
        // 任一条目非法整批拒绝（WIT 契约）——缺两字段都缺时显性点名，不作静默跳过
        let root = match (s.path, s.saf_tree_uri) {
            (Some(path), _) => crate::base::SharedDirRoot::Fs {
                path: std::path::PathBuf::from(path),
            },
            (None, Some(tree_uri)) => crate::base::SharedDirRoot::Saf { tree_uri },
            (None, None) => {
                return Err(format!(
                    "set shared roots: entry '{}' missing 'path' or 'safTreeUri'",
                    s.id
                ))
            }
        };
        entries.push(crate::base::SharedDirEntry {
            id: s.id,
            name: s.name,
            root,
        });
    }
    let ctx = ports.peer_ctx()?;
    sync_result(block_on(ports, crate::set_shared_roots(ctx, entries)))
}

pub fn peer_list_shared_roots(ports: &Arc<dyn PeerPorts>, plugin_id: &str, session: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_list_shared_roots") {
        return Err(denied());
    }
    let roots = with_auto_redial(ports, plugin_id, session, |node_id| {
        let ctx = ports.peer_ctx()?;
        sync_result(block_on(
            ports,
            crate::list_remote_roots_for_plugin(ctx, node_id.to_string()),
        ))
    })?;
    serde_json::to_string(&roots).map_err(|e| format!("serialize shared roots failed: {e}"))
}

pub fn peer_browse_directory(
    ports: &Arc<dyn PeerPorts>,
    plugin_id: &str,
    session: &str,
    dir_id: &str,
    rel_path: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_browse_directory") {
        return Err(denied());
    }
    let (dir_id, rel_path) = (dir_id.to_string(), rel_path.to_string());
    let dto = with_auto_redial(ports, plugin_id, session, |node_id| {
        let ctx = ports.peer_ctx()?;
        sync_result(block_on(
            ports,
            crate::browse_remote_for_plugin(ctx, node_id.to_string(), dir_id.clone(), rel_path.clone()),
        ))
    })?;
    serde_json::to_string(&dto).map_err(|e| format!("serialize browse listing failed: {e}"))
}

pub fn peer_pull_files(
    ports: &Arc<dyn PeerPorts>,
    plugin_id: &str,
    session: &str,
    dir_id: &str,
    files_json: &str,
) -> Result<u32, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_pull_files") {
        return Err(denied());
    }
    // RemotePullFileDto 未实现 Clone：闭包内按 JSON 串重复解析（重拨场景才二次执行）
    let dir_id = dir_id.to_string();
    let files_json_owned = files_json.to_string();
    // 引擎入参已是 `u32`（v31 收窄后无窄化转换），原语直接返回它
    with_auto_redial(ports, plugin_id, session, |node_id| {
        let files: Vec<crate::RemotePullFileDto> =
            serde_json::from_str(&files_json_owned).map_err(|e| format!("pull files: invalid files json: {e}"))?;
        let ctx = ports.peer_ctx()?;
        sync_result(block_on(
            ports,
            crate::pull_files_for_plugin(ctx, node_id.to_string(), dir_id.clone(), files),
        ))
    })
}

pub fn peer_set_download_dir(ports: &Arc<dyn PeerPorts>, plugin_id: &str, path: &str) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_set_download_dir") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    let path = if path.is_empty() { None } else { Some(path.to_string()) };
    sync_result(block_on(ports, crate::set_download_dir_for_plugin(ctx, path)))
}

/// 无租约装配时的兼容路径警告（每进程一次，不刷屏）
fn warn_no_lease_assembly(api: &str) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            api = %api,
            "peer service lease registry not assembled (headless/test); \
             falling back to direct node lifecycle without holder accounting"
        );
    });
}

/// 按需获取本机 peer 节点引用（`host-peer.start-node`）：幂等。
///
/// 生产装配走应用作用域服务注册表（`net.peer-node`）：首个引用拉起节点，
/// 多应用共享；返回 `true` = 本次调用真正拉起了节点。
/// 无租约装配（无头 / 测试）退化为直接调引擎并落一次 `warn`。
///
/// 非持有者停止时以错误上抛，文案不回带对方 id（与 `ensure_handle_owner` 同口径）。
pub fn peer_start_node(ports: &Arc<dyn PeerPorts>, plugin_id: &str) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_start_node") {
        return Err(denied());
    }
    if let Some(registry) = ports.service_registry() {
        let holder = plugin_id.to_string();
        let outcome = block_on(ports, async move {
            registry.acquire(crate::service::PEER_NODE_SERVICE_KEY, &holder).await
        })
        .map_err(|e| e.to_string())?;
        return Ok(matches!(
            outcome,
            wasmnest_server_base::service::AcquireOutcome::Started
        ));
    }
    warn_no_lease_assembly("host_peer_start_node");
    let ctx = ports.peer_ctx()?;
    sync_result(block_on(ports, crate::start_peer_node(ctx))).map(|_| true)
}

/// 释放本机节点引用（`host-peer.stop-node`）：最后一个引用释放才真正关停
/// （停广播 / 关监听 / 排水连接与入站记账）。
///
/// 未持有该引用时以「not owner of peer node」拒绝（保持旧「非属主拒绝」语义，
/// 不猜测「谁该停」，也不提供强制关停的后门）。
pub fn peer_stop_node(ports: &Arc<dyn PeerPorts>, plugin_id: &str) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_stop_node") {
        return Err(denied());
    }
    if let Some(registry) = ports.service_registry() {
        let holder = plugin_id.to_string();
        let outcome = block_on(ports, async move {
            registry.release(crate::service::PEER_NODE_SERVICE_KEY, &holder).await
        })
        .map_err(|e| e.to_string())?;
        return match outcome {
            wasmnest_server_base::service::ReleaseOutcome::NotHeld => Err("not owner of peer node".to_string()),
            wasmnest_server_base::service::ReleaseOutcome::Released
            | wasmnest_server_base::service::ReleaseOutcome::Stopped => Ok(true),
        };
    }
    warn_no_lease_assembly("host_peer_stop_node");
    let ctx = ports.peer_ctx()?;
    sync_result(block_on(ports, crate::stop_peer_node(ctx))).map(|_| true)
}

/// 活跃传输批清单（传输编排下沉票 1）：宿主会话表投影（仅引擎会话事实），
/// 供插件事件归约状态机首屏重建。依赖节点运行时状态表——无头上下文报错
/// （与既有 peer 原语同口径，不静默降级为空列表假象）
pub fn peer_active_transfers(ports: &Arc<dyn PeerPorts>, plugin_id: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_active_transfers") {
        return Err(denied());
    }
    let ctx = ports.peer_ctx()?;
    sync_result(block_on(ports, crate::active_transfers_for_plugin(ctx)))
}

/// 发送源收集（传输编排下沉票 1）：目录递归 + 批内同名去重（仅元数据）。
/// 纯文件系统枚举，不依赖节点运行时——无头上下文亦可用（`peer_ctx` 口径
/// 差异见 WIT 注释：不存在「看似成功实则空」的假成功风险面）
pub fn peer_collect_outgoing(ports: &Arc<dyn PeerPorts>, plugin_id: &str, paths_json: &str) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PEER, "host_peer_collect_outgoing") {
        return Err(denied());
    }
    let paths: Vec<String> =
        serde_json::from_str(paths_json).map_err(|e| format!("collect outgoing: invalid paths json: {e}"))?;
    sync_result(block_on(ports, crate::collect_outgoing_for_plugin(paths)))
}

// ==================== 能力模块自报（WIT 绑定层，`common-host` feature） ====================

// WIT 绑定层依赖（host-kit / wasmtime）只随 `common-host` feature 编译：
// 能力域默认形态 = 纯引擎机制（零 WIT 依赖），任何宿主可直接引用。
#[cfg(feature = "common-host")]
use wasmnest_host_kit::{HostModule, HostModuleDesc, ModuleEntry, WasmPluginState};
#[cfg(feature = "common-host")]
use wasmtime::component::{bindgen, Linker};

/// 能力模块名（宿主白名单键 = 装载期日志与错误文案里的模块名）
///
/// **常编译 pub**（票 02 批次 03）：内核不再点名本域（`host_api/peer.rs` 迁宿主
/// `src-tauri/src/plugin/peer.rs`），白名单条目（`expect_host_module!`）与装载期
/// 一致性核对改在宿主侧引用本常量。
pub const MODULE_NAME: &str = "peer-net";

/// 本域提供的 WIT 接口（必须与 `wasmnest.wit` 逐字一致；改错即 guest import 失配）
pub const MODULE_INTERFACES: &[&str] = &["wasmnest:plugin@0.0.2/host-peer"];

/// 本域的权限位（必须与 `wasmnest.wit` / SDK 权限表逐字一致）
pub const MODULE_PERMISSIONS: &[&str] = &["peer"];

/// 能力模块描述符（机制面：接口路径 / 权限位 / ABI 下界；**禁带产品名词**，spec D4）
///
/// 三个字符串字段取自上面三常量：描述符是机制面唯一真源，宿主白名单与一致性核对
/// 引用同一组常量 ⇒ 两处不可能漂移。
#[cfg(feature = "common-host")]
const DESC: HostModuleDesc = HostModuleDesc {
    name: MODULE_NAME,
    interfaces: MODULE_INTERFACES,
    permissions: MODULE_PERMISSIONS,
    abi_min: 31,
};

/// 对等网络能力域模块（`host-peer`，19 条原语）
#[cfg(feature = "common-host")]
pub struct PeerNetModule;

#[cfg(feature = "common-host")]
impl HostModule for PeerNetModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        wasmnest::plugin::host_peer::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
    }
}

/// getter：让 guest 侧 import 取到可变的状态引用（与宿主既有接线同款）
#[cfg(feature = "common-host")]
type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

/// 静态单例（供 `inventory::submit!` 取址）
#[cfg(feature = "common-host")]
static MODULE: PeerNetModule = PeerNetModule;

// 能力模块自报（linker-section 静态）
//
// **依赖前提**：宿主必须有一行强制引用本 crate（见宿主的组件运行时接线处），
// 否则本 rlib 不进最终二进制、静态不执行 ⇒ 注册丢失，且 guest 会在实例化期报
// 「无该 import」。无 `common-host` feature 的宿主（移动端 / 无头）**不应**
// 注册——它没有插件宿主机制，桌面侧强制引用行同步 `#[cfg(feature = "common-host")]`。
#[cfg(feature = "common-host")]
inventory::submit! {
    ModuleEntry { module: &MODULE }
}

/// 能力域名（宿主上下文里的键；[`wasmnest_host_kit::ports::HostPorts::domain_ports`]）
pub const DOMAIN: &str = "peer";

/// 装配端口的便捷入口（宿主开机期调用）
pub fn install<P: PeerPorts + 'static>(ports: P) {
    ports::install_ports(Arc::new(ports));
}

/// [`ports::install_ports`] 的再导出（宿主 adapter 需要直接装**已构造好的**端口对象：
/// 同一份要同时登记进程级与实例级，不能经 `install` 新建）
pub use ports::install_ports;

/// 取本插件实例该用的端口：**实例级优先**，未装配则回落到进程级装配
///
/// 为什么要两级（见 `wasmnest_host_kit::ports` 模块文档）：进程级只有一格，而一个
/// 进程可以有多份宿主上下文（无头测试每个用例一份）；实例级让端口与**本实例的**
/// 权限管理器绑定，能力域代码不感知上下文数量。
///
/// 宿主注入的是 `Arc<dyn Any>` 包着的 `Arc<dyn PeerPorts>`（能力域的端口类型只有
/// 能力域自己认识，kit 与宿主都不能把它裸存进表），故这里向下转型后**克隆内层
/// Arc**（同形对象，多个实例共享一份 adapter，无副作用）。
///
/// 依赖 `WasmPluginState`（host-kit 类型），随 `common-host` feature 编译。
#[cfg(feature = "common-host")]
fn ports_for(state: &WasmPluginState) -> Arc<dyn PeerPorts> {
    match state
        .host
        .domain_ports(DOMAIN)
        .and_then(wasmnest_host_kit::ports::downcast_domain_ports::<Arc<dyn PeerPorts>>)
    {
        Some(ports) => Arc::clone(&ports),
        None => ports::ports(),
    }
}

#[cfg(feature = "common-host")]
bindgen!({
    // provider 侧绑定：宿主自己的 `wasmnest` 模块是 **guest 视角**（import 是调用
    // 函数，不是 `Host` trait + `add_to_linker`），能力 crate 要自己装配就必须生成
    // provider 侧。
    //
    // ⚠️ 由此产生的**硬约束**：本 crate 与宿主各自生成的
    // `wasmnest::plugin::host_peer::Host` 是**同名但不同类型**的 trait。宿主必须
    // 同时删掉自己的 peer `Host` impl 与 `add_to_linker` 行，否则同一个 interface
    // 被注册两次 → 装配期 `defined twice`。
    // 票 05 / ADR 0052 D2：契约面脱端——本文件是 `host-peer` 的**共享契约真源**
    // （`world cap-peer`，双端 compose 直接消费），不再读桌面 SDK 生成物目录，
    // 也不再是「core.wit 的副本」。
    path: "wit/peer.wit",
    world: "cap-peer",
    // 与宿主同款：全部导出绑定生成 async 变体（wasmtime async store 要求）。
    // cap-peer 无 export 成员，此配置无生效对象（实测编译绿，票 05 实施记录）
    exports: { default: async },
});

// ==================== 宿主绑定层（Host trait 实现，`common-host` feature） ====================
//
// 每个接口方法 = 一条 WIT 原语。权限门在本文件内的域函数里（随实现同迁，
// 经端口问宿主结果），此层只做「取端口 → 转调 → 按 WIT `result` 形状返回」。

#[cfg(feature = "common-host")]
impl wasmnest::plugin::host_peer::Host for WasmPluginState {
    fn dial_peer(&mut self, endpoint_json: String) -> Result<String, String> {
        peer_dial(&ports_for(self), &self.plugin_id, &endpoint_json)
    }

    fn close(&mut self, handle: String) -> Result<bool, String> {
        peer_close(&ports_for(self), &self.plugin_id, &handle)
    }

    fn respond_consent(&mut self, request_id: String, accepted: bool) -> Result<bool, String> {
        peer_respond_consent(&ports_for(self), &self.plugin_id, &request_id, accepted)
    }

    fn list_trusted(&mut self) -> Result<String, String> {
        peer_list_trusted(&ports_for(self), &self.plugin_id)
    }

    fn revoke_trusted(&mut self, node_id: String) -> Result<bool, String> {
        peer_revoke_trusted(&ports_for(self), &self.plugin_id, &node_id)
    }

    fn send_files(&mut self, session: String, paths_json: String) -> Result<String, String> {
        peer_send_files(&ports_for(self), &self.plugin_id, &session, &paths_json)
    }

    fn respond_transfer(&mut self, batch_id: String, accept: bool) -> Result<(), String> {
        peer_respond_transfer(&ports_for(self), &self.plugin_id, &batch_id, accept)
    }

    fn set_receive_policy(&mut self, mode: String, timeout_secs: u64) -> Result<(), String> {
        peer_set_receive_policy(&ports_for(self), &self.plugin_id, &mode, timeout_secs)
    }

    fn pause_transfer(&mut self, batch_id: String) -> Result<(), String> {
        peer_pause_transfer(&ports_for(self), &self.plugin_id, &batch_id)
    }

    fn resume_transfer(&mut self, batch_id: String) -> Result<(), String> {
        peer_resume_transfer(&ports_for(self), &self.plugin_id, &batch_id)
    }

    fn set_shared_roots(&mut self, dirs_json: String) -> Result<(), String> {
        peer_set_shared_roots(&ports_for(self), &self.plugin_id, &dirs_json)
    }

    fn list_shared_roots(&mut self, session: String) -> Result<String, String> {
        peer_list_shared_roots(&ports_for(self), &self.plugin_id, &session)
    }

    fn browse_directory(&mut self, session: String, dir_id: String, rel_path: String) -> Result<String, String> {
        peer_browse_directory(&ports_for(self), &self.plugin_id, &session, &dir_id, &rel_path)
    }

    fn pull_files(&mut self, session: String, dir_id: String, files_json: String) -> Result<u32, String> {
        peer_pull_files(&ports_for(self), &self.plugin_id, &session, &dir_id, &files_json)
    }

    fn set_download_dir(&mut self, path: String) -> Result<(), String> {
        peer_set_download_dir(&ports_for(self), &self.plugin_id, &path)
    }

    fn start_node(&mut self) -> Result<bool, String> {
        peer_start_node(&ports_for(self), &self.plugin_id)
    }

    fn stop_node(&mut self) -> Result<bool, String> {
        peer_stop_node(&ports_for(self), &self.plugin_id)
    }

    fn active_transfers(&mut self) -> Result<String, String> {
        peer_active_transfers(&ports_for(self), &self.plugin_id)
    }

    fn collect_outgoing(&mut self, paths_json: String) -> Result<String, String> {
        peer_collect_outgoing(&ports_for(self), &self.plugin_id, &paths_json)
    }
}

#[cfg(test)]
mod tests;
