//! host-pty 句柄注册表与回收面（机制内核）
//!
//! ## 本模块持有什么
//!
//! ① **在册表**（`PTYS`：句柄 → 属主 + 引擎会话 + 输出环）：插件私有 PTY 的唯一
//! 真源。属主隔离（`with_entry`）与配额判据（`registered_count_for`）都在这里。
//!
//! ② **配额表**（`QUOTAS`：属主 → 生效条数）：真源是 manifest 的 `ptyQuota` 声明，
//! 登记点在插件加载漏斗（域侧 `plugin_binding::on_manifest_load`，宿主的
//! `manager::loader` 只下发 manifest 原文）；区间合法性由**同一处**仲裁（越界即拒绝
//! 装载，票 02 批次 03 从内核 `validate_pty_quota` 迁来），故本模块只取不判。
//! 表内无记录 = 未声明（既有插件、无头测试上下文）→ 取默认档
//! [`PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN`]（真源 `wasmnest-server-base::constants`），
//! 与引入声明字段之前的行为逐字一致。
//!
//! ③ **回收面**（停用回收 / 引擎层全量回收 / 在册计数）：宿主生命周期动作，**不经
//! 权限门、不取参数**——停用时插件已不可调用任何原语。
//!
//! ## 零业务代码红线（ADR 0022 / spec D1）
//!
//! 句柄表是**属主隔离的通用寻址表**，不含任何产品概念：键是本域铸造的
//! `pty-<uuid>` 句柄，值是引擎会话与环。「用户可同时开多少个终端」是插件自己的
//! 产品档位（经 manifest 声明进来），本模块不替插件决定业务上该怎样。

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use crate::wire::owned_topic;
use wasmnest_server_base::constants::PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN;

use crate::plugin_binding::ports::{self, PtyPorts};
use crate::{PtyRing, PtySession, PtySessionStatus, PtyTerminated};

// ==================== 常量与文案 ====================

/// 非属主操作的统一拒绝文案（属主仲裁，同 mdns / ws 先例）
pub(crate) const NOT_OWNER: &str = "not owner of pty handle";

/// 句柄前缀（`pty-<uuid>`）
pub(crate) const HANDLE_PREFIX: &str = "pty-";

/// 生命周期事件名（topic = `<owner>::pty:exit`，事件名段与 SDK `PTY_EXIT` 常量逐字一致）
pub(crate) const EVENT_EXIT: &str = "pty:exit";

/// 退出事件发布后的**只读窗口**：句柄在册、环仍可 fetch（属主退出处理器取尾段），
/// 窗口到期由延迟任务最终摘除。
///
/// 为什么需要：退出事件经宿主事件泵**异步**投递，发布返回 ≠ 处理器已跑完——
/// 先摘环会让退出处理器必然 `pty handle not found`，最后未被 drain 的字节（含
/// 50ms 限频窗口内的最后一批）永久丢失（#12A）。窗口只需覆盖投递 + 一次尾帧
/// fetch 链，取 3s；期间进程已死，写类操作在会话层自然失败（不新增门禁分支）。
pub(crate) const EXIT_READ_WINDOW: Duration = Duration::from_secs(3);

/// 句柄不在册的拒绝文案（kill 摘除后立即不可寻址；自然退出有只读窗口，
/// 见 [`EXIT_READ_WINDOW`]）
pub(crate) fn not_found(pty_id: &str) -> String {
    format!("pty handle not found: {pty_id}")
}

// ==================== 注册表 ====================

/// 在册插件 PTY：句柄属主 + 引擎会话 + 输出环
pub(crate) struct PtyEntry {
    pub(crate) owner: String,
    /// 进程存活性的持有者：`PtySession` 最后一次引用被 drop 即杀子进程
    pub(crate) session: PtySession,
    pub(crate) ring: Arc<Mutex<PtyRing>>,
    /// 退出事件已发布（**发布权认领位**）：置位后句柄进入只读窗口
    ///（[`EXIT_READ_WINDOW`]），环仍可 fetch 供退出处理器取尾段；回收路径
    /// 见位跳过重复发布（单一发布者不变量的判据，替代「谁 remove 成功」）。
    /// 配额计数（[`registered_count_for`]）不含已置位条目——窗口期不得吃配额
    pub(crate) exit_published: bool,
}

/// 全局插件 PTY 注册表（句柄 → 条目；跨插件按 owner 隔离）
pub(crate) static PTYS: LazyLock<Mutex<HashMap<String, PtyEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 每插件在册条数上限（属主 → 生效配额）
static QUOTAS: LazyLock<Mutex<HashMap<String, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 登记某插件的生效配额（加载期调用；`None` = 未声明，落默认档）
pub fn register_quota(plugin_id: &str, declared: Option<usize>) {
    let effective = declared.unwrap_or(PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN);
    QUOTAS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(plugin_id.to_string(), effective);
    tracing::debug!(plugin_id = %plugin_id, quota = effective, "host-pty: 配额已登记");
}

/// 某插件当前生效配额（`spawn` 的判据）
pub(crate) fn quota_of(plugin_id: &str) -> usize {
    QUOTAS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(plugin_id)
        .copied()
        .unwrap_or(PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN)
}

/// 某插件当前在册 PTY 条数（配额判据与副作用断言共用）
///
/// **不含已发布退出事件的窗口期条目**（`exit_published`）：自然退出后句柄在
/// 只读窗口内仍在册，但进程已死、不再占用会话档位——计入会让连开连关的
/// 会话提前顶到配额上限。
pub(crate) fn registered_count_for(plugin_id: &str) -> usize {
    PTYS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|entry| entry.owner == plugin_id && !entry.exit_published)
        .count()
}

/// 属主校验 + 在注册表锁内读取条目资源（锁内只做查表与克隆，不在锁内 await）
pub(crate) fn with_entry<T>(
    pty_id: &str,
    plugin_id: &str,
    f: impl FnOnce(&PtyEntry) -> T,
) -> Result<T, String> {
    let table = PTYS.lock().unwrap_or_else(|e| e.into_inner());
    match table.get(pty_id) {
        Some(entry) if entry.owner == plugin_id => Ok(f(entry)),
        Some(_) => Err(NOT_OWNER.to_string()),
        None => Err(not_found(pty_id)),
    }
}

/// 取会话句柄（`PtySession: Clone` 共享同一内部状态，取出后即可在锁外 await）
pub(crate) fn session_of(plugin_id: &str, pty_id: &str) -> Result<PtySession, String> {
    with_entry(pty_id, plugin_id, |entry| entry.session.clone())
}

// ==================== 退出事件发布 ====================

/// 退出原因映射（spec D4）：`killed` 以宿主侧 kill 请求位为准
///
/// portable-pty 的 `ExitStatus` 不带 signal（信号终止也报 `code=1`），无法从退出码
/// 区分「被杀」与 `exit 1`——判据只在 [`PtyTerminated::killed`] 上（票 01 定案）。
pub(crate) fn exit_reason_of(terminated: &PtyTerminated) -> &'static str {
    if terminated.killed {
        "killed"
    } else if terminated.status == PtySessionStatus::Error {
        "error"
    } else {
        "stopped"
    }
}

/// 组装 `<owner>::pty:exit` payload（camelCase，与 WIT/SDK 文档一致）
///
/// `exit_code` 为 `None`（回收失败/无句柄）时**省略字段**而非报 0——插件据字段有无
/// 判断「拿不到退出码」，与「退出码就是 0」区分开。
fn pty_exit_payload(pty_id: &str, reason: &str, exit_code: Option<i32>) -> serde_json::Value {
    let mut payload = serde_json::json!({ "ptyId": pty_id, "reason": reason });
    if let Some(code) = exit_code {
        payload["exitCode"] = serde_json::json!(code);
    }
    payload
}

/// 发布退出事件到属主私有 topic（与 mdns / ws 同路：`<owner>::pty:exit`，
/// 非属主订阅被总线命名空间门禁拒绝，他人也伪投递不进）
pub(crate) fn publish_pty_exit(
    ports: &Arc<dyn PtyPorts>,
    owner: &str,
    pty_id: &str,
    reason: &str,
    exit_code: Option<i32>,
) {
    ports.publish(
        &owned_topic(owner, EVENT_EXIT),
        pty_exit_payload(pty_id, reason, exit_code),
    );
}

// ==================== 回收面（宿主生命周期动作） ====================

/// 在册句柄快照（`owner = None` → 全部属主；注册表锁内只取 id，回收在锁外做）
fn registered_handles(owner: Option<&str>) -> Vec<String> {
    let table = PTYS.lock().unwrap_or_else(|e| e.into_inner());
    table
        .iter()
        .filter(|(_, entry)| owner.map_or(true, |o| entry.owner == o))
        .map(|(pty_id, _)| pty_id.clone())
        .collect()
}

/// 回收一批在册句柄：摘除 → kill → 按属主补发 `pty:exit`（reason=killed）
///
/// **只有从注册表成功摘除的那一方发布事件**（票 04 单一发布者不变量的半段）：与退出
/// 监听竞争时，监听任务若先摘除则本函数跳过该句柄（事件已由其发布），不多发也不漏发。
/// 事件按 `entry.owner` 投递，故本函数不必知道调用来源（按属主回收 / 全量回收同路）。
fn reclaim_handles(ports: &Arc<dyn PtyPorts>, handles: Vec<String>) -> usize {
    let mut reclaimed = 0;
    for pty_id in handles {
        let entry = PTYS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&pty_id);
        let Some(entry) = entry else {
            continue; // 监听任务抢先摘除：事件已由其发布
        };
        let owner = entry.owner.clone();
        // kill 需 await 引擎面：经端口的同步↔异步桥驱动（真实驱动实现在宿主，
        // 本域不得复制第二份，见 `ports::block_on_any`）。借用 `entry.session` 即可
        // （`PtySession` 内部共享状态，克隆与借用同义）
        if let Err(e) = ports::block_on(ports, entry.session.kill()) {
            // 进程此时多已自行结束，kill 失败属可恢复；仍摘除并补发事件（不泄漏句柄）
            tracing::warn!(plugin_id = %owner, pty_id = %pty_id, error = %e, "PTY 回收 kill 降级");
        }
        // 会话的最后一次引用在**发布事件之前**释放（进程此时确已退出并被回收）：
        // 顺序与迁移前逐字一致——事件一旦发出，属主插件可能立刻起新 PTY，旧句柄的
        // 会话句柄不该还挂在收尾路径上
        drop(entry.session);
        drop(entry.ring);
        // 退出监听已发布过（自然退出的只读窗口期内被回收）：不重复发
        //（单一发布者判据 = `exit_published` 认领位，与退出监听的「谁先置位」一致）
        if !entry.exit_published {
            publish_pty_exit(ports, &owner, &pty_id, "killed", None);
        }
        reclaimed += 1;
    }
    reclaimed
}

/// 插件停用回收：kill 并摘除其全部 PTY，逐条补发 `<owner>::pty:exit`（reason=killed）
///
/// **只碰本人**（同 mdns / ws 的按属主回收）：其他插件在册句柄不受影响。事件由本函数
/// 发布（先摘除后 kill，停用窗口内不再接受任何针对该句柄的调用）；对应的退出监听任务
/// 稍后醒来看不到句柄即静默结束（单一发布者不变量的另一半）。
///
/// 走**进程级装配端口**（宿主开机期装的那一份）——这是宿主生命周期动作，与哪个插件
/// 实例的上下文无关。
pub fn purge_for_plugin(plugin_id: &str) -> usize {
    purge_for_plugin_with_ports(&ports::ports(), plugin_id)
}

/// [`purge_for_plugin`] 的显式端口版（宿主多上下文场景：按属主用其所属上下文的端口
/// 投递事件，避免读到别的上下文的总线）
pub fn purge_for_plugin_with_ports(ports: &Arc<dyn PtyPorts>, plugin_id: &str) -> usize {
    let purged = reclaim_handles(ports, registered_handles(Some(plugin_id)));
    if purged > 0 {
        tracing::info!(plugin_id = %plugin_id, purged, "host-pty: 停用回收完成");
    }
    purged
}

/// 引擎层**全量**回收（系统关停路径）：跨属主 kill 并摘除全部在册插件 PTY，
/// 逐条按属主补发 `<owner>::pty:exit`（reason=killed）
///
/// 为什么必须由引擎自持（会话引擎下沉 P1 开放点 4：关停走引擎层全局 kill）：关机时
/// 插件可能已停用 / 超时 / trap，按属主回收依赖「插件停用流程被调到」；引擎自持回收
/// 保证不留孤儿进程，同时事件仍按属主投递（「谁在册谁收到终态」不因回收来源而变）。
pub fn kill_all_registered() -> usize {
    kill_all_registered_with_ports(&ports::ports())
}

/// [`kill_all_registered`] 的显式端口版（同 [`purge_for_plugin_with_ports`] 的理由）
pub fn kill_all_registered_with_ports(ports: &Arc<dyn PtyPorts>) -> usize {
    let reclaimed = reclaim_handles(ports, registered_handles(None));
    if reclaimed > 0 {
        tracing::info!(reclaimed, "host-pty: 引擎层全量回收完成（系统关停）");
    }
    reclaimed
}

/// 在册插件 PTY 条数（引擎事实：关停守卫 / 诊断用；**非 WIT 原语**、不设权限门、不取参数）
///
/// 在册即存活：终态（读线程 EOF + 子进程回收齐备）由退出监听摘除句柄，故本计数就是
/// 「活着的插件私有 PTY 数」。会话引擎下沉 P1 后，关窗守卫的判据将由会话状态改为
/// 「引擎事实：存活 PTY 计数 > 0」（开放点 4 / spec 验收项）。
pub fn live_count() -> usize {
    PTYS.lock().unwrap_or_else(|e| e.into_inner()).len()
}
