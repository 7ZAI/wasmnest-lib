//! host-pty 逻辑层 —— 插件私有伪终端原语（ABI v16，6 条）
//!
//! spec：`.scratch/2026-09-19-pty-base-service/spec.md`；本模块随能力域整面迁入
//! `wasmnest-pty-engine`（.scratch/2026-10-06-pty-capability-domain/spec.md D1/D2）。
//!
//! **零业务代码红线（ADR 0022 / spec D1）**：本模块只做引擎原语——裸 PTY 创建、
//! 字节读写面、句柄登记、属主仲裁、按游标应答。spawn 只收
//! `command + args + env + workingDir + cols/rows`，**不做** shell 包装
//! （`bash -lic` / PowerShell `-Command` / CMD `/K`）、WSL 路径转换、危险字符校验、
//! 默认 shell 探测（那些是宿主业务会话线与插件产品的语义，spec D5）。
//!
//! **与业务会话线零交叉（spec D2）**：插件 PTY 不进 `SessionComponents`、不注册
//! `GlobalOutputManager`、不参与业务会话事件链；共享同一 PTY 引擎
//! （[`PtySession`]）但互不可见。边界对侧是 `host-terminal` / `host-session` /
//! `terminal-hooks`（服务宿主业务会话），三者与本接口不得互相转发。
//!
//! **输出面是纯拉取（spec D3）**：每个 PTY 一条有界环形缓冲 [`PtyRing`]，读线程
//! 单生产者写入，插件按自己的游标 `ring-fetch`。慢插件只损失自己的历史（淘汰最旧并
//! 以 `truncated` 上报缺口），背压绝不回传到读线程；**没有 push 回调**（wasmtime
//! Store 不可重入，异步唤醒插件在语义上不成立）。限频通知面见
//! [`super::output`]（只是提示，不是数据面）。
//!
//! **P2 限频唤醒（2026-09-27 补）**：在拉取语义之上加一条**通知**而非数据推送——
//! 写侧装饰器 `OutputNotifySink` 在落环之后按限频（≤1 次/50 ms/句柄）向属主私有
//! topic `<owner>::pty:output` 发布 `{ ptyId }`，插件收到后自行按游标拉取。
//! 它是**提示而非承诺**：可被合并 / 丢弃（无订阅、队列满、插件未激活），
//! 数据面与背压语义一字未变（消费者兜底仍是轮询 + `truncated` resync），
//! 不改 WIT / 不改 ABI（ADR 0022 D3 的拉取语义保持，见 ADR 0029 §7）。
//!
//! **宿主广播声明已退役（websocket 业务下沉票 08）**：`hostBroadcastSessionId`
//! 字段与广播句柄映射已删除——PTY 引擎不再知道 session id，会话 id → pty 句柄的
//! 映射只在插件登记域（`session record.pty_id`），插件经 `ring-fetch` 自持输出游标
//! （spec §4.3）。宿主历史/输出读取改经插件互调。
//!
//! **多消费者并发拉取语义（票 07 的输入，写死在契约里）**：同一句柄的环可被属主
//! 插件（`ring-fetch`）与宿主广播面（直读）**同时**拉取。游标由各调用方自持，
//! [`PtyRing::fetch`] 是纯读（不消费、不推进全局状态）——两个消费的游标互不知晓、
//! 互不影响；淘汰由**产出量**驱动（环满即淘汰最旧），任一消费者的读取都不释放空间，
//! 各自落后于驻留起点都会 `truncated`。环容量必须覆盖最慢消费者的滞后（07 实测）。
//!
//! **终止与摘除的单一发布者不变量（票 04）**：`kill()` 只发起终止（引擎侧优雅中断 →
//! 兜底强杀），**不**自己发事件；句柄摘除与事件发布统一由 spawn 时起动的退出监听
//! 任务在「读线程 EOF + 子进程回收」齐备（票 01 的 [`PtyTerminated`] 汇聚门）时完成，
//! 且**只有从注册表 `remove` 成功的那一方**才发布事件——自然退出 / 主动 kill / 停用
//! 回收三条路径交汇时，每条 PTY 恰好一条 `pty:exit`，不多发也不漏发。

use std::collections::HashMap;
use std::sync::Arc;

use crate::wire::{PERMISSION_PTY_IO, PERMISSION_PTY_SPAWN};
use portable_pty::CommandBuilder;
use serde::Deserialize;
use wasmnest_server_base::constants::{
    PLUGIN_PTY_MAX_WRITE_BYTES, PLUGIN_PTY_RING_BYTES, PLUGIN_PTY_RING_FETCH_MAX_BYTES,
    PLUGIN_PTY_RING_MAX_BYTES,
};

use crate::plugin_binding::output::OutputNotifySink;
use crate::plugin_binding::ports::{block_on, BoxedTask, PtyPorts};
use crate::plugin_binding::registry::{
    exit_reason_of, publish_pty_exit, quota_of, registered_count_for, session_of, with_entry,
    EXIT_READ_WINDOW, PtyEntry, HANDLE_PREFIX, PTYS,
};
use crate::{PtyOutputSink, PtyRing, PtyRingFetch, PtyRingSink, PtySession, PtyTerminated};

fn denied_spawn() -> String {
    "permission denied: pty:spawn".to_string()
}

fn denied_io() -> String {
    "permission denied: pty:io".to_string()
}

// ==================== 参数契约与仲裁 ====================

/// `spawn` 的 config-json 契约（纯引擎参数，camelCase，spec D5）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpawnConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Option<HashMap<String, String>>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    cols: Option<u16>,
    #[serde(default)]
    rows: Option<u16>,
    /// 本条 PTY 输出环容量（字节）：省略取 [`PLUGIN_PTY_RING_BYTES`]，
    /// 超 [`PLUGIN_PTY_RING_MAX_BYTES`] 直接拒绝（宿主仲裁，见 `resolve_ring_bytes`）
    #[serde(default)]
    ring_bytes: Option<u64>,
}

/// 仲裁插件声明的输出环容量：`None` → 默认值；`Some(0)` 或超上限 → `Err`
///
/// **不夹取到上限**：静默降级会让插件按自己声明的历史深度规划上下文、实际却少得多，
/// 与 spec D9 的「配额类失败必须可见」同一分级（数据面只有读侧截断不是错误）。
fn resolve_ring_bytes(declared: Option<u64>) -> Result<u64, String> {
    let capacity = match declared {
        None => PLUGIN_PTY_RING_BYTES,
        Some(0) => return Err("pty spawn: ringBytes must be greater than 0".to_string()),
        Some(bytes) if bytes > PLUGIN_PTY_RING_MAX_BYTES => {
            return Err(format!(
                "pty spawn: ringBytes too large ({bytes} > limit {PLUGIN_PTY_RING_MAX_BYTES})"
            ))
        }
        Some(bytes) => bytes,
    };
    Ok(capacity)
}

/// 在册条数配额判据：`in_use >= quota` 即拒绝（**先判后动**，不留半成品进程）
///
/// 真源是 manifest 的 `ptyQuota` 声明（见 [`super::registry::register_quota`）；
/// 未声明者取内核默认档 [`PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN`]。
fn resolve_session_quota(plugin_id: &str) -> Result<(), String> {
    let in_use = registered_count_for(plugin_id);
    let quota = quota_of(plugin_id);
    if in_use >= quota {
        return Err(format!(
            "pty spawn: too many ptys for this plugin ({in_use} in use, limit {quota})"
        ));
    }
    Ok(())
}

// ==================== 创建域（pty:spawn） ====================

/// 创建插件私有裸 PTY：成功返回 `pty-<uuid>` 句柄并登记属主
///
/// 失败只回错误、不发布任何事件（无句柄可寻址），且不留注册表项与进程。
pub fn pty_spawn(
    ports: &Arc<dyn PtyPorts>,
    plugin_id: &str,
    config_json: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PTY_SPAWN, "host_pty_spawn") {
        return Err(denied_spawn());
    }
    let config: SpawnConfig =
        serde_json::from_str(config_json).map_err(|e| format!("pty spawn: invalid config: {e}"))?;
    let command = config.command.trim();
    if command.is_empty() {
        return Err("pty spawn: command must not be empty".to_string());
    }
    // 配额与容量在任何副作用之前判定（不留下开好的 fd / 起动的进程）
    let ring_bytes = resolve_ring_bytes(config.ring_bytes)?;
    resolve_session_quota(plugin_id)?;

    // 裸 argv：宿主不做 shell 解析、不做危险字符校验（参数数组 exec 天然免注入）
    let mut builder = CommandBuilder::new(command);
    for arg in &config.args {
        builder.arg(arg);
    }
    // env 是「追加」语义（继承宿主环境后覆盖同名键）：整体清空会让 PATH 类命令不可用
    if let Some(env) = &config.env {
        for (key, value) in env {
            builder.env(key, value);
        }
    }
    if let Some(dir) = &config.working_dir {
        builder.cwd(dir);
    }

    let host_config = ports.config();
    let cols = config.cols.unwrap_or(host_config.default_cols);
    let rows = config.rows.unwrap_or(host_config.default_rows);

    let pty_id = format!("{HANDLE_PREFIX}{}", uuid::Uuid::new_v4());
    let (ring_sink, ring) =
        PtyRingSink::paired_with_limits(ring_bytes, PtyRing::DEFAULT_MAX_CHUNKS);
    // P2 限频唤醒：写侧装饰器 = 落环 + 按限频发 `<owner>::pty:output` 通知（只带句柄，
    // 数据仍由插件游标拉取；装配见 `output` 模块文档）
    let sink: Arc<dyn PtyOutputSink> = Arc::new(OutputNotifySink::new(
        ring_sink,
        plugin_id.to_string(),
        pty_id.clone(),
        Arc::clone(ports),
    ));
    let session = PtySession::with_private_command(
        pty_id.clone(),
        cols,
        rows,
        builder,
        sink,
        // E1/D5 参数化：引擎不读宿主配置，宿主经端口交快照
        host_config.engine,
    )
    .map_err(|e| format!("pty spawn: 打开伪终端失败 (plugin {plugin_id}): {e}"))?;
    // **start 之前**订阅终态：广播不补发历史，短命命令（`/bin/true`）完全可能在登记
    // 与监听起动之前就 EOF + 回收完毕——晚订阅即永远等不到事件，句柄与环双双泄漏
    let lifecycle_rx = session.subscribe_lifecycle();

    if let Err(e) = block_on(ports, session.start()) {
        // 启动失败：session 在本作用域末被 drop，引擎 Drop 路径负责清理半成品进程
        return Err(format!(
            "pty spawn: 启动子进程失败 (pty_id {pty_id}, plugin {plugin_id}): {e}"
        ));
    }

    PTYS.lock().unwrap_or_else(|e| e.into_inner()).insert(
        pty_id.clone(),
        PtyEntry {
            owner: plugin_id.to_string(),
            session,
            ring,
            exit_published: false,
        },
    );
    // 退出监听在登记之后起动：保证「摘除 + 发布」时句柄必已在册
    spawn_exit_monitor(
        Arc::clone(ports),
        pty_id.clone(),
        plugin_id.to_string(),
        lifecycle_rx,
    );
    tracing::info!(
        plugin_id = %plugin_id,
        pty_id = %pty_id,
        cols,
        rows,
        args = config.args.len(),
        "host-pty: 插件私有 PTY 已创建"
    );
    Ok(pty_id)
}

// ==================== 数据域（pty:io） ====================

/// 写入输入字节（票 03）
///
/// 分块与让出节奏在引擎侧（`PtySession::write`：4000 字节分块 + 逐块 yield，避免打满
/// PTY 内核缓冲）；本层的 [`PLUGIN_PTY_MAX_WRITE_BYTES`] 是**一次调用的准入上限**，
/// 超限直接 `Err`——静默截断会让插件把「半条命令」喂进交互进程，比失败更糟。
pub fn pty_write(
    ports: &Arc<dyn PtyPorts>,
    plugin_id: &str,
    pty_id: &str,
    data: &[u8],
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PTY_IO, "host_pty_write") {
        return Err(denied_io());
    }
    if data.len() > PLUGIN_PTY_MAX_WRITE_BYTES {
        return Err(format!(
            "pty write: payload too large ({} bytes > limit {PLUGIN_PTY_MAX_WRITE_BYTES})",
            data.len()
        ));
    }
    let session = session_of(plugin_id, pty_id)?;
    block_on(ports, session.write(data))
        .map_err(|e| format!("pty write: 写入失败 (pty_id {pty_id}): {e}"))
}

/// 调整终端尺寸（票 03）
///
/// 透传到 PTY 尺寸即视为成功；**不承诺同步生效时序**（内核把 winsize 变更以 SIGWINCH
/// 通知前台进程组，全屏程序在下一帧重绘才对齐），插件按输出形态验证。
pub fn pty_resize(
    ports: &Arc<dyn PtyPorts>,
    plugin_id: &str,
    pty_id: &str,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PTY_IO, "host_pty_resize") {
        return Err(denied_io());
    }
    let session = session_of(plugin_id, pty_id)?;
    block_on(ports, session.resize(cols, rows))
        .map_err(|e| format!("pty resize: 调整尺寸失败 (pty_id {pty_id}, {cols}x{rows}): {e}"))
}

/// 查询进程是否仍在运行（票 03）
///
/// 判据 = `running` 标志 **且** 读线程尚未终结：子进程自然退出时引擎的 `running`
/// 不会翻下（只有 kill/销毁会，业务线依赖这一语义），而插件私有 PTY 释放了 slave
/// fd，EOF 即退出信号，故两路合一才如实。定位是「bus 不缓冲不重放」下丢失
/// `pty:exit` 后的自愈快照，不是事件替代品。
pub fn pty_is_running(
    ports: &Arc<dyn PtyPorts>,
    plugin_id: &str,
    pty_id: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PTY_IO, "host_pty_is_running") {
        return Err(denied_io());
    }
    let session = session_of(plugin_id, pty_id)?;
    Ok(running_verdict(
        session.is_running(),
        session.output_terminated(),
    ))
}

/// `is-running` 的判据组合（纯函数：真值表可确定性锁定，见票 03 变异 C-②）
///
/// 单独抽出来的唯一理由是「进程已自然退出」这一格无法稳定抓窗口——EOF 之后毫秒级
/// 就会被退出监听摘除句柄。故把组合逻辑做成纯判定，四格真值表直接断言；会话状态
/// 的两路输入由 [`PtySession::is_running`] / [`PtySession::output_terminated`] 供。
pub(crate) fn running_verdict(running: bool, output_terminated: bool) -> bool {
    running && !output_terminated
}

/// 终止并销毁（票 04）：优雅 Ctrl-C → 兜底强杀，复用引擎既有语义
///
/// `Ok(())` 表示**终止已发起**；句柄摘除与 `<owner>::pty:exit`（reason=killed）由退出
/// 监听在「EOF + 子进程回收」齐备时完成（见模块头的单一发布者不变量）。因此 kill 后
/// 立刻 `ring-fetch` 仍可能取到尾帧，而后再取即 `pty handle not found`。
pub fn pty_kill(ports: &Arc<dyn PtyPorts>, plugin_id: &str, pty_id: &str) -> Result<(), String> {
    if !ports.check_permission(plugin_id, PERMISSION_PTY_SPAWN, "host_pty_kill") {
        return Err(denied_spawn());
    }
    let session = session_of(plugin_id, pty_id)?;
    block_on(ports, session.kill())
        .map_err(|e| format!("pty kill: 终止失败 (pty_id {pty_id}): {e}"))
}

// ==================== ring-fetch（按游标拉取输出历史） ====================

/// 按游标拉取输出历史
///
/// `Ok(None)` = 游标已追平产出端（无新字节）；`Ok(Some)` = 自游标起的字节 + 续拉
/// 游标，游标落后于环驻留起点时 `truncated = true`（缺口如实上报，不静默补洞）。
/// 单次返回不超过 [`PLUGIN_PTY_RING_FETCH_MAX_BYTES`]（约束一次 wasm 边界拷贝量）。
pub fn pty_ring_fetch(
    ports: &Arc<dyn PtyPorts>,
    plugin_id: &str,
    pty_id: &str,
    from_offset: u64,
    max_bytes: u32,
) -> Result<Option<PtyRingFetch>, String> {
    if !ports.check_permission(plugin_id, PERMISSION_PTY_IO, "host_pty_ring_fetch") {
        return Err(denied_io());
    }
    // 注册表锁内只取环句柄，应答在锁外完成——两把锁不交叉持有
    let ring = with_entry(pty_id, plugin_id, |entry| Arc::clone(&entry.ring))?;
    let budget = max_bytes.min(PLUGIN_PTY_RING_FETCH_MAX_BYTES) as usize;
    let fetched = ring
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .fetch(from_offset, budget);
    if fetched.data.is_empty() && !fetched.truncated {
        return Ok(None);
    }
    Ok(Some(fetched))
}

// ==================== 退出监听 ====================

/// 起一条退出监听任务：等终态 → 摘注册表 → 发布事件
///
/// **必须经端口派生到宿主 runtime**（[`PtyPorts::spawn_task`]），不能用本域的
/// `tokio::spawn`：WASI 预打开模式下插件调用跑在**无 runtime handle 的阻塞线程**上，
/// 本函数由 `pty_spawn` 的同步路径直接调用，该线程上 `tokio::spawn` 立即 panic
/// （"there is no reactor running"）——panic 穿透会污染 wasmtime Store，让插件
/// 整体失效。宿主实现内部用那份唯一的 ambient 句柄（与调用线程的 runtime 状态
/// 无关），且任务生命周期本就应该长于单次宿主调用（它等的是任意时刻才到达的终态事件）。
fn spawn_exit_monitor(
    ports: Arc<dyn PtyPorts>,
    pty_id: String,
    owner: String,
    lifecycle_rx: tokio::sync::broadcast::Receiver<PtyTerminated>,
) {
    // 任务自身还要用端口发布退出事件，故传入克隆（本函数参数已是 `Arc`，克隆廉价）
    let task_ports = Arc::clone(&ports);
    let task: BoxedTask = Box::pin(reap_and_publish(task_ports, pty_id, owner, lifecycle_rx));
    ports.spawn_task("pty_exit_monitor", task);
}

async fn reap_and_publish(
    ports: Arc<dyn PtyPorts>,
    pty_id: String,
    owner: String,
    mut lifecycle_rx: tokio::sync::broadcast::Receiver<PtyTerminated>,
) {
    let terminated = match lifecycle_rx.recv().await {
        Ok(terminated) => terminated,
        // 发送端随会话 drop：句柄已由他方摘除（停用回收路径），事件也已由他方发布
        Err(e) => {
            tracing::debug!(pty_id = %pty_id, plugin_id = %owner, error = %e, "PTY 退出监听未收到终态事件即结束");
            return;
        }
    };
    let reason = exit_reason_of(&terminated);
    // 发布权认领 + 打开只读窗口（#12A）：`exit_published` 置位即唯一发布者
    //（与停用回收的竞争判据由「谁 remove 成功」改为「谁先置位」），句柄
    // **暂留注册表**——退出事件经宿主事件泵异步投递，先摘环会让属主退出
    // 处理器（终端插件尾帧 fetch）必然 `pty handle not found`，最后未被
    // drain 的字节永久丢失。
    let claimed = {
        let mut table = PTYS.lock().unwrap_or_else(|e| e.into_inner());
        match table.get_mut(&pty_id) {
            Some(entry) if entry.owner == owner && !entry.exit_published => {
                entry.exit_published = true;
                true
            }
            _ => false,
        }
    };
    if !claimed {
        tracing::debug!(
            plugin_id = %owner,
            pty_id = %pty_id,
            reason = %reason,
            "host-pty: 终态到达时句柄已被摘除或事件已发布（停用回收路径），不重复发"
        );
        return;
    }
    tracing::info!(
        plugin_id = %owner,
        pty_id = %pty_id,
        reason = %reason,
        exit_code = ?terminated.exit_code,
        "host-pty: 插件私有 PTY 已终止（退出只读窗口开启）"
    );
    publish_pty_exit(&ports, &owner, &pty_id, reason, terminated.exit_code);
    // 窗口到期摘除：环最后一次引用在此释放（进程此时确已退出并被回收）。
    // 到期前若被停用回收抢先摘除，此处 remove 落空即静默结束
    ports.spawn_task(
        "pty_exit_read_window",
        Box::pin(async move {
            tokio::time::sleep(EXIT_READ_WINDOW).await;
            if let Some(entry) = PTYS.lock().unwrap_or_else(|e| e.into_inner()).remove(&pty_id) {
                drop(entry);
                tracing::debug!(pty_id = %pty_id, "host-pty: 退出只读窗口到期，句柄已摘除");
            }
        }),
    );
}
