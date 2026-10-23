//! PTY Process Management
//!
//! 封装 portable-pty，提供跨平台的 PTY 管理功能
//! 核心职责：PTY 会话的生命周期管理（创建、启动、终止、resize）
//!
//! **零业务语义（2026-09-23 PTY 解耦票）**：本引擎只接受**调用方算好的**
//! `CommandBuilder`（argv 形态）——不做 shell 包装（`bash -lic` / PowerShell
//! `-Command` / CMD `/K`）、不做 WSL 路径转换、不做危险字符校验、不注入业务环境变量
//! （含 `WASMNEST_SESSION_ID`）。业务会话的命令构造与注入在业务层
//! （`session/session_manager.rs::launch_command`）；插件私有 PTY（host-pty）由插件
//! 构造 argv。两条消费线共用同一套读线程 / 回收 / 终态门语义。

// 仅在 Windows 平台使用（kill 的 taskkill 路径），避免 Linux/macOS 编译下 unused 警告
use crate::lifecycle::{PtyTerminated, PtyTerminationGate};
use crate::output_sink::PtyOutputSink;
use crate::pty_reader::PtyReader;
use crate::PtyEngineConfig;
use wasmnest_server_base::error::{AppError, Result};
#[cfg(target_os = "windows")]
use wasmnest_server_base::process::create_command;

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtyPair, PtySize};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::{broadcast, Mutex};

/// PTY slave fd 生命周期策略（票 3 已统一为 `ReleaseOnSpawn`，枚举退役）
///
/// **为什么统一释放**：父进程只要还持有 slave fd，内核就不会让 master 侧读返回 EOF——
/// 「子进程自然退出」因此在读线程上是不可观测的（读线程会永久阻塞在 `read()`，
/// 每会话泄漏一条线程）。释放 slave 后，子进程一退出就读到 EOF，
/// 「读线程关闭」才成为可靠的输出终结信号（实证见 2026-09-19 票 01 记录）。
///
/// 业务线曾用 `Hold`（终态事件只在 kill/销毁时到达），压制了既有的终态处理链
/// （`session_manager` 订阅任务收到 PtyTerminated → 置 Stopped + 状态事件），导致
/// 会话自然退出时状态滞留 Running、任务域「意外退出兜底」永不触发（插件
/// `task/state.rs` 注释明证会永久卡在运行中）。票 3 统一为释放：自然退出 → EOF →
/// 终态事件 → 既有处理链解锁（翻 Stopped + 状态事件 + 生命周期 Stopped）。

/// PTY 会话内部状态
///
/// 使用 Arc<Mutex<>> 包装所有非 Send/Sync 的类型，确保线程安全
pub struct PtySessionState {
    /// 会话 ID
    pub id: String,
    /// 会话名称
    pub name: String,
    /// 运行标志
    pub running: Arc<AtomicBool>,
    /// 未启动前的完整 PTY pair（`start()` 取 slave 侧 spawn 子进程）
    pub pair: Option<PtyPair>,
    /// 未启动前的命令（`start()` 取走并 spawn，一次性；argv 由调用方算好）
    pub command: Option<CommandBuilder>,
    /// 启动后的 master（resize / 读取端克隆来源）
    pub master: Option<Box<dyn MasterPty + Send>>,
    /// 写入器
    pub writer: Option<Box<dyn Write + Send>>,
    /// 读取线程句柄
    pub reader_handle: Option<JoinHandle<()>>,
    /// 进程 ID（用于强制终止）
    pub process_id: Option<u32>,
}

/// PTY 会话 - 线程安全的包装器
///
/// 所有内部状态都通过 Arc<Mutex<>> 保护，自动实现 Send + Sync
pub struct PtySession {
    state: Arc<Mutex<PtySessionState>>,
    /// 运行标志的共享引用（用于快速检查）
    running: Arc<AtomicBool>,
    /// 本会话是否被 `kill()` 主动终止（终态事件据此区分被杀与自然退出）
    kill_requested: Arc<AtomicBool>,
    /// 终态汇聚门（读线程关闭 + 子进程回收两路信号齐备后发出一条事件）
    gate: Arc<PtyTerminationGate>,
    /// 会话 ID 的缓存（避免频繁加锁）
    id: String,
    /// 输出投递目标（业务会话环 / 插件自备缓冲）
    sink: Arc<dyn PtyOutputSink>,
    /// 引擎级配置快照（E1/D5 参数化：原 `AppConfig::global()` 读点）
    config: PtyEngineConfig,
}

// 自动派生 Send + Sync，因为所有内部字段都是线程安全的
// Arc<Mutex<T>> 是 Send + Sync (当 T: Send)
// Arc<AtomicBool> 是 Send + Sync
// Arc<dyn PtyOutputSink> / Arc<PtyTerminationGate> 由 trait 的 Send + Sync 约束保证
// String 是 Send + Sync

impl PtySession {
    /// 引擎唯一构造入口：调用方算好的 argv + 输出汇 + 引擎级配置
    ///
    /// `command` 必须已由调用方构造完毕（argv 数组 + cwd + env）——本层不做任何命令
    /// 加工，只负责 openpty / spawn / 读线程 / 终态门。spawn 后释放 slave fd（票 3
    /// 统一）：自然退出 → EOF → 终态事件 → 既有处理链翻 Stopped。
    ///
    /// `config` 是引擎消费的宿主配置快照（[`PtyEngineConfig`]：生命周期广播容量 /
    /// 输出读缓冲大小），原读 `AppConfig::global()`（wasm-core-purity E1/D5 参数化）
    /// ——引擎不再感知宿主配置来源。
    ///
    /// 业务会话线（`name` = 会话名、sink = `session::SessionOutputSink`）与插件私有线
    /// （`name` 取 argv[0]、sink = 插件自备环）共用本入口。
    pub fn with_command(
        id: String,
        name: String,
        cols: u16,
        rows: u16,
        command: CommandBuilder,
        sink: Arc<dyn PtyOutputSink>,
        config: PtyEngineConfig,
    ) -> Result<Self> {
        Self::build(id, name, cols, rows, command, sink, config)
    }

    /// 便捷入口（host-pty 插件私有 PTY 的 spawn 面）：name 取 argv[0]（仅日志/诊断）
    ///
    /// 与 [`PtySession::with_command`] 同一实现，只是省去调用方传 name。
    pub fn with_private_command(
        id: String,
        cols: u16,
        rows: u16,
        command: CommandBuilder,
        sink: Arc<dyn PtyOutputSink>,
        config: PtyEngineConfig,
    ) -> Result<Self> {
        let name = command
            .get_argv()
            .first()
            .map(|arg| arg.to_string_lossy().into_owned())
            .unwrap_or_else(|| id.clone());
        Self::build(id, name, cols, rows, command, sink, config)
    }

    fn build(
        id: String,
        name: String,
        cols: u16,
        rows: u16,
        command: CommandBuilder,
        sink: Arc<dyn PtyOutputSink>,
        config: PtyEngineConfig,
    ) -> Result<Self> {
        let pty_system = native_pty_system();

        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| AppError::Pty(format!("打开伪终端失败 (session {}): {}", id, e)))?;

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| AppError::Pty(format!("获取 PTY 写入器失败 (session {}): {}", id, e)))?;
        let (lifecycle_tx, _) = broadcast::channel(config.lifecycle_capacity);

        let running = Arc::new(AtomicBool::new(true));
        let kill_requested = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(PtyTerminationGate::new(
            id.clone(),
            lifecycle_tx,
            kill_requested.clone(),
        ));

        let state = PtySessionState {
            id: id.clone(),
            name,
            pair: Some(pair),
            command: Some(command),
            master: None,
            writer: Some(writer),
            running: running.clone(),
            reader_handle: None,
            process_id: None,
        };

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            running,
            kill_requested,
            gate,
            id,
            sink,
            config,
        })
    }

    /// 获取会话 ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 获取会话名称
    pub async fn name(&self) -> String {
        let state = self.state.lock().await;
        state.name.clone()
    }

    /// 启动 PTY 会话
    #[tracing::instrument(name = "pty_start", skip_all, fields(session_id = %self.id))]
    pub async fn start(&self) -> Result<()> {
        let (cmd, pair) = {
            let mut state = self.state.lock().await;
            // 命令已在构造期算好（argv 形态）：本层原样 exec，不做包装 / 注入
            let cmd = state.command.take().ok_or_else(|| {
                AppError::Pty(format!(
                    "PTY 命令已消耗，无法重复启动 (session {})",
                    self.id
                ))
            })?;

            // 从 state 中取出 pair
            let pair = state.pair.take().ok_or_else(|| {
                AppError::Pty(format!("PTY pair already used (session {})", self.id))
            })?;

            (cmd, pair)
        };

        let child = pair.slave.spawn_command(cmd).map_err(|e| {
            AppError::Pty(format!("启动 PTY 子进程失败 (session {}): {}", self.id, e))
        })?;

        // 获取进程 ID 用于后续强制终止
        let pid = child.process_id();

        // 拆分 pair：master 常驻（resize / 读取端来源）；slave 统一立即释放——
        // 丢掉 slave 即关闭父进程侧 slave fd：子进程一退出 master 读即 EOF，
        // 终态门（读线程关闭 + 回收齐备）得以触发（票 3 统一语义）
        let PtyPair { slave, master } = pair;
        {
            let mut state = self.state.lock().await;
            state.master = Some(master);
            drop(slave);
            state.process_id = pid;
        }

        // 子进程句柄交给回收线程：阻塞 wait() 回收进程并带出退出码
        // （此前直接 drop 会让进程沦为僵尸，且退出码无从取得）
        self.gate.spawn_reaper(child);

        // 启动输出读取线程
        self.start_output_reader().await?;

        tracing::info!(session_id = %self.id, pid = ?pid, "PTY session started");
        Ok(())
    }

    /// 写入输入
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        // PTY 内核缓冲区通常为 4096 字节，超过此长度分块写入避免背压阻塞
        const CHUNK_SIZE: usize = 4000;

        if data.len() <= CHUNK_SIZE {
            let mut state = self.state.lock().await;
            let writer = state.writer.as_mut().ok_or_else(|| {
                tracing::error!("[PtyProcess] write: writer not available");
                AppError::Pty("Writer not available".to_string())
            })?;
            writer.write_all(data)?;
            writer.flush()?;
            return Ok(());
        }

        // 分块写入：每块之间短暂 yield，让 PTY 有时间消费缓冲区
        for chunk in data.chunks(CHUNK_SIZE) {
            // 锁严格限制在块内（写完成即释放，绝不跨 await 持锁）：write_all/flush
            // 是同步 syscall 且 TM 上快速完成，但 yield 点放锁外
            {
                let mut state = self.state.lock().await;
                let writer = state.writer.as_mut().ok_or_else(|| {
                    tracing::error!("[PtyProcess] write: writer not available");
                    AppError::Pty("Writer not available".to_string())
                })?;
                writer.write_all(chunk)?;
                writer.flush()?;
            }
            // 让出执行权，避免连续写入导致 PTY 缓冲区溢出
            tokio::task::yield_now().await;
        }

        Ok(())
    }

    /// 写入字符串
    pub async fn write_str(&self, text: &str) -> Result<()> {
        self.write(text.as_bytes()).await
    }

    /// 发送特殊键
    pub async fn send_special_key(&self, key: &str) -> Result<()> {
        let combo = crate::wire::key::KeyCombo::parse(key)
            .ok_or_else(|| AppError::InvalidInput(format!("Unknown special key: {}", key)))?;

        let bytes = combo
            .to_pty_bytes()
            .ok_or_else(|| AppError::InvalidInput(format!("Unsupported key combo: {}", key)))?;

        self.write(&bytes).await
    }

    /// 调整终端大小
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let mut state = self.state.lock().await;
        let master = state.master.as_mut().ok_or_else(|| {
            AppError::Pty(format!(
                "PTY master 不可用（会话未启动或已销毁 {}）",
                self.id
            ))
        })?;

        master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| {
                AppError::Pty(format!("调整 PTY 尺寸失败 (session {}): {}", self.id, e))
            })?;

        Ok(())
    }

    /// 订阅生命周期事件（进程退出、错误等）
    ///
    /// 恰好收到一条 [`PtyTerminated`]：读线程关闭与子进程回收两者齐备后才发出，
    /// 因此 `exit_code` 与「输出已终结」在同一事件里保证一致。
    pub fn subscribe_lifecycle(&self) -> broadcast::Receiver<PtyTerminated> {
        self.gate.subscribe()
    }

    /// 获取会话状态
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 输出是否已终结（读线程已见到 EOF / 读错误）
    ///
    /// **为什么需要它**：`running` 标志只在 `kill()`/`Drop` 时被翻下，子进程**自然退出**
    /// 时它仍是 true——业务线的 `Hold` 策略下这不可观测（拿不到 EOF），也就无人读取；
    /// 但插件私有 PTY 用 `ReleaseOnSpawn`，EOF 就是进程退出的可靠信号，host-pty 的
    /// `is-running` 必须如实回答「已经死了」。故本方法只加判据、不改 `running` 语义，
    /// 业务链路零感知。
    pub fn output_terminated(&self) -> bool {
        self.gate.reader_closed()
    }

    /// 终止会话
    pub async fn kill(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        // 终态事件据此给出 killed=true：portable-pty 的 ExitStatus 不区分
        // 信号终止与 exit 1，只能由宿主侧记录「是谁要求它结束的」
        self.kill_requested.store(true, Ordering::SeqCst);

        // 获取进程 ID
        let pid = {
            let state = self.state.lock().await;
            tracing::info!(session_id = %self.id, pid = ?state.process_id, "Kill session");
            state.process_id
        };

        // 先尝试优雅退出（失败属预期：进程可能已自行结束）
        if let Err(e) = self.send_special_key("ctrl+c").await {
            tracing::debug!(session_id = %self.id, error = %e, "优雅终止首选手法不可用，继续强杀");
        }
        if let Err(e) = self.write_str("\nexit\n").await {
            tracing::debug!(session_id = %self.id, error = %e, "退出写入不可用，继续强杀");
        }

        // 如果有进程 ID，强制终止进程树
        if let Some(pid) = pid {
            #[cfg(target_os = "windows")]
            {
                tracing::info!(pid = %pid, "Executing taskkill");
                let output = create_command("cmd")
                    .args(["/C", &format!("taskkill /F /T /PID {}", pid)])
                    .output();
                match output {
                    Ok(o) => {
                        tracing::info!("taskkill output: {}", String::from_utf8_lossy(&o.stdout))
                    }
                    Err(e) => tracing::error!("taskkill failed: {}", e),
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                let delivered = std::process::Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .output();
                match delivered {
                    Ok(o) => tracing::debug!(
                        session_id = %self.id,
                        pid = %pid,
                        stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                        "SIGKILL 已投递"
                    ),
                    Err(e) => tracing::error!(
                        session_id = %self.id,
                        pid = %pid,
                        error = %e,
                        "kill -9 执行失败，进程可能残留"
                    ),
                }
            }
        } else {
            tracing::warn!(session_id = %self.id, "No process_id available");
        }

        tracing::info!(session_id = %self.id, pid = ?pid, "PTY session killed");
        Ok(())
    }

    /// 启动输出读取线程
    async fn start_output_reader(&self) -> Result<()> {
        let reader = {
            let mut state = self.state.lock().await;
            let master = state.master.as_mut().ok_or_else(|| {
                AppError::Pty(format!("PTY master not available (session {})", self.id))
            })?;

            master.try_clone_reader().map_err(|e| {
                AppError::Pty(format!("克隆 PTY 读取器失败 (session {}): {}", self.id, e))
            })?
        };

        let pty_reader = PtyReader::start(
            reader,
            self.sink.clone(),
            self.gate.clone(),
            self.id.clone(),
            self.running.clone(),
            self.config.read_buffer_size,
        );

        // 保存线程句柄
        {
            let mut state = self.state.lock().await;
            state.reader_handle = Some(pty_reader.into_inner());
        }

        Ok(())
    }
}

impl Clone for PtySession {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            running: self.running.clone(),
            kill_requested: self.kill_requested.clone(),
            gate: self.gate.clone(),
            id: self.id.clone(),
            sink: self.sink.clone(),
            config: self.config,
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Only stop if this is the last reference
        if Arc::strong_count(&self.state) == 1 {
            self.running.store(false, Ordering::SeqCst);
            // 与 kill() 同语义：本会话是主动终止方，终态事件不得报成自然退出
            self.kill_requested.store(true, Ordering::SeqCst);

            // 尝试终止进程（同步方式，因为 Drop 不能是 async）
            if let Ok(state) = self.state.try_lock() {
                if let Some(pid) = state.process_id {
                    #[cfg(target_os = "windows")]
                    {
                        let _ = create_command("cmd")
                            .args(["/C", &format!("taskkill /F /T /PID {}", pid)])
                            .output();
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        let _ = std::process::Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output();
                    }
                    tracing::info!(session_id = %self.id, pid = %pid, "PTY session killed on drop");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::output_sink::test_support::CollectingSink;

    /// 丢弃式输出汇（不关心输出的用例）
    struct NoopSink;

    #[async_trait::async_trait]
    impl PtyOutputSink for NoopSink {
        async fn on_bytes(&self, _bytes: Vec<u8>, _timestamp_ms: i64) {}
    }

    fn noop_sink() -> Arc<dyn PtyOutputSink> {
        Arc::new(NoopSink)
    }

    /// 最小引擎命令（不 start，仅验证创建/属性/订阅/终止路径）
    fn echo_command() -> CommandBuilder {
        let mut cmd = CommandBuilder::new("echo");
        cmd.arg("hello");
        cmd
    }

    #[tokio::test]
    async fn with_command_creates_session_with_properties_and_kill_stops_it() {
        let session = PtySession::with_command(
            "sess-1".to_string(),
            "test-session".to_string(),
            80,
            24,
            echo_command(),
            noop_sink(),
            PtyEngineConfig::default(),
        )
        .expect("openpty should succeed on this platform");

        assert_eq!(session.id(), "sess-1");
        assert_eq!(session.name().await, "test-session");
        assert!(session.is_running());

        // 生命周期订阅通道可用
        let _lifecycle_rx = session.subscribe_lifecycle();

        // kill 在未启动进程时仅翻转标志（无 process_id，跳过 taskkill）
        session.kill().await.expect("kill should succeed");
        assert!(!session.is_running());
    }

    /// Linux 命令（真实 PTY spawn 往返，票据 03）：`bash -c <脚本>`
    ///
    /// 引擎面已收 argv（宿主不再做 shell 包装）：测试自己给出 `bash -c` 形态，
    /// 与业务层 `session_manager::launch_command` 的产物同形。
    #[cfg(target_os = "linux")]
    fn linux_command(script: &str) -> CommandBuilder {
        let mut cmd = CommandBuilder::new("bash");
        cmd.arg("-c");
        cmd.arg(script);
        cmd
    }

    /// 指定 id 的业务线形态会话（argv 已算好 + 丢弃 sink）
    #[cfg(target_os = "linux")]
    fn new_session_with_id(sid: String, script: &str) -> PtySession {
        PtySession::with_command(
            sid,
            "itest-pty".to_string(),
            120,
            40,
            linux_command(script),
            noop_sink(),
            PtyEngineConfig::default(),
        )
        .expect("openpty")
    }

    /// 自动 id 的业务线形态会话（不关心 id 的用例）
    #[cfg(target_os = "linux")]
    fn new_session(script: &str) -> PtySession {
        new_session_with_id(unique_sid("itest-pty"), script)
    }

    /// 真实 PTY：start 后 is_running + kill 后停止（票据 03）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn start_spawns_real_process_and_reports_running() {
        let session = new_session("sleep 30");
        session
            .start()
            .await
            .expect("start should spawn real process");
        assert!(session.is_running(), "start 后应 running");
        assert_eq!(session.name().await, "itest-pty");
        session.kill().await.expect("kill");
        assert!(!session.is_running());
    }

    /// 真实 PTY：write_str 写入命令，输出落入会话环（票据 03 + 拉取模型）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn write_str_reaches_process_output() {
        use crate::pty_ring::PtyRingSink;

        let sid = format!(
            "itest-pty-write-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let marker = format!("WASMNEST_PTY_WRITE_{sid}");
        // 票 11：输出汇 = **引擎环**（`PtyRingSink` 的配对环）——业务会话环随
        // `session/` 目录删除，引擎环是唯一输出环
        let (sink, ring) = PtyRingSink::paired(1024 * 1024);
        let session = PtySession::with_command(
            sid.clone(),
            "itest-pty".to_string(),
            120,
            40,
            linux_command(&format!("echo {marker}; sleep 5")),
            sink,
            PtyEngineConfig::default(),
        )
        .expect("openpty");

        session.start().await.expect("start");
        session
            .write_str(&format!("echo {marker}\n"))
            .await
            .expect("write_str");

        let mut collected = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !collected.contains(&marker) && std::time::Instant::now() < deadline {
            {
                let guard = ring.lock().unwrap_or_else(|e| e.into_inner());
                let (min, max) = guard.watermarks();
                collected = String::from_utf8_lossy(&guard.fetch(min, (max - min) as usize).data)
                    .into_owned();
            }
            if !collected.contains(&marker) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        assert!(
            collected.contains(&marker),
            "write_str 的输出应落入引擎环: {collected}"
        );

        session.kill().await.expect("kill");
    }

    /// resize 不 panic 且写入后仍可 kill（票据 03）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn resize_after_start_does_not_panic() {
        let session = new_session("sleep 30");
        session.start().await.expect("start");
        session
            .resize(100, 30)
            .await
            .expect("resize should succeed");
        session.resize(80, 24).await.expect("resize idempotent");
        assert!(session.is_running());
        session.kill().await.expect("kill");
    }

    /// send_special_key：非法 key 报错（票据 03）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn send_special_key_invalid_key_errors() {
        let session = new_session("sleep 30");
        session.start().await.expect("start");
        let err = session
            .send_special_key("not_a_real_key")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("key"), "非法 key 应报错: {err}");
        session.kill().await.expect("kill");
    }

    /// 8KB 大负载分块写入不失败（票据 03：CHUNK_SIZE=4000 分块约束）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn write_large_payload_chunks_without_failure() {
        let session = new_session("sleep 30");
        session.start().await.expect("start");
        let big: Vec<u8> = vec![b'x'; 9000];
        session.write(&big).await.expect("8KB 分块写入不应失败");
        session.kill().await.expect("kill");
    }

    /// 全局唯一会话 ID（避免测试间通过全局单例互相干扰）
    #[cfg(target_os = "linux")]
    fn unique_sid(prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// 插件私有 PTY（自备 sink + 释放 slave fd）
    #[cfg(target_os = "linux")]
    fn private_session(script: &str) -> (PtySession, Arc<CollectingSink>) {
        let sink = CollectingSink::new();
        let session = PtySession::with_command(
            unique_sid("itest-private"),
            "itest-pty".to_string(),
            120,
            40,
            linux_command(script),
            sink.clone(),
            PtyEngineConfig::default(),
        )
        .expect("openpty");
        (session, sink)
    }

    /// 等待终态事件（真 PTY 路径，超时防挂死）
    #[cfg(target_os = "linux")]
    async fn recv_termination(
        rx: &mut tokio::sync::broadcast::Receiver<PtyTerminated>,
    ) -> PtyTerminated {
        tokio::time::timeout(std::time::Duration::from_secs(15), rx.recv())
            .await
            .expect("15s 内应收到 PTY 终态事件")
            .expect("终态事件不得丢失")
    }

    /// 真 PTY 自然退出（释放 slave fd）：退出码随终态事件带出（票据 01 地基能力 ①）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn natural_exit_reports_exit_code_in_termination_event() {
        use crate::pty_status::PtySessionStatus;

        let (session, _sink) = private_session("exit 7");
        let mut lifecycle_rx = session.subscribe_lifecycle();
        session.start().await.expect("start");

        let terminated = recv_termination(&mut lifecycle_rx).await;
        assert_eq!(
            terminated.exit_code,
            Some(7),
            "短命命令的退出码必须随终态事件带出"
        );
        assert_eq!(
            terminated.status,
            PtySessionStatus::Stopped,
            "EOF 终态应为 Stopped"
        );
        assert!(!terminated.killed, "自然退出不得标记 killed");
    }

    /// 真 PTY 成功退出：退出码 0（与「取不到退出码」的 None 区分开）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn successful_exit_reports_zero_code_not_none() {
        let (session, _sink) = private_session("true");
        let mut lifecycle_rx = session.subscribe_lifecycle();
        session.start().await.expect("start");

        assert_eq!(recv_termination(&mut lifecycle_rx).await.exit_code, Some(0));
    }

    /// 真 PTY + 自备 sink（票据 01 地基能力 ②）：输出投递到调用方给的缓冲
    ///
    /// 票 11：原用例还断言「业务会话总线未注册」——该总线随 `session/` 目录删除，
    /// 「宿主业务线零感知」现在是结构事实（输出面只有引擎环，且它只由
    /// `PtyRingSink` 持有者看到）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn session_with_private_sink_receives_output() {
        let sid = unique_sid("itest-private-sink-pty");
        let marker = format!("WASMNEST_PTY_PRIVATE_{sid}");
        let sink = CollectingSink::new();
        let session = PtySession::with_command(
            sid.clone(),
            "itest-pty".to_string(),
            120,
            40,
            linux_command(&format!("echo {marker}")),
            sink.clone(),
            PtyEngineConfig::default(),
        )
        .expect("openpty");
        let mut lifecycle_rx = session.subscribe_lifecycle();

        session.start().await.expect("start");
        let terminated = recv_termination(&mut lifecycle_rx).await;
        assert_eq!(terminated.exit_code, Some(0), "echo 正常退出退出码应为 0");

        // 终态事件 ≠ sink 已收到尾帧：读线程只保证「尾帧已入有序队列」
        // （`gate.mark_reader_closed` 早于独立消费者任务的 `on_bytes`，见
        // `pty_reader::start` 注释）→ 有界轮询等待投递完成，不依赖严格先后
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut collected = String::new();
        while std::time::Instant::now() < deadline {
            collected = String::from_utf8_lossy(&sink.collected()).into_owned();
            if collected.contains(&marker) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            collected.contains(&marker),
            "自备 sink 应收到进程输出: {collected}"
        );
    }

    /// 业务会话线（`Hold`）现役语义回归锁：子进程自然退出**不产生**终态事件
    /// 业务会话自然退出（票 3 统一 ReleaseOnSpawn）：EOF 可观测 → 终态事件自动到达，
    /// 既有处理链（session_manager 订阅任务）据此翻 Stopped——修复 Hold 下状态滞留
    /// Running / 任务域「意外退出兜底」永不触发的问题。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn natural_exit_emits_termination_event_without_kill() {
        let session = new_session("exit 7");
        let mut lifecycle_rx = session.subscribe_lifecycle();
        session.start().await.expect("start");

        let terminated = recv_termination(&mut lifecycle_rx).await;
        assert!(
            !terminated.killed,
            "自然退出必须 killed=false（区别于 kill 路径），exit_code 应为 7"
        );
        assert_eq!(terminated.exit_code, Some(7), "自然退出必须带出真实退出码");
    }

    /// 真 PTY 被 kill：终态事件与自然退出可区分（killed=true）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kill_marks_termination_event_as_killed() {
        use crate::pty_status::PtySessionStatus;

        let session = new_session("sleep 30");
        let mut lifecycle_rx = session.subscribe_lifecycle();
        session.start().await.expect("start");
        assert!(session.is_running(), "kill 前应仍在运行");

        session.kill().await.expect("kill");

        let terminated = recv_termination(&mut lifecycle_rx).await;
        assert!(
            terminated.killed,
            "kill 终止必须标记 killed（信号终止无退出码可判）"
        );
        assert_eq!(terminated.status, PtySessionStatus::Stopped);
        assert!(!session.is_running());
    }
}
