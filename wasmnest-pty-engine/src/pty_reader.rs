//! PTY Output Reader
//!
//! PTY 输出读取线程：`read → 有序队列 → 单消费者入输出汇`。
//!
//! **投递目标可注入**（`PtyOutputSink`）：读取线程不感知字节最终落在业务会话环
//! 还是插件自备缓冲——业务链路与插件私有 PTY 共用同一条读线程语义。
//!
//! **源零等待（spec §4.1/§4.6 背压下移）**：读取路径不含任何暂停/水位判定，
//! 也不感知任何订阅者。数据量超出会话环容量时由环淘汰最旧（订阅者各自按
//! 游标拉取），慢订阅者的节流只发生在它自己的订阅者执行体里——单个慢消费者
//! 不再能冻结源产出（历史教训：会话级共享水位 + 源侧暂停 = 多订阅者场景下
//! 一个端 ack 滞留就冻结整条链路）。

use std::io::{BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::pty_status::PtySessionStatus;
use crate::lifecycle::PtyTerminationGate;
use crate::output_sink::PtyOutputSink;

/// PTY 输出读取器
pub struct PtyReader {
    handle: Option<JoinHandle<()>>,
}

impl PtyReader {
    /// 创建并启动输出读取线程
    ///
    /// - `reader`: PTY 读取器
    /// - `sink`: 输出投递目标（业务总线 / 插件自备缓冲）
    /// - `gate`: 终态汇聚门（读线程关闭 = 终态信号 ①）
    /// - `session_id`: 会话 ID（日志与终态事件寻址）
    /// - `running`: 运行标志
    pub fn start(
        reader: Box<dyn Read + Send + 'static>,
        sink: Arc<dyn PtyOutputSink>,
        gate: Arc<PtyTerminationGate>,
        session_id: String,
        running: Arc<AtomicBool>,
        read_buffer_size: usize,
    ) -> Self {
        let mut buf_reader = BufReader::new(reader);

        // 有序输出队列：PTY 读线程按 read 顺序 blocking_send，单消费者任务顺序
        // on_bytes——根治「spawn 并发 on_output 乱序」竞态（多任务在 index 分配
        // 与广播之间互相插入 → 队列 push/broadcast 顺序与事件产生顺序错乱 → 字节
        // 错位残渣）。队列满时 blocking_send 阻塞读线程——这是唯一残留的源侧
        // 等待，仅在入环消费者彻底停摆时发生（正常路径 on_bytes 只做入环 + 通告
        // 水印，无 await 等待任何订阅者）
        let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, i64)>(16384);
        let consumer_session_id = session_id.clone();
        crate::runtime::spawn(async move {
            while let Some((bytes, timestamp_ms)) = output_rx.recv().await {
                sink.on_bytes(bytes, timestamp_ms).await;
            }
            tracing::debug!(session_id = %consumer_session_id, "PTY output consumer exited");
        });

        let handle = thread::spawn(move || {
            let mut buffer = vec![0u8; read_buffer_size];
            let mut exit_status = PtySessionStatus::Stopped;

            while running.load(Ordering::SeqCst) {
                match buf_reader.read(&mut buffer) {
                    Ok(0) => {
                        // EOF - process exited
                        tracing::info!(session_id = %session_id, "PTY session ended");
                        break;
                    }
                    Ok(n) => {
                        let timestamp = chrono::Utc::now();
                        let raw_bytes = buffer[..n].to_vec();

                        // 经有序队列顺序发送（单消费者顺序投递，消除 spawn 并发
                        // 乱序）。队列关闭 = 消费者已退出（应用关闭中），读循环退出
                        if output_tx
                            .blocking_send((raw_bytes, timestamp.timestamp_millis()))
                            .is_err()
                        {
                            tracing::debug!("PTY output queue closed, reader exiting");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("PTY read error: {}", e);
                        exit_status = PtySessionStatus::Error;
                        break;
                    }
                }
            }

            // 终态信号 ①：**尾帧已入队**（不是「已投递」——真正的 `sink.on_bytes`
            // 在独立消费者任务里按序异步执行，本标记可能先于它完成）。退出码要等
            // 子进程回收，事件由门齐备后发出（发送失败 = 无订阅者，属正常终止路径；
            // 门内 warn 保留可观测性）。
            //
            // 因此：终态事件到达 ≠ sink 已收到全部尾帧。消费方若在终态事件后立即
            // 断言 sink 内容，必须容忍这一间隙（有界轮询），不能依赖严格先后。
            gate.mark_reader_closed(exit_status);
        });

        Self { handle: Some(handle) }
    }

    /// 等待线程结束
    pub fn wait(self) {
        if let Some(handle) = self.handle {
            let _ = handle.join();
        }
    }

    /// 获取内部线程句柄（用于保存到状态中）
    pub fn into_inner(self) -> JoinHandle<()> {
        self.handle.expect(" PtyReader handle is None")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty_status::PtySessionStatus;
    use crate::lifecycle::PtyTerminated;
    use crate::output_sink::test_support::CollectingSink;
    use crate::pty_ring::PtyRingSink;
    use std::io::Read;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tokio::sync::broadcast;

    /// 内存 Reader：一次性吐出数据后 EOF（模拟 PTY 主设备读取）
    struct MemoryReader {
        data: std::io::Cursor<Vec<u8>>,
    }

    impl Read for MemoryReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.data.read(buf)
        }
    }

    /// 记录每次 read 实际读入字节数的 Reader
    struct RecordingReader {
        data: Vec<u8>,
        pos: usize,
        reads: Arc<std::sync::Mutex<Vec<usize>>>,
    }

    impl Read for RecordingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0); // EOF
            }
            let n = std::cmp::min(buf.len(), self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            self.reads.lock().unwrap().push(n);
            Ok(n)
        }
    }

    /// 全局唯一会话 ID（避免测试间通过全局单例互相干扰）
    fn unique_session_id(prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// 轮询**引擎环**直至累计字节达到期望值（读线程是独立 OS 线程，投递异步）
    ///
    /// 票 11：参数从业务会话环改为引擎 `PtyRing`（`PtyRingSink::paired` 的另一半）。
    async fn drain_engine_ring_until(ring: &Arc<std::sync::Mutex<crate::PtyRing>>, want: usize) -> Vec<u8> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            {
                let guard = ring.lock().unwrap_or_else(|e| e.into_inner());
                let (min, max) = guard.watermarks();
                if max.saturating_sub(min) as usize >= want {
                    return guard.fetch(min, want).data;
                }
            }
            if std::time::Instant::now() >= deadline {
                return Vec::new();
            }
            tokio::task::yield_now().await;
        }
    }

    /// 轮询自备 sink 直至累计字节达到期望值（消费者任务是异步的）
    async fn drain_sink_until(sink: &Arc<CollectingSink>, want: usize) -> Vec<u8> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let collected = sink.collected();
            if collected.len() >= want {
                return collected;
            }
            if std::time::Instant::now() >= deadline {
                return collected;
            }
            tokio::task::yield_now().await;
        }
    }

    /// 测试用终态门（回收侧由 `mark_reaped` 手动补上，本模块只测读线程）
    fn test_gate(session_id: &str) -> (Arc<PtyTerminationGate>, broadcast::Receiver<PtyTerminated>) {
        let (tx, rx) = broadcast::channel(8);
        let gate = Arc::new(PtyTerminationGate::new(
            session_id.to_string(),
            tx,
            Arc::new(AtomicBool::new(false)),
        ));
        (gate, rx)
    }

    /// 负载超过默认 read_buffer_size（4096）→ 强制分多次 read → 多轮输出
    fn oversized_payload() -> Vec<u8> {
        (0..9000u32).map(|i| (i % 251) as u8).collect()
    }

    fn memory_reader(payload: Vec<u8>) -> Box<dyn Read + Send + 'static> {
        Box::new(MemoryReader {
            data: std::io::Cursor::new(payload),
        })
    }

    /// EOF → 读线程关闭：退出码未就位前不得发出终态事件，回收后补发 Stopped
    #[test]
    fn eof_marks_reader_closed_and_emits_stopped_only_after_reap() {
        let (gate, mut lifecycle_rx) = test_gate("test-session");
        let running = Arc::new(AtomicBool::new(true));
        let sink = CollectingSink::new();

        let pty_reader = PtyReader::start(
            memory_reader(oversized_payload()),
            sink,
            gate.clone(),
            "test-session".to_string(),
            running,
            4096,
        );
        pty_reader.wait(); // EOF 后线程自行退出，join 返回

        assert_eq!(
            lifecycle_rx.try_recv().unwrap_err(),
            broadcast::error::TryRecvError::Empty,
            "读线程单独关闭时不得发出终态事件（退出码尚不可用）"
        );

        gate.mark_reaped(Some(0));
        let terminated = lifecycle_rx.try_recv().expect("读线程关闭 + 回收齐备后应发出终态事件");
        assert_eq!(terminated.status, PtySessionStatus::Stopped);
        assert_eq!(terminated.exit_code, Some(0));
    }

    /// 零字节输入（进程未产出任何输出即退出）也走完整终止路径
    #[test]
    fn empty_input_exits_with_stopped_lifecycle() {
        let (gate, mut lifecycle_rx) = test_gate("empty");
        let running = Arc::new(AtomicBool::new(true));

        let pty_reader = PtyReader::start(
            memory_reader(Vec::new()),
            CollectingSink::new(),
            gate.clone(),
            "empty".to_string(),
            running,
            4096,
        );
        pty_reader.wait();
        assert_eq!(
            lifecycle_rx.try_recv().unwrap_err(),
            broadcast::error::TryRecvError::Empty,
            "回收未就位前不得发出终态事件"
        );

        gate.mark_reaped(None);
        let terminated = lifecycle_rx.try_recv().expect("lifecycle event should be sent");
        assert_eq!(terminated.status, PtySessionStatus::Stopped);
        assert_eq!(terminated.exit_code, None, "无退出码时事件仍须发出且缺省");
    }

    /// 引擎环投递（票据 04 + 拉取模型）：产出字节必须完整按序落入**引擎环**
    /// （订阅者随后按游标从环上拉取）。
    ///
    /// 零订阅者场景同时是「源不依赖消费者」的回归护栏：没有任何订阅者时
    /// 产出照常全量入环（引擎环是纯缓冲，没有推送面）。
    ///
    /// 票 11：读源从业务会话环改为引擎 `PtyRingSink::paired`——引擎环现在是
    /// 唯一输出环。
    #[test]
    fn output_bytes_reach_engine_ring_complete_and_in_order() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sid = unique_session_id("itest-delivery");

            let (gate, _rx) = test_gate(&sid);
            let running = Arc::new(AtomicBool::new(true));
            let payload = oversized_payload();
            let (sink, ring) = PtyRingSink::paired(1024 * 1024);
            let pty_reader = PtyReader::start(memory_reader(payload.clone()), sink, gate, sid.clone(), running, 4096);
            pty_reader.wait();

            let collected = drain_engine_ring_until(&ring, payload.len()).await;
            assert_eq!(collected, payload, "PTY 输出必须完整按序落入引擎环（票据 04）");
        });
    }

    /// 自备 sink 投递（票据 01 输出汇可注入）：同一条读线程把字节投递到引擎环
    /// 之外的目标——内容、分块与顺序均不得变化
    #[test]
    fn output_bytes_reach_private_sink_in_order() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sid = unique_session_id("itest-private-sink");

            let (gate, _rx) = test_gate(&sid);
            let running = Arc::new(AtomicBool::new(true));
            let payload = oversized_payload();
            let sink = CollectingSink::new();
            let pty_reader = PtyReader::start(memory_reader(payload.clone()), sink.clone(), gate, sid.clone(), running, 4096);
            pty_reader.wait();

            let collected = drain_sink_until(&sink, payload.len()).await;
            assert_eq!(collected, payload, "自备 sink 必须收到完整按序字节");
            assert!(
                sink.chunks().len() > 1,
                "负载应经多次 read 分块投递（否则未验证顺序契约）: {:?}",
                sink.chunks().len()
            );
        });
    }

    /// Err 分支（票据 04）：假 Reader 返回 Err → 生命周期事件为 Error
    #[test]
    fn reader_error_reports_error_lifecycle() {
        struct ErrReader;
        impl Read for ErrReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected read error"))
            }
        }

        let (gate, mut lifecycle_rx) = test_gate("err-session");
        let running = Arc::new(AtomicBool::new(true));
        let reader: Box<dyn Read + Send + 'static> = Box::new(ErrReader);
        let pty_reader = PtyReader::start(
            reader,
            CollectingSink::new(),
            gate.clone(),
            "err-session".to_string(),
            running,
            4096,
        );
        pty_reader.wait();
        gate.mark_reaped(None);

        let terminated = lifecycle_rx.try_recv().expect("lifecycle event should be sent");
        assert_eq!(
            terminated.status,
            PtySessionStatus::Error,
            "读错误应上报 Error 生命周期"
        );
    }

    /// running=false（启动即退出）：读线程不读任何字节，生命周期报 Stopped
    #[test]
    fn running_flag_cleared_before_read_exits_without_reading() {
        let (gate, mut lifecycle_rx) = test_gate("stop-session");
        let running = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let reader: Box<dyn Read + Send + 'static> = Box::new(RecordingReader {
            data: b"never read".to_vec(),
            pos: 0,
            reads: reads.clone(),
        });

        let pty_reader = PtyReader::start(
            reader,
            CollectingSink::new(),
            gate.clone(),
            "stop-session".to_string(),
            running,
            4096,
        );
        pty_reader.wait();
        gate.mark_reaped(Some(3));

        assert!(reads.lock().unwrap().is_empty(), "running=false 时不得发生任何 read");
        let terminated = lifecycle_rx.try_recv().expect("lifecycle event should be sent");
        assert_eq!(
            terminated.status,
            PtySessionStatus::Stopped,
            "running=false 退出应报 Stopped"
        );
        assert_eq!(terminated.exit_code, Some(3));
    }
}
