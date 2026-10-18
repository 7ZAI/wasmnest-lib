//! Plugin PTY Ring
//!
//! 插件私有 PTY 的输出环形缓冲（host-pty 输出面，spec D3）。形态与业务会话环
//! （`session/session_output.rs::UnifiedOutputQueue`）同源：单生产者（PTY 读线程经
//! [`PtyRingSink`] 投递）+ 消费者按全局字节偏移拉取，驻留超容量即淘汰最旧块。
//!
//! **刻意自持实现**而非抽取复用业务环：二者生命周期不同（业务环随业务会话、
//! 本环随插件 pty 句柄），且 2026-09-17 刚重构完的业务链路不背回归风险；
//! 代码级抽取候选登记在票 07 的 ADR。
//!
//! **源零等待**：[`PtyRing::push`] 只做一次入队 + 均摊 O(1) 淘汰，不等待也不感知
//! 消费者——慢插件只能看到自己的历史被截断（`truncated`），背压绝不回传到读线程
//! （历史教训见 `.scratch/2026-09-17-pty-pull-subscribers/spec.md`）。
//!
//! 偏移语义：`max_offset` = 累计产出字节（单调递增，永不因淘汰回退），
//! `min_offset` = 驻留最旧字节位置。拉取区间为 `[游标, next_offset)`，
//! 请求游标落后于 `min_offset`（有字节已被淘汰）时 `truncated = true`，
//! 调用方据此重建上下文（resync）。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::output_sink::PtyOutputSink;

/// 环上驻留的字节块（一次 `push` 一块，块间区间连续无重叠）
struct RingChunk {
    /// 块起点（累计字节偏移）
    start: u64,
    bytes: Vec<u8>,
}

impl RingChunk {
    fn end(&self) -> u64 {
        self.start + self.bytes.len() as u64
    }
}

/// 一次拉取的结果（对应 WIT `ring-fetch-result`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRingFetch {
    /// 本次返回的字节，区间为 `[实际起点, next_offset)`
    pub data: Vec<u8>,
    /// 下一次拉取应传的游标
    pub next_offset: u64,
    /// 请求游标落后于环驻留起点 → 中间有字节已被淘汰，调用方需 resync
    pub truncated: bool,
}

impl PtyRingFetch {
    fn empty(at: u64, truncated: bool) -> Self {
        Self {
            data: Vec::new(),
            next_offset: at,
            truncated,
        }
    }
}

/// 有界字节环形缓冲（单生产者 + 游标拉取）
pub struct PtyRing {
    chunks: VecDeque<RingChunk>,
    /// 驻留最旧字节位置（队首块起点）
    min_offset: u64,
    /// 累计产出字节（生产端游标）
    max_offset: u64,
    /// 驻留字节总量（淘汰基准）
    resident_bytes: u64,
    /// 驻留字节上限
    capacity_bytes: u64,
    /// 驻留条目上限（防御极小块风暴：字节没超容量但块数失控时同样淘汰最旧）
    ///
    /// 沿用会话输出环的块级惯例（旧 `channels.global_queue_max_chunks` 已随会话下沉退役）；正常读块量级（KB 级）
    /// 下字节上限先触发，本值只在碎块场景兜底——**前提是尾块合并**（`push` 内），
    /// 否则行式输出的短读块会先于字节上限触发（见 [`PtyRing::DEFAULT_MAX_CHUNKS`]）。
    max_chunks: usize,
}

impl PtyRing {
    /// 尾块合并目标（字节）
    ///
    /// 取 `PLUGIN_PTY_RING_FETCH_MAX_BYTES`（16 KiB，单次 `ring-fetch` 上限）同值：
    /// 合并块不超过任何消费者的单次取数窗口（块边界对 `fetch` 不可见，此值只为让
    /// 「块数 = 容量 / 合并目标」这个估算是诚实的），同时足够大到能吸掉 PTY 的短读
    /// （行式输出实测 ~7 B/次）。
    ///
    /// **上限也是淘汰粒度的上限**：淘汰只能整块丢，所以合并块越大，一次淘汰就越
    /// 可能连带丢掉仍可服务的历史（消费者只落后 1 字节也会被 `truncated`）。16 KiB
    /// 把这个过冲钉在 4 MiB 环的 0.4%，可接受；不宜再大。
    pub const COALESCE_TARGET: usize = 16 * 1024;

    /// 启用尾块合并的**最小环容量**（字节）
    ///
    /// 容量小于本值时保持「一次 push 一块」：此时 `DEFAULT_MAX_CHUNKS`（4096）与
    /// 字节容量已是同一量级（4096 × 16 B = 64 KiB），条目上限几乎不是生效维度，
    /// 而精确的块粒度换来更细的淘汰（不过冲）。容量 ≥ 64 KiB 时条目上限会先于字节
    /// 上限成为瓶颈（实测 4 MiB 环在 29 KiB 处淘汰），必须靠合并把字节上限恢复为
    /// 唯一权威维度。
    pub const COALESCE_MIN_CAPACITY: u64 = 64 * 1024;

    /// 默认条目上限（碎块防御）
    ///
    /// 沿用会话输出环块级惯例，本环量级下取 4096：
    /// 正常读块（KB 级）时字节容量先触发淘汰，本值只挡「一次 read 只回几字节」的病态
    /// 碎块场景——否则块数可堆到容量值，元数据开销反超数据本身。
    ///
    /// **前提是尾块合并**（见 [`PtyRing::push`]): 没有合并时，行式输出的 ~7 B/次
    /// 读块会先于字节容量撞上本上限（实测：声明 4 MiB 的会话环在产出 29 KiB 处
    /// 就开始淘汰）。合并后块数由容量决定（4 MiB → 256 块），本值回到「病态硬闸」。
    pub const DEFAULT_MAX_CHUNKS: usize = 4096;

    pub fn new(capacity_bytes: u64) -> Self {
        Self::with_limits(capacity_bytes, Self::DEFAULT_MAX_CHUNKS)
    }

    pub fn with_limits(capacity_bytes: u64, max_chunks: usize) -> Self {
        Self {
            chunks: VecDeque::with_capacity(max_chunks.min(4096)),
            min_offset: 0,
            max_offset: 0,
            resident_bytes: 0,
            capacity_bytes,
            max_chunks,
        }
    }

    /// 追加一段产出（生产端唯一入口，均摊 O(1)）
    ///
    /// **尾块合并**：尾块未达 [`COALESCE_TARGET`] 时把新段并进去，而不是「一次
    /// 读一块」。这不是优化而是**正确性前提**——PTY 主设备的一次 `read` 只返回
    /// 当时已到达的字节（行式输出实测 **~7 B/次**），若每次 push 都新开一块，
    /// 则 [`DEFAULT_MAX_CHUNKS`] 会在**字节容量远未用满**时先触发淘汰：
    /// 实测声明 4 MiB 的会话环在产出 29 KiB 处就开始淘汰（`min_offset=29062`
    /// ≈ 4096 × 7 B，2026-09-30 跨端压力测试），即「4 MiB 环」对行式输出实际
    /// 只相当于 28 KiB 环，每次淘汰都逼客户端清屏重锚。合并后块数由
    /// 「容量 / [`COALESCE_TARGET`]`」决定（4 MiB → 256 块），字节上限重新成为
    /// 唯一生效维度，`max_chunks` 退回它本来的定位：**病态场景的硬闸**。
    ///
    /// 合并不改变可观测语义：`fetch` 本就跨块合并，块边界对消费者不可见；游标、
    /// 偏移、淘汰与 `truncated` 语义全部不变（每块区间仍连续无重叠）。
    ///
    /// 淘汰规则不变：超字节容量或超条目上限时按最旧优先淘汰；单段即超容量时整环
    /// 腾清后仍保留该段——至少驻留一块，否则消费者的游标将永远落在驻留区间之外。
    pub fn push(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut rest = bytes;
        // ① 并入未满的尾块（仅大环启用；小环保持精确淘汰粒度，见 COALESCE_MIN_CAPACITY）
        let target = if self.capacity_bytes >= Self::COALESCE_MIN_CAPACITY {
            Self::COALESCE_TARGET
        } else {
            0
        };
        loop {
            let room = match self.chunks.back() {
                Some(tail) => target.saturating_sub(tail.bytes.len()),
                None => 0,
            };
            if room == 0 || rest.is_empty() {
                break;
            }
            while self.resident_bytes + 1 > self.capacity_bytes && self.chunks.len() > 1 {
                if !self.evict_oldest() {
                    break;
                }
            }
            let free = self.capacity_bytes.saturating_sub(self.resident_bytes) as usize;
            let take = room.min(rest.len()).min(free);
            if take == 0 {
                break;
            }
            let tail = self.chunks.back_mut().expect("刚判定过尾块存在");
            tail.bytes.extend_from_slice(&rest[..take]);
            self.max_offset = tail.start + tail.bytes.len() as u64;
            self.resident_bytes += take as u64;
            rest = &rest[take..];
            // 驻留起点不受影响（只动尾块）
        }
        if rest.is_empty() {
            return;
        }
        // ② 余量作为新块（先淘汰腾位）
        let len = rest.len() as u64;
        while self.resident_bytes + len > self.capacity_bytes || self.chunks.len() + 1 > self.max_chunks {
            if !self.evict_oldest() {
                break;
            }
        }
        let start = self.max_offset;
        self.chunks.push_back(RingChunk {
            start,
            bytes: rest.to_vec(),
        });
        self.resident_bytes += len;
        self.max_offset = start + len;
        // 淘汰后驻留起点前移；环此前为空时即本块起点
        self.min_offset = self.chunks.front().map(|chunk| chunk.start).unwrap_or(self.max_offset);
    }

    /// 淘汰最旧一块；返回 `false` = 环已空（调用方据此停止淘汰）
    fn evict_oldest(&mut self) -> bool {
        match self.chunks.pop_front() {
            Some(evicted) => {
                self.resident_bytes -= evicted.bytes.len() as u64;
                true
            }
            None => false,
        }
    }

    /// 从 `from_offset` 起拉取至多 `max_bytes` 字节（跨块合并，对消费者隐藏块边界）
    ///
    /// 游标钳位规则（全部路径都返回可用的 `next_offset`，调用方无需判错）：
    /// - 落后于 `min_offset`（数据已淘汰）→ 从 `min_offset` 起返回，`truncated = true`
    /// - 超前于 `max_offset`（非法/未来游标）→ 按「已追平」处理，回带 `max_offset` 自愈
    pub fn fetch(&self, from_offset: u64, max_bytes: usize) -> PtyRingFetch {
        let truncated = from_offset < self.min_offset;
        let start = from_offset.max(self.min_offset).min(self.max_offset);
        let end = self.max_offset.min(start.saturating_add(max_bytes as u64));
        if end <= start {
            return PtyRingFetch::empty(start, truncated);
        }

        // 块区间按序铺满 [min_offset, max_offset)，二分定位 start 所在块；
        // 下标一律饱和取值——环不变量被破坏时返回残缺区间而非 panic
        let mut data = Vec::with_capacity((end - start) as usize);
        let first = self.chunks.partition_point(|chunk| chunk.end() <= start);
        for chunk in self.chunks.iter().skip(first) {
            if chunk.start >= end {
                break;
            }
            let lo = start.saturating_sub(chunk.start).min(chunk.bytes.len() as u64) as usize;
            let hi = (end - chunk.start).min(chunk.bytes.len() as u64) as usize;
            if lo < hi {
                data.extend_from_slice(&chunk.bytes[lo..hi]);
            }
        }

        PtyRingFetch {
            data,
            next_offset: end,
            truncated,
        }
    }

    /// 驻留水印 `(min_offset, max_offset)`
    pub fn watermarks(&self) -> (u64, u64) {
        (self.min_offset, self.max_offset)
    }

    /// 驻留字节总量（淘汰后的实际可拉取字节数）
    pub fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    /// 驻留条目（字节块）数：`max_chunks` 维度的可观测面（淘汰归因用）
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

/// 输出汇：把读线程产出写入 [`PtyRing`]（插件私有 PTY 专用，业务链路不经此处）
pub struct PtyRingSink {
    ring: Arc<Mutex<PtyRing>>,
}

impl PtyRingSink {
    /// 创建配对的（输出汇, 环形缓冲），条目上限取 [`PtyRing::DEFAULT_MAX_CHUNKS`]
    pub fn paired(capacity_bytes: u64) -> (Arc<Self>, Arc<Mutex<PtyRing>>) {
        Self::paired_with_limits(capacity_bytes, PtyRing::DEFAULT_MAX_CHUNKS)
    }

    /// 创建配对的（输出汇, 环形缓冲），字节容量与条目上限均由调用方给定
    ///
    /// sink 交 `PtySession::with_private_sink` / `with_private_command`，ring 由宿主侧
    /// 按游标应答 `ring-fetch`；二者共享同一 `Arc<Mutex<PtyRing>>`。容量是**调用方
    /// 参数**（host-pty 由插件在 spawn config 里声明、宿主仲裁上限），不是编译期常量。
    pub fn paired_with_limits(capacity_bytes: u64, max_chunks: usize) -> (Arc<Self>, Arc<Mutex<PtyRing>>) {
        let ring = Arc::new(Mutex::new(PtyRing::with_limits(capacity_bytes, max_chunks)));
        let sink = Arc::new(Self {
            ring: Arc::clone(&ring),
        });
        (sink, ring)
    }
}

#[async_trait]
impl PtyOutputSink for PtyRingSink {
    async fn on_bytes(&self, bytes: Vec<u8>, _timestamp_ms: i64) {
        // 时间戳不入环：偏移即顺序，游标拉取不需要帧到达时刻
        // 锁中毒（持锁线程 panic）不连带打断产出链，取回内部值继续
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.push(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 可辨识负载：`tag` 重复 `len` 次，便于断言字节来自哪一次投递
    fn payload(tag: u8, len: usize) -> Vec<u8> {
        vec![tag; len]
    }

    fn ring_with_capacity(capacity: u64) -> PtyRing {
        PtyRing::new(capacity)
    }

    /// C-001 正例：单次投递后从头拉取，拿到全部字节且游标推进到产出端
    #[test]
    fn push_then_fetch_returns_all_bytes_and_advances_cursor() {
        let mut ring = ring_with_capacity(1024);
        ring.push(&payload(b'A', 10));

        let fetched = ring.fetch(0, 1024);
        assert_eq!(fetched.data, payload(b'A', 10));
        assert_eq!(fetched.next_offset, 10);
        assert!(!fetched.truncated);
        assert_eq!(ring.watermarks(), (0, 10));
        assert_eq!(ring.resident_bytes(), 10);
    }

    /// C-002 正例：按 `next_offset` 续拉，只得到新增字节（不重复已消费部分）
    #[test]
    fn fetch_from_next_offset_returns_only_new_bytes() {
        let mut ring = ring_with_capacity(1024);
        ring.push(&payload(b'A', 10));
        let first = ring.fetch(0, 1024);

        ring.push(&payload(b'B', 5));
        let second = ring.fetch(first.next_offset, 1024);

        assert_eq!(second.data, payload(b'B', 5));
        assert_eq!(second.next_offset, 15);
        assert!(!second.truncated);
    }

    /// C-003 边界：游标已追平产出端 → 空数据、游标不前进、不算淘汰
    #[test]
    fn fetch_at_produced_end_returns_empty_and_not_truncated() {
        let mut ring = ring_with_capacity(1024);
        ring.push(&payload(b'A', 10));

        let fetched = ring.fetch(10, 1024);
        assert!(fetched.data.is_empty());
        assert_eq!(fetched.next_offset, 10);
        assert!(!fetched.truncated);
    }

    /// C-004 边界：单次返回截断到 `max_bytes`，游标停在截断处（剩余留待下次）
    #[test]
    fn fetch_caps_data_at_max_bytes_and_keeps_cursor() {
        let mut ring = ring_with_capacity(1024);
        ring.push(&payload(b'A', 10));

        let fetched = ring.fetch(0, 4);
        assert_eq!(fetched.data, payload(b'A', 4));
        assert_eq!(fetched.next_offset, 4);
        assert!(!fetched.truncated);

        let rest = ring.fetch(4, 4);
        assert_eq!(rest.data, payload(b'A', 4));
        assert_eq!(rest.next_offset, 8);
    }

    /// C-005 正例：多次投递跨块合并，块边界对消费者不可见且顺序不变
    #[test]
    fn fetch_merges_chunks_in_produce_order() {
        let mut ring = ring_with_capacity(1024);
        ring.push(&payload(b'A', 3));
        ring.push(&payload(b'B', 4));
        ring.push(&payload(b'C', 5));

        let fetched = ring.fetch(0, 1024);
        assert_eq!(
            fetched.data,
            [payload(b'A', 3), payload(b'B', 4), payload(b'C', 5)].concat()
        );
        assert_eq!(fetched.next_offset, 12);

        // 跨块边界的半块拉取（游标 4 落在 B[3,7) 内部 → 裁头取 B 尾 3 字节 + C 头 2 字节）
        let middle = ring.fetch(4, 5);
        assert_eq!(middle.data, [payload(b'B', 3), payload(b'C', 2)].concat());
        assert_eq!(middle.next_offset, 9);
    }

    /// C-006 边界：驻留超容量即淘汰最旧块，`min_offset` 前移、`max_offset` 不回退
    #[test]
    fn push_beyond_capacity_evicts_oldest_chunks() {
        let mut ring = ring_with_capacity(10);
        ring.push(&payload(b'A', 4));
        ring.push(&payload(b'B', 4));

        // 4+4+4 > 10 → 最旧块淘汰，仅驻留 B、C
        ring.push(&payload(b'C', 4));

        assert_eq!(ring.watermarks(), (4, 12));
        assert_eq!(ring.resident_bytes(), 8);
        let fetched = ring.fetch(4, 1024);
        assert_eq!(fetched.data, [payload(b'B', 4), payload(b'C', 4)].concat());
        assert!(!fetched.truncated, "游标未落后于环起点时不得报淘汰");
    }

    /// C-007 反例（resync）：游标落后于环起点 → 从 `min_offset` 起返回并置 `truncated`
    #[test]
    fn fetch_behind_ring_start_reports_truncated_and_resumes_at_min_offset() {
        let mut ring = ring_with_capacity(8);
        ring.push(&payload(b'A', 4));
        ring.push(&payload(b'B', 4));
        // 容量 8、驻留已达 8 → 本段插入前淘汰 A，B、C 并存于 [4,12)
        ring.push(&payload(b'C', 4));

        let stale = ring.fetch(0, 1024);
        assert!(stale.truncated, "被淘汰的区间必须如实上报缺口");
        assert_eq!(stale.data, [payload(b'B', 4), payload(b'C', 4)].concat());
        assert_eq!(stale.next_offset, 12, "续拉游标应对齐实际返回区间末端");

        // 以纠正后的游标重试：缺口已消除
        let resynced = ring.fetch(stale.next_offset, 1024);
        assert!(resynced.data.is_empty());
        assert!(!resynced.truncated);
    }

    /// C-008 异常：未来游标钳到产出端（自愈、不 panic、不回退已有偏移）
    #[test]
    fn fetch_with_future_cursor_clamps_to_produced_end() {
        let mut ring = ring_with_capacity(64);
        ring.push(&payload(b'A', 6));

        let fetched = ring.fetch(999, 32);
        assert!(fetched.data.is_empty());
        assert_eq!(fetched.next_offset, 6);
        assert!(!fetched.truncated);

        // 钳位后照常产出可续拉
        ring.push(&payload(b'B', 2));
        assert_eq!(ring.fetch(6, 32).data, payload(b'B', 2));
    }

    /// C-009 边界：单段即超容量 → 整环腾清后仍驻留该段（游标仍可推进）
    #[test]
    fn push_larger_than_capacity_keeps_only_that_chunk() {
        let mut ring = ring_with_capacity(8);
        ring.push(&payload(b'A', 4));

        ring.push(&payload(b'B', 20));

        assert_eq!(ring.watermarks(), (4, 24));
        assert_eq!(ring.resident_bytes(), 20);
        let fetched = ring.fetch(0, 1024);
        assert!(fetched.truncated, "A 段已淘汰");
        assert_eq!(fetched.data, payload(b'B', 20));
    }

    /// C-010 边界：`max_bytes = 0` → 空数据且游标不前进（不吞掉任何字节）
    #[test]
    fn fetch_with_zero_max_bytes_returns_empty_without_advancing() {
        let mut ring = ring_with_capacity(64);
        ring.push(&payload(b'A', 6));

        let fetched = ring.fetch(2, 0);
        assert!(fetched.data.is_empty());
        assert_eq!(fetched.next_offset, 2);
        assert!(!fetched.truncated);
    }

    /// C-011 边界：空投递不产生块、不推进偏移、不影响水印
    #[test]
    fn push_empty_bytes_leaves_offsets_unchanged() {
        let mut ring = ring_with_capacity(64);
        ring.push(&payload(b'A', 6));

        ring.push(&[]);

        assert_eq!(ring.watermarks(), (0, 6));
        assert_eq!(ring.resident_bytes(), 6);
        assert_eq!(ring.chunks.len(), 1);
    }

    /// C-012 副作用：sink 投递**只**落自备环（ADR 0022 业务隔离）
    ///
    /// 票 11：原用例还断言「业务会话环零留痕」——那个环随 `session/` 目录删除，
    /// 「隔离」现在是结构事实（引擎环是唯一的输出环，sink 只持有它自己的那段）。
    /// 保留的部分断言了 sink ↔ ring 的配对契约与字节完整性。
    #[tokio::test]
    async fn ring_sink_delivers_only_to_its_own_ring() {
        let (sink, ring) = PtyRingSink::paired(1024);
        sink.on_bytes(payload(b'A', 3), 1000).await;
        sink.on_bytes(payload(b'B', 3), 1001).await;

        let guard = ring.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.fetch(0, 1024).data, [payload(b'A', 3), payload(b'B', 3)].concat());
        assert_eq!(guard.watermarks(), (0, 6), "自备环是这 6 字节的唯一去处");
    }

    /// C-013 并发：读线程写、宿主函数读，跨线程可见且总量守恒
    #[test]
    fn ring_is_visible_across_producer_and_consumer_threads() {
        let ring = Arc::new(Mutex::new(PtyRing::new(4096)));
        let producer_ring = Arc::clone(&ring);

        let producer = std::thread::spawn(move || {
            for tag in 0u8..10 {
                producer_ring
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(&payload(tag, 8));
            }
        });
        producer.join().expect("生产线程不得 panic");

        let guard = ring.lock().unwrap_or_else(|e| e.into_inner());
        let (min, max) = guard.watermarks();
        assert_eq!((min, max), (0, 80));
        let fetched = guard.fetch(0, 4096);
        let expected: Vec<u8> = (0u8..10).flat_map(|tag| payload(tag, 8)).collect();
        assert_eq!(fetched.data, expected);
        assert!(!fetched.truncated);
    }

    /// C-014 碎块防御：字节有余量、块数达上限时同样淘汰最旧（票 05 条目上限）
    ///
    /// 压满条目上限需要**超过合并目标**的单次 push（否则尾块会吸进去，见
    /// C-017）——这里用 18 KiB/次，块数维度才是唯一生效维度。
    #[test]
    fn chunk_count_cap_evicts_even_when_bytes_fit() {
        // 每段 18 KiB：超过合并目标 ⇒ 每次 push 自成一块（条目上限才能生效）
        const BIG: usize = PtyRing::COALESCE_TARGET + 1024;
        // 容量 256 KiB：6 × 18 KiB = 108 KiB 远未满（字节维度不触发）
        let mut ring = PtyRing::with_limits(256 * 1024, 4);
        for tag in 0u8..6 {
            ring.push(&payload(tag, BIG));
        }

        let (min, max) = ring.watermarks();
        assert_eq!(max, (6 * BIG) as u64, "产出偏移与条目上限无关，永不回退");
        assert_eq!(min, (2 * BIG) as u64, "只驻留最后 4 块（每块 18 KiB）");
        assert_eq!(ring.resident_bytes(), (4 * BIG) as u64, "块数被钳在上限内");
        assert_eq!(ring.chunk_count(), 4);

        let behind = ring.fetch(0, 1024 * 1024);
        assert!(behind.truncated, "块数淘汰同样造成缺口，必须如实上报");
        assert_eq!(
            behind.data,
            (2u8..6).flat_map(|tag| payload(tag, BIG)).collect::<Vec<u8>>()
        );
    }

    /// C-015 量级关系：正常块尺寸下字节容量先触发，条目上限不参与（不误伤历史深度）
    #[test]
    fn byte_cap_evicts_before_chunk_cap_at_normal_chunk_sizes() {
        let mut ring = PtyRing::with_limits(32, 4096);
        for tag in 0u8..4 {
            ring.push(&payload(tag, 16));
        }

        let (min, max) = ring.watermarks();
        assert_eq!((min, max), (32, 64), "字节容量 32 生效：只驻留最后两块");
        assert_eq!(
            ring.chunk_count(),
            2,
            "容量 32 < COALESCE_MIN_CAPACITY ⇒ 不合并，保持精确淘汰粒度；\
             块数远低于上限，条目维度不参与淘汰"
        );
    }

    /// C-017 行式输出回归：极短 push 在字节容量用满前**不得**触发淘汰
    ///
    /// 实测缺陷（2026-09-30 跨端压力测试）：PTY 主设备一次 `read` 只返回已到达的
    /// 字节，行式输出实测 ~7 B/次。原实现「一次 push 一块」+ 固定 4096 块上限，
    /// 使得声明 4 MiB 的会话环在产出 29 KiB 处就开始淘汰（客户端每次被逼清屏重锚）。
    /// 本用例在修复前必然红（`min_offset` 会是 28672 = 4096 × 7）。
    #[test]
    fn tiny_pushes_reach_full_byte_capacity_before_any_eviction() {
        const PUSHES: usize = 200_000; // 200k 次 ~7 B 短读 = 1.33 MiB
        let mut ring = PtyRing::with_limits(4 * 1024 * 1024, PtyRing::DEFAULT_MAX_CHUNKS);
        for i in 0..PUSHES {
            ring.push(&payload((i % 251) as u8, 7));
        }

        let (min, max) = ring.watermarks();
        assert_eq!(
            min, 0,
            "字节容量未满时不得淘汰：有效驻留窗口必须等于声明容量，否则慢消费者 \
             被无谓地逼进重锚（历史教训：会话输出环的固定块数上限）"
        );
        assert_eq!(max, (PUSHES * 7) as u64, "产出偏移 = 全部短读之和，不丢字节");
        assert_eq!(ring.resident_bytes(), (PUSHES * 7) as u64, "驻留字节 = 产出字节");
        assert!(
            ring.chunk_count() <= 4 * 1024 * 1024 / PtyRing::COALESCE_TARGET + 1,
            "块数由「容量 / 合并目标」决定（4 MiB → ≤257），不得回到「一次 push 一块」：{}",
            ring.chunk_count()
        );
    }

    /// C-019 合并 + 淘汰 叠加下的字节级连续性：慢消费者按游标续拉，序列不得有洞
    ///
    /// 盯的是「合并把块变粗」与「淘汰只能整块丢」叠加后的行为：游标停在原地、
    /// 产出继续推进到多次淘汰之后，消费者必须**自缺口处续上**且与产出逐字节相等。
    /// 若合并实现的容量/游标记账有偏差，这里会报长度不等或中间缺口。
    #[test]
    fn coalescing_with_eviction_keeps_stream_byte_exact() {
        const CAPACITY: u64 = 64 * 1024; // ≥ COALESCE_MIN_CAPACITY ⇒ 合并启用
        const PUSHES: usize = 20_000; // 20k × 7 B = 140 KB ⇒ 淘汰 2 轮以上
        let mut ring = PtyRing::new(CAPACITY);
        let mut expected: Vec<u8> = Vec::new();
        for i in 0..PUSHES {
            let chunk = payload((i % 251) as u8, 7);
            ring.push(&chunk);
            expected.extend_from_slice(&chunk);
        }

        let (min, max) = ring.watermarks();
        let total = expected.len() as u64;
        // 驻留量不得超过声明容量（淘汰只能整块丢 ⇒ 实际驻留可能**小于**容量，
        // 过冲上限 = 一个合并块；这是「合并换取块数可控」的已知代价）
        assert!(
            ring.resident_bytes() <= CAPACITY,
            "驻留字节不得超过声明容量：{} > {CAPACITY}",
            ring.resident_bytes()
        );
        assert_eq!(max - min, ring.resident_bytes(), "偏移差必须等于驻留字节（记账自洽）");
        assert!(min >= total - CAPACITY, "淘汰不得少于溢出量（min={min}）");
        assert!(min < total, "环不得被清空");
        // ① 游标落后于驻留起点 ⇒ 必须报缺口（淘汰的诚实性），且从 min_offset 起续
        let behind = ring.fetch(0, 4 * 1024);
        assert!(behind.truncated, "已被淘汰的字节必须如实上报，不得静默补洞");
        assert_eq!(behind.next_offset, min + 4096, "从驻留起点起返回，且不超过请求上限");

        // ② 自驻留起点续拉到底：必须与产出对应区间逐字节相等
        let mut cursor = min;
        let mut got: Vec<u8> = Vec::new();
        let mut pulls = 0;
        while cursor < max {
            let f = ring.fetch(cursor, 4 * 1024);
            assert!(!f.truncated, "游标已在驻留区内，不得再报缺口");
            assert!(f.next_offset > cursor, "游标必须推进（防空转）");
            got.extend_from_slice(&f.data);
            cursor = f.next_offset;
            pulls += 1;
            assert!(pulls < 1000, "续拉不得空转");
        }
        assert_eq!(
            got,
            expected[min as usize..],
            "自驻留起点拿到的字节必须与产出对应区间逐字节相等（合并不得造成空洞/错位）"
        );
    }

    /// C-018 合并的字节级保真：短读与大块交替时，序列逐字节不变、游标单调推进
    #[test]
    fn coalescing_preserves_byte_exact_sequence_and_cursor_progress() {
        // 容量必须**大于**总产出（否则会淘汰，`truncated` 是预期行为而非本用例对象）
        let mut ring = PtyRing::new(1024 * 1024);
        let mut expected: Vec<u8> = Vec::new();
        for round in 0..8u8 {
            // 短读段（7 B，模拟行式输出）
            let small = payload(round, 7);
            ring.push(&small);
            expected.extend_from_slice(&small);
            // 大块段（20 KiB，超过合并目标 → 自成一块）
            let big = payload(round.wrapping_add(100), 20 * 1024);
            ring.push(&big);
            expected.extend_from_slice(&big);
        }

        // 逐块按游标取回，必须与期望序列逐字节相等（合并不得错位 / 重叠 / 丢字节）
        let mut cursor = 0u64;
        let mut got: Vec<u8> = Vec::new();
        while cursor < expected.len() as u64 {
            let f = ring.fetch(cursor, 16 * 1024);
            assert!(!f.truncated, "容量充足不得报缺口");
            assert!(f.next_offset > cursor, "游标必须单调推进（防空转）");
            assert!(f.data.len() <= 16 * 1024, "单次取数不超过请求上限");
            cursor = f.next_offset;
            got.extend_from_slice(&f.data);
        }
        assert_eq!(got, expected, "合并后字节序列必须与产出逐字节相等");
        assert_eq!(ring.watermarks().1, expected.len() as u64);
    }

    /// C-016 多消费者：一个消费者的读取不释放空间、不影响他人游标（票 05 契约，
    /// 07 的输入）
    ///
    /// `fetch` 是纯读（不消费、不推进全局状态），淘汰由**产出量**驱动（环满即淘汰
    /// 最旧）——快消费者读完不改变慢消费者的驻留窗口：慢消费者（游标未动）落后即
    /// `truncated`，快消费者按自己游标续拉不受影响。
    #[test]
    fn reads_by_one_consumer_do_not_extend_another_consumers_window() {
        let mut ring = ring_with_capacity(16);
        ring.push(&payload(b'A', 8));
        let fast = ring.fetch(0, 1024).next_offset; // 快消费者读走全部，自持游标 = 8
        assert_eq!(fast, 8);

        // 快消费者的读取不为慢消费者保留空间：继续产出溢过容量，A 被淘汰
        ring.push(&payload(b'B', 8));
        ring.push(&payload(b'C', 8)); // 24 > 16 → 淘汰 A；驻留 [8,24)

        let slow = ring.fetch(0, 1024);
        assert!(slow.truncated, "慢消费者（游标 0 未动）落后即报缺口——读取不共享窗口");
        assert_eq!(slow.data, [payload(b'B', 8), payload(b'C', 8)].concat());
        assert_eq!(slow.next_offset, 24);

        // 快消费者以自己游标续拉：不因慢消费者落后而受影响，也不重复
        let fast_rest = ring.fetch(fast, 1024);
        assert!(!fast_rest.truncated, "快消费者游标仍在驻留区间内");
        assert_eq!(fast_rest.data, [payload(b'B', 8), payload(b'C', 8)].concat());
        assert_eq!(fast_rest.next_offset, 24);
    }
}
