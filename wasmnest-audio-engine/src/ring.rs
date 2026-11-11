//! 帧环形缓冲（消费侧唯一的历史窗口，纯拉取模型的数据底座）
//!
//! ## 为什么是这个形态
//!
//! 采集回调是**实时线程**：它只能做「解码 → 归一 → 追加到环」这一件事，既不能等待
//! 消费者，也不能因为消费者慢而放慢（麦克风不会等你）。所以本环与 host-pty 的输出环
//! 同判据：**源零等待**，驻留超容量即淘汰最旧字节，落后消费者的缺口用 `truncated`
//! 如实上报（背压绝不回传到采集线程）。
//!
//! 与 PTY 环的差别只有一处，且是数据形状决定的：PTY 产出是**变长短读**（行式输出实测
//! ~7 B/次），所以那边需要「尾块合并」来保证字节容量而不是块数先触发淘汰；本引擎产出是
//! **定长帧**（交错 S16LE，一次追加整数帧），于是不需要块表，直接用字节粒度的环形缓冲：
//!
//! - 淘汰粒度 = 1 帧（对齐后）→ 驻留窗口精确等于声明容量，没有「合并块过冲」导致的历史
//!   过抛（PTY 侧那个 0.4% 的代价在这里是 0）。
//! - 追加 = 至多两次 `memcpy`，无 compaction、无分配 → 满足实时线程纪律。
//!
//! ## 偏移语义
//!
//! 全部偏移是**自流起的绝对字节偏移**，单调递增、永不因淘汰回退（`end()`），停 / 起
//! 也不清零（见 `engine`：重启只复位重采样相位与电平窗口，历史与游标连续性不变）。
//! `residency_start() = end() - usage()` 是驻留最旧字节位置。
//!
//! ## 帧对齐契约
//!
//! [`FrameRing::fetch`] 把起、损两端都对齐到帧边界（[`FrameRing::frame_bytes`]），因此
//! 消费者永远拿不到「半个样本」——交错 PCM 里半样本无法解释，ASR 侧还要按样本计数。
//! 对齐方向刻意选**向下取整**：宁可重交一小帧（消费者按游标去重），也不静默丢掉字节。
//! 前提是不变量「追加的都是整数帧」——由归一管线保证（`PcmNormalizer` 只输出整帧），
//! 追加非整帧字节时余数照样入环，但对齐窗口会把它当成不完整帧对待。

use crate::error::AudioError;

/// 一次拉取的结果（对应 WIT `ring-fetch-result`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingFetch {
    /// 本次返回的字节，区间为 `[实际起点, next_offset)`，长度是帧的整数倍
    pub data: Vec<u8>,
    /// 下一次拉取应传的游标（帧对齐）
    pub next_offset: u64,
    /// 请求游标落后于驻留起点 → 中间有字节已被淘汰，调用方需按 `next_offset` 重建上下文
    pub truncated: bool,
}

/// 帧宽上界（字节）
///
/// 本引擎实际用到的最宽帧 = 2 声道 × S16 = 4 字节；留到 64 是给「宿主自带更宽帧格式」
/// 的扩展位。上界存在是为了让 [`FrameRing`] 的不足一帧寄存走**栈上定长数组**而不是
/// `Vec`——实时线程的写入口不做分配。
pub const MAX_FRAME_BYTES: usize = 64;

/// 有界字节环形缓冲（帧对齐的多读者游标拉取）
///
/// 内部是一段固定容量的 `Vec<u8>` + 队首下标 + 累计写入量：容量在构造时定死，
/// 之后**不再分配**（淘汰靠覆盖，不靠重排）。
pub struct FrameRing {
    buf: Vec<u8>,
    /// 驻留最旧字节在 `buf` 里的下标
    head: usize,
    /// 驻留字节数（恒为帧宽整数倍）
    len: usize,
    /// 累计写入字节（= 产出端绝对偏移，单调；恒为帧宽整数倍）
    written: u64,
    /// 一帧字节数（1..=`MAX_FRAME_BYTES`）
    frame_bytes: usize,
    /// 尚未凑满一帧的尾字节（稳态为空，见 [`FrameRing::append`]）
    residue: [u8; MAX_FRAME_BYTES],
    /// `residue` 的有效长度
    residue_len: usize,
}

impl FrameRing {
    /// 以字节容量与帧宽构造
    ///
    /// 容量按帧取整（向下）：非整帧的尾字节无法驻留，宁可让窗口短一帧也不留下
    /// 「半个样本驻留在环里」这种解释不定的状态。
    ///
    /// # Errors
    /// [`AudioError::InvalidConfig`] —— `frame_bytes` 为 0 或超 [`MAX_FRAME_BYTES`]，
    /// 或 `capacity_bytes` 不足一帧。
    pub fn new(capacity_bytes: usize, frame_bytes: usize) -> Result<Self, AudioError> {
        if frame_bytes == 0 || frame_bytes > MAX_FRAME_BYTES {
            return Err(AudioError::InvalidConfig {
                reason: format!("frame_bytes {frame_bytes} is outside 1..={MAX_FRAME_BYTES}"),
            });
        }
        let capacity = capacity_bytes / frame_bytes * frame_bytes;
        if capacity == 0 {
            return Err(AudioError::InvalidConfig {
                reason: format!(
                    "ring capacity {capacity_bytes} bytes is smaller than one frame ({frame_bytes} bytes)"
                ),
            });
        }
        Ok(Self {
            buf: vec![0u8; capacity],
            head: 0,
            len: 0,
            written: 0,
            frame_bytes,
            residue: [0u8; MAX_FRAME_BYTES],
            residue_len: 0,
        })
    }

    /// 一帧字节数（消费者据此把游标对齐到帧边界）
    pub const fn frame_bytes(&self) -> usize {
        self.frame_bytes
    }

    /// 字节容量（构造时按帧取整后的实际值）
    pub const fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// 驻留字节数（实际可拉取的历史量）
    pub const fn usage(&self) -> usize {
        self.len
    }

    /// 产出端绝对偏移（单调递增，永不回退）
    pub const fn end(&self) -> u64 {
        self.written
    }

    /// 驻留起点（最旧可拉字节偏移）
    pub fn residency_start(&self) -> u64 {
        self.written - self.len as u64
    }

    /// 累计淘汰（含覆盖写丢弃）字节数 = 驻留起点
    pub fn dropped(&self) -> u64 {
        self.residency_start()
    }

    /// 追加一段产出（采集线程唯一写入口，均摊 O(帧数)）
    ///
    /// 只驻留**整帧**：不足一帧的尾字节先进 `residue`（宽 < `frame_bytes`），下次追加
    /// 时补齐——这使「`written` / 驻留起点 / 返回长度都是帧的整数倍」成为**结构事实**
    /// 而非调用方约定，`fetch` 因此不需要任何防错位钳位（也就没有减到负数的 panic 面）。
    /// 稳态下归一管线恒交整帧，`residue` 全程为空 ⇒ 无额外拷贝。
    ///
    /// 返回**本次掉出驻留窗口的字节数**（= 驻留起点位移量，仅供日志 / 指标；正确性不
    /// 依赖它：缺口由 `fetch` 的 `truncated` 表达）。单段即超容量时只驻留其**尾部**
    /// `capacity` 字节——至少留一块，否则消费者游标将永远落在驻留区间之外。
    pub fn append(&mut self, bytes: &[u8]) -> usize {
        let mut src = bytes;
        let mut dropped = 0usize;

        if self.residue_len > 0 {
            let need = self.frame_bytes - self.residue_len;
            let fill = need.min(src.len());
            self.residue[self.residue_len..self.residue_len + fill].copy_from_slice(&src[..fill]);
            self.residue_len += fill;
            src = &src[fill..];
            if self.residue_len < self.frame_bytes {
                return dropped; // 仍不足一帧：整段继续寄存，不推进偏移
            }
            // 帧补齐：把寄存段 + 本次填充段搬到栈上一次性入环（无分配）
            let mut frame = [0u8; MAX_FRAME_BYTES];
            frame[..self.residue_len].copy_from_slice(&self.residue[..self.residue_len]);
            self.residue_len = 0;
            dropped += self.write_raw(&frame[..self.frame_bytes]);
        }

        let aligned = src.len() / self.frame_bytes * self.frame_bytes;
        if aligned > 0 {
            dropped += self.write_raw(&src[..aligned]);
        }
        if aligned < src.len() {
            let rest = src.len() - aligned;
            self.residue[..rest].copy_from_slice(&src[aligned..]);
            self.residue_len = rest;
        }
        dropped
    }

    /// 写入一段**整帧**字节（`bytes.len()` 为帧宽整数倍）
    ///
    /// 至多两次 `memcpy`，无分配、无重排；淘汰 = 覆盖最旧（环满时新写入的尾段正是
    /// 被覆盖的最旧段），故 head 只需按淘汰量前移。
    fn write_raw(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len();
        if n == 0 {
            return 0;
        }
        let capacity = self.buf.len();
        let start_before = self.residency_start();
        if n >= capacity {
            // 整环被本段覆盖：只留尾段，head 归零（后续追加从环首开始写）
            self.buf.copy_from_slice(&bytes[n - capacity..]);
            self.head = 0;
            self.len = capacity;
        } else {
            // 写入区 = 驻留窗口之后的 n 格（可能回绕，回绕段必然落在环首）
            let write_at = (self.head + self.len) % capacity;
            let first = (capacity - write_at).min(n);
            self.buf[write_at..write_at + first].copy_from_slice(&bytes[..first]);
            if first < n {
                self.buf[..n - first].copy_from_slice(&bytes[first..]);
            }
            let evict = (self.len + n).saturating_sub(capacity);
            self.head = (self.head + evict) % capacity;
            self.len = (self.len + n).min(capacity);
        }
        self.written += n as u64;
        (self.residency_start() - start_before) as usize
    }

    /// 从 `from_offset` 起拉取至多 `max_bytes` 字节
    ///
    /// 游标钳位（全部路径都返回可用的 `next_offset`，调用方无需判错）：
    /// - 落后于驻留起点（已淘汰）→ 从驻留起点起返回，`truncated = true`
    /// - 超前于产出端（未来游标）→ 按「已追平」处理，回带产出端自愈
    ///
    /// 起、损两端都向下对齐到帧边界（[`FrameRing::append`] 保证所有边界都在帧格上）。
    /// 对齐方向刻意选**向下**：宁可让调用方多拿一小帧（按游标去重），也不静默丢字节。
    pub fn fetch(&self, from_offset: u64, max_bytes: usize) -> RingFetch {
        let resident_start = self.residency_start();
        let requested = self.floor_to_frame_u64(from_offset);
        let truncated = requested < resident_start;
        let start = requested.max(resident_start).min(self.written);
        let cap = self.floor_to_frame_u64(max_bytes as u64);
        let end = (start + cap).min(self.written);
        if end <= start {
            return RingFetch {
                data: Vec::new(),
                next_offset: start,
                truncated,
            };
        }
        RingFetch {
            data: self.slice(start, end),
            next_offset: end,
            truncated,
        }
    }

    /// 取绝对偏移区间 `[from, to)` 的字节（区间由调用方保证落在驻留范围内）
    fn slice(&self, from: u64, to: u64) -> Vec<u8> {
        let capacity = self.buf.len();
        let lo = (from - self.residency_start()) as usize;
        let len = (to - from) as usize;
        let begin = (self.head + lo) % capacity;
        let first = (capacity - begin).min(len);
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&self.buf[begin..begin + first]);
        if first < len {
            out.extend_from_slice(&self.buf[..len - first]);
        }
        out
    }

    /// 向下对齐到帧边界（偏移即「帧号 × 帧宽」，保证不越过环起/末）
    fn floor_to_frame_u64(&self, value: u64) -> u64 {
        value / self.frame_bytes as u64 * self.frame_bytes as u64
    }
}

#[cfg(test)]
mod tests {
    use super::FrameRing;

    /// 16 k 单声道 S16LE：一帧 2 字节
    const FRAME: usize = 2;

    fn ring(capacity: usize) -> FrameRing {
        FrameRing::new(capacity, FRAME).expect("测试容量恒 ≥ 一帧")
    }

    fn tagged(tag: u8, frames: usize) -> Vec<u8> {
        vec![tag; frames * FRAME]
    }

    /// R-001 反例：帧宽为 0 / 超上界 / 容量不足一帧当场拒，不静默造一个用不了的环
    #[test]
    fn construction_rejects_degenerate_sizes() {
        let err = FrameRing::new(1024, 0)
            .err()
            .expect("frame_bytes=0 必须被拒");
        assert!(
            err.to_string().contains("frame_bytes"),
            "错误必须点名非法字段，got: {err}"
        );
        assert!(FrameRing::new(1024, super::MAX_FRAME_BYTES + 1).is_err());
        let err = FrameRing::new(1, FRAME)
            .err()
            .expect("不足一帧的容量必须被拒");
        assert!(err.to_string().contains("smaller than one frame"));
    }

    /// R-002 边界：容量按帧取整（奇数字节容量留不下半帧）
    #[test]
    fn capacity_is_rounded_down_to_whole_frames() {
        let ring = FrameRing::new(9, 4).expect("9 字节含两整帧");
        assert_eq!(ring.capacity(), 8, "尾半帧不留驻，窗口只短不坏");
    }

    /// R-003 正例：追加后从头拉取拿到全部字节，游标推进到产出端
    #[test]
    fn append_then_fetch_returns_all_bytes() {
        let mut ring = ring(64);
        assert_eq!(ring.append(&tagged(b'A', 10)), 0, "未满不淘汰");
        let fetched = ring.fetch(0, 64);
        assert_eq!(fetched.data, tagged(b'A', 10));
        assert_eq!(fetched.next_offset, 20);
        assert!(!fetched.truncated);
        assert_eq!((ring.residency_start(), ring.end()), (0, 20));
        assert_eq!(ring.usage(), 20);
    }

    /// R-004 正例：按 `next_offset` 续拉只得到新增字节（游标契约）
    #[test]
    fn follow_up_fetch_returns_only_new_bytes() {
        let mut ring = ring(64);
        ring.append(&tagged(b'A', 10));
        let first = ring.fetch(0, 64);
        ring.append(&tagged(b'B', 5));
        let second = ring.fetch(first.next_offset, 64);
        assert_eq!(second.data, tagged(b'B', 5));
        assert_eq!(second.next_offset, 30);
        assert!(!second.truncated);
    }

    /// R-005 边界：单次上限截断，游标停在截断处（剩余留待下次）
    #[test]
    fn fetch_caps_at_max_bytes() {
        let mut ring = ring(64);
        ring.append(&tagged(b'A', 20));
        let fetched = ring.fetch(0, 10);
        assert_eq!(fetched.data, tagged(b'A', 5), "10 字节 = 5 帧");
        assert_eq!(fetched.next_offset, 10);
        let rest = ring.fetch(10, 1024);
        assert_eq!(rest.data.len(), 30, "剩余 15 帧");
        assert_eq!(rest.next_offset, 40);
    }

    /// R-006 边界：`max_bytes` 非整帧时向下取整，绝不交出半样本
    #[test]
    fn fetch_never_returns_half_a_frame() {
        let mut ring = ring(64);
        ring.append(&tagged(b'A', 10));
        // 帧宽 2：请求奇数字节 → 只给偶数
        let fetched = ring.fetch(0, 7);
        assert_eq!(fetched.data.len(), 6, "奇数请求向下对齐到 3 帧");
        assert_eq!(fetched.next_offset, 6);

        // 4 字节帧宽更明显
        let mut wide = FrameRing::new(64, 4).expect("64 含 16 帧");
        wide.append(&[b'A'; 16]);
        assert_eq!(wide.fetch(0, 6).data.len(), 4, "6 字节只够一整帧");
        // 游标 2 向下对齐到 0（帧网格），因此拿到全部 16 字节；游标 6 对齐到 4
        assert_eq!(
            wide.fetch(2, 1024).data.len(),
            16,
            "非对齐游标向下取整到帧首"
        );
        assert_eq!(wide.fetch(6, 1024).data.len(), 12, "游标 6 → 帧首 4");
    }

    /// R-007 正例：超容量覆盖最旧，驻留窗口精确等于容量（无块过冲）
    #[test]
    fn append_beyond_capacity_overwrites_oldest() {
        let mut ring = ring(16);
        ring.append(&tagged(b'A', 4)); // 8 字节
        ring.append(&tagged(b'B', 4)); // 8 字节 → 满 16
        assert_eq!(ring.usage(), 16);
        assert_eq!(ring.append(&tagged(b'C', 4)), 8, "淘汰 A 段 8 字节");

        assert_eq!((ring.residency_start(), ring.end()), (8, 24));
        assert_eq!(ring.dropped(), 8);
        let fetched = ring.fetch(8, 1024);
        assert_eq!(fetched.data, [tagged(b'B', 4), tagged(b'C', 4)].concat());
        assert!(!fetched.truncated, "游标未落后于驻留起点不得报缺口");
    }

    /// R-008 正例（resync）：游标落后于驻留起点 → 从驻留起点起返回并置 `truncated`
    #[test]
    fn stale_cursor_reports_truncated_and_resumes_at_residency_start() {
        let mut ring = ring(16);
        for tag in *b"ABC" {
            ring.append(&tagged(tag, 4));
        }
        let stale = ring.fetch(0, 1024);
        assert!(stale.truncated, "被淘汰区间必须如实上报");
        assert_eq!(stale.data, [tagged(b'B', 4), tagged(b'C', 4)].concat());
        assert_eq!(stale.next_offset, 24);
        let resynced = ring.fetch(stale.next_offset, 1024);
        assert!(resynced.data.is_empty());
        assert!(!resynced.truncated, "纠正后的游标已在驻留区内");
    }

    /// R-009 异常：未来游标钳到产出端（自愈、不 panic、不回退）
    #[test]
    fn future_cursor_clamps_to_produced_end() {
        let mut ring = ring(64);
        ring.append(&tagged(b'A', 6));
        let fetched = ring.fetch(9_000, 32);
        assert!(fetched.data.is_empty());
        assert_eq!(fetched.next_offset, 12, "回带产出端，供调用方自纠");
        assert!(!fetched.truncated);
        ring.append(&tagged(b'B', 2));
        assert_eq!(ring.fetch(12, 32).data, tagged(b'B', 2));
    }

    /// R-010 边界：单段即超容量 → 只驻留其尾部整帧（游标仍可推进）
    #[test]
    fn oversized_append_keeps_only_its_tail() {
        let mut ring = ring(16);
        ring.append(&tagged(b'A', 4));
        assert_eq!(
            ring.append(&tagged(b'B', 20)),
            32,
            "A 全掉出 + B 前 12 帧被覆盖"
        );
        assert_eq!(ring.usage(), 16);
        assert_eq!((ring.residency_start(), ring.end()), (32, 48));
        let fetched = ring.fetch(0, 1024);
        assert!(fetched.truncated);
        assert_eq!(fetched.data, tagged(b'B', 8), "只剩 B 的最后 8 帧");
    }

    /// R-011 边界：空追加零副作用；`max_bytes = 0` 零返回且游标不前进
    #[test]
    fn empty_operations_are_no_ops() {
        let mut ring = ring(64);
        ring.append(&tagged(b'A', 6));
        assert_eq!(ring.append(&[]), 0);
        assert_eq!(
            (ring.residency_start(), ring.end(), ring.usage()),
            (0, 12, 12)
        );
        let fetched = ring.fetch(4, 0);
        assert!(fetched.data.is_empty());
        assert_eq!(fetched.next_offset, 4, "0 上限不吞字节、不推进游标");
    }

    /// R-012 回绕正确性：head≠0 时跨越环尾的写入与读取逐字节正确
    ///
    /// 环容量 16、每轮追加 12 字节 ⇒ 每轮 head 前移 4（模 16），第 2 轮起写入必然
    /// 分两段（尾段 + 回绕段），读取区间同样可能跨尾。
    #[test]
    fn wraparound_write_and_read_are_byte_exact() {
        let mut ring = ring(16);
        let mut expected: Vec<u8> = Vec::new();
        // 11 轮 = 132 字节（每轮 12 字节 × 11）；刻意避开 12 轮（head 恰好回到 0，
        // 那样本用例就退化成非回绕路径，等于没测）
        for i in 0u8..11 {
            let chunk = tagged(i, 6); // 12 字节 = 6 帧
            ring.append(&chunk);
            expected.extend_from_slice(&chunk);
        }
        let (start, end) = (ring.residency_start(), ring.end());
        assert_eq!((start, end), (116, 132), "只驻留最后 16 字节");
        assert!(ring.head != 0, "本用例必须处在 head≠0 的回绕状态");

        let fetched = ring.fetch(start, 1024);
        assert_eq!(
            fetched.data,
            expected[start as usize..end as usize],
            "跨越环尾的回绕读写必须逐字节对齐"
        );
    }

    /// R-013 多消费者：读取不消费、不推进他人游标，窗口只由产出驱动
    #[test]
    fn reads_do_not_move_another_consumers_cursor() {
        let mut ring = ring(16);
        ring.append(&tagged(b'A', 4));
        let fast = ring.fetch(0, 1024).next_offset;
        ring.append(&tagged(b'B', 4));
        ring.append(&tagged(b'C', 4)); // 24 > 16 → A 被淘汰

        let slow = ring.fetch(0, 1024);
        assert!(slow.truncated, "慢消费者落后即报缺口：读取不共享窗口");
        assert_eq!(slow.data, [tagged(b'B', 4), tagged(b'C', 4)].concat());

        let fast_rest = ring.fetch(fast, 1024);
        assert!(!fast_rest.truncated, "快消费者游标仍在驻留区内");
        assert_eq!(fast_rest.data, [tagged(b'B', 4), tagged(b'C', 4)].concat());
    }

    /// R-014 不变量：长时间「边产边拉」后，偏移单调、窗口自洽、取回字节与产出序列
    /// 在**绝对偏移**上一一对应（缺口只以 truncated 存在，绝不错位）
    #[test]
    fn invariants_hold_under_a_long_mixed_sequence() {
        let mut ring = ring(32);
        let mut expected: Vec<u8> = Vec::new();
        let mut last_written = 0u64;
        let mut cursor = 0u64;
        for round in 0..500u32 {
            let frames = (round % 7) as usize + 1;
            let chunk = tagged((round % 251) as u8, frames);
            ring.append(&chunk);
            expected.extend_from_slice(&chunk);

            assert!(ring.usage() <= ring.capacity());
            assert_eq!(
                ring.end() - ring.residency_start(),
                ring.usage() as u64,
                "偏移差必须等于驻留字节（记账自洽）"
            );
            assert!(ring.end() >= last_written, "产出端偏移不得回退");
            last_written = ring.end();

            if round % 2 != 1 {
                continue;
            }
            let fetched = ring.fetch(cursor, 12);
            assert!(fetched.next_offset >= cursor, "续拉游标不得倒退");
            assert_eq!(fetched.data.len() % FRAME, 0, "返回长度必须是整帧");
            assert!(fetched.data.len() <= 12);
            // 实际起点 = 请求游标钳位后；返回字节必须等于产出序列该区间切片
            let used_start = fetched.next_offset - fetched.data.len() as u64;
            assert_eq!(
                fetched.data,
                expected[used_start as usize..fetched.next_offset as usize],
                "第 {round} 轮取回字节与产出区间不对应"
            );
            if used_start > cursor {
                assert!(fetched.truncated, "游标被前移必然是因为落后于驻留起点");
            }
            cursor = fetched.next_offset;
        }
        // 收尾：追平后应当无新数据，且不算缺口
        let tail = ring.fetch(cursor, 1024);
        assert_eq!(tail.next_offset, ring.end());
        assert!(!tail.truncated || cursor < ring.residency_start());
    }

    /// R-015 帧对齐是**结构事实**：逐字节投喂与整帧投喂得到完全相同的可拉取序列
    ///
    /// 盯的是「不足一帧的尾字节先进寄存、绝不进环」这条不变量——若尾字节被当成
    /// 驻留数据，`fetch` 的帧网格会整体错位，消费者拿到的就是噪声。
    #[test]
    fn byte_by_byte_feeding_matches_whole_frame_feeding() {
        let mut trickle = FrameRing::new(32, 4).expect("32 含 8 帧");
        let mut whole = FrameRing::new(32, 4).expect("32 含 8 帧");
        let stream: Vec<u8> = (0u8..24).collect();
        for byte in &stream {
            trickle.append(&[*byte]);
        }
        for chunk in stream.chunks(8) {
            whole.append(chunk);
        }

        assert_eq!(trickle.end(), 24, "24 字节 = 6 整帧，全部最终入环");
        assert_eq!(trickle.residue_len, 0, "整帧结尾不留寄存");
        assert_eq!(whole.end(), 24);
        let a = trickle.fetch(0, 1024);
        let b = whole.fetch(0, 1024);
        assert_eq!(a.data, b.data, "投喂粒度不得改变取回字节");
        assert_eq!(a.next_offset, b.next_offset);

        // 奇数尾字节只寄存，不推进产出端
        let mut partial = FrameRing::new(32, 4).expect("32 含 8 帧");
        partial.append(&[1, 2, 3, 4, 5]);
        assert_eq!(partial.end(), 4, "第 5 字节尚未凑满一帧");
        assert_eq!(partial.fetch(0, 1024).data, vec![1, 2, 3, 4]);
        partial.append(&[6]);
        assert_eq!(partial.end(), 4, "两字节仍不足一帧：产出端不动");
        assert!(partial.fetch(4, 1024).data.is_empty());
        partial.append(&[7, 8]);
        assert_eq!(partial.end(), 8, "凑满第 2 帧后入环");
        assert_eq!(partial.fetch(4, 1024).data, vec![5, 6, 7, 8]);
    }

    /// R-016 游标钳位在帧网格上：非对齐游标向下取整，绝不返回环外字节
    #[test]
    fn misaligned_cursors_never_escape_the_residency_window() {
        let mut ring = FrameRing::new(32, 8).expect("32 含 4 帧");
        for tag in 0u8..8 {
            ring.append(&[tag; 8]);
        }
        // 产出 64 字节 > 容量 32 ⇒ 驻留 [32, 64)
        assert_eq!((ring.residency_start(), ring.end()), (32, 64));
        for cursor in [0u64, 1, 5, 31, 33, 37, 63, 65, 1_000] {
            let fetched = ring.fetch(cursor, 1_000);
            assert_eq!(fetched.data.len() % 8, 0, "游标 {cursor}：长度整帧");
            assert!(fetched.next_offset >= ring.residency_start());
            assert!(fetched.next_offset <= ring.end());
            assert!(fetched.data.len() <= ring.usage());
        }
        // 33 → 向下对齐到 32（驻留起点），交付全部驻留字节
        let behind = ring.fetch(33, 1_000);
        assert_eq!(behind.next_offset, 64);
        assert_eq!(behind.data.len(), 32);
        assert!(!behind.truncated, "对齐后与驻留起点重合，不算缺口");
        // 63 → 向下对齐到 56，只给最后 8 字节
        let near_end = ring.fetch(63, 1_000);
        assert_eq!(
            (
                near_end.next_offset - near_end.data.len() as u64,
                near_end.data.len()
            ),
            (56, 8)
        );
    }
}
