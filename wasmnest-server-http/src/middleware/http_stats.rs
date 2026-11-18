//! 请求完成事件的秒级聚合计数
//!
//! **为什么存在**：请求完成日志的成功分支从 `debug` 降到 `trace` 之后（见
//! [`super::http_filter`] 完成事件处注释），「成功请求是否还在流动」不能随之完全
//! 失明——排查「客户端说调不通、宿主这边什么都没有」时，第一个要回答的就是
//! 「到底有没有请求进来」。本模块只保留**进程级计数**，不缓冲任何事件。
//!
//! 形态约束（热路径）：
//! - 每个请求固定 **1 次 `Instant::elapsed` + 少量原子加一**，零分配、零锁、零 I/O；
//! - 本模块**不主动输出任何日志**（无后台任务、无定时器），唯一出口是成功完成事件
//!   的 `requests_in_window` 字段——trace 关闭时它不产生任何输出开销；
//! - 值语义 = 当前日志窗口（[`LOG_AGGREGATOR_WINDOW_MS`]，与日志时间戳毫秒精度
//!   对齐）内累计的「已过过滤链的请求数」，并按状态档位给出 2xx/3xx、4xx、5xx 与
//!   下游异常三档——一眼能看出「200 很多」是正常轮询还是错误重试风暴。
//!
//! 这是**观测**，不是业务真源（宿主薄壳红线 B3 不适用）：不对外暴露 query、不参与
//! 任何裁决，删除它不影响任何行为。

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;
use std::time::Instant;

/// 聚合窗口（毫秒）：与日志时间戳的毫秒精度对齐，读一行日志即知这一秒发生了什么
pub const LOG_AGGREGATOR_WINDOW_MS: u64 = 1_000;

/// 进程启动时刻（窗口计算的单调时钟原点）
static WINDOW_ORIGIN: OnceLock<Instant> = OnceLock::new();

/// 当前窗口序号（`elapsed / 窗口 + 1`）
static WINDOW: AtomicU64 = AtomicU64::new(0);

/// 本窗口内已过过滤链的请求数
static REQUESTS: AtomicU64 = AtomicU64::new(0);
/// 本窗口内 2xx / 3xx 请求数
static OK: AtomicU64 = AtomicU64::new(0);
/// 本窗口内 4xx 请求数
static CLIENT_ERR: AtomicU64 = AtomicU64::new(0);
/// 本窗口内 5xx 请求数
static SERVER_ERR: AtomicU64 = AtomicU64::new(0);
/// 本窗口内下游异常（未产生响应）的请求数
static FAILED: AtomicU64 = AtomicU64::new(0);

/// 记录一次请求完成，返回**本窗口内**累计请求数（含本次）
///
/// `status = None` 表示下游/读体异常（未拿到响应）。窗口推进时清零：只有第一个
/// 观察到新窗口的请求能 CAS 抢到窗口号，输者直接累加——热路径上通常只是两次
/// 原子读 + 一次加一。
pub fn record(status: Option<u16>) -> u64 {
    let origin = *WINDOW_ORIGIN.get_or_init(Instant::now);
    let window = origin.elapsed().as_millis() as u64 / LOG_AGGREGATOR_WINDOW_MS + 1;

    let current = WINDOW.load(Relaxed);
    if window != current && WINDOW.compare_exchange(current, window, Relaxed, Relaxed).is_ok() {
        for counter in [&REQUESTS, &OK, &CLIENT_ERR, &SERVER_ERR, &FAILED] {
            counter.store(0, Relaxed);
        }
    }

    let slot = match status {
        Some(s) if (200..400).contains(&s) => &OK,
        Some(s) if (400..500).contains(&s) => &CLIENT_ERR,
        Some(_) => &SERVER_ERR,
        None => &FAILED,
    };
    slot.fetch_add(1, Relaxed);
    REQUESTS.fetch_add(1, Relaxed) + 1
}

/// 当前窗口快照 `(总请求, 2xx/3xx, 4xx, 5xx, 下游异常)`——诊断面 / 测试用
///
/// 各字段分别读取，不保证同一时刻的强一致快照（只用于观测，不做裁决）
pub fn window_snapshot() -> (u64, u64, u64, u64, u64) {
    (
        REQUESTS.load(Relaxed),
        OK.load(Relaxed),
        CLIENT_ERR.load(Relaxed),
        SERVER_ERR.load(Relaxed),
        FAILED.load(Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 返回值 = 本窗口内累计请求数（含本次），可直接作为日志字段
    #[test]
    fn record_returns_cumulative_count_and_buckets_by_status() {
        let before = window_snapshot();
        let first = record(Some(200));
        let second = record(Some(204));
        record(Some(304));
        record(Some(404));
        record(Some(500));
        record(None);
        let after = window_snapshot();

        if second == first + 1 {
            // 同窗口内：计数逐次 +1，各档位分别累加
            assert_eq!(after.0, before.0 + 6, "总计数应增加 6");
            assert_eq!(after.1, before.1 + 3, "2xx/3xx 应增加 3");
            assert_eq!(after.2, before.2 + 1, "4xx 应增加 1");
            assert_eq!(after.3, before.3 + 1, "5xx 应增加 1");
            assert_eq!(after.4, before.4 + 1, "下游异常应增加 1");
        } else {
            // 恰好跨窗口：计数已清零，至少能确认新窗口从 1 起算且未溢出
            assert!(after.0 >= 1, "新窗口计数应 >= 1");
        }
    }

    /// 窗口推进后清零：等过一个窗口再记录，返回值应从 1 起算
    #[test]
    fn window_rollover_resets_counts() {
        record(Some(200));
        std::thread::sleep(std::time::Duration::from_millis(LOG_AGGREGATOR_WINDOW_MS + 50));
        assert_eq!(record(Some(200)), 1, "新窗口计数应从 1 开始");
        assert_eq!(window_snapshot(), (1, 1, 0, 0, 0), "新窗口只含本次请求");
    }
}
