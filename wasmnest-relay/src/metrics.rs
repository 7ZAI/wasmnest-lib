//! 指标聚合：只记计数，不记业务面。
//!
//! **不变量**：中继看不到也记不下 payload / 文件名 / 路径 / token。这里的结构体
//! 因此只有 `u64` 计数与固定词汇的拒绝原因表——没有「额外字段」可放业务信息，
//! 想加也只能加计数。
//!
//! 字节数说明：`libp2p-relay` 0.22 的 `CircuitClosed` 事件不带字节数
//!（`CopyFuture::bytes_sent` 是 crate 私有字段），因此 v1 不提供字节指标——
//! 拒绝伪造一个「看起来有」的数字。计数与拒绝原因分布足以支撑容量与滥用排查。

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use serde::Serialize;

/// 拒绝原因（固定词汇；指标标签用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RejectReason {
    /// reservation 被准入策略或速率限制拒绝
    ReservationDenied,
    /// circuit 被准入策略或配额拒绝
    CircuitDenied,
    /// 单 IP 入站连接数超限
    IpConnectionLimit,
}

impl RejectReason {
    /// 指标标签字面量
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReservationDenied => "reservation-denied",
            Self::CircuitDenied => "circuit-denied",
            Self::IpConnectionLimit => "ip-connection-limit",
        }
    }
}

/// 指标快照（`/metrics` 与自检共用）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    /// 当前 reservation 数
    pub reservations_active: u64,
    /// 累计接受的 reservation 请求（含续期）
    pub reservations_total: u64,
    /// 其中属于续期的请求数
    pub reservations_renewed: u64,
    /// 主动关闭的 reservation 数
    pub reservations_closed: u64,
    /// 超时失效的 reservation 数
    pub reservations_timed_out: u64,
    /// 当前 circuit 数
    pub circuits_active: u64,
    /// 累计建立的 circuit 数
    pub circuits_total: u64,
    /// 当前入站连接数
    pub connections_active: u64,
    /// 累计入站连接数
    pub connections_total: u64,
    /// 拒绝原因分布
    pub rejected: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
struct Inner {
    reservations_active: u64,
    reservations_total: u64,
    reservations_renewed: u64,
    reservations_closed: u64,
    reservations_timed_out: u64,
    circuits_active: u64,
    circuits_total: u64,
    connections_active: u64,
    connections_total: u64,
    rejected: BTreeMap<String, u64>,
}

/// 线程安全指标表
#[derive(Debug, Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

impl Metrics {
    /// 新建空指标表
    pub fn new() -> Self {
        Self::default()
    }

    /// reservation 被接受（`renewed` = 续期而非新建）
    pub fn reservation_accepted(&self, renewed: bool) {
        let mut inner = self.lock();
        inner.reservations_total = inner.reservations_total.saturating_add(1);
        if renewed {
            inner.reservations_renewed = inner.reservations_renewed.saturating_add(1);
        } else {
            inner.reservations_active = inner.reservations_active.saturating_add(1);
        }
    }

    /// reservation 关闭
    pub fn reservation_closed(&self) {
        let mut inner = self.lock();
        inner.reservations_closed = inner.reservations_closed.saturating_add(1);
        inner.reservations_active = inner.reservations_active.saturating_sub(1);
    }

    /// reservation 超时
    pub fn reservation_timed_out(&self) {
        let mut inner = self.lock();
        inner.reservations_timed_out = inner.reservations_timed_out.saturating_add(1);
        inner.reservations_active = inner.reservations_active.saturating_sub(1);
    }

    /// circuit 被接受
    pub fn circuit_accepted(&self) {
        let mut inner = self.lock();
        inner.circuits_total = inner.circuits_total.saturating_add(1);
        inner.circuits_active = inner.circuits_active.saturating_add(1);
    }

    /// circuit 关闭
    pub fn circuit_closed(&self) {
        let mut inner = self.lock();
        inner.circuits_active = inner.circuits_active.saturating_sub(1);
    }

    /// 入站连接建立
    pub fn connection_established(&self) {
        let mut inner = self.lock();
        inner.connections_total = inner.connections_total.saturating_add(1);
        inner.connections_active = inner.connections_active.saturating_add(1);
    }

    /// 入站连接关闭
    pub fn connection_closed(&self) {
        let mut inner = self.lock();
        inner.connections_active = inner.connections_active.saturating_sub(1);
    }

    /// 记录一次拒绝
    pub fn rejected(&self, reason: RejectReason) {
        let mut inner = self.lock();
        *inner
            .rejected
            .entry(reason.as_str().to_string())
            .or_insert(0) += 1;
    }

    /// 取快照
    pub fn snapshot(&self) -> MetricsSnapshot {
        let inner = self.lock();
        MetricsSnapshot {
            reservations_active: inner.reservations_active,
            reservations_total: inner.reservations_total,
            reservations_renewed: inner.reservations_renewed,
            reservations_closed: inner.reservations_closed,
            reservations_timed_out: inner.reservations_timed_out,
            circuits_active: inner.circuits_active,
            circuits_total: inner.circuits_total,
            connections_active: inner.connections_active,
            connections_total: inner.connections_total,
            rejected: inner.rejected.clone(),
        }
    }

    /// 渲染为 Prometheus 文本格式（`/metrics` 响应体）
    pub fn render(&self) -> String {
        let snapshot = self.snapshot();
        let mut out = String::new();
        emit_metric(
            &mut out,
            "wasmnest_relay_reservations_active",
            "当前 reservation 数",
            "gauge",
            snapshot.reservations_active,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_reservations_total",
            "累计接受的 reservation 请求（含续期）",
            "counter",
            snapshot.reservations_total,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_reservations_renewed_total",
            "累计 reservation 续期请求",
            "counter",
            snapshot.reservations_renewed,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_reservations_closed_total",
            "累计关闭的 reservation",
            "counter",
            snapshot.reservations_closed,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_reservations_timed_out_total",
            "累计超时失效的 reservation",
            "counter",
            snapshot.reservations_timed_out,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_circuits_active",
            "当前 circuit 数",
            "gauge",
            snapshot.circuits_active,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_circuits_total",
            "累计建立的 circuit 数",
            "counter",
            snapshot.circuits_total,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_connections_active",
            "当前入站连接数",
            "gauge",
            snapshot.connections_active,
        );
        emit_metric(
            &mut out,
            "wasmnest_relay_connections_total",
            "累计入站连接数",
            "counter",
            snapshot.connections_total,
        );
        if !snapshot.rejected.is_empty() {
            out.push_str(
                "# HELP wasmnest_relay_rejected_total 按原因统计的拒绝次数\n# TYPE wasmnest_relay_rejected_total counter\n",
            );
            for (reason, count) in &snapshot.rejected {
                out.push_str(&format!(
                    "wasmnest_relay_rejected_total{{reason=\"{reason}\"}} {count}\n"
                ));
            }
        }
        out
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("指标表锁中毒")
    }
}

/// 输出一条 Prometheus 指标（HELP / TYPE / 值）
fn emit_metric(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 计数按事件累加() {
        let metrics = Metrics::new();
        metrics.reservation_accepted(false);
        metrics.reservation_accepted(true);
        metrics.circuit_accepted();
        metrics.connection_established();
        metrics.rejected(RejectReason::ReservationDenied);
        metrics.rejected(RejectReason::ReservationDenied);
        metrics.rejected(RejectReason::IpConnectionLimit);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.reservations_active, 1);
        assert_eq!(snapshot.reservations_total, 2);
        assert_eq!(snapshot.reservations_renewed, 1);
        assert_eq!(snapshot.circuits_active, 1);
        assert_eq!(snapshot.circuits_total, 1);
        assert_eq!(snapshot.connections_active, 1);
        assert_eq!(
            snapshot.rejected.get("reservation-denied"),
            Some(&2),
            "拒绝原因应分桶计数"
        );
        assert_eq!(snapshot.rejected.get("ip-connection-limit"), Some(&1));
    }

    #[test]
    fn 续期不增加活跃_reservation() {
        let metrics = Metrics::new();
        metrics.reservation_accepted(true);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.reservations_active, 0, "续期是替换而非新增");
        assert_eq!(snapshot.reservations_total, 1);
        assert_eq!(snapshot.reservations_renewed, 1);
    }

    #[test]
    fn 关闭与超时让活跃数归零_且不会下溢() {
        let metrics = Metrics::new();
        metrics.circuit_closed();
        metrics.reservation_closed();
        metrics.reservation_timed_out();
        metrics.connection_closed();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.reservations_active, 0);
        assert_eq!(snapshot.circuits_active, 0);
        assert_eq!(snapshot.connections_active, 0);
        assert_eq!(snapshot.reservations_closed, 1);
        assert_eq!(snapshot.reservations_timed_out, 1);
    }

    #[test]
    fn 渲染文本含全部计数器() {
        let metrics = Metrics::new();
        metrics.reservation_accepted(false);
        metrics.rejected(RejectReason::CircuitDenied);
        let text = metrics.render();
        assert!(text.contains("wasmnest_relay_reservations_active 1"));
        assert!(text.contains("# TYPE wasmnest_relay_circuits_total counter"));
        assert!(text.contains("wasmnest_relay_rejected_total{reason=\"circuit-denied\"} 1"));
        assert!(text.ends_with('\n'), "每行应以换行结束");
    }

    #[test]
    fn 渲染文本不含业务面词汇() {
        // 不变量 5 的自检：指标里只允许出现计数与固定拒绝原因
        let metrics = Metrics::new();
        metrics.reservation_accepted(false);
        let text = metrics.render().to_lowercase();
        for forbidden in [
            "filename",
            "file_name",
            "path=",
            "payload",
            "token",
            "http_",
        ] {
            assert!(!text.contains(forbidden), "指标不应出现 {forbidden}");
        }
    }
}
