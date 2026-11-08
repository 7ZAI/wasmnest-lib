//! 一次性配对票据（不变量 4）。
//!
//! 票据只开配对窗口，不代表应用信任：TTL ≤ 120s、绑定目标端口、用后立即失效，
//! **不绑定接入路径**（LAN 直连与中继两条路径都可用，由调用方在拨号成功后消费）。
//! 票据明文只出现在 QR / 连接串（带外）与本进程内存表中：不落日志、不进指标、
//! 错误原因只写长度或类别。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};

use crate::tunnel::{Result, TunnelError, CODE_TICKET_EXPIRED};

pub const MAX_TICKET_TTL_SECS: u32 = 120;
pub const TICKET_RANDOM_BYTES: usize = 32;

/// 接入路径只作可观测记录，不参与票据校验（票据不得绑定单一接入路径）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPath {
    LanDirect,
    WanRelay,
}

#[derive(Debug, Clone)]
struct IssuedTicket {
    port: u16,
    expires_at_ms: u64,
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    })
}

/// 进程内票据表；配对成功 / 过期 / 用户取消时立即清除条目
#[derive(Clone)]
pub struct TicketIssuer {
    entries: Arc<Mutex<HashMap<String, IssuedTicket>>>,
    now_ms: Clock,
}

impl Default for TicketIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl TicketIssuer {
    pub fn new() -> Self {
        Self::with_clock(system_clock())
    }

    /// 注入时钟仅用于测试；生产路径走系统时钟
    pub fn with_clock(now_ms: Clock) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            now_ms,
        }
    }

    /// 签发：TTL 必须 1..=120s，目标端口非 0；返回 64 位 hex 票据
    pub fn issue(&self, port: u16, ttl_secs: u32) -> Result<String> {
        if port == 0 {
            return Err(TunnelError::new(CODE_TICKET_EXPIRED, "票据必须绑定有效目标端口"));
        }
        if ttl_secs == 0 || ttl_secs > MAX_TICKET_TTL_SECS {
            return Err(TunnelError::new(
                CODE_TICKET_EXPIRED,
                format!("TTL {ttl_secs}s 超出 1..={MAX_TICKET_TTL_SECS}s"),
            ));
        }
        let mut random = [0u8; TICKET_RANDOM_BYTES];
        OsRng.fill_bytes(&mut random);
        let id = hex::encode(random);
        let expires_at_ms = (self.now_ms)().saturating_add(u64::from(ttl_secs) * 1000);
        self.entries
            .lock()
            .expect("ticket table poisoned")
            .insert(id.clone(), IssuedTicket { port, expires_at_ms });
        Ok(id)
    }

    /// 消费：任何使用尝试都先摘除条目（防重放 / 防枚举），再判过期与端口
    pub fn consume(&self, ticket: &str, port: u16, _path: AccessPath) -> Result<()> {
        let entry = self
            .entries
            .lock()
            .expect("ticket table poisoned")
            .remove(ticket)
            .ok_or_else(|| TunnelError::new(CODE_TICKET_EXPIRED, "票据已使用或不存在"))?;
        if entry.expires_at_ms <= (self.now_ms)() {
            return Err(TunnelError::new(CODE_TICKET_EXPIRED, "票据已过期"));
        }
        if entry.port != port {
            return Err(TunnelError::new(
                CODE_TICKET_EXPIRED,
                format!("票据绑定的目标端口 {}", entry.port),
            ));
        }
        Ok(())
    }

    /// 配对成功 / 票据失效 / 用户取消：立即清除，配对窗口不得残留
    pub fn revoke(&self, ticket: &str) -> bool {
        self.entries
            .lock()
            .expect("ticket table poisoned")
            .remove(ticket)
            .is_some()
    }

    pub fn purge_expired(&self) -> usize {
        let now = (self.now_ms)();
        let mut entries = self.entries.lock().expect("ticket table poisoned");
        let before = entries.len();
        entries.retain(|_, t| t.expires_at_ms > now);
        before - entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("ticket table poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fixed_clock() -> (Clock, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(1_000_000));
        let probe = Arc::clone(&now);
        (Arc::new(move || probe.load(Ordering::SeqCst)), now)
    }

    #[test]
    fn ticket_is_single_use_on_both_access_paths() {
        let (clock, _) = fixed_clock();
        let issuer = TicketIssuer::with_clock(clock);
        let lan = issuer.issue(8765, 120).unwrap();
        let relay = issuer.issue(8765, 120).unwrap();
        assert_eq!(lan.len(), TICKET_RANDOM_BYTES * 2);
        assert_ne!(lan, relay, "票据必须随机且互不复用");

        assert!(issuer.consume(&lan, 8765, AccessPath::LanDirect).is_ok());
        assert_eq!(
            issuer.consume(&lan, 8765, AccessPath::LanDirect).unwrap_err().code,
            CODE_TICKET_EXPIRED,
            "LAN 路径二次使用必须拒绝"
        );
        assert!(issuer.consume(&relay, 8765, AccessPath::WanRelay).is_ok());
        assert_eq!(
            issuer.consume(&relay, 8765, AccessPath::WanRelay).unwrap_err().code,
            CODE_TICKET_EXPIRED,
            "中继路径二次使用必须拒绝"
        );
    }

    #[test]
    fn ticket_is_bound_to_target_port() {
        let (clock, _) = fixed_clock();
        let issuer = TicketIssuer::with_clock(clock);
        let ticket = issuer.issue(8765, 60).unwrap();
        let err = issuer.consume(&ticket, 9999, AccessPath::LanDirect).unwrap_err();
        assert_eq!(err.code, CODE_TICKET_EXPIRED);
        assert!(!err.detail.contains(&ticket), "错误原因不得回显票据明文");
        assert!(issuer.is_empty(), "端口不符的使用尝试同样消费票据");
    }

    #[test]
    fn ttl_is_capped_and_expiry_is_enforced() {
        let (clock, now) = fixed_clock();
        let issuer = TicketIssuer::with_clock(clock);
        assert_eq!(issuer.issue(8765, 0).unwrap_err().code, CODE_TICKET_EXPIRED);
        assert_eq!(issuer.issue(8765, 121).unwrap_err().code, CODE_TICKET_EXPIRED);
        assert_eq!(issuer.issue(0, 30).unwrap_err().code, CODE_TICKET_EXPIRED);
        assert!(issuer.issue(8765, 120).is_ok());

        let ticket = issuer.issue(8765, 30).unwrap();
        now.store(1_000_000 + 30_000, Ordering::SeqCst);
        assert_eq!(
            issuer.consume(&ticket, 8765, AccessPath::WanRelay).unwrap_err().code,
            CODE_TICKET_EXPIRED
        );
    }

    #[test]
    fn revoke_and_purge_clear_the_pairing_window() {
        let (clock, now) = fixed_clock();
        let issuer = TicketIssuer::with_clock(clock);
        let a = issuer.issue(8765, 10).unwrap();
        let b = issuer.issue(8765, 10).unwrap();
        assert!(issuer.revoke(&a), "配对成功即清除窗口");
        assert!(!issuer.revoke(&a));
        assert!(issuer.consume(&a, 8765, AccessPath::LanDirect).is_err());
        now.store(1_000_000 + 11_000, Ordering::SeqCst);
        assert_eq!(issuer.purge_expired(), 1);
        assert!(issuer.is_empty());
        assert!(issuer.consume(&b, 8765, AccessPath::WanRelay).is_err());
    }
}
