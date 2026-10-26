//! Traffic Filter Chain — HTTP 与 WS 收发数据的拦截责任链（预留加密机制）
//!
//! 为服务器（HTTP REST + WebSocket）预留报文级扩展点：过滤器以责任链模式
//! 注册到全局单例 [`TrafficFilterChain`]，每个方向的传输数据按注册顺序依次
//! 流经链上过滤器：
//!
//! - **观察型**过滤器只读取 [`FilterContext`]（审计、指标、调试日志）
//! - **转换型**过滤器原地改写 `ctx.data` 实现加密/解密/压缩
//!   （可直接使用 `wasmnest_crypto_engine` 的 AES-GCM / ChaCha20Poly1305 等）
//!
//! 执行语义：
//! - 入站（客户端 → 桌面端）：数据先过链再进入业务处理；HTTP 在 handler 之前、
//!   WS 在帧分派之前
//! - 出站（桌面端 → 客户端）：数据先过链再写出；HTTP 在响应返回前、WS 在写帧前
//! - 任一过滤器返回 [`Verdict::Reject`] 短路整条链：接线点自行决定拒绝行为
//!   （HTTP → 400 错误响应，WS → 丢弃该帧并记 warn 日志）
//! - 链为空时走零开销快速路径（不缓冲、不分配），默认部署零影响
//!
//! 过滤器方法为同步签名：加密运算属 CPU 密钥操作，且 WS actor 的消息处理是
//! 同步上下文；需要异步资源的逻辑请在过滤器内部自行 spawn。
//!
//! # 用法示例
//!
//! ```
//! use std::sync::Arc;
//! use wasmnest_server_core::filter::{Direction, FilterContext, TrafficFilter, Verdict};
//!
//! struct AesGcmCipher { /* key material */ }
//!
//! impl TrafficFilter for AesGcmCipher {
//!     fn name(&self) -> &str { "aes-gcm-cipher" }
//!
//!     fn on_inbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
//!         match decrypt(&ctx.data) {
//!             Ok(plain) => { ctx.data = plain; Verdict::Continue }
//!             Err(e) => Verdict::Reject(format!("decrypt failed: {e}")),
//!         }
//!     }
//!
//!     fn on_outbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
//!         ctx.data = encrypt(&ctx.data);
//!         Verdict::Continue
//!     }
//! }
//!
//! // TrafficFilterChain::global().register(Arc::new(AesGcmCipher { .. }));
//! # fn decrypt(d: &[u8]) -> Result<Vec<u8>, String> { Ok(d.to_vec()) }
//! # fn encrypt(d: &[u8]) -> Vec<u8> { d.to_vec() }
//! ```
//!
//! # 接线点
//!
//! - HTTP：`app::serve` 最内层 face wrap → http 面 `TrafficFilter`（注入组合）
//!   （启用过滤器时请求体/响应体会整体缓冲后转换；链为空时零影响）
//! - WS：`wasmnest-server-websocket` 的 `conn.rs` 收帧与全部出站写帧路径；
//!   心跳 Ping/Pong 属协议控制帧，不过滤

use std::sync::{Arc, RwLock};

// ==================== 类型定义 ====================

/// 流量通道类型（过滤器可据此选择性处理）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficChannel {
    /// HTTP REST API（含插件动态端点 /api/plugin/*）
    Http,
    /// WS 终端通道（移动端每会话终端链路 /ws/terminal/session/*）
    WsTerminal,
    /// WS 事件通道（设备在线判定 + 同步广播 /ws/event）
    WsEvent,
    /// WS 插件端点通道（`/ws/plugin/{plugin_id}/{path}`，插件入站端点帧）
    ///
    /// 参与流量过滤链（帧级 inbound / outbound），但不参与链路加密
    /// （`LinkEncryptionFilter::should_process` 对本品恒 `false`）——链路加密是
    /// 移动端配对设备专用协商协议，插件端点的第三方客户端不参与
    WsPlugin,
}

impl TrafficChannel {
    /// 通道名（日志字段使用）
    pub fn as_str(&self) -> &'static str {
        match self {
            TrafficChannel::Http => "http",
            TrafficChannel::WsTerminal => "ws-terminal",
            TrafficChannel::WsEvent => "ws-event",
            TrafficChannel::WsPlugin => "ws-plugin",
        }
    }
}

/// 传输方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 入站：客户端 → 桌面端
    Inbound,
    /// 出站：桌面端 → 客户端
    Outbound,
}

/// 单次过滤的上下文快照
///
/// `data` 是当前传输载荷；观察型过滤器只读，转换型过滤器原地改写
/// （链条上后续过滤器看到的是改写后的数据）。
pub struct FilterContext<'a> {
    /// 流量通道
    pub channel: TrafficChannel,
    /// 传输方向
    pub direction: Direction,
    /// 对端标识：HTTP = 客户端 SocketAddr，WS = 对端 addr 字符串
    pub peer: &'a str,
    /// 路由提示：HTTP = 请求 path，WS = 帧类别（"text" / "binary"）
    pub route: &'a str,
    /// 协商信号（链路加密）：HTTP = 请求头 `X-WasmNest-Crypto` 原始值
    /// （如 "v1 <ek_b64>"），无协商为空串；WS 不用此字段（握手态由
    /// link_crypto 的连接密码表按 peer 查询）。issue 02 引入。
    pub negotiation: &'a str,
    /// 当前载荷（可原地替换实现加解密）
    pub data: Vec<u8>,
    /// 出站附加响应头（HTTP 专用）：过滤器在出站转换成功后写入
    /// （如响应加密标记 `X-WasmNest-Crypto: v1`），由 http_filter 重建
    /// 响应时注入；WS 通道不消费此字段。
    pub outbound_headers: Vec<(String, String)>,
}

/// 过滤器裁决
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// 继续传递给下一个过滤器（数据如被修改则以修改后为准）
    Continue,
    /// 中断链条并拒绝该次数据传输（携带原因，用于日志与错误响应）
    Reject(String),
}

/// 责任链节点 —— 一个传输层流量过滤器
///
/// 实现者按需覆盖 `on_inbound` / `on_outbound`（默认放行）。
/// 名称应全局唯一（注销按名称进行）。
pub trait TrafficFilter: Send + Sync + 'static {
    /// 过滤器名称（注销与日志定位用）
    fn name(&self) -> &str;

    /// 入站数据过滤（客户端 → 桌面端）
    fn on_inbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
        Verdict::Continue
    }

    /// 出站数据过滤（桌面端 → 客户端）
    fn on_outbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
        Verdict::Continue
    }
}

/// 拒绝详情（哪个过滤器因什么原因拒绝）
#[derive(Debug, Clone)]
pub struct Rejection {
    pub filter_name: String,
    pub reason: String,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "traffic filter '{}' rejected: {}", self.filter_name, self.reason)
    }
}

// ==================== 责任链 ====================

/// 全局责任链注册表（单例）
///
/// 注册顺序即执行顺序（先注册先执行）。执行前对过滤器列表做快照，
/// 不持锁调用过滤器——过滤器内若再触达本链不会死锁。
struct Inner {
    filters: RwLock<Vec<Arc<dyn TrafficFilter>>>,
}

pub struct TrafficFilterChain {
    inner: Inner,
}

impl TrafficFilterChain {
    /// 获取全局单例
    pub fn global() -> &'static Self {
        static INSTANCE: std::sync::LazyLock<TrafficFilterChain> = std::sync::LazyLock::new(|| TrafficFilterChain {
            inner: Inner {
                filters: RwLock::new(Vec::new()),
            },
        });
        &INSTANCE
    }

    /// 创建独立实例（测试或嵌入式场景用；运行期统一走 global()）
    pub fn new() -> Self {
        Self {
            inner: Inner {
                filters: RwLock::new(Vec::new()),
            },
        }
    }

    /// 注册过滤器到链尾（后注册者后执行）
    ///
    /// 同名重复注册不拦截（由调用方保证唯一性）；需要替换语义时先 unregister 再 register
    pub fn register(&self, filter: Arc<dyn TrafficFilter>) {
        tracing::info!(name = filter.name(), "Traffic filter registered");
        if let Ok(mut guards) = self.inner.filters.write() {
            guards.push(filter);
        } else {
            tracing::error!("TrafficFilterChain lock poisoned, filter registration dropped");
        }
    }

    /// 按名称注销过滤器，返回是否移除
    pub fn unregister(&self, name: &str) -> bool {
        match self.inner.filters.write() {
            Ok(mut guard) => {
                let before = guard.len();
                guard.retain(|f| f.name() != name);
                let removed = guard.len() != before;
                if removed {
                    tracing::info!(name, "Traffic filter unregistered");
                }
                removed
            }
            Err(_) => false,
        }
    }

    /// 清空所有过滤器（服务器关闭 / 测试隔离用）
    pub fn clear(&self) {
        if let Ok(mut guard) = self.inner.filters.write() {
            guard.clear();
        }
    }

    /// 当前过滤器名称列表（诊断用）
    pub fn list_names(&self) -> Vec<String> {
        match self.inner.filters.read() {
            Ok(guard) => guard.iter().map(|f| f.name().to_string()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// 链是否为空（接线点的零开销快速路径判断）
    pub fn is_empty(&self) -> bool {
        match self.inner.filters.read() {
            Ok(guard) => guard.is_empty(),
            // 锁中毒退化为不过滤（可用性优先；中毒本身已由写入方记 error 日志）
            Err(_) => true,
        }
    }

    /// 某名称的过滤器是否在链上（接线点按名判定「本端是否参与」；无分配）
    ///
    /// 供 HTTP 接线点做 fail-visible 裁决：请求带加密协商头、而本端对应能力
    /// **未参与**（`trafficEncryption.enabled=false` ⇒ 过滤器未注册）时必须显性
    /// 拒绝，而不是把密文原样透给下游业务解析（那会回出误导性业务码）。
    pub fn contains(&self, name: &str) -> bool {
        match self.inner.filters.read() {
            Ok(guard) => guard.iter().any(|f| f.name() == name),
            // 锁中毒退化为「不在链上」：调用方据此走**显性拒绝**（fail-closed）。
            // 与上面 `is_empty` 的中毒退化方向相反且刻意如此：那条放行的是**明文**
            // （可解读），这条要放行的是**无法解读的密文**。
            Err(_) => false,
        }
    }

    /// 入站执行：按注册顺序依次调用 `on_inbound`
    ///
    /// 返回 Err 表示被某过滤器拒绝（短路，后续过滤器不再执行）
    pub fn run_inbound(&self, ctx: &mut FilterContext<'_>) -> Result<(), Rejection> {
        for filter in self.snapshot() {
            if let Verdict::Reject(reason) = filter.on_inbound(ctx) {
                return Err(Rejection {
                    filter_name: filter.name().to_string(),
                    reason,
                });
            }
        }
        Ok(())
    }

    /// 出站执行：按注册顺序依次调用 `on_outbound`
    ///
    /// 返回 Err 表示被某过滤器拒绝（短路，后续过滤器不再执行）
    pub fn run_outbound(&self, ctx: &mut FilterContext<'_>) -> Result<(), Rejection> {
        for filter in self.snapshot() {
            if let Verdict::Reject(reason) = filter.on_outbound(ctx) {
                return Err(Rejection {
                    filter_name: filter.name().to_string(),
                    reason,
                });
            }
        }
        Ok(())
    }

    /// 过滤器列表快照：短暂持锁克隆 Arc 列表，避免跨过滤器调用持锁
    fn snapshot(&self) -> Vec<Arc<dyn TrafficFilter>> {
        match self.inner.filters.read() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl Default for TrafficFilterChain {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 观察型过滤器：记录调用次数，不改数据
    struct Observer {
        calls_inbound: AtomicUsize,
        calls_outbound: AtomicUsize,
    }

    impl Observer {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls_inbound: AtomicUsize::new(0),
                calls_outbound: AtomicUsize::new(0),
            })
        }
        fn inbound_calls(&self) -> usize {
            self.calls_inbound.load(Ordering::SeqCst)
        }
        fn outbound_calls(&self) -> usize {
            self.calls_outbound.load(Ordering::SeqCst)
        }
    }

    impl TrafficFilter for Observer {
        fn name(&self) -> &str {
            "observer"
        }
        fn on_inbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
            self.calls_inbound.fetch_add(1, Ordering::SeqCst);
            Verdict::Continue
        }
        fn on_outbound(&self, _ctx: &mut FilterContext<'_>) -> Verdict {
            self.calls_outbound.fetch_add(1, Ordering::SeqCst);
            Verdict::Continue
        }
    }

    /// 转换型过滤器：入站解"密"（每字节 -1），出站加"密"（每字节 +1）
    struct ShiftCipher;

    impl TrafficFilter for ShiftCipher {
        fn name(&self) -> &str {
            "shift-cipher"
        }
        fn on_inbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
            ctx.data.iter_mut().for_each(|b| *b = b.wrapping_sub(1));
            Verdict::Continue
        }
        fn on_outbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
            ctx.data.iter_mut().for_each(|b| *b = b.wrapping_add(1));
            Verdict::Continue
        }
    }

    /// 拒绝型过滤器：命中指定路由即拒绝
    struct RouteBlocker {
        blocked_route: &'static str,
    }

    impl TrafficFilter for RouteBlocker {
        fn name(&self) -> &str {
            "route-blocker"
        }
        fn on_inbound(&self, ctx: &mut FilterContext<'_>) -> Verdict {
            if ctx.route == self.blocked_route {
                Verdict::Reject(format!("route {} is blocked", ctx.route))
            } else {
                Verdict::Continue
            }
        }
    }

    /// 构造入站 HTTP 过滤上下文（peer 用空串占位即可满足生命周期）
    fn http_ctx(route: &'static str, data: &[u8]) -> FilterContext<'static> {
        FilterContext {
            channel: TrafficChannel::Http,
            direction: Direction::Inbound,
            peer: "",
            route,
            negotiation: "",
            data: data.to_vec(),
            outbound_headers: Vec::new(),
        }
    }

    #[test]
    fn empty_chain_is_zero_overhead_passthrough() {
        let chain = TrafficFilterChain::new();
        assert!(chain.is_empty());
        assert!(chain.list_names().is_empty());

        let mut ctx = http_ctx("/api/sessions", b"payload");
        assert!(chain.run_inbound(&mut ctx).is_ok());
        assert_eq!(ctx.data, b"payload");
    }

    /// 插件端点通道（`TrafficChannel::WsPlugin`）参与帧级过滤链：inbound / outbound
    /// 均执行（spec §4.6 / 票 05 checklist），且通道名稳定（日志字段）
    #[test]
    fn ws_plugin_channel_runs_both_directions() {
        assert_eq!(TrafficChannel::WsPlugin.as_str(), "ws-plugin");

        let chain = TrafficFilterChain::new();
        let observer = Observer::new();
        chain.register(observer.clone());

        let mut in_ctx = FilterContext {
            channel: TrafficChannel::WsPlugin,
            direction: Direction::Inbound,
            peer: "192.168.1.42:5001",
            route: "text",
            negotiation: "",
            data: b"hello".to_vec(),
            outbound_headers: Vec::new(),
        };
        assert!(chain.run_inbound(&mut in_ctx).is_ok());
        assert_eq!(in_ctx.data, b"hello", "无转换型过滤器时载荷原样透传");
        assert_eq!(observer.inbound_calls(), 1, "插件端点入站帧必须过链");

        let mut out_ctx = FilterContext {
            channel: TrafficChannel::WsPlugin,
            direction: Direction::Outbound,
            peer: "192.168.1.42:5001",
            route: "binary",
            negotiation: "",
            data: b"hello".to_vec(),
            outbound_headers: Vec::new(),
        };
        assert!(chain.run_outbound(&mut out_ctx).is_ok());
        assert_eq!(observer.outbound_calls(), 1, "插件端点出站帧必须过链");
    }

    #[test]
    fn filters_run_in_registration_order_and_transform_data() {
        let chain = TrafficFilterChain::new();
        let observer1 = Observer::new();
        let observer2 = Observer::new();
        chain.register(observer1.clone());
        chain.register(Arc::new(ShiftCipher));
        chain.register(observer2.clone());

        assert_eq!(
            chain.list_names(),
            vec![
                "observer".to_string(),
                "shift-cipher".to_string(),
                "observer".to_string()
            ]
        );

        // 入站：ShiftCipher 把每字节 -1（b'c' → b'b'）
        let mut in_ctx = http_ctx("/x", b"ccc");
        assert!(chain.run_inbound(&mut in_ctx).is_ok());
        assert_eq!(in_ctx.data, b"bbb");
        assert_eq!(observer1.inbound_calls(), 1);
        assert_eq!(observer2.inbound_calls(), 1);

        // 出站：+1 还原
        let mut out_ctx = FilterContext {
            channel: TrafficChannel::WsTerminal,
            direction: Direction::Outbound,
            peer: "127.0.0.1:5000",
            route: "text",
            negotiation: "",
            data: b"bbb".to_vec(),
            outbound_headers: Vec::new(),
        };
        assert!(chain.run_outbound(&mut out_ctx).is_ok());
        assert_eq!(out_ctx.data, b"ccc");
        assert_eq!(observer1.outbound_calls(), 1);
        assert_eq!(observer2.outbound_calls(), 1);

        // 注销后不再参与执行
        assert!(chain.unregister("shift-cipher"));
        assert!(!chain.unregister("shift-cipher"), "重复注销应返回 false");
        let mut ctx2 = http_ctx("/x", b"abc");
        assert!(chain.run_inbound(&mut ctx2).is_ok());
        assert_eq!(ctx2.data, b"abc", "移除转换器后数据应原样透传");
        assert_eq!(observer1.inbound_calls(), 2);
    }

    #[test]
    fn reject_short_circuits_chain_with_details() {
        let chain = TrafficFilterChain::new();
        let observer = Observer::new();
        chain.register(Arc::new(RouteBlocker {
            blocked_route: "/api/secret",
        }));
        chain.register(observer.clone());

        // 命中阻断路由：第一个过滤器拒绝，第二个不被调用
        let mut ctx = http_ctx("/api/secret", b"x");
        let err = chain.run_inbound(&mut ctx).unwrap_err();
        assert_eq!(err.filter_name, "route-blocker");
        assert_eq!(err.reason, "route /api/secret is blocked");
        assert_eq!(observer.inbound_calls(), 0, "Reject 应短路后续过滤器");

        // 未命中路由：全链通过
        let mut ok_ctx = http_ctx("/api/health", b"x");
        assert!(chain.run_inbound(&mut ok_ctx).is_ok());
        assert_eq!(observer.inbound_calls(), 1);
    }

    #[test]
    fn clear_removes_all_filters() {
        let chain = TrafficFilterChain::new();
        chain.register(Observer::new());
        chain.register(Arc::new(ShiftCipher));
        assert_eq!(chain.list_names().len(), 2);

        chain.clear();
        assert!(chain.is_empty());

        let mut ctx = http_ctx("/x", b"data");
        assert!(chain.run_inbound(&mut ctx).is_ok());
        assert_eq!(ctx.data, b"data");
    }
}
