//! 插件日志域实现层（转发到宿主 tracing，附加 plugin_id 前缀 + per-plugin 级别阈值）
//!
//! 自桌面 `packages/wasmnest-wasm-core/src/host_api/log.rs` 上移（票 18 批次 4），
//! **以桌面机制为完整基准**（2026-10-09 用户指令「以目前 wasm-core 具有的机制为准
//! 重构移动端」）：统一 callsite（[`PLUGIN_LOG_CALLSITE`]）+ 按调用点缓存的
//! `'static` Metadata（[`plugin_log_metadata`]）+ per-plugin 日志级别阈值
//! （[`emit_plugin_log`] 入口过滤，`WASMNEST_PLUGIN_LOG=id=level,…` 环境变量）。
//! 双端 adapter（桌面 `host_api/log.rs` / 移动 `component.rs` 内联 host-log 域）
//! 直接调用本层——移动端由此获得桌面全套日志机制（此前仅裸 `tracing::*!` 输出）。
//!
//! ## target 命名
//!
//! 统一为 [`LOG_TARGET`]（`wasmnest_host_api_core::plugin_log`）——原桌面 target
//! `wasmnest_desktop_lib::wasm_core::plugin_log` 无过滤消费者（实测），中性命名
//! 供双端日志过滤规则共用。
//!
//! ## 零平台依赖
//!
//! 本层只依赖 tracing / std（thread_local 阈值缓存），无 tauri / tokio / SDK 类型。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tracing::callsite::{self, Callsite};
use tracing::field::{self, Value};
use tracing::metadata::Kind;
use tracing::{Event, Level, Metadata};

/// 插件日志统一 tracing target（双端共用；无历史 filter 消费者）
pub const LOG_TARGET: &str = "wasmnest_host_api_core::plugin_log";

/// 插件日志统一 callsite：所有动态 Metadata 共享同一字段集（message）
///
/// tracing 的 callsite 机制用于订阅者兴趣缓存；插件日志按调用点动态生成
/// Metadata（file/line 各不相同），字段集一致即可共用此 callsite 标识
struct PluginLogCallsite;

static PLUGIN_LOG_CALLSITE: PluginLogCallsite = PluginLogCallsite;

impl Callsite for PluginLogCallsite {
    fn set_interest(&self, _interest: tracing::subscriber::Interest) {}

    fn metadata(&self) -> &'static Metadata<'static> {
        static META: Metadata<'static> = Metadata::new(
            LOG_TARGET,
            LOG_TARGET,
            Level::INFO,
            None,
            None,
            None,
            field::FieldSet::new(&["message"], callsite::Identifier(&PLUGIN_LOG_CALLSITE)),
            Kind::EVENT,
        );
        &META
    }
}

/// 插件日志 Metadata 缓存（按 file + line + level 键控）
///
/// `Event::dispatch` 要求 Metadata 为 `'static`，而插件 file 是 WASM 线性内存
/// 中的运行时字符串，首次出现时泄漏一份（Box::leak）转为 `'static` 复用。
/// 插件日志调用点数量有限（每个插件几十个），缓存有界，不会无限增长。
static PLUGIN_LOG_META_CACHE: OnceLock<
    Mutex<HashMap<(String, u32, Level), &'static Metadata<'static>>>,
> = OnceLock::new();

/// 获取（或缓存构造）指定插件调用点的日志 Metadata
pub fn plugin_log_metadata(level: Level, file: &str, line: u32) -> &'static Metadata<'static> {
    let cache = PLUGIN_LOG_META_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry((file.to_string(), line, level))
        .or_insert_with(|| {
            // 泄漏转 'static：同一调用点后续命中缓存，仅首次泄漏
            let file: &'static str = Box::leak(file.to_string().into_boxed_str());
            let fields =
                field::FieldSet::new(&["message"], callsite::Identifier(&PLUGIN_LOG_CALLSITE));
            Box::leak(Box::new(Metadata::new(
                LOG_TARGET,
                LOG_TARGET,
                level,
                Some(file),
                Some(line),
                Some(LOG_TARGET),
                fields,
                Kind::EVENT,
            )))
        })
}

/// 发出 info 日志（组件形态不携带插件调用点，file/line 传 ""/0）
pub fn log_info(plugin_id: &str, message: &str, file: &str, line: u32) {
    emit_plugin_log(plugin_id, Level::INFO, file, line, message);
}

/// 发出 debug 日志
pub fn log_debug(plugin_id: &str, message: &str, file: &str, line: u32) {
    emit_plugin_log(plugin_id, Level::DEBUG, file, line, message);
}

/// 发出 warn 日志
pub fn log_warn(plugin_id: &str, message: &str, file: &str, line: u32) {
    emit_plugin_log(plugin_id, Level::WARN, file, line, message);
}

/// 发出 error 日志
pub fn log_error(plugin_id: &str, message: &str, file: &str, line: u32) {
    emit_plugin_log(plugin_id, Level::ERROR, file, line, message);
}

// ==================== Per-plugin 日志级别 ====================

// 插件日志级别阈值映射缓存（thread_local）：键 = 插件 ID，值 = 该插件日志
// 允许的最低级别。缓存用 thread_local 是因为插件日志事件在调用线程内同步
// dispatch，各线程解析结果一致（进程级 env）；测试环境下不同测试可在线程内
// 独立 set_var + reset 互不污染（进程级 OnceLock 会被并行测试抢先填充）
thread_local! {
    static PLUGIN_LOG_THRESHOLDS: std::cell::RefCell<Option<HashMap<String, Level>>> =
        const { std::cell::RefCell::new(None) };
}

/// 按插件日志级别阈值映射（`WASMNEST_PLUGIN_LOG=id=level,id2=level2`）
///
/// 键 = 插件 ID，值 = 该插件日志允许的最低级别。比阈值更 verbose 的级别在
/// `emit_plugin_log` 入口直接丢弃——tracing filter 无法按字段过滤，
/// 宿主侧判定是 per-plugin 级别的唯一可靠位置。未列出的插件无阈值，
/// 沿用宿主全局过滤语义。
///
/// 首次访问时从环境变量懒解析并缓存
fn plugin_log_threshold(plugin_id: &str) -> Option<Level> {
    PLUGIN_LOG_THRESHOLDS.with(|cell| {
        let mut guard = cell.borrow_mut();
        let map = guard.get_or_insert_with(load_plugin_log_thresholds);
        map.get(plugin_id).cloned()
    })
}

/// 从 `WASMNEST_PLUGIN_LOG` 解析阈值映射（逗号分隔 `id=level`）
///
/// 容错：未知插件 ID / 非法级别 / 空条目一律忽略（不 panic、不影响其他
/// 条目）；未设置环境变量时返回空映射（所有插件沿用全局语义）
fn load_plugin_log_thresholds() -> HashMap<String, Level> {
    let mut map = HashMap::new();
    let Ok(raw) = std::env::var("WASMNEST_PLUGIN_LOG") else {
        return map;
    };
    for entry in raw.split(',') {
        let entry = entry.trim();
        let Some((id, level_str)) = entry.split_once('=') else {
            continue;
        };
        let level = match level_str.trim() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => continue,
        };
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        map.insert(id.to_string(), level);
    }
    map
}

/// 测试用：清空当前线程的阈值缓存，下次访问时重新读环境变量
#[cfg(test)]
fn reset_plugin_log_thresholds() {
    PLUGIN_LOG_THRESHOLDS.with(|cell| *cell.borrow_mut() = None);
}

/// 以插件调用点位置发出 tracing 事件（消息带 `[plugin:xxx]` 前缀，保持旧格式）
fn emit_plugin_log(plugin_id: &str, level: Level, file: &str, line: u32, message: &str) {
    // per-plugin 阈值过滤：比配置级别更 verbose（数值更大：DEBUG=4 > WARN=2）
    // 的级别直接丢弃（不产生事件、不经过 filter）；等于或低于阈值照常放行
    if let Some(threshold) = plugin_log_threshold(plugin_id) {
        if level > threshold {
            return;
        }
    }
    let meta = plugin_log_metadata(level, file, line);
    let fieldset = meta.fields();
    let formatted = format!("[plugin:{}] {}", plugin_id, message);
    // value_set_all 按字段集顺序填充值；插件日志字段集仅 "message" 一项
    let display_value = field::display(formatted);
    let value_slots = [Some(&display_value as &dyn Value)];
    let values = fieldset.value_set_all(&value_slots);
    // 必须先过宿主 `enabled()` 判定（等价 tracing 宏路径 `__is_enabled` →
    // `dispatch.enabled(meta)`）：per-layer filter（FilterFn / Targets /
    // EnvFilter）的级别与 target 判定只在 `enabled()` pass 里执行，而
    // `Event::dispatch` 直接派发只走 `event_enabled`（默认 true，仅重查
    // `enabled()` pass 设置的 FilterState 位）。跳过本门禁会让插件日志
    // 绕过宿主全部 per-layer filter——实测桌面 error.log 收全级别插件行、
    // frontend.log 混入插件行、release 下 runtime 级别过滤对插件失效。
    if !tracing::dispatcher::get_default(|d| d.enabled(meta)) {
        return;
    }
    Event::dispatch(meta, &values);
}

// ==================== Tests ====================

/// 测试捕获基建（本层与各端 wasm-core 的 trap/级别过滤测试共用）
///
/// 与项目默认订阅者（文件落盘）互不影响：with_default 只替换当前线程
/// 的默认订阅者，且测试通过共享 Arc 取回捕获结果
pub mod capture {
    use std::sync::{Arc, Mutex};
    use tracing::field::Visit;
    use tracing::span;
    use tracing::subscriber::with_default;
    use tracing::{Event, Level, Metadata, Subscriber};

    /// 捕获的单个事件（level / 调用点 / 消息 / 结构化字段）
    #[derive(Clone, Debug)]
    pub struct CapturedEvent {
        /// 日志级别
        pub level: Level,
        /// 调用点源文件（插件 file 或 None）
        pub file: Option<&'static str>,
        /// 调用点行号
        pub line: Option<u32>,
        /// 消息文本（含 `[plugin:xxx]` 前缀）
        pub message: String,
        /// 结构化字段（plugin_id / trap / export 等），供断言宿主日志携带上下文
        pub fields: Vec<(String, String)>,
    }

    /// 极简订阅者：把 event 原样记录到共享 vec，供断言
    pub struct CaptureSubscriber {
        /// 捕获事件共享列表
        pub events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    /// 从 event 字段集中提取 message 与其余结构化字段
    ///
    /// 字段可见性为 pub(crate)：tests 模块的宿主门禁回归订阅者
    /// （`ErrorOnlySubscriber` / `RejectAll`）复用同一提取逻辑
    pub(crate) struct MessageVisitor(pub String, pub Vec<(String, String)>);

    impl Visit for MessageVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.0 = value.to_string();
            } else {
                self.1.push((field.name().to_string(), value.to_string()));
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{:?}", value);
            } else {
                self.1
                    .push((field.name().to_string(), format!("{:?}", value)));
            }
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.1.push((field.name().to_string(), value.to_string()));
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.1.push((field.name().to_string(), value.to_string()));
        }

        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            self.1.push((field.name().to_string(), value.to_string()));
        }
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attrs: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

        fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = MessageVisitor(String::new(), Vec::new());
            event.record(&mut visitor);
            self.events.lock().unwrap().push(CapturedEvent {
                level: *event.metadata().level(),
                file: event.metadata().file(),
                line: event.metadata().line(),
                message: visitor.0,
                fields: visitor.1,
            });
        }

        fn enter(&self, _span: &span::Id) {}

        fn exit(&self, _span: &span::Id) {}
    }

    /// 以捕获订阅者为默认订阅者执行闭包，返回捕获到的事件列表
    pub fn capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber {
            events: events.clone(),
        };
        with_default(subscriber, f);
        let captured = events.lock().unwrap();
        captured.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tracing::span;
    use tracing::Subscriber;

    use super::capture::*;
    use super::*;

    // ==================== plugin_log_metadata ====================

    /// 同一调用点（file+line+level）命中缓存：返回同一 'static 指针
    #[test]
    fn plugin_log_metadata_cached_same_pointer() {
        let m1 = plugin_log_metadata(Level::INFO, "guest.rs", 10);
        let m2 = plugin_log_metadata(Level::INFO, "guest.rs", 10);
        assert!(std::ptr::eq(m1, m2), "cache must return the same metadata");
        assert_eq!(m1.level(), &Level::INFO);
        assert_eq!(m1.file(), Some("guest.rs"));
        assert_eq!(m1.line(), Some(10));
        assert_eq!(m1.target(), LOG_TARGET);
    }

    /// 不同 level 视为不同调用点：各自独立缓存（字段集一致但级别不同）
    #[test]
    fn plugin_log_metadata_level_is_cache_key_part() {
        let info = plugin_log_metadata(Level::INFO, "guest.rs", 10);
        let warn = plugin_log_metadata(Level::WARN, "guest.rs", 10);
        assert!(!std::ptr::eq(info, warn));
        assert_eq!(info.level(), &Level::INFO);
        assert_eq!(warn.level(), &Level::WARN);
        // file/line 相同：证明 key 区分的是 level
        assert_eq!(info.file(), warn.file());
        assert_eq!(info.line(), warn.line());
    }

    /// 不同 file 视为不同调用点：各自独立缓存
    #[test]
    fn plugin_log_metadata_file_is_cache_key_part() {
        let m1 = plugin_log_metadata(Level::DEBUG, "a.rs", 1);
        let m2 = plugin_log_metadata(Level::DEBUG, "b.rs", 1);
        assert!(!std::ptr::eq(m1, m2));
        assert_eq!(m1.file(), Some("a.rs"));
        assert_eq!(m2.file(), Some("b.rs"));
    }

    // ==================== emit_plugin_log ====================

    /// 消息带 [plugin:{id}] 前缀（保持旧格式，日志可区分来源插件），
    /// 调用点位置透传到 Metadata
    #[test]
    fn emit_plugin_log_formats_message_with_prefix() {
        let captured = capture(|| {
            emit_plugin_log("my-plugin", Level::WARN, "virtual.rs", 42, "boom");
        });
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].level, Level::WARN);
        assert_eq!(captured[0].file, Some("virtual.rs"));
        assert_eq!(captured[0].line, Some(42));
        assert_eq!(captured[0].message, "[plugin:my-plugin] boom");
    }

    /// 四个级别宏映射到对应 Level（组件形态调用点为空字符串/0）
    #[test]
    fn log_level_macros_map_to_levels() {
        let captured = capture(|| {
            log_info("p", "i", "", 0);
            log_debug("p", "d", "", 0);
            log_warn("p", "w", "", 0);
            log_error("p", "e", "", 0);
        });
        assert_eq!(captured.len(), 4);
        let levels: Vec<Level> = captured.iter().map(|e| e.level.clone()).collect();
        assert_eq!(
            levels,
            vec![Level::INFO, Level::DEBUG, Level::WARN, Level::ERROR]
        );
        // 前缀对各级别一致生效
        assert_eq!(captured[3].message, "[plugin:p] e");
    }

    // ==================== per-plugin 日志级别 ====================

    /// env 修改测试串行化：WASMNEST_PLUGIN_LOG 是进程级环境变量，并行测试
    /// 同时 set_var 会互相污染；阈值缓存首次访问后不再重读 env，重置后
    /// 的重新读取同样需要串行保护
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 在受保护区域设置 env + 重置缓存，执行闭包后还原 env
    fn with_plugin_log_env(raw: &str, f: impl FnOnce()) {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("WASMNEST_PLUGIN_LOG").ok();
        std::env::set_var("WASMNEST_PLUGIN_LOG", raw);
        reset_plugin_log_thresholds();
        f();
        reset_plugin_log_thresholds();
        match prev {
            Some(v) => std::env::set_var("WASMNEST_PLUGIN_LOG", v),
            None => std::env::remove_var("WASMNEST_PLUGIN_LOG"),
        }
    }

    /// 解析容错：多条目 / 非法级别忽略 / 空条目忽略 / 未设环境变量空映射
    #[test]
    fn load_plugin_log_thresholds_tolerant_parsing() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("WASMNEST_PLUGIN_LOG", "a=trace,b=warn,,c=verbose,x=");
        let map = load_plugin_log_thresholds();
        std::env::remove_var("WASMNEST_PLUGIN_LOG");
        assert_eq!(map.get("a"), Some(&Level::TRACE));
        assert_eq!(map.get("b"), Some(&Level::WARN));
        // 非法级别（verbose）、空 id、空级别一律忽略
        assert!(!map.contains_key("c"));
        assert!(!map.contains_key("x"));
        assert_eq!(map.len(), 2);

        std::env::remove_var("WASMNEST_PLUGIN_LOG");
        assert!(load_plugin_log_thresholds().is_empty());
    }

    /// 低于阈值的级别被丢弃、高于阈值的正常出现、未列出的插件不受影响
    #[test]
    fn emit_plugin_log_filters_below_threshold() {
        with_plugin_log_env("noisy=warn", || {
            let captured = capture(|| {
                // noisy 阈值 warn：debug/info 丢弃，warn/error 保留
                log_debug("noisy", "d", "", 0);
                log_info("noisy", "i", "", 0);
                log_warn("noisy", "w", "", 0);
                log_error("noisy", "e", "", 0);
                // 未列出的插件沿用全局语义，全部正常出现
                log_debug("quiet", "d", "", 0);
            });
            let levels: Vec<Level> = captured.iter().map(|e| e.level.clone()).collect();
            assert_eq!(levels, vec![Level::WARN, Level::ERROR, Level::DEBUG]);
            assert_eq!(captured[0].message, "[plugin:noisy] w");
            assert_eq!(captured[1].message, "[plugin:noisy] e");
            assert_eq!(captured[2].message, "[plugin:quiet] d");
        });
    }

    /// 未设置环境变量时全部插件不受过滤（回归保护：既有行为不变）
    #[test]
    fn emit_plugin_log_no_env_means_no_filtering() {
        with_plugin_log_env("", || {
            let captured = capture(|| {
                log_debug("any", "d", "", 0);
                log_info("any", "i", "", 0);
            });
            assert_eq!(captured.len(), 2);
        });
    }

    // ==================== 宿主 enabled() 门禁（P0 防回归） ====================

    /// 模拟桌面 error 层 per-layer filter 的订阅者：`enabled()` 仅放行
    /// ERROR（span 全放行，与 `system/logging.rs` error_filter 同判据），
    /// 并计数 `enabled()` 调用次数；`event()` 记录事件供断言。
    ///
    /// 用裸 Subscriber 而非 tracing-subscriber 层：不引入额外依赖
    /// （本 crate 依赖纪律只允许 serde_json / tracing）；判据与捕获语义
    /// 足以复现「per-layer filter 在 enabled() 里判定、事件走 event_enabled」
    /// 的 dispatch 契约。
    struct ErrorOnlySubscriber {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
        enabled_calls: Arc<Mutex<usize>>,
    }

    impl Subscriber for ErrorOnlySubscriber {
        fn enabled(&self, meta: &Metadata<'_>) -> bool {
            *self.enabled_calls.lock().unwrap() += 1;
            if meta.is_span() {
                true
            } else {
                *meta.level() <= Level::ERROR
            }
        }

        fn new_span(&self, _attrs: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

        fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = MessageVisitor(String::new(), Vec::new());
            event.record(&mut visitor);
            self.events.lock().unwrap().push(CapturedEvent {
                level: *event.metadata().level(),
                file: event.metadata().file(),
                line: event.metadata().line(),
                message: visitor.0,
                fields: visitor.1,
            });
        }

        fn enter(&self, _span: &span::Id) {}

        fn exit(&self, _span: &span::Id) {}
    }

    /// 在 ERROR-only 订阅者下运行闭包，返回 (捕获事件, enabled 调用次数)
    fn capture_with_error_only<F: FnOnce()>(f: F) -> (Vec<CapturedEvent>, usize) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let enabled_calls = Arc::new(Mutex::new(0));
        let subscriber = ErrorOnlySubscriber {
            events: events.clone(),
            enabled_calls: enabled_calls.clone(),
        };
        tracing::subscriber::with_default(subscriber, f);
        let captured = events.lock().unwrap().clone();
        let calls = *enabled_calls.lock().unwrap();
        (captured, calls)
    }

    /// P0 回归：非 ERROR 插件日志被宿主 enabled() 门禁拦下，不产生事件。
    /// 修复前直接 `Event::dispatch` 绕过 enabled()（事件走 event_enabled
    /// 默认 true），DEBUG/INFO/WARN 全部泄漏进 error-only 面。
    #[test]
    fn emit_plugin_log_respects_host_error_only_enabled() {
        let (captured, enabled_calls) = capture_with_error_only(|| {
            emit_plugin_log("p", Level::DEBUG, "virtual.rs", 1, "debug leaked");
            emit_plugin_log("p", Level::INFO, "virtual.rs", 2, "info leaked");
            emit_plugin_log("p", Level::WARN, "virtual.rs", 3, "warn leaked");
            emit_plugin_log("p", Level::ERROR, "virtual.rs", 4, "error kept");
        });
        // 门禁必须先经宿主 enabled()：四个级别至少各评估一次（精确值不可断言，
        // 见 reject_all 测试注释；修复前直接 Event::dispatch 该计数为 0）
        assert!(
            enabled_calls >= 4,
            "enabled() must be consulted per event, got {enabled_calls}"
        );
        // 仅 ERROR 通过
        assert_eq!(
            captured.len(),
            1,
            "only ERROR should reach events, got {:?}",
            captured.iter().map(|e| e.level.clone()).collect::<Vec<_>>()
        );
        assert_eq!(captured[0].level, Level::ERROR);
        assert_eq!(captured[0].message, "[plugin:p] error kept");
        assert_eq!(captured[0].file, Some("virtual.rs"));
        assert_eq!(captured[0].line, Some(4));
    }

    /// P0 回归变体：per-plugin 阈值（warn）与宿主 ERROR-only 门禁叠加——
    /// 阈值先于门禁（warn 通过阈值但被门禁拦），error 两者都过
    #[test]
    fn emit_plugin_log_threshold_then_host_enabled_stack() {
        // 插件 id 用 envp：避免与 log_level_macros_map_to_levels 的 "p" 在
        // 并行测试下经进程级 WASMNEST_PLUGIN_LOG 互相污染
        with_plugin_log_env("envp=warn", || {
            let (captured, enabled_calls) = capture_with_error_only(|| {
                emit_plugin_log("envp", Level::DEBUG, "v.rs", 1, "below threshold");
                emit_plugin_log("envp", Level::WARN, "v.rs", 2, "warn meets threshold");
                emit_plugin_log("envp", Level::ERROR, "v.rs", 3, "error both pass");
            });
            // DEBUG 被 per-plugin 阈值丢弃，不进入 enabled()；精确值不可断言
            // （with_default 注册期 callsite 重建会额外计数）
            assert!(
                enabled_calls >= 2,
                "threshold-filtered events skip enabled()"
            );
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].message, "[plugin:envp] error both pass");
        });
    }

    /// P0 回归变体：host enabled() 全拒（模拟 frontend 层 target=frontend
    /// 不匹配）时零事件，且 enabled() 仍被咨询
    #[test]
    fn emit_plugin_log_host_enabled_reject_all_produces_nothing() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let enabled_calls = Arc::new(Mutex::new(0));
        // enabled() 恒 false：等价 target 不匹配的 Targets filter
        struct RejectAll {
            events: Arc<Mutex<Vec<CapturedEvent>>>,
            enabled_calls: Arc<Mutex<usize>>,
        }
        impl Subscriber for RejectAll {
            fn enabled(&self, _meta: &Metadata<'_>) -> bool {
                *self.enabled_calls.lock().unwrap() += 1;
                false
            }
            fn new_span(&self, _attrs: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
            fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut visitor = MessageVisitor(String::new(), Vec::new());
                event.record(&mut visitor);
                self.events.lock().unwrap().push(CapturedEvent {
                    level: *event.metadata().level(),
                    file: event.metadata().file(),
                    line: event.metadata().line(),
                    message: visitor.0,
                    fields: visitor.1,
                });
            }
            fn enter(&self, _span: &span::Id) {}
            fn exit(&self, _span: &span::Id) {}
        }
        let subscriber = RejectAll {
            events: events.clone(),
            enabled_calls: enabled_calls.clone(),
        };
        tracing::subscriber::with_default(subscriber, || {
            emit_plugin_log("p", Level::ERROR, "v.rs", 1, "even error rejected");
        });
        assert!(
            events.lock().unwrap().is_empty(),
            "reject-all enabled() must block all events"
        );
        // enabled() 至少被咨询一次（精确值不可断言：with_default 注册会触发
        // rebuild_callsite_interest，对进程内既有 callsite 重跑 register_callsite）
        assert!(
            *enabled_calls.lock().unwrap() >= 1,
            "enabled() must still be consulted"
        );
    }
}
