//! `host-bus` 实现层（topic 形态机制 + 命名空间/订阅面/互调门禁 + 发布门禁链）
//!
//! 自桌面 `host_api/bus.rs` 与桌面 SDK `host/bus.rs` 上移：
//! **topic 形态即 ACL**——判定只看串，不查激活表，形态边界无时序漏。
//! 队列与订阅簿（背压 / 派发形状）留各端；本模块只承载门禁语义与发布判定链。
//!
//! ## topic 形态机制的真源位置
//!
//! 本模块是**宿主侧单点**；guest 侧拷贝仍在双端 SDK（`host::bus`，桌面有 / 移动
//! 无）。三方逐字一致由双端对照锁钉住。
//!
//! ## 两端策略分叉的端口承载
//!
//! - **权限位**：移动端有（`PERMISSION_BUS` granted 集）、桌面无（形态即 ACL）——
//!   经 [`BusPorts::check_permission`] 承载，发布/订阅函数收 `Option<&PermissionGate>`
//!   （`None` = 该端无权限位策略，如桌面）；
//! - **互调门**：ADR 0017 层 1（`wasmnest.api.<api>` 请求道须命中已激活插件声明
//!   清单）——桌面走 core-security 授权框架；移动 WIT 无 host-api-call 域，适配器
//!   恒放行（= 既有行为）。回复道（`wasmnest.api.reply.`）免校验：回复的调用方即目标。
//!
//! ## 错误文本纪律
//!
//! 桌面 guest 可见错误文本**逐字承自桌面**（trap 文本是既有行为面）；移动端自本批
//! 起对齐同文（此前移动无任何门禁——双份漂移税）。

use serde_json::Value;

use crate::gate::PermissionGate;

// ==================== topic 形态机制（宿主侧单点；guest 侧在双端 SDK） ====================

/// 私有 topic 命名空间分隔符（插件 id 字符集不含 `:`，故无歧义）
pub const TOPIC_NS_SEP: &str = "::";

/// 互调请求道前缀：`wasmnest.api.<api>`（服务方订阅此道接请求）
pub const API_TOPIC_PREFIX: &str = "wasmnest.api.";

/// 互调回复道前缀：`wasmnest.api.reply.<caller>.<request-id>`
///
/// 回复道是 caller 的收件箱，但**不**走私有命名空间：响应者是别的插件，必须能
/// 发布进 caller 的回复道。窃听由「订阅面 host-only」堵（回复订阅由宿主在
/// `host-api-call` 内静态注册），抢答由「宿主校验回复 sender == api 声明属主」堵。
pub const REPLY_TOPIC_PREFIX: &str = "wasmnest.api.reply.";

/// 构造属主私有 topic：`<owner>::<name>`
pub fn owned_topic(owner: &str, name: &str) -> String {
    format!("{owner}{TOPIC_NS_SEP}{name}")
}

/// 解析 topic 的属主（第一个 `::` 之前）；`None` = 公开 topic
pub fn topic_owner(topic: &str) -> Option<&str> {
    topic.split_once(TOPIC_NS_SEP).map(|(owner, _)| owner)
}

/// 是否互调回复道 topic
pub fn is_reply_topic(topic: &str) -> bool {
    topic.starts_with(REPLY_TOPIC_PREFIX)
}

// ==================== 端口 ====================

/// 宿主服务端口（门禁层只认端口，不认任何一端的宿主类型）
///
/// dyn 兼容；实现方 = 各端 adapter（桌面包 BusScope + SecurityScope，移动包
/// `WasmPluginState`）。发布投递是同步调用（总线内部异步派发）；订阅/退订的
/// 投递机制（spawn / block 驱动）留各端，本模块只出**门禁**。
pub trait BusPorts: Send + Sync {
    /// 权限判定（移动端 granted 集消费 `PERMISSION_BUS`；桌面无权限位 → 恒 `true`）。
    /// 返回 `false` 时实现方必须已按 AGENTS §8 落拒绝 warn。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 互调门禁（ADR 0017 层 1）：目标 api 是否命中**已激活插件**的声明清单。
    /// 桌面经 core-security 授权框架三段管线；移动无 host-api-call 域 → 恒 `true`。
    fn authorize_api_call(&self, plugin_id: &str, api: &str) -> bool;

    /// 发布 JSON 消息（同步投递）
    fn publish_json(&self, topic: &str, sender: &str, payload: Value);

    /// 发布二进制消息（v11 语义：字节原样透传，零编解码）
    fn publish_binary(&self, topic: &str, sender: &str, payload: Vec<u8>);
}

// ==================== 门禁（桌面既有语义逐字上移） ====================

/// 命名空间门禁：`<owner>::<name>` 形态的 topic 只有属主插件（与宿主）可读写
///
/// 形态即边界——判定只看串，不查激活表、不看安装表，因此与「属主是否已激活 /
/// 是否已安装」无关，抢在属主之前订阅或伪发布都进不去（这是选命名空间而非
/// 「解析 owner 段」的根本原因：后者的边界会随时序漏）。
pub fn check_namespace(
    plugin_id: &str,
    topic: &str,
    action: &str,
    target: &str,
) -> Result<(), String> {
    let owner = match topic_owner(topic) {
        Some(owner) => owner,
        None => return Ok(()),
    };
    if owner == plugin_id {
        return Ok(());
    }
    tracing::warn!(
        plugin_id = %plugin_id,
        topic = %topic,
        namespace_owner = %owner,
        "bus {action}: cross-namespace topic rejected (topic namespace gate, audit ticket 05)"
    );
    Err(format!(
        "bus error: topic '{topic}' is in the namespace of plugin '{owner}' — only {target} may {action} it"
    ))
}

/// 订阅面门禁（`subscribe` / `subscribe-binary`）：命名空间 + 回复道形态规则
///
/// - 回复道 `wasmnest.api.reply.*`：caller 的收件箱，订阅由宿主在 `host-api-call`
///   内静态注册，对 WASM 一律关闭——此前任意插件可订阅他人回复道窃听互调结果，
///   且 correlation id 是可猜的单调计数器；
pub fn check_subscribe_access(plugin_id: &str, topic: &str) -> Result<(), String> {
    check_namespace(plugin_id, topic, "subscribe", "that plugin (and the host)")?;
    if is_reply_topic(topic) {
        tracing::warn!(
            plugin_id = %plugin_id,
            topic = %topic,
            "bus subscribe: reply lane is host-managed, rejected"
        );
        return Err(format!(
            "bus error: topic '{topic}' is on the inter-plugin reply lane (wasmnest.api.reply.*) \u{2014} reply subscriptions are host-managed by host-api-call"
        ));
    }
    Ok(())
}

/// 互调门禁（ADR 0017 层 1，JSON 与二进制发布共用）：`wasmnest.api.<api>` 请求
/// topic 的目标 api 必须命中某已激活插件的声明清单；`wasmnest.api.reply.` 是响应
/// 通道（回复 topic 的调用方即为目标），免校验；普通广播 topic 不校验。
fn check_api_gate(ports: &dyn BusPorts, plugin_id: &str, topic: &str) -> Result<(), String> {
    if let Some(api) = topic.strip_prefix(API_TOPIC_PREFIX) {
        if !api.starts_with("reply.") && !ports.authorize_api_call(plugin_id, api) {
            tracing::warn!(
                plugin_id = %plugin_id,
                topic = %topic,
                api = %api,
                "bus publish: api call to undeclared api rejected (inter-plugin call gate, ADR-0017)"
            );
            return Err(format!(
                "bus error: api '{}' is not declared by any activated plugin (gate)",
                api
            ));
        }
    }
    Ok(())
}

// ==================== 发布 / 订阅访问（投递机制留各端） ====================

/// 权限位判定（两端策略分叉的统一入口：`None` = 该端无权限位，如桌面——
/// 形态即 ACL）。发布链内部已含本步骤；订阅/退订由 adapter 显式调用
/// （其投递机制各端自持，门禁步骤在投递之前）。
pub fn check_gate(
    ports: &dyn BusPorts,
    plugin_id: &str,
    gate: Option<&PermissionGate<'_>>,
) -> Result<(), String> {
    match gate {
        Some(gate) => {
            if ports.check_permission(plugin_id, gate.permission, gate.api) {
                Ok(())
            } else {
                Err(gate.deny())
            }
        }
        None => Ok(()),
    }
}

/// 发布 JSON 消息（权限位[如有] → JSON 严格解析 → 命名空间 → 互调门 → 投递）
///
/// JSON 解析**严格拒绝**（fail-visible）：降级成字符串会让 guest 以为已投递、
/// 订阅方收到形状不同的载荷——移动端自本批起对齐该语义（此前降级为原始串；
/// SDK 侧 `bus_publish` 收 `serde_json::Value`，序列化
/// 恒为合法 JSON，既有插件不受影响）。
pub fn bus_publish(
    ports: &dyn BusPorts,
    plugin_id: &str,
    topic: &str,
    payload_json: &str,
    gate: Option<&PermissionGate<'_>>,
) -> Result<(), String> {
    check_gate(ports, plugin_id, gate)?;
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|e| format!("bus error: invalid JSON payload: {}", e))?;
    check_namespace(plugin_id, topic, "publish", "that plugin (and the host)")?;
    check_api_gate(ports, plugin_id, topic)?;
    ports.publish_json(topic, plugin_id, payload);
    Ok(())
}

/// 发布二进制消息（权限位[如有] → 命名空间 → 互调门 → 投递；字节原样透传）
pub fn bus_publish_binary(
    ports: &dyn BusPorts,
    plugin_id: &str,
    topic: &str,
    payload: Vec<u8>,
    gate: Option<&PermissionGate<'_>>,
) -> Result<(), String> {
    check_gate(ports, plugin_id, gate)?;
    check_namespace(plugin_id, topic, "publish", "that plugin (and the host)")?;
    check_api_gate(ports, plugin_id, topic)?;
    ports.publish_binary(topic, plugin_id, payload);
    Ok(())
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    /// 假端口：按插件授权集 + api 声明集 + 发布捕获
    struct MockPorts {
        granted: Mutex<HashMap<String, HashSet<String>>>,
        api_declared: Mutex<HashSet<String>>,
        published: Mutex<Vec<(String, String, Value)>>,
        published_binary: Mutex<Vec<(String, String, Vec<u8>)>>,
    }

    impl MockPorts {
        fn new() -> Self {
            Self {
                granted: Mutex::new(HashMap::new()),
                api_declared: Mutex::new(HashSet::new()),
                published: Mutex::new(Vec::new()),
                published_binary: Mutex::new(Vec::new()),
            }
        }

        fn grant(&self, plugin_id: &str, permission: &str) {
            self.granted
                .lock()
                .unwrap()
                .entry(plugin_id.to_string())
                .or_default()
                .insert(permission.to_string());
        }

        fn declare_api(&self, api: &str) {
            self.api_declared.lock().unwrap().insert(api.to_string());
        }
    }

    impl BusPorts for MockPorts {
        fn check_permission(&self, plugin_id: &str, permission: &str, _api: &str) -> bool {
            self.granted
                .lock()
                .unwrap()
                .get(plugin_id)
                .is_some_and(|perms| perms.contains(permission))
        }

        fn authorize_api_call(&self, _plugin_id: &str, api: &str) -> bool {
            self.api_declared.lock().unwrap().contains(api)
        }

        fn publish_json(&self, topic: &str, sender: &str, payload: Value) {
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), sender.to_string(), payload));
        }

        fn publish_binary(&self, topic: &str, sender: &str, payload: Vec<u8>) {
            self.published_binary.lock().unwrap().push((
                topic.to_string(),
                sender.to_string(),
                payload,
            ));
        }
    }

    const PLUGIN: &str = "com.a";
    const PERM: &str = "bus";

    fn gate() -> Option<PermissionGate<'static>> {
        Some(PermissionGate {
            permission: PERM,
            api: "host_bus_publish",
            deny_error: "permission denied: bus",
        })
    }

    // ==================== topic 形态机制（桌面 SDK 用例语义随迁） ====================

    /// 私有 topic 构造 ↔ 解析闭环；多 `::` 取第一段；空属主段仍判为命名空间
    #[test]
    fn topic_form_helpers_roundtrip() {
        let t = owned_topic("com.x", "pty:exit");
        assert_eq!(t, "com.x::pty:exit");
        assert_eq!(topic_owner(&t), Some("com.x"));
        assert_eq!(topic_owner("task:status-changed"), None);
        assert_eq!(topic_owner("com.x::a::b"), Some("com.x"));
        assert_eq!(topic_owner("::x"), Some(""));
    }

    /// 回复道判定（含 `.id` 边界防误判）
    #[test]
    fn reply_form_recognition() {
        assert!(is_reply_topic("wasmnest.api.reply.com.x.req-1"));
        assert!(!is_reply_topic("wasmnest.api.com.x.echo"));
    }

    // ==================== 发布门禁链 ====================

    /// 权限位（移动策略）→ 严格 JSON → 命名空间 → 互调门，逐段文本逐字
    #[test]
    fn publish_json_gate_chain_texts() {
        let ports = MockPorts::new();
        // ① 权限位 deny_error 逐字透传
        assert_eq!(
            bus_publish(&ports, PLUGIN, "t", "{}", gate().as_ref()).unwrap_err(),
            "permission denied: bus"
        );
        // ② 严格 JSON（fail-visible，桌面既有文案；serde 明细文案不钉死——只钉
        //    稳定前缀与「解析失败」语义，防 serde 版本漂移误红）
        ports.grant(PLUGIN, PERM);
        let err = bus_publish(&ports, PLUGIN, "t", "not-json", gate().as_ref()).unwrap_err();
        assert!(
            err.starts_with("bus error: invalid JSON payload:") && err.contains("expected"),
            "got: {err}"
        );
        // ③ 他人命名空间伪发布拒绝（点名属主）
        let err = bus_publish(
            &ports,
            PLUGIN,
            "com.victim::pty:exit",
            "{}",
            gate().as_ref(),
        )
        .unwrap_err();
        assert!(
            err.contains("namespace") && err.contains("com.victim"),
            "got: {err}"
        );
        // ④ 互调门：未声明 api 拒绝（点名 api）
        let err = bus_publish(
            &ports,
            PLUGIN,
            "wasmnest.api.com.x.remove",
            "{}",
            gate().as_ref(),
        )
        .unwrap_err();
        assert!(
            err.contains("not declared") && err.contains("com.x.remove"),
            "got: {err}"
        );
        // ⑤ 互调门：已声明 api 放行
        ports.declare_api("com.x.add");
        bus_publish(
            &ports,
            PLUGIN,
            "wasmnest.api.com.x.add",
            r#"{"jsonrpc":"2.0"}"#,
            gate().as_ref(),
        )
        .expect("declared api must pass gate");
        // ⑥ 回复道免互调校验
        bus_publish(
            &ports,
            PLUGIN,
            "wasmnest.api.reply.com.b.req-1",
            r#"{"ok":1}"#,
            gate().as_ref(),
        )
        .expect("reply lane must bypass api gate");
        // ⑦ 公开 topic + 自有命名空间放行，载荷原样投递
        bus_publish(
            &ports,
            PLUGIN,
            "task:status-changed",
            r#"{"n":1}"#,
            gate().as_ref(),
        )
        .expect("public ok");
        bus_publish(
            &ports,
            PLUGIN,
            "com.a::inbox",
            r#"{"n":2}"#,
            gate().as_ref(),
        )
        .expect("own ns ok");
        let published = ports.published.lock().unwrap();
        assert_eq!(published.len(), 4);
        assert_eq!(published[0].2, serde_json::json!({"jsonrpc": "2.0"}));
        assert_eq!(published[3].0, "com.a::inbox");
        assert_eq!(published[3].2, serde_json::json!({"n":2}));
    }

    /// 无权限位策略（桌面形态）：gate = None 时权限判定整个跳过
    #[test]
    fn publish_without_permission_gate_skips_permission_check() {
        let ports = MockPorts::new();
        bus_publish(&ports, PLUGIN, "t", "{}", None).expect("no gate = no permission check");
    }

    /// 二进制发布：同一套门禁 + 字节原样透传
    #[test]
    fn publish_binary_gates_and_bytes_passthrough() {
        let ports = MockPorts::new();
        ports.grant(PLUGIN, PERM);
        let err = bus_publish_binary(
            &ports,
            PLUGIN,
            "com.victim::blob",
            vec![1, 2],
            gate().as_ref(),
        )
        .unwrap_err();
        assert!(err.contains("namespace"), "got: {err}");
        bus_publish_binary(
            &ports,
            PLUGIN,
            "com.a::blob",
            vec![1, 2, 3],
            gate().as_ref(),
        )
        .expect("own ns ok");
        bus_publish_binary(&ports, PLUGIN, "task:chunk", vec![9], gate().as_ref())
            .expect("public ok");
        let published = ports.published_binary.lock().unwrap();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].2, vec![1, 2, 3]);
    }

    // ==================== 订阅 / 退订门禁 ====================

    /// 订阅面：他人命名空间 / 回复道（含自身）/ legacy 拒绝；自有命名空间、
    /// 请求道、公开 topic 放行；legacy 拒绝文案回带新形态
    #[test]
    fn subscribe_access_gate_texts() {
        let err = check_subscribe_access("com.evil", "com.victim::pty:exit").unwrap_err();
        assert!(
            err.contains("namespace") && err.contains("com.victim"),
            "got: {err}"
        );
        let err =
            check_subscribe_access("com.evil", "wasmnest.api.reply.com.victim.req-1").unwrap_err();
        assert!(err.contains("reply"), "got: {err}");
        let err = check_subscribe_access("com.victim", "wasmnest.api.reply.com.victim.req-1")
            .unwrap_err();
        assert!(err.contains("reply"), "自身回复道亦不对 WASM 开放: {err}");
        check_subscribe_access("com.victim", "com.victim::pty:exit").expect("own ns ok");
        check_subscribe_access("com.victim", "wasmnest.api.com.victim.echo")
            .expect("request lane ok");
        check_subscribe_access("com.evil", "peer:consent").expect("public ok");
    }

    /// 退订只过命名空间门：回复道不拦（清理动作幂等可用）
    #[test]
    fn unsubscribe_gate_is_namespace_only() {
        assert!(check_namespace(
            "com.evil",
            "com.victim::t",
            "unsubscribe",
            "that plugin (and the host)"
        )
        .is_err());
        check_namespace(
            "com.victim",
            "wasmnest.api.reply.com.victim.req-1",
            "unsubscribe",
            "that plugin (and the host)",
        )
        .expect("回复道退订放行");
    }
}
