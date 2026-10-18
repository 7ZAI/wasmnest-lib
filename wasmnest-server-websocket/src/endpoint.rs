//! 插件 WS 端点注册表（服务端域，spec `.scratch/2026-09-18-ws-base-service/`）
//!
//! **职责边界（spec D1 零业务代码红线）**：本表只登记引擎级事实——属主、路径后缀、
//! 认证策略、上限、事件总线；不解读、不拼装任何业务字段（消息格式 / 房间 / 协议 /
//! 重连策略一律归插件）。
//!
//! - **命名空间注入（D5）**：插件只提供后缀 `path`，宿主拼出完整挂载路径
//!   `/ws/plugin/<plugin-id>/<path>`——属主段由宿主按调用方注入，插件之间
//!   不存在路径抢占（不同属主物理上挂不到同一路径）；
//! - **属主隔离**：冲突只在同插件内判定（同属主同后缀 → 拒绝）；回收
//!   （[`purge_for_plugin`]）只命中本人端点；
//! - **与 [`super::registry::WsSessionRegistry`] 的分工**：本表是**端点级**（挂载点）
//!   注册，会话注册表是**连接级**（在线客户端）注册；`clientCount` 等在线数据取自后者。
//!
//! 上限语义（spec §4.4）：端点数超限 → 注册返回 `Err` 且无副作用；插件传入的
//! `maxClients` / `maxMessageBytes` 一律按宿主常量 / 配置上限截断（插件不能放宽
//! 宿主安全边界）。

use wasmnest_server_base::constants::{PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT, PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN};
use wasmnest_server_base::ports::BusPort;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

/// 端点句柄前缀（`wse-<uuid>`；与客户端域 `wsc-<uuid>` 对称）
pub const ENDPOINT_HANDLE_PREFIX: &str = "wse-";

/// 插件端点挂载路径前缀：完整路径 `{PREFIX}/{plugin_id}/{path}`（spec D5）
pub const PLUGIN_ENDPOINT_ROUTE_PREFIX: &str = "/ws/plugin";

/// 端点认证档位（spec D8）——本 crate 自持副本（[`crate::wire`]，能力域脱绑 P3：
/// 与桌面 SDK 原版逐字一致由平台仓漂移锁
/// `cross-end-tests/tests/wire_drift_locks.rs` 钉死，漂移即红）
///
/// 票 08 起 WS 注册面与 HTTP 声明面共用这一张表，避免「两 transport 各自抄一遍
/// `none|jwt`」的词汇漂移。缺省档位各面自己给：WS = `None`（本文件，历史行为），
/// HTTP = `Jwt`（见 `wasm_core::manager::registry`，票 08 裁决 1「未声明即最严」）。
pub use crate::wire::EndpointAuth;

/// 已注册端点（克隆开销 = 一次 `Arc` + 三个短字符串）
#[derive(Clone)]
pub struct EndpointEntry {
    /// 端点句柄（`wse-<uuid>`，插件侧寻址入口）
    pub endpoint_id: String,
    /// 属主插件 id（宿主注入的命名空间段）
    pub owner: String,
    /// 插件提供的路径后缀
    pub path: String,
    /// 完整挂载路径 `/ws/plugin/<owner>/<path>`
    pub mount_path: String,
    /// 首消息认证策略
    pub auth: EndpointAuth,
    /// 入站客户端数上限（已按 `PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT` 截断）
    pub max_clients: usize,
    /// 单帧 / 单消息字节上限（已按宿主配置上限截断）
    pub max_message_bytes: usize,
    /// 该端点的事件总线 + 帧投递端口（注册时宿主壳注入；连接侧不依赖
    /// 端口实现由宿主壳注入，测试可用自建假端口直接驱动与断言）
    pub bus: Arc<dyn BusPort>,
}

/// 手工 Debug（`dyn BusPort` 不实现 Debug；端点标识与上限是排障所需字段）
impl std::fmt::Debug for EndpointEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointEntry")
            .field("endpoint_id", &self.endpoint_id)
            .field("owner", &self.owner)
            .field("path", &self.path)
            .field("mount_path", &self.mount_path)
            .field("auth", &self.auth)
            .field("max_clients", &self.max_clients)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish_non_exhaustive()
    }
}

/// 端点表（按句柄索引 + 按挂载路径反查）
#[derive(Default)]
struct EndpointTable {
    by_id: HashMap<String, EndpointEntry>,
    id_by_mount: HashMap<String, String>,
}

static ENDPOINTS: LazyLock<Mutex<EndpointTable>> = LazyLock::new(|| Mutex::new(EndpointTable::default()));

/// 统一取锁（毒化后继续使用：本表为纯数据表，不持锁执行会 panic 的表达式）
fn lock() -> std::sync::MutexGuard<'static, EndpointTable> {
    ENDPOINTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// 由属主与后缀拼出完整挂载路径（单一事实源，路由与注册共用）
pub fn mount_path(owner: &str, path: &str) -> String {
    format!("{PLUGIN_ENDPOINT_ROUTE_PREFIX}/{owner}/{path}")
}

/// 注册端点（上限截断 + 同插件冲突判定；失败零副作用）
///
/// 冲突判定按**完整挂载路径**（含属主段）——同属主同后缀视为冲突，
/// 不同属主物理上不可能相同（路径内嵌 plugin-id）。
pub fn register(
    owner: &str,
    path: &str,
    auth: EndpointAuth,
    max_clients: Option<usize>,
    max_message_bytes: Option<usize>,
    bus: Arc<dyn BusPort>,
) -> Result<EndpointEntry, String> {
    let mut table = lock();

    // 端点数上限：超限直接 Err，不产生任何副作用（spec §4.4）
    let owned = table.by_id.values().filter(|e| e.owner == owner).count();
    if owned >= PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN {
        return Err(format!(
            "ws register-endpoint: endpoint limit reached ({PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN})"
        ));
    }

    let mount = mount_path(owner, path);
    if table.id_by_mount.contains_key(&mount) {
        return Err(format!("ws register-endpoint: path already registered: {mount}"));
    }

    // 宿主配置上限为硬边界：插件只能收紧，不能放宽（spec §4.4 上限截断为常量）
    let host_limit = crate::routes::ws_frame_limit().max(1);
    let entry = EndpointEntry {
        endpoint_id: format!("{ENDPOINT_HANDLE_PREFIX}{}", uuid::Uuid::new_v4()),
        owner: owner.to_string(),
        path: path.to_string(),
        mount_path: mount.clone(),
        auth,
        max_clients: max_clients
            .unwrap_or(PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT)
            .clamp(1, PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT),
        max_message_bytes: max_message_bytes.map_or(host_limit, |v| v.clamp(1, host_limit)),
        bus,
    };

    table.id_by_mount.insert(mount, entry.endpoint_id.clone());
    table.by_id.insert(entry.endpoint_id.clone(), entry.clone());
    tracing::info!(
        plugin_id = %owner,
        endpoint_id = %entry.endpoint_id,
        mount_path = %entry.mount_path,
        auth = entry.auth.as_str(),
        max_clients = entry.max_clients,
        "plugin ws endpoint registered"
    );
    Ok(entry)
}

/// 按句柄取端点
pub fn get(endpoint_id: &str) -> Option<EndpointEntry> {
    lock().by_id.get(endpoint_id).cloned()
}

/// 按完整挂载路径取端点（路由分发唯一入口）
pub fn find_by_mount(mount: &str) -> Option<EndpointEntry> {
    let table = lock();
    let id = table.id_by_mount.get(mount)?;
    table.by_id.get(id).cloned()
}

/// 该属主是否拥有此端点（属主仲裁：跨插件调用一律拒绝）
pub fn is_owner(endpoint_id: &str, owner: &str) -> bool {
    lock().by_id.get(endpoint_id).is_some_and(|e| e.owner == owner)
}

/// 本插件的端点清单（`list-endpoints` 数据源）
pub fn list_by_owner(owner: &str) -> Vec<EndpointEntry> {
    let mut entries: Vec<EndpointEntry> = lock().by_id.values().filter(|e| e.owner == owner).cloned().collect();
    // 稳定顺序（按挂载路径升序）：清单输出可预测，便于插件与测试断言
    entries.sort_by(|a, b| a.mount_path.cmp(&b.mount_path));
    entries
}

/// 摘除端点（返回被摘除的条目；未知句柄 → `None`）
pub fn remove(endpoint_id: &str) -> Option<EndpointEntry> {
    let mut table = lock();
    let entry = table.by_id.remove(endpoint_id)?;
    table.id_by_mount.remove(&entry.mount_path);
    Some(entry)
}

/// 回收该属主的全部端点（插件停用 / 卸载；只碰本人）
pub fn purge_for_plugin(owner: &str) -> Vec<EndpointEntry> {
    let entries = list_by_owner(owner);
    for entry in &entries {
        remove(&entry.endpoint_id);
    }
    if !entries.is_empty() {
        tracing::info!(
            plugin_id = %owner,
            endpoints = entries.len(),
            "plugin ws endpoints purged"
        );
    }
    entries
}

/// 本插件已注册端点数
pub fn count_by_owner(owner: &str) -> usize {
    lock().by_id.values().filter(|e| e.owner == owner).count()
}

/// 清空全部端点（仅测试用：全局表在 test 进程内跨用例共享）
#[cfg(test)]
pub fn clear_all() {
    let mut table = lock();
    table.by_id.clear();
    table.id_by_mount.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmnest_server_base::ports::BusMessageHandler;

    /// 唯一属主（全局表按属主隔离，并行用例互不干扰）
    fn owner(seed: &str) -> String {
        format!("test-endpoint-{seed}")
    }

    fn register_path(owner: &str, path: &str) -> Result<EndpointEntry, String> {
        register(owner, path, EndpointAuth::None, None, None, Arc::new(TestBus))
    }

    /// 测试假总线（端点表只存句柄不调用；无头/单测上下文）
    struct TestBus;
    #[async_trait::async_trait]
    impl BusPort for TestBus {
        fn publish(&self, _topic: &str, _sender: &str, _payload: serde_json::Value) {}
        fn publish_binary(&self, _topic: &str, _sender: &str, _payload: Vec<u8>) {}
        async fn subscribe_static(&self, _subscriber: &str, _topic: &str, _handler: Box<dyn BusMessageHandler>) {}
        async fn deliver_endpoint_frame(
            &self,
            _owner: &str,
            _endpoint_id: &str,
            _client_id: &str,
            _kind: &str,
            _payload: Vec<u8>,
        ) {
        }
    }

    /// WS 注册面的档位**策略**：缺省 = `none`（插件自管首消息认证，历史行为）。
    /// 档位词汇本身由 SDK 锁（`EndpointAuth::parse_with` 及其 SDK 单测），这里只锁
    /// WS 传给它的缺省档与「未定义取值不回落」这两条 transport 级判据。
    #[test]
    fn ws_endpoint_auth_defaults_to_none_and_rejects_unknown() {
        let d = |raw: Option<&str>| EndpointAuth::parse_with(raw, EndpointAuth::None);
        assert_eq!(d(None).unwrap(), EndpointAuth::None);
        assert_eq!(d(Some("")).unwrap(), EndpointAuth::None);
        assert_eq!(d(Some(" none ")).unwrap(), EndpointAuth::None);
        assert_eq!(d(Some("jwt")).unwrap(), EndpointAuth::Jwt);
        // 未定义取值必须报错（不静默降级为 none —— 认证策略错误方向危险）
        for bad in ["JWT", "token"] {
            let err = d(Some(bad)).expect_err("未定义档位不得回落到缺省档");
            assert!(
                err.contains(bad) && err.contains("none") && err.contains("jwt"),
                "文案须点明非法取值与合法档位: {err}"
            );
        }
    }

    #[test]
    fn mount_path_injects_owner_namespace() {
        assert_eq!(mount_path("com.a", "chat"), "/ws/plugin/com.a/chat");
        // 属主段由宿主注入：不同插件的同后缀路径互不相同（无跨插件抢占）
        assert_ne!(mount_path("com.a", "chat"), mount_path("com.b", "chat"));
    }

    #[test]
    fn register_conflict_and_lookup_roundtrip() {
        let plugin = owner("roundtrip");
        assert_eq!(count_by_owner(&plugin), 0);

        let entry = register_path(&plugin, "chat").expect("register");
        assert!(entry.endpoint_id.starts_with(ENDPOINT_HANDLE_PREFIX), "句柄前缀");
        assert_eq!(entry.max_clients, PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT, "缺省取宿主上限");
        assert_eq!(count_by_owner(&plugin), 1);

        // 反查 / 属主仲裁
        let found = find_by_mount(&entry.mount_path).expect("find by mount");
        assert_eq!(found.endpoint_id, entry.endpoint_id);
        assert!(is_owner(&entry.endpoint_id, &plugin));
        assert!(!is_owner(&entry.endpoint_id, "someone-else"));

        // 同插件同后缀 → 冲突拒绝（不产生第二条端点）
        let conflict = register_path(&plugin, "chat").expect_err("duplicate rejected");
        assert!(conflict.contains("already registered"), "got: {conflict}");
        assert_eq!(count_by_owner(&plugin), 1, "冲突不得产生副作用");

        // 未知句柄 / 路径：None，不 panic
        assert!(get("wse-none").is_none());
        assert!(find_by_mount("/ws/plugin/none/x").is_none());
        assert!(remove("wse-none").is_none());

        // 摘除后反查失效
        assert!(remove(&entry.endpoint_id).is_some());
        assert!(find_by_mount(&entry.mount_path).is_none());
        assert_eq!(count_by_owner(&plugin), 0);
    }

    #[test]
    fn register_enforces_endpoint_limit_without_side_effects() {
        let plugin = owner("limit");
        for i in 0..PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN {
            register_path(&plugin, &format!("p{i}")).expect("register within limit");
        }
        let err = register_path(&plugin, "over").expect_err("over limit rejected");
        assert!(err.contains("endpoint limit reached"), "got: {err}");
        assert_eq!(
            count_by_owner(&plugin),
            PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN,
            "超限拒绝不得留下副作用"
        );

        // 清理本用例端点（全局表跨用例共享）
        for entry in list_by_owner(&plugin) {
            remove(&entry.endpoint_id);
        }
    }

    #[test]
    fn limits_are_clamped_to_host_boundaries() {
        let plugin = owner("clamp");
        // 插件只能收紧，不能放宽：超限值被截断为宿主上限
        let entry = register(
            &plugin,
            "clamp",
            EndpointAuth::Jwt,
            Some(PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT + 1000),
            Some(usize::MAX),
            Arc::new(TestBus),
        )
        .expect("register");
        assert_eq!(entry.max_clients, PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT);
        assert_eq!(entry.max_message_bytes, crate::routes::ws_frame_limit().max(1));

        // 下限保护：0 被抬到 1（不能注册出「任何连接都拒绝」的端点）
        let zero =
            register(&plugin, "zero", EndpointAuth::None, Some(0), Some(0), Arc::new(TestBus)).expect("register");
        assert_eq!(zero.max_clients, 1);
        assert_eq!(zero.max_message_bytes, 1);

        for entry in list_by_owner(&plugin) {
            remove(&entry.endpoint_id);
        }
    }

    #[test]
    fn purge_only_touches_owner_and_is_idempotent() {
        let victim = owner("purge");
        let bystander = owner("purge-bystander");
        let victim_entry = register_path(&victim, "chat").expect("victim register");
        let bystander_entry = register_path(&bystander, "chat").expect("bystander register");

        let purged = purge_for_plugin(&victim);
        assert_eq!(purged.len(), 1);
        assert_eq!(purged[0].endpoint_id, victim_entry.endpoint_id);
        assert!(find_by_mount(&victim_entry.mount_path).is_none(), "本人端点已摘除");
        assert!(find_by_mount(&bystander_entry.mount_path).is_some(), "他人端点不受影响");
        // 幂等：再次回收命中 0
        assert!(purge_for_plugin(&victim).is_empty());

        remove(&bystander_entry.endpoint_id);
    }

    #[test]
    fn list_by_owner_is_stable_and_scoped() {
        let plugin = owner("list");
        let other = owner("list-other");
        for path in ["zeta", "alpha"] {
            register_path(&plugin, path).expect("register");
        }
        register_path(&other, "mine").expect("register other");

        let paths: Vec<String> = list_by_owner(&plugin).into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec!["alpha", "zeta"], "按挂载路径升序，且不含他人端点");

        for entry in list_by_owner(&plugin) {
            remove(&entry.endpoint_id);
        }
        for entry in list_by_owner(&other) {
            remove(&entry.endpoint_id);
        }
    }
}
