//! 插件 HTTP 端点动态注册表（ABI v29 服务端域，spec
//! `.scratch/2026-09-25-http-route-registration-downsink/`）
//!
//! **职责边界（无业务内核红线）**：本表只登记引擎级事实——属主、内部端点段、对外
//! URL 别名、方法、认证档位；不解读、不拼装任何业务字段（URL 形状、模板段名、
//! 认证语义全部由插件声明）。
//!
//! - **命名空间注入（用户裁定 ⑤）**：插件只提供相对端点段 `path`，宿主拼出内部
//!   可达路径 `/api/plugin/<plugin-id>/<path>`——属主段由宿主按调用方注入，插件之间
//!   不存在内部路径抢占；
//! - **对外 URL 空间唯一（用户裁定 ⑤ 双保险）**：同一 `host_path + method` 已被
//!   注册 → 后注册者 `Err`（fail-visible，不覆盖在位者）。跨插件与同插件一律仲裁；
//! - **属主隔离**：回收（[`purge_for_plugin`]）只命中本人；注销他人端点 → `Err`；
//! - **模板匹配**：host 路径支持 `{name}` 模板段（段名 `[a-zA-Z_]\w*`，注册期校验）；
//!   捕获值经路由侧 `params` 字段传给插件，宿主**不拿捕获值构造任何路径**（防注入）。
//!
//! 上限语义：端点数超限 → 注册返回 `Err` 且无副作用（常量
//! [`PLUGIN_HTTP_MAX_ENDPOINTS_PER_PLUGIN`]）。

use crate::wire::EndpointAuth;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use wasmnest_server_base::constants::PLUGIN_HTTP_MAX_ENDPOINTS_PER_PLUGIN;

/// 端点句柄前缀（`http-<uuid>`；与 WS 端点 `wse-<uuid>` 形态对称）
pub const ENDPOINT_HANDLE_PREFIX: &str = "http-";

/// 插件内部路由前缀：完整内部路径 `{PREFIX}/{plugin_id}/{path}`（命名空间注入）
pub const PLUGIN_ROUTE_PREFIX: &str = "/api/plugin";

/// 一次 host 路径匹配结果（路由侧据此转发 + 注入模板捕获参数）
#[derive(Debug, Clone)]
pub struct HostMatch {
    pub entry: HttpRouteEntry,
    /// 模板段捕获值（`{id}` → 请求路径对应段；精确命中时为空）
    pub params: HashMap<String, String>,
}

/// 已注册端点
#[derive(Debug, Clone)]
pub struct HttpRouteEntry {
    /// 端点句柄（`http-<uuid>`，插件侧注销寻址入口）
    pub endpoint_id: String,
    /// 属主插件 id（宿主注入的命名空间段）
    pub owner: String,
    /// 插件提供的相对端点段（`_http_endpoint` 的 `path` 字段）
    pub path: String,
    /// 内部可达路径 `/api/plugin/<owner>/<path>`
    pub internal_path: String,
    /// 对外 URL 别名（None = 无别名，仅内部路径可达）
    pub host_path: Option<String>,
    /// host 别名的允许方法（内部路径可达性不受方法限制——插件自答 405）
    pub methods: Vec<String>,
    /// 认证档位（路由侧据此决定是否要求宿主已验签）
    pub auth: EndpointAuth,
}

/// 端点表：按句柄索引 + 内部路径反查 + host 别名（路径,方法）反查
#[derive(Default)]
struct RouteTable {
    by_id: HashMap<String, HttpRouteEntry>,
    id_by_internal: HashMap<String, String>,
    id_by_host: HashMap<(String, String), String>,
}

static ROUTES: LazyLock<Mutex<RouteTable>> = LazyLock::new(|| Mutex::new(RouteTable::default()));

/// 统一取锁（毒化后继续使用：本表为纯数据表）
fn lock() -> std::sync::MutexGuard<'static, RouteTable> {
    ROUTES.lock().unwrap_or_else(|e| e.into_inner())
}

// ==================== 路径形状工具 ====================

/// 路径 → 段列表（空段剔除：前导/尾随/连续 `/` 不产生空段）
fn split_segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// 模板段解析：`{name}` → Some(name)（段名必须 `[a-zA-Z_]\w*`，否则 None）
fn template_segment(seg: &str) -> Option<&str> {
    let inner = seg.strip_prefix('{')?.strip_suffix('}')?;
    let mut chars = inner.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(inner)
}

/// host 路径注册期校验：每段要么是合法模板段，要么是普通字面量（不含 `{`/`}`）
fn validate_host_template(path: &str) -> Result<(), String> {
    for seg in split_segments(path) {
        if seg.contains('{') || seg.contains('}') {
            if template_segment(seg).is_none() {
                return Err(format!(
                    "http register-endpoint: invalid template segment '{seg}' in host path '{path}' \
                     (template segments must be {{name}} with name matching [a-zA-Z_]\\w*)"
                ));
            }
        }
    }
    Ok(())
}

/// 简单百分号解码（`%XX`）；畸形编码 → None（该路径不命中模板匹配，fail-closed）
fn percent_decode(seg: &str) -> Option<String> {
    if !seg.contains('%') {
        return Some(seg.to_string());
    }
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ==================== 注册 ====================

/// 注册插件端点（上限 + 内部路径冲突 + host 别名冲突；失败零副作用）
///
/// - `path`：插件内相对端点段（trim + 去前导 `/` 归一）；空段拒绝。
/// - `host_path`：对外别名（必须以 `/` 开头；支持 `{name}` 模板段）。
/// - `methods`：host 别名的允许方法；空 → 缺省 `["GET"]`。
/// - `auth`：认证档位（缺省语义由调用方给定：HTTP 面未声明即最严 `jwt`）。
pub fn register(
    owner: &str,
    path: &str,
    host_path: Option<&str>,
    methods: &[String],
    auth: EndpointAuth,
) -> Result<HttpRouteEntry, String> {
    let mut table = lock();

    // 端点数上限：超限直接 Err，不产生任何副作用
    let owned = table.by_id.values().filter(|e| e.owner == owner).count();
    if owned >= PLUGIN_HTTP_MAX_ENDPOINTS_PER_PLUGIN {
        return Err(format!(
            "http register-endpoint: endpoint limit reached ({PLUGIN_HTTP_MAX_ENDPOINTS_PER_PLUGIN})"
        ));
    }

    let path = path.trim().trim_start_matches('/');
    if path.is_empty() {
        return Err("http register-endpoint: path must not be empty".to_string());
    }
    let internal_path = format!("{PLUGIN_ROUTE_PREFIX}/{owner}/{path}");
    if table.id_by_internal.contains_key(&internal_path) {
        return Err(format!(
            "http register-endpoint: internal path already registered: {internal_path}"
        ));
    }

    // host 别名：形状校验（`/` 开头 + 模板段合法）+ 对外 URL 空间冲突仲裁
    // + 宿主自有面保护（引擎端点不可被插件别名占用：/api/health 健康检查与
    // /api/plugin 插件代理前缀是宿主路由面，插件别名占用会劫持或遮蔽宿主面）
    let mut host: Option<String> = None;
    let mut effective_methods: Vec<String> = Vec::new();
    if let Some(h) = host_path {
        let h = h.trim();
        if h.is_empty() {
            return Err("http register-endpoint: host path must not be empty".to_string());
        }
        if !h.starts_with('/') {
            return Err(format!("http register-endpoint: host path must start with '/': {h}"));
        }
        if h == "/api/health" || h.starts_with("/api/plugin") {
            return Err(format!(
                "http register-endpoint: host path '{h}' is reserved by the host HTTP surface"
            ));
        }
        validate_host_template(h)?;
        effective_methods = if methods.is_empty() {
            vec!["GET".to_string()]
        } else {
            methods.to_vec()
        };
        for m in &effective_methods {
            let key = (h.to_string(), m.to_string());
            if let Some(existing_id) = table.id_by_host.get(&key) {
                let existing = table.by_id.get(existing_id).map(|e| e.owner.as_str()).unwrap_or("?");
                return Err(format!(
                    "http register-endpoint: host path '{h}' with method {m} already registered by plugin '{existing}'"
                ));
            }
        }
        host = Some(h.to_string());
    }

    let entry = HttpRouteEntry {
        endpoint_id: format!("{ENDPOINT_HANDLE_PREFIX}{}", uuid::Uuid::new_v4()),
        owner: owner.to_string(),
        path: path.to_string(),
        internal_path: internal_path.clone(),
        host_path: host.clone(),
        methods: effective_methods.clone(),
        auth,
    };

    table.by_id.insert(entry.endpoint_id.clone(), entry.clone());
    table.id_by_internal.insert(internal_path, entry.endpoint_id.clone());
    if let Some(h) = &host {
        for m in &effective_methods {
            table
                .id_by_host
                .insert((h.clone(), m.clone()), entry.endpoint_id.clone());
        }
    }
    tracing::info!(
        plugin_id = %owner,
        endpoint_id = %entry.endpoint_id,
        internal_path = %entry.internal_path,
        host_path = %host.as_deref().unwrap_or("(none)"),
        auth = auth.as_str(),
        "plugin http endpoint registered"
    );
    Ok(entry)
}

// ==================== 查询 ====================

/// 按句柄取端点
pub fn get(endpoint_id: &str) -> Option<HttpRouteEntry> {
    lock().by_id.get(endpoint_id).cloned()
}

/// 按内部路径取端点（`/api/plugin/*` 路由分发唯一入口）
pub fn find_by_internal(internal_path: &str) -> Option<HttpRouteEntry> {
    let table = lock();
    let id = table.id_by_internal.get(internal_path)?;
    table.by_id.get(id).cloned()
}

/// 按对外别名（路径 + 方法）匹配端点：精确命中优先，其次模板匹配。
///
/// 返回命中条目与模板捕获参数（精确命中时 params 为空）。
pub fn find_by_host(path: &str, method: &str) -> Option<HostMatch> {
    let table = lock();

    // 1. 精确匹配（path, method）
    if let Some(id) = table.id_by_host.get(&(path.to_string(), method.to_string())) {
        let entry = table.by_id.get(id)?.clone();
        return Some(HostMatch {
            entry,
            params: HashMap::new(),
        });
    }

    // 2. 模板匹配：逐条扫描含模板段的 host 别名（条数小，线性足够）
    let path_segments = split_segments(path);
    let candidates: Vec<HttpRouteEntry> = table
        .by_id
        .values()
        .filter(|e| e.host_path.as_ref().is_some_and(|h| h.contains('{')))
        .cloned()
        .collect();
    drop(table);
    for entry in candidates {
        let host = entry.host_path.as_ref()?;
        if !entry.methods.iter().any(|m| m == method) {
            continue;
        }
        let host_segments = split_segments(host);
        if host_segments.len() != path_segments.len() {
            continue;
        }
        let mut params = HashMap::new();
        let mut matched = true;
        for (hs, ps) in host_segments.iter().zip(&path_segments) {
            if let Some(name) = template_segment(hs) {
                let Some(value) = percent_decode(ps) else {
                    matched = false;
                    break;
                };
                if value.is_empty() {
                    matched = false;
                    break;
                }
                params.insert(name.to_string(), value);
            } else if *hs != *ps {
                matched = false;
                break;
            }
        }
        if matched {
            return Some(HostMatch { entry, params });
        }
    }
    None
}

/// 该属主是否拥有此端点（属主仲裁：跨插件注销一律拒绝）
pub fn is_owner(endpoint_id: &str, owner: &str) -> bool {
    lock().by_id.get(endpoint_id).is_some_and(|e| e.owner == owner)
}

/// 本插件的端点清单（稳定顺序：按内部路径升序）
pub fn list_by_owner(owner: &str) -> Vec<HttpRouteEntry> {
    let mut entries: Vec<HttpRouteEntry> = lock().by_id.values().filter(|e| e.owner == owner).cloned().collect();
    entries.sort_by(|a, b| a.internal_path.cmp(&b.internal_path));
    entries
}

/// 本插件已注册端点数
pub fn count_by_owner(owner: &str) -> usize {
    lock().by_id.values().filter(|e| e.owner == owner).count()
}

// ==================== 注销 / 回收 ====================

/// 注销端点（属主仲裁）：未知句柄 → `Ok(false)`（幂等）；他人句柄 → `Err`
pub fn remove_if_owner(endpoint_id: &str, owner: &str) -> Result<bool, String> {
    let mut table = lock();
    let Some(entry) = table.by_id.remove(endpoint_id) else {
        return Ok(false);
    };
    if entry.owner != owner {
        // 拒绝不得消费句柄：原样放回
        table.by_id.insert(endpoint_id.to_string(), entry);
        return Err("not owner of http endpoint".to_string());
    }
    table.id_by_internal.remove(&entry.internal_path);
    if let Some(h) = &entry.host_path {
        for m in &entry.methods {
            table.id_by_host.remove(&(h.clone(), m.clone()));
        }
    }
    tracing::info!(
        plugin_id = %owner,
        endpoint_id = %endpoint_id,
        internal_path = %entry.internal_path,
        "plugin http endpoint unregistered"
    );
    Ok(true)
}

/// 回收该属主的全部端点（插件停用 / 卸载；只碰本人）
pub fn purge_for_plugin(owner: &str) -> Vec<HttpRouteEntry> {
    let entries = list_by_owner(owner);
    for entry in &entries {
        let _ = remove_if_owner(&entry.endpoint_id, owner);
    }
    if !entries.is_empty() {
        tracing::info!(
            plugin_id = %owner,
            endpoints = entries.len(),
            "plugin http endpoints purged"
        );
    }
    entries
}

/// 清空全部端点（仅测试用：全局表在 test 进程内跨用例共享）
#[cfg(test)]
pub fn clear_all() {
    let mut table = lock();
    table.by_id.clear();
    table.id_by_internal.clear();
    table.id_by_host.clear();
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 唯一属主（全局表按属主隔离，并行用例互不干扰）
    fn owner(seed: &str) -> String {
        format!("test-http-{seed}")
    }

    fn register_path(owner: &str, path: &str) -> Result<HttpRouteEntry, String> {
        register(owner, path, None, &[], EndpointAuth::Jwt)
    }

    fn register_alias(
        owner: &str,
        path: &str,
        host: &str,
        methods: &[&str],
        auth: EndpointAuth,
    ) -> Result<HttpRouteEntry, String> {
        let methods: Vec<String> = methods.iter().map(|s| s.to_string()).collect();
        register(owner, path, Some(host), &methods, auth)
    }

    #[test]
    fn register_roundtrip_and_owner_arbitration() {
        let plugin = owner("roundtrip");
        let entry = register_path(&plugin, "configs").expect("register");
        assert!(entry.endpoint_id.starts_with(ENDPOINT_HANDLE_PREFIX), "句柄前缀");
        assert_eq!(entry.internal_path, "/api/plugin/test-http-roundtrip/configs");
        assert_eq!(count_by_owner(&plugin), 1);

        // 反查 / 属主仲裁
        let found = find_by_internal(&entry.internal_path).expect("find by internal");
        assert_eq!(found.endpoint_id, entry.endpoint_id);
        assert!(is_owner(&entry.endpoint_id, &plugin));
        assert!(!is_owner(&entry.endpoint_id, "someone-else"));

        // 同插件同内部路径 → 冲突拒绝
        let conflict = register_path(&plugin, "configs").expect_err("duplicate internal rejected");
        assert!(conflict.contains("already registered"), "got: {conflict}");
        assert_eq!(count_by_owner(&plugin), 1, "冲突不得产生副作用");

        // 注销：属主命中；他人拒绝且不消费句柄
        assert!(remove_if_owner(&entry.endpoint_id, "someone-else").is_err());
        assert!(is_owner(&entry.endpoint_id, &plugin), "他人注销不得消费句柄");
        assert!(remove_if_owner(&entry.endpoint_id, &plugin).unwrap());
        assert!(!remove_if_owner(&entry.endpoint_id, &plugin).unwrap(), "幂等 false");
        assert!(find_by_internal(&entry.internal_path).is_none());
        assert_eq!(count_by_owner(&plugin), 0);
    }

    #[test]
    fn internal_paths_are_namespaced_per_owner() {
        // 两个插件注册同名相对段 → 各自进自家命名空间，互不冲突
        let a = owner("ns-a");
        let b = owner("ns-b");
        register_path(&a, "shared").expect("a register");
        register_path(&b, "shared").expect("b register");

        assert_eq!(
            find_by_internal(&format!("/api/plugin/{a}/shared"))
                .expect("a entry")
                .owner,
            a
        );
        assert_eq!(
            find_by_internal(&format!("/api/plugin/{b}/shared"))
                .expect("b entry")
                .owner,
            b
        );

        for entry in list_by_owner(&a).into_iter().chain(list_by_owner(&b)) {
            let _ = remove_if_owner(&entry.endpoint_id, &entry.owner);
        }
    }

    #[test]
    fn host_alias_conflict_is_fail_visible_and_keeps_incumbent() {
        let a = owner("host-a");
        let b = owner("host-b");
        register_alias(&a, "configs", "/api/configs-a", &["GET"], EndpointAuth::Jwt).expect("a first");

        // 跨插件同 host+method → Err（不覆盖在位者）
        let err = register_alias(&b, "configs2", "/api/configs-a", &["GET"], EndpointAuth::Jwt)
            .expect_err("cross-plugin conflict");
        assert!(err.contains("/api/configs-a"), "文案点名冲突路径: {err}");
        assert!(err.contains("already registered"), "got: {err}");

        // 同插件重复注册同 host+method → 同样 Err
        let err = register_alias(&a, "configs", "/api/configs-a", &["GET"], EndpointAuth::Jwt)
            .expect_err("same-owner duplicate");
        assert!(err.contains("already registered"), "got: {err}");

        // 在位者不受影响
        let m = find_by_host("/api/configs-a", "GET").expect("incumbent intact");
        assert_eq!(m.entry.owner, a);

        // 不同方法可共占同一 host 路径（方法维度区分）
        register_alias(&a, "configs2", "/api/configs-a", &["POST"], EndpointAuth::Jwt).expect("POST ok");
        assert!(find_by_host("/api/configs-a", "POST").is_some());

        purge_for_plugin(&a);
        purge_for_plugin(&b);
    }

    #[test]
    fn host_match_is_exact_on_method() {
        let plugin = owner("method");
        register_alias(&plugin, "configs", "/api/configs-m", &["GET"], EndpointAuth::Jwt).expect("register");

        assert!(find_by_host("/api/configs-m", "GET").is_some());
        assert!(find_by_host("/api/configs-m", "POST").is_none(), "方法不符不命中");
        assert!(find_by_host("/api/configs-mx", "GET").is_none(), "前缀相似不命中");
        assert!(find_by_host("/api/configs-m/", "GET").is_none());

        purge_for_plugin(&plugin);
    }

    #[test]
    fn host_template_match_captures_params() {
        let plugin = owner("tpl");
        register_alias(
            &plugin,
            "sessions/stop",
            "/api/sessions/{id}/stop",
            &["POST"],
            EndpointAuth::Jwt,
        )
        .expect("register template");

        // 精确命中模板 → 捕获 id
        let m = find_by_host("/api/sessions/s-1/stop", "POST").expect("template match");
        assert_eq!(m.entry.path, "sessions/stop");
        assert_eq!(m.params.get("id").map(String::as_str), Some("s-1"));

        // 段数不符 / 字面段不符 → 不命中
        assert!(find_by_host("/api/sessions/s-1/stop/extra", "POST").is_none());
        assert!(
            find_by_host("/api/sessions/s-1/start", "POST").is_none(),
            "字面段必须一致"
        );
        assert!(
            find_by_host("/api/sessions/s-1/stop", "GET").is_none(),
            "方法不符不命中模板"
        );

        purge_for_plugin(&plugin);
    }

    #[test]
    fn template_capture_decodes_percent_encoding() {
        let plugin = owner("tpl-decode");
        register_alias(&plugin, "x", "/api/x/{id}/y", &["GET"], EndpointAuth::Jwt).expect("register");

        let m = find_by_host("/api/x/a%20b/y", "GET").expect("percent-decoded capture");
        assert_eq!(m.params.get("id").map(String::as_str), Some("a b"));

        // 畸形百分号编码 → 不命中（fail-closed，不把畸形值当参数）
        assert!(find_by_host("/api/x/a%2/y", "GET").is_none());

        purge_for_plugin(&plugin);
    }

    #[test]
    fn host_template_validation_rejects_bad_shapes() {
        let plugin = owner("tpl-bad");
        // 不以 / 开头
        assert!(register_alias(&plugin, "x", "api/x", &["GET"], EndpointAuth::Jwt).is_err());
        // 模板段名非法（数字开头 / 空 / 含保留符）
        assert!(register_alias(&plugin, "x", "/api/{1id}/x", &["GET"], EndpointAuth::Jwt).is_err());
        assert!(register_alias(&plugin, "x", "/api/{}/x", &["GET"], EndpointAuth::Jwt).is_err());
        assert!(register_alias(&plugin, "x", "/api/{id-x}/x", &["GET"], EndpointAuth::Jwt).is_err());
        // 字面段含 { / } → 拒绝（不合法模板段也不当字面量放行）
        assert!(register_alias(&plugin, "x", "/api/a{b}/x", &["GET"], EndpointAuth::Jwt).is_err());
        // 合法模板段名通过
        assert!(register_alias(&plugin, "x", "/api/sessions-v/{id}/stop", &["POST"], EndpointAuth::Jwt).is_ok());
        assert!(register_alias(&plugin, "y", "/api/sessions-v/{_x9}/stop", &["GET"], EndpointAuth::Jwt).is_ok());

        purge_for_plugin(&plugin);
    }

    #[test]
    fn host_reserved_surfaces_are_protected() {
        let plugin = owner("reserved");
        // /api/health（健康检查）与 /api/plugin（插件代理前缀）是宿主路由面：
        // 插件别名不得占用（劫持或遮蔽宿主面）
        let err =
            register_alias(&plugin, "x", "/api/health", &["GET"], EndpointAuth::Jwt).expect_err("health reserved");
        assert!(err.contains("reserved"), "got: {err}");
        let err = register_alias(&plugin, "x", "/api/plugin/other-plugin/y", &["GET"], EndpointAuth::Jwt)
            .expect_err("plugin prefix reserved");
        assert!(err.contains("reserved"), "got: {err}");
        // 前缀相似但不同（/api/healthx）不误伤
        assert!(register_alias(&plugin, "x", "/api/healthx", &["GET"], EndpointAuth::Jwt).is_ok());
        purge_for_plugin(&plugin);
    }

    #[test]
    fn register_enforces_endpoint_limit_without_side_effects() {
        let plugin = owner("limit");
        for i in 0..PLUGIN_HTTP_MAX_ENDPOINTS_PER_PLUGIN {
            register_path(&plugin, &format!("p{i}")).expect("register within limit");
        }
        let err = register_path(&plugin, "over").expect_err("over limit rejected");
        assert!(err.contains("endpoint limit reached"), "got: {err}");
        assert_eq!(
            count_by_owner(&plugin),
            PLUGIN_HTTP_MAX_ENDPOINTS_PER_PLUGIN,
            "超限拒绝不得留下副作用"
        );

        purge_for_plugin(&plugin);
    }

    #[test]
    fn purge_only_touches_owner_and_is_idempotent() {
        let victim = owner("purge");
        let bystander = owner("purge-bystander");
        let victim_entry =
            register_alias(&victim, "configs", "/api/configs-p", &["GET"], EndpointAuth::Jwt).expect("victim register");
        let bystander_entry = register_alias(
            &bystander,
            "configs",
            "/api/configs-bystander",
            &["GET"],
            EndpointAuth::Jwt,
        )
        .expect("bystander register");

        let purged = purge_for_plugin(&victim);
        assert_eq!(purged.len(), 1);
        assert_eq!(purged[0].endpoint_id, victim_entry.endpoint_id);
        assert!(
            find_by_internal(&victim_entry.internal_path).is_none(),
            "本人端点已摘除"
        );
        assert!(
            find_by_host("/api/configs-bystander", "GET").is_some(),
            "他人别名不受影响"
        );
        assert!(find_by_host("/api/configs-p", "GET").is_none(), "本人别名已摘除");
        // 幂等：再次回收命中 0
        assert!(purge_for_plugin(&victim).is_empty());

        purge_for_plugin(&bystander);
        let _ = bystander_entry;
    }

    #[test]
    fn list_by_owner_is_stable_and_scoped() {
        let plugin = owner("list");
        let other = owner("list-other");
        for p in ["zeta", "alpha"] {
            register_path(&plugin, p).expect("register");
        }
        register_path(&other, "mine").expect("register other");

        let paths: Vec<String> = list_by_owner(&plugin).into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec!["alpha", "zeta"], "按内部路径升序，且不含他人端点");

        purge_for_plugin(&plugin);
        purge_for_plugin(&other);
    }
}
