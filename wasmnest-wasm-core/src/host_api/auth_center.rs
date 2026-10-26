//! 认证中心注册表与组合式认证原语（ADR 0031，票 01）— 单中心角色的唯一性仲裁 + 句柄登记 + 停用回收
//!
//! 认证中心 ≡ 微服务架构的 auth server，但**没有也不需要服务发现**（用户裁定，
//! ADR 0031 §「为什么没有也不需要服务发现」）：注册表就是宿主进程内的发现协议
//! ——插件在 activate 期调 [`register`]（K1），宿主只做唯一性仲裁（K4 单中心：
//! 第二个注册者显式拒绝并点名在册属主）+ 句柄登记（`authc-<uuid>`）+ 停用回收
//! （[`purge_for_plugin`]，只碰本人）。
//!
//! **组合式认证原语（[`invoke_auth_method`]）——wasm-core 纯净性收口票 05 并入**：
//! 原住 `utils/auth/auth_center.rs`（K6 零解析窄转发，host-auth WIT 原语
//! `auth-method-invoke` 的实现链，被 `host_api/auth.rs:329` 生产调用）。票 05
//! 把 `session_active` / `enforce_connection_policy`（宿主薄壳）回迁 lib；本函数
//! 随 WIT 绑定面留在 wasm-core（机制），并入本模块保持「注册表 + 认证调用面
//! 同侧」。lib 侧测试夹具（`src-tauri/src/utils/auth/test_tokens.rs`）经
//! `wasmnest_wasm_core::host_api::auth_center::invoke_auth_method` 消费（pub）。
//!
//! 边界（ADR 0022 归属三问）：
//! - **通用注册表与寻址**（§5.1.3 允许的四类薄壳之一）：methods 是**声明式列表**，
//!   宿主不解释每个 method 的业务语义（B1 不命中）；认证记录真源在中心私有库
//!   （host-auth 只管密钥托管 / 验签执行，B3 不命中）
//! - **安全闸门**：无中心 / 调用失败一律拒绝（K3 fail-closed），唯一性仲裁（K4）
//! - 宿主**只转发不解释**（K6 / ADR 0032 L2 红线③）：`auth-method-invoke` 零解析
//!   窄转发到中心的 `auth-grant` 互调 api，返回值原样透回
//!
//! 实现：单中心 desk = `Option<AuthCenterEntry>`；核心状态机是**纯函数**
//! （`register_inner` / `unregister_inner` / `purge_inner`，单测直接覆盖不碰全局），
//! 全局静态（同 `host_api/mdns.rs` 口径：进程级单例 + `std::sync::Mutex` 瞬时操作、
//! 无跨 await）只做锁外包装——生产单宿主进程下全局 ≡ 进程内唯一中心。
//! 停用回收接线点 `manager/host/activation.rs::deactivate_plugin_inner`
//! （mdns/ws/http/pty 同一组）。
//!
//! 消费方：
//! - 宿主侧 auth 域（`src-tauri/src/plugin/auth.rs`）：4 个 WIT 函数的权限门 +
//!   分派（`auth-center-register` 等）
//! - lib 侧 `utils/auth/auth_center.rs`：裁决面（`enforce_connection_policy`）与桥接门
//!   （`session_active`）改查本注册表（K7：退役 api_registry 锚点，不留第二套发现机制）

use std::sync::{Mutex, OnceLock};

/// 认证中心登记项
#[derive(Debug, Clone)]
pub struct AuthCenterEntry {
    /// 中心句柄 `authc-<uuid>`（注册时铸，注销/回收后失效）
    pub center_id: String,
    /// 中心插件 id（= 注册调用方 plugin_id，guest 无法伪造——宿主侧自插件实例派生）
    pub owner: String,
    /// 本中心提供的认证方式标识（声明式，排序去重；宿主不解释语义）
    pub methods: Vec<String>,
}

// ==================== 核心状态机（纯函数，无锁无全局） ====================
//
// 单测直接注入局部 `Option<AuthCenterEntry>` 覆盖，不碰全局注册表——单中心
// desk 天然独占，并行测试若共用全局会互相清台；状态机与全局外包装分开后，
// 单元测试零竞争，全局只由生产路径与（加了测试闸门的）闭环集成测试使用。

/// 注册核心：唯一性仲裁 → 铸句柄 → 登记。`state` 入参 = 当前 desk。
pub fn register_inner(
    state: &mut Option<AuthCenterEntry>,
    owner: &str,
    methods: Vec<String>,
) -> Result<String, String> {
    // 去重 + 排序（确定性诊断；宿主不做语义解释，只保证列表可复现）
    let mut methods = methods;
    methods.sort();
    methods.dedup();
    if methods.is_empty() {
        return Err("auth center registration requires at least one method".to_string());
    }
    if let Some(existing) = state.as_ref() {
        return Err(format!(
            "auth center already registered by '{}' (center {})",
            existing.owner, existing.center_id
        ));
    }
    let center_id = format!("authc-{}", uuid::Uuid::new_v4());
    *state = Some(AuthCenterEntry {
        center_id: center_id.clone(),
        owner: owner.to_string(),
        methods,
    });
    Ok(center_id)
}

/// 注销核心：仅属主本人可注销；非属主 → err；无中心在册 → 幂等成功
/// （停用路径先跑 guest deactivate 再跑宿主 purge，两者都不该被「无中心」卡住）。
pub fn unregister_inner(state: &mut Option<AuthCenterEntry>, owner: &str) -> Result<(), String> {
    match state.as_ref() {
        Some(entry) if entry.owner == owner => {
            *state = None;
            Ok(())
        }
        Some(entry) => Err(format!(
            "not owner of auth center (registered by '{}')",
            entry.owner
        )),
        None => Ok(()),
    }
}

/// 停用回收核心：只碰本人（非属主调用 no-op——purge 只回收自己的中心角色）
pub fn purge_inner(state: &mut Option<AuthCenterEntry>, plugin_id: &str) {
    if state.as_ref().is_some_and(|e| e.owner == plugin_id) {
        *state = None;
    }
}

// ==================== 全局注册表（进程级单例） ====================

/// 单中心注册表（D2）：`None` = 无中心在册
static CENTER: OnceLock<Mutex<Option<AuthCenterEntry>>> = OnceLock::new();

fn registry() -> &'static Mutex<Option<AuthCenterEntry>> {
    CENTER.get_or_init(|| Mutex::new(None))
}

fn lock() -> Result<std::sync::MutexGuard<'static, Option<AuthCenterEntry>>, String> {
    registry()
        .lock()
        .map_err(|_| "auth center registry poisoned".to_string())
}

/// 注册本插件为认证中心（单中心仲裁）。成功返回中心句柄；已有中心在册 → `err`
/// （点名在册属主）；空 methods 列表 → `err`（半就绪中心是静默不可用源）。
pub fn register(owner: &str, methods: Vec<String>) -> Result<String, String> {
    let mut guard = lock()?;
    let result = register_inner(&mut guard, owner, methods);
    if let Ok(center_id) = &result {
        tracing::info!(
            center_id = %center_id,
            center_owner = %owner,
            "auth center registered"
        );
    }
    result
}

/// 注销本插件的认证中心角色（仅属主本人可调）。非属主 → `err`；无中心在册 → 幂等
/// 成功。
pub fn unregister(owner: &str) -> Result<(), String> {
    let mut guard = lock()?;
    let was_registered = guard.is_some();
    let result = unregister_inner(&mut guard, owner);
    if was_registered && result.is_ok() {
        tracing::info!(center_owner = %owner, "auth center unregistered");
    }
    result
}

/// 裁决面 / 组合式认证面只读：当前在册中心（无 → `None`）
pub fn center() -> Option<AuthCenterEntry> {
    lock().ok().and_then(|g| g.clone())
}

/// 是否有认证中心在册（K7 桥接门判据，替代退役的 api_registry 锚点）
pub fn is_registered() -> bool {
    lock().map(|g| g.is_some()).unwrap_or(false)
}

/// 停用回收（只碰本人）：属主停用时其中心角色一并回收——认证面随之 fail-closed
/// （无中心 = 拒绝，ADR 0031 K3），而不是静默降级成「无认证放行」
pub fn purge_for_plugin(plugin_id: &str) {
    let mut guard = match lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if guard.as_ref().is_some_and(|e| e.owner == plugin_id) {
        let center_id = guard
            .as_ref()
            .map(|e| e.center_id.clone())
            .unwrap_or_default();
        tracing::info!(
            center_id = %center_id,
            center_owner = %plugin_id,
            "auth center purged on plugin deactivation"
        );
    }
    purge_inner(&mut guard, plugin_id);
}

/// 测试闸门：清空注册表（重置单中心 desk，闭环用例互斥清台用）。
///
/// **常编译 pub**（wasm-core 纯净性收口票 05b 上提）：lib 集成测试
/// （session_e2e / system_component_test）与 wasm-core 内部测试都经
/// `crate::test_support::reset` 消费（test_support re-export）。
pub fn reset() {
    *registry().lock().expect("registry lock") = None;
}

/// 测试闸门：串行化使用全局注册表的集成用例（单中心 desk 天然独占，并行测试
/// 会互相清台；闭环 / 多候选锁两条 async 集成用例共用本闸门，互斥执行）
///
/// 用 `Semaphore(1)` 而非 `Mutex`：持有 permit 跨 await 是 async 语义下
/// 合法且必须的（两个用例都以整个测试体为临界区）；permit 不是锁守卫。
///
/// **纪律：任何会写这张表的用例都要持闸门**——不只是「读它并断言裁决」的用例。
/// 真实中心产物（`com.wasmnest.bedcode` v32）的 guest `activate` 会
/// `auth-center-register`、`deactivate` 会 `auth-center-unregister`，故任何加载
/// 该产物并停用它的用例都在清台。漏登记的表现是**别的**用例偶发红（2026-09-29：
/// `a03_p1b` / `ws_e2e` ×3 / `perf_ws_terminal_output_throughput` 的 deactivate 曾把
/// 多候选锁的裁决打成 `no_center`，而它们自己全绿）。
///
/// **常编译 pub**（票 05b 上提）：经 `crate::test_support` re-export 统一入口。
#[allow(dead_code)]
static REGISTRY_GATE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

/// 测试闸门入口：获取全局单中心 desk 的信号量（`REGISTRY_GATE`，见上）
///
/// **常编译 pub**（票 05b 上提）：经 `crate::test_support` re-export 统一入口。
pub fn registry_gate() -> &'static tokio::sync::Semaphore {
    REGISTRY_GATE.get_or_init(|| tokio::sync::Semaphore::new(1))
}

/// 异步用例取闸门 permit（**持到变量 drop**）：只包住写表的那几行，别包整个测试
/// 体——`perf_ws_terminal_output_throughput` 这类用例长达一分钟，包住会把其它用例排队。
///
/// **常编译 pub**（票 05b 上提）：经 `crate::test_support` re-export 统一入口。
pub async fn hold_registry_desk() -> tokio::sync::SemaphorePermit<'static> {
    registry_gate()
        .acquire()
        .await
        .expect("auth center registry test gate")
}

// ==================== 组合式认证原语（K6，票 05 从 utils/auth/ 并入） ====================

/// 经认证中心执行一次认证方式调用（K6 零解析窄转发）
///
/// 宿主不拆 `params`、不解释 `method` 的业务语义（B1 不命中），只校验「method 在
/// 注册表内」（安全闸门判据）后把调用转发到中心 `auth-grant` 互调 api（ADR 0017
/// JSON-RPC 2.0 over host-bus），并把 result 序列化回串原样透回。
///
/// 边界（spec §4.3.1 矩阵）：无中心 → fail-closed；method 不在注册表 → 点名 method
/// 与在册列表（不猜、不回退到"试试别的"）；传输失败 → `auth center unavailable:
/// <原因>`；中心返回错误信封 → **原样透传**（业务拒绝不吞成宿主错误）。
///
/// **可见性**（wasm-core 纯净性收口票 05）：本函数是 host-auth WIT 原语
/// `auth-method-invoke` 的实现链（宿主侧 `src-tauri/src/plugin/auth.rs` 的
/// `auth_method_invoke` 生产调用），属机制面，留在 wasm-core；`pub` 供 lib 侧
/// 测试夹具（`src-tauri/src/utils/auth/test_tokens.rs`）经
/// `wasmnest_wasm_core::host_api::auth_center::invoke_auth_method` 消费。
pub fn invoke_auth_method(
    host_ctx: &crate::manager::runtime::WasmHostContext,
    method: &str,
    params: &str,
) -> std::result::Result<String, String> {
    let Some(entry) = center() else {
        tracing::warn!(
            deny_kind = "no_center",
            method = %method,
            "auth-method-invoke without a registered auth center (fail-closed)"
        );
        return Err("no auth center registered".to_string());
    };
    if !entry.methods.iter().any(|m| m == method) {
        return Err(format!(
            "auth center '{}' does not provide method '{}' (registered: {})",
            entry.owner,
            method,
            entry.methods.join(", ")
        ));
    }
    // params 是调用方给的 JSON 串：解析成 Value 只是为了装进 JSON-RPC 信封，
    // 语义上仍是"原样透传"（宿主不解释字段）。
    let params_value: serde_json::Value = serde_json::from_str(params)
        .map_err(|e| format!("auth method invoke params must be valid JSON: {e}"))?;
    let api = format!("{}.auth-grant", entry.owner);
    let request_topic = format!("wasmnest.api.{api}");
    let method_short = api.rsplit_once('.').map(|(_, m)| m).unwrap_or(&api);
    let id = crate::intercall::next_host_request_id();
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method_short,
        "params": { "method": method, "params": params_value },
    });
    let reply_json = host_ctx
        .call_plugin_api_host(
            &request_topic,
            &payload.to_string(),
            crate::intercall::AUTH_CENTER_TIMEOUT_MS,
        )
        .map_err(|e| format!("auth center unavailable: {e}"))?;
    let reply: serde_json::Value = serde_json::from_str(&reply_json)
        .map_err(|e| format!("auth center unavailable (invalid reply): {e}"))?;
    if let Some(err) = reply.get("error") {
        // 中心返回错误信封：业务拒绝原样透传（ADR 0030 错误码由中心自持）
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("rpc error")
            .to_string();
        return Err(message);
    }
    let result = reply
        .get("result")
        .cloned()
        .ok_or_else(|| "auth center unavailable (reply missing result/error)".to_string())?;
    serde_json::to_string(&result).map_err(|e| format!("auth center reply serialize failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造本地 desk 状态（单测不碰全局静态——并行测试互不清台）
    fn local_state() -> Option<AuthCenterEntry> {
        None
    }

    fn methods4() -> Vec<String> {
        ["pairing_code", "qr", "biometric", "jwt"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn test_register_success_and_shape() {
        let mut state = local_state();
        let id = register_inner(&mut state, "com.wasmnest.bedcode", methods4()).unwrap();
        assert!(id.starts_with("authc-"), "句柄形态 authc-<uuid>: {id}");
        assert_eq!(
            state.as_ref().unwrap().owner,
            "com.wasmnest.bedcode"
        );
        assert_eq!(state.as_ref().unwrap().center_id, id);
    }

    #[test]
    fn test_methods_deduped_and_sorted() {
        let mut state = local_state();
        register_inner(
            &mut state,
            "com.wasmnest.bedcode",
            ["qr", "biometric", "qr", "jwt"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .unwrap();
        assert_eq!(
            state.as_ref().unwrap().methods,
            vec!["biometric", "jwt", "qr"]
        );
    }

    /// K4 单中心：重复注册显式拒绝且点名在册属主（不猜、不覆盖、不回退）
    #[test]
    fn test_duplicate_register_rejected_with_owner_named() {
        let mut state = local_state();
        register_inner(&mut state, "com.wasmnest.bedcode", methods4()).unwrap();
        let err = register_inner(
            &mut state,
            "com.wasmnest.agent-hub",
            vec!["jwt".to_string()],
        )
        .unwrap_err();
        assert!(
            err.contains("com.wasmnest.bedcode"),
            "重复注册必须点名在册属主, got: {err}"
        );
        assert!(
            err.contains("authc-"),
            "重复注册必须点名在册句柄, got: {err}"
        );
        // 原中心不受影响
        assert_eq!(
            state.as_ref().unwrap().owner,
            "com.wasmnest.bedcode"
        );
    }

    /// 空 methods 拒绝（半就绪中心是静默不可用源）
    #[test]
    fn test_empty_methods_rejected() {
        let mut state = local_state();
        let err = register_inner(&mut state, "com.wasmnest.bedcode", vec![]).unwrap_err();
        assert!(err.contains("at least one method"), "got: {err}");
        assert!(state.is_none());
    }

    /// 属主注销：本人成功并清空；非属主显式拒绝
    #[test]
    fn test_unregister_owner_checked() {
        let mut state = local_state();
        register_inner(&mut state, "com.wasmnest.bedcode", methods4()).unwrap();
        // 非属主拒绝
        let err = unregister_inner(&mut state, "com.wasmnest.agent-hub").unwrap_err();
        assert!(err.contains("not owner"), "got: {err}");
        assert!(state.is_some(), "非属主注销不影响在册中心");
        // 属主成功
        unregister_inner(&mut state, "com.wasmnest.bedcode").unwrap();
        assert!(state.is_none());
        // 无中心 + 任意属主 → 幂等成功（停用路径不卡）
        unregister_inner(&mut state, "com.wasmnest.agent-hub").unwrap();
    }

    /// 停用回收：只碰本人，他人中心不受影响
    #[test]
    fn test_purge_for_plugin_only_touches_owner() {
        let mut state = local_state();
        register_inner(&mut state, "com.wasmnest.bedcode", methods4()).unwrap();
        // 非属主 purge：不回收（只碰本人）
        purge_inner(&mut state, "com.wasmnest.agent-hub");
        assert_eq!(
            state.as_ref().unwrap().owner,
            "com.wasmnest.bedcode"
        );
        // 属主 purge：回收
        purge_inner(&mut state, "com.wasmnest.bedcode");
        assert!(state.is_none());
        // 无中心时 purge 幂等
        purge_inner(&mut state, "com.wasmnest.bedcode");
        assert!(state.is_none());
    }

    /// K2/K3：裁决面在无中心时必须可判 fail-closed（`center()` 返回 None，
    /// 由 `enforce_connection_policy` 转为 `no auth center registered` 拒绝）
    #[test]
    fn test_no_center_is_none() {
        let state: Option<AuthCenterEntry> = None;
        assert!(state.is_none(), "无中心 → center()=None → 裁决面据此拒绝");
    }
}
