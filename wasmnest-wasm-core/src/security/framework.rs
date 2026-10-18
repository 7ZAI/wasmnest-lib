//! 统一授权框架（core-security 骨架，票据 04）
//!
//! 资源授权的三段决策管线（任一阶段拒绝即整体拒绝）：
//!
//! 1. [`ResourceAuthorizer::check_declared`]——manifest 声明快速失败
//!    （前端校验仅是 UX，声明检查是宿主侧第一道闸门）
//! 2. [`ResourceAuthorizer::check_approved`]——授权审批/持久化授权记录
//!    （默认无审批段直接放行；返回 [`AuthDecision::RequireApproval`] 不中止
//!    管线，交由 enforce 内完成弹窗/等待——fs 三层校验即此形态）
//! 3. [`ResourceAuthorizer::enforce`]——运行时强制（Rust 端最终仲裁）
//!
//! 既有实现的归位映射：
//! - fs 资源：[`FsAuthorizer`]——check_permission（阶段 1）+ FsAuthChecker
//!   三层校验（阶段 2/3）；宿主侧 fs 域实现（`src-tauri/src/plugin/fs.rs`）
//!   调用链即此管线的手工内联形态
//! - api-call 资源：[`ApiCallAuthorizer`]——互调门（ADR 0017：注册即声明，
//!   未声明不可调）；bus_publish 门禁经本框架路由
//!
//! 新资源类型实现 [`ResourceAuthorizer`] 并 [`SecurityFramework::register`]
//! 即接入管线；每次决策计数埋点进 core-monitor（plugin_id 维度）。

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::config::StoreLimits;
use crate::monitor::{AuthzDecisionKind, MetricsRegistry};
use crate::permission::{PermissionManager, PERMISSION_FS_READ, PERMISSION_FS_WRITE};
// ResourceOverrides：中性单份（票 02 M4，crate::config 唯一真源）
use crate::config::ResourceOverrides;

use super::api_registry::ApiRegistry;
use super::fs_auth::{FsAuthChecker, FsOp, FsOps};

// ==================== 资源与决策 ====================

/// 受管资源类型（`Custom` 容纳框架外演进的新资源，避免枚举膨胀即破坏）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Fs,
    Network,
    Process,
    Storage,
    Bus,
    ApiCall,
    Custom(&'static str),
}

/// 一次授权请求：谁在什么资源上做什么操作（目标）
#[derive(Debug, Clone)]
pub struct AuthRequest<'a> {
    /// 发起方插件 ID
    pub plugin_id: &'a str,
    /// 资源类型
    pub resource: ResourceKind,
    /// 操作（fs: "read"/"write"；api-call: "invoke"；……）
    pub operation: &'a str,
    /// 操作目标（路径 / api 全限定名 / topic ……）
    pub target: &'a str,
}

/// 授权决策
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// 放行
    Allow,
    /// 拒绝（携带人类可读原因，不含凭据）
    Deny(String),
    /// 需要授权审批（阶段 2 语义；不中止管线，由 enforce 完成弹窗/等待）
    RequireApproval,
}

impl From<&AuthDecision> for AuthzDecisionKind {
    fn from(d: &AuthDecision) -> Self {
        match d {
            AuthDecision::Allow => AuthzDecisionKind::Allow,
            AuthDecision::Deny(_) => AuthzDecisionKind::Deny,
            AuthDecision::RequireApproval => AuthzDecisionKind::RequireApproval,
        }
    }
}

// ==================== 资源仲裁器 ====================

/// 资源仲裁器：每类受管资源实现本 trait 接入三段决策管线
pub trait ResourceAuthorizer: Send + Sync + 'static {
    /// 仲裁的资源类型
    fn kind(&self) -> ResourceKind;
    /// 阶段 1：manifest 声明快速失败
    fn check_declared(&self, req: &AuthRequest) -> AuthDecision;
    /// 阶段 2：授权审批/持久化授权记录（默认无审批段直接放行）
    fn check_approved(&self, _req: &AuthRequest) -> AuthDecision {
        AuthDecision::Allow
    }
    /// 阶段 3：运行时强制（最终仲裁）
    fn enforce(&self, req: &AuthRequest) -> AuthDecision;
}

// ==================== 授权框架 ====================

/// 统一授权框架：仲裁器注册表 + 三段决策管线执行 + 决策埋点
///
/// 挂于 `WasmHostContext`（能力上下文），监控句柄两阶段注入
/// （`set_monitor`——core-monitor 生于 WasmRuntime，晚于宿主上下文构建）
pub struct SecurityFramework {
    authorizers: RwLock<HashMap<ResourceKind, Arc<dyn ResourceAuthorizer>>>,
    monitor: RwLock<Option<Arc<MetricsRegistry>>>,
}

impl SecurityFramework {
    pub fn new() -> Self {
        Self {
            authorizers: RwLock::new(HashMap::new()),
            monitor: RwLock::new(None),
        }
    }

    /// 注入监控句柄（决策计数埋点；两阶段初始化）
    pub fn set_monitor(&self, monitor: Arc<MetricsRegistry>) {
        *self.monitor.write().expect("security monitor lock poisoned") = Some(monitor);
    }

    /// 注册资源仲裁器（同类型后注册覆盖）
    pub fn register(&self, authorizer: Arc<dyn ResourceAuthorizer>) {
        self.authorizers
            .write()
            .expect("authorizer lock poisoned")
            .insert(authorizer.kind(), authorizer);
    }

    /// 三段决策管线：声明 → 审批 → 强制；任一拒绝即整体拒绝
    ///
    /// RequireApproval 不中止管线（enforce 内完成弹窗/等待，见 fs 资源）。
    /// 每次调用的最终决策计数进 core-monitor。
    pub fn authorize(&self, req: &AuthRequest) -> AuthDecision {
        let authorizer = {
            self.authorizers
                .read()
                .expect("authorizer lock poisoned")
                .get(&req.resource)
                .cloned()
        };
        let decision = match authorizer {
            None => AuthDecision::Deny(format!("资源 {:?} 未注册仲裁器，默认拒绝", req.resource)),
            Some(a) => {
                let first = a.check_declared(req);
                let second = match first {
                    AuthDecision::Allow => a.check_approved(req),
                    other => other,
                };
                match second {
                    AuthDecision::Allow | AuthDecision::RequireApproval => a.enforce(req),
                    other => other,
                }
            }
        };
        if let Some(m) = self.monitor.read().expect("security monitor lock poisoned").as_ref() {
            m.plugin(req.plugin_id)
                .record_authz_decision(AuthzDecisionKind::from(&decision));
        }
        decision
    }
}

impl Default for SecurityFramework {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== fs 资源仲裁器 ====================

/// fs 资源仲裁器：现有 fs 三层校验的框架适配
///
/// 管线映射（与宿主侧 fs 域实现的手工内联链语义一致）：
/// - 阶段 1：manifest `fs:read` / `fs:write` 权限声明（PermissionManager）
/// - 阶段 2：免弹窗判定——硬拒绝记录 / 第一方目录 / 授权记录（含操作集）/ 旧记录
///   （`FsAuthChecker::is_granted`，票 02 起带所需能力集）
/// - 阶段 3：完整判定（命中放行，未命中弹窗，`FsAuthChecker::check`）
pub struct FsAuthorizer {
    permission: Arc<PermissionManager>,
    fs_auth: Arc<FsAuthChecker>,
}

impl FsAuthorizer {
    pub fn new(permission: Arc<PermissionManager>, fs_auth: Arc<FsAuthChecker>) -> Self {
        Self { permission, fs_auth }
    }
}

/// fs 操作名 → 操作类型（未知操作返回 None，调用方按拒绝处理）
///
/// 单点映射：阶段 1（权限位）、阶段 2（所需能力集）、阶段 3（弹窗文案与落账）
/// 必须对同一操作名给出一致理解，否则「声明了 fs:read 却按写放行」这类错位会藏在
/// 三处各写一遍的 match 里。
fn fs_op_of(operation: &str) -> Option<FsOp> {
    match operation {
        "read" => Some(FsOp::Read),
        "write" => Some(FsOp::Write),
        _ => None,
    }
}

impl ResourceAuthorizer for FsAuthorizer {
    fn kind(&self) -> ResourceKind {
        ResourceKind::Fs
    }

    fn check_declared(&self, req: &AuthRequest) -> AuthDecision {
        let permission = match fs_op_of(req.operation) {
            Some(FsOp::Read) => PERMISSION_FS_READ,
            Some(FsOp::Write) => PERMISSION_FS_WRITE,
            None => return AuthDecision::Deny(format!("未知 fs 操作 '{}'", req.operation)),
        };
        if self.permission.check(req.plugin_id, permission) {
            AuthDecision::Allow
        } else {
            AuthDecision::Deny(format!("插件未声明权限 '{permission}'"))
        }
    }

    fn check_approved(&self, req: &AuthRequest) -> AuthDecision {
        // 所需能力 = 本次操作（票 02 操作拆分）：授权记录带操作集，「授权读」不再覆盖写。
        // 阶段 1 已对未知操作 Deny，这里再兜一次（本函数可被单独调用）
        let Some(op) = fs_op_of(req.operation) else {
            return AuthDecision::Deny(format!("未知 fs 操作 '{}'", req.operation));
        };
        let granted = crate::runtime_util::block_on_async(self.fs_auth.is_granted(
            req.plugin_id,
            req.target,
            FsOps::single(op),
        ));
        if granted {
            AuthDecision::Allow
        } else {
            AuthDecision::RequireApproval
        }
    }

    fn enforce(&self, req: &AuthRequest) -> AuthDecision {
        let Some(op) = fs_op_of(req.operation) else {
            return AuthDecision::Deny(format!("未知 fs 操作 '{}'", req.operation));
        };
        let allowed = crate::runtime_util::block_on_async(self.fs_auth.check(req.plugin_id, req.target, op));
        if allowed {
            AuthDecision::Allow
        } else {
            AuthDecision::Deny("fs 三层校验拒绝".to_string())
        }
    }
}

// ==================== api-call 资源仲裁器 ====================

/// 互调资源仲裁器（ADR-0017 层 1 门禁的框架适配）
///
/// 阶段 1 恒放行：互调无调用方声明段——目标方 manifest `api` 声明
/// 已由注册表承载（激活登记/停用注销）；阶段 3 即注册表命中判定。
pub struct ApiCallAuthorizer {
    registry: Arc<ApiRegistry>,
}

impl ApiCallAuthorizer {
    pub fn new(registry: Arc<ApiRegistry>) -> Self {
        Self { registry }
    }
}

impl ResourceAuthorizer for ApiCallAuthorizer {
    fn kind(&self) -> ResourceKind {
        ResourceKind::ApiCall
    }

    fn check_declared(&self, _req: &AuthRequest) -> AuthDecision {
        AuthDecision::Allow
    }

    fn enforce(&self, req: &AuthRequest) -> AuthDecision {
        // 走 `gate`（单读锁内「存在性 + 属主」）而非裸 `contains`：与回复道
        // 的属主解析（api_gate_target_owner 亦用 gate）同一语义同一把锁，
        // 门禁放行与属主解析不跨锁漂移（S-05）
        if self.registry.gate(req.target).is_some() {
            AuthDecision::Allow
        } else {
            AuthDecision::Deny(format!("api '{}' 未由任何已激活插件声明（互调门）", req.target))
        }
    }
}

// ==================== 资源覆盖仲裁 ====================

impl SecurityFramework {
    /// 单插件 Store 资源覆盖的仲裁（core-config × core-security，票据 07）
    ///
    /// 插件只能自我收紧：最终值逐字段取 `min`（请求值、内核配置值、编译期
    /// 硬上限）——放宽请求被钳回上限并 warn（结构化字段 `plugin_id`）。
    /// 无请求（旧插件 / 未声明 `resourceOverrides`）时原样返回内核配置，
    /// 行为与票据 07 之前完全一致（零迁移）。
    ///
    /// 仲裁点在安全模块而非配置模块：资源上限属于安全边界，与授权决策同源
    /// （spec 配置模块决策：per-plugin 覆盖由安全模块钳制在安全上限内）。
    pub fn resolve_store_limits(
        &self,
        plugin_id: &str,
        config: &StoreLimits,
        request: Option<&ResourceOverrides>,
    ) -> StoreLimits {
        let Some(req) = request else {
            return config.clone();
        };
        let merged = crate::config::apply_store_overrides(config, req);
        // 双重天花板：不得突破运维配置值（配置覆盖有效），也不得突破编译期硬上限
        let granted = merged.clamped_within(config).clamped_within(&StoreLimits::default());
        if granted != merged {
            tracing::warn!(
                plugin_id = %plugin_id,
                "[SecurityFramework] 插件资源覆盖请求超出上限，已钳制（插件只能自我收紧）"
            );
        }
        granted
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试资源：记录各阶段调用顺序，按脚本返回决策
    struct FakeAuthorizer {
        kind: ResourceKind,
        declared: AuthDecision,
        approved: AuthDecision,
        enforce: AuthDecision,
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    impl ResourceAuthorizer for FakeAuthorizer {
        fn kind(&self) -> ResourceKind {
            self.kind
        }
        fn check_declared(&self, _req: &AuthRequest) -> AuthDecision {
            self.calls.lock().unwrap().push("declared");
            self.declared.clone()
        }
        fn check_approved(&self, _req: &AuthRequest) -> AuthDecision {
            self.calls.lock().unwrap().push("approved");
            self.approved.clone()
        }
        fn enforce(&self, _req: &AuthRequest) -> AuthDecision {
            self.calls.lock().unwrap().push("enforce");
            self.enforce.clone()
        }
    }

    fn fake(
        declared: AuthDecision,
        approved: AuthDecision,
        enforce: AuthDecision,
    ) -> (Arc<FakeAuthorizer>, SecurityFramework) {
        let a = Arc::new(FakeAuthorizer {
            kind: ResourceKind::Custom("fake"),
            declared,
            approved,
            enforce,
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let fw = SecurityFramework::new();
        fw.register(a.clone());
        (a, fw)
    }

    fn req<'a>() -> AuthRequest<'a> {
        AuthRequest {
            plugin_id: "com.wasmnest.test",
            resource: ResourceKind::Custom("fake"),
            operation: "op",
            target: "target",
        }
    }

    #[test]
    fn pipeline_runs_three_stages_in_order() {
        let (a, fw) = fake(AuthDecision::Allow, AuthDecision::Allow, AuthDecision::Allow);
        assert_eq!(fw.authorize(&req()), AuthDecision::Allow);
        assert_eq!(*a.calls.lock().unwrap(), vec!["declared", "approved", "enforce"]);
    }

    #[test]
    fn pipeline_short_circuits_on_declared_deny() {
        let (a, fw) = fake(
            AuthDecision::Deny("未声明".into()),
            AuthDecision::Allow,
            AuthDecision::Allow,
        );
        assert!(matches!(fw.authorize(&req()), AuthDecision::Deny(_)));
        assert_eq!(
            *a.calls.lock().unwrap(),
            vec!["declared"],
            "阶段 1 拒绝后不得进入后续阶段"
        );
    }

    #[test]
    fn pipeline_short_circuits_on_approved_deny() {
        let (a, fw) = fake(
            AuthDecision::Allow,
            AuthDecision::Deny("审批拒绝".into()),
            AuthDecision::Allow,
        );
        assert!(matches!(fw.authorize(&req()), AuthDecision::Deny(_)));
        assert_eq!(*a.calls.lock().unwrap(), vec!["declared", "approved"]);
    }

    #[test]
    fn require_approval_proceeds_to_enforce() {
        let (a, fw) = fake(AuthDecision::Allow, AuthDecision::RequireApproval, AuthDecision::Allow);
        assert_eq!(fw.authorize(&req()), AuthDecision::Allow);
        assert_eq!(*a.calls.lock().unwrap(), vec!["declared", "approved", "enforce"]);
    }

    /// 决策矩阵：阶段 3 拒绝是最终仲裁——允许×允许×拒绝 → 拒绝，
    /// 且拒绝原因来自 enforce（而非被前两段放行掩盖）
    #[test]
    fn pipeline_surfaces_enforce_deny_as_final_denial() {
        let (_a, fw) = fake(
            AuthDecision::Allow,
            AuthDecision::Allow,
            AuthDecision::Deny("运行时强制拒绝".into()),
        );
        let decision = fw.authorize(&req());
        assert!(
            matches!(&decision, AuthDecision::Deny(m) if m == "运行时强制拒绝"),
            "enforce 段拒绝必须成为最终决策: {decision:?}"
        );
    }

    /// 决策矩阵：弹窗后强制拒绝 —— 允许×弹窗×拒绝 → 拒绝
    /// （RequireApproval 不中止管线，弹窗结果由 enforce 段最终裁决）
    #[test]
    fn pipeline_surfaces_enforce_deny_after_require_approval() {
        let (_a, fw) = fake(
            AuthDecision::Allow,
            AuthDecision::RequireApproval,
            AuthDecision::Deny("弹窗被拒".into()),
        );
        let decision = fw.authorize(&req());
        assert!(
            matches!(&decision, AuthDecision::Deny(m) if m == "弹窗被拒"),
            "弹窗后的强制拒绝必须成为最终决策: {decision:?}"
        );
    }

    #[test]
    fn unregistered_resource_defaults_to_deny() {
        let fw = SecurityFramework::new();
        let r = AuthRequest {
            plugin_id: "p",
            resource: ResourceKind::Network,
            operation: "connect",
            target: "x",
        };
        assert!(matches!(fw.authorize(&r), AuthDecision::Deny(_)));
    }

    #[test]
    fn decisions_are_counted_into_monitor() {
        let (_a, fw) = fake(
            AuthDecision::Allow,
            AuthDecision::Allow,
            AuthDecision::Deny("强制拒绝".into()),
        );
        let monitor = Arc::new(MetricsRegistry::new());
        fw.set_monitor(monitor.clone());
        fw.authorize(&req());
        fw.authorize(&req());
        let snap = monitor.snapshot();
        assert_eq!(
            snap["plugins"]["com.wasmnest.test"]["authz"]["deny"].as_u64().unwrap(),
            2
        );
    }

    // ==================== FsAuthorizer（fs 资源适配，票据 04） ====================

    /// fs 资源测试环境：真实 PermissionManager + FsAuthChecker（无头，弹窗层不可用）；
    /// 返回 (permission, storage, authorizer, framework)——authorizer 供单阶段直调，
    /// framework 已注册同一实例供管线端到端；storage 供预置持久授权记录
    #[allow(clippy::type_complexity)]
    /// 第一方清单里的插件 id（票 08/P0-2：中性测试 id——测试表由 fs_environment 注入，
    /// 判定机制与插件名无关，wasm-core 测试不持产品清单）
    const FIRST_PARTY_PLUGIN: &str = "test.first-party";

    fn fs_environment() -> (
        Arc<PermissionManager>,
        Arc<crate::storage::PluginStorage>,
        Arc<FsAuthorizer>,
        SecurityFramework,
    ) {
        let db = crate::db::Database::new(&std::path::Path::new(":memory:")).expect("in-memory db");
        db.init_schema().expect("init schema");
        let storage = Arc::new(crate::storage::PluginStorage::new(Arc::new(
            std::sync::Mutex::new(db),
        )));
        let permission = Arc::new(PermissionManager::new());
        // 票 08/P0-2：豁免表宿主注入——本测试环境注入测试表（.claude 项目段），
        // 使 first-party 断言成立；第三方插件不在表内 → 无豁免
        let fs_auth = Arc::new(FsAuthChecker::new(
            storage.clone(),
            None,
            vec![(
                FIRST_PARTY_PLUGIN,
                vec![crate::security::fs_auth::TrustedDir::ProjectSegment(".claude")],
            )],
        ));
        let authorizer = Arc::new(FsAuthorizer::new(permission.clone(), fs_auth));
        let fw = SecurityFramework::new();
        fw.register(authorizer.clone());
        (permission, storage, authorizer, fw)
    }

    fn fs_req<'a>(plugin_id: &'a str, operation: &'a str, target: &'a str) -> AuthRequest<'a> {
        AuthRequest {
            plugin_id,
            resource: ResourceKind::Fs,
            operation,
            target,
        }
    }

    /// 阶段 1 映射：read/write 分别查 fs:read / fs:write 声明；未知操作拒绝且指明操作名
    #[test]
    fn fs_declared_stage_maps_operation_to_permission() {
        let (permission, _storage, authorizer, _fw) = fs_environment();

        // 未声明权限：read → Deny 并指出 fs:read；write → Deny 并指出 fs:write
        let deny_read = authorizer.check_declared(&fs_req("com.test.p", "read", "/tmp/x"));
        assert!(
            matches!(&deny_read, AuthDecision::Deny(m) if m.contains(PERMISSION_FS_READ)),
            "deny reason must name the missing permission: {deny_read:?}"
        );
        let deny_write = authorizer.check_declared(&fs_req("com.test.p", "write", "/tmp/x"));
        assert!(
            matches!(&deny_write, AuthDecision::Deny(m) if m.contains(PERMISSION_FS_WRITE)),
            "{deny_write:?}"
        );

        // 只授 fs:read：read 放行、write 仍拒绝（权限粒度隔离，防越权升格）
        permission.grant_permissions("com.test.p", &[PERMISSION_FS_READ.to_string()]);
        assert_eq!(
            authorizer.check_declared(&fs_req("com.test.p", "read", "/tmp/x")),
            AuthDecision::Allow
        );
        assert!(matches!(
            authorizer.check_declared(&fs_req("com.test.p", "write", "/tmp/x")),
            AuthDecision::Deny(_)
        ));

        // 未知操作：拒绝且指明操作名（防未映射操作溜过声明段）
        let unknown = authorizer.check_declared(&fs_req("com.test.p", "exec", "/tmp/x"));
        assert!(
            matches!(&unknown, AuthDecision::Deny(m) if m.contains("exec")),
            "{unknown:?}"
        );
    }

    /// 端到端（票 07 改判）：**第一方**在具名集成目录段内经三层校验放行，
    /// 第三方在同一目录段被拒——旧实现按 `.claude/` 子串对**任何**插件放行，
    /// 那条判据已退役，这里锁的是改造后的两侧行为。
    #[tokio::test]
    async fn fs_first_party_integration_dir_allowed_third_party_denied() {
        let (permission, _storage, _authorizer, fw) = fs_environment();
        permission.grant_permissions(FIRST_PARTY_PLUGIN, &[PERMISSION_FS_READ.to_string()]);
        permission.grant_permissions("com.test.p", &[PERMISSION_FS_READ.to_string()]);

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("proj").join(".claude").join("sub").join("f.txt");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "x").unwrap();

        assert_eq!(
            fw.authorize(&fs_req(FIRST_PARTY_PLUGIN, "read", target.to_str().unwrap())),
            AuthDecision::Allow,
            "第一方在其具名集成目录段内须免弹窗放行"
        );
        assert!(
            matches!(
                fw.authorize(&fs_req("com.test.p", "read", target.to_str().unwrap())),
                AuthDecision::Deny(_)
            ),
            "第三方在同一 `.claude` 段必须被拒（无头无弹窗）——票 07 红测的管线侧"
        );
    }

    /// 端到端反例：无 fs:read 声明时，即便路径落在第一方集成目录段也拒绝
    /// （声明段是管线第一道闸门，权限不足优先于目录预授权）
    #[tokio::test]
    async fn fs_undeclared_permission_denied_even_for_trusted_dir() {
        let (_permission, _storage, _authorizer, fw) = fs_environment();

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join(".claude").join("f.txt");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "x").unwrap();

        assert!(
            matches!(
                fw.authorize(&fs_req(FIRST_PARTY_PLUGIN, "read", target.to_str().unwrap())),
                AuthDecision::Deny(_)
            ),
            "未声明 fs:read 时目录预授权也不得越过声明闸门"
        );
    }

    /// 端到端反例：有声明但路径非白名单且无持久授权、无头弹窗不可用 → 拒绝
    /// （enforce 段最终仲裁，错误文案与手工链一致）
    #[tokio::test]
    async fn fs_headless_ungranted_path_denied_end_to_end() {
        let (permission, _storage, _authorizer, fw) = fs_environment();
        permission.grant_permissions("com.test.p", &[PERMISSION_FS_READ.to_string()]);

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("plain").join("f.txt");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "x").unwrap();

        let decision = fw.authorize(&fs_req("com.test.p", "read", target.to_str().unwrap()));
        assert!(
            matches!(&decision, AuthDecision::Deny(m) if m.contains("fs 三层校验拒绝")),
            "headless ungranted fs access must be denied by enforce stage: {decision:?}"
        );
    }

    /// 端到端：持久化授权前缀命中（check_approved 段 Allow）→ 管线整体放行，
    /// 且授权前缀之外的兄弟目录不被误放行（前缀边界语义）
    #[tokio::test]
    async fn fs_persisted_grant_prefix_allowed_end_to_end() {
        let (permission, storage, _authorizer, fw) = fs_environment();
        permission.grant_permissions("com.test.p", &[PERMISSION_FS_READ.to_string()]);

        let tmp = tempfile::TempDir::new().unwrap();
        let granted_root = tmp.path().join("shared");
        std::fs::create_dir_all(&granted_root).unwrap();
        storage
            .set(
                "com.test.p",
                "fs_granted_paths",
                serde_json::json!([granted_root.to_str().unwrap()]),
            )
            .await
            .expect("seed persisted grant");

        let inside = granted_root.join("data.jsonl");
        std::fs::write(&inside, "x").unwrap();
        assert_eq!(
            fw.authorize(&fs_req("com.test.p", "read", inside.to_str().unwrap())),
            AuthDecision::Allow,
            "persisted grant prefix must allow the path"
        );

        // 授权前缀的相邻目录（shared-other）不误匹配
        let sibling = tmp.path().join("shared-other").join("data.jsonl");
        std::fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        std::fs::write(&sibling, "x").unwrap();
        assert!(
            matches!(
                fw.authorize(&fs_req("com.test.p", "read", sibling.to_str().unwrap())),
                AuthDecision::Deny(_)
            ),
            "sibling directory of a granted prefix must not be allowed"
        );
    }

    /// 票 04 端到端：`always_allow` 档放行未覆盖目标并落账，但**越不过声明闸门**
    ///
    /// 两段断言在同一条管线上：① 未声明 `fs:read` 时即使档位是「始终允许」也 Deny
    /// （manifest 声明门在阶段 1，策略层在阶段 2/3——spec §4.2 的硬闸门）；
    /// ② 补上声明后同一路径放行，且读模型里出现一条 `always_allow` 记录。
    /// 变异判据：把策略判定提到声明段之前（或让声明段放行）⇒ ① 转红。
    #[tokio::test]
    async fn always_allow_allows_undeclared_target_only_after_declaration() {
        use crate::security::auth_policy::{AuthPolicyStore, AuthResource, AuthStrategy};

        let (permission, storage, _authorizer, fw) = fs_environment();
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("new").join("f.txt");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "x").unwrap();

        let store = AuthPolicyStore::new(storage.db());
        store
            .set_strategy("com.test.p", AuthResource::Fs, AuthStrategy::AlwaysAllow)
            .await
            .expect("set strategy");

        let decision = fw.authorize(&fs_req("com.test.p", "read", target.to_str().unwrap()));
        assert!(
            matches!(&decision, AuthDecision::Deny(m) if m.contains(PERMISSION_FS_READ)),
            "始终允许档不得绕过 manifest 声明闸门: {decision:?}"
        );
        assert!(
            store
                .records_for_match("com.test.p", AuthResource::Fs)
                .await
                .unwrap()
                .is_empty(),
            "被声明门拒绝的调用不得留下自动放行记录"
        );

        permission.grant_permissions("com.test.p", &[PERMISSION_FS_READ.to_string()]);
        assert_eq!(
            fw.authorize(&fs_req("com.test.p", "read", target.to_str().unwrap())),
            AuthDecision::Allow,
            "声明补齐后未覆盖目标免询问放行"
        );
        let overview = store.overview("com.test.p", "T", Vec::new()).await.unwrap();
        assert_eq!(overview.records.len(), 1, "免询问放行必须留痕: {overview:?}");
        assert_eq!(overview.records[0].source, "always_allow");
        assert_eq!(overview.records[0].ops, vec!["read".to_string()]);
    }

    // ==================== 资源覆盖仲裁（票据 07） ====================

    /// 无请求（旧插件 / 未声明 resourceOverrides）：原样返回内核配置（零迁移）
    #[test]
    fn resolve_store_limits_without_request_returns_config() {
        let fw = SecurityFramework::new();
        let cfg = StoreLimits::default();
        let granted = fw.resolve_store_limits("com.wasmnest.legacy", &cfg, None);
        assert_eq!(granted, cfg, "无请求时必须与内核配置完全一致");
    }

    /// 仲裁：收紧请求保留（插件自我约束合法）；放宽请求钳回内核配置值
    #[test]
    fn resolve_store_limits_clamps_relaxed_request_and_keeps_tighter_one() {
        let fw = SecurityFramework::new();
        let cfg = StoreLimits::default();

        // 放宽：请求值超过内核配置 → 钳回配置值（插件不得突破运维设定）
        let relaxed = ResourceOverrides {
            max_memory_bytes: Some(cfg.max_memory_bytes * 2),
            fuel_per_call: Some(cfg.fuel_per_call * 2),
            ..ResourceOverrides::default()
        };
        let granted = fw.resolve_store_limits("com.wasmnest.heavy", &cfg, Some(&relaxed));
        assert_eq!(granted.max_memory_bytes, cfg.max_memory_bytes, "放宽请求须被钳回");
        assert_eq!(granted.fuel_per_call, cfg.fuel_per_call);

        // 收紧：请求值低于内核配置 → 保留（自我约束）
        let tightened = ResourceOverrides {
            max_memory_bytes: Some(1024),
            ..ResourceOverrides::default()
        };
        let granted = fw.resolve_store_limits("com.wasmnest.tight", &cfg, Some(&tightened));
        assert_eq!(granted.max_memory_bytes, 1024, "收紧请求须保留");
        // 未请求字段继承配置
        assert_eq!(granted.max_tables, cfg.max_tables);
    }

    /// 运行时配置覆盖优先于插件请求：运维把上限降到 4MiB，插件请求 8MiB → 钳到 4MiB
    /// （否则插件可借 manifest 绕过运维的运行时覆盖）
    #[test]
    fn resolve_store_limits_clamps_below_runtime_config_override() {
        let fw = SecurityFramework::new();
        let mut cfg = StoreLimits::default();
        cfg.max_memory_bytes = 4 * 1024 * 1024;

        let request = ResourceOverrides {
            max_memory_bytes: Some(8 * 1024 * 1024),
            ..ResourceOverrides::default()
        };
        let granted = fw.resolve_store_limits("com.wasmnest.heavy", &cfg, Some(&request));
        assert_eq!(
            granted.max_memory_bytes,
            4 * 1024 * 1024,
            "插件请求不得突破运维的运行时配置覆盖"
        );
    }

    /// api-call 资源：未声明不可调（ADR-0017 语义经框架保持）
    #[test]
    fn api_call_gate_via_framework() {
        let registry = Arc::new(ApiRegistry::new());
        registry
            .register("com.wasmnest.target", &["com.wasmnest.target.run".to_string()])
            .unwrap();
        let fw = SecurityFramework::new();
        fw.register(Arc::new(ApiCallAuthorizer::new(registry)));

        let allow = AuthRequest {
            plugin_id: "com.wasmnest.caller",
            resource: ResourceKind::ApiCall,
            operation: "invoke",
            target: "com.wasmnest.target.run",
        };
        assert_eq!(fw.authorize(&allow), AuthDecision::Allow);

        let deny = AuthRequest {
            target: "com.wasmnest.target.undeclared",
            ..allow
        };
        assert!(matches!(fw.authorize(&deny), AuthDecision::Deny(_)));
    }
}
