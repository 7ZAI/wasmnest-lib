//! `preauth` — PluginHost 预授权路径收集（P2）
//!
//! 自 `host.rs` 主 impl 拆出：注册的 provider 优先，默认回退 storage 读取。

use super::*;

/// 预授权路径提供者签名：返回插件「启用前需要授权的路径列表」。
///
/// 由 `PluginHost::register_preauth_provider` 注册；默认回退到
/// `PluginStorage::get(plugin_id, "preauth_paths")` 读取。
pub type PreauthProvider = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// 服务型 wasm 免权限拦截判据（issue #6 D4）
///
/// **两条同时成立才豁免**：
/// 1. 来源非 [`PluginSource::UserInstalled`]（随包 / FileScan / 静态注册 = 构建期
///    信任域）；
/// 2. manifest `type` 属**角色驱动**（L1 基础服务 / L2 内部业务，
///    [`PluginKind::is_role_driven`]）。
///
/// 判据服务的面是**路径预授权**（[`PluginHost::preauthorize_plugin`] 不再弹目录授权
/// 框，声明路径直接落账）。审批门（`activation.rs::approval_gate`）不引用本函数：
/// 它早已对**一切**非 `UserInstalled` 来源返回 `Ok(None)`，口径比本判据更宽；若把
/// 它收窄成「仍要角色驱动」，随包 L3 应用会因为「没有批准记录」被判 `NeedsApproval`
/// ——那是一次与 D4 无关的全量回归。
///
/// **硬红线**：`UserInstalled` 来源永不豁免——`type` 是插件自报字段，只允许在
/// 「来源已可信」的前提下参与判定，否则用户 zip 自报 `internal-business` 就是一条
/// 提权通道（免掉审批门与目录授权弹窗）。反例用例见
/// `tests/approval_test.rs::user_installed_cannot_claim_service_exemption`。
pub(crate) fn is_exempt_service(source: &PluginSource, kind: PluginKind) -> bool {
    *source != PluginSource::UserInstalled && kind.is_role_driven()
}

/// 预授权 storage key（宿主只按这个 key 读插件私有 storage，**不认得是谁写的**：
/// 写入方是插件自己的挂载配置面，经 `host-storage` 用同名 key 追加/去重）。
/// 需要「启用前先拿到目录授权」的插件也可由 provider 动态提供；
/// 缺字段 = 视为「无预授权路径」，直接放行（启用先行，避免
/// 「配置需激活 → 激活需先配置」死锁）。
pub const PREAUTH_PATHS_STORAGE_KEY: &str = "preauth_paths";

/// 预授权提供者注册表:静态注册 + host function 动态注册共用,跨 PluginHost
/// 实例共享(测试可单例化)。PluginHost::activate_plugin 阶段1 入口调
/// collect_preauth_paths 收集,再走 fs_auth::check_batch 单次合并弹窗。
static PREAUTH_PROVIDERS: OnceLock<RwLock<HashMap<String, PreauthProvider>>> = OnceLock::new();

pub(crate) fn preauth_providers() -> &'static RwLock<HashMap<String, PreauthProvider>> {
    PREAUTH_PROVIDERS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// 注册预授权路径提供者(供 plugin 内部 host function 调用,优先级高于
/// 默认 storage 读取)。同名 plugin_id 覆盖;运行期增量注册即时生效。
pub async fn register_preauth_provider(plugin_id: &str, provider: PreauthProvider) {
    let mut map = preauth_providers().write().await;
    map.insert(plugin_id.to_string(), provider);
}

/// 收集插件的预授权路径:注册的 provider 优先,否则从 PluginStorage 读
/// `preauth_paths` 数组。返回空 Vec 表示「无需预授权」。
pub(crate) async fn collect_preauth_paths(plugin_id: &str) -> Vec<String> {
    if let Some(provider) = preauth_providers().read().await.get(plugin_id).cloned() {
        return provider(plugin_id);
    }
    Vec::new()
}

impl PluginHost {
    /// 该插件是否享受「服务型 wasm 免权限拦截」（判据见 [`is_exempt_service`]）
    ///
    /// 读一次 `plugins` 表即释放（不跨 await 持锁）。
    async fn is_exempt_service_plugin(&self, plugin_id: &str) -> bool {
        let plugins = self.plugins.read().await;
        plugins
            .get(plugin_id)
            .map(|loaded| is_exempt_service(&loaded.source, loaded.manifest.kind))
            .unwrap_or(false)
    }

    /// 激活插件
    ///
    /// 预授权(启用前置):收集插件需授权路径 → 调 `fs_auth::check_batch`
    /// 单次合并弹窗。失败直接 `mark_error` + 返回 `AppError::Plugin`,
    /// 不进入 `Activating` 中间态。**必须在 `activate_plugin` 阶段1 入口
    /// (置 Activating 之前)调用,持有 plugins 锁时禁止调用**(check_batch
    /// 会发事件、可能回调宿主,持锁会死锁)。
    ///
    /// 路径来源:已注册的 `PreauthProvider` 优先;否则从 `PluginStorage`
    /// `preauth_paths` 数组读(file-transfer mount-local 同步写入);
    /// 另并入 manifest `wasiPreopenDirs` 展开后的声明目录(如 ai-chatbox
    /// 数据目录)——插件 activate 内 fs_request_auth 的弹窗晚于前端 loading
    /// 遮罩,声明目录必须提前到本阶段统一弹窗。
    /// 路径为空 → 直接放行(启用先行:file-transfer 首次启用/全部目录移除后
    /// 均可空目录激活,共享目录配置由插件设置面板引导;硬拒绝会造成
    /// 「配置需激活 → 激活需先配置」死锁)。
    ///
    /// **服务型 wasm 免弹窗**(issue #6 D4):来源非 `UserInstalled` **且** 角色驱动
    /// (L1/L2) 的随包插件,其声明路径直接落账放行(来源标 `service`),不弹目录授权框。
    pub async fn preauthorize_plugin(&self, plugin_id: &str) -> crate::Result<()> {
        // 1. 收集路径(注册 provider 优先,否则 storage 数组)
        let mut paths = collect_preauth_paths(plugin_id).await;
        if paths.is_empty() {
            if let Ok(Some(value)) = self.storage.get(plugin_id, PREAUTH_PATHS_STORAGE_KEY).await {
                if let Value::Array(arr) = value {
                    paths = arr.into_iter().filter_map(|v| v.as_str().map(String::from)).collect();
                }
            }
        }

        // 1.5 并入 manifest wasiPreopenDirs 声明目录(展开不过滤授权,未授权
        // 项正需在此弹窗)。只读档同样要弹窗授权——档位收紧 guest 写能力，
        // 不构成免授权通道（票 07 裁决 3）。
        // **仅 worker 类别可达**（ADR 0034）：非 worker 声明 preopen 在加载期被
        // 显性拒绝，主 wasm-app 文件访问走 host-fs + preauth_paths——本分支是
        // worker 预留能力的授权前置，当前对一切可加载 manifest 不可达。
        // 短读锁克隆后立即释放:check_batch 会发事件、可能
        // 回调宿主,跨 await 持锁有死锁风险
        let declared = {
            let plugins = self.plugins.read().await;
            plugins
                .get(plugin_id)
                .map(|p| p.manifest.wasi_preopen_dirs.clone())
                .unwrap_or_default()
        };
        for dir in crate::manager::runtime::expand_preopen_declarations(plugin_id, &declared) {
            let path = dir.path().to_string();
            if !paths.contains(&path) {
                paths.push(path);
            }
        }

        if paths.is_empty() {
            return Ok(());
        }

        // 2.5 服务型 wasm 免询问放行（issue #6 D4）：随包 L1/L2 插件直接落账其声明
        // 路径，不弹目录授权框——它属构建期信任域，弹窗只是噪声（且服务型插件可能
        // 在无 UI 场景下激活，弹窗没有人应答 = 30s 超时后拒绝，服务起不来）。
        // 判据 `is_exempt_service` 里 `UserInstalled` 永不豁免：自报 `type` 不能提权。
        if self.is_exempt_service_plugin(plugin_id).await {
            let stored = self
                .wasm_runtime
                .fs_auth()
                .grant_service_paths(
                    plugin_id,
                    &paths,
                    crate::security::fs_auth::FsOps::READ_WRITE,
                )
                .await;
            tracing::info!(
                plugin_id = %plugin_id,
                requested = paths.len(),
                stored,
                "[PluginHost] 随包服务型插件免目录授权弹窗（声明路径直接放行）"
            );
            return Ok(());
        }

        // 3. 合并未授权路径为单次弹窗(check_batch 内部已实现事件 emit + 30s 超时)
        //
        // 操作集 = 读 + 写（票 02）：这里授权的是**插件自报的数据目录**（preauth_paths，
        // 由插件自己写、WASI 预打开目录同源），插件显然要在里面读写；按只读落账会让
        // 插件的第一次写触发新弹窗——与改造前「无操作维度 = 读写等价」相比是行为回归
        let allowed = self
            .wasm_runtime
            .fs_auth()
            .check_batch(
                plugin_id,
                &paths,
                crate::security::fs_auth::FsOps::READ_WRITE,
            )
            .await;
        if !allowed {
            return Err(crate::AppError::Plugin(
                "Plugin enable denied: file access authorization rejected".to_string(),
            ));
        }
        Ok(())
    }
}
