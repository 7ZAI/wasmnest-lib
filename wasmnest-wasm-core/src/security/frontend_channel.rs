//! 前端插件通道身份（frontend channel identity，审计票 06 / P0-5）
//!
//! Tauri 的 `#[tauri::command]` **拿不到调用者身份**：同一 webview 内宿主代码与全部插件前端
//! 代码同权，`plugin_*` 命令参数里的 `plugin_id` 因此是**自报值**——任一插件前端可直接
//! `invoke('plugin_storage_get', { pluginId: '受害者', key })` 读写他人存储。本模块给出一个
//! 可验证的身份面，形如「凭证 → 身份」的两级结构：
//!
//! - **loader 会话密钥**（宿主前端面凭证）：每个 webview 的每次页面加载**首个调用者生效**、
//!   只签发一次。宿主前端 bootstrap 在**导入任何插件模块之前**取得并保存在模块作用域变量里
//!   （不进全局、不进 storage）；插件代码开始运行时（其模块已被导入）密钥已被占位 → 取不到。
//!   页面加载时由宿主重置（[`crate::manager::host::PluginHost::reset_frontend_loader_session`]，
//!   挂在 Tauri 的 `on_page_load` 钩子），使 dev 下页面刷新可重新取得。
//! - **插件通道令牌**（插件面凭证）：[`FrontendChannelRegistry::issue_token`] 校验 loader 密钥与
//!   插件激活态后签发，**停用即回收**；令牌决定身份，命令参数里的 `plugin_id` 只作「目标」，
//!   两者不符即拒绝。
//!
//! **作用域按 webview（窗口）分区**（2026-09-26 修复多窗口互踩）：桌面端主窗口之外还有终端
//! 窗口等独立 `WebviewWindow`（各自完整加载前端、各自 bootstrap），而 `on_page_load` 对**每个**
//! webview 触发。凭证表若为全局单例，后加载窗口的页面加载会回收先加载窗口的 loader 密钥与
//! 全部插件令牌，而先加载窗口不会重新 bootstrap（它没重载）→ 其插件面命令全部被拒
//! （`缺少有效通道凭证`），实况表现为「打开终端窗口后，主窗口的会话操作报错」。因此每个
//! webview label 持有**独立凭证域**（loader 密钥 + 令牌表）：页面加载只重置自己那一域，
//! [`FrontendChannelRegistry::authorize`] 用调用方 webview label 定位域，跨窗口的凭证互相
//! 不可用。安全语义不降级：域内仍是「首个调用者生效」，且跨域不可解析（比全局表更严）。
//! 同 label 窗口重建会再次触发 `on_page_load` → 旧域先被重置，无陈旧凭证残留。
//!
//! 凭据本身是 256 位随机值，用 `==` 比较（非恒定时间）：攻击者本地无比较预言机，每次探测要
//! 走一次 IPC 往返（毫秒级），逐字节时序差异不可利用。
//!
//! **诚实边界（不宣称硬隔离）**：同 realm 的原型/时序篡改理论上仍可尝试窃取凭据或他人
//! context——这正是本票裁决 2 删掉 `sandbox: 'isolated'` 虚假承诺的原因。本模块关闭的是
//! 「一行 `invoke` 自报 plugin_id」这条通道，不是「前端与被审代码同权」这个事实。

use crate::AppError;
use std::collections::HashMap;
use std::sync::Mutex;

/// 凭据熵（字节）：loader 会话密钥与插件令牌同规格
const CREDENTIAL_BYTES: usize = 32;

/// 一次前端页面加载内有效的凭证集合（按 webview label 分区）
#[derive(Default)]
pub struct FrontendChannelRegistry {
    /// webview label → 该窗口的凭证域（loader 密钥 + 令牌表）。
    ///
    /// **单一把锁**建模整个凭证域（2026-10-03，S-02）：早先拆成三把独立
    /// `Mutex<HashMap>` 会让 `issue_token` 的「校验 loader 会话 → 写入令牌」
    /// 跨锁非原子（校验通过后 `reset()` 清域、随后过期凭据被插回 → 已过期的
    /// 通道令牌以陈旧身份存活）。合并后校验+写入在同一临界区，其它方法亦然。
    domains: Mutex<HashMap<String, WebviewDomain>>,
}

/// 单 webview 的凭证域：loader 会话密钥 + 令牌双向表
#[derive(Default)]
struct WebviewDomain {
    /// 该窗口当前页面加载的 loader 会话密钥（None = 尚未签发，等待其 bootstrap 取用）
    loader_session: Option<String>,
    /// 通道令牌 → 插件 id（`resolve` 主查表，令牌决定身份）
    tokens: HashMap<String, String>,
    /// 插件 id → 通道令牌（同域覆盖签发时回收旧令牌用）
    plugin_token: HashMap<String, String>,
}

/// 凭证解析出的身份
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelIdentity {
    /// 宿主前端（loader 会话密钥）：可操作任意插件目标
    Host,
    /// 某插件前端（通道令牌）
    Plugin(String),
}

impl FrontendChannelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 重置某 webview 的凭证域：该窗口的旧 loader 密钥与全部插件令牌一律失效
    ///
    /// 返回被回收的插件令牌数（日志用）。由该 webview 的页面加载钩子调用（dev 下页面刷新
    /// 需能重新取得宿主面凭证）；**其它 webview 的域不受影响**——这是多窗口互踩修复的关键：
    /// 终端窗口加载不再回收主窗口的凭证。
    pub fn reset(&self, webview_label: &str) -> usize {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        let removed = domains.remove(webview_label);
        let had_session = removed.as_ref().map(|d| d.loader_session.is_some()).unwrap_or(false);
        let revoked = removed.map(|d| d.tokens.len()).unwrap_or(0);
        tracing::debug!(
            webview = %webview_label,
            had_loader_session = had_session,
            revoked_tokens = revoked,
            "[PluginChannel] 前端通道会话已重置"
        );
        revoked
    }

    /// 签发某 webview 的 loader 会话密钥（宿主前端 bootstrap；**域内首个调用者生效**）
    pub fn issue_loader_session(&self, webview_label: &str) -> crate::Result<String> {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        let domain = domains.entry(webview_label.to_string()).or_default();
        if domain.loader_session.is_some() {
            // 不返回既有密钥：重复取用只可能是插件前端在事后尝试自取
            return Err(AppError::Plugin(
                "frontend loader session already issued for this page load".to_string(),
            ));
        }
        let credential = generate_credential();
        domain.loader_session = Some(credential.clone());
        tracing::info!(
            webview = %webview_label,
            "[PluginChannel] 前端 loader 会话密钥已签发（宿主面凭证）"
        );
        Ok(credential)
    }

    /// 校验某 webview 的 loader 会话密钥
    pub fn verify_loader_session(&self, webview_label: &str, candidate: &str) -> bool {
        let domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        matches!(
            domains.get(webview_label).and_then(|d| d.loader_session.as_deref()),
            Some(current) if current == candidate
        )
    }

    /// 为某 webview 的已激活插件签发通道令牌（覆盖同域旧令牌并回收）
    ///
    /// **校验与登记同临界区**（S-02）：loader 会话校验通过到令牌写入之间
    /// 不再有 `reset()` / `revoke_plugin()` 插缝——夹缝期清掉的域不会被
    /// 过期令牌重新填满。
    pub fn issue_token(&self, webview_label: &str, loader_session: &str, plugin_id: &str) -> crate::Result<String> {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        let domain = domains.entry(webview_label.to_string()).or_default();
        if domain.loader_session.as_deref() != Some(loader_session) {
            return Err(AppError::Plugin(
                "invalid frontend loader session credential".to_string(),
            ));
        }
        let token = generate_credential();
        // 先摘旧令牌、再登记新令牌（同一临界区内）
        if let Some(old) = domain.plugin_token.insert(plugin_id.to_string(), token.clone()) {
            domain.tokens.remove(&old);
        }
        domain.tokens.insert(token.clone(), plugin_id.to_string());
        tracing::debug!(
            webview = %webview_label,
            plugin_id = %plugin_id,
            "[PluginChannel] 插件前端通道令牌已签发"
        );
        Ok(token)
    }

    /// 回收某插件在**所有 webview** 的通道令牌（停用 / 卸载）
    ///
    /// 插件可在多个窗口各有前端实例与各自令牌，停用必须全量回收——只清当前窗口会让
    /// 其它窗口的旧令牌继续解析出身份。
    pub fn revoke_plugin(&self, plugin_id: &str) {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        let mut revoked = 0usize;
        for domain in domains.values_mut() {
            domain.tokens.retain(|_, pid| pid != plugin_id);
            if domain.plugin_token.remove(plugin_id).is_some() {
                revoked += 1;
            }
        }
        if revoked == 0 {
            return;
        }
        tracing::debug!(
            plugin_id = %plugin_id,
            webviews = revoked,
            "[PluginChannel] 插件前端通道令牌已回收"
        );
    }

    /// 解析某 webview 的凭证：插件令牌优先，其次 loader 会话密钥；都命不中返回 `None`
    pub fn resolve(&self, webview_label: &str, credential: &str) -> Option<ChannelIdentity> {
        if credential.is_empty() {
            return None;
        }
        let domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        let domain = domains.get(webview_label)?;
        if let Some(plugin_id) = domain.tokens.get(credential) {
            return Some(ChannelIdentity::Plugin(plugin_id.clone()));
        }
        if domain.loader_session.as_deref() == Some(credential) {
            return Some(ChannelIdentity::Host);
        }
        None
    }

    /// 插件面命令的身份裁决（`webview_label` = 调用方所在窗口）
    ///
    /// - 宿主面凭证（loader 会话密钥）→ 放行任意目标（宿主配置页 / 宿主 `pluginInvoke` 的职权）；
    /// - 插件面令牌 → 目标必须等于令牌身份，否则拒绝；
    /// - 凭证无效 / 属于其它窗口的域 → 拒绝（**fail-closed**，绝不落回「按参数 plugin_id 放行」）。
    pub fn authorize(&self, webview_label: &str, target_plugin_id: &str, credential: &str) -> crate::Result<()> {
        match self.resolve(webview_label, credential) {
            Some(ChannelIdentity::Host) => Ok(()),
            Some(ChannelIdentity::Plugin(caller)) => {
                if caller == target_plugin_id {
                    Ok(())
                } else {
                    tracing::warn!(
                        webview = %webview_label,
                        plugin_id = %target_plugin_id,
                        caller = %caller,
                        "[PluginChannel] 插件前端跨插件调用被拒绝"
                    );
                    Err(AppError::Plugin(format!(
                        "Plugin '{}' may not act as plugin '{}'",
                        caller, target_plugin_id
                    )))
                }
            }
            None => {
                tracing::warn!(
                    webview = %webview_label,
                    plugin_id = %target_plugin_id,
                    "[PluginChannel] 缺少有效通道凭证，插件面命令被拒绝"
                );
                Err(AppError::Plugin(format!(
                    "Missing or invalid channel credential for plugin '{}'",
                    target_plugin_id
                )))
            }
        }
    }
}

/// 生成 32 字节随机凭据（小写十六进制）
fn generate_credential() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; CREDENTIAL_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个 webview：主窗口与一个终端窗口
    const MAIN: &str = "main";
    const TERMINAL: &str = "terminal-0a928b03";

    #[test]
    fn loader_session_issued_only_once_and_verifiable() {
        let registry = FrontendChannelRegistry::new();
        let session = registry.issue_loader_session(MAIN).expect("first issue ok");

        assert!(registry.verify_loader_session(MAIN, &session));
        assert!(!registry.verify_loader_session(MAIN, "forged"));

        // 同一 webview 的第二个调用者拿不到密钥（插件前端事后自取的防线）
        let second = registry.issue_loader_session(MAIN);
        assert!(second.is_err(), "重复取用必须拒绝，实际: {second:?}");
        assert!(
            registry.verify_loader_session(MAIN, &session),
            "拒绝重复取用不得使既有密钥失效"
        );
    }

    #[test]
    fn token_requires_loader_session_and_resolves_to_plugin() {
        let registry = FrontendChannelRegistry::new();
        let session = registry.issue_loader_session(MAIN).unwrap();

        // 反例：伪造 / 空 loader 密钥一律拒绝
        assert!(registry.issue_token(MAIN, "forged", "com.test.a").is_err());
        assert!(registry.issue_token(MAIN, "", "com.test.a").is_err());

        let token = registry.issue_token(MAIN, &session, "com.test.a").expect("issue ok");
        assert_eq!(
            registry.resolve(MAIN, &token),
            Some(ChannelIdentity::Plugin("com.test.a".into()))
        );
        assert_eq!(registry.resolve(MAIN, &session), Some(ChannelIdentity::Host));
        assert_eq!(registry.resolve(MAIN, "forged"), None);
        assert_eq!(registry.resolve(MAIN, ""), None);
    }

    #[test]
    fn reissue_revokes_previous_token_and_deactivate_revokes_current() {
        let registry = FrontendChannelRegistry::new();
        let session = registry.issue_loader_session(MAIN).unwrap();

        let first = registry.issue_token(MAIN, &session, "com.test.a").unwrap();
        let second = registry.issue_token(MAIN, &session, "com.test.a").unwrap();
        assert_ne!(first, second, "重新签发必须换新令牌");
        assert_eq!(registry.resolve(MAIN, &first), None, "旧令牌必须失效");
        assert_eq!(
            registry.resolve(MAIN, &second),
            Some(ChannelIdentity::Plugin("com.test.a".into()))
        );

        registry.revoke_plugin("com.test.a");
        assert_eq!(registry.resolve(MAIN, &second), None, "停用后令牌必须失效");
        // 只回收目标插件：宿主密钥与其它插件不受影响
        assert_eq!(registry.resolve(MAIN, &session), Some(ChannelIdentity::Host));
        let other = registry.issue_token(MAIN, &session, "com.test.b").unwrap();
        registry.revoke_plugin("com.test.a");
        assert_eq!(
            registry.resolve(MAIN, &other),
            Some(ChannelIdentity::Plugin("com.test.b".into()))
        );
    }

    #[test]
    fn reset_only_invalidates_the_loaded_webview_domain() {
        let registry = FrontendChannelRegistry::new();
        let session = registry.issue_loader_session(MAIN).unwrap();
        let token = registry.issue_token(MAIN, &session, "com.test.a").unwrap();

        let revoked = registry.reset(MAIN);
        assert_eq!(revoked, 1, "重置必须报告回收的令牌数");
        assert!(
            !registry.verify_loader_session(MAIN, &session),
            "页面加载后旧 loader 密钥失效"
        );
        assert_eq!(registry.resolve(MAIN, &token), None, "页面加载后插件令牌失效");
        // 新页面加载可重新签发（dev 刷新路径）
        let fresh = registry.issue_loader_session(MAIN).expect("reissue after reset");
        assert_ne!(fresh, session);
    }

    /// 多窗口互踩回归锁（2026-09-26）：终端窗口的页面加载**不得**回收主窗口的凭证
    ///
    /// 复现路径：主窗口已 bootstrap（loader 密钥 + 各插件令牌）→ 用户启动会话打开终端窗口
    /// → 终端窗口页面加载触发 `on_page_load`。修复前这是全局 reset，主窗口随后所有插件面
    /// 命令被拒（`缺少有效通道凭证`）；修复后 reset 只作用于终端窗口自己的域。
    #[test]
    fn page_load_in_one_webview_keeps_other_webviews_credentials() {
        let registry = FrontendChannelRegistry::new();
        // 主窗口：宿主密钥 + 四个插件令牌（实况的插件数量）
        let main_session = registry.issue_loader_session(MAIN).unwrap();
        let main_tokens: Vec<String> = ["a", "b", "c", "d"]
            .iter()
            .map(|p| {
                registry
                    .issue_token(MAIN, &main_session, &format!("com.test.{p}"))
                    .unwrap()
            })
            .collect();

        // 终端窗口加载：reset 只清 TERMINAL 域（该域此前为空 → 回收 0）
        assert_eq!(registry.reset(TERMINAL), 0, "reset 不得越域回收其它窗口的令牌");
        // 终端窗口 bootstrap 签发自己的密钥与令牌
        let terminal_session = registry.issue_loader_session(TERMINAL).unwrap();
        let terminal_token = registry.issue_token(TERMINAL, &terminal_session, "com.test.a").unwrap();
        assert_ne!(terminal_session, main_session, "两窗口密钥必须相互独立");
        assert_ne!(terminal_token, main_tokens[0], "两窗口的同插件令牌必须相互独立");

        // 主窗口凭证全部仍然有效（修复前这里全数失效 → 本次 bug）
        assert!(registry.verify_loader_session(MAIN, &main_session));
        assert_eq!(registry.resolve(MAIN, &main_session), Some(ChannelIdentity::Host));
        for token in &main_tokens {
            assert!(
                registry.resolve(MAIN, token).is_some(),
                "主窗口插件令牌不得因其它窗口加载而失效"
            );
        }
        assert!(registry.authorize(MAIN, "com.test.a", &main_tokens[0]).is_ok());

        // 反向：主窗口刷新（reset MAIN）后终端窗口凭证不受影响
        registry.reset(MAIN);
        assert_eq!(
            registry.resolve(TERMINAL, &terminal_token),
            Some(ChannelIdentity::Plugin("com.test.a".into())),
            "主窗口刷新不得回收终端窗口凭证"
        );
        assert!(registry.verify_loader_session(TERMINAL, &terminal_session));
    }

    /// 跨窗口隔离：一个窗口的凭证在另一个窗口的域里不可解析（fail-closed）
    #[test]
    fn credentials_do_not_cross_webview_domains() {
        let registry = FrontendChannelRegistry::new();
        let main_session = registry.issue_loader_session(MAIN).unwrap();
        let main_token = registry.issue_token(MAIN, &main_session, "com.test.a").unwrap();
        let terminal_session = registry.issue_loader_session(TERMINAL).unwrap();

        // 主窗口的令牌拿到终端窗口用 → 不可解析、不可授权
        assert_eq!(registry.resolve(TERMINAL, &main_token), None);
        assert!(registry.authorize(TERMINAL, "com.test.a", &main_token).is_err());
        // 主窗口的 loader 密钥拿到终端窗口同样无效（也不能替终端窗口签令牌）
        assert_eq!(registry.resolve(TERMINAL, &main_session), None);
        assert!(registry.issue_token(TERMINAL, &main_session, "com.test.a").is_err());
        // 各自域内正常
        assert!(registry.authorize(MAIN, "com.test.a", &main_token).is_ok());
        assert!(registry.issue_token(TERMINAL, &terminal_session, "com.test.a").is_ok());
        // 跨插件目标仍按域内身份裁决（终端窗口令牌不得冒充主窗口插件身份）
        assert!(registry.authorize(TERMINAL, "com.test.b", &main_token).is_err());
    }

    /// 同 label 窗口重建（终端窗口关闭后再开同一会话）：旧域被新页面加载重置，可重新签发
    #[test]
    fn recreated_window_with_same_label_gets_fresh_session() {
        let registry = FrontendChannelRegistry::new();
        let first_session = registry.issue_loader_session(TERMINAL).unwrap();
        let first_token = registry.issue_token(TERMINAL, &first_session, "com.test.a").unwrap();

        // 窗口销毁重建 → 再次页面加载：域内旧凭证先被重置
        assert_eq!(registry.reset(TERMINAL), 1);
        assert_eq!(registry.resolve(TERMINAL, &first_token), None, "旧窗口令牌必须失效");
        assert!(
            registry.issue_loader_session(TERMINAL).is_ok(),
            "重建窗口必须能重新取得密钥"
        );
    }

    /// 宿主面凭证可操作任意目标；插件令牌只能操作自己
    #[test]
    fn authorize_scopes_plugin_token_to_its_own_target() {
        let registry = FrontendChannelRegistry::new();
        let session = registry.issue_loader_session(MAIN).unwrap();
        let alice = registry.issue_token(MAIN, &session, "com.test.alice").unwrap();

        // 宿主面：任意目标放行（宿主配置页读写插件存储、宿主 pluginInvoke 的职权）
        assert!(registry.authorize(MAIN, "com.test.alice", &session).is_ok());
        assert!(registry.authorize(MAIN, "com.test.bob", &session).is_ok());

        // 插件面正例：自己的目标
        assert!(registry.authorize(MAIN, "com.test.alice", &alice).is_ok());

        // 反例：以他人身份行事 —— 必须拒绝且错误信息点明两侧身份
        let err = registry
            .authorize(MAIN, "com.test.bob", &alice)
            .expect_err("跨插件调用必须被拒绝");
        assert!(
            err.to_string().contains("com.test.alice") && err.to_string().contains("com.test.bob"),
            "错误信息必须点名调用者与目标，实际: {err}"
        );
    }

    /// 凭证缺失 / 伪造 / 已回收一律拒绝（fail-closed）
    #[test]
    fn authorize_rejects_missing_forged_and_revoked_credentials() {
        let registry = FrontendChannelRegistry::new();
        let session = registry.issue_loader_session(MAIN).unwrap();
        let token = registry.issue_token(MAIN, &session, "com.test.alice").unwrap();

        for credential in ["", "forged", "deadbeef"] {
            let err = registry
                .authorize(MAIN, "com.test.alice", credential)
                .expect_err("无有效凭证必须拒绝");
            assert!(
                err.to_string().contains("Missing or invalid channel credential"),
                "实际: {err}"
            );
        }

        registry.revoke_plugin("com.test.alice");
        assert!(
            registry.authorize(MAIN, "com.test.alice", &token).is_err(),
            "停用回收后的令牌不得再放行"
        );
        // 页面加载（前端重启）后同样失效，但宿主面在重置前仍有效
        assert!(registry.authorize(MAIN, "com.test.alice", &session).is_ok());
        registry.reset(MAIN);
        assert!(registry.authorize(MAIN, "com.test.alice", &session).is_err());
    }

    /// 停用插件回收其**所有窗口**的令牌，其它插件与宿主密钥不受影响
    #[test]
    fn revoke_plugin_covers_every_webview_domain() {
        let registry = FrontendChannelRegistry::new();
        let main_session = registry.issue_loader_session(MAIN).unwrap();
        let terminal_session = registry.issue_loader_session(TERMINAL).unwrap();
        let main_token = registry.issue_token(MAIN, &main_session, "com.test.a").unwrap();
        let terminal_token = registry.issue_token(TERMINAL, &terminal_session, "com.test.a").unwrap();
        let other = registry.issue_token(MAIN, &main_session, "com.test.b").unwrap();

        registry.revoke_plugin("com.test.a");

        assert_eq!(registry.resolve(MAIN, &main_token), None, "主窗口令牌必须回收");
        assert_eq!(
            registry.resolve(TERMINAL, &terminal_token),
            None,
            "终端窗口令牌必须回收"
        );
        assert_eq!(
            registry.resolve(MAIN, &other),
            Some(ChannelIdentity::Plugin("com.test.b".into())),
            "其它插件令牌不受影响"
        );
        assert_eq!(registry.resolve(MAIN, &main_session), Some(ChannelIdentity::Host));
        assert_eq!(
            registry.resolve(TERMINAL, &terminal_session),
            Some(ChannelIdentity::Host),
            "其它窗口的宿主密钥不受影响"
        );
    }

    #[test]
    fn credentials_are_unique_and_high_entropy() {
        let registry = FrontendChannelRegistry::new();
        let session = registry.issue_loader_session(MAIN).unwrap();
        assert_eq!(session.len(), CREDENTIAL_BYTES * 2, "32 字节 → 64 位十六进制");

        let a = registry.issue_token(MAIN, &session, "com.test.a").unwrap();
        let b = registry.issue_token(MAIN, &session, "com.test.b").unwrap();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
