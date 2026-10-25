//! Plugin Identity Validation
//!
//! 插件身份校验 — 防止冒名顶替（插件目录名与 manifest id 不一致、
//! 非法 id 格式、重复 id 静默覆盖）：
//!
//! - `validate_plugin_id`：manifest id 必须为反向域名格式（`com.wasmnest.xxx`），
//!   拒绝大写/下划线/空段等一切非约定格式
//! - `validate_dir_binding`：插件目录名必须与 manifest id 完全一致 ——
//!   watcher 热重载、卸载、文件服务路径全部依赖「目录名 = id」约定，
//!   不一致说明目录被伪造或复制，一律拒绝加载
//!
//! 信任模型：插件身份 = manifest id 自报字符串（无签名链），校验规则
//! 保证 id 不可歧义（一个 id 只对应一个目录、一份 manifest），为审批
//! 门禁（approval.rs）提供可钉扎的身份锚点。完整模型见 docs/adr/。

// 中性词汇（票 02 M4）：清单统一取自 crate::manifest；`InstanceLifecycle` /
// lifecycle 校验是桌面 manifest 专属面（移动 manifest 无 lifecycle 声明），
// 该校验函数与 import 同随桌面装配面门控（`desktop-assembly`，语义边界不变）
#[cfg(feature = "desktop-assembly")]
use crate::manifest::InstanceLifecycle;
use crate::manifest::PluginManifest;

use crate::security::auth_policy::AuthStrategy;

/// 校验 manifest 必填字段
///
/// loader 目录扫描（`loader.rs::load_manifest`）与 zip 安装
/// （`downloader.rs::install_zip`）两条入口此前各抄一份 id/name/version 非空
/// 检查，新增必填约束时须同改两处——收敛到此处成为唯一真源（票 11 第 6 项）。
///
/// 两条入口各自独有的一道不在收敛范围：安装侧额外要求 id 是反向域名
/// （无签名链时防冒名 id），扫描侧额外要求 TS-only 插件声明 `main`。
/// 它们不是重复项，合并（取并集）会改变既有路径的口径。
pub fn validate_manifest_required(manifest: &PluginManifest) -> crate::Result<()> {
    if manifest.id.is_empty() {
        return Err(crate::AppError::Plugin(
            "plugin.json missing id field".to_string(),
        ));
    }
    if manifest.name.is_empty() {
        return Err(crate::AppError::Plugin(
            "plugin.json missing name field".to_string(),
        ));
    }
    if manifest.version.is_empty() {
        return Err(crate::AppError::Plugin(
            "plugin.json missing version field".to_string(),
        ));
    }
    // `ptyQuota` 区间仲裁**不在此处**（票 02 批次 03）：判据与常量真源都在能力域，
    // 装载期经 `DomainHooks::on_manifest_load` 由 `wasmnest-pty-engine` 自解析、自仲裁，
    // 越界即拒绝装载（`Err` ⇒ 不装载）——内核不再解释该字段（AGENTS §5.1 B6）。
    // 本函数只保住两处入口（目录扫描 / zip 安装）共用的结构性必填字段。
    // 运行期传输租约的 opt-in 必须与入站权限位同声明（两侧入口同口径）。
    validate_background_transport(manifest)?;
    // 生命周期 / preopen 校验为桌面 manifest 专属面（移动 manifest 无这两个字段，
    // fork 票 17 §3.2）——随桌面装配面门控（`desktop-assembly`）
    #[cfg(feature = "desktop-assembly")]
    {
        validate_lifecycle(manifest)?;
        validate_preopen_category(manifest)?;
        validate_platform(manifest)?;
    }
    Ok(())
}

/// 校验运行期传输租约声明（manifest `backgroundTransport`）与入站权限位的搭配
///
/// `backgroundTransport: true` 的语义是「应用整段运行期对外可达」——传输面
/// （端口监听 + mDNS 广播）随应用启动拉起、随停用回收。这个待遇必须与真实
/// 的入站权限位绑定：没有 `ws:server` / `network:http` 的应用既注册不出端点，
/// 也不该仅凭一个布尔位换到「持续对外广播」。
///
/// 权限词汇真源 = 各端 SDK `permission.rs`；此处只比对 wire 字面（内核不反向
/// 依赖端 SDK crate，与 `manager` 其余权限门同形）。**不夹取、不降级**：声明
/// 与权限不配套即拒绝装载，错误点名字段、缺失项与替代做法。
pub fn validate_background_transport(manifest: &PluginManifest) -> crate::Result<()> {
    if !manifest.background_transport {
        return Ok(());
    }
    const SERVER_PERMISSIONS: [&str; 2] = ["ws:server", "network:http"];
    if manifest
        .permissions
        .iter()
        .any(|permission| SERVER_PERMISSIONS.contains(&permission.as_str()))
    {
        return Ok(());
    }
    Err(crate::AppError::Plugin(
        "plugin.json backgroundTransport=true 但 permissions 未声明入站权限位\
         （ws:server / network:http 至少一个）：运行期持有传输租约 = 应用整段运行期\
         对外可达（端口 + mDNS 广播），必须与对应的服务端权限一起声明。\
         只在界面打开时供服的应用请删去该字段（界面挂载会按需 acquire）"
            .to_string(),
    ))
}

/// 校验 manifest 的平台适配声明覆盖**桌面端**（`platform` 必填面之行为契约）
///
/// `platform` 是必填的 adapt/端声明（wire 层由 serde 拒缺失），本函数补上**门禁**
/// 语义：单端声明装载到另一端即显性拒绝——桌面端只放行 `desktop` / `both`，
/// `mobile`（仅移动）在此处 fail-visible，防止把移动端分发包放到桌面 resources /
/// 用户插件目录后「装了却不出现」或运行期行为错乱。
///
/// 为什么门禁住桌面装配面（`desktop-assembly`）：这就是「桌面端如何解释本端」的
/// 端事实，与 `validate_lifecycle` / `validate_preopen_category` 同档；移动端对等
/// 门禁住移动宿主（`plugin/loader.rs` / `plugin/downloader.rs`，移动 SDK 的
/// `PluginPlatform::supports`）。
#[cfg(feature = "desktop-assembly")]
pub fn validate_platform(manifest: &PluginManifest) -> crate::Result<()> {
    use crate::manifest::PluginPlatform;
    if !manifest.platform.supports(PluginPlatform::Desktop) {
        return Err(crate::AppError::Plugin(format!(
            "plugin.json platform=\"{}\" 与桌面端不匹配：该插件声明仅适配另一端\
             （platform 需为 \"desktop\"；双端适配写 \"both\"），桌面端拒绝装载",
            manifest.platform.as_str()
        )));
    }
    Ok(())
}

/// 校验 manifest 声明的实例生命周期策略（ADR 0032）
///
/// `ephemeral`（业务 worker 形态）**本期只预留类型**：宿主的一次性实例机制与
/// 调度框架尚未落地（ADR 0032 §6 的启用清单），因此声明即**加载期显性拒绝**。
///
/// 为什么不能「先当常驻处理」：常驻语义下 worker 会与其存在理由**正好相反**地
/// 长驻——线性内存只能 grow 不能 shrink，长驻实例处理大输入会单调增长到宿主
/// 单实例限额（`runtime.rs::memory_growing` 拒绝增长 → guest trap）且不重启进程
/// 好不了。静默降级会让作者以为 worker 生效了，实际既没省内存又没省限额。
/// 拒绝时点名缺什么（缺调度方 + 传参协议 + 配额），便于对着清单补齐后再启用。
#[cfg(feature = "desktop-assembly")]
pub fn validate_lifecycle(manifest: &PluginManifest) -> crate::Result<()> {
    if manifest.lifecycle != InstanceLifecycle::Persistent {
        return Err(crate::AppError::Plugin(format!(
            "plugin.json lifecycle=\"{}\" 暂不可用：一次性实例机制与调度框架尚未落地 \
             （业务 worker 形态已登记，见 ADR 0032 §6；启用前需补齐调度方、store 传参协议、\
             权限模型与 per-app 配额）。请改用 lifecycle=\"persistent\" 或删去该字段",
            manifest.lifecycle.as_str()
        )));
    }
    Ok(())
}

/// 校验 manifest 声明的 WASI 预打开目录归属类别（ADR 0034）
///
/// `wasiPreopenDirs` 仅 worker 类别（`lifecycle: ephemeral`）可用——主 wasm-app
/// 文件访问一律走宿主 `host-fs` 授权机制（`fs:read` / `fs:write` 权限 + `fs_request_auth`
/// / preauth 目录授权）。非 worker 声明即**加载期显性拒绝**：静默忽略会让「声明了却
/// 没人读它」的目录配置一路活到分发链（§8 fail-visible 形态之③）。
///
/// worker 未实现期间（ADR 0032 §6 双侧拒绝）`ephemeral` 本身被 [`validate_lifecycle`]
/// 拒绝，故本字段当前对一切 manifest 不可达——此处的类别闸门是取值域层面的落死，
/// worker 启用（ephemeral 放行）后 preopen 即恢复为 worker 专属能力。
#[cfg(feature = "desktop-assembly")]
pub fn validate_preopen_category(manifest: &PluginManifest) -> crate::Result<()> {
    if !manifest.wasi_preopen_dirs.is_empty() && manifest.lifecycle != InstanceLifecycle::Ephemeral
    {
        return Err(crate::AppError::Plugin(
            "plugin.json wasiPreopenDirs 仅 worker 类别（lifecycle=\"ephemeral\"）可用：\
             业务应用文件访问一律走宿主 host-fs 授权机制（permissions 声明 fs:read/fs:write，\
             目录经 fs_request_auth / preauth 授权并持久化），见 ADR 0034"
                .to_string(),
        ));
    }
    Ok(())
}

/// 解析 manifest 文本（含必填字段校验 + 授权策略声明拒绝）——两条入口的统一口径
///
/// 先解析成 `serde_json::Value` 再查策略声明、最后反序列化：宿主 manifest 结构里
/// **根本没有**策略字段，反序列化之后未知键已被 serde 丢掉，届时再查就查不到了
/// （这正是不加这道检查时「声明了也静默无效」的机制）。
pub fn parse_manifest_json(content: &str) -> crate::Result<PluginManifest> {
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| crate::AppError::Plugin(format!("Failed to parse plugin.json: {}", e)))?;
    reject_policy_declaration(&value)?;
    let manifest: PluginManifest = serde_json::from_value(value)
        .map_err(|e| crate::AppError::Plugin(format!("Failed to parse plugin.json: {}", e)))?;
    validate_manifest_required(&manifest)?;
    Ok(manifest)
}

/// 授权策略相关的 manifest 键名（小写比较；**命中即拒，不看取值**）
///
/// 键名按「插件作者会怎么写」列全而不是只挡一个拼写：漏挡的后果是允许一条
/// 「声明了却没有任何一行代码读它」的配置留在包里，作者以为档位生效了。
const POLICY_DECLARATION_KEYS: &[&str] = &[
    "authstrategy",
    "authstrategies",
    "authpolicy",
    "authpolicies",
    "authorizationstrategy",
    "authorizationstrategies",
    "authorizationpolicy",
    "authorizationpolicies",
    "permissionstrategy",
    "permissionstrategies",
    "fsstrategy",
    "fsstrategies",
    "networkstrategy",
    "networkstrategies",
];

/// 通用键名（`strategy` / `policy` 一类）：只在取值命中档位词汇表时才拒
///
/// 这类键名太常见（别的用途也会叫 policy），一律拒会误伤正常声明；
/// 「键名像策略 + 取值是档位词汇」的组合才说明作者确实在声明档位。
const GENERIC_POLICY_KEYS: &[&str] = &["strategy", "strategies", "policy", "policies"];

/// 档位取值词汇表（与宿主 `AuthStrategy` 的 wire 值同源，两处各拼一套必然漂移）
const TIER_VALUES: [&str; 3] = [
    AuthStrategy::AlwaysAsk.as_str(),
    AuthStrategy::Default.as_str(),
    AuthStrategy::AlwaysAllow.as_str(),
];

/// manifest 不得声明授权策略档位 —— 声明即加载期显性拒绝（spec §11 B5）
///
/// 档位是**用户**对某个应用的安全决定（宿主主库 `plugin_auth_policies` 是真源）；
/// manifest 是应用自报的静态声明，若允许它声明档位，等于应用自报「我可以免询问」。
/// 静默忽略比报错更危险：作者会以为声明生效了（详见 `parse_manifest_json` 的注释）。
pub fn reject_policy_declaration(value: &serde_json::Value) -> crate::Result<()> {
    if let Some((key_path, shown)) = find_policy_declaration(value) {
        return Err(crate::AppError::Plugin(format!(
            "plugin.json 不得声明授权策略档位（发现 {key_path} = {shown}）：\
             策略由用户在设置页按应用设置，真源在宿主主库，manifest 声明不会被读取"
        )));
    }
    Ok(())
}

/// 递归查找策略声明，返回 `(键路径, 取值摘要)`
///
/// 递归（含 `contributes` 等嵌套对象与数组元素）：写 `contributes.fsStrategy` 与写
/// 顶层一样都是「声明档位」，只查顶层等于留一条绕过路径。
fn find_policy_declaration(value: &serde_json::Value) -> Option<(String, String)> {
    find_policy_declaration_at(value, "")
}

fn find_policy_declaration_at(value: &serde_json::Value, path: &str) -> Option<(String, String)> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let key_lc = key.to_ascii_lowercase();
                let key_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if POLICY_DECLARATION_KEYS.contains(&key_lc.as_str()) {
                    return Some((key_path, describe_value(child)));
                }
                if GENERIC_POLICY_KEYS.contains(&key_lc.as_str()) && carries_tier_value(child) {
                    return Some((key_path, describe_value(child)));
                }
                if let Some(found) = find_policy_declaration_at(child, &key_path) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if let Some(found) = find_policy_declaration_at(item, &format!("{path}[{index}]")) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

/// 取值（含数组元素形态）是否命中档位词汇表
fn carries_tier_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => TIER_VALUES.contains(&s.as_str()),
        serde_json::Value::Array(items) => items.iter().any(carries_tier_value),
        serde_json::Value::Object(map) => map.values().any(carries_tier_value),
        _ => false,
    }
}

/// 取值摘要（错误文案点名用；超长截断，避免把整个 manifest 抄进错误里）
fn describe_value(value: &serde_json::Value) -> String {
    let raw = value.to_string();
    if raw.chars().count() > 60 {
        format!("{}…", raw.chars().take(60).collect::<String>())
    } else {
        raw
    }
}

/// 插件 id 最大长度（反向域名约定，避免超长 id 打日志/路径）
pub const PLUGIN_ID_MAX_LEN: usize = 100;

/// 校验插件 id 是否为合法反向域名格式
///
/// 规则：小写字母/数字开头的小写段，以 `.` 分段（至少两段），
/// 段内可含连字符（不允许首尾连字符、连续点、下划线、大写）。
/// 如 `com.wasmnest.bedcode` ✓，`Com.WasmNest.X` ✗，`my_plugin` ✗。
pub fn validate_plugin_id(id: &str) -> bool {
    if id.is_empty() || id.len() > PLUGIN_ID_MAX_LEN {
        return false;
    }
    // 至少两段反向域名：segment(.segment)+
    let segments: Vec<&str> = id.split('.').collect();
    if segments.len() < 2 {
        return false;
    }
    segments.iter().enumerate().all(|(i, seg)| {
        if seg.is_empty() {
            return false;
        }
        let bytes = seg.as_bytes();
        // 首段必须纯字母数字（spec：^[a-z0-9]+），拒绝 "my-plugin.com" 形态
        if i == 0 {
            return bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        }
        if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
            return false;
        }
        if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        {
            return false;
        }
        bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    })
}

/// 校验插件目录名与 manifest id 绑定一致
///
/// 目录名是插件文件系统的物理锚点（watcher 热重载按目录名取 id、
/// 卸载按 `plugins_dir/{id}` 删除、文件服务挂载路径含 id），
/// manifest.id 是权限/存储/注册表的逻辑锚点。两者不一致 =
/// 目录被复制改名或 manifest 被替换，直接拒绝。
pub fn validate_dir_binding(dir_name: &str, manifest_id: &str) -> bool {
    dir_name == manifest_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ids() {
        for id in [
            "com.wasmnest.bedcode",
            "com.wasmnest.file-transfer",
            "com.wasmnest.ai-chatbox",
            "com.example.plugin",
            "a.b",
            "a1.b2.c3",
            "com.wasmnest.x-1",
        ] {
            assert!(validate_plugin_id(id), "id should be valid: {}", id);
        }
    }

    #[test]
    fn test_invalid_ids() {
        for id in [
            "",                                 // 空
            "noplugin",                         // 单段
            "my-plugin.com",                    // 首段连字符（spec 拒绝）
            "com..wasmnest",                    // 连续点（空段）
            "com.wasmnest.",                    // 尾点
            ".com.wasmnest",                    // 首点
            "Com.WasmNest.X",                   // 大写
            "com.wasmnest.my_plugin",           // 下划线
            "com.wasmnest.-x",                  // 段首连字符
            "com.wasmnest.x-",                  // 段尾连字符
            "com.wasmnest.x y",                 // 空格
            "com.wasmnest.x/y",                 // 路径分隔符
            &"a".repeat(PLUGIN_ID_MAX_LEN + 1), // 超长
        ] {
            assert!(!validate_plugin_id(id), "id should be invalid: {}", id);
        }
    }

    // `ptyQuota` 区间仲裁的两条用例随判据迁往能力域（票 02 批次 03）：
    // `wasmnest-pty-engine::plugin_binding::manifest_quota_tests`。内核不再拥有该判据，
    // 在此留同名用例只会要求内核继续解释 manifest 字段（AGENTS §5.1 B6）。

    /// 角色维度（ADR 0032）：`lifecycle` 声明的校验在**加载期**生效
    ///
    /// 正例：缺省与显式 `persistent` 都照常加载（旧产物零迁移）；
    /// 反例：`ephemeral` 必须加载期失败并点名缺什么——静默当常驻处理会让作者
    /// 以为 worker 已生效，而常驻恰好是 worker 存在理由的反面（线性内存只增不减）。
    // 生命周期声明面 = 桌面 manifest 专属（移动 SDK 无 InstanceLifecycle，fork 票 17 §3.2）
    #[cfg(feature = "desktop-assembly")]
    #[test]
    fn lifecycle_ephemeral_is_rejected_at_load_persistent_and_absent_pass() {
        let parse = |extra: &str| -> crate::Result<PluginManifest> {
            parse_manifest_json(&format!(
                r#"{{"id":"com.wasmnest.worker","name":"worker","version":"1.0.0","platform":"both"{extra}}}"#
            ))
        };

        assert!(
            parse("").is_ok(),
            "缺省（未声明 lifecycle）= 常驻，既有插件零迁移"
        );
        assert_eq!(
            parse(r#","lifecycle":"persistent""#)
                .expect("显式声明常驻合法")
                .lifecycle,
            crate::manifest::InstanceLifecycle::Persistent
        );

        let err = parse(r#","lifecycle":"ephemeral""#)
            .err()
            .expect("预留形态声明必须加载期显性拒绝");
        let text = err.to_string();
        assert!(
            text.contains("lifecycle") && text.contains("ephemeral") && text.contains("ADR 0032"),
            "错误必须点名字段、取值与缺口（否则作者无从下手），got: {text}"
        );

        // 非法取值不得回落常驻（serde 反序列化即拒，host 侧根本拿不到 manifest）
        assert!(
            parse(r#","lifecycle":"workerish""#).is_err(),
            "未知 lifecycle 取值必须失败，不得静默当常驻"
        );
    }

    /// `wasiPreopenDirs` 的归属类别闸门（ADR 0034）：仅 worker（`lifecycle: ephemeral`）
    /// 可声明，主 wasm-app 文件访问一律走宿主 host-fs。
    ///
    /// 正例：无声明（一切现有 manifest）照常加载；
    /// 反例：缺省 / 显式 `persistent` 声明 preopen → 加载期显性拒绝并点名 host-fs 替代；
    /// `ephemeral` + preopen → 由既有 `validate_lifecycle` 闸门先拒（worker 未实现，
    /// 点名 ADR 0032 缺口）——两类缺口不许混同。
    ///
    /// 变异判据：把 `validate_preopen_category` 从 `validate_manifest_required` 摘掉，
    /// 反例全部转红（preopen 声明会静默进入宿主、按 manifest 预打开目录）。
    // 桌面装配面（desktop-assembly）专属：WASI preopen / 角色 `type` 词汇是桌面
    // 契约事实（ADR 0032/0034；移动 Manifest 无 kind 字段、无 WASI 面——
    // 移动形态零 preopen、零角色驱动加载，票 02 M12 语义边界）。
    #[cfg(feature = "desktop-assembly")]
    #[test]
    fn wasi_preopen_dirs_on_non_worker_is_rejected_at_load() {
        let parse = |extra: &str| -> crate::Result<PluginManifest> {
            parse_manifest_json(&format!(
                r#"{{"id":"com.wasmnest.po","name":"po","version":"1.0.0","platform":"both"{extra}}}"#
            ))
        };

        // 无声明：既有 manifest 零迁移
        assert!(parse("").is_ok());
        assert!(parse(r#","lifecycle":"persistent""#).is_ok());

        // 缺省 lifecycle（= persistent）声明 preopen → 拒
        let err = parse(r#","wasiPreopenDirs":["${home}/data"]"#)
            .err()
            .expect("persistent manifest declaring preopen must be rejected");
        let text = err.to_string();
        assert!(
            text.contains("wasiPreopenDirs")
                && text.contains("host-fs")
                && text.contains("ADR 0034"),
            "错误必须点名字段、替代机制与 ADR，got: {text}"
        );

        // 显式 persistent 声明 preopen → 同样拒
        assert!(
            parse(r#","lifecycle":"persistent","wasiPreopenDirs":["/x"]"#).is_err(),
            "显式 persistent 声明 preopen 必须拒绝"
        );

        // ephemeral + preopen：由既有 lifecycle 闸门先拒（worker 未实现），
        // 错误指向 ADR 0032 缺口而不是 ADR 0034 类别
        let err = parse(r#","lifecycle":"ephemeral","wasiPreopenDirs":["/x"]"#)
            .err()
            .expect("ephemeral manifest must be rejected by the lifecycle gate");
        assert!(
            err.to_string().contains("ADR 0032"),
            "ephemeral 缺口必须点名 ADR 0032，got: {err}"
        );
    }

    /// 角色（`type`）的取值域在反序列化期收口：三角色 + 旧拼写别名，
    /// 其余一律拒（不回落缺省 L3——那会让「声明了基础服务却被当业务应用装配」
    /// 这类错误一路活到运行期）
    // 桌面装配面（desktop-assembly）专属：WASI preopen / 角色 `type` 词汇是桌面
    // 契约事实（ADR 0032/0034；移动 Manifest 无 kind 字段、无 WASI 面——
    // 移动形态零 preopen、零角色驱动加载，票 02 M12 语义边界）。
    #[cfg(feature = "desktop-assembly")]
    #[test]
    fn manifest_role_spelling_domain_is_closed_at_load() {
        let parse = |kind: &str| -> crate::Result<PluginManifest> {
            parse_manifest_json(&format!(
                r#"{{"id":"com.wasmnest.role","name":"role","version":"1.0.0","platform":"both","type":"{kind}"}}"#
            ))
        };
        assert!(parse("basic-service").is_ok());
        assert!(parse("internal-business").is_ok());
        assert!(parse("business-app").is_ok());
        assert!(
            parse("system").is_ok(),
            "旧拼写（L1）仍按别名解析，旧产物零迁移"
        );
        assert!(parse("application").is_ok(), "旧拼写（L3）仍按别名解析");
        for bad in ["systemm", "internal", "BASIC-SERVICE", ""] {
            assert!(parse(bad).is_err(), "非法角色取值必须加载期失败: {bad:?}");
        }
    }

    /// `platform` 声明的门禁语义：只放行本端 / 双端，另一端专属声明加载期显性拒绝
    ///
    /// 正例：`"desktop"` 与 `"both"` 均照常加载；
    /// 反例：`"mobile"`（仅移动）必须加载期失败并点名字段与可用取值；
    /// 异常：缺失（wire 必填，serde 即拒）与未知取值（`"linux"`）都必须失败——
    /// 不得回落 `Default` 的 `Both`（回落会把「装错端」从显性拒绝变成静默装载）。
    ///
    /// 变异判据：把 `validate_platform` 从 `validate_manifest_required` 摘掉，
    /// `"mobile"` 反例会静默装载成功（转红）；把 enum 的 serde 换成
    /// `#[serde(default)]` 后缺失用例转红。
    ///
    /// 命名说明（ADR 0047 D2「自持标识符零端名」，移动纯净锁
    /// `mobile_wasm_core_purity_lock.rs` 扫描声明位）：标识符不得含端名，
    /// 本端语义放注释与断言，函数名保持端中立。
    #[cfg(feature = "desktop-assembly")]
    #[test]
    fn platform_declaration_must_cover_hosting_end() {
        use crate::manifest::PluginPlatform;
        let parse = |platform: &str| -> crate::Result<PluginManifest> {
            parse_manifest_json(&format!(
                r#"{{"id":"com.wasmnest.plat","name":"plat","version":"1.0.0","platform":"{platform}"}}"#
            ))
        };

        // 正例：本端专属与双端声明都放行
        assert_eq!(
            parse("desktop").expect("desktop 声明").platform,
            PluginPlatform::Desktop
        );
        assert_eq!(
            parse("both").expect("both 声明").platform,
            PluginPlatform::Both
        );

        // 反例：另一端专属 → 显性拒绝，错误点名字段、声明值与可用取值
        let err = parse("mobile").err().expect("仅移动端声明在桌面端必须拒绝");
        let text = err.to_string();
        assert!(
            text.contains("platform") && text.contains("mobile") && text.contains("both"),
            "错误必须点名字段、声明值与可用取值（否则作者无从下手），got: {text}"
        );

        // 异常：缺失字段（wire 必填无缺省，与 id/name/version 同档）与非法取值均在解析期拒绝
        let missing =
            parse_manifest_json(r#"{"id":"com.wasmnest.plat","name":"plat","version":"1.0.0"}"#)
                .err()
                .expect("platform 缺失必须拒绝");
        assert!(
            missing.to_string().contains("platform"),
            "缺失错误必须点名 platform，got: {missing}"
        );
        assert!(
            parse("linux").is_err(),
            "未知 platform 取值必须失败，不得回落缺省"
        );
    }

    /// `backgroundTransport` opt-in 必须与入站权限位同声明（应用整段运行期对外可达）
    ///
    /// 变异判据：把 `validate_background_transport` 从 `validate_manifest_required`
    /// 摘掉，反例全部转红（只有布尔位、没有服务端权限的 manifest 会静默装载，
    /// 运行期却拿不到任何端点，作者会以为「声明生效了」）。
    #[test]
    fn background_transport_requires_inbound_server_permission() {
        let with = |extra: &str| -> crate::Result<PluginManifest> {
            parse_manifest_json(&format!(
                r#"{{"id":"com.wasmnest.srv","name":"srv","version":"1.0.0","platform":"both"{extra}}}"#
            ))
        };

        // 缺省 / 显式 false：既有 manifest 零迁移
        assert!(!with("").expect("未声明").background_transport);
        assert!(
            !with(r#","backgroundTransport":false"#)
                .expect("显式 false")
                .background_transport
        );

        // true + 任一入站权限位 → 放行
        for permission in ["ws:server", "network:http"] {
            let manifest = with(&format!(
                r#","backgroundTransport":true,"permissions":["{permission}"]"#
            ))
            .unwrap_or_else(|e| panic!("{permission} 应放行: {e}"));
            assert!(manifest.background_transport);
        }

        // true 但无入站权限位（只有出站 ws:client / 只有存储 / 空清单）→ 加载期拒绝
        for permissions in [r#"["storage"]"#, r#"["ws:client"]"#, r#"[]"#] {
            let err = with(&format!(
                r#","backgroundTransport":true,"permissions":{permissions}"#
            ))
            .err()
            .unwrap_or_else(|| panic!("backgroundTransport 无入站权限位必须拒绝: {permissions}"));
            let text = err.to_string();
            assert!(
                text.contains("backgroundTransport")
                    && text.contains("ws:server")
                    && text.contains("network:http"),
                "错误必须点名字段与缺失权限位，got: {text}"
            );
        }

        // 形态非法（非布尔）在反序列化期拒绝，不得静默回落 false
        assert!(
            with(r#","backgroundTransport":"true""#).is_err(),
            "backgroundTransport 只接受布尔值"
        );
    }

    /// 授权策略档位声明在**加载期显性拒绝**（spec §11 B5：宿主不得替插件决定业务策略）
    ///
    /// 变异判据：把 `reject_policy_declaration` 从 `parse_manifest_json` 里摘掉，
    /// 本条全部转红（这些 manifest 会静默加载成功，档位声明等于没写）。
    #[test]
    fn policy_declaration_in_manifest_is_rejected_at_load() {
        let with = |extra: &str| {
            parse_manifest_json(&format!(
                r#"{{"id":"com.wasmnest.p","name":"p","version":"1.0.0","platform":"both"{extra}}}"#
            ))
        };

        // 策略味儿键名：命中即拒，不看取值
        for extra in [
            r#","authStrategy":"always_ask""#,
            r#","authPolicies":{"fs":"default"}"#,
            r#","authorizationStrategies":["always_allow"]"#,
            r#","fsStrategy":"always_allow""#,
            r#","networkStrategy":"default""#,
            r#","permissionStrategies":{"fs":"always_ask"}"#,
        ] {
            let err = with(extra)
                .err()
                .unwrap_or_else(|| panic!("策略声明必须被拒绝: {extra}"));
            assert!(
                err.to_string().contains("不得声明授权策略档位"),
                "错误必须说清拒绝理由，got: {err}"
            );
        }

        // 通用键名 + 档位取值：拒（作者确实在声明档位）
        for extra in [
            r#","strategy":"always_ask""#,
            r#","strategies":["default"]"#,
            r#","policy":{"fs":"always_allow"}"#,
        ] {
            assert!(
                with(extra).is_err(),
                "通用键名带档位取值也必须拒绝: {extra}"
            );
        }

        // 嵌套（contributes 内）与一般未知键：前者拒，后者照常加载（老端忽略未知字段的演进约定）
        assert!(
            with(r#","contributes":{"fsStrategy":"always_ask"}"#).is_err(),
            "嵌套位置的策略声明同样是声明档位（只查顶层等于留一条绕过路径）"
        );
        assert!(
            with(r#","retentionPolicy":"default""#).is_ok(),
            "键名不像策略、取值只是碰巧是 default 的声明不得误伤"
        );
        assert!(
            with(r#","sandbox":"isolated""#).is_ok(),
            "退役字段照常加载（票 06 裁决 2）——本闸门只针对策略档位"
        );
    }

    /// 档位词汇表与宿主 `AuthStrategy` 同源（词表漂移会让闸门漏挡或误伤）
    #[test]
    fn tier_vocabulary_matches_host_strategy_values() {
        assert_eq!(
            TIER_VALUES,
            [
                AuthStrategy::AlwaysAsk.as_str(),
                AuthStrategy::Default.as_str(),
                AuthStrategy::AlwaysAllow.as_str()
            ]
        );
    }

    #[test]
    fn test_dir_binding() {
        assert!(validate_dir_binding(
            "com.wasmnest.bedcode",
            "com.wasmnest.bedcode"
        ));
        // 目录名与 id 不一致：伪造/复制目录
        assert!(!validate_dir_binding(
            "com.wasmnest.evil",
            "com.wasmnest.bedcode"
        ));
        assert!(!validate_dir_binding(
            "session",
            "com.wasmnest.bedcode"
        ));
    }
}
