//! 插件权限审批与内容钉扎
//!
//! 插件权限审批与内容钉扎（content pinning）：
//!
//! - 权限门禁：生效权限 = 用户批准的权限 ∩ manifest 请求的权限
//!   （`effective_permissions`），杜绝「manifest 声明即信任」的自动全量授权
//! - 哈希钉扎：批准时对插件目录全部文件计算 SHA-256，激活时重算校验。
//!   插件文件在批准后被替换（冒名顶替的在位攻击）→ 哈希不匹配 →
//!   批准自动撤销，必须重新人工审批
//!
//! 信任边界：内置插件（桌面 resources 随包 / 移动 APK assets）属于
//! 应用构建信任域，视为已批准（`trusted=true` 直接放行）；
//! 用户安装的插件必须经过本模块审批后才能激活。
//!
//! 持久化：`plugin_storage` 表 `__system__` 空间 `plugin_approvals` key，
//! 与激活状态持久化（storage.rs ACTIVATION_STATE_KEY）同一模式。

use crate::storage::PluginStorage;
use crate::AppError;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// 审批记录存储 key（系统级 plugin_id 空间下）
pub const APPROVAL_STORAGE_KEY: &str = "plugin_approvals";

/// 系统级 plugin_id（与 storage.rs SYSTEM_PLUGIN_ID 同值，避免数据混入插件空间）
const SYSTEM_PLUGIN_ID: &str = "__system__";

/// 单条插件审批记录
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginApproval {
    /// 用户批准时同意的权限列表（生效权限 = 该列表 ∩ manifest 请求）
    pub approved_permissions: Vec<String>,
    /// 批准时插件目录内容 SHA-256（激活时校验，防批准后替换）
    pub content_hash: String,
    /// 批准时的插件版本
    pub version: String,
    /// 批准时间（RFC3339）
    pub approved_at: String,
}

/// 审批校验结果
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalStatus {
    /// 已批准且内容哈希一致
    Approved,
    /// 无审批记录（或权限集合为空）
    Pending,
    /// 有审批记录但内容哈希不匹配（文件被替换，需重新批准）
    HashMismatch,
}

/// 审批存储：基于 PluginStorage 的 JSON map（plugin_id → PluginApproval）
pub struct PluginApprovalStore {
    storage: Arc<PluginStorage>,
}

impl PluginApprovalStore {
    pub fn new(storage: Arc<PluginStorage>) -> Self {
        Self { storage }
    }

    /// 加载全部审批记录（无记录 → 空 map；**损坏 → 删除坏行并回落空 map**）
    ///
    /// 损坏不可恢复会让后续 approve/revoke 全部失败直到手工清 key（早年实测形态：
    /// 日志说 resetting 实际没 reset）。这里真正落盘重置：删掉坏行，下次
    /// `get` / `approve` 从干净状态继续，并且复位动作本身不阻断本次加载。
    pub async fn load_all(&self) -> crate::Result<HashMap<String, PluginApproval>> {
        match self
            .storage
            .get(SYSTEM_PLUGIN_ID, APPROVAL_STORAGE_KEY)
            .await?
        {
            Some(value) => match serde_json::from_value::<HashMap<String, PluginApproval>>(value) {
                Ok(map) => Ok(map),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to parse plugin approvals; resetting stored approvals");
                    // 尽力而为清除坏行；失败仅记 warn（下次触发会再次尝试重置）
                    if let Err(clear_err) = self
                        .storage
                        .delete(SYSTEM_PLUGIN_ID, APPROVAL_STORAGE_KEY)
                        .await
                    {
                        tracing::warn!(error = %clear_err, "Failed to clear corrupted plugin approvals");
                    }
                    Ok(HashMap::new())
                }
            },
            None => Ok(HashMap::new()),
        }
    }

    /// 保存全部审批记录
    pub async fn save_all(&self, map: &HashMap<String, PluginApproval>) -> crate::Result<()> {
        let value = serde_json::to_value(map)?;
        self.storage
            .set(SYSTEM_PLUGIN_ID, APPROVAL_STORAGE_KEY, value)
            .await
    }

    /// 读取单个插件审批记录
    pub async fn get(&self, plugin_id: &str) -> crate::Result<Option<PluginApproval>> {
        Ok(self.load_all().await?.remove(plugin_id))
    }

    /// 记录/更新审批（覆盖式：以本次批准的权限集合为准）
    ///
    /// **原子读-改-写**（S-04）：读 map → 插入 → 写回 全程在同一 DB 锁内完成，
    /// 并发 approve/revoke（多实例各自构造的 `PluginApprovalStore` 共享同一
    /// `Arc<PluginStorage>`）不再互相覆盖——先前的「load_all → save_all」两次
    /// 独立操作在并发交错下会丢掉其中一方的修改（revoke 丢失 = 过期授予存活）。
    pub async fn approve(
        &self,
        plugin_id: &str,
        approved_permissions: &[String],
        content_hash: &str,
        version: &str,
    ) -> crate::Result<()> {
        let plugin_id = plugin_id.to_string();
        let approved_permissions = approved_permissions.to_vec();
        let content_hash = content_hash.to_string();
        let version = version.to_string();
        self.storage
            .update(SYSTEM_PLUGIN_ID, APPROVAL_STORAGE_KEY, move |value| {
                let mut map = parse_approvals(value)?;
                map.insert(
                    plugin_id,
                    PluginApproval {
                        approved_permissions,
                        content_hash,
                        version,
                        approved_at: chrono::Utc::now().to_rfc3339(),
                    },
                );
                Ok(serde_json::to_value(map)?)
            })
            .await
    }

    /// 撤销审批（哈希不匹配 / 卸载时调用）；同样走原子读-改-写（S-04）
    pub async fn revoke(&self, plugin_id: &str) -> crate::Result<()> {
        let plugin_id = plugin_id.to_string();
        self.storage
            .update(SYSTEM_PLUGIN_ID, APPROVAL_STORAGE_KEY, move |value| {
                let mut map = parse_approvals(value)?;
                map.remove(&plugin_id);
                Ok(serde_json::to_value(map)?)
            })
            .await
    }
}

/// 从存储值解析审批 map；损坏/缺失统一回落到空 map（配合 S-10 的 reset 语义：
/// 写路径遇到坏数据也不致永败，而是以空 map 为基线继续）
fn parse_approvals(
    value: Option<serde_json::Value>,
) -> crate::Result<HashMap<String, PluginApproval>> {
    match value {
        Some(v) => serde_json::from_value(v).map_err(|e| {
            tracing::warn!(error = %e, "Failed to parse plugin approvals; continuing with empty map");
            crate::AppError::Plugin(format!("Invalid plugin approvals: {}", e))
        }),
        None => Ok(HashMap::new()),
    }
}

// 哈希排除的运行时数据文件（非安装内容）：**根级**私有 SQLite 库及其边车文件
//
// 插件私有 SQLite 库位于插件安装目录内（`app_data/plugins/<id>/plugin.db`，
// 见 `host_api::context` 的私有库路径装配与移动侧 `plugin_db` 布局），批准之后
// 运行期会持续变化；把它计入哈希会让「批准 → 启用 → 停用 → 再启用」每次都
// 判成 HashMismatch 并撤销批准，插件再也起不来。排除的只是**数据面**：
// plugin.json / index.js / *.wasm 等代码面仍在哈希内，替换代码依然会被抓住。
//
// 排除规则按**根相对路径**精确匹配（S-08）：`rel == "plugin.db"` 或
// `rel.starts_with("plugin.db-")`——只有根级的库与边车文件豁免，
// `assets/plugin.db*` 等嵌套同名文件仍参与哈希（过宽的裸文件名匹配会让
// 深层数据文件在审批后改动而不失效钉扎）。

/// 计算插件目录内容 SHA-256（相对路径排序 + 长度前缀帧）
///
/// 覆盖目录下全部文件（含 plugin.json / wasm / js 产物），任一文件被替换都会
/// 导致哈希变化；根级运行时数据文件按上述规则排除。拒绝含符号链接的目录
/// （S-03，fail-closed）。哈希帧带文件计数与每字段长度前缀（S-07），
/// 内容含 NUL 也不产生帧歧义。
pub fn compute_dir_hash(dir: &Path) -> crate::Result<String> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    fn collect(dir: &Path, base: &Path, files: &mut Vec<(String, Vec<u8>)>) -> crate::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .map_err(|e| AppError::Plugin(format!("Hash path strip failed: {}", e)))?
                .to_string_lossy()
                .to_string();
            // lstat 语义（entry.file_type() 不跟随符号链接，S-03）：插件目录里的
            // symlink 一律拒绝——跟随它可读取/哈希插件根外文件、链接环可致递归
            // 栈溢出 DoS；钉扎语义要求哈希覆盖的正是目录树本身
            let file_type = entry.file_type().map_err(|e| {
                AppError::Plugin(format!("Failed to stat '{}' for hashing: {}", rel, e))
            })?;
            if file_type.is_symlink() {
                return Err(AppError::Plugin(format!(
                    "Plugin directory contains symlink '{}'; symbolic links are not allowed in pinned content (approval blocked)",
                    rel
                )));
            }
            if file_type.is_dir() {
                collect(&path, base, files)?;
            } else if file_type.is_file() {
                // 排除规则按**根相对路径**精确匹配（S-08）：只豁免根级的私有库
                // 及其 SQLite 边车文件；`assets/plugin.db*` 等嵌套同名文件仍参与哈希
                let excluded = rel == "plugin.db" || rel.starts_with("plugin.db-");
                if excluded {
                    continue;
                }
                let content = std::fs::read(&path).map_err(|e| {
                    AppError::Plugin(format!("Failed to read '{}' for hashing: {}", rel, e))
                })?;
                files.push((rel, content));
            }
        }
        Ok(())
    }
    collect(dir, dir, &mut files)?;

    // 相对路径排序，保证遍历顺序稳定（文件系统枚举顺序不保证）
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    // 防哈希帧歧义（S-07）：文件计数 + 每字段 u64 LE 长度前缀，字段间不再依赖
    // NUL 分隔——内容含 NUL 时「rel+[0]+content+[0]」可能使不同文件集产出相同
    // 摘要（在位替换攻击可保持哈希不变）。旧版钉扎摘要格式已变，存量已批准
    // 插件需重新审批（fail-visible，不静默沿用旧摘要）。
    hasher.update((files.len() as u64).to_le_bytes());
    for (rel, content) in &files {
        hasher.update((rel.len() as u64).to_le_bytes());
        hasher.update(rel.as_bytes());
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// 计算生效权限集：用户批准 ∩ manifest 请求
///
/// `trusted=true`（内置插件）时直接全量返回请求权限。
///
/// **没有任何恒授予的特例**：`storage` 曾在旧形态下被无条件塞进结果集，
/// 使「manifest 声明即信任」退化为「不声明也有」（票 02 已在
/// `PermissionManager::grant_permissions` 取消默认位，本处是同一决策的收尾）。
pub fn effective_permissions(
    requested: &[String],
    approval: Option<&PluginApproval>,
    trusted: bool,
) -> HashSet<String> {
    if trusted {
        return requested.iter().cloned().collect();
    }
    match approval {
        Some(appr) => {
            let approved: HashSet<&str> = appr
                .approved_permissions
                .iter()
                .map(|s| s.as_str())
                .collect();
            requested
                .iter()
                .filter(|p| approved.contains(p.as_str()))
                .cloned()
                .collect()
        }
        None => HashSet::new(),
    }
}

/// 过滤出 SDK 词汇表内的权限（保持声明顺序、去重）
///
/// 审批记录里存的必须是「真能生效的位」——把词汇表外的装饰声明也写进批准清单，
/// 会让用户看到的批准集与实际生效集不一致（授权时仍会被 `PermissionManager`
/// 过滤掉），弹层就成了假账。词汇真源是 SDK 的 [`VALID_PERMISSIONS`]。
///
/// [`VALID_PERMISSIONS`]: crate::permission::VALID_PERMISSIONS
pub fn known_permissions(requested: &[String]) -> Vec<String> {
    let valid: HashSet<&str> = crate::permission::VALID_PERMISSIONS
        .iter()
        .copied()
        .collect();
    let mut seen: HashSet<&str> = HashSet::new();
    requested
        .iter()
        .filter(|p| valid.contains(p.as_str()))
        .filter(|p| seen.insert(p.as_str()))
        .cloned()
        .collect()
}

/// 校验审批状态：哈希钉扎检查
///
/// 返回 (status, 当前目录哈希)。Pending / HashMismatch 均表示
/// 插件不可按既有审批激活，调用方应要求重新人工批准。
pub fn verify_approval(
    approval: Option<&PluginApproval>,
    dir: &Path,
) -> crate::Result<(ApprovalStatus, String)> {
    let current_hash = compute_dir_hash(dir)?;
    let status = match approval {
        None => ApprovalStatus::Pending,
        Some(appr) => {
            if appr.approved_permissions.is_empty() {
                // 空权限集 = 从未批准任何权限（文档口径：Pending）——把零权限审批
                // 当有效授权会让调用方拿着空集继续（S-09，fail-visible）
                ApprovalStatus::Pending
            } else if appr.content_hash == current_hash {
                ApprovalStatus::Approved
            } else {
                ApprovalStatus::HashMismatch
            }
        }
    };
    Ok((status, current_hash))
}

// 权限词汇漂移锁测试的样本词汇 = 桌面 SDK 词表（process:run 等）——移动形态
// 词表为 SDK 子集（fork 测试样本用 bus/mdns），测试面按形态分叉（票 06 批次 03；
// 移动测试面等价形态见 fork security/approval.rs tests，随批次 03 收口对齐）
#[cfg(all(test, feature = "desktop-assembly"))]
mod tests {
    use super::*;
    use crate::db::Database;
    use std::sync::Arc;
    use std::sync::Mutex;

    async fn test_store() -> PluginApprovalStore {
        let db = Database::new(&std::path::Path::new(":memory:")).unwrap();
        db.init_schema().unwrap();
        PluginApprovalStore::new(Arc::new(PluginStorage::new(Arc::new(Mutex::new(db)))))
    }

    fn write_plugin_dir(dir: &Path, files: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).unwrap();
        for (name, content) in files {
            let p = dir.join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, content).unwrap();
        }
    }

    #[tokio::test]
    async fn test_approve_roundtrip_and_revoke() {
        let store = test_store().await;
        assert!(store.get("com.test.p").await.unwrap().is_none());

        store
            .approve("com.test.p", &["fs:read".to_string()], "abc123", "1.0.0")
            .await
            .unwrap();
        let approval = store.get("com.test.p").await.unwrap().expect("approved");
        assert_eq!(approval.approved_permissions, vec!["fs:read"]);
        assert_eq!(approval.content_hash, "abc123");
        assert_eq!(approval.version, "1.0.0");

        store.revoke("com.test.p").await.unwrap();
        assert!(store.get("com.test.p").await.unwrap().is_none());
    }

    #[test]
    fn test_compute_dir_hash_stable_and_sensitive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("p");
        write_plugin_dir(
            &dir,
            &[
                ("plugin.json", r#"{"id":"com.test.p"}"#),
                ("dist/main.js", "console.log(1)"),
                ("icon.png", "PNG-DATA"),
            ],
        );

        let h1 = compute_dir_hash(&dir).unwrap();
        let h2 = compute_dir_hash(&dir).unwrap();
        assert_eq!(h1, h2, "同内容哈希必须稳定");

        // 修改任意文件 → 哈希变化（钉扎生效）
        std::fs::write(dir.join("dist/main.js"), "console.log(2)").unwrap();
        let h3 = compute_dir_hash(&dir).unwrap();
        assert_ne!(h1, h3, "文件替换后哈希必须变化");

        // 新增文件 → 哈希变化
        std::fs::write(dir.join("extra.bin"), "x").unwrap();
        let h4 = compute_dir_hash(&dir).unwrap();
        assert_ne!(h3, h4, "新增文件后哈希必须变化");
    }

    fn approval_with(perms: &[&str]) -> PluginApproval {
        PluginApproval {
            approved_permissions: perms.iter().map(|p| p.to_string()).collect(),
            content_hash: "h".to_string(),
            version: "1.0.0".to_string(),
            approved_at: "now".to_string(),
        }
    }

    #[test]
    fn test_effective_permissions_gating() {
        let requested = vec![
            "fs:read".to_string(),
            "process:run".to_string(),
            "storage".to_string(),
        ];

        // 未批准：一位都不生效（反例：旧形态恒授 storage）
        let eff = effective_permissions(&requested, None, false);
        assert!(
            eff.is_empty(),
            "无批准记录时生效权限必须为空集，实际: {:?}",
            eff
        );

        // 批准子集：批准 ∩ 请求（正例 + 两条反例）
        let eff = effective_permissions(&requested, Some(&approval_with(&["fs:read"])), false);
        assert!(eff.contains("fs:read"), "批准的位且在请求内 → 生效");
        assert!(
            !eff.contains("process:run"),
            "未批准的 process:run 不得授予"
        );
        assert!(!eff.contains("storage"), "storage 不再有恒授予特例");

        // 批准了请求里没有的权限：不生效（交集语义）
        let eff = effective_permissions(&requested, Some(&approval_with(&["fs:write"])), false);
        assert!(
            eff.is_empty(),
            "批准集与请求集无交集 → 空集，实际: {:?}",
            eff
        );

        // 内置可信：全量（含 storage，因为请求里有）
        let eff = effective_permissions(&requested, None, true);
        assert_eq!(eff.len(), 3);
        assert!(eff.contains("process:run"));
        assert!(eff.contains("storage"));
    }

    /// `known_permissions`：保留词汇内位、丢弃词汇外位、去重且保持声明顺序
    #[test]
    fn test_known_permissions_filters_and_dedupes() {
        let requested = vec![
            "process:run".to_string(),
            "not:a:real:permission".to_string(),
            "process:run".to_string(),
            "".to_string(),
        ];
        assert_eq!(
            known_permissions(&requested),
            vec!["process:run".to_string()],
            "词汇内位按声明顺序保留（去重），装饰词汇被丢弃"
        );
        assert!(known_permissions(&[]).is_empty());
    }

    /// 运行时数据文件（私有库及其 SQLite 边车文件）不参与哈希：
    /// 否则「批准 → 启用（建库）→ 再启用」会被误判为内容被替换
    #[test]
    fn test_compute_dir_hash_ignores_runtime_data_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("p");
        write_plugin_dir(&dir, &[("plugin.json", r#"{"id":"com.test.p"}"#)]);
        let before = compute_dir_hash(&dir).unwrap();

        // 私有库被创建（首次启用）→ 哈希不变
        std::fs::write(dir.join("plugin.db"), b"SQLite format 3").unwrap();
        assert_eq!(
            compute_dir_hash(&dir).unwrap(),
            before,
            "新建 plugin.db 不得改变哈希"
        );

        // WAL / SHM 边车文件增长 → 哈希不变
        std::fs::write(dir.join("plugin.db-wal"), vec![0u8; 32]).unwrap();
        std::fs::write(dir.join("plugin.db-shm"), vec![1u8; 32]).unwrap();
        assert_eq!(
            compute_dir_hash(&dir).unwrap(),
            before,
            "SQLite 边车文件不得改变哈希"
        );

        // 代码面仍受钉扎保护（反例：同目录下的其它新文件会改哈希）
        std::fs::write(dir.join("evil.js"), "// injected").unwrap();
        assert_ne!(
            compute_dir_hash(&dir).unwrap(),
            before,
            "非排除文件名仍必须改变哈希"
        );
    }

    #[test]
    fn test_verify_approval_status() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("p");
        write_plugin_dir(&dir, &[("plugin.json", r#"{"id":"com.test.p"}"#)]);

        // 无审批 → Pending
        let (status, hash) = verify_approval(None, &dir).unwrap();
        assert_eq!(status, ApprovalStatus::Pending);
        assert!(!hash.is_empty());

        // 审批哈希一致 → Approved
        let approval = PluginApproval {
            approved_permissions: vec!["storage".to_string()],
            content_hash: hash.clone(),
            version: "1.0.0".to_string(),
            approved_at: "now".to_string(),
        };
        let (status, _) = verify_approval(Some(&approval), &dir).unwrap();
        assert_eq!(status, ApprovalStatus::Approved);

        // 空权限集 → Pending（S-09：零权限审批不得当作有效授权）
        let empty = PluginApproval {
            approved_permissions: vec![],
            content_hash: hash.clone(),
            version: "1.0.0".to_string(),
            approved_at: "now".to_string(),
        };
        let (status, _) = verify_approval(Some(&empty), &dir).unwrap();
        assert_eq!(status, ApprovalStatus::Pending, "空权限集必须判 Pending");

        // 文件被替换 → HashMismatch
        std::fs::write(
            dir.join("plugin.json"),
            r#"{"id":"com.test.p","name":"evil"}"#,
        )
        .unwrap();
        let (status, _) = verify_approval(Some(&approval), &dir).unwrap();
        assert_eq!(status, ApprovalStatus::HashMismatch);
    }

    /// S-03：插件目录含符号链接 → 哈希计算拒绝（fail-closed；lstat 不跟随）
    #[test]
    fn compute_dir_hash_rejects_symlinks() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tmp.path().join("outside.txt");
        std::fs::write(&outside, "secret").unwrap();
        let dir = tmp.path().join("p");
        write_plugin_dir(&dir, &[("plugin.json", r#"{"id":"com.test.p"}"#)]);
        // 目录内链接指向插件根外文件
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, dir.join("leak.txt")).unwrap();
        #[cfg(windows)]
        {
            // 文件链接需要管理员权限，退化为目录链接（同样触发拒绝）
            std::os::windows::fs::symlink_dir(&outside.parent().unwrap(), dir.join("leak"))
                .unwrap();
        }

        let err = compute_dir_hash(&dir).expect_err("含 symlink 的目录必须被拒绝");
        assert!(
            format!("{err}").contains("symlink"),
            "错误须点名 symlink 原因: {err}"
        );
    }

    /// S-08：排除规则只豁免**根级**私有库——嵌套同名 `assets/plugin.db` 参与哈希
    #[test]
    fn compute_dir_hash_excludes_only_root_level_runtime_db() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("p");
        write_plugin_dir(&dir, &[("plugin.json", r#"{"id":"com.test.p"}"#)]);
        let before = compute_dir_hash(&dir).unwrap();

        // 根级 plugin.db 及其边车：豁免
        std::fs::write(dir.join("plugin.db"), b"sqlite").unwrap();
        std::fs::write(dir.join("plugin.db-wal"), b"wal").unwrap();
        assert_eq!(
            compute_dir_hash(&dir).unwrap(),
            before,
            "根级库与边车必须豁免"
        );

        // 嵌套同名文件：必须改变哈希（过宽匹配会漏掉它）
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("assets").join("plugin.db"), b"nested sqlite").unwrap();
        assert_ne!(
            compute_dir_hash(&dir).unwrap(),
            before,
            "嵌套 plugin.db 必须参与哈希"
        );
    }

    /// S-10：损坏的审批存储必须自愈——读路径删坏行回落空 map，写路径以空 map
    /// 为基线继续（旧形态：损坏后 approve/revoke 永败直到手工清 key）
    #[tokio::test]
    async fn corrupted_approvals_are_reset_not_fatal() {
        let store = test_store().await;
        // 写入一个不是对象形态的坏值（如纯字符串）
        store
            .storage
            .set(
                SYSTEM_PLUGIN_ID,
                APPROVAL_STORAGE_KEY,
                serde_json::json!("corrupted"),
            )
            .await
            .unwrap();

        // 读路径：损坏 → 回落空 map，且坏行被真正清掉
        assert!(
            store.load_all().await.unwrap().is_empty(),
            "损坏数据必须回落空 map"
        );
        assert!(
            store.load_all().await.unwrap().is_empty(),
            "坏行必须真正清掉（否则后续还是失败）"
        );

        // 写路径：损坏 → 以空 map 为基线 approve，不永败
        store
            .approve("com.test.p", &["fs:read".to_string()], "h", "1.0.0")
            .await
            .unwrap();
        let approval = store
            .get("com.test.p")
            .await
            .unwrap()
            .expect("approve 后必须可读");
        assert_eq!(approval.approved_permissions, vec!["fs:read"]);
    }

    /// S-04：并发 approve/revoke 经 `PluginStorage::update` 原子化——交错执行
    /// 不丢任何一方的写入（旧形态 load→save 两次独立操作在并发交错下互相覆盖）
    #[tokio::test]
    async fn concurrent_approve_revoke_do_not_lose_updates() {
        let db = Database::new(&std::path::Path::new(":memory:")).unwrap();
        db.init_schema().unwrap();
        let store =
            PluginApprovalStore::new(Arc::new(PluginStorage::new(Arc::new(Mutex::new(db)))));
        // 两个实例共享同一 storage（生产形态：boot / install / activation 各处
        // 各自 new PluginApprovalStore，共享同一 Arc<PluginStorage>）
        let s1 = PluginApprovalStore::new(store.storage.clone());
        let s2 = PluginApprovalStore::new(store.storage.clone());

        // 并发双 approve：都成功且都可见
        let perms_a = vec!["fs:read".to_string()];
        let perms_b = vec!["fs:read".to_string()];
        let (r1, r2) = tokio::join!(
            s1.approve("com.a", &perms_a, "h1", "1.0.0"),
            s2.approve("com.b", &perms_b, "h2", "1.0.0"),
        );
        r1.unwrap();
        r2.unwrap();
        let map = store.load_all().await.unwrap();
        assert!(
            map.contains_key("com.a") && map.contains_key("com.b"),
            "并发双写不得丢一方"
        );

        // 并发 approve C + revoke A：两者都落盘（旧形态 revoke 的 load 可覆盖 approve）
        let perms_c = vec!["storage".to_string()];
        let (r1, r2) = tokio::join!(
            s1.approve("com.c", &perms_c, "h3", "1.0.0"),
            s2.revoke("com.a"),
        );
        r1.unwrap();
        r2.unwrap();
        let map = store.load_all().await.unwrap();
        assert!(
            map.contains_key("com.c"),
            "approve 结果不得被并发 revoke 覆盖"
        );
        assert!(!map.contains_key("com.a"), "revoke 结果必须生效");
    }
}
