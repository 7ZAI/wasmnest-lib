//! `host-fs` 双端交集 6 原语的**共享实现核**（wasm-core-mobile-purity 票 05）
//!
//! 自移动 wasm-core `runtime/bare/host_impl/fs.rs` 上移。**桌面侧不在本次抽范围内**
//! （其 fs 实现体仍耦合 WSL 桥 / 任务单元两个消费者，抽取另票）——本模块不取代它，
//! 只把**双端共同的那一段**收敛成机制单点，后续桌面改用与否不影响本层成立。
//!
//! ## 抽取得失判据（为什么这一段可以抽）
//!
//! 6 原语的机制面是各端逐字相同的三件事：
//! 1. **权限门**：`fs:read` / `fs:write` 位缺失即拒（词汇经 [`crate::gate::PermissionGate`] 入参）；
//! 2. **访问闸门裁决**：紧接权限门之后的路径授权判定（白名单 / 弹窗 / 持久授权
//!    真源留宿主，本层只见 bool）；`copy` 要 Read + Write 两次，`request-auth` 走批量；
//! 3. **路径形状守卫**：写自动建父目录、删除幂等（不存在视为成功）。
//!
//! **平台差**只剩一条：删除在 Android 走 MediaStore/SAF 通道，其余平台走标准
//! `std::fs`——经 [`FsHostPorts::platform_delete`] 注入，本层不认平台名词。
//!
//! ## 顺序与形状纪律（看得见的语义，不许「顺手整理」）
//!
//! - 权限门恒在访问闸门**之前**：未声明权限的插件不得触达授权弹窗（探多少次也不弹）；
//! - `exists` 的 debug 日志带 `exists` 结构化字段（AGENTS §8：字段不拼进消息串）；
//! - `request_auth` 空 `paths` 恒 `Ok(true)`：「无需授权」与「授权失败」是两件事，
//!   合并会让 guest 拿不到 core ABI 需要的三态；
//! - 错误文本逐字保留（guest 可见文案不自造：`permission denied: fs:*` /
//!   `access denied by fs_auth: <path>` / `failed to create parent directory: ` …）。
//!
//! ## 依赖纪律
//!
//! 只依赖 std + serde_json + tracing（本 crate 头注 §边界判据，由
//! `tests/boundary_lock.rs` 钉住）。**无 tokio**：异步驱动由各端 adapter 在本层
//! 之外完成——本层只见同步 bool。

use std::path::Path;

pub use crate::gate::PermissionGate;

// ==================== 端口 ====================

/// 文件系统访问操作类别
///
/// 双端各自的 `FsAuthOp`（平行的代数）同名不同源，本枚举是共享核的自持词汇——
/// 各端 adapter 在端口实现里做一次映射，映射理由写在 adapter 头注里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    /// 读（`exists` / `request-auth` 也按读裁决：探查路径元数据与读同一授权面）
    Read,
    /// 写（含删除：覆盖 / 移除同属写授权面）
    Write,
}

/// `host-fs` 的宿主端口（实现层只认端口，不认任何一端的宿主类型）
///
/// dyn 兼容：域函数收 `&dyn FsHostPorts`，实现方 = 各端 adapter；实现应当轻——
/// 每条原语调用都要经它。
pub trait FsHostPorts: Send + Sync {
    /// 权限判定（`fs:read` / `fs:write`）
    ///
    /// 返回 `false` 时**实现方**必须已按 AGENTS §8 落拒绝 warn（结构化字段
    /// `plugin_id` / `permission` / `api`），本层不重复落日志。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 单路径访问裁决（路径白名单 / 弹窗 / 持久授权的真源在宿主）
    fn check_access(&self, plugin_id: &str, path: &str, op: FsOp) -> bool;

    /// 批量路径访问裁决（`request-auth` 面；「全部同意」语义）
    fn check_access_batch(&self, plugin_id: &str, paths: &[String], op: FsOp) -> bool;

    /// 平台专属删除：`Some(result)` = 删除已由平台通道完成（如 Android
    /// MediaStore/SAF 的 Kotlin 桥）；`None` = 本平台走标准 `std::fs::remove_file`
    fn platform_delete(&self, path: &str) -> Option<Result<(), String>>;
}

// ==================== 原语 ====================

/// 读取文件（不存在返回 `Ok(None)`——SDK 契约里「缺失」是空值而非错误）
pub fn fs_read(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    path: &str,
    gate: &PermissionGate<'_>,
) -> Result<Option<String>, String> {
    require(ports, plugin_id, gate)?;
    require_access(ports, plugin_id, path, FsOp::Read)?;
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("file read failed: {}", e)),
    }
}

/// 写入文件（自动创建父目录）
pub fn fs_write(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    path: &str,
    data: &str,
    gate: &PermissionGate<'_>,
) -> Result<(), String> {
    require(ports, plugin_id, gate)?;
    require_access(ports, plugin_id, path, FsOp::Write)?;
    ensure_parent_dir(path)?;
    std::fs::write(path, data).map_err(|e| format!("file write failed: {}", e))
}

/// 复制文件（需读+写权限；源与目标分别裁决，目标父目录自动创建）
///
/// 两个门分开传入，而**拒绝文案由各端自持**：移动侧历史上就是一条合成文案
/// 合成文案 `permission denied: fs:read+fs:write`（缺任一位都返回它），调用方把
/// 两个 gate 的 `deny_error` 都填成同一条即可复刻；本层不替各端拆词。
pub fn fs_copy(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    src: &str,
    dst: &str,
    read_gate: &PermissionGate<'_>,
    write_gate: &PermissionGate<'_>,
) -> Result<(), String> {
    require(ports, plugin_id, read_gate)?;
    require(ports, plugin_id, write_gate)?;
    if !ports.check_access(plugin_id, src, FsOp::Read) {
        return Err(deny_access(&format!("{} -> {}", src, dst)));
    }
    if !ports.check_access(plugin_id, dst, FsOp::Write) {
        return Err(deny_access(&format!("{} -> {}", src, dst)));
    }
    ensure_parent_dir(dst)?;
    std::fs::copy(src, dst)
        .map(|_| ())
        .map_err(|e| format!("file copy failed: {}", e))
}

/// 检查文件是否存在
pub fn fs_exists(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    path: &str,
    gate: &PermissionGate<'_>,
) -> Result<bool, String> {
    require(ports, plugin_id, gate)?;
    require_access(ports, plugin_id, path, FsOp::Read)?;
    let exists = Path::new(path).exists();
    tracing::debug!(plugin_id = %plugin_id, path = %path, exists = %exists, "host_fs_exists");
    Ok(exists)
}

/// 批量请求目录授权（`paths-json` = JSON 字符串数组）
///
/// 用户拒绝 / 超时 = `Ok(false)`，与「失败」（`Err`）严格区分——合并会让 guest
/// 分不清「不同意」与「弹不出来」。
pub fn fs_request_auth(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    paths_json: &str,
    gate: &PermissionGate<'_>,
) -> Result<bool, String> {
    require(ports, plugin_id, gate)?;
    let paths: Vec<String> =
        serde_json::from_str(paths_json).map_err(|e| format!("invalid paths json: {}", e))?;
    if paths.is_empty() {
        return Ok(true);
    }
    Ok(ports.check_access_batch(plugin_id, &paths, FsOp::Read))
}

/// 删除文件（不存在视为成功；平台通道优先，无通道退回标准删除）
pub fn fs_delete(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    path: &str,
    gate: &PermissionGate<'_>,
) -> Result<(), String> {
    require(ports, plugin_id, gate)?;
    require_access(ports, plugin_id, path, FsOp::Write)?;
    // 幂等：不存在视为成功（双端共同语义，不是「查不到就放行」的弱化）
    if !Path::new(path).exists() {
        return Ok(());
    }
    match ports.platform_delete(path) {
        Some(result) => result.map_err(|e| format!("android delete failed: {}", e)),
        None => std::fs::remove_file(path).map_err(|e| format!("file delete failed: {}", e)),
    }
}

// ==================== 内部守卫 ====================

/// 权限门（拒绝时用各端传入的文案逐字返回）
fn require(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    gate: &PermissionGate<'_>,
) -> Result<(), String> {
    if ports.check_permission(plugin_id, gate.permission, gate.api) {
        Ok(())
    } else {
        Err(gate.deny_error.to_string())
    }
}

/// 路径访问裁决
fn require_access(
    ports: &dyn FsHostPorts,
    plugin_id: &str,
    path: &str,
    op: FsOp,
) -> Result<(), String> {
    if ports.check_access(plugin_id, path, op) {
        Ok(())
    } else {
        Err(deny_access(path))
    }
}

/// 访问被拒的统一文案（`copy` 带 `src -> dst` 形状）
fn deny_access(path: &str) -> String {
    format!("access denied by fs_auth: {}", path)
}

/// 自动创建父目录（写 / 复制的兜底形状守卫）
fn ensure_parent_dir(path: &str) -> Result<(), String> {
    let Some(parent) = Path::new(path).parent() else {
        return Ok(());
    };
    if parent.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create parent directory: {}", e))
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 假端口：权限按 `granted` 集判定；路径按前缀裁决；删除记一笔并真删（模拟平台通道）
    struct FakePorts {
        granted: Vec<String>,
        allowed_prefix: String,
        platform_deletes: Mutex<Vec<String>>,
    }

    impl FakePorts {
        fn new(perms: &[&str], prefix: &str) -> Self {
            Self {
                granted: perms.iter().map(|s| s.to_string()).collect(),
                allowed_prefix: prefix.to_string(),
                platform_deletes: Mutex::new(Vec::new()),
            }
        }
    }

    impl FsHostPorts for FakePorts {
        fn check_permission(&self, _plugin_id: &str, permission: &str, _api: &str) -> bool {
            self.granted.iter().any(|p| p == permission)
        }

        fn check_access(&self, _plugin_id: &str, path: &str, _op: FsOp) -> bool {
            path.starts_with(&self.allowed_prefix)
        }

        fn check_access_batch(&self, _plugin_id: &str, paths: &[String], _op: FsOp) -> bool {
            paths.iter().all(|p| p.starts_with(&self.allowed_prefix))
        }

        fn platform_delete(&self, path: &str) -> Option<Result<(), String>> {
            self.platform_deletes.lock().unwrap().push(path.to_string());
            Some(std::fs::remove_file(path).map_err(|e| e.to_string()))
        }
    }

    const READ: PermissionGate<'static> = PermissionGate {
        permission: "fs:read",
        api: "host_fs_read",
        deny_error: "permission denied: fs:read",
    };
    const WRITE: PermissionGate<'static> = PermissionGate {
        permission: "fs:write",
        api: "host_fs_write",
        deny_error: "permission denied: fs:write",
    };

    /// 临时目录（靠进程内自增计数器 + pid 前缀避免并发用例互相踩）
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("fs-core-{tag}-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 缺失文件 = `Ok(None)`（不得降级为 Err——SDK 契约里这俩是两件事）
    #[test]
    fn read_missing_file_is_none_not_error() {
        let dir = tmp_dir("read");
        let ports = FakePorts::new(&["fs:read"], dir.to_str().unwrap());
        let missing = dir.join("nope.txt");
        assert_eq!(
            fs_read(&ports, "p1", missing.to_str().unwrap(), &READ).unwrap(),
            None
        );
    }

    /// 写入 → 读回往返；写侧自动建父目录
    #[test]
    fn write_read_roundtrip_with_auto_parent_dir() {
        let dir = tmp_dir("rw");
        let ports = FakePorts::new(&["fs:read", "fs:write"], dir.to_str().unwrap());
        let target = dir.join("nested/deep/a.txt");
        fs_write(&ports, "p1", target.to_str().unwrap(), "hello", &WRITE).unwrap();
        assert_eq!(
            fs_read(&ports, "p1", target.to_str().unwrap(), &READ).unwrap(),
            Some("hello".to_string())
        );
        assert!(fs_exists(&ports, "p1", target.to_str().unwrap(), &READ).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 权限门先于访问闸门：未授权时不触达路径裁决（缺两个位时 Synthetic 文案来自各端）
    #[test]
    fn permission_gate_precedes_access_gate() {
        let ports = FakePorts::new(&[], "/tmp");
        assert_eq!(
            fs_exists(&ports, "p1", "/tmp/x", &READ).unwrap_err(),
            "permission denied: fs:read"
        );
        assert_eq!(
            fs_write(&ports, "p1", "/tmp/x", "d", &WRITE).unwrap_err(),
            "permission denied: fs:write"
        );
    }

    /// 访问裁决拒绝文案逐字稳定（`access denied by fs_auth: <path>`）
    #[test]
    fn access_denied_has_stable_text() {
        let ports = FakePorts::new(&["fs:read"], "/allowed-only");
        let err = fs_read(&ports, "p1", "/tmp/secret", &READ).unwrap_err();
        assert_eq!(err, "access denied by fs_auth: /tmp/secret");
    }

    /// copy：缺任一位即拒；双位齐了还要源/目标分别过访问裁决
    #[test]
    fn copy_requires_both_permissions_and_both_paths() {
        let dir = tmp_dir("copy");
        let root = dir.to_str().unwrap().to_string();
        let src = dir.join("src.txt");
        let dst = dir.join("sub/dst.txt");
        std::fs::write(&src, "payload").unwrap();

        let read_only = FakePorts::new(&["fs:read"], &root);
        let err = fs_copy(
            &read_only,
            "p1",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            &READ,
            &WRITE,
        )
        .unwrap_err();
        assert_eq!(err, "permission denied: fs:write");

        // 双权限但目标不在允许前缀（background 前缀只含 src.txt 的父路径）
        let narrow = FakePorts::new(&["fs:read", "fs:write"], src.to_str().unwrap());
        let err = fs_copy(
            &narrow,
            "p1",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            &READ,
            &WRITE,
        )
        .unwrap_err();
        assert!(err.starts_with("access denied by fs_auth: "), "got: {err}");

        let both = FakePorts::new(&["fs:read", "fs:write"], &root);
        fs_copy(
            &both,
            "p1",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            &READ,
            &WRITE,
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `request-auth`：空表恒 true；批量是「全部同意」；非法 JSON 显式拒绝
    #[test]
    fn request_auth_empty_is_true_batch_is_all_or_nothing() {
        let ports = FakePorts::new(&["fs:read"], "/allowed");
        assert!(fs_request_auth(&ports, "p1", "[]", &READ).unwrap());
        assert!(fs_request_auth(&ports, "p1", r#"["/allowed/a", "/allowed/b"]"#, &READ).unwrap());
        let mixed = fs_request_auth(&ports, "p1", r#"["/allowed/a", "/nope"]"#, &READ).unwrap();
        assert!(!mixed, "批量裁决必须是「全部同意」语义");
        let bad = fs_request_auth(&ports, "p1", "not-json", &READ).unwrap_err();
        assert!(bad.starts_with("invalid paths json: "), "got: {bad}");
    }

    /// 删除：走平台通道（优先）+ 幂等（路径已消失直接成功）
    #[test]
    fn delete_prefers_platform_channel_and_is_idempotent() {
        let dir = tmp_dir("del");
        let ports = FakePorts::new(&["fs:write"], dir.to_str().unwrap());
        let file = dir.join("a.txt");
        std::fs::write(&file, "x").unwrap();

        fs_delete(&ports, "p1", file.to_str().unwrap(), &WRITE).unwrap();
        assert_eq!(
            ports.platform_deletes.lock().unwrap().len(),
            1,
            "删除必须走平台通道"
        );
        // 通道已删 ⇒ 幂等再删一次（path 不存在）直接成功，不再二次进通道
        fs_delete(&ports, "p1", file.to_str().unwrap(), &WRITE).unwrap();
        assert_eq!(ports.platform_deletes.lock().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
