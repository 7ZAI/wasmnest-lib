//! 本能力域的契约词汇自持副本（权限位 / 句柄前缀）
//!
//! v1 无事件面，故无 topic 副本。真源约束：
//! - 权限位必须与平台双端权限词汇表逐字一致（`stt:infer` / `stt:model`）；
//! - 句柄前缀只属于本域（`stt-` / `stt-job-`），宿主与插件都不解析其内部结构。

/// 推理权限：会话 / 任务 / 模型清单（消耗推理资源）
pub const PERMISSION_STT_INFER: &str = "stt:infer";

/// 模型权限：下载 / 删除 / 本地导入（写宿主共享资产）
pub const PERMISSION_STT_MODEL: &str = "stt:model";

/// 会话句柄前缀
pub const SESSION_HANDLE_PREFIX: &str = "stt-";

/// 任务句柄前缀
pub const JOB_HANDLE_PREFIX: &str = "stt-job-";

/// 本域全部权限位（宿主描述符与权限表一致性核对用）
pub const PERMISSIONS: &[&str] = &[PERMISSION_STT_INFER, PERMISSION_STT_MODEL];

/// 是否形如本域会话句柄（只做前缀检查；真实性由会话表回答）
pub fn is_session_handle(value: &str) -> bool {
    value.starts_with(SESSION_HANDLE_PREFIX)
        && !value.starts_with(JOB_HANDLE_PREFIX)
        && value.len() > SESSION_HANDLE_PREFIX.len()
}

/// 是否形如本域任务句柄（只做前缀检查；真实性由任务表回答）
pub fn is_job_handle(value: &str) -> bool {
    value.starts_with(JOB_HANDLE_PREFIX) && value.len() > JOB_HANDLE_PREFIX.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 权限词汇与宿主描述符逐字一致（宿主白名单校验的本地镜像）
    #[test]
    fn permissions_match_module_descriptor() {
        assert_eq!(
            PERMISSIONS,
            crate::plugin_binding::MODULE_PERMISSIONS,
            "wire 权限副本与宿主描述符漂移"
        );
    }

    /// 句柄前缀不互相吞并（`stt-job-` 也以 `stt-` 开头，但语义必须分开）
    #[test]
    fn handles_are_disjoint_by_prefix() {
        assert!(is_session_handle("stt-123"));
        assert!(is_job_handle("stt-job-123"));
        assert!(!is_session_handle("stt-job-123"));
        assert!(!is_job_handle("stt-123"));
    }
}
