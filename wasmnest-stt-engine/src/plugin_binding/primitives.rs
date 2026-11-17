//! host-stt 域原语（机制层）
//!
//! 每条原语 = 权限门 → 句柄形状 → 引擎调用 → 错误转写。这里**没有** WIT 类型
//! （WIT 记录的映射在 `plugin_binding.rs` 的 Host 实现里），于是这些原语能在没有
//! `common-host` feature 的构建里被完整测试。
//!
//! ## 权限两域
//!
//! | 原语 | 权限 | 理由 |
//! | --- | --- | --- |
//! | 会话 / 任务 / `models-list` / `model-status` | `stt:infer` | 消耗推理资源或读取推理状态 |
//! | `model-download` / `model-remove` / `model-import` | `stt:model` | 写宿主共享模型资产 |
//!
//! 权限先于参数：未授权时连句柄/参数错误都不回显（避免把解析行为当探测面）。

use std::path::Path;
use std::sync::Arc;

use crate::error::SttError;
use crate::hub::{JobResultView, JobStatusView, SttHub};
use crate::model_store::{DownloadView, ModelView};
use crate::plugin_binding::ports::SttPorts;
use crate::wire::{is_job_handle, is_session_handle, PERMISSION_STT_INFER, PERMISSION_STT_MODEL};

fn denied(permission: &str) -> String {
    format!("permission denied: {permission}")
}

fn check_infer(ports: &Arc<dyn SttPorts>, plugin_id: &str, api: &str) -> Result<(), String> {
    if ports.check_permission(plugin_id, PERMISSION_STT_INFER, api) {
        Ok(())
    } else {
        Err(denied(PERMISSION_STT_INFER))
    }
}

fn check_model(ports: &Arc<dyn SttPorts>, plugin_id: &str, api: &str) -> Result<(), String> {
    if ports.check_permission(plugin_id, PERMISSION_STT_MODEL, api) {
        Ok(())
    } else {
        Err(denied(PERMISSION_STT_MODEL))
    }
}

fn session_handle(value: &str) -> Result<&str, String> {
    if is_session_handle(value) {
        Ok(value)
    } else {
        Err(format!("invalid session handle: {value}"))
    }
}

fn job_handle(value: &str) -> Result<&str, String> {
    if is_job_handle(value) {
        Ok(value)
    } else {
        Err(format!("invalid job handle: {value}"))
    }
}

/// 打开会话
pub fn stt_open_session(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    options_json: &str,
) -> Result<String, String> {
    check_infer(ports, plugin_id, "host_stt_open_session")?;
    hub.open_session(plugin_id, options_json)
        .map_err(|err| err.to_string())
}

/// 追加 PCM
pub fn stt_append(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    session_id: &str,
    pcm_bytes: &[u8],
) -> Result<u64, String> {
    check_infer(ports, plugin_id, "host_stt_append")?;
    let session_id = session_handle(session_id)?;
    hub.append(plugin_id, session_id, pcm_bytes)
        .map_err(|err| err.to_string())
}

/// 结束会话并提交任务
pub fn stt_finalize(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &Arc<SttHub>,
    session_id: &str,
) -> Result<String, String> {
    check_infer(ports, plugin_id, "host_stt_finalize")?;
    let session_id = session_handle(session_id)?;
    hub.finalize(plugin_id, session_id)
        .map_err(|err| err.to_string())
}

/// 放弃会话
pub fn stt_abort_session(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    session_id: &str,
) -> Result<bool, String> {
    check_infer(ports, plugin_id, "host_stt_abort_session")?;
    let session_id = session_handle(session_id)?;
    hub.abort_session(plugin_id, session_id)
        .map_err(|err| err.to_string())
}

/// 任务状态
pub fn stt_job_status(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    job_id: &str,
) -> Result<String, String> {
    check_infer(ports, plugin_id, "host_stt_job_status")?;
    let job_id = job_handle(job_id)?;
    let status: JobStatusView = hub
        .job_status(plugin_id, job_id)
        .map_err(|err| err.to_string())?;
    serde_json::to_string(&status).map_err(|err| format!("stt job status: serialize failed: {err}"))
}

/// 任务结果
pub fn stt_job_result(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    job_id: &str,
) -> Result<String, String> {
    check_infer(ports, plugin_id, "host_stt_job_result")?;
    let job_id = job_handle(job_id)?;
    let result: JobResultView = hub
        .job_result(plugin_id, job_id)
        .map_err(|err| err.to_string())?;
    serde_json::to_string(&result).map_err(|err| format!("stt job result: serialize failed: {err}"))
}

/// 取消任务
pub fn stt_job_cancel(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    job_id: &str,
) -> Result<bool, String> {
    check_infer(ports, plugin_id, "host_stt_job_cancel")?;
    let job_id = job_handle(job_id)?;
    hub.job_cancel(plugin_id, job_id)
        .map_err(|err| err.to_string())
}

/// 模型清单
pub fn stt_models_list(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
) -> Result<Vec<ModelView>, String> {
    check_infer(ports, plugin_id, "host_stt_models_list")?;
    Ok(hub.models_list())
}

/// 开始下载模型
pub fn stt_model_download(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &Arc<SttHub>,
    model_id: &str,
) -> Result<String, String> {
    check_model(ports, plugin_id, "host_stt_model_download")?;
    hub.download_model(model_id).map_err(|err| err.to_string())
}

/// 模型下载状态
pub fn stt_model_status(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    model_id: &str,
) -> Result<DownloadView, String> {
    check_infer(ports, plugin_id, "host_stt_model_status")?;
    hub.model_status(model_id).map_err(|err| err.to_string())
}

/// 删除模型
pub fn stt_model_remove(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    model_id: &str,
) -> Result<bool, String> {
    check_model(ports, plugin_id, "host_stt_model_remove")?;
    hub.remove_model(model_id).map_err(|err| err.to_string())
}

/// 导入本地模型
pub fn stt_model_import(
    ports: &Arc<dyn SttPorts>,
    plugin_id: &str,
    hub: &SttHub,
    model_id: &str,
    path: &str,
) -> Result<bool, String> {
    check_model(ports, plugin_id, "host_stt_model_import")?;
    let path = Path::new(path);
    ports.authorize_import_path(plugin_id, path)?;
    hub.import_model(model_id, path)
        .map_err(|err| err.to_string())
}

/// 把引擎错误转成 WIT 错误串（保留分类前缀，便于宿主日志与调用方区分）
pub fn error_string(err: SttError) -> String {
    format!("{}: {}", err.kind(), err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::hub::SessionLimits;
    use crate::model_store::ModelStore;
    use std::path::PathBuf;

    struct Ports {
        allow: bool,
        import_ok: bool,
    }

    impl SttPorts for Ports {
        fn check_permission(&self, _: &str, _: &str, _: &str) -> bool {
            self.allow
        }

        fn authorize_import_path(&self, _: &str, _: &Path) -> Result<(), String> {
            if self.import_ok {
                Ok(())
            } else {
                Err("path is not authorized".to_string())
            }
        }
    }

    fn hub() -> Arc<SttHub> {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("wasmnest-stt-prim-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(ModelStore::new(dir.join("models"), None, None).unwrap());
        Arc::new(SttHub::new(
            Arc::new(MockBackend::new("x")),
            store,
            SessionLimits::default(),
        ))
    }

    #[test]
    fn denies_infer_before_touching_engine() {
        let ports: Arc<dyn SttPorts> = Arc::new(Ports {
            allow: false,
            import_ok: false,
        });
        let hub = hub();
        let err = stt_open_session(&ports, "p1", &hub, "{}").unwrap_err();
        assert_eq!(err, "permission denied: stt:infer");
    }

    #[test]
    fn denies_model_ops_with_model_permission() {
        let ports: Arc<dyn SttPorts> = Arc::new(Ports {
            allow: false,
            import_ok: false,
        });
        let hub = hub();
        let err = stt_model_download(&ports, "p1", &hub, "small").unwrap_err();
        assert_eq!(err, "permission denied: stt:model");
    }

    #[test]
    fn import_path_is_authorized_before_copy() {
        let ports: Arc<dyn SttPorts> = Arc::new(Ports {
            allow: true,
            import_ok: false,
        });
        let hub = hub();
        let err = stt_model_import(&ports, "p1", &hub, "small", "/tmp/whatever.bin").unwrap_err();
        assert_eq!(err, "path is not authorized");
    }

    #[test]
    fn session_handle_shape_is_checked() {
        let ports: Arc<dyn SttPorts> = Arc::new(Ports {
            allow: true,
            import_ok: true,
        });
        let hub = hub();
        let err = stt_append(&ports, "p1", &hub, "not-a-session", &[0, 0]).unwrap_err();
        assert!(err.contains("invalid session handle"));
    }

    #[test]
    fn infer_ops_succeed_with_permission() {
        let ports: Arc<dyn SttPorts> = Arc::new(Ports {
            allow: true,
            import_ok: true,
        });
        let hub = hub();
        let session = stt_open_session(&ports, "p1", &hub, r#"{"modelId":"small"}"#).unwrap();
        assert!(session.starts_with("stt-"));
        let total = stt_append(&ports, "p1", &hub, &session, &[0, 0]).unwrap();
        assert_eq!(total, 2);
        assert!(stt_abort_session(&ports, "p1", &hub, &session).unwrap());
    }
}
