//! 音频采集引擎错误类型
//!
//! **为什么自带错误类型**（与 `wasmnest-crypto-engine::error` 同判据）：本 crate 是
//! 中性机制引擎，不含业务语义、不含平台判断，也不该为了拿一个错误信封把宿主框架
//! （`server-base` 的 `AppError` 及其 tauri / rusqlite / sysinfo 传递面）钉进自己的
//! 正常依赖树。语义变体按「调用方能据此行动的事」划分，不是按后端内部错误码划分。
//!
//! **消费方映射责任**：能力域层（`plugin_binding`）把本类型 `.to_string()` 成 WIT
//! `result<_, string>`；各端宿主若要落进自己的信封（`AppError::InvalidInput` 等），
//! 按变体显式映射——映射是显式的、可测的，不是 `From` 的隐式连带。
//!
//! | 变体 | 语义 | 典型触发 |
//! | --- | --- | --- |
//! | [`AudioError::NoInputDevice`] | 系统里没有可用输入设备 | 无麦克风的机器 / 音频服务已起但无输入 |
//! | [`AudioError::DeviceNotFound`] | 点名的设备 id 不在当前清单里 | 设备被拔出 / id 跨重启失效 |
//! | [`AudioError::BackendUnavailable`] | 采集后端本身起不来 | cpal 拿不到 host（PipeWire / PulseAudio 未运行） |
//! | [`AudioError::AccessDenied`] | 操作系统层面拒绝访问麦克风 | Android 未授 `RECORD_AUDIO` / macOS 隐私设置 |
//! | [`AudioError::DeviceBusy`] | 设备被独占（可择时重试） | 独占模式的其它应用 / AAudio EXCLUSIVE |
//! | [`AudioError::FormatUnsupported`] | 协商不出设备能给的格式 | 目标采样率越界 / 设备无输入配置 |
//! | [`AudioError::InvalidConfig`] | 调用方参数非法（本域当场拒，不夹取） | `ringBytes` 为 0 或超宿主上限 |
//! | [`AudioError::QuotaExceeded`] | 每插件在册采集流条数已满 | 第 N+1 条 `open` |
//! | [`AudioError::HandleNotFound`] | 句柄不存在（含已被停用回收） | 拼错的 id / 插件已回收 |
//! | [`AudioError::NotOwner`] | 句柄属主不是调用插件 | 跨插件越权调用 |
//! | [`AudioError::InvalidState`] | 状态机不允许该动作 | 已 `running` 再 `start` / 已停再 `stop` 取流 |
//! | [`AudioError::StreamFailed`] | 运行期设备/流失败 | `play()` 报错、后端流内部故障 |

/// 音频采集引擎错误（语义变体 + 结构化字段）
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AudioError {
    /// 系统里没有可用输入设备
    #[error("no audio input device available")]
    NoInputDevice,

    /// 点名的输入设备不在当前设备清单里
    #[error("audio input device not found: `{id}`")]
    DeviceNotFound {
        /// 调用方传入的设备 id
        id: String,
    },

    /// 采集后端不可达（`backend` 是后端名，`reason` 是后端给的原文）
    #[error("audio backend `{backend}` is unavailable: {reason}")]
    BackendUnavailable {
        /// 后端名（如 `cpal` / `scripted`）
        backend: String,
        /// 后端原文失败原因
        reason: String,
    },

    /// 操作系统拒绝访问麦克风（**不是**能力域的权限门——那是宿主侧的 `audio:*` 判定）
    #[error("audio capture access denied by the platform: {detail}")]
    AccessDenied {
        /// 平台侧原因原文
        detail: String,
    },

    /// 设备被其它使用者占用，择时重试可能成功
    #[error("audio input device is busy: {detail}")]
    DeviceBusy {
        /// 后端给出的占用说明
        detail: String,
    },

    /// 协商不出目标格式
    #[error("unsupported audio format: {detail}")]
    FormatUnsupported {
        /// 缺什么、期望什么
        detail: String,
    },

    /// 调用方参数非法（本域当场拒绝，**不夹取、不降级**）
    #[error("invalid audio capture config: {reason}")]
    InvalidConfig {
        /// 哪个字段、为什么非法
        reason: String,
    },

    /// 每插件在册采集流条数已达上限
    #[error("reached per-plugin audio stream limit ({limit})")]
    QuotaExceeded {
        /// 生效的条数上限
        limit: usize,
    },

    /// 句柄不存在（含插件停用后被回收的情形）
    #[error("audio stream handle not found: `{id}`")]
    HandleNotFound {
        /// 传入的句柄
        id: String,
    },

    /// 句柄属主不是调用插件（属主隔离红线）
    #[error("not owner of audio stream handle `{id}`")]
    NotOwner {
        /// 被访问的句柄
        id: String,
    },

    /// 当前状态不允许该动作（状态机判据，见 `engine::SessionState`）
    #[error("audio stream `{id}` is {state}, the requested action needs {needs}")]
    InvalidState {
        /// 被操作的句柄
        id: String,
        /// 当前状态文本
        state: String,
        /// 该动作要求的状态文本
        needs: String,
    },

    /// 运行期流操作失败（起停设备流本身出错）
    #[error("audio stream operation failed: {detail}")]
    StreamFailed {
        /// 后端原文
        detail: String,
    },
}

impl AudioError {
    /// 该失败是否属于「设备/后端没了」一类（调用方据此决定重开还是重试）
    ///
    /// 判据刻意收窄到**可由调用方重新 `open` 恢复**的三类：设备消失、平台拒绝、占用。
    /// 参数非法、越权、配额满都是「改了调用方自己」的失败，不算设备失效。
    pub fn needs_reopen(&self) -> bool {
        matches!(
            self,
            Self::DeviceNotFound { .. } | Self::AccessDenied { .. } | Self::DeviceBusy { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::AudioError;
    use std::error::Error;

    /// 文案是对外契约面：点名主体（设备 id / 后端名 / 句柄）与判据，不留空泛措辞
    #[test]
    fn messages_name_the_subject() {
        assert_eq!(
            AudioError::DeviceNotFound { id: "hw:2".into() }.to_string(),
            "audio input device not found: `hw:2`"
        );
        assert_eq!(
            AudioError::BackendUnavailable {
                backend: "cpal".into(),
                reason: "no host".into()
            }
            .to_string(),
            "audio backend `cpal` is unavailable: no host"
        );
        assert_eq!(
            AudioError::QuotaExceeded { limit: 2 }.to_string(),
            "reached per-plugin audio stream limit (2)"
        );
        assert_eq!(
            AudioError::NotOwner {
                id: "audio-x".into()
            }
            .to_string(),
            "not owner of audio stream handle `audio-x`"
        );
    }

    /// `std::error::Error` 面成立（库错误类型的硬要求：Debug + Display + Send + Sync + 'static）
    #[test]
    fn is_a_std_error_and_send_sync_static() {
        fn assert_send_sync_static<T: Error + Send + Sync + 'static>() {}
        assert_send_sync_static::<AudioError>();
    }

    /// 设备类失败与调用方类失败必须可区分（上层据此决定重开还是修参数）
    #[test]
    fn needs_reopen_separates_device_from_caller_faults() {
        assert!(AudioError::DeviceNotFound { id: "a".into() }.needs_reopen());
        assert!(AudioError::AccessDenied { detail: "x".into() }.needs_reopen());
        assert!(AudioError::DeviceBusy { detail: "x".into() }.needs_reopen());
        assert!(!AudioError::InvalidConfig { reason: "x".into() }.needs_reopen());
        assert!(!AudioError::QuotaExceeded { limit: 1 }.needs_reopen());
        assert!(!AudioError::NotOwner { id: "a".into() }.needs_reopen());
    }
}
