//! 自播面共享契约：mDNS 服务类型常量 + 广播配置 + 自持错误类型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// mDNS 服务类型
pub const SERVICE_TYPE: &str = "_wasmnest._tcp.local.";

/// mDNS 广播错误（本 crate 自持，不反向依赖宿主 `AppError`——机制 crate 的依赖
/// 锁只允许 `wasmnest-host-kit`，错误类型随机制同迁)
#[derive(Debug)]
pub enum AdvertiserError {
    /// 输入校验失败（空服务名 / 端口 0 / 超长实例名）
    InvalidInput(String),
    /// daemon 创建 / 注册 / 注销等运行期失败
    Internal(String),
}

impl fmt::Display for AdvertiserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvertiserError::InvalidInput(msg) | AdvertiserError::Internal(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

impl std::error::Error for AdvertiserError {}

/// 本 crate 广播侧统一结果类型
pub type AdvertiserResult<T> = std::result::Result<T, AdvertiserError>;

/// mDNS 广播配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvertiseConfig {
    /// 实例名（如 "WasmNest-DESKTOP-X1"）
    pub service_name: String,
    /// 服务端口
    pub port: u16,
    /// TXT 记录键值对
    pub txt_records: HashMap<String, String>,
}

impl AdvertiseConfig {
    /// 输入校验（§8 输入校验在 Rust 端）：空服务名 / 端口 0 / 实例名超长均拒绝
    pub fn validate(&self) -> AdvertiserResult<()> {
        if self.service_name.trim().is_empty() {
            return Err(AdvertiserError::InvalidInput(
                "mDNS 服务名不能为空".to_string(),
            ));
        }
        if self.port == 0 {
            return Err(AdvertiserError::InvalidInput(
                "mDNS 服务端口不能为 0".to_string(),
            ));
        }
        // RFC 6763：实例名 ≤ 63 字节（单个 label），此处按宽松上限防异常输入
        if self.service_name.len() > 255 {
            return Err(AdvertiserError::InvalidInput(format!(
                "mDNS 实例名超过 255 字节: {}",
                self.service_name.len()
            )));
        }
        Ok(())
    }
}
