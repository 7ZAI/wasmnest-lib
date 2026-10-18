//! host-http 能力域的 wire 契约词汇（自持副本）
//!
//! ## 为什么自持（能力域脱绑 P1，2026-10-08）
//!
//! 能力域默认形态 = 纯引擎机制 + 端口抽象（零 WIT 依赖），任何宿主（桌面 / 移动端 /
//! 无头测试宿主）可直接引用。本 crate 原先直连桌面 SDK（`wasmnest-plugin-api`）
//! 的两个 wire 词汇因此改为**本域自持副本**：
//!
//! - [`PERMISSION_NETWORK_HTTP`]：权限位判据字符串（宿主安全闸门的 wire 契约）；
//! - [`EndpointAuth`]：端点认证档位（manifest / 线协议取值，带仲裁逻辑）。
//!
//! 两者都是纯 wire 契约，不携带宿主机制——移进本 crate 不改变任何依赖方向。
//! 桌面 SDK 原常量**不删除**（另有消费方：wasm-core 的 host_api 总线 / WIT 契约面），
//! 副本与原版逐字一致由平台仓漂移锁钉死（三仓拆分 L2/E2b 票 08 迁出本 crate：
//! `cross-end-tests/tests/wire_drift_locks.rs`）：任一侧漂移即红。
//!
//! 注意：本模块定义块的注释与桌面 SDK **逐字一致**（漂移锁按文本块比对），
//! 本地说明一律写在本模块文档与下方分隔注释里，不要改动定义块内注释。

use serde::{Deserialize, Serialize};

/// 权限位：`network:http`（与桌面 SDK `wasmnest_plugin_api::permission` 逐字一致）
///
/// 权限门的判据字符串是宿主与能力域之间的 wire 契约；漂移会让插件声明面与
/// 判定面脱节（插件声明 `network:http` 却匹配不上宿主权限位），故由漂移锁
/// 比对 SDK 原版，改值必须双侧同步。
pub const PERMISSION_NETWORK_HTTP: &str = "network:http";

// ==================== 以下 EndpointAuth 定义块与桌面 SDK 逐字一致 ====================
// （漂移锁提取「行首为三个斜杠 + 空格 + 端点认证档位」至「行首为三个斜杠 + 空格 +
// 一条 HTTP 端点声明」之间的文本块比对，不要改动块内任何字符——含注释。
// 本地说明请写在本分隔注释前后，且不要在本文件其它地方原样引用这两个标记文本。）

/// 端点认证档位（WS 端点注册与 HTTP 端点声明共用这一张词汇表）
///
/// 只有 `none | jwt` 两档。**缺省档位由各传输面自己决定**，不在这里表达：
/// WS 首消息认证的历史缺省是 `none`（插件自管认证），HTTP 声明缺省是 `jwt`
/// （票 08 裁决 1「未声明即最严」）。未知取值一律 Err，绝不静默降级为较宽档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointAuth {
    /// 免凭证：宿主不校验 JWT（环回 hook、配对 / QR 这类「拿 token 之前」的入口）
    None,
    /// 必须通过宿主 JWT 验签
    Jwt,
}

impl EndpointAuth {
    /// manifest / 线协议取值
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Jwt => "jwt",
        }
    }

    /// 解析声明值：缺省 / 空串 → `default`（由调用方给档位）；未知取值 → Err
    ///
    /// 大小写敏感——与 WS 注册面既有行为一致，`"JWT"` 视为拼写错误而非合法档位。
    pub fn parse_with(raw: Option<&str>, default: Self) -> Result<Self, String> {
        match raw.map(str::trim).unwrap_or("") {
            "" => Ok(default),
            "none" => Ok(Self::None),
            "jwt" => Ok(Self::Jwt),
            other => Err(format!(
                "unknown auth '{}' (expected \"none\" or \"jwt\")",
                other
            )),
        }
    }
}

// 一条 HTTP 端点声明
// （上面这行是与桌面 SDK 下一条注释的共享起笔文本，漂移锁用作 EndpointAuth
// 提取块的结束标记；本 crate 不复制 HttpEndpointContribution 定义。
// 非 doc 注释：本文件末尾无被文档化的项，`///` 会成悬空 doc 编译错误；
// 锁已迁平台仓 cross-end-tests/tests/wire_drift_locks.rs，本行即其本地结束标记。）
