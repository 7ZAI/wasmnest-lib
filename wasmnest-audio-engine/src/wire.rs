//! host-audio 能力域的 wire 契约词汇（自持副本）
//!
//! ## 为什么自持（能力域脱绑 P4 同款判据）
//!
//! 能力域默认形态 = 纯引擎机制 + 端口抽象（零 WIT / 零 SDK 依赖），任何宿主可直接
//! 引用。本 crate 因此不依赖桌面 SDK 的 wire 词汇，而是自持本域真正会用到的那几项：
//!
//! - [`crate::wire::PERMISSION_AUDIO_CAPTURE`] / [`crate::wire::PERMISSION_AUDIO_IO`]：权限位判据字符串
//!   （真源 = 桌面 SDK 的权限词表；同步口径见 AGENTS §2.3）；
//! - [`crate::wire::HANDLE_PREFIX`]：句柄前缀（`audio-<uuid>`），既是 `FromStr` 校验面也是日志辨认面。
//!
//! **v1 没有 topic / 事件名副本**：`host-audio` 刻意不含事件面（无 push 回调），
//! 状态变化靠 `status` 快照自愈——没有事件名就没有 topic 契约要自持。若将来接线票
//! 增加事件面，届时再按其它能力域的范式补 topic 块并登记漂移锁。
//!
//! 术语说明：权限词汇的真源在 `wasm-core/src/permission.rs`，但本 crate 的默认形态
//! 不能依赖它；这里的常量是**同值副本**，由测试仓 `permission_vocabulary_lock` 与
//! 平台生成物对齐（接线票的登记项，见 AGENTS §2.3）。

/// 权限位：`audio:capture`（`open` / `start` / `stop` / `close`——占用麦克风的高风险面）
pub const PERMISSION_AUDIO_CAPTURE: &str = "audio:capture";

/// 权限位：`audio:io`（`list-devices` / `status` / `ring-fetch` / `level`——数据与元数据面）
pub const PERMISSION_AUDIO_IO: &str = "audio:io";

/// 句柄前缀（`audio-<uuid>`）
///
/// 前缀是**契约面**：宿主侧日志与本域句柄解析都按它辨认，改名即破坏性变更。
pub const HANDLE_PREFIX: &str = "audio-";

#[cfg(test)]
mod tests {
    use super::*;

    /// 权限词汇是跨仓同值副本：拼写必须与 WIT 文档与平台词表逐字一致
    #[test]
    fn permission_vocabulary_shape() {
        assert_eq!(PERMISSION_AUDIO_CAPTURE, "audio:capture");
        assert_eq!(PERMISSION_AUDIO_IO, "audio:io");
        // `audio:` 是本域命名空间；`:` 不得出现在句柄前缀里（句柄是另一套形状）
        for permission in [PERMISSION_AUDIO_CAPTURE, PERMISSION_AUDIO_IO] {
            assert!(permission.starts_with("audio:"));
        }
        assert_eq!(HANDLE_PREFIX, "audio-");
        assert!(!HANDLE_PREFIX.contains(':'));
    }
}
