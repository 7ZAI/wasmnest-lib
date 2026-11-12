//! 权限门入参（双端域函数共用的权限词汇载体）
//!
//! 权限词汇**经参数传入**——本 crate 不依赖任何一端 SDK 的权限常量；拒绝文案
//! 由各端自持（历史双份，强行统一属行为变更，走独立裁决）。判定**执行**在各端
//! adapter 的端口实现里（桌面 PermissionManager / 移动 granted 集），本结构只是
//! 把「哪个权限位、哪个原语名、拒绝时说什么」三样随调用带给端口。

/// 权限门入参
#[derive(Clone, Copy)]
pub struct PermissionGate<'a> {
    /// 权限位（各端 SDK 的 `PERMISSION_STORAGE` 等）
    pub permission: &'a str,
    /// 原语名（适配器拒绝 warn 的 `api` 结构化字段）
    pub api: &'a str,
    /// 权限拒绝时返回给 guest 的错误文本（逐字透传，双端自持）
    pub deny_error: &'a str,
}

impl<'a> PermissionGate<'a> {
    /// 端口判定未过时返回拒绝错误（各端 deny_error 逐字透传）
    pub fn deny(&self) -> String {
        self.deny_error.to_string()
    }
}
