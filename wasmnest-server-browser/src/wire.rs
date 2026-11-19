//! host-browser 能力域的 wire 契约词汇（自持副本）
//!
//! 权限位判据字符串是宿主与能力域之间的 wire 契约：插件声明面按它授权，
//! 能力域按同一字面量判定，两侧不相等即「声明了却匹配不上」。
//!
//! 权限词汇真源在上层机制 crate 的权限表；本 crate 默认形态（纯引擎）不依赖
//! 机制内核，故持有**同值副本**。改值必须双侧同步，否则权限门恒拒绝。

/// 权限位：`network:browser`
///
/// 与 `network:http` 不互相隐含：静态 HTTP 走前者，需要执行页面脚本或读取
/// DOM 才走本位。本位是更高风险的出站面（默认连私网都不去）。
pub const PERMISSION_NETWORK_BROWSER: &str = "network:browser";

#[cfg(test)]
mod tests {
    /// 副本字面量固定（改值必须同步权限真源与 manifest 映射）
    #[test]
    fn permission_literal_is_stable() {
        assert_eq!(super::PERMISSION_NETWORK_BROWSER, "network:browser");
    }
}
