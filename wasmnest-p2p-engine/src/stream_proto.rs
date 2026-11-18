//! 流协议名注册表：P1 线协议迁移的单一事实源。
//!
//! 现役 peer-net 的三组线协议（信任状态帧 / 传输批 / 共享目录）P1 起各自跑在
//! 一条具名 libp2p 流上；协议名 = `/wasmnest/<域>/<主版本>`——域段与现役帧
//! 协议的 `PROTOCOL_VERSION` v1 对齐，**演进只允许追加新版本名，不改旧名**
//! （线上契约纪律，对齐 frame.rs 的版本化先例）。
//!
//! P0 只持常量与判据（本 crate 尚不开流）；P1 由 peer-net 的流行为按名开流/
//! 收流，本表钉住「名字只在这一处写」。漂移单测（见 [`tests`])保证：
//! 全部以 `/wasmnest/` 起头、版本段存在、彼此不重名、[`ALL`] 与各常量一致。

/// 信任状态帧（首连信任态交换）
pub const TRUST_STATUS: &str = "/wasmnest/trust-status/1";
/// 传输批（文件发送 / 接收 / 暂停 / 恢复 / 取消）
pub const TRANSFER: &str = "/wasmnest/transfer/1";
/// 共享目录（浏览 / 拉取）
pub const SHARED_DIR: &str = "/wasmnest/shared-dir/1";
/// 会话（连接保活 / 首帧分流前的常驻会话；peer-net `dial` 的默认流）
///
/// 单独一条协议而不是复用 TRANSFER：常驻会话流空闲时不承担传输语义，
/// 也避免「一个协议名同时承载两种生命周期」导致的流注册歧义。
pub const SESSION: &str = "/wasmnest/session/1";
/// 穿透通道（内网穿透 T05）：首帧 `u32be len | JSON`，之后裸字节双向 pipe。
///
/// 准入不能沿用业务流的 `Admitted` 闸门：未匹配 peer 需凭配对票据进入
/// 配对窗口，故本协议的接收器必须以 `require_admitted = false` 注册，
/// 匹配校验由通道层按「已匹配 / 票据 / allowedPeers / 端口规则」逐条裁决。
pub const TUNNEL: &str = "/wasmnest/tunnel/1";

/// 全部已注册的流协议名（漂移单测的对照面）
pub const ALL: &[&str] = &[TRUST_STATUS, TRANSFER, SHARED_DIR, SESSION, TUNNEL];

/// 协议名前缀（本引擎的命名空间）
pub const NAMESPACE: &str = "/wasmnest/";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 全部协议名_命名空间内_带版本段_不重名() {
        let mut seen = std::collections::BTreeSet::new();
        for name in ALL {
            assert!(
                name.starts_with(NAMESPACE),
                "{name} 不在命名空间 {NAMESPACE} 内"
            );
            // 形态 = 前缀 + 域段（非空、无斜杠）+ '/v主版本'
            let rest = &name[NAMESPACE.len()..];
            let (domain, version) = rest
                .rsplit_once('/')
                .unwrap_or_else(|| panic!("{name} 缺版本段分隔"));
            assert!(
                !domain.is_empty() && !domain.contains('/'),
                "{name} 域段非法"
            );
            assert_eq!(version, "1", "{name} 版本段应为 1（v1 线）");
            assert!(seen.insert(*name), "{name} 重复登记");
        }
    }

    #[test]
    fn all_表_与各常量一致() {
        assert_eq!(ALL, &[TRUST_STATUS, TRANSFER, SHARED_DIR, SESSION, TUNNEL]);
        assert_eq!(ALL.len(), 5);
    }
}
