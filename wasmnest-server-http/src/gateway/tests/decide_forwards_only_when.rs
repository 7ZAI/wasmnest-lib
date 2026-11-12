//! 判定 — crate 内单元测试（自 packages/wasmnest-server-http/src/gateway.rs 迁出）

use super::scaffold::*;
use super::*;

/// 转发条件：已验签 × 属主激活 × 档位齐备
#[test]
fn decide_forwards_only_when_verified_activated_and_tier_ok() {
    assert_eq!(decide(EndpointAuth::Jwt, true, true), GatewayDecision::Forward);
    assert_eq!(
        decide(EndpointAuth::None, false, true),
        GatewayDecision::Forward,
        "none 档免验签转发"
    );
    // 未验签 + jwt 档 → 要认证（报「要认证」而非「插件未激活」）
    assert_eq!(decide(EndpointAuth::Jwt, false, true), GatewayDecision::AuthRequired);
    // 属主未激活（注册在册与停用竞态）→ 明确报「插件未激活」
    assert_eq!(decide(EndpointAuth::Jwt, true, false), GatewayDecision::PluginRequired);
    assert_eq!(
        decide(EndpointAuth::None, false, false),
        GatewayDecision::PluginRequired
    );
}
