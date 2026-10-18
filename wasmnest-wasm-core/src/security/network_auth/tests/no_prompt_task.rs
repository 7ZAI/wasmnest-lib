//! 无询问面（任务单元） — crate 内单元测试（自桌面宿主旧 `wasm_core/security/network_auth.rs` 面迁出）

use super::scaffold::*;
use super::*;

/// 池线程只认记录：无记录拒绝、allow 放行、deny 压过 allow
#[tokio::test]
async fn is_granted_only_trusts_records() {
    let checker = headless().await;
    assert!(
        !checker.is_granted("com.wasmnest.test", "https://api.x.com:443/v1").await,
        "无记录必须拒绝（池线程不弹窗）"
    );
    seed_allow(&checker, "com.wasmnest.test", "https://api.x.com:443").await;
    assert!(checker.is_granted("com.wasmnest.test", "https://api.x.com:443/v1").await);
    seed_deny(&checker, "com.wasmnest.test", "https://api.x.com:443").await;
    assert!(
        !checker.is_granted("com.wasmnest.test", "https://api.x.com:443/v1").await,
        "deny 必须压过 allow（无询问面同源）"
    );
}
/// 属主隔离：别的应用的记录不得为本次请求放行
#[tokio::test]
async fn other_plugins_records_do_not_release_this_plugin() {
    let checker = headless().await;
    seed_allow(&checker, "com.wasmnest.other", "https://api.x.com:443").await;
    assert!(!checker.is_granted("com.wasmnest.test", "https://api.x.com:443/v1").await);
}
/// 决定枚举：wire 值与解析一一对应，未知值显性拒绝（不放行兜底）
#[test]
fn network_decision_wire_values_round_trip() {
    for (wire, decision) in [
        ("allow_once", NetworkDecision::AllowOnce),
        ("deny", NetworkDecision::Deny),
        ("deny_always", NetworkDecision::DenyAlways),
    ] {
        assert_eq!(NetworkDecision::parse(wire), Some(decision));
        assert_eq!(decision.as_str(), wire);
    }
    assert_eq!(NetworkDecision::parse("allow"), None, "未知值必须 None（调用方报错）");
    assert_eq!(NetworkDecision::parse("ALLOW_ONCE"), None, "大小写不容混");
}
