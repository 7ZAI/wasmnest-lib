//! wasClean 规则（D11）

use super::*;

#[tokio::test]
async fn was_clean_only_for_peer_close_1xxx() {
    assert!(close_was_clean(Some(1000)), "对端正常关闭 → clean");
    assert!(close_was_clean(Some(1001)), "对端 going away → clean");
    assert!(!close_was_clean(None), "无 Close 帧（异常断开）→ 不 clean");
    assert!(!close_was_clean(Some(4001)), "认证失败 → 不 clean");
    assert!(!close_was_clean(Some(4004)), "宿主踢出 → 不 clean");
    assert!(!close_was_clean(Some(4005)), "端点注销/属主回收 → 不 clean");
    assert!(!close_was_clean(Some(1006)), "异常关闭码 → 不 clean");
}
