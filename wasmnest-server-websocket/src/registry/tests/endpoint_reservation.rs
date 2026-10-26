//! 端点域寻址 / 属主回收 / 按端点断开 — crate 内单元测试（自 packages/wasmnest-server-websocket/src/registry.rs 迁出）

use super::scaffold::*;

#[test]
fn endpoint_reservation_enforces_limit_before_upgrade() {
    let registry = local_registry();
    assert!(registry.reserve_endpoint_client("wse-a", "client-a", 1));
    assert!(!registry.reserve_endpoint_client("wse-a", "client-b", 1));
    registry.release_endpoint_reservation("wse-a", "client-a");
    assert!(registry.reserve_endpoint_client("wse-a", "client-b", 1));
}
