//! 回收（只碰本人）

use super::scaffold::*;
use super::*;

#[tokio::test]
async fn purge_for_plugin_only_touches_owner() {
    let victim = test_plugin("purge");
    let bystander = test_plugin("bystander");
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[]);
    let victim_handle = format!("wsc-{}", uuid::Uuid::new_v4());
    let bystander_handle = format!("wsc-{}", uuid::Uuid::new_v4());
    fake_client(&ports, &victim, &victim_handle, "ws://127.0.0.1:1/");
    fake_client(&ports, &bystander, &bystander_handle, "ws://127.0.0.1:1/");

    assert_eq!(purge_for_plugin(&victim, &ports), 1);
    {
        let table = CLIENTS.lock().unwrap();
        assert!(!table.contains_key(&victim_handle), "victim purged");
        assert!(table.contains_key(&bystander_handle), "bystander survives");
    }
    // 幂等：再次回收命中 0
    assert_eq!(purge_for_plugin(&victim, &ports), 0);

    drop_client(&bystander_handle);
}
