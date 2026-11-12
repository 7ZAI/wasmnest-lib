//! 降级路径（未导出 events-ws）

use super::scaffold::*;
use super::*;

#[tokio::test]
async fn dropped_frame_accounting_counts_and_warns_once() {
    let plugin = test_plugin("dropcount");
    assert_eq!(dropped_frame_count(&plugin), 0);
    record_dropped_frame(&plugin, "wsc-x");
    record_dropped_frame(&plugin, "wsc-x");
    record_dropped_frame(&plugin, "wsc-y");
    assert_eq!(dropped_frame_count(&plugin), 3, "计数累计");
    {
        let warned = WS_DROP_WARNED.lock().unwrap();
        assert!(warned.contains(&plugin), "首次告警标记已置位");
    }
    // 属主回收后计数与标记一并清理
    let ports: Arc<dyn WsPorts> = FakePorts::with(&[]);
    purge_for_plugin(&plugin, &ports);
    assert_eq!(dropped_frame_count(&plugin), 0);
}

/// 帧投递三态：未导出 → 计数；投递器未注入 → 不计数不 panic；投递失败 → 只补上下文
#[tokio::test]
async fn dispatch_outcomes_only_count_the_not_exported_case() {
    let plugin = test_plugin("dispatch3");
    let fake = FakePorts::with(&[]);
    let ports: Arc<dyn WsPorts> = fake.clone();

    // 未导出 events-ws：降级计数
    fake.set_dispatch_result(FrameDispatch::NotExported);
    deliver_frame(&ports, &plugin, "wsc-1", "text", b"a".to_vec()).await;
    assert_eq!(dropped_frame_count(&plugin), 1, "未导出必须计入丢弃计数");

    // 投递器未注入（两阶段初始化中间态）：不计数、不 panic
    fake.set_dispatch_result(FrameDispatch::Unavailable);
    deliver_frame(&ports, &plugin, "wsc-1", "text", b"b".to_vec()).await;
    assert_eq!(dropped_frame_count(&plugin), 1, "未注入不得计入丢弃计数");

    // 投递失败（trap）：宿主已统一记录并触发重载，本域只补上下文
    fake.set_dispatch_result(FrameDispatch::Failed("trap".to_string()));
    deliver_frame(&ports, &plugin, "wsc-1", "binary", b"c".to_vec()).await;
    assert_eq!(dropped_frame_count(&plugin), 1, "投递失败不是丢弃降级");

    // 已投递：不计数
    fake.set_dispatch_result(FrameDispatch::Delivered);
    deliver_frame(&ports, &plugin, "wsc-1", "text", b"d".to_vec()).await;
    assert_eq!(dropped_frame_count(&plugin), 1);

    purge_for_plugin(&plugin, &ports);
    assert_eq!(dropped_frame_count(&plugin), 0, "回收清零");
}

/// 服务端域帧目标标识 = `<endpoint>/<client>`（日志与计数用；缺段即错配）
#[tokio::test]
async fn frame_target_label_covers_both_domains() {
    assert_eq!(WsFrameTarget::Client("wsc-1").label(), "wsc-1");
    assert_eq!(
        WsFrameTarget::EndpointClient {
            endpoint_id: "wse-1",
            client_id: "127.0.0.1:9"
        }
        .label(),
        "wse-1/127.0.0.1:9"
    );
}
