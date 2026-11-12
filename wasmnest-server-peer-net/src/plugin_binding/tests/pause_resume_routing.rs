//! 暂停/恢复的方向路由用例（`host-peer` 两个控制面原语的组合层）
//!
//! **为什么这组用例单独成文件**：`peer_pause_transfer` / `peer_resume_transfer`
//! 是全端**单一原语管双向**的入口（发送句柄表 / serve 供流登记表 / pull 会话表 /
//! 接收会话表四张表共用一个批 id 空间，归属由传输方向决定）。它们的正确性完全
//! 落在「未命中时的回退顺序」上：任何一层把 miss 当错误上抛，方向回退分支就永远
//! 到不了。真机事故即此类——手机端暂停下载后点恢复报
//! `peer_resume_transfer: Invalid input: resume transfer: no send session with
//! that id (pull-…)`，因为发送侧未命中被报成了错误，接收侧回退根本没机会跑。

use super::scaffold::FakePorts;
use super::*;
use crate::PeerCtx;

const PLUGIN: &str = "com.wasmnest.file-transfer";

fn ports_with(ctx: Arc<PeerCtx>) -> Arc<dyn PeerPorts> {
    FakePorts::with_ctx(&[(PLUGIN, PERMISSION_PEER)], ctx)
}

/// 正例（真机场景回归锁）：pull 会话（本端在对端拉取下载）暂停后必须能恢复
/// ——发送侧未命中要**回退**到接收侧并向 pull 会话表下发 Resume 帧。
/// 修复前此处直接报 `no send session with that id`。
#[test]
fn pause_and_resume_route_pull_session_through_receive_side() {
    let ctx = crate::test_ctx::headless_ctx();
    let slot = crate::peer_engine_remote::register_pull_for_test(&ctx, "pull-1792143196774125420");
    let ports = ports_with(Arc::clone(&ctx));

    super::peer_pause_transfer(&ports, PLUGIN, "pull-1792143196774125420").expect("pull 会话应可暂停");
    assert!(slot.is_paused(), "暂停必须经 pull 会话表置位数据面门控");

    super::peer_resume_transfer(&ports, PLUGIN, "pull-1792143196774125420").expect("pull 会话应可恢复");
    assert!(!slot.is_paused(), "恢复必须经 pull 会话表清除数据面门控");
}

/// 反例：四张表都没有的批 id，两个原语都必须**失败**，且失败原因是本层自己的
/// 「无命中」文案——不得把引擎内部的「不在发送句柄表」上抛成 InvalidInput
/// （那正是真机事故的文案：宿主命令失败日志直接把它当成调用错误）
#[test]
fn pause_and_resume_on_unknown_batch_report_binding_level_miss() {
    let ctx = crate::test_ctx::headless_ctx();
    let ports = ports_with(ctx);

    assert_eq!(
        super::peer_pause_transfer(&ports, PLUGIN, "batch-never-registered").unwrap_err(),
        "pause transfer: no running transfer with that id"
    );
    assert_eq!(
        super::peer_resume_transfer(&ports, PLUGIN, "batch-never-registered").unwrap_err(),
        "resume transfer: no paused transfer with that id"
    );
}

/// 反例（防恒真假绿）：pull 会话只在 pause/resume 两条路上生效——取消走的
/// 是另一条原语，此处不重复钉；反向钉「未登记的 pull id 不得命中接收侧回退」
/// 会被上面的未知批用例覆盖。此用例只确认 serve 登记表缺席时 resume 不误命中
/// （`set_serve_paused` 未命中即 false，不得凭空成功）
#[test]
fn resume_without_serve_or_pull_session_does_not_hit() {
    let ctx = crate::test_ctx::headless_ctx();
    let ports = ports_with(ctx);
    let err = super::peer_resume_transfer(&ports, PLUGIN, "pull-not-registered").unwrap_err();
    assert_eq!(err, "resume transfer: no paused transfer with that id");
}
