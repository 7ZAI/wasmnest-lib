//! 引擎契约的可执行判据（会话表 / 状态机 / 配额 / 属主隔离 / 帧环游标 / 终止 / 回收）
//!
//! 全部用例跑在 [`ScriptedBackend`] 上：没有硬件、没有线程、没有真实音频——
//! 采集帧由测试投喂，失败由脚本注入。这使「慢消费者只损失自己的历史」「终止后 stop
//! 幂等、start 显性失败」这类机制不变量可被确定性断言。
//!
//! 用例编号（E-xxx）只用于本文件内的脉络对照，不是契约面。

use std::sync::Arc;

use super::*;
use crate::backend::TerminationReason;
use crate::format::{PcmFormat, SampleFormat, TargetFormat};
use crate::test_util::{ScriptedBackend, ScriptedOp};

/// 16 k 单声道 s16（与缺省目标格式同形 ⇒ 归一走同速率快路径）
fn native_format() -> PcmFormat {
    PcmFormat::new(16_000, 1, SampleFormat::S16)
}

fn scripted_backend() -> ScriptedBackend {
    ScriptedBackend::new(native_format())
}

fn make_hub(backend: &ScriptedBackend) -> AudioHub {
    AudioHub::new(Arc::new(backend.clone()), AudioLimits::default())
}

fn make_hub_with(backend: &ScriptedBackend, limits: AudioLimits) -> AudioHub {
    AudioHub::new(Arc::new(backend.clone()), limits)
}

/// 投喂 `frames` 帧恒定电平（16 k 单声道 s16 = 每帧 2 字节）
fn push_frames(backend: &ScriptedBackend, frames: usize, sample: i16) {
    let samples = vec![sample; frames];
    backend.push(native_format(), &PcmBuffer::S16(&samples));
}

fn open_running(hub: &AudioHub, owner: &str) -> StreamHandle {
    let handle = hub.open(owner, OpenParams::default()).expect("打开成功");
    hub.start(owner, &handle).expect("启动成功");
    handle
}

/// E-001 正例：open 不启动；start 后按游标续拉不重复，追平返回 `Ok(None)`
#[test]
fn open_does_not_start_and_cursor_follow_up_is_exact() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = hub
        .open("owner-a", OpenParams::default())
        .expect("打开成功");

    assert_eq!(
        hub.status("owner-a", &handle).expect("状态").state,
        "idle",
        "open 不得顺手起流"
    );
    push_frames(&backend, 4, 1_000);
    assert!(
        hub.ring_fetch("owner-a", &handle, 0, 1024)
            .expect("拉取成功")
            .is_none(),
        "未启动时后端回调必须被丢弃（状态闸门），环里不得有字节"
    );

    hub.start("owner-a", &handle).expect("启动成功");
    push_frames(&backend, 5, 1_000);
    let first = hub
        .ring_fetch("owner-a", &handle, 0, 1024)
        .expect("拉取成功")
        .expect("有数据");
    assert_eq!(first.data.len(), 10, "5 帧 × 2 字节");
    assert_eq!(first.next_offset, 10);
    assert!(!first.truncated);

    push_frames(&backend, 3, -1_000);
    let second = hub
        .ring_fetch("owner-a", &handle, first.next_offset, 1024)
        .expect("拉取成功")
        .expect("有增量");
    assert_eq!(second.data.len(), 6, "只拿新增的 3 帧");
    assert_eq!(second.next_offset, 16);
    assert!(
        hub.ring_fetch("owner-a", &handle, second.next_offset, 1024)
            .expect("拉取成功")
            .is_none(),
        "追平即无数据（不是错误）"
    );

    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.bytes_produced, 16);
    assert_eq!(status.frames_captured, 8);
    assert_eq!(status.ring_usage_bytes, 16);
    assert_eq!(status.callbacks, 2);
    assert_eq!(status.produced_ms, 1, "8 帧 @16k ≈ 0.5ms，向上取整 1ms");
}

/// E-002 边界：单次拉取被 `maxFetchBytes` 钳制（wasm 边界拷贝预算，不是调用方意图）
#[test]
fn fetch_budget_is_clamped_not_rejected() {
    let backend = scripted_backend();
    let hub = make_hub_with(
        &backend,
        AudioLimits {
            max_fetch_bytes: 6,
            ..AudioLimits::default()
        },
    );
    let handle = open_running(&hub, "owner-a");
    push_frames(&backend, 5, 0);

    let first = hub
        .ring_fetch("owner-a", &handle, 0, 1_024)
        .expect("拉取成功")
        .expect("有数据");
    assert_eq!(first.data.len(), 6, "钳到 6 字节（3 帧，帧对齐）");
    assert_eq!(first.next_offset, 6);
    let rest = hub
        .ring_fetch("owner-a", &handle, first.next_offset, 1_024)
        .expect("拉取成功")
        .expect("剩余数据");
    assert_eq!(rest.data.len(), 4);
    assert_eq!(rest.next_offset, 10);
}

/// E-003 边界：环容量不足时落后游标报 `truncated`，并从驻留起点重交
#[test]
fn stale_cursor_reports_truncated_and_resyncs() {
    let backend = scripted_backend();
    let hub = make_hub_with(
        &backend,
        AudioLimits {
            default_ring_bytes: 32,
            ..AudioLimits::default()
        },
    );
    let handle = open_running(&hub, "owner-a");
    push_frames(&backend, 30, 7); // 60 字节 > 32 字节容量

    let stale = hub
        .ring_fetch("owner-a", &handle, 0, 1_024)
        .expect("拉取成功")
        .expect("有数据");
    assert!(stale.truncated, "被淘汰区间必须如实上报");
    assert_eq!(stale.data.len(), 32, "只交驻留窗口");
    assert_eq!(stale.next_offset, 60);
    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.ring_dropped_bytes, 28);
    assert_eq!(status.ring_usage_bytes, 32);
    assert_eq!(status.ring_bytes, 32, "容量按帧取整后回报");
}

/// E-003b 边界：未来游标自愈（回带产出端，而不是永远「无新数据」）
#[test]
fn future_cursor_self_heals_to_the_produced_end() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = open_running(&hub, "owner-a");
    push_frames(&backend, 3, 0);

    let healed = hub
        .ring_fetch("owner-a", &handle, 9_000, 1_024)
        .expect("拉取成功")
        .expect("未来游标必须回带修正值，而不是 Ok(None)");
    assert!(healed.data.is_empty());
    assert_eq!(healed.next_offset, 6, "回带产出端");
    assert!(!healed.truncated);

    push_frames(&backend, 1, 0);
    let tail = hub
        .ring_fetch("owner-a", &handle, healed.next_offset, 1_024)
        .expect("拉取成功")
        .expect("自纠后能继续拉");
    assert_eq!(tail.data.len(), 2);
    assert_eq!(tail.next_offset, 8);
}

/// E-004 反例：配额满时第 N+1 条 open 失败，且不登记半成品
#[test]
fn quota_blocks_the_extra_stream_without_leaving_partial_state() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    assert_eq!(hub.quota_of("owner-a"), 2, "缺省档 = 2");
    let _first = hub.open("owner-a", OpenParams::default()).expect("第 1 条");
    let _second = hub.open("owner-a", OpenParams::default()).expect("第 2 条");
    let err = hub
        .open("owner-a", OpenParams::default())
        .expect_err("第 3 条必须被拒");
    assert!(
        matches!(err, AudioError::QuotaExceeded { limit: 2 }),
        "实得 {err:?}"
    );
    assert_eq!(hub.live_count(), 2, "失败的 open 不得留下半成品会话");
    assert_eq!(hub.sessions_of("owner-a").len(), 2);

    // 配额按属主隔离：另一个插件不受影响
    assert!(hub.open("owner-b", OpenParams::default()).is_ok());
}

/// E-005 反例：配额声明越界（0 / 超天花板）一律拒绝登记，不夹取
#[test]
fn declared_quota_is_arbitrated_not_clamped() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let ceiling = hub.limits().max_sessions_ceiling_per_owner;
    hub.set_quota("owner-a", Some(1)).expect("下界可登记");
    assert_eq!(hub.quota_of("owner-a"), 1);
    hub.set_quota("owner-a", None).expect("缺省档可登记");
    assert_eq!(hub.quota_of("owner-a"), 2);

    for bad in [0usize, ceiling + 1, 10_000] {
        let err = hub
            .set_quota("owner-a", Some(bad))
            .err()
            .unwrap_or_else(|| panic!("audioQuota={bad} 必须被拒"));
        assert!(
            err.to_string().contains(&bad.to_string())
                || err.to_string().contains("greater than zero"),
            "错误必须点名越界值，实得 {err}"
        );
    }
    assert_eq!(hub.quota_of("owner-a"), 2, "被拒的声明不得改写生效配额");
}

/// E-005b 正例：后端在 `start` 返回前投来的首帧必须入环（不得被状态闸门丢弃）
///
/// 真实后端（cpal `play()`）会在返回前就回调；引擎若等后端返回后才置 `Running`，
/// 首帧会被计成 `ignored_callbacks` 并丢弃——那既丢音频又让「非采集态回调」计数失真。
#[test]
fn callbacks_delivered_inside_backend_start_are_kept() {
    let backend = scripted_backend().with_push_on_start(5);
    let hub = make_hub(&backend);
    let handle = hub
        .open("owner-a", OpenParams::default())
        .expect("打开成功");
    hub.start("owner-a", &handle).expect("启动成功");

    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.bytes_produced, 10, "首帧（5 帧 × 2 字节）必须入环");
    assert_eq!(status.ignored_callbacks, 0, "采集态回调不得计成被忽略");
    assert_eq!(status.callbacks, 1);
}

/// E-006 反例：属主隔离——非属主既不能读也不能操作（且不泄露「存在与否」以外的东西）
#[test]
fn non_owner_is_rejected_on_every_primitive() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = hub
        .open("owner-a", OpenParams::default())
        .expect("打开成功");

    for err in [
        hub.start("owner-b", &handle).expect_err("start 越权"),
        hub.stop("owner-b", &handle).expect_err("stop 越权"),
        hub.status("owner-b", &handle).expect_err("status 越权"),
        hub.level("owner-b", &handle).expect_err("level 越权"),
        hub.ring_fetch("owner-b", &handle, 0, 16)
            .expect_err("ring-fetch 越权"),
        hub.close("owner-b", &handle).expect_err("close 越权"),
    ] {
        assert!(matches!(err, AudioError::NotOwner { .. }), "实得 {err:?}");
    }
    assert_eq!(hub.live_count(), 1, "越权 close 不得摘掉别人的句柄");
    // 越权失败后属主仍然可用
    hub.start("owner-a", &handle).expect("属主不受影响");
}

/// E-007 反例：不存在的句柄一律 `HandleNotFound`（含 close 后的重复访问）
#[test]
fn unknown_or_closed_handles_are_not_found() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = hub
        .open("owner-a", OpenParams::default())
        .expect("打开成功");
    hub.close("owner-a", &handle).expect("关闭成功");
    assert_eq!(hub.live_count(), 0);

    for err in [
        hub.status("owner-a", &handle).expect_err("status 失败"),
        hub.start("owner-a", &handle).expect_err("start 失败"),
        hub.close("owner-a", &handle).expect_err("二次 close 失败"),
    ] {
        assert!(
            matches!(err, AudioError::HandleNotFound { .. }),
            "实得 {err:?}"
        );
    }
    let unknown = "audio-does-not-exist"
        .parse::<StreamHandle>()
        .expect("形状合法");
    assert!(matches!(
        hub.status("owner-a", &unknown).expect_err("未知句柄"),
        AudioError::HandleNotFound { .. }
    ));
}

/// E-008 正例：stop 保留句柄与历史，再次 start 续写同一游标（消费者无感）
#[test]
fn stop_keeps_history_and_restart_resumes_the_same_offsets() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = open_running(&hub, "owner-a");
    push_frames(&backend, 5, 500);

    hub.stop("owner-a", &handle).expect("停止成功");
    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.state, "stopped");
    assert_eq!(status.bytes_produced, 10, "停止不回退产出端");

    let kept = hub
        .ring_fetch("owner-a", &handle, 0, 1_024)
        .expect("停止后仍可拉取")
        .expect("历史仍在");
    assert_eq!(kept.next_offset, 10);

    push_frames(&backend, 2, 500);
    assert_eq!(
        hub.status("owner-a", &handle)
            .expect("状态")
            .ignored_callbacks,
        1,
        "停止后到达的回调只计数、不入环"
    );

    hub.start("owner-a", &handle).expect("可再次启动");
    push_frames(&backend, 2, 500);
    let resumed = hub
        .ring_fetch("owner-a", &handle, kept.next_offset, 1_024)
        .expect("续拉成功")
        .expect("新数据");
    assert_eq!(resumed.next_offset, 14, "偏移在停—起之间连续");
    assert_eq!(resumed.data.len(), 4);
}

/// E-009 反例：状态机不允许的动作显性失败（不在错误状态上假装成功）
#[test]
fn invalid_state_transitions_are_rejected() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = hub
        .open("owner-a", OpenParams::default())
        .expect("打开成功");

    let err = hub.stop("owner-a", &handle).expect_err("idle 不能 stop");
    assert!(
        matches!(&err, AudioError::InvalidState { state, needs, .. } if state == "idle" && needs == "running"),
        "实得 {err:?}"
    );

    hub.start("owner-a", &handle).expect("启动成功");
    let err = hub
        .start("owner-a", &handle)
        .expect_err("重复 start 必须拒");
    assert!(matches!(&err, AudioError::InvalidState { state, .. } if state == "running"));
    assert_eq!(
        backend.op_count(|op| matches!(op, ScriptedOp::Start)),
        1,
        "被拒的 start 不得触达后端"
    );
}

/// E-010 正例：后端自报终止 → `terminated` 态；stop 幂等成功，start 要求重开
#[test]
fn backend_termination_is_sticky_and_requires_reopen() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = open_running(&hub, "owner-a");
    push_frames(&backend, 2, 100);

    backend.terminate(TerminationReason::DeviceLost {
        detail: "unplugged".to_string(),
    });
    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.state, "terminated");
    assert_eq!(status.backend_errors, 1);
    let termination = status.termination.expect("终止详情必须在册");
    assert_eq!(termination.code, "device_lost");
    assert_eq!(termination.detail, "unplugged");
    assert!(termination.suggests_reopen);

    hub.stop("owner-a", &handle)
        .expect("终止态 stop 幂等成功（后置条件已成立）");
    let err = hub
        .start("owner-a", &handle)
        .expect_err("终止态不得重新 start");
    assert!(
        matches!(&err, AudioError::InvalidState { needs, .. } if needs.contains("reopen")),
        "错误必须给出路（close 后重开），实得 {err:?}"
    );
    assert_eq!(
        hub.status("owner-a", &handle).expect("状态").state,
        "terminated",
        "被拒的 start 不得改写状态"
    );
    // 历史仍可拉取（收尾语义）
    assert!(hub
        .ring_fetch("owner-a", &handle, 0, 1024)
        .expect("可拉取")
        .is_some());

    // 重复终止只计错误，不覆盖首个原因
    backend.terminate(TerminationReason::Failed {
        detail: "second".to_string(),
    });
    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.backend_errors, 2);
    assert_eq!(
        status.termination.expect("仍在册").code,
        "device_lost",
        "首个终止原因才是事实"
    );
}

/// E-011 正例：close 先停手再释放后端流（Drop 发生在会话摘表之后）
#[test]
fn close_stops_then_drops_the_backend_stream() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = open_running(&hub, "owner-a");
    hub.close("owner-a", &handle).expect("关闭成功");

    let ops = backend.ops();
    assert!(matches!(ops[0], ScriptedOp::Open(_)));
    assert_eq!(ops[1], ScriptedOp::Start);
    assert_eq!(ops[2], ScriptedOp::Stop, "release 必须先停手");
    assert_eq!(ops[3], ScriptedOp::Dropped, "后端资源必须被 Drop");
    assert_eq!(ops.len(), 4);
}

/// E-012 正例：停用回收只碰本人（句柄 + 配额登记一起回收）
#[test]
fn purge_reclaims_only_the_owner_and_clears_its_quota() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    hub.set_quota("owner-a", Some(1)).expect("登记配额");
    let _a = hub.open("owner-a", OpenParams::default()).expect("a 打开");
    let _b1 = hub.open("owner-b", OpenParams::default()).expect("b 打开");
    let handle_b2 = hub
        .open("owner-b", OpenParams::default())
        .expect("b 再打开");

    assert_eq!(hub.purge("owner-a"), 1);
    assert_eq!(hub.live_count(), 2, "他人句柄不受影响");
    assert!(hub.sessions_of("owner-a").is_empty());
    assert_eq!(
        hub.quota_of("owner-a"),
        hub.limits().max_sessions_per_owner,
        "回收顺带摘掉配额登记（重新装载会重新登记）"
    );
    assert_eq!(hub.sessions_of("owner-b").len(), 2);
    assert!(hub.status("owner-b", &handle_b2).is_ok());
    assert_eq!(hub.purge("owner-a"), 0, "重复回收是零，不是错误");
}

/// E-013 正例：关停全量回收（跨属主），返回回收条数
#[test]
fn close_all_reclaims_every_owner() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    hub.open("owner-a", OpenParams::default()).expect("a 打开");
    hub.open("owner-b", OpenParams::default()).expect("b 打开");
    hub.open("owner-b", OpenParams::default())
        .expect("b 再打开");
    assert_eq!(hub.close_all(), 3);
    assert_eq!(hub.live_count(), 0);
    assert_eq!(
        backend.op_count(|op| matches!(op, ScriptedOp::Dropped)),
        3,
        "每条流都必须释放后端资源"
    );
    assert_eq!(hub.close_all(), 0);
}

/// E-014 正例：电平计量只覆盖归一后的产出；`start` 复位窗口
#[test]
fn level_measures_produced_pcm_and_resets_on_start() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = hub
        .open("owner-a", OpenParams::default())
        .expect("打开成功");
    assert!(
        hub.level("owner-a", &handle).expect("读取成功").is_none(),
        "未采集时是缺席，不是静音"
    );

    hub.start("owner-a", &handle).expect("启动成功");
    push_frames(&backend, 160, 32_000);
    let level = hub
        .level("owner-a", &handle)
        .expect("读取成功")
        .expect("有读数");
    assert!(
        (level.rms - 0.976_562_5).abs() < 1e-3,
        "满刻度正弦外的常量电平 rms 应为 32000/32768，实得 {}",
        level.rms
    );
    assert!(level.peak >= level.rms);
    assert_eq!(level.window_samples, 160, "单声道 ⇒ 样本数 = 帧数");

    hub.stop("owner-a", &handle).expect("停止成功");
    hub.start("owner-a", &handle).expect("再次启动");
    assert!(
        hub.level("owner-a", &handle).expect("读取成功").is_none(),
        "start 复位电平窗口（不带上一段的余音）"
    );
}

/// E-015 反例：后端起停失败必须显性，且不污染状态机
#[test]
fn backend_start_and_stop_failures_surface_without_state_corruption() {
    let backend = scripted_backend().with_start_failure();
    let hub = make_hub(&backend);
    let handle = hub
        .open("owner-a", OpenParams::default())
        .expect("打开成功");
    let err = hub.start("owner-a", &handle).expect_err("start 必须失败");
    assert!(
        matches!(err, AudioError::StreamFailed { .. }),
        "实得 {err:?}"
    );
    assert_eq!(
        hub.status("owner-a", &handle).expect("状态").state,
        "idle",
        "起流失败不改写状态（可直接重试）"
    );

    let backend = scripted_backend().with_stop_failure();
    let hub = make_hub(&backend);
    let handle = open_running(&hub, "owner-a");
    let err = hub.stop("owner-a", &handle).expect_err("stop 必须失败");
    assert!(
        matches!(err, AudioError::StreamFailed { .. }),
        "实得 {err:?}"
    );
    assert_eq!(
        hub.status("owner-a", &handle).expect("状态").state,
        "running",
        "停流失败不得假装已停"
    );
}

/// E-016 反例：open 失败不登记会话，且错误原样透出后端原因
#[test]
fn open_failure_leaves_no_session() {
    let backend = scripted_backend().with_open_failure(AudioError::BackendUnavailable {
        backend: "scripted".to_string(),
        reason: "host gone".to_string(),
    });
    let hub = make_hub(&backend);
    let err = hub
        .open("owner-a", OpenParams::default())
        .expect_err("open 必须失败");
    assert!(
        err.to_string().contains("host gone"),
        "后端原文必须透出，实得 {err}"
    );
    assert_eq!(hub.live_count(), 0);
    assert!(hub.sessions_of("owner-a").is_empty());
    assert_eq!(
        hub.quota_of("owner-a"),
        2,
        "失败不改变配额（配额没有预留态）"
    );
}

/// E-017 反例：`open` 参数越界显性拒绝（0 容量 / 超上限 / 采样率与声道数区间）
#[test]
fn open_params_reject_out_of_range_values() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let max_ring = hub.limits().max_ring_bytes;

    let cases = [
        OpenParams {
            ring_bytes: Some(0),
            ..OpenParams::default()
        },
        OpenParams {
            ring_bytes: Some(max_ring + 1),
            ..OpenParams::default()
        },
        OpenParams {
            target_sample_rate: Some(0),
            ..OpenParams::default()
        },
        OpenParams {
            target_sample_rate: Some(200_000),
            ..OpenParams::default()
        },
        OpenParams {
            target_channels: Some(0),
            ..OpenParams::default()
        },
        OpenParams {
            target_channels: Some(3),
            ..OpenParams::default()
        },
    ];
    for params in cases {
        let err = hub
            .open("owner-a", params.clone())
            .err()
            .unwrap_or_else(|| panic!("越界参数必须被拒：{params:?}"));
        assert!(
            matches!(err, AudioError::InvalidConfig { .. }),
            "{params:?} 应产生 InvalidConfig，实得 {err:?}"
        );
    }
    assert_eq!(hub.live_count(), 0, "被拒的 open 不得留下会话");
    assert_eq!(
        backend.op_count(|op| matches!(op, ScriptedOp::Open(_))),
        0,
        "参数仲裁必须先于后端副作用"
    );
}

/// E-018 正例：只填一半目标格式是允许的（缺的那一半取缺省），并按目标格式换算产出
#[test]
fn partial_target_uses_defaults_and_normalizes_to_it() {
    let backend = ScriptedBackend::new(PcmFormat::new(48_000, 2, SampleFormat::F32)); // 48k 立体声 f32
    let hub = make_hub(&backend);
    let handle = hub
        .open(
            "owner-a",
            OpenParams {
                target_sample_rate: Some(16_000),
                ..OpenParams::default()
            },
        )
        .expect("打开成功");
    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.target_sample_rate, 16_000);
    assert_eq!(status.target_channels, 1, "缺省声道数 = 单声道");
    assert_eq!(status.actual_format.sample_rate, 48_000, "实际格式如实回报");

    hub.start("owner-a", &handle).expect("启动成功");
    let samples = vec![0.25f32; 480 * 2]; // 10 ms @48k 立体声
    backend.push(
        PcmFormat::new(48_000, 2, SampleFormat::F32),
        &PcmBuffer::F32(&samples),
    );
    let fetched = hub
        .ring_fetch("owner-a", &handle, 0, 4_096)
        .expect("拉取成功")
        .expect("有数据");
    // 10 ms @16k 单声道 = 160 帧 = 320 字节（线性重采样允许 ±2 帧）
    let frames = fetched.data.len() / 2;
    assert!(
        (158..=162).contains(&frames),
        "产出帧数异常：{frames}（{} 字节）",
        fetched.data.len()
    );
}

/// E-019 正例：`status` JSON 是插件侧消费契约（camelCase 扁平形状，与 WIT 文档一致）
#[test]
fn status_json_matches_the_documented_shape() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = open_running(&hub, "owner-a");
    push_frames(&backend, 4, 0);
    let json = serde_json::to_value(hub.status("owner-a", &handle).expect("状态")).expect("序列化");

    for key in [
        "handle",
        "state",
        "backend",
        "targetSampleRate",
        "targetChannels",
        "actualFormat",
        "framesCaptured",
        "bytesProduced",
        "ringBytes",
        "ringUsageBytes",
        "ringDroppedBytes",
        "producedMs",
        "callbacks",
        "backendErrors",
        "ignoredCallbacks",
    ] {
        assert!(json.get(key).is_some(), "status 缺字段 `{key}`：{json}");
    }
    assert_eq!(json["state"], "running");
    assert_eq!(json["backend"], "scripted");
    assert_eq!(json["targetSampleRate"], 16_000);
    assert_eq!(json["actualFormat"]["sampleRate"], 16_000);
    assert_eq!(
        json["actualFormat"]["sampleFormat"], "s16",
        "actual-format 的记录字段名"
    );
    assert_eq!(json["framesCaptured"], 4);
    assert_eq!(json["bytesProduced"], 8);
    assert!(
        json.get("termination").is_some(),
        "非终止态是 null 而非缺字段"
    );
    assert!(json["termination"].is_null());
}

/// E-020 正例：设备清单直通后端（含「没有设备」这一后端故障面）
#[test]
fn devices_pass_through_the_scripted_backend() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let devices = hub.devices().expect("枚举成功");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id.as_str(), "scripted-input");
    assert!(devices[0].is_default);

    let failing =
        ScriptedBackend::new(native_format()).with_devices_error(AudioError::NoInputDevice);
    let hub = make_hub(&failing);
    assert!(matches!(hub.devices(), Err(AudioError::NoInputDevice)));
}

/// E-021 不变量：并发投喂不丢字节（回调只在 `runtime` 锁内追加，锁序不依赖调用顺序）
#[test]
fn concurrent_producers_do_not_lose_bytes() {
    let backend = scripted_backend();
    let hub = make_hub(&backend);
    let handle = open_running(&hub, "owner-a");
    let sink = backend.sink().expect("open 已登记 sink");

    let mut workers = Vec::new();
    for _ in 0..4 {
        let sink = Arc::clone(&sink);
        workers.push(std::thread::spawn(move || {
            let samples = vec![123i16; 2];
            for _ in 0..50 {
                sink.push(native_format(), &PcmBuffer::S16(&samples));
            }
        }));
    }
    for worker in workers {
        worker.join().expect("投喂线程不得 panic");
    }

    let status = hub.status("owner-a", &handle).expect("状态");
    assert_eq!(status.callbacks, 200, "每次回调都计数");
    assert_eq!(status.bytes_produced, 200 * 4, "4 字节/回调 × 200");
    let fetched = hub
        .ring_fetch("owner-a", &handle, 0, 4_096)
        .expect("拉取成功")
        .expect("有数据");
    assert_eq!(fetched.data.len(), 800, "并发投喂不得丢字节");
}

/// E-022 正例：句柄形状校验（只判形状，不判存在；拒绝空 id 与非常规字符）
#[test]
fn handle_parsing_validates_shape_only() {
    let handle = "audio-0b0e7c1a-6f3d-4c8a-9a11-2f4c5d6e7f80"
        .parse::<StreamHandle>()
        .expect("标准 uuid 形状合法");
    assert!(handle.as_str().starts_with("audio-"));
    assert_eq!(handle.to_string(), handle.as_str());
    "audio-a.b_c-1"
        .parse::<StreamHandle>()
        .expect("点/下划线/连字符允许");

    for bad in ["", "audio-", "pty-abc", "audio-a b", "audio-a/b", "audiox"] {
        assert!(
            bad.parse::<StreamHandle>().is_err(),
            "`{bad}` 必须被拒（句柄会被拼进日志，不能塞任意文本）"
        );
    }
    // 生成器与解析器同一形状（前缀常量只有一处真源）
    let generated = StreamHandle::generate();
    assert_eq!(
        generated
            .as_str()
            .parse::<StreamHandle>()
            .expect("自产句柄必须可解析"),
        generated
    );
    assert!(generated.as_str().starts_with(crate::wire::HANDLE_PREFIX));
}

/// E-023 正例：`OpenParams::resolve` 只补缺省、不夹取，且目标格式校验一次
#[test]
fn resolve_fills_defaults_without_clamping() {
    let limits = AudioLimits::default();
    let resolved = OpenParams::default()
        .resolve(&limits)
        .expect("全缺省可解析");
    assert_eq!(resolved.target, TargetFormat::default());
    assert_eq!(resolved.ring_bytes, limits.default_ring_bytes);
    assert_eq!(resolved.device, None);

    let resolved = OpenParams {
        device: Some("hw:1".to_string()),
        target_channels: Some(2),
        ..OpenParams::default()
    }
    .resolve(&limits)
    .expect("只填声道数合法");
    assert_eq!(resolved.target.sample_rate, 16_000, "缺的采样率取缺省");
    assert_eq!(resolved.target.channels, 2);
    assert_eq!(
        resolved.device.map(|id| id.as_str().to_string()),
        Some("hw:1".to_string())
    );
}
