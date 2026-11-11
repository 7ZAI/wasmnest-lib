//! host-audio 域原语（8 条，机制层）
//!
//! 每条原语 = 权限门 → 参数/句柄解析 → 引擎调用 → 错误转写。这里**没有** WIT 类型
//! （`RingFetchResult` / `LevelSnapshot` 的映射在 `plugin_binding` 的 Host 实现里），
//! 于是这些原语能在没有 `common-host` feature 的构建里被完整测试。
//!
//! ## 权限两域
//!
//! | 原语 | 权限 | 理由 |
//! | --- | --- | --- |
//! | `open` / `start` / `stop` / `close` | `audio:capture` | 占用麦克风的高风险面（开关设备、消耗电量与隐私预算） |
//! | `list-devices` / `status` / `ring-fetch` / `level` | `audio:io` | 数据面与元数据面（只读；`ring-fetch` 拿到的是自己的采集字节） |
//!
//! 权限判定经宿主端口（[`crate::plugin_binding::ports::AudioPorts`]），本域只把 `false` 翻译成拒绝文案；判定顺序是
//! **权限先于参数**——未授权时连参数错误都不该被回显（避免把解析行为当探测面）。
//!
//! ## 错误面
//!
//! 全部错误 `.to_string()` 后回 WIT `result<_, string>`：本域错误文案已经点名主体
//! （句柄 / 字段 / 越界值），宿主侧若要落结构化信封自行按变体映射（映射是显式的，不是
//! `From` 的隐式连带）。

use std::str::FromStr;
use std::sync::Arc;

use serde::Deserialize;

use crate::backend::DeviceInfo;
use crate::engine::{AudioHub, OpenParams, StreamHandle};
use crate::level::LevelSnapshot;
use crate::plugin_binding::ports::AudioPorts;
use crate::ring::RingFetch;
use crate::wire::{PERMISSION_AUDIO_CAPTURE, PERMISSION_AUDIO_IO};

/// 拒绝文案（与其它能力域同形：`permission denied: <permission>`）
fn denied(permission: &str) -> String {
    format!("permission denied: {permission}")
}

/// `open` 的 config-json 契约（纯引擎参数，camelCase）
///
/// `deviceId` 缺省取系统默认输入设备；`targetSampleRate` / `targetChannels` 只填一半
/// 时另一半取缺省（见 [`OpenParams::resolve`]）；`ringBytes` 缺省取宿主默认容量。
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenConfig {
    device_id: Option<String>,
    target_sample_rate: Option<u32>,
    target_channels: Option<u16>,
    ring_bytes: Option<u64>,
}

/// 枚举输入设备（`audio:io`）
///
/// # Errors
/// 权限缺失、或后端不可达（`BackendUnavailable` / `NoInputDevice`）。
pub fn audio_list_devices(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
) -> Result<Vec<DeviceInfo>, String> {
    if !ports.check_permission(plugin_id, PERMISSION_AUDIO_IO, "host_audio_list_devices") {
        return Err(denied(PERMISSION_AUDIO_IO));
    }
    hub.devices().map_err(|err| err.to_string())
}

/// 打开一条采集流（`audio:capture`，不启动）
///
/// # Errors
/// 权限缺失、config-json 非法、参数越界、配额满、后端打开失败。
pub fn audio_open(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
    config_json: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_AUDIO_CAPTURE, "host_audio_open") {
        return Err(denied(PERMISSION_AUDIO_CAPTURE));
    }
    let config: OpenConfig = serde_json::from_str(config_json)
        .map_err(|err| format!("audio open: invalid config json: {err}"))?;
    let ring_bytes = match config.ring_bytes {
        // 上限由引擎按宿主限额仲裁；这里只做「能塞进 usize」这一层地址宽度校验
        Some(bytes) => Some(usize::try_from(bytes).map_err(|_| {
            format!("audio open: ringBytes {bytes} exceeds the addressable size of this host")
        })?),
        None => None,
    };
    let params = OpenParams {
        device: config.device_id,
        target_sample_rate: config.target_sample_rate,
        target_channels: config.target_channels,
        ring_bytes,
    };
    hub.open(plugin_id, params)
        .map(|handle| handle.to_string())
        .map_err(|err| err.to_string())
}

/// 开始采集（`audio:capture`）
///
/// # Errors
/// 权限缺失、句柄形状非法 / 不存在、非属主、状态不允许、后端起流失败。
pub fn audio_start(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
    stream_id: &str,
) -> Result<(), String> {
    check_capture(ports, plugin_id, "host_audio_start")?;
    let handle = parse_handle(stream_id)?;
    hub.start(plugin_id, &handle).map_err(|err| err.to_string())
}

/// 停止采集（`audio:capture`，保留句柄与历史）
///
/// # Errors
/// 权限缺失、句柄非法 / 不存在、非属主、状态不允许（`idle` / `stopped`）、后端停流失败。
/// 已终止（`terminated`）上调用是幂等成功。
pub fn audio_stop(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
    stream_id: &str,
) -> Result<(), String> {
    check_capture(ports, plugin_id, "host_audio_stop")?;
    let handle = parse_handle(stream_id)?;
    hub.stop(plugin_id, &handle).map_err(|err| err.to_string())
}

/// 关闭并摘句柄（`audio:capture`）
///
/// # Errors
/// 权限缺失、句柄非法 / 不存在、非属主；后端停流失败时句柄仍被释放，错误只作告警面。
pub fn audio_close(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
    stream_id: &str,
) -> Result<(), String> {
    check_capture(ports, plugin_id, "host_audio_close")?;
    let handle = parse_handle(stream_id)?;
    hub.close(plugin_id, &handle).map_err(|err| err.to_string())
}

/// 状态快照 JSON（`audio:io`）
///
/// # Errors
/// 权限缺失、句柄非法 / 不存在、非属主；JSON 序列化失败（结构性编程错误，显性上报）。
pub fn audio_status(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
    stream_id: &str,
) -> Result<String, String> {
    check_io(ports, plugin_id, "host_audio_status")?;
    let handle = parse_handle(stream_id)?;
    let status = hub
        .status(plugin_id, &handle)
        .map_err(|err| err.to_string())?;
    serde_json::to_string(&status).map_err(|err| format!("audio status: serialize failed: {err}"))
}

/// 按游标拉取帧环（`audio:io`）
///
/// `Ok(None)` = 游标已追平产出端（不是错误）；单次字节数由引擎钳到宿主上限。
///
/// # Errors
/// 权限缺失、句柄非法 / 不存在、非属主。
pub fn audio_ring_fetch(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
    stream_id: &str,
    from_offset: u64,
    max_bytes: u32,
) -> Result<Option<RingFetch>, String> {
    check_io(ports, plugin_id, "host_audio_ring_fetch")?;
    let handle = parse_handle(stream_id)?;
    hub.ring_fetch(plugin_id, &handle, from_offset, max_bytes as usize)
        .map_err(|err| err.to_string())
}

/// 最近一个完整电平窗口（`audio:io`；`Ok(None)` = 还没有任何一帧）
///
/// # Errors
/// 权限缺失、句柄非法 / 不存在、非属主。
pub fn audio_level(
    ports: &Arc<dyn AudioPorts>,
    plugin_id: &str,
    hub: &AudioHub,
    stream_id: &str,
) -> Result<Option<LevelSnapshot>, String> {
    check_io(ports, plugin_id, "host_audio_level")?;
    let handle = parse_handle(stream_id)?;
    hub.level(plugin_id, &handle).map_err(|err| err.to_string())
}

/// `audio:capture` 权限门
fn check_capture(ports: &Arc<dyn AudioPorts>, plugin_id: &str, api: &str) -> Result<(), String> {
    if ports.check_permission(plugin_id, PERMISSION_AUDIO_CAPTURE, api) {
        Ok(())
    } else {
        Err(denied(PERMISSION_AUDIO_CAPTURE))
    }
}

/// `audio:io` 权限门
fn check_io(ports: &Arc<dyn AudioPorts>, plugin_id: &str, api: &str) -> Result<(), String> {
    if ports.check_permission(plugin_id, PERMISSION_AUDIO_IO, api) {
        Ok(())
    } else {
        Err(denied(PERMISSION_AUDIO_IO))
    }
}

/// 句柄形状解析（只判形状；存在与否由引擎查表，属主校验也在那里一起做）
fn parse_handle(stream_id: &str) -> Result<StreamHandle, String> {
    StreamHandle::from_str(stream_id).map_err(|err| err.to_string())
}
