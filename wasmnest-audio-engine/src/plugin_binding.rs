//! host-audio 能力域接线（8 条原语 + 能力模块自报 + 端口取用）
//!
//! ## 分层
//!
//! ```text
//!   本文件        接线（8 条原语的 Host 实现 + 模块自报 + 端口取用）
//!   primitives.rs 域原语（权限门 / config-json 解析 / 句柄解析 / 错误转写）
//!   registry.rs   进程级引擎持有者（AudioHub 一次装配）+ 生命周期回收面
//!   ports.rs      边界：权限门（宿主才有的那件事）
//! ```
//!
//! 引擎（[`crate::engine::AudioHub`]）与后端（[`crate::backend::CaptureBackend`]）都在
//! 本 crate 内、默认形态可用；本层只把「WIT 调用」翻译成「引擎调用」，并补上宿主唯一的
//! 安全闸门——权限判定。**本层不做业务编排、不发事件、不起后台任务**（v1 无事件面）。
//!
//! ## 脱绑形态
//!
//! WIT 绑定层（`DESC` / `HostModule` / `inventory::submit!` / `bindgen!` / `impl Host`）
//! 以 `#[cfg(feature = "common-host")]` 门控：桌面宿主开 feature 后行为逐字不变；无
//! feature 的宿主（移动端 / 无头）拿纯引擎与域原语，描述符字段值拆成默认可用的纯字符串
//! 常量（[`crate::plugin_binding::MODULE_NAME`] 等），宿主白名单校验在无头态也能引用。
//!
//! ## 引擎由宿主装配
//!
//! [`crate::AudioHub`] 需要一份后端实现（cpal / 宿主自带 / 无头测试），能力域无法替宿主
//! 选择，故由宿主在开机期调用 [`crate::plugin_binding::install_hub`] 一次。未装配时所有原语返回显性错误
//! （fail-visible，不静默给空数据）。
//!
//! 装载期钩子只仲裁**声明了音频能力**的 manifest（`audioQuota` 或 `audio:capture` /
//! `audio:io` 权限）：引擎未装配时这些 manifest 得到 `Unavailable` 分类，
//! 内核记录错误后继续装载（原语调用仍显性失败），不会让一个域拖垮全部应用；未声明音频
//! 能力的 manifest 完全不受本域影响。声明越界（`audioQuota` 为 0 / 超上界）则是插件
//! 自己的问题，返回 `Rejected` 分类拒绝该插件。

use std::sync::Arc;

use crate::engine::AudioHub;

/// 宿主能力端口（边界层；见 [`ports`] 模块文档）
pub mod ports;

/// 域原语（8 条 WIT 原语的机制实现）
pub mod primitives;

/// 进程级引擎持有者 + 生命周期回收面
pub mod registry;

/// [`ports::install_ports`] 的再导出（宿主 adapter 需要直接装**已构造好的**端口对象）
pub use ports::install_ports;
/// 引擎装配与生命周期面（宿主开机 / 停用 / 关停路径）
pub use registry::{close_all, install_hub, live_count, purge_for_plugin};

// ==================== 描述符纯字符串常量（默认形态可用） ====================

/// 能力模块名（`audio`）
pub const MODULE_NAME: &str = "audio";

/// 能力模块接口路径（与 WIT 契约逐字一致）
pub const MODULE_INTERFACES: &[&str] = &["wasmnest:audio@0.0.1/host-audio"];

/// 能力模块权限位（`audio:capture` / `audio:io`）
pub const MODULE_PERMISSIONS: &[&str] = &["audio:capture", "audio:io"];

/// ABI 下界
///
/// `host-audio` 是随本 crate 首次登记的全新 interface，接线票落地时按当时的内核
/// ABI 版本抬到实际值（早于该版本的插件不会 import 本 interface，声明值只影响
/// 兼容性元数据，不影响运行期行为）。
pub const MODULE_ABI_MIN: u32 = 1;

/// 能力域名（宿主上下文里的键；`HostPorts::domain_ports`）
pub const DOMAIN: &str = "audio";

/// 装配端口与引擎的便捷入口（无头测试 / 最小宿主用；真实宿主分别调用两个 install）
pub fn install<P: ports::AudioPorts + 'static>(ports: P, hub: Arc<AudioHub>) {
    ports::install_ports(Arc::new(ports));
    registry::install_hub(hub);
}

// ==================== 能力模块自报（WIT 绑定层，`common-host` feature） ====================

#[cfg(feature = "common-host")]
use wasmnest_host_kit::{
    DomainHooks, HostModule, HostModuleDesc, ManifestLoadFailure, ModuleEntry, WasmPluginState,
};
#[cfg(feature = "common-host")]
use wasmtime::component::{bindgen, Linker};

/// 能力模块描述符（机制面：接口路径 / 权限位 / ABI 下界；**禁带产品名词**）
#[cfg(feature = "common-host")]
pub const DESC: HostModuleDesc = HostModuleDesc {
    name: MODULE_NAME,
    interfaces: MODULE_INTERFACES,
    permissions: MODULE_PERMISSIONS,
    abi_min: MODULE_ABI_MIN,
};

/// 音频采集能力域模块（`host-audio`，8 条原语）
#[cfg(feature = "common-host")]
pub struct AudioModule;

#[cfg(feature = "common-host")]
impl HostModule for AudioModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        wasmnest::audio::host_audio::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
    }
}

/// getter：让 guest 侧 import 取到可变的状态引用（与其它能力域接线同款）
#[cfg(feature = "common-host")]
type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

/// 静态单例（供 `inventory::submit!` 取址）
#[cfg(feature = "common-host")]
static MODULE: AudioModule = AudioModule;

// 能力模块自报（linker-section 静态）
//
// **依赖前提**：宿主必须有一行强制引用本 crate（与其它能力域同款），否则本 rlib 不进
// 最终二进制、静态不执行 ⇒ 注册丢失，且 guest 会在实例化期报「无该 import」。
#[cfg(feature = "common-host")]
inventory::submit! {
    ModuleEntry { module: &MODULE }
}

/// manifest 是否声明了音频能力面
///
/// 判据取两处（任一声明即算）：`audioQuota` 字段，或 `permissions` 里的
/// `audio:capture` / `audio:io`。**作用域收窄是加载隔离的前提**：未声明音频能力的
/// 应用与音频域无关，本域是否装配不得影响它装载。
#[cfg(feature = "common-host")]
fn declares_audio_capability(manifest: &serde_json::Value) -> bool {
    if manifest
        .get("audioQuota")
        .is_some_and(|quota| !quota.is_null())
    {
        return true;
    }
    manifest
        .get("permissions")
        .and_then(|permissions| permissions.as_array())
        .is_some_and(|permissions| {
            permissions
                .iter()
                .filter_map(|permission| permission.as_str())
                .any(|permission| MODULE_PERMISSIONS.contains(&permission))
        })
}

/// 装载期回调：从 manifest **原文**解析本域配额（`audioQuota`）并**仲裁区间**
///
/// 与其它能力域同判据：manifest 字段的解释权属于能力域（内核不解释产品声明），
/// 区间（`1..=max_sessions_ceiling_per_owner`）在装载期就判定，越界即拒绝装载，
/// **不夹取**——静默降级会让插件按自己声明的并发数规划业务、实际却少得多。
///
/// **失败分类**（见 [`ManifestLoadFailure`]）：
/// - 引擎未装配且 manifest 声明了音频能力 ⇒ `Unavailable`：宿主接线缺口，不能因此
///   拒绝该插件或拖垮无关应用；原语调用仍逐次显性报错。
/// - `audioQuota` 越界 ⇒ `Rejected`：插件自己的声明非法，不装载该插件。
#[cfg(feature = "common-host")]
fn on_manifest_load(plugin_id: &str, manifest_json: &str) -> Result<(), ManifestLoadFailure> {
    manifest_load_with(registry::try_hub(), plugin_id, manifest_json)
}

/// [`on_manifest_load`] 的可测内核（引擎显式传入，避免用例依赖进程级单例顺序）
#[cfg(feature = "common-host")]
fn manifest_load_with(
    hub: Option<Arc<AudioHub>>,
    plugin_id: &str,
    manifest_json: &str,
) -> Result<(), ManifestLoadFailure> {
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(manifest_json) else {
        // JSON 语法由内核校验面先拒；本域不替内核做通用 manifest 判决
        return Ok(());
    };
    if !declares_audio_capability(&manifest) {
        return Ok(());
    }
    let declared: Option<usize> = manifest
        .get("audioQuota")
        .cloned()
        .and_then(|value| serde_json::from_value::<Option<usize>>(value).ok())
        .flatten();
    let Some(hub) = hub else {
        return Err(ManifestLoadFailure::Unavailable(
            "audio engine is not installed: the host must call `plugin_binding::install_hub` before loading plugins"
                .to_string(),
        ));
    };
    hub.set_quota(plugin_id, declared).map_err(|err| {
        ManifestLoadFailure::Rejected(format!("plugin.json audioQuota rejected: {err}"))
    })
}

/// 停用期回调：回收本插件的全部采集流（停流 + 摘句柄 + 清配额登记）
#[cfg(feature = "common-host")]
fn on_plugin_purge(plugin_id: &str) {
    match registry::try_hub() {
        Some(hub) => {
            let reclaimed = hub.purge(plugin_id);
            tracing::debug!(plugin_id = %plugin_id, count = reclaimed, "host-audio: 停用回收完成");
        }
        None => tracing::warn!(
            plugin_id = %plugin_id,
            "host-audio: 停用回收跳过——引擎未装配（宿主接线缺口）"
        ),
    }
}

/// 生命周期钩子自报（内核遍历 `DomainHooksRegistry`，不点名本域）
#[cfg(feature = "common-host")]
pub static HOOKS: DomainHooks = DomainHooks {
    name: MODULE_NAME,
    on_manifest_load: Some(on_manifest_load),
    on_plugin_purge: Some(on_plugin_purge),
};

#[cfg(feature = "common-host")]
wasmnest_host_kit::submit_hooks!(HOOKS);

#[cfg(feature = "common-host")]
bindgen!({
    // provider 侧绑定：宿主自己的 `wasmnest` 模块是 **guest 视角**（import 是调用函数，
    // 不是 `Host` trait + `add_to_linker`），能力 crate 要自己装配就必须生成 provider 侧。
    //
    // ⚠️ 由此产生的硬约束：本 crate 与宿主各自生成的
    // `wasmnest::audio::host_audio::Host` 是**同名但不同类型**的 trait。宿主若也生成了
    // 本 interface，必须删掉自己的 `Host` impl 与 `add_to_linker` 行，否则同一 interface
    // 被注册两次 → 装配期 `defined twice`。
    //
    // 契约面脱端：bindgen 指本 crate 自持分片 `wit/audio.wit`（`world cap-audio`），
    // 不读桌面 SDK 生成物目录（端组合在平台仓 compose.json）。
    path: "wit/audio.wit",
    world: "cap-audio",
    // 与宿主同款：全部导出绑定生成 async 变体（wasmtime async store 要求）。
    // cap-audio 无 export 成员，此配置无生效对象。
    exports: { default: async },
});

/// 取本插件实例该用的端口：**实例级优先**，未装配则回落到进程级装配
///
/// 权限判定必须落在**本实例**的 PermissionManager 上（多上下文场景不得读到别人的
/// 授权），故宿主可把端口绑到实例；无头 / 单上下文宿主只需进程级装配。
///
/// 宿主注入的是 `Arc<dyn Any>` 包着的 `Arc<dyn AudioPorts>`（端口类型只有本域认识，
/// kit 与宿主都不能把它裸存进表），故这里向下转型后克隆内层 `Arc`。
#[cfg(feature = "common-host")]
pub fn ports_for(state: &WasmPluginState) -> Arc<dyn ports::AudioPorts> {
    match state
        .host
        .domain_ports(DOMAIN)
        .and_then(wasmnest_host_kit::ports::downcast_domain_ports::<Arc<dyn ports::AudioPorts>>)
    {
        Some(ports) => Arc::clone(&ports),
        None => ports::ports(),
    }
}

/// 取进程级引擎；未装配时返回显性错误（fail-visible，不静默给空数据）
#[cfg(feature = "common-host")]
fn hub_or_error() -> Result<Arc<AudioHub>, String> {
    registry::try_hub().ok_or_else(|| {
        "audio engine is not installed: the host must call `plugin_binding::install_hub` during boot"
            .to_string()
    })
}

// ==================== 宿主绑定层（Host trait 实现，`common-host` feature） ====================
//
// 每条 WIT 原语 = 一条转调：取端口 → 取引擎 → 域原语 → 按 WIT `result` 形状返回。
// 权限门与参数仲裁都在 `primitives` 内（随实现同层，便于无 WIT 测试）。

#[cfg(feature = "common-host")]
impl wasmnest::audio::host_audio::Host for WasmPluginState {
    fn status(&mut self, stream_id: String) -> Result<String, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::audio_status(&ports, &self.plugin_id, &hub, &stream_id)
    }

    fn list_devices(&mut self) -> Result<Vec<wasmnest::audio::host_audio::DeviceInfo>, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::audio_list_devices(&ports, &self.plugin_id, &hub).map(|devices| {
            devices
                .into_iter()
                .map(|device| wasmnest::audio::host_audio::DeviceInfo {
                    id: device.id.as_str().to_string(),
                    name: device.name,
                    is_default: device.is_default,
                    max_input_channels: u32::from(device.max_input_channels),
                    sample_rates: device.sample_rates,
                })
                .collect()
        })
    }

    fn open(&mut self, config_json: String) -> Result<String, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::audio_open(&ports, &self.plugin_id, &hub, &config_json)
    }

    fn start(&mut self, stream_id: String) -> Result<(), String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::audio_start(&ports, &self.plugin_id, &hub, &stream_id)
    }

    fn stop(&mut self, stream_id: String) -> Result<(), String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::audio_stop(&ports, &self.plugin_id, &hub, &stream_id)
    }

    fn close(&mut self, stream_id: String) -> Result<(), String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::audio_close(&ports, &self.plugin_id, &hub, &stream_id)
    }

    fn ring_fetch(
        &mut self,
        stream_id: String,
        from_offset: u64,
        max_bytes: u32,
    ) -> Result<wasmnest::audio::host_audio::RingFetchResult, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        let fetched = primitives::audio_ring_fetch(
            &ports,
            &self.plugin_id,
            &hub,
            &stream_id,
            from_offset,
            max_bytes,
        )?;
        // WIT 的记录没有 option：追平时返回「空 data + 原游标」（契约文档写明的形状）
        Ok(match fetched {
            Some(ring) => wasmnest::audio::host_audio::RingFetchResult {
                data: ring.data,
                next_offset: ring.next_offset,
                truncated: ring.truncated,
            },
            None => wasmnest::audio::host_audio::RingFetchResult {
                data: Vec::new(),
                next_offset: from_offset,
                truncated: false,
            },
        })
    }

    fn level(
        &mut self,
        stream_id: String,
    ) -> Result<Option<wasmnest::audio::host_audio::LevelSnapshot>, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::audio_level(&ports, &self.plugin_id, &hub, &stream_id).map(|level| {
            level.map(|snapshot| wasmnest::audio::host_audio::LevelSnapshot {
                rms: snapshot.rms,
                peak: snapshot.peak,
                window_samples: snapshot.window_samples,
            })
        })
    }
}

#[cfg(test)]
mod tests;
