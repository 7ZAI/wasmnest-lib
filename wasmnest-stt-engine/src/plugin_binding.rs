//! host-stt 能力域接线（模型 / 会话 / 任务 / 模型管理 + 模块自报）
//!
//! ## 分层
//!
//! ```text
//!   本文件        接线（WIT Host 实现 + 模块自报 + 端口取用）
//!   primitives.rs 域原语（权限门 / 句柄形状 / 引擎调用 / 错误转写）
//!   registry.rs   进程级引擎持有者 + 生命周期回收面
//!   ports.rs      边界：权限门与本地导入路径授权（宿主才有的两件事）
//! ```
//!
//! 引擎（[`crate::hub::SttHub`]）与后端（[`crate::backend::SttBackend`]）都在本
//! crate 内、默认形态可用；本层只把「WIT 调用」翻译成「引擎调用」。
//!
//! ## 脱绑形态
//!
//! WIT 绑定层（`DESC` / `HostModule` / `inventory::submit!` / `bindgen!` / `impl Host`）
//! 以 `#[cfg(feature = "common-host")]` 门控：桌面宿主开 feature 后行为逐字不变；
//! 无 feature 的宿主拿纯引擎与域原语，描述符字段值拆成默认可用的纯字符串常量。

/// 宿主能力端口（权限门 + 导入路径授权）
pub mod ports;

/// 域原语（WIT 原语的机制实现；无 WIT 类型，可在默认形态测试）
pub mod primitives;

/// 进程级引擎持有者 + 生命周期回收面
pub mod registry;

/// [`ports::install_ports`] 的再导出（宿主 adapter 需要直接装**已构造好的**端口对象）
pub use ports::install_ports;
/// 引擎装配与生命周期面（宿主开机 / 停用 / 关停路径）
pub use registry::{
    close_all, install_hub, job_count, live_count, purge_for_plugin, session_count,
};

// ==================== 描述符纯字符串常量（默认形态可用） ====================

/// 能力模块名（宿主白名单键）
pub const MODULE_NAME: &str = "stt";

/// 能力模块接口路径（与 WIT 契约逐字一致）
pub const MODULE_INTERFACES: &[&str] = &["wasmnest:stt@0.0.1/host-stt"];

/// 能力模块权限位（`stt:infer` / `stt:model`）
pub const MODULE_PERMISSIONS: &[&str] = &["stt:infer", "stt:model"];

/// ABI 下界（全新 interface；早于该版本的插件不会 import 本接口）
pub const MODULE_ABI_MIN: u32 = 1;

/// 能力域名（宿主上下文里的键；`HostPorts::domain_ports`）
pub const DOMAIN: &str = "stt";

/// 装配端口与引擎的便捷入口（无头测试 / 最小宿主用）
pub fn install<P: ports::SttPorts + 'static>(ports: P, hub: std::sync::Arc<crate::hub::SttHub>) {
    ports::install_ports(std::sync::Arc::new(ports));
    registry::install_hub(hub);
}

// ==================== 能力模块自报（WIT 绑定层，`common-host` feature） ====================

#[cfg(feature = "common-host")]
use wasmnest_host_kit::{DomainHooks, HostModule, HostModuleDesc, WasmPluginState};
#[cfg(feature = "common-host")]
use wasmtime::component::{bindgen, Linker};

/// 能力模块描述符（机制面：接口路径 / 权限位 / ABI 下界）
#[cfg(feature = "common-host")]
pub const DESC: HostModuleDesc = HostModuleDesc {
    name: MODULE_NAME,
    interfaces: MODULE_INTERFACES,
    permissions: MODULE_PERMISSIONS,
    abi_min: MODULE_ABI_MIN,
};

/// 本地语音识别能力域模块
#[cfg(feature = "common-host")]
pub struct SttModule;

#[cfg(feature = "common-host")]
impl HostModule for SttModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        wasmnest::stt::host_stt::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
    }
}

/// getter：让 guest 侧 import 取到可变的状态引用（与其它能力域接线同款）
#[cfg(feature = "common-host")]
type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

/// 静态单例（供 `inventory::submit!` 取址）
#[cfg(feature = "common-host")]
static MODULE: SttModule = SttModule;

// 能力模块自报（linker-section 静态）
//
// 依赖前提：宿主必须有一行强制引用本 crate，否则本 rlib 不进最终二进制、
// 静态不执行 ⇒ 注册丢失，且 guest 会在实例化期报「无该 import」。
#[cfg(feature = "common-host")]
wasmnest_host_kit::submit_module!(MODULE);

/// 停用期回调：取消本插件的在途任务、丢弃会话与任务历史
#[cfg(feature = "common-host")]
fn on_plugin_purge(plugin_id: &str) {
    registry::purge_for_plugin(plugin_id);
}

/// 生命周期钩子自报（只关心停用回收；本域没有 manifest 配额声明）
#[cfg(feature = "common-host")]
pub static HOOKS: DomainHooks = DomainHooks {
    name: MODULE_NAME,
    on_manifest_load: None,
    on_plugin_purge: Some(on_plugin_purge),
};

#[cfg(feature = "common-host")]
wasmnest_host_kit::submit_hooks!(HOOKS);

#[cfg(feature = "common-host")]
bindgen!({
    // provider 侧绑定：本 crate 自持分片 `wit/stt.wit`（`world cap-stt`），
    // 不读桌面 SDK 生成物目录（端组合在平台仓 compose.json）。
    path: "wit/stt.wit",
    world: "cap-stt",
    // 与宿主同款：全部导出绑定生成 async 变体（wasmtime async store 要求）。
    // cap-stt 无 export 成员，此配置无生效对象。
    exports: { default: async },
});

/// 取本插件实例该用的端口：**实例级优先**，未装配则回落到进程级装配
#[cfg(feature = "common-host")]
pub fn ports_for(state: &WasmPluginState) -> std::sync::Arc<dyn ports::SttPorts> {
    match state.host.domain_ports(DOMAIN).and_then(
        wasmnest_host_kit::ports::downcast_domain_ports::<std::sync::Arc<dyn ports::SttPorts>>,
    ) {
        Some(ports) => std::sync::Arc::clone(&ports),
        None => ports::ports(),
    }
}

/// 取进程级引擎；未装配时返回显性错误（fail-visible，不静默给空数据）
#[cfg(feature = "common-host")]
fn hub_or_error() -> Result<std::sync::Arc<crate::hub::SttHub>, String> {
    registry::try_hub().ok_or_else(|| {
        "stt engine is not installed: the host must call `plugin_binding::install_hub` during boot"
            .to_string()
    })
}

// ==================== 宿主绑定层（Host trait 实现，`common-host` feature） ====================

#[cfg(feature = "common-host")]
impl wasmnest::stt::host_stt::Host for WasmPluginState {
    fn open_session(&mut self, options_json: String) -> Result<String, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_open_session(&ports, &self.plugin_id, &hub, &options_json)
    }

    fn append(&mut self, session_id: String, pcm: Vec<u8>) -> Result<u64, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_append(&ports, &self.plugin_id, &hub, &session_id, &pcm)
    }

    fn finalize(&mut self, session_id: String) -> Result<String, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_finalize(&ports, &self.plugin_id, &hub, &session_id)
    }

    fn abort_session(&mut self, session_id: String) -> Result<bool, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_abort_session(&ports, &self.plugin_id, &hub, &session_id)
    }

    fn job_status(&mut self, job_id: String) -> Result<String, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_job_status(&ports, &self.plugin_id, &hub, &job_id)
    }

    fn job_result(&mut self, job_id: String) -> Result<String, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_job_result(&ports, &self.plugin_id, &hub, &job_id)
    }

    fn job_cancel(&mut self, job_id: String) -> Result<bool, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_job_cancel(&ports, &self.plugin_id, &hub, &job_id)
    }

    fn models_list(&mut self) -> Result<Vec<wasmnest::stt::host_stt::ModelInfo>, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_models_list(&ports, &self.plugin_id, &hub).map(|models| {
            models
                .into_iter()
                .map(|model| wasmnest::stt::host_stt::ModelInfo {
                    id: model.id,
                    name: model.name,
                    description: model.description,
                    languages: model.languages,
                    size_bytes: model.size_bytes,
                    installed: model.installed,
                    downloading: model.downloading,
                    recommended: model.recommended,
                })
                .collect()
        })
    }

    fn model_download(&mut self, model_id: String) -> Result<String, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_model_download(&ports, &self.plugin_id, &hub, &model_id)
    }

    fn model_status(
        &mut self,
        model_id: String,
    ) -> Result<wasmnest::stt::host_stt::DownloadStatus, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_model_status(&ports, &self.plugin_id, &hub, &model_id).map(|status| {
            wasmnest::stt::host_stt::DownloadStatus {
                model_id: status.model_id,
                state: status.state,
                downloaded_bytes: status.downloaded_bytes,
                total_bytes: status.total_bytes,
                message: status.message,
            }
        })
    }

    fn model_remove(&mut self, model_id: String) -> Result<bool, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_model_remove(&ports, &self.plugin_id, &hub, &model_id)
    }

    fn model_import(&mut self, model_id: String, path: String) -> Result<bool, String> {
        let ports = ports_for(self);
        let hub = hub_or_error()?;
        primitives::stt_model_import(&ports, &self.plugin_id, &hub, &model_id, &path)
    }
}

// 显式引用：确保本 crate 的 inventory 静态进入宿主二进制（宿主 adapter 也有一行，
// 两处都保留——任一处被删都仍能注册，且宿主 adapter 的那行是「能力 crate 被链接」
// 的直接证据）。
#[cfg(feature = "common-host")]
use wasmnest_host_kit as _;
