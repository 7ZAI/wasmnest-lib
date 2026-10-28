//! host-pty 能力域 —— 插件私有伪终端（6 条原语 + 能力模块自报）
//!
//! spec：`.scratch/2026-10-06-pty-capability-domain/spec.md`（D1/D2：引擎 crate
//! 升格为能力域 crate，WIT 接线随域机制整体迁出内核，边界走窄端口 trait）。
//!
//! **零业务代码红线（ADR 0022）**：本文件与 [`primitives`] / [`registry`] /
//! [`output`] 只做引擎原语与机制闸门；PTY 之外的任何解读（会话、终端产品线、AI…）
//! 全在插件侧。
//!
//! ## 分层
//!
//! ```text
//!   本文件        接线（6 条原语的宿主实现 + 能力模块自报 + 端口取用）
//!   primitives.rs 域机制（创建 / 数据面 / 拉取 / 终止 / 退出监听）
//!   registry.rs  句柄表 + 配额表 + 回收面 + 退出事件组装
//!   output.rs    限频唤醒装饰器
//!   ports.rs     边界：权限门 / 总线投递 / 配置快照 / 异步桥 / 任务派生
//! ```
//!
//! 宿主侧只剩一个 adapter（票 02 批次 02 起住宿主
//! `桌面宿主 src-tauri/src/plugin/pty.rs` 的 `HostPtyPorts`，原
//! `wasm_core::host_api::pty`）与一次开机装配调用——与 http / ws / peer-net / mdns
//! 四域同形。
//!
//! **脱绑（能力域脱绑 P4）**：WIT 绑定层（`DESC` / `HostModule` / `inventory::submit!` /
//! `ports_for` / `bindgen!` / `impl Host`）以 `#[cfg(feature = "common-host")]` 门控——
//! 桌面宿主开 feature 后行为逐字不变；无 feature 的宿主（移动端 / 无头）拿纯引擎：
//! 域机制（[`primitives`] / [`registry`] / [`output`]）、端口、装配（[`install`] /
//! [`ports::install_ports`]）默认全部可用。描述符字段值（模块名 / 接口路径 / 权限位）
//! 拆为默认可用的纯字符串常量（[`MODULE_NAME`] 等），宿主白名单校验在无头态也能引用。

use std::sync::Arc;

use crate::plugin_binding::ports::PtyPorts;

/// 宿主能力端口（边界层；见 [`ports`] 模块文档）
pub mod ports;

/// 域机制（6 条原语 + 参数仲裁 + 退出监听）
pub mod primitives;

/// 句柄注册表 / 配额表 / 回收面
pub mod registry;

/// 输出可用通知（限频唤醒装饰器）
pub mod output;

/// [`ports::install_ports`] 的再导出（宿主 adapter 需要直接装**已构造好的**端口对象：
/// 同一份要同时登记进程级与实例级，不能经 [`install`] 新建）
pub use ports::install_ports;

/// 宿主生命周期面（停用回收 / 关停全量回收 / 在册计数 / 加载期配额登记）的再导出
///
/// **为什么经本层再导出**：这四件事的调用方是宿主（`manager::host::activation` /
/// `manager::loader` / `system::lifecycle`），它们问的是「这个能力域」，不是「这个
/// 域的注册表模块」——路径止于 `plugin_binding`，域内分层不外泄。
pub use registry::{
    kill_all_registered, kill_all_registered_with_ports, live_count, purge_for_plugin,
    purge_for_plugin_with_ports, register_quota,
};

// ==================== 能力模块自报（WIT 绑定层，`common-host` feature） ====================

// WIT 绑定层依赖（host-kit / wasmtime）只随 `common-host` feature 编译：
// 能力域默认形态 = 纯引擎机制（零 WIT 依赖），任何宿主可直接引用。
#[cfg(feature = "common-host")]
use wasmnest_host_kit::{DomainHooks, HostModule, HostModuleDesc, ModuleEntry, WasmPluginState};
#[cfg(feature = "common-host")]
use wasmtime::component::{bindgen, Linker};

/// 能力模块名（`host-pty`；纯字符串，默认可用——宿主白名单校验 / 无头态引用）
pub const MODULE_NAME: &str = "pty";

/// 能力模块接口路径（与 WIT 契约逐字一致；纯字符串，默认可用）
pub const MODULE_INTERFACES: &[&str] = &["wasmnest:plugin@0.0.2/host-pty"];

/// 能力模块权限位（`pty:spawn` / `pty:io`；纯字符串，默认可用）
pub const MODULE_PERMISSIONS: &[&str] = &["pty:spawn", "pty:io"];

/// ABI 下界：`host-pty` 的 6 条原语自 ABI v16 追加，低于该版本的插件不导入本 interface
pub const MODULE_ABI_MIN: u32 = 16;

/// 能力模块描述符（机制面：接口路径 / 权限位 / ABI 下界；**禁带产品名词**）
///
/// `abi_min = 16`：`host-pty` 的 6 条原语自 ABI v16 追加，低于该版本的插件不导入
/// 本 interface。
///
/// 字段值取上方默认可用的纯字符串常量（宿主无头态也能引用描述符形状）。
#[cfg(feature = "common-host")]
pub const DESC: HostModuleDesc = HostModuleDesc {
    name: MODULE_NAME,
    interfaces: MODULE_INTERFACES,
    permissions: MODULE_PERMISSIONS,
    abi_min: MODULE_ABI_MIN,
};

/// PTY 能力域模块（`host-pty`，6 条原语）
#[cfg(feature = "common-host")]
pub struct PtyModule;

#[cfg(feature = "common-host")]
impl HostModule for PtyModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        wasmnest::plugin::host_pty::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
    }
}

/// getter：让 guest 侧 import 取到可变的状态引用（与宿主既有接线同款）
#[cfg(feature = "common-host")]
type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

/// 静态单例（供 `inventory::submit!` 取址）
#[cfg(feature = "common-host")]
static MODULE: PtyModule = PtyModule;

// 能力模块自报（linker-section 静态）
//
// **依赖前提**：宿主必须有一行强制引用本 crate（见 `wasm_core::manager::runtime::component`
// 的 `use wasmnest_pty_engine as _;`），否则本 rlib 不进最终二进制、静态不执行 ⇒
// 注册丢失，且 guest 会在实例化期报「无该 import」。无 `common-host` feature 的宿主
// （移动端 / 无头）**不应**注册——它没有插件宿主机制，桌面侧强制引用行同步
// `#[cfg(feature = "common-host")]`。
#[cfg(feature = "common-host")]
inventory::submit! {
    ModuleEntry { module: &MODULE }
}

/// 装载期回调：从 manifest **原文**解析本域配额（`ptyQuota`）并**仲裁区间**
///
/// **为什么内核只下发原文**：manifest 字段的解释权属于能力域——内核一旦解释
/// 「pty 配额是多少」就是在解释产品声明（AGENTS §5.1 B6）。字段名随 SDK 演进时
/// 只改本函数，内核与 host-kit 都不动。
///
/// **区间仲裁也归本域（票 02 批次 03）**：`1..=PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN`
/// 这条判据原在内核 `manager/validation.rs::validate_pty_quota`（内核为此要读 SDK
/// manifest 的 `pty_quota` 字段，等于替本域解释声明语义）。判据落在装载期而不是
/// `spawn`：配额是自我声明的静态事实，装载时就能判定，拖到运行期等于把配置错误
/// 转嫁成「第 N+1 条会话创建失败」的产品故障。越界与 0 一律 `Err` ⇒ 内核不装载该
/// 插件，**不夹取**到上限（同 `PLUGIN_PTY_RING_MAX_BYTES` 口径：静默降级会让插件按
/// 自己声明的并发数规划业务、实际却少得多）。
///
/// 解析失败（字段缺失 / 类型不符）落默认档（`register_quota` 的 `None` 分支），
/// 与「未声明」同形——既有插件零迁移。
#[cfg(feature = "common-host")]
use wasmnest_server_base::constants::{
    PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN, PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN,
};

#[cfg(feature = "common-host")]
fn on_manifest_load(plugin_id: &str, manifest_json: &str) -> Result<(), String> {
    let declared: Option<usize> = serde_json::from_str::<serde_json::Value>(manifest_json)
        .ok()
        .and_then(|value| value.get("ptyQuota").cloned())
        .and_then(|value| {
            serde_json::from_value::<Option<usize>>(value)
                .ok()
                .flatten()
        });
    if let Some(quota) = declared {
        if quota == 0 || quota > PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN {
            // 先判后动：拒绝时不登记（不让越界值残留在配额表）
            return Err(format!(
                "plugin.json ptyQuota out of range ({quota}); allowed 1..={PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN}, omit the field for the default {PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN}"
            ));
        }
    }
    registry::register_quota(plugin_id, declared);
    Ok(())
}

/// 停用期回调：回收本插件的全部私有 PTY
///
/// 适配器：域内 `purge_for_plugin` 返回回收计数（关停面要用），而钩子契约是
/// `fn(&str)`——回收计数对「单个插件停用」没有消费者，在此处就地记 debug 日志
/// 吸收，不让返回值形状反向污染通用契约。
#[cfg(feature = "common-host")]
fn on_plugin_purge(plugin_id: &str) {
    let reclaimed = registry::purge_for_plugin(plugin_id);
    tracing::debug!(
        plugin_id = %plugin_id,
        count = reclaimed,
        "host-pty: 停用回收完成"
    );
}

/// 生命周期钩子自报（票 02 批次 01 机制）
///
/// 内核侧改为遍历 `DomainHooksRegistry`，**不再点名本域**——这是内核能去掉对本
/// crate 依赖的前提（批次 02 第三步摘依赖）。
#[cfg(feature = "common-host")]
pub static HOOKS: DomainHooks = DomainHooks {
    name: MODULE_NAME,
    on_manifest_load: Some(on_manifest_load),
    on_plugin_purge: Some(on_plugin_purge),
};

#[cfg(feature = "common-host")]
wasmnest_host_kit::submit_hooks!(HOOKS);

/// 装载期配额仲裁的域侧单测（原内核 `manager/validation.rs` 两条用例迁此，
/// 票 02 批次 03：判据随真源一起搬离内核）
#[cfg(all(test, feature = "common-host"))]
mod manifest_quota_tests {
    use super::*;
    use crate::plugin_binding::registry::quota_of;
    use wasmnest_server_base::constants::PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN as DEFAULT_MAX;
    use wasmnest_server_base::constants::PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN as CEILING;

    /// 带 `ptyQuota` 声明的 manifest 原文（键名就是 SDK 的 camelCase `ptyQuota`）
    fn manifest(quota: &str) -> String {
        format!(
            r#"{{"id":"com.wasmnest.quota","name":"quota","version":"1.0.0","ptyQuota":{quota}}}"#
        )
    }

    /// 正例：缺省（= 默认档，既有插件零迁移）与区间两端；
    /// 反例：0 与越上限——一律拒绝装载，且不夹取、不登记
    #[test]
    fn quota_accepts_absent_and_in_range_rejects_out_of_range() {
        let owner = "pty-test.manifest-quota";
        on_manifest_load(
            owner,
            r#"{"id":"com.wasmnest.quota","name":"quota","version":"1.0.0"}"#,
        )
        .expect("缺省即默认档，不得拒绝");
        assert_eq!(quota_of(owner), DEFAULT_MAX, "未声明 ⇒ 默认档");

        on_manifest_load(owner, &manifest("1")).expect("声明下界可装载");
        assert_eq!(quota_of(owner), 1, "声明值必须原样生效");
        on_manifest_load(owner, &manifest(&CEILING.to_string())).expect("声明上界可装载");
        assert_eq!(quota_of(owner), CEILING);

        for bad in [0, CEILING + 1, 10_000] {
            let err = on_manifest_load(owner, &manifest(&bad.to_string()))
                .err()
                .unwrap_or_else(|| panic!("ptyQuota={bad} 必须被拒绝"));
            assert!(
                err.contains(&bad.to_string()) && err.contains("ptyQuota"),
                "错误必须点名越界值与字段名，got: {err}"
            );
        }
        assert_eq!(
            quota_of(owner),
            CEILING,
            "被拒的声明不得改写在册配额（先判后动）"
        );
    }
}

#[cfg(feature = "common-host")]
bindgen!({
    // provider 侧绑定：宿主自己的 `wasmnest` 模块是 **guest 视角**（import 是调用
    // 函数，不是 `Host` trait + `add_to_linker`），能力 crate 要自己装配就必须生成
    // provider 侧。
    //
    // ⚠️ 由此产生的**硬约束**：本 crate 与宿主各自生成的
    // `wasmnest::plugin::host_pty::Host` 是**同名但不同类型**的 trait。宿主必须
    // 同时删掉自己的 pty `Host` impl 与 `add_to_linker` 行，否则同一个 interface
    // 被注册两次 → 装配期 `defined twice`（本次迁移同批删除，见 spec §3.2）。
    // 票 05：契约面脱端——bindgen 改指本 crate 自持分片 `wit/pty.wit`
    // （`world cap-pty`，票 03 起兼作端组合的 cap 真源，compose.json caps.pty 指向它），
    // 不再读桌面 SDK 生成物目录（桌面宿主绑整 world 是端组合根的本分，ADR 0045）。
    path: "wit/pty.wit",
    world: "cap-pty",
    // 与宿主同款：全部导出绑定生成 async 变体（wasmtime async store 要求）。
    // cap-pty 无 export 成员，此配置无生效对象（实测编译绿，票 05 实施记录）
    exports: { default: async },
});

// ==================== 端口取用 ====================

/// 能力域名（宿主上下文里的键；[`wasmnest_host_kit::ports::HostPorts::domain_ports`]）
pub const DOMAIN: &str = "pty";

/// 装配端口的便捷入口（宿主开机期调用）
pub fn install<P: PtyPorts + 'static>(ports: P) {
    ports::install_ports(Arc::new(ports));
}

/// 取本插件实例该用的端口：**实例级优先**，未装配则回落到进程级装配
///
/// 为什么要两级（见 `wasmnest_host_kit::ports` 模块文档）：进程级只有一格，而一个进程
/// 可以有多份宿主上下文（无头测试每个用例一份）。实例级让端口与**本实例的**权限管理器
/// / 消息总线绑定——guest 调 `host-pty` 原语时的权限判定必须落在**本实例**的
/// PermissionManager 上，否则多上下文场景会读到别人的授权。
///
/// 宿主注入的是 `Arc<dyn Any>` 包着的 `Arc<dyn PtyPorts>`（能力域的端口类型只有
/// 能力域自己认识，kit 与宿主都不能把它裸存进表），故这里向下转型后**克隆内层 Arc**。
///
/// 依赖 `WasmPluginState`（host-kit 类型），随 `common-host` feature 编译。
#[cfg(feature = "common-host")]
pub fn ports_for(state: &WasmPluginState) -> Arc<dyn PtyPorts> {
    match state
        .host
        .domain_ports(DOMAIN)
        .and_then(wasmnest_host_kit::ports::downcast_domain_ports::<Arc<dyn PtyPorts>>)
    {
        Some(ports) => Arc::clone(&ports),
        None => ports::ports(),
    }
}

// ==================== 宿主绑定层（Host trait 实现，`common-host` feature） ====================
//
// 每个接口方法 = 一条 WIT 原语。权限门在 [`primitives`] 内的域函数里（随实现同迁，
// 经端口问宿主结果），此层只做「取端口 → 转调 → 按 WIT `result` 形状返回」。

#[cfg(feature = "common-host")]
impl wasmnest::plugin::host_pty::Host for WasmPluginState {
    fn spawn(&mut self, config_json: String) -> Result<String, String> {
        primitives::pty_spawn(&ports_for(self), &self.plugin_id, &config_json)
    }

    fn write(&mut self, pty_id: String, data: Vec<u8>) -> Result<(), String> {
        primitives::pty_write(&ports_for(self), &self.plugin_id, &pty_id, &data)
    }

    fn resize(&mut self, pty_id: String, cols: u16, rows: u16) -> Result<(), String> {
        primitives::pty_resize(&ports_for(self), &self.plugin_id, &pty_id, cols, rows)
    }

    fn kill(&mut self, pty_id: String) -> Result<(), String> {
        primitives::pty_kill(&ports_for(self), &self.plugin_id, &pty_id)
    }

    fn ring_fetch(
        &mut self,
        pty_id: String,
        from_offset: u64,
        max_bytes: u32,
    ) -> Result<Option<wasmnest::plugin::host_pty::RingFetchResult>, String> {
        primitives::pty_ring_fetch(
            &ports_for(self),
            &self.plugin_id,
            &pty_id,
            from_offset,
            max_bytes,
        )
        .map(|fetched| {
            fetched.map(|ring| wasmnest::plugin::host_pty::RingFetchResult {
                data: ring.data,
                next_offset: ring.next_offset,
                truncated: ring.truncated,
            })
        })
    }

    fn is_running(&mut self, pty_id: String) -> Result<bool, String> {
        primitives::pty_is_running(&ports_for(self), &self.plugin_id, &pty_id)
    }
}
#[cfg(test)]
mod tests;
