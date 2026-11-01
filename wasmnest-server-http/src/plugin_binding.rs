//! host-http 能力域 —— HTTP 协议能力（出站 fetch 1 条；服务端域端点注册引擎 API）
//!
//! spec：`.scratch/2026-10-04-wasm-core-lib-split/spec.md` §3.1 / §7 D10；票 06
//! （自宿主 host_api 域的 http 实现整体迁入本 crate，入站 + 出站同 crate 两个模块）。
//!
//! **ADR 0052 D4 归位（票 03）**：`host-http-endpoint`（桌面扩展）的 **WIT 声明**
//! 归桌面 `wit-src/cap-http.wit`（world `cap-http-endpoint`，T-02 落位）、**`impl Host`**
//! 归桌面宿主 `src-tauri/src/plugin/http.rs`；本文件只保留**服务器引擎 API**
//! （[`http_register_endpoint`] / [`http_unregister_endpoint`] / [`purge_for_plugin`]）
//! 与路由表 [`crate::registry`]——后者被服务器自身的 `routes.rs` /
//! `middleware/auth_gateway.rs` 与生命周期回收直接消费，是服务器引擎基础设施，
//! 不是端扩展的 WIT 绑定面（逐项盘点见票 03 Comments）。
//!
//! **零业务代码红线（D1）**：本模块只做引擎原语——端点登记与属主仲裁、句柄铸造、
//! 权限门位置、载荷形状校验、出站请求执行；HTTP 语义之外的任何解读（会话、供应商
//! 协议、AI 格式…）全在插件侧。本域一律以 JSON 文本过界，不新增任何业务字段。
//!
//! ## 分层
//!
//! ```text
//!   本文件        入站机制 + WIT 接线（3 条原语的宿主实现 + 能力模块自报）
//!   egress.rs     出站机制（客户端池 / 跳转裁决 / 请求执行 / SSE 切分）
//!   ports.rs      边界：权限门 / 出站授权裁决 / 前端事件通道 / 异步桥
//! ```
//!
//! **脱绑（能力域脱绑 P1）**：本文件混住机制面与 WIT 绑定层。机制面（端口 /
//! 出站 / 端点注册与注销 / 回收 / 装配）默认编译，任何宿主可用；WIT 绑定层
//! （`bindgen!` / `HostModule` / `inventory::submit!` / `impl Host`）以
//! `#[cfg(feature = "common-host")]` 门控——桌面宿主开 feature 后行为逐字不变
//! （ABI / WIT / 权限位 / 事件形状 / inventory 注册零变化），无 feature 的宿主
//! （移动端 / 无头）拿纯引擎。
//!
//! 宿主侧只剩一个 adapter（宿主 host_api 域的 http 适配器）与一次开机装配调用。
//!
//! ## 入站（服务端域，ABI v29；端点注册引擎 API）
//!
//! 插件在宿主 HTTP 服务器挂载端点：内部路径 `/api/plugin/<owner>/<path>`（命名空间
//! 段由宿主注入）+ 可选对外 URL 别名。端点表与冲突仲裁是**本 crate 既有**的
//! [`crate::registry`]（本域只做「权限门 + config 契约解析 + 属主仲裁」三件事，
//! 登记本身一次转发），fail-visible 语义不变：config 解析失败 / 形状非法 /
//! 冲突 → `Err`，**不覆盖在位者**。
//!
//! 本组的两个 `pub fn` 是服务器引擎的插件面 API（WIT-无关，默认形态编译）：
//! 桌面宿主的 `impl Host for host-http-endpoint`（`src/plugin/http.rs`）薄转发到这里；
//! crate 内单测（`plugin_binding/tests/inbound.rs`）也直接消费它们。

use std::sync::Arc;

use serde::Deserialize;

use crate::plugin_binding::ports::HttpPorts;
use crate::wire::{EndpointAuth, PERMISSION_NETWORK_HTTP};

/// 宿主能力端口（边界层；见 [`ports`] 模块文档）
pub mod ports;

/// 出站段（客户端池 / 跳转裁决 / 请求执行 / SSE 切分）
pub mod egress;

// ==================== 服务端域（ABI v29：插件动态路由注册） ====================

/// `register-endpoint` 的 config-json 契约（服务端域，camelCase）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndpointRegistrationConfig {
    /// 插件内相对端点段（宿主拼出 `/api/plugin/<plugin-id>/<path>`）
    path: String,
    /// 可选对外 URL 别名（支持 `{id}` 模板段）
    #[serde(default)]
    host: Option<String>,
    /// host 别名的允许方法（缺省 `["GET"]`）
    #[serde(default)]
    methods: Vec<String>,
    /// 认证档位："jwt"（缺省，最严）| "none"（免凭证）
    #[serde(default)]
    auth: Option<String>,
}

/// 注册插件 HTTP 端点（WIT `host-http.register-endpoint`，ABI v29 服务端域）
///
/// 权限门 `network:http`（与前端面 `http.registerEndpoint` 同权限位）；config 解析
/// 失败 / 形状非法 / 冲突仲裁 → `Err`（fail-visible，不覆盖在位者）。
/// 成功 → 返回端点句柄 `http-<uuid>`。
pub fn http_register_endpoint(
    ports: &Arc<dyn HttpPorts>,
    plugin_id: &str,
    config_json: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, PERMISSION_NETWORK_HTTP, "host_http_register_endpoint") {
        return Err("permission denied: network:http".to_string());
    }
    let config: EndpointRegistrationConfig =
        serde_json::from_str(config_json).map_err(|e| format!("http register-endpoint: invalid config: {e}"))?;
    // HTTP 面缺省档 = jwt（未声明即最严，与 manifest 声明面同一裁决）；
    // 未定义取值报错，绝不静默降级为较宽档位
    let auth = EndpointAuth::parse_with(config.auth.as_deref(), EndpointAuth::Jwt)
        .map_err(|e| format!("http register-endpoint: {e}"))?;
    let entry = crate::registry::register(plugin_id, &config.path, config.host.as_deref(), &config.methods, auth)?;
    Ok(entry.endpoint_id)
}

/// 注销插件 HTTP 端点（WIT `host-http.unregister-endpoint`，ABI v29 服务端域）
///
/// 属主仲裁：未知句柄 → `Ok(false)`（幂等）；他人句柄 → `Err`。
/// 插件停用时的自动回收另见 [`purge_for_plugin`]（该回收不设权限门——它是宿主
/// 生命周期动作，不是 guest 调用）。
pub fn http_unregister_endpoint(
    ports: &Arc<dyn HttpPorts>,
    plugin_id: &str,
    endpoint_id: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, PERMISSION_NETWORK_HTTP, "host_http_unregister_endpoint") {
        return Err("permission denied: network:http".to_string());
    }
    crate::registry::remove_if_owner(endpoint_id, plugin_id)
}

/// 回收指定插件的全部 HTTP 端点（插件停用/卸载时由宿主调用；只碰本人）
///
/// 不经权限门、不取端口：这是**宿主生命周期动作**（停用回收），与 guest 调用面
/// 不是一回事——停用时插件已不可调用任何原语。
pub fn purge_for_plugin(plugin_id: &str) -> usize {
    let entries = crate::registry::purge_for_plugin(plugin_id);
    entries.len()
}

// ==================== 能力模块自报（WIT 绑定层，`common-host` feature） ====================

// WIT 绑定层依赖（host-kit / wasmtime）只随 `common-host` feature 编译：
// 能力域默认形态 = 纯引擎机制（零 WIT 依赖），任何宿主可直接引用。
#[cfg(feature = "common-host")]
use wasmnest_host_kit::{HostModule, HostModuleDesc, ModuleEntry, WasmPluginState};
#[cfg(feature = "common-host")]
use wasmtime::component::{bindgen, Linker};

/// 能力模块名（宿主白名单键 = 装载期日志与错误文案里的模块名）
///
/// **常编译 pub**（票 02 批次 03）：adapter 迁宿主后白名单条目
/// （`expect_host_module!`）与装载期一致性核对改在宿主侧引用本常量。
pub const MODULE_NAME: &str = "http";

/// 本域提供的 WIT 接口（必须与拼装 package 逐字一致；改错即 guest import 失配）
///
/// ADR 0052 D2/D4：`host-http`（出站交集）契约真源在本 crate `wit/http.wit`；
/// 服务端域 `host-http-endpoint`（桌面扩展）的 WIT 声明与 `impl Host` 已归桌面
/// 宿主（本模块不再注册/声明它）。
pub const MODULE_INTERFACES: &[&str] = &["wasmnest:plugin@0.0.2/host-http"];

/// 本域的权限位（必须与 `wasmnest.wit` / SDK 权限表逐字一致）
pub const MODULE_PERMISSIONS: &[&str] = &["network:http"];

/// 能力模块描述符（机制面：接口路径 / 权限位 / ABI 下界；**禁带产品名词**）
///
/// `abi_min = 29`：本域入站服务端域两条原语在 ABI v29 追加（声明/实现已归桌面
/// 宿主模块，见模块头笔记）；保留常量值以避免宿主白名单元数据漂移。
#[cfg(feature = "common-host")]
const DESC: HostModuleDesc = HostModuleDesc {
    name: MODULE_NAME,
    interfaces: MODULE_INTERFACES,
    permissions: MODULE_PERMISSIONS,
    abi_min: 29,
};

/// HTTP 能力域模块（`host-http` 出站 fetch 1 条）
#[cfg(feature = "common-host")]
pub struct HttpModule;

#[cfg(feature = "common-host")]
impl HostModule for HttpModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        wasmnest::plugin::host_http::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
    }
}

/// getter：让 guest 侧 import 取到可变的状态引用（与宿主既有接线同款）
#[cfg(feature = "common-host")]
type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

/// 静态单例（供 `inventory::submit!` 取址）
#[cfg(feature = "common-host")]
static MODULE: HttpModule = HttpModule;

// 能力模块自报（linker-section 静态）
//
// **依赖前提**：宿主必须有一行强制引用本 crate（见宿主的组件运行时接线处），
// 否则本 rlib 不进最终二进制、静态不执行 ⇒ 注册丢失，且 guest 会在实例化期报
// 「无该 import」。无 `common-host` feature 的宿主（移动端 / 无头）**不应**
// 注册——它没有插件宿主机制，桌面侧强制引用行同步 `#[cfg(feature = "common-host")]`。
#[cfg(feature = "common-host")]
inventory::submit! {
    ModuleEntry { module: &MODULE }
}

/// 能力域名（宿主上下文里的键；[`wasmnest_host_kit::ports::HostPorts::domain_ports`]）
///
/// 纯字符串常量（无 WIT 依赖），默认可用：宿主 adapter 在 `common-host` 装配路径
/// 引用它。
pub const DOMAIN: &str = "http";

/// 停用期回调：清空本插件的全部动态路由（含对外 URL 别名与内部路径，只碰本人）
///
/// 适配器：域内 [`purge_for_plugin`] 返回回收计数（关停面要用），而钩子契约是
/// `fn(&str)`——计数对「单个插件停用」没有消费者，此处就地记 debug 日志吸收。
#[cfg(feature = "common-host")]
fn on_plugin_purge(plugin_id: &str) {
    let reclaimed = purge_for_plugin(plugin_id);
    tracing::debug!(
        plugin_id = %plugin_id,
        count = reclaimed,
        "host-http: 停用回收完成"
    );
}

/// 生命周期钩子自报（票 02 批次 01 机制，批次 03 本域接入）
///
/// 接入后内核 `manager/host/activation.rs` 不再直调本域回收入口——这是内核摘掉本域
/// adapter 的前提（另一处是 `HttpUnitExecutor` 的消费点，见票面「ws / http 实测」节）。
#[cfg(feature = "common-host")]
pub static HOOKS: wasmnest_host_kit::DomainHooks = wasmnest_host_kit::DomainHooks {
    name: MODULE_NAME,
    on_manifest_load: None,
    on_plugin_purge: Some(on_plugin_purge),
};

#[cfg(feature = "common-host")]
wasmnest_host_kit::submit_hooks!(HOOKS);

/// 装配端口的便捷入口（宿主开机期调用）
///
/// 纯 Rust（不依赖 `WasmPluginState`），默认可用：任何宿主持有端口实现即可装配。
pub fn install<P: HttpPorts + 'static>(ports: P) {
    ports::install_ports(Arc::new(ports));
}

/// [`ports::install_ports`] 的再导出（宿主 adapter 需要直接装**已构造好的**端口对象：
/// 同一份要同时登记进程级与实例级，不能经 `install` 新建）
pub use ports::install_ports;

/// 取本插件实例该用的端口：**实例级优先**，未装配则回落到进程级装配
///
/// 为什么要两级（见 `wasmnest_host_kit::ports` 模块文档）：进程级只有一格，而一个
/// 进程可以有多份宿主上下文（无头测试每个用例一份）；实例级让端口与**本实例的**
/// 权限管理器 / 出站授权闸门绑定，能力域代码不感知上下文数量。
///
/// 宿主注入的是 `Arc<dyn Any>` 包着的 `Arc<dyn HttpPorts>`（能力域的端口类型只有
/// 能力域自己认识，kit 与宿主都不能把它裸存进表），故这里向下转型后**克隆内层
/// Arc**（同形对象，多个实例共享一份 adapter，无副作用）。
///
/// 依赖 `WasmPluginState`（host-kit 类型），随 `common-host` feature 编译。
#[cfg(feature = "common-host")]
pub fn ports_for(state: &WasmPluginState) -> Arc<dyn HttpPorts> {
    match state
        .host
        .domain_ports(DOMAIN)
        .and_then(wasmnest_host_kit::ports::downcast_domain_ports::<Arc<dyn HttpPorts>>)
    {
        Some(ports) => Arc::clone(&ports),
        None => ports::ports(),
    }
}

#[cfg(feature = "common-host")]
bindgen!({
    // provider 侧绑定：宿主自己的 `wasmnest` 模块是 **guest 视角**（import 是调用
    // 函数，不是 `Host` trait + `add_to_linker`），能力 crate 要自己装配就必须生成
    // provider 侧。
    //
    // ⚠️ 由此产生的**硬约束**：本 crate 与宿主各自生成的
    // `wasmnest::plugin::host_http::Host` 是**同名但不同类型**的 trait。宿主必须
    // 同时删掉自己的 http `Host` impl 与 `add_to_linker` 行，否则同一个 interface
    // 被注册两次 → 装配期 `defined twice`。
    // 票 05：契约面脱端——bindgen 改指本 crate 自持分片 `wit/http.wit`
    // （`world cap-http` 只 import 出站 `host-http`；ADR 0052 D2/D4 后服务端域
    // `host-http-endpoint` 已移出本分片，声明在桌面 wit-src、impl 在桌面宿主），
    // 不再读桌面 SDK 生成物目录。
    path: "wit/http.wit",
    world: "cap-http",
    // 与宿主同款：全部导出绑定生成 async 变体（wasmtime async store 要求）。
    // cap-http 无 export 成员，此配置无生效对象（实测编译绿，票 05 实施记录）
    exports: { default: async },
});

// ==================== 宿主绑定层（Host trait 实现，`common-host` feature） ====================
//
// 每个接口方法 = 一条 WIT 原语。权限门在本 crate 内的域函数里（随实现同迁，
// 经端口问宿主结果），此层只做「取端口 → 转调 → 按 WIT `result` 形状返回」。

#[cfg(feature = "common-host")]
impl wasmnest::plugin::host_http::Host for WasmPluginState {
    fn fetch(&mut self, request_json: String) -> Result<Option<String>, String> {
        // may_prompt = true：插件主流程（guest 调用栈）可弹窗询问出站授权
        egress::http_fetch(&ports_for(self), &self.plugin_id, &request_json, true)
    }
}

/// v37 / ADR 0052 D4：`host-http-endpoint`（桌面扩展服务端域）的 `impl Host`
/// 已迁桌面宿主 `src-tauri/src/plugin/http.rs`（路径 B 模块 `http-endpoint`）——
/// 本模块不再生成/实现该 trait。

#[cfg(test)]
mod tests;
