//! WasmNest 浏览器渲染能力域（`host-browser`，1 条原语）
//!
//! 把「导航 + 执行页面脚本 + 声明式 CSS 提取」做成应用无关的宿主机制：
//! 插件只传 URL 与选择器，拿回文本与结构化条目；浏览器进程由端实现经端口
//! 注入，能力域不携带任何端实现或浏览器依赖。
//!
//! ## 分层
//!
//! ```text
//!   guard.rs    闸门：协议白名单 / 私网裁决 / 超时收敛 / 选择器形状
//!   script.rs   机制：页面内固定提取脚本的生成与输出解析（相对链接绝对化）
//!   limits.rs   机制：文本按 UTF-8 边界截断 / 条目条数截断 / 显性 truncated
//!   service.rs  流程：权限门 → 闸门 → 脚本 → 端渲染 → 解析 → 收敛
//!   ports.rs    边界：权限判定 / 私网授权 / 端渲染实现
//!   error.rs    契约：稳定错误码与分类
//!   lib.rs      常驻常量 + `common-host` 下的 WIT 绑定与能力模块自报
//! ```
//!
//! ## 默认形态
//!
//! `default = []`：纯引擎机制 + 端口抽象，零 WIT、零 SDK、零 wasmtime、
//! 零 native 浏览器依赖，任何宿主可直接引用。`common-host` feature 才装配
//! `bindgen!` / `HostModule` / `inventory` / `impl Host`，装配后的 ABI、权限位、
//! 载荷形状与不开 feature 时逐字一致。
//!
//! ## 边界
//!
//! - 不接受任意脚本：选择器只作为 JSON 字面量注入固定提取逻辑；
//! - 不返回整页 HTML：只返回页面文本与结构化条目；
//! - 不解释业务语义：标题、时间文本、摘要原样返回；时间语义由调用方解析；
//! - 不携带端实现：桌面 sidecar / 移动 stub 都经 [`BrowserPorts`] 注入；
//! - 失败一律显性：闸门拒绝、后端错误与端口缺席都返回稳定错误码或 panic，
//!   不静默降级为空结果。
//!
//! ## 端可用性
//!
//! 契约双端同形，但能力只在提供真实后端的端可用；不支持的端把
//! [`BrowserErrorKind::Unsupported`] 映射为 `browser.unsupported`，调用方据此
//! 展示「此能力仅桌面可用」，而不是把失败当成网络错误重试。

pub mod error;
pub mod guard;
pub mod limits;
pub mod model;
pub mod ports;
pub mod script;
pub mod service;
pub mod wire;

pub use error::{BrowserError, BrowserErrorKind};
pub use guard::{ensure_public_ip, is_private_ip, is_private_url, validate_url, ValidatedRequest};
pub use limits::{MAX_HTML_BYTES, MAX_ITEMS, MAX_TEXT_BYTES};
pub use model::{BrowserRequest, BrowserResponse, ExtractedItem, ListSpec, PageSpec, WaitUntil};
pub use ports::{install, install_ports, BrowserPorts, RenderRequest, RenderedPage};
pub use service::fetch_rendered;
pub use wire::PERMISSION_NETWORK_BROWSER;

/// 本能力域 WIT 包全名（`namespace:name@version`）
///
/// 与 `wit/browser.wit` 的 `package` 行逐字一致（下方锁测试断言），也是宿主
/// `MODULE_INTERFACES` 各项的前缀。拆包后每个能力域独立版本：只在本包 WIT
/// 变更时 bump。
pub const WIT_PACKAGE: &str = "wasmnest:browser@0.0.1";

/// 能力模块名（宿主白名单键；纯字符串，默认可用）
pub const MODULE_NAME: &str = "browser";

/// 本模块提供的 guest interface 路径（与 WIT 契约逐字一致）
pub const MODULE_INTERFACES: &[&str] = &["wasmnest:browser@0.0.1/host-browser"];

/// 本模块读写的权限位（与权限词汇真源逐字一致）
pub const MODULE_PERMISSIONS: &[&str] = &[PERMISSION_NETWORK_BROWSER];

/// 支持的最低 ABI 下界
///
/// 新接口只在声明它的插件里出现，旧插件不会 import；下界取 1 表示不额外限制。
pub const MODULE_ABI_MIN: u32 = 1;

// ==================== 能力模块自报（WIT 绑定层，`common-host` feature） ====================

#[cfg(feature = "common-host")]
use wasmnest_host_kit::{HostModule, HostModuleDesc, ModuleEntry, WasmPluginState};
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

/// 浏览器能力域模块
#[cfg(feature = "common-host")]
pub struct BrowserModule;

#[cfg(feature = "common-host")]
impl HostModule for BrowserModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        wasmnest::browser::host_browser::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
    }
}

/// getter：让 guest 侧 import 取到可变的状态引用
#[cfg(feature = "common-host")]
type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

/// 静态单例（供 `inventory::submit!` 取址）
#[cfg(feature = "common-host")]
static MODULE: BrowserModule = BrowserModule;

// 能力模块自报（linker-section 静态）
//
// **依赖前提**：宿主必须有强制引用本 crate 的一行（例如 `use
// wasmnest_server_browser as _;`），否则本 rlib 不进最终二进制、静态不执行，
// 注册丢失，guest 会在实例化期报「无该 import」。不开 `common-host` 的引用方
// 不应注册——它没有插件宿主机制。
#[cfg(feature = "common-host")]
inventory::submit! {
    ModuleEntry { module: &MODULE }
}

#[cfg(feature = "common-host")]
bindgen!({
    // provider 侧绑定：宿主自己的 `wasmnest` 模块是 guest 视角（import 是调用
    // 函数，不是 `Host` trait + `add_to_linker`），能力 crate 要自己装配就必须
    // 生成 provider 侧。
    //
    // 由此产生的硬约束：本 crate 与宿主各自生成的
    // `wasmnest::browser::host_browser::Host` 是同名但不同类型的 trait。宿主必须
    // 同时删掉自己的 browser `Host` impl 与 `add_to_linker` 行，否则同一个
    // interface 被注册两次，装配期报重复注册。
    path: "wit/browser.wit",
    world: "cap-browser",
    // 与既有能力域同款：全部导出绑定生成 async 变体（wasmtime async store 要求）。
    // cap-browser 无 export 成员，此配置无生效对象。
    exports: { default: async },
});

// ==================== 宿主绑定层（Host trait 实现，`common-host` feature） ====================

#[cfg(feature = "common-host")]
use wasmnest::browser::host_browser as wit;

#[cfg(feature = "common-host")]
impl wit::Host for WasmPluginState {
    fn fetch_rendered(&mut self, req: wit::Request) -> Result<wit::Response, String> {
        let request = BrowserRequest {
            url: req.url,
            wait_until: from_wit_wait_until(req.wait_until),
            timeout_ms: req.timeout_ms,
            allow_private_network: req.allow_private_network,
            extract_list: req.extract_list.map(|spec| ListSpec {
                item: spec.item,
                title: spec.title,
                url: spec.url,
                time: spec.time,
                summary: spec.summary,
            }),
            extract_page: req.extract_page.map(|page| PageSpec {
                content: page.content,
            }),
        };
        let ports = ports::ports();
        let response = fetch_rendered(ports.as_ref(), &self.plugin_id, request)
            .map_err(|error| error.to_string())?;
        Ok(into_wit_response(response))
    }
}

#[cfg(feature = "common-host")]
fn from_wit_wait_until(value: wit::WaitUntil) -> WaitUntil {
    match value {
        wit::WaitUntil::Load => WaitUntil::Load,
        wit::WaitUntil::DomContentLoaded => WaitUntil::DomContentLoaded,
        wit::WaitUntil::NetworkIdle => WaitUntil::NetworkIdle,
    }
}

#[cfg(feature = "common-host")]
fn into_wit_response(response: BrowserResponse) -> wit::Response {
    wit::Response {
        status: response.status,
        final_url: response.final_url,
        title: response.title,
        text: response.text,
        content_text: response.content_text,
        items: response
            .items
            .into_iter()
            .map(|item| wit::ExtractedItem {
                title: item.title,
                url: item.url,
                time_text: item.time_text,
                summary: item.summary,
            })
            .collect(),
        truncated: response.truncated,
    }
}

#[cfg(test)]
mod wit_package_lock {
    /// 常量 ↔ 分片真源 package 行（两侧任一手改即红）
    #[test]
    fn wit_package_matches_slice_package_line() {
        let raw = include_str!("../wit/browser.wit");
        let line = raw
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("package "))
            .expect("WIT 分片缺 package 行");
        assert_eq!(line, format!("package {};", super::WIT_PACKAGE));
    }

    /// 宿主模块接口路径必须属于本包（包名 / 版本漂移 = 运行期 import 失配）
    #[test]
    fn module_interfaces_belong_to_wit_package() {
        for iface in super::MODULE_INTERFACES {
            assert!(
                iface.starts_with(&format!("{}/", super::WIT_PACKAGE)),
                "MODULE_INTERFACES 项 {iface} 不属于 {}",
                super::WIT_PACKAGE
            );
        }
    }

    /// 描述符权限位必须与 wire 副本同值
    #[test]
    fn module_permissions_match_the_wire_copy() {
        assert_eq!(
            super::MODULE_PERMISSIONS,
            &[super::PERMISSION_NETWORK_BROWSER]
        );
    }

    /// 契约的 world 名与接口名固定（端组合按此拼装）
    #[test]
    fn contract_declares_the_expected_world_and_interface() {
        let raw = include_str!("../wit/browser.wit");
        assert!(raw.contains("interface host-browser"));
        assert!(raw.contains("world cap-browser"));
        assert!(raw.contains("fetch-rendered: func(req: request) -> result<response, string>"));
    }
}
