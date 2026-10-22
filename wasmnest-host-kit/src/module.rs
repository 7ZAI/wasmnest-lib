//! 能力模块契约：把「一个 guest 可 import 的宿主 interface 的实现」表达成可自报的单元
//!
//! ## 解决的问题
//!
//! 改造前，宿主把 22 个 interface 的接线**逐行硬编码**在一个装配函数里（每个
//! interface 一行 `add_to_linker::<WasmPluginState, D>`）。新增一个能力域要改宿主
//! 装配代码——「实现搬进 crate」与「装配」被绑死，于是能力实现只能住在内核里。
//!
//! 本模块把两者拆开：能力 crate 用 `inventory::submit!` 自报，宿主一次收集后遍历
//! 装配。**加一个能力域 = 加一个 crate 依赖 + 一行白名单**，宿主装配代码不动。
//!
//! ## 描述符红线（AGENTS §5.1 B1/B5）
//!
//! [`HostModuleDesc`] 只允许三类机制属性：**接口路径 / 权限位 / ABI 下界**。
//! 任何产品名词（会话 / 终端 / 配对 / 设备 / 传输任务 / AI…）都不得进入描述符，
//! 否则模块注册表从「通用注册表」退化成业务容器（AGENTS §5.1.3 明列的宿主允许薄壳
//! 之一是「通用注册表与寻址」）。

use wasmtime::component::Linker;

use crate::state::WasmPluginState;

/// 能力模块描述符（只描述机制，禁带产品名词）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostModuleDesc {
    /// 模块名（白名单键；全局唯一，小写下划线风格，如 `sqlite` / `discovery`）
    pub name: &'static str,
    /// 本模块提供的 guest interface 路径（如 `wasmnest:plugin@0.0.2/host-plugin-database`；
    /// 版本化契约下为全名，运行期匹配不吃它——`verify_whitelist` 只比 `name`）
    pub interfaces: &'static [&'static str],
    /// 本模块读写的权限位（如 `database:query`）——用于装载期一致性核对
    pub permissions: &'static [&'static str],
    /// 支持的最低 ABI 版本（低于此值的能力面变更需在描述符里同步）
    pub abi_min: u32,
}

/// 一个可自报、可装配的宿主能力模块
///
/// 实现方是能力 crate（`packages/wasmnest-*` 的 `plugin_binding` 子模块）或各端宿主
/// adapter（`src-tauri/src/plugin/<domain>.rs`，路径 B 域）。
/// 宿主**不**持有这些实现的清单——清单由 [`crate::registry`] 收集 + 白名单校验。
pub trait HostModule: Send + Sync + 'static {
    /// 本模块描述符
    fn desc(&self) -> HostModuleDesc;

    /// 把本模块的 interface 实现装配进插件 linker
    ///
    /// 实现体是「本模块自己那几行 `add_to_linker`」——即 crate 化后从宿主搬过来的
    /// 接线代码。**不得**在此装配别的模块的 interface（越权即重复注册）。
    ///
    /// 返回类型即 `add_to_linker` 的原生错误（[`wasmtime::Error`]）——装配面唯一
    /// 可能的失败是 linker 注册冲突/重名（典型：同一 interface 被两个模块装配）。
    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()>;

    /// 本模块是否为**兜底 / 兼容桩**（默认 `false`）
    ///
    /// 语义：只为 import 闭合（或跨端同进程装配）而存在的实现，**有正式实现时让位**。
    /// `ModuleRegistry::install_all` 第二遍装配这类模块，并跳过接口已被正式实现占用的
    /// 那些（例：移动侧的 `mobile-desktop-compat`——它把桌面专属 interface 实现成
    /// fail-visible 桩，跨端跨进程测试里桌面真实现同时在场时必须让位）。
    /// 单端装配下无竞争，行为与普通模块一致（照装）。
    fn fallback(&self) -> bool {
        false
    }
}

/// inventory 提交类型（能力 crate 用 `submit!` 自报；宿主用 `collect!` 收集）
///
/// **必须在定义本类型的 crate 里 `collect!`**——`inventory::collect!` 展开为
/// 「为 `ModuleEntry` 实现 `inventory::Collect`」，而该 trait 是孤儿规则下的
/// **本地类型**要求：能力 crate 自己写 `inventory::submit!` 可以（不需要实现
/// `Collect`），但**收集点**必须在 kit。
pub struct ModuleEntry {
    /// 静态单例（能力 crate 用 `&'static` 常量提交）
    pub module: &'static dyn HostModule,
}

inventory::collect!(ModuleEntry);

/// 能力 crate 侧提交宏：把一个模块自报进全局注册表
///
/// 用法（能力 crate 内）：
/// ```ignore
/// wasmnest_host_kit::submit_module!(DISCOVERY);
/// ```
///
/// 其中 `DISCOVERY` 是一个 `static DISCOVERY: DiscoveryModule = DiscoveryModule;`
/// 与 `impl wasmnest_host_kit::HostModule for DiscoveryModule`。
#[macro_export]
macro_rules! submit_module {
    ($module:expr) => {
        ::inventory::submit! {
            $crate::ModuleEntry {
                module: &$module,
            }
        }
    };
}
