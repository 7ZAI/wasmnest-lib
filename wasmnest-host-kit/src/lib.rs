//! WasmNest 插件宿主**机制内核**（host kit）
//!
//! 本 crate 只装「机制」：插件实例状态、能力模块契约与自动注册表、能力域自报面
//! （生命周期钩子 / 端口装配器 / 路由词汇）这些与**任何产品概念无关**的东西，从各端
//! 宿主的 bin crate 里抬到可被能力 crate 依赖的位置。它是**双端共用**的锚点：桌面与
//! 移动宿主都在直接依赖它（非「将来」），ADR 0018 的「双端契约各自演进」不因共享
//! 机制内核而改变。
//!
//! ## 为什么必须独立成 crate（两条硬约束，均已实测）
//!
//! 1. **被链接性**：`inventory::submit!` 展开为 linker-section 静态；未被任何
//!    item 引用的 rlib 不进最终二进制，静态不执行 ⇒ 注册丢失。**已固化成两个
//!    自动化用例**（票 09）：`tests/forced_link.rs`（顶层 `use ... as _;` ⇒ 收集
//!    结果恰好等于探针自报的那一项）与 `tests/forced_link_absent.rs`
//!    （全文件不提及探针 crate ⇒ 收集结果为空）。两者是两个测试二进制——强制
//!    引用是链接期属性，同进程内无法既「有」又「无」。
//! 2. **Cargo 环路**：能力 crate 必须能命名两样东西——① `collect!` 里声明的
//!    提交类型；② [`state::WasmPluginState`]（`add_to_linker::<S, D>` 是**单态**的，
//!    S 不能是调用方的类型）。这两样若住在宿主 bin crate 内，能力 crate 就得依赖
//!    宿主，而宿主又必须依赖能力 crate ⇒ Cargo 硬拒循环依赖（实测退出码 101，
//!    `crate-type` 含 `rlib` 亦然）。
//!
//! ## 分层
//!
//! ```text
//!   wasmnest-host-kit（本 crate）
//!     ├── state      插件实例状态（机制字段）
//!     ├── ports      宿主能力端口（marker + 向下转型出口）
//!     ├── module     能力模块契约（HostModule / 描述符 / 提交类型）
//!     ├── lifecycle  能力域生命周期钩子（装载 / 停用回调；内核不点名能力域）
//!     ├── assembly   宿主装配侧自报（期望模块清单 / 能力域端口装配器；同上）
//!     ├── route      能力路由词汇自报（能力名 / 方法族前缀 / 导出函数名；同上）
//!     ├── registry   自动注册表（收集 → 排序 → 白名单校验 → linker 装配）
//!     ├── limits     Store 资源上限 + 编译期默认值
//!     └── metrics    单插件指标值对象（原子记账）
//!            ▲                    ▲
//!            │                    │ 依赖
//!   能力 crate（packages/wasmnest-*）   两端宿主（wasm-core / src-tauri）
//! ```
//!
//! ## 边界红线（AGENTS §5.1）
//!
//! 本 crate 内**禁止出现任何产品名词**（会话 / 终端 / 配对 / 设备 / 传输 / AI…）。
//! [`module::HostModuleDesc`] 只描述接口路径、权限位与 ABI 下界三类机制属性；
//! 违反即命中 §5.1 B1（业务类型）/ B5（业务策略）红线。

#![deny(missing_docs)]

pub mod assembly;
pub mod limits;
pub mod lifecycle;
pub mod metrics;
pub mod module;
pub mod ports;
pub mod registry;
pub mod route;
pub mod state;

pub use assembly::{
    expected_host_modules, install_domain_ports, DomainPortsInstaller, DomainPortsInstallerEntry,
    ExpectedModuleEntry,
};
pub use lifecycle::{DomainHooks, DomainHooksEntry, DomainHooksRegistry};
pub use limits::{defaults, StoreLimits};
pub use metrics::{
    AuthzDecisionKind, CallTimer, LifecycleEvent, PluginMetrics, PluginMetricsSnapshot,
};
pub use module::{HostModule, HostModuleDesc, ModuleEntry};
pub use ports::HostPorts;
pub use registry::{DescriptorNounViolation, ModuleRegistry, PRODUCT_NOUN_DENYLIST};
pub use route::{collected_routable_capabilities, RoutableCapability, RoutableCapabilityEntry};
pub use state::WasmPluginState;

/// 本 crate 统一结果类型（机制面错误）
///
/// 与宿主 `AppError` **解耦**：能力 crate 只依赖本 crate 时不应被迫认识宿主的
/// 错误枚举；宿主侧自行做 `From` 转换（见宿主 adapter 层）。
pub type Result<T> = std::result::Result<T, HostKitError>;

/// 机制内核错误（装配面）
#[derive(Debug)]
pub enum HostKitError {
    /// 能力模块注册失败（linker 装配阶段；含重复注册）
    Register {
        /// 出问题的能力模块名（`HostModuleDesc::name`）
        module: &'static str,
        /// 底层原因（wasmtime linker 错误 / 重复注册）
        source: wasmtime::Error,
    },
    /// 自动收集到的能力模块集与白名单不一致（防「模块没链上」静默漂移）
    ///
    /// **两个方向各有不同的修法，故错误串分别点名**（fail-visible，不静默降级）：
    /// - `missing`（白名单有、没收集到）：该能力 crate 没进最终二进制。查
    ///   Cargo 依赖是否还在，以及宿主那行 `use <crate> as _;` 强制引用是否被删。
    /// - `unlisted`（收集到、白名单没有）：有 crate 未经 review 就进了能力面，
    ///   或强制引用行旁的白名单项被漏加。
    WhitelistMismatch {
        /// 只在收集结果里、白名单里没有的模块名
        unlisted: Vec<String>,
        /// 白名单里有、但没被收集到的模块名
        missing: Vec<String>,
    },
    /// 宿主上下文向下转型失败（宿主未把自己的上下文注册成该能力域要求的端口实现）
    ///
    /// **显性失败，不静默降级**：能力域拿到空的宿主能力继续跑，等于让一个未装配
    /// 的能力以「什么都不做」的面貌出现在插件 import 集里。
    HostPortUnavailable {
        /// 期望的宿主上下文类型名（诊断用）
        expected: &'static str,
        /// 实际拿到的类型名
        actual: &'static str,
    },
}

impl std::fmt::Display for HostKitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register { module, source } => {
                write!(f, "host module '{module}' registration failed: {source}")
            }
            Self::WhitelistMismatch { unlisted, missing } => write!(
                f,
                "host module whitelist mismatch: unlisted={unlisted:?} (collected but not \
                 declared in the host whitelist — add a reviewed whitelist entry or drop the \
                 capability crate dependency), missing={missing:?} (declared but not \
                 collected — the capability crate is not linked into the binary; check its \
                 Cargo dependency and the `use <crate> as _;` forced-reference line)"
            ),
            Self::HostPortUnavailable { expected, actual } => write!(
                f,
                "host ports unavailable: expected context `{expected}`, got `{actual}` — \
                 the host did not implement the capability domain's port trait"
            ),
        }
    }
}

impl std::error::Error for HostKitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // wasmtime 48 的 `Error` 未实现 `std::error::Error`（它是 anyhow 风格的
        // 自有类型），故此处不向上暴露 source；错误信息已在 `Display` 里完整展开。
        None
    }
}
