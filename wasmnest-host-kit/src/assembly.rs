//! 宿主装配侧自报：能力模块期望清单 + 能力域端口装配器
//!
//! ## 解决的问题
//!
//! 装配面有两件只有**宿主**能回答的事，过去却被写死在机制 crate 里：
//!
//! 1. **白名单**（[`expected_host_modules`]）：[`crate::registry::ModuleRegistry::verify_whitelist`]
//!    的比对基准。写死在内核 ⇒ 每次「能力域迁宿主」都要改内核源码；
//! 2. **端口装配**（[`install_domain_ports`]）：迁出内核的能力域在宿主侧有端口实现，
//!    必须在任何插件实例化**之前**装上（否则 guest 一调该域原语就 panic，
//!    fail-visible）。实现搬出内核后，内核的装配链不能再点名该域。
//!
//! 处置与 [`crate::lifecycle`] 同范式：**宿主自报**（`inventory::submit!`），
//! 装配方一次遍历 —— 内核源码里不再出现任何具体能力域名（wasm-core 纯净性收口
//! 票 02 批次 02；首个迁移域 = pty）。
//!
//! ## 「强制引用行 + 期望清单同处」纪律
//!
//! 宿主侧每个域的适配器文件里，[`crate::expect_host_module`] 与
//! `use <crate> as _;`（强制引用行）必须写在**同一处**：
//!
//! - 漏强制引用 ⇒ 该 crate 的 `ModuleEntry` 自报静态不进最终二进制 ⇒ 装载期
//!   被 `missing` 方向点名；
//! - 漏期望清单 ⇒ 自报模块进了二进制但没被 review ⇒ 装载期被 `unlisted` 方向点名。
//!
//! 两个方向都是显性失败（见 [`crate::HostKitError::WhitelistMismatch`]），
//! 不会静默降级成「该能力不存在」。
//!
//! ## 红线
//!
//! 本模块只承载机制语义：模块名、期望清单、装配函数指针。禁止任何产品名词或
//! 业务默认值（AGENTS §5.1 B1/B5）。

use std::sync::Arc;

use crate::ports::HostPorts;

// ==================== 能力模块期望清单（白名单的宿主侧来源） ====================

/// 宿主自报的「期望能力模块」条目
///
/// 语义 = 「本宿主的最终二进制里应当有这样一个能力模块」；与
/// [`crate::registry::ModuleRegistry::collected`] 的收集结果做**双向**比对。
pub struct ExpectedModuleEntry {
    /// 能力模块名（与 [`crate::module::HostModuleDesc::name`] 同源）
    pub name: &'static str,
}

inventory::collect!(ExpectedModuleEntry);

/// 宿主侧提交宏：声明本宿主要求最终二进制里出现的能力模块
///
/// 用法（宿主侧适配器文件内，**紧贴强制引用行**写）：
/// ```ignore
/// use wasmnest_pty_engine as _;
/// wasmnest_host_kit::expect_host_module!(wasmnest_pty_engine::plugin_binding::MODULE_NAME);
/// ```
#[macro_export]
macro_rules! expect_host_module {
    ($name:expr) => {
        ::inventory::submit! {
            $crate::assembly::ExpectedModuleEntry { name: $name }
        }
    };
}

/// 宿主自报的期望模块名（去重、字典序）
///
/// 与 [`crate::registry::ModuleRegistry::collected`] 一起构成
/// `verify_whitelist` 的两侧：收集侧来自能力 crate 自报，期望侧来自宿主声明。
///
/// **去重不报错**：同一模块被两处声明（域适配器文件 + 宿主组合根）语义相同，
/// 不是漂移——比对的是集合而非声明条数。
pub fn expected_host_modules() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = inventory::iter::<ExpectedModuleEntry>
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

// ==================== 能力域端口装配器（宿主侧实现） ====================

/// 能力域端口装配器
///
/// `install` 的实现体是宿主侧适配器的「双登记」（实例级
/// `WasmHostContext::set_domain_ports` + 进程级 `<域>::install_ports`，见各能力域
/// 自己的端口 trait 文档）。`HostPorts` 是本 crate 能命名的唯一宿主类型通道——
/// 具体宿主类型（桌面端 `WasmHostContext`）由实现侧向下转型
/// （[`crate::ports::downcast_host`]），机制内核不认识它。
pub struct DomainPortsInstaller {
    /// 能力域名（与 [`crate::module::HostModuleDesc::name`] 同源；日志与断言定位用）
    pub name: &'static str,
    /// 装配函数：把该域的端口实现装到宿主上下文与进程级通道上
    pub install: fn(Arc<dyn HostPorts>),
}

/// inventory 提交类型（宿主用 `submit!` 自报；收集点必须在本 crate，孤儿规则）
pub struct DomainPortsInstallerEntry {
    /// 静态单例（宿主用 `&'static` 常量提交）
    pub installer: &'static DomainPortsInstaller,
}

inventory::collect!(DomainPortsInstallerEntry);

/// 宿主侧提交宏：把一个能力域端口装配器自报进全局注册表
///
/// 用法（宿主侧适配器文件内）：
/// ```ignore
/// static PTY_PORTS_INSTALLER: wasmnest_host_kit::DomainPortsInstaller =
///     wasmnest_host_kit::DomainPortsInstaller { name: "pty", install: install };
/// wasmnest_host_kit::submit_domain_ports_installer!(PTY_PORTS_INSTALLER);
/// ```
#[macro_export]
macro_rules! submit_domain_ports_installer {
    ($installer:expr) => {
        ::inventory::submit! {
            $crate::assembly::DomainPortsInstallerEntry { installer: &$installer }
        }
    };
}

/// 装配全部宿主自报的能力域端口（按域名**字典序**），返回已装配的域名
///
/// 排序口径与 [`crate::registry::ModuleRegistry`] / [`crate::lifecycle::DomainHooksRegistry`]
/// 一致：各域装配彼此独立、顺序本无语义，固定顺序只为让日志可复现。
///
/// **调用时机是契约的一部分**：必须在任何插件实例化之前（内核装配链的单一入口
/// 里调一次），否则该域 guest 一调原语就 panic。
///
/// 未自报任何装配器 ⇒ 返回空表（无头 / 不含该域的宿主是合法形态，不是错误）。
pub fn install_domain_ports(host: Arc<dyn HostPorts>) -> Vec<&'static str> {
    let mut installers: Vec<&'static DomainPortsInstaller> =
        inventory::iter::<DomainPortsInstallerEntry>
            .into_iter()
            .map(|entry| entry.installer)
            .collect();
    installers.sort_by_key(|installer| installer.name);

    let mut installed = Vec::with_capacity(installers.len());
    for installer in installers {
        (installer.install)(Arc::clone(&host));
        installed.push(installer.name);
    }
    installed
}

#[cfg(test)]
mod tests {
    //! 注册表自身行为的单测（自报与收集需要 inventory 静态，故在本 crate 内起探针；
    //! `tests/` 目录另有独立测试二进制，本模块的探针只进本单元的测试二进制）

    use super::*;
    use std::any::Any;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // 探针期望清单：同一模块声明两次（钉去重语义）
    crate::expect_host_module!("kit-assembly-probe");
    crate::expect_host_module!("kit-assembly-probe");

    /// 探针装配器：记录被调用一次
    static PROBE_INSTALL_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn probe_install(_host: Arc<dyn HostPorts>) {
        PROBE_INSTALL_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    static PROBE_INSTALLER: DomainPortsInstaller = DomainPortsInstaller {
        name: "kit-assembly-probe",
        install: probe_install,
    };

    crate::submit_domain_ports_installer!(PROBE_INSTALLER);

    /// 最小 HostPorts 替身（装配器只做类型擦除，不消费任何方法）
    struct StubHost;

    impl HostPorts for StubHost {
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    /// 自报的期望模块必须被收集到（收集点在本 crate ⇒ 强制引用天然成立）
    #[test]
    fn declared_expectation_is_collected() {
        let names = expected_host_modules();
        assert!(
            names.contains(&"kit-assembly-probe"),
            "宿主自报的期望模块应被收集到，实际：{names:?}"
        );
    }

    /// 同一模块声明两次 ⇒ 期望清单只出现一次（集合语义，不是声明条数）
    #[test]
    fn duplicate_declarations_collapse_to_one() {
        let names = expected_host_modules();
        assert_eq!(
            names.iter().filter(|n| **n == "kit-assembly-probe").count(),
            1,
            "重复声明必须去重：{names:?}"
        );
    }

    /// 期望清单按字典序返回（日志与报错可复现）
    #[test]
    fn expected_names_are_sorted() {
        let names = expected_host_modules();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "期望清单必须字典序：{names:?}");
    }

    /// 自报的端口装配器必须被遍历到，且被调用
    #[test]
    fn submitted_installer_is_invoked() {
        let before = PROBE_INSTALL_CALLS.load(Ordering::SeqCst);
        let installed = install_domain_ports(Arc::new(StubHost));
        assert!(
            installed.contains(&"kit-assembly-probe"),
            "已装配域名应含探针，实际：{installed:?}"
        );
        assert_eq!(
            PROBE_INSTALL_CALLS.load(Ordering::SeqCst),
            before + 1,
            "自报的装配器必须被调用一次"
        );
    }

    /// 已装配域名按字典序（与收集顺序无关）
    #[test]
    fn installed_names_are_sorted() {
        let installed = install_domain_ports(Arc::new(StubHost));
        let mut sorted = installed.clone();
        sorted.sort_unstable();
        assert_eq!(installed, sorted, "已装配域名必须字典序：{installed:?}");
    }
}
