//! 能力路由词汇：能力域自报「我这一族原语怎么被路由」，内核只消费不写字面量
//!
//! ## 解决的问题（票 02 批次 03）
//!
//! 「可路由能力」此前是内核里的一张 `const` 闭表：能力名、三层方法族前缀、提供者
//! 必须导出的全部函数名**都写在内核**（如 `host-mdns` 与它的 5 条导出路径）。这些
//! 是**域词汇**——WIT 接口长什么样只有该域自己知道；内核持有字面量后，接口改名 /
//! 增删原语都要改内核，而能力域 crate 早已从内核依赖图摘出（批次 02/03），内核连
//! 引用它的常量都做不到。
//!
//! 处置与 [`crate::module`] / [`crate::lifecycle`] / [`crate::assembly`] 同范式：
//! **域自报、内核收集**。能力域（开 `common-host` feature 时）用
//! [`submit_routable_capability!`] 提交一条 [`RoutableCapability`]；内核经
//! [`collected_routable_capabilities`] 取回，与自己的内建行（如 `host-storage`——
//! 它的端口与真源确实在内核）合并成路由表。
//!
//! ## 红线（AGENTS §5.1）
//!
//! 本模块只承载**机制属性**（能力名 / 方法族前缀 / 导出函数名三类字符串），与
//! [`crate::module::HostModuleDesc`] 同类：不得新增字段承载业务语义（配额、默认值、
//! 产品档位…），违反即命中 B1（业务类型）/ B5（业务策略）。
//!
//! ## 调用面为什么不在本模块
//!
//! 提供者实例是 wasmtime 组件，调它的导出必须**编译期具名**（内核
//! `CapabilityTarget` 的 `mdns_*` 一族 + 对应的 `forward_mdns_*`），那是机制
//! （通用注册表 + 寻址，AGENTS §5.1.3 薄壳③）。本模块只传词汇，不传调用。

/// 一条可路由能力的词汇（能力域自报）
#[derive(Debug, Clone, Copy)]
pub struct RoutableCapability {
    /// 能力名（宿主原语能力清单里逐字同名的一项，如 `host-mdns`）
    pub capability: &'static str,
    /// 三层路由方法族的共同前缀：端口 `forward_<prefix>_*` / 内核转发 / 提供者窄端口
    /// `<prefix>_*`（三层同名是既有约定，闭表锁按此前缀比对）
    pub forward_prefix: &'static str,
    /// 提供者组件必须**全部**导出才算「提供该能力」的函数名（`ItemName` 路径语法，
    /// 如 `wasmnest:plugin/host-mdns.browse`）——少一条即视为未提供
    pub exports: &'static [&'static str],
}

/// inventory 提交类型（能力域用 [`submit_routable_capability!`] 自报）
///
/// 与 [`crate::module::ModuleEntry`] 同款约束：`inventory::collect!` 展开为「为本类型
/// 实现 `inventory::Collect`」，该 trait 要求本地类型 ⇒ 收集点只能在本 crate。
pub struct RoutableCapabilityEntry {
    /// 静态单例（能力域用 `&'static` 常量提交）
    pub route: &'static RoutableCapability,
}

inventory::collect!(RoutableCapabilityEntry);

/// 能力域侧提交宏：把一条路由词汇自报进全局注册表
///
/// 用法（能力域 crate 内）：
/// ```ignore
/// static ROUTE: wasmnest_host_kit::RoutableCapability = wasmnest_host_kit::RoutableCapability {
///     capability: CAPABILITY,
///     forward_prefix: FORWARD_PREFIX,
///     exports: EXPORTS,
/// };
/// wasmnest_host_kit::submit_routable_capability!(ROUTE);
/// ```
///
/// **与强制引用行的关系**：自报表只在本 rlib 被链接进最终二进制时才会执行 ⇒ 宿主
/// 侧仍需 `use <crate> as _;`（漏引用由装载期白名单双向校验点名，见
/// [`crate::assembly`]）。
#[macro_export]
macro_rules! submit_routable_capability {
    ($route:expr) => {
        ::inventory::submit! {
            $crate::RoutableCapabilityEntry { route: &$route }
        }
    };
}

/// 收集全部自报的可路由能力（按能力名字典序）
///
/// 顺序固定只为让日志与报错可复现（各条彼此独立、本无语义）；**重复能力名不由本函数
/// 消除**——重复即装配错误，由内核侧闭表锁（`manager::capability` 的
/// `routable_table_entries_are_well_formed`）点名，不在此静默去重。
pub fn collected_routable_capabilities() -> Vec<&'static RoutableCapability> {
    let mut routes: Vec<&'static RoutableCapability> = inventory::iter::<RoutableCapabilityEntry>
        .into_iter()
        .map(|entry| entry.route)
        .collect();
    routes.sort_by_key(|route| route.capability);
    routes
}

#[cfg(test)]
mod tests {
    //! 自报与收集的单测（自报需要 inventory 静态，故在本 crate 内起一个探针；`tests/`
    //! 目录受治理锁约束 ⇒ 一律写在 `src/` 并 `#[cfg(test)] mod` 引入）

    use super::{collected_routable_capabilities, RoutableCapability};

    static PROBE: RoutableCapability = RoutableCapability {
        capability: "host-kit-route-probe",
        forward_prefix: "kit_probe",
        exports: &["wasmnest:plugin/host-kit-route-probe.ping@0.1.0"],
    };

    crate::submit_routable_capability!(PROBE);

    /// 自报的探针必须被收集到（强制引用在本文件内成立 ⇒ inventory 静态被执行）
    #[test]
    fn submitted_route_is_collected() {
        let routes = collected_routable_capabilities();
        let probe = routes
            .iter()
            .find(|route| route.capability == "host-kit-route-probe")
            .expect("自报的路由词汇应被收集到");
        assert_eq!(probe.forward_prefix, "kit_probe");
        assert_eq!(probe.exports, &["wasmnest:plugin/host-kit-route-probe.ping@0.1.0"]);
    }

    /// 收集顺序按能力名字典序（日志 / 报错可复现）
    #[test]
    fn collection_is_sorted_by_capability() {
        let names: Vec<&str> = collected_routable_capabilities()
            .iter()
            .map(|route| route.capability)
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "收集顺序必须按能力名字典序");
    }
}
