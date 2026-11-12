//! 强制链接探针：一个**除了自报之外什么都不做**的能力模块
//!
//! ## 它回答什么问题
//!
//! 宿主那套「能力 crate 用 `inventory::submit!` 自报、宿主一次收集」的自动装配，
//! 有一个人人都知道但**没人自动化**的失效模式：`inventory` 的提交展开为
//! linker-section 静态，而**未被引用的 rlib 不进最终二进制，静态不执行** ⇒
//! 收集结果静默少一项 ⇒ 该能力域从插件 import 集里消失，而 guest 编译期照常
//! import、运行期才在实例化时炸。
//!
//! 宿主侧的兜底是「`component.rs` 里强制引用行 + 白名单双向锁」，但那条兜底本身
//! 也需要证据支撑，否则它只是注释里的断言。本 crate 就是那个证据的载体：它
//! **故意什么都不提供**，只自报一个空壳模块，于是「链上 / 没链上」的差异在收集
//! 结果上是二值可见的。
//!
//! ## 怎么用（不要在本目录直接跑 cargo）
//!
//! 两侧用法都在 `wasmnest-host-kit` 的集成测试里，各占一个测试二进制——
//! 强制引用是**链接期属性**，同一进程内无法同时「有」与「无」：
//!
//! - `tests/forced_link.rs`：顶层写 `use wasmnest_cap_forced_link_probe as _;`
//!   ⇒ 收集结果必须**恰好**等于本探针自报的那一项；
//! - `tests/forced_link_absent.rs`：全文件不提及本 crate
//!   ⇒ 收集结果必须**为空**。
//!
//! 两个二进制都由 `cd packages/wasmnest-host-kit && cargo test` 构建；
//! 直接在本目录跑 cargo 只会得到一个无断言的空构建（且 dev-dep 环让本 crate
//! 无法脱离 host-kit 的测试装配独立成产品）。

use wasmnest_host_kit::{HostModule, HostModuleDesc, ModuleEntry, WasmPluginState};
use wasmtime::component::Linker;

/// 探针自报的接口路径（空壳命名空间，不取任何真实 interface 名）
///
/// **刻意不用真实 interface 名**：探针一旦蹭进生产二进制，会与真实能力域
/// 抢同一个 interface 名字段（装配期 `defined twice`）。空壳名让误链接的后果
/// 变成「白名单多出一项」这种一眼可辨的红，而不是装配期崩。
const PROBE_INTERFACE: &str = "probe:fixture/forced-link";

/// 探针模块名（宿主白名单锁会把它当未登记项点名）
const PROBE_MODULE: &str = "forced_link_probe";

const DESC: HostModuleDesc = HostModuleDesc {
    name: PROBE_MODULE,
    interfaces: &[PROBE_INTERFACE],
    permissions: &[],
    abi_min: 1,
};

/// 探针能力模块（零状态）
pub struct ProbeModule;

impl HostModule for ProbeModule {
    fn desc(&self) -> HostModuleDesc {
        DESC
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        // 必须真在 instance 里**定义一个函数**才算「装配过」：`Linker::instance`
        // 允许对同一名字重复开启（wasmtime 有意为之），不报错也什么都不注册。
        let mut instance = linker.instance(PROBE_INTERFACE)?;
        instance.func_new("ping", |_store, _ty, _args, _rets| Ok(()))?;
        Ok(())
    }
}

/// 静态单例（供 `submit_module!` 取址）
static MODULE: ProbeModule = ProbeModule;

// 自报进全局注册表（linker-section 静态；只有本 crate 被真正链接时才执行）
//
// 注释用 `//` 而非 `///`：rustdoc 不为宏调用生成文档，`///` 会触发
// `unused_doc_comments` 警告。
inventory::submit! {
    ModuleEntry { module: &MODULE }
}