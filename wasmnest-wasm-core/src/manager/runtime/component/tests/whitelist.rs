//! 能力模块白名单双向校验 + 描述符零产品名词锁（component.rs 专用）
//!
//! 自 `component.rs` 的 `mod tests` 拆出（共享脚手架在父 `mod tests`，
//! 经 `use super::*` 可见）；fixture 互斥与产物构建语义不变。

use super::*;

// 单形态（2026-10-13）：lib test 二进制经 dev-deps 开启 server crates 的
// `common-host`（DomainHooks 停用回收钩子必需）——其 HostModule 自报进测试
// 二进制，白名单（纯 `expected_host_modules`）须在此声明同 3 个模块名才能双向
// 匹配（与生产形态解耦：桌面宿主在生产二进制声明，移动不自报）。
wasmnest_host_kit::expect_host_module!(wasmnest_server_websocket::plugin_binding::MODULE_NAME);
wasmnest_host_kit::expect_host_module!(wasmnest_server_peer_net::plugin_binding::MODULE_NAME);
wasmnest_host_kit::expect_host_module!(wasmnest_server_http::plugin_binding::MODULE_NAME);

/// 自动收集到的能力模块集与树内白名单**完全相等**（双向）
///
/// 这是「自动装配」机制唯一的不静默漂移护栏（wasm-core-lib-split 票 03）：
/// - 多出（unlisted）：有 crate 被加进依赖却没过 review，或强制引用行被人加了
///   注释掉 ⇒ 红
/// - 少了（missing）：依赖被删 / 能力 crate 没被链接进来（inventory 的
///   linker-section 静态不执行）⇒ 红。**这是自动装配最容易静默失效的点**：
///   缺了它，能力域会从插件 import 集里悄悄消失，而 guest 编译期照常 import。
#[test]
fn capability_registry_matches_whitelist() {
    let registry = wasmnest_host_kit::ModuleRegistry::collected();
    registry
        .verify_whitelist(&host_module_whitelist())
        .unwrap_or_else(|e| panic!("capability module whitelist must match collected set: {e}"));
}

/// 白名单 = 纯宿主自报期望（单形态 2026-10-13）：`expected_host_modules` 去重 +
/// 字典序（host-kit 实现语义），原「内建在册 ∪ 宿主期望」合并函数随
/// `IN_CRATE_HOST_MODULES` 一并删除（端差异宿主组装——白名单不承载内建列表）。
/// 双向校验本体仍由 [`capability_registry_matches_whitelist`] 覆盖。

/// fail-visible 形态①：能力模块**缺失**时实例化期显性失败，并点名缺哪个
///
/// 走的是生产入口 [`verify_host_module_registry`]（`add_to_linker` 的第一段），
/// 只把白名单换成一份含不存在的模块名的清单来触发失败。断言三件事：
/// ① 失败（不静默降级为「该能力不存在」）；
/// ② 错误文本点名缺失的模块（运维据此知道查哪个 crate）；
/// ③ 错误文本给出**两个方向各自**的修法（missing 与 unlisted 不同）。
///
/// ③ 不能省：双向差异共用一条错误串，只写「whitelist mismatch」时，
/// 「依赖被删」与「能力悄悄进来了」两种事故看起来一模一样。
#[test]
fn missing_capability_module_fails_loudly_with_remediation() {
    let err = verify_host_module_registry(&["capability-that-is-not-collected"])
        .expect_err("a capability module that was never collected must fail the check");
    let msg = err.to_string();

    assert!(
        msg.contains("capability-that-is-not-collected"),
        "error must name the missing module: {msg}"
    );
    assert!(
        msg.contains("missing="),
        "error must say which direction failed: {msg}"
    );
    assert!(
        msg.contains("forced-reference") && msg.contains("whitelist"),
        "error must carry remediation for both directions (forced-reference line / \
             reviewed whitelist entry): {msg}"
    );
}

// fail-visible 形态① 反向（收集到但白名单没有）**不在本文件测**：本 crate 的
// 测试二进制收集集随迁移批次收缩（票 02 批次 03 起 http / ws / peer / mdns 陆续
// 移出本 crate，最终为空），任何依赖「收集集非空」的用例都会在后续批次变成
// 恒真或必红。该方向的判据由两处承担：
// ① `wasmnest-host-kit/tests/registry.rs`（探针模块保证收集集非空；含
//    `unlisted=` / `missing=` 与两个方向修法文案的断言）；
// ② 宿主侧集成锁 `src-tauri/tests/pty_wiring.rs`（宿主真实白名单的双向比对，
//    即原先本用例在宿主侧的对偶）。

/// 收集到的模块名全局唯一（inventory 按静态收集，重复 `submit!` 会在此暴露）
#[test]
fn collected_module_names_are_unique() {
    let registry = wasmnest_host_kit::ModuleRegistry::collected();
    let mut names: Vec<&str> = registry.descs().iter().map(|d| d.name).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        total,
        "duplicate capability module submitted to inventory: {names:?}"
    );
}

/// 描述符零产品名词（AGENTS §5.1 B1/B5 红线）
///
/// 模块注册表必须是「通用注册表与寻址」（§5.1.3 明列的宿主允许薄壳），一旦
/// 描述符里出现产品名词，它就退化成业务容器。
///
/// **判据与词表的单一真源在 host-kit**（`ModuleRegistry::product_noun_violations`）：
/// `inventory` 收集按**测试二进制**隔离，本文件只能看到本二进制收集到的模块（经
/// dev-deps 开 `common-host` 的三个 server 能力域）；各端宿主 adapter 自报的模块由
/// 各端宿主自己的锁扫描（桌面 / 移动各一份）。匹配粒度 = 词段相等而非子串包含的
/// 契约例随判据住在 `packages/wasmnest-host-kit/src/registry.rs`。
#[test]
fn capability_module_descriptors_carry_no_product_nouns() {
    let registry = wasmnest_host_kit::ModuleRegistry::collected();
    let violations = registry.product_noun_violations();
    assert!(
        violations.is_empty(),
        "capability module descriptors contain product nouns: {violations:?}"
    );
}
