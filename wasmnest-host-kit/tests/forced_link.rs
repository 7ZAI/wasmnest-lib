//! 强制引用的**正面**一侧：顶层一行 `use ... as _;` ⇒ 探针自报的模块被收集到
//!
//! 与 `tests/forced_link_absent.rs` 成对。两个文件是**两个独立的测试二进制**
//! （cargo 对 `tests/` 下每个 `.rs` 各编一个），强制引用是链接期属性——同一个
//! 进程里无法既「链上」又「没链上」，所以这件事只能跨二进制断言。

// 强制引用行（与宿主 `wasm_core::manager::runtime::component` 里的那几行同形）：
// 名字被 `as _` 匿名使用，作用仅仅是让本 rlib 进最终二进制，其 linker-section
// 静态才会执行。**删掉这行，下面那条断言会立刻红** —— 这就是本测试的全部价值。
use wasmnest_cap_forced_link_probe as _;

use wasmnest_host_kit::ModuleRegistry;

/// 加了强制引用 ⇒ 探针模块出现在收集结果里，且恰好只有它
#[test]
fn forced_reference_makes_the_probe_module_collected() {
    let registry = ModuleRegistry::collected();
    let names: Vec<&str> = registry.descs().iter().map(|d| d.name).collect();

    assert_eq!(
        names,
        vec!["forced_link_probe"],
        "with the forced reference the probe must be collected (and be the only one)"
    );
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());
}

/// 跨 crate 的**描述符载荷**也一起过来（不只是「有个条目」）
///
/// 只断言名字在场是不够的：若自报被优化成只剩占位，收集到的模块会带着空描述符
/// 流到宿主，白名单名字对了而 interface 路径 / 权限位全丢——那是更难查的坏。
#[test]
fn collected_descriptor_survives_the_crate_boundary() {
    let registry = ModuleRegistry::collected();
    let desc = registry
        .descs()
        .into_iter()
        .find(|d| d.name == "forced_link_probe")
        .expect("probe module collected");

    assert_eq!(desc.interfaces, &["probe:fixture/forced-link"][..]);
    assert_eq!(desc.permissions, &[] as &[&str]);
    assert_eq!(desc.abi_min, 1);
}

/// 被引用的探针能真的装进 linker（自报不是纸面条目）
///
/// 不写成「`install_all` 不报错」：空注册表也会不报错，那条断言在强制引用行
/// 被删掉时依然绿（已实测）。这里改为**反向取证**：装完之后再声明一次同名函数，
/// 报 `defined twice` ⇒ 证明探针的 `register` 真的执行过、且函数真的进了
/// linker 的 instance。
#[test]
fn forced_linked_probe_installs_a_real_function_into_the_linker() {
    let engine = wasmtime::Engine::default();
    let mut linker = wasmtime::component::Linker::new(&engine);
    ModuleRegistry::collected()
        .install_all(&mut linker)
        .expect("probe module installs");

    let err = linker
        .instance("probe:fixture/forced-link")
        .expect("probe instance namespace was opened by install_all")
        .func_new("ping", |_store, _ty, _args, _rets| Ok(()))
        .expect_err("re-declaring the probe function must prove install_all defined it");
    assert!(
        err.to_string().contains("defined twice"),
        "unexpected wasmtime error: {err}"
    );
}
