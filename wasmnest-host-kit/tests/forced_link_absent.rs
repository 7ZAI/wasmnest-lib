//! 强制引用的**反面**一侧：本文件全篇不提及探针 crate ⇒ 收集结果为空
//!
//! 与 `tests/forced_link.rs` 成对。它存在的理由是：那条「强制引用 ⇒ 有值」的
//! 正例，**单独存在时任何改坏都测不出来**——只要探针 crate 因为别的原因（测试
//! 辅助代码碰了它、dev-dep 变成普通 dep、rustc 改了 rlib 裁剪策略）被链进来，
//! 正例就恒绿，而宿主那行强制引用被谁注释掉也照样绿。
//!
//! 反例把这件事钉死：**不引用就一个都没有**。于是
//! 「强制引用行有效」成为被两条用例夹出来的实测结论，而不是注释里的断言。

use wasmnest_host_kit::{HostKitError, ModuleRegistry};

/// 不引用探针 ⇒ 收集结果为空（这正是宿主漏掉强制引用行时的形态）
///
/// 断言的是 `is_empty()` 而不是「不含某个名字」：本二进制里没有任何自报来源，
/// 任何非空收集都意味着「有 crate 在未被引用的情况下自己链了进来」——
/// 那会让宿主的强制引用行失去意义，属机制级回归。
#[test]
fn unreferenced_capability_crate_collects_to_empty() {
    let registry = ModuleRegistry::collected();
    let names: Vec<&str> = registry.descs().iter().map(|d| d.name).collect();
    assert!(
        registry.is_empty(),
        "an unreferenced capability crate must contribute nothing, but collected: {names:?}"
    );
}

/// 白名单锁因此会点名「缺了什么」——宿主侧的 fail-visible 就是这一条路径
///
/// 这里断言的是**缺项被点名**（而不是「校验通过」）：白名单里写了探针名时，
/// 本二进制必须红，且名字必须出现在 `missing` 里、错误串里也必须带得上。
/// 这钉住宿主 `verify_whitelist` 的 missing 方向在真实「没链上」形态下确实触发。
#[test]
fn whitelist_names_the_module_that_failed_to_link() {
    let registry = ModuleRegistry::collected();
    let err = registry
        .verify_whitelist(&["forced_link_probe"])
        .expect_err("a module that failed to link must be reported as missing");

    match &err {
        HostKitError::WhitelistMismatch { unlisted, missing } => {
            assert_eq!(missing, &vec!["forced_link_probe".to_string()]);
            assert!(unlisted.is_empty(), "nothing extra was collected");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    let text = err.to_string();
    assert!(
        text.contains("forced_link_probe"),
        "error text must name the module so the operator can find the crate: {text}"
    );
    assert!(
        text.contains("missing"),
        "error text must say which direction failed: {text}"
    );
}
