//! 契约包名的**单点派生**（ADR 0051 D3/D4 · `wit-package-semver` 票 03）
//!
//! ## 为什么运行期全部走这里，而不是各写一个字面量
//!
//! 组件模型的 import / export 名带包版本（`ns:pkg/iface@version`），wasmtime 对
//! import 名做**含版本的精确匹配** ⇒ 任何拼错版本都是**编译面全绿、运行期实例化
//! 才炸**的静默断链。所以导出名的版本部分是**构造参数**，在本模块集中注入一次，
//! 30 余个消费点只传「接口名 + 函数名」两个词汇。
//!
//! ## 派生形态（由 wasmtime 48 + wit-parser 0.256 实测定死，勿凭直觉改）
//!
//! - 组件**导出实例**的键 = `ns:pkg/iface@version`（**版本在末尾**）；
//! - 实例**内部**函数名的键 = **平名**（`on-message`），故 `ItemName` 的两段查找
//!   （顶层按接口实例 → 实例内按平名）是唯一可用机制；
//! - `ItemName` 字面量的版本**只能写在末尾**：`wasmnest:plugin@0.0.1/events.on-message`
//!   解析失败（wit-parser 在 `ns:pkg` 后强制要求 `/`），
//!   `wasmnest:plugin/events.on-message@0.0.1` 才合法且命中。
//!
//! ## 版本真源
//!
//! [`PACKAGE_NAME`] / [`PACKAGE_VERSION`] / [`PACKAGE`] `include!` 仓根唯一手写处
//! `contracts/wasmnest-plugin-package.rs`。改版本只改那一个文件；const 上下文
//! （能力域 crate 的 `inventory` 静态自报）直接 `include!` 同一文件，编译期即一致；
//! 其余散落副本由 `桌面宿主 src-tauri/tests/wit_package_version_lock.rs` 钉住。

use std::sync::{Mutex, OnceLock};

mod package {
    // 能力仓仓根直挂 crate（standalone = `wasmnest-lib/`，mount 后 = 平台仓
    // `packages/`）：从 `src/` 上两级即仓根，contracts 随仓根同处，两种布局同值。
    include!("../../contracts/wasmnest-plugin-package.rs");
}

pub use package::{PACKAGE, PACKAGE_NAME, PACKAGE_VERSION};

/// 派生缓存（进程内唯一；条目数为导出词汇的常数上界，构造期一次性填齐）
///
/// 返回 `&'static str` 而非 `String`：调用面（`owner.rs` 的 `OpKind::export`、
/// `capability.rs` 的闭表、探测表）大量位置期望 `&'static [&'static str]`，
/// 派生函数返回拥有所有权的 `String` 会把整条链改成 `Vec<String>`，与既有闭表锁
/// （按 `&[&str]` 比对）的形态冲突。池化后同一 (iface, func) 恒返回同一指针。
static DERIVED: OnceLock<Mutex<Vec<(String, &'static str)>>> = OnceLock::new();

/// 单点派生入口：返回池中已有的 `&'static str`，无则构造并存入
fn derive(key: String, make: impl FnOnce() -> String) -> &'static str {
    let pool = DERIVED.get_or_init(|| Mutex::new(Vec::new()));
    let mut pool = pool.lock().expect("派生池锁中毒（先前一次派生 panic）");
    if let Some((_, value)) = pool.iter().find(|(k, _)| *k == key) {
        return value;
    }
    let value: &'static str = Box::leak(make().into_boxed_str());
    pool.push((key, value));
    value
}

/// 导出项名（`ItemName` 路径语法）：`ns:pkg/<interface>.<func>@<version>`
///
/// 组件的接口导出是「接口实例」嵌套形态，实例内函数名按**平名**查找 ⇒ 必须用
/// 点号路径语法，平名 `iface#func` 恒不命中（wasmtime 47 实证，本仓曾因此让
/// 二进制导出从未真正被发现）。
pub fn export_item(interface: &str, func: &str) -> &'static str {
    let key = format!("{interface}.{func}");
    derive(key, || {
        format!("{PACKAGE_NAME}/{interface}.{func}@{PACKAGE_VERSION}")
    })
}

/// 接口全名（`ns:pkg/<interface>@<version>`）——组件**导出实例**的键形态
///
/// 用于按接口整体探测（而非逐函数）；与 [`export_item`] 同池，重复派生返回同一指针。
pub fn interface_path(interface: &str) -> &'static str {
    let key = format!("iface:{interface}");
    derive(key, || format!("{PACKAGE_NAME}/{interface}@{PACKAGE_VERSION}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 派生形态是 wasmtime 匹配的事实前提：末尾版本 + 点号路径
    ///
    /// 预期值由真源常量派生（不写版本字面量）——否则 bump 时本用例会静止失败，
    /// 而这正是版本单点化要避免的散落副本（`wit_package_version_lock.rs` 同旨）。
    #[test]
    fn export_item_has_trailing_version_and_dot_path() {
        let name = export_item("events", "on-message");
        assert_eq!(
            name,
            format!("wasmnest:plugin/events.on-message@{PACKAGE_VERSION}")
        );
        // ItemName 必须能解析，且 instance_name 与组件导出实例键逐字一致
        let item = name
            .parse::<wasmtime::component::wit_parser::ItemName>()
            .expect("派生名是合法 ItemName");
        assert_eq!(
            item.instance_name().as_deref(),
            Some(format!("wasmnest:plugin/events@{PACKAGE_VERSION}").as_str()),
            "instance_name 必须等于组件导出实例键（版本在末尾）"
        );
    }

    /// 旧名（无版本）对版本化产物恒不命中 —— 双形态单测的「旧名」一侧
    #[test]
    fn unversioned_legacy_name_does_not_match_versioned_instance_key() {
        let legacy = "wasmnest:plugin/events.on-message";
        let item = legacy
            .parse::<wasmtime::component::wit_parser::ItemName>()
            .expect("旧名语法合法");
        assert_eq!(
            item.instance_name().as_deref(),
            Some("wasmnest:plugin/events"),
            "旧名解析出的实例键无版本，与版本化产物的键不等 ⇒ 探测恒 None"
        );
        assert_ne!(
            item.instance_name(),
            export_item("events", "on-message")
                .parse::<wasmtime::component::wit_parser::ItemName>()
                .unwrap()
                .instance_name(),
            "旧名与新名的实例键必须不等（否则版本形同虚设）"
        );
    }

    /// 平名不是可用的查找形态（历史踩坑：二进制导出从未真正被发现）
    ///
    /// 两类失效方式都被本用例钉住：`events` 语法合法但解析出的实例键是**平名**
    /// `events`（≠ 版本化键）；`iface#func` 形态**连语法都不合法**（`#` 是
    /// `ItemName` 的非法字符）——后者正是历史上「探测恒返回 None」的机制。
    #[test]
    fn flat_names_are_not_the_lookup_form() {
        let bare = "events"
            .parse::<wasmtime::component::wit_parser::ItemName>()
            .expect("平名语法合法");
        assert_ne!(
            bare.instance_name().as_deref(),
            Some(interface_path("events")),
            "平名 events 不得解析成版本化实例键"
        );

        for flat in ["events#on-message", "wasmnest:plugin/events#on-message"] {
            assert!(
                flat.parse::<wasmtime::component::wit_parser::ItemName>().is_err(),
                "{flat} 应连 ItemName 语法都不合法（`#` 是非法字符）——若哪天合法了，说明 \
                 wasmtime 改了语法，本仓的路径形态需重新核对"
            );
        }
    }

    /// 派生池：同一 (iface, func) 恒返回同一指针（闭表按 `&[&'static str]` 比对的前提）
    #[test]
    fn derive_is_stable_and_distinct() {
        assert_eq!(
            export_item("events", "on-message") as *const str,
            export_item("events", "on-message") as *const str
        );
        assert_ne!(
            export_item("events", "on-message"),
            export_item("events", "on-process-done")
        );
    }

    /// 版本常量与仓根真源一致（真源改版本而本文件未 include 到新值即红）
    #[test]
    fn package_constants_are_self_consistent() {
        assert_eq!(PACKAGE, format!("{PACKAGE_NAME}@{PACKAGE_VERSION}"));
        let parts: Vec<&str> = PACKAGE_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "版本须三段 semver：{PACKAGE_VERSION}");
        assert!(parts
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_digit())));
    }
}