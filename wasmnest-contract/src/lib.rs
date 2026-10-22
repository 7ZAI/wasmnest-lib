//! WasmNest 插件契约包名与版本——**全仓唯一手写真源**（ADR 0051 D3/D4）
//!
//! 为什么是 Rust 常量而不是 JSON（票 03 实施期修正）：能力域 crate 的导出名清单走
//! `inventory` 静态自报（`wasmnest-discovery-engine/src/routing.rs` 的
//! `static ROUTE` + `const EXPORTS`），`inventory::submit!` 要求编译期常量 ⇒ 版本必须
//! 在 **const 上下文**可用。JSON 真源只能运行期解析，与该约束结构性冲突。
//!
//! 三条使用路径（唯一真源 + 漂移锁兜底，与 WIT 生成物同款范式）：
//!
//! 1. **运行期派生**：`wasmnest-wasm-core` 以普通 crate 依赖 `use` 本 crate，
//!    `contract::export_item(iface, func)` 拼出 `ns:pkg/iface.func@version`
//!    （wasmtime `ItemName` 路径语法，**版本在末尾**——wit-parser 在 `ns:pkg` 后
//!    强制要求 `/`，版本写中间会解析失败）；
//! 2. **编译期常量**：能力域 crate 在 `const` / `static` 位置写导出名字面量，由
//!    桌面宿主的 `wit_package_version_lock.rs` 断言与本 crate 一致。能力域**不**
//!    `include!` 本文件：`inventory` 自报要求编译期常量，而版本嵌在串中段的组合
//!    名**没有 const 插值机制**（`concat!` 只收字面量、`format!` 非 const）——
//!    跨 crate 纯拷贝可行（`const X: &str = wasmnest_contract::PACKAGE_NAME;`），
//!    锁钉住的恰是那些组合串，锁的价值不变、理由换准；
//! 3. **构建期解析**：平台仓 `scripts/compose-wit.mjs` 正则读本文件，把版本注入
//!    生成的 `wasmnest.wit`（端清单 `compose.json` 只声明包名，不持版本）。
//!
//! **文本形状是跨语言契约**：常量必须保持 `pub const <NAME>: &str = "<值>";` 的
//! 精确形态（含 `: &str` 类型注解，无 macro、无 `env!` / `concat!`）——平台仓的
//! WIT 拼装脚本与发布清单锁都按此形状做正则解析。改形状 = 同时打穿两处解析器，
//! 必须同批修改并重跑 `pnpm run check:wit` / `check:manifest`。
//!
//! **bump 政策**（ADR 0051 D4）：任何 WIT 变更（**含函数级追加**）→ patch
//! （`0.1.0` → `0.1.1`）；interface 增删 / 签名变 → minor（`0.1.x` → `0.2.0`）。
//! bump 后须重跑 `node scripts/compose-wit.mjs --all` 并重建插件产物——版本进入
//! import 名，宿主与 guest 版本不等即实例化失败。
//!
//! 版本线（2026-10-18 三仓拆分）：新仓内所有内部构建视为**全新**，版本自 0.0.1
//! 重开——契约版本与旧单仓的 0.3.0 无继承关系（旧仓转为文档真源与回退点，代码冻结）。
//! 旧线历次版本（0.1.x / 0.2.0 / 0.3.0，含 wasmnest-end-rename 的包名改名窗口）
//! 见旧仓 git 历史与 ADR 0051 / 0056。
//!
//! **crate 自身 `version` 与 [`PACKAGE_VERSION`] 不强制相等**：前者是打包事实，
//! 后者是协议事实；强行绑定会让「只改打包元数据」也构成契约 bump。两者的一致性
//! 只要求 [`PACKAGE`] 是本 crate 内 `PACKAGE_NAME@PACKAGE_VERSION` 的自洽派生。
//!
//! **不登记 `SPLIT_CRATES`**：该表管辖的是「宿主 bin 拆分产物」的回归面，登记会
//! 要求宿主清单直接声明本 crate——而契约只允许经 `wasmnest-wasm-core` 的 re-export
//! 消费（宿主直连 = 版本面出现第二个消费入口）。本 crate 的结构管辖落在平台仓的
//! crate 结构锁与能力 crate 语义锁，不在拼接产物登记表。

/// 契约包名（`namespace:name`，不含版本）
pub const PACKAGE_NAME: &str = "wasmnest:plugin";

/// 契约包版本（三段 semver）
pub const PACKAGE_VERSION: &str = "0.0.2";

/// 契约包全名（`namespace:name@version`）——组件**导出实例**的键形态
pub const PACKAGE: &str = "wasmnest:plugin@0.0.2";

#[cfg(test)]
mod tests {
    use super::*;

    /// 三个常量的内部自洽（真源改了一处而忘了另一处即红）
    #[test]
    fn package_constants_are_self_consistent() {
        assert_eq!(PACKAGE, format!("{PACKAGE_NAME}@{PACKAGE_VERSION}"));
        let parts: Vec<&str> = PACKAGE_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "版本须三段 semver：{PACKAGE_VERSION}");
        assert!(
            parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
            "版本段必须是纯数字：{PACKAGE_VERSION}"
        );
        assert!(
            PACKAGE_NAME.contains(':'),
            "包名应为 `wasmnest:<ns>` 形态：{PACKAGE_NAME}"
        );
    }

    /// 文本形状锁：平台仓两处 node 解析器按 `pub const <NAME>: &str = "<值>";`
    /// 正则取值，改成 macro / `env!` / 省类型注解都会静默打穿解析链
    ///
    /// 判据用「从常量现算 needle」而不是写死值：值可以合法 bump，形状不能变。
    #[test]
    fn constants_keep_the_plain_literal_shape() {
        let source = include_str!("lib.rs");
        for (name, value) in [
            ("PACKAGE_NAME", PACKAGE_NAME),
            ("PACKAGE_VERSION", PACKAGE_VERSION),
            ("PACKAGE", PACKAGE),
        ] {
            let needle = format!("pub const {name}: &str = \"{value}\";");
            assert!(
                source.contains(&needle),
                "契约常量的文本形状漂移，平台仓脚本的正则解析会失败：{needle}"
            );
        }
    }
}
