//! `WasmNest` 剪贴板域契约房（**只持契约，零实现**；ADR 0052 D2/D4 · 票 04）
//!
//! ## 为什么是一个独立 crate
//!
//! 系统剪贴板读写是**双端同功能**的能力（R2 功能级交集）：桌面经 Tauri
//! clipboard-manager 插件读写系统剪贴板、移动经 Android clipboard 桥读写，
//! 功能一致 → 统一为一份共享契约 `wit/clipboard.wit`。本域没有可共享的引擎
//! 实现（两端底层机制完全不同，且都只有几行宿主代码），故按 ADR 0052 D2/D4
//! 的轻量契约房形态承载：crate 只持 WIT + 端口词汇（当前无端口），实现按端
//! 住宿主（桌面 `src-tauri/src/plugin/clipboard.rs`；移动 `src-tauri/src/plugin/clipboard.rs`）。
//!
//! ## 边界（防回接）
//!
//! - 本 crate **不得**出现任何桌面 / 移动专属实现或依赖（端差异归宿主）；
//! - `wit/clipboard.wit` 是 `host-clipboard` 的**唯一真源**——双端 `compose.json`
//!   经 `caps.clipboard` 直接消费它，端生成物由 `scripts/compose-wit.mjs` 拼装；
//! - 剪贴板操作返回 `result<T, string>`，错误内容为宿主侧可读的 UTF-8 消息。
//!
//! 实现落点与权限语义的现行口径见 `wit/clipboard.wit` 的 interface 文档与各端
//! 宿主 adapter（本文件不复制漂移源）。

// ==================== 契约包身份（WIT 按包拆分，ADR 0061） ====================

/// 本能力域 WIT 包全名（`namespace:name@version`）
///
/// 与 `wit/clipboard.wit` 的 `package` 行逐字一致（下方锁测试断言），也是宿主
/// `MODULE_INTERFACES` 各项的前缀。拆包后每个能力域独立版本：只在本包 WIT
/// 变更时 bump，不再随 `wasmnest:plugin` 全局版本前进。
pub const WIT_PACKAGE: &str = "wasmnest:clipboard@0.0.1";

#[cfg(test)]
mod wit_package_lock {
    /// 契约房身份自证：`[dependencies]` 恒空（「零 Rust 实现」的唯一退化方向
    /// 是被顺手加一个 engine 模块/依赖，与 `wasmnest-contract` 同款常驻断言）
    #[test]
    fn manifest_has_no_dependencies() {
        let manifest = include_str!("../Cargo.toml");
        let offenders: Vec<&str> = manifest
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.starts_with("[dependencies")
                    || line.starts_with("[build-dependencies")
                    || line.starts_with("[dev-dependencies")
                    || (line.starts_with("[target") && line.contains("dependencies"))
            })
            .collect();
        assert!(
            offenders.len() <= 1 && offenders.iter().all(|s| *s == "[dependencies]"),
            "契约房必须保持零依赖：{offenders:?}"
        );
        let mut in_deps = false;
        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_deps = trimmed == "[dependencies]";
                continue;
            }
            assert!(
                !in_deps || trimmed.is_empty() || trimmed.starts_with('#'),
                "契约房 `[dependencies]` 段出现依赖条目：{trimmed}"
            );
        }
    }
    /// 常量 ↔ 分片真源 package 行（两侧任一手改即红）
    #[test]
    fn wit_package_matches_slice_package_line() {
        let raw = include_str!("../wit/clipboard.wit");
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("package "))
            .expect("WIT 分片缺 package 行");
        assert_eq!(line, format!("package {};", super::WIT_PACKAGE));
    }
}
