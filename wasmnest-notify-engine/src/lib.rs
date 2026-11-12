//! `WasmNest` 通知域契约房（**只持契约，零实现**；ADR 0052 D2/D4 · 票 04）
//!
//! ## 为什么是一个独立 crate
//!
//! 系统通知是**双端同功能**的能力（R2 功能级交集）：桌面经 Tauri 事件发前端
//! toast、移动经 Android 通知桥投递，功能一致 → 统一为一份共享契约
//! `wit/notify.wit`。本域没有可共享的引擎实现（两端投递机制完全不同，且都只有
//! 几行宿主代码），故按 ADR 0052 D2/D4 的轻量契约房形态承载：
//! crate 只持 WIT + 端口词汇（当前无端口），实现按端住宿主
//! （桌面 `src-tauri/src/plugin/notify.rs`；移动 `src-tauri/src/plugin/notify.rs`）。
//!
//! ## 边界（防回接）
//!
//! - 本 crate **不得**出现任何桌面 / 移动专属实现或依赖（端差异归宿主）；
//! - `wit/notify.wit` 是 `host-notify` 的**唯一真源**——双端 `compose.json`
//!   经 `caps.notify` 直接消费它，端生成物由 `scripts/compose-wit.mjs` 拼装；
//! - 通知的**平台不支持项静默忽略**（桌面无震动 / 提示音通道）写死在契约文档里，
//!   实现端不得改成报错（见 WIT 文档）。
//!
//! 实现落点与权限语义的现行口径见 `wit/notify.wit` 的 interface 文档与各端宿主
//! adapter（本文件不复制漂移源）。

// ==================== 契约包身份（WIT 按包拆分，ADR 0061） ====================

/// 本能力域 WIT 包全名（`namespace:name@version`）
///
/// 与 `wit/notify.wit` 的 `package` 行逐字一致（下方锁测试断言），也是宿主
/// `MODULE_INTERFACES` 各项的前缀。拆包后每个能力域独立版本：只在本包 WIT
/// 变更时 bump，不再随 `wasmnest:plugin` 全局版本前进。
pub const WIT_PACKAGE: &str = "wasmnest:notify@0.0.1";

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
        let raw = include_str!("../wit/notify.wit");
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("package "))
            .expect("WIT 分片缺 package 行");
        assert_eq!(line, format!("package {};", super::WIT_PACKAGE));
    }
}
