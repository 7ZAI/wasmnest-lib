//! WasmNest 通知域契约房（**只持契约，零实现**；ADR 0052 D2/D4 · 票 04）
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
