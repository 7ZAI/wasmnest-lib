//! 旧 SDK 产物实例化失败的重建指引判据（stale_artifact_rebuild_hint）
//!
//! 自 `common/component.rs` 的 `mod tests` 拆出（共享脚手架在父 `mod tests`，
//! 经 `use super::*` 可见）；fixture 互斥与产物构建语义不变。
//!
//! 项目不承担 ABI 向后兼容义务（研发起步期无外部公开契约，AGENTS.md §0）：
//! 不再按历史 ABI 版本枚举判据矩阵（v27/v28/v31/v33/v36/v37… 逐版重建文案与
//! 「升级 WasmNest」反向分支）。判据收敛为 wasmtime 的「缺失 import/export」通用
//! 文案：命中则给统一重建指引；与契约无关的失败返回空串（不加噪音）。

use super::*;

/// wasmtime 的缺失 import/export 文案（含 interface 名的几种形态）→ 必须附重建
/// 指引；与之无关的实例化失败（WASI 缺目录 / trap）→ 不得附（噪音会掩盖真因）。
///
/// 端到端那一半（真拿一个旧 ABI 产物加载）**无法在本环境复现**：插件产物不入库、
/// 旧 SDK 与旧 WIT 都已不在工作区。故本用例锁的是**判据本身**。
#[test]
fn stale_artifact_instantiation_hint_is_selective() {
    // 形态 1：组件模型缺失 import 的标准文案（import instance 形态）
    let msg = "component imports instance `wasmnest:plugin/host-session`, but a matching \
                   implementation was not found in the linker";
    let hint = LoadedWasmPlugin::stale_artifact_rebuild_hint(msg);
    assert!(
        hint.contains("重建插件产物"),
        "缺失 import 必须给重建指引: {hint}"
    );

    // 形态 2：缺失单个 import 函数/接口的文案（`unknown import … has not been
    // defined`）——旧产物 import 已退役函数（如 host-events.broadcast-sync）即此形态
    let hint_fn = LoadedWasmPlugin::stale_artifact_rebuild_hint(
        "unknown import `wasmnest:plugin/host-events.broadcast-sync` has not been defined",
    );
    assert!(
        hint_fn.contains("重建插件产物"),
        "缺失 import 函数必须给重建指引: {hint_fn}"
    );

    // 形态 3：被删的 export interface（宿主按必选导出实例化，缺导出同样失败）
    let hint_export =
        LoadedWasmPlugin::stale_artifact_rebuild_hint("component does not export terminal-hooks");
    assert!(
        hint_export.contains("重建插件产物"),
        "缺失必选导出必须给重建指引: {hint_export}"
    );

    // 反向：与契约变更无关的实例化失败不得附指引（避免掩盖 WASI 缺目录 / trap 真因）
    assert!(
        LoadedWasmPlugin::stale_artifact_rebuild_hint("failed to find a pre-opened directory")
            .is_empty(),
        "WASI 缺目录不是旧契约失败，不得附重建指引"
    );
    assert!(LoadedWasmPlugin::stale_artifact_rebuild_hint(
        "wasm trap: out of bounds memory access"
    )
    .is_empty());
    // 纯业务错误文案也不得误命中（判据锚在 wasmtime 缺失 import 形态，非关键词）
    assert!(LoadedWasmPlugin::stale_artifact_rebuild_hint("认证中心未注册").is_empty());
}
