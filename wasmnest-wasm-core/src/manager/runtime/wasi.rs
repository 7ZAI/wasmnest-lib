//! WASI 装配面（preview2 / preview3）——**内核常编译能力，双端同源**
//!
//! **用户裁决（2026-10-12）**：WASI（p2/p3）**住核心**、双端都可用且**默认全开**，
//! 开 / 关交给外部配置（[`WasiConfig`]）；目的是将来 **worker 类别**插件
//! （ADR 0034 L3.b）双端都要跑 wasm 时，不必各端再自建一份接线。
//!
//! 因此形态（桌面 / 移动）不再是「有 WASI / 无 WASI」的差异轴：
//! - 装配面（p2/p3 linker 注册 + 预打开上下文构建）在本模块，双端共用的**唯一**
//!   运行时壳消费同一份（单形态 2026-10-13 起无 common/bare 两壳）。
//!   移动宿主当前产物是 wasm32-unknown-unknown（不 import WASI），注册惰性无效；
//!   将来 worker 产物改为 wasip2/p3 即直接可用，无需再改装配代码。
//! - 开关是**运行期配置**（不是编译期形态 feature）。注册发生在运行时构建期
//!   （linker 一次装配就固化），故 [`crate::config::WasiConfig`] 的运行期覆盖对
//!   已建 linker 不生效——与 Engine 参数的固化语义同类，见
//!   [`crate::manager::runtime::WasmRuntime::set_config`] 的 warn；要改需重建运行时。
//!
//! 预打开目录（manifest `wasiPreopenDirs`，**仅 worker 类别**，ADR 0034）的展开 /
//! 授权过滤 / 挂载也在本模块：`expand_preopen_declarations` →
//! `resolve_preopen_dirs` → `build_ctx`。

use wasmtime::component::Linker;
use wasmtime_wasi::{p2, p3, FsPerms, WasiCtxBuilder};

use super::{WasmHostContext, WasmPluginState};
use crate::config::WasiConfig;
use crate::manifest::WasiPreopenDir;
use crate::runtime_util::block_on_async;
use crate::AppError;

// ==================== linker 注册（配置驱动） ====================

/// 将 WASI 接口注册到 component linker（按 [`WasiConfig`]）
///
/// - [`WasiConfig::enabled`] 关：p2 / p3 一律不注册——此后任何 import WASI 的插件
///   在**实例化**阶段即失败（缺 import 实现），失败可见、不静默降级；
/// - [`WasiConfig::p2`] / [`WasiConfig::p3`] 分别控制两代接口（版本不同名，可共存）。
///
/// 不 import 对应 WASI 的插件（unknown-unknown 既有产物 / 无 wasi 需求者）不受影响
/// ——linker 中无对应 import 的注册是惰性的。
pub(crate) fn add_to_linker(
    linker: &mut Linker<WasmPluginState>,
    cfg: &WasiConfig,
) -> crate::Result<()> {
    if !cfg.enabled {
        tracing::info!(
            "WASI 面按配置关闭（wasi.enabled=false）：p2/p3 均不注册，import WASI 的插件将实例化失败"
        );
        return Ok(());
    }
    if cfg.p2 {
        // WASI preview2（wasm32-wasip2 插件经 std::fs 直接访问文件所需的全部接口：
        // clock/random/cli/filesystem/io/sockets）。
        // 票 02：同步 adapter（add_to_linker_sync）在 async store 下调用线进入
        // tokio runtime 上下文后其内部 ambient block_on 会重入 panic
        // （"Cannot start a runtime from within a runtime"，实证 wasi preopen e2e），
        // 改使 async adapter（fiber 内原生 await，与 wasip3 p3 同机制）。
        p2::add_to_linker_async(linker).map_err(|e| {
            AppError::Plugin(format!(
                "Failed to register WASI preview2 interfaces: {}",
                e
            ))
        })?;
    } else {
        tracing::info!("WASI preview2 按配置关闭（wasi.p2=false）");
    }
    if cfg.p3 {
        // WASI 0.3（wasm32-wasip3 插件）：p3 模块提供 wasi:cli@0.3.0 / clocks / random /
        // filesystem / sockets，接口版本与 p2（wasi:cli@0.2.0 等）不同名可共存；
        // 内部以 func_wrap_async 注册（CM_ASYNC 并发模型），仅 wasip3 组件消费，
        // 既有插件不导入 wasi0.3 则注册惰性无效。
        p3::add_to_linker(linker).map_err(|e| {
            AppError::Plugin(format!(
                "Failed to register WASI 0.3 (p3) interfaces: {}",
                e
            ))
        })?;
    } else {
        tracing::info!("WASI 0.3（p3）按配置关闭（wasi.p3=false）");
    }
    Ok(())
}

// ==================== WASI 预打开（挂载档 + 授权过滤） ====================

/// 空 WASI 上下文（无预打开目录）
///
/// 用于「无 manifest 预打开声明面」的实例化路径（移动形态当前即此类：插件产物是
/// wasm32-unknown-unknown，不 import WASI；worker 接线后改经 [`build_ctx`] 装配声明）。
/// 与「有声明但全部未授权」同形——guest 侧自检会引导用户，不静默放行。
pub(crate) fn empty_ctx() -> wasmtime_wasi::WasiCtx {
    WasiCtxBuilder::new().build()
}

/// 构建 WASI 上下文：将 manifest 声明（`wasiPreopenDirs`，经展开+授权过滤）的
/// 目录逐项预打开到 guest 路径 `/data`、`/data1`、…；无声明时为空上下文。
/// 单项失败仅告警不阻断（该目录 guest 不可见，由插件激活时自检并引导用户）。
///
/// **仅 worker 类别（`lifecycle: ephemeral`，ADR 0032 L3.b 预留）可用**（ADR 0034）：
/// 主 wasm-app 文件访问一律走宿主 `host-fs` 授权机制，非 worker 声明 preopen 在
/// 构建期与加载期双侧显性拒绝——本函数是 worker 启用后的预留能力装配点，
/// 当前对一切可加载 manifest 不可达（worker 未实现）。
///
/// 挂载档由条目声明决定（审计票 07 只读档）：`readonly: true` → `FsPerms::ReadOnly`，
/// 其余（裸路径 / `readonly` 缺省或 false）→ `FsPerms::ReadWrite`，与改造前逐字一致。
/// 档位**不影响是否放行**——未授权目录两档都建不出 preopen（[`resolve_preopen_dirs`]）。
///
/// 返回 `(WasiCtx, 实际预打开成功目录)`：后者供激活时判定「新授权目录是否已
/// 纳入当前实例」（见 `LoadedWasmPlugin::preopened_dirs`）。
///
/// 目录创建是宿主职责：授权即代表用户同意插件在该路径写数据；而
/// `preopened_dir` 要求目录已存在（wasmtime 语义），首次启用前数据目录通常
/// 尚未创建，缺失会导致 preopen 静默失败、/data 挂不上。故此处先幂等
/// `create_dir_all` 再挂载——修复首次启用「WASI 预打开目录未就绪」死循环。
/// 只读档同样先建目录：宿主建空目录只是给 guest 一个可挂载的锚点，guest 自己
/// 仍写不进去——写能力在 WASI 层由 `OpenMode` 拒掉（见 wasmtime-wasi 的
/// `preopened_dir`：`ReadOnly` → `OpenMode::READ`）。
pub(crate) fn build_ctx(
    host_ctx: &WasmHostContext,
    plugin_id: &str,
    declared_dirs: &[WasiPreopenDir],
    cfg: &WasiConfig,
) -> (wasmtime_wasi::WasiCtx, Vec<String>) {
    // 配置整体关闭：不给任何预打开能力（空上下文，与「无声明」同形）
    if !cfg.enabled {
        tracing::info!(
            plugin_id = %plugin_id,
            "wasi.enabled=false：跳过 WASI 预打开装配（空上下文）"
        );
        return (empty_ctx(), Vec::new());
    }
    let mut builder = WasiCtxBuilder::new();
    let mut preopened = Vec::new();
    for (i, dir) in resolve_preopen_dirs(host_ctx, plugin_id, declared_dirs)
        .into_iter()
        .enumerate()
    {
        // 首个声明挂载到 /data（WASI 插件约定根），后续依次 /data1、/data2…
        let guest_path = if i == 0 {
            "/data".to_string()
        } else {
            format!("/data{}", i)
        };
        let host_path = dir.path().to_string();
        let (perms, perms_label) = if dir.readonly() {
            (FsPerms::ReadOnly, "read-only")
        } else {
            (FsPerms::ReadWrite, "read-write")
        };
        if let Err(e) = std::fs::create_dir_all(&host_path) {
            tracing::warn!(
                plugin_id = %plugin_id,
                dir = %host_path,
                error = %e,
                "WASI preopen dir creation failed, directory not visible to plugin"
            );
            continue;
        }
        match builder.preopened_dir(&host_path, &guest_path, perms) {
            Ok(_) => {
                tracing::info!(
                    plugin_id = %plugin_id,
                    dir = %host_path,
                    perms = %perms_label,
                    "WASI preopened dir at {} (manifest declared)",
                    guest_path
                );
                preopened.push(host_path);
            }
            Err(e) => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    dir = %host_path,
                    error = %e,
                    "WASI preopen failed, directory not visible to plugin"
                );
            }
        }
    }
    (builder.build(), preopened)
}

/// 展开 manifest `wasiPreopenDirs` 声明为主机路径候选列表（挂载档原样带过）
///
/// 纯字符串处理（`${home}` 展开 + 剥尾部分隔符 + 滤空），不查授权、不依赖
/// tokio 运行时——preauthorize 阶段用它收集「需弹窗授权」的路径候选
/// （[`resolve_preopen_dirs`] 在此基础上再过滤未授权项）。
///
/// 消费方在桌面装配面（`manager/host/preauth.rs`：移动宿主不经 host.rs 的
/// preauthorize 编排，files 授权直连 host_api/fs）；移动形态不消费，单形态
/// 共享故保留 + 按形态豁免
#[cfg_attr(not(feature = "desktop-assembly"), allow(dead_code))]
pub(crate) fn expand_preopen_declarations(
    plugin_id: &str,
    declared_dirs: &[WasiPreopenDir],
) -> Vec<WasiPreopenDir> {
    expand_preopen_declarations_with_home(plugin_id, declared_dirs, None)
}

/// [`expand_preopen_declarations`] 的可注入 home 变体（测试用临时目录构造伪 HOME，
/// 避免依赖真实 `$HOME` 导致的无主目录环境静默跳过，dev 合入）
fn expand_preopen_declarations_with_home(
    plugin_id: &str,
    declared_dirs: &[WasiPreopenDir],
    home_override: Option<&std::path::Path>,
) -> Vec<WasiPreopenDir> {
    let home = home_override
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(['/', '\\'])
                .to_string()
        })
        .or_else(|| {
            dirs::home_dir().map(|p| {
                p.to_string_lossy()
                    .trim_end_matches(['/', '\\'])
                    .to_string()
            })
        });
    declared_dirs
        .iter()
        .filter_map(|decl| {
            let dir = match home.as_ref() {
                Some(home) => decl.path().trim().replacen("${home}", home, 1),
                None => {
                    tracing::warn!(plugin_id = %plugin_id, "wasiPreopenDirs: home_dir unavailable, skipping");
                    return None;
                }
            };
            // 只剥尾部分隔符：trim_matches 会连 POSIX 绝对路径的起始 '/' 一起
            // 剥掉（/tmp/x → tmp/x），相对化后授权匹配必然失败——Windows 盘符
            // 前缀掩盖了此问题，Linux 首次跑通前从未暴露
            let dir = dir.trim().trim_end_matches(['/', '\\']).trim_end().to_string();
            (!dir.is_empty()).then(|| decl.clone().with_path(dir))
        })
        .collect()
}

/// 解析 manifest `wasiPreopenDirs` 声明为可预打开的主机路径列表（含挂载档）
///
/// **仅 worker 类别可用**（ADR 0034，机制保留为 worker 预留能力）；主 wasm-app
/// 不经过此路径（非 worker 声明 preopen 已被加载期闸门拒绝）。
///
/// - 先经 [`expand_preopen_declarations`] 展开
/// - 仅保留已授权目录（is_granted 无弹窗校验）：manifest 路径可能指向任意
///   主机位置，不得绕过授权机制建立预打开。只读档同样要授权——档位只收紧
///   guest 能力，不放宽宿主边界（票 07 裁决 3）
/// - **所需能力按档位取**（票 02 操作拆分）：只读档要读授权，读写档要读 + 写授权。
///   预打开把这两项能力直接交给 guest（WASI 层不再过宿主闸门），所以授权记录必须
///   覆盖对应能力——否则「授权读」的目录换来一个可写 preopen，操作拆分被原地架空
/// - 无 tokio 运行时上下文（无头场景）无法查询授权 → 返回空（不阻断加载）
pub(crate) fn resolve_preopen_dirs(
    host_ctx: &WasmHostContext,
    plugin_id: &str,
    declared_dirs: &[WasiPreopenDir],
) -> Vec<WasiPreopenDir> {
    resolve_preopen_dirs_with_home(host_ctx, plugin_id, declared_dirs, None)
}

/// [`resolve_preopen_dirs`] 的可注入 home 变体（测试用临时目录构造伪 HOME，dev 合入）
fn resolve_preopen_dirs_with_home(
    host_ctx: &WasmHostContext,
    plugin_id: &str,
    declared_dirs: &[WasiPreopenDir],
    home_override: Option<&std::path::Path>,
) -> Vec<WasiPreopenDir> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Vec::new();
    }
    use crate::security::fs_auth::FsOps;
    expand_preopen_declarations_with_home(plugin_id, declared_dirs, home_override)
        .into_iter()
        .filter(|dir| {
            let needed = if dir.readonly() {
                FsOps::READ
            } else {
                FsOps::READ_WRITE
            };
            // 票 02 B5：`is_granted` 是 FsAuthChecker 具体机制方法（不在窄
            // FsAuthGate trait 上）——经下转型访问器取回（桌面装配恒 Some）
            let checker = host_ctx.fs_auth_checker();
            block_on_async(checker.is_granted(plugin_id, dir.path(), needed))
        })
        .collect()
}
