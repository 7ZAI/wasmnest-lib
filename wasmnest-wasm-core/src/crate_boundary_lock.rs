//! crate 边界锁共享面（wasm-core-whole-crate 票 05 落点：登记表唯一化）
//!
//! 原 `SPLIT_CRATES` / `server_lib_src_roots()` 定义在 lib `server/crate_boundary_lock.rs`，
//! 被 wasm_core 的两把退役面锁（`api_bridge.rs` / `wasm_flow_test.rs`）与 lib 侧的
//! 全图断言共同消费。整核抽出后两个消费方随 `wasm_core/` 迁入本 crate，而 lib 的锁仍在
//! lib——crate 不能反向依赖 lib（循环），故**登记表的单一事源上提本 crate**：lib 侧的
//! `server/crate_boundary_lock.rs` 经 `wasmnest_wasm_core::crate_boundary_lock` 取本模块
//! （lib → crate 方向合法，单向引用）。新增/改名拆分产物只需改本表一处。
//!
//! 本模块是只读磁盘路径的工具面（`std` 自带），不引入任何生产依赖；常编译（非
//! `#[cfg(test)]`）是因为 lib 侧的锁在**非 test 构建**里也要经它取登记表。

/// 拆分产物清单（`(crate 名, 相对本 crate manifest 目录的父目录的路径)`）——**单一事实源**。
///
/// **路径列现在只有一类**：能力域 / 传输面 crate、机制内核 `wasmnest-host-kit` 与
/// 本 crate `wasmnest-wasm-core` 自身全部落**仓库根 `packages/`**（2026-10-08
/// 整核本体迁根，与 2026-10-07 迁根的 8 个能力域 crate 同根），记作裸 crate 名。
/// 基准目录两种写法都必须能解析到真实目录——
/// 断言① 会逐条扫 `src`，路径写错会退化成「扫不到即无命中」的假绿灯。
///
/// 含 `wasmnest-wasm-core` 自身：整核抽出后它也是拆分产物（宿主 bin → 可复用 crate），
/// 登记进来让 lib 侧全图断言（断言① 无横向边 / 断言③ 宿主清单声明全部拆分产物）
/// 把它一并纳入检查——否则本 crate 的依赖清单不受边界锁管辖。
/// 含 `wasmnest-pty-engine`：wasm-core 纯净性收口票 02 从本 crate 迁出的 PTY
/// 引擎面（票 02 批次 02 起宿主**直接**依赖它：端口 adapter / 强制引用行 /
/// 白名单条目同落 `src-tauri/src/plugin/pty.rs`，本 crate 与它的依赖边已摘——
/// lib 侧 ALLOWED_DOWNWARD_EDGES / REQUIRED_DOWNWARD_EDGES 同步摘除）。
pub const SPLIT_CRATES: &[(&str, &str)] = &[
    ("wasmnest-server-base", "wasmnest-server-base"),
    ("wasmnest-server-core", "wasmnest-server-core"),
    ("wasmnest-server-http", "wasmnest-server-http"),
    ("wasmnest-server-websocket", "wasmnest-server-websocket"),
    ("wasmnest-server-peer-net", "wasmnest-server-peer-net"),
    ("wasmnest-crypto-engine", "wasmnest-crypto-engine"),
    ("wasmnest-host-kit", "wasmnest-host-kit"),
    // 组播发现能力域：票 02 批次 03 起宿主直接依赖（adapter 在
    // `src-tauri/src/plugin/mdns.rs`），本 crate 与它已无边。
    ("wasmnest-discovery-engine", "wasmnest-discovery-engine"),
    // host-pty 能力域（票 02 迁引擎体 → ADR 0039 整面迁出）：引擎面 + WIT 接线 +
    // 域机制全在 wasmnest-pty-engine（自带 `bindgen!` + `HostModule` 自报，不依赖本
    // crate）；端口 adapter 自票 02 批次 02 起住宿主
    // `src-tauri/src/plugin/pty.rs`（宿主直接依赖，本 crate 与它已无边）。
    ("wasmnest-pty-engine", "wasmnest-pty-engine"),
    // 本 crate 自身（wasm-core-whole-crate 票 05：拆分产物清单含整核抽出本体）
    ("wasmnest-wasm-core", "wasmnest-wasm-core"),
];

/// 拆分产物的 `src` 扫描根（供 crate / lib 两侧退役面防回接锁共用）
///
/// 基准 = 本 crate 的 manifest 目录（`packages/wasmnest-wasm-core`，2026-10-08 迁根）
/// 的**父目录**（=`packages/` 仓库根，与 lib 侧 `crate_root().join("..").join("..")`
/// `.join("packages")` 同一落点）；表内的裸 crate 名条目即由此直接解析。
/// lib 侧 `server_lib_src_roots()` 输出相同路径集合。
pub fn server_lib_src_roots() -> Vec<std::path::PathBuf> {
    let packages_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    SPLIT_CRATES
        .iter()
        .map(|(_, rel)| packages_dir.join(rel).join("src"))
        .collect()
}
