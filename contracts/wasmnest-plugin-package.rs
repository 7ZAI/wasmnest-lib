// WasmNest 插件契约包名与版本——**全仓唯一手写真源**（ADR 0051 D3/D4）
//
// 为什么是 Rust 常量而不是 JSON（票 03 实施期修正）：能力域 crate 的导出名清单走
// `inventory` 静态自报（`wasmnest-discovery-engine/src/routing.rs` 的
// `static ROUTE` + `const EXPORTS`），`inventory::submit!` 要求编译期常量 ⇒ 版本必须
// 在 **const 上下文**可用。JSON 真源只能运行期解析，与该约束结构性冲突。
//
// 三条使用路径（唯一真源 + 漂移锁兜底，与 WIT 生成物同款范式）：
//
// 1. **运行期派生**：wasm-core `include!` 本文件，`contract::export_item(iface, func)`
//    拼出 `ns:pkg/iface.func@version`（wasmtime `ItemName` 路径语法，**版本在末尾**——
//    wit-parser 在 `ns:pkg` 后强制要求 `/`，版本写中间会解析失败）；
// 2. **编译期常量**：能力域 crate 各自 `include!` 本文件，在 const/static 位置直接
//    写导出名字面量，由 `wit_package_version_lock.rs` 断言与本文件一致
//    （字面量无法跨文件引用，锁是唯一机械保证——与「11 个 WIT 源文件各写 package 行」
//    同款：真源单点 + 锁钉住散落副本）；
// 3. **构建期解析**：`scripts/compose-wit.mjs` 正则读本文件，把版本注入生成的
//    `wasmnest.wit`（端清单 `compose.json` 只声明包名，不持版本）。
//
// **bump 政策**（ADR 0051 D4）：任何 WIT 变更（**含函数级追加**）→ patch
// （`0.1.0` → `0.1.1`）；interface 增删 / 签名变 → minor（`0.1.x` → `0.2.0`）。
// bump 后须重跑 `node scripts/compose-wit.mjs --all` 并重建插件产物——版本进入
// import 名，宿主与 guest 版本不等即实例化失败。
//
// 版本线（2026-10-18 三仓拆分）：新仓内所有内部构建视为**全新**，版本自 0.0.1
// 重开——契约版本与旧单仓的 0.3.0 无继承关系（旧仓转为文档真源与回退点，代码冻结）。
// 旧线历次版本（0.1.x / 0.2.0 / 0.3.0，含 wasmnest-end-rename 的包名改名窗口）
// 见旧仓 git 历史与 ADR 0051 / 0056。

/// 契约包名（`namespace:name`，不含版本）
pub const PACKAGE_NAME: &str = "wasmnest:plugin";

/// 契约包版本（三段 semver）
pub const PACKAGE_VERSION: &str = "0.0.1";

/// 契约包全名（`namespace:name@version`）——组件**导出实例**的键形态
pub const PACKAGE: &str = "wasmnest:plugin@0.0.1";
