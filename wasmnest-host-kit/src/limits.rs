//! Store 资源上限（机制面）：单插件维度的线性内存 / 表 / 燃料上限
//!
//! 与宿主 `core-config` 的关系：本文件是**上限值对象 + 编译期默认值 + 纯逻辑计算**，
//! 宿主 `core-config` 保留「Engine 参数 + 配置文件分层加载 + 覆盖合并」这些面。
//! 拆分理由：这些上限值对象的**消费方是机制**（`WasmPluginState` 的 ResourceLimiter
//! 与燃料注入点），而消费方住在宿主 bin crate 内 ⇒ 值对象必须与消费方同 crate 才能
//! 被字段类型直接引用。
//!
//! **本文件不读进程环境、不做构建形态判断**（2026-10-14 收口）：debug 模式燃料放大
//! 的开关判断（`WASMNEST_PLUGIN_DEBUG` + `debug_assertions`）与纯 Engine 参数默认值
//! （backtrace 帧数）已上移 wasm-core `config`——调用方把 [`StoreLimits::fuel_budget_for`]
//! 的 `debug_mode` 显式传入。本模块只剩「state 字段类型需要的那部分」：值对象 +
//! 编译期默认值 + 纯函数。
//!
//! 「覆盖请求合并」（[`StoreLimits::clamped_within`] 的收紧语义）**刻意留在宿主**：
//! 它的输入是插件 SDK 的 manifest 类型，属宿主配置面而非机制面；宿主以
//! `config::apply_store_overrides(&base, &request)` 自由函数承接。

use serde::{Deserialize, Serialize};

// ==================== 编译期默认值 ====================

/// 编译期默认值——与历史生产常量逐一相等（对照测试锁定），
/// 也是单插件覆盖的硬上限（任何覆盖不得突破）
pub mod defaults {
    /// 单次 wasm 导出调用允许消耗的燃料（指令数）——防失控/恶意插件无限执行
    ///
    /// 用燃料（fuel）而非 epoch 墙钟窗口做看门狗：
    /// - 燃料只计 guest 指令数，宿主调用阻塞期间（授权弹窗、目录扫描、网络）
    ///   guest 零消耗——慢宿主调用无论多久都不会被误杀；epoch 按墙钟计，
    ///   宿主阻塞期间照走，正是历史上误杀慢调用的根因
    /// - 纯 guest 死循环持续烧燃料，必然耗尽被 trap（确定性，不受宿主负载影响）
    /// - 每次导出调用前重置燃料，预算只约束单次调用内 guest 计算量，
    ///   与宿主延迟彻底解耦
    ///   64G 指令 ≈ 数十秒纯 guest 计算（wasm32 release 约 1-3G 指令/秒），
    ///   覆盖大 JSON 解析等重活；死循环最迟烧完被 trap
    pub const FUEL_PER_CALL: u64 = 64_000_000_000;
    /// 插件调试模式（`WASMNEST_PLUGIN_DEBUG=1`）下燃料预算放大倍率
    ///
    /// debug profile 的 wasm 产物不做优化，指令数与体积相对 release 成倍膨胀
    /// （典型 10-30 倍），同一逻辑在 debug 产物下烧燃料更快；若不放大，正常
    /// 插件调用可能被燃料看门狗误判为失控 trap。取 32 倍覆盖 debug 膨胀上界
    /// 并留余量；仅调用方显式传入的 `debug_mode` 为真时生效（判断在 wasm-core
    /// `config::plugin_debug_mode`）
    pub const FUEL_DEBUG_MULTIPLIER: u64 = 32;
    /// 单插件线性内存上限（字节）——防失控/恶意插件耗尽宿主内存
    ///
    /// 双重身份：既是资源限制器的增长拒绝线，也是 Engine 层
    /// `memory_reservation` 预留量的估算依据（估算的最大线性内存）：实例化时按此值
    /// 一次性预留虚拟地址空间，guest 内存增长全程落在预留内（零系统调用、基址不搬移），
    /// 触及上限前已被 limiter 拒绝。预留只占虚拟地址空间，物理内存仍按实际触碰页提交。
    /// 两处必须严格一致：预留小于上限会让合法增长退化为搬移路径，
    /// 大于上限则白白放大 VA 占用
    pub const MAX_PLUGIN_MEMORY_BYTES: usize = 256 * 1024 * 1024;
    /// 单插件表元素上限
    pub const MAX_PLUGIN_TABLE_ENTRIES: usize = 1_000_000;
    /// Wasm 执行栈深度上限（字节）——guest 深度递归超限即确定性栈溢出 trap
    ///
    /// 防递归打穿真实线程栈导致进程 abort。宿主函数栈帧不计入此预算但计入真实
    /// 线程栈，故该值必须显著小于调用方线程栈余量（tokio blocking / std 线程
    /// 默认 2MiB）。与 wasmtime 默认一致（512KiB），显式钉死防止上游默认漂移
    pub const MAX_WASM_STACK_BYTES: usize = 512 * 1024;
    /// 单 Store 核心实例数上限
    ///
    /// 组件实例化会为 wit-component 嵌入的 adapter module 派生额外核心实例
    /// （正常插件 1-2 个），留余量的同时封顶防滥用；超限实例化直接报错
    pub const MAX_PLUGIN_INSTANCES_PER_STORE: usize = 8;
    /// 单 Store 线性内存数量上限
    ///
    /// 每个线性内存独立预留 VA（上限 × ~288MiB 含 guard），多内存声明会线性
    /// 放大虚拟地址空间占用，WASI preview2 插件正常仅 1 个内存
    pub const MAX_PLUGIN_MEMORIES_PER_STORE: usize = 4;
    /// 单 Store 表数量上限
    pub const MAX_PLUGIN_TABLES_PER_STORE: usize = 16;
}

/// Store 资源上限（单插件维度，实例化时快照注入）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoreLimits {
    /// 单次导出调用燃料预算（debug 模式按 [`Self::fuel_debug_multiplier`] 放大）
    pub fuel_per_call: u64,
    /// 插件调试模式燃料放大倍率
    pub fuel_debug_multiplier: u64,
    /// 单插件线性内存上限（字节）
    pub max_memory_bytes: usize,
    /// 单插件表元素上限
    pub max_table_entries: usize,
    /// Wasm 执行栈深度上限（字节）——Engine 构建参数，此处仅为覆盖快照同构保留
    pub max_wasm_stack_bytes: usize,
    /// 单 Store 核心实例数上限
    pub max_instances: usize,
    /// 单 Store 线性内存数量上限
    pub max_memories: usize,
    /// 单 Store 表数量上限
    pub max_tables: usize,
}

impl StoreLimits {
    /// 燃料预算的纯逻辑形态：按 `debug_mode` 决定是否应用放大倍率
    ///
    /// debug 判断由调用方显式传入（wasm-core `config::plugin_debug_mode`，见
    /// 模块头「本文件不读进程环境」）——使本层单测可直接覆盖倍率分支、不依赖
    /// 进程级环境变量（测试并行安全）；机制锚点也无需再持有宿主策略。
    ///
    /// 乘法饱和防溢出（R-03）：放大倍率与燃料预算都是配置可控值，超大组合在
    /// debug 构建 panic / release 静默回卷会让看门狗预算失真；饱和到 u64::MAX
    /// 后 wasmtime 侧超限注入会拒绝而非回卷出小预算（伪看门狗）。非法配置本身
    /// 由宿主 `CoreConfig::validate` 的 checked_mul 检查在加载期拒绝。
    pub fn fuel_budget_for(&self, debug_mode: bool) -> u64 {
        if debug_mode {
            self.fuel_per_call
                .saturating_mul(self.fuel_debug_multiplier)
        } else {
            self.fuel_per_call
        }
    }

    /// 当前配置值内的钳制（逐字段 min）——单插件覆盖的收紧语义：
    /// 请求可更紧，放宽被钳回
    pub fn clamped_within(&self, ceiling: &StoreLimits) -> StoreLimits {
        StoreLimits {
            fuel_per_call: self.fuel_per_call.min(ceiling.fuel_per_call),
            fuel_debug_multiplier: self
                .fuel_debug_multiplier
                .min(ceiling.fuel_debug_multiplier),
            max_memory_bytes: self.max_memory_bytes.min(ceiling.max_memory_bytes),
            max_table_entries: self.max_table_entries.min(ceiling.max_table_entries),
            max_wasm_stack_bytes: self.max_wasm_stack_bytes.min(ceiling.max_wasm_stack_bytes),
            max_instances: self.max_instances.min(ceiling.max_instances),
            max_memories: self.max_memories.min(ceiling.max_memories),
            max_tables: self.max_tables.min(ceiling.max_tables),
        }
    }
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            fuel_per_call: defaults::FUEL_PER_CALL,
            fuel_debug_multiplier: defaults::FUEL_DEBUG_MULTIPLIER,
            max_memory_bytes: defaults::MAX_PLUGIN_MEMORY_BYTES,
            max_table_entries: defaults::MAX_PLUGIN_TABLE_ENTRIES,
            max_wasm_stack_bytes: defaults::MAX_WASM_STACK_BYTES,
            max_instances: defaults::MAX_PLUGIN_INSTANCES_PER_STORE,
            max_memories: defaults::MAX_PLUGIN_MEMORIES_PER_STORE,
            max_tables: defaults::MAX_PLUGIN_TABLES_PER_STORE,
        }
    }
}
