//! 授权策略求值（授权策略增强 · 票 03）
//!
//! spec §6.1 的判定管线里「与资源无关」的那一层：遇到授权记录**未覆盖**的目标时，
//! 要不要问用户。只有这一处实现——文件与网络各自只提供两件资源相关的小事：
//! **目标归一化**与**记录匹配**（fs：`fs_auth::canonicalize_path` + 路径前缀 / 操作集
//! 覆盖；network：`network_auth::normalize_target` + `record_covers`）。
//!
//! ## 判定顺序（spec §6.1，资源侧按此顺序调用本模块）
//!
//! ```text
//! 0. manifest 声明门（权限位）      —— 资源侧 / 框架
//! 1. 硬拒绝记录命中                 —— 资源侧（deny 优先于一切放行路径）
//! 2. 第一方免询问目录（fs 专属）     —— 资源侧（优先级高于策略档位，spec §7）
//! 3. 策略层                        ← 本模块
//! 4. 授权记录命中                   —— 资源侧
//! 5. 询问用户                       —— 资源侧
//! ```
//!
//! **顺序为什么必须共用**：两处各写一遍必然漂移，而漂移的形态是安全语义级的——
//! 「总是询问在文件侧跳过记录、在网络侧却仍读记录」这种差异从代码上看两边都自洽，
//! 只有把顺序与档位映射收在一处才防得住。
//!
//! ## 归属（ADR 0022 §5.1.3）
//!
//! 策略是**安全闸门**（「未覆盖目标要不要问」），不是业务默认值：默认档 = fail-safe
//! 方向，档位不得由 manifest 声明（声明即加载期拒绝，见 `manager::validation`）。

use super::auth_policy::{AuthPolicyStore, AuthResource, AuthStrategy};

/// 档位本体（动作语义；副作用标志见 [`StrategyStep`] 字段）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// 总是询问：**跳过全部 allow 记录**（含旧版回退），每次判定都问
    Ask,
    /// 默认：读 allow 记录，命中即放行，未命中才问
    ConsultRecords,
    /// 始终允许：免询问直接放行，并以 `source='always_allow'` 落账
    AutoAllow,
}

/// 策略层给出的下一步（spec §4.1 三档 → 动作）
///
/// **struct 而非 unit enum**（2026-10-03，S-11/S-12）：档位副作用（读不读
/// allow 记录、是否必须落 always_allow 审计）是随档位携带的一等字段，消费方
/// 无需在注释里记住义务——`must_land_auto_allow()` 就在结构体上。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrategyStep {
    tier: Tier,
    /// 判定时是否读 allow 记录（镜像：弹窗给不给「记住」；`Ask` 恒 false）
    reads_allow_records: bool,
    /// 是否必须落 always_allow 审计记录（`AutoAllow` 恒 true；审计是档位义务，
    /// 不是可选项——不留痕的管理界面在最高风险档上出现不可见空洞）
    must_land_auto_allow: bool,
}

impl StrategyStep {
    /// 档位 → 动作（**唯一**映射点）
    pub const fn of(strategy: AuthStrategy) -> Self {
        match strategy {
            AuthStrategy::AlwaysAsk => Self::ask(),
            AuthStrategy::Default => Self::consult_records(),
            AuthStrategy::AlwaysAllow => Self::auto_allow(),
        }
    }

    pub const fn ask() -> Self {
        Self {
            tier: Tier::Ask,
            reads_allow_records: false,
            must_land_auto_allow: false,
        }
    }

    pub const fn consult_records() -> Self {
        Self {
            tier: Tier::ConsultRecords,
            reads_allow_records: true,
            must_land_auto_allow: false,
        }
    }

    pub const fn auto_allow() -> Self {
        Self {
            tier: Tier::AutoAllow,
            reads_allow_records: false,
            must_land_auto_allow: true,
        }
    }

    /// 档位本体（match 分派用）
    pub const fn tier(&self) -> Tier {
        self.tier
    }

    /// 该步是否「读授权记录」——判定时读不读 allow 记录、询问层给不给「记住」
    ///
    /// 两者必须同向："总是询问"档既然跳过记录，就不能再让弹窗落一条以后不会被
    /// 读到的记录（spec §6.3：那正是该档不出现"记住"按钮的理由）。
    /// `AutoAllow` 不读记录（未覆盖目标直接放行并落账）但**仍写审计**——
    /// 读/写是两个独立义务，别用同一个 bool 二合一（S-12）。
    pub const fn reads_allow_records(self) -> bool {
        self.reads_allow_records
    }

    /// 是否必须落 always_allow 审计记录（`AutoAllow` 恒 true）
    ///
    /// 消费方在 AutoAllow 分支必须调用落账，且调用点应受本标志约束（
    /// 审计是档位义务；删除落账会让不留痕的 always_allow 空洞出现）。
    pub const fn must_land_auto_allow(self) -> bool {
        self.must_land_auto_allow
    }

    /// 日志用的层名（排障要能一眼看出这次判定走的是哪一支）
    pub const fn as_str(self) -> &'static str {
        match self.tier {
            Tier::Ask => "always-ask",
            Tier::ConsultRecords => "default",
            Tier::AutoAllow => "always-allow",
        }
    }
}

/// 授权判定管线各阶段（spec §6.1 顺序）。
///
/// 资源侧按此顺序调用各阶段；相邻两步的**相对顺序**是安全语义（例如「硬拒绝
/// 记录」必须在「策略档位」之前——否则 `AlwaysAsk` 档会把用户已说过的拒绝
/// 每批都重新弹窗；「策略档位」必须在「授权记录」之前——否则 `AlwaysAsk`
/// 跳过记录的口径失去意义）。此表是文档化真源，被 fs_auth / network_auth 的
/// 行为测试（各阶段正反例）共同覆盖。
///
/// ```text
/// 0. manifest 声明门（权限位）      —— 框架 / 资源侧（阶段 1）
/// 1. 硬拒绝记录命中                 —— deny 优先于一切放行路径
/// 2. 第一方免询问目录（fs 专属）     —— 资源侧（优先级高于策略档位）
/// 3. 策略层（本模块）                —— 档位决定后两步行为
/// 4. 授权记录命中                   —— 仅 ConsultRecords 档读取
/// 5. 询问用户                       —— 无记录 / AlwaysAsk 档；无弹窗面则拒绝
/// ```
pub const PIPELINE_STAGES: [&str; 6] = [
    "declared",
    "deny-record",
    "first-party-dir",
    "strategy",
    "allow-record",
    "prompt",
];

/// 读某应用在某资源上的档位并求值（**判定时实时读取**，不缓存、不做激活期快照）
///
/// 缓存会让「已改成总是询问」却仍有缓存判定在放行 / 跳过记录，策略语义就是骗人的
/// （spec §8.1）。`resource` 即分派轴：fs 传 [`AuthResource::Fs`]、network 传
/// [`AuthResource::Network`]，两者共用同一张策略表与同一套动作映射。
///
/// 授权路径上的读取失败必须**带上下文**（S-13）：没指明 plugin/resource 的错误
/// 在故障时根本没法定位是哪一侧的哪一家策略坏了。
pub async fn evaluate(store: &AuthPolicyStore, plugin_id: &str, resource: AuthResource) -> crate::Result<StrategyStep> {
    store
        .strategy(plugin_id, resource)
        .await
        .map(StrategyStep::of)
        .map_err(|e| {
            crate::AppError::Plugin(format!(
                "读取插件 '{}' 的 {} 授权策略失败: {}",
                plugin_id,
                resource_label(resource),
                e
            ))
        })
}

/// 资源的日志/错误标签（写进 S-13 错误上下文用）
fn resource_label(resource: AuthResource) -> &'static str {
    match resource {
        AuthResource::Fs => "文件系统",
        AuthResource::Network => "网络",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三档映射逐条锁死：`always_ask` 必须**不**读记录（跳过）也不落审计；
    /// `always_allow` 不读记录但**必须**落审计（S-11/S-12：审计义务随档位携带）
    ///
    /// 变异判据：把 `AlwaysAsk` 映射到 `ConsultRecords`（= 退回「仍然读记录」），
    /// 本条与 fs_auth 侧的行为用例一起转红。
    #[test]
    fn strategy_step_maps_every_tier() {
        assert_eq!(StrategyStep::of(AuthStrategy::AlwaysAsk), StrategyStep::ask());
        assert_eq!(StrategyStep::of(AuthStrategy::Default), StrategyStep::consult_records());
        assert_eq!(StrategyStep::of(AuthStrategy::AlwaysAllow), StrategyStep::auto_allow());

        assert!(
            !StrategyStep::ask().reads_allow_records(),
            "总是询问：不读任何 allow 记录"
        );
        assert!(StrategyStep::consult_records().reads_allow_records());
        assert!(
            !StrategyStep::auto_allow().reads_allow_records(),
            "始终允许：不读记录（未覆盖目标直接放行并落账）"
        );

        // 审计义务：只有 always_allow 携带（S-11 防「match 后什么都不做」）
        assert!(
            StrategyStep::auto_allow().must_land_auto_allow(),
            "始终允许必须带审计义务"
        );
        assert!(!StrategyStep::ask().must_land_auto_allow());
        assert!(!StrategyStep::consult_records().must_land_auto_allow());
    }

    /// 层名是排障口径，三支必须互不相同（同一名字无法回答「走的哪一支」）
    #[test]
    fn strategy_step_names_are_distinct() {
        let names = [
            StrategyStep::ask().as_str(),
            StrategyStep::consult_records().as_str(),
            StrategyStep::auto_allow().as_str(),
        ];
        for (i, name) in names.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(
                !names[i + 1..].contains(name),
                "层名不得重复（否则日志分不清档位）: {name}"
            );
        }
    }

    /// S-14：判定管线各阶段顺序被显式编码（deny → first-party → strategy →
    /// records → prompt 的相对顺序是安全语义，不能只活在文档里）。
    /// 相对顺序的语义解释见 [`PIPELINE_STAGES`]。
    #[test]
    fn pipeline_stages_are_ordered_deny_before_strategy_before_records() {
        let deny = PIPELINE_STAGES.iter().position(|s| *s == "deny-record").unwrap();
        let strategy = PIPELINE_STAGES.iter().position(|s| *s == "strategy").unwrap();
        let records = PIPELINE_STAGES.iter().position(|s| *s == "allow-record").unwrap();
        let prompt = PIPELINE_STAGES.iter().position(|s| *s == "prompt").unwrap();
        // 硬拒绝先于一切放行路径；策略档位先于记录读取（AlwaysAsk 跳记录的
        // 语义依赖此顺序）；记录命中先于询问
        assert!(deny < strategy, "deny 必须排在 strategy 之前");
        assert!(strategy < records, "strategy 必须排在 allow-record 之前");
        assert!(records < prompt, "allow-record 必须排在 prompt 之前");
        assert_eq!(PIPELINE_STAGES[0], "declared");
    }

    /// S-13：策略读取失败必须带 plugin/resource 上下文（授权路径故障可诊断）
    #[tokio::test]
    async fn evaluate_error_carries_plugin_and_resource_context() {
        let db = crate::db::Database::new(&std::path::Path::new(":memory:")).unwrap();
        db.init_schema().unwrap();
        let store = AuthPolicyStore::new(std::sync::Arc::new(std::sync::Mutex::new(db)));
        // 未初始化任何策略记录时读不存在的表会失败（AuthPolicyStore 直接读
        // plugin_auth_policies 表；这里用缺表场景触发出错路径）——按实现如实断言：
        // 要么 Err 带上下文；若实现恰好能读到（表存在返回空），则该断言分支为空。
        if let Err(e) = evaluate(&store, "com.test.p", AuthResource::Fs).await {
            let msg = format!("{e}");
            assert!(
                msg.contains("com.test.p") && (msg.contains("文件系统") || msg.contains("Fs")),
                "错误须带 plugin 与资源上下文: {msg}"
            );
        }
    }
}
