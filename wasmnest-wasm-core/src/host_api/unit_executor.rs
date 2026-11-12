//! 任务单元执行器策略接口（C4：core-task 只依赖接口，不依赖具体域函数）
//!
//! `manager::task` 的 execute_unit 原本按 kind 字符串直调 `host_api::{fs,http,
//! process}` 具体函数（manager → host_api 具体实现的横向耦合）。本 trait 由各
//! 能力域实现（fs / process / http 执行器），`manager::task` 经注册表（组合根 /
//! 测试装配注入）按 kind 分发——依赖方向收束为「host_api 定义接口、manager 组合
//! 实现」，单元执行语义零变化（spec 票 07 C4：wire 不变量不变，params 原样透传）。
//!
//! ## 为什么接口留在内核（票 02 批次 05 对票面 §3 清单的修正）
//!
//! 本 trait 的**消费方是留内核的任务引擎**（`manager::task` 的执行器注册表与
//! dispatch）——C4 的「消费方定义接口」判据下，引擎不迁则接口不迁。随域迁出的是
//! **执行器实现**（`FsUnitExecutor` / `HttpUnitExecutor` 留在各自域文件、
//! `ProcessUnitExecutor` 随 host-process 域迁宿主），它们的**注册**改走下方
//! 「自报收集」面：域文件 `submit_unit_executor!` 自报，内核装配点遍历收集——
//! 内核注册点不点名任何具体执行器，宿主侧执行器迁入后内核装配代码零改动。

use std::any::Any;
use std::sync::Arc;

use crate::host_api::context::WasmHostContext;

/// 单元执行器（策略）：按 kind 匹配 + 执行既有域原语
///
/// - `matches(&kind)`：本执行器是否负责该 kind（fs 执行器为 `fs.` 前缀）
/// - `execute`：执行单元。授权预检属于各域自己的契约（fs 执行器先做「声明闸门 +
///   fs_auth 已授权校验」，**绝不从池线程触发弹窗**；需要新授权时插件须先经
///   `host-fs.request-auth`）。返回值是单元原语返回值的 JSON 编码。
///
/// `Any` 超接口用于注册表按具体类型幂等去重（组合根与测试装配都可能注册）。
pub trait UnitExecutor: Any + Send + Sync + 'static {
    /// 本执行器是否负责该 kind
    fn matches(&self, kind: &str) -> bool;

    /// 执行一个 kind 单元（permission 门禁由目标域函数内部再把守）
    fn execute(
        &self,
        host_ctx: &Arc<WasmHostContext>,
        owner: &str,
        kind: &str,
        params: &serde_json::Value,
    ) -> Result<Option<String>, String>;
}

// ==================== 执行器自报（域自报、内核收集；与 host-kit 钩子/端口同范式） ====================

/// 执行器自报条目（域文件提交；内核装配点遍历注册）
///
/// `make` 是工厂而非实例：`UnitExecutor: Any` 的幂等去重要按具体类型取 `type_id`，
/// 每次注册现造实例即可（进程级注册表按类型去重后只留一份）。
pub struct UnitExecutorEntry {
    /// 执行器名（装配日志可读；kind 前缀即名，如 `"fs."` / `"http.fetch"`）
    pub name: &'static str,
    /// 构造执行器实例
    pub make: fn() -> Arc<dyn UnitExecutor>,
}

inventory::collect!(UnitExecutorEntry);

/// 域侧提交宏：把本域的任务单元执行器自报进全局收集表
///
/// 用法（域实现文件内）：
/// ```ignore
/// crate::submit_unit_executor!("fs.", || Arc::new(FsUnitExecutor));
/// ```
#[macro_export]
macro_rules! submit_unit_executor {
    ($name:expr, $make:expr) => {
        ::inventory::submit! {
            $crate::host_api::unit_executor::UnitExecutorEntry { name: $name, make: $make }
        }
    };
}

/// 遍历全部已自报的单元执行器条目（内核装配点唯一入口——**调用方不得点名任何
/// 具体执行器**；内核测试二进制只见内核内自报，宿主二进制另见宿主侧自报）
pub fn collected_unit_executors() -> impl Iterator<Item = &'static UnitExecutorEntry> {
    inventory::iter::<UnitExecutorEntry>.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内核内自报的执行器（fs / http——随各自域文件 `submit_unit_executor!`）
    /// 必须被收集到（本测试二进制不链宿主 lib，process 执行器不在场属预期）
    #[test]
    fn in_crate_executors_are_self_reported_and_collected() {
        let names: Vec<&str> = collected_unit_executors().map(|e| e.name).collect();
        assert!(
            names.contains(&"fs."),
            "fs 执行器自报必须在场（漏报 = fs.* 单元运行期 unknown kind），实际: {names:?}"
        );
        assert!(
            names.contains(&"http.fetch"),
            "http 执行器自报必须在场（漏报 = http.fetch 单元运行期 unknown kind），实际: {names:?}"
        );
        assert!(
            !names.contains(&"process.run-sync"),
            "process 执行器已随域迁宿主（内核测试二进制不链宿主 lib，不应出现）: {names:?}"
        );
        // 工厂真的能造出对象（matches 契约抽查）
        for entry in collected_unit_executors() {
            let executor = (entry.make)();
            match entry.name {
                "fs." => assert!(executor.matches("fs.read")),
                "http.fetch" => assert!(executor.matches("http.fetch")),
                other => panic!("未预期的内核执行器自报: {other}（登记进本用例后再放行）"),
            }
        }
    }
}
