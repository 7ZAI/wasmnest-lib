//! host-http 内核侧残余：任务单元执行器（`http.fetch`）
//!
//! **本文件只剩一件事**（wasm-core 纯净性收口票 02 批次 03）：[`HttpUnitExecutor`]
//! —— 它是内核 host-task 面的执行器（注册进留 core 的任务引擎 `manager::task`，
//! 注册点必须与引擎同侧），不属「端口 adapter」范畴，故不随 adapter 迁宿主；最终
//! 去向随 host-task 面（票 02 批次 05）统一处置，见票面「第 3 步」裁决。
//!
//! 原 adapter（`HostHttpPorts` / `install` / `AppHandleEventSink` / 白名单常量）已迁
//! 宿主 `src-tauri/src/plugin/http.rs`（与 pty / mdns / peer / ws 同款「四件同处」）。
//! **Cargo 边保留**：`wasmnest-server-http` 仍在最终二进制里——本文件的
//! [`egress::http_fetch`] 消费点与 `component.rs` 白名单条目的域常量为证；这不是
//! 「端口 adapter 回流内核」。
//!
//! ## 端口从哪来（迁出后不再构造 adapter）
//!
//! 执行器是**进程级注册**的进程级对象（不持任何上下文），执行时按本次调用的宿主
//! 上下文取端口：走**实例级下发通道** `HostPorts::domain_ports`（宿主 adapter 在开机
//! 期把与本实例同一份上下文绑定的端口挂在它上面，见 `wasmnest_host_kit::ports` 模块
//! 文档「两条通道」）。取不到即**显性报错**——不回落进程级 `ports()`：后者只有一格，
//! 多上下文场景会读到别人的库，且在无头测试进程里直接 panic。

use std::sync::Arc;

use wasmnest_host_kit::ports::{downcast_domain_ports, HostPorts};
use wasmnest_server_http::plugin_binding::egress;
use wasmnest_server_http::plugin_binding::ports::HttpPorts;

use crate::host_api::context::WasmHostContext;
use crate::host_api::unit_executor::UnitExecutor;

// ==================== 任务单元执行器（注册点留宿主） ====================

/// 执行器自报（票 02 批次 05）：内核装配点经 `collected_unit_executors` 遍历注册
/// ——manager 不点名本域；本执行器留内核（批次 03 裁决：注册点与引擎同侧），
/// 自报静态随之常编译。
fn make_http_executor() -> Arc<dyn UnitExecutor> {
    Arc::new(HttpUnitExecutor)
}

crate::submit_unit_executor!("http.fetch", make_http_executor);

/// http 单元执行器（kind `http.fetch`）
///
/// **为什么执行器留内核**：它注册进留 core 的任务引擎（`manager::task` 的执行器
/// 注册表），注册点必须与引擎同侧——能力域不持有任务引擎，也不该知道 kind 路由表。
/// 本类型只做「kind 匹配 + 取端口 + 转调能力域域函数」，执行体在
/// [`wasmnest_server_http::plugin_binding::egress`]。params 原样透传，返回体与既有
/// `execute_unit` 语义一致：`value` 按原生值 JSON 编码。
pub(crate) struct HttpUnitExecutor;

impl UnitExecutor for HttpUnitExecutor {
    fn matches(&self, kind: &str) -> bool {
        kind == "http.fetch"
    }

    fn execute(
        &self,
        host_ctx: &Arc<WasmHostContext>,
        owner: &str,
        _kind: &str,
        params: &serde_json::Value,
    ) -> Result<Option<String>, String> {
        // 端口来源 = 宿主 adapter（`src/plugin/http.rs::install`）装在**本实例上下文**
        // 上的那一份（实例级下发通道）。语义等价于迁移前「每次调用从 host_ctx 构造
        // adapter」，但不构造任何 adapter 对象、也不存在多上下文串库的可能。
        let ports: Arc<dyn HttpPorts> = match host_ctx
            .domain_ports(wasmnest_server_http::plugin_binding::DOMAIN)
            .and_then(downcast_domain_ports::<Arc<dyn HttpPorts>>)
        {
            Some(ports) => Arc::clone(&ports),
            None => {
                return Err(format!(
                    "host-http ports unavailable for `{owner}` task unit `http.fetch` — \
                     the host must install its domain ports during boot"
                ))
            }
        };
        // may_prompt = false：池线程绝不弹窗（与 fs 任务单元同款约束，见 egress 侧文档）
        match egress::http_fetch(&ports, owner, &params.to_string(), false) {
            Ok(opt) => Ok(opt.map(|v| serde_json::json!(v).to_string())),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 执行器注册面不变：`http.fetch` 归本执行器，其余 kind 不归
    #[test]
    fn unit_executor_claims_only_http_fetch_kind() {
        let executor = HttpUnitExecutor;
        assert!(executor.matches("http.fetch"));
        assert!(!executor.matches("fs.read"));
        assert!(!executor.matches("http.register-endpoint"));
    }

    /// 端口缺失必须显性报错（fail-visible：不 panic、不静默空转）
    ///
    /// 内核测试二进制不链宿主 lib ⇒ 宿主自报的域端口装配器不在场，实例级通道必然为空
    /// —— 正是「宿主没装端口」这一失败形态的最小复现（生产路径由宿主 adapter 装入）。
    #[test]
    fn missing_domain_ports_fail_loudly() {
        let ctx = crate::host_api::tests::build_host_ctx();
        let err = HttpUnitExecutor
            .execute(
                &ctx,
                "com.wasmnest.probe",
                "http.fetch",
                &serde_json::json!({ "url": "http://127.0.0.1:1/" }),
            )
            .expect_err("未装域端口的上下文必须显性报错，不得静默返回空结果");
        assert!(
            err.contains("host-http ports unavailable"),
            "报错必须点名端口缺失与来源要求：{err}"
        );
    }
}
