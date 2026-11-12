//! HTTP 传输面（server-lib-split 票 04）
//!
//! 动态路由注册表（`registry`）、协议网关（`gateway`：查注册表通用判定/转发）、
//! 插件代理控制器（`controllers`）、请求/响应 DTO 契约锚点（`dtos`）、中间件链
//! （`middleware`）与路由装配（`routes`：两个公开端点 + `/api` scope 及其 `wrap` 链）。
//!
//! 依赖方向（不变量 I2）：本 crate 只**向下**依赖 `wasmnest-server-core`（过滤器链 /
//! 链路加密 / 指标）与 `wasmnest-server-base`（错误/常量/端口 traits），与
//! `wasmnest-server-websocket` 之间零横向 import（I1）。
//!
//! **不依赖宿主 crate**：面内所有「要宿主做的事」经 `wasmnest_server_base::ports::get()`
//! 取注入的端口实现——`PluginInvoker`（转发插件 `_http_endpoint` / 激活判定）、
//! `AuthCenter`（连接裁决）、`PathsPort`（应用数据目录）。端口缺席（无头 / 单测）时
//! 各点按其自身语义 fail-visible，不静默降级成「无数据」。
//!
//! 认证档位词汇 `EndpointAuth` 与权限位 `network:http` 为本 crate **自持副本**
//! （[`wire`] 模块；能力域脱绑 P1：默认形态零 WIT / 零桌面 SDK 依赖）。
//! **边界声明（2026-11-08 P0）**：本 crate 是**传输面**，默认依赖树含 actix——
//! 「任何宿主可直接引用」的承诺不适用于它（只有 `common-host` 之外的能力域引擎
//! 才在承诺内，见 AGENTS §3.1）；无 actix 的 engine 面拆分待 P1 票据。
//! 副本与桌面 SDK 原版逐字一致由测试仓漂移锁
//! `wasmnest-test/cross-end-tests/tests/wire_drift_locks.rs` 钉死（漂移即红）。
//!
//! DTO 口径（AGENTS §5.1.1 B4 合法残留）：`dtos` 进生产构建的只有 `common_dto`
//! （通用 API 信封 + 两个业务码）。会话 / 文件 / git 三组是「移动端看到的字节」这一
//! 跨端 wire 契约的**黄金样本**，已整组 `#[cfg(test)]` 门控——门控即锁，生产代码引用
//! 它们会编译失败（细节见 `dtos` 模块头）。路由真身已在插件侧（ABI v29）。
//! `config_dto` 暂因 `wasmnest-wasm-core` 的跨 crate 黄金比对未门控（已知方向性耦合）。
//! 改这些形状 = 改跨端 wire 契约，必须两端同步评估。
//!
//! **插件绑定层（wasm-core-lib-split 票 06）**：[`plugin_binding`] 是本 crate 的
//! `host-http` 能力域（3 条原语）——入站端点注册 / 注销两条与服务端域注册表同住，
//! 出站 `fetch`（含 SSE 流式推流）在同 crate 的 [`plugin_binding::egress`] 模块。
//! WIT 接线与能力模块自报都在该模块里，经 `wasmnest-host-kit` 的能力模块注册表
//! 自动装配；宿主侧只剩一个端口 adapter（宿主 host_api 域的 http 适配器）与一次
//! 开机装配调用，不再有该域的逐接口接线。

pub mod controllers;
pub mod dtos;
pub mod face;
pub mod gateway;
pub mod middleware;
pub mod peer_face;
pub mod plugin_binding;
pub mod registry;
pub mod routes;
pub mod wire;

pub use face::HttpTransportFace;
pub use routes::configure_routes;

// ==================== 契约包身份（WIT 按包拆分，ADR 0061） ====================

/// 本能力域 WIT 包全名（`namespace:name@version`）
///
/// 与 `wit/http.wit` 的 `package` 行逐字一致（下方锁测试断言），也是宿主
/// `MODULE_INTERFACES` 各项的前缀。拆包后每个能力域独立版本：只在本包 WIT
/// 变更时 bump，不再随 `wasmnest:plugin` 全局版本前进。
pub const WIT_PACKAGE: &str = "wasmnest:http@0.0.1";

#[cfg(test)]
mod wit_package_lock {
    /// 常量 ↔ 分片真源 package 行（两侧任一手改即红）
    #[test]
    fn wit_package_matches_slice_package_line() {
        let raw = include_str!("../wit/http.wit");
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("package "))
            .expect("WIT 分片缺 package 行");
        assert_eq!(line, format!("package {};", super::WIT_PACKAGE));
    }

    /// 宿主模块接口路径必须属于本包（包名/版本漂移＝运行期 import 失配，编译面不红）
    #[test]
    fn module_interfaces_belong_to_wit_package() {
        for iface in crate::plugin_binding::MODULE_INTERFACES {
            assert!(
                iface.starts_with(&format!("{}/", super::WIT_PACKAGE)),
                "MODULE_INTERFACES 项 {iface} 不属于 {}",
                super::WIT_PACKAGE
            );
        }
    }
}
