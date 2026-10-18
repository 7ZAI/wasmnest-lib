//! 安全模块（core-security）
//!
//! 资源授权框架——三段决策管线：
//! manifest 声明（前端快速失败）→ 授权审批（弹窗/持久化授权记录）→ 运行时强制（Rust 端最终仲裁）
//!
//! 当前为归位形态：fs 三层校验（[`fs_auth`]）、授权审批（[`approval`]）、
//! 互调门（[`api_registry`]，ADR 0017）、前端通道身份（[`frontend_channel`]，审计票 06）
//! 四个既有实现；统一的资源类型抽象（资源 × 操作 × 仲裁点）在票据 04 落地。
//! 2026-09-27 起新增授权策略与授权记录真源（[`auth_policy`]）：回答「未覆盖的目标要不要
//! 问用户」，是安全闸门的配给账，不含业务语义（spec §11 / ADR 0022 §5.1.3）。
//! 同批新增网络出站判定与询问（[`network_auth`]，票 05）：fs 侧判定在 [`fs_auth`]，
//! 网络侧自带 origin 归一化（目标形态不同），但两者共用同一套记录与策略真源。
//! 策略档位到动作的映射（总是询问 / 默认 / 始终允许）收在 [`strategy`] 一处，
//! fs 与 network 只提供各自的「目标归一化 + 记录匹配」（票 03，spec §6.1 判定顺序）。

pub mod api_registry;
pub mod approval;
pub mod auth_policy;
pub mod framework;
pub mod frontend_channel;
pub mod fs_auth;
pub mod network_auth;
pub mod strategy;

pub use framework::{AuthDecision, AuthRequest, ResourceAuthorizer, ResourceKind, SecurityFramework};
