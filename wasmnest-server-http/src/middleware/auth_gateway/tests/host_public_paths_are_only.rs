//! general — crate 内单元测试（自 packages/wasmnest-server-http/src/middleware/auth_gateway.rs 迁出）

use super::*;

use actix_web::web;

/// 宿主自持公开端点只剩 `/api/health` 与 `/health`（历史别名）。
/// `/api/auth/*` 的前缀放行规则已随 ABI v29 路由下沉退役——公开判定走动态
/// 注册表档位（`auth: "none"` 精确匹配），不再是宿主中间件的前缀规则。
#[test]
fn host_public_paths_are_only_health() {
    assert!(is_public_path("/api/health"));
    assert!(is_public_path("/health"));
    // 票 07 起 /api/auth/* 编排归插件：公开性由插件注册档位声明（none），
    // 不再由宿主前缀规则放行
    assert!(!is_public_path("/api/auth/pairing"));
    assert!(!is_public_path("/api/auth/verify"));
    assert!(!is_public_path("/api/auth/biometric-challenge"));
    assert!(!is_public_path("/api/auth/biometric-bind"));
}
#[test]
fn non_public_paths_require_auth() {
    assert!(!is_public_path("/api/sessions"));
    assert!(!is_public_path("/api/settings"));
    assert!(!is_public_path("/"));
    // 前缀相似但路径不同，不应误放行
    assert!(!is_public_path("/api/authx"));
    assert!(!is_public_path("/api/authbiometric"));
    assert!(!is_public_path("/api/healthz"));
}
#[test]
fn plugin_paths_are_recognized() {
    assert!(is_plugin_path("/api/plugin/com.wasmnest.demo/execute"));
    assert!(is_plugin_path("/api/plugin/"));
    // 非插件路径与仅前缀（无尾斜杠）不匹配
    assert!(!is_plugin_path("/api/sessions"));
    assert!(!is_plugin_path("/api/plugin"));
    assert!(!is_plugin_path("/api/plugin2/"));
}
