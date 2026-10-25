//! `PluginType` 形态三档词汇单测（2026-10-26 语义重定义，wasmnest-apps#21）
//!
//! 宿主是 plugin.json pluginType 的反序列化真源：三形态合法、退役值逐一点名
//! 拒绝并给出迁移出路（fail-visible）、`has_backend` 判据——与双端 SDK 的
//! 同形枚举测试（桌面 `types/tests.rs` / 校验器 `manifest-validate`）对偶。

use serde_json::json;

use crate::manifest::PluginType;

#[test]
fn wire_values_lowercase() {
    assert_eq!(
        serde_json::to_value(PluginType::Frontend).unwrap(),
        json!("frontend")
    );
    assert_eq!(
        serde_json::to_value(PluginType::Backend).unwrap(),
        json!("backend")
    );
    assert_eq!(
        serde_json::to_value(PluginType::Full).unwrap(),
        json!("full")
    );
    assert_eq!(PluginType::Full.as_str(), "full");
}

#[test]
fn retired_values_rejected_with_migration_path() {
    for (old, expect_path) in [
        ("ts-only", "'frontend'"),
        ("rust", "'backend'"),
        ("rust-ts", "'full'"),
    ] {
        let err = serde_json::from_value::<PluginType>(json!(old))
            .expect_err("retired value must be rejected");
        let msg = err.to_string();
        assert!(msg.contains(old), "须点名旧值 {old}: {msg}");
        assert!(
            msg.contains(expect_path),
            "须给出新值出路 {expect_path}: {msg}"
        );
        assert!(msg.contains("已退役"), "须说明退役事实: {msg}");
    }
    // 移动端原 wasm 值单独核：出路文案覆盖两档（full / backend）
    let err =
        serde_json::from_value::<PluginType>(json!("wasm")).expect_err("'wasm' must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("'wasm'") && msg.contains("'full'") && msg.contains("'backend'"),
        "wasm 出路须双档: {msg}"
    );
    // 完全未知的值点名值本身并列出合法集
    let err = serde_json::from_value::<PluginType>(json!("gopher"))
        .expect_err("unknown value must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("'gopher'") && msg.contains("frontend / backend / full"),
        "{msg}"
    );
}

#[test]
fn has_backend_matches_form_semantics() {
    assert!(!PluginType::Frontend.has_backend());
    assert!(PluginType::Backend.has_backend());
    assert!(PluginType::Full.has_backend());
}

#[test]
fn manifest_default_and_roundtrip() {
    // 缺省 = 纯前端（与双端 SDK 同一真源语义）
    let m: crate::manifest::PluginManifest = serde_json::from_value(
        json!({"id":"com.wasmnest.x","name":"X","version":"1.0.0","platform":"both"}),
    )
    .unwrap();
    assert_eq!(m.plugin_type, PluginType::Frontend);
    // 整清单往返：pluginType 以新词汇落 wire
    let back = serde_json::to_value(&m).unwrap();
    assert_eq!(back["pluginType"], json!("frontend"));
}
