//! 转发入参 — crate 内单元测试（自 packages/wasmnest-server-http/src/gateway.rs 迁出）

use super::scaffold::*;
use super::*;

use crate::controllers::plugin_controller::build_plugin_http_args;
use crate::middleware::auth_gateway::auth_gateway;

/// 转发入参形状：与 `/api/plugin/*` 共用同一构造器，故两条路径不可能各答一版。
///
/// `params`（ABI v29 模板捕获）恒存在：精确命中时为 `{}`，模板命中时携带捕获值；
/// `device` 只在已验签时出现。
#[test]
fn forwarded_request_shape_locks_device_headers_and_params() {
    let mut headers = serde_json::Map::new();
    headers.insert("content-type".to_string(), Value::String("application/json".into()));
    let args = build_plugin_http_args(&PluginHttpRequest {
        endpoint_path: "configs",
        method: "GET",
        headers,
        body: Value::Null,
        query: Value::Object(serde_json::Map::from_iter([(
            "session_id".to_string(),
            Value::String("s-1".to_string()),
        )])),
        params: serde_json::Map::new(),
        caller: HttpCaller::Device,
        device: Some(serde_json::json!({ "deviceId": "device-1" })),
    });
    assert_eq!(
        args,
        serde_json::json!({
            "method": "GET",
            "path": "configs",
            "headers": { "content-type": "application/json" },
            "body": null,
            "query": { "session_id": "s-1" },
            "params": {},
            "caller": "device",
            "device": { "deviceId": "device-1" },
        })
    );

    // 模板捕获参数：`{id}` 捕获值随 `params` 注入插件
    let with_params = build_plugin_http_args(&PluginHttpRequest {
        endpoint_path: "sessions/stop",
        method: "POST",
        headers: serde_json::Map::new(),
        body: Value::Null,
        query: Value::Object(serde_json::Map::new()),
        params: serde_json::Map::from_iter([("id".to_string(), Value::String("s-1".to_string()))]),
        caller: HttpCaller::Localhost,
        device: None,
    });
    assert_eq!(with_params["params"], serde_json::json!({ "id": "s-1" }));

    let no_device = build_plugin_http_args(&PluginHttpRequest {
        endpoint_path: "configs",
        method: "GET",
        headers: serde_json::Map::new(),
        body: Value::Null,
        query: Value::Object(serde_json::Map::new()),
        params: serde_json::Map::new(),
        caller: HttpCaller::Localhost,
        device: None,
    });
    assert!(no_device.get("device").is_none(), "无验签结果时不写 device 键");
    assert_eq!(
        no_device.get("caller").and_then(|v| v.as_str()),
        Some("localhost"),
        "免凭证调用方也必须带可区分的身份"
    );
}
/// 查询串解析：与 `web::Query<HashMap<String,String>>` 提取器同口径
#[test]
fn query_object_keeps_query_extractor_semantics() {
    assert_eq!(
        query_object("session_id=s-1&limit=3").unwrap(),
        serde_json::json!({ "session_id": "s-1", "limit": "3" })
    );
    assert_eq!(query_object("").unwrap(), serde_json::json!({}));
    // 百分号转义必须与宿主提取器同解码口径（否则插件看到的参数与宿主不同）
    assert_eq!(
        query_object("path=%2Fsrv%2Fapp").unwrap(),
        serde_json::json!({ "path": "/srv/app" })
    );
    // 提取器的既有语义一并锁住（不是网关的解释）：重复键后者覆盖、非 UTF-8 走 lossy
    assert_eq!(query_object("a=1&a=2").unwrap(), serde_json::json!({ "a": "2" }));
    assert_eq!(
        query_object("bad=%FF").unwrap(),
        serde_json::json!({ "bad": "\u{FFFD}" })
    );
}
