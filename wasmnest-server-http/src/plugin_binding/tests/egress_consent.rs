//! 出站批量授权询问（`request-egress-consent`）的行为契约用例组
//!
//! 断言口径：请求形状与上限 / 权限门位置 / 非法协议只回索引 / 端口只收到合法
//! URL / 逐项结果按入参索引回填 / 稳定错误码映射 / 凭据不随错误串暴露。

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::scaffold::{as_ports, granting};
use crate::plugin_binding::consent::{
    request_egress_consent, CONSENT_ALWAYS_ASK, CONSENT_INTERNAL, CONSENT_INVALID_REQUEST, CONSENT_PERMISSION_DENIED,
    CONSENT_STORE_FAILED, CONSENT_TOO_MANY, CONSENT_UNAVAILABLE, CONSENT_UNSUPPORTED,
};
use crate::plugin_binding::ports::{
    BatchAuthSource, BatchOutboundAuth, BatchOutboundVerdict, BoxedBlocked, HttpEventSink, HttpPorts, OutboundAuth,
};

// ==================== 批量端口替身 ====================

/// 批量裁决脚本（宿主侧真实授权库在本 crate 不可见，用例按脚本驱动）
#[derive(Clone)]
enum BatchScript {
    /// 逐项裁决 + 未落账条数
    Verdicts {
        verdicts: Vec<BatchOutboundVerdict>,
        dropped_records: usize,
    },
    AlwaysAsk,
    Unsupported,
    Unavailable(String),
    StoreFailed(String),
    Internal(String),
}

/// 只覆写批量授权端口的测试替身（其余方法按用例需求最小实现）
struct BatchPorts {
    permission_granted: bool,
    script: BatchScript,
    calls: Mutex<Vec<Vec<String>>>,
}

impl BatchPorts {
    fn granting(script: BatchScript) -> Arc<Self> {
        Arc::new(Self {
            permission_granted: true,
            script,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn without_permission() -> Arc<Self> {
        Arc::new(Self {
            permission_granted: false,
            script: BatchScript::Unsupported,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().expect("batch call log poisoned").clone()
    }

    fn call_count(&self) -> usize {
        self.calls.lock().expect("batch call log poisoned").len()
    }
}

impl HttpPorts for BatchPorts {
    fn check_permission(&self, _plugin_id: &str, _permission: &str, _api: &str) -> bool {
        self.permission_granted
    }

    fn authorize_outbound(&self, _plugin_id: &str, _url: &str, _may_prompt: bool) -> OutboundAuth {
        panic!("批量授权用例不应调用单 origin 授权端口")
    }

    fn authorize_outbound_batch(&self, _plugin_id: &str, urls: &[String]) -> BatchOutboundAuth {
        self.calls.lock().expect("batch call log poisoned").push(urls.to_vec());
        match &self.script {
            BatchScript::Verdicts {
                verdicts,
                dropped_records,
            } => BatchOutboundAuth::Verdicts {
                verdicts: verdicts.clone(),
                dropped_records: *dropped_records,
            },
            BatchScript::AlwaysAsk => BatchOutboundAuth::AlwaysAsk,
            BatchScript::Unsupported => BatchOutboundAuth::Unsupported,
            BatchScript::Unavailable(detail) => BatchOutboundAuth::Unavailable(detail.clone()),
            BatchScript::StoreFailed(detail) => BatchOutboundAuth::StoreFailed(detail.clone()),
            BatchScript::Internal(detail) => BatchOutboundAuth::Internal(detail.clone()),
        }
    }

    fn event_sink(&self) -> Option<Arc<dyn HttpEventSink>> {
        None
    }

    fn block_on_any(&self, _fut: BoxedBlocked) -> Box<dyn std::any::Any + Send> {
        panic!("批量授权用例不驱动异步桥")
    }
}

// ==================== 助手 ====================

fn batch_ports(ports: &Arc<BatchPorts>) -> Arc<dyn HttpPorts> {
    Arc::clone(ports) as Arc<dyn HttpPorts>
}

fn allowed(origin: &str, source: BatchAuthSource) -> BatchOutboundVerdict {
    BatchOutboundVerdict::Allowed {
        origin: origin.to_string(),
        source,
    }
}

fn denied(origin: &str, source: BatchAuthSource) -> BatchOutboundVerdict {
    BatchOutboundVerdict::Denied {
        origin: origin.to_string(),
        source,
    }
}

fn request_json(urls: &[&str]) -> String {
    json!({ "urls": urls }).to_string()
}

fn consent(ports: &Arc<BatchPorts>, request: &str) -> Result<Value, String> {
    request_egress_consent(&batch_ports(ports), "test-http-consent", request)
        .map(|response| serde_json::from_str(&response).expect("响应必须是合法 JSON"))
}

// ==================== 形状与上限 ====================

/// 空列表：成功空结果，不弹窗、不调用端口
#[test]
fn empty_urls_succeed_without_asking() {
    let ports = BatchPorts::granting(BatchScript::Unsupported);
    let response = consent(&ports, &request_json(&[])).expect("空列表必须成功");
    assert_eq!(response["results"], json!([]));
    assert_eq!(response["droppedRecords"], json!(0));
    assert_eq!(ports.call_count(), 0, "空列表不得触发批量询问");
}

/// 1 项：按索引回填 origin / decision / source，且响应不回显原始 path
#[test]
fn single_url_returns_indexed_allow_result() {
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts: vec![allowed("https://registry.npmjs.org:443", BatchAuthSource::User)],
        dropped_records: 0,
    });
    let request = request_json(&["https://registry.npmjs.org/semver/latest?token=SECRET"]);
    let text = request_egress_consent(&batch_ports(&ports), "test-http-consent", &request).expect("单项批量必须成功");
    let response: Value = serde_json::from_str(&text).expect("响应必须是合法 JSON");

    assert_eq!(
        response["results"],
        json!([{
            "index": 0,
            "origin": "https://registry.npmjs.org:443",
            "decision": "allow",
            "source": "user",
        }])
    );
    assert_eq!(response["droppedRecords"], json!(0));
    assert_eq!(
        ports.calls(),
        vec![vec!["https://registry.npmjs.org/semver/latest?token=SECRET".to_string()]]
    );
    assert!(
        !response.to_string().contains("/semver/latest"),
        "响应不得回显原始 path"
    );
    assert!(!response.to_string().contains("SECRET"), "响应不得回显 query 凭据");
}

/// 50 项：上限边界内全部逐项回填，端口收到全部合法 URL
#[test]
fn fifty_urls_are_accepted_and_backfilled() {
    let urls: Vec<String> = (0..50)
        .map(|index| format!("https://mirror-{index}.example.com/semver/latest"))
        .collect();
    let verdicts: Vec<BatchOutboundVerdict> = (0..50)
        .map(|index| {
            allowed(
                &format!("https://mirror-{index}.example.com:443"),
                BatchAuthSource::Record,
            )
        })
        .collect();
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts,
        dropped_records: 0,
    });

    let url_refs: Vec<&str> = urls.iter().map(String::as_str).collect();
    let response = consent(&ports, &request_json(&url_refs)).expect("50 项必须成功");
    let results = response["results"].as_array().expect("results 是数组");

    assert_eq!(results.len(), 50);
    for (index, item) in results.iter().enumerate() {
        assert_eq!(item["index"], json!(index));
        assert_eq!(item["origin"], json!(format!("https://mirror-{index}.example.com:443")));
        assert_eq!(item["decision"], "allow");
        assert_eq!(item["source"], "record");
    }
    assert_eq!(ports.calls()[0].len(), 50, "端口必须收到全部合法 URL");
}

/// 51 项：显性返回超量错误码，不调端口
#[test]
fn fifty_one_urls_are_rejected_as_too_many() {
    let urls: Vec<String> = (0..51)
        .map(|index| format!("https://mirror-{index}.example.com/semver/latest"))
        .collect();
    let url_refs: Vec<&str> = urls.iter().map(String::as_str).collect();
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts: Vec::new(),
        dropped_records: 0,
    });

    let error = consent(&ports, &request_json(&url_refs)).expect_err("51 项必须被拒");
    assert_eq!(error, CONSENT_TOO_MANY);
    assert_eq!(ports.call_count(), 0, "超量请求不得触发批量询问");
}

/// 同一 origin 的多个 URL：弹窗去重由宿主完成，响应仍按入参索引逐项回填
#[test]
fn duplicate_origins_are_backfilled_per_input_index() {
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts: vec![
            allowed("https://registry.npmjs.org:443", BatchAuthSource::User),
            allowed("https://registry.npmjs.org:443", BatchAuthSource::User),
        ],
        dropped_records: 0,
    });
    let response = consent(
        &ports,
        &request_json(&[
            "https://registry.npmjs.org/semver/latest",
            "https://registry.npmjs.org/npm/latest",
        ]),
    )
    .expect("同 origin 多项必须成功");

    let results = response["results"].as_array().expect("results 是数组");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["index"], json!(0));
    assert_eq!(results[1]["index"], json!(1));
    assert_eq!(results[0]["origin"], results[1]["origin"]);
    assert_eq!(ports.calls()[0].len(), 2, "能力域不去重，宿主按 origin 合并询问");
}

// ==================== 非法项与输入校验 ====================

/// 非法协议 / 缺 host / 不可解析：记 invalid（只回索引），只把合法 URL 交给端口
#[test]
fn invalid_urls_are_marked_and_never_reach_the_port() {
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts: vec![
            allowed("https://ok.example.com:443", BatchAuthSource::Record),
            denied("https://second.example.com:443", BatchAuthSource::DenyRecord),
        ],
        dropped_records: 0,
    });
    let response = consent(
        &ports,
        &request_json(&[
            "file:///etc/passwd",
            "https://ok.example.com/a?token=SECRET",
            "ftp://example.com/x",
            "data:text/plain,hi",
            "javascript:alert(1)",
            "example.com/x",
            "http://",
            "http://second.example.com/b",
        ]),
    )
    .expect("混合非法项必须成功");

    let results = response["results"].as_array().expect("results 是数组");
    assert_eq!(results.len(), 8);
    for invalid_index in [0, 2, 3, 4, 5, 6] {
        assert_eq!(results[invalid_index]["index"], json!(invalid_index));
        assert_eq!(results[invalid_index]["decision"], "invalid");
        assert!(results[invalid_index].get("origin").is_none(), "invalid 项不得回显 URL");
        assert!(
            results[invalid_index].get("source").is_none(),
            "invalid 项不得带 source"
        );
    }
    assert_eq!(results[1]["index"], json!(1));
    assert_eq!(results[1]["decision"], "allow");
    assert_eq!(results[7]["index"], json!(7));
    assert_eq!(results[7]["decision"], "deny");

    assert_eq!(
        ports.calls(),
        vec![vec![
            "https://ok.example.com/a?token=SECRET".to_string(),
            "http://second.example.com/b".to_string(),
        ]],
        "端口只应收到合法 URL，且保持入参相对顺序"
    );
}

/// 全部项非法：不调端口、不弹窗，逐项返回 invalid
#[test]
fn all_invalid_urls_succeed_without_asking() {
    let ports = BatchPorts::granting(BatchScript::Unsupported);
    let response = consent(&ports, &request_json(&["file:///x", "not a url"])).expect("全非法项仍是成功结果");

    assert_eq!(ports.call_count(), 0);
    assert_eq!(
        response["results"],
        json!([
            { "index": 0, "decision": "invalid" },
            { "index": 1, "decision": "invalid" },
        ])
    );
}

/// 请求形状非法（非 JSON / 缺 urls / urls 非字符串数组 / 未知字段）一律拒绝
#[test]
fn malformed_requests_are_rejected_without_asking() {
    for request in [
        "not-json",
        "[]",
        "{}",
        r#"{"urls":null}"#,
        r#"{"urls":"https://a.example.com/x"}"#,
        r#"{"urls":[1]}"#,
        r#"{"urls":["https://a.example.com/x"],"reason":"please"}"#,
    ] {
        let ports = BatchPorts::granting(BatchScript::Verdicts {
            verdicts: Vec::new(),
            dropped_records: 0,
        });
        let error = consent(&ports, request).expect_err("非法请求形状必须被拒");
        assert_eq!(error, CONSENT_INVALID_REQUEST, "request: {request}");
        assert_eq!(ports.call_count(), 0, "request: {request}");
    }
}

/// 未声明 network:http：声明门在最前，请求形状再错也先报权限拒绝
#[test]
fn permission_denied_precedes_request_validation() {
    let ports = BatchPorts::without_permission();
    let error = consent(&ports, "not-json").expect_err("无权限调用必须被拒");
    assert_eq!(error, CONSENT_PERMISSION_DENIED);
    assert_eq!(ports.call_count(), 0, "无权限请求不得触发批量询问");
}

// ==================== 端口结果映射 ====================

/// 「总是询问」档：批量语义不成立，显性返回错误码
#[test]
fn always_ask_maps_to_stable_error_code() {
    let ports = BatchPorts::granting(BatchScript::AlwaysAsk);
    let error = consent(&ports, &request_json(&["https://a.example.com/x"])).expect_err("总是询问档不可批量");
    assert_eq!(error, CONSENT_ALWAYS_ASK);
    assert_eq!(ports.call_count(), 1, "该分支已询问宿主一次，由宿主拒绝批量");
}

/// 没有批量能力的端口（trait 默认实现，如当前移动端）：显性 unsupported
#[test]
fn default_port_implementation_reports_unsupported() {
    let ports = granting();
    let error = request_egress_consent(
        &as_ports(&ports),
        "test-http-consent",
        &request_json(&["https://a.example.com/x"]),
    )
    .expect_err("默认端口实现必须显性失败");
    assert_eq!(error, CONSENT_UNSUPPORTED);
}

/// 宿主失败分支全部映射为稳定错误码；细节只进日志，不进错误串
#[test]
fn host_failure_details_never_leak_into_error_strings() {
    let cases = [
        (BatchScript::Unsupported, CONSENT_UNSUPPORTED),
        (BatchScript::AlwaysAsk, CONSENT_ALWAYS_ASK),
        (
            BatchScript::Unavailable("no window channel".to_string()),
            CONSENT_UNAVAILABLE,
        ),
        (
            BatchScript::StoreFailed("sqlite /home/user/private/secret.db".to_string()),
            CONSENT_STORE_FAILED,
        ),
        (BatchScript::Internal("internal boom".to_string()), CONSENT_INTERNAL),
    ];

    for (script, expected) in cases {
        let ports = BatchPorts::granting(script);
        let error = consent(&ports, &request_json(&["https://a.example.com/x?token=SECRET"]))
            .expect_err("失败脚本必须返回错误");
        assert_eq!(error, expected);
        assert!(!error.contains("secret.db"), "错误串不得携带宿主内部细节");
        assert!(!error.contains("no window channel"), "错误串不得携带宿主内部细节");
        assert!(!error.contains("SECRET"), "错误串不得携带原始 URL");
    }
}

/// 端口返回条数与合法入参不符：宿主实现违约，显性 internal（不静默截断）
#[test]
fn verdict_arity_mismatch_is_internal() {
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts: vec![allowed("https://a.example.com:443", BatchAuthSource::User)],
        dropped_records: 0,
    });
    let error = consent(
        &ports,
        &request_json(&["https://a.example.com/x", "https://b.example.com/y"]),
    )
    .expect_err("条数不符必须显性失败");
    assert_eq!(error, CONSENT_INTERNAL);
}

/// 允许 / 拒绝来源词汇逐项映射；去重询问不影响索引对齐
#[test]
fn verdict_sources_and_indexes_are_stable() {
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts: vec![
            allowed("https://a.example.com:443", BatchAuthSource::Record),
            denied("https://b.example.com:443", BatchAuthSource::DenyRecord),
            denied("https://c.example.com:443", BatchAuthSource::UserDenied),
            denied("https://d.example.com:443", BatchAuthSource::UserDeniedAlways),
            allowed("https://e.example.com:443", BatchAuthSource::AlwaysAllow),
            allowed("https://f.example.com:443", BatchAuthSource::User),
        ],
        dropped_records: 0,
    });
    let response = consent(
        &ports,
        &request_json(&[
            "https://a.example.com/1",
            "https://b.example.com/2",
            "https://c.example.com/3",
            "https://d.example.com/4",
            "https://e.example.com/5",
            "https://f.example.com/6",
        ]),
    )
    .expect("来源映射必须成功");

    assert_eq!(
        response["results"],
        json!([
            { "index": 0, "origin": "https://a.example.com:443", "decision": "allow", "source": "record" },
            { "index": 1, "origin": "https://b.example.com:443", "decision": "deny", "source": "deny-record" },
            { "index": 2, "origin": "https://c.example.com:443", "decision": "deny", "source": "user-denied" },
            { "index": 3, "origin": "https://d.example.com:443", "decision": "deny", "source": "user-denied-always" },
            { "index": 4, "origin": "https://e.example.com:443", "decision": "allow", "source": "always-allow" },
            { "index": 5, "origin": "https://f.example.com:443", "decision": "allow", "source": "user" },
        ])
    );
}

/// 记录容量触顶：放行方向不变，未落账条数透传给应用
#[test]
fn dropped_records_are_reported() {
    let ports = BatchPorts::granting(BatchScript::Verdicts {
        verdicts: vec![
            allowed("https://a.example.com:443", BatchAuthSource::User),
            allowed("https://b.example.com:443", BatchAuthSource::User),
        ],
        dropped_records: 2,
    });
    let response = consent(
        &ports,
        &request_json(&["https://a.example.com/x", "https://b.example.com/y"]),
    )
    .expect("容量触顶仍应成功（放行方向不变）");

    assert_eq!(response["droppedRecords"], json!(2));
    assert_eq!(response["results"].as_array().expect("results 是数组").len(), 2);
}
