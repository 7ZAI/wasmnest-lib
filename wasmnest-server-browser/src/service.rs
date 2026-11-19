//! 能力域执行流程：权限门 → 请求闸门 → 脚本生成 → 端渲染 → 解析 → 上限收敛
//!
//! 顺序不可交换：先过权限门再解析任何请求字段，避免未授权插件用非法请求探测
//! 闸门细节；先过闸门再调用端实现，避免把私网目标送进浏览器进程。

use crate::error::{BrowserError, BrowserErrorKind};
use crate::guard;
use crate::limits;
use crate::model::{BrowserRequest, BrowserResponse};
use crate::ports::{BrowserPorts, RenderRequest};
use crate::script;
use crate::wire::PERMISSION_NETWORK_BROWSER;

/// 执行一次 `fetch-rendered`
///
/// # Errors
///
/// 未声明 `network:browser` → `Denied`；请求非法 → `InvalidRequest`；私网未授权
/// → `BlockedPrivate`；其余错误由端实现分类透传。
pub fn fetch_rendered(
    ports: &dyn BrowserPorts,
    plugin_id: &str,
    request: BrowserRequest,
) -> Result<BrowserResponse, BrowserError> {
    let started = std::time::Instant::now();
    if !ports.check_permission(
        plugin_id,
        PERMISSION_NETWORK_BROWSER,
        "host_browser_fetch_rendered",
    ) {
        tracing::warn!(
            plugin_id = %plugin_id,
            permission = PERMISSION_NETWORK_BROWSER,
            api = "host_browser_fetch_rendered",
            "browser fetch denied"
        );
        return Err(BrowserError::new(
            BrowserErrorKind::Denied,
            format!("permission denied: {PERMISSION_NETWORK_BROWSER}"),
        ));
    }

    let validated = guard::validate(&request, |origin| {
        ports.authorize_private_network(plugin_id, origin)
    })
    .inspect_err(|error| {
        tracing::warn!(
            plugin_id = %plugin_id,
            code = error.code(),
            "browser request rejected"
        );
    })?;
    let origin = validated.url.origin().ascii_serialization();
    let script = script::build(&validated);
    let page = ports
        .render(
            plugin_id,
            &RenderRequest {
                url: &validated.url,
                wait_until: validated.wait_until,
                timeout_ms: validated.timeout_ms,
                script: &script,
            },
        )
        .inspect_err(|error| {
            tracing::warn!(
                plugin_id = %plugin_id,
                origin = %origin,
                code = error.code(),
                duration_ms = started.elapsed().as_millis() as u64,
                "browser fetch failed"
            );
        })?;
    let response = script::parse_payload(page.status, &page.final_url, &page.payload).inspect_err(
        |error| {
            tracing::warn!(
                plugin_id = %plugin_id,
                origin = %origin,
                code = error.code(),
                duration_ms = started.elapsed().as_millis() as u64,
                "browser payload rejected"
            );
        },
    )?;
    let response = limits::apply(response);
    tracing::info!(
        plugin_id = %plugin_id,
        origin = %origin,
        status = response.status,
        items = response.items.len(),
        truncated = response.truncated,
        duration_ms = started.elapsed().as_millis() as u64,
        "browser fetch completed"
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BrowserRequest, ExtractedItem, ListSpec, WaitUntil};
    use crate::ports::RenderedPage;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakePorts {
        allow_permission: bool,
        authorize_private: bool,
        response: Option<Result<RenderedPage, BrowserError>>,
        seen: Mutex<Vec<String>>,
    }

    impl BrowserPorts for FakePorts {
        fn check_permission(&self, _plugin_id: &str, permission: &str, _api: &str) -> bool {
            self.allow_permission && permission == PERMISSION_NETWORK_BROWSER
        }

        fn authorize_private_network(&self, _plugin_id: &str, origin: &str) -> bool {
            self.seen
                .lock()
                .expect("seen lock")
                .push(origin.to_string());
            self.authorize_private
        }

        fn render(
            &self,
            _plugin_id: &str,
            request: &RenderRequest<'_>,
        ) -> Result<RenderedPage, BrowserError> {
            self.seen
                .lock()
                .expect("seen lock")
                .push(request.script.to_string());
            self.response.clone().unwrap_or_else(|| {
                Err(BrowserError::new(
                    BrowserErrorKind::Unavailable,
                    "no fake response",
                ))
            })
        }
    }

    fn request(url: &str) -> BrowserRequest {
        BrowserRequest {
            url: url.to_string(),
            wait_until: WaitUntil::DomContentLoaded,
            timeout_ms: 5_000,
            allow_private_network: false,
            extract_list: None,
            extract_page: None,
        }
    }

    fn payload() -> String {
        r#"{
            "title": "Example",
            "text": "body",
            "contentText": null,
            "items": [{"title": "One", "url": "/one", "timeText": null, "summary": null}],
            "location": "https://example.com/list"
        }"#
        .to_string()
    }

    /// 权限未声明时不触达闸门与端实现
    #[test]
    fn permission_gate_short_circuits_everything() {
        let ports = FakePorts {
            allow_permission: false,
            ..FakePorts::default()
        };
        let error =
            fetch_rendered(&ports, "plugin", request("https://example.com/")).expect_err("denied");
        assert_eq!(error.kind(), BrowserErrorKind::Denied);
        assert!(ports.seen.lock().expect("seen lock").is_empty());
    }

    /// 私网目标未授权时不调用端实现
    #[test]
    fn private_target_never_reaches_the_backend() {
        let ports = FakePorts {
            allow_permission: true,
            ..FakePorts::default()
        };
        let error =
            fetch_rendered(&ports, "plugin", request("http://192.168.1.10/")).expect_err("blocked");
        assert_eq!(error.kind(), BrowserErrorKind::BlockedPrivate);
        assert!(ports.seen.lock().expect("seen lock").is_empty());
    }

    /// 正常路径：脚本进入端实现，返回结果被解析并绝对化
    #[test]
    fn happy_path_returns_a_normalized_response() {
        let ports = FakePorts {
            allow_permission: true,
            response: Some(Ok(RenderedPage {
                status: 200,
                final_url: "https://example.com/list".to_string(),
                payload: payload(),
            })),
            ..FakePorts::default()
        };
        let mut req = request("https://example.com/list");
        req.extract_list = Some(ListSpec {
            item: "li".to_string(),
            ..ListSpec::default()
        });
        let response = fetch_rendered(&ports, "plugin", req).expect("response");
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].url, "https://example.com/one");
        assert_eq!(response.text.as_deref(), Some("body"));
        assert!(!response.truncated);

        let seen = ports.seen.lock().expect("seen lock").clone();
        assert_eq!(seen.len(), 1, "私网未申请时只应产生脚本一次调用");
        assert!(seen[0].contains("querySelectorAll"));
    }

    /// 端实现错误原样透传（超时 / 不可用等分类不丢）
    #[test]
    fn backend_errors_keep_their_kind() {
        let ports = FakePorts {
            allow_permission: true,
            response: Some(Err(BrowserError::new(
                BrowserErrorKind::Timeout,
                "navigation timed out",
            ))),
            ..FakePorts::default()
        };
        let error =
            fetch_rendered(&ports, "plugin", request("https://example.com/")).expect_err("timeout");
        assert_eq!(error.kind(), BrowserErrorKind::Timeout);
        assert_eq!(error.to_string(), "browser.timeout: navigation timed out");
    }

    /// 端返回超过 200 条时在能力域收敛并标记截断
    #[test]
    fn oversized_results_are_truncated_after_parsing() {
        let items: Vec<String> = (0..crate::limits::MAX_ITEMS + 1)
            .map(|index| format!(r#"{{"title":"t{index}","url":"/i/{index}"}}"#))
            .collect();
        let payload = format!(
            r#"{{"items":[{}],"location":"https://example.com/"}}"#,
            items.join(",")
        );
        let ports = FakePorts {
            allow_permission: true,
            response: Some(Ok(RenderedPage {
                status: 200,
                final_url: "https://example.com/".to_string(),
                payload,
            })),
            ..FakePorts::default()
        };
        let response =
            fetch_rendered(&ports, "plugin", request("https://example.com/")).expect("response");
        assert_eq!(response.items.len(), crate::limits::MAX_ITEMS);
        assert!(response.truncated);
        assert!(matches!(response.items[0], ExtractedItem { .. }));
    }

    /// 私网授权查询只发生在私网目标上
    #[test]
    fn private_authorization_is_not_queried_for_public_targets() {
        let ports = Arc::new(FakePorts {
            allow_permission: true,
            authorize_private: false,
            response: Some(Ok(RenderedPage {
                status: 200,
                final_url: "https://example.com/".to_string(),
                payload: "{}".to_string(),
            })),
            ..FakePorts::default()
        });
        let mut req = request("https://example.com/");
        req.allow_private_network = true;
        fetch_rendered(ports.as_ref(), "plugin", req).expect("public");
        let seen = ports.seen.lock().expect("seen lock").clone();
        assert_eq!(seen.len(), 1, "公网目标不应查询私网授权：{seen:?}");
    }
}
