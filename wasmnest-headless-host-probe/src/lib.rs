//! 无头测试宿主探针（能力域脱绑 P6 验证矩阵 ③ 的长期载体）
//!
//! ## 角色
//!
//! 能力域脱绑（P1–P5）之后，根 `packages/` 的能力域 crate 默认形态 = 纯引擎
//! 机制 + 端口抽象（零 WIT 依赖），**任何宿主**可直接引用。本 crate 就是那个
//! 「任何宿主」的最小实证：以非桌面宿主形态（永不开 `common-host` feature）
//! 引用全部五个带桌面 WIT 绑定面的能力域 + server 地基，编译通过 + 引擎面
//! smoke 断言即门禁。
//!
//! ## 钉住的三件事
//!
//! 1. **链接自足**：五行 `use … as _;` 强制引用让五个 rlib 进本 crate 的编译图
//!    ——`common-host` 未开 ⇒ `inventory::submit!` 静态不存在 ⇒ 无任何注册，
//!    链接成功即证明纯引擎形态不需要插件宿主机制。
//! 2. **零桌面依赖**：配套 `cargo tree -i wasmnest-plugin-api` 与
//!    `cargo tree | grep -E "wasmtime|wit-bindgen|inventory|wasmnest-host-kit"`
//!    必须为空——能力域的 optional 依赖若被 feature 传递带回来，在此现形。
//! 3. **wire 词汇可独立消费**：各能力域 / server-base 的自持副本（漂移锁钉与
//!    桌面 SDK 逐字一致）在非桌面宿主侧可直接取值 / 解析——smoke 断言在下面。
//!
//! ## 边界
//!
//! - 本 crate **不进任何宿主依赖清单**、不登记 `SPLIT_CRATES`（不是拆分产物，
//!   是验证夹具）；受 `capability_crates_unit_tests_only` 锁自动治理（单测放
//!   `src/` 内、零内部 dev-dependencies）。
//! - 移动端真实接线（`移动宿主` 引能力域）归下游 `dual-end-shared-libs`
//!   的 M 票——本 crate 承担其编译面等价验证（spec §3.3 ② 的载体），不预接线。

// ==================== 强制引用（rlib 进编译图的最小面） ====================
//
// 五行缺一不可：少一行 = 该 crate 未被链接 = 「可引用」断言静默缩水。
// `common-host` 未开 ⇒ 这些引用不触发任何 inventory 注册（非桌面宿主
// 不应注册——它没有插件宿主机制，语义见各能力域 plugin_binding 模块头）。
use wasmnest_discovery_engine as _;
use wasmnest_pty_engine as _;
use wasmnest_server_http as _;
use wasmnest_server_peer_net as _;
use wasmnest_server_websocket as _;

/// server 地基的总线消息契约（P5 自持副本的公开消费形状）
pub use wasmnest_server_base::wire::BusMessage;

#[cfg(test)]
mod smoke {
    use crate::BusMessage;
    use wasmnest_server_http::wire::{EndpointAuth as HttpEndpointAuth, PERMISSION_NETWORK_HTTP};
    use wasmnest_server_peer_net::wire::PERMISSION_PEER;
    use wasmnest_server_websocket::endpoint::{
        EndpointAuth as WsEndpointAuth, ENDPOINT_HANDLE_PREFIX,
    };

    /// 总线消息契约 serde roundtrip（非桌面宿主可直接构造 / 序列化）
    #[test]
    fn bus_message_roundtrip() {
        let msg = BusMessage {
            topic: "task:status-changed".to_string(),
            sender: "com.example.plugin".to_string(),
            payload: serde_json::json!({ "ok": true }),
            payload_binary: None,
            timestamp: 1_760_000_000,
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: BusMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.topic, msg.topic);
        assert_eq!(back.sender, msg.sender);
        assert_eq!(back.payload_binary, None);
    }

    /// 各能力域 wire 自持副本可独立取值 / 解析（零桌面 SDK 引用面）
    #[test]
    fn wire_vocabulary_consumable_without_desktop_sdk() {
        assert_eq!(PERMISSION_NETWORK_HTTP, "network:http");
        assert_eq!(PERMISSION_PEER, "peer");
        assert_eq!(ENDPOINT_HANDLE_PREFIX, "wse-");
        // WS 端点认证档位：缺省 / 合法值 / 未知值三态（仲裁语义随副本同迁）
        assert_eq!(
            WsEndpointAuth::parse_with(Some("jwt"), WsEndpointAuth::None),
            Ok(WsEndpointAuth::Jwt)
        );
        assert_eq!(
            HttpEndpointAuth::parse_with(None, HttpEndpointAuth::Jwt),
            Ok(HttpEndpointAuth::Jwt)
        );
        assert!(WsEndpointAuth::parse_with(Some("JWT"), WsEndpointAuth::None).is_err());
    }
}
