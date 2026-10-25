//! `wasmnest-p2p-engine`：libp2p 机制引擎（P0 批次）
//!
//! 把 libp2p 封装成**应用无关**的三件机制：节点身份桥（node_id ↔ PeerId）+
//! swarm 生命周期（监听 / 拨号 / 事件泵 / 关停）+ 入站准入闸门（首连确认端口化）。
//! 为替换文件传输底层传输栈做准备：现役 `wasmnest-server-peer-net` 的
//! base/{transport,tls,cert}（自管 TcpListener + tokio-rustls + rcgen 自签证书）
//! 在后续批次换到本引擎上——host-peer WIT 面、信任列表语义、`peer:*` 事件词汇
//! **零变化**（替换压在 WIT 面之下，插件零改动）。
//!
//! ## 与 peer-net 的分工（分层稳定态）
//!
//! 本 crate 只做**机制**：连接怎么建、流怎么开、身份怎么验、闸门怎么拦；
//! 信任列表（谁可信）、线协议语义（传输批 / 共享目录）、host-peer WIT 域全部
//! 留在 peer-net。P0 无消费者（peer-net 于 P1 接入），先以环回集成测试钉行为。
//!
//! ## 依赖纪律（本 crate 的存在意义，对齐 `wasmnest-ws-client-engine` 先例）
//!
//! 纯引擎机制形态：零 WIT / 零 SDK / 零平台依赖 / **零内部 crate 依赖**——
//! 端口 trait（[`ports`]）本 crate 自持，任何宿主（桌面宿主 / 移动宿主 / 无头
//! 测试宿主 / 第三方）可直接引用。边界由 [`boundary_lock`]（crate 内单测）钉死。
//!
//! ## 发现红线（P1 接入时必须遵守）
//!
//! 本 crate **不含任何 mDNS 机制**、也绝不应启用 libp2p 的 mdns feature——
//! mDNS 单 listener 不变量要求发现继续走 `wasmnest-discovery-engine` 共享守护
//! （经端口注入），发现的地址喂给 [`engine::RunningNode::dial`]。
//!
//! ## 与现役栈的不变量孪生（P1 替换时对齐的判据）
//!
//! - node_id 派生：`hex(SHA-256(raw ed25519 公钥 32B))`，与 peer-net
//!   base/identity.rs 逐字一致（[`identity_bridge`] 头注有对齐说明）；
//! - 准入常量：确认超时 30s / pending 上限 8，与 peer-net base/transport.rs 的
//!   `CONFIRM_TIMEOUT` / `MAX_PENDING_CONFIRMATIONS` 同值同因；
//! - 安全语义：指纹即身份（PeerId 公钥 ↔ node_id 互验）、未信任方停应用层
//!   确认闸门、失败一律 fail-visible（见 [`error::P2pError`]）。
//!
//! ## 路线图
//!
//! - **P0（本批次）**：身份桥 / swarm 引擎 / 准入闸门 / 流协议名注册表 + 环回测试；
//! - **P1**：peer-net 传输栈换轨（自管 TCP+TLS → 本引擎 swarm 流），线协议帧
//!   编解码原样复用（其实现只依赖 `AsyncRead`/`AsyncWrite`）；
//! - **P2（独立票据）**：QUIC / relay / 打洞（跨 NAT）、外部地址学习——每项各自评估
//!   feature 面与 Android 构建链影响。

/// 入站准入闸门：首连确认端口化 + pending 上限 / 超时拒绝结算
pub mod admission;
/// 边界锁（crate 内单测）：生产源码零平台 / 零内部 crate，依赖清单零内部边
#[cfg(test)]
mod boundary_lock;
/// swarm 生命周期（start/listen/dial/事件泵/关停）与连接状态机
pub mod engine;
/// 引擎错误（fail-visible：每个变体点名成因与出路）
pub mod error;
/// 节点身份桥：NodeKey（seed → Keypair/PeerId/node_id）与 PeerId → node_id 互验
pub mod identity_bridge;
/// 宿主端口面：PeerAdmissionPort（首连确认）+ P2pEventSink（连接态事件出口）
pub mod ports;
/// 流协议名注册表（P1 线协议迁移的单一事实源 + 漂移单测）
pub mod stream_proto;
