//! swarm 装配与事件循环。
//!
//! 装配顺序有意固定：**先注册控制协议接收器，再 `listen_on`**。反过来会出现
//! 「端口已开、协议未登记」的窗口，客户端在这几百毫秒内开控制流会协商失败。
//!
//! 事件循环只做四类事：把 relay 事件映射成计数、执行每 IP 连接配额、维护监听
//! 地址快照、响应停止信号。业务面（谁能不能访问谁）不在这里——中继只转发密文。

use std::{
    collections::HashMap,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::StreamExt;
use libp2p::{
    core::ConnectedPoint,
    identity::Keypair,
    multiaddr::{Multiaddr, Protocol},
    ping, relay,
    swarm::{ConnectionId, NetworkBehaviour, StreamProtocol, Swarm, SwarmEvent},
    PeerId, SwarmBuilder,
};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    access::AllowedPeers,
    addrs,
    config::RelayConfig,
    control::{ControlContext, ControlService},
    error::{RelayError, Result},
    identity::{short_peer, RelayIdentity},
    metrics::{Metrics, RejectReason},
    metrics_server::{self, HealthInfo},
    quota::{IpConnTracker, QuotaPolicy},
    wire::CONTROL_PROTOCOL,
    RELAY_VERSION,
};

/// 等待首个监听地址的上限（端口占用等情况要在这里显性失败，而不是静默空转）
const LISTEN_READY_TIMEOUT: Duration = Duration::from_secs(5);
/// 连接空闲超时：要长于 ping 间隔且足以容纳静默的控制连接，否则长连接客户端会被
/// 无谓断开、reservation 跟着丢
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

/// 组合行为面
#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    ping: ping::Behaviour,
    stream: libp2p_stream::Behaviour,
}

/// 运行中的中继
pub struct RelayRuntime {
    /// 中继 PeerId
    pub peer_id: PeerId,
    /// 指标表（测试与 `/metrics` 共用同一份）
    pub metrics: Arc<Metrics>,
    /// 准入集合（enrollment 后共享可见）
    pub allowed: AllowedPeers,
    /// 实际绑定成功的监听地址
    listen_addrs: Vec<Multiaddr>,
    /// 对外通告地址（已含 `/p2p/<peerId>`，端口 0 已按实际端口回填）
    advertise_addrs: Vec<Multiaddr>,
    /// 指标端点实际地址
    metrics_addr: Option<std::net::SocketAddr>,
    shutdown: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl RelayRuntime {
    /// 实际监听地址
    pub fn listen_addrs(&self) -> &[Multiaddr] {
        &self.listen_addrs
    }

    /// 对外通告地址（含 `/p2p/<peerId>`）
    pub fn advertise_addrs(&self) -> &[Multiaddr] {
        &self.advertise_addrs
    }

    /// 指标端点地址
    pub fn metrics_addr(&self) -> Option<std::net::SocketAddr> {
        self.metrics_addr
    }

    /// 停止：通知所有任务退出并等待收尾
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let tasks = {
            let mut guard = self.tasks.lock().expect("任务表锁中毒");
            std::mem::take(&mut *guard)
        };
        for task in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
    }
}

/// 启动中继（返回后监听地址与指标端点均已就绪）
pub async fn start(
    config: RelayConfig,
    config_path: &Path,
    identity: RelayIdentity,
) -> Result<RelayRuntime> {
    config.validate()?;
    let peer_id = identity.peer_id();
    let quota = QuotaPolicy::from_config(&config.quota)?;
    let allowlist = config.allowlist_peers()?;
    let allowed = AllowedPeers::new(
        config.access.mode,
        allowlist,
        Some(RelayConfig::peers_path(config_path)),
    )?;
    let tokens = crate::tokens::TokenStore::load(&RelayConfig::tokens_path(config_path))?;
    let metrics = Arc::new(Metrics::new());

    // 控制协议接收器必须在 listen 之前登记（见模块头注）
    let stream_behaviour = libp2p_stream::Behaviour::new();
    let mut control = stream_behaviour.new_control();
    let incoming = control
        .accept(StreamProtocol::new(CONTROL_PROTOCOL))
        .map_err(|_| RelayError::Swarm(format!("控制协议重复登记：{CONTROL_PROTOCOL}")))?;

    let (reservation_limiter, circuit_limiter) = allowed.limiters();
    let relay_config = quota.relay_config(reservation_limiter, circuit_limiter);
    let listen_addrs = config.listen_addrs()?;

    let keypair: Keypair = identity.keypair().clone();
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| RelayError::Swarm(format!("TCP / Noise / Yamux 传输栈装配失败：{e}")))?
        .with_behaviour(|key| {
            // 必须显式 Enable：默认 `Status::Disable` 不对外通告 HOP，
            // 客户端只会得到 `Reservation(Unsupported)`
            let mut relay = relay::Behaviour::new(key.public().to_peer_id(), relay_config);
            relay.set_status(Some(relay::Status::Enable));
            RelayBehaviour {
                relay,
                ping: ping::Behaviour::new(ping::Config::new()),
                stream: stream_behaviour,
            }
        })
        .map_err(|e| RelayError::Swarm(format!("行为面装配失败：{e}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build();

    // 先挂对外通告地址：relay 会在 reservation 响应里回带这些地址；没有通告地址时
    // 客户端会得到 `NoAddressesInReservation`，等于「预留成功但拨不动」
    let configured_advertise = config.advertise_addrs()?;
    for addr in &configured_advertise {
        swarm.add_external_address(addr.clone());
    }

    for addr in &listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| RelayError::Swarm(format!("无法监听 {addr}：{e:?}")))?;
    }

    let (addr_tx, mut addr_rx) = watch::channel(Vec::<Multiaddr>::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let loop_state = EventLoopState {
        metrics: Arc::clone(&metrics),
        tracker: IpConnTracker::new(quota.max_connections_per_ip),
        counted: HashMap::new(),
        listen_addrs: Vec::new(),
        addr_tx,
    };
    let mut tasks = vec![tokio::spawn(run_event_loop(
        swarm,
        loop_state,
        shutdown_rx.clone(),
    ))];

    // 控制面：enrollment 兑换 + 版本/模式查询
    let control_context = Arc::new(ControlContext {
        allowed: allowed.clone(),
        tokens: Mutex::new(tokens),
        relay_version: RELAY_VERSION,
        peer_id,
    });
    tasks.push(tokio::spawn(
        ControlService::new(incoming, control_context).run(),
    ));

    // 等首个监听地址：端口占用之类的问题必须在此显性失败
    let bound = match wait_first_listen_addr(&mut addr_rx).await {
        Ok(bound) => bound,
        Err(err) => {
            // 失败路径必须把已起的任务收回，不能留下还在监听的孤儿 swarm
            stop_tasks(&shutdown_tx, &mut tasks).await;
            return Err(err);
        }
    };

    // 端口 0 时用实际端口回填通告地址，否则 `print-addrs` 会给出不可拨的 :0
    let actual_port = bound
        .iter()
        .find_map(|addr| crate::config::tcp_port(addr))
        .unwrap_or(0);
    let advertise_addrs: Vec<Multiaddr> = configured_advertise
        .iter()
        .map(|addr| match (crate::config::tcp_port(addr), actual_port) {
            (Some(0), port) if port != 0 => replace_tcp_port(addr, port),
            _ => addr.clone(),
        })
        .map(|addr| addrs::with_peer_id(&addr, &peer_id))
        .collect();

    // 指标端点：绑定失败就把中继一起停掉——「以为有指标其实没有」比没有指标更糟
    let metrics_addr = {
        let listen = config.metrics_socket_addr()?;
        let listener = match metrics_server::bind(listen).await {
            Ok(listener) => listener,
            Err(err) => {
                stop_tasks(&shutdown_tx, &mut tasks).await;
                return Err(err);
            }
        };
        let addr = listener.local_addr().map_err(RelayError::Io)?;
        let health = Arc::new(HealthInfo {
            status: "ok".to_string(),
            version: RELAY_VERSION.to_string(),
            peer_id: peer_id.to_base58(),
            peer_id_sha256: identity.fingerprint(),
            access: allowed.mode().as_str().to_string(),
            control_protocol: CONTROL_PROTOCOL.to_string(),
            listen_addrs: bound.iter().map(|addr| addr.to_string()).collect(),
            advertise_addrs: advertise_addrs
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
        });
        let metrics_for_server = Arc::clone(&metrics);
        tasks.push(tokio::spawn(async move {
            let _ =
                metrics_server::serve(listener, metrics_for_server, health, shutdown_rx.clone())
                    .await;
        }));
        Some(addr)
    };

    tracing::info!(
        peer = %short_peer(&peer_id),
        access = %allowed.mode().as_str(),
        listen = ?bound,
        advertise = ?advertise_addrs,
        "中继已启动（HOP 已启用；reservation 不代表授权）"
    );

    Ok(RelayRuntime {
        peer_id,
        metrics,
        allowed,
        listen_addrs: bound,
        advertise_addrs,
        metrics_addr,
        shutdown: shutdown_tx,
        tasks: Mutex::new(tasks),
    })
}

struct EventLoopState {
    metrics: Arc<Metrics>,
    tracker: IpConnTracker,
    counted: HashMap<ConnectionId, IpAddr>,
    listen_addrs: Vec<Multiaddr>,
    addr_tx: watch::Sender<Vec<Multiaddr>>,
}

async fn run_event_loop(
    mut swarm: Swarm<RelayBehaviour>,
    mut state: EventLoopState,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = wait_shutdown(&mut shutdown) => break,
            event = swarm.select_next_some() => handle_swarm_event(&mut swarm, &mut state, event),
        }
    }
    tracing::info!("中继事件循环已停止");
}

fn handle_swarm_event(
    swarm: &mut Swarm<RelayBehaviour>,
    state: &mut EventLoopState,
    event: SwarmEvent<RelayBehaviourEvent>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::debug!(addr = %address, "监听地址就绪");
            state.listen_addrs.push(address);
            let _ = state.addr_tx.send(state.listen_addrs.clone());
        }
        SwarmEvent::ListenerClosed {
            addresses, reason, ..
        } => {
            // 监听面消失对中继是致命信号：必须让人看见，不能静默
            tracing::warn!(?addresses, reason = ?reason, "监听器关闭");
        }
        SwarmEvent::ListenerError { listener_id, error } => {
            tracing::warn!(?listener_id, error = %error, "监听器错误");
        }
        SwarmEvent::ExternalAddrConfirmed { address } => {
            tracing::debug!(addr = %address, "对外通告地址已确认");
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            ..
        } => {
            if let ConnectedPoint::Listener { send_back_addr, .. } = &endpoint {
                // 非 IP 来源（circuit 转发的入站）不参与每 IP 配额：它的 IP 已经在
                // 发起方那条连接上计过一次，重复计数会让「一个 NAT 后多设备」被误杀
                let Some(ip) = addrs::addr_ip(send_back_addr) else {
                    return;
                };
                if state.tracker.on_connect(ip) {
                    state.counted.insert(connection_id, ip);
                    state.metrics.connection_established();
                } else {
                    state.metrics.rejected(RejectReason::IpConnectionLimit);
                    tracing::info!(
                        peer = %short_peer(&peer_id),
                        ip = %ip,
                        limit = state.tracker.limit(),
                        "单 IP 连接数超限，关闭该连接"
                    );
                    swarm.close_connection(connection_id);
                }
            }
        }
        SwarmEvent::ConnectionClosed { connection_id, .. } => {
            if let Some(ip) = state.counted.remove(&connection_id) {
                state.tracker.on_disconnect(ip);
                state.metrics.connection_closed();
            }
        }
        SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => {
            handle_relay_event(state, event)
        }
        SwarmEvent::Behaviour(RelayBehaviourEvent::Ping(ping::Event { peer, result, .. })) => {
            match result {
                Ok(rtt) => tracing::trace!(
                    peer = %short_peer(&peer),
                    rtt_ms = rtt.as_millis(),
                    "ping 成功"
                ),
                Err(err) => tracing::debug!(
                    peer = %short_peer(&peer),
                    error = %err,
                    "ping 失败（连接将被回收后重建）"
                ),
            }
        }
        SwarmEvent::Behaviour(RelayBehaviourEvent::Stream(_)) => {}
        _ => {}
    }
}

fn handle_relay_event(state: &EventLoopState, event: relay::Event) {
    match event {
        relay::Event::ReservationReqAccepted {
            src_peer_id,
            renewed,
        } => {
            state.metrics.reservation_accepted(renewed);
            tracing::info!(
                peer = %short_peer(&src_peer_id),
                renewed,
                "reservation 已接受"
            );
        }
        relay::Event::ReservationReqDenied {
            src_peer_id,
            status,
        } => {
            state.metrics.rejected(RejectReason::ReservationDenied);
            tracing::info!(
                peer = %short_peer(&src_peer_id),
                status = ?status,
                "reservation 被拒绝（配额或白名单）"
            );
        }
        relay::Event::ReservationClosed { src_peer_id } => {
            state.metrics.reservation_closed();
            tracing::debug!(peer = %short_peer(&src_peer_id), "reservation 已关闭");
        }
        relay::Event::ReservationTimedOut { src_peer_id } => {
            state.metrics.reservation_timed_out();
            tracing::debug!(peer = %short_peer(&src_peer_id), "reservation 超时");
        }
        relay::Event::CircuitReqAccepted {
            src_peer_id,
            dst_peer_id,
        } => {
            state.metrics.circuit_accepted();
            tracing::debug!(
                src = %short_peer(&src_peer_id),
                dst = %short_peer(&dst_peer_id),
                "circuit 已建立"
            );
        }
        relay::Event::CircuitReqDenied {
            src_peer_id,
            dst_peer_id,
            status,
        } => {
            state.metrics.rejected(RejectReason::CircuitDenied);
            tracing::info!(
                src = %short_peer(&src_peer_id),
                dst = %short_peer(&dst_peer_id),
                status = ?status,
                "circuit 被拒绝（配额或白名单）"
            );
        }
        relay::Event::CircuitClosed { .. } => {
            state.metrics.circuit_closed();
        }
        relay::Event::StatusChanged { status } => {
            tracing::warn!(?status, "relay 通告状态发生变化");
        }
        // 其余事件（含已标记 deprecated 的失败明细）不影响计数口径
        _ => {}
    }
}

/// 等首个监听地址（超时 = 显性失败）
async fn wait_first_listen_addr(
    rx: &mut watch::Receiver<Vec<Multiaddr>>,
) -> Result<Vec<Multiaddr>> {
    let wait = async {
        loop {
            let current = rx.borrow().clone();
            if !current.is_empty() {
                return current;
            }
            if rx.changed().await.is_err() {
                return Vec::new();
            }
        }
    };
    match tokio::time::timeout(LISTEN_READY_TIMEOUT, wait).await {
        Ok(addrs) if !addrs.is_empty() => Ok(addrs),
        _ => Err(RelayError::Swarm(format!(
            "{} 秒内没有可用监听地址：端口可能被占用，或没有权限绑定（检查 listen.addrs 与防火墙）",
            LISTEN_READY_TIMEOUT.as_secs()
        ))),
    }
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// 停止并等待已起的任务（启动中途失败的清场路径）
async fn stop_tasks(shutdown: &watch::Sender<bool>, tasks: &mut Vec<JoinHandle<()>>) {
    let _ = shutdown.send(true);
    for task in tasks.drain(..) {
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
}

fn replace_tcp_port(addr: &Multiaddr, port: u16) -> Multiaddr {
    let mut out = Multiaddr::empty();
    for protocol in addr.iter() {
        match protocol {
            Protocol::Tcp(_) => out.push(Protocol::Tcp(port)),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use libp2p::swarm::dial_opts::DialOpts;
    use tokio::sync::mpsc;

    use super::*;
    use crate::access::AccessMode;

    const ECHO_PROTOCOL: &str = "/wasmnest/test-echo/1";

    fn loopback_config() -> RelayConfig {
        let mut config = RelayConfig::default();
        config.listen.addrs = vec!["/ip4/127.0.0.1/tcp/0".to_string()];
        config.advertise.addrs = vec!["/ip4/127.0.0.1/tcp/0".to_string()];
        config.metrics.listen = "127.0.0.1:0".to_string();
        config
    }

    async fn start_relay(config: RelayConfig) -> (RelayRuntime, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("临时目录");
        let config_path = dir.path().join("config.toml");
        let identity = RelayIdentity::generate();
        identity
            .save(&RelayConfig::default().identity_path(&config_path))
            .expect("身份落盘");
        let runtime = start(config, &config_path, identity)
            .await
            .expect("启动中继");
        (runtime, dir)
    }

    #[tokio::test]
    async fn 启动后监听地址与通告地址端口一致且带_peer_id() {
        let (runtime, _dir) = start_relay(loopback_config()).await;
        let listen = runtime.listen_addrs();
        assert_eq!(listen.len(), 1, "{listen:?}");
        let bound_port = crate::config::tcp_port(&listen[0]).expect("监听端口");
        assert_ne!(bound_port, 0, "端口 0 应被回填为实际端口");

        let advertise = runtime.advertise_addrs();
        assert_eq!(advertise.len(), 1);
        let text = advertise[0].to_string();
        assert!(
            text.ends_with(&format!("/p2p/{}", runtime.peer_id)),
            "通告地址应带本地 PeerId：{text}"
        );
        assert_eq!(
            crate::config::tcp_port(&advertise[0]),
            Some(bound_port),
            "通告端口必须等于实际绑定端口：{text}"
        );
        assert!(runtime.metrics_addr().is_some(), "指标端点应已就绪");
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn 端口占用时启动显性失败() {
        // 先占用一个端口，再让中继监听同一端口
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("占位监听");
        let port = occupied.local_addr().expect("地址").port();

        let dir = tempfile::tempdir().expect("临时目录");
        let config_path = dir.path().join("config.toml");
        let identity = RelayIdentity::generate();
        identity
            .save(&RelayConfig::default().identity_path(&config_path))
            .expect("身份落盘");

        let mut config = loopback_config();
        config.listen.addrs = vec![format!("/ip4/127.0.0.1/tcp/{port}")];
        config.advertise.addrs = vec![format!("/ip4/127.0.0.1/tcp/{port}")];

        let result = tokio::time::timeout(
            LISTEN_READY_TIMEOUT + Duration::from_secs(5),
            start(config, &config_path, identity),
        )
        .await
        .expect("启动不应挂死");
        let err = result.err().expect("端口占用应启动失败");
        assert!(
            err.to_string().contains("监听"),
            "错误应点名监听失败：{err}"
        );
        drop(occupied);
    }

    #[tokio::test]
    async fn 指标端口占用时启动失败且不留下监听() {
        // 挑一个当前空闲端口作为中继监听端口（端口占用失败的清场判据）
        let free_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("探测端口");
            listener.local_addr().expect("地址").port()
        };
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("占位指标端口");
        let occupied_port = occupied.local_addr().expect("地址").port();

        let dir = tempfile::tempdir().expect("临时目录");
        let config_path = dir.path().join("config.toml");
        let identity = RelayIdentity::generate();
        identity
            .save(&RelayConfig::default().identity_path(&config_path))
            .expect("身份落盘");

        let mut config = loopback_config();
        config.listen.addrs = vec![format!("/ip4/127.0.0.1/tcp/{free_port}")];
        config.advertise.addrs = vec![format!("/ip4/127.0.0.1/tcp/{free_port}")];
        config.metrics.listen = format!("127.0.0.1:{occupied_port}");

        let err = start(config, &config_path, identity)
            .await
            .err()
            .expect("指标端口占用应启动失败");
        assert!(err.to_string().contains("指标端点"), "{err}");

        // 清场判据：中继的监听端口必须已释放（否则进程内残留 swarm 继续占端口）
        std::net::TcpListener::bind(("127.0.0.1", free_port)).expect("失败路径应释放中继监听端口");
        drop(occupied);
    }

    #[test]
    fn 端口回填只改_tcp_段() {
        let addr: Multiaddr = "/ip4/203.0.113.10/tcp/0".parse().expect("地址");
        assert_eq!(
            replace_tcp_port(&addr, 4001).to_string(),
            "/ip4/203.0.113.10/tcp/4001"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn 白名单模式拒绝未登记_peer_的_reservation() {
        let mut config = loopback_config();
        config.access.mode = AccessMode::Allowlist;
        let (runtime, _dir) = start_relay(config).await;
        let relay_addr = runtime.advertise_addrs()[0].clone();

        let mut client = spawn_client(build_test_client(), |swarm| {
            swarm
                .listen_on(relay_addr.with(Protocol::P2pCircuit))
                .expect("请求预留");
        });

        // 权威判据在 relay 侧：白名单外的 reservation 必须被拒绝并计数
        let wait = wait_until(Duration::from_secs(15), || {
            runtime
                .metrics
                .snapshot()
                .rejected
                .get("reservation-denied")
                .copied()
                .unwrap_or(0)
                >= 1
        })
        .await;
        if let Err(err) = wait {
            let mut observed = Vec::new();
            while let Ok(event) = client.events.try_recv() {
                observed.push(format!("{event:?}"));
            }
            panic!("未观察到 reservation 被拒绝：{err}；客户端事件：{observed:?}");
        }

        // 客户端不应拿到可用的 circuit 监听地址
        let mut circuit_listen = Vec::new();
        while let Ok(event) = client.events.try_recv() {
            if let ClientEvent::ListenAddr {
                addr,
                circuit: true,
            } = event
            {
                circuit_listen.push(addr.to_string());
            }
        }
        assert!(
            circuit_listen.is_empty(),
            "白名单外不应拿到 circuit 监听地址：{circuit_listen:?}"
        );
        let snapshot = runtime.metrics.snapshot();
        assert_eq!(snapshot.reservations_active, 0, "{snapshot:?}");
        runtime.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn 开放模式经_relay_建立_circuit_并转发字节() {
        let (runtime, _dir) = start_relay(loopback_config()).await;
        let relay_addr = runtime.advertise_addrs()[0].clone();

        // 被访问方 A：预留 + 监听 circuit + 注册 echo 协议
        let mut a = spawn_client(build_test_client(), |swarm| {
            swarm
                .listen_on(relay_addr.clone().with(Protocol::P2pCircuit))
                .expect("请求预留");
        });
        wait_for(&mut a, Duration::from_secs(20), |event| {
            matches!(event, ClientEvent::ListenAddr { circuit: true, .. })
        })
        .await
        .expect("A 应预留成功并拿到 circuit 监听地址");

        let mut incoming = a
            .control
            .accept(StreamProtocol::new(ECHO_PROTOCOL))
            .expect("注册 echo 协议");
        tokio::spawn(async move {
            while let Some((_peer, mut stream)) = incoming.next().await {
                let mut buffer = [0u8; 5];
                if stream.read_exact(&mut buffer).await.is_ok() {
                    let _ = stream.write_all(&buffer).await;
                    let _ = stream.flush().await;
                }
            }
        });

        // 访问方 B：经 relay 拨 A
        let dial_addr = relay_addr
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(a.peer_id));
        let mut b = spawn_client(build_test_client(), |swarm| {
            swarm.dial(DialOpts::from(dial_addr)).expect("拨号");
        });
        let established = wait_for(&mut b, Duration::from_secs(20), |event| {
            matches!(event, ClientEvent::Established { relayed: true, .. })
        })
        .await
        .expect("应经 relay 建立连接");
        let ClientEvent::Established { peer_id, .. } = established else {
            unreachable!("predicate 已限定 Established");
        };
        assert_eq!(peer_id, a.peer_id, "应连到被访问方 A");

        // 真正跑一次字节往返：证明中继在转发而不是只登记连接
        let mut stream = tokio::time::timeout(
            Duration::from_secs(15),
            b.control
                .open_stream(a.peer_id, StreamProtocol::new(ECHO_PROTOCOL)),
        )
        .await
        .expect("开流不应超时")
        .expect("应能开流");
        stream.write_all(b"hello").await.expect("写");
        stream.flush().await.expect("flush");
        let mut echoed = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut echoed))
            .await
            .expect("读不应超时")
            .expect("读回");
        assert_eq!(&echoed, b"hello", "中继应原样转发字节");

        wait_until(Duration::from_secs(10), || {
            runtime.metrics.snapshot().circuits_total >= 1
        })
        .await
        .expect("relay 应记录到 circuit");
        let snapshot = runtime.metrics.snapshot();
        assert!(snapshot.reservations_active >= 1, "{snapshot:?}");
        assert!(snapshot.connections_total >= 1, "{snapshot:?}");
        runtime.shutdown().await;
    }

    // ==================== 测试用最小中继客户端 ====================

    #[derive(NetworkBehaviour)]
    struct TestClientBehaviour {
        ping: ping::Behaviour,
        relay_client: relay::client::Behaviour,
        stream: libp2p_stream::Behaviour,
    }

    #[derive(Debug, Clone)]
    // 诊断载荷（`RelayClient` / `Error`）只在失败时的 Debug 输出里被读，编译器看不见
    #[allow(dead_code)]
    enum ClientEvent {
        ListenAddr {
            addr: Multiaddr,
            circuit: bool,
        },
        Established {
            peer_id: PeerId,
            relayed: bool,
        },
        #[allow(dead_code)]
        Closed {
            peer_id: PeerId,
        },
        RelayClient(String),
        Error(String),
    }

    struct ClientHandle {
        peer_id: PeerId,
        control: libp2p_stream::Control,
        events: mpsc::UnboundedReceiver<ClientEvent>,
        task: JoinHandle<()>,
    }

    impl Drop for ClientHandle {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn build_test_client() -> (Swarm<TestClientBehaviour>, libp2p_stream::Control) {
        let key = Keypair::generate_ed25519();
        let stream_behaviour = libp2p_stream::Behaviour::new();
        let control = stream_behaviour.new_control();
        let swarm = SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .expect("传输栈")
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .expect("relay 客户端")
            .with_behaviour(|_key, relay_client| TestClientBehaviour {
                ping: ping::Behaviour::new(ping::Config::new()),
                relay_client,
                stream: stream_behaviour,
            })
            .expect("行为面")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();
        (swarm, control)
    }

    fn spawn_client(
        client: (Swarm<TestClientBehaviour>, libp2p_stream::Control),
        prepare: impl FnOnce(&mut Swarm<TestClientBehaviour>),
    ) -> ClientHandle {
        let (mut swarm, control) = client;
        let peer_id = *swarm.local_peer_id();
        prepare(&mut swarm);
        let (tx, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let circuit = address.iter().any(|p| matches!(p, Protocol::P2pCircuit));
                        let _ = tx.send(ClientEvent::ListenAddr {
                            addr: address,
                            circuit,
                        });
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    } => {
                        let _ = tx.send(ClientEvent::Established {
                            peer_id,
                            relayed: endpoint.is_relayed(),
                        });
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        num_established,
                        ..
                    } => {
                        if num_established == 0 {
                            let _ = tx.send(ClientEvent::Closed { peer_id });
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        let _ = tx.send(ClientEvent::Error(format!("{error:?}")));
                    }
                    SwarmEvent::Behaviour(TestClientBehaviourEvent::RelayClient(event)) => {
                        let _ = tx.send(ClientEvent::RelayClient(format!("{event:?}")));
                    }
                    _ => {}
                }
            }
        });
        ClientHandle {
            peer_id,
            control,
            events: rx,
            task,
        }
    }

    async fn wait_for(
        client: &mut ClientHandle,
        timeout: Duration,
        mut predicate: impl FnMut(&ClientEvent) -> bool,
    ) -> Result<ClientEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RelayError::Swarm("等待客户端事件超时".to_string()));
            }
            match tokio::time::timeout(remaining, client.events.recv()).await {
                Ok(Some(event)) => {
                    if predicate(&event) {
                        return Ok(event);
                    }
                }
                Ok(None) => return Err(RelayError::Swarm("客户端事件通道已关闭".to_string())),
                Err(_) => return Err(RelayError::Swarm("等待客户端事件超时".to_string())),
            }
        }
    }

    async fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(RelayError::Swarm("等待条件超时".to_string()))
    }
}
