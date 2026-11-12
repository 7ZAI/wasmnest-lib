//! `host-tunnel` 能力域 —— WIT 层（T06）。
//!
//! ## 分层
//!
//! ```text
//!   本文件          权限门位置 + 服务租约 acquire/release + WIT 形状转换
//!   manager.rs      单一引用计数 / 句柄表 / 对等面生命周期 / 状态投影
//!   server/client/… T05 的线协议、票据、准入、面登记与本地代理
//! ```
//!
//! **零业务代码**：本域只做内网穿透机制；应用语义（远程访问开关、二维码内容、
//! 会话/终端）全部留在 wasm 应用。`allowWan` / relay 地址是应用自持配置经
//! [`TunnelPorts::check_permission`] 之外的 `configure` 原语写入的（宿主只做计数
//! 与拨号，不替应用保存产品语义）。
//!
//! ## 权限门（双门 + 服务租约）
//!
//! - `tunnel:serve` → `configure`（任一权限即可）/ `expose` / `unexpose` /
//!   `issue-pairing-ticket`；
//! - `tunnel:connect` → `configure` / `connect` / `close`；
//! - `status` → 两权限任一（只读投影；不触达网络）。
//!
//! 门禁在**本文件**的域函数入口（与 peer / pty / ws 同款），取端口后按
//! `check_permission` 结果 fail-closed；未声明权限的应用永远 lan-only（不变量 8）。
//!
//! ## 服务租约
//!
//! `expose` / `connect` 按插件 acquire `net.tunnel`；`unexpose` / `close` 在该插件
//! **不再持有任何隧道资源**时 release。`configure` / `status` 只读写内存，不拉起
//! 服务。
//!
//! `issue-pairing-ticket` 同样 acquire：纯配对场景没有 expose / connect，若不记
//! 账，另一插件释放最后租约触发的 `stop` 会把刚签发的票据清掉（L6）。票据租约
//! 按签发次数记账，在 TTL 后回收；回收时若插件仍持有 expose / connect 资源则
//! 不 release（注册表按 holder 去重，提前 release 会误伤他人持有的同一租约）。

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use wasmnest_p2p_engine::probe::{ProbeError, ProbeReport};
use wasmnest_p2p_engine::Multiaddr;
use wasmnest_server_base::service::ServiceRegistry;

use crate::tunnel::frame::TunnelKind;
use crate::tunnel::manager::{TunnelConfig, TunnelManager};
use crate::tunnel::policy::ExposeConfig;
use crate::tunnel::service::NET_TUNNEL_SERVICE_KEY;
use crate::wire::{PERMISSION_TUNNEL_CONNECT, PERMISSION_TUNNEL_PROBE, PERMISSION_TUNNEL_SERVE};

// ==================== 宿主端口 ====================

/// 类型擦除的「同步驱动异步」入参（与 peer 端口同款）
pub type BoxedBlocked = Pin<Box<dyn Future<Output = Box<dyn Any + Send>> + Send>>;

/// 探测实现（T19）：默认走真实引擎；测试替身覆盖以便不触网地测域层
pub type BoxedProbe = Pin<Box<dyn Future<Output = Result<ProbeReport, ProbeError>> + Send>>;

/// 宿主能力端口（边界层）
pub trait TunnelPorts: Send + Sync + 'static {
    /// 权限判定（`tunnel:serve` / `tunnel:connect`）
    ///
    /// 返回 `false` 时宿主侧必须已落 `warn`（结构化字段 plugin_id / permission /
    /// api）；本域只问结果，不复制权限管理器。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 已装配的隧道管理器（宿主开机期构造并注入；无头 / 未装配返回 `None`）
    fn tunnel_manager(&self) -> Option<Arc<TunnelManager>>;

    /// 在宿主运行时上同步驱动异步计算（复用宿主唯一的同步↔异步桥）
    fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send>;

    /// 应用作用域服务注册表（`None` = 无头 / 测试装配，退化为不记账并落一次 warn）
    fn service_registry(&self) -> Option<Arc<ServiceRegistry>> {
        None
    }

    /// relay 连通性探测（T19）：默认接真实引擎，测试替身可覆盖
    ///
    /// 探测**不**持有任何隧道资源（无 reservation / 规则 / 租约），故不需要
    /// [`Self::tunnel_manager`]；宿主未装配该原语时缺的是 WIT 导出本身。
    fn probe_relay(&self, addrs: Vec<Multiaddr>, timeout: Duration) -> BoxedProbe {
        Box::pin(async move { wasmnest_p2p_engine::probe::probe_relay(&addrs, timeout).await })
    }
}

/// 强类型版同步驱动（端口方法包装；类型不符 = 装配期编程错误，直接 panic 点名）
pub fn block_on<T: Send + 'static>(ports: &Arc<dyn TunnelPorts>, fut: impl Future<Output = T> + Send + 'static) -> T {
    let erased: BoxedBlocked = Box::pin(async move { Box::new(fut.await) as Box<dyn Any + Send> });
    match ports.block_on_any(erased).downcast::<T>() {
        Ok(value) => *value,
        Err(_) => panic!(
            "tunnel ports block_on_any returned an unexpected result type (expected {})",
            std::any::type_name::<T>()
        ),
    }
}

// ==================== 端口装配（进程级单例） ====================

static PORTS: std::sync::OnceLock<Arc<dyn TunnelPorts>> = std::sync::OnceLock::new();

/// 装配宿主端口实现（宿主开机期一次；重复装配被忽略而非替换——首次装配者胜出）
pub fn install_ports(ports: Arc<dyn TunnelPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的宿主端口；未装配即 panic 点名（fail-visible，不允许静默空转）
pub fn ports() -> Arc<dyn TunnelPorts> {
    PORTS
        .get()
        .cloned()
        .expect("tunnel plugin binding ports are not installed — the host must call `install_ports` during boot")
}

// ==================== 域函数（权限门 + 租约 + 转调） ====================

const DENIED_SERVE: &str = "permission denied: tunnel:serve";
const DENIED_CONNECT: &str = "permission denied: tunnel:connect";
const DENIED_PROBE: &str = "permission denied: tunnel:probe";
const MANAGER_UNAVAILABLE: &str = "tunnel manager is not assembled (host boot must install it)";

fn warn_no_lease(api: &str) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            api = %api,
            "net.tunnel service registry not assembled (headless/test); \
             tunnel primitives run without holder accounting"
        );
    });
}

fn require(ports: &Arc<dyn TunnelPorts>, plugin_id: &str, permission: &str, api: &str) -> Result<(), String> {
    if ports.check_permission(plugin_id, permission, api) {
        Ok(())
    } else if permission == PERMISSION_TUNNEL_SERVE {
        Err(DENIED_SERVE.to_string())
    } else if permission == PERMISSION_TUNNEL_PROBE {
        Err(DENIED_PROBE.to_string())
    } else {
        Err(DENIED_CONNECT.to_string())
    }
}

fn require_either(ports: &Arc<dyn TunnelPorts>, plugin_id: &str, api: &str) -> Result<(), String> {
    if ports.check_permission(plugin_id, PERMISSION_TUNNEL_SERVE, api)
        || ports.check_permission(plugin_id, PERMISSION_TUNNEL_CONNECT, api)
    {
        Ok(())
    } else {
        Err(DENIED_CONNECT.to_string())
    }
}

fn manager(ports: &Arc<dyn TunnelPorts>) -> Result<Arc<TunnelManager>, String> {
    ports.tunnel_manager().ok_or_else(|| MANAGER_UNAVAILABLE.to_string())
}

fn acquire_lease(ports: &Arc<dyn TunnelPorts>, plugin_id: &str, api: &str) -> Result<(), String> {
    let Some(registry) = ports.service_registry() else {
        warn_no_lease(api);
        return Ok(());
    };
    let holder = plugin_id.to_string();
    block_on(
        ports,
        async move { registry.acquire(NET_TUNNEL_SERVICE_KEY, &holder).await },
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn release_lease(ports: &Arc<dyn TunnelPorts>, plugin_id: &str, api: &str) -> Result<(), String> {
    let Some(registry) = ports.service_registry() else {
        warn_no_lease(api);
        return Ok(());
    };
    let holder = plugin_id.to_string();
    block_on(
        ports,
        async move { registry.release(NET_TUNNEL_SERVICE_KEY, &holder).await },
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn wire_err(e: crate::tunnel::TunnelError) -> String {
    e.as_wire_error()
}

/// 未消费的配对票据租约计数（plugin_id → 在飞票据数）
static PAIRING_LEASES: LazyLock<Mutex<HashMap<String, usize>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// 该插件是否仍有未过期的票据租约（unexpose / close 不得提前释放服务）
fn pairing_leases_pending(plugin_id: &str) -> bool {
    PAIRING_LEASES
        .lock()
        .expect("pairing lease table poisoned")
        .get(plugin_id)
        .is_some_and(|count| *count > 0)
}

/// 票据 TTL 到期后回收该次 acquire 的租约（L6）。
///
/// 不按「票据消费」提前回收：消费回调不在本层，且租约是 holder 级去重，
/// 多张票据 / 同时持有 expose 时提前 release 会误伤仍生效的资源。TTL 上限
/// 120s，服务多存活一个窗口是可接受代价。
fn schedule_pairing_lease_release(
    ports: &Arc<dyn TunnelPorts>,
    manager: Arc<TunnelManager>,
    plugin_id: &str,
    ttl_secs: u32,
) {
    let Some(registry) = ports.service_registry() else {
        return;
    };
    let plugin = plugin_id.to_string();
    let fut = async move {
        tokio::time::sleep(Duration::from_secs(u64::from(ttl_secs.max(1)))).await;
        let should_release = {
            let mut counts = PAIRING_LEASES.lock().expect("pairing lease table poisoned");
            match counts.get_mut(&plugin) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        counts.remove(&plugin);
                        true
                    } else {
                        false
                    }
                }
                None => false,
            }
        };
        // 仍持有 expose / connect 时租约由那些资源负责；这里不能替它们 release
        if should_release && !manager.has_open_resources(&plugin) {
            if let Err(e) = registry.release(NET_TUNNEL_SERVICE_KEY, &plugin).await {
                tracing::warn!(plugin_id = %plugin, "pairing ticket lease release failed: {e}");
            }
        }
    };
    // 借宿主运行时派生；无运行时（无头/测试）时票据租约留在进程内，不 panic
    let _ = block_on(ports, async move { tokio::spawn(fut) });
}

/// `tunnel.configure`：写入应用自持的 allowWan / relay 地址（只改计数）
pub fn tunnel_configure(
    ports: &Arc<dyn TunnelPorts>,
    plugin_id: &str,
    allow_wan: bool,
    relay_addrs_json: &str,
) -> Result<(), String> {
    require_either(ports, plugin_id, "host_tunnel_configure")?;
    let relay_addrs: Vec<String> =
        serde_json::from_str(relay_addrs_json).map_err(|e| format!("wan-disabled: relayAddrs 不是字符串数组：{e}"))?;
    let manager = manager(ports)?;
    let call = Arc::clone(&manager);
    let plugin = plugin_id.to_string();
    block_on(ports, async move {
        call.configure(&plugin, TunnelConfig { allow_wan, relay_addrs }).await
    })
    .map_err(wire_err)
}

/// `tunnel.expose`：登记暴露规则（返回规则 id；幂等）
pub fn tunnel_expose(
    ports: &Arc<dyn TunnelPorts>,
    plugin_id: &str,
    port: u16,
    kind: &str,
    label: &str,
    allowed_peers: Vec<String>,
) -> Result<String, String> {
    require(ports, plugin_id, PERMISSION_TUNNEL_SERVE, "host_tunnel_expose")?;
    let kind = TunnelKind::parse(kind)
        .ok_or_else(|| format!("port-not-exposed: 未知通道 kind `{kind}`（只支持 http / tcp）"))?;
    let manager = manager(ports)?;
    acquire_lease(ports, plugin_id, "host_tunnel_expose")?;
    let call = Arc::clone(&manager);
    let plugin = plugin_id.to_string();
    let label = label.to_string();
    let result = block_on(ports, async move {
        call.expose(
            &plugin,
            ExposeConfig {
                port,
                kind,
                label,
                allowed_peers,
            },
        )
        .await
    });
    match result {
        Ok(rule_id) => Ok(rule_id),
        Err(e) => {
            if !manager.has_open_resources(plugin_id) {
                let _ = release_lease(ports, plugin_id, "host_tunnel_expose");
            }
            Err(wire_err(e))
        }
    }
}

/// `tunnel.unexpose`：撤销暴露规则（非属主 / 未知 id 显性失败）
pub fn tunnel_unexpose(ports: &Arc<dyn TunnelPorts>, plugin_id: &str, rule_id: &str) -> Result<bool, String> {
    require(ports, plugin_id, PERMISSION_TUNNEL_SERVE, "host_tunnel_unexpose")?;
    let manager = manager(ports)?;
    let call = Arc::clone(&manager);
    let plugin = plugin_id.to_string();
    let rule = rule_id.to_string();
    let result = block_on(ports, async move { call.unexpose(&plugin, &rule).await }).map_err(wire_err)?;
    if result && !manager.has_open_resources(plugin_id) && !pairing_leases_pending(plugin_id) {
        release_lease(ports, plugin_id, "host_tunnel_unexpose")?;
    }
    Ok(result)
}

/// `tunnel.connect`：建立本地回环代理（返回句柄 JSON）
pub fn tunnel_connect(
    ports: &Arc<dyn TunnelPorts>,
    plugin_id: &str,
    node_id: &str,
    port: u16,
    kind: &str,
    addrs_json: &str,
    pairing_ticket: Option<String>,
) -> Result<String, String> {
    require(ports, plugin_id, PERMISSION_TUNNEL_CONNECT, "host_tunnel_connect")?;
    let manager = manager(ports)?;
    acquire_lease(ports, plugin_id, "host_tunnel_connect")?;
    let call = Arc::clone(&manager);
    let plugin = plugin_id.to_string();
    let node = node_id.to_string();
    let kind = kind.to_string();
    let addrs = addrs_json.to_string();
    let result = block_on(ports, async move {
        call.connect(&plugin, &node, port, &kind, &addrs, pairing_ticket).await
    });
    match result {
        Ok(entry) => serde_json::to_string(&entry).map_err(|e| format!("connect: 句柄序列化失败：{e}")),
        Err(e) => {
            if !manager.has_open_resources(plugin_id) {
                let _ = release_lease(ports, plugin_id, "host_tunnel_connect");
            }
            Err(wire_err(e))
        }
    }
}

/// `tunnel.close`：关闭句柄（listener + 在飞流）
pub fn tunnel_close(ports: &Arc<dyn TunnelPorts>, plugin_id: &str, handle: &str) -> Result<bool, String> {
    require(ports, plugin_id, PERMISSION_TUNNEL_CONNECT, "host_tunnel_close")?;
    let manager = manager(ports)?;
    let call = Arc::clone(&manager);
    let plugin = plugin_id.to_string();
    let handle = handle.to_string();
    let result = block_on(ports, async move { call.close(&plugin, &handle).await }).map_err(wire_err)?;
    if !manager.has_open_resources(plugin_id) && !pairing_leases_pending(plugin_id) {
        release_lease(ports, plugin_id, "host_tunnel_close")?;
    }
    Ok(result)
}

/// `tunnel.issue-pairing-ticket`：签发一次性票据（不落日志）
pub fn tunnel_issue_pairing_ticket(
    ports: &Arc<dyn TunnelPorts>,
    plugin_id: &str,
    port: u16,
    ttl_secs: u32,
) -> Result<String, String> {
    require(
        ports,
        plugin_id,
        PERMISSION_TUNNEL_SERVE,
        "host_tunnel_issue_pairing_ticket",
    )?;
    let manager = manager(ports)?;
    // L6：纯配对场景也要持有服务租约，否则别的插件释放最后租约触发的 stop
    // 会清掉刚签发的票据 / 对等面。租约按 TTL 在后台回收（见上方说明）。
    acquire_lease(ports, plugin_id, "host_tunnel_issue_pairing_ticket")?;
    let call = Arc::clone(&manager);
    let result = block_on(ports, async move { call.issue_pairing_ticket(port, ttl_secs).await });
    match result {
        Ok(ticket) => {
            {
                let mut counts = PAIRING_LEASES.lock().expect("pairing lease table poisoned");
                *counts.entry(plugin_id.to_string()).or_insert(0) += 1;
            }
            schedule_pairing_lease_release(ports, manager, plugin_id, ttl_secs);
            Ok(ticket)
        }
        Err(e) => {
            // 签发失败且没有其他资源：归还刚取得的租约（有资源时租约已被持有，
            // release 会误伤那些资源，不能调用）。
            if !manager.has_open_resources(plugin_id) {
                let _ = release_lease(ports, plugin_id, "host_tunnel_issue_pairing_ticket");
            }
            Err(wire_err(e))
        }
    }
}

/// `tunnel.probe-relay`：只读连通性探测（T19）
///
/// 与其余原语不同，本函数**不碰管理器也不取服务租约**：探测无持久副作用
/// （见 `tunnel::probe` 模块头注）。域层实现住 `tunnel::probe`。
pub fn tunnel_probe_relay(
    ports: &Arc<dyn TunnelPorts>,
    plugin_id: &str,
    addrs_json: &str,
    timeout_ms: u32,
) -> Result<String, String> {
    crate::tunnel::probe::probe_relay(ports, plugin_id, addrs_json, timeout_ms)
}

/// `tunnel.status`：只读投影（两权限任一；不触达网络写面）
pub fn tunnel_status(ports: &Arc<dyn TunnelPorts>, plugin_id: &str) -> Result<String, String> {
    require_either(ports, plugin_id, "host_tunnel_status")?;
    let manager = manager(ports)?;
    let plugin = plugin_id.to_string();
    let status = block_on(ports, async move { manager.status(&plugin).await });
    serde_json::to_string(&status).map_err(|e| format!("status: 投影序列化失败：{e}"))
}

// ==================== 能力模块自报（WIT 绑定层） ====================

#[cfg(feature = "common-host")]
pub use wit_layer::*;

#[cfg(feature = "common-host")]
mod wit_layer {
    use super::*;
    use wasmnest_host_kit::{HostModule, HostModuleDesc, ModuleEntry, WasmPluginState};
    use wasmtime::component::{bindgen, Linker};

    /// 能力模块名（宿主白名单键）
    pub const MODULE_NAME: &str = "tunnel";
    /// 本域提供的 WIT 接口（必须与分片逐字一致）
    pub const MODULE_INTERFACES: &[&str] = &["wasmnest:tunnel@0.0.1/host-tunnel"];
    /// 本域读写的权限位（三位：serve / connect / probe）
    ///
    /// T19 的 `tunnel:probe` 只授予 `probe-relay`，**不**授权任何写面——第三位的
    /// 存在本身是安全判据（配置中心不因「测一下」获得端口映射能力）。
    pub const MODULE_PERMISSIONS: &[&str] = &[
        PERMISSION_TUNNEL_SERVE,
        PERMISSION_TUNNEL_CONNECT,
        PERMISSION_TUNNEL_PROBE,
    ];

    const DESC: HostModuleDesc = HostModuleDesc {
        name: MODULE_NAME,
        interfaces: MODULE_INTERFACES,
        permissions: MODULE_PERMISSIONS,
        abi_min: 38,
    };

    pub struct TunnelModule;

    impl HostModule for TunnelModule {
        fn desc(&self) -> HostModuleDesc {
            DESC
        }

        fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
            wasmnest::tunnel::host_tunnel::add_to_linker::<WasmPluginState, HasSelf>(linker, |s| s)
        }
    }

    type HasSelf = wasmtime::component::HasSelf<WasmPluginState>;

    static MODULE: TunnelModule = TunnelModule;

    inventory::submit! {
        ModuleEntry { module: &MODULE }
    }

    fn ports_for(state: &WasmPluginState) -> Arc<dyn TunnelPorts> {
        match state
            .host
            .domain_ports(MODULE_NAME)
            .and_then(wasmnest_host_kit::ports::downcast_domain_ports::<Arc<dyn TunnelPorts>>)
        {
            Some(ports) => Arc::clone(&ports),
            None => super::ports(),
        }
    }

    bindgen!({
        // provider 侧绑定：能力域自持契约分片（与 peer 域同款，不读端 SDK 生成物）
        path: "wit/tunnel.wit",
        world: "cap-tunnel",
        exports: { default: async },
    });

    impl wasmnest::tunnel::host_tunnel::Host for WasmPluginState {
        fn configure(&mut self, config: wasmnest::tunnel::host_tunnel::TunnelConfig) -> Result<bool, String> {
            tunnel_configure(
                &ports_for(self),
                &self.plugin_id,
                config.allow_wan,
                &config.relay_addrs_json,
            )?;
            Ok(true)
        }

        fn expose(&mut self, config: wasmnest::tunnel::host_tunnel::ExposeConfig) -> Result<String, String> {
            tunnel_expose(
                &ports_for(self),
                &self.plugin_id,
                config.port,
                &config.kind,
                &config.label,
                config.allowed_peers,
            )
        }

        fn unexpose(&mut self, rule_id: String) -> Result<bool, String> {
            tunnel_unexpose(&ports_for(self), &self.plugin_id, &rule_id)
        }

        fn connect(
            &mut self,
            node_id: String,
            port: u16,
            kind: String,
            addrs_json: String,
            pairing_ticket: Option<String>,
        ) -> Result<String, String> {
            tunnel_connect(
                &ports_for(self),
                &self.plugin_id,
                &node_id,
                port,
                &kind,
                &addrs_json,
                pairing_ticket,
            )
        }

        fn close(&mut self, handle: String) -> Result<bool, String> {
            tunnel_close(&ports_for(self), &self.plugin_id, &handle)
        }

        fn issue_pairing_ticket(&mut self, port: u16, ttl_secs: u32) -> Result<String, String> {
            tunnel_issue_pairing_ticket(&ports_for(self), &self.plugin_id, port, ttl_secs)
        }

        fn probe_relay(&mut self, relay_addrs_json: String, timeout_ms: u32) -> Result<String, String> {
            tunnel_probe_relay(&ports_for(self), &self.plugin_id, &relay_addrs_json, timeout_ms)
        }

        fn status(&mut self) -> Result<String, String> {
            tunnel_status(&ports_for(self), &self.plugin_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        granted: Vec<(&'static str, &'static str)>,
        manager: Option<Arc<TunnelManager>>,
        registry: Option<Arc<ServiceRegistry>>,
    }

    impl TunnelPorts for Fake {
        fn check_permission(&self, _plugin_id: &str, permission: &str, _api: &str) -> bool {
            self.granted.iter().any(|(p, _)| *p == permission)
        }

        fn tunnel_manager(&self) -> Option<Arc<TunnelManager>> {
            self.manager.clone()
        }

        fn block_on_any(&self, _fut: BoxedBlocked) -> Box<dyn Any + Send> {
            panic!("权限门 / 未装配路径不得进入 block_on（测试只覆盖拒绝面）")
        }

        fn service_registry(&self) -> Option<Arc<ServiceRegistry>> {
            self.registry.clone()
        }
    }

    fn fake(granted: Vec<(&'static str, &'static str)>) -> Arc<dyn TunnelPorts> {
        Arc::new(Fake {
            granted,
            manager: None,
            registry: None,
        }) as Arc<dyn TunnelPorts>
    }

    #[test]
    fn serve_and_connect_are_separate_bits() {
        let serve = fake(vec![(PERMISSION_TUNNEL_SERVE, "tunnel:serve")]);
        assert!(tunnel_expose(&serve, "p", 8765, "http", "x", vec![]).is_err());
        assert_eq!(
            tunnel_unexpose(&serve, "p", "rule").unwrap_err(),
            "tunnel manager is not assembled (host boot must install it)"
        );
        assert_eq!(
            tunnel_connect(&serve, "p", "n", 8765, "http", "[]", None).unwrap_err(),
            DENIED_CONNECT
        );

        let connect = fake(vec![(PERMISSION_TUNNEL_CONNECT, "tunnel:connect")]);
        assert_eq!(
            tunnel_expose(&connect, "p", 8765, "http", "x", vec![]).unwrap_err(),
            DENIED_SERVE
        );
        assert_eq!(
            tunnel_close(&connect, "p", "h").unwrap_err(),
            "tunnel manager is not assembled (host boot must install it)"
        );
    }

    #[test]
    fn no_permission_is_fail_closed() {
        let none = fake(vec![]);
        assert!(tunnel_expose(&none, "p", 8765, "http", "x", vec![]).is_err());
        assert!(tunnel_connect(&none, "p", "n", 8765, "http", "[]", None).is_err());
        assert!(tunnel_status(&none, "p").is_err());
        assert!(tunnel_configure(&none, "p", false, "[]").is_err());
        assert!(tunnel_issue_pairing_ticket(&none, "p", 8765, 60).is_err());
        assert_eq!(
            tunnel_probe_relay(&none, "p", "[]", 0).unwrap_err(),
            DENIED_PROBE,
            "tunnel:probe 未声明时探测必须 fail-closed"
        );
    }

    /// T19：probe 位是**独立第三位**——只声明 serve / connect 不获得探测面
    #[test]
    fn probe_is_a_separate_bit() {
        for bit in [PERMISSION_TUNNEL_SERVE, PERMISSION_TUNNEL_CONNECT] {
            let ports = fake(vec![(bit, "x")]);
            assert_eq!(
                tunnel_probe_relay(&ports, "p", "[]", 0).unwrap_err(),
                DENIED_PROBE,
                "只声明 {bit} 不应获得 tunnel:probe"
            );
        }
        // 只声明 probe：地址校验先于任何管理器 / 端口调用
        let probe_only = fake(vec![(PERMISSION_TUNNEL_PROBE, "tunnel:probe")]);
        assert!(tunnel_probe_relay(&probe_only, "p", "not-json", 0)
            .unwrap_err()
            .starts_with("relay-address-invalid:"));
    }

    #[test]
    fn status_accepts_either_bit_but_still_requires_manager() {
        for bit in [PERMISSION_TUNNEL_SERVE, PERMISSION_TUNNEL_CONNECT] {
            let ports = fake(vec![(bit, "x")]);
            assert_eq!(tunnel_status(&ports, "p").unwrap_err(), MANAGER_UNAVAILABLE);
        }
    }

    #[test]
    fn configure_parses_relay_addrs_before_touching_manager() {
        let ports = fake(vec![(PERMISSION_TUNNEL_CONNECT, "x")]);
        assert!(tunnel_configure(&ports, "p", true, "not-json").is_err());
        assert_eq!(
            tunnel_configure(&ports, "p", true, "[]").unwrap_err(),
            MANAGER_UNAVAILABLE
        );
    }

    /// 模块描述符与 WIT 分片逐字一致（接口路径 / 权限位）
    #[cfg(feature = "common-host")]
    #[test]
    fn module_descriptor_matches_contract_shard() {
        const WIT: &str = include_str!("../../wit/tunnel.wit");
        assert!(WIT.contains(&format!("interface {}", "host-tunnel")));
        for iface in crate::tunnel::plugin_binding::MODULE_INTERFACES {
            assert_eq!(*iface, "wasmnest:tunnel@0.0.1/host-tunnel");
        }
        for perm in crate::tunnel::plugin_binding::MODULE_PERMISSIONS {
            assert!(["tunnel:serve", "tunnel:connect", "tunnel:probe"].contains(perm));
        }
        assert_eq!(
            crate::tunnel::plugin_binding::MODULE_PERMISSIONS.len(),
            3,
            "T19 起隧道域是三位：serve / connect / probe"
        );
        assert_eq!(crate::tunnel::plugin_binding::MODULE_NAME, "tunnel");
    }
}
