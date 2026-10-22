//! mDNS 基础能力服务引擎：共享守护 + 浏览/广播双句柄表
//!
//! **全局唯一 `ServiceDaemon`**（`OnceLock` 单例，init 一次性
//! `disable_virtual_interfaces`）+ BROWSERS / ADVERTISERS 双句柄表（每条带
//! `owner: plugin_id`）。与 peer-net 引擎共享同一守护——消灭「双 daemon 同绑
//! 5353 互抢多播包」的结构性病灶（真机实证：只发现自己、发现不了对端）。
//!
//! **listener 级不变量（ADR 0054）**：共享守护只是第一层——mdns-sd 对每个服务类型
//! 只有**一个 listener 槽**且重复 `browse` 是「后到覆盖先到」，所以本进程对同一服务
//! 类型的 `daemon.browse` / `stop_browse` **只能由类型中枢**
//! （[`crate::type_hub`]）代持：任意数量的消费者（含 peer-net 与移动旧链路）在其中枢
//! 上挂进程内 fan-out 订阅，重查也经中枢统一执行。本模块的浏览原语因此只挂订阅，
//! **不再自己 `daemon.browse`**（那正是「插件 browse 被 peer-net 重查顶成死信道」的
//! 病灶，见 `type_hub` 模块头）。
//!
//! - **事件定向投递**：browse 事件按属主发布到私有 topic `<owner>::mdns:found` /
//!   `<owner>::mdns:lost`（owner = 发起 browse 的插件 id），非属主插件的订阅被
//!   总线命名空间门禁拒绝——业务隔离；
//! - **广播原语**：`advertise` 纯引擎参数透传，宿主零业务拼装；句柄带属主，
//!   跨插件 stop / 查询一律拒绝；周期 re-announce 续期（mdns-sd 注册后不主动
//!   周期广播，须手动续期）；
//! - **双表回收**：[`purge_for_plugin`] 回收某插件全部浏览 + 广播句柄，只碰本人；
//! - **宿主身份广播**（owner=`host`，peer-net 节点身份）：注册动作由引擎经
//!   [`shared_daemon`] 完成（TXT/ServiceInfo 引擎构造，零业务代码），
//!   本模块只做句柄登记，作为「host 与插件 advertise 共存于单守护、互不注销
//!   对方」的可验证凭据。

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use crate::ports::{BoxedTask, DiscoveryPorts, DiscoveryTask};
use crate::wire::{owned_topic, MDNS_FOUND, MDNS_LOST};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Deserialize;

// ==================== 全局共享守护 ====================

/// 全局唯一 mDNS 守护（本进程共享同一实例；mdns-sd 设计即为单守护多服务共享，
/// browse / register 各自独立订阅，互不干扰）。
///
/// `OnceLock`：首次任一原语访问时初始化（browse / advertise / shared_daemon）；
/// stop/query 路径只在「守护已初始化」时触网——单测表操作不强制拉起真实
/// 守护（保持测试与宿主机 mDNS 环境解耦）
static DAEMON: OnceLock<ServiceDaemon> = OnceLock::new();

/// 共享守护初始化平台钩子（D3，双端共享 lib spec M3）
///
/// `init_daemon` 创建守护后调用，宿主按平台装配：桌面无需（`disable_virtual_interfaces`
/// 已在 `init_daemon` 内执行）；移动端注册 Android 多播锁获取（fire-and-forget，
/// 宿主闭包内自行 spawn）。进程级装配一次；未注册 = 无操作（纯引擎零平台知识）。
static DAEMON_INIT_HOOK: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// 装配守护初始化平台钩子（见 [`DAEMON_INIT_HOOK`]；重复装配取首次，静默忽略）
pub fn set_daemon_init_hook(hook: impl Fn() + Send + Sync + 'static) {
    let _ = DAEMON_INIT_HOOK.set(Box::new(hook));
}

fn init_daemon() -> ServiceDaemon {
    tracing::info!("mdns service daemon initializing (single shared instance)");
    let daemon = ServiceDaemon::new().expect("mdns service daemon init failed");
    // 虚拟/回环网卡禁用：多接口监听会在空等解析响应（VMware/Hyper-V/WSL 虚拟
    // 交换机不转发组播，对端 resolve 可延迟分钟级）。仅初始化执行一次——共享
    // 守护对 peer-net 引擎与全部插件浏览一视同仁（peer-net 不再重复执行）
    disable_virtual_interfaces(&daemon);
    // 平台钩子（可选）：移动端 Android 多播锁随守护常驻获取
    if let Some(hook) = DAEMON_INIT_HOOK.get() {
        hook();
    }
    daemon
}

/// 已知虚拟/回环网卡名模式（mDNS 机制，2026-10-22 peer-net-dissolve 归位：
/// 原住 `wasmnest-peer-net`，本质是 mDNS 守护的接口过滤，随守护一并归属本 crate）
const VIRTUAL_IFACE_PATTERNS: &[&str] = &[
    "vmware", "virtualbox", "vbox", "vethernet", "hyper-v", "wsl", "docker",
    "loopback", "loopback pseudo", "virbr", "libvirt",
];

/// 禁用已知虚拟/回环网卡的 mDNS 收发（枚举失败则保持默认全接口，降级不阻断）
///
/// pub：宿主侧独立浏览订阅（host-mdns）同样受多网卡解析延迟困扰，复用本逻辑。
pub fn disable_virtual_interfaces(daemon: &ServiceDaemon) {
    let Ok(ifaces) = local_ip_address::list_afinet_netifas() else {
        tracing::debug!("peer mDNS interface enumeration unavailable, keep all interfaces");
        return;
    };
    let mut disabled: Vec<String> = Vec::new();
    for (name, _) in &ifaces {
        let lower = name.to_lowercase();
        if VIRTUAL_IFACE_PATTERNS.iter().any(|p| lower.contains(p))
            && !disabled.iter().any(|d| d == name)
        {
            match daemon.disable_interface(name.as_str()) {
                Ok(()) => disabled.push(name.clone()),
                Err(e) => tracing::debug!(iface = %name, error = %e, "disable interface failed"),
            }
        }
    }
    if !disabled.is_empty() {
        tracing::info!(ifaces = ?disabled, "peer mDNS virtual interfaces disabled");
    }
}

/// 取全局守护（首次访问触发初始化）
fn daemon() -> &'static ServiceDaemon {
    DAEMON.get_or_init(init_daemon)
}

/// 守护若已初始化则返回（stop/query 前预防性保护：单测表操作不触网）
///
/// `pub`：双端宿主共享化后（spec M3）stop 路径需在不拉起守护的前提下取句柄
/// （host_ports / 命令面 stop 分支）；clone 廉价（mdns-sd 守护句柄内部 Arc）
pub fn daemon_if_initialized() -> Option<ServiceDaemon> {
    DAEMON.get().map(|d| d.clone())
}

/// 周期 re-announce 间隔：mdns-sd 注册后不主动周期广播，须手动续期。
/// 与 peer-net `REANNOUNCE_INTERVAL`（45s）同节奏——同一共享守护上的宿主
/// 身份广播续期由引擎自己的 re-announce 循环负责，本间隔只服务插件 advertise 句柄
const REANNOUNCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(45);

// ==================== 句柄表 ====================

/// 单条浏览订阅：服务类型 + 事件任务句柄 + 中枢退订守卫
struct BrowserEntry {
    service_type: String,
    #[allow(dead_code)] // 事件循环退出以 receiver 断开为准；句柄保留只为表内生命周期可见性
    task: Arc<dyn DiscoveryTask>,
    /// 类型中枢订阅守卫（不透明）：**条目移除即 Drop ⇒ 中枢退订**（该浏览通道关闭、
    /// 浏览任务 recv 断开退出）；同类型其他订阅者不受影响，归零则中枢自行
    /// `stop_browse` 并移除（spec §2.1-④）。字段不读取，纯生命周期托管
    _subscription: Box<dyn std::any::Any + Send + Sync>,
    /// 所属插件（停用时按属主回收全部句柄）
    owner: String,
}

/// 单条广播登记：注销凭据 + 周期续期任务 + 属主
struct AdvertiserEntry {
    /// 服务类型（unregister 按实例全名；按类型用于日志/调试）
    service_type: String,
    /// 完整实例名（`{escaped_instance}.{service_type}`，注销按全名寻址）
    fullname: String,
    /// 周期 re-announce 任务（stop 时回收——不中止会导致已注销服务被重新注册）
    reannounce_task: Arc<dyn DiscoveryTask>,
    /// 属主：插件 id 或 "host"（peer-net 节点身份）
    owner: String,
}

static BROWSERS: LazyLock<Mutex<HashMap<String, BrowserEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static ADVERTISERS: LazyLock<Mutex<HashMap<String, AdvertiserEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn denied() -> String {
    "permission denied: mdns".to_string()
}

/// 非属主操作的统一拒绝文案（属主仲裁）
const NOT_OWNER: &str = "not owner of mdns handle";

/// 取全局共享守护句柄（clone 廉价）：peer-net 引擎接线用
///
/// **全仓共享守护的创建点只有 [`init_daemon`] 一处**——本函数是它的唯一出口，
/// peer-net 引擎与全部插件浏览都经此拿同一个 `ServiceDaemon` 实例。切勿在别处
/// 另建守护：两个守护会争抢同一组播端口（真机实证：只发现自己、发现不了对端）。
///
/// **浏览侧另有一层不变量**：同一服务类型的 `daemon.browse` / `stop_browse` 只允许
/// 类型中枢（[`crate::type_hub`]）调用——共享守护让 peer-net 与插件落到同一个
/// listener 槽上，谁重复 `browse` 谁就把对方的事件流顶成死信道（ADR 0054）。
/// 需要浏览事件请改用 [`crate::type_hub::subscribe_type`]。
pub fn shared_daemon() -> ServiceDaemon {
    daemon().clone()
}

// ==================== 浏览原语 ====================

/// 浏览某服务类型：铸造 browser-id（`mdnsbr-<uuid>`）并启动事件定向投递循环
///
/// 浏览**建立**走类型中枢（[`crate::type_hub::subscribe_type`]）：同类型的多个插件
/// 共享该类型唯一的一条 `daemon.browse`，本模块只挂 fan-out 订阅并把退订守卫托管进
/// [`BrowserEntry`]——不再自己 `daemon.browse`（否则会覆盖别处 listener，
/// 见模块头「listener 级不变量」）。
pub fn browse(
    ports: &Arc<dyn DiscoveryPorts>,
    plugin_id: &str,
    service_type: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, "host_mdns_browse") {
        return Err(denied());
    }
    // 能力路由：本能力由系统组件提供时转发到它的同形导出（票 09 扩表）；
    // 无提供者才走本域引擎。位置与 kv 域一致：**权限门之后、引擎副作用之前**。
    if let Some(result) = ports.forward_mdns_browse(plugin_id, service_type) {
        return result;
    }
    let service_type = service_type.trim().to_string();
    if service_type.is_empty() {
        return Err("mdns browse: service type must not be empty".to_string());
    }
    let (receiver, subscription_guard) =
        crate::type_hub::subscribe_type(&service_type)?.into_parts();

    let browser_id = format!("mdnsbr-{}", uuid::Uuid::new_v4());
    let task_browser_id = browser_id.clone();
    let owner = plugin_id.to_string();
    let event_service_type = service_type.clone();
    // 自播回显过滤用：端口在事件时刻实时读取本机节点 ID
    // （节点可能晚于 browse 启动，须在事件时刻比对而非 browse 时刻）
    let task_ports = ports.clone();
    let task: BoxedTask = Box::pin(async move {
        let browser_id = task_browser_id;
        // found/lost 定向投递；SearchStarted/Resolved 之外的编排事件忽略
        while let Ok(event) = receiver.recv_async().await {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let txt_records: std::collections::BTreeMap<String, String> = info
                        .get_properties()
                        .iter()
                        .map(|p| (p.key().to_string(), p.val_str().to_string()))
                        .collect();
                    // 自播回显过滤：本机广播也会被自己的浏览收到（引擎
                    // handle_browse_event 同口径）。TXT `id` == 本机 NodeId
                    // 即自身，跳过不推送——否则设备列表出现自己、拨号连自己
                    if is_self_broadcast(task_ports.as_ref(), &txt_records) {
                        tracing::debug!(
                            instance = %info.get_fullname(),
                            "mdns browse self-broadcast filtered"
                        );
                        continue;
                    }
                    let addresses: Vec<String> = {
                        // IPv4 优先（与引擎拨号寻址口径一致），同族内保持库序
                        let all: Vec<_> = info.get_addresses().iter().collect();
                        let mut v4: Vec<_> = all
                            .iter()
                            .filter(|a| a.is_ipv4())
                            .map(|a| a.to_ip_addr().to_string())
                            .collect();
                        let rest: Vec<_> = all
                            .iter()
                            .filter(|a| !a.is_ipv4())
                            .map(|a| a.to_ip_addr().to_string())
                            .collect();
                        v4.extend(rest);
                        v4
                    };
                    publish_dir_event(
                        task_ports.as_ref(),
                        &owner,
                        &event_service_type,
                        &browser_id,
                        true,
                        serde_json::json!({
                            "instanceName": info.get_fullname(),
                            "addresses": addresses,
                            "port": info.get_port(),
                            "txtRecords": txt_records,
                        }),
                    );
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    publish_dir_event(
                        task_ports.as_ref(),
                        &owner,
                        &event_service_type,
                        &browser_id,
                        false,
                        serde_json::json!({ "instanceName": fullname }),
                    );
                }
                _ => {}
            }
        }
        tracing::debug!(browser_id = %browser_id, "mdns browse loop exited");
    });
    let task_handle = ports.spawn(task);

    BROWSERS
        .lock()
        .expect("mdns browser table lock poisoned")
        .insert(
            browser_id.clone(),
            BrowserEntry {
                service_type: service_type.clone(),
                task: task_handle,
                _subscription: subscription_guard,
                owner: plugin_id.to_string(),
            },
        );
    tracing::info!(browser_id = %browser_id, service_type = %service_type, plugin = %plugin_id, "mdns browse started");
    Ok(browser_id)
}

/// 停止浏览并回收句柄：权限门 + 属主校验后退订；事件循环随 channel 断开退出。
/// 返回是否存在该句柄（幂等：未知句柄 false）
pub fn stop_browse(
    ports: &Arc<dyn DiscoveryPorts>,
    plugin_id: &str,
    browser_id: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, "host_mdns_stop_browse") {
        return Err(denied());
    }
    if let Some(result) = ports.forward_mdns_stop_browse(plugin_id, browser_id) {
        return result;
    }
    stop_browser_inner(plugin_id, browser_id)
}

/// 取出并停止单条浏览订阅（属主校验：非属主拒绝；幂等：未知句柄 false）
///
/// 退订动作就是**条目移除**：条目里的中枢订阅守卫随之 Drop ⇒ 该浏览的中枢订阅被移除、
/// 通道关闭 ⇒ 浏览事件循环 `recv` 断开退出（日志 `mdns browse loop exited`，与旧的
/// `daemon.stop_browse` 断联形态一致）。该类型的 listener 归零时由中枢自行
/// `stop_browse`；仍有其他订阅者（别的插件 / peer-net）时 listener 不动——这正是
/// 本模块不再直接 `daemon.stop_browse` 的原因（旧写法会摘掉整类型、杀掉别人的浏览）。
fn stop_browser_inner(owner: &str, browser_id: &str) -> Result<bool, String> {
    let mut table = BROWSERS.lock().expect("mdns browser table lock poisoned");
    let Some(entry) = table.remove(browser_id) else {
        return Ok(false);
    };
    if entry.owner != owner {
        table.insert(browser_id.to_string(), entry);
        return Err(NOT_OWNER.to_string());
    }
    let service_type = entry.service_type.clone();
    drop(table);
    // 显式释放守卫（退订）后再落日志：退出时序与日志同序，便于排障对照
    drop(entry);
    tracing::info!(browser_id = %browser_id, service_type = %service_type, "mdns browse stopped");
    Ok(true)
}

// ==================== 广播原语 ====================

/// advertise config JSON 契约：宿主只校验 serviceType 非空，
/// 其余字段原样透传。instanceName 缺省时按 `{plugin}-{短指纹}` 默认
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdvertiseConfig {
    service_type: String,
    #[serde(default)]
    instance_name: Option<String>,
    port: u16,
    #[serde(default)]
    txt_records: HashMap<String, String>,
}

/// 广播某服务类型：铸造 advertise 句柄（`mdnsad-<uuid>`），
/// 共享守护注册 + 周期续期 + 句柄登记（owner = 调用插件）
pub fn advertise(
    ports: &Arc<dyn DiscoveryPorts>,
    plugin_id: &str,
    config_json: &str,
) -> Result<String, String> {
    if !ports.check_permission(plugin_id, "host_mdns_advertise") {
        return Err(denied());
    }
    if let Some(result) = ports.forward_mdns_advertise(plugin_id, config_json) {
        return result;
    }
    let config: AdvertiseConfig = serde_json::from_str(config_json)
        .map_err(|e| format!("mdns advertise: invalid config: {e}"))?;
    let service_type = config.service_type.trim().to_string();
    if service_type.is_empty() {
        return Err("mdns advertise: service type must not be empty".to_string());
    }
    let instance_name = match config.instance_name {
        // 显式实例名优先；空白视为缺省
        Some(name) if !name.trim().is_empty() => name.trim().to_string(),
        _ => default_instance_name(plugin_id),
    };
    // 只校验「serviceType 非空」，其余原样透传（含中文 TXT 值不转义损坏）
    let service_info = ServiceInfo::new(
        &service_type,
        &instance_name,
        &format!("{instance_name}.local."),
        "",
        config.port,
        config.txt_records,
    )
    .map_err(|e| format!("mdns advertise: service info build failed: {e}"))?
    .enable_addr_auto();
    advertise_inner(ports, plugin_id, service_type, service_info)
}

/// 默认实例名 `{plugin}-{短指纹}`：插件 id 的确定性短指纹（进程内稳定），
/// 同插件重复 advertise 同名幂等，不同插件互斥；显式 instanceName 优先
fn default_instance_name(plugin_id: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    plugin_id.hash(&mut hasher);
    let short = hasher.finish() as u32;
    format!("{plugin_id}-{short:08x}")
}

/// 注册某广播到共享守护 + 周期 re-announce + 句柄登记（供插件 advertise、
/// 宿主身份登记与**自播面**共用——后两者 owner="host"，见 [`register_host_service`]
/// 与 `crate::advertiser`）
pub(crate) fn advertise_inner(
    ports: &Arc<dyn DiscoveryPorts>,
    owner: &str,
    service_type: String,
    service_info: ServiceInfo,
) -> Result<String, String> {
    daemon()
        .register(service_info.clone())
        .map_err(|e| format!("mdns advertise: register failed: {e}"))?;
    let fullname = service_info.get_fullname().to_string();

    let advertise_id = format!("mdnsad-{}", uuid::Uuid::new_v4());
    let loop_task: BoxedTask = Box::pin(run_reannounce_loop(daemon().clone(), service_info));
    let reannounce_task = ports.spawn(loop_task);
    ADVERTISERS
        .lock()
        .expect("mdns advertiser table lock poisoned")
        .insert(
            advertise_id.clone(),
            AdvertiserEntry {
                service_type,
                fullname: fullname.clone(),
                reannounce_task,
                owner: owner.to_string(),
            },
        );
    tracing::info!(advertise_id = %advertise_id, instance = %fullname, owner = %owner, "mdns advertise registered");
    Ok(advertise_id)
}

/// 周期 re-announce 任务：每隔 [`REANNOUNCE_INTERVAL`] 重复 register 自身服务
///
/// mdns-sd 的 `register` 幂等（同名覆盖），重复调用直接触发 unsolicited
/// announce（RFC 6762 §8.3 自动补发第二条），不 probe、不发 goodbye——对端
/// 不会误判离线，又能持续收到续期广播，规避 browse 查询指数退避（上限 1 小时）
/// 超过缓存 TTL 导致的「启动互见、随后互不可见」。stop 时上层取消回收。
async fn run_reannounce_loop(daemon: ServiceDaemon, service_info: ServiceInfo) {
    let mut interval = tokio::time::interval(REANNOUNCE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // 首个 tick 立即到期：跳过（advertise_inner 启动时已 register 过一次）
    interval.tick().await;
    loop {
        interval.tick().await;
        if let Err(e) = daemon.register(service_info.clone()) {
            // register 失败只是本次续期丢失（下拍重试），不影响句柄表
            tracing::warn!(
                instance = %service_info.get_fullname(),
                error = %e,
                "mdns re-announce register failed"
            );
        }
    }
}

/// 停止广播并回收句柄：权限门 + 属主校验 → 注销 → 回收续期任务。
/// 返回是否存在该句柄（幂等：未知句柄 false）
pub fn stop_advertise(
    ports: &Arc<dyn DiscoveryPorts>,
    plugin_id: &str,
    advertise_id: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, "host_mdns_stop_advertise") {
        return Err(denied());
    }
    if let Some(result) = ports.forward_mdns_stop_advertise(plugin_id, advertise_id) {
        return result;
    }
    stop_advertise_inner(plugin_id, advertise_id, ports)
}

/// 取出并停止单条广播（属主校验；幂等：未知句柄 false）
///
/// 注销走共享守护 unregister（按实例全名，发 goodbye 对端即时移除本机）；
/// 只注销本人句柄，其余插件广播与本机其他广播不受影响。
///
/// **unregister 是尽力而为**（失败仅 warn，靠缓存 TTL 收敛）——表条目移除 + 续期
/// 取消即停播成功；self 自播面（`advertiser::MdnsAdvertiser::stop`）同此语义
pub(crate) fn stop_advertise_inner(
    owner: &str,
    advertise_id: &str,
    ports: &Arc<dyn DiscoveryPorts>,
) -> Result<bool, String> {
    let mut table = ADVERTISERS
        .lock()
        .expect("mdns advertiser table lock poisoned");
    let Some(entry) = table.remove(advertise_id) else {
        return Ok(false);
    };
    if entry.owner != owner {
        table.insert(advertise_id.to_string(), entry);
        return Err(NOT_OWNER.to_string());
    }
    let fullname = entry.fullname.clone();
    let service_type = entry.service_type.clone();
    // 回收续期任务（不中止会让已注销服务被续期循环重新注册回去）
    entry.reannounce_task.cancel();
    drop(table);
    if let Some(daemon) = daemon_if_initialized() {
        match daemon.unregister(&fullname) {
            Ok(status) => {
                // 注销确认在后台等待（unregister 发 goodbye 是异步完成）；宿主
                // host 调用是同步返回，不 block 等待——状态日志 best-effort
                ports.spawn(Box::pin(async move {
                    let _ = status.recv_async().await;
                }));
            }
            Err(e) => tracing::warn!(instance = %fullname, "mdns unregister failed: {e}"),
        }
    }
    tracing::info!(advertise_id = %advertise_id, service_type = %service_type, "mdns advertise stopped");
    Ok(true)
}

/// 查询广播状态（返回是否存在该句柄）：权限门 + 属主校验（跨插件拒绝）
pub fn is_advertising(
    ports: &Arc<dyn DiscoveryPorts>,
    plugin_id: &str,
    advertise_id: &str,
) -> Result<bool, String> {
    if !ports.check_permission(plugin_id, "host_mdns_is_advertising") {
        return Err(denied());
    }
    if let Some(result) = ports.forward_mdns_is_advertising(plugin_id, advertise_id) {
        return result;
    }
    let table = ADVERTISERS
        .lock()
        .expect("mdns advertiser table lock poisoned");
    match table.get(advertise_id) {
        Some(entry) if entry.owner == plugin_id => Ok(true),
        Some(_) => Err(NOT_OWNER.to_string()),
        None => Ok(false),
    }
}

// ==================== 宿主身份广播登记（owner=host）====================

/// 空任务占位（宿主身份登记用）：本行不挂续期任务，句柄仍参与表内生命周期可见性
///
/// 不实际 spawn（登记上下文可能无端口 / 无运行时——移动端 peer-net 登记、桌面
/// MdnsPort 实现均无端口对象可传），cancel 为 no-op（stop 时无事可收）。
struct NullTask;
impl DiscoveryTask for NullTask {
    fn cancel(&self) {}
}

/// 登记宿主（peer-net 引擎）节点身份广播：注册动作由引擎经 [`shared_daemon`]
/// 完成（TXT/ServiceInfo 由引擎构造——节点身份/证书/能力位是引擎语义，本
/// 模块零业务拼装）；本函数只做 ADVERTISERS 句柄登记（owner=host），作为
/// 「host 与插件 advertise 共存于单守护、互不注销对方」的可验证凭据。
///
/// 注意：节点身份广播的周期续期由引擎自己的 re-announce 循环负责（与
/// [`REANNOUNCE_INTERVAL`] 同节奏），本登记行不挂续期任务，避免双续期
pub fn register_host_service(service_type: &str, fullname: &str) -> Result<String, String> {
    let advertise_id = format!("mdnsad-{}", uuid::Uuid::new_v4());
    let reannounce_task: Arc<dyn DiscoveryTask> = Arc::new(NullTask);
    ADVERTISERS
        .lock()
        .expect("mdns advertiser table lock poisoned")
        .insert(
            advertise_id.clone(),
            AdvertiserEntry {
                service_type: service_type.to_string(),
                fullname: fullname.to_string(),
                reannounce_task,
                owner: "host".to_string(),
            },
        );
    tracing::info!(advertise_id = %advertise_id, instance = %fullname, "host mdns service registered (owner=host)");
    Ok(advertise_id)
}

/// 注销宿主身份广播登记（节点停机时调用）：只移除 owner=host 的登记行，
/// 实际 unregister 由引擎的 DiscoveryDaemon.stop() 按全名完成。幂等
pub fn stop_host_service(advertise_id: &str) -> Result<bool, String> {
    let mut table = ADVERTISERS
        .lock()
        .expect("mdns advertiser table lock poisoned");
    let Some(entry) = table.remove(advertise_id) else {
        return Ok(false);
    };
    if entry.owner != "host" {
        table.insert(advertise_id.to_string(), entry);
        return Err(NOT_OWNER.to_string());
    }
    tracing::info!(advertise_id = %advertise_id, "host mdns service registration removed");
    Ok(true)
}

// ==================== 双表回收 ====================

/// 回收指定插件的全部浏览 + 广播句柄（插件停用/卸载时由宿主调用）。
/// 只回收本人句柄；其余插件与宿主（owner=host）登记不受影响
pub fn purge_for_plugin(plugin_id: &str, ports: &Arc<dyn DiscoveryPorts>) -> usize {
    let mut purged = 0;
    let browse_ids: Vec<String> = BROWSERS
        .lock()
        .expect("mdns browser table lock poisoned")
        .iter()
        .filter(|(_, e)| e.owner == plugin_id)
        .map(|(id, _)| id.clone())
        .collect();
    for id in browse_ids {
        if stop_browser_inner(plugin_id, &id).unwrap_or(false) {
            purged += 1;
        }
    }
    let advertise_ids: Vec<String> = ADVERTISERS
        .lock()
        .expect("mdns advertiser table lock poisoned")
        .iter()
        .filter(|(_, e)| e.owner == plugin_id)
        .map(|(id, _)| id.clone())
        .collect();
    for id in advertise_ids {
        if stop_advertise_inner(plugin_id, &id, ports).unwrap_or(false) {
            purged += 1;
        }
    }
    purged
}

// ==================== 事件定向投递 ====================

/// 定向 publish：browse 事件按属主 topic 发布（payload 增量追加
/// serviceType / browserId，既有 4 字段不变——老订阅者按「忽略未知字段」
/// 增量原则兼容）
fn publish_dir_event(
    ports: &dyn DiscoveryPorts,
    owner: &str,
    service_type: &str,
    browser_id: &str,
    found: bool,
    mut payload: serde_json::Value,
) {
    payload["serviceType"] = serde_json::Value::String(service_type.to_string());
    payload["browserId"] = serde_json::Value::String(browser_id.to_string());
    // owned_topic 拼出完整 topic（含 `<owner>::` 前缀）后交给宿主投递；
    // 总线的订阅方隔离仍属宿主门禁职责
    let topic = owned_topic(owner, if found { MDNS_FOUND } else { MDNS_LOST });
    ports.publish(&topic, payload);
}

/// 自播回显判定：browse 会收到本机自己的广播（TXT `id` == 本机节点 ID）。
///
/// 端口拿不到本机节点 ID（无宿主句柄的无头/测试环境，或节点未启动）时返回
/// false——无法比对即不拦截，与引擎 `handle_browse_event` 的同口径过滤一致。
fn is_self_broadcast(
    ports: &dyn DiscoveryPorts,
    txt: &std::collections::BTreeMap<String, String>,
) -> bool {
    let Some(own) = ports.local_node_id() else {
        return false;
    };
    txt.get("id").map(|v| v.as_str()) == Some(own.as_str())
}
// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 假端口（不触宿主、不起守护）
    struct FakePorts {
        /// 已授权 `network:mdns` 的属主
        granted: Vec<String>,
        /// 本机节点 ID（自播回显过滤）
        node_id: Option<String>,
        /// 捕获到的事件投递（topic, payload）
        published: Mutex<Vec<(String, serde_json::Value)>>,
        /// 「系统组件」代持 `host-mdns` 能力的属主（能力路由用例用）
        routed: Vec<String>,
        /// 「系统组件」侧收到的调用（`(原语, 参数)`，与引擎自有双表**分开**：
        /// 两条路径必须可区分，否则「命中转发」与「走引擎」在断言里长得一样）
        routed_calls: Mutex<Vec<(String, String)>>,
    }

    impl FakePorts {
        fn allow(plugin_id: &str) -> Self {
            Self {
                granted: vec![plugin_id.to_string()],
                node_id: None,
                published: Mutex::new(Vec::new()),
                routed: Vec::new(),
                routed_calls: Mutex::new(Vec::new()),
            }
        }
        fn deny_all() -> Self {
            Self {
                granted: Vec::new(),
                node_id: None,
                published: Mutex::new(Vec::new()),
                routed: Vec::new(),
                routed_calls: Mutex::new(Vec::new()),
            }
        }
        /// 把该属主标为「`host-mdns` 由系统组件代持」（授权已在 `allow` 里给）
        fn routed(mut self) -> Self {
            self.routed = self.granted.clone();
            self
        }
        /// 「系统组件」侧收到的调用记录
        fn routed_calls(&self) -> Vec<(String, String)> {
            self.routed_calls
                .lock()
                .expect("routed sink poisoned")
                .clone()
        }
        /// 能力路由的统一判据：属主在代持集合里才转发
        fn routes(&self, plugin_id: &str) -> bool {
            self.routed.iter().any(|r| r == plugin_id)
        }
        /// 「系统组件」的应答：**刻意取与引擎相反的值**（见路由用例注释）
        ///
        /// `arg` 含 `route-fail` 时回 `Err`（原样透传，不吞不改写）。
        fn provider_result(
            &self,
            plugin_id: &str,
            op: &str,
            arg: &str,
        ) -> Option<Result<String, String>> {
            if !self.routes(plugin_id) {
                return None;
            }
            self.routed_calls
                .lock()
                .expect("routed sink poisoned")
                .push((op.to_string(), arg.to_string()));
            if arg.contains("route-fail") {
                return Some(Err(
                    "system component capability call failed: provider trap".to_string(),
                ));
            }
            Some(Ok(format!("{op}-from-provider")))
        }
        /// 同上，`result<bool, string>` 形状的三条（恒 `false`——引擎在「句柄存在
        /// 且属主相符」时会给 `true`，故 `false` 本身就是「走的不是引擎」证据）
        fn provider_flag(
            &self,
            plugin_id: &str,
            op: &str,
            arg: &str,
        ) -> Option<Result<bool, String>> {
            if !self.routes(plugin_id) {
                return None;
            }
            self.routed_calls
                .lock()
                .expect("routed sink poisoned")
                .push((op.to_string(), arg.to_string()));
            if arg.contains("route-fail") {
                return Some(Err(
                    "system component capability call failed: provider trap".to_string(),
                ));
            }
            Some(Ok(false))
        }
    }

    /// 空任务句柄（测试不真跑后台循环——真跑要起 mDNS 守护）
    struct NoopTask;

    impl DiscoveryTask for NoopTask {
        fn cancel(&self) {}
    }

    impl DiscoveryPorts for FakePorts {
        fn check_permission(&self, plugin_id: &str, _api: &str) -> bool {
            self.granted.iter().any(|g| g == plugin_id)
        }
        fn local_node_id(&self) -> Option<String> {
            self.node_id.clone()
        }
        fn publish(&self, topic: &str, payload: serde_json::Value) {
            self.published
                .lock()
                .expect("published sink poisoned")
                .push((topic.to_string(), payload));
        }
        fn spawn(&self, _task: BoxedTask) -> Arc<dyn DiscoveryTask> {
            // **不执行**：真跑要 tokio runtime + 真实守护；单测只验表与门禁语义
            Arc::new(NoopTask)
        }
        fn forward_mdns_browse(
            &self,
            plugin_id: &str,
            service_type: &str,
        ) -> Option<Result<String, String>> {
            self.provider_result(plugin_id, "browse", service_type)
        }
        fn forward_mdns_stop_browse(
            &self,
            plugin_id: &str,
            browser_id: &str,
        ) -> Option<Result<bool, String>> {
            self.provider_flag(plugin_id, "stop-browse", browser_id)
        }
        fn forward_mdns_advertise(
            &self,
            plugin_id: &str,
            config_json: &str,
        ) -> Option<Result<String, String>> {
            self.provider_result(plugin_id, "advertise", config_json)
        }
        fn forward_mdns_stop_advertise(
            &self,
            plugin_id: &str,
            advertise_id: &str,
        ) -> Option<Result<bool, String>> {
            self.provider_flag(plugin_id, "stop-advertise", advertise_id)
        }
        fn forward_mdns_is_advertising(
            &self,
            plugin_id: &str,
            advertise_id: &str,
        ) -> Option<Result<bool, String>> {
            self.provider_flag(plugin_id, "is-advertising", advertise_id)
        }
    }

    fn ports(p: FakePorts) -> Arc<dyn DiscoveryPorts> {
        Arc::new(p)
    }

    /// 端口 + 可回查的假端口句柄（能力路由用例用）
    ///
    /// 与 [`ports`] 的区别：那边假端口被搬进 trait object 就再也回不来了，而
    /// 路由用例必须能反查「提供者侧到底收到了什么」——否则只能断言返回值，
    /// 判别力不足。
    fn ports_handle(p: FakePorts) -> (Arc<dyn DiscoveryPorts>, Arc<FakePorts>) {
        let arc = Arc::new(p);
        (arc.clone(), arc)
    }

    /// 进程内静态表隔离（cargo test 多线程并行）：每个用例用唯一前缀 id，
    /// 只操作自己插的条目，绝不 clear 全表
    fn test_owner(seed: &str) -> String {
        format!("test-plugin-{seed}")
    }

    fn fake_browser(owner: &str, id: &str, service_type: &str) {
        BROWSERS.lock().unwrap().insert(
            id.to_string(),
            BrowserEntry {
                service_type: service_type.to_string(),
                task: Arc::new(NoopTask),
                // 单测只验表与门禁语义，不接真中枢：空守卫（`()` 无 Drop 副作用）
                _subscription: Box::new(()),
                owner: owner.to_string(),
            },
        );
    }

    fn fake_advertiser(owner: &str, id: &str, service_type: &str, fullname: &str) {
        ADVERTISERS.lock().unwrap().insert(
            id.to_string(),
            AdvertiserEntry {
                service_type: service_type.to_string(),
                fullname: fullname.to_string(),
                reannounce_task: Arc::new(NoopTask),
                owner: owner.to_string(),
            },
        );
    }

    /// 权限门：未授予 `network:mdns` 即拒绝浏览/广播
    #[test]
    fn mdns_denied_without_permission() {
        let p = ports(FakePorts::deny_all());
        assert_eq!(
            browse(&p, "com.wasmnest.no-mdns", "_wasmnest._tcp").unwrap_err(),
            denied()
        );
        assert_eq!(
            stop_browse(&p, "com.wasmnest.no-mdns", "mdnsbr-nonexistent").unwrap_err(),
            denied()
        );
    }

    /// 正例（防「恒拒绝」假绿）：授予后越过权限门，报错来自参数校验而非权限
    /// （用坏配置打门后的第一段代码，避免真起 mDNS 守护）
    #[test]
    fn mdns_granted_passes_permission_gate() {
        let p = ports(FakePorts::allow("com.wasmnest.mdns-ok"));
        let err = advertise(&p, "com.wasmnest.mdns-ok", "not-a-json").expect_err("坏配置应报错");
        assert!(
            !err.contains("permission denied"),
            "已授予仍被权限门拒绝: {err}"
        );
        assert!(err.contains("invalid config"), "预期参数校验错误: {err}");
    }

    /// stop_browser 对未知句柄幂等返回 false（表为空时不 panic）
    #[test]
    fn stop_unknown_browser_is_idempotent_false() {
        assert!(!stop_browser_inner("any-plugin", "mdnsbr-nonexistent").unwrap_or(true));
    }

    /// stop_advertise 对未知句柄幂等返回 false
    #[test]
    fn stop_unknown_advertise_is_idempotent_false() {
        let p = ports(FakePorts::deny_all());
        assert!(!stop_advertise_inner("any-plugin", "mdnsad-nonexistent", &p).unwrap_or(true));
    }

    /// 属主仲裁：非属主 stop / 查询拒绝；属主可操作
    #[test]
    fn cross_plugin_stop_and_query_rejected() {
        let owner = test_owner("ownercheck");
        let other = "intruder-plugin";
        let bid = format!("mdnsbr-{}", uuid::Uuid::new_v4());
        let aid = format!("mdnsad-{}", uuid::Uuid::new_v4());
        let p = ports(FakePorts::deny_all());
        fake_browser(&owner, &bid, "_t1._cp.local.");
        fake_advertiser(&owner, &aid, "_t1._cp.local.", "x._t1._cp.local.");

        // 跨插件 stop / is-advertising → 拒绝（句柄仍保留）
        assert_eq!(
            stop_browser_inner(other, &bid).expect_err("cross stop-browse"),
            NOT_OWNER
        );
        assert_eq!(
            stop_advertise_inner(other, &aid, &p).expect_err("cross stop-advertise"),
            NOT_OWNER
        );
        {
            let table = ADVERTISERS.lock().unwrap();
            assert!(
                table.contains_key(&aid),
                "rejected stop must not consume handle"
            );
        }
        // 属主本人可停
        assert!(stop_browser_inner(&owner, &bid).expect("owner stop browse"));
        assert!(stop_advertise_inner(&owner, &aid, &p).expect("owner stop advertise"));
    }

    /// purge 双表：只回收指定插件句柄，host（owner=host）与它插件登记不动
    #[test]
    fn purge_dual_table_and_preserves_others() {
        let victim = test_owner("purgee");
        let bystander = test_owner("bystander");
        let bid1 = format!("mdnsbr-{}", uuid::Uuid::new_v4());
        let bid2 = format!("mdnsbr-{}", uuid::Uuid::new_v4());
        let bid3 = format!("mdnsbr-{}", uuid::Uuid::new_v4());
        let aid = format!("mdnsad-{}", uuid::Uuid::new_v4());
        let host_aid = format!("mdnsad-{}", uuid::Uuid::new_v4());
        let bystander_aid = format!("mdnsad-{}", uuid::Uuid::new_v4());
        let p = ports(FakePorts::deny_all());
        fake_browser(&victim, &bid1, "_t2._cp.local.");
        fake_browser(&victim, &bid2, "_t2._cp.local.");
        fake_browser(&bystander, &bid3, "_t2._cp.local.");
        fake_advertiser(&victim, &aid, "_t2._cp.local.", "a._t2._cp.local.");
        fake_advertiser("host", &host_aid, "_t2._cp.local.", "h._t2._cp.local.");
        fake_advertiser(
            &bystander,
            &bystander_aid,
            "_t2._cp.local.",
            "b._t2._cp.local.",
        );

        // 只回收 victim 的 2 browse + 1 advertise
        assert_eq!(purge_for_plugin(&victim, &p), 3);
        {
            let ads = ADVERTISERS.lock().unwrap();
            assert!(
                ads.contains_key(&host_aid),
                "host row must survive plugin purge"
            );
            assert!(
                ads.contains_key(&bystander_aid),
                "third-party registration must survive"
            );
            assert!(!ads.contains_key(&aid), "victim advertise purged");
        }
        {
            let bro = BROWSERS.lock().unwrap();
            assert!(
                !bro.contains_key(&bid1) && !bro.contains_key(&bid2),
                "victim browsers purged"
            );
            assert!(bro.contains_key(&bid3), "bystander browser survives");
        }
        // 清理
        let _ = stop_browser_inner(&bystander, &bid3);
        let _ = stop_host_service(&host_aid);
        let _ = stop_advertise_inner(&bystander, &bystander_aid, &p);
    }

    /// advertise 状态翻转：登记 → is-advertising true → stop → false（幂等）
    #[test]
    fn advertise_state_flip_roundtrip() {
        let owner = test_owner("flip");
        let aid = format!("mdnsad-{}", uuid::Uuid::new_v4());
        let p = ports(FakePorts::allow(&owner));
        fake_advertiser(&owner, &aid, "_t3._cp.local.", "f._t3._cp.local.");
        {
            let table = ADVERTISERS.lock().unwrap();
            // 表内状态即 is-advertising 的数据源（权限门 + 属主比对后查表）
            assert_eq!(
                table.get(&aid).map(|e| e.owner.as_str()),
                Some(owner.as_str())
            );
        }
        // 查询断言必须**在锁外**：`is_advertising` 自己要取同一把 Mutex，
        // 放进上面的 guard 作用域里会自死锁（Mutex 不可重入）
        assert!(is_advertising(&p, &owner, &aid).expect("owner query"));
        assert!(stop_advertise(&p, &owner, &aid).expect("stop converts to false"));
        assert!(!stop_advertise(&p, &owner, &aid).expect("repeat stop idempotent false"));
    }

    /// 默认实例名：`{plugin}-{8-hex}`，同插件稳定、跨插件不同
    #[test]
    fn default_instance_name_is_stable_and_distinct() {
        let a1 = default_instance_name("com.wasmnest.file-transfer");
        let a2 = default_instance_name("com.wasmnest.file-transfer");
        let b = default_instance_name("com.wasmnest.other");
        assert_eq!(a1, a2, "same plugin deterministic");
        assert_ne!(a1, b, "different plugins distinct");
        assert!(
            a1.starts_with("com.wasmnest.file-transfer-"),
            "prefix shape {{plugin}}-{{short}}"
        );
    }

    /// 自播回显：端口拿不到本机节点 ID（无头/测试）时不拦截（无法比对即放行）
    #[test]
    fn self_broadcast_filter_needs_node_id() {
        let txt = std::collections::BTreeMap::from([("id".to_string(), "some-node".to_string())]);
        let p = ports(FakePorts::deny_all());
        assert!(
            !is_self_broadcast(p.as_ref(), &txt),
            "no node id ⇒ no filtering"
        );
    }

    /// 自播回显（正例）：TXT `id` == 本机节点 ID ⇒ 判为自己并跳过
    #[test]
    fn self_broadcast_filter_matches_local_node_id() {
        let mut fp = FakePorts::deny_all();
        fp.node_id = Some("node-1".to_string());
        let p = ports(fp);
        let own = std::collections::BTreeMap::from([("id".to_string(), "node-1".to_string())]);
        assert!(
            is_self_broadcast(p.as_ref(), &own),
            "own TXT must be filtered"
        );
        let other = std::collections::BTreeMap::from([("id".to_string(), "node-2".to_string())]);
        assert!(!is_self_broadcast(p.as_ref(), &other), "peer TXT must pass");
    }

    /// 定向事件 payload 增量字段：serviceType / browserId 追加，既有字段保留；
    /// topic 走属主私有命名空间（与 SDK 共用 owned_topic）
    #[test]
    fn directed_event_payload_increments_fields() {
        let payload = serde_json::json!({
            "instanceName": "svc._t4._cp.local.",
            "addresses": ["192.168.1.5"],
            "port": 19000,
            "txtRecords": { "id": "abc" },
        });
        // 手动执行与 publish_dir_event 相同的注入，断言增量字段形状
        let mut enriched = payload.clone();
        enriched["serviceType"] = serde_json::Value::String("_t4._cp.local.".into());
        enriched["browserId"] = serde_json::Value::String("mdnsbr-x".into());
        assert_eq!(enriched["instanceName"], "svc._t4._cp.local.");
        assert_eq!(enriched["port"], 19000);
        assert_eq!(enriched["txtRecords"]["id"], "abc");
        assert_eq!(enriched["serviceType"], "_t4._cp.local.");
        assert_eq!(enriched["browserId"], "mdnsbr-x");
        // topic 形状（属主私有命名空间）
        assert_eq!(owned_topic("plugin-a", MDNS_FOUND), "plugin-a::mdns:found");
        assert_eq!(owned_topic("plugin-a", MDNS_LOST), "plugin-a::mdns:lost");
    }

    /// 集成：双插件同服务类型 browse 隔离（句柄级 + topic 级两层）
    #[test]
    fn browse_owner_isolation_across_plugins() {
        let owner_a = test_owner("iso-a");
        let owner_b = test_owner("iso-b");
        let bid_a = format!("mdnsbr-{}", uuid::Uuid::new_v4());
        let bid_b = format!("mdnsbr-{}", uuid::Uuid::new_v4());
        let p = ports(FakePorts::deny_all());
        fake_browser(&owner_a, &bid_a, "_iso._cp.local.");
        fake_browser(&owner_b, &bid_b, "_iso._cp.local.");
        {
            let table = BROWSERS.lock().unwrap();
            assert_eq!(
                table.get(&bid_a).map(|e| e.owner.as_str()),
                Some(owner_a.as_str())
            );
            assert_eq!(
                table.get(&bid_b).map(|e| e.owner.as_str()),
                Some(owner_b.as_str())
            );
            assert_ne!(bid_a, bid_b, "distinct browser handles");
        }
        // A 的定向 topic 与 B 的互斥（宿主只向属主命名空间投递）
        assert_eq!(
            owned_topic(&owner_a, MDNS_FOUND),
            "test-plugin-iso-a::mdns:found"
        );
        assert_ne!(
            owned_topic(&owner_a, MDNS_FOUND),
            owned_topic(&owner_b, MDNS_FOUND)
        );
        assert_ne!(
            owned_topic(&owner_a, MDNS_LOST),
            owned_topic(&owner_b, MDNS_LOST)
        );
        // purge A 只回收 A 的句柄，B 的浏览不受影响
        assert_eq!(purge_for_plugin(&owner_a, &p), 1);
        {
            let table = BROWSERS.lock().unwrap();
            assert!(!table.contains_key(&bid_a), "A purged");
            assert!(table.contains_key(&bid_b), "B survives plugin A purge");
        }
        let _ = stop_browser_inner(&owner_b, &bid_b);
    }

    /// 集成：host（owner=host）与插件 advertise 共存于单守护
    #[test]
    fn host_and_plugin_advertise_coexist_on_shared_daemon() {
        let plugin = test_owner("coexist");
        let plugin_aid = format!("mdnsad-{}", uuid::Uuid::new_v4());
        let p = ports(FakePorts::deny_all());
        // host 登记（register_host_service：owner=host）
        let host_reg = register_host_service("_co._cp.local.", "h._co._cp.local.")
            .expect("host registration books handle");
        fake_advertiser(&plugin, &plugin_aid, "_co._cp.local.", "p._co._cp.local.");
        {
            let table = ADVERTISERS.lock().unwrap();
            assert!(table.contains_key(&host_reg), "host row present");
            assert!(table.contains_key(&plugin_aid), "plugin row present");
        }
        // 插件 purge 只回收本人，host 登记不动
        assert_eq!(purge_for_plugin(&plugin, &p), 1);
        {
            let table = ADVERTISERS.lock().unwrap();
            assert!(
                table.contains_key(&host_reg),
                "host registration survives plugin purge"
            );
        }
        // 宿主停机（stop_host_service）只移除 host 登记；插件行保留
        fake_advertiser(&plugin, &plugin_aid, "_co._cp.local.", "p._co._cp.local.");
        assert!(stop_host_service(&host_reg).expect("host registration removable"));
        {
            let table = ADVERTISERS.lock().unwrap();
            assert!(
                !table.contains_key(&host_reg),
                "host row removed on node stop"
            );
            assert!(
                table.contains_key(&plugin_aid),
                "plugin advertise survives host stop"
            );
        }
        let _ = stop_advertise_inner(&plugin, &plugin_aid, &p);
    }

    /// 端口未装配即显性失败（fail-visible，不静默空转）
    #[test]
    #[should_panic(expected = "discovery engine ports are not installed")]
    fn uninstalled_ports_panic_loudly() {
        let _ = crate::ports::ports();
    }

    // ==================== 能力路由（host-mdns 由系统组件代持）====================

    /// 代持属主的五条原语全部转发到系统组件，且**引擎侧零副作用**
    ///
    /// 判别力来自「两侧返回值刻意相反」：`stop-browse` / `stop-advertise` /
    /// `is-advertising` 的引擎实现在「句柄存在且属主相符」时会给 `Ok(true)`，
    /// 而假系统组件恒给 `Ok(false)`；`browse` / `advertise` 的引擎实现在这里会
    /// 真起守护（单测不可接受），假系统组件返回 `*-from-provider` 这种引擎不可能
    /// 造出的句柄。故「返回值 == 提供者的值」即证明没走引擎。
    #[test]
    fn routed_mdns_calls_reach_the_system_component_instead_of_the_engine() {
        let owner = test_owner("route-all");
        let browser_id = "mdnsbr-route-all".to_string();
        let advertise_id = "mdnsad-route-all".to_string();
        fake_browser(&owner, &browser_id, "_route._tcp");
        fake_advertiser(
            &owner,
            &advertise_id,
            "_route._tcp.local.",
            "x._route._tcp.local.",
        );

        let (p, fake) = ports_handle(FakePorts::allow(&owner).routed());

        assert_eq!(
            browse(&p, &owner, "_route._tcp").expect("routed browse"),
            "browse-from-provider"
        );
        assert_eq!(
            advertise(&p, &owner, r#"{"serviceType":"_route._tcp","port":1234}"#)
                .expect("routed advertise"),
            "advertise-from-provider"
        );
        assert!(
            !stop_browse(&p, &owner, &browser_id).expect("routed stop-browse"),
            "provider said the handle is unknown even though the engine table has it"
        );
        assert!(
            !stop_advertise(&p, &owner, &advertise_id).expect("routed stop-advertise"),
            "provider said the handle is unknown even though the engine table has it"
        );
        assert!(
            !is_advertising(&p, &owner, &advertise_id).expect("routed is-advertising"),
            "provider said the handle is unknown even though the engine table has it"
        );

        // 提供者侧确实收到了五条调用（顺序即调用序）
        assert_eq!(
            fake.routed_calls(),
            vec![
                ("browse".to_string(), "_route._tcp".to_string()),
                (
                    "advertise".to_string(),
                    r#"{"serviceType":"_route._tcp","port":1234}"#.to_string()
                ),
                ("stop-browse".to_string(), browser_id.clone()),
                ("stop-advertise".to_string(), advertise_id.clone()),
                ("is-advertising".to_string(), advertise_id.clone()),
            ]
        );
        // 引擎双表未被触碰（转发是纯返回，不做引擎副作用）
        assert!(BROWSERS.lock().unwrap().contains_key(&browser_id));
        assert!(ADVERTISERS.lock().unwrap().contains_key(&advertise_id));
    }

    /// 未代持的属主仍走引擎原语（转发端口返回 `None` ⇒ 回落），互不串味
    #[test]
    fn unrouted_owner_keeps_using_the_engine_primitives() {
        let owner = test_owner("route-none");
        let browser_id = "mdnsbr-unrouted".to_string();
        fake_browser(&owner, &browser_id, "_unrouted._tcp");

        let (p, fake) = ports_handle(FakePorts::allow(&owner));

        // 句柄存在且属主相符 ⇒ 引擎给 `true`（假提供者恒给 false，故这是判别式）
        assert!(
            stop_browse(&p, &owner, &browser_id).expect("engine stop-browse"),
            "the engine path must answer `true` for a handle it owns"
        );
        assert!(
            fake.routed_calls().is_empty(),
            "an owner that is not routed must never reach the system component"
        );
    }

    /// 提供者的失败原样透传给调用方（不吞、不改写、不回落引擎）
    ///
    /// 宿主路由层会把这类失败隔离为调用方可见的 `Err` 并让能力回落宿主原语
    /// （见 `manager::capability::unwrap_forward_result`）；能力域这一侧只负责
    /// **不篡改**——一旦这里把错误换成 `Ok` 或自己再跑一遍引擎，
    /// 宿主的「trap 隔离 + 自愈」就永远不会触发。
    #[test]
    fn provider_failure_is_propagated_verbatim_without_engine_fallback() {
        let owner = test_owner("route-fail");
        let (p, fake) = ports_handle(FakePorts::allow(&owner).routed());

        let err =
            browse(&p, &owner, "_route._tcp?route-fail").expect_err("provider failure surfaces");
        assert!(
            err.contains("provider trap"),
            "provider error must be propagated verbatim, got: {err}"
        );
        assert_eq!(
            fake.routed_calls(),
            vec![("browse".to_string(), "_route._tcp?route-fail".to_string())]
        );
        // 且没有偷偷回落成「引擎自己跑一遍」（browse 的引擎路径会起守护并登记句柄）
        assert!(
            !BROWSERS
                .lock()
                .unwrap()
                .values()
                .any(|e| e.service_type == "_route._tcp?route-fail"),
            "no engine browser may be registered when the provider failed"
        );
    }

    /// 权限门优先于能力路由：未授权属主即使被代持也不转发
    ///
    /// 顺序即语义——若有人把转发段提到权限门之前，未授权插件就能借系统组件的
    /// 身份发起组播操作（宿主自己的权限判定被旁路）。
    #[test]
    fn permission_gate_precedes_capability_routing() {
        let owner = test_owner("route-denied");
        // `deny_all()` 不含任何授权；`routed` 以 granted 为源，故此构造下为空集
        let (p, fake) = ports_handle(FakePorts::deny_all());

        assert_eq!(
            browse(&p, &owner, "_route._tcp").unwrap_err(),
            denied(),
            "unauthorized caller must be rejected before routing"
        );
        assert!(fake.routed_calls().is_empty());
    }
}
