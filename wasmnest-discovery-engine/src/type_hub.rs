//! mDNS 类型中枢：全进程对同一服务类型只保留一条 `daemon.browse()`
//!
//! ## 为什么需要它（根因）
//!
//! mdns-sd 的 `service_queriers: HashMap<String, Sender<ServiceEvent>>` 对每个服务
//! 类型只有**一个 listener 槽**，重复 `browse` 是「后到覆盖先到」（库里对非重传命令
//! 直接 `insert`）；且旧 listener 的 sender 被指数重传链永久保活——旧 receiver 从此
//! 收不到任何事件、不报错、也不会 `browse loop exited`。共享守护（一个进程一个
//! `ServiceDaemon`，ADR 0042）把 peer-net 的「每 30s 重查再 browse」与各插件的
//! browse 放进同一守护后，peer-net 每次重查都会静默杀死插件的事件流（真机现场：
//! 插件 browse 建立 2ms 后即死亡，且全程零日志）。
//!
//! 本模块把该槽位的**唯一所有者**收归进程内的「类型中枢」：消费者只挂 fan-out 订阅，
//! 重查改由中枢统一执行（重发 browse + 换绑 receiver + 缓存重放广播全员）。
//!
//! ## 生命周期
//!
//! ```text
//! 首个订阅者 → 建档：daemon.browse ×1（该类型唯一 listener，其余订阅者只挂表）
//! 订阅者 N   → 挂表 + 一次「后缘补齐」合并 browse（保证新订阅者也拿到缓存重放）
//! 重查请求   → 前缘吞并（距上次 browse < 合并窗的请求丢弃，共享同一次缓存重放）
//! 归零       → 立即 daemon.stop_browse + 移除（无 linger）；再次订阅即重建（幂等）
//! ```
//!
//! ## 注入缝
//!
//! daemon 交互（browse / stop_browse）与后台任务派生各自只经一个微型 trait
//! （[`TypeDaemon`] / [`TaskSpawner`]）——生产实现分别接共享守护与宿主端口，单测注入
//! fake 后**零触网**。进程级出口是 [`subscribe_type`] / [`request_type_requery`]；
//! 单测用 [`TypeHubSet::with_parts`] 建独立实例，避免进程级静态表串扰。
//!
//! ## 与 `engine` 的分工
//!
//! `engine` 保留插件侧全部语义（权限门 / 属主仲裁 / 定向 topic 投递 / 双句柄表）；
//! 浏览的**建立与重查**下沉到此：`engine::browse` 只挂中枢订阅并把退订守卫托管进
//! `BrowserEntry`，`stop_browser_inner` 移除条目即守卫 Drop（= 退订）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mdns_sd::ServiceEvent;

use crate::ports::{BoxedTask, DiscoveryTask};

// ==================== 常量 ====================

/// 订阅者通道容量（spec §2.3-D2）：不小于 mdns-sd 自身 listener 通道（bounded(10)）。
/// 满 → 丢弃该条 + 限频 debug：mDNS 事件可重放（重查 / 缓存重放兜底），丢弃只延迟
/// 可见性，不是数据丢失
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 64;

/// 重查合并窗（spec §2.3-D3）：周期 / 即时重查前缘吞并；新订阅者加入后缘补齐
const MERGE_WINDOW: Duration = Duration::from_millis(100);

/// 控制通道容量：只承载「唤醒」语义（Join / Requery / Shutdown），满即吞并
/// （请求本身不带业务数据，重复请求等价于一次唤醒）
const CONTROL_CHANNEL_CAPACITY: usize = 8;

/// 订阅者通道满而丢事件的日志限频间隔（每订阅者一条 debug）
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(1);

// ==================== 注入缝 ====================

/// daemon 交互注入缝（生产 = 共享守护包装；单测 = fake）。
///
/// **为什么只两条方法**：中枢只需要「该类型 listener 的建立 / 摘除」两件事——
/// `register` / `unregister` 属广播面（`engine` 的 ADVERTISERS 表），不在此模块。
/// 窄接口让 fake 只需模拟 mdns-sd 的「单 listener 槽 + 后到覆盖」语义即可验证全部
/// 中枢逻辑。
pub trait TypeDaemon: Send + Sync + 'static {
    /// 建立（或重建）该服务类型的浏览，返回该类型**唯一** listener 的接收端
    fn browse(&self, service_type: &str) -> Result<flume::Receiver<ServiceEvent>, String>;
    /// 摘除该服务类型的 listener（订阅归零时调用）
    fn stop_browse(&self, service_type: &str) -> Result<(), String>;
}

/// 后台任务派生注入缝（生产 = `DiscoveryPorts::spawn`；单测 = 用例运行时派生）。
///
/// 中枢泵任务必须挂在**宿主运行时**上（引擎调用栈不保证处于 tokio runtime 上下文，
/// 直接 `tokio::spawn` 会 panic），故与浏览事件循环同源走端口派生。
pub trait TaskSpawner: Send + Sync + 'static {
    fn spawn(&self, task: BoxedTask) -> Arc<dyn DiscoveryTask>;
}

/// 生产 daemon 缝：每次交互时取共享守护。
///
/// **为什么惰性**：`engine::shared_daemon()` 会初始化进程唯一的 `ServiceDaemon`；
/// 只有真有人订阅（要 browse）时才该触网——不订阅的进程（单测 / 无头）不拉起守护。
struct SharedDaemonSeam;

impl TypeDaemon for SharedDaemonSeam {
    fn browse(&self, service_type: &str) -> Result<flume::Receiver<ServiceEvent>, String> {
        crate::engine::shared_daemon()
            .browse(service_type)
            .map_err(|e| format!("mdns type hub: browse failed: {e}"))
    }

    fn stop_browse(&self, service_type: &str) -> Result<(), String> {
        crate::engine::shared_daemon()
            .stop_browse(service_type)
            .map_err(|e| format!("mdns type hub: stop_browse failed: {e}"))
    }
}

/// 生产任务派生缝：宿主端口（未装配即 fail-visible panic，与 `engine` 其余路径同款）
struct PortsSpawner;

impl TaskSpawner for PortsSpawner {
    fn spawn(&self, task: BoxedTask) -> Arc<dyn DiscoveryTask> {
        crate::ports::ports().spawn(task)
    }
}

// ==================== 订阅句柄 ====================

/// 类型中枢订阅句柄（值形态；与 `wasmnest-server-base::ports::MdnsTypeSubscription`
/// 逐字对齐：私有字段 + [`new`](Self::new) / [`into_parts`](Self::into_parts)）。
///
/// **生命周期不可脱钩（spec §2.3 硬性要求）**：receiver 与退订守卫同处一个句柄，
/// 不实现 `Clone`，也不提供「只取一方」的访问器——只留 receiver 而丢弃守卫会造成
/// 退订泄漏（订阅者永远留在中枢表里，类型 browse 永不归零）。
pub struct MdnsBrowseSubscription {
    /// 中枢 fan-out 的事件通道接收端（容量见 [`SUBSCRIBER_CHANNEL_CAPACITY`]）
    receiver: flume::Receiver<ServiceEvent>,
    /// 退订守卫：Drop ⇒ 中枢移除该订阅（宿主侧只持不解释，纯生命周期托管）
    guard: Box<dyn std::any::Any + Send + Sync>,
}

impl MdnsBrowseSubscription {
    /// 由中枢订阅出口铸造：receiver 与守卫在此同时被接管，句柄存活期间守卫不释放
    pub fn new(
        receiver: flume::Receiver<ServiceEvent>,
        guard: Box<dyn std::any::Any + Send + Sync>,
    ) -> Self {
        Self { receiver, guard }
    }

    /// 解构为 `(receiver, 守卫)`：双方**同时**移交，新持有者必须成对持有 / 释放。
    ///
    /// `engine::browse` 在此消费（receiver 交给浏览事件循环，守卫进 `BrowserEntry`）；
    /// 票 04 的宿主 glue 也把双方移交给 peer-net 的值形态 `PeerMdnsBrowse`。
    pub fn into_parts(
        self,
    ) -> (
        flume::Receiver<ServiceEvent>,
        Box<dyn std::any::Any + Send + Sync>,
    ) {
        (self.receiver, self.guard)
    }
}

/// 订阅退订守卫：Drop ⇒ 在所属注册表移除本订阅；该类型订阅归零则**立即**拆除中枢
/// （`stop_browse` + 注册表行移除）。
///
/// **为什么 Drop 里同步做**（而不是给泵任务投递退订消息）：spec §2.1-④ 要求归零
/// **立即** `stop_browse`；同步完成既满足该不变量，也避免「泵任务已死 → 退订永不
/// 生效」的依赖倒挂。守卫只持注册表 + 服务类型 + 订阅号，**不持** `Arc<Hub>`——
/// 否则守卫会把中枢的控制端一并保活，泵任务永不退出。
struct SubscriptionGuard {
    hubs: Arc<TypeHubSet>,
    service_type: String,
    subscriber_id: u64,
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.hubs
            .unsubscribe(&self.service_type, self.subscriber_id);
    }
}

// ==================== 中枢状态 ====================

/// 单个服务类型的中枢（注册表的一行）
struct Hub {
    /// 代次：拆除 / 换代后，旧泵任务的重查不再对新代中枢生效（mdns-sd 单 listener 槽
    /// 的「后到覆盖」语义不允许跨代交错 browse）。注册表 + 泵任务共同以它识别身份
    id: u64,
    service_type: String,
    /// 泵任务 / 注册表 / 守卫共享的中枢状态
    state: Arc<Mutex<HubState>>,
    /// 泵任务控制端（Join / Requery / Shutdown）。
    /// `is_disconnected()` = 泵任务已退出（receiver 被 drop）⇒ 该代中枢是僵尸
    control: flume::Sender<HubCmd>,
}

/// 中枢共享状态（订阅表 + 合并窗水位）
struct HubState {
    /// 订阅者表（fan-out 目标）
    subscribers: Vec<Subscriber>,
    /// 最近一次 `daemon.browse` 时刻（前缘吞并判据）
    last_browse: Instant,
    /// 后缘补齐到期时刻：`None` = 无待办；新订阅者加入时置为「加入时刻 + 合并窗」，
    /// 窗口内多次加入反复推后（合并为一次 browse，取最后一次加入）
    join_deadline: Option<Instant>,
}

/// 单个订阅者：fan-out 发送端 + 满通道丢弃统计
struct Subscriber {
    id: u64,
    tx: flume::Sender<ServiceEvent>,
    /// 累计因通道满而丢弃的事件数
    dropped: u64,
    /// 上次丢弃日志时刻（限频：每 [`DROP_LOG_INTERVAL`] 最多一条 debug）
    last_drop_log: Option<Instant>,
}

/// 泵任务控制命令（只承载「唤醒」语义：判定所需状态都在 [`HubState`]，命令不带数据）
enum HubCmd {
    /// 新订阅者已挂表：泵重读 `join_deadline`，到点执行后缘补齐 browse
    Join,
    /// 重查请求：前缘吞并由泵按 `last_browse` 判定
    Requery,
    /// 中枢拆除：泵退出
    Shutdown,
}

/// 取中枢状态锁（**毒锁不阻断中枢**：panic 已由泵侧错误边界记录，继续服务其余订阅者
/// 优于让一次已记录的 panic 冻结整个发现面）
fn lock_state(state: &Mutex<HubState>) -> MutexGuard<'_, HubState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ==================== 注册表 ====================

/// 类型中枢注册表：`service_type → Hub`（进程级实例见 [`hubs`]）。
///
/// **锁序纪律**：需要同时持注册表锁与状态锁时，一律「注册表 → 状态」，永不反向。
/// daemon 的 browse / stop_browse 必须在**注册表锁内**调用：mdns-sd 的单 listener 槽
/// 是「后到覆盖」语义，同一类型的两次 browse 一旦交错，后一次会把前一次的 listener
/// 顶成死信道——持锁让「建档 browse」与「泵侧重发 browse」严格串行。
pub struct TypeHubSet {
    daemon: Arc<dyn TypeDaemon>,
    spawner: Arc<dyn TaskSpawner>,
    /// 重查合并窗（生产 = [`MERGE_WINDOW`]；单测注入短窗，免真实等待）
    window: Duration,
    hubs: Mutex<HashMap<String, Arc<Hub>>>,
    next_hub_id: AtomicU64,
    next_subscriber_id: AtomicU64,
}

impl TypeHubSet {
    /// 组装（注入缝）：单测传 fake 建**独立实例**，进程级静态表不参与，用例间零串扰
    pub fn with_parts(
        daemon: Arc<dyn TypeDaemon>,
        spawner: Arc<dyn TaskSpawner>,
        window: Duration,
    ) -> Self {
        Self {
            daemon,
            spawner,
            window,
            hubs: Mutex::new(HashMap::new()),
            next_hub_id: AtomicU64::new(1),
            next_subscriber_id: AtomicU64::new(1),
        }
    }

    /// 订阅某服务类型：首个订阅者建档（唯一 browse），其余只挂表 + 后缘补齐。
    ///
    /// `self: &Arc<Self>`：订阅守卫要持有注册表句柄，才能在 Drop 时同步退订。
    pub fn subscribe(
        self: &Arc<Self>,
        service_type: &str,
    ) -> Result<MdnsBrowseSubscription, String> {
        let service_type = service_type.trim();
        if service_type.is_empty() {
            return Err("mdns type hub: service type must not be empty".to_string());
        }
        loop {
            let mut hubs = self.hubs.lock().expect(REGISTRY_LOCK);
            if let Some(hub) = hubs.get(service_type).cloned() {
                if hub.control.is_disconnected() {
                    // R7：泵任务已退出（panic / 被取消）⇒ 该代中枢是僵尸（无人 fan-out）。
                    // 以 drained 同路径拆除，下一轮按「首个订阅」重建（幂等）。
                    drop(hubs);
                    self.teardown_stale(&hub);
                    continue;
                }
                // 挂表与「拆除」互斥（同一把注册表锁）：不会挂进一个已从注册表摘除、
                // listener 已停的旧代中枢
                let (subscription, subscriber_id, subscribers) = {
                    let mut state = lock_state(&hub.state);
                    let (subscription, subscriber_id) =
                        self.attach_locked(&mut state, service_type, true);
                    (subscription, subscriber_id, state.subscribers.len())
                };
                drop(hubs);
                tracing::debug!(
                    service_type = %service_type,
                    hub_id = hub.id,
                    subscriber_id,
                    subscribers,
                    "mdns type hub reused"
                );
                // 唤醒泵重读后缘补齐窗口（命令不带数据；通道满 = 已有待处理唤醒，等价）
                let _ = hub.control.try_send(HubCmd::Join);
                return Ok(subscription);
            }
            // 建档：唯一 browse。**持注册表锁调用**（理由见结构体文档），
            // 失败原样上报调用方（首个订阅者拿得到错误，不静默）
            let receiver = self.daemon.browse(service_type)?;
            let hub_id = self.next_hub_id.fetch_add(1, Ordering::SeqCst);
            let (control, control_rx) = flume::bounded::<HubCmd>(CONTROL_CHANNEL_CAPACITY);
            let state = Arc::new(Mutex::new(HubState {
                subscribers: Vec::new(),
                last_browse: Instant::now(),
                join_deadline: None,
            }));
            let hub = Arc::new(Hub {
                id: hub_id,
                service_type: service_type.to_string(),
                state: Arc::clone(&state),
                control,
            });
            // 先登记 + 挂上首个订阅者，再起泵：建档 browse 已产生的缓存重放还压在
            // listener 通道缓冲里，泵起来时订阅者已在表内 ⇒ 首屏事件不会漏给建档者
            let (subscription, subscriber_id, subscribers) = {
                let mut state = lock_state(&state);
                let (subscription, subscriber_id) =
                    self.attach_locked(&mut state, service_type, false);
                (subscription, subscriber_id, state.subscribers.len())
            };
            hubs.insert(service_type.to_string(), Arc::clone(&hub));
            drop(hubs);
            tracing::info!(
                service_type = %service_type,
                hub_id,
                subscriber_id,
                subscribers,
                "mdns type hub created"
            );
            // 泵任务：该类型唯一浏览事件的 fan-out 点 + 重查合并窗执行者。
            // 返回句柄不持有：退出由 Shutdown 命令 / 控制通道断开驱动（与引擎浏览
            // 任务「以通道断开为准」同款）；崩掉则由下次 subscribe 检测控制通道重建
            self.spawner.spawn(Box::pin(run_hub(
                Arc::clone(self),
                hub,
                receiver,
                control_rx,
            )));
            return Ok(subscription);
        }
    }

    /// 请求该类型立即重查（前缘吞并 / 后缘补齐规则见模块头）。
    ///
    /// 无活跃中枢（该类型当前无订阅者）= 无操作：无人需要重查结果，重新订阅时建档
    /// browse 自带缓存重放。
    pub fn request_requery(&self, service_type: &str) {
        let service_type = service_type.trim();
        let hub = self
            .hubs
            .lock()
            .expect(REGISTRY_LOCK)
            .get(service_type)
            .cloned();
        let Some(hub) = hub else { return };
        match hub.control.try_send(HubCmd::Requery) {
            Ok(()) => {}
            // 通道满 ⇒ 已有一个待处理的同义请求（请求是纯唤醒，泵会重读状态判定）
            Err(flume::TrySendError::Full(_)) => {
                tracing::debug!(
                    service_type = %service_type,
                    hub_id = hub.id,
                    "mdns type hub requery coalesced (control queue full)"
                );
            }
            // 泵任务已退出（僵尸中枢）：按 drained 同路径拆除，下次订阅重建（R7）
            Err(flume::TrySendError::Disconnected(_)) => self.teardown_stale(&hub),
        }
    }

    /// 退订（守卫 Drop 路径）：移除订阅者；该类型订阅归零则立即拆除中枢
    /// （`stop_browse` + 注册表行移除，无 linger——spec §2.1-④ / D4）
    fn unsubscribe(&self, service_type: &str, subscriber_id: u64) {
        let mut hubs = self.hubs.lock().expect(REGISTRY_LOCK);
        // 该代已拆除 / 已被换代（旧守卫晚到）：无事可做，幂等
        let Some(hub) = hubs.get(service_type).cloned() else {
            return;
        };
        let drained = {
            let mut state = lock_state(&hub.state);
            state.subscribers.retain(|sub| sub.id != subscriber_id);
            state.subscribers.is_empty()
        };
        if !drained {
            return;
        }
        hubs.remove(service_type);
        drop(hubs);
        self.drain_hub(&hub);
    }

    /// 拆除归零的中枢（守卫退订路径，调用方已摘除注册表行）
    fn drain_hub(&self, hub: &Hub) {
        // 先唤醒泵退出（免得它在下一次 select 里先看到 listener 断开而落一条无关 warn），
        // 再摘 listener。泵任务已死时 try_send 返回 Disconnected——那是 R7 的正常分支
        // （拆除照做，只是无人接收唤醒），故不视为错误
        let _ = hub.control.try_send(HubCmd::Shutdown);
        self.stop_listener_and_log(hub);
    }

    /// 泵自检订阅归零（惰性剔除后无人订阅）⇒ 拆除中枢（spec §2.1-④）
    ///
    /// 与守卫退订同语义，但调用方是泵自身：不再投递 Shutdown（自己 break 退出）。
    fn drain_from_pump(&self, hub: &Hub) {
        self.remove_row(hub);
        self.stop_listener_and_log(hub);
    }

    /// 拆除「泵任务已退出」的僵尸中枢（R7）：移除注册表行 + 摘 listener；
    /// 调用方随后按「首个订阅」重建（幂等）
    fn teardown_stale(&self, hub: &Hub) {
        let removed = self.remove_row(hub);
        tracing::warn!(
            service_type = %hub.service_type,
            hub_id = hub.id,
            removed,
            "mdns type hub pump exited: stale hub torn down (rebuilt on next subscribe)"
        );
        if let Err(e) = self.daemon.stop_browse(&hub.service_type) {
            tracing::warn!(
                service_type = %hub.service_type,
                hub_id = hub.id,
                error = %e,
                "mdns type hub stop_browse failed"
            );
        }
    }

    /// 摘除 listener + `drained-stop` 生命周期日志（拆除路径共用）
    fn stop_listener_and_log(&self, hub: &Hub) {
        if let Err(e) = self.daemon.stop_browse(&hub.service_type) {
            tracing::warn!(
                service_type = %hub.service_type,
                hub_id = hub.id,
                error = %e,
                "mdns type hub stop_browse failed"
            );
        }
        tracing::info!(
            service_type = %hub.service_type,
            hub_id = hub.id,
            "mdns type hub drained-stop"
        );
    }

    /// 按**代次**移除注册表行（幂等：该代已被换代 / 已摘除则 `false`，不得误删新代）
    fn remove_row(&self, hub: &Hub) -> bool {
        let mut hubs = self.hubs.lock().expect(REGISTRY_LOCK);
        let own_row = hubs.get(&hub.service_type).map(|row| row.id) == Some(hub.id);
        if own_row {
            hubs.remove(&hub.service_type);
        }
        own_row
    }

    /// 把新订阅者挂到中枢订阅表（调用方持注册表锁 + 状态锁）。
    ///
    /// `arm_join_window`：
    /// - 建档者 = `false`（它的缓存重放来自建档那次 browse，无需再补）；
    /// - 后续加入者 = `true`（后缘补齐：到期时刻推到「最后一次加入 + 合并窗」，
    ///   窗口内多次加入合并为一次 browse——保证每个新订阅者都拿到自己的缓存重放，
    ///   spec §2.1-⑤「不缩水的立即重放」）。
    fn attach_locked(
        self: &Arc<Self>,
        state: &mut HubState,
        service_type: &str,
        arm_join_window: bool,
    ) -> (MdnsBrowseSubscription, u64) {
        let subscriber_id = self.next_subscriber_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = flume::bounded::<ServiceEvent>(SUBSCRIBER_CHANNEL_CAPACITY);
        state.subscribers.push(Subscriber {
            id: subscriber_id,
            tx,
            dropped: 0,
            last_drop_log: None,
        });
        if arm_join_window {
            state.join_deadline = Some(Instant::now() + self.window);
        }
        let guard = SubscriptionGuard {
            hubs: Arc::clone(self),
            service_type: service_type.to_string(),
            subscriber_id,
        };
        (
            MdnsBrowseSubscription::new(rx, Box::new(guard)),
            subscriber_id,
        )
    }

    /// 把一条 daemon 事件 fan-out 给该类型全部订阅者。
    ///
    /// - 通道满（`Full`）⇒ 丢弃该订阅者的这一条 + 限频 debug（见 [`DROP_LOG_INTERVAL`]）；
    /// - 通道断开（`Disconnected`）⇒ **惰性剔除**：守卫丢失路径的兜底（spec D4）；
    /// - 剔除后订阅归零 ⇒ 返回 [`FanOut::Drained`]，由调用方按 drained 同路径拆除。
    fn fan_out(&self, hub: &Hub, event: &ServiceEvent) -> FanOut {
        let mut state = lock_state(&hub.state);
        let now = Instant::now();
        let mut kept: Vec<Subscriber> = Vec::with_capacity(state.subscribers.len());
        let mut evicted = 0usize;
        for mut sub in std::mem::take(&mut state.subscribers) {
            match sub.tx.try_send(event.clone()) {
                Ok(()) => kept.push(sub),
                Err(flume::TrySendError::Full(_)) => {
                    // 慢消费者丢事件：mDNS 事件可重放（重查 / 缓存重放兜底），只延迟可见性
                    sub.dropped += 1;
                    let should_log = sub
                        .last_drop_log
                        .map(|at| now.saturating_duration_since(at) >= DROP_LOG_INTERVAL)
                        .unwrap_or(true);
                    if should_log {
                        sub.last_drop_log = Some(now);
                        tracing::debug!(
                            service_type = %hub.service_type,
                            hub_id = hub.id,
                            subscriber_id = sub.id,
                            dropped = sub.dropped,
                            "mdns type hub subscriber lagging: event dropped"
                        );
                    }
                    kept.push(sub);
                }
                Err(flume::TrySendError::Disconnected(_)) => {
                    evicted += 1;
                    tracing::debug!(
                        service_type = %hub.service_type,
                        hub_id = hub.id,
                        subscriber_id = sub.id,
                        "mdns type hub subscriber evicted (receiver gone)"
                    );
                }
            }
        }
        state.subscribers = kept;
        let drained = evicted > 0 && state.subscribers.is_empty();
        drop(state);
        if drained {
            FanOut::Drained
        } else {
            FanOut::Continue
        }
    }

    /// 泵侧重发 browse（重查 / 后缘补齐）并在成功时换绑 listener。
    ///
    /// **持注册表锁校验代次**：旧代泵（拆除后仍在收尾）不得覆盖新代中枢的 listener
    /// ——mdns-sd 单 listener 槽的「后到覆盖」语义下一旦交错，被覆盖方的 receiver 就
    /// 成了死信道。返回 `None` = 该代已不在册（调用方保留当前 listener）或重发失败
    /// （已 warn）。
    fn rebrowse_guarded(
        &self,
        hub: &Hub,
        reason: RebrowseReason,
    ) -> Option<flume::Receiver<ServiceEvent>> {
        let hubs = self.hubs.lock().expect(REGISTRY_LOCK);
        if hubs.get(&hub.service_type).map(|row| row.id) != Some(hub.id) {
            return None;
        }
        match self.daemon.browse(&hub.service_type) {
            Ok(receiver) => {
                {
                    let mut state = lock_state(&hub.state);
                    state.last_browse = Instant::now();
                    // 本次 browse 的缓存重放同时发给此刻全员（含刚加入者）⇒ 后缘补齐的
                    // 待办窗口已被满足，清掉免得再补一次
                    state.join_deadline = None;
                }
                tracing::debug!(
                    service_type = %hub.service_type,
                    hub_id = hub.id,
                    reason = reason.as_str(),
                    "mdns type hub rebrowse"
                );
                Some(receiver)
            }
            Err(e) => {
                tracing::warn!(
                    service_type = %hub.service_type,
                    hub_id = hub.id,
                    error = %e,
                    "mdns type hub rebrowse failed"
                );
                None
            }
        }
    }

    /// 订阅者数（单测可观察量：订阅表增删的真实结果）
    #[cfg(test)]
    fn subscriber_count(&self, service_type: &str) -> usize {
        let Some(hub) = self
            .hubs
            .lock()
            .expect(REGISTRY_LOCK)
            .get(service_type)
            .cloned()
        else {
            return 0;
        };
        // 先落成局部量再返回：`lock_state` 返回的临时守卫会在块的局部量之后才析构，
        // 直接作为尾表达式会触发「`hub` 借用活得不够久」的 E0597。
        let count = lock_state(&hub.state).subscribers.len();
        count
    }

    /// 该类型是否在册（单测可观察量：拆除 / 重建的真实结果）
    #[cfg(test)]
    fn is_active(&self, service_type: &str) -> bool {
        self.hubs
            .lock()
            .expect(REGISTRY_LOCK)
            .contains_key(service_type)
    }

    /// 该类型中枢的泵任务是否仍在线（单测可观察量：用于「模拟泵任务退出」的时序等待）
    #[cfg(test)]
    fn pump_alive(&self, service_type: &str) -> bool {
        self.hubs
            .lock()
            .expect(REGISTRY_LOCK)
            .get(service_type)
            .map(|hub| !hub.control.is_disconnected())
            .unwrap_or(false)
    }
}

/// fan-out 结果（是否因惰性剔除而订阅归零）
enum FanOut {
    Continue,
    Drained,
}

/// 泵侧重发 browse 的缘由（日志字段用）
enum RebrowseReason {
    /// 周期 / 即时重查（前缘吞并后放行）
    Requery,
    /// 新订阅者加入的后缘补齐
    JoinWindow,
}

impl RebrowseReason {
    fn as_str(&self) -> &'static str {
        match self {
            RebrowseReason::Requery => "requery",
            RebrowseReason::JoinWindow => "join-rebrowse",
        }
    }
}

// ==================== 中枢泵任务 ====================

/// 中枢泵任务：该服务类型唯一浏览事件的 fan-out 点 + 重查合并窗执行者。
///
/// 三路等待（控制命令 / listener 事件 / 后缘补齐到期）都在这里收口——浏览事件不经过
/// 任何消费者自己的循环，消费者只看各自的中枢订阅通道（`try_send` 非阻塞，故慢消费者
/// 不会拖住 mdns-sd 的发送线程，风险 R2 由此消除）。
async fn run_hub(
    hubs: Arc<TypeHubSet>,
    hub: Arc<Hub>,
    mut events: flume::Receiver<ServiceEvent>,
    control: flume::Receiver<HubCmd>,
) {
    loop {
        // 后缘补齐到期：无待办时永久挂起（`None` 分支不能退化成「远未来定时器」，
        // 否则空转）
        let deadline = lock_state(&hub.state).join_deadline;
        let timer = async move {
            match deadline {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(timer);

        enum Wake {
            Cmd(Result<HubCmd, flume::RecvError>),
            Event(Result<ServiceEvent, flume::RecvError>),
            JoinWindow,
        }
        let wake = tokio::select! {
            cmd = control.recv_async() => Wake::Cmd(cmd),
            event = events.recv_async() => Wake::Event(event),
            _ = &mut timer => Wake::JoinWindow,
        };

        match wake {
            Wake::Cmd(Ok(HubCmd::Shutdown)) => break,
            // 唤醒语义：下一轮重读 `join_deadline`
            Wake::Cmd(Ok(HubCmd::Join)) => {}
            Wake::Cmd(Ok(HubCmd::Requery)) => {
                // 前缘吞并：距上次 browse 不足一个合并窗的请求丢弃（与上次共享同一次
                // 缓存重放，spec §2.3-D3）
                let since = lock_state(&hub.state).last_browse.elapsed();
                if since < hubs.window {
                    tracing::debug!(
                        service_type = %hub.service_type,
                        hub_id = hub.id,
                        "mdns type hub requery merged (within window)"
                    );
                } else if let Some(receiver) = hubs.rebrowse_guarded(&hub, RebrowseReason::Requery)
                {
                    events = receiver;
                }
            }
            // 控制端全部断开（中枢已无主）：退出
            Wake::Cmd(Err(_)) => break,
            Wake::Event(Ok(event)) => {
                // 错误边界：单条事件的处理 panic 只终结本类型中枢（下次 subscribe 检测
                // 控制通道已关即按 drained 同路径重建，R7），不拖垮宿主进程
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    hubs.fan_out(&hub, &event)
                }));
                match outcome {
                    Ok(FanOut::Continue) => {}
                    Ok(FanOut::Drained) => {
                        hubs.drain_from_pump(&hub);
                        break;
                    }
                    Err(_) => {
                        tracing::error!(
                            service_type = %hub.service_type,
                            hub_id = hub.id,
                            "mdns type hub panicked while fanning out; hub retires until next subscribe"
                        );
                        break;
                    }
                }
            }
            // 该类型 listener 断开（共享守护停机 / 别处 stop_browse）：中枢随之中止
            Wake::Event(Err(e)) => {
                tracing::warn!(
                    service_type = %hub.service_type,
                    hub_id = hub.id,
                    error = %e,
                    "mdns type hub listener closed"
                );
                break;
            }
            Wake::JoinWindow => {
                // 后缘补齐到期：清标记后重发 browse（缓存重放由新 listener 独享 →
                // 广播全员，spec §2.1-⑤）
                let due = lock_state(&hub.state).join_deadline.take().is_some();
                if !due {
                    // 已被新加入者推后 / 已被上一轮 browse 满足：无事可做
                    continue;
                }
                if let Some(receiver) = hubs.rebrowse_guarded(&hub, RebrowseReason::JoinWindow) {
                    events = receiver;
                }
            }
        }
    }
    tracing::debug!(
        service_type = %hub.service_type,
        hub_id = hub.id,
        "mdns type hub pump exited"
    );
}

// ==================== 进程级出口 ====================

/// 注册表锁中毒文案（表结构是纯机制数据，中毒只可能是本模块自身的 panic）
const REGISTRY_LOCK: &str = "mdns type hub registry lock poisoned";

/// 进程级类型中枢注册表（惰性：不订阅的进程不拉起共享守护，见 [`SharedDaemonSeam`]）
static HUBS: LazyLock<Arc<TypeHubSet>> = LazyLock::new(|| {
    Arc::new(TypeHubSet::with_parts(
        Arc::new(SharedDaemonSeam),
        Arc::new(PortsSpawner),
        MERGE_WINDOW,
    ))
});

/// 订阅某服务类型的中枢 fan-out（spec §2.3 接口形态）。
///
/// 首个订阅者触发该类型**唯一**一次 `daemon.browse`；其后每个订阅者只挂表并触发一次
/// 「后缘补齐」合并重查（约一个合并窗后重发 browse + 缓存重放广播全员），保证新订阅者
/// 的「立即缓存重放」语义不缩水。返回句柄的守卫 Drop 即退订。
pub fn subscribe_type(service_type: &str) -> Result<MdnsBrowseSubscription, String> {
    HUBS.subscribe(service_type)
}

/// 请求该服务类型立即重查（周期 / 即时重查的统一入口；合并窗规则见模块头）。
///
/// 消费方（如 peer-net 的 30s 周期）只负责节奏，重发 browse / 换绑 / 重放都在中枢。
pub fn request_type_requery(service_type: &str) {
    HUBS.request_requery(service_type)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== 夹具 ====================

    /// 假 daemon：模拟 mdns-sd 的**单 listener 槽 + 后到覆盖**语义（spec §0.2）。
    ///
    /// - `browse`：新建通道并**覆盖**该类型的槽位（旧 sender 随之释放——真实库靠指数
    ///   重传链把旧 sender 保活，这里取更严格的「覆盖即断」形态，正中「每订阅者各自
    ///   browse」实现的死穴：变异后旧订阅者连事件都收不到）；
    /// - 每次 browse 立即向新 listener 投递一条可判别的「缓存重放」事件（模拟
    ///   `query_cache_for_service` 只给新 listener 的重放），供用例断言「换绑 / 后缘
    ///   补齐后全员都拿到各自的缓存重放」；
    /// - 调用序列全部登记，供断言「该类型只 browse 了一次」。
    struct FakeDaemon {
        browse_calls: Mutex<Vec<String>>,
        stop_calls: Mutex<Vec<String>>,
        slots: Mutex<HashMap<String, flume::Sender<ServiceEvent>>>,
        /// browse 序号（重放事件的判别标识来源；真实库无此概念，纯粹为可断言）
        seq: AtomicU64,
        /// browse 时是否投递缓存重放（默认关：只验 fan-out 的用例不需要它）
        replay_on_browse: bool,
    }

    impl FakeDaemon {
        fn new(replay_on_browse: bool) -> Self {
            Self {
                browse_calls: Mutex::new(Vec::new()),
                stop_calls: Mutex::new(Vec::new()),
                slots: Mutex::new(HashMap::new()),
                seq: AtomicU64::new(0),
                replay_on_browse,
            }
        }

        /// 已发生的 browse 调用序列（按服务类型，调用序）
        fn browse_calls(&self) -> Vec<String> {
            self.browse_calls.lock().expect("browse log").clone()
        }

        /// 已发生的 stop_browse 调用序列
        fn stop_calls(&self) -> Vec<String> {
            self.stop_calls.lock().expect("stop log").clone()
        }

        /// 往该类型当前 listener 槽投递一条事件（= 真机上的 mDNS 结果到达）
        fn emit(&self, service_type: &str, event: ServiceEvent) {
            let slots = self.slots.lock().expect("slots");
            let tx = slots
                .get(service_type)
                .expect("该类型应有一条活跃 listener（用例前置写错？）");
            tx.try_send(event)
                .expect("listener 通道应有余量（用例未把监听通道压满）");
        }
    }

    impl TypeDaemon for FakeDaemon {
        fn browse(&self, service_type: &str) -> Result<flume::Receiver<ServiceEvent>, String> {
            // 容量对齐 mdns-sd 的 listener 通道（bounded(10)）
            let (tx, rx) = flume::bounded::<ServiceEvent>(10);
            let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
            {
                let mut slots = self.slots.lock().expect("slots");
                // **覆盖**旧槽：这就是「后到覆盖先到」的现场（旧 receiver 从此收不到事件）
                slots.insert(service_type.to_string(), tx.clone());
            }
            self.browse_calls
                .lock()
                .expect("browse log")
                .push(service_type.to_string());
            if self.replay_on_browse {
                tx.try_send(found_event(service_type, &format!("replay-{seq}")))
                    .expect("新 listener 通道应有余量");
            }
            Ok(rx)
        }

        fn stop_browse(&self, service_type: &str) -> Result<(), String> {
            self.stop_calls
                .lock()
                .expect("stop log")
                .push(service_type.to_string());
            self.slots.lock().expect("slots").remove(service_type);
            Ok(())
        }
    }

    /// 宿主 `DiscoveryTask` 同款语义：cancel = abort
    struct TestTask {
        handle: tokio::task::JoinHandle<()>,
    }

    impl DiscoveryTask for TestTask {
        fn cancel(&self) {
            self.handle.abort();
        }
    }

    /// 派生缝：在本用例的 tokio 运行时上跑泵任务，并保留 abort 句柄
    /// （矩阵 7 用它模拟「泵任务退出」）
    #[derive(Default)]
    struct TestSpawner {
        aborts: Mutex<Vec<tokio::task::AbortHandle>>,
    }

    impl TestSpawner {
        /// 让已派生的泵任务终结（等价于任务 panic 后退出的事件面）
        fn abort_all(&self) {
            for abort in self.aborts.lock().expect("aborts").drain(..) {
                abort.abort();
            }
        }
    }

    impl TaskSpawner for TestSpawner {
        fn spawn(&self, task: BoxedTask) -> Arc<dyn DiscoveryTask> {
            let handle = tokio::spawn(task);
            self.aborts
                .lock()
                .expect("aborts")
                .push(handle.abort_handle());
            Arc::new(TestTask { handle })
        }
    }

    /// 组装被测中枢：**独立注册表实例**（假 daemon + 本用例派生缝 + 注入的合并窗），
    /// 进程级静态表与共享守护一概不参与（零触网、用例间零串扰）
    fn harness(
        window: Duration,
        replay_on_browse: bool,
    ) -> (Arc<TypeHubSet>, Arc<FakeDaemon>, Arc<TestSpawner>) {
        let daemon = Arc::new(FakeDaemon::new(replay_on_browse));
        let spawner = Arc::new(TestSpawner::default());
        let hubs = Arc::new(TypeHubSet::with_parts(
            daemon.clone(),
            spawner.clone(),
            window,
        ));
        (hubs, daemon, spawner)
    }

    /// 取一条事件（超时即用例失败）：fan-out 是异步的，等待本身也让泵任务得以运行
    async fn next_event(rx: &flume::Receiver<ServiceEvent>) -> ServiceEvent {
        tokio::time::timeout(Duration::from_secs(2), rx.recv_async())
            .await
            .expect("事件应在超时前到达（fan-out 未生效？）")
            .expect("订阅通道不得关闭")
    }

    /// 事件的可判别标识（断言「哪一条重放到达了谁」）
    fn instance_of(event: &ServiceEvent) -> String {
        match event {
            ServiceEvent::ServiceResolved(info) => info.get_fullname().to_string(),
            other => panic!("用例只投递 ServiceResolved，实际收到: {other:?}"),
        }
    }

    /// 期望的 fullname 形状（与 mdns-sd 的 `{instance}.{service_type}` 同形）
    fn fullname(service_type: &str, instance: &str) -> String {
        format!("{instance}.{service_type}")
    }

    /// 构造投递事件（实例名可判别）
    ///
    /// mdns-sd 0.20 的 `ServiceResolved` 载荷是 `Box<ResolvedService>`（不是 `ServiceInfo`），
    /// 故先建 `ServiceInfo` 再经 `as_resolved_service()` 转成解析结果。
    fn found_event(service_type: &str, instance: &str) -> ServiceEvent {
        let info = mdns_sd::ServiceInfo::new(
            service_type,
            instance,
            "hub-test.local.",
            "",
            1234,
            HashMap::new(),
        )
        .expect("用例事件必须是合法 ServiceInfo");
        ServiceEvent::ServiceResolved(Box::new(info.as_resolved_service()))
    }

    // ==================== 矩阵 1：唯一 browse + 全员收到同一事件 ====================

    /// 矩阵 1：同类型两次 subscribe **只**发生一次 `daemon.browse`，且两个订阅者都收到同一
    /// 事件（先加入者不被后到者顶掉）。
    ///
    /// 合并窗取大值：本用例只验「新增订阅者不触发再次 browse」与 fan-out；后缘补齐的计数
    /// 另有用例（小窗会在等待期间多补一次 browse，干扰这里的计数断言）。
    ///
    /// 变异自检：把中枢退回「每订阅者各自 `daemon.browse`（后到覆盖）」⇒ 第二次 subscribe
    /// 立刻再 browse 一次（断言 2 红），且新 listener 顶掉旧槽 ⇒ 先加入者收不到事件
    /// （断言 3 红）。
    #[tokio::test]
    async fn two_subscribers_share_one_browse_and_both_receive_the_event() {
        let ty = "_hub-one._tcp.local.";
        let (hubs, daemon, _spawner) = harness(Duration::from_secs(60), false);

        let (rx_a, guard_a) = hubs.subscribe(ty).expect("首个订阅建档").into_parts();
        assert_eq!(
            daemon.browse_calls(),
            vec![ty.to_string()],
            "建档恰好 browse 一次"
        );

        let (rx_b, guard_b) = hubs.subscribe(ty).expect("第二个订阅挂表").into_parts();
        assert_eq!(
            daemon.browse_calls(),
            vec![ty.to_string()],
            "新增订阅者不得再触发 browse"
        );
        assert_eq!(hubs.subscriber_count(ty), 2, "两订阅者都在 fan-out 表内");

        // 同一事件穿过唯一 listener，必须同时到达两个订阅者
        daemon.emit(ty, found_event(ty, "svc-1"));
        let event_a = next_event(&rx_a).await;
        let event_b = next_event(&rx_b).await;
        assert_eq!(
            instance_of(&event_a),
            fullname(ty, "svc-1"),
            "先加入者收到事件"
        );
        assert_eq!(
            instance_of(&event_b),
            fullname(ty, "svc-1"),
            "后加入者收到同一事件"
        );
        assert_eq!(daemon.browse_calls().len(), 1, "事件投递不触发额外 browse");

        drop(guard_a);
        drop(guard_b);
        assert_eq!(
            daemon.stop_calls(),
            vec![ty.to_string()],
            "归零后摘 listener 恰一次"
        );
    }

    // ==================== 矩阵 2：requery 换绑 + 后缘补齐 ====================

    /// 矩阵 2：requery 换绑——旧 listener 失效后，两个订阅者仍收到**换绑后**的实时事件与
    /// 缓存重放。
    ///
    /// 同一场景顺带覆盖「后缘补齐」：B 加入后窗口补一次 browse（B 由此拿到自己的缓存重放）。
    /// A 的事件序列：r1（建档重放）→ r2（补齐重放）→ r3(重查重放）→ 实时事件；
    /// B 的序列：r2 → r3 → 实时事件（B 加入时 r1 已被消费）。序列本身即断言。
    #[tokio::test]
    async fn requery_rebinds_listener_and_replays_to_every_subscriber() {
        let ty = "_hub-two._tcp.local.";
        let window = Duration::from_millis(20);
        let (hubs, daemon, _spawner) = harness(window, true);

        let (rx_a, guard_a) = hubs.subscribe(ty).expect("首个订阅建档").into_parts();
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "replay-1"),
            "建档 browse 的缓存重放给建档者"
        );

        let (rx_b, guard_b) = hubs.subscribe(ty).expect("第二个订阅挂表").into_parts();
        assert_eq!(
            instance_of(&next_event(&rx_b).await),
            fullname(ty, "replay-2"),
            "新订阅者必须拿到自己的缓存重放（后缘补齐）"
        );
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "replay-2"),
            "补齐 browse 的重放广播全员"
        );
        assert_eq!(daemon.browse_calls().len(), 2, "建档 + 一次后缘补齐");

        // 等出前缘窗再 requery：换绑 listener（生成 replay-3 的新 listener）
        tokio::time::sleep(window * 2).await;
        hubs.request_requery(ty);
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "replay-3"),
            "换绑后的缓存重放必须到先加入者"
        );
        assert_eq!(
            instance_of(&next_event(&rx_b).await),
            fullname(ty, "replay-3"),
            "换绑后的缓存重放必须到后加入者"
        );
        assert_eq!(daemon.browse_calls().len(), 3);

        // 换绑后 listener 上的实时事件同样广播全员
        daemon.emit(ty, found_event(ty, "svc-live"));
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "svc-live")
        );
        assert_eq!(
            instance_of(&next_event(&rx_b).await),
            fullname(ty, "svc-live")
        );
        assert_eq!(daemon.browse_calls().len(), 3, "实时事件不触发 browse");

        drop(guard_a);
        drop(guard_b);
    }

    // ==================== 矩阵 3：合并窗（前缘吞并 + 后缘补齐） ====================

    /// 矩阵 3：窗内两次 requery 只产生一次 browse；窗内多次加入合并为一次补齐 browse。
    ///
    /// 前缘吞并的判别方式：requery #2 落在窗内（被吞并），随后窗外的 requery #3 必然
    /// browse。控制命令 FIFO，故 #3 的重放到账即证明 #2 已被处理过——此刻 browse 总数仍是
    /// 3（建档 + #1 + #3），说明 #2 没有 browse（若吞并失效会是 4）。
    #[tokio::test]
    async fn merge_window_absorbs_requeries_and_coalesces_joining_subscribers() {
        let ty = "_hub-three._tcp.local.";
        let window = Duration::from_millis(20);
        let (hubs, daemon, _spawner) = harness(window, true);

        let (rx_a, guard_a) = hubs.subscribe(ty).expect("首个订阅建档").into_parts();
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "replay-1"),
            "建档 browse"
        );

        // 前缘吞并（放行侧）：出窗后的 requery #1 立即重发 browse
        tokio::time::sleep(window * 2).await;
        hubs.request_requery(ty);
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "replay-2"),
            "窗外 requery 放行"
        );
        assert_eq!(daemon.browse_calls().len(), 2);

        // 前缘吞并（吞并侧）：窗内的 requery #2 被丢弃
        hubs.request_requery(ty);
        tokio::time::sleep(window * 2).await;
        hubs.request_requery(ty);
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "replay-3"),
            "窗外 requery 放行"
        );
        assert_eq!(
            daemon.browse_calls().len(),
            3,
            "窗内那次 requery 必须被吞并（否则为 4）"
        );

        // 后缘补齐：窗内两次加入只补一次 browse，两个新订阅者各自拿到重放
        let (rx_b, guard_b) = hubs.subscribe(ty).expect("B 加入").into_parts();
        let (rx_c, guard_c) = hubs.subscribe(ty).expect("C 加入（同窗内）").into_parts();
        assert_eq!(daemon.browse_calls().len(), 3, "加入本身不触发 browse");
        assert_eq!(
            instance_of(&next_event(&rx_b).await),
            fullname(ty, "replay-4"),
            "B 拿到自己的缓存重放"
        );
        assert_eq!(
            instance_of(&next_event(&rx_c).await),
            fullname(ty, "replay-4"),
            "C 与 B 共享同一次补齐（窗内合并）"
        );
        assert_eq!(
            daemon.browse_calls().len(),
            4,
            "窗内两次加入只补一次 browse"
        );
        assert_eq!(hubs.subscriber_count(ty), 3);

        drop(guard_a);
        drop(guard_b);
        drop(guard_c);
    }

    // ==================== 矩阵 4：守卫退订 / 归零拆除 / 重建幂等 ====================

    /// 矩阵 4：drop 订阅句柄 ⇒ 该通道关闭、订阅者移除；归零 ⇒ `stop_browse` 恰一次 +
    /// 中枢移除（无 linger）；再次 subscribe 走建档路径重建（幂等）。
    #[tokio::test]
    async fn dropping_subscriptions_removes_rows_and_drains_hub_exactly_once() {
        let ty = "_hub-four._tcp.local.";
        let (hubs, daemon, _spawner) = harness(Duration::from_secs(60), false);

        let (rx_a, guard_a) = hubs.subscribe(ty).expect("A 建档").into_parts();
        let (rx_b, guard_b) = hubs.subscribe(ty).expect("B 挂表").into_parts();
        assert_eq!(hubs.subscriber_count(ty), 2);

        // A 退订：只摘 A；B 仍在 ⇒ 不得摘 listener
        drop(guard_a);
        assert_eq!(hubs.subscriber_count(ty), 1, "退订者已从 fan-out 表移除");
        assert!(rx_a.is_disconnected(), "退订后该订阅通道必须关闭");
        assert!(
            !rx_b.is_disconnected(),
            "未退订订阅者的通道必须保持打开（退订不得牵连他人）"
        );
        assert!(
            daemon.stop_calls().is_empty(),
            "仍有订阅者时不得摘 listener"
        );
        assert!(hubs.is_active(ty), "仍有订阅者时中枢在册");

        // B 退订 ⇒ 归零：立即摘 listener + 移除中枢
        drop(guard_b);
        assert_eq!(hubs.subscriber_count(ty), 0);
        assert!(!hubs.is_active(ty), "归零后中枢必须从注册表移除");
        assert_eq!(
            daemon.stop_calls(),
            vec![ty.to_string()],
            "归零后 stop_browse 恰一次"
        );

        // 重建幂等：再订阅即新建档（再 browse 一次），扇出可用
        let (rx_c, guard_c) = hubs.subscribe(ty).expect("重建").into_parts();
        assert_eq!(
            daemon.browse_calls(),
            vec![ty.to_string(), ty.to_string()],
            "重建走建档路径"
        );
        assert!(hubs.is_active(ty));
        daemon.emit(ty, found_event(ty, "svc-rebuilt"));
        assert_eq!(
            instance_of(&next_event(&rx_c).await),
            fullname(ty, "svc-rebuilt"),
            "重建后的扇出可用"
        );

        drop(guard_c);
        assert_eq!(daemon.stop_calls().len(), 2, "再次归零再摘一次（不累积）");
    }

    // ==================== 矩阵 5：惰性兜底（守卫丢失路径） ====================

    /// 矩阵 5：不经守卫直接 drop receiver ⇒ 下一次 fan-out 惰性剔除，不影响其他订阅者；
    /// 唯一订阅者被剔除即归零 ⇒ 照样摘 listener；晚到的守卫 Drop 必须幂等。
    #[tokio::test]
    async fn lazy_eviction_drops_dead_subscribers_and_drains_when_last() {
        let ty = "_hub-five._tcp.local.";
        let other = "_hub-five-other._tcp.local.";
        let (hubs, daemon, _spawner) = harness(Duration::from_secs(60), false);

        // 阶段一：A 的 receiver 被直接 drop（守卫仍活），B 正常 —— 剔除不得牵连他人
        let (rx_a, guard_a) = hubs.subscribe(ty).expect("A 建档").into_parts();
        let (rx_b, guard_b) = hubs.subscribe(ty).expect("B 挂表").into_parts();
        drop(rx_a);
        daemon.emit(ty, found_event(ty, "svc-1"));
        assert_eq!(
            instance_of(&next_event(&rx_b).await),
            fullname(ty, "svc-1"),
            "其他订阅者不受剔除影响"
        );
        assert_eq!(hubs.subscriber_count(ty), 1, "死订阅者被惰性剔除");
        assert!(hubs.is_active(ty), "仍有存活订阅者，中枢不拆");

        // 阶段二：另一类型的唯一订阅者 receiver 被直接 drop ⇒ 剔除即归零 ⇒ 摘 listener
        let (rx_other, guard_other) = hubs.subscribe(other).expect("另一类型建档").into_parts();
        drop(rx_other);
        daemon.emit(other, found_event(other, "svc-2"));
        // 剔除发生在泵任务处理事件时：轮询等它生效（超时即断言失败）
        let mut drained = false;
        for _ in 0..64 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            if !hubs.is_active(other) {
                drained = true;
                break;
            }
        }
        assert!(drained, "唯一订阅者的通道消失后，中枢必须被拆除");
        assert_eq!(
            daemon.stop_calls(),
            vec![other.to_string()],
            "归零后 stop_browse 恰一次"
        );

        // 守卫丢失路径的收尾：晚到的守卫 Drop 幂等（不得再摘一次 listener）
        drop(guard_other);
        assert_eq!(
            daemon.stop_calls(),
            vec![other.to_string()],
            "晚到的守卫 Drop 不得重复摘 listener"
        );

        // 阶段一的 B 仍可用，收尾退订（A 的守卫同样是「订阅已被剔除」的晚到路径）
        daemon.emit(ty, found_event(ty, "svc-3"));
        assert_eq!(instance_of(&next_event(&rx_b).await), fullname(ty, "svc-3"));
        drop(guard_a);
        drop(guard_b);
        assert_eq!(
            daemon.stop_calls(),
            vec![other.to_string(), ty.to_string()],
            "两个类型各摘一次 listener"
        );
    }

    // ==================== 矩阵 7：泵任务退出后重建（R7） ====================

    /// 矩阵 7：泵任务退出（模拟 panic / 被宿主取消）后，再次 subscribe 检测到控制通道已关，
    /// 按 drained 同路径拆旧代并按首个订阅重建（R7 的 fail-visible 恢复路径）。
    #[tokio::test]
    async fn subscribe_rebuilds_hub_after_pump_task_exit() {
        let ty = "_hub-seven._tcp.local.";
        let (hubs, daemon, spawner) = harness(Duration::from_secs(60), false);

        let (rx_a, guard_a) = hubs.subscribe(ty).expect("A 建档").into_parts();
        daemon.emit(ty, found_event(ty, "svc-before"));
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "svc-before"),
            "泵在线时扇出可用"
        );

        // 模拟泵任务退出（真实触发器：任务 panic / 宿主运行时取消任务）
        spawner.abort_all();
        let mut exited = false;
        for _ in 0..64 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            if !hubs.pump_alive(ty) {
                exited = true;
                break;
            }
        }
        assert!(exited, "取消后泵任务应已退出（控制通道对端关闭）");

        // 再次订阅：检测到僵尸中枢 ⇒ 拆旧代（摘 listener）+ 重建（新 browse）
        let (rx_b, guard_b) = hubs.subscribe(ty).expect("重建").into_parts();
        assert_eq!(
            daemon.browse_calls(),
            vec![ty.to_string(), ty.to_string()],
            "重建走建档路径（再 browse 一次）"
        );
        assert_eq!(
            daemon.stop_calls(),
            vec![ty.to_string()],
            "拆旧代时摘一次 listener"
        );
        assert!(rx_a.is_disconnected(), "旧代订阅通道随旧代中枢一起回收");
        daemon.emit(ty, found_event(ty, "svc-after"));
        assert_eq!(
            instance_of(&next_event(&rx_b).await),
            fullname(ty, "svc-after"),
            "重建后的扇出可用"
        );

        drop(guard_a);
        drop(guard_b);
    }

    // ==================== 附加契约：入参校验 / 慢消费者（R1 / D2） ====================

    /// 契约：空服务类型在**触网之前**被拒绝（不得向 daemon 发 browse），也不留注册表行
    #[tokio::test]
    async fn empty_service_type_is_rejected_before_touching_daemon() {
        let (hubs, daemon, _spawner) = harness(Duration::from_secs(60), false);

        let err = hubs.subscribe("   ").err().expect("空白服务类型必须拒绝");
        assert!(
            err.contains("must not be empty"),
            "错误信息需点名原因，实际: {err}"
        );
        assert!(daemon.browse_calls().is_empty(), "拒绝路径不得触碰 daemon");
        assert!(!hubs.is_active(""), "被拒绝的订阅不得留下注册表行");
        assert_eq!(hubs.subscriber_count(""), 0);
    }

    /// 附加（R1 / D2）：订阅者通道满 ⇒ 只丢该订阅者的事件，不阻塞也不剔除；其他订阅者照常
    /// 全量到账；丢弃只延迟可见性（消费出存量后仍能收新事件）。
    #[tokio::test]
    async fn full_subscriber_channel_drops_events_without_evicting_or_blocking_others() {
        let ty = "_hub-cap._tcp.local.";
        let (hubs, daemon, _spawner) = harness(Duration::from_secs(60), false);

        // A 全程不消费（通道必然被填满），B 每条都收 —— 一个慢消费者
        let (rx_a, guard_a) = hubs.subscribe(ty).expect("A 建档").into_parts();
        let (rx_b, guard_b) = hubs.subscribe(ty).expect("B 挂表").into_parts();

        let total = SUBSCRIBER_CHANNEL_CAPACITY + 6;
        for seq in 0..total {
            daemon.emit(ty, found_event(ty, &format!("svc-{seq}")));
            // 以 B 的到账为栅栏：该条事件确实已被泵处理（A 是否收到不影响栅栏）
            assert_eq!(
                instance_of(&next_event(&rx_b).await),
                fullname(ty, &format!("svc-{seq}")),
                "慢消费者的存在不得阻塞其他订阅者"
            );
        }

        assert_eq!(
            rx_a.len(),
            SUBSCRIBER_CHANNEL_CAPACITY,
            "满通道只保留容量内的条目（多出的被丢弃）"
        );
        assert_eq!(
            hubs.subscriber_count(ty),
            2,
            "通道满不得被误判为断开而剔除订阅者"
        );
        assert!(hubs.is_active(ty), "慢消费者不得触发拆除");

        // 丢弃只延迟可见性：消费出存量后仍能收到新事件
        for _ in 0..SUBSCRIBER_CHANNEL_CAPACITY {
            rx_a.try_recv().expect("存量事件仍在通道里");
        }
        daemon.emit(ty, found_event(ty, "svc-tail"));
        assert_eq!(
            instance_of(&next_event(&rx_a).await),
            fullname(ty, "svc-tail"),
            "通道腾空后可继续接收"
        );

        drop(guard_a);
        drop(guard_b);
    }
}
