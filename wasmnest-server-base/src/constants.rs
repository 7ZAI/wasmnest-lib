//! 应用常量定义
//!
//! 按领域分组，统一管理所有魔法值，避免硬编码散布各处
//! （2026-09-23 由 `constants/` 目录下 8 个文件合并而来，常量内容未变）

// ==================== 认证（JWT / 配对） ====================

/// JWT 签发者标识
pub const JWT_ISSUER: &str = "WasmNest";

/// 配对码有效期缺省（秒）
///
/// 真源与策略在 `com.wasmnest.bedcode` 插件；宿主这边只剩一个用途：
/// `host-auth` 记录面的 `pairing_code_ttl` 设置缺省（`host_impl/config.rs`），
/// 与插件侧 `pairing/code.rs::PAIRING_CODE_TTL_SECS` 同值对齐。
pub const PAIRING_CODE_TTL_SECS: u64 = 60;

// ==================== Tauri 事件名称 ====================

/// 统一管理所有 emit/listen 的事件字符串，避免拼写错误和重复定义
///
/// 票 09 删除 `SESSION_STATUS_CHANGED`（`"session-status-changed"`）：它的唯一
/// 发布者是内核状态订阅转接通道（`events/forwarder.rs`，同批退役），前端那条
/// 注册名（`session:statusChange`）与它本就不一致、且零生产消费方。会话状态的前端
/// 可见性由插件自己经 `host-events` / `host-bus` 发布。
///
/// 票 07（websocket 业务下沉）删除 `DEVICE_CONNECTED` / `DEVICE_DISCONNECTED`：
/// 设备在线事件由 `com.wasmnest.bedcode` 插件自发布（SDK
/// `EVENT_DEVICE_CONNECTED` = `device:connected`，经 host-events.emit），
/// 宿主不再持有设备业务事件名。
/// 生命周期：应用启动完成
pub const LIFECYCLE_STARTUP: &str = "lifecycle:startup";

/// 生命周期：应用即将关闭
pub const LIFECYCLE_SHUTDOWN: &str = "lifecycle:shutdown";

/// 插件开发模式热重载通知
pub const PLUGIN_DEV_RELOAD: &str = "plugin:dev-reload";

/// 插件自检失败提示（host_mark_plugin_error）— 前端提示，不改插件状态
///
/// payload: 错误信封 `{ code, request_id, params: { plugin } }`，code 恒为
/// `host.plugin.self-check-failed`（ADR 0030 决定 7）；自检详情只进宿主日志。
pub const PLUGIN_ERROR: &str = "plugin:error";

/// 插件运行时异常统一上报（WASM 调用 panic / trap / 自动恢复失败）
///
/// payload: 错误信封 `{ code, request_id, params: { name } }`（与 IPC 信封同形状）；
/// code 由异常 kind 映射（`panic` | `trap` → `host.plugin.trap`，
/// `recovery_failed` → `host.plugin.recovery-failed`，未知 kind → `host.internal`），
/// 映射表见 `manager/host/errors.rs::runtime_error_code`。panic 消息 / 回溯等
/// 全量详情只进宿主日志，与信封 `request_id` 同条带出。
///
/// 与 `PLUGIN_ERROR`（插件主动自检上报）不同：本事件由宿主在检测到插件异常时
/// 主动发出，前端统一 toast 提示用户（节流：同一插件 15s 内合并）。
pub const PLUGIN_RUNTIME_ERROR: &str = "plugin:runtime-error";

/// 窗口关闭请求 — 有运行中会话时发送到前端，请求用户确认
pub const WINDOW_CLOSE_REQUESTED: &str = "window-close-requested";

// ==================== 生命周期钩子 ====================

/// 单个 Shutdown/Startup 钩子的超时时间（秒）
pub const HOOK_TIMEOUT_SECS: u64 = 5;

// ==================== mDNS 广播 ====================

/// mDNS 服务实例名前缀
///
/// 实例名格式为 "WasmNest-{hostname}"
pub const SERVICE_NAME_PREFIX: &str = "WasmNest-";

/// TXT Record key：平台标识
pub const TXT_KEY_PLATFORM: &str = "platform";

/// TXT Record value：桌面端平台
pub const TXT_VALUE_PLATFORM: &str = "desktop";

/// TXT Record key：设备名称
pub const TXT_KEY_DEVICE_NAME: &str = "device_name";

/// TXT Record key：应用版本
pub const TXT_KEY_VERSION: &str = "version";

/// 无法获取主机名时的默认值
pub const DEFAULT_HOSTNAME: &str = "Desktop";

// ==================== 网络 / 连接 ====================

/// 本地回环地址（用于 QR 码 IP fallback）
pub const LOCALHOST_IP: &str = "127.0.0.1";

/// IPv4 回环地址前缀（用于过滤非外部 IP）
pub const IP_LOOPBACK_PREFIX: &str = "127.";

/// IPv4 链路本地地址前缀（用于过滤非外部 IP）
pub const IP_LINK_LOCAL_PREFIX: &str = "169.254.";

// 同步事件广播容量 `SYNC_EVENT_BROADCAST_CAPACITY` 常量已随 websocket 业务下沉票 08 删除：
// 宿主不再持有 `HostSyncEvent` 同步广播通道（插件事件改 bus+emit，见票 05/06）

// ==================== 插件系统 ====================

// 原 SDK 共享常量 re-export（CLAUDE_CONFIG_DIR_NAME 等四项）已随能力域脱绑 P5 删除：
// 全仓零消费者（auto-task 面退役后无引用），SDK 原常量保留（另有独立消费方）。

/// 插件回调超时（秒）
///
/// on_startup / on_shutdown 等插件回调的最大执行时间
pub const PLUGIN_CALLBACK_TIMEOUT_SECS: u64 = 5;

/// 插件包文件名（zip 安装约定）
pub const PLUGIN_MANIFEST_FILE: &str = "plugin.json";

/// WASM 模块文件扩展名
pub const WASM_FILE_EXT: &str = ".wasm";

/// 用户安装来源标记（写于插件目录，与移动端约定一致）
pub const PLUGIN_SOURCE_MARKER: &str = ".wasmnest-source";

/// 来源标记值：本地 zip 安装
pub const SOURCE_FILE_INSTALL: &str = "file-install";

/// zip 安装临时目录（用户插件目录下，安装失败/完成后清理）
pub const PLUGIN_DOWNLOAD_TEMP_DIR: &str = "plugins/_download_tmp";

/// 插件数据目录（app_data_dir 下；插件私有库落点；真源宿主
/// `system/constants/plugin.rs` 逐字对齐）。
/// 票 06 批次 03 超集化：移动 host_impl/db 域消费，桌面侧零消费零影响
pub const PLUGIN_DATA_DIR: &str = "plugins";

/// 插件存储文件子目录名（旧 JSON 文件存储迁移扫描面；真源宿主
/// `system/constants/plugin.rs` 同值）。票 06 批次 03 超集化同上
pub const PLUGIN_STORAGE_DIR: &str = "plugins";

/// 插件热重载防抖时间（毫秒）
///
/// 同一插件在防抖窗口内只触发一次重载，避免 cargo build 连续写入多次触发
pub const PLUGIN_RELOAD_DEBOUNCE_MS: u64 = 500;

/// 插件 HTTP 代理连接超时（秒）
pub const PLUGIN_HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;

/// 插件 HTTP 代理非流式请求总超时（秒）
///
/// 流式请求不设总超时（长连接不应被截断），仅受连接超时约束
pub const PLUGIN_HTTP_TIMEOUT_SECS: u64 = 120;

/// 插件 HTTP 代理非流式响应体上限（字节）
///
/// 非流式 `http_fetch` 响应体会经 canonical ABI 拷入插件线性内存并由插件
/// serde 解析（guest 指令，消耗单次导出调用 fuel 预算）。无上限响应体可能耗尽
/// fuel 触发 trap 污染 Store（`CannotEnterComponent`）；大载荷必须走
/// `stream:true` 流式模式（宿主后台任务经事件逐 chunk 推送，不经 guest 内存）。
/// 32MB 对目录列举/元数据绰绰有余（guest 解析约几 G 指令，远低于 FUEL_PER_CALL 64G）。
pub const PLUGIN_HTTP_RESPONSE_BODY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

/// 单插件可注册 HTTP 端点数量上限（ABI v29 服务端域）：超限 `register-endpoint`
/// 返回 `Err`，无副作用。
///
/// 取值 64 是**抗滥用闸门**（AGENTS §5.1.3 ② 安全闸门）：端点表是无界增长的宿主
/// 资源，单插件占满会让其余插件无法注册。取值不按任何业务端点数量标定，也不随
/// 插件增减调整——插件不能放宽宿主边界。
pub const PLUGIN_HTTP_MAX_ENDPOINTS_PER_PLUGIN: usize = 64;

// ==================== host-database 执行护栏（票据 05，spec `.scratch/2026-09-18-db-http-base-service/`） ====================

/// 插件 SQL 语句执行超时（秒）：
///
/// 主库是内核与全部插件共用的单一连接（全局 Mutex），慢查询会阻塞配对/会话配置/
/// 设置等全部内核 DB 读写。SQLite progress handler 在宿主侧硬中断超时语句，
/// 超时调用返回「查询超时」类错误。保守起步，语义对齐 HTTP 非流式总超时 `PLUGIN_HTTP_TIMEOUT_SECS`。
/// 护栏不可由插件参数调整（安全边界，AGENTS.md §8）。
/// 插件 SQL 语句执行超时（秒）：真源在 `wasmnest-host-api-core::database`（票 18
/// 批次 3 上移共享核），本处 re-export 保既有 `wasmnest_server_base::constants::*` 路径。
///
/// **2026-10-09 双端机制决策**：主库由 wasm-core 管理、不给插件直接调用
/// （`host-database` 退役），本护栏覆盖**插件私有库**（`host-plugin-database`）的
/// 单条语句执行——每插件独立连接，超时护栏防单条语句失控拖垮插件自身。
/// SQLite progress handler 硬中断超时语句；护栏不可由插件参数调整（安全边界）。
pub use wasmnest_host_api_core::database::PLUGIN_DB_STATEMENT_TIMEOUT_SECS;

/// 插件 SQL 查询结果集行数上限（真源同上）：
///
/// 取行循环内计数，超限立即截断并返回带明确说明的错误（引导插件加 LIMIT 或分批）。
/// 查询面（query）结果行会经 canonical ABI 拷入插件线性内存，无上限结果集可能耗尽
/// 单次调用 fuel 预算触发 trap 污染 Store。
pub use wasmnest_host_api_core::database::PLUGIN_DB_QUERY_MAX_ROWS;

/// 插件 SQL 查询结果集序列化字节上限（真源同上；对齐 HTTP 响应体上限 32MB 的既有模式）：
///
/// 取行循环内对每行序列化长度累计计数，超限立即截断报错。
pub use wasmnest_host_api_core::database::PLUGIN_DB_QUERY_MAX_BYTES;

/// 插件 execute-batch 单次调用语句数上限（真源同上）：
///
/// 事务持有全局连接锁期间其他插件/内核调用会等待，语句数上限 + 05 超时护栏
/// 双兜底避免长事务阻塞内核 DB（票据 06）。
pub use wasmnest_host_api_core::database::PLUGIN_DB_EXECUTE_BATCH_MAX_STATEMENTS;

// ==================== host-websocket（ABI v14，spec `.scratch/2026-09-18-ws-base-service/`） ====================

/// 插件 WS 客户端域握手超时上限（秒）：`connect` 同步阻塞至握手完成，
/// 插件传入的 `connect-timeout-secs` 超过本值即截断（spec D4 / §4.4）
pub const PLUGIN_WS_CONNECT_TIMEOUT_SECS: u64 = 10;

/// 插件 WS 单帧/单消息字节上限兜底（配置不可读时使用）。
///
/// 正常路径取 `wasmnest_server_websocket::routes::ws_frame_limit()`（网络配置：ws_max_frame_size_kb ×
/// ws_max_message_size_mb），与移动端终端链路同一事实源（spec §4.4）
pub const PLUGIN_WS_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// 每条 WS 连接的发送队列长度：入队成功即 `Ok`（不代表已送达对端），
/// 队列满立即 `Err`（fail-visible，宿主不做无界缓冲与背压等待，spec D10）
pub const PLUGIN_WS_SEND_QUEUE_CAPACITY: usize = 64;

/// 单插件 WS 客户端域（出站）连接数上限：超限 `connect` 直接 `Err`（spec §4.4）
pub const PLUGIN_WS_MAX_CONNS_PER_PLUGIN: usize = 32;

/// 单端点入站客户端数上限：超限在协议升级前拒绝（503，不产生连接事件，spec §4.4）
pub const PLUGIN_WS_MAX_CLIENTS_PER_ENDPOINT: usize = 64;

/// 单插件可注册端点数量上限：超限 `register-endpoint` 返回 `Err`，无副作用
pub const PLUGIN_WS_MAX_ENDPOINTS_PER_PLUGIN: usize = 16;

/// 插件端点首消息认证窗口（秒）：`auth:"jwt"` 未在窗口内完成认证 → close(4001)
/// （默认对齐终端链路 `WS_AUTH_TIMEOUT_SECS`，spec D8）
pub const PLUGIN_WS_AUTH_TIMEOUT_SECS: u64 = 10;

/// 插件端点 path 段长度上限（字符）：防超长路径占用路由匹配（spec §4.2）
pub const PLUGIN_WS_ENDPOINT_PATH_MAX_LEN: usize = 64;

// ==================== host-pty（ABI v16，spec `.scratch/2026-09-19-pty-base-service/`） ====================

/// 每插件在册私有 PTY 数量的**默认**上限：manifest 未声明 `ptyQuota` 时取本值；
/// 超限 `spawn` 直接 `Err`（fail-visible，不排队、不静默淘汰自己已有的句柄，spec D9）
///
/// 取值依据：一条私有 PTY 的资源画像 = 一个子进程 + 一对 fd + 一条读线程 + 一块
/// 输出环，与 `PLUGIN_WS_MAX_CONNS_PER_PLUGIN`（出站连接 8 条）同档；8 条够
/// 「多 shell 并发」型插件的常态用量，且越界不牵连同宿主其他插件的配额。
///
/// 会话引擎下沉 P1（H1）后业务会话也住在本注册表，「用户可开多少终端」随属主插件
/// 的声明走（见 [`PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN`]），本值只服务未声明者。
pub const PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN: usize = 8;

/// manifest `ptyQuota` 可声明的硬上限：超过（或声明 0）在**加载期**即拒绝该插件
///
/// 判据落在加载期而不是 `spawn`：配额是插件自我声明的静态事实，装载时就能校验，
/// 没有理由让它在运行期以「第 N+1 条会话创建失败」的形态暴露给用户。
/// **不夹取到上限**（与 [`PLUGIN_PTY_RING_MAX_BYTES`] 同一口径）：静默降级会让插件按
/// 自己声明的并发数规划业务、实际却少得多。
///
/// 取值 64：一条会话 PTY 的常驻成本主要是输出环（默认 256 KB，可声明至 10 MiB），
/// 64 条 × 默认档 = 16 MiB 上界；单插件会话产品的实际并发远不到此值，留出的余量
/// 是给「批量起任务」类用法的，而不是给内核背无限的债。
pub const PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN: usize = 64;

/// 插件私有 PTY 输出环的**默认**容量（字节）：spawn config 未声明 `ringBytes` 时取本值
///
/// 满则淘汰最旧字节（消费者以 `truncated` 感知缺口）——**淘汰只发生在插件自己的
/// 历史上，绝不把背压踢回 PTY 读取端**（spec D3）。刻意不与原业务会话环
/// （旧 `channels.global_queue_max_bytes` 50 MB 档，已随会话下沉退役）同档：插件环随 pty 句柄
/// 存活、每插件可有多条，256 KB 已够一个 TUI 全屏重绘数十帧。需要更深历史的插件
/// 在 spawn 时自行声明 `ringBytes`（上限见 [`PLUGIN_PTY_RING_MAX_BYTES`]）。
pub const PLUGIN_PTY_RING_BYTES: u64 = 256 * 1024;

/// 插件可声明的 `ringBytes` 上限：超过即 `spawn` 返回 `Err`
///
/// **不夹取到上限**——静默降级会让插件按自己声明的深度规划上下文、实际却少得多，
/// 与「配额失败要可见」的分级一致（spec D9）。取值依据：单插件默认并发
/// （`PLUGIN_PTY_MAX_SESSIONS_PER_PLUGIN` = 8）全开即 80 MiB 常驻上界，仍显著
/// 小于业务线单条会话队列的 50 MB 档；声明式配额（最多
/// `PLUGIN_PTY_SESSIONS_CEILING_PER_PLUGIN` = 64 条）下的上界 640 MiB 由「条数 ×
/// 容量」共同约束，且环**按需增长**（空闲会话不占容量）。
///
/// 2026-10-15 由 4 MiB 提到 10 MiB：消费端（`com.wasmnest.bedcode`）按
/// 本上限声明会话环，10 MiB 用于承载「页面不在场期间的产出留存 + fresh subscribe
/// 整段重放窗口」（移动端整段重放受解析速率驱动，环深直接决定回看深度）。
pub const PLUGIN_PTY_RING_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// 单次 `ring-fetch` 返回字节上限：限制一次 wasm 边界拷贝的量
/// （插件传入的 `max-bytes` 超过本值即**截断**——读侧是数据面，截断不是错误，
/// 余下字节按 `next-offset` 续拉即可，spec D9）
pub const PLUGIN_PTY_RING_FETCH_MAX_BYTES: u32 = 16 * 1024;

/// 单次 `write` 字节上限：超限直接 `Err`（fail-visible，不静默截断，spec D6/D9）
///
/// 与引擎侧 4000 字节分块 + 逐块让出（`PtySession::write`）协调：本值是「一次调用」
/// 的准入上限，分块是上限之内的投递节奏。取值 64 KiB ≈ 16 个分块，够一次粘贴级输入。
pub const PLUGIN_PTY_MAX_WRITE_BYTES: usize = 64 * 1024;

// ==================== host-task（ABI v20，spec `.scratch/2026-09-21-host-task-concurrency/`） ====================

/// 全局池线程数：宿主专用 OS 线程池执行插件单元操作计划的并行度。
///
/// **不与 tokio blocking 池共用**：`spawn_blocking` 池与 PTY 读线程、WS 任务共享，
/// 插件批量单元可饿死它们；专用池独立队列 + 利用率可观测（spec §5.2）。
/// 取值 8：经 block_on_async ambient 桥的 IO/CPU 混合单元，8 线程已覆盖典型
/// 并发扇出（50 stat / 3 git），且不与宿主主 runtime 抢调度。
pub const PLUGIN_TASK_POOL_THREADS: usize = 8;

/// 每插件并发在册任务上限（含 running + queued）：超限 `submit` / `execute-batch`
/// 直接 `Err`（fail-visible，宿主仲裁、不排队、不静默降级，spec §7）
pub const PLUGIN_TASK_MAX_JOBS_PER_PLUGIN: usize = 4;

/// 单计划单元数上限：超限 plan 整体拒绝（防单批超大 plan 打爆池队列）
pub const PLUGIN_TASK_MAX_UNITS_PER_PLAN: usize = 256;

/// 单元结果上限（字节，JSON 文本长度）：超出**截断** + `truncated` 标记
/// （保护回调载荷与插件线性内存，spec §7；大结果别靠 status 兜底）
pub const PLUGIN_TASK_UNIT_RESULT_MAX_BYTES: usize = 1024 * 1024;

/// 任务墙钟缺省超时（毫秒）：plan 未给 `jobTimeoutMs` 时按此执行；超时 →
/// cancelled + 已完成单元结果保留（运行中单元跑完或超时）
pub const PLUGIN_TASK_JOB_TIMEOUT_MS: u64 = 3_600_000;

/// 每插件回调队列深度：`events-task` 事件的有界队列。溢出策略：progress 事件可丢
/// （丢弃 + warn + `droppedEvents` 计数，status 可见）；terminal 事件优先入队，
/// 极端情况下 terminal 也丢则 error! 留痕——回调是尽力投递，`status` 是权威快照
/// （spec §5.3）
pub const PLUGIN_TASK_CALLBACK_QUEUE_DEPTH: usize = 64;

/// status 终态结果保留条数上限：超出只留计数（大结果别靠 status 兜底，spec §7）
pub const PLUGIN_TASK_STATUS_RESULTS_MAX: usize = 64;

// ==================== host-worker（worker 机制，spec `.scratch/2026-10-28-worker-mechanism/`） ====================

/// worker 输入字节上限（JSON 字符串长度）：`submit` 同步校验，超限 `Err`
///
/// WIT 传参走 `string` 承载 JSON；超大输入显性报错，文件路径留给 preopen 阶段
/// （ADR 0059）。取值 1 MiB 与 task 单元结果上限（`PLUGIN_TASK_UNIT_RESULT_MAX_BYTES`）
/// 同档：worker 回调事件直载输出（无结果暂存仓库），上限把事件载荷与 guest 内存
/// 拷贝量一起兜住。
pub const PLUGIN_WORKER_INPUT_MAX_BYTES: usize = 1024 * 1024;

/// worker 输出字节上限（JSON 字符串长度）：超限按运行期失败处理（终态 `failed` 事件）
pub const PLUGIN_WORKER_OUTPUT_MAX_BYTES: usize = 1024 * 1024;

/// worker 等待队列深度（全局共享）：submit 受理语义——队列未满即 `Ok`（受理，
/// 运行期失败经终态事件呈现），溢出同步 `Err`（ADR 0059 裁决 A）
pub const PLUGIN_WORKER_QUEUE_DEPTH: usize = 64;

/// worker 全局并发上限（同时在飞的 worker job 数）
///
/// 一线程一 worker、用完即弃；与 task 池线程数（`PLUGIN_TASK_POOL_THREADS`）同量级，
/// 不与 task 池 / tokio blocking 池共享线程。
pub const PLUGIN_WORKER_MAX_CONCURRENT_GLOBAL: usize = 8;

/// per-plugin worker 并发上限（单个声明插件同时在飞的 worker job 数）
pub const PLUGIN_WORKER_MAX_CONCURRENT_PER_PLUGIN: usize = 4;

/// 单个 manifest 可声明的 worker 条目数上限（装载期结构校验）
///
/// 每个条目都是一个独立 Store 的潜在实例化目标（默认 128 MiB 档、per-plugin 并发 4），
/// 条数不设上限等于把宿主资源面交给清单——装载期挡在实例化之前，取值留出
/// 「并发档位 × 2」的池化余量。
pub const PLUGIN_WORKER_DECLARATIONS_MAX: usize = 8;

// ==================== 服务器 / WebSocket / HTTP ====================

/// 默认服务器端口
pub const DEFAULT_SERVER_PORT: u16 = 8765;

// WebSocket 事件通道路径 `WS_EVENT_PATH` 常量已随 websocket 业务下沉票 08 删除：
// `/ws/event` 业务路由退役，宿主只留 `/ws/plugin/{plugin_id}/{path}` 通用插件端点（routes.rs 内联）

/// 健康检查 API 路径
pub const API_HEALTH_PATH: &str = "/api/health";

/// CORS 预检请求缓存时间（秒）
pub const CORS_MAX_AGE_SECS: usize = 3600;

/// WebSocket 心跳间隔（秒）
pub const HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// WebSocket 首消息认证超时（秒）
///
/// spec §4.3：连接建立后 10s 内未完成首消息认证（JWT 或配对流程），
/// 服务端主动关闭连接
pub const WS_AUTH_TIMEOUT_SECS: u64 = 10;

/// 远程客户端超时（秒）
///
/// 移动端在高负载（输出风暴 + 前端渲染 + 日志 I/O）下 Pong 回复可能延迟，
/// 远程通道放宽到 45s 避免高负载误断导致的断连-重连-再订阅循环
pub const REMOTE_CLIENT_TIMEOUT_SECS: u64 = 45;

/// WebSocket 事件广播容量
///
/// 用于 WebSocketManager 内部 ServerEvent 广播
pub const WS_EVENT_BROADCAST_CAPACITY: usize = 16;

/// 服务器重启等待时间（毫秒）
///
/// stop() 后等待旧连接清理完毕再 start()
pub const SERVER_RESTART_DELAY_MS: u64 = 500;

/// 指标采样间隔（秒）
pub const METRICS_SAMPLING_INTERVAL_SECS: u64 = 5;

/// 指标历史记录容量
///
/// VecDeque 预分配容量，同时也是保留的最大条目数
pub const METRICS_HISTORY_CAPACITY: usize = 60;

/// TCP 绑定地址
pub const BIND_ADDRESS: &str = "0.0.0.0";

/// 无法获取对端地址时的占位值
pub const PLACEHOLDER_PEER_ADDR: &str = "0.0.0.0:0";

/// 最大合法端口号
pub const MAX_PORT: u16 = 65535;

/// 端口被占用时搜索替代端口的最大尝试次数
pub const PORT_SEARCH_MAX_ATTEMPTS: u16 = 10;

// ==================== 终端 ====================

/// 终端背景图片文件名前缀（复制后的文件统一命名为 `<前缀>.<ext>`）
pub const TERMINAL_BG_FILE_PREFIX: &str = "terminal_bg";

/// 支持的终端背景图片扩展名
pub const TERMINAL_BG_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico"];

/// 背景图片文件大小上限（20MB）
pub const TERMINAL_BG_MAX_BYTES: u64 = 20 * 1024 * 1024;

/// 提交输入行缓冲区的字节上限（每会话）
///
/// 防御性容量限制：正常用户输入（含多行粘贴）远小于此值，
/// 仅在永不提交的异常字节流下才会触及。超限时丢弃前半部分，
/// 保留尾部内容（对日志场景，最近的输入更有价值）
pub const MAX_SUBMITTED_LINE_BUFFER_BYTES: usize = 256 * 1024;
