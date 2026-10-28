//! 权限管理器（Host）——双端唯一真源（2026-10-14 移动权限面收口）
//!
//! Permission Manager
//!
//! 插件权限校验 — 双重校验的后端最终仲裁层。桌面与移动的授权/撤销/判定全部落
//! 本表（桌面 `PluginHost` 与移动 `PluginManager` 同一条路径）；移动宿主原有的
//! `granted_permissions` 副本 + `for_plugin` 逐实例注入已退役。本模块由 wasm-core
//! 自持（机制层零 SDK 依赖），宿主侧经 `WasmHostContext::{grant_permissions,
//! has_permission, granted_permissions, revoke_permissions}` 窄接口进出。
//!
//! **权限词汇单一真源**：本文件的 [`VALID_PERMISSIONS`] 与 [`PERMISSION_API_MAP`]
//! 是桌面端唯一的权限清单。打包 CLI（`bin/cli.js`）的列表是**生成物**，由 `cargo run
//! --manifest-path rust/Cargo.toml --example gen_permission_vocabulary`（即 SDK 的
//! `pnpm run gen:permissions`）重出，禁止手抄；两份（真源 + CLI 生成物）一致性由
//! **平台仓**漂移锁断言（三仓拆分 L2/E2b 票 08 迁出本 crate：
//! `cross-end-tests/tests/permission_vocabulary_lock.rs`——真源是本文件公开常量，
//! 由平台测试经 wasm-core 公开面读取；能力仓不再读平台文件）。
//!
//! desktop-host-frontend-downsink（2026-10-17）：原「宿主前端生成物」
//! `src/plugin/permission.ts` / `permission-vocabulary.ts` 随宿主前端整树退役——
//! 前端不再消费权限词汇，同步点只留打包 CLI 一份。

use std::collections::{HashMap, HashSet};

/// 所有合法权限常量
pub const PERMISSION_TERMINAL_INPUT: &str = "terminal:input";
pub const PERMISSION_TERMINAL_OUTPUT: &str = "terminal:output";
// v27 退役（会话引擎下沉票 10）：`terminal:observe`（提交输入行观察面，票 03 删派发点）
// 与 `session:write`（宿主会话写原语，随 `host-session` 整 interface 删除）。
/// 会话读取（前端 `session.*` 窗口原语面）：**票 10 起只剩宿主终端窗口事实**
/// （预测初始网格 / 打开 / 关闭窗口 / 窗口在场查询）——会话数据面与事件面已分别
/// 随票 08 / 09 退役（插件读会话走自家命令通道）。
pub const PERMISSION_SESSION_READ: &str = "session:read";
/// 宿主 server 在册连接清单读取（WIT `host-connection`，票 04，desktop 独有）：枚举宿主
/// WS 连接注册表的原始条目（含 `fingerprint` 设备标识、未认证连接也在册）。
///
/// **为什么单独立位**（票 04 裁决）：原挂 `session:read`，但那回答不了审计问题
/// 「谁能读到别人的连接清单」——连接在册与否与会话读写无关（会话真源已在插件登记域）。
/// 域名与权限位同源：`host-connection` ↔ `connection:read`。
pub const PERMISSION_CONNECTION_READ: &str = "connection:read";
pub const PERMISSION_UI_SIDEBAR: &str = "ui:sidebar";
pub const PERMISSION_UI_TOOLBOX: &str = "ui:toolbox";
pub const PERMISSION_UI_STATUSBAR: &str = "ui:statusbar";
pub const PERMISSION_UI_DIALOG: &str = "ui:dialog";
/// 页面工具栏项贡献（纯前端贡献面）：`ui.registerPageToolbarItem`
pub const PERMISSION_UI_PAGE_TOOLBAR: &str = "ui:pageToolbar";
/// 设置分组贡献（纯前端贡献面，无 WASM 宿主函数对应）：`ui.registerSettingsSection`
pub const PERMISSION_UI_SETTINGS: &str = "ui:settings";
pub const PERMISSION_UI_INPUT: &str = "ui:input";
/// 文件处理器贡献（纯前端贡献面）：`ui.registerFileHandler`
pub const PERMISSION_UI_FILE_HANDLER: &str = "ui:fileHandler";
pub const PERMISSION_NETWORK_HTTP: &str = "network:http";
pub const PERMISSION_STORAGE: &str = "storage";
pub const PERMISSION_FS_READ: &str = "fs:read";
pub const PERMISSION_FS_WRITE: &str = "fs:write";
/// 系统文件选择器（WIT `host-platform` 的 `pick-files` / `pick-folders`）：
/// 调起**系统原生**对话框（Windows IFileDialog / Linux
/// xdg-desktop-portal），用户可在**整盘任意位置**浏览与选择。
///
/// **为什么单独立位**（与 `fs:read` / `fs:write` 分域）：
/// - 「能调起选择器」与「能读写任意路径」是两种权力。前者只让插件把用户**已经
///   亲手选中**的路径拿到手（拿到后仍要过 `fs_auth` 授权校验），后者是任意路径
///   读写。合成一位会让「只想让用户挑一个文件传出去」的插件被动获得全盘读取面；
/// - 选择器是**平台交互动作**（系统对话框由用户驱动，宿主不读任何数据），但
///   选择结果落到具体路径，因此**选择结束后必须做路径授权校验**（宿主
///   `fs_auth` 三层校验的第二/第三层）：已授权目录下的选择静默放行，未授权的
///   弹一次授权框；「记住」按**所在目录**落账，使同目录后续选择免弹。
///
/// 声明即信任「本插件会调起系统文件选择器」这一行为面；不代表任意路径读写
/// （那仍是 `fs:read` / `fs:write` 的门）。
pub const PERMISSION_FS_PICK: &str = "fs:pick";
pub const PERMISSION_BROADCAST: &str = "broadcast";
/// 定时器：注册宿主周期回调（到点调用插件 command，见 ADR 0003）
pub const PERMISSION_TIMER: &str = "timer:schedule";
/// 进程执行：在桌面端进程内 spawn 外部命令/脚本（host-process，v8）
///
/// 高危能力（执行任意命令），插件 manifest 声明即信任；
/// 每次执行由宿主全量审计日志（命令/参数/cwd/env/结果）
pub const PERMISSION_PROCESS: &str = "process:run";
/// 随包 CLI 生命周期：安装/卸载到用户 bin 目录并注册 PATH（host-app，v8）
///
/// 与 process:run 同信任域（CLI 本质是进程执行入口的封装）；
/// 幂等安装/卸载，仅操作本插件声明的文件与 PATH 条目
pub const PERMISSION_APP_CLI: &str = "app:cli";
/// 用户级 PATH 目录登记（host-app `register-path` / `unregister-path`）
///
/// 与 `app:cli` 分域：`app:cli` 管「插件随包 CLI 装到宿主默认 bin 目录」，
/// 本位管「把某个**已有目录**登记进用户 PATH」——两者写的 PATH 条目来源不同
/// （宿主 bin 目录 vs 插件自持目录，如插件自己下载的运行时）。
///
/// **必须单独立位**：PATH 是**持久化**用户环境面——一条被塞进用户 PATH 的目录
/// 会在之后每个新开的终端/进程里生效，恶意插件借此获得持久化劫持面。
/// 审批文案必须让用户看清「把某个目录加入你的用户 PATH，新开终端生效」。
pub const PERMISSION_APP_PATH: &str = "app:path";
/// 对等网络：发现/信任/拨号/收发/浏览的宿主 peer-net 能力（host-peer）
pub const PERMISSION_PEER: &str = "peer";
/// mDNS 基础能力服务（host-mdns v2）：浏览 + 广播原语，事件按属主定向投递
pub const PERMISSION_MDNS: &str = "mdns";
/// WebSocket 客户端域（host-websocket 出站连接：connect / 收发 / 关闭 / 状态查询）
///
/// 与 `ws:server` 分域：出站连接是 SSRF 面（插件可代宿主访问任意 `ws://` 地址），
/// 入站端点是在局域网新增暴露面——单权限通吃会让「只需出站」的插件被动获得
/// 入站监听能力（spec D6）
pub const PERMISSION_WS_CLIENT: &str = "ws:client";
/// WebSocket 服务端域（host-websocket 入站端点：注册 / 收发 / 广播 / 踢出 / 注销 / 清单）
pub const PERMISSION_WS_SERVER: &str = "ws:server";
/// 密钥托管（host-auth / secret-store，v15）：属主隔离的凭据读写
///
/// 认证中心语义下沉的基础权限——声明即信任宿主代管凭据（JWT 密钥 / 配对种子），
/// 插件间互不可见；密钥明文不落日志、持久化于主库 plugin_secrets 表
pub const PERMISSION_AUTH: &str = "auth";
/// 插件私有伪终端·创建域（host-pty，v16）：`spawn` / `kill`
///
/// 与 `pty:io` 分域：spawn 是「在宿主机器上执行任意命令」的高风险面
/// （与 `process:run` 同信任域），kill 决定进程生死；数据面（读写/尺寸/
/// 游标拉取/存活查询）单独一域，便于「只做输出观测」的插件最小授权
pub const PERMISSION_PTY_SPAWN: &str = "pty:spawn";
/// 插件私有伪终端·数据域（host-pty，v16）：`write` / `resize` / `ring-fetch` / `is-running`
pub const PERMISSION_PTY_IO: &str = "pty:io";
/// 宿主并发任务域（host-task，v20，desktop 独有）：`execute-batch` / `submit` /
/// `status` / `cancel` / `list-jobs`
///
/// 管「占用宿主线程池资源」这件事本身（宿主专用 OS 线程池真并行执行单元操作
/// 计划）。**双门结构**：每个单元另过其 kind 对应的既有域权限门（`fs:read` /
/// `fs:write` / `process:run` / `network:http`），仅授本权限不授域权限的插件所有
/// 单元都会失败——并发能力与数据访问能力解耦授权、解耦审计。
pub const PERMISSION_TASK_RUN: &str = "task:run";
/// 内嵌 worker 调度域（host-worker，worker 机制 / ADR 0059）：`submit` / `cancel`
///
/// 「占用宿主并行资源」的准入门（一线程一 worker、per-plugin 并发 4 / 全局 8），
/// 与 `task:run` 同款判据：并发能力与数据访问能力解耦授权。worker 本体是声明
/// 插件的私属子资源（manifest `workers` 块 + 插件包 `worker/` 目录），经宿主
/// 中介调用、终态经 `events-worker` 回调；submit / cancel 同门。
pub const PERMISSION_WORKER_RUN: &str = "worker:run";
/// 宿主加密引擎·AEAD 域（host-crypto，v26，desktop 独有双端偏离）：加解密 / 密钥 / nonce
pub const PERMISSION_CRYPTO_AEAD: &str = "crypto:aead";
/// 宿主加密引擎·非对称/密钥交换域（host-crypto，v26）：X25519（rsa 按需扩展）
pub const PERMISSION_CRYPTO_ASYM: &str = "crypto:asym";
/// 宿主加密引擎·密钥派生域（host-crypto，v26）：HKDF
pub const PERMISSION_CRYPTO_KDF: &str = "crypto:kdf";
/// 运行监控（WIT `host-metrics.snapshot`）：读取所有已加载插件的运行时指标快照
///
/// **为什么单独立位**：快照可读**全局**插件维度（内存 / 调用量 / 耗时 / trap /
/// 授权决策 / 总线背压），能推断其他应用的活跃度与健康度——这是监控应用的
/// 功能性前提，但也是跨应用信息面。与 `session:read` / `connection:read` 同款
/// 判据：能读到「别人在做什么」的能力必须能被用户单独拒绝。
///
/// 数据面**只含计数与 plugin_id**，不含会话文本 / 文件内容 / 凭据。
pub const PERMISSION_METRICS_READ: &str = "metrics:read";
/// 系统通知与提醒反馈（共享域契约 `host-notify`，ADR 0052 D3）：通知 / 震动 / 声音
/// 是用户打扰面（高频弹通知或狂震会骚扰用户），独立成位、fail-closed。
/// 无前端 API 面（WASM-only 权限，宿主在 host fn 层仲裁）。
///
/// **双端口径**（批 2 自移动 SDK 收口上提，平台仓 issue #36）：移动宿主
/// `plugin/notify.rs` 域函数入口为本位的门禁落点；桌面 host-notify 实现暂无
/// 独立权限门（缺口已记录，随批 2 遗留跟进）。
pub const PERMISSION_NOTIFY: &str = "notify";

/// 权限词汇反射表：`(常量标识符, 权限串)`
///
/// 标识符由 `stringify!` 取自常量本身，与值同源、不可能漂移。有了这一列，宿主测试
/// 就能把「源码里出现的 `PERMISSION_*` 引用」机械还原成权限串，从而断言
/// 「每一条词汇都有真实门禁落点」（平台仓锁 `cross-end-tests/tests/permission_vocabulary_lock.rs`），
/// 而不需要再手抄一份清单。
pub const PERMISSION_VOCABULARY: &[(&str, &str)] = &[
    (
        stringify!(PERMISSION_TERMINAL_INPUT),
        PERMISSION_TERMINAL_INPUT,
    ),
    (
        stringify!(PERMISSION_TERMINAL_OUTPUT),
        PERMISSION_TERMINAL_OUTPUT,
    ),
    (stringify!(PERMISSION_SESSION_READ), PERMISSION_SESSION_READ),
    (
        stringify!(PERMISSION_CONNECTION_READ),
        PERMISSION_CONNECTION_READ,
    ),
    (stringify!(PERMISSION_UI_SIDEBAR), PERMISSION_UI_SIDEBAR),
    (stringify!(PERMISSION_UI_TOOLBOX), PERMISSION_UI_TOOLBOX),
    (stringify!(PERMISSION_UI_STATUSBAR), PERMISSION_UI_STATUSBAR),
    (stringify!(PERMISSION_UI_DIALOG), PERMISSION_UI_DIALOG),
    (
        stringify!(PERMISSION_UI_PAGE_TOOLBAR),
        PERMISSION_UI_PAGE_TOOLBAR,
    ),
    (stringify!(PERMISSION_UI_SETTINGS), PERMISSION_UI_SETTINGS),
    (stringify!(PERMISSION_UI_INPUT), PERMISSION_UI_INPUT),
    (
        stringify!(PERMISSION_UI_FILE_HANDLER),
        PERMISSION_UI_FILE_HANDLER,
    ),
    (stringify!(PERMISSION_NETWORK_HTTP), PERMISSION_NETWORK_HTTP),
    (stringify!(PERMISSION_STORAGE), PERMISSION_STORAGE),
    (stringify!(PERMISSION_FS_READ), PERMISSION_FS_READ),
    (stringify!(PERMISSION_FS_WRITE), PERMISSION_FS_WRITE),
    (stringify!(PERMISSION_FS_PICK), PERMISSION_FS_PICK),
    (stringify!(PERMISSION_BROADCAST), PERMISSION_BROADCAST),
    (stringify!(PERMISSION_TIMER), PERMISSION_TIMER),
    (stringify!(PERMISSION_PROCESS), PERMISSION_PROCESS),
    (stringify!(PERMISSION_APP_CLI), PERMISSION_APP_CLI),
    (stringify!(PERMISSION_APP_PATH), PERMISSION_APP_PATH),
    (stringify!(PERMISSION_PEER), PERMISSION_PEER),
    (stringify!(PERMISSION_MDNS), PERMISSION_MDNS),
    (stringify!(PERMISSION_WS_CLIENT), PERMISSION_WS_CLIENT),
    (stringify!(PERMISSION_WS_SERVER), PERMISSION_WS_SERVER),
    (stringify!(PERMISSION_AUTH), PERMISSION_AUTH),
    (stringify!(PERMISSION_PTY_SPAWN), PERMISSION_PTY_SPAWN),
    (stringify!(PERMISSION_PTY_IO), PERMISSION_PTY_IO),
    (stringify!(PERMISSION_TASK_RUN), PERMISSION_TASK_RUN),
    (stringify!(PERMISSION_WORKER_RUN), PERMISSION_WORKER_RUN),
    (stringify!(PERMISSION_CRYPTO_AEAD), PERMISSION_CRYPTO_AEAD),
    (stringify!(PERMISSION_CRYPTO_ASYM), PERMISSION_CRYPTO_ASYM),
    (stringify!(PERMISSION_CRYPTO_KDF), PERMISSION_CRYPTO_KDF),
    (stringify!(PERMISSION_METRICS_READ), PERMISSION_METRICS_READ),
    (stringify!(PERMISSION_NOTIFY), PERMISSION_NOTIFY),
];

/// 合法权限集合 — 桌面端权限词汇的**唯一真源**（由 [`PERMISSION_VOCABULARY`] 派生）
///
/// 未列入本表的权限在 [`PermissionManager::grant_permissions`] 授权时被静默过滤，
/// 因此 manifest 声明了这里没有的字段等于没声明（票 01 的词汇清零即为此而设）。
/// 新增/拆分权限位只需在反射表加一行，再重跑生成器（见模块头），
/// 否则平台仓词汇漂移锁转红（锁位见模块头）。
const fn valid_permissions() -> [&'static str; PERMISSION_VOCABULARY.len()] {
    let mut out = [""; PERMISSION_VOCABULARY.len()];
    let mut i = 0;
    while i < out.len() {
        out[i] = PERMISSION_VOCABULARY[i].1;
        i += 1;
    }
    out
}

pub static VALID_PERMISSIONS: &[&str] = &valid_permissions();

/// 权限到 API 方法的映射
///
/// 单一消费者共用本表（生成物由打包 CLI 读取；desktop-host-frontend-downsink
/// 2026-10-17 起前端 consumer 随宿主前端退役）：
/// - **`PermissionManager::check_api` 审计名**：`pty.*` / `ws.*` / `peer.*` / `mdns.*`
///   等 WASM-only 方法无前端调用点，登记于此仅作审计与互调面口径，
///   实际门禁在宿主侧各域函数入口的 `check_permission`。
///
/// 表内每个权限都必有一条门禁落点（宿主侧域函数入口 `check_permission`）
/// ——无落点的权限位由平台仓词汇漂移锁拒绝
///（`cross-end-tests/tests/permission_vocabulary_lock.rs`）。
pub static PERMISSION_API_MAP: &[(&str, &[&str])] = &[
    // 票 08：`terminal.sendInput` 随宿主输入通道（`plugin_terminal_send_input`）
    // 注销——插件写自家会话输入走自有命令通道（不受本表管辖）。
    (PERMISSION_TERMINAL_INPUT, &["terminal.onInput"]),
    (PERMISSION_TERMINAL_OUTPUT, &["terminal.onOutput"]),
    (
        PERMISSION_SESSION_READ,
        &[
            // 票 08：`session.list` / `session.get` 随宿主会话数据命令面注销
            // （插件读会话走自有命令通道 `session.list` / `session.get`）。
            // 票 09：`session.onStatusChange` 随内核状态订阅转接通道注销。
            // 本表剩下的全是**宿主窗口事实**（窗口本体 / 字体测量在宿主，
            // spec D3）：预测初始网格 / 打开 / 关闭宿主终端窗口 / 窗口在场查询。
            "session.predictTerminalSize",
            "session.openTerminal",
            "session.closeTerminal",
            "session.isTerminalOpen",
        ],
    ),
    (
        PERMISSION_UI_SIDEBAR,
        &["ui.registerSidebarPanel", "ui.registerPage"],
    ),
    (PERMISSION_UI_TOOLBOX, &["ui.registerToolboxPage"]),
    (
        PERMISSION_UI_STATUSBAR,
        &["ui.registerStatusBarItem", "ui.registerTitleBarItem"],
    ),
    (PERMISSION_UI_DIALOG, &["ui.showDialog"]),
    (PERMISSION_UI_PAGE_TOOLBAR, &["ui.registerPageToolbarItem"]),
    (PERMISSION_UI_SETTINGS, &["ui.registerSettingsSection"]),
    (
        PERMISSION_UI_INPUT,
        &[
            "ui.registerInputExtension",
            "ui.registerTerminalToolbarItem",
        ],
    ),
    (PERMISSION_UI_FILE_HANDLER, &["ui.registerFileHandler"]),
    (PERMISSION_NETWORK_HTTP, &["http.registerEndpoint"]),
    (
        PERMISSION_STORAGE,
        &[
            "storage.get",
            "storage.set",
            "storage.delete",
            "storage.flush",
        ],
    ),
    // 票 08（websocket 业务下沉）：`broadcast.sync` 随 host-events.broadcast-sync
    // 退役（插件事件走 bus/emit）——PERMISSION_BROADCAST 不再映射任何宿主方法。
    // `broadcast` 位保留：前端 events.on/emit 仍经 manifest-gen FRONTEND_PERMISSION_RULES
    // 声明它（apiMap 空清单按 api_map_keys_must_be_known_permissions 约定省略条目）。
    (PERMISSION_FS_READ, &["fs.read", "fs.copy"]),
    (PERMISSION_FS_WRITE, &["fs.write", "fs.copy"]),
    // 系统文件选择器（WASM-only：宿主 `host-platform.pick-*`，无前端调用点）。
    // 与权限位同源命名，前缀 `platform.` 区别于 `fs.*`（后者是 host-fs 域）
    (
        PERMISSION_FS_PICK,
        &[
            "platform.pickFiles",
            "platform.pickFolder",
            "platform.pickFolders",
        ],
    ),
    (PERMISSION_TIMER, &["timer.register"]),
    (PERMISSION_PROCESS, &["process.run", "process.kill"]),
    (PERMISSION_APP_CLI, &["app.cliInstall", "app.cliUninstall"]),
    // 用户级 PATH 目录登记：审批文案必须点明「新开终端生效」（持久化用户环境面）
    (
        PERMISSION_APP_PATH,
        &["app.pathRegister", "app.pathUnregister"],
    ),
    (
        PERMISSION_PEER,
        &[
            "peer.listDevices",
            "peer.dial",
            "peer.disconnect",
            "peer.respondConsent",
            "peer.listTrusted",
            "peer.revokeTrusted",
            "peer.sendFiles",
            "peer.listTransfers",
            "peer.cancelTransfer",
            "peer.retryTransfer",
            "peer.clearTransferHistory",
            "peer.listReceiving",
            "peer.respondTransfer",
            "peer.cancelReceiving",
            "peer.clearReceivingHistory",
            "peer.getReceiveSettings",
            "peer.setReceivePolicy",
            "peer.listSharedDirectories",
            "peer.removeSharedDirectory",
            "peer.addSharedDirectory",
            "peer.listSharedRoots",
            "peer.browseDirectory",
            "peer.pullFiles",
            "peer.pickFiles",
            // ADR 0022 v2 新增原语
            "peer.dialEndpoint",
            "peer.close",
            "peer.setSharedRoots",
        ],
    ),
    (
        PERMISSION_MDNS,
        &[
            "mdns.browse",
            "mdns.stopBrowse",
            "mdns.advertise",
            "mdns.stopAdvertise",
            "mdns.isAdvertising",
        ],
    ),
    (
        PERMISSION_WS_CLIENT,
        &[
            "ws.connect",
            "ws.sendText",
            "ws.sendBinary",
            "ws.close",
            "ws.isConnected",
        ],
    ),
    (
        PERMISSION_WS_SERVER,
        &[
            "ws.registerEndpoint",
            "ws.sendTextToClient",
            "ws.sendBinaryToClient",
            "ws.broadcastText",
            "ws.broadcastBinary",
            "ws.closeClient",
            "ws.unregisterEndpoint",
            "ws.listClients",
            "ws.listEndpoints",
        ],
    ),
    (PERMISSION_PTY_SPAWN, &["pty.spawn", "pty.kill"]),
    (
        PERMISSION_PTY_IO,
        &["pty.write", "pty.resize", "pty.ringFetch", "pty.isRunning"],
    ),
    (
        PERMISSION_CRYPTO_AEAD,
        &[
            "crypto.aeadEncrypt",
            "crypto.aeadDecrypt",
            "crypto.aeadGenerateKey",
            "crypto.aeadGenerateNonce",
        ],
    ),
    (
        PERMISSION_CRYPTO_ASYM,
        &["crypto.keyAgreementGenerate", "crypto.keyAgreementShared"],
    ),
    (PERMISSION_CRYPTO_KDF, &["crypto.kdfDerive"]),
    // 运行监控（WASM-only：宿主 `host-metrics.snapshot`，无前端调用点）。
    // 门禁落点 = `manager/runtime/core_binding.rs` 的 Host impl 首行。
    (PERMISSION_METRICS_READ, &["metrics.snapshot"]),
    // 内嵌 worker 调度（WASM-only：宿主 `host-worker.submit/cancel`，无前端调用点）。
    // 门禁落点 = `manager/runtime/core_binding.rs` 的 Host impl 首行（同 metrics 范式）。
    (PERMISSION_WORKER_RUN, &["worker.submit", "worker.cancel"]),
];

/// 权限管理器
pub struct PermissionManager {
    /// 插件 ID → 已授予的权限集合
    granted: std::sync::RwLock<HashMap<String, HashSet<String>>>,
}

impl PermissionManager {
    pub fn new() -> Self {
        Self {
            granted: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// 为插件授权（从 manifest permissions 字段解析，过滤非法权限）
    ///
    /// 只授予 manifest 声明且在本表内的权限——**没有任何默认授予**（票 02：
    /// 旧形态在此无条件塞进 `storage`，使主库/私有库权限门恒过，
    /// 「manifest 声明即信任」变成了「不声明也有」）。
    /// 词汇表外的声明会被过滤，调用方（宿主激活路径）负责把被过滤项告警出来，
    /// 不允许静默丢弃。
    pub fn grant_permissions(&self, plugin_id: &str, requested: &[String]) -> HashSet<String> {
        let valid_set: HashSet<&str> = VALID_PERMISSIONS.iter().copied().collect();
        let granted: HashSet<String> = requested
            .iter()
            .filter(|p| valid_set.contains(p.as_str()))
            .cloned()
            .collect();

        let mut lock = self.granted.write().unwrap_or_else(|e| e.into_inner());
        lock.insert(plugin_id.to_string(), granted.clone());

        granted
    }

    /// 检查插件是否拥有指定权限
    pub fn check(&self, plugin_id: &str, permission: &str) -> bool {
        let lock = self.granted.read().unwrap_or_else(|e| e.into_inner());
        lock.get(plugin_id)
            .map(|perms| perms.contains(permission))
            .unwrap_or(false)
    }

    /// 检查插件是否拥有调用指定 API 方法的权限
    pub fn check_api(&self, plugin_id: &str, api_method: &str) -> bool {
        let lock = self.granted.read().unwrap_or_else(|e| e.into_inner());
        let perms = match lock.get(plugin_id) {
            Some(p) => p,
            None => return false,
        };

        for (perm, apis) in PERMISSION_API_MAP {
            if apis.iter().any(|a| *a == api_method) {
                return perms.contains(*perm);
            }
        }
        false
    }

    /// 移除插件的权限（停用时调用）
    pub fn revoke_all(&self, plugin_id: &str) {
        let mut lock = self.granted.write().unwrap_or_else(|e| e.into_inner());
        lock.remove(plugin_id);
    }

    /// 获取插件的已授予权限列表
    pub fn get_granted(&self, plugin_id: &str) -> HashSet<String> {
        let lock = self.granted.read().unwrap_or_else(|e| e.into_inner());
        lock.get(plugin_id).cloned().unwrap_or_default()
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 退役权限位（fail-visible 形态③） ====================

/// 已退役权限位（票 2026-10-10 批次 C2；**移动壳**退役表）
///
/// 宿主壳改纯 surface 形态后，`ui.registerToolboxPage` / `ui.registerNavTab` /
/// `ui.registerTerminalToolbarItem` / `ui.registerTerminalView` 四个旧嵌入扩展点
/// 在**移动壳**整面退役，对应的 `ui:toolbox` / `ui:navtab` / `ui:input` 三个权限位
/// 在移动侧随之失效。**桌面壳仍保留 toolbox / input 活面**（桌面 VALID 与 API_MAP
/// 未退役），故本表只由移动装载链消费——桌面 loader 不得接本表。
///
/// 为什么必须显式登记而不是「从 VALID_PERMISSIONS 删掉就算」：权限位不在白名单时
/// `grant_permissions` 会**静默丢弃**——旧插件声明了退役位却照常加载、只是能力
/// 凭空消失，排查时看到的是「功能莫名不好使」而非「这个位已经没了」。
/// 登记在此 + 装载期显式报错（§5.1.3 fail-visible 形态③），断链才可见。
///
/// 批 2 自移动 SDK 收口上提（平台仓 issue #36）：机制归机制层；移动 SDK 侧副本
/// 已删（guest 面本无此 API）。
pub static RETIRED_PERMISSIONS: &[(&str, &str)] = &[
    ("ui:toolbox", "registerToolboxPage"),
    ("ui:navtab", "registerNavTab"),
    (
        "ui:input",
        "registerTerminalToolbarItem / registerTerminalView",
    ),
];

/// 校验清单未声明退役权限位；命中即返回指名错误
///
/// 供宿主装载期调用（移动宿主 `plugin/loader.rs`）。
/// 返回 `Err` 而非 bool：调用方需要把「哪个位、为什么、迁移到哪」原样写进错误，
/// 静默的 bool 只会退化成又一处静默降级。
pub fn check_retired_permissions(plugin_id: &str, permissions: &[String]) -> Result<(), String> {
    for (perm, retired_api) in RETIRED_PERMISSIONS {
        if permissions.iter().any(|p| p == perm) {
            return Err(format!(
                "plugin '{plugin_id}' declares retired permission '{perm}' \
                 (retired extension point: ui.{retired_api}). \
                 The host shell now loads apps only through ui.registerSurface — \
                 replace it with registerSurface, and use registerRoute + openPage for in-app sub-pages."
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod retired_permissions_tests {
    use super::*;

    #[test]
    fn retired_permissions_rejected_at_load() {
        // 票 2026-10-10 C2 fail-visible 形态③：清单声明退役权限位必须装载期报错，
        // 而不是「不在白名单 → grant 静默丢弃 → 功能凭空消失」
        for (perm, _) in RETIRED_PERMISSIONS {
            let err = check_retired_permissions("p", &[perm.to_string()])
                .expect_err("退役权限位应被判退");
            assert!(err.contains(perm), "报错应指名权限位: {err}");
            assert!(err.contains("registerSurface"), "报错应给出迁移出路: {err}");
        }
    }

    #[test]
    fn retired_permissions_allow_clean_manifest() {
        // 反例面：只用存活权限位的清单不得被误伤
        assert!(check_retired_permissions(
            "p",
            &[
                "session:read".to_string(),
                "ui:route".to_string(),
                "storage".to_string()
            ]
        )
        .is_ok());
    }

    #[test]
    fn retired_table_is_mobile_scoped() {
        // 本表是移动壳退役表：toolbox / input 在桌面仍是活词汇（桌面 VALID 含它们），
        // 断言本表成员「桌面侧仍合法」防止有人把本表误当双端退役表接进桌面 loader
        assert!(VALID_PERMISSIONS.contains(&"ui:toolbox"));
        assert!(VALID_PERMISSIONS.contains(&"ui:input"));
        // navtab 是移动专属位（桌面词汇从来没有过）
        assert!(!VALID_PERMISSIONS.contains(&"ui:navtab"));
    }

    #[test]
    fn notify_vocabulary_registered() {
        // 批 2 收口（issue #36）：notify 位进双端真源；门禁落点 = 移动宿主
        // notify.rs（跨端词汇锁扫描面已扩移动宿主源码）
        assert!(VALID_PERMISSIONS.contains(&PERMISSION_NOTIFY));
    }

    #[test]
    fn worker_vocabulary_registered() {
        // worker 机制契约面（issue #10 / ADR 0059）：worker:run 进双端真源，
        // submit / cancel 同门；门禁落点 = `manager/runtime/core_binding.rs`
        // 的 host-worker Host impl 首行（API 映射登记审计名 worker.submit/cancel）
        assert!(VALID_PERMISSIONS.contains(&PERMISSION_WORKER_RUN));
        let entry = PERMISSION_API_MAP
            .iter()
            .find(|(perm, _)| *perm == PERMISSION_WORKER_RUN)
            .expect("worker:run 应在 API 映射表内");
        assert_eq!(entry.1, &["worker.submit", "worker.cancel"][..]);
    }
}
