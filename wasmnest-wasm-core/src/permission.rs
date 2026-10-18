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
/// 宿主加密引擎·AEAD 域（host-crypto，v26，desktop 独有双端偏离）：加解密 / 密钥 / nonce
pub const PERMISSION_CRYPTO_AEAD: &str = "crypto:aead";
/// 宿主加密引擎·非对称/密钥交换域（host-crypto，v26）：X25519（rsa 按需扩展）
pub const PERMISSION_CRYPTO_ASYM: &str = "crypto:asym";
/// 宿主加密引擎·密钥派生域（host-crypto，v26）：HKDF
pub const PERMISSION_CRYPTO_KDF: &str = "crypto:kdf";


/// 权限词汇反射表：`(常量标识符, 权限串)`
///
/// 标识符由 `stringify!` 取自常量本身，与值同源、不可能漂移。有了这一列，宿主测试
/// 就能把「源码里出现的 `PERMISSION_*` 引用」机械还原成权限串，从而断言
/// 「每一条词汇都有真实门禁落点」（平台仓锁 `cross-end-tests/tests/permission_vocabulary_lock.rs`），
/// 而不需要再手抄一份清单。
pub const PERMISSION_VOCABULARY: &[(&str, &str)] = &[
    (stringify!(PERMISSION_TERMINAL_INPUT), PERMISSION_TERMINAL_INPUT),
    (stringify!(PERMISSION_TERMINAL_OUTPUT), PERMISSION_TERMINAL_OUTPUT),
    (stringify!(PERMISSION_SESSION_READ), PERMISSION_SESSION_READ),
    (stringify!(PERMISSION_CONNECTION_READ), PERMISSION_CONNECTION_READ),
    (stringify!(PERMISSION_UI_SIDEBAR), PERMISSION_UI_SIDEBAR),
    (stringify!(PERMISSION_UI_TOOLBOX), PERMISSION_UI_TOOLBOX),
    (stringify!(PERMISSION_UI_STATUSBAR), PERMISSION_UI_STATUSBAR),
    (stringify!(PERMISSION_UI_DIALOG), PERMISSION_UI_DIALOG),
    (stringify!(PERMISSION_UI_PAGE_TOOLBAR), PERMISSION_UI_PAGE_TOOLBAR),
    (stringify!(PERMISSION_UI_SETTINGS), PERMISSION_UI_SETTINGS),
    (stringify!(PERMISSION_UI_INPUT), PERMISSION_UI_INPUT),
    (stringify!(PERMISSION_UI_FILE_HANDLER), PERMISSION_UI_FILE_HANDLER),
    (stringify!(PERMISSION_NETWORK_HTTP), PERMISSION_NETWORK_HTTP),
    (stringify!(PERMISSION_STORAGE), PERMISSION_STORAGE),
    (stringify!(PERMISSION_FS_READ), PERMISSION_FS_READ),
    (stringify!(PERMISSION_FS_WRITE), PERMISSION_FS_WRITE),
    (stringify!(PERMISSION_FS_PICK), PERMISSION_FS_PICK),
    (stringify!(PERMISSION_BROADCAST), PERMISSION_BROADCAST),
    (stringify!(PERMISSION_TIMER), PERMISSION_TIMER),
    (stringify!(PERMISSION_PROCESS), PERMISSION_PROCESS),
    (stringify!(PERMISSION_APP_CLI), PERMISSION_APP_CLI),
    (stringify!(PERMISSION_PEER), PERMISSION_PEER),
    (stringify!(PERMISSION_MDNS), PERMISSION_MDNS),
    (stringify!(PERMISSION_WS_CLIENT), PERMISSION_WS_CLIENT),
    (stringify!(PERMISSION_WS_SERVER), PERMISSION_WS_SERVER),
    (stringify!(PERMISSION_AUTH), PERMISSION_AUTH),
    (stringify!(PERMISSION_PTY_SPAWN), PERMISSION_PTY_SPAWN),
    (stringify!(PERMISSION_PTY_IO), PERMISSION_PTY_IO),
    (stringify!(PERMISSION_TASK_RUN), PERMISSION_TASK_RUN),
    (stringify!(PERMISSION_CRYPTO_AEAD), PERMISSION_CRYPTO_AEAD),
    (stringify!(PERMISSION_CRYPTO_ASYM), PERMISSION_CRYPTO_ASYM),
    (stringify!(PERMISSION_CRYPTO_KDF), PERMISSION_CRYPTO_KDF),
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
    (PERMISSION_UI_SIDEBAR, &["ui.registerSidebarPanel", "ui.registerPage"]),
    (PERMISSION_UI_TOOLBOX, &["ui.registerToolboxPage"]),
    (PERMISSION_UI_STATUSBAR, &["ui.registerStatusBarItem", "ui.registerTitleBarItem"]),
    (PERMISSION_UI_DIALOG, &["ui.showDialog"]),
    (PERMISSION_UI_PAGE_TOOLBAR, &["ui.registerPageToolbarItem"]),
    (PERMISSION_UI_SETTINGS, &["ui.registerSettingsSection"]),
    (PERMISSION_UI_INPUT, &["ui.registerInputExtension", "ui.registerTerminalToolbarItem"]),
    (PERMISSION_UI_FILE_HANDLER, &["ui.registerFileHandler"]),
    (PERMISSION_NETWORK_HTTP, &["http.registerEndpoint"]),
    (PERMISSION_STORAGE, &["storage.get", "storage.set", "storage.delete", "storage.flush"]),
    // 票 08（websocket 业务下沉）：`broadcast.sync` 随 host-events.broadcast-sync
    // 退役（插件事件走 bus/emit）——PERMISSION_BROADCAST 不再映射任何宿主方法。
    // `broadcast` 位保留：前端 events.on/emit 仍经 manifest-gen FRONTEND_PERMISSION_RULES
    // 声明它（apiMap 空清单按 api_map_keys_must_be_known_permissions 约定省略条目）。
    (PERMISSION_FS_READ, &["fs.read", "fs.copy"]),
    (PERMISSION_FS_WRITE, &["fs.write", "fs.copy"]),
    // 系统文件选择器（WASM-only：宿主 `host-platform.pick-*`，无前端调用点）。
    // 与权限位同源命名，前缀 `platform.` 区别于 `fs.*`（后者是 host-fs 域）
    (PERMISSION_FS_PICK, &["platform.pickFiles", "platform.pickFolder", "platform.pickFolders"]),
    (PERMISSION_TIMER, &["timer.register"]),
    (PERMISSION_PROCESS, &["process.run", "process.kill"]),
    (PERMISSION_APP_CLI, &["app.cliInstall", "app.cliUninstall"]),
    (PERMISSION_PEER, &[
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
    ]),
    (PERMISSION_MDNS, &[
        "mdns.browse",
        "mdns.stopBrowse",
        "mdns.advertise",
        "mdns.stopAdvertise",
        "mdns.isAdvertising",
    ]),
    (PERMISSION_WS_CLIENT, &[
        "ws.connect",
        "ws.sendText",
        "ws.sendBinary",
        "ws.close",
        "ws.isConnected",
    ]),
    (PERMISSION_WS_SERVER, &[
        "ws.registerEndpoint",
        "ws.sendTextToClient",
        "ws.sendBinaryToClient",
        "ws.broadcastText",
        "ws.broadcastBinary",
        "ws.closeClient",
        "ws.unregisterEndpoint",
        "ws.listClients",
        "ws.listEndpoints",
    ]),
    (PERMISSION_PTY_SPAWN, &["pty.spawn", "pty.kill"]),
    (PERMISSION_PTY_IO, &["pty.write", "pty.resize", "pty.ringFetch", "pty.isRunning"]),
    (PERMISSION_CRYPTO_AEAD, &["crypto.aeadEncrypt", "crypto.aeadDecrypt", "crypto.aeadGenerateKey", "crypto.aeadGenerateNonce"]),
    (PERMISSION_CRYPTO_ASYM, &["crypto.keyAgreementGenerate", "crypto.keyAgreementShared"]),
    (PERMISSION_CRYPTO_KDF, &["crypto.kdfDerive"]),
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
        lock.get(plugin_id)
            .cloned()
            .unwrap_or_default()
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}
