//! Core 机制绑定层：**双端唯一一份**（票 03 Option A 裁决；ADR 0052 D1 收窄为机制面）
//!
//! ## 这份是什么
//!
//! `bindgen!` 直接绑定 **契约真源** `wit/core.wit` 的 `world core`——内核机制能力面
//! （10 import + 3 必选导出；业务能力交集住各能力域 crate 的 `wit/<domain>.wit`，
//! 由双端 compose.json 的 caps 直接消费）。各端**组合面**（`cap-pty` / `cap-mdns` /
//! `cap-peer` / `cap-http` / `cap-ws` / `cap-http-endpoint` / `cap-ws-server` /
//! `cap-desktop` / `cap-mobile`）不在这里绑定：由各端宿主自有 `bindgen!` +
//! `HostModule` 自报汇入同一个 `Linker`（机制见 [`add_to_linker`] 第二段与 host-kit
//! 的 `registry` / `assembly`）。
//!
//! 绑定真源而非端生成物（`wasmnest-*/packages/plugin-sdk-*/rust/wit`）是「零 cap 痕迹」的
//! 关键：生成物目录是 `compose.json` 的产物、随各端 cap 组合增删，经它绑定等于把
//! 「组合了什么」这个端差异搬进内核。
//!
//! ## 为什么交集绑定留内核而不整体上移（裁决依据）
//!
//! 本模块承载的 8 个 interface 实现体是**对共享机制 `host_api::*` 的薄转发**，两端
//! 逐字同构（桌面直调、移动经宿主侧 `host_domains/` 同形转发到同一处）。整体上移
//! 宿主会在两个宿主各写一份，重新制造差异代码——正撞「wasm-core 就应该是统一的，
//! 不应该有差异代码」的裁决。
//! 与之相对，cap 域本就按端形状不同（`events` 导出双端各自定义，不在 core.wit 内），
//! 上移无重复成本。
//!
//! ## 导出面分工（`world core` 只导出 command / lifecycle / manifest）
//!
//! | 导出 | 归属 | 机制 |
//! | --- | --- | --- |
//! | `command.invoke` / `lifecycle.*` / `manifest.get` | 本模块（core 绑定的类型化 Guest） | 业务导出调用面 |
//! | `abi.version` | 内核 | `abi` 是 core interface 但不在 `world core` 导出表内 ⇒ 走原生 `TypedFunc` 探测，零绑定零 cap |
//! | `events.*` / `abi-form` | 各端宿主自有绑定 | cap 导出 |
//!
//! 可选导出一律实例化后用原生 `TypedFunc` 探测，不经绑定（见 `WasmPluginState`
//! 的可选导出字段）：`events-binary` / `events-ws` / `events-task` 已接线；
//! `events-worker` 的契约面在本票就位，探测随 worker 运行时端到端票接线。

use crate::host_api::check_permission;
use crate::host_api::context::HostCtxOf;
use crate::host_api::{bus, config, database, events, fs, log, platform, sqlite, status, storage};
use crate::permission::{PERMISSION_METRICS_READ, PERMISSION_WORKER_RUN};
use crate::AppError;
use wasmnest_host_kit::WasmPluginState;
use wasmtime::component::{bindgen, Linker};

bindgen!({
    // 契约真源（票 03 Option A）：`wit/core.wit` 自包含（无 `use`、全部 interface 内联
    // 定义），可直接单文件 bindgen，不经端生成物目录——生成物随各端 compose.json 增删
    // cap 分片，经它绑定会把端差异引进内核。路径基准是 `CARGO_MANIFEST_DIR`（crate 根）。
    path: "wit/core.wit",
    world: "core",
    // 单份 async（用户 2026-10-11 裁决）：wasip3 组件实例化后 Store 为 async-required，
    // 同步 call 报 "store configuration requires that `*_async` functions are used"。
    // 统一 async 化让 wasip3 / wasip2 / unknown-unknown 插件走同一条调用路径——同步组件
    // 在 async 路径下行为等价（`engine::InstantiateMode::Async` 的同一实证）。
    exports: { default: async },
});

// ==================== Host trait 实现（import 接口） ====================
//
// 每个接口对应 `host_api/` 中一个功能域的逻辑层函数，实现体全部是薄转发；
// WIT `result<T, string>` → `Result<T, String>`，错误内容为宿主侧可读消息，
// 跨 wasm 边界后由调用方转为 AppError。
//
// 已迁宿主 / 迁能力域（不在本文件，见各段注释）：host-auth / host-crypto /
// host-process / host-app / host-timer / host-connection-registry / host-task /
// host-api-call（桌面 `src-tauri/src/plugin/` 路径 B 域）；host-notify（共享域契约
// `wasmnest-notify-engine/wit/notify.wit`，实现按端住宿主 `plugin/notify.rs`）；
// host-pty / host-http-endpoint / host-websocket-server（能力域 crate 的端扩展面，
// T-03 起迁桌面宿主）；host-peer / host-mdns / host-http / host-websocket（双端功能级
// 交集，契约真源已随 ADR 0052 D2 迁各能力域 crate 的 `wit/<domain>.wit`，由 caps
// 组合——不再在 core.wit）。

// ==================== host-storage ====================

impl wasmnest::plugin::host_storage::Host for WasmPluginState {
    fn get(&mut self, key: String) -> Result<Option<String>, String> {
        storage::storage_get(&sqlite::ports_for(self.host_ctx()), &self.plugin_id, &key)
            .map(|opt| opt.map(|v| v.to_string()))
    }

    fn set(&mut self, key: String, value: String) -> Result<(), String> {
        let json_value: serde_json::Value =
            serde_json::from_str(&value).map_err(|e| format!("invalid JSON value: {}", e))?;
        storage::storage_set(
            &sqlite::ports_for(self.host_ctx()),
            &self.plugin_id,
            &key,
            json_value,
        )
    }

    fn delete(&mut self, key: String) -> Result<(), String> {
        storage::storage_delete(&sqlite::ports_for(self.host_ctx()), &self.plugin_id, &key)
    }
}

// ==================== host-plugin-database ====================
// ADR 0036：`host-database` / `host-plugin-database` / `host-storage` 三 interface 的
// 机制实现留在 `host_api::{database, sqlite}`，故 `Host` impl 在本文件。期间它们被搬进
// `wasmnest-sqlite-engine`（provider 侧自生成同名 trait，两侧同时注册会让 linker 报
// `defined twice`），随 crate 撤销一并归位。
//
// 端口按**本次调用**的上下文现取（`sqlite::ports_for`），无进程级单例、无实例级登记、
// 无强制链接行——见 `host_api::sqlite_ports` 模块文档。

impl wasmnest::plugin::host_plugin_database::Host for WasmPluginState {
    fn execute(&mut self, sql: String) -> Result<u32, String> {
        database::plugin_db_execute(&sqlite::ports_for(self.host_ctx()), &self.plugin_id, &sql)
    }

    fn query(&mut self, sql: String) -> Result<Option<String>, String> {
        database::plugin_db_query(&sqlite::ports_for(self.host_ctx()), &self.plugin_id, &sql)
    }

    fn execute_params(&mut self, sql: String, params_json: String) -> Result<u32, String> {
        database::plugin_db_execute_params(
            &sqlite::ports_for(self.host_ctx()),
            &self.plugin_id,
            &sql,
            &params_json,
        )
    }

    fn query_params(&mut self, sql: String, params_json: String) -> Result<Option<String>, String> {
        database::plugin_db_query_params(
            &sqlite::ports_for(self.host_ctx()),
            &self.plugin_id,
            &sql,
            &params_json,
        )
    }

    fn execute_batch(&mut self, sqls_json: String) -> Result<u32, String> {
        database::plugin_db_execute_batch(
            &sqlite::ports_for(self.host_ctx()),
            &self.plugin_id,
            &sqls_json,
        )
    }
}

// ==================== host-log ====================

impl wasmnest::plugin::host_log::Host for WasmPluginState {
    fn info(&mut self, message: String) {
        log::log_info(&self.plugin_id, &message, "", 0);
    }

    fn debug(&mut self, message: String) {
        log::log_debug(&self.plugin_id, &message, "", 0);
    }

    fn warn(&mut self, message: String) {
        log::log_warn(&self.plugin_id, &message, "", 0);
    }

    fn error(&mut self, message: String) {
        log::log_error(&self.plugin_id, &message, "", 0);
    }

    fn mark_plugin_error(&mut self, error: String) {
        status::mark_plugin_error(self.host_ctx(), self.plugin_id.clone(), error);
    }
}

// ==================== host-config ====================

impl wasmnest::plugin::host_config::Host for WasmPluginState {
    fn get(&mut self, key: String) -> Result<Option<String>, String> {
        // 端专属键经宿主注入的端口取（network.port → 端事实端口；下载目录 →
        // 引擎端口），本端无对应物 / 未注入时域内 fail-visible（白名单词汇是
        // 双端并集，见 `host_api::config`）
        let facts = self.host_ctx().host_facts();
        config::config_get(
            self.host_ctx(),
            self.host_ctx().ports().as_ref(),
            facts.as_ref(),
            &self.plugin_id,
            &key,
        )
    }
}

// ==================== host-metrics ====================
//
// 只读快照出口：权限门在**调用点首行**（词汇漂移锁按 `PERMISSION_*` 引用还原
// 门禁落点）；快照源由装配面注入（`WasmHostContext::set_metrics_snapshot_source`），
// 内核绑定层不认识注册表持有者。未装配 → `Err`（fail-visible，不返回空对象）。

impl wasmnest::plugin::host_metrics::Host for WasmPluginState {
    fn snapshot(&mut self) -> Result<String, String> {
        if !check_permission(
            self.host_ctx(),
            &self.plugin_id,
            PERMISSION_METRICS_READ,
            "metrics.snapshot",
        ) {
            return Err(format!(
                "permission denied: {} (declare it in plugin.json permissions)",
                PERMISSION_METRICS_READ
            ));
        }
        self.host_ctx().metrics_snapshot().snapshot_json()
    }
}

// ==================== host-worker ====================
//
// worker 调度契约面（ADR 0059；spec `.scratch/2026-10-28-worker-mechanism/`）。
// 机制本体（调度器 / worker 实例化 / 终态事件投递）随 worker 运行时端到端票
// （issue #11）落地——契约面票（issue #10）先落**权限门 + fail-visible 桩**：
// manifest 已可声明 `workers` 块与 `worker:run` 权限，submit / cancel 走到的是
// 显性 `Err` 而非静默无操作。权限门在**调用点首行**（词汇漂移锁按 `PERMISSION_*`
// 引用还原门禁落点，与 host-metrics 同范式）；submit / cancel 同门
// （`worker:run`，WIT 头注的准入门判据）。

impl wasmnest::plugin::host_worker::Host for WasmPluginState {
    fn submit(&mut self, worker: String, input: String) -> Result<String, String> {
        if !check_permission(
            self.host_ctx(),
            &self.plugin_id,
            PERMISSION_WORKER_RUN,
            "worker.submit",
        ) {
            return Err(format!(
                "permission denied: {} (declare it in plugin.json permissions)",
                PERMISSION_WORKER_RUN
            ));
        }
        let _ = (worker, input);
        Err(
            "host-worker 尚未接线：worker 调度器随 worker 运行时端到端票落地（当前仅契约面）"
                .to_string(),
        )
    }

    fn cancel(&mut self, job_id: String) -> Result<(), String> {
        if !check_permission(
            self.host_ctx(),
            &self.plugin_id,
            PERMISSION_WORKER_RUN,
            "worker.cancel",
        ) {
            return Err(format!(
                "permission denied: {} (declare it in plugin.json permissions)",
                PERMISSION_WORKER_RUN
            ));
        }
        let _ = job_id;
        Err(
            "host-worker 尚未接线：worker 调度器随 worker 运行时端到端票落地（当前仅契约面）"
                .to_string(),
        )
    }
}

// ==================== host-events ====================

impl wasmnest::plugin::host_events::Host for WasmPluginState {
    // WIT 中 emit 无错误返回，宿主侧记录日志
    fn emit(&mut self, event_name: String, payload_json: String) {
        if let Err(e) = events::emit_event(self.host_ctx(), &event_name, &payload_json) {
            tracing::error!(error = %e, event = %event_name, "host_events.emit failed");
        }
    }
}

// 2026-10-13 功能级统一（ADR 0052 D3）：`notify` 本体迁共享域契约
// `wasmnest-notify-engine/wit/notify.wit`（双端 caps 消费），桌面
// `host-events-desktop` 整 interface 退役；实现按端住宿主
// （桌面 / 移动各自 `src-tauri/src/plugin/notify.rs`），内核不再持有通知实现。

// ==================== host-fs ====================

impl wasmnest::plugin::host_fs::Host for WasmPluginState {
    fn read(&mut self, path: String) -> Result<Option<String>, String> {
        fs::fs_read(self.host_ctx(), &self.plugin_id, &path)
    }

    fn write(&mut self, path: String, data: String) -> Result<(), String> {
        fs::fs_write(self.host_ctx(), &self.plugin_id, &path, &data)
    }

    fn copy(&mut self, src: String, dst: String) -> Result<(), String> {
        fs::fs_copy(self.host_ctx(), &self.plugin_id, &src, &dst)
    }

    fn delete(&mut self, path: String) -> Result<(), String> {
        fs::fs_delete(self.host_ctx(), &self.plugin_id, &path)
    }

    fn exists(&mut self, path: String) -> Result<bool, String> {
        fs::fs_exists(self.host_ctx(), &self.plugin_id, &path)
    }

    fn request_auth(&mut self, paths_json: String) -> Result<bool, String> {
        fs::fs_request_auth(
            self.host_ctx(),
            self.host_ctx(),
            &self.plugin_id,
            &paths_json,
        )
    }
}

// v36：`host-fs.read-dir / canonicalize / stat` 拆入 `host-fs-desktop`（桌面独有交集
// 切片，文件浏览域），WIT impl 在桌面宿主 `src-tauri/src/plugin/fs.rs`。

// ==================== host-bus ====================

impl wasmnest::plugin::host_bus::Host for WasmPluginState {
    fn publish(&mut self, topic: String, payload_json: String) -> Result<(), String> {
        bus::bus_publish(
            self.host_ctx(),
            self.host_ctx(),
            &self.plugin_id,
            &topic,
            &payload_json,
        )
    }

    /// v11：二进制载荷发布（零 JSON 编解码，可传非 UTF-8 与大载荷）
    fn publish_binary(&mut self, topic: String, payload: Vec<u8>) -> Result<(), String> {
        bus::bus_publish_binary(
            self.host_ctx(),
            self.host_ctx(),
            &self.plugin_id,
            &topic,
            payload,
        )
    }

    fn subscribe(&mut self, topic: String) -> Result<(), String> {
        bus::bus_subscribe(self.host_ctx(), &self.plugin_id, &topic)
    }

    /// v11：以二进制格式偏好订阅（只接收 publish-binary 投递）
    fn subscribe_binary(&mut self, topic: String) -> Result<(), String> {
        bus::bus_subscribe_binary(self.host_ctx(), &self.plugin_id, &topic)
    }

    fn unsubscribe(&mut self, topic: String) -> Result<(), String> {
        bus::bus_unsubscribe(self.host_ctx(), &self.plugin_id, &topic)
    }
}

// host-api-call（互调，ADR-0017）的 **WIT impl** 在桌面宿主
// `src-tauri/src/plugin/api_call.rs` 路径 B 薄转发：无权限门，互调门禁在注册表。
// 回复道编排（`api_call` + `ReplyHandler` + 属主校验）留内核 `host_api/api.rs`。

// ==================== host-platform（ADR 0022 v2）====================
//
// host-peer / host-mdns / host-websocket / host-http 已随 ADR 0052 D2 移出 core.wit
// （契约真源在各能力域 crate 的 `wit/<domain>.wit`，由双端 caps 组合；实现按端不同
// ——桌面在宿主 adapter、移动在移动宿主），故本文件不实现它们——core 绑定层只覆盖
// 内核自己实现、双端同源的那 8 个机制 interface。

impl wasmnest::plugin::host_platform::Host for WasmPluginState {
    // `pick-*` 需两件 scope：权限门（`fs:pick`）+ fs_auth（选择结果授权校验）。
    // 选择器本体不在内核：经宿主装配的 `PlatformPickerPort` 注入（桌面原生对话框
    // / 移动 SAF，端差异实现住各端宿主，ADR 0052 D1；见 `host_api::ports`）。
    fn pick_files(&mut self) -> Result<String, String> {
        let picker = self.host_ctx().platform_picker();
        platform::platform_pick_files(
            self.host_ctx(),
            self.host_ctx(),
            picker.as_ref(),
            &self.plugin_id,
        )
    }

    /// `pick-folders`（2026-10-13 功能级统一，ADR 0052 D3：原
    /// `pick-folder` 单值形与桌面扩展多选形合并）：返回 string[] JSON，
    /// 空数组 = 用户取消 / 未选任何目录。
    fn pick_folders(&mut self) -> Result<String, String> {
        let picker = self.host_ctx().platform_picker();
        platform::platform_pick_folders(
            self.host_ctx(),
            self.host_ctx(),
            picker.as_ref(),
            &self.plugin_id,
        )
    }

    /// 宿主平台标识（v38；无权限门——平台事实不是能力）
    ///
    /// 双端共享产物（file-transfer 单产物）经此在同一 trait 的双实现间分支；
    /// 端值由各端宿主实现 [`crate::host_api::ports::HostFactsPort`] 并在装配期注入
    /// （内核零端名、零端分支；未注入取到契约外取值 `"unknown"`，guest 显性拒绝）。
    /// WIT 签名无 result 包装 ⇒ 不可失败（端值是宿主注入的常量事实）。
    fn platform(&mut self) -> String {
        let facts = self.host_ctx().host_facts();
        platform::platform_id(facts.as_ref())
    }
}

// 2026-10-13 功能级统一（ADR 0052 D3）：桌面扩展 `host-platform-desktop.pick-folders`
// 已并入 core `host-platform.pick-folders`（本文件上方 impl），桌面扩展只剩
// wsl-distros / local-ipv4-addresses / reveal-in-dir 三函数，WIT impl 在桌面宿主
// `src-tauri/src/plugin/platform.rs`。

// ==================== 导出调用面（world core 的 3 个导出） ====================

/// core 交集导出绑定类型（`world core` 的 `bindgen!` 生成物）
pub(crate) type CoreExports = Core;

/// core 交集导出绑定（`world core` 的类型化包装）
///
/// 覆盖 `command.invoke` / `lifecycle.*` / `manifest.get` —— 业务导出调用面全部
/// 在此，双端一份。**cap 导出不在此**：`events`（双端各自定义）与 `abi-form`
/// （桌面独有）由各端宿主自有绑定调用。
pub(crate) fn exports(
    store: &mut wasmtime::Store<WasmPluginState>,
    instance: &wasmtime::component::Instance,
) -> crate::Result<Core> {
    Core::new(&mut *store, instance)
        .map_err(|e| AppError::Plugin(format!("WASM component exports access failed: {}", e)))
}

/// ABI 形态探测（`wasmnest:plugin@<version>/abi-form.form` → `u32`，桌面独有 cap 导出）
///
/// 原生探测（无绑定的 `TypedFunc` 直取，`abi-form` 不在 `world core` 表内）：`() -> u32` **无 `result` 返回**，因此能
/// 用 `TypedFunc` 表达（带 `result` 的导出如 `events.*` 不能，见 ticket-03 §9.6）。
/// 语义上 `form` 只判「component 形态 vs core 形态」这一跨端一致的事实，具体
/// 期望值是端策略（桌面 `FORM_COMPONENT = 1`），由调用方比对。
pub(crate) fn abi_form(
    store: &mut wasmtime::Store<WasmPluginState>,
    instance: &wasmtime::component::Instance,
) -> crate::Result<Option<u32>> {
    let Some(item) = crate::contract::export_item("abi-form", "form")
        .parse::<wasmtime::component::wit_parser::ItemName>()
        .ok()
    else {
        return Ok(None);
    };
    let func = match instance.get_typed_func::<(), (u32,)>(&mut *store, &item) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    crate::runtime_util::block_on_async(func.call_async(&mut *store, ()))
        .map(|(form,)| Some(form))
        .map_err(|e| AppError::Plugin(format!("Failed to call abi-form.form(): {}", e)))
}

// ==================== Linker 装配（交集段） ====================

/// 把 core 交集 interface 注册到 component linker（双端唯一一份）
///
/// 与宿主 / 能力域自报的 cap interface **合流到同一个 `Linker`**：`Linker` 按
/// interface 全名（`wasmnest:plugin@<version>/host-*`，版本化契约下为含版本全名）索引，
/// 重名注册才报 `defined twice`。
/// core 8 与各端 cap 域天然不重叠，故两端宿主只需照常自报自己的域，本函数不必知道
/// 它们的存在。
///
/// 每接口一个 `add_to_linker`（`HasSelf<T>` 让 getter 返回 `&mut T`）。
///
/// **不在 linker 中注册对端能力无副作用**：linker 中无对应 import 的注册是惰性的，
/// 所以按交集注册不会让「只导入子集」的插件失败，反之少注册才会报缺失。
pub(crate) fn add_to_linker(linker: &mut Linker<WasmPluginState>) -> crate::Result<()> {
    type D = wasmtime::component::HasSelf<WasmPluginState>;
    for iface in [
        wasmnest::plugin::host_storage::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_log::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_config::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_plugin_database::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_events::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_fs::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_bus::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_platform::add_to_linker::<WasmPluginState, D>,
        wasmnest::plugin::host_metrics::add_to_linker::<WasmPluginState, D>,
    ] {
        iface(linker, |s| s).map_err(|e| {
            AppError::Plugin(format!(
                "Failed to register component host interface: {}",
                e
            ))
        })?;
    }
    Ok(())
}
