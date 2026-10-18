//! host-pty 能力域的宿主端口（边界层）
//!
//! ## 设计依据（`wasmnest-server-base::ports` 先例；http / ws / peer-net / mdns 四域同款）
//!
//! 消费方（本 crate）声明端口，宿主实现。本 crate **不依赖 tauri、不依赖宿主 bin
//! crate**，故出站域机制（PTY 注册表 / 配额仲裁 / 句柄属主校验 / 退出事件组装 /
//! 限频通知裁决）自持，只把「宿主才有的五件事」经端口要过来。
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | [`PtyPorts::check_permission`] | 权限门（`pty:spawn` / `pty:io`）是**宿主安全闸门**（AGENTS §5.1.3 四类薄壳之二），不该可插拔 ⇒ 留宿主，本域只问结果（拒绝文案与 warn 落宿主侧） |
//! | [`PtyPorts::publish`] | 消息总线投递面在宿主（`<owner>::pty:exit` / `<owner>::pty:output` 的命名空间门禁与有界队列是总线裁决）；topic 拼装留本域（纯字符串逻辑） |
//! | [`PtyPorts::config`] | 宿主配置真源（终端默认列行 / 读缓冲 / 生命周期广播容量）在本域之外，本域只收快照 |
//! | [`PtyPorts::block_on_any`] | 同步↔异步桥：guest 侧 host function 是同步的，而引擎面是 async。**桥的实现在宿主**（含 wasmtime-wasi ambient runtime 与 actix `current_thread` 自锁规避），本域不复制第二份 |
//! | [`PtyPorts::spawn_task`] | 退出监听必须派生到宿主 runtime（调用线程可能无 reactor handle，直接 `tokio::spawn` 会 panic 并污染 wasmtime Store） |
//!
//! ## 为什么 [`PtyPorts::check_permission`] 返回 bool 而不是 Result
//!
//! 与 `HttpPorts` 同款：**拒绝文案与 warn 落宿主侧**（宿主才认得 PermissionManager 与
//! 结构化日志字段），本域只把 `false` 翻译成本域既有的 `permission denied: …` 串。
//! 拿不到权限管理器时（无头 / 测试）宿主实现**必须返回 false**（fail-safe）。
//!
//! ## 为什么 [`PtyPorts::publish`] 不带 sender
//!
//! 本域两处发布都是 `sender = "host"`（机制常量，非本域可解释的语义）。与
//! `DiscoveryPorts::publish` 同款形状：sender 由宿主实现固定，域只给 topic 与载荷。
//!
//! ## 为什么本域函数收 `&Arc<dyn PtyPorts>` 而不是 `&dyn PtyPorts`
//!
//! 与 http / mdns 域同款：退出监听任务与限频通知装饰器要活过本次调用，需要一份
//! `'static` 端口引用（域自持后台任务，见 [`crate::plugin_binding::registry`]）。

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::PtyEngineConfig;

/// 类型擦除的「同步驱动异步」入参（[`PtyPorts::block_on_any`]）
///
/// **为什么不要求 `'static`**：宿主那份桥（`runtime_util::block_on_async`）的契约是
/// `F: Future + Send`（无 `'static`），它的 current_thread / 重入分支靠
/// `std::thread::scope` 驱动非 `'static` future。域里的 `session.start()` /
/// `session.write(data)` 等 future **借用会话句柄**，若在端口层强加 `'static` 就得
/// 先 clone 句柄再自造生命周期——那是把宿主的既���契约改窄，故此处逐字对齐。
pub type BoxedBlocked<'a> = Pin<Box<dyn Future<Output = Box<dyn Any + Send>> + Send + 'a>>;

/// 后台任务（[`PtyPorts::spawn_task`]）
pub type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// 宿主配置快照（本域唯二需要的配置面：终端默认值 + 引擎两个行为参数）
///
/// 引擎侧的 [`PtyEngineConfig`] 直接复用而非另立字段——同一组数值在
/// `PtySession::with_private_command` 的参数位与「插件未声明时的默认行列」都用到，
/// 宿主从同一份 `AppConfig` 取一次即可（`terminal.read_buffer_size` /
/// `channels.lifecycle_capacity`）。
#[derive(Debug, Clone, Copy)]
pub struct PtyHostConfig {
    /// 插件未声明 `cols` 时的默认列数（宿主终端配置）
    pub default_cols: u16,
    /// 插件未声明 `rows` 时的默认行数（宿主终端配置）
    pub default_rows: u16,
    /// 引擎行为参数（生命周期广播容量 / 读缓冲大小）
    pub engine: PtyEngineConfig,
}

/// 宿主能力端口
///
/// 实现方是各端宿主的适配器（桌面端见 `桌面宿主 src-tauri/src/plugin/pty.rs`
/// 的 `HostPtyPorts`；票 02 批次 02 从 wasm-core `host_api/pty.rs` 整文件迁入）。
pub trait PtyPorts: Send + Sync + 'static {
    /// 权限判定（`pty:spawn` / `pty:io`）
    ///
    /// 返回 `false` 时**宿主侧**必须已按 AGENTS §8 落 `warn`（结构化字段
    /// `plugin_id` / `permission` / `api`）；本域不重复落日志。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 向**已拼好的完整 topic** 投递一个载荷
    ///
    /// topic 由本域用 SDK 的 `owned_topic(owner, event)` 拼好（含 `<owner>::`
    /// 前缀与命名空间仲裁所需的 owner）——纯字符串逻辑留能力域侧；宿主负责
    /// 「往这个 topic 上发」并做订阅方隔离与背压。
    fn publish(&self, topic: &str, payload: serde_json::Value);

    /// 宿主配置快照（每次 spawn 现取，不缓存——宿主配置可运行期变更）
    fn config(&self) -> PtyHostConfig;

    /// 在宿主运行时上**同步驱动**一段异步计算（guest host function 是同步的）
    ///
    /// 实现即宿主那份唯一的同步↔异步桥。**必须复用宿主那份实现**，不得在本域复制
    /// 第二份桥（重入自锁与 ambient runtime 语义是实测产物）。
    fn block_on_any<'a>(&self, fut: BoxedBlocked<'a>) -> Box<dyn Any + Send>;

    /// 在宿主 runtime 上派生一条后台任务（带错误边界的 spawn）
    ///
    /// 宿主调用栈不保证处于 tokio runtime 上下文（wasmtime async store 的 fiber 内
    /// 直接 `tokio::spawn` 会 panic 并污染 Store），故任务派生必须经宿主。
    fn spawn_task(&self, name: &'static str, task: BoxedTask);
}

// ==================== 泛型助手 ====================

/// 强类型版同步驱动（端口方法的包装：擦除入参 → 驱动 → 还原类型）
///
/// 类型不符是**装配期编程错误**（调用方传错了 future 的输出类型），直接 panic
/// 点名，不静默返回 `None` 之类的假值。
pub fn block_on<'a, T: Send + 'static>(
    ports: &'a Arc<dyn PtyPorts>,
    fut: impl Future<Output = T> + Send + 'a,
) -> T {
    let erased: BoxedBlocked<'a> =
        Box::pin(async move { Box::new(fut.await) as Box<dyn Any + Send> });
    match ports.block_on_any(erased).downcast::<T>() {
        Ok(value) => *value,
        Err(_) => panic!(
            "pty ports block_on_any returned an unexpected result type (expected {})",
            std::any::type_name::<T>()
        ),
    }
}

// ==================== 端口装配（进程级单例） ====================

/// 进程级端口持有者
///
/// **为什么是全局**：`impl Host for WasmPluginState` 住在本 crate（它用本 crate 的
/// `bindgen!` 生成的 `Host` trait），而**端口的具体实现属于宿主**，crate 之间无从
/// 互相指名——故用「宿主开机装一次、之后经本函数取」的单向装配。与 http / ws /
/// peer-net / mdns 四域同款。
static PORTS: std::sync::OnceLock<Arc<dyn PtyPorts>> = std::sync::OnceLock::new();

/// 装配宿主端口实现（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
///
/// 重复装配必须被忽略而不是替换：在册 PTY 的退出监听与限频通知装饰器已经持有一份
/// 旧端口，换掉会让运行中的 PTY 把事件投到另一套总线。首次装配者胜出。
pub fn install_ports(ports: Arc<dyn PtyPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的宿主端口
///
/// # Panics
/// 尚未装配时 panic 并点名——**fail-visible**：让一个未接宿主的能力域以「跑起来
/// 但什么都做不了」的面貌存在，比启动即炸难诊断得多。
pub fn ports() -> Arc<dyn PtyPorts> {
    ports_from(&PORTS)
}

/// `ports` 的可测入口（**参数化单例格**）
///
/// 为什么不直接测 [`ports`]：进程级单例一旦被同进程任一测试装配过，`#[should_panic]`
/// 用例就变成**顺序依赖的假红**（并行执行下谁先跑不确定）。把格子作参数传入，
/// 「未装配 ⇒ 显性炸出」这条 fail-visible 契约就能被确定性断言。
fn ports_from(cell: &std::sync::OnceLock<Arc<dyn PtyPorts>>) -> Arc<dyn PtyPorts> {
    cell.get().cloned().expect(
        "pty engine ports are not installed — the host must call `install_ports` during boot",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 端口替身：`block_on_any` 直接返回固定值（不驱动 future——本组用例只验类型
    /// 不符时的显性失败，不碰异步驱动语义；真实驱动由宿主 adapter 负责）
    struct Stub;

    impl PtyPorts for Stub {
        fn check_permission(&self, _: &str, _: &str, _: &str) -> bool {
            true
        }
        fn publish(&self, _: &str, _: serde_json::Value) {}
        fn config(&self) -> PtyHostConfig {
            PtyHostConfig {
                default_cols: 80,
                default_rows: 24,
                engine: PtyEngineConfig::default(),
            }
        }
        fn block_on_any<'a>(&self, _fut: BoxedBlocked<'a>) -> Box<dyn Any + Send> {
            Box::new(7u8) as Box<dyn Any + Send>
        }
        fn spawn_task(&self, _: &'static str, _: BoxedTask) {}
    }

    fn stub() -> Arc<dyn PtyPorts> {
        Arc::new(Stub)
    }

    /// 返回类型不符：端口交回 `u8` 而调用方要 `String` ⇒ 必须显性炸出而不是静默降级
    #[test]
    fn block_on_rejects_unexpected_result_type() {
        let ports = stub();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(&ports, async { "expected-type".to_string() });
        }))
        .is_err();
        assert!(panicked, "返回类型不符必须 panic 点名，不得静默给出假值");
    }

    /// 端口未装配即取 ⇒ panic 点名（fail-visible，不得静默给一份空实现）
    ///
    /// 用**空的单例格**断言（不碰进程级 `PORTS`）：否则本组断言会与同进程其它
    /// 装配端口的用例构成顺序依赖（先跑者决定结果）。
    #[test]
    #[should_panic(expected = "pty engine ports are not installed")]
    fn ports_panics_when_host_never_installed() {
        let empty = std::sync::OnceLock::new();
        let _ = ports_from(&empty);
    }
}
