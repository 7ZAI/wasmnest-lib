//! host-http 能力域的宿主端口（边界层）
//!
//! ## 设计依据（`wasmnest-server-base::ports` 先例；ws / peer-net / mdns 三域同款）
//!
//! 消费方（本 crate）声明端口，宿主实现。本 crate **不依赖 tauri、不依赖宿主
//! bin crate**，故出站域的机制面（客户端池 / 跳转裁决 / 响应体上限 / SSE 切分 /
//! 载荷校验）自持，只把「宿主才有的四件事」经端口要过来。
//!
//! | 方法 | 为什么需要它 |
//! | --- | --- |
//! | [`HttpPorts::check_permission`] | 权限门（`network:http`）是**宿主安全闸门**（AGENTS §5.1.3 四类薄壳之二），不该可插拔 ⇒ 留宿主，本域只问结果（拒绝文案与 warn 落宿主侧） |
//! | [`HttpPorts::authorize_outbound`] | 出站授权裁决（弹窗询问 / 网络授权记录 / 档位策略）**整条链留在宿主**（票 06 验收项；闸门不应可插拔），本域只消费三态结果 |
//! | [`HttpPorts::event_sink`] | 流式推送的前端事件通道（宿主才有前端事件面）。**必须能表达「缺席」**——无头上下文的流式请求要显性报错，不得静默丢弃 chunk |
//! | [`HttpPorts::block_on_any`] | 同步↔异步桥：guest 侧的 host function 是同步的，而 HTTP 客户端是 async。**桥的实现在宿主**（含 wasmtime-wasi ambient runtime 与 actix `current_thread` 自锁规避），本域不复制第二份 |
//!
//! ## 为什么 [`HttpPorts::authorize_outbound`] 是同步方法（而不是 async）
//!
//! 授权 future 由**宿主**造（它才认得授权检查器），本域既造不出那个 future，也就
//! 只能拿到结果。宿主实现内部自行驱动（用宿主那份唯一的桥），本域拿到的是「已经
//! 裁决完」的答案。本域在**同一个同步栈**里用它继续（放行 / 拒绝 / 检查失败），
//! 位置不变：声明门之后、任何网络动作之前。
//!
//! ## 为什么 [`HttpPorts::event_sink`] 返回 `Option`
//!
//! 迁移前流式分支的语义是「拿不到 AppHandle ⇒ `http error: streaming requires
//! app_handle`」，与「事件投递失败」（迁移前被 `let _ =` 忽略）是**两件事**。
//! 用 `Option` 保留这个区分；只提供「尽力 emit」的 sink 会把二者压成一件，
//! 无头下 chunk 会静静消失（fail-visible 判据）。
//!
//! ## 为什么本域函数收 `&Arc<dyn HttpPorts>` 而不是 `&dyn HttpPorts`
//!
//! 与 ws 域同款：流式后台任务要活到响应结束之后，需要一份 `'static` 端口引用。

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// 类型擦除的「同步驱动异步」入参（[`HttpPorts::block_on_any`]）
pub type BoxedBlocked = Pin<Box<dyn Future<Output = Box<dyn Any + Send>> + Send>>;

/// 前端事件投递（流式 chunk / 完成 / 错误事件）
///
/// 失败语义与迁移前一致：投递失败不逐 chunk 上抛（流式路径不能因一次 emit 失败
/// 而中断整个响应），实现方可按自身约定落日志。
pub trait HttpEventSink: Send + Sync {
    /// 向**已拼好的完整事件名**投递一个载荷（事件名由本域用请求里的 `streamEvent`
    /// 拼好——纯字符串逻辑留能力域侧）
    fn emit(&self, event: &str, payload: serde_json::Value);
}

/// 出站授权裁决三态（与宿主授权层的判定一一对应，**刻意不复用**宿主类型）
///
/// 刻意不复用：宿主那份裁决类型住在安全闸门模块内（含业务化的 reason 词汇），
/// 搬进能力域会让本 crate 反向认识宿主类型。字段语义逐条对应，见各变体文档。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundAuth {
    /// 放行（`origin` = 归一化后的 origin，进 debug 日志）
    Allowed {
        /// 归一化 origin（不含 path / query——AGENTS §8 凭据红线）
        origin: String,
    },
    /// 拒绝（携带 reason 词汇与归一化 origin，供错误串逐字复原）
    Denied {
        /// 拒绝原因词汇（稳定的短标识，如 `no-record` / `user-denied`）
        reason: String,
        /// 归一化 origin（不含 path / query）
        origin: String,
    },
    /// 授权检查自身失败（取不到授权记录 / 通道异常）：错误分类与「拒绝」不同
    CheckFailed(String),
}

/// 宿主能力端口
///
/// 实现方是各端宿主的适配器（桌面端见宿主 adapter `src-tauri/src/plugin/http.rs`
/// 的 `HostHttpPorts`——票 02 批次 03 自 `wasm_core::host_api::http` 迁出）。
pub trait HttpPorts: Send + Sync + 'static {
    /// 权限判定（`network:http`）
    ///
    /// 返回 `false` 时**宿主侧**必须已按 AGENTS §8 落 `warn`（结构化字段
    /// `plugin_id` / `permission` / `api`）；本域不重复落日志。宿主侧也拿不到
    /// 权限管理器时（无头 / 测试）**必须返回 false**（fail-safe）。
    fn check_permission(&self, plugin_id: &str, permission: &str, api: &str) -> bool;

    /// 出站授权裁决（声明门之后、任何网络动作之前）
    ///
    /// `may_prompt = true` 是 WIT import 路径（插件主流程，可弹窗询问用户）；
    /// `false` 是任务单元路径（池线程绝不弹窗——弹窗会占住池槽位最短 30s，
    /// 且用户在错误的时机看到问题，与 fs 任务单元同款约束）。
    fn authorize_outbound(&self, plugin_id: &str, url: &str, may_prompt: bool) -> OutboundAuth;

    /// 流式推送所需的前端事件通道；`None` = 无头上下文（本域据此显性报错）
    fn event_sink(&self) -> Option<Arc<dyn HttpEventSink>>;

    /// 请求级 Bearer 代注的 token 源（请求 JSON 里 `"jwtAuth": true` 时取）
    ///
    /// **默认实现 `Ok(None)`** = 本宿主没有「全局会话 token」这个概念（桌面侧形态），
    /// guest 自带 `Authorization` 头即可，能力域行为零变化。覆写方的不变式：
    /// - 有 token → `Ok(Some(token))`：由本域代注 `Authorization: Bearer`
    ///   （token 不落插件，C4；与 ws 域 `jwt-auth` 首帧代发同款凭据红线）；
    /// - 要求代注但当前无 token → `Err`（fail-visible：匿名请求在对端必 401，
    ///   晚失败不如早失败，**禁止**静默降级为匿名请求）。
    fn jwt_auth_token(&self, _plugin_id: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    /// 在宿主运行时上**同步驱动**一段异步计算（guest host function 是同步的）
    ///
    /// 实现即宿主那份唯一的同步↔异步桥（多线程运行时走 `block_in_place`、
    /// current_thread / 无句柄线程走新线程 ambient 兜底）。**必须复用宿主那份
    /// 实现**，不得在本域复制第二份桥（重入自锁与 ambient runtime 语义是实测产物）。
    fn block_on_any(&self, fut: BoxedBlocked) -> Box<dyn Any + Send>;
}

// ==================== 泛型助手 ====================

/// 强类型版同步驱动（端口方法的包装：擦除入参 → 驱动 → 还原类型）
///
/// 类型不符是**装配期编程错误**（调用方传错了 future 的输出类型），直接 panic
/// 点名，不静默返回 `None` 之类的假值。
pub fn block_on<T: Send + 'static>(ports: &Arc<dyn HttpPorts>, fut: impl Future<Output = T> + Send + 'static) -> T {
    let erased: BoxedBlocked = Box::pin(async move { Box::new(fut.await) as Box<dyn Any + Send> });
    match ports.block_on_any(erased).downcast::<T>() {
        Ok(value) => *value,
        Err(_) => panic!(
            "http ports block_on_any returned an unexpected result type (expected {})",
            std::any::type_name::<T>()
        ),
    }
}

// ==================== 端口装配（进程级单例） ====================

/// 进程级端口持有者
///
/// **为什么是全局**：`impl Host for WasmPluginState` 住在本 crate（它用本 crate
/// 的 `bindgen!` 生成的 `Host` trait），而**端口的具体实现属于宿主**，crate 之间
/// 无从互相指名——故用「宿主开机装一次、之后经本函数取」的单向装配。与
/// ws / peer-net / mdns 三域同款。
static PORTS: std::sync::OnceLock<Arc<dyn HttpPorts>> = std::sync::OnceLock::new();

/// 装配宿主端口实现（宿主开机期调用一次，幂等：重复装配被忽略而非替换）
///
/// 重复装配必须被忽略而不是替换：流式后台任务已经持有一份旧端口，换掉会让
/// 运行中的请求投到另一套事件通道。首次装配者胜出。
pub fn install_ports(ports: Arc<dyn HttpPorts>) {
    let _ = PORTS.set(ports);
}

/// 取已装配的宿主端口
///
/// # Panics
/// 尚未装配时 panic 并点名——**fail-visible**：让一个未接宿主的能力域以
/// 「跑起来但什么都做不了」的面貌存在，比启动即炸难诊断得多。
pub fn ports() -> Arc<dyn HttpPorts> {
    PORTS
        .get()
        .cloned()
        .expect("http plugin binding ports are not installed — the host must call `install_ports` during boot")
}
