//! 授权策略与授权记录的宿主真源（2026-09-27 授权策略增强，票 01）
//!
//! 两张宿主主库表（`plugin_auth_policies` / `plugin_auth_records`，DDL 见
//! `src-tauri/src/db/schema.sql`——ADR 0036 撤销 SQLite 能力域 crate 后引擎面与
//! 本模块同在宿主内）承载两件不同的事：
//!
//! - **授权策略**：每个 (wasm 应用, 受管资源) 至多一条，回答「遇到授权记录未覆盖的
//!   目标时，要不要问用户」——三档 `always_ask` / `default` / `always_allow`；
//!   缺行 = `default`。策略只决定**是否询问**：不放宽 manifest 声明门、SSRF 防护、
//!   路径规范化、配额与属主隔离这些硬闸门（spec §4.2）。
//! - **授权记录**：每个 (应用, 资源, 目标) 至多一条，落账「某目标被允许 / 被拒绝」
//!   的运行期事实。文件侧 target = 规范路径前缀 + 生效操作集（`ops`），网络侧
//!   target = 归一化 origin（query / fragment 绝不入库，AGENTS §8 凭据红线）。
//!
//! ## 归属（ADR 0022 §5.1.3）
//!
//! 授权策略与记录是**安全闸门的配给账**，不是产品事实：任意第三方插件可按同一
//! 形状复用（「某事要不要问用户」+「问过的结果」），宿主在此只做引擎簿记与读模型
//! 投影，不含业务编排、不解释产品事件、不替插件决定业务策略（spec §11 红线自检）。
//!
//! ## 本票范围
//!
//! 票 01 提供真源读面与读模型装配（`plugin_auth_overview` 命令的数据源）；
//! 判定管线接入（策略求值 / 记录匹配 / 落账）由 02–06 票在 `fs_auth` /
//! host-http 侧完成（出站闸门的宿主 adapter 在 `src-tauri/src/plugin/http.rs`）。
//! 写入面（[`AuthPolicyStore::grant`] /
//! [`AuthPolicyStore::deny`] / [`AuthPolicyStore::revoke`] /
//! [`AuthPolicyStore::remove_deny`]）自 02 票起与判定面同处一个模块——落账与判定
//! 共用同一组库值常量（[`AUTH_EFFECT_ALLOW`] / [`AUTH_EFFECT_DENY`] /
//! [`AuthRecordSource`]），两边各拼一套字符串必然漂移。票 03 起档位也有写入面
//! （[`AuthPolicyStore::set_strategy`]，设置页策略控件的数据源）；档位到动作的
//! 求值不在这里，在 `super::strategy`（fs / network 共用同一处顺序裁决）。

use crate::db::Database;
use crate::monitor::MetricsRegistry;
use crate::security::fs_auth::FirstPartyDirEntry;
use std::sync::{Arc, RwLock};
// db 锁形态统一为 std Mutex（单形态票 02 M2，与 storage.rs 同款裁决）：
// 锁获取行统一为同步锁 + 短临界区（auth_policy 内无跨 await 持有的锁——
// guard 非 Send，编译器强制）；`.await` 形态随 tokio 锁一并退役。
use std::sync::Mutex;

/// 每 (应用, 资源) 的授权记录条数上限（spec §8.2）
///
/// 文件侧若无封顶，遍历型插件会把碰过的每个目标累积成无界增长的表（网络侧 origin
/// 数量天然有限，但共用同一条上限）。超出即**丢弃新记录**并在 core-monitor 计数——
/// 丢弃只影响「留痕」，放行判定仍然照常（`always_allow` 的语义是「不问」，不是
/// 「留不下痕就不放行」）。
pub const AUTH_RECORDS_CAP: usize = 500;

/// 落账结果（`grant` 的返回；调用方按它决定要不要留痕）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantOutcome {
    /// 已落账（新建一行，或并入既有 allow 行的操作集）
    Stored,
    /// 该 (应用, 资源) 已达 [`AUTH_RECORDS_CAP`]：本次**丢弃**，core-monitor 已计数
    DroppedByCap,
}

/// 受管资源类别（策略与记录都按它分区；本期 fs / network 两类）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResource {
    /// 文件系统访问（fs:read / fs:write 判定链）
    Fs,
    /// 网络出站请求（host-http `fetch`；入站方向不在范围，spec §6.4）
    Network,
}

impl AuthResource {
    /// 全部受管资源（读模型按此顺序补齐策略，缺行也补齐——顺序即界面顺序）
    pub const ALL: [AuthResource; 2] = [AuthResource::Fs, AuthResource::Network];

    /// 库值与 wire 值（`plugin_auth_policies.resource` / `plugin_auth_records.resource`）
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Network => "network",
        }
    }

    /// 解析 wire 值；未知值返回 `None`（调用方显性报错——不猜资源类别，
    /// 猜错的代价是写到另一个资源的记录里）
    ///
    /// 非 `const fn`：`str` 比较在常量上下文里尚不可用（rustc E0658）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fs" => Some(Self::Fs),
            "network" => Some(Self::Network),
            _ => None,
        }
    }
}

/// 授权策略档位（spec §4.1）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStrategy {
    /// 总是询问：跳过全部 allow 记录，每次判定都问（deny 记录仍优先，spec §6.1）
    AlwaysAsk,
    /// 默认：记录命中即放行，未命中才问
    Default,
    /// 始终允许：不问直接放行，并以 `source='always_allow'` 落账（免询问也留痕）
    AlwaysAllow,
}

impl AuthStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysAsk => "always_ask",
            Self::Default => "default",
            Self::AlwaysAllow => "always_allow",
        }
    }

    /// 解析 wire 值；未知值返回 `None`（**写入面**用显性报错，不猜档位）
    ///
    /// 与读面 [`AuthStrategy::parse`] 的兜底方向相反，理由在「写」这件事上：
    /// `always_allow` 手误成 `always_allowed` 若被判成默认档存下去，用户看到的
    /// 是「设置成功」而实际档位没生效——策略界面骗人比报错严重得多。
    pub fn parse_wire(raw: &str) -> Option<Self> {
        match raw {
            "always_ask" => Some(Self::AlwaysAsk),
            "default" => Some(Self::Default),
            "always_allow" => Some(Self::AlwaysAllow),
            _ => None,
        }
    }

    /// 解析库值：**未知值一律回落 [`AuthStrategy::Default`]**
    ///
    /// fail-safe 方向的单点：不认识的档位绝不能等价于「免询问自动放行」，
    /// 也不能等价于「跳过记录」——两者都比默认档更宽松。取值词汇表只有
    /// [`AuthStrategy::parse_wire`] 一处，两处各拼一套必然漂移。
    pub fn parse(raw: &str) -> Self {
        Self::parse_wire(raw).unwrap_or(Self::Default)
    }
}

/// 授权记录来源（写入口径的单点：来源取值只在这里拼）
///
/// 与库值一一对应（`plugin_auth_records.source`），语义见 spec §8.4：
/// - [`User`](Self::User)：用户在弹窗里确认并「记住」；
/// - [`AlwaysAllow`](Self::AlwaysAllow)：`always_allow` 档免询问自动放行（界面标「未经确认」）；
/// - [`Legacy`](Self::Legacy)：旧版遗留记录（`fs_granted_paths` 首次迁入新表时的来源位，本期只读不做迁移）；
/// - [`UserDeny`](Self::UserDeny)：用户显式拒绝（弹窗「以后都拒绝」或管理界面撤销）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRecordSource {
    User,
    AlwaysAllow,
    Legacy,
    UserDeny,
}

impl AuthRecordSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::AlwaysAllow => "always_allow",
            Self::Legacy => "legacy",
            Self::UserDeny => "user_deny",
        }
    }
}

/// 记录效果取值（库值单点）
pub const AUTH_EFFECT_ALLOW: &str = "allow";
/// 记录效果：硬拒绝（deny 优先于一切放行路径，spec §6.1 第 1 步）
pub const AUTH_EFFECT_DENY: &str = "deny";

/// 判定用的轻量记录行：只含匹配所需字段
///
/// 前缀 / 段边界匹配留在调用侧做——SQL 里做不了 `Path` 组件语义（`.wasmnest` 与
/// `.wasmnest-other` 必须分开），且 fs 侧同一形状将来网络侧要按 origin 段边界复用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRecordMatch {
    /// 记录目标（fs: 规范路径；network: 归一化 origin，可带 path 前缀）
    pub target: String,
    /// `allow` | `deny`
    pub effect: String,
    /// fs: 生效操作集；network 恒空
    pub ops: Vec<String>,
    /// network: target 是否按 path 前缀匹配（fs 恒 false）
    ///
    /// 必须带进判定面：网络侧「整站放行」与「只放行 `/v1` 前缀」是两种授权，
    /// 判定时不看这个标记就会把收紧的授权当整站放行（票 05）。
    pub prefix_match: bool,
}

/// 一条授权记录（与 `plugin_auth_records` 列一一对应的读模型投影）
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRecord {
    pub id: i64,
    pub plugin_id: String,
    /// `fs` | `network`
    pub resource: String,
    /// fs: 规范路径前缀；network: `scheme://host:port[/path-prefix]`
    pub target: String,
    /// `allow` | `deny`
    pub effect: String,
    /// fs: `["read"]` / `["read","write"]`；network 恒空
    pub ops: Vec<String>,
    /// network: target 是否按 path 前缀匹配；fs 恒 false
    pub prefix_match: bool,
    /// `user` | `always_allow` | `legacy` | `user_deny`
    pub source: String,
    /// unix 毫秒
    pub created_at: i64,
}

/// 某资源上的策略取值（读模型里策略字段固定两条，缺行也补齐）
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceStrategy {
    pub resource: String,
    pub strategy: String,
}

/// 单个应用的授权读模型（spec §9.3）
///
/// 设置页「应用授权」总览与应用详情页「授权记录」区块共用同一份数据，
/// 各写一套查询会立刻漂移（两页对同一目标给出不同策略/记录）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginAuthOverview {
    pub plugin_id: String,
    /// 应用显示名（来自 manifest，宿主不另立命名）
    pub name: String,
    /// 两类受管资源的策略，顺序 = [`AuthResource::ALL`]
    pub strategies: Vec<ResourceStrategy>,
    /// 该应用全部授权记录（allow 与 deny 都在；按资源 + 创建时间稳定排序）
    pub records: Vec<AuthRecord>,
    /// 该应用的第一方免询问项（只读展示；撤销在 08 票接 deny 记录）
    pub first_party_dirs: Vec<FirstPartyDirEntry>,
}

/// 授权策略与记录真源
///
/// 与 `PluginStorage` 同一形态：持 `Arc<Mutex<Database>>`，每次调用短暂持锁做
/// 只读查询。判定路径（02–06 票）会在这里加查询方法；本票只有读模型装配。
pub struct AuthPolicyStore {
    db: Arc<Mutex<Database>>,
    /// core-monitor 句柄（记录容量丢弃计数；两阶段注入，见 [`Self::set_monitor`]）
    ///
    /// `Option` + 内部可变：core-monitor 生于 `WasmRuntime`，晚于校验器构造
    /// （与 `SecurityFramework::set_monitor` / `MessageBus::set_monitor` 同一形态）。
    /// 未注入时计数只丢失可观测性，判定行为一字不变。
    monitor: RwLock<Option<Arc<MetricsRegistry>>>,
}

impl AuthPolicyStore {
    pub fn new(db: Arc<Mutex<Database>>) -> Self {
        Self {
            db,
            monitor: RwLock::new(None),
        }
    }

    /// 注入 core-monitor 句柄（两阶段初始化；重复注入覆盖）
    pub fn set_monitor(&self, monitor: Arc<MetricsRegistry>) {
        *self.monitor.write().expect("auth policy monitor lock poisoned") = Some(monitor);
    }

    /// 装配单应用读模型（spec §9.3）
    ///
    /// `plugin_id` 未知（无策略、无记录）不是错误：返回空记录 + 全 `default` 策略，
    /// 使设置页总览在「刚装完还没发生过任何授权」的应用上照常渲染。
    ///
    /// `first_party_dirs`：第一方免弹窗项只读投影（**票 08/P0-2**：产品清单出厂 lib，
    /// 读模型数据经 `FsAuthChecker::first_party_trusted_dirs()` 取——本存储不持有
    /// 清单）；空投影 = 无免弹窗可见项。
    pub async fn overview(
        &self,
        plugin_id: &str,
        name: &str,
        first_party_dirs: Vec<FirstPartyDirEntry>,
    ) -> crate::Result<PluginAuthOverview> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let strategies = load_strategies(db.conn(), plugin_id)?;
        let records = load_records(db.conn(), plugin_id)?;
        let first_party_dirs = first_party_dirs
            .into_iter()
            .filter(|entry| entry.plugin_id == plugin_id)
            .collect();
        Ok(PluginAuthOverview {
            plugin_id: plugin_id.to_string(),
            name: name.to_string(),
            strategies,
            records,
            first_party_dirs,
        })
    }

    /// 判定期读策略档位（spec §6.1 第 3 步的输入）
    ///
    /// **实时读取**、不缓存、不做激活期快照（spec §8.1）：否则「已改成总是询问」却仍有
    /// 缓存判定在放行，策略语义就是骗人的。缺行 / 非法值都回落默认档
    /// （fail-safe 方向见 [`AuthStrategy::parse`]）。
    pub async fn strategy(&self, plugin_id: &str, resource: AuthResource) -> crate::Result<AuthStrategy> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let raw = db.conn().query_row(
            "SELECT strategy FROM plugin_auth_policies WHERE plugin_id = ?1 AND resource = ?2",
            rusqlite::params![plugin_id, resource.as_str()],
            |row| row.get::<_, String>(0),
        );
        match raw {
            Ok(value) => Ok(AuthStrategy::parse(&value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(AuthStrategy::Default),
            Err(e) => Err(crate::AppError::Database(e)),
        }
    }

    // ==================== 判定链读面（fs / network 判定侧自行做目标匹配） ====================

    /// 加载某应用在某资源上的全部记录（allow 与 deny 都在）
    ///
    /// 判定链每次判定实时读取、不缓存（spec §8.1：缓存会让「已改成总是询问却仍在放行」
    /// 这类漂移无法解释）。每 (应用, 资源) 记录数有上限（spec §8.2），单次加载是小的。
    pub async fn records_for_match(
        &self,
        plugin_id: &str,
        resource: AuthResource,
    ) -> crate::Result<Vec<AuthRecordMatch>> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db.conn().prepare(
            "SELECT id, target, effect, ops, prefix_match FROM plugin_auth_records \
             WHERE plugin_id = ?1 AND resource = ?2 ORDER BY effect, target",
        )?;
        let rows = stmt.query_map(rusqlite::params![plugin_id, resource.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, target, effect, ops, prefix_match) = row?;
            out.push(AuthRecordMatch {
                target,
                effect,
                ops: parse_ops(&ops, plugin_id, id)?,
                prefix_match: prefix_match != 0,
            });
        }
        Ok(out)
    }

    // ==================== 写面（策略档位 / 落账 / 撤销） ====================

    /// 写策略档位（设置页策略控件的唯一写入口；spec §4.1 三档）
    ///
    /// upsert：每个 (应用, 资源) 至多一行（主键即该二元组），重复设置不堆行。
    /// 档位取值由调用方用 [`AuthStrategy::parse_wire`] 解析后传入——未知值不得
    /// 走到这里（写面不猜档位，见该方法的文档）。
    pub async fn set_strategy(
        &self,
        plugin_id: &str,
        resource: AuthResource,
        strategy: AuthStrategy,
    ) -> crate::Result<()> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp_millis();
        db.conn().execute(
            "INSERT INTO plugin_auth_policies (plugin_id, resource, strategy, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(plugin_id, resource) DO UPDATE SET strategy = ?3, updated_at = ?4",
            rusqlite::params![plugin_id, resource.as_str(), strategy.as_str(), now],
        )?;
        Ok(())
    }

    /// 落账一条 allow 记录（spec §5.2：新记录一律进本表，`fs_granted_paths` 不再被写入）
    ///
    /// 每个 (应用, 资源, 目标) 至多一行：命中既有行时**操作集取并集**（先授权读、
    /// 后授权写 ⇒ 一行 `["read","write"]`），来源保留用户确认——`user` 是比免询问
    /// 自动放行更强的来源，界面按它决定是否标「未经确认」。
    ///
    /// 目标上若残留 deny 行这里**不清理**：deny 优先于一切放行路径（spec §6.1 第 1 步），
    /// 用户要恢复访问得先在界面移除该 deny 记录（spec §8.4 的另一种出口）。
    ///
    /// **容量上限**（spec §8.2）：新建行前先数该 (应用, 资源) 的现有记录，达到
    /// [`AUTH_RECORDS_CAP`] 即丢弃本次落账（返回 [`GrantOutcome::DroppedByCap`] +
    /// core-monitor 计数）。既有目标的并入**不受上限影响**：它不新增行，丢的会是
    /// 「用户已授权过的那一条」的增量信息。上限只拦新目标，正是为了拦住无界增长的那一半。
    pub async fn grant(
        &self,
        plugin_id: &str,
        resource: AuthResource,
        target: &str,
        ops: &[String],
        source: AuthRecordSource,
    ) -> crate::Result<GrantOutcome> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let conn = db.conn();
        let now = chrono::Utc::now().timestamp_millis();
        let existing = conn.query_row(
            "SELECT id, ops, source FROM plugin_auth_records \
             WHERE plugin_id = ?1 AND resource = ?2 AND target = ?3 AND effect = ?4",
            rusqlite::params![plugin_id, resource.as_str(), target, AUTH_EFFECT_ALLOW],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        );
        match existing {
            Ok((id, raw_ops, existing_source)) => {
                let mut merged = parse_ops(&raw_ops, plugin_id, id)?;
                for op in ops {
                    if !merged.iter().any(|known| known == op) {
                        merged.push(op.clone());
                    }
                }
                let next_source = if existing_source == AuthRecordSource::User.as_str() {
                    existing_source
                } else {
                    source.as_str().to_string()
                };
                conn.execute(
                    "UPDATE plugin_auth_records SET ops = ?1, source = ?2, created_at = ?3 \
                     WHERE id = ?4",
                    rusqlite::params![serde_json::to_string(&merged)?, next_source, now, id],
                )?;
                Ok(GrantOutcome::Stored)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let stored: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM plugin_auth_records WHERE plugin_id = ?1 AND resource = ?2",
                    rusqlite::params![plugin_id, resource.as_str()],
                    |row| row.get(0),
                )?;
                if stored as usize >= AUTH_RECORDS_CAP {
                    if let Some(monitor) = self.monitor.read().expect("auth policy monitor lock poisoned").as_ref() {
                        monitor.plugin(plugin_id).record_authz_record_dropped();
                    }
                    tracing::warn!(
                        plugin_id = %plugin_id,
                        resource = resource.as_str(),
                        cap = AUTH_RECORDS_CAP,
                        target = %target,
                        source = source.as_str(),
                        "auth_policy: 授权记录已达容量上限，本次落账丢弃（core-monitor 已计数）"
                    );
                    return Ok(GrantOutcome::DroppedByCap);
                }
                conn.execute(
                    "INSERT INTO plugin_auth_records \
                     (plugin_id, resource, target, effect, ops, prefix_match, source, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
                    rusqlite::params![
                        plugin_id,
                        resource.as_str(),
                        target,
                        AUTH_EFFECT_ALLOW,
                        serde_json::to_string(ops)?,
                        source.as_str(),
                        now
                    ],
                )?;
                Ok(GrantOutcome::Stored)
            }
            Err(e) => Err(crate::AppError::Database(e)),
        }
    }

    /// 落账一条 deny 记录（用户显式拒绝：弹窗「以后都拒绝」或管理界面撤销）
    ///
    /// 幂等：同目标已有 deny 行则只刷新时间戳，不堆重复行。
    pub async fn deny(
        &self,
        plugin_id: &str,
        resource: AuthResource,
        target: &str,
        source: AuthRecordSource,
    ) -> crate::Result<()> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let conn = db.conn();
        let now = chrono::Utc::now().timestamp_millis();
        let updated = conn.execute(
            "UPDATE plugin_auth_records SET source = ?1, created_at = ?2 \
             WHERE plugin_id = ?3 AND resource = ?4 AND target = ?5 AND effect = ?6",
            rusqlite::params![
                source.as_str(),
                now,
                plugin_id,
                resource.as_str(),
                target,
                AUTH_EFFECT_DENY
            ],
        )?;
        if updated == 0 {
            conn.execute(
                "INSERT INTO plugin_auth_records \
                 (plugin_id, resource, target, effect, ops, prefix_match, source, created_at) \
                 VALUES (?1, ?2, ?3, ?4, '[]', 0, ?5, ?6)",
                rusqlite::params![
                    plugin_id,
                    resource.as_str(),
                    target,
                    AUTH_EFFECT_DENY,
                    source.as_str(),
                    now
                ],
            )?;
        }
        Ok(())
    }

    /// 撤销（spec §8.4）：删除该目标的 allow 记录 + 落一条 deny 记录
    ///
    /// 返回被删除的 allow 行数（0 表示该目标本来就没有 allow——界面按此判断是否需要刷新）。
    ///
    /// target 支持 `~/` 前缀（仅文件资源）：第一方免询问项（home 形态）撤销时前端
    /// 拿不到 `$HOME`，传 `~/<rel>` 由这里展开成绝对路径再落账——判定链
    /// （`fs_auth::record_signals`）只认规范化绝对路径，不展开直接落账的 `~/` 目标
    /// 永远匹配不上（静默撤销无效）；home 不可得时显性报错、不落账（§8 fail-visible）。
    pub async fn revoke(&self, plugin_id: &str, resource: AuthResource, target: &str) -> crate::Result<usize> {
        let target = resolve_revoke_target(resource, target)?;
        let removed = {
            let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
            db.conn().execute(
                "DELETE FROM plugin_auth_records \
                 WHERE plugin_id = ?1 AND resource = ?2 AND target = ?3 AND effect = ?4",
                rusqlite::params![plugin_id, resource.as_str(), target, AUTH_EFFECT_ALLOW],
            )?
        };
        self.deny(plugin_id, resource, &target, AuthRecordSource::UserDeny)
            .await?;
        Ok(removed)
    }

    /// 移除该目标的 deny 记录（界面「硬拒绝」分区自行移除，spec §8.4 的恢复出口）
    ///
    /// 只删 deny 行，不动同目标的 allow 行。返回删除行数（0 = 本就没有 deny）。
    pub async fn remove_deny(&self, plugin_id: &str, resource: AuthResource, target: &str) -> crate::Result<usize> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let removed = db.conn().execute(
            "DELETE FROM plugin_auth_records \
             WHERE plugin_id = ?1 AND resource = ?2 AND target = ?3 AND effect = ?4",
            rusqlite::params![plugin_id, resource.as_str(), target, AUTH_EFFECT_DENY],
        )?;
        Ok(removed)
    }

    /// 清空某应用的授权策略与授权记录（**卸载**清空面，spec §8.3）
    ///
    /// 卸载清空、重装即全新授权（与 ADR 0020 的内容哈希钉扎同调：重装 = 一次新审批）。
    /// **停用不清**（见 `deactivate_preserves_*` 的锁）：停用是运行期开关，用户停了
    /// 又开是常事，连带把他授权过的目录一起清掉等于让「停用」变成不可逆操作——
    /// 这两件事容易被后人「顺手统一」，所以各有各的落点与锁。
    ///
    /// 返回被清掉的 (记录数, 策略数)，供调用方记日志：清零无声意味着「重装后授权
    /// 记录凭空消失」这类问题无从追查（AGENTS §8：真源侧动作要留痕）。
    pub async fn purge_plugin(&self, plugin_id: &str) -> crate::Result<(usize, usize)> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let conn = db.conn();
        let records = conn.execute(
            "DELETE FROM plugin_auth_records WHERE plugin_id = ?1",
            rusqlite::params![plugin_id],
        )?;
        let policies = conn.execute(
            "DELETE FROM plugin_auth_policies WHERE plugin_id = ?1",
            rusqlite::params![plugin_id],
        )?;
        tracing::info!(
            plugin_id = %plugin_id,
            records = records,
            policies = policies,
            "auth_policy: 卸载清空授权记录与策略（spec §8.3）"
        );
        Ok((records, policies))
    }
}

/// 撤销目标的 `~/` 展开（仅文件资源）：第一方 home 形态免询问项撤销用
///
/// 前端拿不到 `$HOME`，撤销内置免询问项（如 `~/.agents`）时传 `~/<rel>`；这里展开成
/// 绝对路径后再走落账，否则判定链（`record_signals` 的 `strip_prefix`）永远匹配不上
/// 相对形态的 `~/` 字符串——撤销按钮点了等于没点（静默降级，§8 禁止）。
///
/// - 非文件资源：原样返回（network target 是归一化 origin，无 `~/` 语义）
/// - 文件资源且无 `~/` 前缀：原样返回（授权记录 target 本身是规范路径）
/// - 文件资源且 `~/` 前缀：展开为 home 绝对路径；home 不可得时显性报错、不落账
fn resolve_revoke_target(resource: AuthResource, target: &str) -> crate::Result<String> {
    if resource != AuthResource::Fs || !target.starts_with("~/") {
        return Ok(target.to_string());
    }
    let Some(home) = dirs::home_dir() else {
        return Err(crate::AppError::InvalidInput(format!(
            "无法解析家目录目标 '{target}'（home_dir 不可用）"
        )));
    };
    let expanded = home.join(&target[2..]);
    tracing::debug!(target = %target, expanded = %expanded.display(), "auth_policy: ~/ target expanded for revoke");
    Ok(expanded.to_string_lossy().into_owned())
}

/// 解析 `ops` 列（JSON 数组文本）
///
/// 解析失败即报错、不降级成空数组：空 ops 在判定里等于「该子树不含任何操作」
/// = 一条有效拒绝，静默降级会把脏数据伪装成用户的拒绝决定。错误带应用与记录行
/// 上下文，否则脏数据只能靠人肉翻库定位。
fn parse_ops(raw: &str, plugin_id: &str, record_id: i64) -> crate::Result<Vec<String>> {
    serde_json::from_str(raw).map_err(|e| {
        crate::AppError::Internal(format!(
            "授权记录 ops 列不是合法 JSON 数组（plugin_id={plugin_id}, record_id={record_id}）: {e}"
        ))
    })
}

/// 读某应用两类资源的策略：缺行 / 非法值都回落 `default`（见 [`AuthStrategy::parse`]）
fn load_strategies(conn: &rusqlite::Connection, plugin_id: &str) -> crate::Result<Vec<ResourceStrategy>> {
    let mut out = Vec::with_capacity(AuthResource::ALL.len());
    for resource in AuthResource::ALL {
        let raw = conn.query_row(
            "SELECT strategy FROM plugin_auth_policies WHERE plugin_id = ?1 AND resource = ?2",
            rusqlite::params![plugin_id, resource.as_str()],
            |row| row.get::<_, String>(0),
        );
        let strategy = match raw {
            Ok(value) => AuthStrategy::parse(&value),
            Err(rusqlite::Error::QueryReturnedNoRows) => AuthStrategy::Default,
            Err(e) => return Err(crate::AppError::Database(e)),
        };
        out.push(ResourceStrategy {
            resource: resource.as_str().to_string(),
            strategy: strategy.as_str().to_string(),
        });
    }
    Ok(out)
}

/// 读某应用全部授权记录（allow + deny）
///
/// 排序 `(resource, created_at, id)`：资源分区稳定、同批落账按落账顺序，
/// 界面直接渲染即可（不再依赖前端二次排序）。
fn load_records(conn: &rusqlite::Connection, plugin_id: &str) -> crate::Result<Vec<AuthRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, plugin_id, resource, target, effect, ops, prefix_match, source, created_at \
         FROM plugin_auth_records WHERE plugin_id = ?1 \
         ORDER BY resource, created_at, id",
    )?;
    let rows = stmt.query_map(rusqlite::params![plugin_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (id, plugin_id, resource, target, effect, ops, prefix_match, source, created_at) = row?;
        let ops = parse_ops(&ops, &plugin_id, id)?;
        out.push(AuthRecord {
            id,
            plugin_id,
            resource,
            target,
            effect,
            ops,
            prefix_match: prefix_match != 0,
            source,
            created_at,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// 建库并跑生产初始化（迁移被破坏时本模块用例随之变红）
    async fn store() -> AuthPolicyStore {
        let db = Database::new(Path::new(":memory:")).expect("open in-memory db");
        db.init_schema().expect("init schema");
        AuthPolicyStore::new(Arc::new(Mutex::new(db)))
    }

    /// 直接插记录（写入面是 02–06 票的方法，读模型用例只消费已落库的事实）
    ///
    /// 参数多是刻意：读模型用例要能造出**每一列**的形状（含 `prefix_match` / `source`
    /// 这类只在特定路径上出现的列），打包成结构体反而会多出一套「默认值由谁定」的判断。
    #[allow(clippy::too_many_arguments)]
    async fn seed_record(
        store: &AuthPolicyStore,
        plugin_id: &str,
        resource: &str,
        target: &str,
        effect: &str,
        ops: &str,
        prefix_match: i64,
        source: &str,
        created_at: i64,
    ) {
        let db = store.db.lock().expect("auth policy db lock poisoned");
        db.conn()
            .execute(
                "INSERT INTO plugin_auth_records \
                 (plugin_id, resource, target, effect, ops, prefix_match, source, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    plugin_id,
                    resource,
                    target,
                    effect,
                    ops,
                    prefix_match,
                    source,
                    created_at
                ],
            )
            .expect("seed auth record");
    }

    async fn seed_strategy(store: &AuthPolicyStore, plugin_id: &str, resource: &str, strategy: &str) {
        let db = store.db.lock().expect("auth policy db lock poisoned");
        db.conn()
            .execute(
                "INSERT INTO plugin_auth_policies (plugin_id, resource, strategy, updated_at) \
                 VALUES (?1, ?2, ?3, 1)",
                rusqlite::params![plugin_id, resource, strategy],
            )
            .expect("seed auth policy");
    }

    /// C1 正例：空库（从未发生过授权）装配读模型不报错，记录为空、策略补齐为默认档
    ///
    /// 设置页总览在「刚装完的应用」上就依赖这条：缺行不是错误，是默认档。
    #[tokio::test]
    async fn overview_on_empty_db_yields_default_strategies_and_no_records() {
        let store = store().await;
        let overview = store
            .overview("com.wasmnest.agent-hub", "Agent Hub", Vec::new())
            .await
            .expect("empty db overview must not fail");

        assert_eq!(overview.plugin_id, "com.wasmnest.agent-hub");
        assert_eq!(overview.name, "Agent Hub");
        assert!(overview.records.is_empty(), "空库不得凭空给出记录");
        assert_eq!(
            overview
                .strategies
                .iter()
                .map(|s| (s.resource.as_str(), s.strategy.as_str()))
                .collect::<Vec<_>>(),
            vec![("fs", "default"), ("network", "default")],
            "两类资源都要补齐为默认档（缺行 = default，fail-safe）"
        );
    }

    /// C1 反例：库里的非法档位值不得被当成更宽松的档位
    ///
    /// 变异判据：把 [`AuthStrategy::parse`] 的兜底从 `Default` 改成 `AlwaysAllow`
    /// 或 `AlwaysAsk`，本条转红（两者都比默认档更宽松：一个免询问放行、一个跳过记录）。
    #[tokio::test]
    async fn unknown_strategy_value_falls_back_to_default() {
        let store = store().await;
        seed_strategy(&store, "com.wasmnest.test", "fs", "bypass").await;
        seed_strategy(&store, "com.wasmnest.test", "network", "ALWAYS_ALLOW").await;

        let overview = store.overview("com.wasmnest.test", "T", Vec::new()).await.expect("overview");
        assert_eq!(
            overview
                .strategies
                .iter()
                .map(|s| s.strategy.as_str())
                .collect::<Vec<_>>(),
            vec!["default", "default"],
            "未识别的档位值必须回落默认档（不认识 ≠ 放行）"
        );
    }

    /// C1 边界：显式写入的档位值原样读出（读模型不吞掉已配置的档位）
    #[tokio::test]
    async fn explicit_strategies_are_projected_as_stored() {
        let store = store().await;
        seed_strategy(&store, "com.wasmnest.test", "fs", "always_ask").await;
        seed_strategy(&store, "com.wasmnest.test", "network", "always_allow").await;

        let overview = store.overview("com.wasmnest.test", "T", Vec::new()).await.expect("overview");
        assert_eq!(
            overview
                .strategies
                .iter()
                .map(|s| (s.resource.as_str(), s.strategy.as_str()))
                .collect::<Vec<_>>(),
            vec![("fs", "always_ask"), ("network", "always_allow")]
        );
    }

    /// C2：记录投影保真 —— 字段逐列对应、ops 解析成数组、prefix_match 成布尔、deny 也在模型里
    ///
    /// 变异判据：ops 解析丢弃 / prefix_match 恒 false / deny 被过滤掉，三者各让本条转红。
    #[tokio::test]
    async fn records_are_projected_faithfully_including_deny() {
        let store = store().await;
        seed_record(
            &store,
            "com.wasmnest.test",
            "fs",
            "/home/u/data",
            "allow",
            "[\"read\",\"write\"]",
            0,
            "user",
            1_700_000_000_000,
        )
        .await;
        seed_record(
            &store,
            "com.wasmnest.test",
            "fs",
            "/home/u/secret",
            "deny",
            "[]",
            0,
            "user_deny",
            1_700_000_001_000,
        )
        .await;
        seed_record(
            &store,
            "com.wasmnest.test",
            "network",
            "https://api.github.com:443",
            "allow",
            "[]",
            1,
            "always_allow",
            1_700_000_002_000,
        )
        .await;

        let overview = store.overview("com.wasmnest.test", "T", Vec::new()).await.expect("overview");
        assert_eq!(overview.records.len(), 3, "allow 与 deny 都必须进读模型");
        assert_eq!(
            overview.records[0],
            AuthRecord {
                id: 1,
                plugin_id: "com.wasmnest.test".to_string(),
                resource: "fs".to_string(),
                target: "/home/u/data".to_string(),
                effect: "allow".to_string(),
                ops: vec!["read".to_string(), "write".to_string()],
                prefix_match: false,
                source: "user".to_string(),
                created_at: 1_700_000_000_000,
            }
        );
        assert_eq!(overview.records[1].effect, "deny");
        assert_eq!(overview.records[1].source, "user_deny");
        assert_eq!(overview.records[2].resource, "network");
        assert!(
            overview.records[2].prefix_match,
            "网络记录的 path 前缀标记必须读出（否则 /v1 前缀收紧在界面上不可见）"
        );
    }

    /// C2 反例：别人的记录不得出现在本应用的读模型里（属主隔离的最低要求）
    #[tokio::test]
    async fn overview_excludes_other_plugins_records() {
        let store = store().await;
        seed_record(
            &store,
            "com.wasmnest.mine",
            "fs",
            "/tmp/mine",
            "allow",
            "[]",
            0,
            "user",
            1,
        )
        .await;
        seed_record(
            &store,
            "com.wasmnest.other",
            "fs",
            "/tmp/other",
            "allow",
            "[]",
            0,
            "user",
            1,
        )
        .await;

        let overview = store.overview("com.wasmnest.mine", "Mine", Vec::new()).await.expect("overview");
        assert_eq!(overview.records.len(), 1);
        assert_eq!(overview.records[0].target, "/tmp/mine");
    }

    /// C2 异常：ops 列是脏 JSON 时报错，不静默降级成空操作集
    ///
    /// 空 ops 在判定里等价于「该子树不含任何操作」= 一条有效拒绝；把解析失败
    /// 伪装成空数组，会让脏数据悄悄变成用户的拒绝决定。
    #[tokio::test]
    async fn corrupt_ops_column_is_reported_not_silently_emptied() {
        let store = store().await;
        seed_record(
            &store,
            "com.wasmnest.test",
            "fs",
            "/tmp/x",
            "allow",
            "not-json",
            0,
            "user",
            1,
        )
        .await;
        assert!(
            store.overview("com.wasmnest.test", "T", Vec::new()).await.is_err(),
            "脏 ops 必须让读模型报错（fail-visible）"
        );
    }

    // ==================== 写面（落账 / 撤销 / 移除 deny） ====================

    fn ops(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// 落账去重 + 操作集并集 + 来源不降级
    ///
    /// 变异判据：upsert 退化成「每次 INSERT」（多行）或「覆盖 ops」（丢读授权）、
    /// 或用新来源覆盖既有 `user`，本条各有一处转红。
    #[tokio::test]
    async fn grant_merges_ops_into_one_row_and_keeps_user_source() {
        let store = store().await;
        // 别人的记录不得混进来
        store
            .grant(
                "com.wasmnest.other",
                AuthResource::Fs,
                "/tmp/other",
                &ops(&["read"]),
                AuthRecordSource::User,
            )
            .await
            .unwrap();

        store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/dir",
                &ops(&["read"]),
                AuthRecordSource::User,
            )
            .await
            .unwrap();
        // 免询问自动放行补上写：操作集并集、来源仍是用户确认（不降级成「未经确认」）
        store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/dir",
                &ops(&["write"]),
                AuthRecordSource::AlwaysAllow,
            )
            .await
            .unwrap();
        // 重复落同一操作不得堆叠
        store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/dir",
                &ops(&["read"]),
                AuthRecordSource::User,
            )
            .await
            .unwrap();

        let rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "每个 (应用, 资源, 目标) 至多一行");
        assert_eq!(rows[0].target, "/tmp/dir");
        assert_eq!(rows[0].ops, ops(&["read", "write"]), "操作集取并集且不重复");
        let overview = store.overview("com.wasmnest.test", "T", Vec::new()).await.unwrap();
        assert_eq!(overview.records[0].source, "user", "用户确认的溯源不得被自动放行覆盖");
        assert!(!overview.records[0].prefix_match, "fs 记录不按 path 前缀匹配");
    }

    /// 容量上限（spec §8.2，票 04）：第 501 个新目标丢弃 + core-monitor 计数；
    /// 既有目标并入与 deny 落账都不受上限影响
    ///
    /// 变异判据：去掉 `stored >= AUTH_RECORDS_CAP` 分支 ⇒ 第 501 条被落账，
    /// 本条转红；把新目标判断写成「所有 grant 一律丢弃」⇒ 既有目标并入断言转红。
    #[tokio::test]
    async fn grant_drops_new_targets_at_cap_and_counts_into_monitor() {
        let store = store().await;
        let monitor = Arc::new(MetricsRegistry::new());
        store.set_monitor(monitor.clone());

        assert_eq!(AUTH_RECORDS_CAP, 500, "spec §8.2 的封顶值不得漂移");

        for i in 0..AUTH_RECORDS_CAP {
            let outcome = store
                .grant(
                    "com.wasmnest.test",
                    AuthResource::Fs,
                    &format!("/tmp/cap-dir-{i}"),
                    &ops(&["read"]),
                    AuthRecordSource::AlwaysAllow,
                )
                .await
                .unwrap();
            assert_eq!(outcome, GrantOutcome::Stored, "第 {i} 条在容量内，必须落账");
        }

        // 第 501 个**新**目标 → 丢弃 + 计数（放行判定不受影响，只是不留痕）
        let dropped = store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/cap-overflow",
                &ops(&["read"]),
                AuthRecordSource::AlwaysAllow,
            )
            .await
            .unwrap();
        assert_eq!(dropped, GrantOutcome::DroppedByCap, "超上限的新目标必须被丢弃");
        assert_eq!(
            store
                .records_for_match("com.wasmnest.test", AuthResource::Fs)
                .await
                .unwrap()
                .len(),
            AUTH_RECORDS_CAP,
            "丢弃后行数不得增长"
        );
        assert_eq!(
            monitor.snapshot()["plugins"]["com.wasmnest.test"]["authz"]["records_dropped"]
                .as_u64()
                .unwrap(),
            1,
            "丢弃必须进 core-monitor 计数（spec §8.2）"
        );

        // 既有目标并入：不新增行，因此不受上限影响（丢的是「用户已授权过的那条」的增量）
        let merged = store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/cap-dir-0",
                &ops(&["write"]),
                AuthRecordSource::AlwaysAllow,
            )
            .await
            .unwrap();
        assert_eq!(merged, GrantOutcome::Stored, "既有目标的并入不受上限影响");

        // 上限按 (应用, 资源) 分区：其他应用不受本应用封顶影响
        let other = store
            .grant(
                "com.wasmnest.other",
                AuthResource::Fs,
                "/tmp/cap-other",
                &ops(&["read"]),
                AuthRecordSource::User,
            )
            .await
            .unwrap();
        assert_eq!(other, GrantOutcome::Stored, "封顶不得跨应用生效");

        // deny 不经 grant、不封顶：拒绝记录是安全事实，任何情况下都不允许被丢弃
        store
            .deny(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/cap-deny",
                AuthRecordSource::UserDeny,
            )
            .await
            .unwrap();
        let rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(rows.len(), AUTH_RECORDS_CAP + 1, "deny 行必须照常落账");
        assert!(rows.iter().any(|r| r.effect == AUTH_EFFECT_DENY));
    }

    /// 撤销（spec §8.4）：删 allow + 落 deny；重复撤销幂等；deny 行 ops 为空
    #[tokio::test]
    async fn revoke_deletes_allow_and_records_deny_idempotently() {
        let store = store().await;
        store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/dir",
                &ops(&["read"]),
                AuthRecordSource::User,
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .revoke("com.wasmnest.test", AuthResource::Fs, "/tmp/dir")
                .await
                .unwrap(),
            1,
            "撤销应删掉那条 allow 记录"
        );
        let rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "撤销后只剩 deny 行");
        assert_eq!(rows[0].effect, AUTH_EFFECT_DENY);
        assert_eq!(rows[0].ops, Vec::<String>::new(), "deny 行不带操作集（整目标硬拒绝）");

        // 重复撤销：不堆行、返回 0（界面据此判断无需刷新）
        assert_eq!(
            store
                .revoke("com.wasmnest.test", AuthResource::Fs, "/tmp/dir")
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .records_for_match("com.wasmnest.test", AuthResource::Fs)
                .await
                .unwrap()
                .len(),
            1
        );
        let overview = store.overview("com.wasmnest.test", "T", Vec::new()).await.unwrap();
        assert_eq!(overview.records[0].source, "user_deny");
    }

    /// 第一方 home 形态撤销（07 票）：`~/` 前缀展开为 home 绝对路径再落账
    ///
    /// 判定链 `record_signals` 用 `strip_prefix` 匹配**规范绝对路径**——前端拿不到
    /// `$HOME`，传 `~/` 前缀；不展开直接落账的话 deny 行永远匹配不上（静默撤销无效）。
    /// 落账后从读模型断言的是绝对路径 + `user_deny` 溯源。
    #[tokio::test]
    async fn revoke_expands_tilde_home_prefix_for_fs() {
        let store = store().await;
        let home = dirs::home_dir().expect("测试环境应有 home_dir");
        store
            .revoke("com.wasmnest.agent-hub", AuthResource::Fs, "~/.agents")
            .await
            .unwrap();

        let rows = store
            .records_for_match("com.wasmnest.agent-hub", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].effect, AUTH_EFFECT_DENY);
        assert!(
            rows[0].target.starts_with(home.to_string_lossy().as_ref()),
            "deny 目标必须是展开后的绝对路径（判定链才能命中），实际：{}",
            rows[0].target
        );
        assert!(
            rows[0].target.ends_with("/.agents"),
            "`~/` 前缀应拼上清单相对段，实际：{}",
            rows[0].target
        );
    }

    /// network 资源的 target 是归一化 origin：`~/` 展开只对文件资源生效，网络原样落账
    #[tokio::test]
    async fn revoke_does_not_expand_tilde_for_network() {
        let store = store().await;
        store
            .revoke("com.wasmnest.test", AuthResource::Network, "https://api.github.com:443")
            .await
            .unwrap();

        let rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Network)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target, "https://api.github.com:443");
    }

    /// 移除 deny 记录 = 只删 deny，不动同目标的 allow（spec §8.4 的另一种出口）
    #[tokio::test]
    async fn remove_deny_only_touches_deny_rows() {
        let store = store().await;
        store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/dir",
                &ops(&["read"]),
                AuthRecordSource::User,
            )
            .await
            .unwrap();
        store
            .deny(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/dir",
                AuthRecordSource::UserDeny,
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .remove_deny("com.wasmnest.test", AuthResource::Fs, "/tmp/dir")
                .await
                .unwrap(),
            1
        );
        let rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "allow 行必须留下");
        assert_eq!(rows[0].effect, AUTH_EFFECT_ALLOW);
        assert_eq!(rows[0].ops, ops(&["read"]));

        // 再移除（没有 deny 了）→ 0，不报错
        assert_eq!(
            store
                .remove_deny("com.wasmnest.test", AuthResource::Fs, "/tmp/dir")
                .await
                .unwrap(),
            0
        );
    }

    /// 录入 deny 幂等：同目标重复落 deny 不堆行
    #[tokio::test]
    async fn deny_is_idempotent_per_target() {
        let store = store().await;
        for _ in 0..2 {
            store
                .deny(
                    "com.wasmnest.test",
                    AuthResource::Fs,
                    "/tmp/dir",
                    AuthRecordSource::UserDeny,
                )
                .await
                .unwrap();
        }
        let rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].effect, AUTH_EFFECT_DENY);
    }

    /// 判定读面按资源分区、不串应用
    #[tokio::test]
    async fn records_for_match_is_partitioned_by_resource() {
        let store = store().await;
        store
            .grant(
                "com.wasmnest.test",
                AuthResource::Fs,
                "/tmp/dir",
                &ops(&["read"]),
                AuthRecordSource::User,
            )
            .await
            .unwrap();
        store
            .grant(
                "com.wasmnest.test",
                AuthResource::Network,
                "https://api.x.com:443",
                &[],
                AuthRecordSource::User,
            )
            .await
            .unwrap();

        let fs_rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Fs)
            .await
            .unwrap();
        assert_eq!(fs_rows.len(), 1);
        assert_eq!(fs_rows[0].target, "/tmp/dir");
        let net_rows = store
            .records_for_match("com.wasmnest.test", AuthResource::Network)
            .await
            .unwrap();
        assert_eq!(net_rows.len(), 1);
        assert_eq!(net_rows[0].target, "https://api.x.com:443");
    }

    // ==================== 策略档位写面（票 03） ====================

    /// 档位 upsert：每个 (应用, 资源) 至多一行，重设只改值不堆行；两类资源互不串台
    ///
    /// 变异判据：upsert 退化成「每次 INSERT」（第二次设置就抛主键冲突 / 堆两行）、
    /// 或把 `resource` 写死成 fs（网络档位设置后读回 fs），本条各有一处转红。
    #[tokio::test]
    async fn set_strategy_upserts_one_row_per_resource_and_survives_reread() {
        let store = store().await;

        store
            .set_strategy("com.wasmnest.test", AuthResource::Fs, AuthStrategy::AlwaysAsk)
            .await
            .unwrap();
        assert_eq!(
            store.strategy("com.wasmnest.test", AuthResource::Fs).await.unwrap(),
            AuthStrategy::AlwaysAsk,
            "写入的档位必须原样读回（重启后仍生效 = 只依赖本表）"
        );
        assert_eq!(
            store.strategy("com.wasmnest.test", AuthResource::Network).await.unwrap(),
            AuthStrategy::Default,
            "另一资源不得被顺带改写（两类资源独立设置）"
        );

        // 重设同资源：改值不堆行
        store
            .set_strategy("com.wasmnest.test", AuthResource::Fs, AuthStrategy::Default)
            .await
            .unwrap();
        let rows: i64 = {
            let db = store.db.lock().expect("auth policy db lock poisoned");
            db.conn()
                .query_row(
                    "SELECT COUNT(*) FROM plugin_auth_policies WHERE plugin_id = ?1",
                    rusqlite::params!["com.wasmnest.test"],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(rows, 1, "每 (应用, 资源) 至多一行");
        assert_eq!(
            store.strategy("com.wasmnest.test", AuthResource::Fs).await.unwrap(),
            AuthStrategy::Default
        );
        // 别人的档位不得被波及
        assert_eq!(
            store.strategy("com.wasmnest.other", AuthResource::Fs).await.unwrap(),
            AuthStrategy::Default
        );
    }

    /// 写面不猜档位：未知 wire 值 `parse_wire` 返回 `None`（而读面兜底默认档）
    ///
    /// 两个方向的差是故意的：读面遇脏值要 fail-safe 到默认档，写面遇未知值必须
    /// 报错——`always_allow` 手误成别的拼写却静默存成 `default`，用户会以为设置
    /// 成功了。变异判据：把 `parse_wire` 的 `_ => None` 改成 `unwrap_or(Default)`，
    /// 本条转红。
    #[test]
    fn unknown_strategy_wire_value_is_rejected_by_write_face() {
        assert_eq!(AuthStrategy::parse_wire("always_ask"), Some(AuthStrategy::AlwaysAsk));
        assert_eq!(AuthStrategy::parse_wire("default"), Some(AuthStrategy::Default));
        assert_eq!(
            AuthStrategy::parse_wire("always_allow"),
            Some(AuthStrategy::AlwaysAllow)
        );
        for bad in ["always_allowed", "ALWAYS_ASK", "bypass", "", "default "] {
            assert_eq!(
                AuthStrategy::parse_wire(bad),
                None,
                "写入面不得把未知档位猜成任何一档: {bad}"
            );
            assert_eq!(
                AuthStrategy::parse(bad),
                AuthStrategy::Default,
                "读面同值必须回落默认档（fail-safe）"
            );
        }
    }

    /// C3：第一方免询问项按归属过滤导出（读模型要能回答「这个应用有哪些免询问特权」）
    ///
    /// 票 08/P0-2：产品清单出厂 lib，机制侧用**测试投影**（中性 plugin_id 字面量）
    /// 验证过滤逻辑——数据源形态 = `FsAuthChecker::first_party_trusted_dirs()` 输出。
    #[tokio::test]
    async fn first_party_dirs_are_exported_per_owner() {
        let store = store().await;

        let projection = vec![
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.agent-hub",
                kind: "home",
                value: ".agents",
            },
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.agent-hub",
                kind: "home",
                value: ".claude/skills",
            },
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.agent-hub",
                kind: "home",
                value: ".pi/agent/skills",
            },
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.agent-hub",
                kind: "home",
                value: ".wasmnest/agent-hub/runs",
            },
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.terminal-session",
                kind: "project-segment",
                value: ".claude",
            },
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.terminal-session",
                kind: "project-segment",
                value: ".codex",
            },
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.terminal-session",
                kind: "project-segment",
                value: ".pi",
            },
            crate::security::fs_auth::FirstPartyDirEntry {
                plugin_id: "test.terminal-session",
                kind: "project-segment",
                value: ".opencode",
            },
        ];

        let agent_hub = store
            .overview("test.agent-hub", "Agent Hub", projection.clone())
            .await
            .unwrap();
        assert_eq!(
            agent_hub
                .first_party_dirs
                .iter()
                .map(|d| (d.kind, d.value))
                .collect::<Vec<_>>(),
            vec![
                ("home", ".agents"),
                ("home", ".claude/skills"),
                ("home", ".pi/agent/skills"),
                ("home", ".wasmnest/agent-hub/runs"),
            ],
            "agent-hub 的内置免询问项是家目录前缀形态"
        );

        let session = store
            .overview("test.terminal-session", "Terminal Session", projection)
            .await
            .unwrap();
        assert_eq!(
            session
                .first_party_dirs
                .iter()
                .map(|d| (d.kind, d.value))
                .collect::<Vec<_>>(),
            vec![
                ("project-segment", ".claude"),
                ("project-segment", ".codex"),
                ("project-segment", ".pi"),
                ("project-segment", ".opencode"),
            ],
            "terminal-session 的是项目目录段形态"
        );

        let third_party = store.overview("com.wasmnest.test", "T", Vec::new()).await.unwrap();
        assert!(
            third_party.first_party_dirs.is_empty(),
            "不在第一方清单里的应用不得凭空获得免询问项"
        );
    }
}
