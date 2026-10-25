-- Schema for Claude Code Remote

-- 2026-09-22 认证记录下沉（v24）：`pairings` / `connection_history` / `session_configs`
-- 三表退役——认证记录（配对设备 / 连接历史）与会话配置真源已下沉
-- `com.wasmnest.bedcode` 插件私有库。2026-09-23 用户裁定不再兼容旧版本
-- 存量用户：宿主侧 legacy 迁移链（auth_records / quick_actions / session_db /
-- task_data 四迁移）整体退役，旧库滞留表不读不迁不清理。
-- 内核主库只保留配置与引擎原语。

-- App settings table
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Plugin key-value storage (per-plugin isolation)
CREATE TABLE IF NOT EXISTS plugin_storage (
    plugin_id TEXT NOT NULL,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plugin_id, key)
);

-- 密钥托管（v15 host-auth secret-store，按插件属主隔离）
-- 明文不落日志（宿主只记长度）；本表是凭据的唯一指定存储位（AGENTS.md §8
-- 「日志与存储中凭据只记长度不落明文」的例外/指定位——secret-store 的用途即
-- 可读回凭据，其余任何存储/日志位置禁止出现值本身）。
-- v24 曾追加：生物凭证公钥亦托管于此（key = `biometric:<fingerprint>`）；
-- v34（B-downsink）起生物公钥真源迁认证中心插件私有库 `auth_biometric_keys`，
-- 宿主不再持有任何生物凭证材料，旧 `biometric:*` 行由 `run_migrations` 幂等清扫。
CREATE TABLE IF NOT EXISTS plugin_secrets (
    plugin_id  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plugin_id, key)
);

-- 授权策略（2026-09-27 授权策略增强 / 票 01）：每个 (wasm 应用, 受管资源) 至多一行，回答
-- 「遇到授权记录未覆盖的目标时，要不要问用户」。三档 always_ask / default /
-- always_allow；缺行 = default。策略只决定是否询问，不放宽任何安全硬闸门
-- （manifest 声明门 / SSRF / 路径规范化 / 配额 / 属主隔离）。
-- 真源单点：.scratch/2026-09-27-host-authorization-policy/spec.md §5.1
CREATE TABLE IF NOT EXISTS plugin_auth_policies (
    plugin_id  TEXT NOT NULL,
    resource   TEXT NOT NULL,      -- 'fs' | 'network'
    strategy   TEXT NOT NULL,      -- 'always_ask' | 'default' | 'always_allow'
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (plugin_id, resource)
);

-- 授权记录（2026-09-27 授权策略增强 / 票 01）：每个 (wasm 应用, 资源, 目标) 至多一行，落账
-- 「某目标被允许或被拒绝」的运行期事实。fs 侧 target = 规范路径前缀，
-- ops 记生效操作集；network 侧 target = 归一化 origin（query / fragment
-- 绝不入库，AGENTS §8 凭据红线），prefix_match 标记 path 前缀收紧。
-- 与 fs 旧记录（plugin_storage.fs_granted_paths）的关系：本表命中即完全
-- 接管，未命中才回退旧扁平前缀表（spec §5.2）。
CREATE TABLE IF NOT EXISTS plugin_auth_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id    TEXT NOT NULL,
    resource     TEXT NOT NULL,     -- 'fs' | 'network'
    target       TEXT NOT NULL,     -- fs: 规范路径 | network: 'https://host:port[/prefix]'
    effect       TEXT NOT NULL,     -- 'allow' | 'deny'
    ops          TEXT NOT NULL DEFAULT '[]',  -- fs: ["read","write"]；network 恒 '[]'
    prefix_match INTEGER NOT NULL DEFAULT 0,  -- network: 1 表示 target 带 path 前缀
    source       TEXT NOT NULL,     -- 'user' | 'always_allow' | 'legacy' | 'user_deny'
    created_at   INTEGER NOT NULL
);

-- 读模型 / 判定共用的查表路径（(应用, 资源, 目标) 三元组）
CREATE INDEX IF NOT EXISTS idx_auth_records_lookup
  ON plugin_auth_records(plugin_id, resource, target);