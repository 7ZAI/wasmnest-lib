//! mDNS 能力域的 wire 契约词汇（自持副本）
//!
//! ## 为什么自持（能力域脱绑 P2，2026-10-08）
//!
//! 能力域默认形态 = 纯引擎机制 + 端口抽象（零 WIT 依赖），任何宿主（桌面 / 移动端 /
//! 无头测试宿主）可直接引用。本 crate 原先直连桌面 SDK（`wasmnest-plugin-api`）的
//! wire 词汇因此改为**本域自持副本**：发现事件名（`mdns:found` / `mdns:lost`）与
//! 属主私有 topic 拼接规则（`<owner>::<name>`，`::` 分隔符——插件 id 字符集不含
//! `:`，故无歧义）。
//!
//! 都是纯 wire 契约（事件名 / 命名空间形状），不携带宿主机制——移进本 crate
//! 不改变任何依赖方向。桌面 SDK 原常量**不删除**（宿主 bus 面 / 插件侧仍有消费方），
//! 副本与原版逐字一致由平台仓漂移锁钉死（三仓拆分 L2/E2b 票 08 迁出本 crate：
//! `cross-end-tests/tests/wire_drift_locks.rs`）：任一侧漂移即红。
//!
//! 注意：本模块定义块的注释与桌面 SDK **逐字一致**（漂移锁按文本块比对），
//! 本地说明一律写在本模块文档与下方分隔注释里，不要改动定义块内注释。

// ==================== 以下 topic 词汇块与桌面 SDK host/bus.rs 逐字一致 ====================
// （漂移锁分别提取「行首为三个斜杠 + 空格 + 私有 topic 命名空间分隔符」至「行首为
// 三个斜杠 + 空格 + 互调请求道前缀」、以及「行首为三个斜杠 + 空格 + 构造属主私有
// topic」至「行首为三个斜杠 + 空格 + 解析 topic 的属主」之间的文本块比对，不要改动
// 块内任何字符——含注释。SDK 的 TOPIC_NS_SEP 与 owned_topic 定义之间隔着互调
// 前缀常量，本 crate 不复制那些宿主面常量，故锁拆两块。）

/// 私有 topic 命名空间分隔符（插件 id 字符集不含 `:`，故无歧义）
pub const TOPIC_NS_SEP: &str = "::";

/// 互调请求道前缀
// （上面这行是与桌面 SDK host/bus.rs 下一条注释的共享起笔文本，漂移锁用作
// TOPIC_NS_SEP 提取块的结束标记；本 crate 不复制 API_TOPIC_PREFIX 等互调前缀。）
/// 构造属主私有 topic：`<owner>::<name>`
pub fn owned_topic(owner: &str, name: &str) -> String {
    format!("{owner}{TOPIC_NS_SEP}{name}")
}

/// 解析 topic 的属主
// （上面这行是与桌面 SDK host/bus.rs 下一条注释的共享起笔文本，漂移锁用作 owned_topic
// 提取块的结束标记；本 crate 不复制 topic_owner / is_reply_topic 等宿主面助手。）

// ==================== 以下 mDNS 事件名常量块与桌面 SDK host/mdns.rs 逐字一致 ====================
// （漂移锁提取「行首为三个斜杠 + 空格 + 发现到新实例」至「行首为三个斜杠 + 空格 +
// 生成属主私有发现事件 topic」之间的文本块比对，不要改动块内任何字符——含注释。）

/// 发现到新实例（唯一的「新增/更新」事件）
pub const MDNS_FOUND: &str = "mdns:found";
/// 实例离开（TTL 过期 / byebye）
pub const MDNS_LOST: &str = "mdns:lost";

// 生成属主私有发现事件 topic
// （非 doc 注释：本文件末尾无被文档化的项，`///` 会成悬空 doc 编译错误；
// 平台仓漂移锁 cross-end-tests/tests/wire_drift_locks.rs 的本地结束标记同此文本。）