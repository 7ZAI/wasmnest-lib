//! 命令目录模型：内建命令 + 插件命令的聚合、命名空间派生与冲突拒绝
//!
//! 目录是 CLI 侧唯一词汇面：前端帮助 / 补全从它生成，宿主侧解析以它为权威。
//! 插件命令经 manifest `contributes.commands[].cli` 段声明后由装配侧**拉取 manifest
//! 并在本crate 解析**（[`parse_cli_segment`]）再并入目录——内核对段只做 opaque
//! 透传，段的严格形状真源在本模块（fail-visible：畸形段点名命令 id）。

use crate::builtin::{BuiltinArg, BuiltinEntry, BUILT_IN, RESERVED_NAMESPACES};
use serde::{Deserialize, Serialize};

/// 参数类型（轻量 schema 的全部取值；json 类型承载任意结构化值）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgType {
    String,
    Number,
    Boolean,
    Json,
}

impl ArgType {
    /// 帮助 / manifest 段里的类型名（string / number / boolean / json）
    pub fn as_str(self) -> &'static str {
        match self {
            ArgType::String => "string",
            ArgType::Number => "number",
            ArgType::Boolean => "boolean",
            ArgType::Json => "json",
        }
    }

    /// 从 manifest 段的类型名解析（未知名显性报错）
    pub fn from_str_checked(s: &str) -> Result<Self, String> {
        match s {
            "string" => Ok(ArgType::String),
            "number" => Ok(ArgType::Number),
            "boolean" => Ok(ArgType::Boolean),
            "json" => Ok(ArgType::Json),
            other => Err(format!(
                "未知参数类型 {}（合法值：string / number / boolean / json）",
                other
            )),
        }
    }
}

/// 单个参数声明（位置参数按声明顺序填充；布尔参数可经 `--name` 旗标置位）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgSpec {
    pub name: String,
    pub ty: ArgType,
    /// 缺省 false：非必填参数缺省值未提供时不进参数集
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    /// 可选缺省值（提供则未传时落入参数集）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// 命令来源：内建（宿主管理命令）或插件（manifest 声明 + 既有 command 导出执行）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CommandKind {
    BuiltIn,
    /// 执行经装配侧 handler 路由到该插件该命令的既有 command 导出
    Plugin {
        plugin_id: String,
        command_id: String,
    },
}

/// 目录中的单条命令
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandSpec {
    /// 命令路径词元（如 `["plugin", "list"]` / `["system", "config", "get"]`）
    pub path: Vec<String>,
    pub kind: CommandKind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ArgSpec>,
    /// 隐藏命令（不进帮助与补全；仍可显式执行）
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    /// 人审声明镜像（呈现用；策略真源住宿主装配侧 handler）
    #[serde(
        rename = "confirmReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub confirm_reason: Option<String>,
}

/// 插件命令的 CLI 元数据（manifest cli 段解析产物）
#[derive(Debug, Clone, PartialEq)]
pub struct PluginCommandMeta {
    /// 对应 `contributes.commands[].id`（由装配侧带入，双处核对）
    pub command_id: String,
    pub title: String,
    pub namespace: Option<String>,
    pub help: Option<String>,
    pub hidden: bool,
    pub args: Vec<ArgSpec>,
}

/// 从 manifest 的单个 `contributes.commands[].cli` 段解析（fail-visible）
///
/// `command_id` 仅用于报错点名（段本身不含 id——id 在外层命令声明上）。
/// 严格形状：未知键、未知类型名、未知 visibility 取值一律报错——研究期收紧，
/// 漂移在目录构建时现形而不是静默忽略。
pub fn parse_cli_segment(
    command_id: &str,
    segment: &serde_json::Value,
) -> Result<PluginCommandMeta, String> {
    let Some(obj) = segment.as_object() else {
        return Err(format!("命令 {} 的 cli 段必须是对象", command_id));
    };
    for key in obj.keys() {
        if !matches!(key.as_str(), "namespace" | "help" | "visibility" | "args") {
            return Err(format!(
                "命令 {} 的 cli 段含未知键 {}（合法键：namespace / help / visibility / args）",
                command_id, key
            ));
        }
    }
    let namespace = match obj.get("namespace") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| format!("命令 {} 的 cli.namespace 必须是字符串", command_id))?
                .to_string(),
        ),
    };
    let help = match obj.get("help") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| format!("命令 {} 的 cli.help 必须是字符串", command_id))?
                .to_string(),
        ),
    };
    let hidden = match obj.get("visibility") {
        None => false,
        Some(serde_json::Value::String(s)) if s == "visible" => false,
        Some(serde_json::Value::String(s)) if s == "hidden" => true,
        Some(_) => {
            return Err(format!(
                "命令 {} 的 cli.visibility 只能是 visible 或 hidden",
                command_id
            ))
        }
    };
    let mut args = Vec::new();
    if let Some(list) = obj.get("args") {
        let Some(list) = list.as_array() else {
            return Err(format!("命令 {} 的 cli.args 必须是数组", command_id));
        };
        for (idx, item) in list.iter().enumerate() {
            args.push(parse_arg_spec(command_id, idx, item)?);
        }
    }
    Ok(PluginCommandMeta {
        command_id: command_id.to_string(),
        title: String::new(),
        namespace,
        help,
        hidden,
        args,
    })
}

/// 解析单个参数声明（cli 段内；idx 仅用于报错定位）
fn parse_arg_spec(
    command_id: &str,
    idx: usize,
    item: &serde_json::Value,
) -> Result<ArgSpec, String> {
    let Some(obj) = item.as_object() else {
        return Err(format!(
            "命令 {} 的 cli.args[{}] 必须是对象",
            command_id, idx
        ));
    };
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "name" | "type" | "required" | "default" | "help"
        ) {
            return Err(format!(
                "命令 {} 的 cli.args[{}] 含未知键 {}（合法键：name / type / required / default / help）",
                command_id, idx, key
            ));
        }
    }
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("命令 {} 的 cli.args[{}].name 必须是字符串", command_id, idx))?
        .to_string();
    let ty =
        ArgType::from_str_checked(obj.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
            format!("命令 {} 的 cli.args[{}].type 必须是字符串", command_id, idx)
        })?)?;
    let required = match obj.get("required") {
        None => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => {
            return Err(format!(
                "命令 {} 的 cli.args[{}].required 必须是布尔",
                command_id, idx
            ))
        }
    };
    let default = obj.get("default").cloned().filter(|v| !v.is_null());
    let help = match obj.get("help") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| {
                    format!("命令 {} 的 cli.args[{}].help 必须是字符串", command_id, idx)
                })?
                .to_string(),
        ),
    };
    Ok(ArgSpec {
        name,
        ty,
        required,
        default,
        help,
    })
}

/// 命令目录：内建表 + 已并入的插件命令
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    commands: Vec<CommandSpec>,
}

impl Catalog {
    /// 内建命令目录（词汇真源 = [`BUILT_IN`] 表）
    pub fn builtin() -> Self {
        let mut catalog = Catalog {
            commands: Vec::with_capacity(BUILT_IN.len()),
        };
        for entry in BUILT_IN {
            catalog.commands.push(builtin_entry_to_spec(entry));
        }
        catalog
    }

    /// 并入一个插件的命令（manifest 命令声明 + 已解析的 cli 段元数据）
    ///
    /// `titles` 与 `metas` 按下标配对（同一条命令声明的 title 与 cli 元数据）；
    /// 命令声明无 cli 段的（`metas[i]` 为 `None`）**不并入**（opt-in 裁决）。
    pub fn merge_plugin(
        &mut self,
        plugin_id: &str,
        titles: &[(String, String)],
        metas: &[Option<PluginCommandMeta>],
    ) -> Result<(), String> {
        if titles.len() != metas.len() {
            return Err(format!(
                "插件 {} 的命令声明数（{}）与 cli 元数据数（{}）不一致",
                plugin_id,
                titles.len(),
                metas.len()
            ));
        }
        for ((command_id, title), meta) in titles.iter().zip(metas.iter()) {
            let Some(meta) = meta else {
                continue; // 无 cli 段：不进 CLI 目录（opt-in）
            };
            if meta.command_id != *command_id {
                return Err(format!(
                    "插件 {} 的 cli 元数据命令 id {} 与命令声明 {} 不一致",
                    plugin_id, meta.command_id, command_id
                ));
            }
            let namespace = match &meta.namespace {
                Some(ns) => ns.clone(),
                None => derive_namespace(plugin_id)?.to_string(),
            };
            // 命令 id 约定以自身命名空间开头（`agent-hub.get-state`）：首段与命名空间
            // 相同时不重复拼接（`demo.run` → ["demo","run"] 而非 ["demo","demo","run"]）
            let mut path = vec![namespace.clone()];
            match command_id.strip_prefix(&format!("{}.", namespace)) {
                Some(rest) => path.extend(rest.split('.').map(str::to_string)),
                None => path.extend(command_id.split('.').map(str::to_string)),
            }
            let spec = CommandSpec {
                path,
                kind: CommandKind::Plugin {
                    plugin_id: plugin_id.to_string(),
                    command_id: command_id.clone(),
                },
                title: if title.is_empty() {
                    meta.title.clone()
                } else {
                    title.clone()
                },
                help: meta.help.clone(),
                args: meta.args.clone(),
                hidden: meta.hidden,
                confirm_reason: None,
            };
            self.insert_checked(spec)?;
        }
        Ok(())
    }

    /// 插入一条命令（路径冲突 / 命名空间越界显性拒绝）
    fn insert_checked(&mut self, spec: CommandSpec) -> Result<(), String> {
        let namespace = &spec.path[0];
        if RESERVED_NAMESPACES.contains(&namespace.as_str())
            && !matches!(spec.kind, CommandKind::BuiltIn)
        {
            return Err(format!(
                "命名空间 {} 是内建命令保留字，插件命令不得占用（命令 {:?}）",
                namespace, spec.path
            ));
        }
        if self
            .lookup(&spec.path.iter().map(String::as_str).collect::<Vec<_>>())
            .is_some()
        {
            return Err(format!("命令路径 {:?} 已存在，重复注册被拒绝", spec.path));
        }
        self.commands.push(spec);
        Ok(())
    }

    /// 精确路径查找
    pub fn lookup(&self, tokens: &[&str]) -> Option<&CommandSpec> {
        self.commands.iter().find(|spec| {
            spec.path
                .iter()
                .map(String::as_str)
                .eq(tokens.iter().copied())
        })
    }

    /// 全部命令（含隐藏）
    pub fn iter(&self) -> impl Iterator<Item = &CommandSpec> {
        self.commands.iter()
    }

    /// 以 `prefix` 为前缀的全部命令路径（未知命令建议 / 补全的候选源）
    /// 以 `prefix` 为前缀的**可见**命令路径（未知命令建议 / 补全的候选源；
    /// 隐藏命令不进用户面——显式执行仍走 [`lookup`](Self::lookup)）
    pub fn paths_starting_with(&self, prefix: &[&str]) -> Vec<Vec<String>> {
        self.commands
            .iter()
            .filter(|spec| !spec.hidden)
            .filter(|spec| {
                spec.path.len() > prefix.len()
                    && spec
                        .path
                        .iter()
                        .map(String::as_str)
                        .take(prefix.len())
                        .eq(prefix.iter().copied())
            })
            .map(|spec| spec.path.clone())
            .collect()
    }

    /// 目录的 JSON 形（wire `catalog` 操作的载荷；前端经反序列化重建目录做本地帮助）
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "commands": self.commands })
    }
}

/// 内建表条目 → 目录条目（静态表到 owned 模型的一次性转换）
fn builtin_entry_to_spec(entry: &BuiltinEntry) -> CommandSpec {
    CommandSpec {
        path: entry.path.iter().map(|s| s.to_string()).collect(),
        kind: CommandKind::BuiltIn,
        title: entry.title.to_string(),
        help: Some(entry.help.to_string()),
        args: entry
            .args
            .iter()
            .map(|a: &BuiltinArg| ArgSpec {
                name: a.name.to_string(),
                ty: a.ty,
                required: a.required,
                default: None,
                help: Some(a.help.to_string()),
            })
            .collect(),
        hidden: entry.hidden,
        confirm_reason: entry.confirmation.map(str::to_string),
    }
}

/// 从插件 id 派生命名空间（尾段：`com.example.demo` → `demo`）
///
/// 尾段必须非空且字符集 `[a-z0-9-]`（与总线属主判据的 id 字符集同口径），
/// 否则显性报错——空段会让两条命令坍缩到同一路径。
pub fn derive_namespace(plugin_id: &str) -> Result<&str, String> {
    let tail = plugin_id.rsplit('.').next().unwrap_or("");
    if tail.is_empty() {
        return Err(format!(
            "插件 id {} 无法派生命名空间（尾段为空）",
            plugin_id
        ));
    }
    if !tail
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "插件 id {} 的命名空间尾段 {} 含非法字符（合法字符集 [a-z0-9-]）",
            plugin_id, tail
        ));
    }
    Ok(tail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn derive_namespace_takes_last_segment() {
        assert_eq!(derive_namespace("com.example.demo").unwrap(), "demo");
        assert_eq!(derive_namespace("demo").unwrap(), "demo");
        assert!(derive_namespace("com.example.").is_err(), "空尾段必须报错");
        assert!(
            derive_namespace("com.example.Demo").is_err(),
            "大写必须报错"
        );
    }

    #[test]
    fn parse_cli_segment_full_shape() {
        let meta = parse_cli_segment(
            "demo.run",
            &json!({
                "namespace": "overridden",
                "help": "跑一把",
                "visibility": "hidden",
                "args": [
                    { "name": "path", "type": "string", "required": true, "help": "目标路径" },
                    { "name": "n", "type": "number", "default": 3 },
                    { "name": "on", "type": "boolean" },
                    { "name": "extra", "type": "json" }
                ]
            }),
        )
        .unwrap();
        assert_eq!(meta.namespace.as_deref(), Some("overridden"));
        assert!(meta.hidden);
        assert_eq!(meta.args.len(), 4);
        assert_eq!(meta.args[0].ty, ArgType::String);
        assert!(meta.args[0].required);
        assert_eq!(meta.args[1].default, Some(json!(3)));
        assert!(!meta.args[1].required);
    }

    #[test]
    fn parse_cli_segment_defaults_and_rejections() {
        // 空对象 = 全缺省（可见、无参数、自动命名空间）
        let meta = parse_cli_segment("demo.run", &json!({})).unwrap();
        assert!(!meta.hidden);
        assert!(meta.namespace.is_none());
        // 未知键 / 未知类型 / 未知 visibility 均显性报错并点名命令
        assert!(parse_cli_segment("demo.run", &json!({"typo": 1})).is_err());
        assert!(parse_cli_segment(
            "demo.run",
            &json!({ "args": [{ "name": "x", "type": "float" }] })
        )
        .is_err());
        assert!(parse_cli_segment("demo.run", &json!({ "visibility": "secret" })).is_err());
        // 非对象段
        assert!(parse_cli_segment("demo.run", &json!("x")).is_err());
    }

    #[test]
    fn merge_plugin_opt_in_and_namespace_rules() {
        let mut catalog = Catalog::builtin();
        let titles = vec![
            ("demo.run".to_string(), "跑一把".to_string()),
            ("demo.state".to_string(), "取状态".to_string()),
        ];
        let metas = vec![
            Some(
                parse_cli_segment(
                    "demo.run",
                    &json!({ "args": [
                { "name": "p", "type": "string", "required": true }
            ] }),
                )
                .unwrap(),
            ),
            None, // 无 cli 段：不进目录（opt-in）
        ];
        catalog
            .merge_plugin("com.example.demo", &titles, &metas)
            .unwrap();
        assert!(catalog.lookup(&["demo", "run"]).is_some());
        assert!(
            catalog.lookup(&["demo", "state"]).is_none(),
            "无 cli 段不得进目录"
        );
        // kind 落对插件身份
        match &catalog.lookup(&["demo", "run"]).unwrap().kind {
            CommandKind::Plugin {
                plugin_id,
                command_id,
            } => {
                assert_eq!(plugin_id, "com.example.demo");
                assert_eq!(command_id, "demo.run");
            }
            other => panic!("kind 应为 Plugin，实得 {:?}", other),
        }
        // 命令 id 含点 → 多词元路径
        assert!(catalog.lookup(&["demo", "run"]).is_some());
        // 保留命名空间拒绝（即使显式覆写）
        let hostile = parse_cli_segment("x", &json!({ "namespace": "plugin" })).unwrap();
        let err = catalog.merge_plugin(
            "com.example.evil",
            &[("x".to_string(), String::new())],
            &[Some(hostile)],
        );
        assert!(err.is_err(), "保留命名空间必须拒绝");
        // 重复路径拒绝
        let dup = parse_cli_segment("demo.run", &json!({})).unwrap();
        let err = catalog.merge_plugin(
            "com.example.demo",
            &[("demo.run".to_string(), String::new())],
            &[Some(dup)],
        );
        assert!(err.is_err(), "重复路径必须拒绝");
    }

    #[test]
    fn catalog_json_roundtrip_keeps_specs() {
        let mut catalog = Catalog::builtin();
        let meta = parse_cli_segment("demo.run", &json!({})).unwrap();
        catalog
            .merge_plugin(
                "com.example.demo",
                &[("demo.run".to_string(), "跑一把".to_string())],
                &[Some(meta)],
            )
            .unwrap();
        let value = catalog.to_json();
        let specs: Vec<CommandSpec> = serde_json::from_value(value["commands"].clone()).unwrap();
        assert_eq!(specs.len(), catalog.iter().count());
        assert!(specs
            .iter()
            .any(|s| s.path == vec!["plugin".to_string(), "list".to_string()]));
        assert!(specs
            .iter()
            .any(|s| s.path == vec!["demo".to_string(), "run".to_string()]
                && matches!(s.kind, CommandKind::Plugin { .. })));
    }
}
