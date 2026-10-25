//! argv 解析：命令行词元 → 调用计划（路径 + 具名参数集）
//!
//! 规则（与目录 [`ArgSpec`](crate::catalog::ArgSpec) 声明对偶）：
//! - 命令路径 = argv 的**最长可匹配前缀**（`system config get k` 匹配三词元命令后
//!   余参归参数集）；
//! - 位置参数按声明顺序填充；`--name` 置位布尔参数；`--name value` / `--name=value`
//!   给非布尔参数赋值；
//! - 类型强制：number / boolean / json 的字面量解析失败即显性报错（点名参数）；
//! - 未传的必填参数报错；未传的可选参数落 `default`（声明提供时），否则不进参数集。
//!
//! 一切失败 fail-visible：未知命令给出「目录里真实存在」的建议路径（自洽单测钉住
//! 建议面无孤儿），未知旗标列出合法旗标名。

use crate::catalog::{ArgType, Catalog};
use serde_json::{Map, Value};

/// 解析产物：目标命令路径 + 具名参数集（JSON object）
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    pub path: Vec<String>,
    pub args: Map<String, Value>,
}

/// 解析失败（全部变体携带用户可读信息；Display 面向 CLI 前端直接展示）
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    UnknownCommand {
        input: Vec<String>,
        suggestions: Vec<String>,
    },
    UnknownFlag {
        name: String,
        known: Vec<String>,
    },
    MissingArg {
        name: String,
    },
    BadValue {
        arg: String,
        reason: String,
    },
    UnexpectedPositional {
        value: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnknownCommand { input, suggestions } => {
                write!(f, "未知命令 {}", input.join(" "))?;
                if !suggestions.is_empty() {
                    write!(f, "（可用：{}）", suggestions.join("、"))?;
                }
                Ok(())
            }
            ParseError::UnknownFlag { name, known } => write!(
                f,
                "未知参数 --{}（合法参数：{}）",
                name,
                if known.is_empty() {
                    "无".to_string()
                } else {
                    known.join("、")
                }
            ),
            ParseError::MissingArg { name } => write!(f, "缺少必填参数 {}", name),
            ParseError::BadValue { arg, reason } => {
                write!(f, "参数 {} 的值不合法：{}", arg, reason)
            }
            ParseError::UnexpectedPositional { value } => {
                write!(f, "多余参数 {}（该命令的全部参数已按声明填充）", value)
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// 解析 argv（不含程序名；wire 层原样透传 argv，宿主侧以本函数为权威）
pub fn parse(catalog: &Catalog, argv: &[String]) -> Result<Invocation, ParseError> {
    // 最长可匹配命令路径前缀
    let mut spec = None;
    let mut matched = 0usize;
    for take in (1..=argv.len()).rev() {
        let tokens: Vec<&str> = argv[..take].iter().map(String::as_str).collect();
        if let Some(found) = catalog.lookup(&tokens) {
            spec = Some(found);
            matched = take;
            break;
        }
    }
    let Some(spec) = spec else {
        let prefix: Vec<&str> = argv.iter().map(String::as_str).collect();
        let suggestions = suggest(catalog, &prefix);
        return Err(ParseError::UnknownCommand {
            input: argv.to_vec(),
            suggestions,
        });
    };

    let rest = &argv[matched..];
    let mut args: Map<String, Value> = Map::new();
    let mut positional_idx = 0usize;

    let mut i = 0usize;
    while i < rest.len() {
        let token = &rest[i];
        if let Some(flag) = token.strip_prefix("--") {
            let (name_part, inline_value) = match flag.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (flag.to_string(), None),
            };
            let declared = spec.args.iter().find(|a| a.name == name_part);
            let Some(arg) = declared else {
                return Err(ParseError::UnknownFlag {
                    name: name_part,
                    known: spec.args.iter().map(|a| a.name.clone()).collect(),
                });
            };
            let value = match (arg.ty, inline_value) {
                // 无值布尔旗标 = 置位（--on 等价 --on=true）
                (ArgType::Boolean, Some(v)) => Some(v),
                (ArgType::Boolean, None) => Some("true".to_string()),
                (_, Some(v)) => Some(v),
                (_, None) => {
                    // 取下一词元为值
                    i += 1;
                    rest.get(i).cloned()
                }
            };
            let Some(value) = value else {
                return Err(ParseError::BadValue {
                    arg: arg.name.clone(),
                    reason: "--flag 之后没有可取的值".to_string(),
                });
            };
            args.insert(arg.name.clone(), coerce(&arg.name, arg.ty, &value)?);
        } else {
            // 位置参数：按声明顺序的**单调游标**填进下一个未设置参数——被旗标
            // 赋值的参数跳过但不占位置坑位（否则过滤列表收缩会让游标越位）
            while positional_idx < spec.args.len()
                && args.contains_key(spec.args[positional_idx].name.as_str())
            {
                positional_idx += 1;
            }
            match spec.args.get(positional_idx) {
                Some(arg) => {
                    args.insert(arg.name.clone(), coerce(&arg.name, arg.ty, token)?);
                    positional_idx += 1;
                }
                None => {
                    return Err(ParseError::UnexpectedPositional {
                        value: token.clone(),
                    })
                }
            }
        }
        i += 1;
    }

    // 必填校验 + 缺省值落位
    for arg in &spec.args {
        if !args.contains_key(&arg.name) {
            if arg.required {
                return Err(ParseError::MissingArg {
                    name: arg.name.clone(),
                });
            }
            if let Some(default) = &arg.default {
                args.insert(arg.name.clone(), default.clone());
            }
        }
    }

    Ok(Invocation {
        path: spec.path.clone(),
        args,
    })
}

/// 类型强制（失败点名参数与原因）
fn coerce(name: &str, ty: ArgType, raw: &str) -> Result<Value, ParseError> {
    match ty {
        ArgType::String => Ok(Value::String(raw.to_string())),
        ArgType::Number => {
            // 先整型后浮点：CLI 字面量的整型保真（配置值等场景 7 ≠ 7.0 的 JSON 形状）
            raw.parse::<i64>()
                .map(Value::from)
                .or_else(|_| raw.parse::<f64>().map(Value::from))
                .map_err(|_| ParseError::BadValue {
                    arg: name.to_string(),
                    reason: format!("{} 不是合法数字", raw),
                })
        }
        ArgType::Boolean => match raw {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            other => Err(ParseError::BadValue {
                arg: name.to_string(),
                reason: format!("{} 不是合法布尔（true / false）", other),
            }),
        },
        ArgType::Json => serde_json::from_str(raw).map_err(|_| ParseError::BadValue {
            arg: name.to_string(),
            reason: format!("{} 不是合法 JSON 字面量", raw),
        }),
    }
}

/// 未知命令建议：真实存在的命令路径（按「有命中的最长前缀」回退取整组）
///
/// 建议面**只含真实路径**（自洽单测钉住）：`system nope` 建议全部 system 命令；
/// 连首词元都拼错时建议全目录。隐藏命令不进建议（与帮助 / 补全同口径）。
fn suggest(catalog: &Catalog, input: &[&str]) -> Vec<String> {
    for take in (0..=input.len()).rev() {
        let hits = catalog.paths_starting_with(&input[..take]);
        if !hits.is_empty() {
            return hits.into_iter().map(|p| p.join(" ")).collect();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> Catalog {
        let mut c = Catalog::builtin();
        let meta = crate::catalog::parse_cli_segment(
            "demo.run",
            &json!({ "args": [
                { "name": "path", "type": "string", "required": true },
                { "name": "n", "type": "number", "default": 3 },
                { "name": "on", "type": "boolean" },
                { "name": "extra", "type": "json" }
            ] }),
        )
        .unwrap();
        c.merge_plugin(
            "com.example.demo",
            &[("demo.run".to_string(), "跑一把".to_string())],
            &[Some(meta)],
        )
        .unwrap();
        c
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn positional_args_fill_in_declaration_order() {
        let invocation = parse(&catalog(), &argv(&["demo", "run", "/tmp/x"])).unwrap();
        assert_eq!(invocation.path, vec!["demo", "run"]);
        assert_eq!(invocation.args["path"], json!("/tmp/x"));
        assert_eq!(invocation.args["n"], json!(3), "缺省值必须落位");
        assert!(
            !invocation.args.contains_key("on"),
            "无可缺省的可选参数不进集"
        );
    }

    #[test]
    fn flags_and_inline_values() {
        let invocation = parse(
            &catalog(),
            &argv(&["demo", "run", "p", "--on", "--n", "7", "--extra={\"a\":1}"]),
        )
        .unwrap();
        assert_eq!(invocation.args["on"], json!(true));
        assert_eq!(invocation.args["n"], json!(7));
        assert_eq!(invocation.args["extra"], json!({"a": 1}));
    }

    #[test]
    fn longest_path_prefix_wins() {
        // system config get k：三词元命令 + 1 位置参数，而不是把 get 当参数
        let invocation = parse(&catalog(), &argv(&["system", "config", "get", "k"])).unwrap();
        assert_eq!(invocation.path, vec!["system", "config", "get"]);
        assert_eq!(invocation.args["key"], json!("k"));
    }

    #[test]
    fn fail_visible_matrix() {
        let c = catalog();
        // 未知命令（带真实建议）
        match parse(&c, &argv(&["system", "nope"])).unwrap_err() {
            ParseError::UnknownCommand { suggestions, .. } => {
                assert!(suggestions.iter().all(|s| s.contains("system")));
            }
            other => panic!("{}", other),
        }
        // 必填缺失
        assert_eq!(
            parse(&c, &argv(&["demo", "run"])).unwrap_err(),
            ParseError::MissingArg {
                name: "path".into()
            }
        );
        // 类型不合法（点名参数）
        assert!(matches!(
            parse(&c, &argv(&["demo", "run", "p", "--n", "abc"])).unwrap_err(),
            ParseError::BadValue { arg, .. } if arg == "n"
        ));
        assert!(matches!(
            parse(&c, &argv(&["demo", "run", "p", "--extra", "not-json"])).unwrap_err(),
            ParseError::BadValue { arg, .. } if arg == "extra"
        ));
        // 未知旗标（列出合法名）
        assert!(matches!(
            parse(&c, &argv(&["demo", "run", "p", "--zap"])).unwrap_err(),
            ParseError::UnknownFlag { name, .. } if name == "zap"
        ));
        // 多余位置参数（四个声明坑位填满后第五个即越位）
        assert!(matches!(
            parse(&c, &argv(&["demo", "run", "p", "1", "true", "{}", "zz"])).unwrap_err(),
            ParseError::UnexpectedPositional { .. }
        ));
        // 空命令行
        assert!(matches!(
            parse(&c, &[]).unwrap_err(),
            ParseError::UnknownCommand { .. }
        ));
    }
}
