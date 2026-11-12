//! 帮助与补全生成（渲染无关：输出纯文本行，前端自行上色 / 排版）
//!
//! 顶层帮助按首词元分组（内建组 + 插件命名空间并列）；命令帮助列用法 / 参数表 /
//! 人审标记。补全只给「下一个词元」候选——历史与光标逻辑住前端。

use crate::catalog::{ArgType, Catalog, CommandSpec};

/// 顶层帮助：`<bin> --help` 的全文
pub fn render_top(catalog: &Catalog, bin: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("用法：{} <命令组> <命令> [参数]\n\n命令：\n", bin));
    // 按首词元分组，组内按路径字典序稳定输出
    let mut groups: Vec<(String, Vec<&CommandSpec>)> = Vec::new();
    for spec in catalog.iter() {
        if spec.hidden {
            continue;
        }
        let top = spec.path[0].clone();
        match groups.iter_mut().find(|(t, _)| *t == top) {
            Some((_, list)) => list.push(spec),
            None => groups.push((top, vec![spec])),
        }
    }
    for (group, mut specs) in groups {
        out.push_str(&format!("  {}\n", group));
        specs.sort_by(|a, b| a.path.cmp(&b.path));
        for spec in specs {
            out.push_str(&format!("    {:<24} {}\n", spec.path.join(" "), spec.title));
        }
    }
    out.push_str(&format!("\n详情：{} <命令> --help\n", bin));
    out
}

/// 单命令帮助：`<bin> <命令> --help` 的全文
pub fn render_command(spec: &CommandSpec, bin: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n\n", spec.title));
    if let Some(help) = &spec.help {
        out.push_str(help);
        out.push_str("\n\n");
    }
    out.push_str(&format!("用法：{} {}", bin, spec.path.join(" ")));
    for arg in &spec.args {
        match (arg.required, arg.ty) {
            (true, ArgType::Boolean) => out.push_str(&format!(" --{}", arg.name)),
            (true, _) => out.push_str(&format!(" <{}>", arg.name)),
            (false, ArgType::Boolean) => out.push_str(&format!(" [--{}]", arg.name)),
            (false, _) => out.push_str(&format!(" [{}]", arg.name)),
        }
    }
    out.push('\n');
    if !spec.args.is_empty() {
        out.push_str("\n参数：\n");
        for arg in &spec.args {
            let meta = format!(
                "{}（{}{}）",
                arg.ty.as_str(),
                if arg.required { "必填" } else { "可选" },
                if arg.default.is_some() {
                    "，有缺省值"
                } else {
                    ""
                }
            );
            out.push_str(&format!(
                "  {:<12} {:<28} {}\n",
                arg.name,
                meta,
                arg.help.clone().unwrap_or_default()
            ));
        }
    }
    if let Some(reason) = &spec.confirm_reason {
        out.push_str(&format!("\n需要确认：{}\n", reason));
    }
    out
}

/// 补全候选：给定已输入词元，返回「下一个词元」的候选（去重、隐藏命令排除）
///
/// 命中到具体命令后给该命令的参数旗标（`--` 前缀）。
pub fn complete(catalog: &Catalog, tokens: &[String]) -> Vec<String> {
    let prefix: Vec<&str> = tokens.iter().map(String::as_str).collect();
    // 已完整命中命令：候选转参数旗标
    if let Some(spec) = catalog.lookup(&prefix) {
        return spec.args.iter().map(|a| format!("--{}", a.name)).collect();
    }
    let mut candidates: Vec<String> = Vec::new();
    for path in catalog.paths_starting_with(&prefix) {
        let next = path[prefix.len()].clone();
        if !candidates.contains(&next) {
            candidates.push(next);
        }
    }
    candidates.sort();
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog_with_plugin() -> Catalog {
        let mut c = Catalog::builtin();
        let meta = crate::catalog::parse_cli_segment(
            "demo.run",
            &json!({ "args": [{ "name": "path", "type": "string", "required": true }] }),
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

    #[test]
    fn top_help_groups_by_first_token() {
        let text = render_top(&catalog_with_plugin(), "wasmnest");
        // 每个分组的命令行都以「组名 缩进 + 路径」呈现
        assert!(text.contains("  plugin\n"));
        assert!(text.contains("  system\n"));
        assert!(text.contains("  bus\n"));
        assert!(text.contains("  demo\n"), "插件命名空间必须并列成组");
        assert!(text.contains("plugin list"));
        assert!(text.contains("demo run"));
    }

    #[test]
    fn hidden_commands_stay_out_of_help_and_completion() {
        let mut c = Catalog::builtin();
        let meta =
            crate::catalog::parse_cli_segment("demo.secret", &json!({ "visibility": "hidden" }))
                .unwrap();
        c.merge_plugin(
            "com.example.demo",
            &[("demo.secret".to_string(), String::new())],
            &[Some(meta)],
        )
        .unwrap();
        let top = render_top(&c, "wasmnest");
        assert!(!top.contains("demo secret"), "隐藏命令不得进顶层帮助");
        let completion = complete(&c, &["demo".to_string()]);
        assert!(
            !completion.contains(&"secret".to_string()),
            "隐藏命令不得进补全"
        );
        // 但仍可显式执行（lookup 命中）
        assert!(c.lookup(&["demo", "secret"]).is_some());
    }

    #[test]
    fn completion_walks_path_then_flags() {
        let c = catalog_with_plugin();
        // 组级：下一词元是组内命令
        assert_eq!(
            complete(&c, &["plugin".to_string()]),
            vec![
                "disable",
                "enable",
                "inspect",
                "install",
                "list",
                "reload",
                "uninstall"
            ]
        );
        // 顶层：下一词元是分组名
        let tops = complete(&c, &[]);
        assert!(tops.contains(&"plugin".to_string()));
        assert!(tops.contains(&"demo".to_string()));
        // 命令级：下一词元是参数旗标
        assert_eq!(
            complete(&c, &["demo".to_string(), "run".to_string()]),
            vec!["--path".to_string()]
        );
    }
}
