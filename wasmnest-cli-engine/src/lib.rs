//! WasmNest CLI 能力域机制骨架（纯契约 + 纯函数，零实现面；7ZAI/wasmnest-lib#9）
//!
//! ## 为什么是一个独立 crate（归属三问）
//!
//! 1. **机制还是产品语义**：命令目录聚合 / argv 解析 / 帮助与补全生成 / 本机 IPC 帧
//!    契约是可被任何前端复用的机制；具体命令的执行 handler（插件装卸、配置读写）
//!    是宿主职权装配，产品命令语义住应用仓——本 crate 只到「目录 + 契约」为止。
//! 2. **谁需要它**：CLI 前端与宿主两侧（装配侧两个消费方）需要**同一份**目录与帧
//!    类型（编译期绑定，无文本漂移面）；移动宿主不引用 = 零代价「只有骨架」。
//! 3. **可复用形态**：纯引擎 + 契约（无端口 trait 面的极简形态——目录与解析本身
//!    就是函数边界；执行端口刻意住装配侧，因为执行天然需要异步运行时与宿主状态）。
//!
//! ## 边界（防回接）
//!
//! - 零 WIT / 零 `wit/` 目录：插件命令复用内核既有 `command` 导出与分发面，本域
//!   不新增 guest 契约（一期零契约变更）；
//! - 零 wasm / 零 tokio / 零端装配依赖：`cargo tree` 出现 wasmtime / wit-bindgen /
//!   inventory / wasmnest-host-kit 即违规（受无头探针默认形态门禁长期钉住）；
//! - 内部依赖仅 server-base（错误信封），且关 `tauri-compat`；
//! - 内建命令表是**词汇真源**，但「哪些操作需要人审」的策略表住装配侧 handler——
//!   目录里的确认标记只是帮助呈现用的声明镜像。
//!
//! ## 骨架语义（fail-visible）
//!
//! 装配侧端口缺席（目录源 / 执行体 / 确认应答方不在场）时一切显性失败：未知命令
//! 带建议报错、畸形 manifest cli 段点名命令 id 报错、wire 帧违例整行拒绝——没有
//! 「查不到就返回空」的静默降级路径。

pub mod builtin;
pub mod catalog;
pub mod help;
pub mod parse;
pub mod wire;

pub use catalog::{ArgSpec, ArgType, Catalog, CommandKind, CommandSpec, PluginCommandMeta};
pub use parse::{Invocation, ParseError};
pub use wire::{Decision, Frame, RequestOp, WireError};

#[cfg(test)]
mod drift_tests {
    //! 自洽漂移单测（AGENTS §6.4：新增能力域必须自持）——表 ↔ 解析器 ↔ 帮助三面
    //! 互为对偶锁：任何一面新增 / 改名而漏配另一面，这里即红。
    use super::*;

    /// 每个内建命令的参数声明都能被解析器自恰解析（表 ↔ 解析器无孤儿）
    #[test]
    fn every_builtin_parses_own_arg_declaration() {
        let catalog = Catalog::builtin();
        for spec in catalog.iter() {
            // 按声明合成一条最小 argv（必填参数给各类型样例值），解析必须成功且
            // 覆盖全部必填名
            let mut argv: Vec<String> = spec.path.iter().cloned().collect();
            let mut required_names = Vec::new();
            for arg in &spec.args {
                if !arg.required {
                    continue;
                }
                required_names.push(arg.name.clone());
                match arg.ty {
                    ArgType::String => argv.push("sample".to_string()),
                    ArgType::Number => argv.push("1".to_string()),
                    ArgType::Boolean => argv.push(format!("--{}", arg.name)),
                    ArgType::Json => argv.push("{}".to_string()),
                }
            }
            let invocation =
                parse::parse(&catalog, &argv).unwrap_or_else(|e| panic!("{:?}: {}", spec.path, e));
            assert_eq!(&invocation.path, &spec.path, "{:?}", spec.path);
            for name in required_names {
                assert!(
                    invocation.args.contains_key(&name),
                    "{:?} 缺必填参数 {}",
                    spec.path,
                    name
                );
            }
        }
    }

    /// 帮助输出恰好覆盖全部可见内建命令（表 ↔ 帮助无孤儿，双向）
    #[test]
    fn top_help_covers_every_visible_builtin() {
        let catalog = Catalog::builtin();
        let text = help::render_top(&catalog, "wasmnest");
        for spec in catalog.iter() {
            let path_line = spec.path.join(" ");
            if spec.hidden {
                assert!(
                    !text.contains(&path_line),
                    "隐藏命令 {:?} 不得出现在顶层帮助",
                    spec.path
                );
            } else {
                assert!(
                    text.lines().any(|l| l.trim_start().starts_with(&path_line)),
                    "可见命令 {:?} 未被顶层帮助覆盖",
                    spec.path
                );
            }
        }
    }

    /// 命令帮助必须列出每个参数名与确认标记（漏配即红）
    #[test]
    fn command_help_lists_every_arg_and_confirmation() {
        let catalog = Catalog::builtin();
        for spec in catalog.iter() {
            let text = help::render_command(spec, "wasmnest");
            for arg in &spec.args {
                assert!(
                    text.contains(&arg.name),
                    "{:?} 的参数 {} 未进命令帮助",
                    spec.path,
                    arg.name
                );
            }
            assert_eq!(
                text.contains("需要确认"),
                spec.confirm_reason.is_some(),
                "{:?} 的确认标记呈现不一致",
                spec.path
            );
        }
    }

    /// 未知子命令的建议必须指向真实存在的命令路径（建议面无孤儿）
    #[test]
    fn unknown_subcommand_suggestions_are_real_paths() {
        let catalog = Catalog::builtin();
        let err = parse::parse(&catalog, &["system".into(), "nope".into()]).unwrap_err();
        match err {
            ParseError::UnknownCommand { suggestions, .. } => {
                assert!(!suggestions.is_empty(), "system 组必须有建议");
                for s in &suggestions {
                    let tokens: Vec<&str> = s.split(' ').collect();
                    assert!(
                        catalog.lookup(&tokens).is_some(),
                        "建议 {} 不是真实命令路径",
                        s
                    );
                }
            }
            other => panic!("应为 UnknownCommand，实得 {}", other),
        }
    }
}
