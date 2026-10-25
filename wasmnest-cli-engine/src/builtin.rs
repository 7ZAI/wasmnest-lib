//! 内建（宿主管理）命令表——CLI 管理词汇的**真源**
//!
//! 表只声明目录面（路径 / 标题 / 帮助 / 参数 / 人审标记镜像）；执行体住宿主装配侧
//! 的共享 handler 模块。「哪些操作需要人审」的策略表同样住装配侧——本表的
//! `confirmation` 是帮助呈现用的声明镜像，二者由装配侧测试对齐（真源在那边）。

use crate::catalog::ArgType;

/// 内建命令的静态参数声明
pub struct BuiltinArg {
    pub name: &'static str,
    pub ty: ArgType,
    pub required: bool,
    pub help: &'static str,
}

/// 内建命令的静态目录条目
pub struct BuiltinEntry {
    /// 命令路径词元（首词元必须在 [`RESERVED_NAMESPACES`] 内——自洽单测钉住）
    pub path: &'static [&'static str],
    pub title: &'static str,
    pub help: &'static str,
    pub args: &'static [BuiltinArg],
    pub hidden: bool,
    /// 人审标记镜像（Some = 该操作执行前需经触发通道交互确认）
    pub confirmation: Option<&'static str>,
}

/// 内建命令保留命名空间（插件命令不得占用；自洽单测钉住与表的一致性）
pub const RESERVED_NAMESPACES: &[&str] = &["plugin", "system", "bus"];

/// 内建命令表（首期清单：插件生命周期 + 系统面 + 总线只读观察）
pub const BUILT_IN: &[BuiltinEntry] = &[
    BuiltinEntry {
        path: &["plugin", "list"],
        title: "列出已安装插件",
        help: "清单含插件 id、版本与启用状态",
        args: &[],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["plugin", "inspect"],
        title: "查看插件详情",
        help: "manifest、状态、权限与命令声明",
        args: &[BuiltinArg {
            name: "id",
            ty: ArgType::String,
            required: true,
            help: "插件 id",
        }],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["plugin", "install"],
        title: "安装插件",
        help: "从 zip 包安装；安装前经触发通道展示其申请的权限并逐项裁决",
        args: &[BuiltinArg {
            name: "zip",
            ty: ArgType::String,
            required: true,
            help: "插件包 zip 路径",
        }],
        hidden: false,
        confirmation: Some("安装将加载新插件代码并按其 manifest 授予权限"),
    },
    BuiltinEntry {
        path: &["plugin", "uninstall"],
        title: "卸载插件",
        help: "移除插件及其数据授权",
        args: &[BuiltinArg {
            name: "id",
            ty: ArgType::String,
            required: true,
            help: "插件 id",
        }],
        hidden: false,
        confirmation: Some("卸载将移除插件及其已授权数据"),
    },
    BuiltinEntry {
        path: &["plugin", "enable"],
        title: "启用插件",
        help: "激活并持久化启用状态",
        args: &[BuiltinArg {
            name: "id",
            ty: ArgType::String,
            required: true,
            help: "插件 id",
        }],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["plugin", "disable"],
        title: "停用插件",
        help: "停用并持久化停用状态",
        args: &[BuiltinArg {
            name: "id",
            ty: ArgType::String,
            required: true,
            help: "插件 id",
        }],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["plugin", "reload"],
        title: "热重载插件（仅开发形态）",
        help: "完整卸载-重载-激活循环；生产构建下由执行体显性报错（开发面语义）",
        args: &[BuiltinArg {
            name: "id",
            ty: ArgType::String,
            required: true,
            help: "插件 id",
        }],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["system", "info"],
        title: "宿主与运行时信息",
        help: "宿主实例模式（图形 / 无头）、版本与运行中插件概览",
        args: &[],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["system", "config", "get"],
        title: "读取宿主配置",
        help: "按键读宿主配置当前值",
        args: &[BuiltinArg {
            name: "key",
            ty: ArgType::String,
            required: true,
            help: "配置键",
        }],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["system", "config", "set"],
        title: "写入宿主配置",
        help: "按键写宿主配置（值以 JSON 字面量给出）",
        args: &[
            BuiltinArg {
                name: "key",
                ty: ArgType::String,
                required: true,
                help: "配置键",
            },
            BuiltinArg {
                name: "value",
                ty: ArgType::Json,
                required: true,
                help: "配置值（JSON 字面量，如 true / 3 / \"text\" / {\"a\":1}）",
            },
        ],
        hidden: false,
        confirmation: Some("修改宿主配置"),
    },
    BuiltinEntry {
        path: &["system", "logs", "tail"],
        title: "跟随宿主日志",
        help: "输出近期日志；--follow 持续跟随（事件帧推送）",
        args: &[BuiltinArg {
            name: "follow",
            ty: ArgType::Boolean,
            required: false,
            help: "持续跟随输出",
        }],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["system", "metrics"],
        title: "运行指标快照",
        help: "各插件内存 / 调用 / 燃料 / 生命周期计数快照（只读）",
        args: &[],
        hidden: false,
        confirmation: None,
    },
    BuiltinEntry {
        path: &["bus", "watch"],
        title: "跟随总线事件流",
        help: "实时输出总线投递（事件帧推送）；topics 给定时只看匹配项",
        args: &[BuiltinArg {
            name: "topics",
            ty: ArgType::Json,
            required: false,
            help: "topic 过滤数组（JSON，如 [\"task:*\"]）；缺省看全部公开 topic",
        }],
        hidden: false,
        confirmation: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// 表自洽：路径唯一、非空、首词元都在保留命名空间内（表 ↔ 保留字无漂移）
    #[test]
    fn builtin_paths_unique_and_namespaced() {
        let mut seen = std::collections::HashSet::new();
        for entry in BUILT_IN {
            assert!(!entry.path.is_empty(), "空路径：{}", entry.title);
            assert!(
                RESERVED_NAMESPACES.contains(&entry.path[0]),
                "命令 {:?} 的首词元不在保留命名空间内",
                entry.path
            );
            assert!(seen.insert(entry.path), "重复路径 {:?}", entry.path);
        }
    }

    /// 有确认标记的条目必须带理由（帮助呈现的完整性）
    #[test]
    fn confirmation_implies_reason() {
        for entry in BUILT_IN {
            if entry.confirmation.is_some() {
                assert!(
                    !entry.confirmation.unwrap().is_empty(),
                    "{:?} 的确认理由为空",
                    entry.path
                );
            }
        }
    }
}
