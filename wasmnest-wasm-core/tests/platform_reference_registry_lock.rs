//! 能力仓「零平台引用」登记锁（票 08 批次三 · 验收项 2）
//!
//! ## 判据
//!
//! 能力仓全文（源码 / 测试 / 构建清单 / 配置注释等一切文本文件）零命中
//! `wasmnest-desktop` / `wasmnest-mobile` 两个**平台仓目录名**——能力仓单克隆时
//! 这两个目录不存在，命中只可能是两类（都该修）：
//!
//! 1. **跨仓读取路径**：拆仓后必然失效的路径字面量（夹具产物 / SDK 源码 / 宿主
//!    源码扫描根）——如果静默消失，以它们为输入的锁会退化成空转（拆仓最危险的
//!    失效形态）；批次三已把全部这类读取归位平台仓或改为仓内自持。
//! 2. **过时注释引用**：拆仓前的位置描述（迁移、字段来源、真源落点）——改述为
//!    「桌面宿主 / 移动宿主」等端词汇，不携带跨仓路径。
//!
//! ## 扫描面
//!
//! 本 crate 的父目录（= 能力仓根）。排除 `target` / `.git` 与 `Cargo.lock`
//! （包管理器生成的锁文件不是源码面）、以及本文件自身（needle 字面量的定义处）。
//!
//! ## 登记豁免（唯一）
//!
//! 两条 **依赖名黑名单**：`dependency_direction_lock` 的判据本身要求 crate 的
//! 依赖清单不得含 `wasmnest-desktop`——那几个字面量是**被判对象**，不是对平台仓
//! 的引用（判据针对 Cargo.toml 依赖名，不产生任何源码读取）。豁免条目必须仍命中
//! （反向自检：豁免随删随清，防悬空条目把新违规静默放行）。

use std::path::{Path, PathBuf};

/// needle 集合（平台仓目录名；三仓布局见旧仓 `AGENTS.md` §0.1）
const NEEDLES: [&str; 2] = ["wasmnest-desktop", "wasmnest-mobile"];

/// 豁免登记表（仓根相对路径）——**唯一合法命中面**
const ALLOWLIST: &[&str] = &[
    // `FORBIDDEN_DEPS` 含 "wasmnest-desktop"：传输面 crate 依赖清单不得反向认识宿主
    "wasmnest-server-websocket/src/dependency_direction_lock.rs",
    "wasmnest-server-peer-net/src/dependency_direction_lock.rs",
];

/// 本锁文件名（needle 字面量的定义处，跳过避免自匹配）
const SELF_FILE_NAME: &str = "platform_reference_registry_lock.rs";

/// 能力仓根（本 crate 的父目录）
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("wasmnest-wasm-core 必有父目录（能力仓根）")
        .to_path_buf()
}

/// 递归收集待扫描文本文件（跳过构建产物与版本控制目录）
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git" | "node_modules" | "dist") {
                continue;
            }
            collect_files(&path, out);
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // 包管理器生成的锁文件不是源码面；本文件是 needle 定义处
        if name == "Cargo.lock" || name == SELF_FILE_NAME {
            continue;
        }
        out.push(path);
    }
}

#[test]
fn repo_has_no_platform_repo_reference_outside_registry() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_files(&root, &mut files);
    assert!(
        files.len() > 100,
        "扫描面异常（{} 个文件）——仓根定位错了？",
        files.len()
    );

    let mut hits: Vec<String> = Vec::new();
    for path in &files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        if !NEEDLES.iter().any(|n| content.contains(n)) {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        hits.push(rel);
    }
    hits.sort();

    let unexpected: Vec<&String> = hits
        .iter()
        .filter(|rel| !ALLOWLIST.contains(&rel.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "能力仓出现登记表外的平台仓引用（`wasmnest-desktop` / `wasmnest-mobile`）：\n{}\n\
         ——跨仓读取路径必须归位平台仓或改为仓内自持；过时注释一律改述为端词汇，\
         确需保留的字面量必须登记进 ALLOWLIST 并写明理由",
        unexpected
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );

    // 反向自检：豁免条目不得悬空（删掉黑名单后本锁必须能看出来，而不是因命中面
    // 变空而假绿）
    for allowed in ALLOWLIST {
        assert!(
            hits.iter().any(|rel| rel == allowed),
            "豁免条目 {allowed} 已不再命中平台仓字面量——请核实后删除（悬空条目会腐化\
             登记表，新违规将被它静默放行）"
        );
    }
}
