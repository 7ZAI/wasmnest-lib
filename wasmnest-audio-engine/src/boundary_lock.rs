//! 能力域形态边界锁（AGENTS §3.1 / §6.1 的机械执行面）
//!
//! 钉住四件在评审里容易被「顺手」破坏的形态事实：
//!
//! 1. **WIT 绑定只出现在接线层**：`bindgen!` 只许在 `src/plugin_binding.rs`（provider 侧
//!    绑定），引擎面（engine / format / ring / level / backend）不得反向依赖 WIT——
//!    否则默认形态再也摘不掉 wasm 依赖。
//! 2. **原生后端只出现在适配器文件**：`cpal::` 只许在 `src/cpal_backend.rs`，且 `lib.rs`
//!    必须以 `#[cfg(feature = "backend-cpal")]` 门控声明它（默认形态零原生音频依赖）。
//! 3. **清单零平台 / 产品依赖**：`tauri` / `actix` / `rusqlite` / 双端 SDK / wasm-core
//!    都不得进 `Cargo.toml`（host-kit 只许 optional，随 `common-host`）。
//! 4. **治理形态**：crate 根无 `tests/`（单测住 `src/` 内）、生产代码零产品插件 id。
//!
//! 锁只扫**非注释行**（`//` / `/*` / `*` 开头的行跳过）：解释「为什么不能这么做」的
//! 注释不算违规，AGENTS §6 要求注释讲清约束。

use std::path::{Path, PathBuf};

/// 本锁自身文件名（自带被禁 needle 字面量，必须自排除）
const SELF_LOCK_FILE: &str = "boundary_lock.rs";

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// 递归收集 `src/` 下全部 `.rs`（相对 `src/` 的路径 + 内容，跳过本锁）
fn src_files() -> Vec<(String, String)> {
    fn visit(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, base, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel == SELF_LOCK_FILE {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&path) {
                    out.push((rel, content));
                }
            }
        }
    }
    let base = crate_root().join("src");
    let mut out = Vec::new();
    visit(&base, &base, &mut out);
    out.sort();
    out
}

/// 非注释行（行首 `//` / `/*` / `*` 视为注释）
fn code_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    content.lines().enumerate().filter_map(|(idx, raw)| {
        let trimmed = raw.trim_start();
        let is_comment =
            trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*');
        (!is_comment).then_some((idx + 1, raw))
    })
}

/// B-001 正例（非空转哨兵）：扫描面确实覆盖了全部模块文件
///
/// 没有这条断言，下面的空集合断言会在 `src/` 路径写错时**静默通过**。
#[test]
fn scan_surface_is_not_vacuous() {
    let files = src_files();
    assert!(
        files.len() >= 10,
        "边界锁扫描面过窄（{} 个文件）——路径或过滤条件写错了？",
        files.len()
    );
    for required in ["lib.rs", "backend.rs", "engine.rs", "plugin_binding.rs"] {
        assert!(
            files.iter().any(|(rel, _)| rel == required),
            "扫描面缺 {required}（形态锁必须覆盖引擎面与接线层）"
        );
    }
    let backend = files
        .iter()
        .find(|(rel, _)| rel == "backend.rs")
        .map(|(_, content)| content)
        .expect("backend.rs 必须在扫描面内");
    assert!(
        backend.contains("pub trait CaptureBackend"),
        "backend.rs 丢掉了后端 trait——引擎的端口抽象是默认形态的前提"
    );
}

/// B-002 反例：`bindgen!` 只许出现在接线层（引擎面不得反向依赖 WIT）
#[test]
fn wit_binding_stays_in_the_binding_layer() {
    let mut violations = Vec::new();
    for (rel, content) in src_files() {
        if rel == "plugin_binding.rs" {
            continue;
        }
        for (line, raw) in code_lines(&content) {
            if raw.contains("bindgen!") {
                violations.push(format!("{rel}:{line}: {}", raw.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "WIT 绑定泄漏到引擎面（默认形态将无法摘掉 wasm 依赖）：\n{}",
        violations.join("\n")
    );

    let binding = src_files()
        .into_iter()
        .find(|(rel, _)| rel == "plugin_binding.rs")
        .map(|(_, content)| content)
        .expect("plugin_binding.rs 必须在扫描面内");
    assert!(
        binding.contains("bindgen!("),
        "接线层的 provider 侧绑定丢失（guest 会报「无该 import」）"
    );
}

/// B-003 反例：`cpal::` 只许出现在适配器文件，且 `lib.rs` 必须 feature 门控它
#[test]
fn native_backend_is_isolated_and_feature_gated() {
    let mut violations = Vec::new();
    for (rel, content) in src_files() {
        if rel == "cpal_backend.rs" {
            continue;
        }
        for (line, raw) in code_lines(&content) {
            if raw.contains("cpal::") {
                violations.push(format!("{rel}:{line}: {}", raw.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "cpal 依赖泄漏到适配器之外（默认形态必须零原生音频依赖）：\n{}",
        violations.join("\n")
    );

    let lib = src_files()
        .into_iter()
        .find(|(rel, _)| rel == "lib.rs")
        .map(|(_, content)| content)
        .expect("lib.rs 必须在扫描面内");
    let gated = lib.contains("#[cfg(feature = \"backend-cpal\")]\npub mod cpal_backend;");
    assert!(
        gated,
        "lib.rs 必须以 `#[cfg(feature = \"backend-cpal\")]` 门控 cpal_backend 模块"
    );
}

/// B-004 反例：清单零平台 / 产品 / 引擎内部依赖；host-kit 只许 optional
#[test]
fn manifest_has_no_platform_or_product_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    // Cargo.toml 的注释以 `#` 起笔（与 Rust 的 `#[...]` 属性不同），必须跳过——
    // 否则解释「为什么不能这么做」的注释会被当违规。
    let lines: Vec<(usize, &str)> = manifest
        .lines()
        .enumerate()
        .filter(|(_, raw)| !raw.trim_start().starts_with('#'))
        .map(|(idx, raw)| (idx + 1, raw))
        .collect();
    let mut violations = Vec::new();
    for needle in [
        "tauri",
        "actix",
        "rusqlite",
        "wasmnest-plugin-api",
        "wasmnest-wasm-core",
        "wasmnest-host-api-core",
        "wasmnest-server-base",
        "wasmnest-pty-engine",
    ] {
        for (line, raw) in &lines {
            if raw.contains(needle) {
                violations.push(format!("Cargo.toml:{line}: {}", raw.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "能力域清单出现平台 / 产品 / 引擎内部依赖：\n{}",
        violations.join("\n")
    );

    for (line, raw) in &lines {
        // 只判依赖声明行；feature 列表里的 `dep:wasmnest-host-kit` 不是依赖边
        if raw.trim_start().starts_with("wasmnest-host-kit") {
            assert!(
                raw.contains("optional = true"),
                "host-kit 只许 optional（随 common-host 装配），实得第 {line} 行：{}",
                raw.trim()
            );
        }
    }
}

/// B-005 反例：治理形态——crate 根无 `tests/` / `benches/` / `examples/`，且零 dev-deps
#[test]
fn governance_shape_has_no_crate_root_test_dirs_or_dev_deps() {
    let root = crate_root();
    for dir in ["tests", "benches", "examples"] {
        assert!(
            !root.join(dir).exists(),
            "crate 根不得有 {dir}/（单测必须住 src/ 内，见 AGENTS §6.4）"
        );
    }
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("[dev-dependencies]"),
        "不得新增 dev-dependencies（能力域自持测试面，见 AGENTS §6.2）"
    );
}

/// B-006 反例：生产代码零产品插件 id（`com.wasmnest.<产品段>`）
#[test]
fn production_code_has_no_product_plugin_ids() {
    let mut violations = Vec::new();
    for (rel, content) in src_files() {
        for (line, raw) in code_lines(&content) {
            if raw.contains("com.wasmnest.") {
                violations.push(format!("{rel}:{line}: {}", raw.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "能力域生产代码出现产品插件 id（业务语义归应用仓）：\n{}",
        violations.join("\n")
    );
}
