//! 边界锁：生产源码零平台 / SDK / wasm-core / 机制内核 / WIT 绑定层，
//! 生产依赖清单零内部 crate、零自建 mDNS
//!
//! ## 这个 crate 的存在意义就是那条边界（AGENTS §0 路径基准 / §5 无业务内核）
//!
//! `wasmnest-p2p-engine` 是**通用能力 crate**：默认形态 = 纯引擎 + 端口抽象。
//! 它的可复用性不是文档承诺，而是靠本锁钉住的不变量：
//!
//! 1. **源码面**：生产代码里不得出现平台类型（`tauri::`）、任一端 SDK
//!    （`wasmnest_plugin_api*`）、任一端 wasm-core（`wasmnest_wasm_core*`）、机制内核
//!    （`wasmnest_host_kit`）、WIT 绑定层标记（`bindgen!` / `inventory::submit`）。
//!    一旦出现，这个 crate 就退化成「某个宿主的实现」，通用性名存实亡——而退化是
//!    编译能过、测试全绿的形态，只有静态锁能挡住。
//! 2. **依赖面**：`[dependencies]` 段零 `wasmnest*` 内部 crate；且必须钉住机制级依赖
//!    仍在场（清单被误删 / 被换成平台依赖时，红的是这条）。
//! 3. **发现红线**：不得直接依赖任何 mDNS 实现（`mdns-sd` / `libp2p-mdns`）——
//!    mDNS 单 listener 不变量要求发现只经 `wasmnest-discovery-engine` 共享守护
//!    由宿主端口注入（lib.rs 头注「发现红线」）。
//!
//! 附带钉治理形态（与桌面 `capability_crates_unit_tests_only` 同判据，本 crate 就地
//! 自查，避免「锁在别的 crate 里、本 crate 结构退化无人发现」）：
//! **单测必须在 `src/` 内、crate 根不得有 `tests/` `benches/` `examples/` 或
//! `[[test]]` 段**。
//!
//! ## 扫描面推导（不靠手写名单）
//!
//! 生产文件 = `src/**/*.rs` 减去「测试专用文件」，测试专用文件由**声明处**推导：
//! ① 路径含 `tests` 段的目录化测试子树；② 任何被 `#[cfg(test)] mod <name>;` 声明的
//! 模块（本锁自身）。本 crate 的用例全部**内联**在模块尾的 `#[cfg(test)] mod tests`
//! 区（prod 扫描在 `#[cfg(test)]` 行截断），无目录化测试文件。
//! 走声明处而非手写文件名，是为了让「新增一个 cfg(test) 模块却忘了从扫描面排除」
//! 不可能发生——它会自动进排除面，而反之（把生产模块改成 cfg(test) 藏起来）会由
//! 下方的覆盖面断言打红。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// ==================== 判据常量 ====================

/// 本 crate 生产源码文件数下限（实测 7：lib + error + identity_bridge + admission +
/// ports + stream_proto + engine；下调留余量）。防「枚举失败 / 路径写错 ⇒ 扫描面
/// 空转而锁照绿」。
const MIN_PROD_FILES: usize = 6;

/// 哨兵文件（必须被枚举到，否则扫描器空转）
const SENTINEL_FILES: &[&str] = &[
    "src/lib.rs",
    "src/engine.rs",
    "src/ports.rs",
    "src/identity_bridge.rs",
    "src/admission.rs",
    "src/stream_proto.rs",
    "src/error.rs",
];

/// 不得出现在生产源码里的**路径形**针脚（左边界匹配即可：右边界必然是标识符）
///
/// 全部是可编译的回接形态。散文里提及类型名（散文本身已被剥注释，见
/// [`strip_line_comments`]）不算命中。
const FORBIDDEN_SOURCE_PREFIXES: &[&str] = &[
    "tauri::",
    "wasmnest_plugin_api",
    "wasmnest_wasm_core",
    "wasmnest_host_kit",
    "bindgen!",
    "inventory::submit",
    "inventory::collect",
    "wasmtime::",
    "wit_bindgen::",
];

/// 不得出现在生产源码里的**宿主类型名**（词边界匹配；需类型化引用才会命中，
/// 例如 `MessageBus::new` / `WasmPluginState` —— 引擎自持的句柄表不得借用宿主类型）
const FORBIDDEN_HOST_TYPES: &[&str] = &[
    "MessageBus",
    "WasmPluginState",
    "WasmHostContext",
    "PluginStorage",
    "HostEnginePorts",
];

/// 生产依赖清单里必须仍在场的机制级依赖（缺项 = 依赖面被误改）
const REQUIRED_DEPS: &[&str] = &[
    "libp2p",
    "tokio",
    "futures-util",
    "sha2",
    "hex",
    "async-trait",
    "tracing",
    "thiserror",
];

/// 生产依赖清单里不得出现的平台 / 传输栈 / 越线发现实现（依赖名级别判定）
const FORBIDDEN_DEPS: &[&str] = &[
    "tauri",
    "actix",
    "actix-web",
    "wasmtime",
    "wit-bindgen",
    "inventory",
    // 发现红线：mDNS 只经共享守护端口注入，本 crate 不得自建实现
    "mdns-sd",
    "libp2p-mdns",
];

/// 内部 crate 的命名前缀（生产与 dev 段都不得出现）
const INTERNAL_CRATE_PREFIX: &str = "wasmnest";

/// crate 根下禁止存在的可编译对外测试面（cargo 自动发现即编译成独立测试二进制）
const FORBIDDEN_CRATE_TEST_DIRS: &[&str] = &["tests", "benches", "examples"];

/// 本 crate 的源码文件数下限（枚举用，与生产面下限分开；7 生产 + 本锁）
const MIN_ALL_FILES: usize = 8;

// ==================== 路径与枚举 ====================

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// 递归枚举 `src/**/*.rs`，返回相对 crate 根的正斜杠路径
fn collect_rs_files(dir: &Path, out: &mut Vec<String>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("边界锁无法枚举 {}：{e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("边界锁 read_dir 条目错误：{e}"))
            .path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(
                path.strip_prefix(crate_root())
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

/// 全部源码文件（相对路径，排序）
fn all_rs_files() -> Vec<String> {
    let mut out = Vec::new();
    collect_rs_files(&crate_root().join("src"), &mut out);
    out.sort();
    out
}

/// 抽出被 `#[cfg(test)] mod <name>;` 声明的模块名（扫描面推导用）
///
/// 逐行状态机：`#[cfg(...test...)]` 之后的**紧邻** `mod <name>;` 计入。
/// 「紧邻」是刻意的：跨过任意多行再匹配会让 `#[cfg(test)]` 与其后的
/// `mod <other>` 错配，把生产模块误排除出扫描面（静默失守）。
fn cfg_test_modules(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut pending = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("#[cfg(") {
            pending = t.contains("test");
            continue;
        }
        if pending {
            if let Some(rest) = t.strip_prefix("mod ") {
                if let Some(name) = rest.strip_suffix(';') {
                    out.insert(name.trim().to_string());
                }
            }
            // 非 `mod …;` 行同样终止挂起状态（属性组 / 文档注释之后的实现行）
            pending = false;
        }
    }
    out
}

/// 该文件是否测试专用（路径含 `tests` 段，或其模块名被 `#[cfg(test)] mod` 声明）
fn is_test_only_file(rel: &str, cfg_test_mods: &BTreeSet<String>) -> bool {
    if rel.split('/').any(|seg| seg == "tests") {
        return true;
    }
    let stem = rel
        .rsplit('/')
        .next()
        .and_then(|f| f.strip_suffix(".rs"))
        .unwrap_or("");
    cfg_test_mods.contains(stem)
}

/// 剥掉一行里的行注释（引号感知）
///
/// 引号感知是**必须**的：朴素实现会在 `format!("ws://…")` 这类行上把 `//` 之后
/// 全丢，而本 crate 恰恰满是 `ws://` 字面量——朴素版会把这些行的后半段（含可能的
/// 真命中）整段跳过，锁被静默解除。逐字节扫描对 UTF-8 安全（多字节续字节 ≥ 0x80，
/// 不会与 ASCII 引号混淆）。
///
/// 块注释 `/* … */` **不剥**（含跨行）：块注释里的字面量会照常报出（假警报），
/// 而剥错会静默失守——宁吵不静守。
fn strip_line_comments(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let (mut i, mut in_str, mut in_char, mut escaped) = (0usize, false, false, false);
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            out.push(b as char);
            escaped = false;
            i += 1;
            continue;
        }
        match b {
            b'\\' if in_str || in_char => {
                out.push(b as char);
                escaped = true;
                i += 1;
            }
            b'"' if !in_char => {
                in_str = !in_str;
                out.push(b as char);
                i += 1;
            }
            b'\'' if !in_str => {
                in_char = !in_char;
                out.push(b as char);
                i += 1;
            }
            b'/' if !in_str && !in_char && i + 1 < bytes.len() && bytes[i + 1] == b'/' => break,
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// 该行是否开启 `#[cfg(…test…)]` 区
fn opens_cfg_test(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("#[cfg(") && t.contains("test")
}

/// 一个文件的生产代码（路径 + 剥注释后的生产行）
struct ProdSource {
    rel: String,
    lines: Vec<String>,
}

/// 取一个文件的生产代码（跳过测试区与注释）
fn prod_source(rel: &str, crate_test_mods: &BTreeSet<String>) -> Option<ProdSource> {
    if is_test_only_file(rel, crate_test_mods) {
        return None;
    }
    let text = fs::read_to_string(crate_root().join(rel))
        .unwrap_or_else(|e| panic!("边界锁读不到 {rel}：{e}"));
    let mut lines = Vec::new();
    for line in text.lines() {
        if opens_cfg_test(line) {
            break;
        }
        lines.push(strip_line_comments(line));
    }
    Some(ProdSource {
        rel: rel.to_string(),
        lines,
    })
}

// ==================== 匹配判据 ====================

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 词边界命中（crate 名 / 类型名是裸标识符，两侧都不得是标识符字符）
fn find_word_hits<'a>(text: &'a str, needle: &'a str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = text[search..].find(needle) {
        let start = search + rel;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = !bytes.get(end).is_some_and(|&b| is_ident_byte(b));
        if before_ok && after_ok {
            out.push(start);
        }
        search = start + 1;
    }
    out
}

/// 左边界命中（路径形针脚；右边界必然紧跟标识符，加右判定会恒假绿——见 peer-net 锁）
fn find_prefix_hits<'a>(text: &'a str, prefix: &'a str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(off) = text[search..].find(prefix) {
        let start = search + off;
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        if before_ok {
            out.push(start);
        }
        search = start + 1;
    }
    out
}

/// 源码违规命中（`(文件, 行号, 行内容)`）
fn find_source_violations(prod: &[ProdSource]) -> Vec<(String, usize, String)> {
    let mut hits = Vec::new();
    for src in prod {
        for (idx, line) in src.lines.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut matched: Vec<&str> = Vec::new();
            for prefix in FORBIDDEN_SOURCE_PREFIXES {
                if !find_prefix_hits(line, prefix).is_empty() {
                    matched.push(prefix);
                }
            }
            for ty in FORBIDDEN_HOST_TYPES {
                if !find_word_hits(line, ty).is_empty() {
                    matched.push(ty);
                }
            }
            for m in matched {
                hits.push((src.rel.clone(), idx + 1, format!("[{m}] {}", line.trim())));
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

// ==================== 清单解析 ====================

/// 段头归一化：`[target.<cfg>.<段>]` 折叠成 `[<段>]`
///
/// **平台条件不改变 dev / prod 归属**——一条 `[target.'cfg(windows)'.dependencies]`
/// 的内部 crate 边同样是越线形态，故按段名归一化，不因挂在 `[target.…]` 下就放过。
/// 形状不完整（缺段名）一律 panic：未覆盖写法猜着解析等于静默漏判。
fn normalize_target_header(inner: &str) -> Option<(String, Option<String>)> {
    let parts: Vec<&str> = inner.split('.').collect();
    if parts.len() < 3 {
        panic!(
            "`[{inner}]` 是形状不完整的平台条件段头（应为 `[target.<cfg>.<段>]`）：\
             本解析按段名判定依赖归属，缺段名会把该段下的依赖静默丢掉——\
             请升级本解析后再移开门禁，而不是让锁失守"
        );
    }
    Some((parts[2].to_string(), parts.get(3).map(|s| s.to_string())))
}

/// 解析行首 TOML 段头 → `(段种类, 子键)`
fn section_header(line: &str) -> Option<(String, Option<String>)> {
    if !line.starts_with('[') || !line.ends_with(']') {
        return None;
    }
    let inner = line[1..line.len() - 1].trim();
    let inner = if inner.starts_with('[') && inner.ends_with(']') {
        inner[1..inner.len() - 1].trim()
    } else {
        inner
    };
    if inner == "target" || inner.starts_with("target.") {
        return normalize_target_header(inner);
    }
    match inner.split_once('.') {
        Some((kind, sub)) => Some((kind.to_string(), Some(sub.to_string()))),
        None => Some((inner.to_string(), None)),
    }
}

/// 取清单某依赖段的条目名集合（点号表形式 `[dev-dependencies.x]` 也计入）
///
/// **按行切段**：段内值常含 `features = ["derive"]` 这类方括号，用「下一个 `[`」
/// 找段尾会把清单截断在该行上。条目行的花括号必须自身配平——否则是折行声明，
/// 续行会被误收成第二个条目名（静默失守），故直接打红。
fn section_deps(manifest: &str, section: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_section = false;
    for (idx, line) in manifest.lines().enumerate() {
        let t = line.trim();
        if let Some((kind, sub)) = section_header(t) {
            if kind == section {
                match sub {
                    Some(dep_name) => {
                        out.insert(dep_name);
                        in_section = false;
                    }
                    None => in_section = true,
                }
            } else {
                in_section = false;
            }
            continue;
        }
        if !in_section || t.is_empty() || t.starts_with('#') {
            continue;
        }
        assert_eq!(
            t.matches('{').count(),
            t.matches('}').count(),
            "第 {} 行 `{t}` 花括号不配平：依赖声明被折行，本锁按行取条目名会把续行误收成第二个条目名",
            idx + 1
        );
        let key = t.split('=').next().unwrap_or("").trim();
        assert!(
            !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'),
            "第 {} 行 `{t}` 不是可解析的依赖条目名——多行声明等未覆盖写法必须报错，不能猜",
            idx + 1
        );
        out.insert(key.to_string());
    }
    out
}

fn read_manifest() -> String {
    fs::read_to_string(crate_root().join("Cargo.toml"))
        .unwrap_or_else(|e| panic!("边界锁读不到 Cargo.toml（扫描器空转）：{e}"))
}

fn format_hits(hits: &[(String, usize, String)]) -> String {
    hits.iter()
        .map(|(f, l, c)| format!("  {f}:{l}: {c}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ==================== 用例 ====================

/// B-1｜判据自身的契约例（防匹配规则被改坏后假绿 + 防扫描器空转）
#[test]
fn boundary_lock_scanners_are_not_vacuous() {
    // ---- 剥注释：引号内的 `//` 不是注释（本 crate 满是 `ws://` 字面量）----
    assert_eq!(
        strip_line_comments(r#"let u = "ws://127.0.0.1:1/";"#),
        r#"let u = "ws://127.0.0.1:1/";"#
    );
    assert_eq!(
        strip_line_comments("let a = 1; // tauri::AppHandle"),
        "let a = 1; "
    );
    // 原始字符串内 `//` 会被切断（保守方向：错在锁红而非锁绿），此处置为已知边界
    assert_eq!(
        strip_line_comments(r#"let s = r"ws://x";"#),
        r#"let s = r"ws://x";"#
    );

    // ---- cfg(test) 区截断：真命中必须落在测试区之后才算被排除 ----
    let text = "let a = 1;\n#[cfg(test)]\nuse tauri::AppHandle;\n";
    let mut prod = Vec::new();
    for line in text.lines() {
        if opens_cfg_test(line) {
            break;
        }
        prod.push(strip_line_comments(line));
    }
    assert_eq!(
        prod,
        vec!["let a = 1;"],
        "cfg(test) 区不得进生产扫描面：{prod:?}"
    );

    // ---- 词边界：类型名命中，同名前缀不误配 ----
    assert_eq!(
        find_word_hits("let b: MessageBus = x;", "MessageBus").len(),
        1
    );
    assert_eq!(
        find_word_hits("let b: MessageBusX = x;", "MessageBus").len(),
        0
    );
    assert_eq!(find_word_hits("let b: x = 1;", "MessageBus").len(), 0);

    // ---- 左边界：前缀形命中，同名左缀不误配 ----
    assert_eq!(
        find_prefix_hits("let a = crate::tauri::AppHandle;", "tauri::").len(),
        1
    );
    assert_eq!(
        find_prefix_hits("let a = mytauri::AppHandle;", "tauri::").len(),
        0
    );

    // ---- 清单解析：段内方括号不截断、点号表与平台段归属正确 ----
    let manifest = "\
[dependencies]
serde = { version = \"1\", features = [\"derive\"] }
tokio-tungstenite = \"0.24\"

[dev-dependencies]
tempfile = \"3\"

[target.'cfg(windows)'.dependencies]
winapi = \"0.3\"

[dev-dependencies.tempfile2]
version = \"3\"
";
    let prod_deps = section_deps(manifest, "dependencies");
    assert!(
        prod_deps.contains("serde")
            && prod_deps.contains("tokio-tungstenite")
            && prod_deps.contains("winapi"),
        "生产依赖解析错误（段内方括号截断或平台段漏收），实得 {prod_deps:?}"
    );
    assert!(
        !prod_deps.contains("tempfile") && !prod_deps.contains("tempfile2"),
        "dev 段不得进生产集合：{prod_deps:?}"
    );
    assert!(
        section_deps(manifest, "dev-dependencies").contains("tempfile2"),
        "点号表 dev 段必须被解析"
    );

    // 未覆盖写法必须 panic 而不是静默跳过
    let malformed = "[dependencies]\nserde = { version = \"1\",\nfeatures = [\"derive\"] }\n";
    assert!(
        std::panic::catch_unwind(|| section_deps(malformed, "dependencies")).is_err(),
        "折行依赖声明必须 panic"
    );
    assert!(
        std::panic::catch_unwind(|| section_deps("[target]\n", "dependencies")).is_err(),
        "形状不完整的平台段头必须 panic"
    );
}

/// B-2｜源码面：生产代码零平台 / SDK / wasm-core / 机制内核 / WIT 绑定层
#[test]
fn production_source_is_free_of_host_and_sdk_references() {
    let all = all_rs_files();
    assert!(
        all.len() >= MIN_ALL_FILES,
        "边界锁空转：只枚举到 {} 个 .rs（下限 {MIN_ALL_FILES}）",
        all.len()
    );
    for sentinel in SENTINEL_FILES {
        assert!(
            all.iter().any(|p| p == sentinel),
            "边界锁空转：枚举清单缺哨兵文件 {sentinel}（实得 {all:?}）"
        );
    }

    // 测试专用模块由 `#[cfg(test)] mod` 声明推导（不手写文件名）
    let cfg_test_mods: BTreeSet<String> = all
        .iter()
        .flat_map(|rel| {
            let text = fs::read_to_string(crate_root().join(rel))
                .unwrap_or_else(|e| panic!("边界锁读不到 {rel}：{e}"));
            cfg_test_modules(&text)
        })
        .collect();
    // 本 crate 用例全部内联（`#[cfg(test)] mod tests { … }`，无 `mod xxx;` 声明），
    // 故声明式 cfg(test) 模块只有本锁自身一个
    assert!(
        cfg_test_mods.contains("boundary_lock"),
        "cfg(test) 模块 `boundary_lock` 未被识别（扫描面推导失守）"
    );

    let prod: Vec<ProdSource> = all
        .iter()
        .filter_map(|rel| prod_source(rel, &cfg_test_mods))
        .collect();
    assert!(
        prod.len() >= MIN_PROD_FILES,
        "边界锁空转：生产面只扫描到 {} 个文件（下限 {MIN_PROD_FILES}）",
        prod.len()
    );

    let hits = find_source_violations(&prod);
    assert!(
        hits.is_empty(),
        "能力 crate 的生产源码出现宿主回接形态（AGENTS §0「默认形态 = 纯引擎 + 端口抽象」被破坏）\n{}\n\
         （tauri:: / wasmnest_plugin_api* / wasmnest_wasm_core* / wasmnest_host_kit / bindgen! / \
         inventory::submit / MessageBus / WasmPluginState … ——平台差异面一律经 ports::P2pPorts 注入）",
        format_hits(&hits)
    );
}

/// B-3｜依赖面：生产清单零内部 crate + 零平台栈，且机制级依赖仍在场
#[test]
fn production_manifest_has_no_internal_or_platform_dependencies() {
    let prod_deps = section_deps(&read_manifest(), "dependencies");
    assert!(
        !prod_deps.is_empty(),
        "生产依赖段解析为空 —— 清单形态与本锁假设不符，扫描器空转"
    );

    for dep in &prod_deps {
        assert!(
            !dep.starts_with(INTERNAL_CRATE_PREFIX),
            "生产依赖出现内部 crate `{dep}` —— 通用能力 crate 一旦依赖任何 `wasmnest*`，\
             就退化成某宿主的实现（换宿主即编译失败）。内部 crate 只允许出现在**适配层**"
        );
        assert!(
            !FORBIDDEN_DEPS.contains(&dep.as_str()),
            "生产依赖出现平台 / 传输栈 crate `{dep}` —— 默认形态必须是纯引擎（零 tauri / 零 actix / \
             零 wasmtime / 零 WIT 绑定层；需要宿主能力一律经 ports 注入）"
        );
    }
    for required in REQUIRED_DEPS {
        assert!(
            prod_deps.contains(*required),
            "生产依赖缺少 `{required}` —— 机制级依赖被误删，或清单被换成平台依赖（通用性名存实亡）"
        );
    }
}

/// B-4｜治理形态：单测在 `src/` 内，crate 根不得有对外可编译测试面
#[test]
fn crate_root_has_no_external_test_surfaces() {
    let root = crate_root();
    let mut violations: Vec<String> = Vec::new();
    for dir in FORBIDDEN_CRATE_TEST_DIRS {
        let path = root.join(dir);
        if path.is_dir() {
            let mut entries: Vec<String> = fs::read_dir(&path)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default();
            entries.sort();
            violations.push(format!(
                "{dir}/ 存在（{}）—— crate 根的 `{dir}/` 是只能经 pub API 访问对外行为的可编译面",
                entries.join(", ")
            ));
        }
    }
    let manifest = read_manifest();
    for kind in ["test", "bench", "example"] {
        if manifest.lines().any(|l| l.trim() == format!("[[{kind}]]")) {
            violations.push(format!(
                "Cargo.toml 登记了 `[[{kind}]]` —— 与 crate 根测试面同一形态，治理 crate 不登记"
            ));
        }
    }
    // dev 段同样零内部 crate（dev 边在依赖图里就是一条真边）
    for dep in section_deps(&manifest, "dev-dependencies") {
        if dep.starts_with(INTERNAL_CRATE_PREFIX) {
            violations.push(format!(
                "[dev-dependencies] 含内部 crate `{dep}` —— 只服务测试的内部依赖边"
            ));
        }
    }
    // WIT **绑定层**的载体不得在场；**纯契约分片**例外（ADR 0052 D2）：双端功能级
    // 交集的契约真源住能力域 crate 的 `wit/<domain>.wit`（本 crate 自 2026-10-13
    // 起持共享客户端域 `ws.wit`，由双端 compose 与 `server-websocket` 的 provider
    // bindgen 消费）。绑定层仍零——B-1 标记禁词与 B-3 依赖面锁（禁 wit-bindgen /
    // wasmtime / 内部 crate 依赖）继续钉住；`wit/` 只允许 `.wit` 契约文件。
    if root.join("wit").is_dir() {
        let only_contracts = fs::read_dir(root.join("wit"))
            .map(|rd| {
                rd.filter_map(|e| e.ok()).all(|e| {
                    e.file_type().map(|t| t.is_file()).unwrap_or(false)
                        && e.file_name().to_string_lossy().ends_with(".wit")
                })
            })
            .unwrap_or(false);
        if !only_contracts {
            violations.push(
                "wit/ 含非契约文件 —— WIT 绑定层载体不得在场（只允许 `.wit` 契约分片，ADR 0052 D2）"
                    .to_string(),
            );
        }
    }
    assert!(
        violations.is_empty(),
        "能力 crate 只保留 `src/` 内的 `#[cfg(test)]` 单元测试：\n  - {}",
        violations.join("\n  - ")
    );
}
