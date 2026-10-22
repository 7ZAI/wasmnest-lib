//! peer-net 引擎域（含底座机制）的依赖方向锁（server-lib-split 票 06）
//!
//! peer-net 与三个传输面（core / http / websocket）**不构成同一条依赖链**——spec
//! 决策 D2 判它是「引擎域」而非「传输面」：它不参与 actix 组合装配、不过流量过滤链、
//! 不用链路加密，只向下依赖基础层。2026-10-22 peer-net-dissolve：原共享引擎 crate
//! `wasmnest-peer-net` 已拆分，底座机制（身份 / TLS / 信任 / mDNS 注册 / 传输会话引擎
//! 原语）并入本 crate `base/` 子模块，mDNS 机制 `disable_virtual_interfaces` 归位
//! discovery-engine——本锁的「共享引擎清单」断言随之退役。这条不变量在
//! 宿主单 crate 时代靠「`use crate::` 统计」人工确认，拆 crate 后改由**依赖清单**静态
//! 钉死（比文本锁更难绕过：要引用必须先改清单，改动必然出现在 diff 里）。
//!
//! 三条断言：
//!
//! - **D2（引擎域独立）**：本 crate 清单**不得**含 `wasmnest-server-core` /
//!   `-http` / `-websocket`（传输面）、`wasmnest-desktop`（宿主）、`tauri` / `actix`
//!   （传输栈）。反向的「内核反向认识传输面」（spec 1.3 B 项）若发生，表现正是本
//!   crate 清单里长出传输面依赖，故一并由本锁覆盖。
//! - **D5 取用（必须向下）**：清单**必须**含 `wasmnest-server-base`（错误类型 /
//!   `error_boundary` / 端口 traits）——缺了说明有人把宿主内模块复制进本 crate，
//!   或清单被误删。
//! - **叶子性**：其余三个 server lib 清单**不得**依赖本 crate（peer-net 是叶子，
//!   任何面经它取能力都是新的横向依赖）。宿主组合根依赖本 crate 是合法的，故不在
//!   本锁的扫描面内。
//! - **mDNS 单 listener 不变量（ADR 0054 / spec §0.4）**：本 crate 清单**不得**含
//!   `wasmnest-discovery-engine`——类型中枢句柄以**纯值**（`flume::Receiver` + 退订
//!   守卫 + 重查闭包）经 `MdnsPort` 注入，server-peer-net 不认识 mDNS 引擎 crate。
//!   （2026-10-22 起 discovery-engine 零内部 crate 依赖，此边本就不存在；锁继续
//!   钉死「引擎认识引擎」不复发。）
//!
//! 源码文本锁只守「不反向引用传输面 / 不回接宿主路径 / 不认识 tauri 类型」三形态
//! （含注释与字符串形态——搬移时最容易把宿主路径连同文档一起带进来）。锁自身文件
//! 不参与源码扫描：它的失败消息与常量表必然携带这些字面量（与 WS 面同款自锁规避）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// 本 crate 源码 `.rs` 文件数下限（票 06 实测 6：lib + 4 个引擎适配/收集模块
/// + 本锁，下调留余量）
const MIN_FILES: usize = 5;

/// 哨兵文件：枚举失败 / 路径写错时防「清单为空 → 断言恒真」
const SENTINEL_FILES: &[&str] = &["src/lib.rs", "src/source_collect.rs"];

/// 不得出现在本 crate 依赖清单里的 crate（传输面 / 宿主 / 传输栈）
const FORBIDDEN_DEPS: &[&str] = &[
    "wasmnest-server-core",
    "wasmnest-server-http",
    "wasmnest-server-websocket",
    "wasmnest-desktop",
    "tauri",
    "actix",
    // mDNS 引擎域（ADR 0054 / spec §0.4）：中枢句柄以纯值经 MdnsPort 注入，
    // server-peer-net 零 mDNS 依赖（引它即把「引擎认识引擎」接成横向边）
    "wasmnest-discovery-engine",
];

/// 必须出现在本 crate 依赖清单里的 crate（D5 向下取用；底座机制已并入本 crate）
const REQUIRED_DEPS: &[&str] = &["wasmnest-server-base"];

/// 不得出现在本 crate 源码里的传输面 crate 名（词边界匹配）
const FORBIDDEN_FACE_CRATES: &[&str] = &[
    "wasmnest_server_core",
    "wasmnest_server_http",
    "wasmnest_server_websocket",
    "wasmnest_crypto_engine",
];

/// 不得出现在本 crate 源码里的宿主路径 / 宿主类型前缀（含注释与字符串形态）
///
/// 全部是**路径形**字面量（带 `::` 或路径分隔）：散文里提及类型名（“把
/// `AppContext` 换成端口”）是合法文档，真实的回接则必是 `AppContext::global()` /
/// `tauri::AppHandle` / `crate::server::xxx` 这类可编译形态。
const FORBIDDEN_SOURCE_PREFIXES: &[&str] = &[
    "crate::server::",
    "server::peer_net",
    "tauri::",
    "wasm_core::",
    "AppContext::",
];

/// 其余 server lib 清单（本 crate 是叶子，反向依赖同样违规）
const SIBLING_LIB_MANIFESTS: &[&str] = &[
    "wasmnest-server-base",
    "wasmnest-crypto-engine",
    "wasmnest-server-core",
    "wasmnest-server-http",
    "wasmnest-server-websocket",
];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// 递归枚举本 crate `src/**/*.rs`（排除本锁文件），返回相对 crate 根的正斜杠路径
fn collect_crate_rs_files() -> Vec<String> {
    let root = crate_root().join("src");
    let mut stack = vec![root];
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("结构锁无法枚举 {}：{e}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| panic!("结构锁 read_dir 条目错误：{e}"));
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let rel = path
                    .strip_prefix(crate_root())
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                // 锁自身携带全部禁用字面量，不参与扫描
                if rel.ends_with("dependency_direction_lock.rs") {
                    continue;
                }
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("结构锁无法读取 {}：{e}", path.display()))
}

fn line_number(src: &str, pos: usize) -> usize {
    src[..pos].bytes().filter(|b| *b == b'\n').count() + 1
}

fn line_content(src: &str, pos: usize) -> String {
    let start = src[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = src[pos..].find('\n').map(|i| pos + i).unwrap_or(src.len());
    src[start..end].trim_end_matches('\r').to_string()
}

/// 词边界匹配（crate 名是裸标识符，前面没有 `::`）
fn find_word_positions(src: &str, needle: &str) -> Vec<usize> {
    let bytes = src.as_bytes();
    let mut positions = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = src[search..].find(needle) {
        let start = search + rel;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = !bytes.get(end).is_some_and(|&b| is_ident_byte(b));
        if before_ok && after_ok {
            positions.push(start);
        }
        search = start + 1;
    }
    positions
}

/// 前缀针脚命中（返回前缀文本 + 字节偏移）
///
/// 只判**左**边界：前缀针脚本身以 `::` 结尾或是一段路径名，右边**必然**紧跟标识符
/// （`AppContext::global` / `tauri::AppHandle`），加右边界判定会把每一个真命中都挡掉
/// ——首版就这么写，M4 变异自检（把 `AppContext::global()` 追加进 lib.rs）实测假绿
/// 才发现。判据与用例共用本函数：契约例自己重写一遍匹配循环，就等于给漂移开了后门。
fn find_prefix_hits<'a>(src: &'a str, prefixes: &[&'a str]) -> Vec<(&'a str, usize)> {
    let bytes = src.as_bytes();
    let mut hits = Vec::new();
    for prefix in prefixes {
        let prefix: &'a str = prefix;
        let mut search = 0usize;
        while let Some(offset) = src[search..].find(prefix) {
            let start = search + offset;
            let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
            if before_ok {
                hits.push((prefix, start));
            }
            search = start + 1;
        }
    }
    hits.sort_by_key(|(_, pos)| *pos);
    hits
}

fn format_hits(hits: &[(String, usize, String)]) -> String {
    hits.iter()
        .map(|(f, l, c)| format!("  {f}:{l}: {c}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 源码文本命中：传输面 crate 名 + 宿主路径 / 宿主类型前缀
fn find_forbidden_refs(files: &[String]) -> Vec<(String, usize, String)> {
    let mut hits = Vec::new();
    for rel in files {
        let src = read_file(&crate_root().join(rel));
        for crate_name in FORBIDDEN_FACE_CRATES {
            for pos in find_word_positions(&src, crate_name) {
                hits.push((rel.clone(), line_number(&src, pos), line_content(&src, pos)));
            }
        }
        for (_rule, start) in find_prefix_hits(&src, FORBIDDEN_SOURCE_PREFIXES) {
            hits.push((rel.clone(), line_number(&src, start), line_content(&src, start)));
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// 取 Cargo.toml 的 `[dependencies]` 段里的**依赖键**集合
///
/// 按**行**切段：段内值常含 `features = ["derive"]` 这类方括号，用「下一个 `[`」
/// 找段尾会把清单截断在 serde 行上（WS 面锁首版实测踩中，误报「清单缺少内核依赖」）。
///
/// **只取条目名（`=` 左侧），不收整段文本**（2026-10-07 迁根时改）：本锁判的是
/// 「有没有依赖某个 crate」，而条目**路径值**里含 `wasmnest-desktop` 的情形现在很常见
/// ——能力域 crate 迁到仓库根 `packages/` 后，WIT 契约依赖的路径写成
/// `../../wasmnest-desktop/packages/plugin-sdk-desktop/rust`。按文本子串匹配会把
/// 「依赖 SDK 契约」误判成「依赖宿主 crate」，锁红而语义未被违反。键级匹配同时把
/// `tauri` / `actix` 这类词的判定也收紧到真正的依赖名上。
fn dependency_table(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_deps = true;
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_deps = false;
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let key = trimmed.split('=').next().unwrap_or("").trim();
        assert!(!key.is_empty(), "`{trimmed}` 行没有 `=` —— 依赖声明形态与本锁假设不符");
        out.insert(key.to_string());
    }
    assert!(
        !out.is_empty(),
        "Cargo.toml 的 [dependencies] 段为空或不存在——清单形态与本锁假设不符（本票只用简单表）"
    );
    out
}

/// 锁本体 A：D2 引擎域独立 + D5 向下取用 + 叶子性
#[test]
fn peer_net_stays_a_leaf_below_base_and_shared_engine() {
    let own = read_file(&crate_root().join("Cargo.toml"));
    let own_deps = dependency_table(&own);

    for forbidden in FORBIDDEN_DEPS {
        assert!(
            !own_deps.contains(*forbidden),
            "D2 违反：wasmnest-server-peer-net 的依赖清单出现 `{forbidden}`\
             （传输面 / 宿主 crate / 传输栈——peer-net 是引擎域，不在传输面依赖链上）"
        );
    }
    for required in REQUIRED_DEPS {
        assert!(
            own_deps.contains(*required),
            "D5 违反：依赖清单缺少 `{required}`——宿主内模块被复制进本 crate 或清单被误删"
        );
    }

    // 叶子性：其余 server lib 不得反向依赖本 crate（宿主组合根依赖它是合法的）
    for sibling in SIBLING_LIB_MANIFESTS {
        let manifest = crate_root().join("..").join(sibling).join("Cargo.toml");
        assert!(
            manifest.exists(),
            "结构锁空转：找不到兄弟 lib 清单 {}（路径错或该 lib 未纳入本锁）",
            manifest.display()
        );
        let deps = dependency_table(&read_file(&manifest));
        assert!(
            !deps.contains("wasmnest-server-peer-net"),
            "叶子性违反：{sibling} 的依赖清单出现 `wasmnest-server-peer-net`\
             （任何传输面经引擎域取能力都是新的横向依赖）"
        );
    }

    // 2026-10-22 peer-net-dissolve：共享引擎 `wasmnest-peer-net` 已拆并入本 crate
    // （`base/` 子模块），「引擎→共享引擎单向、mDNS 引擎不下沉」的清单断言随其退役；
    // discovery-engine 零内部依赖由该 crate 自己的清单保证（本锁的 FORBIDDEN_DEPS
    // 仍钉死 server-peer-net 不得依赖 discovery-engine，引擎认识引擎不复发）。
}

/// 锁本体 B：本 crate 源码不反向引用传输面 / 不回接宿主路径与类型
#[test]
fn peer_net_source_never_reaches_faces_or_back_into_host() {
    let files = collect_crate_rs_files();
    assert!(
        files.len() >= MIN_FILES,
        "结构锁空转：本 crate src 只枚举到 {} 个 .rs（下限 {MIN_FILES}）——\
         路径错或 read_dir 异常被吞",
        files.len()
    );
    for sentinel in SENTINEL_FILES {
        assert!(
            files.iter().any(|p| p == sentinel),
            "结构锁空转：枚举清单缺少哨兵文件 {sentinel}（实际 {} 个文件）",
            files.len()
        );
    }

    let hits = find_forbidden_refs(&files);
    assert!(
        hits.is_empty(),
        "违反：peer-net 源码出现横向引用或宿主回接形态\n{}\n\
         （传输面 crate 名 / crate::server:: / server::peer_net / tauri:: / \
         wasm_core:: / AppContext:: ——需要宿主能力一律经 wasmnest_server_base::ports 端口注入）",
        format_hits(&hits)
    );
}

/// 判据自身的契约例（防匹配规则被改坏后假绿）
#[test]
fn matching_follows_word_and_prefix_boundaries() {
    // 词边界：两个传输面 crate 名命中，同名前缀（…_httpx）不误配
    let src = "use wasmnest_server_core::filter::TrafficFilterChain;\n\
                let _ = wasmnest_server_http::registry::count();\n\
                use wasmnest_server_httpx::y;\n";
    assert_eq!(find_word_positions(src, "wasmnest_server_core").len(), 1);
    assert_eq!(find_word_positions(src, "wasmnest_server_http").len(), 1);
    // 前缀同名的假 crate 不应被当成 HTTP 面（词边界右半侧生效）
    assert_eq!(find_word_positions(src, "wasmnest_server_httpx").len(), 1);
    // 不在本 crate 出现的传输面：零命中（反向验证：不是恒不命中）
    assert_eq!(find_word_positions(src, "wasmnest_server_websocket").len(), 0);

    // 前缀形态：共用判据 `find_prefix_hits`（本例不重写匹配循环）——左边界生效，
    // 右边界**不**生效（`AppContext::` 后面必然是标识符，加右边界会恒假绿）
    let src2 = "let a = mycrate::server::x;\n\
                let b = crate::server::peer_net::y;\n\
                let c = AppContext::global();\n\
                let d = notserver::peer_net::z;\n\
                //! 散文里提 `AppContext` 不算回接。\n";
    let hits = find_prefix_hits(src2, FORBIDDEN_SOURCE_PREFIXES);
    let hit_lines: Vec<usize> = hits
        .iter()
        .map(|(_, pos)| src2[..*pos].matches('\n').count() + 1)
        .collect();
    assert_eq!(
        hit_lines,
        vec![2, 2, 3],
        "前缀边界判定漂移（第 1/4 行被左边界挡下、第 5 行散文裸类型名不得命中）：{hit_lines:?}"
    );
    assert_eq!(
        hits.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        vec!["crate::server::", "server::peer_net", "AppContext::"],
        "第 2 行应同时命中两个路径前缀（`crate::server::peer_net` 的两段都是回接形态）"
    );

    // 依赖清单解析：只看 [dependencies] 段，dev-dependencies / build-dependencies 不得污染判定
    let manifest = "[package]\nname = \"x\"\n\n[dependencies]\nwasmnest-server-base = \"1\"\n\n\
                    [dev-dependencies]\nwasmnest-server-core = \"1\"\n";
    assert!(dependency_table(manifest).contains("wasmnest-server-base"));
    assert!(!dependency_table(manifest).contains("wasmnest-server-core"));

    // 段内方括号（`features = ["derive"]`）不得截断清单
    let with_features = "[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\n\
                        wasmnest-server-base = { path = \"../../../wasmnest-lib/wasmnest-server-base\" }\n\n\
                        [build-dependencies]\ntauri = \"2\"\n";
    assert!(
        dependency_table(with_features).contains("wasmnest-server-base"),
        "段内方括号截断了依赖清单：{:?}",
        dependency_table(with_features)
    );
    assert!(!dependency_table(with_features).contains("tauri"));
}
