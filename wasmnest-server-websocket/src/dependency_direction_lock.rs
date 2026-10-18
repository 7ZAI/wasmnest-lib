//! WS 面的依赖方向锁（server-lib-split 票 05：从宿主 `server/websocket.rs` 迁来并升级）
//!
//! 拆成 crate 后，原文本锁守的不变量换了执行方式，**强度只增不减**：
//!
//! - **I1（http ↮ ws 零横向）**：由 crate 依赖清单双向钉死——本 crate 的 `Cargo.toml`
//!   不得声明 `wasmnest-server-http`，反之 `wasmnest-server-http` 也不得声明本 crate。
//!   想横向引用必须先改清单，改动必然出现在 diff 里（比文本锁更难被绕过）。跨清单读取
//!   的先例是 L2 锁读 `packages/wasmnest-server-base/src/identity.rs`。
//! - **I2（只向下依赖内核）**：本 crate 清单**必须**含 `wasmnest-server-core` 与
//!   `wasmnest-server-base`（缺了说明有人把内核面复制进本面，或清单被误删）；
//!   且**不得**含 `wasmnest-desktop`——「内核/面反向认识宿主」在依赖层面就不成立。
//!   HTTP 面同样只允许向下：它的清单不得含 `wasmnest-desktop`。
//! - **不回接宿主旧路径**：源码里出现 `wasmnest_server_http::…` 或
//!   `crate::server::{http,websocket,core}::…` 即违规。注：`crate::server::*` 这类
//!   宿主路径在本 crate 里本来也编译不过（没有 `server` 模块），本锁挡的是**注释/文档
//!   与字符串形态**的回接暗示，以及清单之外的人为旁路（如 `[patch]`）。
//! - **旧平铺路径不复发**（票 08 断言 B 的 14 个子段）。
//!
//! 锁自身文件不参与源码扫描：它的失败消息与文档必然携带这些字面量（自锁规避手法
//! 与宿主版一致——原先是靠「锁挂在面目录之外」）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// 本 crate 源码 `.rs` 文件数下限（票 05 实测 8：lib + conn + endpoint + registry +
/// routes + websocket_manager + channel.rs + channel/plugin.rs，下调留余量）
const MIN_WS_FILES: usize = 6;

/// 哨兵文件：枚举失败/路径写错时防「清单为空 → 断言恒真」
const SENTINEL_FILES: &[&str] = &["src/websocket_manager.rs", "src/channel/plugin.rs"];

/// 不得出现在本 crate 依赖清单里的 crate（横向面 + 宿主反向依赖）
const FORBIDDEN_DEPS: &[&str] = &["wasmnest-server-http", "wasmnest-desktop"];

/// 必须出现在本 crate 依赖清单里的 crate（I2 向下依赖内核与基础层）
const REQUIRED_DEPS: &[&str] = &["wasmnest-server-core", "wasmnest-server-base"];

/// 断言「旧平铺路径不得复发」的子段清单（票 08 原文）
const LEGACY_SERVER_CHILD_SEGMENTS: &[&str] = &[
    "controllers",
    "dtos",
    "gateway",
    "middleware",
    "services",
    "ws",
    "app",
    "message",
    "connection_types",
    "filter",
    "metrics",
    "link_crypto",
    "supervisor",
    "port_checker",
];

/// HTTP 面的 crate 名与宿主旧路径的段名——出现即横向/回接
const HTTP_FACE_CRATE: &str = "wasmnest_server_http";
const HOST_FACE_SEGMENTS: &[&str] = &["http", "websocket", "core"];

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

fn read_file(rel_from_repo_pkg: &Path) -> String {
    std::fs::read_to_string(rel_from_repo_pkg)
        .unwrap_or_else(|e| panic!("结构锁无法读取 {}：{e}", rel_from_repo_pkg.display()))
}

fn line_number(src: &str, pos: usize) -> usize {
    src[..pos].bytes().filter(|b| *b == b'\n').count() + 1
}

fn line_content(src: &str, pos: usize) -> String {
    let start = src[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = src[pos..].find('\n').map(|i| pos + i).unwrap_or(src.len());
    src[start..end].trim_end_matches('\r').to_string()
}

/// `seg_start` 处段名的前一段名（其前应为 `::`；UTF-8 多字节相邻时返回 None 且不 panic）
fn previous_segment<'a>(src: &'a str, seg_start: usize) -> Option<&'a str> {
    let bytes = src.as_bytes();
    if seg_start < 2 || bytes[seg_start - 2] != b':' || bytes[seg_start - 1] != b':' {
        return None;
    }
    let mut j = seg_start - 2;
    while j > 0 && is_ident_byte(bytes[j - 1]) {
        j -= 1;
    }
    if j == seg_start - 2 {
        return None;
    }
    src.get(j..seg_start - 2)
}

/// 找独立段：前为 `::`、后非标识符字节
fn find_segment_positions(src: &str, segment: &str) -> Vec<usize> {
    let bytes = src.as_bytes();
    let mut positions = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = src[search..].find(segment) {
        let start = search + rel;
        let end = start + segment.len();
        let before_ok = start >= 2 && bytes[start - 2] == b':' && bytes[start - 1] == b':';
        let after_ok = bytes.get(end).map_or(true, |&b| !is_ident_byte(b));
        if before_ok && after_ok {
            positions.push(start);
        }
        search = start + 1;
    }
    positions
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
        let after_ok = bytes.get(end).map_or(true, |&b| !is_ident_byte(b));
        if before_ok && after_ok {
            positions.push(start);
        }
        search = start + 1;
    }
    positions
}

fn format_hits(hits: &[(String, usize, String)]) -> String {
    hits.iter()
        .map(|(f, l, c)| format!("  {f}:{l}: {c}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 源码文本命中：HTTP 面 crate 名 + 宿主面旧路径段
fn find_face_refs(files: &[String]) -> Vec<(String, usize, String)> {
    let mut hits = Vec::new();
    for rel in files {
        let src = read_file(&crate_root().join(rel));
        for pos in find_word_positions(&src, HTTP_FACE_CRATE) {
            hits.push((rel.clone(), line_number(&src, pos), line_content(&src, pos)));
        }
        for seg in HOST_FACE_SEGMENTS {
            for seg_start in find_segment_positions(&src, seg) {
                if previous_segment(&src, seg_start) == Some("server") {
                    hits.push((rel.clone(), line_number(&src, seg_start), line_content(&src, seg_start)));
                }
            }
        }
    }
    hits.sort();
    hits
}

/// 旧平铺路径 `server::{子段}` 命中
fn find_legacy_paths(files: &[String]) -> Vec<(String, usize, String)> {
    let mut hits = Vec::new();
    for rel in files {
        let src = read_file(&crate_root().join(rel));
        for child in LEGACY_SERVER_CHILD_SEGMENTS {
            let needle = format!("server::{child}");
            let mut search = 0usize;
            while let Some(pos_rel) = src[search..].find(&needle) {
                let start = search + pos_rel;
                let after = start + needle.len();
                let before_ok = start == 0 || !is_ident_byte(src.as_bytes()[start - 1]);
                let after_ok = src.as_bytes().get(after).map_or(true, |&b| !is_ident_byte(b));
                if before_ok && after_ok {
                    hits.push((rel.clone(), line_number(&src, start), line_content(&src, start)));
                }
                search = start + 1;
            }
        }
    }
    hits
}

/// 取 Cargo.toml 的 `[dependencies]` 段里的**依赖键**集合
///
/// 按**行**切段：段内值常含 `features = ["derive"]` 这类方括号，用「下一个 `[`」
/// 找段尾会把清单截断在 serde 行上（首版实测踩中，表现为误报「清单缺少内核依赖」）。
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

/// 锁本体 A：双向 I1 + I2 由两份 Cargo.toml 钉死
#[test]
fn crate_manifests_keep_faces_independent_and_downward_only() {
    let own = read_file(&crate_root().join("Cargo.toml"));
    let own_deps = dependency_table(&own);

    for forbidden in FORBIDDEN_DEPS {
        assert!(
            !own_deps.contains(*forbidden),
            "I1/反向依赖违反：wasmnest-server-websocket 的依赖清单出现 `{forbidden}`\
             （横向引用 HTTP 面或反向引用宿主 crate）"
        );
    }
    for required in REQUIRED_DEPS {
        assert!(
            own_deps.contains(*required),
            "I2 违反：依赖清单缺少 `{required}`——内核/基础面被复制进本面或清单被误删"
        );
    }

    // 对侧：HTTP 面不得横向依赖本面，也不得反向依赖宿主 crate
    let http_manifest = crate_root().join("..").join("wasmnest-server-http").join("Cargo.toml");
    let http_manifest_text = read_file(&http_manifest);
    let http_deps = dependency_table(&http_manifest_text);
    for forbidden in &["wasmnest-server-websocket", "wasmnest-desktop"] {
        assert!(
            !http_deps.contains(*forbidden),
            "I1/反向依赖违反：wasmnest-server-http 的依赖清单出现 `{forbidden}`"
        );
    }
}

/// 锁本体 B：本面源码不回接宿主路径 / 不横向引用 HTTP 面 + 旧平铺路径不复发
#[test]
fn websocket_face_never_reaches_sideways_or_back_into_host() {
    let files = collect_crate_rs_files();
    assert!(
        files.len() >= MIN_WS_FILES,
        "结构锁空转：本 crate src 只枚举到 {} 个 .rs（下限 {MIN_WS_FILES}）——\
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

    let face_refs = find_face_refs(&files);
    assert!(
        face_refs.is_empty(),
        "违反：websocket 面源码出现横向/回接路径（{HTTP_FACE_CRATE}::… 或 \
         server::http / server::websocket / server::core）：\n{}",
        format_hits(&face_refs)
    );

    let legacy = find_legacy_paths(&files);
    assert!(
        legacy.is_empty(),
        "旧路径复发（本面源码不得再出现宿主平铺路径 server::{{子段}}）：\n{}",
        format_hits(&legacy)
    );
}

/// 判据自身的契约例（防匹配规则被改坏后假绿）
#[test]
fn matching_follows_segment_and_word_boundaries() {
    // 独立段命中：`::http::` 算；粘连的 `::http_filter::` 不算
    let src = "use crate::server::http::routes;\nuse crate::server::http_filter::No;\n";
    let hits = find_segment_positions(src, "http");
    assert_eq!(hits.len(), 1, "粘连段应被边界挡下，实际命中 {hits:?}");
    assert_eq!(previous_segment(src, hits[0]), Some("server"));

    // actix_web::http：前一段是 actix_web → 不是回接宿主面
    let src2 = "use actix_web::http::header;\n";
    let hits2 = find_segment_positions(src2, "http");
    assert_eq!(hits2.len(), 1);
    assert_eq!(previous_segment(src2, hits2[0]), Some("actix_web"));

    // 非 `::` 前缀（含 UTF-8 多字节相邻）不得 panic、不得误判
    assert_eq!(previous_segment("（http", 3), None);
    assert_eq!(previous_segment("http", 0), None);
    // `server::websocket` 不得被子段 `ws` 误配
    assert!(find_segment_positions("crate::server::websocket::registry;\n", "ws").is_empty());

    // crate 名词边界：两种写法命中，同名前缀不命中
    let src3 = "use wasmnest_server_http::gateway;\n\
                let _ = wasmnest_server_http::registry::count();\n\
                use wasmnest_server_httpx::y;\n";
    let words = find_word_positions(src3, HTTP_FACE_CRATE);
    assert_eq!(words.len(), 2, "crate 名词边界判定漂移：{words:?}");

    // 依赖清单解析：只看 [dependencies] 段，dev-dependencies 不得污染判定
    let manifest = "[package]\nname = \"x\"\n\n[dependencies]\nwasmnest-server-core = \"1\"\n\n\
                    [dev-dependencies]\nwasmnest-server-http = \"1\"\n";
    assert!(dependency_table(manifest).contains("wasmnest-server-core"));
    assert!(!dependency_table(manifest).contains("wasmnest-server-http"));

    // 段内方括号（`features = ["derive"]`）不得截断清单——首版按「下一个 `[`」找段尾，
    // 把 serde 行之后全部吃掉，误报「缺少 wasmnest-server-core」
    let with_features = "[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\n\
                        wasmnest-server-core = { path = \"../wasmnest-server-core\" }\n\n\
                        [build-dependencies]\nwasmnest-server-http = \"1\"\n";
    assert!(
        dependency_table(with_features).contains("wasmnest-server-core"),
        "段内方括号截断了依赖清单：{:?}",
        dependency_table(with_features)
    );
    assert!(!dependency_table(with_features).contains("wasmnest-server-http"));
}
