//! 形态锁：中继守护进程必须**脱离能力仓其余部分可独立构建**。
//!
//! 这条不变量支撑两件事：单文件静态二进制（交叉编译到 linux-arm64 时不带整仓依赖
//! 图）与 Docker 多阶段构建（构建上下文只需本 crate）。它无法用「依赖方向锁」表达
//!（本 crate 没有内部依赖清单可比对），因此用 Cargo.toml 文本 + 部署资产存在性做
//! 显性判据——锁跑红即说明有人把内部 crate 或重依赖引进来了。

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// 生产依赖中不允许出现的内部 crate 前缀
    const INTERNAL_PREFIXES: &[&str] = &["wasmnest-", "wasmnest_"];

    fn manifest() -> &'static str {
        include_str!("../Cargo.toml")
    }

    fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// 取 `[dependencies]` 段（到下一个顶层表为止）
    fn dependencies_section() -> String {
        let text = manifest();
        let mut out = String::new();
        let mut inside = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                inside = trimmed == "[dependencies]";
                continue;
            }
            if inside {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    #[test]
    fn 生产依赖不得含内部_crate_与_path_边() {
        let deps = dependencies_section();
        assert!(
            !deps.is_empty(),
            "未能解析 [dependencies] 段：Cargo.toml 结构变了，本锁需要同步"
        );
        for line in deps.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            for prefix in INTERNAL_PREFIXES {
                assert!(
                    !trimmed.starts_with(prefix),
                    "中继守护进程不得依赖内部 crate（破坏独立构建）：{trimmed}"
                );
            }
            assert!(
                !trimmed.contains("path ="),
                "生产依赖不得使用 path 边（独立构建 / 交叉编译会断）：{trimmed}"
            );
        }
    }

    #[test]
    fn libp2p_保持收窄_feature_面() {
        let deps = dependencies_section();
        assert!(
            deps.contains("default-features = false"),
            "libp2p 必须 default-features = false，否则默认 feature 会拉 DNS/QUIC 等重依赖"
        );
        for forbidden in ["\"quic\"", "\"tls\"", "\"webrtc\"", "\"dns\""] {
            assert!(
                !deps.contains(forbidden),
                "中继只需要 TCP + Noise + Yamux：不应启用 {forbidden}"
            );
        }
        assert!(
            deps.contains("\"relay\""),
            "必须启用 relay feature 才有 HOP 服务端面"
        );
    }

    #[test]
    fn 部署资产在位() {
        // 代码与文档互相引用这些文件（CLI 帮助、错误提示、README）；缺失 = 文档失真
        let root = crate_root();
        let assets = [
            "../deploy/relay/Dockerfile",
            "../deploy/relay/docker-compose.yml",
            "../deploy/relay/config.example.toml",
            "../deploy/relay/install.sh",
            "../deploy/relay/wasmnest-relay.service",
            "../deploy/relay/README.md",
        ];
        for asset in assets {
            let path = root.join(asset);
            assert!(
                path.exists(),
                "部署资产缺失：{}（中继的一键运行链路依赖它）",
                path.display()
            );
        }
    }

    #[test]
    fn 控制协议名只在_wire_模块定义() {
        // 客户端（应用侧）依赖这个字面量；散落多处 = 改版本时必漏改
        let wire = include_str!("wire.rs");
        assert!(wire.contains("pub const CONTROL_PROTOCOL: &str = \"/wasmnest/relay-control/1\""));
        let root = crate_root();
        for entry in std::fs::read_dir(root.join("src")).expect("读 src") {
            let path: PathBuf = entry.expect("目录项").path();
            if path.file_name().and_then(|n| n.to_str()) == Some("wire.rs")
                || path.extension().and_then(|e| e.to_str()) != Some("rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("读源文件");
            let production = text.split("#[cfg(test)]").next().unwrap_or_default();
            // 注释里引用协议名是正常文档行为（本 crate 头注就是这样）；只查代码
            let code: String = production
                .lines()
                .map(|line| line.split("//").next().unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !code.contains("/wasmnest/relay-control/1"),
                "{} 里重复写了控制协议名字面量，应使用 wire::CONTROL_PROTOCOL",
                path.display()
            );
        }
    }

    #[test]
    fn 配置示例可被本版本解析() {
        // config.example.toml 是运维第一手材料：它必须始终是合法配置
        let path = crate_root().join("../deploy/relay/config.example.toml");
        let text = std::fs::read_to_string(&path).expect("读示例配置");
        let config: crate::config::RelayConfig = toml::from_str(&text).expect("示例配置应可解析");
        config.validate().expect("示例配置应通过校验");
        let _ = Path::new(&path);
    }
}
