//! 命令行：`init` / `run` / `doctor` / `print-addrs` / `token create`。
//!
//! 手写解析而不引 clap：子命令只有 5 个、参数类型单一，而 `clap` 会把这个「脱离
//! 能力仓独立构建的守护进程」的依赖面（含 proc-macro 链）明显放大。代价是错误
//! 消息要自己写清楚——这正好符合本仓「失败显性 + 给出路」的口径。

use std::{path::PathBuf, str::FromStr};

use crate::{
    access::AccessMode,
    addrs,
    config::{self, RelayConfig},
    doctor,
    error::{RelayError, Result},
    fsutil,
    identity::{parse_peer_id, RelayIdentity},
    server,
    tokens::TokenStore,
    RELAY_VERSION,
};

/// 帮助文本
pub const USAGE: &str = "\
wasmnest-relay {version} —— WasmNest 内网穿透中继（libp2p Circuit Relay v2 服务端）

用法：
  wasmnest-relay init --dir <数据目录> [--advertise <域名|IP>] [--port <端口>]
                      [--listen <multiaddr>] [--mode open|allowlist]
                      [--allowlist <PeerId>[,<PeerId>...]] [--force]
  wasmnest-relay run [--config <配置路径>]
  wasmnest-relay doctor [--config <配置路径>] [--json]
  wasmnest-relay print-addrs [--config <配置路径>] [--json]
  wasmnest-relay token create --label <标签> [--config <配置路径>] [--max-uses <次数>] [--json]
  wasmnest-relay --version

说明：
  init    生成身份密钥与 config.toml（已有文件需显式 --force；覆盖身份 = 换 PeerId）
  run     启动中继（Ctrl-C / SIGTERM 优雅退出）
  doctor  逐项自检：身份 / 配置 / 端口 / 时钟 / 数据目录 / token / 版本
  print-addrs  输出应用导入用的地址（--json 为应用契约格式）
  token   私有 relay 的 enrollment token（明文只显示一次，落盘只存摘要）

配置路径解析顺序：--config → WASMNEST_RELAY_CONFIG → /data/config.toml → /etc/wasmnest-relay/config.toml
";

/// 解析后的命令
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 生成身份与配置
    Init(InitArgs),
    /// 启动守护进程
    Run {
        /// 配置路径（None = 按默认顺序解析）
        config: Option<PathBuf>,
    },
    /// 自检
    Doctor {
        /// 配置路径
        config: Option<PathBuf>,
        /// JSON 输出
        json: bool,
    },
    /// 输出可导入地址
    PrintAddrs {
        /// 配置路径
        config: Option<PathBuf>,
        /// JSON 输出
        json: bool,
    },
    /// 创建 enrollment token
    TokenCreate {
        /// 配置路径
        config: Option<PathBuf>,
        /// 运维标签
        label: String,
        /// 可兑换次数
        max_uses: u32,
        /// JSON 输出
        json: bool,
    },
    /// 帮助
    Help,
    /// 版本
    Version,
}

/// `init` 参数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    /// 数据目录
    pub dir: PathBuf,
    /// 对外通告主机（域名或 IP）
    pub advertise: Option<String>,
    /// 端口（监听与通告共用）
    pub port: u16,
    /// 监听 multiaddr（None = `/ip4/0.0.0.0/tcp/<port>`）
    pub listen: Option<String>,
    /// 覆盖已有身份 / 配置
    pub force: bool,
    /// 准入模式
    pub mode: AccessMode,
    /// 静态白名单
    pub allowlist: Vec<String>,
}

/// 解析命令行参数（不含 argv[0]）
pub fn parse<I>(args: I) -> Result<Command>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    let Some((head, rest)) = args.split_first() else {
        return Ok(Command::Help);
    };
    match head.as_str() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "-V" | "--version" | "version" => Ok(Command::Version),
        "init" => parse_init(rest),
        "run" => {
            let mut config = None;
            let mut index = 0;
            while index < rest.len() {
                match rest[index].as_str() {
                    "--config" => config = Some(PathBuf::from(take_value(rest, &mut index, "--config")?)),
                    other => return Err(unknown_flag(other, "run")),
                }
                index += 1;
            }
            Ok(Command::Run { config })
        }
        "doctor" => {
            let (config, json) = parse_config_and_json(rest, "doctor")?;
            Ok(Command::Doctor { config, json })
        }
        "print-addrs" => {
            let (config, json) = parse_config_and_json(rest, "print-addrs")?;
            Ok(Command::PrintAddrs { config, json })
        }
        "token" => parse_token(rest),
        other => Err(RelayError::args(format!(
            "未知子命令 `{other}`（可用：init / run / doctor / print-addrs / token；`--help` 看用法）"
        ))),
    }
}

/// 执行命令，返回进程退出码
pub async fn run(command: Command) -> Result<i32> {
    match command {
        Command::Help => {
            print!("{}", USAGE.replace("{version}", RELAY_VERSION));
            Ok(0)
        }
        Command::Version => {
            println!("wasmnest-relay {RELAY_VERSION}");
            Ok(0)
        }
        Command::Init(args) => {
            crate::logging::init("warn");
            init(args)?;
            Ok(0)
        }
        Command::Run { config } => {
            crate::logging::init("info");
            run_daemon(config).await?;
            Ok(0)
        }
        Command::Doctor { config, json } => {
            crate::logging::init("warn");
            let config_path = doctor::resolve_config_path(config)?;
            let checks = doctor::run(&config_path);
            if json {
                println!("{}", doctor::render_json(&checks)?);
            } else {
                print!("{}", doctor::render_text(&checks));
            }
            Ok(doctor::exit_code(&checks))
        }
        Command::PrintAddrs { config, json } => {
            crate::logging::init("warn");
            let config_path = doctor::resolve_config_path(config)?;
            let config = RelayConfig::load(&config_path)?;
            let identity = RelayIdentity::load(&config.identity_path(&config_path))?;
            let payload = addrs::build(&config, &identity)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                print!("{}", addrs::render_text(&payload));
            }
            Ok(0)
        }
        Command::TokenCreate {
            config,
            label,
            max_uses,
            json,
        } => {
            crate::logging::init("warn");
            let config_path = doctor::resolve_config_path(config)?;
            // 先校验配置：配置坏了就不该往里写 token（否则 token 表与配置状态不一致）
            let _ = RelayConfig::load(&config_path)?;
            let tokens_path = RelayConfig::tokens_path(&config_path);
            let mut store = TokenStore::load(&tokens_path)?;
            let token = store.create(&label, max_uses)?;
            if json {
                let output = serde_json::json!({
                    "label": label,
                    "token": token,
                    "maxUses": max_uses,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("enrollment token（只显示这一次，请立刻交给设备）：");
                println!("{token}");
                println!();
                println!("已写入（仅摘要）：{}", tokens_path.display());
                println!("设备侧把它交给应用即可完成白名单开通。");
            }
            Ok(0)
        }
    }
}

fn init(args: InitArgs) -> Result<()> {
    let config_path = args.dir.join(config::CONFIG_FILE_NAME);
    if config_path.exists() && !args.force {
        return Err(RelayError::args(format!(
            "配置已存在：{}；覆盖会丢弃现有配额 / 白名单设置，确需覆盖请加 `--force`",
            config_path.display()
        )));
    }

    let listen = args
        .listen
        .clone()
        .unwrap_or_else(|| format!("/ip4/0.0.0.0/tcp/{}", args.port));
    let advertise = match &args.advertise {
        Some(host) => vec![addrs::describe_host(host, args.port)?.to_string()],
        None => Vec::new(),
    };

    let mut config = RelayConfig::for_init(advertise, args.mode, args.allowlist.clone());
    config.listen.addrs = vec![listen];
    // 先校验再落盘：写一份跑不起来的配置只会让人在 `run` 时才发现问题
    config.validate().map_err(|err| {
        RelayError::config(format!(
            "{err}\n提示：监听到 0.0.0.0 时必须给 `--advertise <公网域名|IP>`；\
             本机自测可用 `--listen /ip4/127.0.0.1/tcp/<端口>`"
        ))
    })?;

    fsutil::ensure_dir(&args.dir)?;
    let identity = RelayIdentity::create(&config.identity_path(&config_path), args.force)?;
    fsutil::write_atomic(
        &config_path,
        config.to_toml()?.as_bytes(),
        // 配置里有白名单与监听地址，但不含密钥材料：0644 允许运维读取排查
        0o644,
    )?;

    let payload = addrs::build(&config, &identity)?;
    println!("已生成：");
    println!(
        "  身份：{}（PeerId {}，指纹 {}）",
        config.identity_path(&config_path).display(),
        identity.peer_id(),
        identity.fingerprint()
    );
    println!("  配置：{}", config_path.display());
    println!();
    println!("下一步：");
    println!(
        "  启动：wasmnest-relay run --config {}",
        config_path.display()
    );
    if config.access.mode == AccessMode::Allowlist {
        println!(
            "  发 enrollment token：wasmnest-relay token create --config {} --label phone",
            config_path.display()
        );
    }
    println!("  应用导入（贴到桌面「中转服务器」卡片）：");
    for addr in &payload.addrs {
        println!("    {addr}");
    }
    Ok(())
}

async fn run_daemon(config: Option<PathBuf>) -> Result<()> {
    let config_path = doctor::resolve_config_path(config)?;
    let config = RelayConfig::load(&config_path)?;
    let identity = RelayIdentity::load(&config.identity_path(&config_path))?;
    let runtime = server::start(config, &config_path, identity).await?;
    println!(
        "wasmnest-relay {RELAY_VERSION} 已启动：peer {}；Ctrl-C / SIGTERM 停止",
        runtime.peer_id
    );
    for addr in runtime.advertise_addrs() {
        println!("  {addr}");
    }
    if let Some(addr) = runtime.metrics_addr() {
        println!("  健康/指标：http://{addr}/healthz、http://{addr}/metrics");
    }
    wait_for_shutdown_signal().await;
    println!("收到停止信号，正在关闭…");
    runtime.shutdown().await;
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(handle) => handle,
            Err(err) => {
                tracing::warn!(error = %err, "无法注册 SIGTERM 处理，仅响应 Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn parse_init(rest: &[String]) -> Result<Command> {
    let mut dir = None;
    let mut advertise = None;
    let mut port = config::DEFAULT_RELAY_PORT;
    let mut listen = None;
    let mut force = false;
    let mut mode = AccessMode::Open;
    let mut allowlist = Vec::new();

    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--dir" => dir = Some(PathBuf::from(take_value(rest, &mut index, "--dir")?)),
            "--advertise" => advertise = Some(take_value(rest, &mut index, "--advertise")?),
            "--port" => {
                let text = take_value(rest, &mut index, "--port")?;
                port = text
                    .parse::<u16>()
                    .map_err(|e| RelayError::args(format!("--port 非法（{text}）：{e}")))?;
            }
            "--listen" => listen = Some(take_value(rest, &mut index, "--listen")?),
            "--force" => force = true,
            "--mode" => {
                let text = take_value(rest, &mut index, "--mode")?;
                mode = AccessMode::from_str(&text)?;
            }
            "--allowlist" => {
                let text = take_value(rest, &mut index, "--allowlist")?;
                for item in text.split(',') {
                    // 形状当场校验：写错的 PeerId 不该等到运行时才「悄悄不匹配」
                    let peer = parse_peer_id(item)?;
                    allowlist.push(peer.to_base58());
                }
            }
            other => return Err(unknown_flag(other, "init")),
        }
        index += 1;
    }

    let dir = dir.ok_or_else(|| RelayError::args("init 需要 `--dir <数据目录>`"))?;
    if port == 0 {
        return Err(RelayError::args(
            "--port 不能为 0（客户端需要一个确定可拨的端口）",
        ));
    }
    Ok(Command::Init(InitArgs {
        dir,
        advertise,
        port,
        listen,
        force,
        mode,
        allowlist,
    }))
}

fn parse_token(rest: &[String]) -> Result<Command> {
    let Some((sub, rest)) = rest.split_first() else {
        return Err(RelayError::args(
            "token 需要一个子命令（可用：token create --label <标签>）",
        ));
    };
    if sub != "create" {
        return Err(RelayError::args(format!(
            "未知 token 子命令 `{sub}`（可用：token create --label <标签>）"
        )));
    }
    let mut config = None;
    let mut label = None;
    let mut max_uses = 1;
    let mut json = false;

    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--config" => config = Some(PathBuf::from(take_value(rest, &mut index, "--config")?)),
            "--label" => label = Some(take_value(rest, &mut index, "--label")?),
            "--max-uses" => {
                let text = take_value(rest, &mut index, "--max-uses")?;
                max_uses = text
                    .parse::<u32>()
                    .map_err(|e| RelayError::args(format!("--max-uses 非法（{text}）：{e}")))?;
                if max_uses == 0 {
                    return Err(RelayError::args("--max-uses 必须 ≥ 1"));
                }
            }
            "--json" => json = true,
            other => return Err(unknown_flag(other, "token create")),
        }
        index += 1;
    }

    let label = label.ok_or_else(|| RelayError::args("token create 需要 `--label <标签>`"))?;
    Ok(Command::TokenCreate {
        config,
        label,
        max_uses,
        json,
    })
}

fn parse_config_and_json(rest: &[String], command: &str) -> Result<(Option<PathBuf>, bool)> {
    let mut config = None;
    let mut json = false;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--config" => config = Some(PathBuf::from(take_value(rest, &mut index, "--config")?)),
            "--json" => json = true,
            other => return Err(unknown_flag(other, command)),
        }
        index += 1;
    }
    Ok((config, json))
}

fn take_value(args: &[String], index: &mut usize, flag: &str) -> Result<String> {
    let value = args
        .get(*index + 1)
        .ok_or_else(|| RelayError::args(format!("{flag} 需要一个值")))?;
    if value.starts_with("--") {
        return Err(RelayError::args(format!(
            "{flag} 需要一个值，但拿到的是另一个选项 `{value}`"
        )));
    }
    *index += 1;
    Ok(value.clone())
}

fn unknown_flag(flag: &str, command: &str) -> RelayError {
    RelayError::args(format!("{command} 不认识参数 `{flag}`（`--help` 看用法）"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn 空参数与帮助与版本() {
        assert_eq!(parse(args(&[])).expect("解析"), Command::Help);
        assert_eq!(parse(args(&["--help"])).expect("解析"), Command::Help);
        assert_eq!(parse(args(&["-h"])).expect("解析"), Command::Help);
        assert_eq!(parse(args(&["--version"])).expect("解析"), Command::Version);
        assert_eq!(parse(args(&["-V"])).expect("解析"), Command::Version);
    }

    #[test]
    fn init_全参数解析() {
        let command = parse(args(&[
            "init",
            "--dir",
            "/etc/wasmnest-relay",
            "--advertise",
            "relay.example.com",
            "--port",
            "4101",
            "--mode",
            "allowlist",
            "--allowlist",
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
            "--force",
        ]))
        .expect("解析");
        let Command::Init(init) = command else {
            panic!("应解析为 init");
        };
        assert_eq!(init.dir, PathBuf::from("/etc/wasmnest-relay"));
        assert_eq!(init.advertise.as_deref(), Some("relay.example.com"));
        assert_eq!(init.port, 4101);
        assert!(init.force);
        assert_eq!(init.mode, AccessMode::Allowlist);
        assert_eq!(init.allowlist.len(), 1);
    }

    #[test]
    fn init_默认端口为_4001_且监听可覆盖() {
        let Command::Init(init) = parse(args(&[
            "init",
            "--dir",
            "/data",
            "--listen",
            "/ip4/127.0.0.1/tcp/4002",
        ]))
        .expect("解析") else {
            panic!("应解析为 init");
        };
        assert_eq!(init.port, config::DEFAULT_RELAY_PORT);
        assert_eq!(init.listen.as_deref(), Some("/ip4/127.0.0.1/tcp/4002"));
    }

    #[test]
    fn init_缺_dir_或端口非法时给出可行动错误() {
        let err = parse(args(&["init", "--advertise", "relay.example.com"])).expect_err("应报错");
        assert!(err.to_string().contains("--dir"), "{err}");

        let err = parse(args(&["init", "--dir", "/data", "--port", "abc"])).expect_err("应报错");
        assert!(err.to_string().contains("--port"), "{err}");

        let err = parse(args(&["init", "--dir", "/data", "--port", "0"])).expect_err("应报错");
        assert!(err.to_string().contains("不能为 0"), "{err}");
    }

    #[test]
    fn init_白名单_peer_id_形状当场校验() {
        let err = parse(args(&[
            "init",
            "--dir",
            "/data",
            "--allowlist",
            "not-a-peer",
        ]))
        .expect_err("应报错");
        assert!(err.to_string().contains("PeerId"), "{err}");
    }

    #[test]
    fn run_doctor_print_addrs_解析() {
        assert_eq!(
            parse(args(&["run", "--config", "/data/config.toml"])).expect("解析"),
            Command::Run {
                config: Some(PathBuf::from("/data/config.toml"))
            }
        );
        assert_eq!(
            parse(args(&["doctor", "--json"])).expect("解析"),
            Command::Doctor {
                config: None,
                json: true
            }
        );
        assert_eq!(
            parse(args(&["print-addrs"])).expect("解析"),
            Command::PrintAddrs {
                config: None,
                json: false
            }
        );
    }

    #[test]
    fn token_create_解析与次数校验() {
        assert_eq!(
            parse(args(&[
                "token",
                "create",
                "--label",
                "phone",
                "--max-uses",
                "2",
                "--json"
            ]))
            .expect("解析"),
            Command::TokenCreate {
                config: None,
                label: "phone".to_string(),
                max_uses: 2,
                json: true,
            }
        );
        let err = parse(args(&[
            "token",
            "create",
            "--label",
            "phone",
            "--max-uses",
            "0",
        ]))
        .expect_err("应报错");
        assert!(err.to_string().contains("--max-uses"), "{err}");
        let err = parse(args(&["token", "create"])).expect_err("应报错");
        assert!(err.to_string().contains("--label"), "{err}");
        let err = parse(args(&["token", "revoke"])).expect_err("应报错");
        assert!(err.to_string().contains("token create"), "{err}");
    }

    #[test]
    fn 未知子命令与未知参数都指路到_help() {
        let err = parse(args(&["serve"])).expect_err("应报错");
        assert!(err.to_string().contains("--help"), "{err}");

        let err = parse(args(&["run", "--verbose"])).expect_err("应报错");
        assert!(err.to_string().contains("--verbose"), "{err}");
        assert!(err.to_string().contains("--help"), "{err}");
    }

    #[test]
    fn 选项缺值时不会被误当成值() {
        let err = parse(args(&["run", "--config", "--json"])).expect_err("应报错");
        assert!(err.to_string().contains("--config"), "{err}");
    }

    #[tokio::test]
    async fn init_落盘后可直接被_run_与_print_addrs_消费() {
        let dir = tempfile::tempdir().expect("临时目录");
        let data = dir.path().join("relay");
        let command = parse(vec![
            "init".to_string(),
            "--dir".to_string(),
            data.display().to_string(),
            "--advertise".to_string(),
            "relay.example.com".to_string(),
        ])
        .expect("解析");
        assert_eq!(run(command).await.expect("执行 init"), 0);

        let config_path = data.join(config::CONFIG_FILE_NAME);
        assert!(config_path.exists(), "应写出配置");
        let config = RelayConfig::load(&config_path).expect("配置可加载");
        assert_eq!(
            config.advertise.addrs,
            vec!["/dns4/relay.example.com/tcp/4001".to_string()]
        );
        let identity =
            RelayIdentity::load(&config.identity_path(&config_path)).expect("身份可加载");
        assert!(identity.peer_id().to_base58().starts_with("12D3"));

        // print-addrs 复用同一份配置与身份
        assert_eq!(
            run(parse(vec![
                "print-addrs".to_string(),
                "--config".to_string(),
                config_path.display().to_string(),
                "--json".to_string(),
            ])
            .expect("解析"))
            .await
            .expect("执行"),
            0
        );
    }

    #[tokio::test]
    async fn init_已存在配置时拒绝覆盖除非_force() {
        let dir = tempfile::tempdir().expect("临时目录");
        let data = dir.path().join("relay");
        let base = vec![
            "init".to_string(),
            "--dir".to_string(),
            data.display().to_string(),
            "--advertise".to_string(),
            "relay.example.com".to_string(),
        ];
        run(parse(base.clone()).expect("解析")).await.expect("首次");

        let err = run(parse(base.clone()).expect("解析"))
            .await
            .expect_err("二次应拒绝");
        assert!(err.to_string().contains("--force"), "{err}");

        let mut forced = base;
        forced.push("--force".to_string());
        assert_eq!(run(parse(forced).expect("解析")).await.expect("强制"), 0);
    }

    #[tokio::test]
    async fn init_缺_advertise_时拒绝并给本机自测出路() {
        let dir = tempfile::tempdir().expect("临时目录");
        let command = parse(vec![
            "init".to_string(),
            "--dir".to_string(),
            dir.path().display().to_string(),
        ])
        .expect("解析");
        let err = run(command).await.expect_err("应拒绝");
        let text = err.to_string();
        assert!(text.contains("advertise"), "{text}");
        assert!(text.contains("127.0.0.1"), "应给出本机自测参数：{text}");
        assert!(
            !dir.path().join(config::CONFIG_FILE_NAME).exists(),
            "校验失败不应落盘配置"
        );
    }

    #[tokio::test]
    async fn 本机自测形态仅给_listen_即可_init() {
        let dir = tempfile::tempdir().expect("临时目录");
        let data = dir.path().join("relay");
        let command = parse(vec![
            "init".to_string(),
            "--dir".to_string(),
            data.display().to_string(),
            "--listen".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        ])
        .expect("解析");
        assert_eq!(run(command).await.expect("执行"), 0);
        let config = RelayConfig::load(&data.join(config::CONFIG_FILE_NAME)).expect("加载");
        assert_eq!(config.listen.addrs, vec!["/ip4/127.0.0.1/tcp/4001"]);
    }

    #[tokio::test]
    async fn token_create_落盘并可被_enroll_校验() {
        let dir = tempfile::tempdir().expect("临时目录");
        let data = dir.path().join("relay");
        run(parse(vec![
            "init".to_string(),
            "--dir".to_string(),
            data.display().to_string(),
            "--advertise".to_string(),
            "relay.example.com".to_string(),
            "--mode".to_string(),
            "allowlist".to_string(),
        ])
        .expect("解析"))
        .await
        .expect("init");

        let config_path = data.join(config::CONFIG_FILE_NAME);
        assert_eq!(
            run(parse(vec![
                "token".to_string(),
                "create".to_string(),
                "--config".to_string(),
                config_path.display().to_string(),
                "--label".to_string(),
                "phone".to_string(),
            ])
            .expect("解析"))
            .await
            .expect("执行"),
            0
        );

        let store = TokenStore::load(&RelayConfig::tokens_path(&config_path)).expect("token 表");
        assert_eq!(store.summary(), vec![("phone".to_string(), 0, 1)]);
    }
}
