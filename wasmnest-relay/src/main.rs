//! 二进制入口：只做参数转发与退出码映射，逻辑全在库侧（便于单测）。

use wasmnest_relay::{cli, RELAY_VERSION};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match cli::parse(args) {
        Ok(command) => match cli::run(command).await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("错误：{err}");
                1
            }
        },
        Err(err) => {
            // 参数错误单独退出码 2：脚本能区分「用法错」与「运行失败」
            eprintln!("{err}");
            eprintln!();
            eprint!("{}", cli::USAGE.replace("{version}", RELAY_VERSION));
            2
        }
    };
    std::process::exit(code);
}
