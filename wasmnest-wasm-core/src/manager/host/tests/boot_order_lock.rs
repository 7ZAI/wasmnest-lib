//! 装配顺序锁：能力域端口必须先于插件扫描安装。
//!
//! 现场来源：端口装在扫描之后时，扫描期 `DomainHooks::on_manifest_load` 取不到
//! 能力域引擎（如 audio 的 `install_hub`），域钩子在装载期不可用。域侧已有
//! `Unavailable` 隔离兜底，但顺序错误仍会让该域的应用带着「引擎未装配」状态启动。
//!
//! 判据用源码顺序而不是运行期探针：两者在同一函数里，位置关系是装配契约的一部分；
//! 运行期探针受进程级单例与用例并行顺序影响，无法稳定区分「先装后扫」。

#[test]
fn capability_domain_ports_precede_plugin_scan() {
    let source = include_str!("../../host.rs");
    let install = source
        .find("install_capability_domain_ports(&wasm_host_ctx)")
        .expect("PluginHost::new 必须调用 install_capability_domain_ports");
    let scan = source
        .find("PluginLoader::load_builtin_and_user")
        .expect("PluginHost::new 必须调用 PluginLoader::load_builtin_and_user");
    assert!(
        install < scan,
        "能力域端口必须先于插件扫描安装：扫描期的 manifest 钩子依赖域引擎，\
         install={install}, scan={scan}"
    );
}
