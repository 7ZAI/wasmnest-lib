//! P3 async host import 机制探针 fixture（测试专用，非生产插件）
//!
//! 与生产形态一致：导出 `guest-probe.run` 与导入 `host-probe.invoke` 都是同步
//! 签名。guest 侧因此是纯同步代码（无 `block_on`/无等待），宿主侧把 import 实现
//! 注册为原生 async —— 探针要证明的正是「这段宿主侧等待期间 Tokio 执行线程被
//! 归还」：guest 完全不需要感知。

wit_bindgen::generate!({
    path: "wit/p3-async-host-probe.wit",
    world: "p3-async-host-probe",
});

struct Guest;

impl crate::exports::wasmnest::p3_async_host_probe::guest_probe::Guest for Guest {
    fn run(mode: String) -> Result<String, String> {
        crate::wasmnest::p3_async_host_probe::host_probe::invoke(&mode)
    }
}

export!(Guest);
