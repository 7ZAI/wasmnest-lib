//! mDNS Service Advertisement（宿主自播面）
//!
//! 广播本设备的 `_wasmnest._tcp.local.` 服务，供移动端发现（ServerSupervisor 启动
//! 时经 `MdnsAdvertiserPort` 端口壳调用本管理器）。
//!
//! **共享守护模型**（并入 `engine`，owner=host）：
//! - 登记走 [`crate::engine::advertise_inner`]：共享守护注册 + 45s re-announce 续期 +
//!   句柄登记（ADVERTISERS 表），与 peer-net 节点身份 / 插件 advertise 同守护、互不
//!   注销——不再自建 `ServiceDaemon`（消灭「双 daemon 同绑 5353」病灶）；
//! - 停播走 [`crate::engine::stop_advertise_inner`]：表条目移除 + 续期取消 + 尽力
//!   unregister（失败仅 warn，靠缓存 TTL 收敛）——**不 shutdown 任何 daemon**；
//! - `is_advertising` 以本地登记 id 为准：id 在册 = 登记成功且未被 stop 清除。
//!   engine 的 owner=host 条目只随本面 stop 消失（`purge_for_plugin` 只碰插件属主，
//!   `stop_host_service` 只删 peer-net 自己的 id），故本地 id 与句柄表同生命周期。
//!
//! 转义注意：mdns-sd 注册时会转义实例名（`.` → `\.`、`\` → `\\`）。停播由 engine
//! 按**注册时 `ServiceInfo::get_fullname()` 的结果**（同源）寻址，业务侧禁止用
//! `format!("{}.{}", name, SERVICE_TYPE)` 重新拼接——含 `.` 的主机名（macOS/Linux）
//! 会导致 unregister 查不到记录、僵尸 mDNS 记录泄漏到局域网。
//!
//! 与插件广播原语（`engine::advertise`）的差别：插件原语走权限门 + 能力路由 +
//! JSON 配置；本面是宿主 supervisor 的直接调用面，配置为强类型
//! [`AdvertiseConfig`]（类型定义在 `types`）。
//!
//! （自 `src-tauri/src/mdns/` 迁入后随共享守护收口：原「自持 daemon + 工厂注入 +
//! shutdown 生命周期」已完全由 engine 句柄表取代。）

use mdns_sd::ServiceInfo;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::engine;
use crate::types::{AdvertiseConfig, AdvertiserError, AdvertiserResult, SERVICE_TYPE};

/// 广播登记层端口：生产 = engine 共享守护（owner=host）；测试 = fake 记录
/// 「对引擎注册/注销的调用契约」。
///
/// **为什么必须经过这个端口**：共享守护句柄表（`engine` 的 ADVERTISERS）是进程级
/// 单例，无法注入；把「登记动作」收口到此 trait，测试才能不触真实守护
/// （peer-net `FakePorts` 同款思路）而验证 start/stop 传给引擎的参数形状。
pub trait AdvertiseTarget: Send + Sync + 'static {
    /// 登记广播到共享守护（返回 engine 句柄 id）；
    /// 失败 = 登记层侧错误（生产路径 engine `daemon().register` 失败可达）
    fn register(
        &self,
        owner: &str,
        service_type: &str,
        service_info: &ServiceInfo,
    ) -> Result<String, String>;
    /// 停播（按句柄 id 寻址；幂等：未知句柄 Ok(false)）
    fn unregister(&self, owner: &str, advertise_id: &str) -> Result<bool, String>;
}

/// 生产登记层：收编进 engine 共享守护
///
/// 依赖 `crate::ports::ports()` 已由插件宿主装配链安装（`PluginHost::new` →
/// `install_capability_domain_ports` → `host_api::mdns::install`）；未装时调用会
/// fail-visible panic（与 engine 的 `uninstalled_ports_panic_loudly` 同先例）。
struct SharedDaemonTarget;

impl AdvertiseTarget for SharedDaemonTarget {
    fn register(
        &self,
        owner: &str,
        service_type: &str,
        service_info: &ServiceInfo,
    ) -> Result<String, String> {
        engine::advertise_inner(
            &crate::ports::ports(),
            owner,
            service_type.to_string(),
            service_info.clone(),
        )
    }
    fn unregister(&self, owner: &str, advertise_id: &str) -> Result<bool, String> {
        engine::stop_advertise_inner(owner, advertise_id, &crate::ports::ports())
    }
}

/// mDNS 广播管理器（宿主自播面）
pub struct MdnsAdvertiser {
    /// engine 句柄表里的登记 id（owner=host 的自播条目）；None = 未广播。
    /// 生命周期与 engine 表条目同步（register 成功落 id、stop 清 id），
    /// `is_advertising` 以此为准
    advertise_id: Arc<RwLock<Option<String>>>,
    /// 登记层端口（生产=engine 共享守护，测试=fake）
    target: Arc<dyn AdvertiseTarget>,
}

impl MdnsAdvertiser {
    /// 创建广播管理器（生产登记层：engine 共享守护，owner=host）
    pub fn new() -> Self {
        Self::with_target(Arc::new(SharedDaemonTarget))
    }

    /// 创建广播管理器并注入登记层端口（仅测试使用）
    fn with_target(target: Arc<dyn AdvertiseTarget>) -> Self {
        Self {
            advertise_id: Arc::new(RwLock::new(None)),
            target,
        }
    }

    /// 启动服务广播
    pub async fn start(&self, config: AdvertiseConfig) -> AdvertiserResult<()> {
        // 输入校验在 Rust 端（§8 红线）：空服务名 / 端口 0 / 超长实例名直接拒绝
        config.validate()?;

        let mut id_guard = self.advertise_id.write().await;
        if id_guard.is_some() {
            tracing::warn!("[MdnsAdvertiser] Already advertising");
            return Ok(());
        }

        let instance_name = &config.service_name;
        // TXT 记录的 key 在 mdns-sd 中自动转小写
        let properties: Vec<(String, String)> = config.txt_records.into_iter().collect();

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            instance_name,
            &format!("{instance_name}.local."),
            "",
            config.port,
            &*properties,
        )
        .map_err(|e| AdvertiserError::Internal(format!("Failed to create ServiceInfo: {e}")))?
        .enable_addr_auto();

        // 登记成功后才落状态（半状态防污染）：engine 侧 register = 共享守护注册 +
        // 句柄登记 + 续期任务挂载，返回的 id 是停播凭据
        let advertise_id = self
            .target
            .register("host", SERVICE_TYPE, &service_info)
            .map_err(|e| {
                AdvertiserError::Internal(format!("Failed to register mDNS service: {e}"))
            })?;
        *id_guard = Some(advertise_id.clone());

        tracing::info!(
            "[MdnsAdvertiser] Advertising {} as {} on port {} (handle {})",
            SERVICE_TYPE,
            instance_name,
            config.port,
            advertise_id
        );
        Ok(())
    }

    /// 停止服务广播
    ///
    /// 顺序：engine 停播（表条目移除 + 续期取消）成功后才清本地 id，避免
    /// 「先置 None 再失败」导致的悬挂。unregister 为尽力而为（engine 失败仅
    /// warn，靠缓存 TTL 收敛）、共享守护不 shutdown——与插件 advertise 停播
    /// 语义全局统一；原实现的「unregister 失败保留广播状态供重试」分支随
    /// 独立守护一起退役。
    pub async fn stop(&self) -> AdvertiserResult<()> {
        let mut id_guard = self.advertise_id.write().await;
        let Some(advertise_id) = id_guard.as_ref() else {
            // 未在广播时幂等返回
            return Ok(());
        };
        self.target.unregister("host", advertise_id).map_err(|e| {
            AdvertiserError::Internal(format!("Failed to unregister mDNS service: {e}"))
        })?;
        // 登记层 Ok(false)（表里已无该句柄）同样视为已停播
        *id_guard = None;
        tracing::info!("[MdnsAdvertiser] Stopped advertising");
        Ok(())
    }

    /// 是否正在广播（本地 id 在册 = 登记成功且未被 stop 清除）
    pub async fn is_advertising(&self) -> bool {
        self.advertise_id.read().await.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// 测试用 fake 登记层：记录 register/unregister 调用契约、可注入失败——
    /// 验证「对引擎登记层的调用契约」而非真实守护（共享守护单例不可注入）
    struct FakeTarget {
        /// (owner, service_type, fullname)
        register_calls: Mutex<Vec<(String, String, String)>>,
        /// (owner, advertise_id)
        unregister_calls: Mutex<Vec<(String, String)>>,
        register_result: Mutex<Result<String, String>>,
        unregister_result: Mutex<Result<bool, String>>,
        next_id: Mutex<usize>,
    }

    impl FakeTarget {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                register_calls: Mutex::new(Vec::new()),
                unregister_calls: Mutex::new(Vec::new()),
                register_result: Mutex::new(Ok("mdnsad-fake".to_string())),
                unregister_result: Mutex::new(Ok(true)),
                next_id: Mutex::new(0),
            })
        }
        fn with_register_failure(err: &str) -> Arc<Self> {
            let t = Self::new();
            *t.register_result.lock().unwrap() = Err(err.to_string());
            t
        }
        fn with_unregister_failure(err: &str) -> Arc<Self> {
            let t = Self::new();
            *t.unregister_result.lock().unwrap() = Err(err.to_string());
            t
        }
        fn register_calls(&self) -> Vec<(String, String, String)> {
            self.register_calls.lock().unwrap().clone()
        }
        fn unregister_calls(&self) -> Vec<(String, String)> {
            self.unregister_calls.lock().unwrap().clone()
        }
    }

    impl AdvertiseTarget for FakeTarget {
        fn register(
            &self,
            owner: &str,
            service_type: &str,
            service_info: &ServiceInfo,
        ) -> Result<String, String> {
            self.register_calls.lock().unwrap().push((
                owner.to_string(),
                service_type.to_string(),
                service_info.get_fullname().to_string(),
            ));
            let mut n = self.next_id.lock().unwrap();
            *n += 1;
            let result = self.register_result.lock().unwrap().clone();
            result.map(|_| format!("mdnsad-fake-{n}"))
        }
        fn unregister(&self, owner: &str, advertise_id: &str) -> Result<bool, String> {
            self.unregister_calls
                .lock()
                .unwrap()
                .push((owner.to_string(), advertise_id.to_string()));
            self.unregister_result.lock().unwrap().clone()
        }
    }

    fn fake_advertiser(target: Arc<FakeTarget>) -> (MdnsAdvertiser, Arc<FakeTarget>) {
        (MdnsAdvertiser::with_target(target.clone()), target)
    }

    fn config(name: &str) -> AdvertiseConfig {
        AdvertiseConfig {
            service_name: name.to_string(),
            port: 7888,
            txt_records: HashMap::new(),
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().unwrap().block_on(f)
    }

    #[test]
    fn new_is_not_advertising() {
        let adv = MdnsAdvertiser::new();
        assert!(!block_on(adv.is_advertising()));
    }

    #[test]
    fn stop_when_not_advertising_is_idempotent() {
        let (adv, fake) = fake_advertiser(FakeTarget::new());
        block_on(async {
            assert!(adv.stop().await.is_ok());
            assert!(adv.stop().await.is_ok());
        });
        // 未广播不该触停播路径
        assert!(fake.unregister_calls().is_empty());
    }

    #[test]
    fn service_type_constant_locked() {
        // 跨端发现契约：移动端按此类型广播/监听，改 `_tcp` → `_udp` 必须触发测试失败
        assert_eq!(SERVICE_TYPE, "_wasmnest._tcp.local.");
    }

    /// 调用契约 + 转义回归锁：start 传给引擎登记层的 owner=host、
    /// service_type=SERVICE_TYPE、fullname 是注册时同源的转义结果（含点主机名
    /// `.` → `\.`，engine 停播按表内 fullname 寻址才能命中）；stop 走同一
    /// 句柄 id。这是原 `fullname_matches_escaped_service_info` 的共享守护版。
    #[test]
    fn register_contract_escapes_instance_and_owner_is_host() {
        let (adv, fake) = fake_advertiser(FakeTarget::new());
        block_on(async {
            assert!(adv.start(config("WasmNest-my.desktop")).await.is_ok());
            assert!(adv.is_advertising().await);

            let calls = fake.register_calls();
            assert_eq!(calls.len(), 1);
            let (owner, service_type, fullname) = &calls[0];
            assert_eq!(owner, "host");
            assert_eq!(service_type, SERVICE_TYPE);
            assert_eq!(fullname, "WasmNest-my\\.desktop._wasmnest._tcp.local.");

            assert!(adv.stop().await.is_ok());
            assert!(!adv.is_advertising().await);
            let stops = fake.unregister_calls();
            assert_eq!(stops.len(), 1);
            assert_eq!(stops[0].0, "host");
        });
    }

    #[test]
    fn start_validates_empty_service_name() {
        let (adv, fake) = fake_advertiser(FakeTarget::new());
        block_on(async {
            let err = adv.start(config("  ")).await.unwrap_err();
            assert!(
                err.to_string().contains("服务名不能为空"),
                "unexpected: {err}"
            );
            assert!(!adv.is_advertising().await);
        });
        // 校验失败不该触登记层
        assert!(fake.register_calls().is_empty());
    }

    #[test]
    fn start_validates_zero_port() {
        let (adv, fake) = fake_advertiser(FakeTarget::new());
        let mut c = config("WasmNest-Test");
        c.port = 0;
        block_on(async {
            let err = adv.start(c).await.unwrap_err();
            assert!(
                err.to_string().contains("端口不能为 0"),
                "unexpected: {err}"
            );
            assert!(!adv.is_advertising().await);
        });
        assert!(fake.register_calls().is_empty());
    }

    /// 重复 start：已广播时警告并返回 Ok，绝不二次登记
    #[test]
    fn start_twice_does_not_double_register() {
        let (adv, fake) = fake_advertiser(FakeTarget::new());
        block_on(async {
            assert!(adv.start(config("WasmNest-Test")).await.is_ok());
            assert!(adv.start(config("WasmNest-Test")).await.is_ok());
        });
        assert_eq!(fake.register_calls().len(), 1);
    }

    /// 登记失败：不落半状态（id 未写），可重试
    #[test]
    fn start_injected_failure_keeps_not_advertising() {
        let (adv, _) = fake_advertiser(FakeTarget::with_register_failure(
            "injected register failure",
        ));
        block_on(async {
            assert!(adv.start(config("WasmNest-Test")).await.is_err());
            assert!(!adv.is_advertising().await);
            // 状态未被污染，再次 start 仍走登记路径（再失败）
            assert!(adv.start(config("WasmNest-Test")).await.is_err());
        });
    }

    /// 停播失败（登记层返回 Err）时保持广播状态供重试 [advertise_target]；
    /// 生产路径 engine 尽力注销恒 Ok，此分支为状态机防御（id 不因单次失败丢失）
    #[test]
    fn stop_failure_keeps_state_for_retry() {
        let (adv, _) = fake_advertiser(FakeTarget::with_unregister_failure(
            "injected unregister failure",
        ));
        block_on(async {
            assert!(adv.start(config("WasmNest-Test")).await.is_ok());
            assert!(adv.stop().await.is_err());
            // 状态未污染：仍标记广播，可重试
            assert!(adv.is_advertising().await);
            assert!(adv.stop().await.is_err());
        });
    }

    #[test]
    fn stop_success_clears_state() {
        let (adv, fake) = fake_advertiser(FakeTarget::new());
        block_on(async {
            assert!(adv.start(config("WasmNest-Test")).await.is_ok());
            assert!(adv.is_advertising().await);
            assert!(adv.stop().await.is_ok());
            assert!(!adv.is_advertising().await);
            assert!(adv.stop().await.is_ok(), "重复停播幂等");
        });
        assert_eq!(fake.unregister_calls().len(), 1, "停播只发生一次");
    }
}
