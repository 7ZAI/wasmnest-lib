//! host-audio 域行为用例（权限门 / 参数仲裁 / 属主隔离 / 游标拉取 / 契约漂移）
//!
//! 这些断言的是**域契约**而不是 WIT 绑定形状：原语函数（`primitives`）不依赖
//! `common-host`，因此默认形态的 `cargo test` 就能覆盖它们。WIT ↔ 原语的漂移锁在文件
//! 末尾，逐条比对 `wit/audio.wit` 的函数名与 `primitives` 的实现函数。
//!
//! 夹具属主 id 统一用 `audio-test.*`（不是产品插件 id 形状）：域只把它当字符串用。

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::engine::AudioHub;
use crate::format::{PcmBuffer, PcmFormat, SampleFormat};
use crate::plugin_binding::ports::AudioPorts;
use crate::plugin_binding::primitives::*;
use crate::test_util::ScriptedBackend;
use crate::wire::{PERMISSION_AUDIO_CAPTURE, PERMISSION_AUDIO_IO};
use crate::AudioLimits;

/// 权限登记表（等价宿主 PermissionManager 的授予面）
struct TestPorts {
    granted: Mutex<HashSet<(String, String)>>,
}

impl TestPorts {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            granted: Mutex::new(HashSet::new()),
        })
    }

    fn grant(&self, plugin_id: &str, permissions: &[&str]) {
        let mut granted = self.granted.lock().unwrap_or_else(|e| e.into_inner());
        for permission in permissions {
            granted.insert((plugin_id.to_string(), (*permission).to_string()));
        }
    }
}

impl AudioPorts for TestPorts {
    fn check_permission(&self, plugin_id: &str, permission: &str, _api: &str) -> bool {
        self.granted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&(plugin_id.to_string(), permission.to_string()))
    }
}

/// 夹具：真实引擎 + 可编排后端 + 可授予端口的组合
struct Fixture {
    grants: Arc<TestPorts>,
    ports: Arc<dyn AudioPorts>,
    hub: AudioHub,
    backend: ScriptedBackend,
}

impl Fixture {
    fn new() -> Self {
        let backend = ScriptedBackend::new(PcmFormat::new(16_000, 1, SampleFormat::S16));
        let grants = TestPorts::new();
        let ports: Arc<dyn AudioPorts> = grants.clone();
        let hub = AudioHub::new(Arc::new(backend.clone()), AudioLimits::default());
        Self {
            grants,
            ports,
            hub,
            backend,
        }
    }

    fn grant(&self, plugin_id: &str, permissions: &[&str]) {
        self.grants.grant(plugin_id, permissions);
    }

    fn grant_all(&self, plugin_id: &str) {
        self.grant(plugin_id, &[PERMISSION_AUDIO_CAPTURE, PERMISSION_AUDIO_IO]);
    }

    fn push_frames(&self, frames: usize, sample: i16) {
        let samples = vec![sample; frames];
        self.backend.push(
            PcmFormat::new(16_000, 1, SampleFormat::S16),
            &PcmBuffer::S16(&samples),
        );
    }
}

const OWNER: &str = "audio-test.owner";
const OTHER: &str = "audio-test.other";

/// P-001 正例：8 条原语的完整链路（枚举 → 打开 → 启动 → 拉取 → 电平 → 状态 → 关闭）
#[test]
fn full_primitive_chain_produces_pullable_pcm() {
    let fixture = Fixture::new();
    fixture.grant_all(OWNER);

    let devices = audio_list_devices(&fixture.ports, OWNER, &fixture.hub).expect("枚举成功");
    assert_eq!(devices.len(), 1);
    assert!(devices[0].is_default);

    let handle = audio_open(
        &fixture.ports,
        OWNER,
        &fixture.hub,
        r#"{"targetSampleRate":16000,"targetChannels":1,"ringBytes":4096}"#,
    )
    .expect("打开成功");
    assert!(handle.starts_with("audio-"), "句柄形状：{handle}");

    audio_start(&fixture.ports, OWNER, &fixture.hub, &handle).expect("启动成功");
    fixture.push_frames(64, 16_384);

    let fetched = audio_ring_fetch(&fixture.ports, OWNER, &fixture.hub, &handle, 0, 4_096)
        .expect("拉取成功")
        .expect("有数据");
    assert_eq!(fetched.data.len(), 128, "64 帧 × 2 字节");
    assert_eq!(fetched.next_offset, 128);
    assert!(
        audio_ring_fetch(&fixture.ports, OWNER, &fixture.hub, &handle, 128, 4_096)
            .expect("拉取成功")
            .is_none(),
        "追平即无数据"
    );

    let level = audio_level(&fixture.ports, OWNER, &fixture.hub, &handle)
        .expect("电平成功")
        .expect("有读数");
    assert!(
        (level.rms - 0.5).abs() < 1e-3,
        "16384/32768 = 0.5，实得 {}",
        level.rms
    );

    let status: serde_json::Value = serde_json::from_str(
        &audio_status(&fixture.ports, OWNER, &fixture.hub, &handle).expect("状态成功"),
    )
    .expect("status 是 JSON");
    assert_eq!(status["state"], "running");
    assert_eq!(status["framesCaptured"], 64);
    assert_eq!(status["actualFormat"]["sampleFormat"], "s16");

    audio_stop(&fixture.ports, OWNER, &fixture.hub, &handle).expect("停止成功");
    audio_close(&fixture.ports, OWNER, &fixture.hub, &handle).expect("关闭成功");
    assert_eq!(fixture.hub.live_count(), 0);
}

/// P-002 反例：两个权限域独立——只有 `audio:capture` 时读面全拒，只有 `audio:io` 时写面全拒
#[test]
fn permission_domains_are_independent() {
    let fixture = Fixture::new();
    fixture.grant(OWNER, &[PERMISSION_AUDIO_CAPTURE]);

    for err in [
        audio_list_devices(&fixture.ports, OWNER, &fixture.hub).expect_err("枚举被拒"),
        audio_status(&fixture.ports, OWNER, &fixture.hub, "audio-x").expect_err("状态被拒"),
        audio_ring_fetch(&fixture.ports, OWNER, &fixture.hub, "audio-x", 0, 16)
            .expect_err("拉取被拒"),
        audio_level(&fixture.ports, OWNER, &fixture.hub, "audio-x").expect_err("电平被拒"),
    ] {
        assert_eq!(err, "permission denied: audio:io", "拒绝文案必须是稳定词汇");
    }
    let handle = audio_open(&fixture.ports, OWNER, &fixture.hub, "{}").expect("capture 权限可打开");

    let fixture = Fixture::new();
    fixture.grant(OWNER, &[PERMISSION_AUDIO_IO]);
    let err =
        audio_open(&fixture.ports, OWNER, &fixture.hub, "{}").expect_err("无 capture 权限必须拒");
    assert_eq!(err, "permission denied: audio:capture");
    // 句柄形状不影响「已授权可读」：不存在的句柄得到的是引擎错误而不是权限错误
    let err = audio_status(&fixture.ports, OWNER, &fixture.hub, &handle).expect_err("句柄不存在");
    assert!(!err.contains("permission denied"), "实得 {err}");
}

/// P-003 反例：权限判定先于参数解析（未授权时不回显解析行为）
#[test]
fn permission_gate_precedes_argument_parsing() {
    let fixture = Fixture::new();
    let err = audio_open(
        &fixture.ports,
        "audio-test.nobody",
        &fixture.hub,
        "not json",
    )
    .expect_err("必须失败");
    assert_eq!(err, "permission denied: audio:capture");
    assert_eq!(fixture.hub.live_count(), 0);
}

/// P-004 反例：config-json 非法与参数越界都显性失败，且不留下会话
#[test]
fn invalid_config_is_rejected_without_side_effects() {
    let fixture = Fixture::new();
    fixture.grant_all(OWNER);

    let err = audio_open(&fixture.ports, OWNER, &fixture.hub, "{oops").expect_err("非法 JSON");
    assert!(err.contains("invalid config json"), "实得 {err}");

    for config in [
        r#"{"ringBytes":0}"#,
        r#"{"ringBytes":999999999}"#,
        r#"{"targetSampleRate":100}"#,
        r#"{"targetChannels":7}"#,
    ] {
        let err = audio_open(&fixture.ports, OWNER, &fixture.hub, config)
            .err()
            .unwrap_or_else(|| panic!("{config} 必须被拒"));
        assert!(
            err.contains("invalid audio capture config"),
            "{config} → {err}"
        );
    }
    assert_eq!(fixture.hub.live_count(), 0, "被拒的打开不得留下会话");
}

/// P-005 反例：句柄形状非法与属主越权（前者是参数错误，后者是隔离红线）
#[test]
fn handle_shape_and_ownership_are_enforced() {
    let fixture = Fixture::new();
    fixture.grant_all(OWNER);
    fixture.grant_all(OTHER);

    let err = audio_start(&fixture.ports, OWNER, &fixture.hub, "mic-1").expect_err("形状非法");
    assert!(err.contains("audio-"), "错误必须点名前缀，实得 {err}");

    let handle = audio_open(&fixture.ports, OWNER, &fixture.hub, "{}").expect("打开成功");
    let err = audio_start(&fixture.ports, OTHER, &fixture.hub, &handle).expect_err("越权必须拒");
    assert!(err.contains("not owner"), "实得 {err}");
    let err =
        audio_close(&fixture.ports, OTHER, &fixture.hub, &handle).expect_err("越权 close 必须拒");
    assert!(err.contains("not owner"), "实得 {err}");
    assert_eq!(fixture.hub.live_count(), 1, "越权不得摘掉别人的句柄");
}

/// P-006 反例：配额经原语面生效，且错误点名上限
#[test]
fn quota_is_enforced_through_the_primitive_face() {
    let fixture = Fixture::new();
    fixture.grant_all(OWNER);
    audio_open(&fixture.ports, OWNER, &fixture.hub, "{}").expect("第 1 条");
    audio_open(&fixture.ports, OWNER, &fixture.hub, "{}").expect("第 2 条");
    let err = audio_open(&fixture.ports, OWNER, &fixture.hub, "{}").expect_err("第 3 条必须被拒");
    assert!(
        err.contains("reached per-plugin audio stream limit (2)"),
        "实得 {err}"
    );
}

// ==================== 契约漂移锁（WIT ↔ 原语 ↔ 描述符） ====================

/// WIT 分片里 `interface host-audio` 的函数名（kebab-case，按出现顺序）
fn wit_function_names() -> Vec<String> {
    let raw = include_str!("../../wit/audio.wit");
    let mut inside = false;
    let mut names = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("interface host-audio") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if trimmed.starts_with("world ") {
            break;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once(": func(") {
            names.push(name.trim().to_string());
        }
    }
    names
}

/// P-007 漂移锁：WIT 的每条原语都在 `primitives` 有同名实现（kebab → snake，`audio_` 前缀）
///
/// 这条锁钉的是「契约面增删函数但实现没跟上」——WIT 编译器只校验 binding，不校验域实现
/// 是否覆盖了业务语义；反向（实现了但 WIT 没声明）同样红，避免留下没人能调的 API。
#[test]
fn every_wit_function_has_a_matching_primitive() {
    let names = wit_function_names();
    assert_eq!(names.len(), 8, "host-audio v1 是 8 条原语，实得 {names:?}");
    let primitives = include_str!("primitives.rs");
    for name in &names {
        let snake = name.replace('-', "_");
        let needle = format!("pub fn audio_{snake}(");
        assert!(
            primitives.contains(&needle),
            "WIT 原语 `{name}` 缺实现：primitives 里找不到 `{needle}`"
        );
    }
    // 反向：primitives 里的 `pub fn audio_*` 全部必须在 WIT 里声明
    for line in primitives.lines() {
        let Some(rest) = line.trim().strip_prefix("pub fn audio_") else {
            continue;
        };
        let Some(snake) = rest.split('(').next() else {
            continue;
        };
        let kebab = snake.replace('_', "-");
        assert!(
            names.contains(&kebab),
            "primitives 实现了 WIT 未声明的原语 `{kebab}`（插件永远调不到）"
        );
    }
}

/// P-008 漂移锁：描述符常量 ↔ WIT 文档 / wire 权限词汇 / 包名
#[test]
fn descriptor_constants_match_the_wit_slice() {
    use crate::plugin_binding::{MODULE_INTERFACES, MODULE_NAME, MODULE_PERMISSIONS};
    use crate::wire::{
        HANDLE_PREFIX, PERMISSION_AUDIO_CAPTURE as CAPTURE, PERMISSION_AUDIO_IO as IO,
    };

    assert_eq!(MODULE_NAME, "audio");
    assert_eq!(
        MODULE_PERMISSIONS,
        &[CAPTURE, IO],
        "描述符权限位必须与 wire 同值"
    );
    let expected_interface = format!("{}/host-audio", crate::WIT_PACKAGE);
    assert_eq!(MODULE_INTERFACES, &[expected_interface.as_str()]);

    let raw = include_str!("../../wit/audio.wit");
    for permission in MODULE_PERMISSIONS {
        assert!(
            raw.contains(permission),
            "WIT 文档必须写明权限位 `{permission}`（插件作者据此申请授权）"
        );
    }
    assert!(raw.contains(&format!("package {};", crate::WIT_PACKAGE)));
    assert!(raw.contains(HANDLE_PREFIX), "WIT 文档必须点名句柄前缀");
}

// ==================== 生命周期钩子（`common-host`） ====================

/// 钩子与 Host trait 的装配面（只在 common-host 形态下存在）
#[cfg(feature = "common-host")]
mod bound {
    use super::*;
    use crate::plugin_binding::{
        manifest_load_with, on_manifest_load, ManifestLoadFailure, HOOKS, MODULE_NAME,
    };

    /// 独立引擎（不碰进程级单例：用例可显式传 `None` 验证不可用分支）
    fn test_hub() -> Arc<AudioHub> {
        let backend = ScriptedBackend::new(PcmFormat::new(16_000, 1, SampleFormat::S16));
        Arc::new(AudioHub::new(Arc::new(backend), AudioLimits::default()))
    }

    /// 全局引擎必须先于插件装载：夹具装一次（进程级单例，首个装配者胜出）
    fn install_global_hub() {
        crate::plugin_binding::install_hub(test_hub());
    }

    /// P-009 正例：缺省 / 区间两端可装载；0 与越界一律拒绝（不夹取）
    #[test]
    fn manifest_quota_is_arbitrated_at_load_time() {
        let hub = test_hub();
        let owner = "audio-test.manifest-quota";

        // 声明了音频权限但未声明 audioQuota ⇒ 默认档（作用域含权限声明）
        manifest_load_with(
            Some(Arc::clone(&hub)),
            owner,
            r#"{"permissions":["audio:capture"]}"#,
        )
        .expect("声明音频权限即默认档");
        assert_eq!(
            hub.quota_of(owner),
            hub.limits().max_sessions_per_owner,
            "未声明 audioQuota ⇒ 默认档"
        );

        manifest_load_with(Some(Arc::clone(&hub)), owner, r#"{"audioQuota":1}"#)
            .expect("下界可装载");
        assert_eq!(hub.quota_of(owner), 1);
        let ceiling = hub.limits().max_sessions_ceiling_per_owner;
        manifest_load_with(
            Some(Arc::clone(&hub)),
            owner,
            &format!(r#"{{"audioQuota":{ceiling}}}"#),
        )
        .expect("上界可装载");
        assert_eq!(hub.quota_of(owner), ceiling);

        for bad in [0usize, ceiling + 1, 10_000] {
            let err = manifest_load_with(
                Some(Arc::clone(&hub)),
                owner,
                &format!(r#"{{"audioQuota":{bad}}}"#),
            )
            .expect_err(&format!("audioQuota={bad} 必须被拒"));
            assert!(
                matches!(err, ManifestLoadFailure::Rejected(_)),
                "插件声明越界必须分类为 Rejected，实得 {err:?}"
            );
            let err = err.to_string();
            assert!(
                err.contains(&bad.to_string()) && err.contains("audioQuota"),
                "错误必须点名越界值与字段，实得 {err}"
            );
        }
        assert_eq!(hub.quota_of(owner), ceiling, "被拒的声明不得改写生效配额");

        // 生产入口（进程级引擎）同样可仲裁
        install_global_hub();
        on_manifest_load(owner, r#"{"audioQuota":1}"#).expect("装配后钩子可仲裁");
        assert_eq!(
            crate::plugin_binding::registry::try_hub()
                .expect("已装配")
                .quota_of(owner),
            1
        );
    }

    /// P-012 反例：引擎未装配时只有声明音频能力的 manifest 受影响，且分类为 `Unavailable`
    ///
    /// 现场来源：未装配音频引擎时钩子拒绝每一个 manifest，10 个随包应用全部装载失败。
    /// 加载隔离要求：无关应用照常装载，音频应用也装载（原语运行期显性报错）。
    #[test]
    fn missing_engine_is_unavailable_and_isolated_to_audio_manifests() {
        let owner = "audio-test.missing-engine";

        for manifest in [
            r#"{"permissions":["audio:capture"]}"#,
            r#"{"permissions":["audio:io"]}"#,
            r#"{"audioQuota":1}"#,
        ] {
            let err = manifest_load_with(None, owner, manifest)
                .expect_err("声明音频能力的 manifest 应得到 Unavailable");
            assert!(
                matches!(err, ManifestLoadFailure::Unavailable(_)),
                "引擎缺口不是插件声明问题，必须分类为 Unavailable，实得 {err:?}"
            );
            assert!(
                err.to_string().contains("install_hub"),
                "错误必须点名装配入口，实得 {err}"
            );
        }

        // 其余应用完全不受影响（含无 permissions 字段与无关权限）
        for manifest in [
            r#"{"id":"x","name":"x","version":"1.0.0"}"#,
            r#"{"permissions":["storage","network:http"]}"#,
            r#"{"permissions":[]}"#,
        ] {
            manifest_load_with(None, owner, manifest).unwrap_or_else(|e| {
                panic!("非音频 manifest 不得被音频域阻断: {manifest} -> {e:?}")
            });
        }
    }

    /// P-010 正例：钩子与模块描述符自报一致（内核按 name 索引，不能各说各话）
    #[test]
    fn hooks_and_module_descriptor_agree() {
        assert_eq!(HOOKS.name, MODULE_NAME);
        assert_eq!(crate::plugin_binding::DESC.name, MODULE_NAME);
        assert_eq!(
            crate::plugin_binding::DESC.permissions,
            crate::plugin_binding::MODULE_PERMISSIONS
        );
    }

    /// P-011 正例：`impl Host for WasmPluginState` 存在（编译期证明，运行期无对象可测）
    #[test]
    fn host_trait_is_implemented_for_the_plugin_state() {
        fn assert_impl<T: crate::plugin_binding::wasmnest::audio::host_audio::Host>() {}
        assert_impl::<wasmnest_host_kit::WasmPluginState>();
    }
}
