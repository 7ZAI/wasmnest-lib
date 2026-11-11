//! WasmNest 音频采集能力域（`host-audio` 8 条原语）+ 可复用 PCM 采集引擎面
//!
//! ## 两层结构
//!
//! ```text
//!   backend / format / level / ring / engine      引擎面（零 wasm、零原生音频依赖）
//!   cpal_backend（feature `backend-cpal`）        可选后端适配器（ALSA/WASAPI/CoreAudio/AAudio）
//!   test_util（cfg(test) / feature `test-util`）  可编排后端（无硬件投喂帧）
//!   plugin_binding（ports / primitives / registry / WIT 绑定）  能力域层
//! ```
//!
//! **引擎面**只做四件机制事：枚举输入设备、按参数打开采集流、把设备原生 PCM 归一成
//! **目标采样率 + 目标声道数的交错 S16LE** 放进**有界帧环**供属主按游标拉取、给出电平
//! 快照。它不含任何产品语义（无录音会话 / 转写 / VAD / 说话人 / 存储），也不认识任何
//! ASR 引擎——语音→文字的编排归应用仓插件（AGENTS §3.5）。
//!
//! ## 形态（AGENTS §3.1）
//!
//! - **默认形态 = 纯引擎 + 端口 + [`CaptureBackend`] trait**：零 WIT、零 SDK、
//!   零 wasmtime、零宿主框架、零原生音频库。任何宿主（桌面 / 移动 / 无头 / 第三方）
//!   可直接引用，也可以自带后端实现 [`CaptureBackend`] 注入（例如移动端要精确控制
//!   `RECORD_AUDIO` 生命周期与音频焦点时）。
//! - `common-host`：装配桌面 WIT 绑定层（`bindgen!` / `HostModule` /
//!   `inventory::submit!` / `impl Host`）。开 feature 前后 ABI、WIT、权限位、句柄形状
//!   与注册行为零变化——它装配依赖，不分叉行为。
//! - `backend-cpal`：装配 cpal 跨平台后端（`cpal_backend::CpalBackend`）。**默认关**：
//!   Linux 需要 `libasound2-dev`、Android 需要 NDK 链 `aaudio`，开在默认树上会让
//!   「默认形态任何宿主可直接引用」失真。
//! - `test-util`：装配可编排后端 `test_util::ScriptedBackend`（`cfg(test)` 下同码
//!   常编译，故本 crate 单测无需开它）。
//!
//! ## 数据面纪律
//!
//! - **采集线程零阻塞**：设备回调只做「解码 → 归一 → 追加环 → 电平」，不解释字节、
//!   不做 IO、不等消费者。慢消费者只损失自己的历史（淘汰最旧 + `truncated`），
//!   背压绝不回传到采集线程。
//! - **纯拉取、无事件面（v1）**：帧环游标由调用方自持，`ring-fetch` 是纯读；状态变化
//!   靠 `status` 快照自愈。事件面需要宿主任务投递，随接线票另议。
//! - **锁序只能 `stream` → `runtime`**，且**绝不在持有 `runtime` 锁时 Drop 后端流**
//!   （cpal 的 `Stream::drop` 会等回调返回，回调可能正等这把锁）。详见 [`engine`] 模块头。
//!
//! ## 零业务语义
//!
//! 归一目标、电平窗口、配额都取宿主声明或引擎限额；混音规则（多声道按目标声道数等分
//! 求均值）是机制而不是产品策略。VAD / 分段 / 编码 / 降噪 / 回放 / 热插拔事件 /
//! 麦克风权限申请 UI 均**不在本域**。

pub mod backend;
pub mod engine;
pub mod error;
pub mod format;
pub mod level;
/// 能力域接线层（端口 / 原语 / 注册表 / WIT 绑定）：默认可用部分 = 纯机制，
/// WIT 绑定随 `common-host` feature 装配。
pub mod plugin_binding;
pub mod ring;
/// wire 契约词汇自持副本（权限位 / 句柄前缀）；v1 无事件面，故无 topic 副本。
pub mod wire;

/// 可编排后端（无硬件 CI 与单测手工灌帧）
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

/// cpal 跨平台采集后端（feature `backend-cpal`，默认关——见 crate 文档「形态」）
#[cfg(feature = "backend-cpal")]
pub mod cpal_backend;

pub use backend::{
    CaptureBackend, CaptureSink, CaptureStream, DeviceId, DeviceInfo, OpenRequest,
    TerminationReason,
};
pub use engine::{
    AudioHub, AudioLimits, OpenParams, ResolvedOpen, Session, SessionState, SessionStatus,
    StreamHandle, TerminationView,
};
pub use error::AudioError;
pub use format::{
    LinearResampler, PcmBuffer, PcmFormat, PcmNormalizer, Resampler, ResamplerFactory,
    SampleFormat, TargetFormat, SPEECH_16K_MONO,
};
pub use level::{LevelMeter, LevelSnapshot};
pub use ring::{FrameRing, RingFetch};

#[cfg(test)]
mod boundary_lock;

// ==================== 契约包身份（WIT 按包拆分，ADR 0061） ====================

/// 本能力域 WIT 包全名（`namespace:name@version`）
///
/// 与 `wit/audio.wit` 的 `package` 行逐字一致（下方锁测试断言），也是宿主
/// `MODULE_INTERFACES` 各项的前缀。拆包后每个能力域独立版本：只在本包 WIT
/// 变更时 bump。
pub const WIT_PACKAGE: &str = "wasmnest:audio@0.0.1";

#[cfg(test)]
mod wit_package_lock {
    /// 常量 ↔ 分片真源 package 行（两侧任一手改即红）
    #[test]
    fn wit_package_matches_slice_package_line() {
        let raw = include_str!("../wit/audio.wit");
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("package "))
            .expect("WIT 分片缺 package 行");
        assert_eq!(line, format!("package {};", super::WIT_PACKAGE));
    }

    /// 宿主模块接口路径必须属于本包（包名/版本漂移＝运行期 import 失配，编译面不红）
    #[test]
    fn module_interfaces_belong_to_wit_package() {
        for iface in crate::plugin_binding::MODULE_INTERFACES {
            assert!(
                iface.starts_with(&format!("{}/", super::WIT_PACKAGE)),
                "MODULE_INTERFACES 项 {iface} 不属于 {}",
                super::WIT_PACKAGE
            );
        }
    }
}
