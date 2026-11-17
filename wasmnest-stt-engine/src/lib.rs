//! WasmNest 本地语音识别能力域（`host-stt`）：模型目录 / 会话 / 异步任务 / 结果
//!
//! ## 两层结构
//!
//! ```text
//!   catalog / pcm / backend / hub / model_store   引擎面（零 wasm、零原生推理依赖）
//!   whisper_backend（feature `backend-whisper`）   可选 whisper.cpp 后端
//!   plugin_binding（ports / primitives / registry / WIT 绑定） 能力域层
//! ```
//!
//! **引擎面**只做机制事：列出 catalog 模型、打开 PCM 会话、把会话交给
//! [`SttBackend`]、在后台线程跑推理、给出任务状态与结果、维护宿主共享的模型目录。
//! 它不含任何产品语义（无录音 / 供应商路由 / 回退 / 历史 / VAD / 分段策略）——
//! 语音→文字的编排归应用仓插件。
//!
//! ## 形态
//!
//! - **默认形态 = 纯引擎 + 端口 + [`SttBackend`] trait**：零 WIT、零 SDK、
//!   零 wasmtime、零宿主框架、零原生推理库。任何宿主可直接引用，也可以自带后端。
//! - `common-host`：装配桌面 WIT 绑定层（`bindgen!` / `HostModule` /
//!   `inventory::submit!` / `impl Host`）。开 feature 前后 ABI、WIT、权限位、
//!   句柄形状与注册行为零变化。
//! - `backend-whisper`：装配 whisper.cpp 后端（`whisper-rs`）。**默认关**：
//!   它是 native 依赖（C++ 工具链 + cmake），由需要真实推理的宿主显式开启。
//! - `model-download`：装配 HTTP 模型下载与 SHA-256 校验。**默认关**：模型下载
//!   是宿主运维动作，不应让纯引擎形态被动拉入网络栈。
//! - `test-util`：装配可编排后端（无模型 / 无硬件 CI 用）。
//!
//! ## 数据面纪律
//!
//! - **属主隔离**：会话与任务句柄只认创建者插件；停用时按属主回收。
//! - **异步推理**：`finalize` 只登记任务并返回 job-id，推理在宿主后台线程执行；
//!   插件轮询 `job-status` / `job-result`，不阻塞 wasm 实例。
//! - **模型是宿主资产**：下载源只来自 catalog（可配镜像前缀），SHA-256 校验通过
//!   后才原子落位；插件只拿模型 id，不碰路径，也不接受任意下载 URL。
//! - **输入固定 16 kHz 单声道 S16LE**：与 host-audio 的归一目标一致；容器解码
//!   不在本域（应用层先把音频归一成 PCM）。

pub mod backend;
pub mod catalog;
pub mod error;
pub mod hub;
pub mod model_store;
pub mod pcm;
pub mod plugin_binding;
pub mod wire;

#[cfg(feature = "backend-whisper")]
pub mod whisper_backend;

pub use backend::{BackendFailure, SttBackend, TranscribeRequest, Transcript, TranscriptSegment};
pub use catalog::{default_model, find_model, ModelEntry, CATALOG};
pub use error::{Result, SttError};
pub use hub::{JobState, JobStatusView, SessionLimits, SttHub};
pub use model_store::{DownloadView, ModelFetcher, ModelStore, ModelView};
pub use pcm::{duration_ms, s16le_to_f32, validate_pcm};

// ==================== 契约包身份（WIT 按包拆分） ====================

/// 本能力域 WIT 包全名（`namespace:name@version`）
///
/// 与 `wit/stt.wit` 的 `package` 行逐字一致（下方锁测试断言），也是宿主
/// `MODULE_INTERFACES` 各项的前缀。拆包后每个能力域独立版本：只在本包 WIT
/// 变更时 bump。
pub const WIT_PACKAGE: &str = "wasmnest:stt@0.0.1";

#[cfg(test)]
mod wit_package_lock {
    /// 常量 ↔ 分片真源 package 行（两侧任一手改即红）
    #[test]
    fn wit_package_matches_slice_package_line() {
        let raw = include_str!("../wit/stt.wit");
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
