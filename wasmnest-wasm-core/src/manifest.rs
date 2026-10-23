//! 插件清单 / 状态 / 贡献 / 角色词汇的中性层（单形态票 02 M4）
//!
//! 机制层不直接依赖任一 SDK crate（`wasmnest-plugin-api` / `_mobile`）：本模块
//! 自持与双端 SDK wire 副本**形状对齐**的 serde 类型——取桌面 + 移动 manifest
//! 字段的**并集超集**（端差异字段全部 `serde(default)`，旧 JSON 零迁移）。双端
//! 绑定层（`manager/runtime/{common,bare}/component.rs` 等）在入口 / 出口经
//! JSON 往返（[`from_sdk_json`]）把 SDK 类型转成本中性形态；加载路径
//! （`manager/loader.rs` 解析 plugin.json）与宿主消费面（`HostPluginInfo`）则
//! 直接只用本模块类型。
//!
//! 词汇面契约仍双端独立演进（ADR 0018）：本模块是**宿主机制**的唯一词汇来源，
//! SDK 副本是 guest 面 wire 形状——两侧以 serde 形状对齐 + 绑定层转换衔接，
//! 不跨 crate 依赖。

use serde::{Deserialize, Serialize};

/// SDK wire 类型 → 中性形态（JSON 往返：双端 SDK 类型与中性超集形状兼容，
/// 序列化端差异字段走 skip/默认，反序列化端 default 补回，语义等价无损）
///
/// 只在绑定层入口 / 出口使用；转换失败是装配期编程错误（形状漂移），显性
/// panic 点名而非静默降级（fail-visible）。
pub fn from_sdk_json<T: Serialize, U: serde::de::DeserializeOwned>(sdk: &T) -> U {
    let value = serde_json::to_value(sdk).expect("neutral conversion: SDK type serializes");
    serde_json::from_value(value).expect("neutral conversion: neutral type deserializes SDK shape")
}

// ==================== PluginManifest（并集超集） ====================

/// 插件描述文件 (plugin.json) 的完整结构（桌面 + 移动字段并集）
///
/// `Default` 是测试夹具与合成 manifest 的构造基线：除 `id` / `name` / `version` /
/// `platform` 四个必填项外，每个字段都带 `#[serde(default)]`，因此 `Default` 与
/// 「一份只写了必填项的 plugin.json 解析结果」逐字段等价（同桌面 SDK 语义，追加
/// 可选字段不再连带测试编译红）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    /// 唯一标识（反向域名格式，如 com.wasmnest.quick-snippets）
    pub id: String,
    /// 显示名称
    pub name: String,
    /// 语义化版本号
    pub version: String,
    /// 适配平台：`desktop`（仅桌面）/ `mobile`（仅移动）/ `both`（双端适配）
    ///
    /// **必填项**（与 id/name/version 同档，无 serde 缺省）——声明本应用适配哪一端；
    /// 宿主在**加载 / zip 安装**时校验声明必须覆盖当前端（见各端装配面与
    /// [`PluginPlatform::supports`]），不匹配即 fail-visible 拒绝：把一端的分发包
    /// 装到另一端后「装了却不工作」比一次显性拒绝难排查得多。
    pub platform: PluginPlatform,
    /// 插件描述
    #[serde(default)]
    pub description: String,
    /// 作者
    #[serde(default)]
    pub author: String,
    /// 入口文件路径（相对于插件根目录，TS-only 插件使用）
    #[serde(default)]
    pub main: String,
    /// 请求的权限列表
    #[serde(default)]
    pub permissions: Vec<String>,
    /// 对外可互调 api 清单（ADR-0017，插件互调机制）
    #[serde(default)]
    pub api: Vec<String>,
    /// 扩展点声明
    #[serde(default)]
    pub contributes: PluginContributes,
    /// 插件类型：rust / rust-ts / ts-only / wasm
    #[serde(default = "default_plugin_type")]
    pub plugin_type: PluginType,
    /// WASM 库文件名（不含路径，相对于插件目录）
    #[serde(default)]
    pub rust_library: String,
    /// WASM 模块内容 SHA-256（小写十六进制；缺省空串 = 不校验）
    #[serde(default)]
    pub wasm_hash: String,
    /// 插件图标：图片路径（相对插件目录）或内联 SVG 标记
    #[serde(default)]
    pub icon: Option<String>,
    /// WASI 预打开目录声明（**仅 worker 类别可用**，ADR 0034；桌面 manifest 专属）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wasi_preopen_dirs: Vec<WasiPreopenDir>,
    /// 装配角色：`basic-service`（L1）/ `internal-business`（L2）/ `business-app`（L3，
    /// 缺省）。历史拼写兼容（反序列化别名）：`application` = L3、`system` = L1。
    #[serde(
        rename = "type",
        default,
        skip_serializing_if = "PluginKind::is_business_app"
    )]
    pub kind: PluginKind,
    /// 能力依赖声明（应用插件消费的能力名，WIT host-* 接口名）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// 单插件 Store 资源覆盖请求（core-config × core-security 仲裁）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_overrides: Option<ResourceOverrides>,
    /// 单插件在册 `host-pty` 句柄数上限声明（会话引擎下沉 P1 / H1）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pty_quota: Option<usize>,
    /// 实例生命周期策略：`persistent`（常驻，缺省）/ `ephemeral`（即用即弃）
    #[serde(default, skip_serializing_if = "InstanceLifecycle::is_persistent")]
    pub lifecycle: InstanceLifecycle,
    /// 启用前预授权目录（移动 manifest 专属；桌面形态不产出该 key，与桌面 SDK JSON 形状一致）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preauth_dirs: Vec<String>,
    /// 外网访问预授权 URL 声明（移动 manifest 专属；桌面形态不产出该 key，与桌面 SDK JSON 形状一致）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preauth_urls: Vec<String>,
}

/// 缺省产物形态（与桌面 SDK 同一真源语义：`pluginType` 缺省 = ts-only）
fn default_plugin_type() -> PluginType {
    PluginType::TsOnly
}

/// 单插件 Store 资源上限覆盖请求（manifest `resourceOverrides`；真源 =
/// `crate::config::ResourceOverrides`，本模块再导出供 manifest 词汇统一）
pub use crate::config::ResourceOverrides;

// ==================== 枚举词汇 ====================

/// 插件产物形态类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginType {
    /// 纯 Rust 插件，无前端组件
    Rust,
    /// Rust + TypeScript 插件
    RustTs,
    /// 纯 TypeScript 插件
    TsOnly,
    /// WASM 插件（移动 SDK 有该形态；桌面 `plugin_type` 词汇缺省面为 ts-only）
    Wasm,
}

impl Default for PluginType {
    fn default() -> Self {
        default_plugin_type()
    }
}

/// 应用适配平台（manifest `platform` 字段，必填）
///
/// 三值：`desktop`（仅桌面）/ `mobile`（仅移动）/ `both`（双端适配）。宿主在加载 /
/// 安装时按本端校验（`supports`），单端声明遇到另一端即拒绝装载。
///
/// `Default` 取 `Both` **仅服务测试夹具与合成清单**（wire 层该字段必填、无 serde
/// 缺省）：合成清单对两端都可装载，不把测试夹具钉死在某一个端。端名（desktop /
/// mobile）在此是**双端共享的 wire 词汇**（与 pluginType 的 wasm 同档）——不是按
/// 端分叉的机制（ADR 0047 D2 判据只针对自持标识符的声明位，wire 取值不在此列）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PluginPlatform {
    /// 仅桌面端
    Desktop,
    /// 仅移动端
    Mobile,
    /// 双端适配（两端均可加载）
    #[default]
    Both,
}

impl PluginPlatform {
    /// wire 值（错误文案 / 对比用；与 serde rename 同源）
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
            Self::Both => "both",
        }
    }

    /// 本声明是否适用于 `host`（宿主当前端；只应传 `Desktop` / `Mobile`）
    ///
    /// `both` 对任一端成立；单端声明只对本端成立——宿主加载 / 安装的门禁判据。
    pub const fn supports(self, host: PluginPlatform) -> bool {
        match (self, host) {
            (Self::Both, _) => true,
            (Self::Desktop, Self::Desktop) => true,
            (Self::Mobile, Self::Mobile) => true,
            _ => false,
        }
    }
}

/// 组件装配角色（manifest `type` 字段，core-plugin-manager · ADR 0032）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PluginKind {
    /// **L3 业务应用**（缺省）
    #[default]
    #[serde(alias = "application")]
    BusinessApp,
    /// **L1 基础服务**（向能力注册表提供 host-* 同形接口能力）
    #[serde(alias = "system")]
    BasicService,
    /// **L2 内部统一业务应用**（宿主网关的裁决依赖方）
    InternalBusiness,
}

impl PluginKind {
    /// 角色驱动加载层顺序（**L1 先于 L2**；L3 走持久化批量激活）
    pub const ROLE_DRIVEN_LOAD_ORDER: [PluginKind; 2] =
        [PluginKind::BasicService, PluginKind::InternalBusiness];

    /// serde skip_serializing_if 钩子：缺省角色（L3）不写入序列化输出
    pub fn is_business_app(&self) -> bool {
        matches!(self, PluginKind::BusinessApp)
    }

    /// 是否**角色驱动**（L1 / L2）：启动由角色而非用户状态决定
    pub fn is_role_driven(&self) -> bool {
        matches!(
            self,
            PluginKind::BasicService | PluginKind::InternalBusiness
        )
    }

    /// 是否向能力注册表提供 host-* 同形接口能力（**仅 L1**）
    pub fn provides_host_capabilities(&self) -> bool {
        matches!(self, PluginKind::BasicService)
    }

    /// 是否 L2（宿主网关裁决依赖方；宿主反向依赖 wasm 组件的唯一角色）
    pub fn is_internal_business(&self) -> bool {
        matches!(self, PluginKind::InternalBusiness)
    }

    /// 日志 / 诊断用的角色标签
    pub fn label(&self) -> &'static str {
        match self {
            PluginKind::BasicService => "L1 基础服务",
            PluginKind::InternalBusiness => "L2 内部统一业务",
            PluginKind::BusinessApp => "L3 业务应用",
        }
    }

    /// manifest wire 拼写（与 serde `rename_all = "kebab-case"` 同源）
    pub fn as_str(&self) -> &'static str {
        match self {
            PluginKind::BusinessApp => "business-app",
            PluginKind::BasicService => "basic-service",
            PluginKind::InternalBusiness => "internal-business",
        }
    }
}

/// 实例生命周期策略（manifest `lifecycle`）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceLifecycle {
    /// 常驻（缺省）
    #[default]
    Persistent,
    /// 即用即弃（业务 worker 形态，本期只预留类型——声明即加载期拒绝）
    Ephemeral,
}

impl InstanceLifecycle {
    /// serde skip_serializing_if 钩子：缺省常驻不写入序列化输出
    pub fn is_persistent(&self) -> bool {
        matches!(self, InstanceLifecycle::Persistent)
    }

    /// wire 值（`lifecycle` 字段的字符串形态）
    pub fn as_str(&self) -> &'static str {
        match self {
            InstanceLifecycle::Persistent => "persistent",
            InstanceLifecycle::Ephemeral => "ephemeral",
        }
    }
}

/// 插件运行时状态（双端 SDK 同 JSON 形状：`{"state": ...}` + 内联 `error`）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum PluginState {
    /// 已发现但未激活（缺省）
    Loaded,
    /// 激活进行中
    Activating,
    /// 激活完成
    Activated,
    /// activate 成功但 on_startup 失败：实例可用、启动初始化未完成
    Degraded {
        /// 退化原因
        error: String,
    },
    /// 权限尚未获用户批准
    NeedsApproval,
    /// 激活失败
    Error {
        /// 错误信息
        error: String,
    },
    /// 已停用
    Deactivated,
}

impl Default for PluginState {
    fn default() -> Self {
        Self::Loaded
    }
}

/// WASI 预打开目录声明条目（桌面 manifest `wasiPreopenDirs`；ADR 0034）
///
/// 两形态：裸路径 = 可写挂载，`{path, readonly}` = 只读挂载。只读档只收紧
/// guest 对该目录的写能力，不放宽授权。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WasiPreopenDir {
    /// 裸路径（可写挂载）
    Path(String),
    /// 声明式条目（`path` + 可选 `readonly`）
    Declared {
        /// 主机目录绝对路径（支持 `${home}` 展开）
        path: String,
        /// 只读挂载（缺省 = 可写）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        readonly: Option<bool>,
    },
}

impl WasiPreopenDir {
    /// 可写挂载条目
    pub fn writable(path: impl Into<String>) -> Self {
        Self::Path(path.into())
    }

    /// 只读挂载条目
    pub fn read_only(path: impl Into<String>) -> Self {
        Self::Declared {
            path: path.into(),
            readonly: Some(true),
        }
    }

    /// 目录路径（两种形态统一取值）
    pub fn path(&self) -> &str {
        match self {
            Self::Path(p) => p,
            Self::Declared { path, .. } => path,
        }
    }

    /// 是否只读档
    pub fn is_readonly(&self) -> bool {
        matches!(
            self,
            Self::Declared {
                readonly: Some(true),
                ..
            }
        )
    }

    /// 只读档查询（旧 SDK 同名方法——绑定层预打开展开调用）
    pub fn readonly(&self) -> bool {
        self.is_readonly()
    }

    /// 路径替换（旧 SDK 同名方法——`${home}` 展开后生成新条目）
    pub fn with_path(&self, path: impl Into<String>) -> Self {
        match self {
            Self::Path(_) => Self::Path(path.into()),
            Self::Declared { readonly, .. } => Self::Declared {
                path: path.into(),
                readonly: *readonly,
            },
        }
    }
}

// ==================== 扩展点贡献词汇 ====================

/// 插件扩展点声明（桌面 + 移动字段并集）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginContributes {
    /// 命令扩展点
    #[serde(default)]
    pub commands: Vec<CommandContribution>,
    /// 视图扩展点
    #[serde(default)]
    pub views: Vec<ViewContribution>,
    /// 终端扩展点
    #[serde(default)]
    pub terminal: Option<TerminalContribution>,
    /// 工具提供者（桌面）
    #[serde(default)]
    pub tool_providers: Vec<ToolProviderContribution>,
    /// 文件处理器（桌面）
    #[serde(default)]
    pub file_handlers: Vec<FileHandlerContribution>,
    /// 插件 HTTP 端点清单（桌面；路径白名单 + 认证档位）
    #[serde(default)]
    pub http_endpoints: Vec<HttpEndpointContribution>,
    /// 插件 WS 端点清单（桌面；声明式路由）
    #[serde(default)]
    pub ws_endpoints: Vec<WsEndpointContribution>,
    /// 配置声明
    #[serde(default)]
    pub configuration: Option<PluginConfiguration>,
    /// 生命周期钩子声明
    #[serde(default)]
    pub lifecycle: Option<LifecycleContribution>,
    /// 声明的发布 topic（文档性质，不做强制校验）
    #[serde(default)]
    pub provides: Vec<String>,
    /// 声明订阅的 topic（宿主据此路由消息）
    #[serde(default)]
    pub subscribes: Vec<String>,
    /// 底部导航扩展点（移动 manifest 专属；桌面形态不产出该 key，与桌面 SDK JSON 形状一致）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nav_tab: Option<NavTabContribution>,
    /// 设置页扩展点（移动 manifest 专属；桌面形态不产出该 key，与桌面 SDK JSON 形状一致）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SettingsContribution>,
    /// 自定义监控面板声明（monitor 统一壳消费；面板实现住提供方应用工程）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub monitor_panels: Vec<MonitorPanelContribution>,
}

/// 自定义监控面板声明
///
/// 只登记元数据（id / 标题 / 排序）；面板 UI 与取数逻辑由提供方应用导出
/// `mountMonitorPanel`，宿主按需装载，monitor 不直接 import 他人 bundle。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorPanelContribution {
    /// 面板 id（同一应用内唯一）
    pub id: String,
    /// 显示标题
    pub title: String,
    /// 排序权重（小者靠前；缺省 100，与双端 SDK 镜像 / 前端排序同口径）
    #[serde(default = "default_monitor_panel_order")]
    pub order: i32,
}

/// 面板缺省排序权重（与 TS SDK 文档 / monitor 壳的 `order ?? 100` 一致）
fn default_monitor_panel_order() -> i32 {
    100
}

/// 命令扩展点声明
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandContribution {
    /// 命令唯一 id
    pub id: String,
    /// 显示标题
    pub title: String,
    /// 图标（可选）
    #[serde(default)]
    pub icon: Option<String>,
}

/// 视图扩展点声明
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewContribution {
    /// 视图唯一 id
    pub id: String,
    /// 视图类型（sidebar / toolbox / statusbar…）
    #[serde(rename = "type")]
    pub view_type: String,
    /// 显示标题
    #[serde(default)]
    pub title: String,
    /// 前端组件路径
    #[serde(default)]
    pub component: String,
}

/// 终端扩展点声明
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalContribution {
    /// 输入处理器
    #[serde(default)]
    pub input_handlers: Vec<String>,
    /// 输出解析器
    #[serde(default)]
    pub output_parsers: Vec<String>,
}

/// 工具提供者扩展点声明（桌面）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolProviderContribution {
    /// 提供者 id
    pub id: String,
    /// 显示名称
    pub name: String,
    /// 工具端点
    pub endpoint: String,
}

/// 文件处理扩展点声明（桌面）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHandlerContribution {
    /// 处理器 id
    pub id: String,
    /// 支持的扩展名列表
    pub extensions: Vec<String>,
    /// 查看器组件路径
    pub viewer: String,
    /// 图标（可选）
    #[serde(default)]
    pub icon: Option<String>,
}

/// 端点认证档位（桌面 HTTP / WS 端点声明共用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointAuth {
    /// 免凭证
    None,
    /// JWT 认证
    Jwt,
}

impl EndpointAuth {
    /// wire 值
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Jwt => "jwt",
        }
    }

    /// 解析声明值（空 / 缺省取 `default`；未知值报错）
    pub fn parse_with(raw: Option<&str>, default: Self) -> Result<Self, String> {
        match raw.map(str::trim).unwrap_or("") {
            "" => Ok(default),
            "none" => Ok(Self::None),
            "jwt" => Ok(Self::Jwt),
            other => Err(format!(
                "unknown auth '{}' (expected \"none\" or \"jwt\")",
                other
            )),
        }
    }
}

/// 插件 HTTP 端点声明（桌面；相对路径段，前缀由宿主补）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HttpEndpointContribution {
    /// 裸路径（缺省最严档 jwt）
    Path(String),
    /// 声明式条目（path + 可选 auth）
    Declared {
        /// 相对路径段
        path: String,
        /// 认证档位（缺省最严档 jwt）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
    },
}

impl HttpEndpointContribution {
    /// 路径（两形态统一取值）
    pub fn path(&self) -> &str {
        match self {
            Self::Path(p) => p,
            Self::Declared { path, .. } => path,
        }
    }

    /// 认证档位原始值（裸路径形态 = None）
    pub fn auth_raw(&self) -> Option<&str> {
        match self {
            Self::Path(_) => None,
            Self::Declared { auth, .. } => auth.as_deref(),
        }
    }
}

impl From<&str> for HttpEndpointContribution {
    fn from(path: &str) -> Self {
        Self::Path(path.to_string())
    }
}

impl From<String> for HttpEndpointContribution {
    fn from(path: String) -> Self {
        Self::Path(path)
    }
}

/// 插件 WS 端点声明（桌面；相对路径段）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WsEndpointContribution {
    /// 裸路径
    Path(String),
    /// 声明式条目（path + 可选 auth）
    Declared {
        /// 相对路径段
        path: String,
        /// 认证档位（缺省按 WS 面默认档 none）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
    },
}

impl WsEndpointContribution {
    /// 路径（两形态统一取值）
    pub fn path(&self) -> &str {
        match self {
            Self::Path(p) => p,
            Self::Declared { path, .. } => path,
        }
    }

    /// 认证档位原始值（裸路径形态 = None）
    pub fn auth_raw(&self) -> Option<&str> {
        match self {
            Self::Path(_) => None,
            Self::Declared { auth, .. } => auth.as_deref(),
        }
    }
}

impl From<&str> for WsEndpointContribution {
    fn from(path: &str) -> Self {
        Self::Path(path.to_string())
    }
}

impl From<String> for WsEndpointContribution {
    fn from(path: String) -> Self {
        Self::Path(path)
    }
}

/// 插件配置声明
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginConfiguration {
    /// 配置页标题
    pub title: String,
    /// 配置属性表
    pub properties: std::collections::HashMap<String, ConfigProperty>,
}

/// 配置属性声明
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigProperty {
    /// 属性类型（string / number / boolean…）
    #[serde(rename = "type")]
    pub prop_type: String,
    /// 显示标题
    pub title: String,
    /// 描述
    #[serde(default)]
    pub description: Option<String>,
    /// 缺省值
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    /// 枚举取值（type 为 string 时使用）
    #[serde(default)]
    pub enum_values: Option<Vec<String>>,
}

/// 生命周期钩子声明（桌面 + 移动字段并集）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleContribution {
    /// 启动钩子
    #[serde(default)]
    pub on_startup: bool,
    /// 停用钩子
    #[serde(default)]
    pub on_shutdown: bool,
    /// 移动端：WebSocket 认证成功
    #[serde(default)]
    pub on_auth_success: bool,
    /// 移动端：连接断开
    #[serde(default)]
    pub on_disconnect: bool,
    /// 移动端：会话创建
    #[serde(default)]
    pub on_session_created: bool,
    /// 移动端：会话停止
    #[serde(default)]
    pub on_session_stopped: bool,
}

impl LifecycleContribution {
    /// 检查是否声明了指定事件（wire 名；未知事件返回 false）
    pub fn is_declared(&self, event_name: &str) -> bool {
        match event_name {
            "onStartup" => self.on_startup,
            "onShutdown" => self.on_shutdown,
            "onAuthSuccess" => self.on_auth_success,
            "onDisconnect" => self.on_disconnect,
            "onSessionCreated" => self.on_session_created,
            "onSessionStopped" => self.on_session_stopped,
            _ => false,
        }
    }
}

/// 底部导航扩展点声明（移动 manifest 专属）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavTabContribution {
    /// 导航项 id
    pub id: String,
    /// 显示标题
    pub title: String,
    /// 图标
    pub icon: String,
    /// 前端组件路径
    pub component: String,
    /// 排序权重
    #[serde(default)]
    pub order: i32,
}

/// 设置页扩展点声明（移动 manifest 专属）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsContribution {
    /// 设置分区名
    pub section: String,
    /// 前端组件路径
    pub component: String,
}

// ==================== 测试（serde 形状漂移锁） ====================

#[cfg(all(test, feature = "desktop-assembly"))]
mod drift_lock {
    use super::*;

    /// 中性 PluginManifest 与桌面 SDK 副本 JSON 形状逐字段一致（漂移锁）：
    /// 两份 manifest（含端差异字段）序列化结果必须完全同形——机制层解析
    /// plugin.json 的字段名/命名规则不得漂移（SDK 是 guest 面 wire 真源）。
    #[test]
    fn neutral_manifest_json_shape_matches_desktop_sdk() {
        let sdk = wasmnest_plugin_api::PluginManifest {
            id: "com.wasmnest.drift".to_string(),
            name: "Drift".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };
        let neutral = from_sdk_json::<_, PluginManifest>(&sdk);
        assert_eq!(
            serde_json::to_value(&sdk).unwrap(),
            serde_json::to_value(&neutral).unwrap(),
            "中性 manifest 与桌面 SDK 的 JSON 形状漂移——改一侧必须双侧同步"
        );
    }
}
