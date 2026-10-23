//! 自动注册表的行为契约（正例 / 反例 / 边界）
//!
//! 依据 `unit-test-discipline`：每个用例断言**可观察行为**，不测 mock 调用次数；
//! 白名单锁必须**双向**都钉住（漏进 / 漏出），否则任一方向单独存在都能被绕过。

use std::cell::RefCell;
use wasmnest_host_kit::{
    HostKitError, HostModule, HostModuleDesc, ModuleRegistry, WasmPluginState,
};
use wasmtime::component::Linker;

// 装配记录（本测试线程上哪些模块的 `register` 真的跑起来了）
//
// **为什么用 thread_local**：`cargo test` 在同一二进制内**并行**跑用例，进程级
// 静态记录会把别的用例的装配结果混进来（断言变成与执行顺序相关、随机红）。
// `install_all` 是同步调用、`register` 就在测试线程内执行，线程局部记录既隔离
// 又无需加锁。
//
// 观察点选择：component `Linker` 没有「查已注册函数」的读 API，故以桩自身的
// 副作用为观察通道。记录的是 `install_all` 的**行为结果**（谁让位、谁装上），
// 不是 mock 调用次数——同一断言直接区分「兜底桩装上」与「真实现装上」两种结果。
thread_local! {
    static INSTALLED: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

fn installed_log() -> Vec<&'static str> {
    INSTALLED.with(|log| log.borrow().clone())
}

fn reset_installed_log() {
    INSTALLED.with(|log| log.borrow_mut().clear());
}

/// 可指定「兜底/兼容桩」身份的测试模块（替身）
///
/// 真实现与桩**刻意用同一函数名**：真实世界里两边都是 wit-bindgen 的
/// `add_to_linker`（函数名逐字相同），「同名 interface + 同名函数」装两次即
/// `defined twice`。让位逻辑一旦失效，这里立刻以该错误红出来，而不是悄悄装成
/// 两份、谁都看不出来。
struct RecordingModule {
    name: &'static str,
    interfaces: &'static [&'static str],
    func: &'static str,
    is_fallback: bool,
}

impl HostModule for RecordingModule {
    fn desc(&self) -> HostModuleDesc {
        HostModuleDesc {
            name: self.name,
            interfaces: self.interfaces,
            permissions: &[],
            abi_min: 1,
        }
    }

    fn fallback(&self) -> bool {
        self.is_fallback
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        let mut instance = linker.instance(self.interfaces[0])?;
        instance.func_new(self.func, |_store, _ty, _args, _rets| Ok(()))?;
        INSTALLED.with(|log| log.borrow_mut().push(self.name));
        Ok(())
    }
}

/// 测试用能力模块（替身：只登记一个空壳 interface 命名空间，不引入 WIT 依赖）
struct StubModule {
    name: &'static str,
    interfaces: &'static [&'static str],
}

impl HostModule for StubModule {
    fn desc(&self) -> HostModuleDesc {
        HostModuleDesc {
            name: self.name,
            interfaces: self.interfaces,
            permissions: &[],
            abi_min: 1,
        }
    }

    fn register(&self, linker: &mut Linker<WasmPluginState>) -> wasmtime::Result<()> {
        // 必须真往 instance 里**定义一个函数**——`Linker::instance(name)` 本身
        // 允许对同一名字重复开启（wasmtime 有意为之，见 `into_instance` 注释：
        // “explicitly allow re-opening an instance multiple times”），不报错。
        // 真正的重复注册护栏是「同一 instance 内同名函数」——也正是 wit-bindgen 的
        // `add_to_linker` 会碰的那条。
        let mut instance = linker.instance(self.interfaces[0])?;
        instance.func_new("ping", |_store, _ty, _args, _rets| Ok(()))?;
        Ok(())
    }
}

// 三个静态提交（名字刻意乱序，用于钉住「按名排序而非注册顺序」）
static ZETA: StubModule = StubModule {
    name: "zeta",
    interfaces: &["test:pkg/zeta"],
};
static ALPHA: StubModule = StubModule {
    name: "alpha",
    interfaces: &["test:pkg/alpha"],
};
static MID: StubModule = StubModule {
    name: "mid",
    interfaces: &["test:pkg/mid"],
};

fn test_engine() -> wasmtime::Engine {
    wasmtime::Engine::default()
}

/// 正例：三个自报模块全部被收集到，且按**模块名字典序**排列
///
/// 排序契约的价值：装配顺序固定 ⇒ 重复注册的报错信息可复现（否则错误串取决于
/// 链接器把 rlib 排在哪，属「同一份代码两次构建两种错误」的不可诊断态）。
#[test]
fn collected_returns_all_submitted_modules_sorted_by_name() {
    let registry = ModuleRegistry::collected();
    let names: Vec<&str> = registry.descs().iter().map(|d| d.name).collect();

    for expected in ["alpha", "mid", "zeta"] {
        assert!(
            names.contains(&expected),
            "module '{expected}' not collected: {names:?}"
        );
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "modules must be sorted by name, got {names:?}"
    );
    assert_eq!(registry.len(), 3, "exactly three stub modules registered");
    assert!(!registry.is_empty());
}

/// 描述符内容随模块一起被收集（接口路径 / 权限位 / ABI 下界三元组）
#[test]
fn collected_preserves_descriptor_payload() {
    let registry = ModuleRegistry::collected();
    let alpha = registry
        .descs()
        .into_iter()
        .find(|d| d.name == "alpha")
        .expect("alpha module collected");
    assert_eq!(alpha.interfaces, &["test:pkg/alpha"][..]);
    assert_eq!(alpha.permissions, &[] as &[&str]);
    assert_eq!(alpha.abi_min, 1);
}

/// 白名单恰好等于收集集 ⇒ 通过（正例）
#[test]
fn whitelist_matching_collected_set_passes() {
    let registry = ModuleRegistry::collected();
    assert!(registry.verify_whitelist(&["alpha", "mid", "zeta"]).is_ok());
}

/// 白名单**顺序无关**（宿主声明顺序不应影响判定）
#[test]
fn whitelist_order_does_not_matter() {
    let registry = ModuleRegistry::collected();
    assert!(registry.verify_whitelist(&["zeta", "alpha", "mid"]).is_ok());
}

/// 反例 A：有模块自报但不在白名单 ⇒ 红，并点名是哪些（防「新能力悄悄进产品」）
#[test]
fn whitelist_rejects_unlisted_module_and_names_it() {
    let registry = ModuleRegistry::collected();
    let err = registry
        .verify_whitelist(&["alpha", "mid"])
        .expect_err("unlisted module must be rejected");

    match err {
        HostKitError::WhitelistMismatch { unlisted, missing } => {
            assert_eq!(
                unlisted,
                vec!["zeta".to_string()],
                "must name the unlisted module"
            );
            assert!(missing.is_empty(), "no module is missing here");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

/// 反例 B：白名单有模块但未被收集 ⇒ 红，并点名缺哪些
///
/// 这条是「依赖被删 / crate 没链上」的唯一早期信号——没有它，能力域会静默从插件
/// import 集消失，而 guest 编译期照常 import、运行期才炸。
#[test]
fn whitelist_rejects_missing_module_and_names_it() {
    let registry = ModuleRegistry::collected();
    let err = registry
        .verify_whitelist(&["alpha", "mid", "zeta", "sqlite"])
        .expect_err("missing module must be rejected");

    match err {
        HostKitError::WhitelistMismatch { unlisted, missing } => {
            assert_eq!(
                missing,
                vec!["sqlite".to_string()],
                "must name the missing module"
            );
            assert!(unlisted.is_empty(), "no extra module here");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

/// 反例 C：双向差异同时出现时，两侧都要被点名（不得只报一侧）
#[test]
fn whitelist_reports_both_directions_at_once() {
    let registry = ModuleRegistry::collected();
    let err = registry
        .verify_whitelist(&["alpha", "ghost"])
        .expect_err("both directions differ");

    match err {
        HostKitError::WhitelistMismatch { unlisted, missing } => {
            assert_eq!(unlisted, vec!["mid".to_string(), "zeta".to_string()]);
            assert_eq!(missing, vec!["ghost".to_string()]);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

/// 装配：全部模块装进 linker 即成功
#[test]
fn install_all_registers_every_module() {
    let engine = test_engine();
    let mut linker = Linker::<WasmPluginState>::new(&engine);
    ModuleRegistry::collected()
        .install_all(&mut linker)
        .expect("all stub modules install");
}

/// 反例 D：同一 linker 上重复装配必须失败并**点名模块**（不得静默覆盖接线）
///
/// 同一 interface 被装两次 = 两个能力域抢同一个 guest import 名字段，
/// 实例化期的行为会难以归因，故在装配期就炸。
///
/// 关键：第二次必须装进**同一个 linker**（宿主实例化期共用一个 linker）——
/// 装进新 linker 不构成重复，无从测起。
#[test]
fn install_all_rejects_duplicate_on_same_linker_and_names_module() {
    let engine = test_engine();
    let registry = ModuleRegistry::collected();
    let mut linker = Linker::<WasmPluginState>::new(&engine);

    registry.install_all(&mut linker).expect("first install");
    let err = registry
        .install_all(&mut linker)
        .expect_err("duplicate registration on the same linker must fail");

    match err {
        HostKitError::Register { module, source } => {
            assert!(
                matches!(module, "alpha" | "mid" | "zeta"),
                "must name the offending module, got {module:?}"
            );
            assert!(
                source.to_string().contains("defined twice"),
                "unexpected wasmtime error: {source}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

/// 边界：每个新 linker 独立装配都成功（装进新 linker 不算重复）
///
/// 与 [`install_all_rejects_duplicate_on_same_linker_and_names_module`] 成对，
/// 钉住「重复」的准确含义：同一 linker 内的二次装配，而非「进程内装过」。
#[test]
fn install_all_into_fresh_linkers_succeeds_each_time() {
    let engine = test_engine();
    let registry = ModuleRegistry::collected();
    for round in 0..2 {
        let mut linker = Linker::<WasmPluginState>::new(&engine);
        registry
            .install_all(&mut linker)
            .unwrap_or_else(|e| panic!("round {round} must install into a fresh linker: {e}"));
    }
}

/// 白名单差异的 **Display 文案**必须给出两个方向各自的修法（运维据此定位）
///
/// 与 [`whitelist_rejects_unlisted_module_and_names_it`]（只判变体字段）互补：本用例
/// 钉的是**人读的串**——`unlisted=` / `missing=` 两个方向标记、以及 forced-reference
/// （漏强制引用行）与 whitelist（未经 review 的白名单项）两条修法关键词。缺任一项，
/// 「依赖被删」与「能力悄悄进来」两种事故在日志里看起来一模一样。
///
/// 本用例在 host-kit 侧测（探针模块保证收集集非空）；wasm-core 侧只保留 missing
/// 方向（其测试二进制的收集集随能力域迁出收缩至空，依赖「非空」的用例会失效）。
#[test]
fn whitelist_mismatch_message_carries_remediation_for_both_directions() {
    let registry = ModuleRegistry::collected();
    let err = registry
        .verify_whitelist(&["alpha", "ghost"])
        .expect_err("双侧差异必须失败");
    let msg = err.to_string();

    assert!(
        msg.contains("unlisted="),
        "文案必须标出 unlisted 方向：{msg}"
    );
    assert!(msg.contains("missing="), "文案必须标出 missing 方向：{msg}");
    // 两侧的名字都要点名（unlisted=[mid, zeta]，missing=[ghost]）
    for name in ["mid", "zeta", "ghost"] {
        assert!(msg.contains(name), "文案必须点名 {name}：{msg}");
    }
    assert!(
        msg.contains("forced-reference"),
        "文案必须给出「漏强制引用行」的修法：{msg}"
    );
    assert!(
        msg.contains("whitelist"),
        "文案必须给出「白名单项需 review」的修法：{msg}"
    );
}

/// 错误串含期望/实际类型名（向下转型失败时必须能定位，fail-visible 的前提）
#[test]
fn host_port_unavailable_error_names_both_types() {
    let err = HostKitError::HostPortUnavailable {
        expected: "wasm_core::host_api::context::WasmHostContext",
        actual: "wasmnest_host_kit::tests::OtherCtx",
    };
    let text = err.to_string();
    assert!(
        text.contains("WasmHostContext"),
        "missing expected type: {text}"
    );
    assert!(text.contains("OtherCtx"), "missing actual type: {text}");
}

inventory::submit! {
    wasmnest_host_kit::ModuleEntry { module: &ALPHA }
}

// ==================== 兜底/兼容桩的两遍装配（cross-end 同进程装配的让位语义）====================

/// 真实现（同接口）：名前置 `z-` 以**字典序排在兜底桩之后**——让位不得依赖
/// 「正式模块恰好先排」这种偶然（装配顺序按名排序，而语义必须是两遍而非一遍）
static SHARED_REAL: RecordingModule = RecordingModule {
    name: "z-real",
    interfaces: &["test:pkg/shared"],
    func: "pinned-fn",
    is_fallback: false,
};

/// 兜底/兼容桩（同接口）：名前置 `a-` 排在真实现之前
static SHARED_COMPAT: RecordingModule = RecordingModule {
    name: "a-compat",
    interfaces: &["test:pkg/shared"],
    func: "pinned-fn",
    is_fallback: true,
};

/// 正例：同一 interface 上兜底桩让位给真实现（不装、不报错、不 shadow）
///
/// 这是跨端同进程装配（桌面 lib 与移动 lib 同时链入）的唯一正解：移动侧的桌面
/// 兼容桩只在「没有真实现」时填位，否则两份 `add_to_linker` 撞同一 interface
/// 即 `defined twice`，当日即红。
#[test]
fn install_all_skips_fallback_when_real_implementation_claims_interface() {
    reset_installed_log();
    let engine = test_engine();
    let mut linker = Linker::<WasmPluginState>::new(&engine);

    ModuleRegistry::from_modules(vec![&SHARED_COMPAT, &SHARED_REAL])
        .install_all(&mut linker)
        .expect("兜底桩让位后必须装配成功（同名 interface 不得 defined twice）");

    assert_eq!(
        installed_log(),
        vec!["z-real"],
        "只有真实现可注册：兜底桩必须被跳过（名字谁先谁后不影响）"
    );
}

/// 正例：接口无人占用时兜底桩照常装配（单端装配下行为不变）
///
/// 生产移动宿主只链移动 lib，兼容桩就是那个 interface 的唯一提供者——若因为
/// 「fallback 一律不装」把这条路径也砍了，跨端共享产物的 import 直接悬空。
#[test]
fn install_all_registers_fallback_when_interface_uncontested() {
    reset_installed_log();
    static SOLO_COMPAT: RecordingModule = RecordingModule {
        name: "solo-compat",
        interfaces: &["test:pkg/compat-only"],
        func: "pinned-fn",
        is_fallback: true,
    };
    let engine = test_engine();
    let mut linker = Linker::<WasmPluginState>::new(&engine);

    ModuleRegistry::from_modules(vec![&SOLO_COMPAT])
        .install_all(&mut linker)
        .expect("无竞争的兜底桩必须装上");

    assert_eq!(installed_log(), vec!["solo-compat"]);
}

/// 反例：两个**真实现**抢同一 interface 必须显性失败并点名（两遍装配不放宽这条）
///
/// 与 `install_all_rejects_duplicate_on_same_linker_and_names_module` 互补：那条
/// 走「同一 registry 装两遍」，本条款走「一个 registry 内两个真实现同名」——
/// 都是能力域抢同一 guest import 名字段，装配期就得炸。
#[test]
fn install_all_rejects_two_real_modules_claiming_same_interface() {
    static REAL_A: RecordingModule = RecordingModule {
        name: "real-a",
        interfaces: &["test:pkg/contested"],
        func: "pinned-fn",
        is_fallback: false,
    };
    static REAL_B: RecordingModule = RecordingModule {
        name: "real-b",
        interfaces: &["test:pkg/contested"],
        func: "pinned-fn",
        is_fallback: false,
    };
    let engine = test_engine();
    let mut linker = Linker::<WasmPluginState>::new(&engine);

    let err = ModuleRegistry::from_modules(vec![&REAL_A, &REAL_B])
        .install_all(&mut linker)
        .expect_err("两个真实现同名 interface 必须失败");

    match err {
        HostKitError::Register { module, source } => {
            assert!(
                matches!(module, "real-a" | "real-b"),
                "必须点名后装的那个模块，got {module:?}"
            );
            assert!(
                source.to_string().contains("defined twice"),
                "unexpected wasmtime error: {source}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

/// 边界：两个兜底桩抢同一 interface——先装者占位，后到者跳过（不炸）
///
/// 桩的语义本就是「没有正式提供者时填位」，桩之间同名属于装配配置问题：按字典序
/// 让先登场的赢，比整份装配失败更符合兜底定位（真需要严谨应由白名单/离线校验管）。
#[test]
fn install_all_skips_second_fallback_claiming_same_interface() {
    reset_installed_log();
    static COMPAT_FIRST: RecordingModule = RecordingModule {
        name: "b-compat-first",
        interfaces: &["test:pkg/dual-compat"],
        func: "pinned-fn",
        is_fallback: true,
    };
    static COMPAT_SECOND: RecordingModule = RecordingModule {
        name: "c-compat-second",
        interfaces: &["test:pkg/dual-compat"],
        func: "pinned-fn",
        is_fallback: true,
    };
    let engine = test_engine();
    let mut linker = Linker::<WasmPluginState>::new(&engine);

    ModuleRegistry::from_modules(vec![&COMPAT_FIRST, &COMPAT_SECOND])
        .install_all(&mut linker)
        .expect("桩间同名不得让整份装配失败");

    assert_eq!(
        installed_log(),
        vec!["b-compat-first"],
        "先登场的兜底桩占位，后到者跳过"
    );
}
inventory::submit! {
    wasmnest_host_kit::ModuleEntry { module: &MID }
}
inventory::submit! {
    wasmnest_host_kit::ModuleEntry { module: &ZETA }
}
