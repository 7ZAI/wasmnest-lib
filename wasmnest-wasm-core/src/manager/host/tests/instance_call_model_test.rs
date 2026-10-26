//! 装配条目结构锁（I1：Store 只经装配条目、属主启动单点、能力导出无直锁调用）。
//!
//! **票 04 迁移记录**：原文件的三条两模型对照用例（命令往返 / 停用再激活 /
//! trap 文案与失败可见性）随「wasm-core 不再持全 world 绑定」迁桌面宿主
//! `src-tauri/tests/wasm_flow_e2e.rs`（`command_round_trip_works_in_both_call_models` /
//! `deactivate_then_reactivate_works_in_both_call_models` /
//! `trap_error_text_and_post_trap_failure_match_across_models`）。留本文件的结构锁
//! 不实例化夹具——它读内核源码形态，属内核机制面。

/// 结构锁（I1）：装配条目是 Store 的唯一宿主；属主启动单点；能力导出/调用面
/// 不再有绕过门面的直锁访问
///
/// 动态用例无法在编译期钉住「不存在第二个 Store 入口」，故按源码形态锁死：
/// 一旦有人在别处 `spawn_owner` / 重新引入 `wasm_plugins` 直锁取实例或
/// `call_capability_export` 直调，本锁立即转红。
#[test]
fn instance_slot_structural_lock() {
    let host_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/manager/host.rs"))
            .expect("read host.rs");
    let owner_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/manager/host/owner.rs"
    ))
    .expect("read owner.rs");
    let commands_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/manager/host/commands.rs"
    ))
    .expect("read commands.rs");
    let capability_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/manager/capability.rs"
    ))
    .expect("read capability.rs");

    assert!(
        host_src.contains("wasm_plugins: Arc<RwLock<HashMap<String, Arc<WasmInstanceEntry>>>>"),
        "装配表必须只存装配条目（Store 只能存在于 InstanceSlot 内——I1）"
    );
    assert!(
        host_src.contains("enum InstanceSlot {"),
        "调用模型必须收敛在 InstanceSlot 枚举（mutex / event-loop 双形态）"
    );
    assert_eq!(
        host_src.matches("spawn_owner(").count(),
        1,
        "属主任务启动必须单点（只在装配条目构造里），且宿主侧不得有第二个 Store 入口"
    );
    assert!(
        host_src.contains("dispatch_mutex_op("),
        "mutex 分支必须委派既有导出方法（错误文案逐字等价 = I5 by construction）"
    );

    // 门面之外不得再有直锁实例的调用面（改造前 `call_plugin_capability_export`
    // 是唯一绕过 trap 封装的调用点，已并入 call_guest）
    assert!(
        !commands_src.contains("call_capability_export"),
        "命令面必须经统一门面（不得直锁实例调能力导出）"
    );
    assert!(
        !capability_src.contains("call_capability_export"),
        "能力转发必须经窄端口 CapabilityTarget（不得直锁提供者实例）"
    );
    assert!(
        capability_src.contains("target.storage_get(")
            && capability_src.contains("target.storage_set("),
        "能力转发必须走端口（超时兜底在端口实现内）"
    );

    // 属主循环形态：常驻 run_concurrent + 单点 start + biased（详见 owner_i4_structural_lock）
    assert_eq!(
        owner_src.matches("run_concurrent(").count(),
        1,
        "属主模型必须只有一处常驻 run_concurrent 作用域"
    );

    // fuel / 指标口径（spec §3.3「task 级计量」）：续费在 start 前发生、
    // 计时器绑到 task 生命周期（start → finish），不得退回「每调用一把锁」的形态
    assert!(
        owner_src.contains("refill_fuel(&mut access"),
        "燃料续费必须在 start 前同步发生（实例级预算，续费点差值记账）"
    );
    assert!(
        owner_src.contains("let _timer = timer;"),
        "调用计时器必须随 guest task 存活（start → finish 生命周期口径）"
    );
}
