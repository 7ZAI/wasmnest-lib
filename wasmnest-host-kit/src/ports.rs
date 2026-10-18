//! 宿主能力端口：能力 crate 与宿主之间的**唯一**边界
//!
//! ## 为什么只有一个 marker trait
//!
//! [`crate::state::WasmPluginState`] 必须住在本 crate（能力 crate 要能命名它，
//! 否则 `add_to_linker::<S, D>` 的单态 `S` 命名不了 ⇒ Cargo 环路）。但它的宿主
//! 上下文字段不能是宿主的 `WasmHostContext` 具体类型——那会把整个宿主（tauri、
//! 数据库、授权闸门…）拖进机制内核。
//!
//! 折中：**状态里存 `Arc<dyn HostPorts>`（本 trait 无方法，只有向下转型出口）**。
//!
//! - **留在宿主的能力域**（core 面）：`impl … Host for WasmPluginState` 块本身就在
//!   宿主 crate 内，直接向下转型回 `&WasmHostContext` 继续用既有 13 个窄 scope，
//!   零改动语义；
//! - **迁出的能力域**（`packages/wasmnest-*` crate）：**不碰向下转型**，改为自声明窄端口
//!   trait（照 `wasmnest-server-base::ports` 先例：消费方声明端口，宿主 adapter
//!   实现），拿到的是它真正消费的那几个方法，而不是整个上帝对象。
//!
//! ## 域端口的下发通道（[`HostPorts::domain_ports`]）
//!
//! 迁出的能力域在本 crate 内跑 `impl … Host for WasmPluginState`，它**拿不到**
//! 宿主上下文（那正是向下转型禁令的目的），只能经两种方式要端口：
//!
//! 1. **进程级装配**（[`install_ports` 语义，各能力域自持）：开机装一次，之后全局
//!    取用。适合「端口与进程同生命周期」的场景（mdns 的共享守护即如此）。
//! 2. **实例级下发**（本方法）：宿主把「与本插件实例同一份宿主上下文绑定」的端口
//!    挂在上下文上，能力域经 `self.host` 取回。
//!
//! **为什么必须有第 2 条**：一个进程里可以有多份宿主上下文（无头测试每个用例一份、
//! 多实例并行），它们各有各的权限管理器与消息总线。第 1 条只有一格，先装者胜出 ⇒
//! 多上下文场景下能力域会读到**别的上下文**的端口（权限判定错库、事件投错总线）。
//! 第 2 条把「哪个上下文」这个决定权交回实例，能力域代码与上下文数量无关。
//!
//! ## 红线
//!
//! 本 trait **不得**新增任何业务方法（那会让机制内核变成业务容器，命中 AGENTS §5.1
//! B1/B5）。新增能力域的端口 trait 请声明在该能力域自己的 crate 里；本方法只传递
//! **不透明容器**（`Arc<dyn Any>`），kit 不认识任何域端口的类型。

use std::any::Any;
use std::sync::Arc;

/// 宿主能力端口（机制面标记 trait）
///
/// 实现方是各端宿主的上下文聚合对象（桌面端当前为 `WasmHostContext`）。
/// 本 trait **只有向下转型出口与域端口下发**，不承载任何业务方法——见模块文档
/// 「为什么只有一个 marker trait」。
pub trait HostPorts: Send + Sync + 'static {
    /// 向下转型出口：让**留在宿主内**的实现块取回具体上下文类型
    ///
    /// 迁出的能力域不应用本方法（它们自声明窄端口，见模块文档）。
    fn as_any(&self) -> &dyn Any;

    /// 向下转型出口（可变版）
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// 实例级能力域端口下发（可选）
    ///
    /// 宿主把**与本插件实例同一份上下文绑定**的窄端口挂在上下文上；能力域用
    /// `domain_ports` 的返回值向下转型成自己的端口 trait 对象（存进去的实际是
    /// `Arc<dyn 域端口>`，见 [`downcast_domain_ports`]）。
    ///
    /// 返回 `None` = 本上下文未为该域装配端口 ⇒ 调用方按各能力域自己的兜底口径
    /// 处理（进程级装配，见模块文档两条通道的分工），**不得**静默当成「无该能力」。
    fn domain_ports(&self, _domain: &str) -> Option<Arc<dyn Any + Send + Sync>> {
        None
    }
}

/// 把域端口容器还原成能力域自己的端口类型（类型不符即 `None`，由调用方按兜底口径处理）
///
/// 宿主注入的实际类型是 `Arc<dyn 域端口>`；这里只做一次向下转型，kit 仍不认识
/// 任何域端口的类型（红线）。
pub fn downcast_domain_ports<P: Send + Sync + 'static>(
    value: Arc<dyn Any + Send + Sync>,
) -> Option<Arc<P>> {
    value.downcast::<P>().ok()
}

/// 向下转型到具体宿主上下文类型（类型不符即**显性失败**）
///
/// 绝不返回 `Option` 静默降级：一个未装配的宿主上下文若以「拿不到上下文」的面貌
/// 继续跑，等于让该能力域以空转姿态出现在插件 import 集里（fail-visible 反例）。
///
/// # Panics
/// 类型不符时 panic 并带上期望/实际类型名。这是**装配期**编程错误（宿主没为本能力
/// 域实现端口 / 状态被塞进了别的上下文），不是运行期可恢复故障。
pub fn downcast_host<P: 'static>(ports: &dyn HostPorts) -> &P {
    match ports.as_any().downcast_ref::<P>() {
        Some(ctx) => ctx,
        None => panic!(
            "{}",
            crate::HostKitError::HostPortUnavailable {
                expected: std::any::type_name::<P>(),
                actual: std::any::type_name_of_val(ports.as_any()),
            }
        ),
    }
}

/// 向下转型到具体宿主上下文类型（可变版；语义同 [`downcast_host`]）
///
/// # Panics
/// 类型不符时 panic，见 [`downcast_host`]。
pub fn downcast_host_mut<P: 'static>(ports: &mut dyn HostPorts) -> &mut P {
    // 先取实际类型名再可变借用：闭包里再借用 `ports` 会与 `as_any_mut` 的可变借用冲突
    let actual = std::any::type_name_of_val(ports.as_any());
    match ports.as_any_mut().downcast_mut::<P>() {
        Some(ctx) => ctx,
        None => panic!(
            "{}",
            crate::HostKitError::HostPortUnavailable {
                expected: std::any::type_name::<P>(),
                actual,
            }
        ),
    }
}
