# 06: `cli-engine` 去 `server-base`：`WireError` 自持 + 兜底码从契约仓取

**What to build:** argv / 帧解析 crate 只依赖零依赖契约仓与 serde；wire 形状 `{code, params?}` 与兜底码不变；`AppError → WireError` 映射从本仓删除（宿主侧随 CLI 票据落地），CLI / 无头宿主不再被桌面 server 错误信封拖入整条依赖链。

**Blocked by:** 02（`DEFAULT_ERROR_CODE` 必须先住契约仓）

**Status:** ready-for-agent

- [ ] `cli-engine` 依赖清单无 `wasmnest-server-base`；`cargo tree --offline -e normal` 无 `server-base` 及其传递依赖。
- [ ] `WireError` 的 wire 形状与兜底码不变；兜底码从 `wasmnest-contract` 取。
- [ ] `from_app_error` 删除或改为纯 `from_code` 构造；依赖 `AppError` 的测试迁移或改写。
- [ ] catalog / parse / help / wire 测试绿；现有消费方（无头探针仅链接）编译绿。
