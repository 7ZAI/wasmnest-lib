# 09: 平台双端宿主适配（可与穿透 T06 同批）

**What to build:** 桌面与移动宿主在 P0 后的能力仓上编译通过：桌面显式开启 `tauri-compat` / `mdns` / `system-info`，密码注册表调用适配 `CryptoResult`，rusqlite / tauri 错误边界显式映射，依赖边锁同步；移动宿主不因 base 默认值变更而回退。

**Blocked by:** 03、04、05

**Status:** ready-for-agent

- [ ] 桌面宿主显式声明 `tauri-compat` / `mdns` / `system-info`（不依赖传递 feature 合并）。
- [ ] 密码注册表调用适配 `CryptoResult`；rusqlite / tauri 错误在边界显式 `map_err`。
- [ ] 桌面依赖边锁的 ALLOWED / REQUIRED 表摘除 `crypto-engine → server-base`，锁绿。
- [ ] 移动宿主编译通过；`MdnsPort` 实现经对等网络引擎 feature 或显式声明获得。
- [ ] 桌面相关 `cargo test` 锁绿；移动 `cargo check` 绿。
- [ ] 若与穿透 T06 同批实施，不重复实现同一批装配改动，并在平台提交中注明同批关系。
