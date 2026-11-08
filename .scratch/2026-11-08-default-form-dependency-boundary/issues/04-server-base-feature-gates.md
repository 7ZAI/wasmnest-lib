# 04: `server-base` 能力面 feature 化：`mdns` / `system-info`

**What to build:** 不消费 mDNS 与系统信息采集的 crate 默认树里不再出现 `mdns-sd` / `flume` / `sysinfo` / `local-ip-address`；对等网络引擎与桌面宿主显式开启所需 feature，无头 / 第三方宿主可自行实现端口。

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] `MdnsPort` / `MdnsTypeSubscription` / `ServerPorts.mdns` 受 `mdns` feature 门控；`SystemInfo::collect()` 与 IP 辅助函数受 `system-info` 门控；`SystemInfo` DTO 与 `SystemInfoPort` 常编译。
- [ ] `server-base` 默认依赖树无 `mdns-sd` / `flume` / `sysinfo` / `local-ip-address`。
- [ ] `wasmnest-server-peer-net` 显式开启 `mdns`，其测试与 `common-host` 形态编译、测试绿。
- [ ] `server-base` 既有测试按 feature 加 `#[cfg]`，默认 `cargo test --offline` 不依赖 mdns / sysinfo。
- [ ] 桌面宿主开启 `system-info`（由 09 承接）；无头宿主可自行实现 `SystemInfoPort`。
