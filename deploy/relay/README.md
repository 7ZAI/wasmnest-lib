# wasmnest-relay 部署手册（Linux）

中继节点是**独立守护进程**：跑在公网 VPS / 自建服务器上，替两端转发 Noise 密文。
它不是 wasm 插件，也不参与设备配对判定——reservation 只代表「可以经我转发」，
真正的访问授权在目标设备的匹配校验上。

仅支持 **Linux**（amd64 / arm64）与 Docker；Windows / macOS 不做二进制或服务包。
只放行 **TCP 4001**（v1 不启用 UDP/QUIC），无需 TLS 证书。

- 二进制 / 镜像：`wasmnest-relay`、`ghcr.io/7zai/wasmnest-relay:<version>`
- 版本轴独立：`relay-vX.Y.Z`（与能力仓 / 应用仓版本无关）
- 身份与版本解耦：升级镜像不换 PeerId，除非你覆盖 `identity.key`

---

## 1. 最短路径（Docker Compose，推荐）

```bash
cd deploy/relay
# 1) 首次生成身份与配置（身份丢了 = PeerId 变 = 所有客户端要重新导入）
docker compose run --rm relay init --dir /data --advertise relay.example.com
# 2) 起服务
docker compose up -d
# 3) 取客户端导入用的地址
docker compose exec relay wasmnest-relay print-addrs --config /data/config.toml
```

生产环境请把 `docker-compose.yml` 里的 `image:` 换成 digest 钉住的形式
（`...@sha256:<digest>`），避免上游 tag 漂移。

不用 Compose 的单条命令：

```bash
docker run -d --name wasmnest-relay --restart unless-stopped \
  -p 4001:4001 -v wasmnest-relay-data:/data \
  ghcr.io/7zai/wasmnest-relay:<version>
```

## 2. 最短路径（systemd 单文件二进制）

```bash
./install.sh --advertise relay.example.com --binary ./wasmnest-relay
```

脚本做四件事：装二进制到 `/usr/local/bin`、建系统用户 `wasmnest-relay`、在
`/etc/wasmnest-relay` 生成身份与配置（已有配置则保留）、装 unit 并启动。
卸载用 `./install.sh --uninstall`（**不删**配置目录：里面有 PeerId）。

## 3. 手动运行 / 自检

```bash
wasmnest-relay init --dir /etc/wasmnest-relay --advertise relay.example.com
wasmnest-relay run  --config /etc/wasmnest-relay/config.toml
wasmnest-relay doctor      --config /etc/wasmnest-relay/config.toml
wasmnest-relay print-addrs --config /etc/wasmnest-relay/config.toml --json
```

`doctor` 的口径是**本机能查的实检，本机不能自证的如实标 `unknown`**：

| 项 | 判据 |
| --- | --- |
| `identity` | 密钥可解析、是 ed25519、权限建议 600 |
| `config` | 版本 / 多地址形状 / 配额越界组合 |
| `listen` | 真实 bind 一次（端口被占用会提示「relay 正在运行？」） |
| `clock` | 时间早于 2025-01-01 视为明显错误（有效期会算错） |
| `data_dir` | 真实写入探针（容器只读卷在这里现形） |
| `tokens` | token 表可解析；allowlist 模式却无白名单无 token 时警告 |
| `metrics` | 非回环地址必须显式 `expose_public = true` |
| `reachability` | 通告地址若是私网/回环 → 警告；否则标 `unknown` 并给出外部验证路径 |
| `version` | relay 版本 / 配置版本 / 控制协议；单 circuit 上限 < 1 GiB 时警告 |

退出码：有 `Fail` 即 1，否则 0（`Warn` / `Unknown` 不阻断）。

---

## 4. 准入：开放 vs 白名单

```toml
[access]
mode = "open"      # 默认：任何人可预留，靠配额防滥用
allowlist = []     # mode = "allowlist" 时生效：PeerId 白名单（base58）
```

`allowlist` 模式下，白名单外的设备**仍然能连上来**（否则它没法自助开通），但它的
reservation / circuit 请求会被拒绝并计入指标。开通有两条路：

1. **静态**：把设备 PeerId 写进 `allowlist`（设备侧可在应用里看到自己的 PeerId）；
2. **enrollment token**（推荐）：

```bash
wasmnest-relay token create --config /etc/wasmnest-relay/config.toml --label phone
```

明文 token 只显示这一次，落盘只有 `sha256` 摘要，默认一次兑换即失效
（`--max-uses N` 可放宽到 N 次）。设备用它在控制协议 `/wasmnest/relay-control/1`
兑换后，PeerId 被写入 `enrolled-peers.json`（重启仍有效）。

**relay 不是授权点**：白名单只决定「谁能蹭你的带宽」，不决定「谁能访问哪台设备」。

## 5. 配额

默认值按「跨 NAT 传 1GB 文件」验收口径设定；libp2p 自带的 `max_circuit_bytes`
只有 128 KiB，直接沿用会让大文件传输中途被掐断（表现为随机失败，极难排查）。

| 配置项 | 默认 | 含义 |
| --- | --- | --- |
| `max_reservations` / `max_reservations_per_peer` | 1024 / 4 | reservation 总量 / 单 peer |
| `reservation_ttl_secs` | 3600 | reservation 有效期 |
| `max_circuits` / `max_circuits_per_peer` | 512 / 64 | 并发 circuit 总量 / 单 peer |
| `max_circuit_duration_secs` | 3600 | 单 circuit 最长存活 |
| `max_circuit_bytes` | 1 GiB | 单 circuit 字节上限（0 = 不限） |
| `max_connections_per_ip` | 32 | 单 IP 入站连接上限 |

`max_circuit_bytes` 是**单条 circuit** 的上限：1GB 传输若中途重建 circuit（网络抖动、
重连续传），每条都按自己的配额重新计，不需要把上限调到 10GB。

## 6. 指标与隐私

`127.0.0.1:9090` 上只有两个只读端点：

```bash
curl -s http://127.0.0.1:9090/healthz   # PeerId / 指纹 / 准入模式 / 通告地址
curl -s http://127.0.0.1:9090/metrics   # Prometheus 文本：reservation / circuit / 拒绝原因
```

- 指标**只含计数**：reservation、circuit、入站连接、按原因分桶的拒绝次数。
- 不记 payload / 文件名 / 路径 / token；日志只打 PeerId 短指纹与事件。
- 字节数暂不提供：`libp2p-relay` 的 `CircuitClosed` 事件不带字节数，与其造一个
  假数字不如不给（后续上游提供后再加，属非破坏性变更）。
- 要公网抓取指标：改 `metrics.listen` 并显式 `expose_public = true`，**同时**
  自行加反代 TLS 或额外 token——否则等于把你家的 PeerId 与用量公开。

## 7. 升级与身份纪律

```bash
# Docker
docker compose pull && docker compose up -d
# systemd
./install.sh --advertise relay.example.com --binary ./wasmnest-relay   # 保留现有身份
```

- 升级**不换** PeerId：`identity.key` 不动即可。
- `init --force` 才会覆盖身份；覆盖后所有客户端必须重新导入中继地址。
- 备份只需 `identity.key`（配置可重建，token 可重发，enrollment 可重做）。

## 8. 排障

| 症状 | 排查顺序 |
| --- | --- |
| 客户端报「中继不可达」 | 云安全组 / 防火墙是否放行 TCP 4001；`doctor` 的 `listen` 项；域名是否解析到本机 |
| 客户端报「中继拒绝预留（配额/白名单）」 | `access.mode` 是否 `allowlist`；`tokens` 项剩余可用次数；`/metrics` 的 `rejected{reason="reservation-denied"}` |
| 预留成功但连不上对端 | 对端是否在线并已预留；两边是否导入同一个 relay 的**同一份**地址（含 `/p2p/<relay PeerId>`） |
| 大文件传到一半失败 | `max_circuit_bytes` / `max_circuit_duration_secs` 是否被调小；`doctor` 的 `version` 项会提示 < 1 GiB |
| 容器起来就退出 | 首次运行前没 `init`：`run` 找不到 `identity.key` 会显性失败并提示；`docker compose logs relay` |
| 重启后 PeerId 变了 | `/data` 卷没挂上或换了卷；用 `print-addrs` 对比 `peerIdSha256` |

日志：`WASMNEST_RELAY_LOG=debug`（容器可 `-e WASMNEST_RELAY_LOG=debug`）。
