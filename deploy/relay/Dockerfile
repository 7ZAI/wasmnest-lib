# ==================== wasmnest-relay 镜像（多架构） ====================
# 构建上下文 = **能力仓根**（需要 wasmnest-relay/ 目录）：
#   docker build -f deploy/relay/Dockerfile -t ghcr.io/7zai/wasmnest-relay:0.0.1 .
# 多架构（需 buildx，amd64 上跑 arm64 走 QEMU，慢但正确）：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f deploy/relay/Dockerfile -t ghcr.io/7zai/wasmnest-relay:0.1.0 --push .
#
# 为什么用 alpine + musl 静态链接：产物要能直接丢到任意 Linux VPS 上跑，不依赖
# 宿主 glibc 版本。Noise 用 ring（C/asm），因此构建阶段需要 build-base + perl。
# syntax=docker/dockerfile:1

FROM rust:1.88-alpine AS builder
RUN apk add --no-cache build-base perl
WORKDIR /src
# 只复制本 crate：中继不依赖能力仓任何内部 crate（形态锁见 src/boundary_lock.rs）
COPY wasmnest-relay/Cargo.toml wasmnest-relay/Cargo.lock ./wasmnest-relay/
COPY wasmnest-relay/src ./wasmnest-relay/src
# 不复制 crate 的 .cargo/config.toml：镜像内不需要共享 target 桶
RUN cargo build --release --locked --manifest-path wasmnest-relay/Cargo.toml \
 && strip wasmnest-relay/target/release/wasmnest-relay

FROM alpine:3.20
# 运行期只需要 CA 时间同步与 busybox（healthcheck 用 wget）
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 -S relay \
 && adduser -u 10001 -S -G relay -h /data relay \
 && mkdir -p /data \
 && chown relay:relay /data
COPY --from=builder /src/wasmnest-relay/target/release/wasmnest-relay /usr/local/bin/wasmnest-relay
VOLUME ["/data"]
# 身份与配置都在 /data：重启不换 PeerId
WORKDIR /data
USER relay
EXPOSE 4001/tcp
EXPOSE 9090/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9090/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/wasmnest-relay"]
# 首次运行前需要先生成身份与配置（没有 identity.key 时 run 会显性失败并提示）：
#   docker run --rm -v wasmnest-relay-data:/data ghcr.io/7zai/wasmnest-relay:<ver> \
#     init --dir /data --advertise relay.example.com
CMD ["run", "--config", "/data/config.toml"]
