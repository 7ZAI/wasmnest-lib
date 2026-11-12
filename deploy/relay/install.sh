#!/bin/sh
# ==================== wasmnest-relay 一键安装（仅 Linux） ====================
# 做什么：装二进制 → 建系统用户 → 生成身份/配置（可选）→ 装 systemd unit → 启动。
# 不做什么：不开防火墙、不论断 TLS（libp2p 层已有 Noise）、不代管你的域名解析。
#
# 用法：
#   ./install.sh --advertise relay.example.com            # 用同目录/当前 PATH 里的二进制
#   ./install.sh --advertise relay.example.com --binary /tmp/wasmnest-relay
#   ./install.sh --advertise relay.example.com --force    # 覆盖既有身份（会换 PeerId！）
#   ./install.sh --uninstall
#
# 依赖：systemd、install、useradd 或 adduser、groupadd 或 addgroup。
# 只支持 systemd 发行版（Debian/Ubuntu/CentOS/Fedora 等）；Alpine+openrc 不支持。
set -eu

BIN_DEST=/usr/local/bin/wasmnest-relay
CONF_DIR=/etc/wasmnest-relay
UNIT_DEST=/etc/systemd/system/wasmnest-relay.service
SERVICE_USER=wasmnest-relay
ADVERTISE=""
BINARY=""
FORCE=""
UNINSTALL=""

log() { printf '%s\n' "$*"; }
die() { printf '错误：%s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --advertise) ADVERTISE="${2:-}"; shift 2 ;;
    --binary) BINARY="${2:-}"; shift 2 ;;
    --force) FORCE="--force"; shift ;;
    --uninstall) UNINSTALL="1"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "未知参数 $1（--help 看用法）" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "需要 root（安装 systemd 服务）"
[ -d /etc/systemd/system ] || die "未找到 /etc/systemd/system：本脚本只支持 systemd 发行版；Docker 部署请用 compose（见 README §1）"

if [ -n "$UNINSTALL" ]; then
  systemctl disable --now wasmnest-relay.service 2>/dev/null || true
  rm -f "$UNIT_DEST"
  systemctl daemon-reload
  log "已停止并移除服务。配置与身份仍在 $CONF_DIR（含 PeerId，删除前请确认没有客户端在用）。"
  exit 0
fi

[ -n "$ADVERTISE" ] || die "缺少 --advertise <公网域名|IP>：客户端需要一个可拨地址"

if [ -z "$BINARY" ]; then
  command -v wasmnest-relay >/dev/null 2>&1 || die "找不到 wasmnest-relay 二进制，用 --binary <路径> 指定"
  BINARY=$(command -v wasmnest-relay)
fi
[ -x "$BINARY" ] || die "二进制不可执行：$BINARY"

log "==> 安装二进制到 $BIN_DEST"
install -m 0755 "$BINARY" "$BIN_DEST"

log "==> 创建系统用户 $SERVICE_USER"
# unit 的 Group= 与配置目录的 chown 都依赖同名组：先建组再建用户，不指望
# useradd/adduser 的默认建组行为（Alpine 的 adduser 降级路径就不建组）。
if ! grep -q "^${SERVICE_USER}:" /etc/group; then
  groupadd --system "$SERVICE_USER" 2>/dev/null || addgroup -S "$SERVICE_USER" \
    || die "无法创建系统组 $SERVICE_USER"
fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --gid "$SERVICE_USER" --shell /usr/sbin/nologin "$SERVICE_USER" \
      || die "无法创建系统用户 $SERVICE_USER"
  else
    adduser -S -H -G "$SERVICE_USER" -s /sbin/nologin "$SERVICE_USER" \
      || die "无法创建系统用户 $SERVICE_USER"
  fi
fi
id "$SERVICE_USER" >/dev/null 2>&1 || die "服务用户 $SERVICE_USER 不存在"
grep -q "^${SERVICE_USER}:" /etc/group || die "服务组 $SERVICE_USER 不存在（unit 的 Group= 会启动失败）"

log "==> 准备配置目录 $CONF_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$CONF_DIR"

if [ -f "$CONF_DIR/config.toml" ] && [ -z "$FORCE" ]; then
  log "!! $CONF_DIR/config.toml 已存在：保留现有身份与配置（要重建请加 --force）"
else
  log "==> 生成身份与配置（advertise=$ADVERTISE）"
  "$BIN_DEST" init --dir "$CONF_DIR" --advertise "$ADVERTISE" $FORCE
  chown -R "$SERVICE_USER:$SERVICE_USER" "$CONF_DIR"
  chmod 0600 "$CONF_DIR/identity.key"
fi

log "==> 安装 systemd unit"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SCRIPT_DIR/wasmnest-relay.service" ]; then
  install -m 0644 "$SCRIPT_DIR/wasmnest-relay.service" "$UNIT_DEST"
else
  die "找不到 wasmnest-relay.service（应与本脚本同目录）"
fi
systemctl daemon-reload
systemctl enable wasmnest-relay.service
systemctl restart wasmnest-relay.service

sleep 1
systemctl --no-pager --lines=10 status wasmnest-relay.service || true

log ""
log "==> 下一步"
log "  1) 防火墙放行 TCP 4001（只需这一个端口）："
log "       ufw allow 4001/tcp    # 或 firewall-cmd --add-port=4001/tcp --permanent"
log "  2) 自检：$BIN_DEST doctor --config $CONF_DIR/config.toml"
log "  3) 把下面地址导入应用（桌面「中转服务器」卡片）："
"$BIN_DEST" print-addrs --config "$CONF_DIR/config.toml" || true
