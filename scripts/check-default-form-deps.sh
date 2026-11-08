#!/bin/sh
# ==================== 默认形态依赖门禁 ====================
#
# 判据：声明「宿主无关」的 crate 的**正常依赖树**（`-e normal`，不含 dev/build）
# 不得出现宿主框架、bundled SQLite、系统信息采集与文件监听。这是 AGENTS §3.1
# 「默认形态 = 零 WIT / 零 SDK / 零宿主框架」的可执行面——文档承诺不成立时直接红。
#
# 为什么需要它：无头探针（wasmnest-headless-host-probe）只断言
# `wasmtime / wit-bindgen / inventory / host-kit`（「默认形态不需要插件宿主机制」），
# 且它**故意**链接 server 栈 ⇒ 不能兼作 Tauri/actix 断言。本门禁是那条不变量的
# 传递闭包补充，按 crate 逐个跑 `cargo tree`。
#
# 用法：
#   sh scripts/check-default-form-deps.sh            # CI / 有网（cargo 自动 fetch）
#   sh scripts/check-default-form-deps.sh --offline  # 本地（用 registry 缓存索引）
#
# 匹配纪律（重要）：按 **crate 名 token 精确匹配**（`cargo tree --prefix none` 每行
# 首列即包名），**不得**用裸 grep —— 本地仓库路径形如 `.../tauriProject/...`，
# 裸 grep `tauri` 会逐行假红。
#
# 失败时对每个违规包打印 `cargo tree -i <包名>` 反向路径，直接指出是哪条边引入。
set -eu

OFFLINE=""
if [ "${1:-}" = "--offline" ]; then
  OFFLINE="--offline"
fi

# 「宿主无关」crate：默认形态必须可被任何宿主引用
CRATES="
wasmnest-server-base
wasmnest-crypto-engine
wasmnest-cli-engine
wasmnest-pty-engine
wasmnest-discovery-engine
wasmnest-ws-client-engine
wasmnest-p2p-engine
"

# 禁止出现在正常依赖树里的包（精确名，大小写不敏感）
FORBIDDEN="
tauri
actix
actix-web
actix-web-actors
rusqlite
sysinfo
notify
inotify
"

# 仅对**不消费 mDNS**的 crate 追加禁止项：`mdns-sd` 对 discovery-engine /
# p2p-engine 是合法能力依赖；出现在 crypto/cli/pty 里说明 server-base 的
# `mdns` feature 泄漏（feature 默认关，只有显式开启的消费方才该看到它）。
MDNS_FREE_CRATES="
wasmnest-crypto-engine
wasmnest-cli-engine
wasmnest-pty-engine
"

fail=0
checked=0

for crate in $CRATES; do
  manifest="$crate/Cargo.toml"
  if [ ! -f "$manifest" ]; then
    echo "✗ 门禁登记了不存在的 crate：$crate（$manifest 缺失）"
    fail=1
    continue
  fi

  # `--prefix none`：每行 `name vX.Y.Z (path)`，首列即包名（无树形前缀字符，
  # 故首列不会出现 `├──` 这类噪声）。
  tree=$(cargo tree --manifest-path "$manifest" -e normal --prefix none $OFFLINE 2>/dev/null) || {
    echo "✗ cargo tree 失败：$crate（先跑一次 `cargo fetch` 补索引，或去掉 --offline）"
    fail=1
    continue
  }
  checked=$((checked + 1))

  names=$(printf '%s\n' "$tree" | awk 'NF >= 2 && $2 ~ /^v[0-9]/ { print tolower($1) }' | sort -u)

  violations=""
  for banned in $FORBIDDEN; do
    if printf '%s\n' "$names" | grep -qx "$banned"; then
      violations="$violations $banned"
    fi
  done

  for mdns_free in $MDNS_FREE_CRATES; do
    if [ "$crate" = "$mdns_free" ] && printf '%s\n' "$names" | grep -qx "mdns-sd"; then
      violations="$violations mdns-sd"
    fi
  done

  if [ -n "$violations" ]; then
    fail=1
    echo "✗ $crate 的默认依赖树含宿主框架 / 重依赖：$violations"
    for banned in $violations; do
      echo "  ── 反向依赖路径（$banned）："
      cargo tree --manifest-path "$manifest" -e normal -i "$banned" $OFFLINE 2>&1 | sed 's/^/     /'
    done
  else
    echo "✓ $crate"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "默认形态依赖门禁失败：上列 crate 的默认依赖树引入了宿主框架 / bundled SQLite /"
  echo "系统信息采集 / 文件监听。修法见 AGENTS §3.1：把具体类型换成端口抽象（端口 trait"
  echo "常编译、具体实现住宿主），或给依赖加 optional + feature 门控，由需要它的消费方"
  echo "显式开启——不要靠「下游反正不会用」放行。"
  exit 1
fi

echo ""
echo "默认形态依赖门禁通过（$checked 个 crate）。"
