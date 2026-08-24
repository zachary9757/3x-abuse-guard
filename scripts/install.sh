#!/usr/bin/env bash
set -Eeuo pipefail

REPO="${REPO:-zachary9757/3x-abuse-guard}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/3x-abuse-guard}"
STATE_DIR="${STATE_DIR:-/var/lib/3x-abuse-guard}"
LOG_DIR="${LOG_DIR:-/var/log/3x-abuse-guard}"
PANEL_URL="${PANEL_URL:-http://127.0.0.1:2053/}"
AUTH_MODE="${AUTH_MODE:-auto}"
PANEL_INSECURE_SKIP_VERIFY="${PANEL_INSECURE_SKIP_VERIFY:-false}"
TOKEN="${THREEX_ABUSE_GUARD_TOKEN:-}"
USERNAME="${THREEX_ABUSE_GUARD_USERNAME:-}"
PASSWORD="${THREEX_ABUSE_GUARD_PASSWORD:-}"
TWO_FACTOR_CODE="${THREEX_ABUSE_GUARD_2FA_CODE:-}"
XRAY_ACCESS_LOG="${XRAY_ACCESS_LOG:-/var/log/x-ui/access.log}"
FIREWALL_BACKEND="${FIREWALL_BACKEND:-iptables}"
POLICY_MODE="${POLICY_MODE:-balanced}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
TELEGRAM_BOT_TOKEN="${THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID:-}"
ASSET_URL="${ASSET_URL:-}"
GO_VERSION="${GO_VERSION:-1.22.12}"
START_SERVICE=1
FORCE_BUILD=0

usage() {
  cat <<'EOF'
3x-abuse-guard 一键安装脚本

用法：
  curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- [参数]

常用参数：
  --panel-url URL            3x-ui 面板地址，默认 http://127.0.0.1:2053/
  --auth-mode auto|token|login
                             面板鉴权方式，默认 auto；优先 token，缺少 token 时用账号密码
  --panel-insecure-skip-verify
                             跳过 3x-ui 面板 HTTPS 证书校验，适合本机自签证书或证书域名不匹配
  --token TOKEN              3x-ui admin API Token；也可用环境变量 THREEX_ABUSE_GUARD_TOKEN
  --username USERNAME        3x-ui 面板用户名；也可用环境变量 THREEX_ABUSE_GUARD_USERNAME
  --password PASSWORD        3x-ui 面板密码；也可用环境变量 THREEX_ABUSE_GUARD_PASSWORD
  --two-factor-code CODE     3x-ui 两步验证码；也可用环境变量 THREEX_ABUSE_GUARD_2FA_CODE
  --access-log PATH          Xray access log 路径，默认 /var/log/x-ui/access.log
  --backend iptables|nft|noop
                             防火墙后端，默认 iptables；noop 只记录不写防火墙
  --mode balanced|strict|observe
                             策略模式，默认 balanced
  --webhook-url URL          通知 webhook，默认空
  --telegram-bot-token TOKEN Telegram Bot Token；也可用环境变量 THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN
  --telegram-chat-id CHAT_ID Telegram Chat ID；也可用环境变量 THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID
  --version VERSION          安装版本，默认 latest
  --install-dir PATH         二进制安装目录，默认 /usr/local/bin
  --asset-url URL            指定 release 二进制压缩包 URL
  --force-build              强制从源码构建
  --no-start                 只安装和写配置，不启动 systemd 服务
  -h, --help                 显示帮助

示例：
  curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
    --token "你的3x-ui-token" \
    --panel-url "http://127.0.0.1:2053/" \
    --backend iptables

  curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
    --auth-mode login \
    --username "你的面板用户名" \
    --password "你的面板密码"
EOF
}

log() {
  printf '\033[0;32m[信息]\033[0m %s\n' "$*"
}

warn() {
  printf '\033[0;33m[警告]\033[0m %s\n' "$*"
}

err() {
  printf '\033[0;31m[错误]\033[0m %s\n' "$*" >&2
}

die() {
  err "$*"
  exit 1
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "请使用 root 运行，例如：curl -fsSL ... | sudo bash -s --"
  fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --token)
        TOKEN="${2:-}"
        shift 2
        ;;
      --panel-url)
        PANEL_URL="${2:-}"
        shift 2
        ;;
      --auth-mode)
        AUTH_MODE="${2:-}"
        shift 2
        ;;
      --panel-insecure-skip-verify)
        PANEL_INSECURE_SKIP_VERIFY=true
        shift
        ;;
      --access-log)
        XRAY_ACCESS_LOG="${2:-}"
        shift 2
        ;;
      --username)
        USERNAME="${2:-}"
        shift 2
        ;;
      --password)
        PASSWORD="${2:-}"
        shift 2
        ;;
      --two-factor-code)
        TWO_FACTOR_CODE="${2:-}"
        shift 2
        ;;
      --backend)
        FIREWALL_BACKEND="${2:-}"
        shift 2
        ;;
      --mode)
        POLICY_MODE="${2:-}"
        shift 2
        ;;
      --webhook-url)
        WEBHOOK_URL="${2:-}"
        shift 2
        ;;
      --telegram-bot-token)
        TELEGRAM_BOT_TOKEN="${2:-}"
        shift 2
        ;;
      --telegram-chat-id)
        TELEGRAM_CHAT_ID="${2:-}"
        shift 2
        ;;
      --version)
        VERSION="${2:-}"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR="${2:-}"
        shift 2
        ;;
      --asset-url)
        ASSET_URL="${2:-}"
        shift 2
        ;;
      --force-build)
        FORCE_BUILD=1
        shift
        ;;
      --no-start)
        START_SERVICE=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "未知参数：$1"
        ;;
    esac
  done
}

validate_args() {
  case "$AUTH_MODE" in
    auto|token|login) ;;
    *) die "--auth-mode 只能是 auto、token 或 login" ;;
  esac
  case "$PANEL_INSECURE_SKIP_VERIFY" in
    true|false) ;;
    *) die "PANEL_INSECURE_SKIP_VERIFY 只能是 true 或 false" ;;
  esac
  case "$FIREWALL_BACKEND" in
    iptables|nft|noop) ;;
    *) die "--backend 只能是 iptables、nft 或 noop" ;;
  esac
  case "$POLICY_MODE" in
    balanced|strict|observe) ;;
    *) die "--mode 只能是 balanced、strict 或 observe" ;;
  esac
  [ -n "$PANEL_URL" ] || die "--panel-url 不能为空"
  [ -n "$INSTALL_DIR" ] || die "--install-dir 不能为空"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    armv6l|armv6) echo "armv6" ;;
    i386|i686|386) echo "386" ;;
    *) die "暂不支持的架构：$(uname -m)" ;;
  esac
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_packages() {
  local packages="$*"
  if has_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y $packages
  elif has_cmd dnf; then
    dnf install -y $packages
  elif has_cmd yum; then
    yum install -y $packages
  elif has_cmd apk; then
    apk add --no-cache $packages
  else
    warn "未识别包管理器，请手动确认已安装：$packages"
  fi
}

ensure_base_deps() {
  local missing=""
  for cmd in curl tar gzip; do
    if ! has_cmd "$cmd"; then
      missing="$missing $cmd"
    fi
  done
  if [ -n "$missing" ]; then
    log "安装基础依赖：$missing"
    install_packages ca-certificates curl tar gzip
  fi
}

go_ok() {
  if ! has_cmd go; then
    return 1
  fi
  local version major minor
  version="$(go version | awk '{print $3}' | sed 's/^go//')"
  major="${version%%.*}"
  minor="${version#*.}"
  minor="${minor%%.*}"
  [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 22 ]; }
}

ensure_go() {
  if go_ok; then
    log "检测到可用 Go：$(go version)"
    return
  fi

  local arch url tmp
  arch="$(detect_arch)"
  case "$arch" in
    amd64|arm64|386) ;;
    *) die "源码构建需要 Go，但当前架构 $arch 不支持自动安装 Go。请手动安装 Go 1.22+ 后重试。" ;;
  esac

  url="https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"
  tmp="$(mktemp -d)"
  log "安装 Go ${GO_VERSION} 到 /usr/local/go"
  curl -fL "$url" -o "$tmp/go.tar.gz"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmp/go.tar.gz"
  export PATH="/usr/local/go/bin:$PATH"
  go_ok || die "Go 安装后仍不可用"
}

download_release_binary() {
  local arch tmp url archive bin
  arch="$(detect_arch)"
  tmp="$(mktemp -d)"

  if [ -n "$ASSET_URL" ]; then
    url="$ASSET_URL"
  elif [ "$VERSION" = "latest" ]; then
    url="https://github.com/${REPO}/releases/latest/download/3x-abuse-guard-linux-${arch}.tar.gz"
  else
    url="https://github.com/${REPO}/releases/download/${VERSION}/3x-abuse-guard-linux-${arch}.tar.gz"
  fi

  archive="$tmp/3x-abuse-guard.tar.gz"
  log "尝试下载 release 二进制：$url"
  if ! curl -fL "$url" -o "$archive"; then
    warn "没有可用的 release 二进制，将回退到源码构建"
    return 1
  fi

  tar -xzf "$archive" -C "$tmp"
  bin="$(find "$tmp" -type f -name 3x-abuse-guard -perm -111 | head -n 1)"
  if [ -z "$bin" ]; then
    warn "release 包里没有找到可执行文件，将回退到源码构建"
    return 1
  fi

  install -m 0755 "$bin" "$INSTALL_DIR/3x-abuse-guard"
  log "已安装二进制：$INSTALL_DIR/3x-abuse-guard"
  return 0
}

build_from_source() {
  local tmp ref
  ensure_base_deps
  if ! has_cmd git; then
    log "安装 git"
    install_packages git
  fi
  ensure_go

  tmp="$(mktemp -d)"
  log "从源码构建 ${REPO}"
  git clone --depth 1 "https://github.com/${REPO}.git" "$tmp/repo"
  if [ "$VERSION" != "latest" ]; then
    ref="$VERSION"
    git -C "$tmp/repo" fetch --depth 1 origin "$ref" || true
    git -C "$tmp/repo" checkout "$ref"
  fi
  (cd "$tmp/repo" && go build -o "$tmp/3x-abuse-guard" ./cmd/3x-abuse-guard)
  install -m 0755 "$tmp/3x-abuse-guard" "$INSTALL_DIR/3x-abuse-guard"
  log "源码构建完成：$INSTALL_DIR/3x-abuse-guard"
}

install_binary() {
  mkdir -p "$INSTALL_DIR"
  if [ "$FORCE_BUILD" -eq 0 ] && download_release_binary; then
    return
  fi
  build_from_source
}

has_panel_auth() {
  case "$AUTH_MODE" in
    token)
      [ -n "$TOKEN" ]
      ;;
    login)
      [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]
      ;;
    auto)
      [ -n "$TOKEN" ] || { [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; }
      ;;
  esac
}

prompt_auth_if_needed() {
  if has_panel_auth; then
    return
  fi
  if [ -t 0 ]; then
    if [ "$AUTH_MODE" != "login" ]; then
      printf '请输入 3x-ui admin API Token（可留空，改用账号密码）：'
      read -r TOKEN
    fi
    if [ -z "$TOKEN" ] && [ "$AUTH_MODE" != "token" ]; then
      printf '请输入 3x-ui 面板用户名（可留空，稍后手动配置）：'
      read -r USERNAME
      if [ -n "$USERNAME" ]; then
        printf '请输入 3x-ui 面板密码：'
        read -r PASSWORD
        printf '请输入 3x-ui 两步验证码（未开启可留空）：'
        read -r TWO_FACTOR_CODE
      fi
    fi
  fi
}

quote_env_value() {
  printf "'"
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

write_env_line() {
  local name="$1"
  local value="$2"
  printf "%s=" "$name" >>"$CONFIG_DIR/env"
  quote_env_value "$value" >>"$CONFIG_DIR/env"
  printf "\n" >>"$CONFIG_DIR/env"
}

write_config() {
  mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
  cat >"$CONFIG_DIR/config.yaml" <<EOF
panel:
  base_url: "$PANEL_URL"
  auth_mode: "$AUTH_MODE"
  token_env: "THREEX_ABUSE_GUARD_TOKEN"
  username_env: "THREEX_ABUSE_GUARD_USERNAME"
  password_env: "THREEX_ABUSE_GUARD_PASSWORD"
  two_factor_code_env: "THREEX_ABUSE_GUARD_2FA_CODE"
  timeout_seconds: 10
  insecure_skip_verify: $PANEL_INSECURE_SKIP_VERIFY
  restart_xray: false

xray:
  access_log: "$XRAY_ACCESS_LOG"
  torrent_tag: "TORRENT"
  blocked_tag: "blocked"

detectors:
  torrent:
    enabled: true
    score: 100
    block_ip_on_hit: true
  blocked:
    enabled: true
    score: 10
  port_scan:
    enabled: true
    window_minutes: 5
    distinct_ports: 50
    score: 80
    cooldown_minutes: 5
  connection_rate:
    enabled: true
    window_minutes: 5
    max_connections: 1500
    score: 60
    cooldown_minutes: 5

firewall:
  backend: "$FIREWALL_BACKEND"
  chain: "THREEX_ABUSE_GUARD"
  block_minutes: 1440
  bypass_ips:
    - "127.0.0.1"
    - "::1"

policy:
  mode: "$POLICY_MODE"
  window_minutes: 60
  torrent_ip_block_on_first_hit: true
  torrent_disable_client_after: 2
  blocked_disable_client_after: 0
  blocked_notify_after: 5
  profiles:
    default:
      notify_score: 50
      block_ip_score: 80
      disable_client_score: 200
    strict:
      notify_score: 30
      block_ip_score: 60
      disable_client_score: 100
    observe:
      notify_score: 50
      block_ip_score: 0
      disable_client_score: 0
    blocked_watch:
      notify_score: 50
      block_ip_score: 0
      disable_client_score: 0
    heuristic:
      notify_score: 80
      block_ip_score: 0
      disable_client_score: 0
  assignments:
    emails: {}
    inbounds: {}
    traffic:
      blocked: blocked_watch
      port_scan: heuristic
      connection_rate: heuristic

notify:
  webhook_url: "$WEBHOOK_URL"
  telegram_bot_token_env: "THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN"
  telegram_chat_id_env: "THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID"

state:
  path: "$STATE_DIR/state.db"

logging:
  dir: "$LOG_DIR"
EOF

  : >"$CONFIG_DIR/env"
  write_env_line "THREEX_ABUSE_GUARD_TOKEN" "$TOKEN"
  write_env_line "THREEX_ABUSE_GUARD_USERNAME" "$USERNAME"
  write_env_line "THREEX_ABUSE_GUARD_PASSWORD" "$PASSWORD"
  write_env_line "THREEX_ABUSE_GUARD_2FA_CODE" "$TWO_FACTOR_CODE"
  write_env_line "THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN" "$TELEGRAM_BOT_TOKEN"
  write_env_line "THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID" "$TELEGRAM_CHAT_ID"

  chmod 600 "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/env"
  log "已写入配置：$CONFIG_DIR/config.yaml"
  log "已写入环境文件：$CONFIG_DIR/env"
}

install_cli_wrapper() {
  local wrapper="$INSTALL_DIR/3x-abuse-guardctl"
  cat >"$wrapper" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_DIR="\${THREEX_ABUSE_GUARD_CONFIG_DIR:-$CONFIG_DIR}"
ENV_FILE="\${THREEX_ABUSE_GUARD_ENV_FILE:-\$CONFIG_DIR/env}"

if [ -f "\$ENV_FILE" ]; then
  set -a
  . "\$ENV_FILE"
  set +a
fi

exec "$INSTALL_DIR/3x-abuse-guard" "\$@"
EOF
  chmod 0755 "$wrapper"
  log "已安装辅助命令：$wrapper"
}

install_service_files() {
  "$INSTALL_DIR/3x-abuse-guard" install --binary "$INSTALL_DIR/3x-abuse-guard"
  write_config
  install_cli_wrapper
  systemctl daemon-reload
}

start_service() {
  if [ "$START_SERVICE" -eq 0 ]; then
    warn "已按 --no-start 跳过启动服务"
    return
  fi
  if ! has_panel_auth; then
    warn "未配置 API Token 或面板账号密码，暂不启动服务。请编辑 $CONFIG_DIR/env 后执行：systemctl enable --now 3x-abuse-guard"
    return
  fi
  systemctl enable --now 3x-abuse-guard
  systemctl status 3x-abuse-guard --no-pager || true
}

print_next_steps() {
  cat <<EOF

安装完成。

下一步：
1. 确认 3x-ui 3.7.0 Token 使用 admin scope，并检查 Xray access log、TORRENT/blocked 出站、routing 规则和 sniffing。
   查看配置片段：
     3x-abuse-guard print-xray-policy

2. 运行检查：
     3x-abuse-guardctl doctor

3. 查看运行状态：
     systemctl status 3x-abuse-guard --no-pager
     journalctl -u 3x-abuse-guard -f --no-pager

EOF
}

main() {
  parse_args "$@"
  validate_args
  need_root
  ensure_base_deps
  prompt_auth_if_needed
  install_binary
  install_service_files
  start_service
  print_next_steps
}

main "$@"
