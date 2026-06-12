# 3x-abuse-guard

`3x-abuse-guard` 是一个面向 3x-ui + Xray 节点的小型防滥用守护进程。它会监听 Xray access log，在防火墙层封禁 BT/种子流量的源 IP，并且可以通过 3x-ui 官方 API 禁用重复违规的客户端。

V1 刻意保持克制：

- 不做 Web UI
- 不直接写入 `/etc/x-ui/x-ui.db`
- 不自动修改全局 Xray 配置
- 优先通过 3x-ui API 集成
- 面向 Linux systemd 部署

## 一键安装（推荐）

如果你的 3x-ui/Xpanel 有 API Token，推荐用 Token 安装：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --token "你的3x-ui API Token" \
  --panel-url "https://你的域名:端口/面板路径/" \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

如果免费版没有 API Token 菜单，改用面板账号密码登录模式：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --auth-mode login \
  --username "你的3x-ui面板用户名" \
  --password "你的3x-ui面板密码" \
  --panel-url "https://你的域名:端口/面板路径/" \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

如果本机访问面板会跳转到 HTTPS，并且证书不是签给 `127.0.0.1`，会出现 `x509: cannot validate certificate for 127.0.0.1`。这种情况下优先把 `--panel-url` 改成证书对应的域名；如果只能本机访问，可以显式跳过面板 TLS 证书校验：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --auth-mode login \
  --username "你的3x-ui面板用户名" \
  --password "你的3x-ui面板密码" \
  --panel-url "https://你的域名:端口/面板路径/" \
  --panel-insecure-skip-verify \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

这个脚本会自动完成：

- 安装基础依赖。
- 优先下载 GitHub Release 二进制；如果没有可用 Release，则自动从源码构建。
- 安装 `/usr/local/bin/3x-abuse-guard`。
- 写入 `/etc/3x-abuse-guard/config.yaml` 和 `/etc/3x-abuse-guard/env`。
- 安装 `/usr/local/bin/3x-abuse-guardctl`，用于自动加载 `/etc/3x-abuse-guard/env` 后执行 `doctor/status/unblock/test-event` 等命令。
- 创建 `/var/lib/3x-abuse-guard`、`/var/log/3x-abuse-guard`。
- 安装并启动 `3x-abuse-guard.service`。

如果暂时不配置面板鉴权，可以先只安装不启动：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- --no-start
```

之后编辑：

```bash
sudo nano /etc/3x-abuse-guard/env
sudo systemctl enable --now 3x-abuse-guard
```

手动运行检查、状态、测试事件时，推荐用 `3x-abuse-guardctl`。它会自动加载 `/etc/3x-abuse-guard/env`，避免直接运行 `sudo 3x-abuse-guard doctor` 时缺少面板账号密码环境变量。

For manual checks, status inspection, and test events, prefer `3x-abuse-guardctl`. It automatically loads `/etc/3x-abuse-guard/env`, so commands such as `doctor`, `status`, `unblock`, and `test-event` can use the panel credentials written by the installer.

## 3x-abuse-guardctl 使用说明 / 3x-abuse-guardctl Usage

`3x-abuse-guardctl` 是辅助命令，不是独立守护进程。它的作用是先读取 `/etc/3x-abuse-guard/env`，再调用 `/usr/local/bin/3x-abuse-guard` 执行真实子命令。

`3x-abuse-guardctl` is a helper wrapper, not a separate daemon. It loads `/etc/3x-abuse-guard/env` first, then delegates to `/usr/local/bin/3x-abuse-guard`.

| 命令 / Command | 作用 / Purpose |
| --- | --- |
| `sudo 3x-abuse-guardctl doctor` | 检查 access log、面板 API、Xray 出站、routing 和 sniffing 是否可用。 / Checks the access log, panel API, Xray outbounds, routing rules, and sniffing. |
| `sudo 3x-abuse-guardctl status` | 查看当前封禁 IP 和最近风险事件；只读，不改配置。 / Shows active bans and recent risk events; read-only. |
| `sudo 3x-abuse-guardctl unblock <ip>` | 手动解除指定 IP 的封禁，并删除本地 ban 记录。 / Manually unblocks an IP and removes the local ban record. |
| `sudo 3x-abuse-guardctl test-event --email <email> --ip <ip> --tag <tag>` | 模拟一次日志命中，用于验证策略、封禁和通知链路。 / Simulates a log hit to verify policy, firewall, and notification behavior. |

`test-event` 常用参数 / Common `test-event` options:

| 参数 / Option | 示例 / Example | 说明 / Description |
| --- | --- | --- |
| `--email` | `alice@example.com` | 3x-ui client email；用于测试是否会累计到用户维度。 / 3x-ui client email; used to test per-client counting. |
| `--ip` | `198.51.100.10` | 模拟违规来源 IP；建议使用文档保留地址，不要用自己的管理 IP。 / Simulated offender IP; use documentation-reserved addresses, not your admin IP. |
| `--tag` | `TORRENT` 或 `blocked` | 模拟 Xray outbound tag。`TORRENT` 触发 BT 处置；`blocked` 触发高危访问计数。 / Simulated Xray outbound tag. `TORRENT` triggers torrent handling; `blocked` counts high-risk access. |

常用示例 / Examples:

```bash
# 中文：检查整套配置是否可用。
# English: Check whether the full setup is ready.
sudo 3x-abuse-guardctl doctor

# 中文：查看当前封禁和近期事件。
# English: Show active bans and recent events.
sudo 3x-abuse-guardctl status

# 中文：模拟一次 BT 命中，验证封禁、状态和通知。
# English: Simulate a torrent hit to verify blocking, state, and notifications.
sudo 3x-abuse-guardctl test-event --email alice@example.com --ip 198.51.100.10 --tag TORRENT

# 中文：解除测试 IP 的封禁。
# English: Unblock the test IP.
sudo 3x-abuse-guardctl unblock 198.51.100.10
```

### 安装脚本参数 / Installer Options

示例中的 `https://你的域名:端口/面板路径/` 是占位地址，请替换成你的 3x-ui/Xpanel 面板真实访问地址。

`https://your-domain:port/panel-path/` is a placeholder. Replace it with the real URL of your 3x-ui/Xpanel panel.

| 参数 / Option | 默认值 / Default | 作用 / Description |
| --- | --- | --- |
| `--panel-url` | `http://127.0.0.1:2053/` | 3x-ui 面板地址，必须是守护进程所在服务器能访问的地址。 / 3x-ui panel URL reachable from the server running the daemon. |
| `--auth-mode` | `auto` | 面板鉴权方式。`auto` 优先用 Token，缺少 Token 时用账号密码；也可以指定 `token` 或 `login`。 / Panel authentication mode. `auto` prefers token auth and falls back to login credentials; `token` and `login` are explicit modes. |
| `--panel-insecure-skip-verify` | 关闭 / Off | 跳过 3x-ui 面板 HTTPS 证书校验。仅建议用于本机自签证书或证书域名不匹配场景。 / Skips HTTPS certificate verification for the panel. Only use for local self-signed certificates or certificate-name mismatch cases. |
| `--token` | 空 / Empty | 写入 3x-ui API Token；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_TOKEN`。 / Writes the 3x-ui API token; you can also pre-set `THREEX_ABUSE_GUARD_TOKEN`. |
| `--username` | 空 / Empty | 写入 3x-ui 面板用户名；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_USERNAME`。 / Writes the 3x-ui panel username; you can also pre-set `THREEX_ABUSE_GUARD_USERNAME`. |
| `--password` | 空 / Empty | 写入 3x-ui 面板密码；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_PASSWORD`。 / Writes the 3x-ui panel password; you can also pre-set `THREEX_ABUSE_GUARD_PASSWORD`. |
| `--two-factor-code` | 空 / Empty | 写入 3x-ui 两步验证码；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_2FA_CODE`。 / Writes the 3x-ui two-factor code; you can also pre-set `THREEX_ABUSE_GUARD_2FA_CODE`. |
| `--access-log` | `/var/log/x-ui/access.log` | Xray access log 路径，必须和 3x-ui/Xray 实际日志路径一致。 / Xray access log path; it must match the path configured in 3x-ui/Xray. |
| `--backend` | `iptables` | 防火墙后端，可选 `iptables`、`nft`、`noop`；`noop` 只记录事件，不封 IP。 / Firewall backend. Valid values are `iptables`, `nft`, and `noop`; `noop` records events without blocking IPs. |
| `--mode` | `balanced` | 策略模式，可选 `balanced`、`strict`、`observe`。 / Policy mode. Valid values are `balanced`, `strict`, and `observe`. |
| `--webhook-url` | 空 / Empty | 通知 Webhook 地址，留空则不发送 Webhook。 / Notification webhook URL; leave empty to disable webhook delivery. |
| `--telegram-bot-token` | 空 / Empty | Telegram Bot Token；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN`。 / Telegram Bot Token; you can also pre-set `THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN`. |
| `--telegram-chat-id` | 空 / Empty | Telegram Chat ID；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID`。 / Telegram Chat ID; you can also pre-set `THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID`. |
| `--version` | `latest` | 指定安装的 GitHub Release 版本；没有 Release 时会回退源码构建。 / GitHub Release version to install; falls back to source build when no release asset is available. |
| `--install-dir` | `/usr/local/bin` | 二进制安装目录。 / Binary installation directory. |
| `--asset-url` | 空 / Empty | 指定二进制压缩包 URL，适合自建下载地址。 / Custom binary archive URL, useful for self-hosted downloads. |
| `--force-build` | 关闭 / Off | 强制从源码构建，不尝试下载 Release。 / Forces a source build and skips release downloads. |
| `--no-start` | 关闭 / Off | 只安装并写配置，不启动 systemd 服务。 / Installs files and writes config without starting the systemd service. |

## 已完成能力

- 监听 Xray access log，解析来源 IP、目标地址、出站标签和 3x-ui client email。
- 兼容 Xray access log 中 `[inbound >> outbound]` 和 `[inbound -> outbound]` 两种出站格式。
- 将 `TORRENT` 出站标签视为 BT/种子滥用。
- 将 `blocked` 出站标签视为高风险访问，但不当作 BT 处理。
- 第一次 BT 命中默认封禁源 IP 24 小时，并尝试通过 `conntrack` 断开现有连接。
- 同一 email 在 60 分钟内第 2 次命中 BT 后，默认通过 3x-ui API 禁用该 client。
- 无 email 的日志只封 IP，不禁用 client。
- 支持 IP 白名单，避免误封本机、内网或中转 IP。
- 支持 `iptables`、`nftables` 和 `noop` 防火墙后端。
- 使用 bbolt 在 `/var/lib/3x-abuse-guard/state.db` 保存本地状态，服务重启后会恢复未过期封禁。
- CLI 读写状态时短暂打开数据库，避免 daemon 运行期间 `status/unblock/test-event` 因 bbolt 文件锁超时。
- 支持 Webhook 和 Telegram Bot 通知。
- 提供 `doctor` 检查 3x-ui API、access log、Xray outbound、routing 和 sniffing。
- 提供 `print-xray-policy` 输出 3x-ui/Xray 需要加入的配置片段。
- 支持 Detector Pipeline：`torrent`、`blocked`、`port_scan`、`connection_rate`。
- 支持 Policy Profiles：可按 email、inbound、流量类型分配不同通知、封 IP、禁用 client 阈值。

它解析如下格式的 Xray access log：

```text
2026/06/10 09:00:58 from 198.51.100.10:6148 accepted tcp:example.com:443 [inbound-1 >> TORRENT] email: alice
2026/06/10 09:00:59 from 198.51.100.10:6149 accepted tcp:1.1.1.1:25 [inbound-1 -> blocked] email: alice
```

## 配置 3x-ui/Xray

先输出需要添加到 Xray 的配置片段：

```bash
3x-abuse-guard print-xray-policy
```

然后在 3x-ui 的 Xray 配置界面中确认这些内容：

- `outbounds` 中存在 `TORRENT` blackhole 出站。
- `outbounds` 中存在 `blocked` blackhole 出站。
- `routing.rules` 中 BT 协议规则放在普通直连/代理规则前面。
- `routing.rules` 中高危端口、私网地址规则放在普通直连/代理规则前面。
- 每个对用户开放的 inbound 开启 sniffing，建议 `HTTP`、`TLS`、`QUIC` 开启，`Route Only` 开启。
- Xray access log 已开启，并写入 `/var/log/x-ui/access.log` 或你在脚本中指定的路径。

详细说明见 [docs/3x-ui-xray.md](docs/3x-ui-xray.md)。

运行就绪检查：

```bash
sudo 3x-abuse-guardctl doctor
```

## 配置文件

默认配置文件：`/etc/3x-abuse-guard/config.yaml`

```yaml
panel:
  base_url: "http://127.0.0.1:2053/"
  auth_mode: "auto"
  token_env: "THREEX_ABUSE_GUARD_TOKEN"
  username_env: "THREEX_ABUSE_GUARD_USERNAME"
  password_env: "THREEX_ABUSE_GUARD_PASSWORD"
  two_factor_code_env: "THREEX_ABUSE_GUARD_2FA_CODE"
  timeout_seconds: 10
  insecure_skip_verify: false
  restart_xray: false

xray:
  access_log: "/var/log/x-ui/access.log"
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
  backend: "iptables"
  chain: "THREEX_ABUSE_GUARD"
  block_minutes: 1440
  bypass_ips:
    - "127.0.0.1"
    - "::1"

policy:
  mode: "balanced"
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
    heuristic:
      notify_score: 80
      block_ip_score: 320
      disable_client_score: 0
  assignments:
    emails: {}
    inbounds: {}
    traffic:
      port_scan: heuristic
      connection_rate: heuristic

notify:
  webhook_url: ""
  telegram_bot_token_env: "THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN"
  telegram_chat_id_env: "THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID"

state:
  path: "/var/lib/3x-abuse-guard/state.db"

logging:
  dir: "/var/log/3x-abuse-guard"
```

### 配置参数说明

| 参数 | 作用 |
| --- | --- |
| `panel.base_url` | 3x-ui 面板 API 地址。通常填本机地址，例如 `http://127.0.0.1:2053/`。 |
| `panel.auth_mode` | 面板鉴权方式：`auto`、`token` 或 `login`。`auto` 优先使用 Token，缺少 Token 时使用账号密码登录。 |
| `panel.token_env` | 从哪个环境变量读取 3x-ui API Token。默认是 `THREEX_ABUSE_GUARD_TOKEN`。 |
| `panel.username_env` | 从哪个环境变量读取 3x-ui 面板用户名。默认是 `THREEX_ABUSE_GUARD_USERNAME`。 |
| `panel.password_env` | 从哪个环境变量读取 3x-ui 面板密码。默认是 `THREEX_ABUSE_GUARD_PASSWORD`。 |
| `panel.two_factor_code_env` | 从哪个环境变量读取 3x-ui 两步验证码。未开启 2FA 时可留空。 |
| `panel.timeout_seconds` | 调用 3x-ui API 的超时时间。 |
| `panel.insecure_skip_verify` | 是否跳过面板 HTTPS 证书校验。默认 `false`；只有在本机访问 HTTPS 面板但证书域名不匹配时才建议设为 `true`。 |
| `panel.restart_xray` | 保留参数，默认不自动重启 Xray，避免误操作。 |
| `xray.access_log` | Xray access log 路径。守护进程通过它识别 `TORRENT` 和 `blocked` 命中。 |
| `xray.torrent_tag` | BT/种子流量命中的出站标签，必须和 Xray routing 的 `outboundTag` 一致。 |
| `xray.blocked_tag` | 高危访问命中的出站标签，必须和 Xray routing 的 `outboundTag` 一致。 |
| `detectors.torrent` | BT 检测器。命中 `TORRENT` 出站后加分，可配置是否首次命中直接封 IP。 |
| `detectors.blocked` | 高危访问检测器。命中 `blocked` 出站后加分，默认只累计风险和通知。 |
| `detectors.port_scan` | 端口扫描检测器。同一源 IP 在窗口内访问多个不同目标端口后加分。默认阈值偏宽松，适配手机全局代理。 |
| `detectors.connection_rate` | 连接速率检测器。同一 email/IP 在窗口内连接数过高后加分。默认阈值偏宽松，适配手机全局代理。 |
| `firewall.backend` | 防火墙后端：`iptables`、`nft` 或 `noop`。 |
| `firewall.chain` | 本项目维护的防火墙链名。默认 `THREEX_ABUSE_GUARD`。 |
| `firewall.block_minutes` | IP 封禁时长，默认 `1440` 分钟，也就是 24 小时。 |
| `firewall.bypass_ips` | 白名单 IP 或 CIDR，命中后不会被封禁。建议加入本机、内网、中转出口。 |
| `policy.mode` | 策略模式：`balanced` 使用下方阈值；`strict` 会把 BT 禁用阈值压到 1；`observe` 不封 IP、不禁用 client，只记录/通知。 |
| `policy.window_minutes` | 统计窗口。同一 email 在这个时间窗口内累计违规。 |
| `policy.torrent_ip_block_on_first_hit` | BT 第一次命中是否立即封源 IP。 |
| `policy.torrent_disable_client_after` | 同一 email 在统计窗口内 BT 命中多少次后禁用 client；`0` 表示不禁用。 |
| `policy.blocked_disable_client_after` | 同一 email 在统计窗口内高危访问命中多少次后禁用 client；默认 `0`，表示不禁用。 |
| `policy.blocked_notify_after` | 同一 email 在统计窗口内高危访问命中多少次后通知；`0` 表示不通知。 |
| `policy.profiles` | 风险分处置阈值。达到 `notify_score` 通知，达到 `block_ip_score` 封 IP，达到 `disable_client_score` 禁用 client。默认内置 `default`、`strict`、`observe` 和 `heuristic`。 |
| `policy.assignments.emails` | 按 3x-ui client email 指定 profile。 |
| `policy.assignments.inbounds` | 按 Xray inbound tag 指定 profile。 |
| `policy.assignments.traffic` | 按检测器类型指定 profile，例如 `torrent`、`blocked`、`port_scan`、`connection_rate`。默认 `port_scan` 和 `connection_rate` 使用 `heuristic`，首次触发通知，持续异常累计到 320 分后封 IP。 |
| `notify.webhook_url` | Webhook 通知地址，留空则关闭。 |
| `notify.telegram_bot_token_env` | 从哪个环境变量读取 Telegram Bot Token。默认是 `THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN`。 |
| `notify.telegram_chat_id_env` | 从哪个环境变量读取 Telegram Chat ID。默认是 `THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID`。 |
| `state.path` | 本地状态数据库路径，用于记录事件和封禁。 |
| `logging.dir` | 守护进程自身日志目录。systemd 日志仍可用 `journalctl` 查看。 |

## 通知和 Telegram

当前版本支持通用 Webhook 和 Telegram Bot 通知。两者可以同时配置，同时配置时会同时发送。

```yaml
notify:
  webhook_url: "https://example.com/your-webhook"
  telegram_bot_token_env: "THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN"
  telegram_chat_id_env: "THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID"
```

守护进程会向该 URL `POST` JSON 事件，包含 `action`、`kind`、`email`、`ip`、`reason`、`timestamp` 等字段。

Telegram 的 token 和 chat id 写在 `/etc/3x-abuse-guard/env`，不要写进 `config.yaml`：

```text
THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN=123456:ABC...
THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID=123456789
```

也可以安装时直接传参：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --auth-mode login \
  --username "你的3x-ui面板用户名" \
  --password "你的3x-ui面板密码" \
  --panel-url "https://你的域名:端口/面板路径/" \
  --telegram-bot-token "你的Telegram Bot Token" \
  --telegram-chat-id "你的Telegram Chat ID" \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

配置完成后可以用模拟事件验证 Telegram 通知：

```bash
sudo systemctl restart 3x-abuse-guard
sudo 3x-abuse-guardctl test-event --email test --ip 198.51.100.10 --tag TORRENT
```

## 默认策略

```yaml
policy:
  mode: "balanced"
  window_minutes: 60
  torrent_ip_block_on_first_hit: true
  torrent_disable_client_after: 2
  blocked_disable_client_after: 0
  blocked_notify_after: 5
  assignments:
    traffic:
      port_scan: heuristic
      connection_rate: heuristic
```

含义：

- 第一次 BT 命中会封禁源 IP。
- 同一 email 在 60 分钟内第二次 BT 命中会禁用该 client。
- `blocked` 高风险访问默认只在 5 次后发送通知，持续累计到默认封禁阈值后封 IP，不自动禁用。
- `port_scan` 和 `connection_rate` 默认使用 `heuristic` profile，首次触发先通知；持续异常累计到 320 分后封 IP，不禁用 client，避免手机全局代理偶发流量误封。
- 按默认分数计算，`port_scan` 大约 60 分钟内连续 4 次触发才封 IP；`connection_rate` 大约 60 分钟内连续 6 次触发才封 IP。

## 常用运维命令

```bash
# 前台运行守护进程，主要用于调试；生产环境建议使用 systemd。
3x-abuse-guard run

# 安装默认配置、环境文件、状态目录、日志目录和 systemd service。
3x-abuse-guard install

# 输出 3x-ui/Xray 需要添加的 TORRENT/blocked outbounds、routing 和 sniffing 片段。
3x-abuse-guard print-xray-policy

# 自动加载 /etc/3x-abuse-guard/env 后检查 access log、面板 API、Xray 配置和 sniffing。
sudo 3x-abuse-guardctl doctor

# 查看当前封禁 IP 和最近风险事件；只读，不会修改防火墙或配置。
sudo 3x-abuse-guardctl status

# 手动解除一个 IP 的封禁，同时删除本地状态库里的 ban 记录。
sudo 3x-abuse-guardctl unblock 198.51.100.10

# 本地模拟一次事件，用于验证策略、封禁和状态记录是否正常。
sudo 3x-abuse-guardctl test-event --email alice --ip 198.51.100.10 --tag TORRENT

# 查看 systemd 服务是否正在运行。
sudo systemctl status 3x-abuse-guard --no-pager

# 查看最近 50 行服务日志，排查启动、面板 API、封禁和解封问题。
sudo journalctl -u 3x-abuse-guard -n 50 --no-pager

# 实时跟随服务日志。
sudo journalctl -u 3x-abuse-guard -f --no-pager

# 查看 Xray access log，确认是否有真实用户流量和 email 字段。
tail -n 30 /var/log/x-ui/access.log

# 查看 iptables raw 表中本项目创建的链和跳转规则。
sudo iptables -t raw -S | grep THREEX_ABUSE_GUARD

# 查看本项目 iptables 链的详细包计数和已封禁 IP。
sudo iptables -t raw -L THREEX_ABUSE_GUARD -n -v
```

## 完全卸载

下面命令会停止服务、删除二进制、配置、状态数据库、日志目录，并清理本项目可能留下的 `iptables`、`ip6tables`、`nftables` 防火墙规则。执行前请确认不再需要 `/etc/3x-abuse-guard` 和 `/var/lib/3x-abuse-guard` 中的数据。

```bash
# 停止并禁用 systemd 服务。
sudo systemctl stop 3x-abuse-guard 2>/dev/null || true
sudo systemctl disable 3x-abuse-guard 2>/dev/null || true

# 清理 iptables raw 表中的跳转规则、封禁规则和项目链。
sudo iptables -t raw -D PREROUTING -j THREEX_ABUSE_GUARD 2>/dev/null || true
sudo iptables -t raw -F THREEX_ABUSE_GUARD 2>/dev/null || true
sudo iptables -t raw -X THREEX_ABUSE_GUARD 2>/dev/null || true

# 清理 IPv6 的 ip6tables raw 表规则。
sudo ip6tables -t raw -D PREROUTING -j THREEX_ABUSE_GUARD 2>/dev/null || true
sudo ip6tables -t raw -F THREEX_ABUSE_GUARD 2>/dev/null || true
sudo ip6tables -t raw -X THREEX_ABUSE_GUARD 2>/dev/null || true

# 如果曾经使用 nft 后端，删除项目 nft table。
sudo nft delete table inet THREEX_ABUSE_GUARD 2>/dev/null || true

# 删除 systemd 服务文件。
sudo rm -f /etc/systemd/system/3x-abuse-guard.service

# 删除二进制和辅助命令。
sudo rm -f /usr/local/bin/3x-abuse-guard
sudo rm -f /usr/local/bin/3x-abuse-guardctl

# 删除配置、状态数据库和本项目日志。
sudo rm -rf /etc/3x-abuse-guard
sudo rm -rf /var/lib/3x-abuse-guard
sudo rm -rf /var/log/3x-abuse-guard

# 重载 systemd 配置。
sudo systemctl daemon-reload

# 确认卸载结果；输出 not found / No such file or directory 表示已删除。
command -v 3x-abuse-guard || true
command -v 3x-abuse-guardctl || true
ls /etc/3x-abuse-guard 2>/dev/null || true
ls /var/lib/3x-abuse-guard 2>/dev/null || true
sudo iptables -t raw -S | grep THREEX_ABUSE_GUARD || true
```

## 从源码安装

```bash
git clone https://github.com/zachary9757/3x-abuse-guard.git
cd 3x-abuse-guard
go build -o 3x-abuse-guard ./cmd/3x-abuse-guard
sudo install -m 0755 3x-abuse-guard /usr/local/bin/3x-abuse-guard
sudo 3x-abuse-guard install
```

写入 3x-ui 鉴权信息，Token 和账号密码二选一即可：

```bash
sudo nano /etc/3x-abuse-guard/env
```

```text
THREEX_ABUSE_GUARD_TOKEN=your-token-here
THREEX_ABUSE_GUARD_USERNAME=
THREEX_ABUSE_GUARD_PASSWORD=
THREEX_ABUSE_GUARD_2FA_CODE=
THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN=
THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID=
```

启动守护进程：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 3x-abuse-guard
sudo systemctl status 3x-abuse-guard --no-pager
```

## 开发

```bash
go mod tidy
go test ./...
go build ./cmd/3x-abuse-guard
```

CI 使用 GitHub Actions 在干净环境执行 `go test ./...`。如果新增或升级依赖，提交前必须运行 `go mod tidy` 并把 `go.mod`、`go.sum` 一起提交，否则 CI 可能因为缺少间接依赖校验记录失败。

在受限环境里测试时，可以把 Go 缓存放到临时目录：

```bash
GOCACHE=/tmp/3x-abuse-guard-go-cache GOPATH=/tmp/3x-abuse-guard-gopath go test ./...
```

## 许可证

MIT。

---

# English

`3x-abuse-guard` is a small abuse-control daemon for 3x-ui + Xray nodes. It watches the Xray access log, blocks torrent source IPs at the firewall layer, and can disable repeat-offending 3x-ui clients through the official 3x-ui API.

V1 is intentionally narrow:

- no Web UI
- no direct writes to `/etc/x-ui/x-ui.db`
- no automatic mutation of global Xray config
- API-first integration with 3x-ui
- systemd-oriented Linux deployment

## What It Does

- Parses Xray access lines like:

  ```text
  2026/06/10 09:00:58 from 198.51.100.10:6148 accepted tcp:example.com:443 [inbound-1 >> TORRENT] email: alice
  ```

- Treats `TORRENT` outbound hits as torrent abuse.
- Treats `blocked` outbound hits as high-risk traffic, but not torrent abuse.
- Blocks torrent source IPs for 24 hours by default.
- Disables a 3x-ui client after 2 torrent hits within 60 minutes by default.
- Supports either Bearer token auth or username/password login auth for 3x-ui API calls.
- Supports a detector pipeline for torrent, blocked, port-scan, and connection-rate findings.
- Supports policy profiles assigned by email, inbound tag, or traffic type.
- Keeps local state in bbolt at `/var/lib/3x-abuse-guard/state.db`.

## Install From Source

```bash
git clone https://github.com/zachary9757/3x-abuse-guard.git
cd 3x-abuse-guard
go build -o 3x-abuse-guard ./cmd/3x-abuse-guard
sudo install -m 0755 3x-abuse-guard /usr/local/bin/3x-abuse-guard
sudo 3x-abuse-guard install
```

Set either a 3x-ui API token or panel login credentials:

```bash
sudo nano /etc/3x-abuse-guard/env
```

```text
THREEX_ABUSE_GUARD_TOKEN=your-token-here
THREEX_ABUSE_GUARD_USERNAME=
THREEX_ABUSE_GUARD_PASSWORD=
THREEX_ABUSE_GUARD_2FA_CODE=
THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN=
THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID=
```

Start the daemon:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 3x-abuse-guard
sudo systemctl status 3x-abuse-guard --no-pager
```

## Configure 3x-ui/Xray

Print the required Xray snippets:

```bash
3x-abuse-guard print-xray-policy
```

Then apply the snippets in the 3x-ui Xray configuration UI. See [docs/3x-ui-xray.md](docs/3x-ui-xray.md).

Run a readiness check:

```bash
sudo 3x-abuse-guardctl doctor
```

## Commands

```text
3x-abuse-guard run
3x-abuse-guard install
3x-abuse-guardctl doctor
3x-abuse-guard print-xray-policy
3x-abuse-guardctl status
3x-abuse-guardctl unblock <ip>
3x-abuse-guardctl test-event --email alice --ip 198.51.100.10 --tag TORRENT
```

## Default Policy

```yaml
policy:
  mode: "balanced"
  window_minutes: 60
  torrent_ip_block_on_first_hit: true
  torrent_disable_client_after: 2
  blocked_disable_client_after: 0
  blocked_notify_after: 5
  assignments:
    traffic:
      port_scan: heuristic
      connection_rate: heuristic
```

This means:

- first torrent hit blocks the source IP
- second torrent hit by the same email within 60 minutes disables that client
- blocked high-risk traffic notifies after 5 hits and can block after the default score threshold
- port_scan and connection_rate use the heuristic profile by default: they notify first, then block the source IP only after sustained heuristic risk reaches 320 points, and they do not disable clients
- with default scores, port_scan blocks after about 4 findings within 60 minutes, while connection_rate blocks after about 6 findings within 60 minutes

## Development

```bash
go mod tidy
go test ./...
go build ./cmd/3x-abuse-guard
```

GitHub Actions runs `go test ./...` in a clean environment. When dependencies change, run `go mod tidy` and commit both `go.mod` and `go.sum`; otherwise CI can fail on missing indirect module checksums.

## License

MIT.
