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
  --panel-url "http://127.0.0.1:2053/" \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

如果免费版没有 API Token 菜单，改用面板账号密码登录模式：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --auth-mode login \
  --username "你的3x-ui面板用户名" \
  --password "你的3x-ui面板密码" \
  --panel-url "http://127.0.0.1:2053/" \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

如果本机访问面板会跳转到 HTTPS，并且证书不是签给 `127.0.0.1`，会出现 `x509: cannot validate certificate for 127.0.0.1`。这种情况下优先把 `--panel-url` 改成证书对应的域名；如果只能本机访问，可以显式跳过面板 TLS 证书校验：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --auth-mode login \
  --username "你的3x-ui面板用户名" \
  --password "你的3x-ui面板密码" \
  --panel-url "https://127.0.0.1:2053/" \
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

### 安装脚本参数

| 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--panel-url` | `http://127.0.0.1:2053/` | 3x-ui 面板地址，必须是守护进程所在服务器能访问的地址。 |
| `--auth-mode` | `auto` | 面板鉴权方式。`auto` 优先用 Token，缺少 Token 时用账号密码；也可以指定 `token` 或 `login`。 |
| `--panel-insecure-skip-verify` | 关闭 | 跳过 3x-ui 面板 HTTPS 证书校验。仅建议用于本机自签证书或证书域名不匹配场景。 |
| `--token` | 空 | 写入 3x-ui API Token；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_TOKEN`。 |
| `--username` | 空 | 写入 3x-ui 面板用户名；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_USERNAME`。 |
| `--password` | 空 | 写入 3x-ui 面板密码；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_PASSWORD`。 |
| `--two-factor-code` | 空 | 写入 3x-ui 两步验证码；也可以提前设置环境变量 `THREEX_ABUSE_GUARD_2FA_CODE`。 |
| `--access-log` | `/var/log/x-ui/access.log` | Xray access log 路径，必须和 3x-ui/Xray 实际日志路径一致。 |
| `--backend` | `iptables` | 防火墙后端，可选 `iptables`、`nft`、`noop`；`noop` 只记录事件，不封 IP。 |
| `--mode` | `balanced` | 策略模式，可选 `balanced`、`strict`、`observe`。 |
| `--webhook-url` | 空 | 通知 Webhook 地址，留空则不发送通知。 |
| `--version` | `latest` | 指定安装的 GitHub Release 版本；没有 Release 时会回退源码构建。 |
| `--install-dir` | `/usr/local/bin` | 二进制安装目录。 |
| `--asset-url` | 空 | 指定二进制压缩包 URL，适合自建下载地址。 |
| `--force-build` | 关闭 | 强制从源码构建，不尝试下载 Release。 |
| `--no-start` | 关闭 | 只安装并写配置，不启动 systemd 服务。 |

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
- 支持 Webhook 通知。
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
    distinct_ports: 8
    score: 80
    cooldown_minutes: 5
  connection_rate:
    enabled: true
    window_minutes: 5
    max_connections: 300
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
  assignments:
    emails: {}
    inbounds: {}
    traffic: {}

notify:
  webhook_url: ""

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
| `detectors.port_scan` | 端口扫描检测器。同一源 IP 在窗口内访问多个不同目标端口后加分。 |
| `detectors.connection_rate` | 连接速率检测器。同一 email/IP 在窗口内连接数过高后加分。 |
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
| `policy.profiles` | 风险分处置阈值。达到 `notify_score` 通知，达到 `block_ip_score` 封 IP，达到 `disable_client_score` 禁用 client。省略时会从旧的 `torrent_disable_client_after`、`blocked_notify_after` 推导默认阈值。 |
| `policy.assignments.emails` | 按 3x-ui client email 指定 profile。 |
| `policy.assignments.inbounds` | 按 Xray inbound tag 指定 profile。 |
| `policy.assignments.traffic` | 按检测器类型指定 profile，例如 `torrent`、`blocked`、`port_scan`、`connection_rate`。 |
| `notify.webhook_url` | Webhook 通知地址，留空则关闭。 |
| `state.path` | 本地状态数据库路径，用于记录事件和封禁。 |
| `logging.dir` | 守护进程自身日志目录。systemd 日志仍可用 `journalctl` 查看。 |

## 默认策略

```yaml
policy:
  mode: "balanced"
  window_minutes: 60
  torrent_ip_block_on_first_hit: true
  torrent_disable_client_after: 2
  blocked_disable_client_after: 0
  blocked_notify_after: 5
```

含义：

- 第一次 BT 命中会封禁源 IP。
- 同一 email 在 60 分钟内第二次 BT 命中会禁用该 client。
- `blocked` 高风险访问默认只在 5 次后发送通知，不自动禁用。

## 命令

```text
3x-abuse-guard run
3x-abuse-guard install
3x-abuse-guardctl doctor
3x-abuse-guard print-xray-policy
3x-abuse-guardctl status
3x-abuse-guardctl unblock <ip>
3x-abuse-guardctl test-event --email alice --ip 198.51.100.10 --tag TORRENT
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
```

This means:

- first torrent hit blocks the source IP
- second torrent hit by the same email within 60 minutes disables that client
- blocked high-risk traffic only notifies after 5 hits

## Development

```bash
go mod tidy
go test ./...
go build ./cmd/3x-abuse-guard
```

GitHub Actions runs `go test ./...` in a clean environment. When dependencies change, run `go mod tidy` and commit both `go.mod` and `go.sum`; otherwise CI can fail on missing indirect module checksums.

## License

MIT.
