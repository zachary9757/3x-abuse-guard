# 3x-abuse-guard

`3x-abuse-guard` 是一个用于 3x-ui + Xray 节点的防滥用守护进程。它持续读取 Xray access log，识别 BT、高风险目标、端口扫描和异常连接速率，并按策略执行通知、封禁来源 IP 或禁用 3x-ui 客户端。

核心流程：

```text
Xray access log
  -> 识别 TORRENT / blocked / 端口扫描 / 连接速率
  -> 按 email、inbound 或流量类型选择策略
  -> 通知、封 IP、禁用客户端
```

## 适用版本与边界

当前代码已按 [3x-ui `v3.8.5`](https://github.com/MHSanaei/3x-ui/releases/tag/v3.8.5) 及其内置 Xray-core `v26.9.9` 的源码和接口核对，并通过本项目单元测试；实际部署仍需执行下方健康检查：

- 支持 Bearer Token 和面板账号密码登录。
- 3x-ui 3.7.0 起的 Token 必须使用 `admin` scope；`monitor` 和 `node-sync` 权限不足。
- 禁用客户端优先使用 `/panel/api/clients/bulkDisable`，旧版接口不可用时自动回退。
- 支持 Xray access log 中的 `>>`、`->` 和 `==>` 路由分隔符。
- Native AmneziaWG 经本机 SOCKS5 relay 进入 Xray：带 email 的事件仍可计分和禁用客户端，但不会封禁回环来源 IP。
- `doctor` 会检查 Xray 运行状态和面板报告的配置错误，将带客户端认证的回环 relay 纳入 sniffing 检查，并识别 AmneziaWG 每客户端 IPv6 出口对后续防滥用规则的遮挡。

本项目不会直接修改 `/etc/x-ui/x-ui.db`，也不会自动改写全局 Xray 配置。升级 3x-ui 或 Xray 后，应重新执行 `doctor` 并检查路由。更多兼容性说明见 [docs/3x-ui-xray.md](docs/3x-ui-xray.md)。

## 功能概览

- 将 `TORRENT` 出站视为 BT/种子滥用。
- 将 `blocked` 出站视为高风险访问，但不等同于 BT。
- 默认第一次 BT 命中封禁来源 IP 24 小时。
- 默认同一 email 在 60 分钟内第二次 BT 命中后禁用该客户端。
- 支持 `iptables`、`nftables` 和只记录不封禁的 `noop` 后端。
- 支持 `torrent`、`blocked`、`port_scan`、`connection_rate` 检测器。
- 支持按 email、inbound、流量类型分配策略。
- 使用 bbolt 保存事件和封禁状态，服务重启后恢复未过期封禁。
- 支持 Webhook、Telegram 风险通知和每日访问统计。
- 提供 `doctor`、`status`、`unblock`、`test-event` 等运维命令。

## 一键安装

### 使用 API Token

3x-ui 3.8.5 请创建 `admin` scope Token。Token 明文只在创建时显示一次；再次运行 `x-ui setting -getApiToken` 会轮换 `cli-fallback` Token，并立即使旧值失效。

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --token "你的3x-ui API Token" \
  --panel-url "https://你的域名:端口/面板路径/" \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

### 使用面板账号密码

没有 API Token 时可以使用登录模式：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- \
  --auth-mode login \
  --username "你的3x-ui面板用户名" \
  --password "你的3x-ui面板密码" \
  --panel-url "https://你的域名:端口/面板路径/" \
  --access-log "/var/log/x-ui/access.log" \
  --backend iptables
```

如果面板使用自签证书或证书域名与访问地址不一致，优先改用证书对应的域名。只有无法解决时才添加：

```text
--panel-insecure-skip-verify
```

### 只安装、不启动

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | sudo bash -s -- --no-start
```

安装脚本会创建：

| 路径 | 作用 |
| --- | --- |
| `/usr/local/bin/3x-abuse-guard` | 主程序 |
| `/usr/local/bin/3x-abuse-guardctl` | 自动加载环境变量的辅助命令 |
| `/etc/3x-abuse-guard/config.yaml` | 守护进程配置 |
| `/etc/3x-abuse-guard/env` | Token、密码和通知密钥 |
| `/var/lib/3x-abuse-guard/state.db` | 事件和封禁状态 |
| `/etc/systemd/system/3x-abuse-guard.service` | systemd 服务 |

重复运行安装脚本时会保留已有的 `config.yaml` 和 `env`，并在替换二进制后显式重启已运行服务。只有确认要用新的命令行参数替换现有策略和凭据时，才使用 `--replace-config`；替换或启动失败时脚本会恢复安装前文件。

Release 二进制必须通过发布页的 `checksums.txt` 校验；缺少校验文件时脚本会回退到源码构建。使用自定义 `--asset-url` 时必须同时提供 `--asset-sha256`。

查看全部安装参数：

```bash
curl -fsSL https://raw.githubusercontent.com/zachary9757/3x-abuse-guard/main/scripts/install.sh | bash -s -- --help
```

## 配置 3x-ui/Xray

这是项目正常工作的必要步骤。修改前请备份现有 Xray 配置，并保留 3x-ui 已有的内部 API、`direct` 出站和其他业务出站。

### 1. 启用 access log

```json
"log": {
  "access": "/var/log/x-ui/access.log",
  "dnsLog": false,
  "error": "/var/log/x-ui/error.log",
  "loglevel": "warning",
  "maskAddress": ""
}
```

`maskAddress` 必须为空，否则守护进程无法取得真实来源 IP。容器部署时，`xray.access_log` 应填写宿主机实际可见的挂载路径。

### 2. 配置黑洞出站

在现有 `outbounds` 中保留或加入以下三项。不要删除已有的 `direct` 出站：

```json
{
  "tag": "TORRENT",
  "protocol": "blackhole",
  "settings": {}
},
{
  "tag": "blocked",
  "protocol": "blackhole",
  "settings": {}
},
{
  "tag": "CN_BLOCKED",
  "protocol": "blackhole",
  "settings": {}
}
```

三个标签的用途不同：

| 标签 | 用途 |
| --- | --- |
| `TORRENT` | BT 命中；进入项目的 BT 封禁和客户端禁用策略 |
| `blocked` | 私网、高风险端口和 UDP 风险流量；进入低置信风险计分 |
| `CN_BLOCKED` | 阻断中国大陆域名和 IP；不作为 `blocked` 事件计分 |

配置标签时必须写成 `CN_BLOCKED`，不能写成 `CN\_BLOCKED`。

### 3. 配置路由

将以下规则合并到现有 `routing`。顺序不能随意改变：Xray 从上到下匹配，命中第一条规则后停止。

```json
"routing": {
  "rules": [
    {
      "type": "field",
      "inboundTag": [
        "api"
      ],
      "outboundTag": "api"
    },
    {
      "type": "field",
      "protocol": [
        "bittorrent"
      ],
      "outboundTag": "TORRENT"
    },
    {
      "type": "field",
      "domain": [
        "geosite:private"
      ],
      "outboundTag": "blocked"
    },
    {
      "type": "field",
      "ip": [
        "geoip:private",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
        "fe80::/10"
      ],
      "outboundTag": "blocked"
    },
    {
      "type": "field",
      "port": "22,23,25,135,137-139,445,465,587,1433,1521,2049,2181,2375,2376,2379,2380,2525,3306,3389,5432,5672,5900,5984,5985,5986,6379,6443,8086,9092,9200,9300,10250,10256,10257,10259,11211,15672,27017",
      "outboundTag": "blocked"
    },
    {
      "type": "field",
      "network": "udp",
      "port": "17,19,69,111,123,137,161,389,520,1900,3702,5353,5683,11211",
      "outboundTag": "blocked"
    },
    {
      "type": "field",
      "domain": [
        "geosite:cn"
      ],
      "outboundTag": "CN_BLOCKED"
    },
    {
      "type": "field",
      "ip": [
        "geoip:cn"
      ],
      "outboundTag": "CN_BLOCKED"
    }
  ],
  "domainStrategy": "IPOnDemand"
}
```

这组规则的实际顺序是：

```text
内部 API
  -> BT
  -> 内网域名
  -> 私网、CGNAT 和链路本地 IP
  -> 通用高风险端口
  -> UDP 风险端口
  -> 中国大陆域名
  -> 中国大陆 IP
  -> 未命中时使用现有默认出站
```

注意：

- 保留 3x-ui `direct.settings.finalRules` 中的 `geoip:private` 阻断；它是额外保护，不能替代显式的 `blocked` 路由。
- UDP 规则会阻断 NTP `123`、SNMP `161`、CLDAP `389`、mDNS `5353` 等服务。如果用户确实需要这些协议，应删除对应端口。
- 不要直接屏蔽 UDP/TCP `53`，否则可能影响普通 DNS。
- 不要屏蔽 UDP `443`，否则会影响 QUIC/HTTP3。
- `geosite:cn`、`geoip:cn`、`geosite:private` 和 `geoip:private` 依赖 Xray 的 geodata 文件；更新 Xray 后应检查数据文件是否存在。

### 4. 为用户入站启用 sniffing

每个 VLESS、VMess、Trojan 等用户入站都应配置：

```json
"sniffing": {
  "enabled": true,
  "destOverride": [
    "http",
    "tls",
    "quic"
  ],
  "metadataOnly": false,
  "routeOnly": true
}
```

不要给内部 `api` 入站添加 sniffing。每个客户端还应设置唯一且非空的 email，否则项目只能按来源 IP 归属事件，无法可靠禁用具体客户端。

### 5. 保存并验证

从 3x-ui 保存配置并重启 Xray，然后执行：

```bash
sudo 3x-abuse-guardctl doctor
sudo tail -n 100 /var/log/x-ui/error.log
sudo tail -f /var/log/x-ui/access.log
```

预期 access log 中可以看到：

```text
BT                         -> TORRENT
私网、危险端口、UDP 风险流量 -> blocked
中国大陆域名或 IP            -> CN_BLOCKED
其他流量                    -> direct（或现有默认出站）
```

`doctor` 会检查 access log、面板 API、Xray 运行状态和配置错误、`TORRENT`/`blocked`、BT 路由顺序、AmneziaWG IPv6 出口遮挡，以及用户入站（含带认证客户端的回环 SOCKS/mixed relay）的 sniffing。状态接口不可用或缺少 Xray 状态时也会报错，不会假定运行正常。

3x-ui 3.8.5 会在新配置存在端口冲突时保留运行中的旧配置。`getConfigJson` 返回生成配置，不是运行配置快照；若 `doctor` 的 `xray runtime` 报告 `config refused`，请先解决面板报告的冲突并重新应用配置。检查通过仅说明配置检查通过且面板未报告运行错误，不证明每条规则已经被真实流量命中；`CN_BLOCKED`、UDP 规则及具体客户端的路由结果仍需通过 access/error log 实测。

### Native AmneziaWG 的每客户端 IPv6 出口

启用每客户端 IPv6 出口、配置有效外部接口且客户端具有 IPv6 AllowedIPs 时，3x-ui 会把 `amneziawg-v6-*` 直连规则插到保存的路由规则之前。该规则按入站和 email 直接匹配，可能绕过后面的 `TORRENT`、`blocked` 以及 `CN_BLOCKED`。

此时 `doctor` 的 `routing AmneziaWG` 会报错并列出相关入站、用户及出站。需要关闭面板中该 AmneziaWG 入站的每客户端 IPv6 出口功能，或在上游解决生成路由的优先级，使防滥用规则先匹配，再重新应用并验证。仅在面板路由编辑器中移动保存的规则不能保证覆盖自动前置规则。本项目只诊断此限制，不自动改写面板配置，也不提供完整的 Xray 路由模拟。

### 禁用客户端与 Xray 重启

3x-ui 3.8.5 的 **Restart Xray After Client Disable** 设置也作用于本项目调用的批量禁用接口。开启时，禁用客户端可能触发整个 Xray 重启，影响同一核心上的其他连接；关闭时，移除客户端凭据通常只阻止新连接，既有连接可能继续，来源 IP 封禁的效果还取决于是否能取得真实来源地址。

是否开启应在 3x-ui 的 Xray 设置中明确选择；本项目不覆盖面板的重启设置。

## 默认策略

| 事件 | 默认行为 |
| --- | --- |
| 第一次 `TORRENT` 命中 | 封禁来源 IP 24 小时 |
| 同一 email 60 分钟内第二次 `TORRENT` 命中 | 禁用对应 3x-ui 客户端 |
| `blocked` 命中 | 每次计 10 分，累计 5 次通知；不自动封 IP、不自动禁用客户端 |
| `port_scan` | 默认 5 分钟内访问 50 个不同端口后通知 |
| `connection_rate` | 默认 5 分钟内达到 1500 次连接后通知 |
| `CN_BLOCKED` | 不触发 `blocked` 检测，但仍进入每日访问统计和通用启发式检测 |

`blocked`、`port_scan` 和 `connection_rate` 都是低置信信号，默认只通知。不要在没有观察实际流量前直接改成自动封禁，否则手机全局代理、共享 NAT 或正常高并发应用可能被误判。

## 守护进程配置

默认配置文件是 `/etc/3x-abuse-guard/config.yaml`，完整示例见 [config.example.yaml](config.example.yaml)。常用配置如下：

```yaml
panel:
  base_url: "http://127.0.0.1:2053/"
  auth_mode: "auto"
  token_env: "THREEX_ABUSE_GUARD_TOKEN"
  username_env: "THREEX_ABUSE_GUARD_USERNAME"
  password_env: "THREEX_ABUSE_GUARD_PASSWORD"
  timeout_seconds: 10
  insecure_skip_verify: false

xray:
  access_log: "/var/log/x-ui/access.log"
  torrent_tag: "TORRENT"
  blocked_tag: "blocked"

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
  profiles:
    default:
      notify_score: 50
      block_ip_score: 80
      disable_client_score: 200
    blocked_watch:
      notify_score: 50
      block_ip_score: 0
      disable_client_score: 0

state:
  path: "/var/lib/3x-abuse-guard/state.db"
  event_retention_days: 30
```

重要配置：

| 参数 | 说明 |
| --- | --- |
| `panel.base_url` | 3x-ui API 地址，优先使用本机回环地址 |
| `panel.auth_mode` | `auto`、`token` 或 `login` |
| `panel.insecure_skip_verify` | 跳过面板 TLS 校验，仅用于无法修复的本机证书不匹配场景 |
| `xray.access_log` | 必须与 Xray 实际 access log 路径一致 |
| `xray.torrent_tag` | 必须与路由中的 `TORRENT` 标签一致 |
| `xray.blocked_tag` | 必须与路由中的 `blocked` 标签一致；不要改成 `CN_BLOCKED` |
| `firewall.backend` | `iptables`、`nft` 或 `noop` |
| `firewall.bypass_ips` | 永不执行防火墙封禁的来源 IP/CIDR，建议保留回环地址 |
| `policy.mode` | `balanced`、`strict` 或 `observe` |
| `policy.profiles` | 正式处置阈值；`0` 表示关闭对应动作 |
| `policy.assignments` | 按 email、inbound 或风险类型选择 profile |
| `state.event_retention_days` | 事件保留天数；`0` 表示不自动清理 |

旧配置中的 `torrent_disable_client_after`、`blocked_disable_client_after` 和 `blocked_notify_after` 仍兼容，并会明确覆盖对应 traffic profile 的分数阈值。新配置不应再混用这两套表达方式；请直接修改 profiles。

敏感信息放在 `/etc/3x-abuse-guard/env`，不要写进 `config.yaml`：

```text
THREEX_ABUSE_GUARD_TOKEN=
THREEX_ABUSE_GUARD_USERNAME=
THREEX_ABUSE_GUARD_PASSWORD=
THREEX_ABUSE_GUARD_2FA_CODE=
THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN=
THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID=
```

## 通知

Webhook 地址写入 `config.yaml`：

```yaml
notify:
  webhook_url: "https://example.com/your-webhook"
  telegram_bot_token_env: "THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN"
  telegram_chat_id_env: "THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID"
```

Telegram token 和 chat id 写入 `/etc/3x-abuse-guard/env`。配置后可以用模拟事件验证通知链路：

```bash
sudo systemctl restart 3x-abuse-guard
sudo 3x-abuse-guardctl test-event --email test --ip 198.51.100.10 --tag TORRENT
```

Telegram 每天北京时间 00:00 发送前一天的访问统计，按 client email 分组；没有 email 时按来源 IP 分组。日报包含连接数、活跃时间、来源 IP、访问目标、入站、出站、协议和事件类型，不包含流量字节数。

日报目前属于 best-effort 内存统计：守护进程重启会丢失尚未发送的当日汇总。守护进程也从 access log 文件末尾开始跟踪，不补处理停机期间的历史日志。Xray 日志时间戳按主机本地时区解释，而日报固定使用北京时间；部署时应确保主机/Xray 时区符合预期。

## 常用命令

`3x-abuse-guardctl` 会先加载 `/etc/3x-abuse-guard/env`，日常运维优先使用它。

| 命令 | 作用 |
| --- | --- |
| `sudo 3x-abuse-guardctl doctor` | 检查 access log、面板 API、Xray 出站、路由和 sniffing |
| `sudo 3x-abuse-guardctl status` | 查看当前封禁和近期事件，不修改配置 |
| `sudo 3x-abuse-guardctl unblock <ip>` | 解除指定 IP 封禁并删除本地 ban 记录 |
| `sudo 3x-abuse-guardctl test-event --email <email> --ip <ip> --tag <tag>` | 模拟 `TORRENT` 或 `blocked` 事件 |
| `3x-abuse-guard print-xray-policy` | 输出项目内置的核心 Xray 配置基线 |

常用排查命令：

```bash
sudo systemctl status 3x-abuse-guard --no-pager
sudo journalctl -u 3x-abuse-guard -n 50 --no-pager
sudo journalctl -u 3x-abuse-guard -f --no-pager
sudo tail -n 30 /var/log/x-ui/access.log
sudo iptables -t raw -S | grep THREEX_ABUSE_GUARD
sudo iptables -t raw -L THREEX_ABUSE_GUARD -n -v
```

`print-xray-policy` 当前输出项目运行所需的 `TORRENT`、`blocked` 和 sniffing 基线；本 README 中的 `CN_BLOCKED`、中国大陆阻断和 UDP 风险规则属于推荐扩展配置，应以本页配置为准。

## 完全卸载

以下操作会删除配置、状态数据库和项目维护的防火墙规则，执行前请确认不再需要这些数据：

```bash
sudo systemctl stop 3x-abuse-guard 2>/dev/null || true
sudo systemctl disable 3x-abuse-guard 2>/dev/null || true

sudo iptables -t raw -D PREROUTING -j THREEX_ABUSE_GUARD 2>/dev/null || true
sudo iptables -t raw -F THREEX_ABUSE_GUARD 2>/dev/null || true
sudo iptables -t raw -X THREEX_ABUSE_GUARD 2>/dev/null || true

sudo ip6tables -t raw -D PREROUTING -j THREEX_ABUSE_GUARD 2>/dev/null || true
sudo ip6tables -t raw -F THREEX_ABUSE_GUARD 2>/dev/null || true
sudo ip6tables -t raw -X THREEX_ABUSE_GUARD 2>/dev/null || true

sudo nft delete table inet THREEX_ABUSE_GUARD 2>/dev/null || true

sudo rm -f /etc/systemd/system/3x-abuse-guard.service
sudo rm -f /usr/local/bin/3x-abuse-guard
sudo rm -f /usr/local/bin/3x-abuse-guardctl
sudo rm -rf /etc/3x-abuse-guard
sudo rm -rf /var/lib/3x-abuse-guard
sudo rm -rf /var/log/3x-abuse-guard
sudo systemctl daemon-reload
```

## 从源码安装

需要 Go 1.22 或更高版本：

```bash
git clone https://github.com/zachary9757/3x-abuse-guard.git
cd 3x-abuse-guard
go build -o 3x-abuse-guard ./cmd/3x-abuse-guard
sudo install -m 0755 3x-abuse-guard /usr/local/bin/3x-abuse-guard
sudo 3x-abuse-guard install
sudo nano /etc/3x-abuse-guard/env
sudo systemctl daemon-reload
sudo systemctl enable --now 3x-abuse-guard
```

## 开发

```bash
go mod tidy
go test ./...
go build ./cmd/3x-abuse-guard
```

GitHub Actions 会在干净环境执行 `go test ./...`。依赖变化后应运行 `go mod tidy`，并同时提交 `go.mod` 和 `go.sum`。

CI 同时执行 `go vet ./...`、安装脚本语法与重复执行测试，以及 `git diff --check`。

## 许可证

MIT。
