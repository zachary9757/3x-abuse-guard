# 3x-abuse-guard

`3x-abuse-guard` 是一个面向 3x-ui + Xray 节点的小型防滥用守护进程。它会监听 Xray access log，在防火墙层封禁 BT/种子流量的源 IP，并且可以通过 3x-ui 官方 API 禁用重复违规的客户端。

V1 刻意保持克制：

- 不做 Web UI
- 不直接写入 `/etc/x-ui/x-ui.db`
- 不自动修改全局 Xray 配置
- 优先通过 3x-ui API 集成
- 面向 Linux systemd 部署

## 功能

- 解析如下格式的 Xray access log：

  ```text
  2026/06/10 09:00:58 from 198.51.100.10:6148 accepted tcp:example.com:443 [inbound-1 >> TORRENT] email: alice
  ```

- 将 `TORRENT` 出站标签视为 BT/种子滥用。
- 将 `blocked` 出站标签视为高风险访问，但不当作 BT 处理。
- 默认封禁 BT 源 IP 24 小时。
- 默认同一 3x-ui client 在 60 分钟内命中 2 次 BT 后自动禁用。
- 使用 bbolt 在 `/var/lib/3x-abuse-guard/state.db` 保存本地状态。

## 从源码安装

```bash
git clone https://github.com/zachary9757/3x-abuse-guard.git
cd 3x-abuse-guard
go build -o 3x-abuse-guard ./cmd/3x-abuse-guard
sudo install -m 0755 3x-abuse-guard /usr/local/bin/3x-abuse-guard
sudo 3x-abuse-guard install
```

在 3x-ui 的 **Settings -> Security -> API Token** 中创建 API token，然后写入环境文件：

```bash
sudo nano /etc/3x-abuse-guard/env
```

```text
THREEX_ABUSE_GUARD_TOKEN=your-token-here
```

启动守护进程：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 3x-abuse-guard
sudo systemctl status 3x-abuse-guard --no-pager
```

## 配置 3x-ui/Xray

输出需要添加到 Xray 的配置片段：

```bash
3x-abuse-guard print-xray-policy
```

然后在 3x-ui 的 Xray 配置界面中应用这些片段。详细说明见 [docs/3x-ui-xray.md](docs/3x-ui-xray.md)。

运行就绪检查：

```bash
sudo THREEX_ABUSE_GUARD_TOKEN=your-token 3x-abuse-guard doctor
```

## 命令

```text
3x-abuse-guard run
3x-abuse-guard install
3x-abuse-guard doctor
3x-abuse-guard print-xray-policy
3x-abuse-guard status
3x-abuse-guard unblock <ip>
3x-abuse-guard test-event --email alice --ip 198.51.100.10 --tag TORRENT
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
```

含义：

- 第一次 BT 命中会封禁源 IP。
- 同一 email 在 60 分钟内第二次 BT 命中会禁用该 client。
- `blocked` 高风险访问默认只在 5 次后发送通知，不自动禁用。

## 开发

```bash
go test ./...
go build ./cmd/3x-abuse-guard
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
- Keeps local state in bbolt at `/var/lib/3x-abuse-guard/state.db`.

## Install From Source

```bash
git clone https://github.com/YOURNAME/3x-abuse-guard.git
cd 3x-abuse-guard
go build -o 3x-abuse-guard ./cmd/3x-abuse-guard
sudo install -m 0755 3x-abuse-guard /usr/local/bin/3x-abuse-guard
sudo 3x-abuse-guard install
```

Create a 3x-ui API token in **Settings -> Security -> API Token**, then set it:

```bash
sudo nano /etc/3x-abuse-guard/env
```

```text
THREEX_ABUSE_GUARD_TOKEN=your-token-here
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
sudo THREEX_ABUSE_GUARD_TOKEN=your-token 3x-abuse-guard doctor
```

## Commands

```text
3x-abuse-guard run
3x-abuse-guard install
3x-abuse-guard doctor
3x-abuse-guard print-xray-policy
3x-abuse-guard status
3x-abuse-guard unblock <ip>
3x-abuse-guard test-event --email alice --ip 198.51.100.10 --tag TORRENT
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
go test ./...
go build ./cmd/3x-abuse-guard
```

## License

MIT.
