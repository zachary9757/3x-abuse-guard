# systemd Deployment

Install:

```bash
go build -o 3x-abuse-guard ./cmd/3x-abuse-guard
sudo install -m 0755 3x-abuse-guard /usr/local/bin/3x-abuse-guard
sudo 3x-abuse-guard install
```

Edit the token environment file:

```bash
sudo nano /etc/3x-abuse-guard/env
```

```text
THREEX_ABUSE_GUARD_TOKEN=your-3x-ui-api-token
```

Start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 3x-abuse-guard
```

Inspect:

```bash
sudo journalctl -u 3x-abuse-guard -f --no-pager
sudo 3x-abuse-guard status
```
