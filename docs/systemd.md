# systemd Deployment

Install:

```bash
go build -o 3x-abuse-guard ./cmd/3x-abuse-guard
sudo install -m 0755 3x-abuse-guard /usr/local/bin/3x-abuse-guard
sudo 3x-abuse-guard install
```

Edit the panel auth environment file. Use either API token auth:

```bash
sudo nano /etc/3x-abuse-guard/env
```

```text
THREEX_ABUSE_GUARD_TOKEN=your-3x-ui-api-token
THREEX_ABUSE_GUARD_USERNAME=
THREEX_ABUSE_GUARD_PASSWORD=
THREEX_ABUSE_GUARD_2FA_CODE=
```

Or use login auth when your panel has no API Token menu:

```text
THREEX_ABUSE_GUARD_TOKEN=
THREEX_ABUSE_GUARD_USERNAME=your-panel-username
THREEX_ABUSE_GUARD_PASSWORD=your-panel-password
THREEX_ABUSE_GUARD_2FA_CODE=
```

Start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 3x-abuse-guard
```

Inspect:

```bash
sudo journalctl -u 3x-abuse-guard -f --no-pager
sudo 3x-abuse-guardctl status
```
