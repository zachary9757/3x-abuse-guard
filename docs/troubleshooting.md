# Troubleshooting

## `doctor` says panel auth is missing

If you installed with `scripts/install.sh`, use the helper command. It loads `/etc/3x-abuse-guard/env` before running the binary:

```bash
sudo 3x-abuse-guardctl doctor
```

Use API token auth when your panel supports it:

```bash
export THREEX_ABUSE_GUARD_TOKEN=your-token
```

Use login auth when your panel has no API Token menu:

```bash
export THREEX_ABUSE_GUARD_USERNAME=your-panel-username
export THREEX_ABUSE_GUARD_PASSWORD=your-panel-password
```

For systemd, put it in:

```text
/etc/3x-abuse-guard/env
```

## `doctor` reports `x509: cannot validate certificate for 127.0.0.1`

This means the panel is being accessed over HTTPS, but its certificate does not contain `127.0.0.1` in the IP SAN list.

Best option: set `panel.base_url` to the domain name covered by the certificate.

For localhost-only access with a self-signed or mismatched certificate, explicitly enable:

```yaml
panel:
  base_url: "https://127.0.0.1:2053/"
  insecure_skip_verify: true
```

If you use the installer, pass:

```bash
--panel-insecure-skip-verify
```

## Torrent events are not detected

Check:

- Xray access log is enabled.
- User-facing inbounds have sniffing enabled.
- Routing has `protocol: ["bittorrent"] -> TORRENT`.
- The `TORRENT` outbound exists and uses `blackhole`.

## IP is blocked but client is not disabled

Check:

- Access log line includes `email: <client-email>`.
- `policy.torrent_disable_client_after` is greater than 0.
- 3x-ui API token is valid, or login auth username/password is valid.
- Client exists in 3x-ui with the same email.

## Port scan or connection-rate detector is too sensitive

Tune the detector thresholds:

```yaml
detectors:
  port_scan:
    distinct_ports: 12
    window_minutes: 5
  connection_rate:
    max_connections: 600
    window_minutes: 5
```

Or assign a softer profile for trusted users:

```yaml
policy:
  assignments:
    emails:
      trusted-user: observe
```

## Unblock an IP

```bash
sudo 3x-abuse-guardctl unblock 198.51.100.10
```

## Use noop firewall for dry runs

```yaml
firewall:
  backend: "noop"
```

This records events and policy decisions without touching iptables/nftables.
