# Troubleshooting

## `doctor` says API token is missing

Create a token in 3x-ui **Settings -> Security -> API Token**, then export it:

```bash
export THREEX_ABUSE_GUARD_TOKEN=your-token
```

For systemd, put it in:

```text
/etc/3x-abuse-guard/env
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
- 3x-ui API token is valid.
- Client exists in 3x-ui with the same email.

## Unblock an IP

```bash
sudo 3x-abuse-guard unblock 198.51.100.10
```

## Use noop firewall for dry runs

```yaml
firewall:
  backend: "noop"
```

This records events and policy decisions without touching iptables/nftables.
