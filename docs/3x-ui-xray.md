# 3x-ui 3.5.0 / Xray Setup

This guide is verified against 3x-ui `v3.5.0`, which bundles Xray-core
`v26.7.11`.

`3x-abuse-guard` depends on the Xray access log and two outbound tags:

- `TORRENT`: torrent traffic, used for IP blocking and repeat-offender disablement.
- `blocked`: high-risk IP or port traffic, used for visibility and optional notifications.

## Important 3.5.0 Defaults

3x-ui 3.5.0 ships with:

- Xray access logging set to `none`.
- A `blocked` blackhole outbound.
- A `bittorrent -> blocked` routing rule.

The default bittorrent rule is not sufficient for this project. A hit routed to
`blocked` is intentionally treated as a low-confidence event, while a hit routed
to `TORRENT` triggers the torrent policy.

## Log Settings

Enable the Xray access log:

```json
"log": {
  "access": "/var/log/x-ui/access.log",
  "dnsLog": false,
  "error": "/var/log/x-ui/error.log",
  "loglevel": "warning",
  "maskAddress": ""
}
```

3x-ui stores configured Xray log filenames in its log directory. The default is
`/var/log/x-ui`; `XUI_LOG_FOLDER` can override it. If 3x-ui runs in a container,
`xray.access_log` in `3x-abuse-guard` must use the host-visible mounted path.
Confirm the real path before starting the daemon:

```bash
sudo ls -l /var/log/x-ui/access.log
sudo tail -n 5 /var/log/x-ui/access.log
```

## Outbounds

Keep the existing `blocked` outbound. Add `TORRENT` if it is absent:

```json
{
  "tag": "TORRENT",
  "protocol": "blackhole",
  "settings": {}
}
```

The resulting configuration must contain both blackhole outbounds:

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
}
```

## Routing Rules

Keep 3x-ui's internal `api -> api` rule first. Replace the existing
`bittorrent -> blocked` rule with the following rule, or insert this rule before
the existing one:

```json
{
  "type": "field",
  "protocol": ["bittorrent"],
  "outboundTag": "TORRENT"
}
```

Do not leave an earlier `bittorrent -> blocked` rule above it, because Xray uses
the first matching routing rule.

Place the high-risk rules after the internal API rule and before ordinary
direct/proxy rules:

```json
{
  "type": "field",
  "ip": ["geoip:private", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"],
  "outboundTag": "blocked"
},
{
  "type": "field",
  "port": "25,465,587,2525",
  "outboundTag": "blocked"
},
{
  "type": "field",
  "port": "22,23,135,137-139,445,1433,1521,2049,2375,2376,3306,3389,5432,5900,6379,9200,9300,11211,27017",
  "outboundTag": "blocked"
}
```

## Sniffing

Enable sniffing on every user-facing inbound:

```json
"sniffing": {
  "enabled": true,
  "destOverride": ["http", "tls", "quic"],
  "metadataOnly": false,
  "routeOnly": true
}
```

This sniffing schema remains valid with Xray-core `v26.7.11`. Xray recognizes
bittorrent separately from `destOverride`, so `bittorrent` does not need to be
added to that list.

Encrypted or obfuscated torrent traffic can still evade protocol detection.
Combine this project with 3x-ui traffic quotas and IP limits.

## Apply And Verify

Save the Xray configuration and restart Xray from 3x-ui. Then run:

```bash
sudo 3x-abuse-guardctl doctor
```

The check must pass for:

- the host access-log file and Xray access-log setting;
- `TORRENT` and `blocked` blackhole outbounds;
- `bittorrent -> TORRENT`;
- at least one IP or port rule routed to `blocked`;
- sniffing on every user-facing inbound.
