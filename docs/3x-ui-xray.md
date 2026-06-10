# 3x-ui / Xray Setup

`3x-abuse-guard` depends on Xray access logs and two outbound tags:

- `TORRENT`: torrent traffic, used for IP blocking and repeat-offender disablement.
- `blocked`: high-risk traffic, used for visibility and optional notifications.

## Log Settings

Set Xray logs to:

```json
"log": {
  "access": "/var/log/x-ui/access.log",
  "dnsLog": false,
  "error": "/var/log/x-ui/error.log",
  "loglevel": "warning",
  "maskAddress": ""
}
```

## Outbounds

Add:

```json
{
  "tag": "TORRENT",
  "protocol": "blackhole"
},
{
  "tag": "blocked",
  "protocol": "blackhole",
  "settings": {}
}
```

## Routing Rules

Place these before ordinary direct/proxy rules:

```json
{
  "type": "field",
  "protocol": ["bittorrent"],
  "outboundTag": "TORRENT"
},
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

`bittorrent` sniffing is not perfect. Encrypted or obfuscated torrent traffic can evade basic protocol detection, so this project should be combined with 3x-ui traffic quotas and IP limits.
