# 3x-ui 3.8.5 / Xray Setup

This guide is checked against the source of 3x-ui `v3.8.5`, which bundles
Xray-core `v26.9.9`. Validate your deployed configuration with `doctor` and real access logs.

`3x-abuse-guard` depends on the Xray access log and two outbound tags:

- `TORRENT`: torrent traffic, used for IP blocking and repeat-offender disablement.
- `blocked`: high-risk IP or port traffic, used for visibility and optional notifications.

## Important 3.8.5 Defaults

The following relevant 3x-ui defaults remain present in 3.8.5:

- Xray access logging set to `none`.
- A `blocked` blackhole outbound.
- A `bittorrent -> blocked` routing rule.
- A `geoip:private` block in the `direct` outbound's `finalRules`.

The default bittorrent rule is not sufficient for this project. A hit routed to
`blocked` is intentionally treated as a low-confidence event, while a hit routed
to `TORRENT` triggers the torrent policy.

Keep the `direct.settings.finalRules` private-range block. It is
useful defense in depth, but it does not replace the explicit `ip -> blocked`
routing rule: traffic rejected inside `direct` does not carry the `blocked`
outbound tag that this project uses for risk accounting.

For an existing `direct` outbound whose `finalRules` only contains `allow`, add
the private-range block before it:

```json
"settings": {
  "domainStrategy": "AsIs",
  "finalRules": [
    {
      "action": "block",
      "ip": ["geoip:private"]
    },
    {
      "action": "allow"
    }
  ]
}
```

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

This sniffing schema remains valid with Xray-core `v26.9.9`. Xray recognizes
bittorrent separately from `destOverride`, so `bittorrent` does not need to be
added to that list.

Encrypted or obfuscated torrent traffic can still evade protocol detection.
Combine this project with 3x-ui traffic quotas and IP limits.

## Native AmneziaWG

3x-ui 3.8.5 relays Native AmneziaWG traffic through an internal loopback
SOCKS5 inbound so Xray routing, sniffing, and the client email remain available.
`3x-abuse-guard` therefore records matching events and can notify or disable the
client by email. The Xray access log sees the relay's loopback source address,
not the client's public address, so the loopback address remains in
`firewall.bypass_ips` and is never firewall-blocked.

Authenticated loopback SOCKS/mixed relays are included in `doctor`'s sniffing
check; anonymous internal proxies are excluded. An AmneziaWG-only deployment
therefore does not need a separate VLESS/VMess inbound to pass this check.

Per-client IPv6 egress can bypass abuse routing: with IPv6 enabled, a valid
external interface and a peer IPv6 AllowedIPs entry, 3x-ui prepends an
`amneziawg-v6-*` rule matching the inbound and user before the saved rules.
`doctor` fails when such a rule precedes `TORRENT` or `blocked` rules. Disable
per-client IPv6 egress in the panel or resolve the generated rule order upstream,
then reapply and verify. Reordering saved rules alone does not override injected
rules. The guard diagnoses this limitation; it does not rewrite panel routing.

## Apply And Verify

Save the Xray configuration and restart Xray from 3x-ui. Then run:

```bash
sudo 3x-abuse-guardctl doctor
```

On 3x-ui 3.8.5, the configured API token must have the `admin` scope. A
`monitor` or `node-sync` token cannot read the assembled Xray config used by
this check.

The check must pass for:

- the host access-log file and Xray access-log setting;
- a running Xray core with no panel-reported config error;
- `TORRENT` and `blocked` blackhole outbounds;
- `bittorrent -> TORRENT`;
- no earlier `bittorrent` rule targeting `blocked` or another outbound;
- no generated AmneziaWG IPv6 egress rule preceding abuse rules;
- at least one IP or port rule routed to `blocked`;
- sniffing on every user-facing inbound.

The panel can refuse a conflicting new config while keeping the old core running.
`getConfigJson` returns the generated config, not a live snapshot; `doctor` also
reads `/panel/api/server/status` and fails for a non-running core, a reported
`xray.errorMsg`, or an unavailable/missing status. A passing check is not proof
of every rule's effective runtime behavior: verify actual access logs too.

In 3.8.5, **Restart Xray After Client Disable** also applies to bulk disable calls
from this guard. Enabling it can restart the entire core and interrupt other
clients; disabling it can leave already-established sessions alive after their
credentials are removed. Choose this setting in 3x-ui. The guard's legacy
`panel.restart_xray` field is not wired into enforcement and does not override it.
