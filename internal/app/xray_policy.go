package app

const XrayPolicySnippet = `3x-ui 3.9.0 (Xray-core v26.9.30) disables the Xray access log by default.
Enable it with filename access.log and make sure the host-visible path matches:

{
  "log": {
    "access": "/var/log/x-ui/access.log",
    "dnsLog": false,
    "error": "/var/log/x-ui/error.log",
    "loglevel": "warning",
    "maskAddress": ""
  }
}

Add TORRENT if it is not already present. 3x-ui already provides blocked:

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

3x-ui 3.9.0 includes a geoip:private block in direct.settings.finalRules.
Keep that defense-in-depth rule. It does not replace the explicit blocked
routing rules below because it does not produce the blocked outbound tag.

"settings": {
  "domainStrategy": "AsIs",
  "finalRules": [
    {"action": "block", "ip": ["geoip:private"]},
    {"action": "allow"}
  ]
}

Keep the internal api -> api rule first. Replace 3x-ui's existing
bittorrent -> blocked rule with bittorrent -> TORRENT, or put this rule
before it. Keep all abuse rules before normal direct/proxy rules:

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

For each user-facing inbound, enable sniffing:

{
  "enabled": true,
  "destOverride": ["http", "tls", "quic"],
  "metadataOnly": false,
  "routeOnly": true
}

Native AmneziaWG uses an internal loopback SOCKS5 relay. Keep 127.0.0.1 and
::1 in firewall.bypass_ips: matching events with a client email are still
scored and can disable the client, but the loopback relay must not be blocked.
Per-client AmneziaWG IPv6 egress can prepend amneziawg-v6-* routes ahead of
these abuse rules. Resolve any routing AmneziaWG failure from doctor in the
panel before relying on this policy. Doctor also checks Xray runtime errors;
generated config alone does not prove the running core applied it.

Native TUIC in 3x-ui 3.9.0 uses a noauth loopback SOCKS5 relay. Doctor reports
this as un-attributable because Xray access logs cannot reliably identify the
TUIC client. Do not block the loopback relay or treat it as a real source IP.
`
