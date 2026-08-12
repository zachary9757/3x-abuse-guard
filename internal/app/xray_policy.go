package app

const XrayPolicySnippet = `3x-ui 3.6.0 disables the Xray access log by default.
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

3x-ui 3.6.0 also adds a geoip:private block to direct.settings.finalRules.
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
`
