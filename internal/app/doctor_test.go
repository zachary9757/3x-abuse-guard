package app

import (
	"testing"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
)

func TestInspectXrayConfigAccepts3xUI360Configuration(t *testing.T) {
	cfg := config.Default()
	xrayConfig := map[string]any{
		"log": map[string]any{"access": "/var/log/x-ui/access.log"},
		"outbounds": []any{
			map[string]any{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]any{"finalRules": []any{
					map[string]any{"action": "block", "ip": []any{"geoip:private"}},
					map[string]any{"action": "allow"},
				}},
			},
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "TORRENT"},
			map[string]any{"ip": []any{"geoip:private"}, "outboundTag": "blocked"},
		}},
		"inbounds": []any{
			map[string]any{"tag": "api"},
			map[string]any{"tag": "panel-egress", "protocol": "socks", "listen": "127.0.0.1"},
			map[string]any{"tag": "inbound-1", "sniffing": map[string]any{"enabled": true}},
		},
	}

	for _, check := range inspectXrayConfig(xrayConfig, cfg) {
		if !check.OK {
			t.Errorf("%s failed: %s", check.Name, check.Message)
		}
	}
}

func TestInspectXrayConfigRejectsEarlierDefaultBittorrentRule(t *testing.T) {
	cfg := config.Default()
	xrayConfig := map[string]any{
		"log": map[string]any{"access": "/var/log/x-ui/access.log"},
		"outbounds": []any{
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "blocked"},
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "TORRENT"},
			map[string]any{"ip": []any{"geoip:private"}, "outboundTag": "blocked"},
		}},
		"inbounds": []any{
			map[string]any{"tag": "inbound-1", "sniffing": map[string]any{"enabled": true}},
		},
	}

	check := findCheck(t, inspectXrayConfig(xrayConfig, cfg), "routing TORRENT")
	if check.OK {
		t.Fatalf("routing check unexpectedly passed: %s", check.Message)
	}
	if check.Message != "first bittorrent rule routes to blocked; move TORRENT before it" {
		t.Fatalf("message = %q", check.Message)
	}
}

func TestInspectXrayConfigRejectsMisleadingMatches(t *testing.T) {
	cfg := config.Default()
	xrayConfig := map[string]any{
		"log": map[string]any{"access": "none"},
		"outbounds": []any{
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"port": "6881", "outboundTag": "TORRENT"},
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "blocked"},
		}},
		"inbounds": []any{
			map[string]any{"tag": "inbound-1", "sniffing": map[string]any{"enabled": true}},
			map[string]any{"tag": "inbound-2", "sniffing": map[string]any{"enabled": false}},
		},
	}

	checks := inspectXrayConfig(xrayConfig, cfg)
	for _, name := range []string{"xray access log", "routing TORRENT", "routing blocked", "sniffing"} {
		check := findCheck(t, checks, name)
		if check.OK {
			t.Errorf("%s unexpectedly passed: %s", check.Name, check.Message)
		}
	}
}

func findCheck(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %q not found", name)
	return Check{}
}
