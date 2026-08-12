package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
)

type Check struct {
	Name    string
	OK      bool
	Message string
}

func Doctor(ctx context.Context, cfg config.Config) []Check {
	checks := []Check{}

	if _, err := os.Stat(cfg.Xray.AccessLog); err != nil {
		checks = append(checks, Check{"access log", false, err.Error()})
	} else {
		checks = append(checks, Check{"access log", true, cfg.Xray.AccessLog})
	}

	client, authMode, err := newPanelClient(cfg)
	if err != nil {
		checks = append(checks, Check{"panel auth", false, err.Error()})
		return checks
	}
	checks = append(checks, Check{"panel auth", true, authMode})

	xrayConfig, err := client.GetConfigJSON(ctx)
	if err != nil {
		checks = append(checks, Check{"panel api", false, err.Error()})
		return checks
	}
	checks = append(checks, Check{"panel api", true, cfg.Panel.BaseURL})

	checks = append(checks, inspectXrayConfig(xrayConfig, cfg)...)
	return checks
}

func inspectXrayConfig(xrayConfig map[string]any, cfg config.Config) []Check {
	checks := []Check{}
	accessOK, accessMessage := hasExpectedAccessLog(xrayConfig, cfg.Xray.AccessLog)
	checks = append(checks, Check{"xray access log", accessOK, accessMessage})
	checks = append(checks, Check{"outbound " + cfg.Xray.TorrentTag, hasOutbound(xrayConfig, cfg.Xray.TorrentTag), "requires blackhole outbound"})
	checks = append(checks, Check{"outbound " + cfg.Xray.BlockedTag, hasOutbound(xrayConfig, cfg.Xray.BlockedTag), "requires blackhole outbound"})
	torrentOK, torrentMessage := hasFirstProtocolRoutingOutbound(xrayConfig, cfg.Xray.TorrentTag, "bittorrent")
	checks = append(checks, Check{"routing " + cfg.Xray.TorrentTag, torrentOK, torrentMessage})
	checks = append(checks, Check{"routing " + cfg.Xray.BlockedTag, hasHighRiskRoutingOutbound(xrayConfig, cfg.Xray.BlockedTag), "requires an ip or port block rule"})
	sniffingOK, sniffingMessage := hasSniffingOnUserInbounds(xrayConfig)
	checks = append(checks, Check{"sniffing", sniffingOK, sniffingMessage})
	return checks
}

func hasExpectedAccessLog(cfg map[string]any, expected string) (bool, string) {
	logConfig, _ := cfg["log"].(map[string]any)
	access := stringValue(logConfig["access"])
	if access == "" || strings.EqualFold(access, "none") {
		return false, "Xray access logging is disabled"
	}
	if filepath.Base(access) != filepath.Base(expected) {
		return false, fmt.Sprintf("Xray writes %s but xray.access_log is %s", access, expected)
	}
	return true, access
}

func hasOutbound(cfg map[string]any, tag string) bool {
	for _, outbound := range list(cfg["outbounds"]) {
		m, ok := outbound.(map[string]any)
		if !ok {
			continue
		}
		if m["tag"] == tag && strings.EqualFold(fmt.Sprint(m["protocol"]), "blackhole") {
			return true
		}
	}
	return false
}

func hasFirstProtocolRoutingOutbound(cfg map[string]any, tag string, protocol string) (bool, string) {
	routing, _ := cfg["routing"].(map[string]any)
	for _, rule := range list(routing["rules"]) {
		m, ok := rule.(map[string]any)
		if !ok || !contains(m["protocol"], protocol) {
			continue
		}
		actual := stringValue(m["outboundTag"])
		if actual == tag {
			return true, fmt.Sprintf("first %s rule routes to %s", protocol, tag)
		}
		if actual == "" {
			actual = "an unsupported target"
		}
		return false, fmt.Sprintf("first %s rule routes to %s; move %s before it", protocol, actual, tag)
	}
	return false, fmt.Sprintf("requires protocol %s rule routed to %s", protocol, tag)
}

func hasHighRiskRoutingOutbound(cfg map[string]any, tag string) bool {
	routing, _ := cfg["routing"].(map[string]any)
	for _, rule := range list(routing["rules"]) {
		m, ok := rule.(map[string]any)
		if !ok || m["outboundTag"] != tag {
			continue
		}
		if hasValues(m["ip"]) || hasValues(m["port"]) {
			return true
		}
	}
	return false
}

func hasSniffingOnUserInbounds(cfg map[string]any) (bool, string) {
	total := 0
	enabledCount := 0
	for _, inbound := range list(cfg["inbounds"]) {
		m, ok := inbound.(map[string]any)
		if !ok {
			continue
		}
		if !isUserFacingInbound(m) {
			continue
		}
		total++
		sniffing, ok := m["sniffing"].(map[string]any)
		if !ok {
			continue
		}
		if enabled, ok := sniffing["enabled"].(bool); ok && enabled {
			enabledCount++
		}
	}
	if total == 0 {
		return false, "no user inbounds found"
	}
	return enabledCount == total, fmt.Sprintf("%d/%d user inbounds have sniffing enabled", enabledCount, total)
}

func isUserFacingInbound(inbound map[string]any) bool {
	if strings.EqualFold(stringValue(inbound["tag"]), "api") {
		return false
	}
	protocol := stringValue(inbound["protocol"])
	listen := strings.Trim(stringValue(inbound["listen"]), "[]")
	return !strings.EqualFold(protocol, "socks") || (listen != "127.0.0.1" && listen != "::1")
}

func contains(value any, expected string) bool {
	if strings.EqualFold(stringValue(value), expected) {
		return true
	}
	for _, item := range list(value) {
		if strings.EqualFold(stringValue(item), expected) {
			return true
		}
	}
	return false
}

func hasValues(value any) bool {
	return len(list(value)) > 0 || stringValue(value) != ""
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func list(v any) []any {
	if v == nil {
		return nil
	}
	if out, ok := v.([]any); ok {
		return out
	}
	return nil
}
