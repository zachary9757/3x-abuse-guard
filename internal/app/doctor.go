package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
	"github.com/zachary9757/3x-abuse-guard/internal/panel"
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
		checks = append(checks, Check{"panel api", false, panelAPIErrorMessage(err)})
		return checks
	}
	checks = append(checks, Check{"panel api", true, cfg.Panel.BaseURL})
	inbounds, err := client.GetInbounds(ctx)
	if err != nil {
		checks = append(checks, Check{"native TUIC attribution", false, "cannot inspect panel inbounds: " + panelAPIErrorMessage(err)})
	} else {
		checks = append(checks, inspectNativeTUIC(inbounds, xrayConfig))
	}
	status, err := client.GetServerStatus(ctx)
	switch {
	case err != nil:
		checks = append(checks, Check{"xray runtime", false, panelAPIErrorMessage(err)})
	case status.Xray == nil || strings.TrimSpace(status.Xray.State) == "":
		checks = append(checks, Check{"xray runtime", false, "panel status has no Xray state; cannot verify runtime health"})
	case strings.TrimSpace(status.Xray.ErrorMsg) != "":
		checks = append(checks, Check{"xray runtime", false, status.Xray.ErrorMsg})
	case status.Xray.State != "running":
		checks = append(checks, Check{"xray runtime", false, "Xray is " + status.Xray.State})
	default:
		message := "Xray is running"
		if version := strings.TrimSpace(status.Xray.Version); version != "" {
			message += " (" + version + ")"
		}
		checks = append(checks, Check{"xray runtime", true, message + "; panel reports no config error"})
	}

	checks = append(checks, inspectXrayConfig(xrayConfig, cfg)...)
	return checks
}

func panelAPIErrorMessage(err error) string {
	status, ok := panel.StatusCode(err)
	if !ok {
		return err.Error()
	}
	switch status {
	case 401:
		return err.Error() + "; token or login credentials are invalid, expired, or rotated"
	case 403:
		return err.Error() + "; 3x-ui API token requires admin scope"
	default:
		return err.Error()
	}
}

func inspectNativeTUIC(inbounds []panel.Inbound, xrayConfig map[string]any) Check {
	generated := map[string]map[string]any{}
	for _, raw := range list(xrayConfig["inbounds"]) {
		inbound, ok := raw.(map[string]any)
		if ok {
			generated[stringValue(inbound["tag"])] = inbound
		}
	}

	var unsupported []string
	var missing []string
	for _, inbound := range inbounds {
		if !inbound.Enable || inbound.NodeID != nil || !strings.EqualFold(inbound.Protocol, "tuic") {
			continue
		}
		relay, ok := generated[inbound.Tag]
		if !ok {
			missing = append(missing, inbound.Tag)
			continue
		}
		settings, _ := relay["settings"].(map[string]any)
		listen := strings.Trim(stringValue(relay["listen"]), "[]")
		if strings.EqualFold(stringValue(relay["protocol"]), "socks") && listen == "127.0.0.1" && strings.EqualFold(stringValue(settings["auth"]), "noauth") {
			unsupported = append(unsupported, inbound.Tag)
		}
	}
	if len(missing) > 0 {
		return Check{"native TUIC attribution", false, fmt.Sprintf("enabled local TUIC inbounds %v have no matching generated Xray relay", missing)}
	}
	if len(unsupported) > 0 {
		return Check{"native TUIC attribution", false, fmt.Sprintf("enabled local TUIC inbounds %v use a noauth loopback relay; Xray access logs cannot reliably attribute abuse to a client", unsupported)}
	}
	return Check{"native TUIC attribution", true, "no un-attributable local native TUIC relay found"}
}

func inspectXrayConfig(xrayConfig map[string]any, cfg config.Config) []Check {
	checks := []Check{}
	accessOK, accessMessage := hasExpectedAccessLog(xrayConfig, cfg.Xray.AccessLog)
	checks = append(checks, Check{"xray access log", accessOK, accessMessage})
	checks = append(checks, Check{"outbound " + cfg.Xray.TorrentTag, hasOutbound(xrayConfig, cfg.Xray.TorrentTag), "requires blackhole outbound"})
	checks = append(checks, Check{"outbound " + cfg.Xray.BlockedTag, hasOutbound(xrayConfig, cfg.Xray.BlockedTag), "requires blackhole outbound"})
	torrentOK, torrentMessage := hasFirstProtocolRoutingOutbound(xrayConfig, cfg.Xray.TorrentTag, "bittorrent")
	checks = append(checks, Check{"routing " + cfg.Xray.TorrentTag, torrentOK, torrentMessage})
	blockedOK, blockedMessage := hasHighRiskRoutingOutbound(xrayConfig, cfg.Xray.BlockedTag)
	checks = append(checks, Check{"routing " + cfg.Xray.BlockedTag, blockedOK, blockedMessage})
	relayOK, relayMessage := hasNoAmneziaWGRouteBypass(xrayConfig, cfg.Xray.TorrentTag, cfg.Xray.BlockedTag)
	checks = append(checks, Check{"routing AmneziaWG", relayOK, relayMessage})
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
	if filepath.IsAbs(access) && filepath.IsAbs(expected) && filepath.Clean(access) != filepath.Clean(expected) {
		return false, fmt.Sprintf("Xray writes %s but xray.access_log is %s", access, expected)
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

func hasHighRiskRoutingOutbound(cfg map[string]any, tag string) (bool, string) {
	routing, _ := cfg["routing"].(map[string]any)
	found := false
	for index, rule := range list(routing["rules"]) {
		m, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		if isCatchAllRoutingRule(m) && !found {
			return false, fmt.Sprintf("catch-all route at rule %d precedes %s abuse rules", index+1, tag)
		}
		if m["outboundTag"] == tag && (hasValues(m["ip"]) || hasValues(m["port"]) || hasValues(m["domain"])) {
			found = true
		}
	}
	if !found {
		return false, "requires an ip, port, or domain block rule"
	}
	return true, "abuse routes precede any catch-all route"
}

func isCatchAllRoutingRule(rule map[string]any) bool {
	if stringValue(rule["outboundTag"]) == "" {
		return false
	}
	for _, matcher := range []string{"inboundTag", "user", "protocol", "domain", "ip", "port", "network", "source", "sourcePort", "attrs"} {
		if hasValues(rule[matcher]) {
			return false
		}
	}
	return true
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
		if hasRequiredSniffing(sniffing) {
			enabledCount++
		}
	}
	if total == 0 {
		return false, "no user inbounds found"
	}
	return enabledCount == total, fmt.Sprintf("%d/%d user inbounds have required sniffing (enabled, http/tls/quic, routeOnly)", enabledCount, total)
}

func hasRequiredSniffing(sniffing map[string]any) bool {
	enabled, _ := sniffing["enabled"].(bool)
	routeOnly, _ := sniffing["routeOnly"].(bool)
	return enabled && routeOnly && contains(sniffing["destOverride"], "http") && contains(sniffing["destOverride"], "tls") && contains(sniffing["destOverride"], "quic")
}

// 3x-ui prepends these per-peer IPv6 egress rules to the saved routing rules.
// Checking only protocol rules misses the earlier inboundTag+user match.
func hasNoAmneziaWGRouteBypass(cfg map[string]any, torrentTag, blockedTag string) (bool, string) {
	routing, _ := cfg["routing"].(map[string]any)
	rules := list(routing["rules"])
	for i, rule := range rules {
		m, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		tag := stringValue(m["outboundTag"])
		if !strings.HasPrefix(tag, "amneziawg-v6-") || !hasValues(m["inboundTag"]) || !hasValues(m["user"]) {
			continue
		}
		for _, later := range rules[i+1:] {
			next, ok := later.(map[string]any)
			if !ok {
				continue
			}
			target := stringValue(next["outboundTag"])
			if target == torrentTag || target == blockedTag {
				return false, fmt.Sprintf("rule %d (%s, inbounds=%v, users=%v) can bypass later %s rules; disable per-client AmneziaWG IPv6 egress or fix the generated routing order in 3x-ui", i+1, tag, m["inboundTag"], m["user"], target)
			}
		}
	}
	return true, "no generated AmneziaWG IPv6 egress rule precedes abuse rules"
}

func isUserFacingInbound(inbound map[string]any) bool {
	if strings.EqualFold(stringValue(inbound["tag"]), "api") {
		return false
	}
	protocol := stringValue(inbound["protocol"])
	listen := strings.Trim(stringValue(inbound["listen"]), "[]")
	if (!strings.EqualFold(protocol, "socks") && !strings.EqualFold(protocol, "mixed")) || (listen != "127.0.0.1" && listen != "::1") {
		return true
	}
	// Authenticated loopback relays carry real client identities (AmneziaWG).
	// Anonymous internal proxies such as panel-egress remain excluded.
	settings, _ := inbound["settings"].(map[string]any)
	if !strings.EqualFold(stringValue(settings["auth"]), "password") {
		return false
	}
	for _, account := range list(settings["accounts"]) {
		m, ok := account.(map[string]any)
		if ok && stringValue(m["user"]) != "" {
			return true
		}
	}
	return false
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
