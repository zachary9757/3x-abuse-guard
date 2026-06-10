package app

import (
	"context"
	"fmt"
	"os"
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
	checks = append(checks, Check{"outbound "+cfg.Xray.TorrentTag, hasOutbound(xrayConfig, cfg.Xray.TorrentTag), "requires blackhole outbound"})
	checks = append(checks, Check{"outbound "+cfg.Xray.BlockedTag, hasOutbound(xrayConfig, cfg.Xray.BlockedTag), "requires blackhole outbound"})
	checks = append(checks, Check{"routing "+cfg.Xray.TorrentTag, hasRoutingOutbound(xrayConfig, cfg.Xray.TorrentTag), "requires protocol bittorrent rule"})
	checks = append(checks, Check{"routing "+cfg.Xray.BlockedTag, hasRoutingOutbound(xrayConfig, cfg.Xray.BlockedTag), "requires high-risk block rules"})
	checks = append(checks, Check{"sniffing", hasAnySniffing(xrayConfig), "at least one inbound has sniffing enabled"})
	return checks
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

func hasRoutingOutbound(cfg map[string]any, tag string) bool {
	routing, _ := cfg["routing"].(map[string]any)
	for _, rule := range list(routing["rules"]) {
		m, ok := rule.(map[string]any)
		if ok && m["outboundTag"] == tag {
			return true
		}
	}
	return false
}

func hasAnySniffing(cfg map[string]any) bool {
	for _, inbound := range list(cfg["inbounds"]) {
		m, ok := inbound.(map[string]any)
		if !ok {
			continue
		}
		sniffing, ok := m["sniffing"].(map[string]any)
		if !ok {
			continue
		}
		if enabled, ok := sniffing["enabled"].(bool); ok && enabled {
			return true
		}
	}
	return false
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
