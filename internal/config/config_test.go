package config

import (
	"strings"
	"testing"
)

func TestExampleYAMLIncludesTelegramNotifyEnv(t *testing.T) {
	yaml := string(ExampleYAML())
	for _, want := range []string{
		`telegram_bot_token_env: THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN`,
		`telegram_chat_id_env: THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID`,
		`distinct_ports: 50`,
		`max_connections: 1500`,
		`blocked_watch:`,
		`heuristic:`,
		`notify_score: 80`,
		`block_ip_score: 0`,
		`blocked: blocked_watch`,
		`port_scan: heuristic`,
		`connection_rate: heuristic`,
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("example yaml missing %q:\n%s", want, yaml)
		}
	}
}

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{
			name: "panel url without scheme",
			change: func(cfg *Config) {
				cfg.Panel.BaseURL = "127.0.0.1:2053"
			},
			want: "panel.base_url",
		},
		{
			name: "same outbound tags",
			change: func(cfg *Config) {
				cfg.Xray.BlockedTag = cfg.Xray.TorrentTag
			},
			want: "must be different",
		},
		{
			name: "invalid bypass",
			change: func(cfg *Config) {
				cfg.Firewall.BypassIPs = []string{"not-an-ip"}
			},
			want: "invalid IP or CIDR",
		},
		{
			name: "unknown assigned profile",
			change: func(cfg *Config) {
				cfg.Policy.Assignments.Traffic["torrent"] = "missing"
			},
			want: "unknown profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.change(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateAppliesDefaultPolicyMode(t *testing.T) {
	cfg := Default()
	cfg.Policy.Mode = ""

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.Mode != "balanced" {
		t.Fatalf("policy mode = %q", cfg.Policy.Mode)
	}
}
