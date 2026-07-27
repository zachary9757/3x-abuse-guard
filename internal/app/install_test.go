package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWritesFiles(t *testing.T) {
	root := t.TempDir()
	if err := Install(root, "/usr/local/bin/3x-abuse-guard"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/etc/3x-abuse-guard/config.yaml",
		"/etc/3x-abuse-guard/env",
		"/etc/systemd/system/3x-abuse-guard.service",
		"/var/lib/3x-abuse-guard",
		"/var/log/3x-abuse-guard",
	} {
		if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(path, "/"))); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "etc/3x-abuse-guard/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	configYAML := string(data)
	for _, want := range []string{
		"blocked_watch:",
		"heuristic:",
		"block_ip_score: 0",
		"blocked: blocked_watch",
		"port_scan: heuristic",
		"connection_rate: heuristic",
		"distinct_ports: 50",
		"max_connections: 1500",
	} {
		if !strings.Contains(configYAML, want) {
			t.Fatalf("config missing %q:\n%s", want, configYAML)
		}
	}
	envData, err := os.ReadFile(filepath.Join(root, "etc/3x-abuse-guard/env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN=",
		"THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID=",
	} {
		if !strings.Contains(string(envData), want) {
			t.Fatalf("env missing %q:\n%s", want, envData)
		}
	}
}
