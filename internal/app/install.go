package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
)

func Install(prefix string, binaryPath string) error {
	if prefix == "" {
		prefix = "/"
	}
	cfgPath := underPrefix(prefix, config.DefaultConfigPath)
	envPath := underPrefix(prefix, "/etc/3x-abuse-guard/env")
	stateDir := underPrefix(prefix, "/var/lib/3x-abuse-guard")
	logDir := underPrefix(prefix, config.DefaultLogDir)
	servicePath := underPrefix(prefix, "/etc/systemd/system/3x-abuse-guard.service")

	for _, dir := range []string{filepath.Dir(cfgPath), filepath.Dir(envPath), stateDir, logDir, filepath.Dir(servicePath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := os.WriteFile(cfgPath, config.ExampleYAML(), 0o600); err != nil {
			return err
		}
	}
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		env := `THREEX_ABUSE_GUARD_TOKEN=
THREEX_ABUSE_GUARD_USERNAME=
THREEX_ABUSE_GUARD_PASSWORD=
THREEX_ABUSE_GUARD_2FA_CODE=
THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN=
THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID=
`
		if err := os.WriteFile(envPath, []byte(env), 0o600); err != nil {
			return err
		}
	}
	if binaryPath == "" {
		binaryPath = "/usr/local/bin/3x-abuse-guard"
	}
	service := fmt.Sprintf(`[Unit]
Description=3x-ui Xray abuse guard
After=network-online.target x-ui.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/3x-abuse-guard/env
ExecStart=%s run --config /etc/3x-abuse-guard/config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, binaryPath)
	return os.WriteFile(servicePath, []byte(service), 0o644)
}

func underPrefix(prefix string, absolutePath string) string {
	if prefix == "/" {
		return absolutePath
	}
	return filepath.Join(prefix, strings.TrimPrefix(absolutePath, "/"))
}
