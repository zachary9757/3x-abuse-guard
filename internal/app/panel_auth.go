package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
	"github.com/zachary9757/3x-abuse-guard/internal/panel"
)

func newPanelClient(cfg config.Config) (*panel.Client, string, error) {
	mode := cfg.Panel.AuthMode
	if mode == "" {
		mode = "auto"
	}

	token := envValue(cfg.Panel.TokenEnv)
	username := envValue(cfg.Panel.UsernameEnv)
	password := envValue(cfg.Panel.PasswordEnv)
	twoFactorCode := envValue(cfg.Panel.TwoFactorCodeEnv)
	opts := panelOptions(cfg)

	switch mode {
	case "token":
		if token == "" {
			return nil, "", fmt.Errorf("missing 3x-ui API token in %s", cfg.Panel.TokenEnv)
		}
		client, err := panel.New(cfg.Panel.BaseURL, token, cfg.PanelTimeout(), opts...)
		return client, "token", err
	case "login":
		if username == "" || password == "" {
			return nil, "", fmt.Errorf("missing 3x-ui login credentials in %s/%s", cfg.Panel.UsernameEnv, cfg.Panel.PasswordEnv)
		}
		client, err := panel.NewWithLogin(cfg.Panel.BaseURL, username, password, twoFactorCode, cfg.PanelTimeout(), opts...)
		return client, "login", err
	case "auto":
		if token != "" {
			client, err := panel.New(cfg.Panel.BaseURL, token, cfg.PanelTimeout(), opts...)
			return client, "token", err
		}
		if username != "" && password != "" {
			client, err := panel.NewWithLogin(cfg.Panel.BaseURL, username, password, twoFactorCode, cfg.PanelTimeout(), opts...)
			return client, "login", err
		}
		return nil, "", fmt.Errorf("missing 3x-ui auth: set %s or %s/%s", cfg.Panel.TokenEnv, cfg.Panel.UsernameEnv, cfg.Panel.PasswordEnv)
	default:
		return nil, "", fmt.Errorf("unsupported panel auth mode: %s", mode)
	}
}

func panelOptions(cfg config.Config) []panel.Option {
	if cfg.Panel.InsecureSkipVerify {
		return []panel.Option{panel.WithInsecureSkipVerify()}
	}
	return nil
}

func envValue(name string) string {
	if name == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}
