package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/detector"
	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/3x-abuse-guard/config.yaml"
	DefaultStatePath  = "/var/lib/3x-abuse-guard/state.db"
	DefaultLogDir     = "/var/log/3x-abuse-guard"
)

type Config struct {
	Panel     PanelConfig     `yaml:"panel"`
	Xray      XrayConfig      `yaml:"xray"`
	Detectors DetectorsConfig `yaml:"detectors"`
	Firewall  FirewallConfig  `yaml:"firewall"`
	Policy    PolicyConfig    `yaml:"policy"`
	Notify    NotifyConfig    `yaml:"notify"`
	State     StateConfig     `yaml:"state"`
	Logging   LoggingConfig   `yaml:"logging"`
}

type PanelConfig struct {
	BaseURL            string `yaml:"base_url"`
	AuthMode           string `yaml:"auth_mode"`
	TokenEnv           string `yaml:"token_env"`
	UsernameEnv        string `yaml:"username_env"`
	PasswordEnv        string `yaml:"password_env"`
	TwoFactorCodeEnv   string `yaml:"two_factor_code_env"`
	TimeoutSeconds     int    `yaml:"timeout_seconds"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	RestartXray        bool   `yaml:"restart_xray"`
}

type XrayConfig struct {
	AccessLog  string `yaml:"access_log"`
	TorrentTag string `yaml:"torrent_tag"`
	BlockedTag string `yaml:"blocked_tag"`
}

type DetectorsConfig = detector.Config

type FirewallConfig struct {
	Backend      string   `yaml:"backend"`
	Chain        string   `yaml:"chain"`
	BlockMinutes int      `yaml:"block_minutes"`
	BypassIPs    []string `yaml:"bypass_ips"`
}

type PolicyConfig struct {
	Mode                      string                         `yaml:"mode"`
	WindowMinutes             int                            `yaml:"window_minutes"`
	TorrentIPBlockOnFirstHit  bool                           `yaml:"torrent_ip_block_on_first_hit"`
	TorrentDisableClientAfter int                            `yaml:"torrent_disable_client_after"`
	BlockedDisableClientAfter int                            `yaml:"blocked_disable_client_after"`
	BlockedNotifyAfter        int                            `yaml:"blocked_notify_after"`
	Profiles                  map[string]PolicyProfileConfig `yaml:"profiles,omitempty"`
	Assignments               PolicyAssignmentsConfig        `yaml:"assignments,omitempty"`
}

type PolicyProfileConfig struct {
	NotifyScore        int `yaml:"notify_score"`
	BlockIPScore       int `yaml:"block_ip_score"`
	DisableClientScore int `yaml:"disable_client_score"`
}

type PolicyAssignmentsConfig struct {
	Emails   map[string]string `yaml:"emails,omitempty"`
	Inbounds map[string]string `yaml:"inbounds,omitempty"`
	Traffic  map[string]string `yaml:"traffic,omitempty"`
}

type NotifyConfig struct {
	WebhookURL          string `yaml:"webhook_url"`
	TelegramBotTokenEnv string `yaml:"telegram_bot_token_env"`
	TelegramChatIDEnv   string `yaml:"telegram_chat_id_env"`
}

type StateConfig struct {
	Path string `yaml:"path"`
}

type LoggingConfig struct {
	Dir string `yaml:"dir"`
}

func Default() Config {
	return Config{
		Panel: PanelConfig{
			BaseURL:            "http://127.0.0.1:2053/",
			AuthMode:           "auto",
			TokenEnv:           "THREEX_ABUSE_GUARD_TOKEN",
			UsernameEnv:        "THREEX_ABUSE_GUARD_USERNAME",
			PasswordEnv:        "THREEX_ABUSE_GUARD_PASSWORD",
			TwoFactorCodeEnv:   "THREEX_ABUSE_GUARD_2FA_CODE",
			TimeoutSeconds:     10,
			InsecureSkipVerify: false,
			RestartXray:        false,
		},
		Xray: XrayConfig{
			AccessLog:  "/var/log/x-ui/access.log",
			TorrentTag: "TORRENT",
			BlockedTag: "blocked",
		},
		Detectors: detector.DefaultConfig(),
		Firewall: FirewallConfig{
			Backend:      "iptables",
			Chain:        "THREEX_ABUSE_GUARD",
			BlockMinutes: 1440,
			BypassIPs:    []string{"127.0.0.1", "::1"},
		},
		Policy: PolicyConfig{
			Mode:                      "balanced",
			WindowMinutes:             60,
			TorrentIPBlockOnFirstHit:  true,
			TorrentDisableClientAfter: 2,
			BlockedDisableClientAfter: 0,
			BlockedNotifyAfter:        5,
			Profiles: map[string]PolicyProfileConfig{
				"default": {
					NotifyScore:        50,
					BlockIPScore:       80,
					DisableClientScore: 200,
				},
				"strict": {
					NotifyScore:        30,
					BlockIPScore:       60,
					DisableClientScore: 100,
				},
				"observe": {
					NotifyScore:        50,
					BlockIPScore:       0,
					DisableClientScore: 0,
				},
				"heuristic": {
					NotifyScore:        80,
					BlockIPScore:       320,
					DisableClientScore: 0,
				},
			},
			Assignments: PolicyAssignmentsConfig{
				Emails:   map[string]string{},
				Inbounds: map[string]string{},
				Traffic: map[string]string{
					"port_scan":       "heuristic",
					"connection_rate": "heuristic",
				},
			},
		},
		Notify: NotifyConfig{
			TelegramBotTokenEnv: "THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN",
			TelegramChatIDEnv:   "THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID",
		},
		State:   StateConfig{Path: DefaultStatePath},
		Logging: LoggingConfig{Dir: DefaultLogDir},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Panel.BaseURL == "" {
		return errors.New("panel.base_url is required")
	}
	if _, err := url.ParseRequestURI(c.Panel.BaseURL); err != nil {
		return fmt.Errorf("panel.base_url is invalid: %w", err)
	}
	switch c.Panel.AuthMode {
	case "", "auto", "token", "login":
	default:
		return errors.New("panel.auth_mode must be auto, token, or login")
	}
	if c.Panel.AuthMode != "login" && c.Panel.TokenEnv == "" {
		return errors.New("panel.token_env is required")
	}
	if c.Panel.AuthMode != "token" && c.Panel.UsernameEnv == "" {
		return errors.New("panel.username_env is required")
	}
	if c.Panel.AuthMode != "token" && c.Panel.PasswordEnv == "" {
		return errors.New("panel.password_env is required")
	}
	if c.Panel.TimeoutSeconds <= 0 {
		return errors.New("panel.timeout_seconds must be positive")
	}
	if c.Xray.AccessLog == "" {
		return errors.New("xray.access_log is required")
	}
	if c.Xray.TorrentTag == "" {
		return errors.New("xray.torrent_tag is required")
	}
	if c.Xray.BlockedTag == "" {
		return errors.New("xray.blocked_tag is required")
	}
	switch c.Firewall.Backend {
	case "iptables", "nft", "noop":
	default:
		return fmt.Errorf("firewall.backend must be iptables, nft, or noop")
	}
	if c.Firewall.Chain == "" {
		return errors.New("firewall.chain is required")
	}
	if c.Firewall.BlockMinutes <= 0 {
		return errors.New("firewall.block_minutes must be positive")
	}
	if c.Policy.Mode == "" {
		c.Policy.Mode = "balanced"
	}
	if c.Policy.Mode != "balanced" && c.Policy.Mode != "strict" && c.Policy.Mode != "observe" {
		return errors.New("policy.mode must be balanced, strict, or observe")
	}
	if c.Policy.WindowMinutes <= 0 {
		return errors.New("policy.window_minutes must be positive")
	}
	if c.State.Path == "" {
		return errors.New("state.path is required")
	}
	return nil
}

func (c Config) PanelTimeout() time.Duration {
	return time.Duration(c.Panel.TimeoutSeconds) * time.Second
}

func (c Config) PolicyWindow() time.Duration {
	return time.Duration(c.Policy.WindowMinutes) * time.Minute
}

func (c Config) BlockDuration() time.Duration {
	return time.Duration(c.Firewall.BlockMinutes) * time.Minute
}

func ExampleYAML() []byte {
	cfg := Default()
	out, _ := yaml.Marshal(cfg)
	return out
}
