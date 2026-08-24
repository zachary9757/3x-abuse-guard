package detector

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
)

type Config struct {
	Torrent        BasicConfig          `yaml:"torrent"`
	Blocked        BasicConfig          `yaml:"blocked"`
	PortScan       PortScanConfig       `yaml:"port_scan"`
	ConnectionRate ConnectionRateConfig `yaml:"connection_rate"`
}

type BasicConfig struct {
	Enabled      bool `yaml:"enabled"`
	Score        int  `yaml:"score"`
	BlockIPOnHit bool `yaml:"block_ip_on_hit"`
}

type PortScanConfig struct {
	Enabled         bool `yaml:"enabled"`
	WindowMinutes   int  `yaml:"window_minutes"`
	DistinctPorts   int  `yaml:"distinct_ports"`
	Score           int  `yaml:"score"`
	CooldownMinutes int  `yaml:"cooldown_minutes"`
}

type ConnectionRateConfig struct {
	Enabled         bool `yaml:"enabled"`
	WindowMinutes   int  `yaml:"window_minutes"`
	MaxConnections  int  `yaml:"max_connections"`
	Score           int  `yaml:"score"`
	CooldownMinutes int  `yaml:"cooldown_minutes"`
}

type Finding struct {
	Kind      string
	Score     int
	Reason    string
	BlockIP   bool
	CreatedAt time.Time
}

type observation struct {
	at     time.Time
	port   int
	target string
}

type Pipeline struct {
	cfg Config

	portScanHistory map[string][]observation
	portScanLast    map[string]time.Time
	rateHistory     map[string][]observation
	rateLast        map[string]time.Time
}

func DefaultConfig() Config {
	return Config{
		Torrent: BasicConfig{
			Enabled:      true,
			Score:        100,
			BlockIPOnHit: true,
		},
		Blocked: BasicConfig{
			Enabled: true,
			Score:   10,
		},
		PortScan: PortScanConfig{
			Enabled:         true,
			WindowMinutes:   5,
			DistinctPorts:   50,
			Score:           80,
			CooldownMinutes: 5,
		},
		ConnectionRate: ConnectionRateConfig{
			Enabled:         true,
			WindowMinutes:   5,
			MaxConnections:  1500,
			Score:           60,
			CooldownMinutes: 5,
		},
	}
}

func NewPipeline(cfg Config) *Pipeline {
	cfg = withDefaults(cfg)
	return &Pipeline{
		cfg:             cfg,
		portScanHistory: make(map[string][]observation),
		portScanLast:    make(map[string]time.Time),
		rateHistory:     make(map[string][]observation),
		rateLast:        make(map[string]time.Time),
	}
}

func (p *Pipeline) Config() Config {
	return p.cfg
}

func (p *Pipeline) Detect(ev logwatch.Event, now time.Time) []Finding {
	if now.IsZero() {
		now = time.Now()
	}
	findings := []Finding{}

	if p.cfg.Torrent.Enabled && ev.Kind == logwatch.KindTorrent {
		findings = append(findings, Finding{
			Kind:      "torrent",
			Score:     p.cfg.Torrent.Score,
			Reason:    "torrent outbound hit",
			BlockIP:   p.cfg.Torrent.BlockIPOnHit,
			CreatedAt: now,
		})
	}
	if p.cfg.Blocked.Enabled && ev.Kind == logwatch.KindBlocked {
		findings = append(findings, Finding{
			Kind:      "blocked",
			Score:     p.cfg.Blocked.Score,
			Reason:    "blocked outbound hit",
			CreatedAt: now,
		})
	}
	if p.cfg.PortScan.Enabled {
		if finding, ok := p.detectPortScan(ev, now); ok {
			findings = append(findings, finding)
		}
	}
	if p.cfg.ConnectionRate.Enabled {
		if finding, ok := p.detectConnectionRate(ev, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func (p *Pipeline) detectPortScan(ev logwatch.Event, now time.Time) (Finding, bool) {
	port, ok := TargetPort(ev.Target)
	if !ok {
		return Finding{}, false
	}
	key := actorKey(ev)
	window := minutes(p.cfg.PortScan.WindowMinutes, 5)
	cutoff := now.Add(-window)
	observations := appendRecent(p.portScanHistory[key], cutoff, observation{at: now, port: port, target: ev.Target})
	p.portScanHistory[key] = observations

	ports := map[int]struct{}{}
	for _, obs := range observations {
		ports[obs.port] = struct{}{}
	}
	if len(ports) < defaultInt(p.cfg.PortScan.DistinctPorts, 8) {
		return Finding{}, false
	}
	if !cooldownReady(p.portScanLast[key], now, minutes(p.cfg.PortScan.CooldownMinutes, 5)) {
		return Finding{}, false
	}
	p.portScanLast[key] = now
	return Finding{
		Kind:      "port_scan",
		Score:     p.cfg.PortScan.Score,
		Reason:    fmt.Sprintf("distinct destination ports in window: %d", len(ports)),
		CreatedAt: now,
	}, true
}

func (p *Pipeline) detectConnectionRate(ev logwatch.Event, now time.Time) (Finding, bool) {
	key := actorKey(ev)
	window := minutes(p.cfg.ConnectionRate.WindowMinutes, 5)
	cutoff := now.Add(-window)
	observations := appendRecent(p.rateHistory[key], cutoff, observation{at: now, target: ev.Target})
	p.rateHistory[key] = observations

	threshold := defaultInt(p.cfg.ConnectionRate.MaxConnections, 300)
	if len(observations) < threshold {
		return Finding{}, false
	}
	if !cooldownReady(p.rateLast[key], now, minutes(p.cfg.ConnectionRate.CooldownMinutes, 5)) {
		return Finding{}, false
	}
	p.rateLast[key] = now
	return Finding{
		Kind:      "connection_rate",
		Score:     p.cfg.ConnectionRate.Score,
		Reason:    fmt.Sprintf("connections in window: %d", len(observations)),
		CreatedAt: now,
	}, true
}

func TargetPort(target string) (int, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, false
	}
	if _, port, err := net.SplitHostPort(target); err == nil {
		return parsePort(port)
	}
	idx := strings.LastIndex(target, ":")
	if idx < 0 || idx == len(target)-1 {
		return 0, false
	}
	return parsePort(target[idx+1:])
}

func parsePort(port string) (int, bool) {
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

func withDefaults(cfg Config) Config {
	def := DefaultConfig()
	if !cfg.Torrent.Enabled && cfg.Torrent.Score == 0 {
		cfg.Torrent = def.Torrent
	}
	if cfg.Torrent.Score <= 0 {
		cfg.Torrent.Score = def.Torrent.Score
	}
	if !cfg.Blocked.Enabled && cfg.Blocked.Score == 0 {
		cfg.Blocked = def.Blocked
	}
	if cfg.Blocked.Score <= 0 {
		cfg.Blocked.Score = def.Blocked.Score
	}
	if !cfg.PortScan.Enabled && cfg.PortScan.Score == 0 && cfg.PortScan.DistinctPorts == 0 {
		cfg.PortScan = def.PortScan
	}
	if cfg.PortScan.Score <= 0 {
		cfg.PortScan.Score = def.PortScan.Score
	}
	if !cfg.ConnectionRate.Enabled && cfg.ConnectionRate.Score == 0 && cfg.ConnectionRate.MaxConnections == 0 {
		cfg.ConnectionRate = def.ConnectionRate
	}
	if cfg.ConnectionRate.Score <= 0 {
		cfg.ConnectionRate.Score = def.ConnectionRate.Score
	}
	return cfg
}

func appendRecent(history []observation, cutoff time.Time, next observation) []observation {
	out := history[:0]
	for _, obs := range history {
		if !obs.at.Before(cutoff) {
			out = append(out, obs)
		}
	}
	return append(out, next)
}

func cooldownReady(last time.Time, now time.Time, cooldown time.Duration) bool {
	return last.IsZero() || !last.Add(cooldown).After(now)
}

func minutes(value int, fallback int) time.Duration {
	return time.Duration(defaultInt(value, fallback)) * time.Minute
}

func defaultInt(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func actorKey(ev logwatch.Event) string {
	if ev.Email != "" {
		return "email:" + ev.Email
	}
	return "ip:" + ev.SourceIP
}
