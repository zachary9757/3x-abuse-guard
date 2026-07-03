package policy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/detector"
	"github.com/zachary9757/3x-abuse-guard/internal/firewall"
	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
	"github.com/zachary9757/3x-abuse-guard/internal/notify"
	"github.com/zachary9757/3x-abuse-guard/internal/state"
)

type Panel interface {
	DisableClient(ctx context.Context, email string) error
}

type Store interface {
	RecordEvent(rec state.EventRecord) (state.EventRecord, error)
	SumScores(email string, sourceIP string, profile string, since time.Time) (int, error)
	UpsertBan(rec state.BanRecord) error
}

type Config struct {
	Window                 time.Duration
	BlockDuration          time.Duration
	TorrentBlockOnFirstHit bool
	TorrentDisableAfter    int
	BlockedDisableAfter    int
	BlockedNotifyAfter     int
	BypassIPs              []string
	ObserveOnly            bool
	Detectors              detector.Config
	Profiles               map[string]Profile
	Assignments            Assignments
}

type Profile struct {
	Name               string
	NotifyScore        int
	BlockIPScore       int
	DisableClientScore int
}

type Assignments struct {
	Emails   map[string]string
	Inbounds map[string]string
	Traffic  map[string]string
}

type Engine struct {
	cfg      Config
	store    Store
	fw       firewall.Firewall
	panel    Panel
	notifier notify.Notifier
	logger   *log.Logger
	pipeline *detector.Pipeline
	profiles map[string]Profile

	mu       sync.Mutex
	disabled map[string]time.Time
	notified map[string]time.Time
}

func NewEngine(cfg Config, store Store, fw firewall.Firewall, panel Panel, notifier notify.Notifier, logger *log.Logger) *Engine {
	if cfg.Window <= 0 {
		cfg.Window = time.Hour
	}
	if cfg.BlockDuration <= 0 {
		cfg.BlockDuration = 24 * time.Hour
	}
	if notifier == nil {
		notifier = notify.Noop{}
	}
	if logger == nil {
		logger = log.Default()
	}
	cfg.Detectors.Torrent.BlockIPOnHit = cfg.TorrentBlockOnFirstHit
	pipeline := detector.NewPipeline(cfg.Detectors)
	cfg.Detectors = pipeline.Config()
	profiles := normalizeProfiles(cfg)
	cfg.Assignments = normalizeAssignments(cfg.Assignments)
	return &Engine{
		cfg:      cfg,
		store:    store,
		fw:       fw,
		panel:    panel,
		notifier: notifier,
		logger:   logger,
		pipeline: pipeline,
		profiles: profiles,
		disabled: make(map[string]time.Time),
		notified: make(map[string]time.Time),
	}
}

func (e *Engine) Handle(ctx context.Context, ev logwatch.Event) error {
	if e.isBypassed(ev.SourceIP) {
		e.logger.Printf("skip bypassed ip %s for %s", ev.SourceIP, ev.Kind)
		return nil
	}

	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	findings := e.pipeline.Detect(ev, ev.Time)
	if len(findings) == 0 {
		return nil
	}
	for _, finding := range findings {
		if err := e.applyFinding(ctx, ev, finding); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) applyFinding(ctx context.Context, ev logwatch.Event, finding detector.Finding) error {
	profile := e.profileFor(ev, finding.Kind)
	if _, err := e.store.RecordEvent(state.EventRecord{
		Kind:      finding.Kind,
		Score:     finding.Score,
		Profile:   profile.Name,
		Reason:    finding.Reason,
		Email:     ev.Email,
		SourceIP:  ev.SourceIP,
		Target:    ev.Target,
		Inbound:   ev.Inbound,
		Outbound:  ev.Outbound,
		CreatedAt: finding.CreatedAt,
		Raw:       ev.Raw,
	}); err != nil {
		return err
	}
	total, err := e.store.SumScores(ev.Email, ev.SourceIP, profile.Name, finding.CreatedAt.Add(-e.cfg.Window))
	if err != nil {
		return err
	}

	if profile.NotifyScore > 0 && total >= profile.NotifyScore {
		e.notifyOnce(ctx, ev, finding, profile, total, profile.NotifyScore, fmt.Sprintf("%s score threshold reached: %d", profile.Name, total), finding.CreatedAt)
	}
	if !e.cfg.ObserveOnly && (finding.BlockIP || (profile.BlockIPScore > 0 && total >= profile.BlockIPScore)) {
		threshold := profile.BlockIPScore
		if threshold == 0 && finding.BlockIP {
			threshold = finding.Score
		}
		if err := e.blockIP(ctx, ev, finding, profile, total, threshold); err != nil {
			return err
		}
	}
	if !e.cfg.ObserveOnly && ev.Email != "" && e.panel != nil && profile.DisableClientScore > 0 && total >= profile.DisableClientScore {
		return e.disableClientOnce(ctx, ev, finding, profile, total, profile.DisableClientScore, fmt.Sprintf("%s score threshold reached: %d", finding.Kind, total))
	}
	return nil
}

func (e *Engine) blockIP(ctx context.Context, ev logwatch.Event, finding detector.Finding, profile Profile, score int, threshold int) error {
	expiresAt := time.Now().Add(e.cfg.BlockDuration)
	if err := e.fw.Block(ctx, ev.SourceIP); err != nil {
		return err
	}
	_ = e.fw.DropConnections(ctx, ev.SourceIP)
	if err := e.store.UpsertBan(state.BanRecord{
		IP:        ev.SourceIP,
		Email:     ev.Email,
		Reason:    finding.Reason,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}); err != nil {
		return err
	}
	_ = e.notifier.Notify(ctx, notificationEvent("ip_blocked", ev, finding, profile, score, threshold, finding.Reason, time.Now()))
	e.logger.Printf("blocked ip=%s email=%s reason=%s until=%s", ev.SourceIP, ev.Email, finding.Reason, expiresAt.Format(time.RFC3339))
	return nil
}

func (e *Engine) notifyOnce(ctx context.Context, ev logwatch.Event, finding detector.Finding, profile Profile, score int, threshold int, reason string, now time.Time) {
	key := actorKey(ev) + ":" + finding.Kind + ":notify"
	e.mu.Lock()
	last, ok := e.notified[key]
	if ok && now.Sub(last) < e.cfg.Window {
		e.mu.Unlock()
		return
	}
	e.notified[key] = now
	e.mu.Unlock()

	_ = e.notifier.Notify(ctx, notificationEvent("score_threshold", ev, finding, profile, score, threshold, reason, now))
}

func (e *Engine) disableClientOnce(ctx context.Context, ev logwatch.Event, finding detector.Finding, profile Profile, score int, threshold int, reason string) error {
	e.mu.Lock()
	last, ok := e.disabled[ev.Email]
	if ok && time.Since(last) < e.cfg.Window {
		e.mu.Unlock()
		return nil
	}
	e.disabled[ev.Email] = time.Now()
	e.mu.Unlock()

	if err := e.panel.DisableClient(ctx, ev.Email); err != nil {
		return err
	}
	_ = e.notifier.Notify(ctx, notificationEvent("client_disabled", ev, finding, profile, score, threshold, reason, time.Now()))
	e.logger.Printf("disabled client email=%s reason=%s", ev.Email, reason)
	return nil
}

func notificationEvent(action string, ev logwatch.Event, finding detector.Finding, profile Profile, score int, threshold int, reason string, timestamp time.Time) notify.Event {
	return notify.Event{
		Action:    action,
		Kind:      finding.Kind,
		Email:     ev.Email,
		IP:        ev.SourceIP,
		Reason:    reason,
		Profile:   profile.Name,
		Score:     score,
		Threshold: threshold,
		Target:    ev.Target,
		Inbound:   ev.Inbound,
		Outbound:  ev.Outbound,
		Timestamp: timestamp,
	}
}

func (e *Engine) isBypassed(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, item := range e.cfg.BypassIPs {
		if item == "" {
			continue
		}
		if candidate := net.ParseIP(item); candidate != nil && candidate.Equal(parsed) {
			return true
		}
		if _, cidr, err := net.ParseCIDR(item); err == nil && cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func (e *Engine) profileFor(ev logwatch.Event, kind string) Profile {
	if name := e.cfg.Assignments.Emails[ev.Email]; name != "" {
		return e.profileByName(name)
	}
	if name := e.cfg.Assignments.Inbounds[ev.Inbound]; name != "" {
		return e.profileByName(name)
	}
	if name := e.cfg.Assignments.Traffic[kind]; name != "" {
		return e.profileByName(name)
	}
	return e.profileByName("default")
}

func (e *Engine) profileByName(name string) Profile {
	if profile, ok := e.profiles[name]; ok {
		return profile
	}
	return e.profiles["default"]
}

func normalizeProfiles(cfg Config) map[string]Profile {
	profiles := map[string]Profile{}
	for name, profile := range cfg.Profiles {
		if profile.Name == "" {
			profile.Name = name
		}
		profiles[name] = profile
	}
	if _, ok := profiles["default"]; !ok {
		profiles["default"] = defaultProfile(cfg)
	}
	if _, ok := profiles["blocked_watch"]; !ok {
		profiles["blocked_watch"] = blockedWatchProfile()
	}
	if _, ok := profiles["heuristic"]; !ok {
		profiles["heuristic"] = heuristicProfile()
	}
	if cfg.ObserveOnly {
		for name, profile := range profiles {
			profile.BlockIPScore = 0
			profile.DisableClientScore = 0
			profiles[name] = profile
		}
	}
	return profiles
}

func normalizeAssignments(assignments Assignments) Assignments {
	if assignments.Traffic == nil {
		assignments.Traffic = map[string]string{}
	}
	if assignments.Traffic["blocked"] == "" {
		assignments.Traffic["blocked"] = "blocked_watch"
	}
	if assignments.Traffic["port_scan"] == "" {
		assignments.Traffic["port_scan"] = "heuristic"
	}
	if assignments.Traffic["connection_rate"] == "" {
		assignments.Traffic["connection_rate"] = "heuristic"
	}
	return assignments
}

func defaultProfile(cfg Config) Profile {
	torrentScore := cfg.Detectors.Torrent.Score
	if torrentScore <= 0 {
		torrentScore = 100
	}
	blockedScore := cfg.Detectors.Blocked.Score
	if blockedScore <= 0 {
		blockedScore = 10
	}
	disableScore := 0
	if cfg.TorrentDisableAfter > 0 {
		disableScore = torrentScore * cfg.TorrentDisableAfter
	}
	if cfg.BlockedDisableAfter > 0 {
		score := blockedScore * cfg.BlockedDisableAfter
		if disableScore == 0 || score < disableScore {
			disableScore = score
		}
	}
	notifyScore := 0
	if cfg.BlockedNotifyAfter > 0 {
		notifyScore = blockedScore * cfg.BlockedNotifyAfter
	}
	return Profile{
		Name:               "default",
		NotifyScore:        notifyScore,
		BlockIPScore:       80,
		DisableClientScore: disableScore,
	}
}

func blockedWatchProfile() Profile {
	return Profile{
		Name:               "blocked_watch",
		NotifyScore:        50,
		BlockIPScore:       0,
		DisableClientScore: 0,
	}
}

func heuristicProfile() Profile {
	return Profile{
		Name:               "heuristic",
		NotifyScore:        80,
		BlockIPScore:       0,
		DisableClientScore: 0,
	}
}

func actorKey(ev logwatch.Event) string {
	if ev.Email != "" {
		return "email:" + ev.Email
	}
	return "ip:" + ev.SourceIP
}
