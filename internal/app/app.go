package app

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
	"github.com/zachary9757/3x-abuse-guard/internal/firewall"
	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
	"github.com/zachary9757/3x-abuse-guard/internal/notify"
	"github.com/zachary9757/3x-abuse-guard/internal/policy"
	"github.com/zachary9757/3x-abuse-guard/internal/state"
)

type App struct {
	Config         config.Config
	Logger         *log.Logger
	store          *state.Store
	fw             firewall.Firewall
	engine         *policy.Engine
	notifier       notify.Notifier
	activity       *activityStats
	lastEventPrune time.Time
}

func New(cfg config.Config, logger *log.Logger) (*App, error) {
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	store, err := state.Open(cfg.State.Path)
	if err != nil {
		return nil, err
	}
	fw, err := firewall.New(cfg.Firewall.Backend, cfg.Firewall.Chain)
	if err != nil {
		store.Close()
		return nil, err
	}

	policyCfg := buildPolicyConfig(cfg)

	var panelClient policy.Panel
	if needsPanel(policyCfg) {
		p, _, err := newPanelClient(cfg)
		if err != nil {
			store.Close()
			return nil, err
		}
		panelClient = p
	}

	notifier := newNotifier(cfg)
	engine := policy.NewEngine(policyCfg, store, fw, panelClient, notifier, logger)

	return &App{Config: cfg, Logger: logger, store: store, fw: fw, engine: engine, notifier: notifier, activity: newActivityStats()}, nil
}

func buildPolicyConfig(cfg config.Config) policy.Config {
	policyCfg := policy.Config{
		Window:                 cfg.PolicyWindow(),
		BlockDuration:          cfg.BlockDuration(),
		TorrentBlockOnFirstHit: cfg.Policy.TorrentIPBlockOnFirstHit,
		BypassIPs:              cfg.Firewall.BypassIPs,
		Detectors:              cfg.Detectors,
		Profiles:               policyProfiles(cfg),
		Assignments:            policyAssignments(cfg),
	}
	applyLegacyPolicyThresholds(&policyCfg, cfg)
	switch cfg.Policy.Mode {
	case "observe":
		policyCfg.ObserveOnly = true
		policyCfg.TorrentBlockOnFirstHit = false
		policyCfg.TorrentDisableAfter = 0
		policyCfg.BlockedDisableAfter = 0
	case "strict":
		policyCfg.TorrentBlockOnFirstHit = true
		policyCfg.TorrentDisableAfter = 1
		strictProfile := policyCfg.Profiles["strict"]
		if strictProfile.Name == "" {
			strictProfile = policyCfg.Profiles["default"]
			strictProfile.Name = "strict"
		}
		torrentScore := cfg.Detectors.Torrent.Score
		if torrentScore <= 0 {
			torrentScore = 100
		}
		strictProfile.DisableClientScore = torrentScore
		if policyCfg.Profiles == nil {
			policyCfg.Profiles = make(map[string]policy.Profile)
		}
		policyCfg.Profiles["strict"] = strictProfile
		if policyCfg.Assignments.Traffic == nil {
			policyCfg.Assignments.Traffic = make(map[string]string)
		}
		policyCfg.Assignments.Traffic["torrent"] = "strict"
	}
	return policyCfg
}

// applyLegacyPolicyThresholds preserves old configurations that used hit counts.
// New configurations should use profiles as the single policy source of truth.
func applyLegacyPolicyThresholds(policyCfg *policy.Config, cfg config.Config) {
	if policyCfg == nil {
		return
	}
	if value := cfg.Policy.TorrentDisableClientAfter; value != nil {
		policyCfg.TorrentDisableAfter = *value
		profileName := isolateLegacyProfile(policyCfg, "torrent", "default", "legacy_torrent")
		profile := policyCfg.Profiles[profileName]
		profile.DisableClientScore = cfg.Detectors.Torrent.Score * *value
		policyCfg.Profiles[profileName] = profile
	}
	if value := cfg.Policy.BlockedDisableClientAfter; value != nil {
		policyCfg.BlockedDisableAfter = *value
		profileName := isolateLegacyProfile(policyCfg, "blocked", "blocked_watch", "legacy_blocked")
		profile := policyCfg.Profiles[profileName]
		profile.DisableClientScore = cfg.Detectors.Blocked.Score * *value
		policyCfg.Profiles[profileName] = profile
	}
	if value := cfg.Policy.BlockedNotifyAfter; value != nil {
		policyCfg.BlockedNotifyAfter = *value
		profileName := isolateLegacyProfile(policyCfg, "blocked", "blocked_watch", "legacy_blocked")
		profile := policyCfg.Profiles[profileName]
		profile.NotifyScore = cfg.Detectors.Blocked.Score * *value
		policyCfg.Profiles[profileName] = profile
	}
}

func isolateLegacyProfile(policyCfg *policy.Config, traffic, fallback, legacyName string) string {
	if policyCfg.Assignments.Traffic == nil {
		policyCfg.Assignments.Traffic = make(map[string]string)
	}
	if policyCfg.Assignments.Traffic[traffic] == legacyName {
		return legacyName
	}
	sourceName := policyCfg.Assignments.Traffic[traffic]
	if sourceName == "" {
		sourceName = fallback
	}
	profile := policyCfg.Profiles[sourceName]
	profile.Name = legacyName
	policyCfg.Profiles[legacyName] = profile
	policyCfg.Assignments.Traffic[traffic] = legacyName
	if policyCfg.ScoreProfileAliases == nil {
		policyCfg.ScoreProfileAliases = make(map[string]string)
	}
	policyCfg.ScoreProfileAliases[legacyName] = sourceName
	return legacyName
}

func newNotifier(cfg config.Config) notify.Notifier {
	return notify.New(notify.Config{
		WebhookURL:       cfg.Notify.WebhookURL,
		TelegramBotToken: envValue(cfg.Notify.TelegramBotTokenEnv),
		TelegramChatID:   envValue(cfg.Notify.TelegramChatIDEnv),
	})
}

func policyProfiles(cfg config.Config) map[string]policy.Profile {
	if len(cfg.Policy.Profiles) == 0 {
		return nil
	}
	profiles := make(map[string]policy.Profile, len(cfg.Policy.Profiles))
	for name, profile := range cfg.Policy.Profiles {
		profiles[name] = policy.Profile{
			Name:               name,
			NotifyScore:        profile.NotifyScore,
			BlockIPScore:       profile.BlockIPScore,
			DisableClientScore: profile.DisableClientScore,
		}
	}
	return profiles
}

func policyAssignments(cfg config.Config) policy.Assignments {
	return policy.Assignments{
		Emails:   cloneAssignments(cfg.Policy.Assignments.Emails),
		Inbounds: cloneAssignments(cfg.Policy.Assignments.Inbounds),
		Traffic:  cloneAssignments(cfg.Policy.Assignments.Traffic),
	}
}

func cloneAssignments(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func needsPanel(cfg policy.Config) bool {
	if cfg.ObserveOnly {
		return false
	}
	if cfg.TorrentDisableAfter > 0 || cfg.BlockedDisableAfter > 0 {
		return true
	}
	reachable := map[string]struct{}{}
	for _, assignments := range []map[string]string{cfg.Assignments.Emails, cfg.Assignments.Inbounds, cfg.Assignments.Traffic} {
		for _, profileName := range assignments {
			reachable[profileName] = struct{}{}
		}
	}
	for _, kind := range []string{"torrent", "blocked", "port_scan", "connection_rate"} {
		if cfg.Assignments.Traffic[kind] == "" {
			reachable["default"] = struct{}{}
		}
	}
	for profileName := range reachable {
		if cfg.Profiles[profileName].DisableClientScore > 0 {
			return true
		}
	}
	return false
}

func (a *App) Close() error {
	if a == nil || a.store == nil {
		return nil
	}
	return a.store.Close()
}

func (a *App) Run(ctx context.Context) error {
	if err := a.fw.Setup(ctx); err != nil {
		return err
	}
	if err := a.restoreBans(ctx); err != nil {
		return err
	}
	if err := a.pruneExpiredEvents(time.Now()); err != nil {
		return err
	}

	lines := make(chan string, 100)
	tailer := logwatch.Tailer{
		Path:       a.Config.Xray.AccessLog,
		PollEvery:  time.Second,
		StartAtEnd: true,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- tailer.Follow(ctx, lines)
	}()

	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()
	reportTimer := time.NewTimer(timeUntilNextMidnight(time.Now()))
	defer reportTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err == context.Canceled {
				return nil
			}
			return err
		case line := <-lines:
			ev, ok := logwatch.ParseLine(line, a.Config.Xray.TorrentTag, a.Config.Xray.BlockedTag)
			if !ok {
				continue
			}
			a.activity.Record(ev)
			if err := a.engine.Handle(ctx, ev); err != nil {
				a.Logger.Printf("handle event failed: %v", err)
			}
		case <-cleanup.C:
			a.engine.Cleanup(time.Now())
			if err := a.cleanupExpiredBans(ctx); err != nil {
				a.Logger.Printf("cleanup failed: %v", err)
			}
			if err := a.pruneExpiredEvents(time.Now()); err != nil {
				a.Logger.Printf("event retention cleanup failed: %v", err)
			}
		case now := <-reportTimer.C:
			if err := a.sendPendingAccessReports(ctx, reportDayFor(now)); err != nil {
				a.Logger.Printf("daily access report failed: %v", err)
			}
			reportTimer.Reset(timeUntilNextMidnight(time.Now()))
		}
	}
}

func (a *App) pruneExpiredEvents(now time.Time) error {
	days := a.Config.State.EventRetentionDays
	if days <= 0 || (!a.lastEventPrune.IsZero() && now.Sub(a.lastEventPrune) < time.Hour) {
		return nil
	}
	if _, err := a.store.DeleteEventsBefore(now.AddDate(0, 0, -days)); err != nil {
		return err
	}
	a.lastEventPrune = now
	return nil
}

func (a *App) HandleTestEvent(ctx context.Context, email string, ip string, tag string) error {
	kind := logwatch.KindNormal
	if tag == a.Config.Xray.TorrentTag {
		kind = logwatch.KindTorrent
	} else if tag == a.Config.Xray.BlockedTag {
		kind = logwatch.KindBlocked
	}
	return a.engine.Handle(ctx, logwatch.Event{
		Time:     time.Now(),
		SourceIP: ip,
		Email:    email,
		Outbound: tag,
		Kind:     kind,
		Raw:      "manual test event",
	})
}

func (a *App) Status(now time.Time) ([]state.BanRecord, []state.EventRecord, error) {
	bans, err := a.store.ListBans(now)
	if err != nil {
		return nil, nil, err
	}
	events, err := a.store.RecentEvents(20)
	if err != nil {
		return nil, nil, err
	}
	return bans, events, nil
}

func (a *App) Unblock(ctx context.Context, ip string) error {
	if err := a.fw.Unblock(ctx, ip); err != nil {
		return err
	}
	return a.store.RemoveBan(ip)
}

func (a *App) restoreBans(ctx context.Context) error {
	bans, err := a.store.ListBans(time.Now())
	if err != nil {
		return err
	}
	for _, ban := range bans {
		if err := a.fw.Block(ctx, ban.IP); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) cleanupExpiredBans(ctx context.Context) error {
	expired, err := a.store.ExpiredBans(time.Now())
	if err != nil {
		return err
	}
	for _, ban := range expired {
		if err := a.fw.Unblock(ctx, ban.IP); err != nil {
			return err
		}
		if err := a.store.RemoveBan(ban.IP); err != nil {
			return err
		}
		a.Logger.Printf("unblocked expired ip=%s", ban.IP)
	}
	return nil
}
