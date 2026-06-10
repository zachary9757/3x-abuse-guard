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
	Config config.Config
	Logger *log.Logger
	store  *state.Store
	fw     firewall.Firewall
	engine *policy.Engine
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

	policyCfg := policy.Config{
		Window:                 cfg.PolicyWindow(),
		BlockDuration:          cfg.BlockDuration(),
		TorrentBlockOnFirstHit: cfg.Policy.TorrentIPBlockOnFirstHit,
		TorrentDisableAfter:    cfg.Policy.TorrentDisableClientAfter,
		BlockedDisableAfter:    cfg.Policy.BlockedDisableClientAfter,
		BlockedNotifyAfter:     cfg.Policy.BlockedNotifyAfter,
		BypassIPs:              cfg.Firewall.BypassIPs,
	}
	switch cfg.Policy.Mode {
	case "observe":
		policyCfg.TorrentBlockOnFirstHit = false
		policyCfg.TorrentDisableAfter = 0
		policyCfg.BlockedDisableAfter = 0
	case "strict":
		policyCfg.TorrentBlockOnFirstHit = true
		policyCfg.TorrentDisableAfter = 1
	}

	var panelClient policy.Panel
	if policyCfg.TorrentDisableAfter > 0 || policyCfg.BlockedDisableAfter > 0 {
		p, _, err := newPanelClient(cfg)
		if err != nil {
			store.Close()
			return nil, err
		}
		panelClient = p
	}

	engine := policy.NewEngine(policyCfg, store, fw, panelClient, notify.NewWebhook(cfg.Notify.WebhookURL), logger)

	return &App{Config: cfg, Logger: logger, store: store, fw: fw, engine: engine}, nil
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

	lines := make(chan string, 100)
	tailer := logwatch.Tailer{
		Path:       a.Config.Xray.AccessLog,
		PollEvery: time.Second,
		StartAtEnd: true,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- tailer.Follow(ctx, lines)
	}()

	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()

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
			if err := a.engine.Handle(ctx, ev); err != nil {
				a.Logger.Printf("handle event failed: %v", err)
			}
		case <-cleanup.C:
			if err := a.cleanupExpiredBans(ctx); err != nil {
				a.Logger.Printf("cleanup failed: %v", err)
			}
		}
	}
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
