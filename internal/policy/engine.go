package policy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

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
	CountEvents(email string, kind string, since time.Time) (int, error)
	UpsertBan(rec state.BanRecord) error
}

type Config struct {
	Window                  time.Duration
	BlockDuration           time.Duration
	TorrentBlockOnFirstHit  bool
	TorrentDisableAfter     int
	BlockedDisableAfter     int
	BlockedNotifyAfter      int
	BypassIPs               []string
}

type Engine struct {
	cfg      Config
	store    Store
	fw       firewall.Firewall
	panel    Panel
	notifier notify.Notifier
	logger   *log.Logger

	mu       sync.Mutex
	disabled map[string]time.Time
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
	return &Engine{
		cfg:      cfg,
		store:    store,
		fw:       fw,
		panel:    panel,
		notifier: notifier,
		logger:   logger,
		disabled: make(map[string]time.Time),
	}
}

func (e *Engine) Handle(ctx context.Context, ev logwatch.Event) error {
	if ev.Kind != logwatch.KindTorrent && ev.Kind != logwatch.KindBlocked {
		return nil
	}
	if e.isBypassed(ev.SourceIP) {
		e.logger.Printf("skip bypassed ip %s for %s", ev.SourceIP, ev.Kind)
		return nil
	}

	now := time.Now()
	if ev.Time.IsZero() {
		ev.Time = now
	}
	if _, err := e.store.RecordEvent(state.EventRecord{
		Kind:      string(ev.Kind),
		Email:     ev.Email,
		SourceIP:  ev.SourceIP,
		Target:    ev.Target,
		Inbound:   ev.Inbound,
		Outbound:  ev.Outbound,
		CreatedAt: ev.Time,
		Raw:       ev.Raw,
	}); err != nil {
		return err
	}

	switch ev.Kind {
	case logwatch.KindTorrent:
		return e.handleTorrent(ctx, ev, now)
	case logwatch.KindBlocked:
		return e.handleBlocked(ctx, ev, now)
	default:
		return nil
	}
}

func (e *Engine) handleTorrent(ctx context.Context, ev logwatch.Event, now time.Time) error {
	if e.cfg.TorrentBlockOnFirstHit {
		if err := e.blockIP(ctx, ev, "torrent"); err != nil {
			return err
		}
	}
	if ev.Email == "" || e.cfg.TorrentDisableAfter <= 0 || e.panel == nil {
		return nil
	}
	count, err := e.store.CountEvents(ev.Email, string(logwatch.KindTorrent), now.Add(-e.cfg.Window))
	if err != nil {
		return err
	}
	if count >= e.cfg.TorrentDisableAfter {
		return e.disableClientOnce(ctx, ev.Email, "torrent threshold reached")
	}
	return nil
}

func (e *Engine) handleBlocked(ctx context.Context, ev logwatch.Event, now time.Time) error {
	if ev.Email == "" {
		return nil
	}
	count, err := e.store.CountEvents(ev.Email, string(logwatch.KindBlocked), now.Add(-e.cfg.Window))
	if err != nil {
		return err
	}
	if e.cfg.BlockedNotifyAfter > 0 && count >= e.cfg.BlockedNotifyAfter {
		_ = e.notifier.Notify(ctx, notify.Event{
			Action:    "blocked_threshold",
			Kind:      string(ev.Kind),
			Email:     ev.Email,
			IP:        ev.SourceIP,
			Reason:    fmt.Sprintf("blocked threshold reached: %d", count),
			Timestamp: now,
		})
	}
	if e.cfg.BlockedDisableAfter > 0 && e.panel != nil && count >= e.cfg.BlockedDisableAfter {
		return e.disableClientOnce(ctx, ev.Email, "blocked threshold reached")
	}
	return nil
}

func (e *Engine) blockIP(ctx context.Context, ev logwatch.Event, reason string) error {
	expiresAt := time.Now().Add(e.cfg.BlockDuration)
	if err := e.fw.Block(ctx, ev.SourceIP); err != nil {
		return err
	}
	_ = e.fw.DropConnections(ctx, ev.SourceIP)
	if err := e.store.UpsertBan(state.BanRecord{
		IP:        ev.SourceIP,
		Email:     ev.Email,
		Reason:    reason,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}); err != nil {
		return err
	}
	_ = e.notifier.Notify(ctx, notify.Event{
		Action:    "ip_blocked",
		Kind:      string(ev.Kind),
		Email:     ev.Email,
		IP:        ev.SourceIP,
		Reason:    reason,
		Timestamp: time.Now(),
	})
	e.logger.Printf("blocked ip=%s email=%s reason=%s until=%s", ev.SourceIP, ev.Email, reason, expiresAt.Format(time.RFC3339))
	return nil
}

func (e *Engine) disableClientOnce(ctx context.Context, email string, reason string) error {
	e.mu.Lock()
	last, ok := e.disabled[email]
	if ok && time.Since(last) < e.cfg.Window {
		e.mu.Unlock()
		return nil
	}
	e.disabled[email] = time.Now()
	e.mu.Unlock()

	if err := e.panel.DisableClient(ctx, email); err != nil {
		return err
	}
	_ = e.notifier.Notify(ctx, notify.Event{
		Action:    "client_disabled",
		Email:     email,
		Reason:    reason,
		Timestamp: time.Now(),
	})
	e.logger.Printf("disabled client email=%s reason=%s", email, reason)
	return nil
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
