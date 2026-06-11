package policy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/detector"
	"github.com/zachary9757/3x-abuse-guard/internal/firewall"
	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
	"github.com/zachary9757/3x-abuse-guard/internal/notify"
	"github.com/zachary9757/3x-abuse-guard/internal/state"
)

type fakePanel struct {
	disabled []string
}

func (p *fakePanel) DisableClient(_ context.Context, email string) error {
	p.disabled = append(p.disabled, email)
	return nil
}

type recordingNotifier struct {
	events []notify.Event
}

func (n *recordingNotifier) Notify(_ context.Context, event notify.Event) error {
	n.events = append(n.events, event)
	return nil
}

func TestTorrentBlocksAndDisablesAfterThreshold(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fw := &firewall.Noop{}
	panel := &fakePanel{}
	engine := NewEngine(Config{
		Window:                 time.Hour,
		BlockDuration:          time.Hour,
		TorrentBlockOnFirstHit: true,
		TorrentDisableAfter:    2,
	}, store, fw, panel, notify.Noop{}, nil)

	ev := logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindTorrent,
		SourceIP: "198.51.100.10",
		Email:    "alice",
		Outbound: "TORRENT",
	}
	if err := engine.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	ev.SourceIP = "198.51.100.11"
	if err := engine.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(fw.Blocked) != 2 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(panel.disabled) != 1 || panel.disabled[0] != "alice" {
		t.Fatalf("disabled = %v", panel.disabled)
	}
}

func TestBypassIP(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fw := &firewall.Noop{}
	engine := NewEngine(Config{
		Window:                 time.Hour,
		BlockDuration:          time.Hour,
		TorrentBlockOnFirstHit: true,
		TorrentDisableAfter:    1,
		BypassIPs:              []string{"198.51.100.0/24"},
	}, store, fw, nil, notify.Noop{}, nil)

	if err := engine.Handle(context.Background(), logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindTorrent,
		SourceIP: "198.51.100.10",
		Email:    "alice",
	}); err != nil {
		t.Fatal(err)
	}
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
}

func TestScoreThresholdNotificationIncludesContext(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	notifier := &recordingNotifier{}
	engine := NewEngine(Config{
		Window:        time.Hour,
		BlockDuration: time.Hour,
		Profiles: map[string]Profile{
			"default": {
				Name:        "default",
				NotifyScore: 10,
			},
		},
	}, store, &firewall.Noop{}, nil, notifier, nil)

	if err := engine.Handle(context.Background(), logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindBlocked,
		SourceIP: "198.51.100.10",
		Email:    "alice",
		Target:   "example.com:22",
		Inbound:  "inbound-1",
		Outbound: "blocked",
	}); err != nil {
		t.Fatal(err)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("events = %v", notifier.events)
	}
	got := notifier.events[0]
	if got.Action != "score_threshold" || got.Kind != "blocked" {
		t.Fatalf("event action/kind = %s/%s", got.Action, got.Kind)
	}
	if got.Score != 10 || got.Threshold != 10 || got.Profile != "default" {
		t.Fatalf("event score/threshold/profile = %d/%d/%s", got.Score, got.Threshold, got.Profile)
	}
	if got.Email != "alice" || got.IP != "198.51.100.10" || got.Target != "example.com:22" {
		t.Fatalf("event actor context = email:%s ip:%s target:%s", got.Email, got.IP, got.Target)
	}
	if got.Inbound != "inbound-1" || got.Outbound != "blocked" {
		t.Fatalf("event route context = inbound:%s outbound:%s", got.Inbound, got.Outbound)
	}
}

func TestPortScanDetectorBlocksAfterDistinctPorts(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fw := &firewall.Noop{}
	notifier := &recordingNotifier{}
	engine := NewEngine(Config{
		Window:        time.Hour,
		BlockDuration: time.Hour,
		Detectors: detector.Config{
			PortScan: detector.PortScanConfig{
				Enabled:       true,
				WindowMinutes: 5,
				DistinctPorts: 3,
				Score:         80,
			},
			ConnectionRate: detector.ConnectionRateConfig{
				Enabled: false,
				Score:   60,
			},
		},
	}, store, fw, nil, notifier, nil)

	for _, target := range []string{"example.com:22", "example.com:23", "example.com:445"} {
		if err := engine.Handle(context.Background(), logwatch.Event{
			Time:     time.Now(),
			Kind:     logwatch.KindNormal,
			SourceIP: "198.51.100.10",
			Target:   target,
			Inbound:  "inbound-1",
			Outbound: "direct",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(fw.Blocked) != 1 || fw.Blocked[0] != "198.51.100.10" {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("events = %v", notifier.events)
	}
	got := notifier.events[0]
	if got.Action != "ip_blocked" || got.Kind != "port_scan" {
		t.Fatalf("event action/kind = %s/%s", got.Action, got.Kind)
	}
	if got.Score != 80 || got.Threshold != 80 || got.Profile != "default" {
		t.Fatalf("event score/threshold/profile = %d/%d/%s", got.Score, got.Threshold, got.Profile)
	}
	if got.Target != "example.com:445" || got.Inbound != "inbound-1" || got.Outbound != "direct" {
		t.Fatalf("event context = target:%s inbound:%s outbound:%s", got.Target, got.Inbound, got.Outbound)
	}
}
