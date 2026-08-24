package policy

import (
	"context"
	"errors"
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

type flakyPanel struct {
	calls int
}

func (p *flakyPanel) DisableClient(_ context.Context, _ string) error {
	p.calls++
	if p.calls == 1 {
		return errors.New("temporary panel failure")
	}
	return nil
}

type flakyNotifier struct {
	calls int
}

func (n *flakyNotifier) Notify(_ context.Context, _ notify.Event) error {
	n.calls++
	if n.calls == 1 {
		return errors.New("temporary webhook failure")
	}
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

func TestDisableClientRetriesAfterPanelFailure(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	panel := &flakyPanel{}
	engine := NewEngine(Config{
		Window:        time.Hour,
		BlockDuration: time.Hour,
		Profiles: map[string]Profile{
			"default": {
				Name:               "default",
				DisableClientScore: 100,
			},
		},
	}, store, &firewall.Noop{}, panel, notify.Noop{}, nil)
	ev := logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindTorrent,
		SourceIP: "198.51.100.10",
		Email:    "alice",
		Outbound: "TORRENT",
	}

	if err := engine.Handle(context.Background(), ev); err == nil {
		t.Fatal("expected first panel call to fail")
	}
	ev.Time = ev.Time.Add(time.Second)
	if err := engine.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if panel.calls != 2 {
		t.Fatalf("panel calls = %d", panel.calls)
	}
}

func TestNotificationRetriesAfterFailure(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	notifier := &flakyNotifier{}
	engine := NewEngine(Config{
		Window:        time.Hour,
		BlockDuration: time.Hour,
		Profiles: map[string]Profile{
			"default": {
				Name:        "default",
				NotifyScore: 10,
			},
		},
		Assignments: Assignments{
			Traffic: map[string]string{"blocked": "default"},
		},
	}, store, &firewall.Noop{}, nil, notifier, nil)
	ev := logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindBlocked,
		SourceIP: "198.51.100.10",
		Email:    "alice",
		Outbound: "blocked",
	}

	if err := engine.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	ev.Time = ev.Time.Add(time.Second)
	if err := engine.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if notifier.calls != 2 {
		t.Fatalf("notifier calls = %d", notifier.calls)
	}
}

func TestBypassIPSkipsBlockButKeepsClientEnforcement(t *testing.T) {
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
		TorrentDisableAfter:    1,
		BypassIPs:              []string{"127.0.0.1"},
	}, store, fw, panel, notify.Noop{}, nil)

	if err := engine.Handle(context.Background(), logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindTorrent,
		SourceIP: "127.0.0.1",
		Email:    "alice",
		Inbound:  "amneziawg-1",
		Outbound: "TORRENT",
	}); err != nil {
		t.Fatal(err)
	}
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(panel.disabled) != 1 || panel.disabled[0] != "alice" {
		t.Fatalf("disabled = %v", panel.disabled)
	}
	events, err := store.RecentEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Email != "alice" || events[0].SourceIP != "127.0.0.1" {
		t.Fatalf("events = %#v", events)
	}
}

func TestBypassIPWithoutClientIdentityIsIgnored(t *testing.T) {
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
		BypassIPs:              []string{"127.0.0.1"},
	}, store, fw, nil, notify.Noop{}, nil)

	if err := engine.Handle(context.Background(), logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindTorrent,
		SourceIP: "127.0.0.1",
		Outbound: "TORRENT",
	}); err != nil {
		t.Fatal(err)
	}
	events, err := store.RecentEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("events = %#v", events)
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
		Assignments: Assignments{
			Traffic: map[string]string{
				"blocked": "default",
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

func TestDefaultConnectionRateNotifiesBeforeBlockThreshold(t *testing.T) {
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
				Enabled: false,
				Score:   80,
			},
			ConnectionRate: detector.ConnectionRateConfig{
				Enabled:         true,
				WindowMinutes:   5,
				MaxConnections:  3,
				Score:           60,
				CooldownMinutes: 5,
			},
		},
	}, store, fw, nil, notifier, nil)

	start := time.Now()
	for group := 0; group < 2; group++ {
		base := start.Add(time.Duration(group*6) * time.Minute)
		for i := 0; i < 3; i++ {
			if err := engine.Handle(context.Background(), logwatch.Event{
				Time:     base.Add(time.Duration(i) * time.Second),
				Kind:     logwatch.KindNormal,
				SourceIP: "198.51.100.10",
				Email:    "alice",
				Target:   "example.com:443",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("events = %v", notifier.events)
	}
	got := notifier.events[0]
	if got.Action != "score_threshold" || got.Kind != "connection_rate" {
		t.Fatalf("event action/kind = %s/%s", got.Action, got.Kind)
	}
	if got.Score != 120 || got.Threshold != 80 || got.Profile != "heuristic" {
		t.Fatalf("event score/threshold/profile = %d/%d/%s", got.Score, got.Threshold, got.Profile)
	}
}

func TestDefaultConnectionRateDoesNotAutoBlockAfterSustainedFindings(t *testing.T) {
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
				Enabled: false,
				Score:   80,
			},
			ConnectionRate: detector.ConnectionRateConfig{
				Enabled:         true,
				WindowMinutes:   5,
				MaxConnections:  3,
				Score:           60,
				CooldownMinutes: 5,
			},
		},
	}, store, fw, nil, notifier, nil)

	start := time.Now()
	for group := 0; group < 6; group++ {
		base := start.Add(time.Duration(group*6) * time.Minute)
		for i := 0; i < 3; i++ {
			if err := engine.Handle(context.Background(), logwatch.Event{
				Time:     base.Add(time.Duration(i) * time.Second),
				Kind:     logwatch.KindNormal,
				SourceIP: "198.51.100.10",
				Email:    "alice",
				Target:   "example.com:443",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("events = %v", notifier.events)
	}
	got := notifier.events[0]
	if got.Action != "score_threshold" || got.Kind != "connection_rate" {
		t.Fatalf("event action/kind = %s/%s", got.Action, got.Kind)
	}
	if got.Score != 120 || got.Threshold != 80 || got.Profile != "heuristic" {
		t.Fatalf("event score/threshold/profile = %d/%d/%s", got.Score, got.Threshold, got.Profile)
	}
}

func TestHeuristicScoresDoNotContributeToDefaultBlock(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fw := &firewall.Noop{}
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
	}, store, fw, nil, notify.Noop{}, nil)

	for _, target := range []string{"example.com:22", "example.com:23", "example.com:445"} {
		if err := engine.Handle(context.Background(), logwatch.Event{
			Time:     time.Now(),
			Kind:     logwatch.KindNormal,
			SourceIP: "198.51.100.10",
			Email:    "alice",
			Target:   target,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Handle(context.Background(), logwatch.Event{
		Time:     time.Now(),
		Kind:     logwatch.KindBlocked,
		SourceIP: "198.51.100.10",
		Email:    "alice",
		Target:   "example.com:25",
		Outbound: "blocked",
	}); err != nil {
		t.Fatal(err)
	}
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
}

func TestDefaultBlockedOnlyNotifies(t *testing.T) {
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
	}, store, fw, nil, notifier, nil)

	for i := 0; i < 8; i++ {
		if err := engine.Handle(context.Background(), logwatch.Event{
			Time:     time.Now().Add(time.Duration(i) * time.Second),
			Kind:     logwatch.KindBlocked,
			SourceIP: "198.51.100.10",
			Email:    "alice",
			Target:   "example.com:25",
			Outbound: "blocked",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("events = %v", notifier.events)
	}
	got := notifier.events[0]
	if got.Action != "score_threshold" || got.Kind != "blocked" {
		t.Fatalf("event action/kind = %s/%s", got.Action, got.Kind)
	}
	if got.Score != 50 || got.Threshold != 50 || got.Profile != "blocked_watch" {
		t.Fatalf("event score/threshold/profile = %d/%d/%s", got.Score, got.Threshold, got.Profile)
	}
}

func TestBlockedCanBlockWhenAssignedToDefaultProfile(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fw := &firewall.Noop{}
	engine := NewEngine(Config{
		Window:        time.Hour,
		BlockDuration: time.Hour,
		Assignments: Assignments{
			Traffic: map[string]string{
				"blocked": "default",
			},
		},
	}, store, fw, nil, notify.Noop{}, nil)

	for i := 0; i < 8; i++ {
		if err := engine.Handle(context.Background(), logwatch.Event{
			Time:     time.Now().Add(time.Duration(i) * time.Second),
			Kind:     logwatch.KindBlocked,
			SourceIP: "198.51.100.10",
			Email:    "alice",
			Target:   "example.com:25",
			Outbound: "blocked",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(fw.Blocked) != 1 || fw.Blocked[0] != "198.51.100.10" {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
}

func TestDefaultPortScanNotifiesBeforeBlockThreshold(t *testing.T) {
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
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("events = %v", notifier.events)
	}
	got := notifier.events[0]
	if got.Action != "score_threshold" || got.Kind != "port_scan" {
		t.Fatalf("event action/kind = %s/%s", got.Action, got.Kind)
	}
	if got.Score != 80 || got.Threshold != 80 || got.Profile != "heuristic" {
		t.Fatalf("event score/threshold/profile = %d/%d/%s", got.Score, got.Threshold, got.Profile)
	}
	if got.Target != "example.com:445" || got.Inbound != "inbound-1" || got.Outbound != "direct" {
		t.Fatalf("event context = target:%s inbound:%s outbound:%s", got.Target, got.Inbound, got.Outbound)
	}
}

func TestDefaultPortScanDoesNotAutoBlockAfterSustainedFindings(t *testing.T) {
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
				Enabled:         true,
				WindowMinutes:   5,
				DistinctPorts:   3,
				Score:           80,
				CooldownMinutes: 5,
			},
			ConnectionRate: detector.ConnectionRateConfig{
				Enabled: false,
				Score:   60,
			},
		},
	}, store, fw, nil, notifier, nil)

	groups := [][]string{
		{"example.com:1001", "example.com:1002", "example.com:1003"},
		{"example.com:1011", "example.com:1012", "example.com:1013"},
		{"example.com:1021", "example.com:1022", "example.com:1023"},
		{"example.com:1031", "example.com:1032", "example.com:1033"},
	}
	start := time.Now()
	for group, targets := range groups {
		base := start.Add(time.Duration(group*6) * time.Minute)
		for i, target := range targets {
			if err := engine.Handle(context.Background(), logwatch.Event{
				Time:     base.Add(time.Duration(i) * time.Second),
				Kind:     logwatch.KindNormal,
				SourceIP: "198.51.100.10",
				Email:    "alice",
				Target:   target,
				Inbound:  "inbound-1",
				Outbound: "direct",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(fw.Blocked) != 0 {
		t.Fatalf("blocked = %v", fw.Blocked)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("events = %v", notifier.events)
	}
	got := notifier.events[0]
	if got.Action != "score_threshold" || got.Kind != "port_scan" {
		t.Fatalf("event action/kind = %s/%s", got.Action, got.Kind)
	}
	if got.Score != 80 || got.Threshold != 80 || got.Profile != "heuristic" {
		t.Fatalf("event score/threshold/profile = %d/%d/%s", got.Score, got.Threshold, got.Profile)
	}
}

func TestPortScanCanBlockWhenAssignedToDefaultProfile(t *testing.T) {
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
		Assignments: Assignments{
			Traffic: map[string]string{
				"port_scan": "default",
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
}
