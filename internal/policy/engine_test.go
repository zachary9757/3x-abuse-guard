package policy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

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
