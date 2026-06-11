package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreEventsAndBans(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now()
	if _, err := store.RecordEvent(EventRecord{
		Kind:      "torrent",
		Email:     "alice",
		SourceIP:  "198.51.100.10",
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	count, err := store.CountEvents("alice", "torrent", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count = %d", count)
	}
	if _, err := store.RecordEvent(EventRecord{
		Kind:      "port_scan",
		Score:     80,
		Email:     "alice",
		SourceIP:  "198.51.100.11",
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	score, err := store.SumScores("alice", "", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if score != 80 {
		t.Fatalf("score = %d", score)
	}

	if err := store.UpsertBan(BanRecord{
		IP:        "198.51.100.10",
		Email:     "alice",
		Reason:    "torrent",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	bans, err := store.ListBans(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("len(bans) = %d", len(bans))
	}
}
