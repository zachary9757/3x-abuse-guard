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
		Profile:   "heuristic",
		Email:     "alice",
		SourceIP:  "198.51.100.11",
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	score, err := store.SumScores("alice", "", "heuristic", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if score != 80 {
		t.Fatalf("score = %d", score)
	}
	score, err = store.SumScores("alice", "", "default", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if score != 0 {
		t.Fatalf("default score = %d", score)
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

func TestStoreDoesNotHoldDatabaseLockBetweenOperations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	if _, err := first.RecordEvent(EventRecord{
		Kind:      "torrent",
		Email:     "alice",
		SourceIP:  "198.51.100.10",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	events, err := second.RecentEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d", len(events))
	}
}
