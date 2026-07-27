package app

import (
	"testing"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
)

func TestBuildPolicyConfigStrictDisablesTorrentOnFirstHit(t *testing.T) {
	cfg := config.Default()
	cfg.Policy.Mode = "strict"

	got := buildPolicyConfig(cfg)

	if !got.TorrentBlockOnFirstHit || got.TorrentDisableAfter != 1 {
		t.Fatalf("strict torrent behavior = block:%t disable_after:%d", got.TorrentBlockOnFirstHit, got.TorrentDisableAfter)
	}
	if got.Assignments.Traffic["torrent"] != "strict" {
		t.Fatalf("torrent profile = %q", got.Assignments.Traffic["torrent"])
	}
	if got.Profiles["strict"].DisableClientScore != cfg.Detectors.Torrent.Score {
		t.Fatalf("strict disable score = %d", got.Profiles["strict"].DisableClientScore)
	}
}

func TestBuildPolicyConfigDoesNotMutateConfigAssignments(t *testing.T) {
	cfg := config.Default()
	cfg.Policy.Mode = "strict"

	_ = buildPolicyConfig(cfg)

	if _, ok := cfg.Policy.Assignments.Traffic["torrent"]; ok {
		t.Fatal("buildPolicyConfig mutated source assignments")
	}
}
