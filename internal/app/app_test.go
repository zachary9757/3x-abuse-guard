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

func TestLegacyDisableThresholdExplicitZeroDisablesEnforcement(t *testing.T) {
	cfg := config.Default()
	zero := 0
	cfg.Policy.TorrentDisableClientAfter = &zero

	got := buildPolicyConfig(cfg)
	if got.Profiles["legacy_torrent"].DisableClientScore != 0 {
		t.Fatalf("legacy torrent disable score = %d", got.Profiles["legacy_torrent"].DisableClientScore)
	}
	if got.Profiles["default"].DisableClientScore != 200 {
		t.Fatalf("legacy threshold changed shared default profile: %+v", got.Profiles["default"])
	}
	if got.Assignments.Traffic["torrent"] != "legacy_torrent" {
		t.Fatalf("torrent assignment = %q", got.Assignments.Traffic["torrent"])
	}
	if needsPanel(got) {
		t.Fatal("explicit zero legacy threshold still requires panel enforcement")
	}
}

func TestLegacyBlockedThresholdsApplyToAssignedProfile(t *testing.T) {
	cfg := config.Default()
	disableAfter := 3
	notifyAfter := 2
	cfg.Policy.BlockedDisableClientAfter = &disableAfter
	cfg.Policy.BlockedNotifyAfter = &notifyAfter

	got := buildPolicyConfig(cfg)
	profile := got.Profiles["legacy_blocked"]
	if profile.DisableClientScore != 30 || profile.NotifyScore != 20 {
		t.Fatalf("blocked_watch profile = %+v", profile)
	}
}
