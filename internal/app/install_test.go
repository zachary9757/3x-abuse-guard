package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWritesFiles(t *testing.T) {
	root := t.TempDir()
	if err := Install(root, "/usr/local/bin/3x-abuse-guard"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/etc/3x-abuse-guard/config.yaml",
		"/etc/3x-abuse-guard/env",
		"/etc/systemd/system/3x-abuse-guard.service",
		"/var/lib/3x-abuse-guard",
		"/var/log/3x-abuse-guard",
	} {
		if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(path, "/"))); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
}
