package logwatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailerReadsAppendedLinesAndTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tailer := Tailer{Path: path, PollEvery: 10 * time.Millisecond, StartAtEnd: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 10)
	errCh := make(chan error, 1)
	go func() { errCh <- tailer.Follow(ctx, lines) }()
	time.Sleep(30 * time.Millisecond)

	if err := appendFile(path, "new\n"); err != nil {
		t.Fatal(err)
	}
	got := waitLine(t, lines)
	if got != "new\n" {
		t.Fatalf("line = %q", got)
	}

	if err := os.WriteFile(path, []byte("after-truncate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = waitLine(t, lines)
	if got != "after-truncate\n" {
		t.Fatalf("line after truncate = %q", got)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("tailer did not stop")
	}
}

func TestTailerWaitsForCompleteLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	tailer := Tailer{Path: path, PollEvery: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 10)
	go func() { _ = tailer.Follow(ctx, lines) }()

	if err := appendFile(path, "part"); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		t.Fatalf("received partial line %q", line)
	case <-time.After(50 * time.Millisecond):
	}

	if err := appendFile(path, "ial\n"); err != nil {
		t.Fatal(err)
	}
	if got := waitLine(t, lines); got != "partial\n" {
		t.Fatalf("line = %q", got)
	}
}

func TestTailerReadsReplacementFileLargerThanOldOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tailer := Tailer{Path: path, PollEvery: 10 * time.Millisecond, StartAtEnd: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 10)
	go func() { _ = tailer.Follow(ctx, lines) }()
	time.Sleep(30 * time.Millisecond)

	if err := os.Rename(path, filepath.Join(dir, "access.log.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement-is-larger\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := waitLine(t, lines); got != "replacement-is-larger\n" {
		t.Fatalf("line = %q", got)
	}
}

func appendFile(path string, text string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(text)
	return err
}

func waitLine(t *testing.T, lines <-chan string) string {
	t.Helper()
	select {
	case line := <-lines:
		return line
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for line")
		return ""
	}
}
