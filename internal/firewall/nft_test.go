package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type nftRunner struct {
	elementExists bool
	calls         []string
}

func (r *nftRunner) Run(_ context.Context, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, " get element ") && !r.elementExists {
		return errors.New("element not found")
	}
	return nil
}

func TestNFTablesBlockAddsMissingElement(t *testing.T) {
	runner := &nftRunner{}
	fw := &NFTables{Table: "TEST", Chain: "TEST", Runner: runner}

	if err := fw.Block(context.Background(), "198.51.100.10"); err != nil {
		t.Fatal(err)
	}

	got := strings.Join(runner.calls, "\n")
	if !strings.Contains(got, "nft get element inet TEST blocked4 { 198.51.100.10 }") {
		t.Fatalf("missing element lookup:\n%s", got)
	}
	if !strings.Contains(got, "nft add element inet TEST blocked4 { 198.51.100.10 }") {
		t.Fatalf("missing element add:\n%s", got)
	}
}

func TestNFTablesBlockSkipsExistingElement(t *testing.T) {
	runner := &nftRunner{elementExists: true}
	fw := &NFTables{Table: "TEST", Chain: "TEST", Runner: runner}

	if err := fw.Block(context.Background(), "2001:db8::10"); err != nil {
		t.Fatal(err)
	}

	if len(runner.calls) != 1 || !strings.Contains(runner.calls[0], "blocked6") {
		t.Fatalf("calls = %v", runner.calls)
	}
}
