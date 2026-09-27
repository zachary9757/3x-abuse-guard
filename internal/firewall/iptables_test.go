package firewall

import (
	"context"
	"strings"
	"testing"
)

type recordingRunner struct {
	calls []string
	failC bool
	fail  string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if r.failC && strings.Contains(call, " -C ") {
		return assertErr{}
	}
	if r.fail != "" && strings.Contains(call, r.fail) {
		return assertErr{}
	}
	return nil
}

func TestIPTablesSetupReturnsIPv6Failure(t *testing.T) {
	runner := &recordingRunner{fail: "ip6tables"}
	firewall := &IPTables{Chain: "TEST", Runner: runner}
	if err := firewall.Setup(context.Background()); err == nil {
		t.Fatal("expected IPv6 setup failure")
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "missing" }

func TestIPTablesBlock(t *testing.T) {
	r := &recordingRunner{failC: true}
	f := &IPTables{Chain: "TEST", Runner: r}
	if err := f.Block(context.Background(), "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(r.calls, "\n")
	if !strings.Contains(got, "iptables -t raw -A TEST -s 198.51.100.10 -j DROP") {
		t.Fatalf("unexpected calls:\n%s", got)
	}
}
