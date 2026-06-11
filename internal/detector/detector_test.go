package detector

import (
	"testing"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
)

func TestTargetPort(t *testing.T) {
	for _, target := range []string{"example.com:443", "198.51.100.10:22", "[2001:db8::1]:8443"} {
		if _, ok := TargetPort(target); !ok {
			t.Fatalf("expected port for %s", target)
		}
	}
	if _, ok := TargetPort("example.com"); ok {
		t.Fatal("unexpected port")
	}
}

func TestConnectionRateFinding(t *testing.T) {
	pipeline := NewPipeline(Config{
		Torrent: BasicConfig{
			Enabled: false,
			Score:   100,
		},
		Blocked: BasicConfig{
			Enabled: false,
			Score:   10,
		},
		ConnectionRate: ConnectionRateConfig{
			Enabled:        true,
			WindowMinutes:  5,
			MaxConnections: 3,
			Score:          60,
		},
	})
	now := time.Now()
	var findings []Finding
	for i := 0; i < 3; i++ {
		findings = pipeline.Detect(logwatch.Event{
			Time:     now.Add(time.Duration(i) * time.Second),
			SourceIP: "198.51.100.10",
			Target:   "example.com:443",
			Email:    "alice",
		}, now.Add(time.Duration(i)*time.Second))
	}
	if len(findings) != 1 || findings[0].Kind != "connection_rate" {
		t.Fatalf("findings = %#v", findings)
	}
}
