package logwatch

import "testing"

func TestParseLineTorrentIPv4(t *testing.T) {
	line := "2026/06/10 09:00:58.762908 from 183.208.48.85:6148 accepted tcp:example.com:443 [inbound-57579 >> TORRENT] email: alice"
	ev, ok := ParseLine(line, "TORRENT", "blocked")
	if !ok {
		t.Fatal("expected parse")
	}
	if ev.SourceIP != "183.208.48.85" || ev.Email != "alice" || ev.Kind != KindTorrent {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestParseLineBlockedIPv6(t *testing.T) {
	line := "2026/06/10 09:00:58 from [2001:db8::1]:6148 accepted tcp:1.1.1.1:25 [inbound-1 >> blocked]"
	ev, ok := ParseLine(line, "TORRENT", "blocked")
	if !ok {
		t.Fatal("expected parse")
	}
	if ev.SourceIP != "2001:db8::1" || ev.Email != "" || ev.Kind != KindBlocked {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestParseLineBlockedSingleArrow(t *testing.T) {
	line := "2026/06/10 09:00:58 from 183.208.48.85:6148 accepted tcp:1.1.1.1:25 [inbound-57570 -> blocked] email: alice"
	ev, ok := ParseLine(line, "TORRENT", "blocked")
	if !ok {
		t.Fatal("expected parse")
	}
	if ev.Inbound != "inbound-57570" || ev.Outbound != "blocked" || ev.Kind != KindBlocked {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestParseLineBlockedDetourArrow(t *testing.T) {
	line := "2026/06/10 09:00:58 from 183.208.48.85:6148 accepted tcp:1.1.1.1:25 [inbound-57570 ==> blocked] email: alice"
	ev, ok := ParseLine(line, "TORRENT", "blocked")
	if !ok {
		t.Fatal("expected parse")
	}
	if ev.Inbound != "inbound-57570" || ev.Outbound != "blocked" || ev.Kind != KindBlocked {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestParseLineNormal(t *testing.T) {
	line := "2026/06/10 09:00:58 from 183.208.48.85:6148 accepted tcp:example.com:443 [inbound-1 >> direct] email: bob"
	ev, ok := ParseLine(line, "TORRENT", "blocked")
	if !ok {
		t.Fatal("expected parse")
	}
	if ev.Kind != KindNormal {
		t.Fatalf("unexpected kind: %s", ev.Kind)
	}
}
