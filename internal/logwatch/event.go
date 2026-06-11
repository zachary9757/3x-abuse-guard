package logwatch

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type EventKind string

const (
	KindUnknown EventKind = "unknown"
	KindTorrent EventKind = "torrent"
	KindBlocked EventKind = "blocked"
	KindNormal  EventKind = "normal"
)

type Event struct {
	Time     time.Time
	SourceIP string
	Target   string
	Network  string
	Inbound  string
	Outbound string
	Email    string
	Raw      string
	Kind     EventKind
}

var accessLogPattern = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? from (.+?) accepted ([^:]+):(.+?) \[(.+?)\s+(?:>>|->)\s+(.+?)\](?: email: (.*))?$`)

func ParseLine(line string, torrentTag string, blockedTag string) (Event, bool) {
	line = strings.TrimSpace(line)
	m := accessLogPattern.FindStringSubmatch(line)
	if len(m) == 0 {
		return Event{}, false
	}

	ts, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], time.Local)
	if err != nil {
		ts = time.Now()
	}
	src, err := sourceIP(m[2])
	if err != nil {
		return Event{}, false
	}

	outbound := strings.TrimSpace(m[6])
	kind := KindNormal
	switch outbound {
	case torrentTag:
		kind = KindTorrent
	case blockedTag:
		kind = KindBlocked
	default:
		kind = KindNormal
	}

	return Event{
		Time:     ts,
		SourceIP: src,
		Target:   strings.TrimSpace(m[4]),
		Network:  strings.TrimSpace(m[3]),
		Inbound:  strings.TrimSpace(m[5]),
		Outbound: outbound,
		Email:    strings.TrimSpace(m[7]),
		Raw:      line,
		Kind:     kind,
	}, true
}

func sourceIP(value string) (string, error) {
	value = strings.TrimPrefix(value, "tcp:")
	value = strings.TrimPrefix(value, "udp:")
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]"), nil
	}
	lastColon := strings.LastIndex(value, ":")
	if lastColon <= 0 {
		return "", fmt.Errorf("missing source port")
	}
	host := strings.Trim(value[:lastColon], "[]")
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("invalid source ip: %s", host)
	}
	return host, nil
}
