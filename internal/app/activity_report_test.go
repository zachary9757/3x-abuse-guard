package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
	"github.com/zachary9757/3x-abuse-guard/internal/notify"
)

func TestActivityStatsDailyReport(t *testing.T) {
	stats := newActivityStats("TORRENT", "blocked")
	day := time.Date(2026, 7, 4, 0, 0, 0, 0, reportLocation)

	stats.Record(logwatch.Event{
		Time:     day.Add(10 * time.Minute),
		SourceIP: "198.51.100.10",
		Target:   "example.com:443",
		Network:  "tcp",
		Inbound:  "inbound-1",
		Outbound: "direct",
		Email:    "alice",
		Kind:     logwatch.KindNormal,
	})
	stats.Record(logwatch.Event{
		Time:     day.Add(20 * time.Minute),
		SourceIP: "198.51.100.10",
		Target:   "example.com:443",
		Network:  "tcp",
		Inbound:  "inbound-1",
		Outbound: "direct",
		Email:    "alice",
		Kind:     logwatch.KindNormal,
	})
	stats.Record(logwatch.Event{
		Time:     day.Add(30 * time.Minute),
		SourceIP: "198.51.100.20",
		Target:   "1.1.1.1:25",
		Network:  "tcp",
		Inbound:  "inbound-2",
		Outbound: "blocked",
		Kind:     logwatch.KindBlocked,
	})
	stats.Record(logwatch.Event{
		Time:     day.AddDate(0, 0, 1).Add(time.Minute),
		SourceIP: "198.51.100.30",
		Target:   "next-day.example:443",
		Network:  "tcp",
		Inbound:  "inbound-3",
		Outbound: "direct",
		Email:    "carol",
		Kind:     logwatch.KindNormal,
	})

	report, ok := pendingActivityReport(stats, day)
	if !ok {
		t.Fatal("expected report")
	}
	for _, want := range []string{
		"3x-abuse-guard 每日代理请求统计",
		"日期: 2026-07-04",
		"(北京时间)",
		"客户端数: 2",
		"总请求: 3",
		"出站命中: TORRENT(0), blocked(1), CN_BLOCKED(0), shared-direct(0), direct(2)",
		"1. alice",
		"请求: 2",
		"访问目标Top: example.com:443(2)",
		"2. ip:198.51.100.20",
		"出站命中: blocked(1)",
		"类型: blocked(1)",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "next-day.example") {
		t.Fatalf("report included next day data:\n%s", report)
	}
}

func TestActivityReportCountsAllOutbounds(t *testing.T) {
	stats := newActivityStats("bt-denied", "risk-denied")
	day := time.Date(2026, 7, 4, 0, 0, 0, 0, reportLocation)
	for _, tag := range []string{"shared-direct", "CN_BLOCKED", "direct", "shared-direct", "risk-denied", "bt-denied", "relay"} {
		stats.Record(logwatch.Event{Time: day, Email: "alice", Outbound: tag})
	}
	report, _ := pendingActivityReport(stats, day)
	for _, want := range []string{
		"总请求: 7",
		"出站命中: bt-denied(1), risk-denied(1), CN_BLOCKED(1), shared-direct(2), direct(1), relay(1)",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}

func TestSendDailyAccessReportDeletesDayAfterNotify(t *testing.T) {
	stats := newActivityStats("TORRENT", "blocked")
	day := time.Date(2026, 7, 4, 0, 0, 0, 0, reportLocation)
	stats.Record(logwatch.Event{
		Time:     day.Add(time.Hour),
		SourceIP: "198.51.100.10",
		Target:   "example.com:443",
		Network:  "tcp",
		Inbound:  "inbound-1",
		Outbound: "direct",
		Email:    "alice",
		Kind:     logwatch.KindNormal,
	})
	notifier := &captureTextNotifier{}
	app := &App{activity: stats, notifier: notifier}

	if err := app.sendDailyAccessReport(context.Background(), day); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(notifier.text, "alice") {
		t.Fatalf("text = %q", notifier.text)
	}
	if _, ok := pendingActivityReport(stats, day); ok {
		t.Fatal("expected reported day to be deleted")
	}
}

func TestSendDailyAccessReportPreservesRequestsRecordedDuringSend(t *testing.T) {
	sendErr := errors.New("temporary send failure")
	for _, tc := range []struct {
		name   string
		err    error
		starts string
		total  string
	}{
		{name: "success", starts: "02:00:00", total: "总请求: 2"},
		{name: "failure", err: sendErr, starts: "01:00:00", total: "总请求: 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := newActivityStats("TORRENT", "blocked")
			day := time.Date(2026, 7, 4, 0, 0, 0, 0, reportLocation)
			stats.Record(logwatch.Event{Time: day.Add(time.Hour), Email: "alice", Outbound: "direct"})
			notifier := &captureTextNotifier{onSend: func() error {
				stats.Record(logwatch.Event{Time: day.Add(2 * time.Hour), Email: "alice", Outbound: "shared-direct"})
				stats.Record(logwatch.Event{Time: day.Add(3 * time.Hour), Email: "bob", Outbound: "CN_BLOCKED"})
				return tc.err
			}}
			app := &App{activity: stats, notifier: notifier}
			if err := app.sendDailyAccessReport(context.Background(), day); !errors.Is(err, tc.err) {
				t.Fatalf("sendDailyAccessReport error = %v, want %v", err, tc.err)
			}
			if !strings.Contains(notifier.text, "总请求: 1") {
				t.Fatalf("sent report:\n%s", notifier.text)
			}
			report, ok := pendingActivityReport(stats, day)
			if !ok || !strings.Contains(report, tc.total) || !strings.Contains(report, "活跃: "+tc.starts+" - 02:00:00") || !strings.Contains(report, "bob") {
				t.Fatalf("pending report:\n%s", report)
			}
		})
	}
}

func TestSendPendingAccessReportsLeavesFutureDay(t *testing.T) {
	stats := newActivityStats("TORRENT", "blocked")
	day := time.Date(2026, 7, 4, 0, 0, 0, 0, reportLocation)
	nextDay := day.AddDate(0, 0, 1)
	stats.Record(logwatch.Event{
		Time:     day.Add(time.Hour),
		SourceIP: "198.51.100.10",
		Target:   "example.com:443",
		Network:  "tcp",
		Inbound:  "inbound-1",
		Outbound: "direct",
		Email:    "alice",
		Kind:     logwatch.KindNormal,
	})
	stats.Record(logwatch.Event{
		Time:     nextDay.Add(time.Hour),
		SourceIP: "198.51.100.20",
		Target:   "next.example:443",
		Network:  "tcp",
		Inbound:  "inbound-2",
		Outbound: "direct",
		Email:    "bob",
		Kind:     logwatch.KindNormal,
	})
	notifier := &captureTextNotifier{}
	app := &App{activity: stats, notifier: notifier}

	if err := app.sendPendingAccessReports(context.Background(), day); err != nil {
		t.Fatal(err)
	}
	if notifier.calls != 1 {
		t.Fatalf("calls = %d", notifier.calls)
	}
	if _, ok := pendingActivityReport(stats, day); ok {
		t.Fatal("expected sent day to be deleted")
	}
	if report, ok := pendingActivityReport(stats, nextDay); !ok || !strings.Contains(report, "bob") {
		t.Fatalf("expected future day to remain, report=%q ok=%v", report, ok)
	}
}

func TestActivityStatsGroupsUTCEventsByBeijingDay(t *testing.T) {
	stats := newActivityStats("TORRENT", "blocked")
	eventTime := time.Date(2026, 7, 3, 16, 30, 0, 0, time.UTC)
	beijingDay := time.Date(2026, 7, 4, 0, 0, 0, 0, reportLocation)
	stats.Record(logwatch.Event{
		Time:     eventTime,
		SourceIP: "198.51.100.10",
		Target:   "example.com:443",
		Network:  "tcp",
		Inbound:  "inbound-1",
		Outbound: "direct",
		Email:    "alice",
		Kind:     logwatch.KindNormal,
	})

	report, ok := pendingActivityReport(stats, beijingDay)
	if !ok {
		t.Fatal("expected Beijing-day report")
	}
	for _, want := range []string{
		"日期: 2026-07-04",
		"活跃: 00:30:00 - 00:30:00",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}

func TestNextMidnightAfterUsesBeijingTime(t *testing.T) {
	now := time.Date(2026, 7, 4, 15, 59, 30, 0, time.UTC)
	want := time.Date(2026, 7, 5, 0, 0, 0, 0, reportLocation)
	if got := nextMidnightAfter(now); !got.Equal(want) {
		t.Fatalf("nextMidnightAfter = %s, want %s", got, want)
	}
	if got := timeUntilNextMidnight(now); got != 30*time.Second {
		t.Fatalf("timeUntilNextMidnight = %s", got)
	}
	if got := reportDayFor(want); dayKey(got) != "2026-07-04" {
		t.Fatalf("report day = %s", got)
	}
}

type captureTextNotifier struct {
	text   string
	calls  int
	onSend func() error
}

func (n *captureTextNotifier) Notify(context.Context, notify.Event) error {
	return nil
}

func (n *captureTextNotifier) NotifyText(_ context.Context, text string) error {
	n.text = text
	n.calls++
	if n.onSend != nil {
		return n.onSend()
	}
	return nil
}

func pendingActivityReport(stats *activityStats, day time.Time) (string, bool) {
	key := dayKey(day)
	clients := stats.days[key]
	if len(clients) == 0 {
		return "", false
	}
	return formatActivityReport(key, clients, stats.outboundTags), true
}
