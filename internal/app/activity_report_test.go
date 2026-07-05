package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
	"github.com/zachary9757/3x-abuse-guard/internal/notify"
)

func TestActivityStatsDailyReport(t *testing.T) {
	stats := newActivityStats()
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

	report, ok := stats.DailyReport(day)
	if !ok {
		t.Fatal("expected report")
	}
	for _, want := range []string{
		"3x-abuse-guard 每日上网行为统计",
		"日期: 2026-07-04",
		"(北京时间)",
		"客户端数: 2",
		"总连接: 3",
		"1. alice",
		"连接: 2",
		"访问目标Top: example.com:443(2)",
		"2. ip:198.51.100.20",
		"出站: blocked(1)",
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

func TestSendDailyAccessReportDeletesDayAfterNotify(t *testing.T) {
	stats := newActivityStats()
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
	if _, ok := stats.DailyReport(day); ok {
		t.Fatal("expected reported day to be deleted")
	}
}

func TestSendPendingAccessReportsLeavesFutureDay(t *testing.T) {
	stats := newActivityStats()
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
	if _, ok := stats.DailyReport(day); ok {
		t.Fatal("expected sent day to be deleted")
	}
	if report, ok := stats.DailyReport(nextDay); !ok || !strings.Contains(report, "bob") {
		t.Fatalf("expected future day to remain, report=%q ok=%v", report, ok)
	}
}

func TestActivityStatsGroupsUTCEventsByBeijingDay(t *testing.T) {
	stats := newActivityStats()
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

	report, ok := stats.DailyReport(beijingDay)
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
	text  string
	calls int
}

func (n *captureTextNotifier) Notify(context.Context, notify.Event) error {
	return nil
}

func (n *captureTextNotifier) NotifyText(_ context.Context, text string) error {
	n.text = text
	n.calls++
	return nil
}
