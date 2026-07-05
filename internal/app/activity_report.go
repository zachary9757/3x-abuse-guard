package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/logwatch"
	"github.com/zachary9757/3x-abuse-guard/internal/notify"
)

const activityReportTopN = 5

var reportLocation = time.FixedZone("Asia/Shanghai", 8*60*60)

type activityStats struct {
	mu   sync.Mutex
	days map[string]map[string]*clientActivity
}

type clientActivity struct {
	Actor       string
	Connections int
	FirstSeen   time.Time
	LastSeen    time.Time
	SourceIPs   map[string]int
	Targets     map[string]int
	Inbounds    map[string]int
	Outbounds   map[string]int
	Kinds       map[string]int
	Networks    map[string]int
}

func newActivityStats() *activityStats {
	return &activityStats{days: map[string]map[string]*clientActivity{}}
}

func (s *activityStats) Record(ev logwatch.Event) {
	if s == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	actor := ev.Email
	if actor == "" && ev.SourceIP != "" {
		actor = "ip:" + ev.SourceIP
	}
	if actor == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	day := dayKey(ev.Time)
	if s.days[day] == nil {
		s.days[day] = map[string]*clientActivity{}
	}
	stats := s.days[day][actor]
	if stats == nil {
		stats = &clientActivity{
			Actor:     actor,
			SourceIPs: map[string]int{},
			Targets:   map[string]int{},
			Inbounds:  map[string]int{},
			Outbounds: map[string]int{},
			Kinds:     map[string]int{},
			Networks:  map[string]int{},
		}
		s.days[day][actor] = stats
	}

	stats.Connections++
	if stats.FirstSeen.IsZero() || ev.Time.Before(stats.FirstSeen) {
		stats.FirstSeen = ev.Time
	}
	if stats.LastSeen.IsZero() || ev.Time.After(stats.LastSeen) {
		stats.LastSeen = ev.Time
	}
	increment(stats.SourceIPs, ev.SourceIP)
	increment(stats.Targets, ev.Target)
	increment(stats.Inbounds, ev.Inbound)
	increment(stats.Outbounds, ev.Outbound)
	increment(stats.Kinds, string(ev.Kind))
	increment(stats.Networks, ev.Network)
}

func (s *activityStats) DailyReport(day time.Time) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := dayKey(day)
	clients := s.days[key]
	if len(clients) == 0 {
		return "", false
	}

	rows := make([]*clientActivity, 0, len(clients))
	total := 0
	for _, stats := range clients {
		rows = append(rows, stats)
		total += stats.Connections
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Connections != rows[j].Connections {
			return rows[i].Connections > rows[j].Connections
		}
		return rows[i].Actor < rows[j].Actor
	})

	lines := []string{
		"3x-abuse-guard 每日上网行为统计",
		"日期: " + key + " (北京时间)",
		fmt.Sprintf("客户端数: %d", len(rows)),
		fmt.Sprintf("总连接: %d", total),
		"",
	}
	for i, stats := range rows {
		lines = append(lines,
			fmt.Sprintf("%d. %s", i+1, stats.Actor),
			fmt.Sprintf("连接: %d, 活跃: %s - %s", stats.Connections, clock(stats.FirstSeen), clock(stats.LastSeen)),
			"来源IP: "+formatTop(stats.SourceIPs, activityReportTopN),
			"访问目标Top: "+formatTop(stats.Targets, activityReportTopN),
			"出站: "+formatTop(stats.Outbounds, activityReportTopN),
			"入站: "+formatTop(stats.Inbounds, activityReportTopN),
			"类型: "+formatTop(stats.Kinds, activityReportTopN),
			"协议: "+formatTop(stats.Networks, activityReportTopN),
			"",
		)
	}
	return strings.TrimSpace(strings.Join(lines, "\n")), true
}

func (s *activityStats) DeleteDay(day time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.days, dayKey(day))
}

func (s *activityStats) DaysThrough(day time.Time) []time.Time {
	if s == nil {
		return nil
	}
	maxKey := dayKey(day)
	s.mu.Lock()
	defer s.mu.Unlock()

	days := []time.Time{}
	for key := range s.days {
		if key > maxKey {
			continue
		}
		parsed, err := time.ParseInLocation("2006-01-02", key, reportLocation)
		if err == nil {
			days = append(days, parsed)
		}
	}
	sort.Slice(days, func(i, j int) bool {
		return days[i].Before(days[j])
	})
	return days
}

func (a *App) sendDailyAccessReport(ctx context.Context, day time.Time) error {
	if a == nil || a.activity == nil {
		return nil
	}
	text, ok := a.activity.DailyReport(day)
	if !ok {
		return nil
	}
	if err := notify.SendText(ctx, a.notifier, text); err != nil {
		return err
	}
	a.activity.DeleteDay(day)
	return nil
}

func (a *App) sendPendingAccessReports(ctx context.Context, through time.Time) error {
	if a == nil || a.activity == nil {
		return nil
	}
	for _, day := range a.activity.DaysThrough(through) {
		if err := a.sendDailyAccessReport(ctx, day); err != nil {
			return err
		}
	}
	return nil
}

func reportDayFor(now time.Time) time.Time {
	return startOfDay(now).AddDate(0, 0, -1)
}

func timeUntilNextMidnight(now time.Time) time.Duration {
	return nextMidnightAfter(now).Sub(now)
}

func nextMidnightAfter(now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.In(reportLocation)
	year, month, day := now.Date()
	return time.Date(year, month, day+1, 0, 0, 0, 0, reportLocation)
}

func startOfDay(t time.Time) time.Time {
	if t.IsZero() {
		t = time.Now()
	}
	t = t.In(reportLocation)
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, reportLocation)
}

func increment(counts map[string]int, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	counts[value]++
}

func clock(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(reportLocation).Format("15:04:05")
}

type countPair struct {
	Value string
	Count int
}

func formatTop(counts map[string]int, limit int) string {
	if len(counts) == 0 {
		return "-"
	}
	pairs := make([]countPair, 0, len(counts))
	for value, count := range counts {
		pairs = append(pairs, countPair{Value: value, Count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		return pairs[i].Value < pairs[j].Value
	})
	if limit > 0 && len(pairs) > limit {
		pairs = pairs[:limit]
	}
	items := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		items = append(items, fmt.Sprintf("%s(%d)", pair.Value, pair.Count))
	}
	return strings.Join(items, ", ")
}

func dayKey(t time.Time) string {
	return startOfDay(t).Format("2006-01-02")
}
