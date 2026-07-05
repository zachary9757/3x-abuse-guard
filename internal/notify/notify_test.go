package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelegramNotifySendsMessage(t *testing.T) {
	var got struct {
		ChatID                string `json:"chat_id"`
		Text                  string `json:"text"`
		DisableWebPagePreview bool   `json:"disable_web_page_preview"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bottoken/sendMessage" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	notifier := &Telegram{
		Token:      "token",
		ChatID:     "12345",
		APIBaseURL: server.URL,
		Client:     server.Client(),
	}
	err := notifier.Notify(context.Background(), Event{
		Action:    "score_threshold",
		Kind:      "blocked",
		Email:     "alice",
		IP:        "198.51.100.10",
		Reason:    "blocked outbound hit",
		Profile:   "default",
		Score:     50,
		Threshold: 50,
		Target:    "example.com:22",
		Inbound:   "inbound-1",
		Outbound:  "blocked",
		Timestamp: time.Date(2026, 6, 11, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ChatID != "12345" {
		t.Fatalf("chat id = %s", got.ChatID)
	}
	if !got.DisableWebPagePreview {
		t.Fatal("expected disabled previews")
	}
	for _, want := range []string{
		"3x-abuse-guard - 风险通知",
		"结论: blocked 风险已达到通知阈值",
		"用户: alice",
		"来源 IP: 198.51.100.10",
		"风险类型: blocked",
		"累计分数: 50 / 50",
		"策略: default",
		"目标: example.com:22",
		"入站: inbound-1",
		"出站: blocked",
		"说明: 命中 blocked 高风险出站规则",
	} {
		if !strings.Contains(got.Text, want) {
			t.Fatalf("message %q missing %q", got.Text, want)
		}
	}
}

func TestNewSkipsTelegramWhenCredentialsMissing(t *testing.T) {
	if _, ok := New(Config{TelegramBotToken: "token"}).(Noop); !ok {
		t.Fatal("expected noop without chat id")
	}
	if _, ok := New(Config{TelegramChatID: "12345"}).(Noop); !ok {
		t.Fatal("expected noop without token")
	}
}

func TestMultiNotifierCallsWebhookAndTelegram(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	notifier := Multi{Notifiers: []Notifier{
		NewWebhook(server.URL),
		&Telegram{
			Token:      "token",
			ChatID:     "12345",
			APIBaseURL: server.URL,
			Client:     server.Client(),
		},
	}}
	if err := notifier.Notify(context.Background(), Event{Action: "score_threshold", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestTelegramNotifyReturnsStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad chat", http.StatusBadRequest)
	}))
	defer server.Close()

	notifier := &Telegram{
		Token:      "token",
		ChatID:     "12345",
		APIBaseURL: server.URL,
		Client:     server.Client(),
	}
	err := notifier.Notify(context.Background(), Event{Action: "client_disabled", Timestamp: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "telegram api returned status 400") {
		t.Fatalf("err = %v", err)
	}
}

func TestTelegramNotifyTextSendsPlainMessage(t *testing.T) {
	var got struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	notifier := &Telegram{
		Token:      "token",
		ChatID:     "12345",
		APIBaseURL: server.URL,
		Client:     server.Client(),
	}
	if err := notifier.NotifyText(context.Background(), "daily report"); err != nil {
		t.Fatal(err)
	}
	if got.ChatID != "12345" || got.Text != "daily report" {
		t.Fatalf("message = %#v", got)
	}
}

func TestTelegramNotifyTextSplitsLongMessage(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var got struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if len(got.Text) > 3900 {
			t.Fatalf("chunk too long: %d", len(got.Text))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	notifier := &Telegram{
		Token:      "token",
		ChatID:     "12345",
		APIBaseURL: server.URL,
		Client:     server.Client(),
	}
	if err := notifier.NotifyText(context.Background(), strings.Repeat("a", 3901)); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}
