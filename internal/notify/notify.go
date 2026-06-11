package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Event struct {
	Action    string    `json:"action"`
	Kind      string    `json:"kind"`
	Email     string    `json:"email,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type Notifier interface {
	Notify(ctx context.Context, event Event) error
}

type Config struct {
	WebhookURL       string
	TelegramBotToken string
	TelegramChatID   string
}

type Noop struct{}

func (Noop) Notify(context.Context, Event) error { return nil }

type Multi struct {
	Notifiers []Notifier
}

func New(cfg Config) Notifier {
	notifiers := []Notifier{}
	if cfg.WebhookURL != "" {
		notifiers = append(notifiers, NewWebhook(cfg.WebhookURL))
	}
	if cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		notifiers = append(notifiers, NewTelegram(cfg.TelegramBotToken, cfg.TelegramChatID))
	}
	if len(notifiers) == 0 {
		return Noop{}
	}
	if len(notifiers) == 1 {
		return notifiers[0]
	}
	return Multi{Notifiers: notifiers}
}

func (m Multi) Notify(ctx context.Context, event Event) error {
	var firstErr error
	for _, notifier := range m.Notifiers {
		if notifier == nil {
			continue
		}
		if err := notifier.Notify(ctx, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type Webhook struct {
	URL    string
	Client *http.Client
}

func NewWebhook(url string) Notifier {
	if url == "" {
		return Noop{}
	}
	return &Webhook{
		URL: url,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (w *Webhook) Notify(ctx context.Context, event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

type Telegram struct {
	Token      string
	ChatID     string
	APIBaseURL string
	Client     *http.Client
}

type telegramMessage struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func NewTelegram(token string, chatID string) Notifier {
	if token == "" || chatID == "" {
		return Noop{}
	}
	return &Telegram{
		Token:      token,
		ChatID:     chatID,
		APIBaseURL: "https://api.telegram.org",
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (t *Telegram) Notify(ctx context.Context, event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	baseURL := strings.TrimRight(t.APIBaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	body := telegramMessage{
		ChatID:                t.ChatID,
		Text:                  formatTelegramText(event),
		DisableWebPagePreview: true,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/bot"+t.Token+"/sendMessage", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func formatTelegramText(event Event) string {
	action := event.Action
	switch event.Action {
	case "ip_blocked":
		action = "IP封禁"
	case "score_threshold":
		action = "风险通知"
	case "client_disabled":
		action = "用户禁用"
	}
	lines := []string{
		"3x-abuse-guard 通知",
		"动作: " + action,
	}
	if event.Kind != "" {
		lines = append(lines, "类型: "+event.Kind)
	}
	if event.Email != "" {
		lines = append(lines, "用户: "+event.Email)
	}
	if event.IP != "" {
		lines = append(lines, "IP: "+event.IP)
	}
	if event.Reason != "" {
		lines = append(lines, "原因: "+event.Reason)
	}
	lines = append(lines, "时间: "+event.Timestamp.Format(time.RFC3339))
	return strings.Join(lines, "\n")
}
