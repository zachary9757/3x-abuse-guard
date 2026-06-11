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
	Profile   string    `json:"profile,omitempty"`
	Score     int       `json:"score,omitempty"`
	Threshold int       `json:"threshold,omitempty"`
	Target    string    `json:"target,omitempty"`
	Inbound   string    `json:"inbound,omitempty"`
	Outbound  string    `json:"outbound,omitempty"`
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
	lines := []string{
		"3x-abuse-guard - " + actionLabel(event.Action),
		"",
		"结论: " + conclusionText(event),
	}
	if event.Email != "" {
		lines = append(lines, "用户: "+event.Email)
	}
	if event.IP != "" {
		lines = append(lines, "来源 IP: "+event.IP)
	}
	if event.Kind != "" {
		lines = append(lines, "风险类型: "+event.Kind)
	}
	if event.Score > 0 && event.Threshold > 0 {
		lines = append(lines, fmt.Sprintf("累计分数: %d / %d", event.Score, event.Threshold))
	} else if event.Score > 0 {
		lines = append(lines, fmt.Sprintf("累计分数: %d", event.Score))
	}
	if event.Profile != "" {
		lines = append(lines, "策略: "+event.Profile)
	}
	if event.Target != "" {
		lines = append(lines, "目标: "+event.Target)
	}
	if event.Inbound != "" {
		lines = append(lines, "入站: "+event.Inbound)
	}
	if event.Outbound != "" {
		lines = append(lines, "出站: "+event.Outbound)
	}
	if event.Reason != "" {
		lines = append(lines, "说明: "+reasonText(event.Reason))
	}
	lines = append(lines, "时间: "+event.Timestamp.Format(time.RFC3339))
	return strings.Join(lines, "\n")
}

func actionLabel(action string) string {
	switch action {
	case "ip_blocked":
		return "IP封禁"
	case "score_threshold":
		return "风险通知"
	case "client_disabled":
		return "用户禁用"
	default:
		if action == "" {
			return "通知"
		}
		return action
	}
}

func conclusionText(event Event) string {
	kind := event.Kind
	if kind == "" {
		kind = "风险"
	}
	switch event.Action {
	case "score_threshold":
		return kind + " 风险已达到通知阈值"
	case "ip_blocked":
		return "来源 IP 已因 " + kind + " 风险被封禁"
	case "client_disabled":
		return "用户已因 " + kind + " 风险被禁用"
	default:
		return "收到 " + kind + " 风险事件"
	}
}

func reasonText(reason string) string {
	switch {
	case reason == "blocked outbound hit":
		return "命中 blocked 高风险出站规则"
	case reason == "torrent outbound hit":
		return "命中 TORRENT 种子/BT 出站规则"
	case strings.HasPrefix(reason, "distinct destination ports in window:"):
		return "同一来源在统计窗口内访问了过多不同目标端口"
	case strings.HasPrefix(reason, "connections in window:"):
		return "同一用户或 IP 在统计窗口内连接数过高"
	case strings.Contains(reason, "score threshold reached"):
		return "累计风险分达到策略阈值"
	default:
		return reason
	}
}
