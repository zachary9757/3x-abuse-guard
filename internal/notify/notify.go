package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
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

type Noop struct{}

func (Noop) Notify(context.Context, Event) error { return nil }

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
