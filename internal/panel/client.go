package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

type APIResponse struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

type ClientDetail struct {
	Client     map[string]any `json:"client"`
	InboundIDs []int          `json:"inboundIds"`
}

func New(baseURL string, token string, timeout time.Duration) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("panel api token is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("panel base url must include scheme and host")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL: u,
		token:   token,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (c *Client) Ping(ctx context.Context) error {
	_, err := c.GetConfigJSON(ctx)
	return err
}

func (c *Client) GetConfigJSON(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/panel/api/server/getConfigJson", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetClient(ctx context.Context, email string) (ClientDetail, error) {
	var out ClientDetail
	if err := c.do(ctx, http.MethodGet, "/panel/api/clients/get/"+url.PathEscape(email), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) DisableClient(ctx context.Context, email string) error {
	detail, err := c.GetClient(ctx, email)
	if err != nil {
		return err
	}
	if detail.Client == nil {
		return fmt.Errorf("client %q not found in response", email)
	}
	detail.Client["enable"] = false
	return c.do(ctx, http.MethodPost, "/panel/api/clients/update/"+url.PathEscape(email), detail.Client, nil)
}

func (c *Client) RestartXray(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/panel/api/server/restartXrayService", nil, nil)
}

func (c *Client) do(ctx context.Context, method string, endpoint string, body any, out any) error {
	reqURL := *c.baseURL
	basePath := strings.TrimRight(reqURL.Path, "/")
	reqURL.Path = path.Join(basePath, endpoint)
	if strings.HasSuffix(endpoint, "/") && !strings.HasSuffix(reqURL.Path, "/") {
		reqURL.Path += "/"
	}

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("panel api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(data, &apiResp); err != nil {
		return err
	}
	if !apiResp.Success {
		if apiResp.Msg == "" {
			apiResp.Msg = "request failed"
		}
		return fmt.Errorf("panel api error: %s", apiResp.Msg)
	}
	if out != nil && len(apiResp.Obj) > 0 {
		if err := json.Unmarshal(apiResp.Obj, out); err != nil {
			return err
		}
	}
	return nil
}
