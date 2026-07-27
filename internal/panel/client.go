package panel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL    *url.URL
	token      string
	username   string
	password   string
	twoFactor  string
	httpClient *http.Client

	mu        sync.Mutex
	csrfToken string
	loggedIn  bool
}

type Option func(*clientOptions)

type clientOptions struct {
	insecureSkipVerify bool
}

func WithInsecureSkipVerify() Option {
	return func(opts *clientOptions) {
		opts.insecureSkipVerify = true
	}
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

type bulkSetEnableResult struct {
	Changed int                   `json:"changed"`
	Skipped []bulkSetEnableReport `json:"skipped"`
}

type bulkSetEnableReport struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type loginRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	TwoFactorCode string `json:"twoFactorCode,omitempty"`
}

type statusError struct {
	status int
	body   string
}

func (e statusError) Error() string {
	return fmt.Sprintf("panel api returned status %d: %s", e.status, e.body)
}

func New(baseURL string, token string, timeout time.Duration, opts ...Option) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("panel api token is required")
	}
	client, err := newBaseClient(baseURL, timeout, opts...)
	if err != nil {
		return nil, err
	}
	client.token = token
	return client, nil
}

func NewWithLogin(baseURL string, username string, password string, twoFactor string, timeout time.Duration, opts ...Option) (*Client, error) {
	if username == "" {
		return nil, fmt.Errorf("panel username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("panel password is required")
	}
	client, err := newBaseClient(baseURL, timeout, opts...)
	if err != nil {
		return nil, err
	}
	client.username = username
	client.password = password
	client.twoFactor = twoFactor
	return client, nil
}

func newBaseClient(baseURL string, timeout time.Duration, opts ...Option) (*Client, error) {
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
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	var options clientOptions
	for _, opt := range opts {
		opt(&options)
	}
	httpClient := &http.Client{
		Timeout: timeout,
		Jar:     jar,
	}
	if options.insecureSkipVerify {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = transport
	}
	return &Client{
		baseURL:    u,
		httpClient: httpClient,
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
	var result bulkSetEnableResult
	err := c.do(ctx, http.MethodPost, "/panel/api/clients/bulkDisable", map[string]any{
		"emails": []string{email},
	}, &result)
	if err == nil {
		for _, skipped := range result.Skipped {
			if skipped.Email == email {
				return fmt.Errorf("client %q was not disabled: %s", email, skipped.Reason)
			}
		}
		return nil
	}
	if !isStatus(err, http.StatusNotFound) {
		return err
	}
	return c.disableClientLegacy(ctx, email)
}

func (c *Client) disableClientLegacy(ctx context.Context, email string) error {
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
	for attempt := 0; attempt < 2; attempt++ {
		if c.usesLogin() {
			if err := c.ensureLogin(ctx); err != nil {
				return err
			}
		}
		err := c.doRaw(ctx, method, endpoint, body, out)
		if !c.usesLogin() || attempt > 0 || !isAuthRetryable(err) {
			return err
		}
		c.clearLogin()
	}
	return nil
}

func (c *Client) ensureLogin(ctx context.Context) error {
	c.mu.Lock()
	if c.loggedIn {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	csrfToken, err := c.fetchCSRFToken(ctx)
	if err != nil {
		if !isStatus(err, http.StatusNotFound) {
			return err
		}
	} else {
		c.mu.Lock()
		c.csrfToken = csrfToken
		c.mu.Unlock()
	}

	if err := c.doRaw(ctx, http.MethodPost, "/login", loginRequest{
		Username:      c.username,
		Password:      c.password,
		TwoFactorCode: c.twoFactor,
	}, nil); err != nil {
		return err
	}

	c.mu.Lock()
	c.loggedIn = true
	c.mu.Unlock()
	return nil
}

func (c *Client) fetchCSRFToken(ctx context.Context) (string, error) {
	var token string
	if err := c.doRaw(ctx, http.MethodGet, "/csrf-token", nil, &token); err != nil {
		return "", err
	}
	if token == "" {
		return "", fmt.Errorf("panel csrf token response was empty")
	}
	return token, nil
}

func (c *Client) clearLogin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loggedIn = false
	c.csrfToken = ""
}

func (c *Client) usesLogin() bool {
	return c.token == ""
}

func (c *Client) doRaw(ctx context.Context, method string, endpoint string, body any, out any) error {
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
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if !isSafeMethod(method) {
		c.mu.Lock()
		csrfToken := c.csrfToken
		c.mu.Unlock()
		if csrfToken != "" {
			req.Header.Set("X-CSRF-Token", csrfToken)
		}
	}
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
		return statusError{status: resp.StatusCode, body: strings.TrimSpace(string(data))}
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

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func isAuthRetryable(err error) bool {
	return isStatus(err, http.StatusUnauthorized) || isStatus(err, http.StatusForbidden)
}

func isStatus(err error, statuses ...int) bool {
	statusErr, ok := err.(statusError)
	if !ok {
		return false
	}
	for _, status := range statuses {
		if statusErr.status == status {
			return true
		}
	}
	return false
}
