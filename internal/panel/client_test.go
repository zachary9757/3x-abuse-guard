package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDisableClient(t *testing.T) {
	var disabled map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/panel/api/clients/bulkDisable":
			if err := json.NewDecoder(r.Body).Decode(&disabled); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"obj": map[string]any{
					"changed": 1,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DisableClient(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if len(disabled["emails"]) != 1 || disabled["emails"][0] != "alice" {
		t.Fatalf("unexpected disable request: %#v", disabled)
	}
}

func TestDisableClientWithLogin(t *testing.T) {
	const csrfToken = "csrf-token"
	const sessionCookie = "session-id"
	var disabled map[string][]string
	loginSeen := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csrf-token":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionCookie})
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": csrfToken})
		case "/login":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != sessionCookie {
				http.Error(w, "missing session cookie", http.StatusUnauthorized)
				return
			}
			if r.Header.Get("X-CSRF-Token") != csrfToken {
				http.Error(w, "missing csrf", http.StatusForbidden)
				return
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["username"] != "admin" || body["password"] != "secret" {
				http.Error(w, "bad credentials", http.StatusUnauthorized)
				return
			}
			loginSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		case "/panel/api/clients/bulkDisable":
			if !loginSeen {
				http.Error(w, "not logged in", http.StatusUnauthorized)
				return
			}
			if r.Header.Get("X-CSRF-Token") != csrfToken {
				http.Error(w, "missing csrf", http.StatusForbidden)
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&disabled); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"obj":     map[string]any{"changed": 1},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewWithLogin(server.URL, "admin", "secret", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DisableClient(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if len(disabled["emails"]) != 1 || disabled["emails"][0] != "alice" {
		t.Fatalf("unexpected disable request: %#v", disabled)
	}
}

func TestDisableClientFallsBackForOlderPanel(t *testing.T) {
	var updated map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/panel/api/clients/bulkDisable":
			http.NotFound(w, r)
		case "/panel/api/clients/get/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"obj": map[string]any{
					"client":     map[string]any{"email": "alice", "enable": true},
					"inboundIds": []int{1},
				},
			})
		case "/panel/api/clients/update/alice":
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DisableClient(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if updated["enable"] != false || updated["email"] != "alice" {
		t.Fatalf("unexpected legacy update: %#v", updated)
	}
}

func TestDisableClientReportsSkippedClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"obj": map[string]any{
				"changed": 0,
				"skipped": []map[string]string{{
					"email":  "alice",
					"reason": "client not found",
				}},
			},
		})
	}))
	defer server.Close()

	client, err := New(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DisableClient(context.Background(), "alice"); err == nil {
		t.Fatal("expected skipped client error")
	}
}

func TestAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "msg": "nope"})
	}))
	defer server.Close()

	client, err := New(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetConfigJSON(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestInsecureSkipVerifyAllowsSelfSignedHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"obj": map[string]any{
				"routing": map[string]any{},
			},
		})
	}))
	defer server.Close()

	client, err := New(server.URL, "secret", time.Second, WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetConfigJSON(context.Background()); err != nil {
		t.Fatal(err)
	}
}
