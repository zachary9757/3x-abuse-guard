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
	var updated map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/panel/api/clients/get/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"obj": map[string]any{
					"client": map[string]any{"email": "alice", "enable": true, "totalGB": 100},
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
		t.Fatalf("unexpected update: %#v", updated)
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
