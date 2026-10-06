package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/config"
	"github.com/zachary9757/3x-abuse-guard/internal/panel"
)

func amneziaWGRelay(sniffing bool) map[string]any {
	return map[string]any{
		"tag": "inbound-1", "protocol": "socks", "listen": "127.0.0.1",
		"settings": map[string]any{
			"auth": "password", "udp": true,
			"accounts": []any{map[string]any{"user": "alice", "pass": "test"}},
		},
		"sniffing": validSniffing(sniffing),
	}
}

func validSniffing(enabled bool) map[string]any {
	return map[string]any{
		"enabled": enabled, "routeOnly": true,
		"destOverride": []any{"http", "tls", "quic"},
	}
}

func compatibilityConfig() map[string]any {
	return map[string]any{
		"log": map[string]any{"access": "/var/log/x-ui/access.log"},
		"outbounds": []any{
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
			map[string]any{"tag": "amneziawg-v6-1-alice", "protocol": "freedom"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"inboundTag": []any{"api"}, "outboundTag": "api"},
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "TORRENT"},
			map[string]any{"ip": []any{"geoip:private"}, "outboundTag": "blocked"},
		}},
		"inbounds": []any{map[string]any{"tag": "api"}, amneziaWGRelay(true)},
	}
}

func TestInspectXrayConfigAmneziaWGRouteOrder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		position int
		wantOK   bool
	}{
		{"before all rules", 0, false},
		{"after torrent but before blocked", 2, false},
		{"after abuse rules", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := compatibilityConfig()
			routing := x["routing"].(map[string]any)
			rules := list(routing["rules"])
			rule := map[string]any{"type": "field", "inboundTag": []any{"inbound-1"}, "user": []any{"alice"}, "outboundTag": "amneziawg-v6-1-alice"}
			ordered := append([]any{}, rules[:tc.position]...)
			ordered = append(ordered, rule)
			routing["rules"] = append(ordered, rules[tc.position:]...)
			check := findCheck(t, inspectXrayConfig(x, config.Default()), "routing AmneziaWG")
			if check.OK != tc.wantOK {
				t.Fatalf("check = %+v", check)
			}
			if !check.OK && (!strings.Contains(check.Message, "alice") || !strings.Contains(check.Message, "inbound-1")) {
				t.Fatalf("missing affected client/inbound: %s", check.Message)
			}
		})
	}
}

func TestInspectXrayConfigAmneziaWGSniffing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mixed    bool
		sniffing bool
	}{
		{"AWG only", false, true},
		{"AWG only missing sniffing", false, false},
		{"mixed with VLESS", true, true},
		{"mixed missing AWG sniffing", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := compatibilityConfig()
			x["inbounds"] = []any{map[string]any{"tag": "api"}, amneziaWGRelay(tc.sniffing), map[string]any{"tag": "panel-egress", "listen": "127.0.0.1", "protocol": "socks"}}
			if tc.mixed {
				x["inbounds"] = append(list(x["inbounds"]), map[string]any{"tag": "inbound-2", "protocol": "vless", "sniffing": validSniffing(true)})
			}
			check := findCheck(t, inspectXrayConfig(x, config.Default()), "sniffing")
			if check.OK != tc.sniffing || strings.Contains(check.Message, "no user inbounds") {
				t.Fatalf("check = %+v", check)
			}
		})
	}
}

func TestDoctorChecksRuntimeStatus(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
		body       string
		wantOK     bool
		message    string
	}{
		{"running", 200, `{"success":true,"obj":{"xray":{"state":"running","errorMsg":"","version":"26.9.30"}}}`, true, "26.9.30"},
		{"refused config", 200, `{"success":true,"obj":{"xray":{"state":"running","errorMsg":"config refused: port collision"}}}`, false, "config refused"},
		{"stopped", 200, `{"success":true,"obj":{"xray":{"state":"stop"}}}`, false, "stop"},
		{"core error", 200, `{"success":true,"obj":{"xray":{"state":"error","errorMsg":"failed to start"}}}`, false, "failed to start"},
		{"missing Xray", 200, `{"success":true,"obj":{}}`, false, "no Xray state"},
		{"missing state", 200, `{"success":true,"obj":{"xray":{}}}`, false, "no Xray state"},
		{"forbidden", 403, `denied`, false, "403"},
		{"unavailable endpoint", 404, `not found`, false, "404"},
		{"malformed", 200, `not json`, false, "invalid character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Panel.AuthMode = "token"
			cfg.Panel.TokenEnv = "GUARD_DOCTOR_TEST_TOKEN"
			t.Setenv(cfg.Panel.TokenEnv, "test-token")
			cfg.Xray.AccessLog = filepath.Join(t.TempDir(), "access.log")
			if err := os.WriteFile(cfg.Xray.AccessLog, nil, 0600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-token" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch r.URL.Path {
				case "/base/panel/api/server/getConfigJson":
					generated := compatibilityConfig()
					generated["log"] = map[string]any{"access": cfg.Xray.AccessLog}
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": generated})
				case "/base/panel/api/inbounds/list":
					_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": []any{}})
				case "/base/panel/api/server/status":
					w.WriteHeader(tc.statusCode)
					_, _ = w.Write([]byte(tc.body))
				default:
					t.Errorf("unexpected endpoint: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			cfg.Panel.BaseURL = server.URL + "/base/"
			checks := Doctor(context.Background(), cfg)
			check := findCheck(t, checks, "xray runtime")
			if check.OK != tc.wantOK || !strings.Contains(check.Message, tc.message) {
				t.Fatalf("check = %+v", check)
			}
			// The generated config is valid even when the running core rejected it.
			for _, other := range checks {
				if other.Name != "xray runtime" && !other.OK {
					t.Fatalf("unrelated check failed: %+v", other)
				}
			}
		})
	}
}

func TestDoctorContinuesAfterInboundListFailure(t *testing.T) {
	cfg := config.Default()
	cfg.Panel.AuthMode = "token"
	cfg.Panel.TokenEnv = "GUARD_DOCTOR_TEST_TOKEN"
	t.Setenv(cfg.Panel.TokenEnv, "test-token")
	cfg.Xray.AccessLog = filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(cfg.Xray.AccessLog, nil, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/panel/api/server/getConfigJson":
			generated := compatibilityConfig()
			generated["log"] = map[string]any{"access": cfg.Xray.AccessLog}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": generated})
		case "/panel/api/inbounds/list":
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
		case "/panel/api/server/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"obj":     map[string]any{"xray": map[string]any{"state": "running", "version": "26.9.30"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg.Panel.BaseURL = server.URL

	checks := Doctor(context.Background(), cfg)
	tuic := findCheck(t, checks, "native TUIC attribution")
	if tuic.OK || !strings.Contains(tuic.Message, "503") {
		t.Fatalf("TUIC check = %+v", tuic)
	}
	if runtime := findCheck(t, checks, "xray runtime"); !runtime.OK {
		t.Fatalf("runtime check = %+v", runtime)
	}
	if routing := findCheck(t, checks, "routing TORRENT"); !routing.OK {
		t.Fatalf("routing check = %+v", routing)
	}
}

func TestInspectNativeTUIC(t *testing.T) {
	nodeID := 7
	for _, tc := range []struct {
		name      string
		inbounds  []panel.Inbound
		generated []any
		wantOK    bool
		message   string
	}{
		{"none", nil, nil, true, "no un-attributable"},
		{"disabled", []panel.Inbound{{Enable: false, Protocol: "tuic", Tag: "tuic-1"}}, nil, true, "no un-attributable"},
		{"remote node", []panel.Inbound{{Enable: true, Protocol: "tuic", Tag: "tuic-1", NodeID: &nodeID}}, nil, true, "no un-attributable"},
		{
			"v3.9 noauth relay",
			[]panel.Inbound{{Enable: true, Protocol: "tuic", Tag: "tuic-1"}},
			[]any{map[string]any{
				"tag": "tuic-1", "protocol": "socks", "listen": "127.0.0.1",
				"settings": map[string]any{"auth": "noauth", "udp": true},
			}},
			false,
			"cannot reliably attribute",
		},
		{
			"missing generated relay",
			[]panel.Inbound{{Enable: true, Protocol: "tuic", Tag: "tuic-1"}},
			nil,
			false,
			"no matching generated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := inspectNativeTUIC(tc.inbounds, map[string]any{"inbounds": tc.generated})
			if check.OK != tc.wantOK || !strings.Contains(check.Message, tc.message) {
				t.Fatalf("check = %+v", check)
			}
		})
	}
}

func TestPanelAPIErrorMessage(t *testing.T) {
	for _, tc := range []struct {
		status  int
		message string
	}{
		{http.StatusUnauthorized, "invalid, expired, or rotated"},
		{http.StatusForbidden, "admin scope"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "denied", tc.status)
		}))
		client, err := panel.New(server.URL, "secret", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetConfigJSON(context.Background())
		server.Close()
		if err == nil || !strings.Contains(panelAPIErrorMessage(err), tc.message) {
			t.Fatalf("message = %q", panelAPIErrorMessage(err))
		}
	}
}

func TestUserFacingLoopbackRelay(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, listen, auth, user string
		want                               bool
	}{
		{"authenticated SOCKS", "socks", "127.0.0.1", "password", "alice", true},
		{"authenticated IPv6 mixed", "mixed", "[::1]", "password", "alice", true},
		{"anonymous internal SOCKS", "socks", "127.0.0.1", "noauth", "", false},
		{"anonymous internal mixed", "mixed", "::1", "noauth", "", false},
		{"empty identity", "socks", "127.0.0.1", "password", "", false},
		{"public SOCKS", "socks", "0.0.0.0", "noauth", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound := map[string]any{
				"tag": "relay", "protocol": tc.protocol, "listen": tc.listen,
				"settings": map[string]any{"auth": tc.auth, "accounts": []any{map[string]any{"user": tc.user}}},
			}
			if got := isUserFacingInbound(inbound); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInspectXrayConfigAccepts3xUI360Configuration(t *testing.T) {
	cfg := config.Default()
	xrayConfig := map[string]any{
		"log": map[string]any{"access": "/var/log/x-ui/access.log"},
		"outbounds": []any{
			map[string]any{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]any{"finalRules": []any{
					map[string]any{"action": "block", "ip": []any{"geoip:private"}},
					map[string]any{"action": "allow"},
				}},
			},
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "TORRENT"},
			map[string]any{"ip": []any{"geoip:private"}, "outboundTag": "blocked"},
		}},
		"inbounds": []any{
			map[string]any{"tag": "api"},
			map[string]any{"tag": "panel-egress", "protocol": "socks", "listen": "127.0.0.1"},
			map[string]any{"tag": "inbound-1", "sniffing": validSniffing(true)},
		},
	}

	for _, check := range inspectXrayConfig(xrayConfig, cfg) {
		if !check.OK {
			t.Errorf("%s failed: %s", check.Name, check.Message)
		}
	}
}

func TestInspectXrayConfigRejectsEarlierDefaultBittorrentRule(t *testing.T) {
	cfg := config.Default()
	xrayConfig := map[string]any{
		"log": map[string]any{"access": "/var/log/x-ui/access.log"},
		"outbounds": []any{
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "blocked"},
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "TORRENT"},
			map[string]any{"ip": []any{"geoip:private"}, "outboundTag": "blocked"},
		}},
		"inbounds": []any{
			map[string]any{"tag": "inbound-1", "sniffing": validSniffing(true)},
		},
	}

	check := findCheck(t, inspectXrayConfig(xrayConfig, cfg), "routing TORRENT")
	if check.OK {
		t.Fatalf("routing check unexpectedly passed: %s", check.Message)
	}
	if check.Message != "first bittorrent rule routes to blocked; move TORRENT before it" {
		t.Fatalf("message = %q", check.Message)
	}
}

func TestInspectXrayConfigRejectsMisleadingMatches(t *testing.T) {
	cfg := config.Default()
	xrayConfig := map[string]any{
		"log": map[string]any{"access": "none"},
		"outbounds": []any{
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"port": "6881", "outboundTag": "TORRENT"},
			map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "blocked"},
		}},
		"inbounds": []any{
			map[string]any{"tag": "inbound-1", "sniffing": validSniffing(true)},
			map[string]any{"tag": "inbound-2", "sniffing": validSniffing(false)},
		},
	}

	checks := inspectXrayConfig(xrayConfig, cfg)
	for _, name := range []string{"xray access log", "routing TORRENT", "routing blocked", "sniffing"} {
		check := findCheck(t, checks, name)
		if check.OK {
			t.Errorf("%s unexpectedly passed: %s", check.Name, check.Message)
		}
	}
}

func TestInspectXrayConfigRejectsCatchAllBeforeBlockedRoute(t *testing.T) {
	xrayConfig := compatibilityConfig()
	routing := xrayConfig["routing"].(map[string]any)
	rules := list(routing["rules"])
	routing["rules"] = append([]any{map[string]any{"outboundTag": "direct"}}, rules...)

	check := findCheck(t, inspectXrayConfig(xrayConfig, config.Default()), "routing blocked")
	if check.OK || !strings.Contains(check.Message, "catch-all") {
		t.Fatalf("check = %+v", check)
	}
}

func TestInspectXrayConfigRejectsIncompleteSniffing(t *testing.T) {
	xrayConfig := compatibilityConfig()
	xrayConfig["inbounds"] = []any{
		map[string]any{"tag": "api"},
		map[string]any{"tag": "inbound-1", "protocol": "vless", "sniffing": map[string]any{"enabled": true}},
	}

	check := findCheck(t, inspectXrayConfig(xrayConfig, config.Default()), "sniffing")
	if check.OK {
		t.Fatalf("check unexpectedly passed: %+v", check)
	}
}

func TestExpectedAccessLogComparesAbsolutePaths(t *testing.T) {
	ok, _ := hasExpectedAccessLog(map[string]any{"log": map[string]any{"access": "/other/access.log"}}, "/var/log/x-ui/access.log")
	if ok {
		t.Fatal("different absolute paths unexpectedly matched")
	}
	ok, _ = hasExpectedAccessLog(map[string]any{"log": map[string]any{"access": "access.log"}}, "/var/log/x-ui/access.log")
	if !ok {
		t.Fatal("filename-only panel config should remain compatible")
	}
}

func findCheck(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %q not found", name)
	return Check{}
}
