package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidateAgentAuth_Precedence(t *testing.T) {
	h := &Handler{agentSecret: "shh"}

	newReq := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
	}

	cases := []struct {
		name        string
		header      string
		query       string
		wantAllowed bool
	}{
		{"header-only-correct", "shh", "", true},
		{"query-only-correct", "", "shh", true},
		{"both-correct", "shh", "shh", true},
		{"header-wrong-query-correct", "nope", "shh", false}, // header wins even though wrong; never falls back
		{"header-empty-query-correct", "", "shh", true},      // falls through when header is empty
		{"neither-present", "", "", false},
		{"header-correct-query-wrong", "shh", "nope", true}, // header wins, query ignored
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq()
			if tc.header != "" {
				req.Header.Set("X-Agent-Token", tc.header)
			}
			if tc.query != "" {
				q := req.URL.Query()
				q.Set("agentSecret", tc.query)
				req.URL.RawQuery = q.Encode()
			}
			if got := h.validateAgentAuth(req); got != tc.wantAllowed {
				t.Fatalf("%s: validateAgentAuth = %v, want %v", tc.name, got, tc.wantAllowed)
			}
		})
	}
}

func TestValidateAgentAuth_NoSecretConfigured_AlwaysAllowed(t *testing.T) {
	h := &Handler{agentSecret: ""}
	req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
	if !h.validateAgentAuth(req) {
		t.Fatal("expected validateAgentAuth to allow when no secret is configured (backward-compat bypass)")
	}
}

func TestValidateAgentAuth_MalformedAndEdgeHeaderValues(t *testing.T) {
	h := &Handler{agentSecret: "shh"}

	t.Run("bearer-prefixed value does not match raw secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
		req.Header.Set("X-Agent-Token", "Bearer shh")
		if h.validateAgentAuth(req) {
			t.Fatal("expected rejection: raw string comparison, no Bearer-prefix parsing")
		}
	})

	t.Run("whitespace-only token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
		req.Header.Set("X-Agent-Token", "   ")
		if h.validateAgentAuth(req) {
			t.Fatal("expected rejection for whitespace-only token")
		}
	})

	t.Run("duplicate headers — first value wins via Header.Get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
		req.Header.Add("X-Agent-Token", "shh")
		req.Header.Add("X-Agent-Token", "nope")
		if !h.validateAgentAuth(req) {
			t.Fatal("expected the first added header value (the correct one) to be used")
		}
	})
}

func TestPingAgent_AuthGate(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "").WithAgentSecret("shh")

	ok := httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil)
	ok.Header.Set("X-Agent-Token", "shh")
	rec := httptest.NewRecorder()
	h.PingAgent(rec, ok)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: status = %d, want 200", rec.Code)
	}

	bad := httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil)
	bad.Header.Set("X-Agent-Token", "wrong")
	rec2 := httptest.NewRecorder()
	h.PingAgent(rec2, bad)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec2.Code)
	}
}

func TestEnrollAgent_AuthGate_NoRowCreatedOnFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "").WithAgentSecret("shh")
		body, _ := json.Marshal(map[string]string{"agentId": "agent-should-not-exist"})
		req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "wrong")
		rec := httptest.NewRecorder()
		h.EnrollAgent(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id = $1`, "agent-should-not-exist").Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatal("EnrollAgent must not create a row when auth fails")
		}
	})
}

func TestHeartbeat_AuthGate_NoRowCreatedOnFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "").WithAgentSecret("shh")
		body, _ := json.Marshal(map[string]string{"agentId": "agent-should-not-exist-2"})
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "wrong")
		rec := httptest.NewRecorder()
		h.Heartbeat(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id = $1`, "agent-should-not-exist-2").Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatal("Heartbeat must not create a row when auth fails")
		}
	})
}
