package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
)

// signResultMAC mirrors integrity.VerifyResultMAC's construction (HMAC-SHA256
// over the raw body, hex-encoded) so tests can build valid MACs without
// importing anything beyond the documented wire contract.
func signResultMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// submitResultReq builds a raw POST /api/scenarios/result request with full
// control over both auth headers. Pass "" for either to omit that header
// entirely (distinct from an explicitly-empty header value only in intent,
// not in observed behavior — both read back as "" server-side).
func submitResultReq(agentToken, mac string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/result", strings.NewReader(string(body)))
	if agentToken != "" {
		req.Header.Set("X-Agent-Token", agentToken)
	}
	if mac != "" {
		req.Header.Set("X-Result-MAC", mac)
	}
	return req
}

// validSubmitResultReq builds a request with correctly-computed auth headers
// for the given secret. Pass "" to build a request with no auth headers at
// all, matching an unconfigured (bypass) agentSecret.
func validSubmitResultReq(secret string, body []byte) *http.Request {
	if secret == "" {
		return submitResultReq("", "", body)
	}
	return submitResultReq(secret, signResultMAC(secret, body), body)
}

// rawResultBody marshals a RawRunResult the same way an agent would.
func rawResultBody(t *testing.T, raw scenario.RawRunResult) []byte {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal RawRunResult: %v", err)
	}
	return b
}

// seedRunRow inserts a minimal agents row (idempotent — ON CONFLICT DO
// NOTHING, so callers don't need to separately track whether an agent ID was
// already seeded) and a scenario_runs row with the given status. A richer
// variant of event_handlers_test.go's narrower seedRun (which hardcodes
// agent/scenario/status). Use seedActiveAgent from run_scenario_gates_test.go
// instead when the agent needs specific OS/state values.
func seedRunRow(t *testing.T, pool *pgxpool.Pool, runID, scenarioID, agentID, status string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')
		 ON CONFLICT (agent_id) DO NOTHING`, agentID); err != nil {
		t.Fatalf("seed agent for run: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
		 VALUES ($1,$2,$3,'test-run',$4,NOW())`, runID, scenarioID, agentID, status); err != nil {
		t.Fatalf("seed run: %v", err)
	}
}

// fakeBrowser is a real WebSocket client standing in for a dashboard browser,
// mirroring fakeAgent in run_dispatch_helpers_test.go. Reusable WS test
// infrastructure, not tied to result ingestion specifically.
type fakeBrowser struct {
	hub      *ws.Hub
	server   *httptest.Server
	conn     *websocket.Conn
	received chan wsEnvelope
}

func startFakeBrowser(t *testing.T, hub *ws.Hub) *fakeBrowser {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeBrowserWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial fake browser: %v", err)
	}
	b := &fakeBrowser{hub: hub, server: server, conn: conn, received: make(chan wsEnvelope, 32)}
	go b.readLoop()
	b.waitConnected(t)
	return b
}

func (b *fakeBrowser) readLoop() {
	for {
		_, raw, err := b.conn.ReadMessage()
		if err != nil {
			return
		}
		var env wsEnvelope
		if json.Unmarshal(raw, &env) == nil {
			b.received <- env
		}
	}
}

// waitConnected polls by broadcasting a harmless probe until this browser's
// own read loop observes it, proving ServeBrowserWS has finished registering
// the connection in hub.browsers. Same bounded-poll-for-connection-readiness
// pattern as waitForAgentConnected — not a poll for business-logic state.
func (b *fakeBrowser) waitConnected(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.hub.BroadcastBrowsers(wsProbeMessage())
		select {
		case env := <-b.received:
			if env.Type == "__test_probe__" {
				return
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("fake browser never showed as connected")
}

func (b *fakeBrowser) WaitForMessage(t *testing.T, timeout time.Duration) wsEnvelope {
	t.Helper()
	select {
	case env := <-b.received:
		if env.Type == "__test_probe__" {
			return b.WaitForMessage(t, timeout)
		}
		return env
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a WebSocket message")
		return wsEnvelope{}
	}
}

func (b *fakeBrowser) Disconnect(t *testing.T) {
	t.Helper()
	_ = b.conn.Close()
	b.server.Close()
}

// Reconnect re-dials against hub, replacing this fakeBrowser's connection and
// read loop in place.
func (b *fakeBrowser) Reconnect(t *testing.T, hub *ws.Hub) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeBrowserWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("reconnect fake browser: %v", err)
	}
	b.hub = hub
	b.server = server
	b.conn = conn
	b.received = make(chan wsEnvelope, 32)
	go b.readLoop()
	b.waitConnected(t)
}

func TestFakeBrowser_ConnectReceiveDisconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	hub := ws.NewHub()
	browser := startFakeBrowser(t, hub)

	hub.BroadcastBrowsers(models.WSMessage{Type: "hello"})
	env := browser.WaitForMessage(t, 2*time.Second)
	if env.Type != "hello" {
		t.Fatalf("received type = %q, want hello", env.Type)
	}

	browser.Disconnect(t)

	browser.Reconnect(t, hub)
	hub.BroadcastBrowsers(models.WSMessage{Type: "hello-again"})
	env2 := browser.WaitForMessage(t, 2*time.Second)
	if env2.Type != "hello-again" {
		t.Fatalf("received type = %q, want hello-again", env2.Type)
	}
}
