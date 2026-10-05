package api

import (
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
)

func TestClassifyAgentOS(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"windows server", "Windows Server 2022", "windows"},
		{"windows lowercase", "windows", "windows"},
		{"windows mixed case", "WiNdOwS 11", "windows"},
		{"ubuntu", "Ubuntu 22.04 LTS", "linux"},
		{"kali", "Kali GNU/Linux Rolling", "linux"},
		{"macos", "macOS Sonoma", "darwin"},
		{"darwin literal", "darwin", "darwin"},
		{"leading/trailing whitespace", "  linux  ", "linux"},
		{"unknown distro with version suffix", "FreeBSD 13.2", ""},
		{"empty string", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAgentOS(tc.in); got != tc.want {
				t.Fatalf("classifyAgentOS(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// wsEnvelope mirrors models.WSMessage's wire shape but keeps Data as raw
// bytes for a second decode stage into whatever concrete payload type a
// specific test expects (models.WSMessage's Data is interface{}, which
// decodes as a generic map — not directly usable as e.g. scenario.ScenarioCommand).
type wsEnvelope struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agentId,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// fakeAgent is a real WebSocket client standing in for an agent in tests,
// so dispatchRun's actual delivery path (not just its DB side effects) is
// exercised. Not dispatch-specific — reusable by any future test that needs
// a connected agent on the hub.
type fakeAgent struct {
	agentID  string
	hub      *ws.Hub
	server   *httptest.Server
	conn     *websocket.Conn
	received chan wsEnvelope
}

func startFakeAgent(t *testing.T, hub *ws.Hub, agentID string) *fakeAgent {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeAgentWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?agentId=" + agentID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial fake agent: %v", err)
	}
	f := &fakeAgent{agentID: agentID, hub: hub, server: server, conn: conn, received: make(chan wsEnvelope, 32)}
	go f.readLoop(f.conn, f.received)
	waitForAgentConnected(t, hub, agentID)
	return f
}

// readLoop takes its connection and channel as arguments rather than reading
// them from f: Reconnect replaces f.conn and f.received while the previous
// loop may still be running, and sharing the fields was a data race.
func (f *fakeAgent) readLoop(conn *websocket.Conn, received chan<- wsEnvelope) {
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var env wsEnvelope
		if json.Unmarshal(raw, &env) == nil {
			received <- env
		}
	}
}

// waitForAgentConnected polls SendToAgent with a harmless probe message until
// the hub reports the agent as connected, so callers don't race the
// dial-then-register sequence inside ServeAgentWS.
func waitForAgentConnected(t *testing.T, hub *ws.Hub, agentID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.SendToAgent(agentID, wsProbeMessage()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fake agent %s never showed as connected", agentID)
}

func wsProbeMessage() models.WSMessage {
	return models.WSMessage{Type: "__test_probe__"}
}

func (f *fakeAgent) WaitForMessage(t *testing.T, timeout time.Duration) wsEnvelope {
	t.Helper()
	select {
	case env := <-f.received:
		if env.Type == "__test_probe__" {
			return f.WaitForMessage(t, timeout) // skip the connectivity probe frame
		}
		return env
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a WebSocket message")
		return wsEnvelope{}
	}
}

// Disconnect closes the fake agent's connection and blocks until the hub has
// actually removed it from its connection map (polls SendToAgent), so a
// subsequent dispatch deterministically sees "offline" rather than racing
// the hub's own cleanup goroutine.
func (f *fakeAgent) Disconnect(t *testing.T) {
	t.Helper()
	_ = f.conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !f.hub.SendToAgent(f.agentID, wsProbeMessage()) {
			f.server.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("hub never removed the disconnected fake agent")
}

// Reconnect re-dials the same agentID against hub, replacing this fakeAgent's
// connection and read loop in place.
func (f *fakeAgent) Reconnect(t *testing.T, hub *ws.Hub) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeAgentWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?agentId=" + f.agentID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("reconnect fake agent: %v", err)
	}
	f.hub = hub
	f.server = server
	f.conn = conn
	f.received = make(chan wsEnvelope, 32)
	go f.readLoop(f.conn, f.received)
	waitForAgentConnected(t, hub, f.agentID)
}

func TestFakeAgent_ConnectSendDisconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	hub := ws.NewHub()
	agent := startFakeAgent(t, hub, "agent-selftest")

	if !hub.SendToAgent("agent-selftest", models.WSMessage{Type: "hello"}) {
		t.Fatal("SendToAgent returned false for a connected fake agent")
	}
	env := agent.WaitForMessage(t, 2*time.Second)
	if env.Type != "hello" {
		t.Fatalf("received type = %q, want hello", env.Type)
	}

	agent.Disconnect(t)
	if hub.SendToAgent("agent-selftest", models.WSMessage{Type: "should-fail"}) {
		t.Fatal("SendToAgent returned true after Disconnect")
	}

	agent.Reconnect(t, hub)
	if !hub.SendToAgent("agent-selftest", models.WSMessage{Type: "hello-again"}) {
		t.Fatal("SendToAgent returned false after Reconnect")
	}
	env2 := agent.WaitForMessage(t, 2*time.Second)
	if env2.Type != "hello-again" {
		t.Fatalf("received type = %q, want hello-again", env2.Type)
	}
}

func minimalPostureScenario(t *testing.T, id string) (*scenario.Scenario, *scenario.Engine) {
	t.Helper()
	engine := scenario.NewEngine(t.TempDir())
	sc := &scenario.Scenario{
		ID:         id,
		Name:       "Posture Test Scenario",
		LocalCheck: true,
	}
	if err := engine.Save(sc); err != nil {
		t.Fatalf("save posture scenario: %v", err)
	}
	got, _ := engine.Get(id)
	return got, engine
}

func minimalLiveScenario(t *testing.T, id string, steps ...scenario.Step) (*scenario.Scenario, *scenario.Engine) {
	t.Helper()
	if len(steps) == 0 {
		steps = []scenario.Step{
			{Name: "step-1", TechniqueID: "T1059", Framework: "custom", Command: "echo step-1"},
		}
	}
	engine := scenario.NewEngine(t.TempDir())
	sc := &scenario.Scenario{
		ID:         id,
		Name:       "Live Test Scenario",
		Executable: true,
		Steps:      steps,
	}
	if err := engine.Save(sc); err != nil {
		t.Fatalf("save live scenario: %v", err)
	}
	got, _ := engine.Get(id)
	return got, engine
}
