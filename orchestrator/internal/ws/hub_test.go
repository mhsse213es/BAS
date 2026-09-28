package ws

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// TestSendToAgent_ClosedChannelDoesNotPanic reproduces the exact race
// SendToAgent must survive: the agent's send channel has already been
// closed by readPump's disconnect cleanup, but the agent entry hasn't been
// removed from h.agents yet (that happens separately, slightly later, in
// ServeAgentWS). Sending on a closed channel panics unconditionally — found
// via a flaky fake-agent test in internal/api that hit this window in ~1-2%
// of runs. Reproduced here deterministically by closing the channel directly
// rather than relying on real goroutine-scheduling timing.
func TestSendToAgent_ClosedChannelDoesNotPanic(t *testing.T) {
	h := NewHub()
	c := &conn{send: make(chan []byte, 128)}
	h.agents["agent-race"] = c
	close(c.send)

	var sent bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SendToAgent panicked: %v", r)
			}
		}()
		sent = h.SendToAgent("agent-race", models.WSMessage{Type: "test"})
	}()
	if sent {
		t.Fatal("SendToAgent returned true for a closed channel, want false")
	}
}

func TestSendToAgent_UnknownAgent(t *testing.T) {
	h := NewHub()
	if h.SendToAgent("does-not-exist", models.WSMessage{Type: "test"}) {
		t.Fatal("SendToAgent returned true for an unregistered agent")
	}
}

// TestCloseAllAgentConnections_ClosesEveryAgentConn verifies the documented
// contract at the level this package's other tests already use: that the
// method drains the agents map, mirroring the same cleanup ServeAgentWS's
// own readPump-exit path performs (hub.go:75-78). conn.ws is left nil here
// deliberately — CloseAllAgentConnections must nil-guard it so this test
// doesn't need a real TCP websocket connection; a conn in h.agents always
// has a real ws in production (only ever constructed in ServeAgentWS after
// a successful upgrader.Upgrade).
func TestIsAgentConnected_TrueForRegisteredAgent(t *testing.T) {
	h := NewHub()
	h.mu.Lock()
	h.agents["agent-connected"] = &conn{send: make(chan []byte, 1)}
	h.mu.Unlock()

	if !h.IsAgentConnected("agent-connected") {
		t.Fatal("IsAgentConnected returned false for a registered agent")
	}
}

func TestIsAgentConnected_FalseForUnknownAgent(t *testing.T) {
	h := NewHub()
	if h.IsAgentConnected("does-not-exist") {
		t.Fatal("IsAgentConnected returned true for an unregistered agent")
	}
}

func TestCloseAllAgentConnections_ClosesEveryAgentConn(t *testing.T) {
	h := NewHub()
	h.mu.Lock()
	h.agents["agent-1"] = &conn{send: make(chan []byte, 1)}
	h.agents["agent-2"] = &conn{send: make(chan []byte, 1)}
	h.mu.Unlock()

	h.CloseAllAgentConnections()

	h.mu.RLock()
	remaining := len(h.agents)
	h.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("agents map has %d entries after CloseAllAgentConnections, want 0", remaining)
	}
}

// TestSendToAgent_SignsInScopeCommandTypes locks in the centralized
// signing boundary: for one of the 8 execution-triggering command types,
// what actually goes out on the wire must be a signed CommandEnvelope,
// not the raw payload -- and this must be true regardless of which of
// the 16 real call sites constructed the WSMessage, since none of them
// are touched by this change.
func TestSendToAgent_SignsInScopeCommandTypes(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // small key -- fast test
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	h := NewHub()
	h.SetSigner(priv)
	c := &conn{send: make(chan []byte, 1)}
	h.mu.Lock()
	h.agents["agent-1"] = c
	h.mu.Unlock()

	type scenarioPayload struct {
		RunID string `json:"runId"`
	}
	sent := h.SendToAgent("agent-1", models.WSMessage{
		Type:    "command_scenario",
		AgentID: "agent-1",
		Data:    scenarioPayload{RunID: "run-1"},
	})
	if !sent {
		t.Fatal("SendToAgent reported not sent")
	}

	raw := <-c.send
	var wire models.WSMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal wire message: %v", err)
	}
	dataBytes, err := json.Marshal(wire.Data)
	if err != nil {
		t.Fatalf("re-marshal wire.Data: %v", err)
	}
	var env models.CommandEnvelope
	if err := json.Unmarshal(dataBytes, &env); err != nil {
		t.Fatalf("wire.Data for a command_scenario message did not unmarshal as a CommandEnvelope: %v", err)
	}
	if len(env.Signature) == 0 {
		t.Error("CommandEnvelope.Signature is empty -- command_scenario was not signed")
	}
	if env.CommandType != "command_scenario" {
		t.Errorf("envelope CommandType = %q, want command_scenario", env.CommandType)
	}
	if env.AgentID != "agent-1" {
		t.Errorf("envelope AgentID = %q, want agent-1", env.AgentID)
	}
}

// TestSendToAgent_PassesThroughOutOfScopeTypesUnchanged confirms message
// types outside the 8 signed command types (e.g. a heartbeat ack, or any
// other non-execution-triggering type) are never wrapped in a
// CommandEnvelope -- the signing boundary only applies to what the spec
// actually calls execution-triggering.
func TestSendToAgent_PassesThroughOutOfScopeTypesUnchanged(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	h := NewHub()
	h.SetSigner(priv)
	c := &conn{send: make(chan []byte, 1)}
	h.mu.Lock()
	h.agents["agent-1"] = c
	h.mu.Unlock()

	type someOtherPayload struct {
		Foo string `json:"foo"`
	}
	h.SendToAgent("agent-1", models.WSMessage{
		Type:    "agentUpdate",
		AgentID: "agent-1",
		Data:    someOtherPayload{Foo: "bar"},
	})

	raw := <-c.send
	var wire models.WSMessage
	json.Unmarshal(raw, &wire)
	dataBytes, _ := json.Marshal(wire.Data)
	var probe map[string]interface{}
	json.Unmarshal(dataBytes, &probe)
	if _, hasSignature := probe["signature"]; hasSignature {
		t.Error("an out-of-scope message type was wrapped in a signed CommandEnvelope")
	}
	if probe["foo"] != "bar" {
		t.Errorf("payload was altered for an out-of-scope type: %+v", probe)
	}
}
