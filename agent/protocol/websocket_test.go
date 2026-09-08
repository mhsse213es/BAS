package protocol

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
)

func TestDialAgentWS_ConnectsAndReadsMessage(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("agentId") != "a1" {
			t.Errorf("agentId query param = %q, want a1", r.URL.Query().Get("agentId"))
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(WSMessage{Type: "command_cancel"})
	}))
	defer server.Close()

	conn, err := DialAgentWS(server.URL, "a1", "")
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.Close()

	msg, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msg.Type != "command_cancel" {
		t.Errorf("msg.Type = %q, want command_cancel", msg.Type)
	}
}

func TestReadMessage_MalformedFrameReturnsError(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteMessage(websocket.TextMessage, []byte("not json"))
	}))
	defer server.Close()

	conn, err := DialAgentWS(server.URL, "a1", "")
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.Close()

	if _, err := ReadMessage(conn); err == nil {
		t.Fatal("ReadMessage: want error decoding malformed JSON, got nil")
	}
}

func TestDialAgentWSWithDialer_UsesSuppliedDialer(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(WSMessage{Type: "command_cancel"})
	}))
	defer server.Close()

	dialCalled := false
	dialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCalled = true
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	conn, err := DialAgentWSWithDialer(server.URL, "a1", "", dialer)
	if err != nil {
		t.Fatalf("DialAgentWSWithDialer: %v", err)
	}
	defer conn.Close()

	if !dialCalled {
		t.Error("supplied dialer's NetDialContext was never called -- DialAgentWSWithDialer did not use it")
	}

	msg, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msg.Type != "command_cancel" {
		t.Errorf("msg.Type = %q, want command_cancel", msg.Type)
	}
}

func TestDialAgentWS_StillWorksUnchanged(t *testing.T) {
	// Regression guard: DialAgentWS itself (the function loadgen calls) must
	// keep working exactly as before now that it's a thin wrapper.
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(WSMessage{Type: "command_cancel"})
	}))
	defer server.Close()

	conn, err := DialAgentWS(server.URL, "a1", "")
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.Close()
	if _, err := ReadMessage(conn); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
}

func TestScenarioCommand_DecodesFromRealisticPayload(t *testing.T) {
	// Captures the shape a real dispatch takes -- ScenarioStep.Resource/.Timeout
	// arrive as opaque JSON objects and must round-trip without error even
	// though agent/protocol never decodes their internal shape.
	raw := `{"runId":"r1","scenarioId":"s1","name":"Test","steps":[
		{"taskId":"t1","techniqueId":"T1003","name":"Dump","executor":"powershell","command":"...",
		 "resource":{"kind":"credential_access","exclusive":true},
		 "timeout":{"scheduleSec":30,"executeSec":60}}
	]}`
	var cmd ScenarioCommand
	if err := json.Unmarshal([]byte(raw), &cmd); err != nil {
		t.Fatalf("Unmarshal ScenarioCommand: %v", err)
	}
	if len(cmd.Steps) != 1 || cmd.Steps[0].TaskID != "t1" {
		t.Fatalf("cmd.Steps = %+v, want 1 step with TaskID=t1", cmd.Steps)
	}
	if len(cmd.Steps[0].Resource) == 0 || len(cmd.Steps[0].Timeout) == 0 {
		t.Error("Resource/Timeout raw JSON not preserved")
	}
}
