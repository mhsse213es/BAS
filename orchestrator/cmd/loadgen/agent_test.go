package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"audspect/agent/protocol"
	"github.com/gorilla/websocket"
)

// newMockServer returns an httptest.Server handling enroll/heartbeat/result
// over HTTP and one scenario dispatch over WS, close enough to the real
// orchestrator's wire behavior to drive simulatedAgent.run through a full
// lifecycle without a live orchestrator.
func newMockServer(t *testing.T, dispatchAfter time.Duration) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(protocol.EnrollResponse{State: "active"})
	})
	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(protocol.HeartbeatResponse{State: "active"})
	})
	mux.HandleFunc("/api/scenarios/result", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if dispatchAfter > 0 {
			time.Sleep(dispatchAfter)
			data, _ := json.Marshal(protocol.ScenarioCommand{
				RunID: "r1", ScenarioID: "s1",
				Steps: []protocol.ScenarioStep{{TaskID: "t1"}},
			})
			conn.WriteJSON(protocol.WSMessage{Type: "command_scenario", Data: data})
		}
		// keep the connection open until the test tears it down
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	return httptest.NewServer(mux)
}

func TestSimulatedAgent_Run_EnrollsAndReportsActive(t *testing.T) {
	server := newMockServer(t, 0)
	defer server.Close()

	metrics := NewMetrics()
	agent := newSimulatedAgent(simConfig{
		ServerURL: server.URL, AgentID: "test-1", Hostname: "TEST-1",
		Heartbeat: 50 * time.Millisecond, ExecutionLatency: 10 * time.Millisecond,
	}, metrics)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	agent.run(ctx)

	snap := metrics.Snapshot()
	if snap.HeartbeatOK == 0 {
		t.Error("expected at least one successful heartbeat")
	}
}

func TestSimulatedAgent_Run_DispatchTriggersResultSubmission(t *testing.T) {
	server := newMockServer(t, 50*time.Millisecond)
	defer server.Close()

	metrics := NewMetrics()
	agent := newSimulatedAgent(simConfig{
		ServerURL: server.URL, AgentID: "test-2", Hostname: "TEST-2",
		Heartbeat: 500 * time.Millisecond, ExecutionLatency: 20 * time.Millisecond,
	}, metrics)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	agent.run(ctx)

	snap := metrics.Snapshot()
	if snap.ResultsTotal == 0 {
		t.Error("expected at least one result submitted after dispatch")
	}
}

func TestSimulatedAgent_Run_EnrollFailureStopsCleanly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	metrics := NewMetrics()
	agent := newSimulatedAgent(simConfig{ServerURL: server.URL, AgentID: "test-3", Heartbeat: time.Second}, metrics)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	agent.run(ctx) // must return promptly, not hang, on enroll failure

	if metrics.Snapshot().ActiveAgents != 0 {
		t.Error("AgentStopped was not called after enroll failure")
	}
}
