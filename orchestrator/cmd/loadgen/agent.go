package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"audspect/agent/protocol"
)

// simConfig holds one simulated agent's run parameters, derived from the
// process-wide Config (main.go) plus this agent's index.
type simConfig struct {
	ServerURL        string
	AgentSecret      string
	AgentID          string
	Hostname         string
	Heartbeat        time.Duration
	ExecutionLatency time.Duration
	ResultSizeBytes  int
	DisconnectRate   float64 // 0.0-1.0, chance per heartbeat interval of a forced reconnect
}

type simulatedAgent struct {
	cfg     simConfig
	metrics *Metrics
	client  *http.Client
}

func newSimulatedAgent(cfg simConfig, metrics *Metrics) *simulatedAgent {
	return &simulatedAgent{
		cfg:     cfg,
		metrics: metrics,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// run drives one simulated agent through its full lifecycle until ctx is
// cancelled: ENROLL -> WS CONNECT -> HEARTBEAT LOOP + WAIT FOR DISPATCH ->
// (on dispatch) SIMULATE EXECUTION -> SUBMIT RESULT -> back to waiting.
// Execution is always fake (a configurable sleep + a synthetic result),
// never the real agent's technique-execution path -- this deliberately
// tests control-plane behavior, not endpoint execution.
func (s *simulatedAgent) run(ctx context.Context) {
	s.metrics.AgentStarted()
	defer s.metrics.AgentStopped()

	t0 := time.Now()
	_, err := protocol.Enroll(ctx, s.client, s.cfg.ServerURL, s.cfg.AgentSecret, protocol.EnrollRequest{
		AgentID:      s.cfg.AgentID,
		Hostname:     s.cfg.Hostname,
		EnvLabel:     "loadgen",
		AgentVersion: "loadgen-1.0",
	})
	s.metrics.RecordEnroll(time.Since(t0))
	if err != nil {
		s.metrics.RecordHTTPError()
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := s.connectAndServe(ctx); err != nil {
			s.metrics.RecordConnectionDrop()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// connectAndServe holds one WS connection open, sending heartbeats on the
// configured interval and reacting to any dispatched scenario, until the
// connection drops, ctx is cancelled, or the configured disconnect-rate
// randomly forces a reconnect (to exercise the real agent's reconnect path
// under load).
func (s *simulatedAgent) connectAndServe(ctx context.Context) error {
	t0 := time.Now()
	conn, err := protocol.DialAgentWS(s.cfg.ServerURL, s.cfg.AgentID, s.cfg.AgentSecret)
	if err != nil {
		s.metrics.RecordHTTPError()
		return err
	}
	s.metrics.RecordWSConnect(time.Since(t0))
	defer conn.Close()

	msgCh := make(chan protocol.WSMessage, 8)
	errCh := make(chan error, 1)
	go func() {
		for {
			msg, err := protocol.ReadMessage(conn)
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- msg
		}
	}()

	hbTicker := time.NewTicker(s.cfg.Heartbeat)
	defer hbTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return fmt.Errorf("WS read: %w", err)
		case msg := <-msgCh:
			s.handleMessage(ctx, msg)
		case <-hbTicker.C:
			ok := s.sendHeartbeat(ctx)
			s.metrics.RecordHeartbeat(ok)
			if s.cfg.DisconnectRate > 0 && rand.Float64() < s.cfg.DisconnectRate {
				return nil // forced reconnect -- exercises the real agent's reconnect path
			}
		}
	}
}

func (s *simulatedAgent) sendHeartbeat(ctx context.Context) bool {
	_, err := protocol.SendHeartbeat(ctx, s.client, s.cfg.ServerURL, s.cfg.AgentSecret, protocol.Heartbeat{
		AgentID:         s.cfg.AgentID,
		Hostname:        s.cfg.Hostname,
		Status:          "idle",
		EnvLabel:        "loadgen",
		AgentVersion:    "loadgen-1.0",
		SchemaVersion:   protocol.SchemaVersion,
		ProtocolVersion: protocol.ProtocolVersion,
		EmitsEvents:     true,
	})
	return err == nil
}

func (s *simulatedAgent) handleMessage(ctx context.Context, msg protocol.WSMessage) {
	if msg.Type != "command_scenario" {
		return // loadgen only reacts to dispatch -- pause/resume/cancel/stop are out of scope for this sub-project
	}
	var cmd protocol.ScenarioCommand
	if err := json.Unmarshal(msg.Data, &cmd); err != nil {
		s.metrics.RecordProtocolError()
		return
	}
	dispatchedAt := time.Now()
	s.metrics.RecordDispatch(time.Since(dispatchedAt)) // dispatch latency is measured server-side too; this is the receipt timestamp

	// SIMULATE EXECUTION: configurable sleep, never real technique logic.
	select {
	case <-ctx.Done():
		return
	case <-time.After(s.cfg.ExecutionLatency):
	}

	results := make([]protocol.ExecResult, len(cmd.Steps))
	for i, step := range cmd.Steps {
		results[i] = protocol.ExecResult{
			TaskID:     step.TaskID,
			ExitCode:   0,
			Stdout:     fakePayload(s.cfg.ResultSizeBytes),
			DurationMs: s.cfg.ExecutionLatency.Milliseconds(),
			ExecutedAt: time.Now(),
		}
	}

	t0 := time.Now()
	err := protocol.SubmitResult(ctx, s.client, s.cfg.ServerURL, s.cfg.AgentSecret, protocol.RawRunResult{
		RunID:      cmd.RunID,
		ScenarioID: cmd.ScenarioID,
		AgentID:    s.cfg.AgentID,
		Results:    results,
	})
	s.metrics.RecordResultSubmit(time.Since(t0))
	if err != nil {
		s.metrics.RecordHTTPError()
	}
}

func fakePayload(size int) string {
	if size <= 0 {
		return ""
	}
	b := make([]byte, size)
	for i := range b {
		b[i] = 'a' + byte(i%26)
	}
	return string(b)
}
