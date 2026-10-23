package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"audspect/agent/protocol"
)

// scenarioEnvelopePayload is a command_scenario payload carrying one dbprobe step.
func scenarioEnvelopePayload(t *testing.T) json.RawMessage {
	t.Helper()
	step := testDBProbeStep(nil)
	cmd := protocol.ScenarioCommand{
		RunID: "run-1", ScenarioID: "dbsim-test", Name: "dbsim",
		Steps: []protocol.ScenarioStep{{
			TaskID: "t1", Executor: "dbprobe", Command: "read_roles", ExecutionClass: "non_destructive",
			DBProbe: step.DBProbe,
		}},
	}
	b, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// connectWSStyleDispatch mirrors connectWS's exact verify-then-dispatch rule:
// the handler is reached ONLY when the real verifyCommandEnvelope accepts the
// envelope. Dispatch itself is replaced by directly executing the decoded
// dbprobe steps (the real dispatchVerifiedCommand needs a live server for
// runScenario). The verifier is the real one, not a mock.
func connectWSStyleDispatch(t *testing.T, a *Agent, raw []byte) (accepted bool) {
	t.Helper()
	env, err := a.verifyCommandEnvelope(raw, "command_scenario")
	if err != nil {
		return false
	}
	var cmd protocol.ScenarioCommand
	if err := json.Unmarshal(env.Payload, &cmd); err != nil {
		t.Fatalf("verified payload did not decode: %v", err)
	}
	for _, ws := range cmd.Steps {
		execStep(context.Background(), decodeStep(ws), nil)
	}
	return true
}

func TestDBProbeTamperedScenarioRefusedBeforeConnect(t *testing.T) {
	key := setupSigningTrust(t)
	fa := setupHappy(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}

	mk := func(id, nonce string) protocol.CommandEnvelope {
		now := time.Now().UTC()
		return protocol.CommandEnvelope{
			Version: protocol.CommandEnvelopeVersion, CommandID: id, CommandType: "command_scenario",
			AgentID: "abc123deadbeef01", IssuedAt: now, ExpiresAt: now.Add(60 * time.Second),
			Nonce: nonce, Payload: scenarioEnvelopePayload(t),
		}
	}

	t.Run("tampered payload after signing", func(t *testing.T) {
		signed := signEnvelopeForDispatchTest(t, key, mk("cmd-tamper", "n1"))
		// Change the host inside the signed payload without re-signing.
		tampered := bytes.Replace(signed, []byte("db.lab.internal"), []byte("evil.example.org"), 1)
		if bytes.Equal(tampered, signed) {
			t.Fatal("test bug: tamper did not change the bytes")
		}
		if connectWSStyleDispatch(t, a, tampered) {
			t.Fatal("tampered envelope was accepted")
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		raw, _ := json.Marshal(mk("cmd-unsigned", "n2")) // no Signature
		if connectWSStyleDispatch(t, a, raw) {
			t.Fatal("unsigned envelope was accepted")
		}
	})
	t.Run("signed by wrong key", func(t *testing.T) {
		other, _ := signingTestKey(t)
		raw := signEnvelopeForDispatchTest(t, other, mk("cmd-wrongkey", "n3"))
		if connectWSStyleDispatch(t, a, raw) {
			t.Fatal("envelope signed by an untrusted key was accepted")
		}
	})
	if fa.count("Connect") != 0 {
		t.Fatalf("adapter Connect called %d time(s) for rejected envelopes", fa.count("Connect"))
	}

	// Positive control + replay: the same properly signed envelope is accepted
	// once (and only then reaches the adapter), the replay is refused.
	good := signEnvelopeForDispatchTest(t, key, mk("cmd-good", "n4"))
	if !connectWSStyleDispatch(t, a, good) {
		t.Fatal("control: a valid signed envelope must be accepted")
	}
	if fa.count("Connect") != 1 {
		t.Fatalf("control: expected exactly one Connect, got %d", fa.count("Connect"))
	}
	if connectWSStyleDispatch(t, a, good) {
		t.Fatal("replayed envelope was accepted")
	}
	if fa.count("Connect") != 1 {
		t.Fatalf("replay reached the adapter: %d Connects", fa.count("Connect"))
	}
}
