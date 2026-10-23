package main

import (
	"bytes"
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

// TestDBProbeTamperedScenarioRefusedBeforeConnect drives the REAL production
// decision point connectWS uses (Agent.verifyAndDispatch -> real
// verifyCommandEnvelope -> real dispatchVerifiedCommand) with a command_scenario
// envelope carrying a dbprobe step. Every rejected envelope must (a) return
// false, (b) never reach dispatchVerifiedCommand (observed through the
// previous-scenario canceller that command_scenario dispatch always invokes),
// and (c) never call the adapter's Connect.
func TestDBProbeTamperedScenarioRefusedBeforeConnect(t *testing.T) {
	key := setupSigningTrust(t)
	fa := setupHappy(t)
	const agentID = "abc123deadbeef01"
	a := newAgent(Config{ServerURL: "http://orchestrator.local:9000"}, Identity{AgentID: agentID})

	dispatched := false
	a.scenarioMu.Lock()
	a.cancelScenario = func() { dispatched = true }
	a.scenarioMu.Unlock()

	mk := func(id, nonce string) protocol.CommandEnvelope {
		now := time.Now().UTC()
		return protocol.CommandEnvelope{
			Version: protocol.CommandEnvelopeVersion, CommandID: id, CommandType: "command_scenario",
			AgentID: agentID, IssuedAt: now, ExpiresAt: now.Add(60 * time.Second),
			Nonce: nonce, Payload: scenarioEnvelopePayload(t),
		}
	}
	reject := func(name string, raw []byte) {
		t.Helper()
		if a.verifyAndDispatch("command_scenario", raw) {
			t.Errorf("%s: envelope was accepted", name)
		}
		if dispatched {
			t.Errorf("%s: rejected envelope reached dispatchVerifiedCommand", name)
		}
		if n := fa.count("Connect"); n != 0 {
			t.Errorf("%s: adapter Connect called %d time(s)", name, n)
		}
	}

	signed := signEnvelopeForDispatchTest(t, key, mk("cmd-tamper", "n1"))
	tampered := bytes.Replace(signed, []byte("db.lab.internal"), []byte("evil.example.org"), 1)
	if bytes.Equal(tampered, signed) {
		t.Fatal("test bug: tamper did not change the bytes")
	}
	reject("tampered payload", tampered)

	unsigned, _ := json.Marshal(mk("cmd-unsigned", "n2"))
	reject("unsigned", unsigned)

	other, _ := signingTestKey(t)
	reject("wrong key", signEnvelopeForDispatchTest(t, other, mk("cmd-wrongkey", "n3")))

	wrongAgent := mk("cmd-wrongagent", "n4")
	wrongAgent.AgentID = "ffffffffffffffff"
	reject("wrong agentId", signEnvelopeForDispatchTest(t, key, wrongAgent))

	expired := mk("cmd-expired", "n5")
	expired.IssuedAt = time.Now().UTC().Add(-2 * time.Hour)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	reject("expired", signEnvelopeForDispatchTest(t, key, expired))

	// Replay: a validly signed envelope is accepted by the verifier once
	// (consuming its command id); the identical bytes are then refused by the
	// real dispatch path. (Dispatching the accepted scenario itself would start
	// a real runScenario, so the first acceptance is made via the verifier.)
	good := signEnvelopeForDispatchTest(t, key, mk("cmd-replay", "n6"))
	if _, err := a.verifyCommandEnvelope(good, "command_scenario"); err != nil {
		t.Fatalf("control: valid envelope must verify: %v", err)
	}
	reject("replayed", good)
}

// --- step-loop pre-execution gates (gateStep is what the step loop calls) ---

func TestDBProbeGateStepWiring(t *testing.T) {
	ok := testDBProbeStep(nil)
	if v := gateStep(ok); v != nil {
		t.Fatalf("clean non_destructive dbprobe step vetoed: %+v", v)
	}

	// dbsim pre-gate: baggage / missing spec.
	bad := testDBProbeStep(nil)
	bad.Cleanup = "rm -rf /tmp/x"
	if v := gateStep(bad); v == nil || v.source != "dbsim_gate" || !v.result.Vetoed {
		t.Fatalf("cleanup baggage must be vetoed by the dbsim gate: %+v", v)
	}
	nospec := testDBProbeStep(nil)
	nospec.DBProbe = nil
	if v := gateStep(nospec); v == nil || v.source != "dbsim_gate" {
		t.Fatalf("missing spec must be vetoed by the dbsim gate: %+v", v)
	}

	// B5 still applies to dbprobe steps: unknown / missing / destructive class.
	for _, class := range []string{"", "bogus", "destructive"} {
		s := testDBProbeStep(nil)
		s.ExecutionClass = class
		v := gateStep(s)
		if v == nil || v.source == "dbsim_gate" || !v.result.Vetoed || v.result.VetoedBlockSource != v.source {
			t.Errorf("class %q: expected a B5 veto, got %+v", class, v)
		}
	}

	// A non-dbprobe destructive shell step is still vetoed exactly as before.
	sh := ScenarioStep{TaskID: "s", Executor: "cmd", Command: "vssadmin delete shadows /all /quiet", ExecutionClass: "non_destructive"}
	if v := gateStep(sh); v == nil || v.source != "local_backstop" {
		t.Fatalf("local backstop must still veto destructive shell text: %+v", v)
	}
	// A benign shell step with a good class passes both gates.
	if v := gateStep(ScenarioStep{TaskID: "s", Executor: "bash", Command: "echo hi", ExecutionClass: "non_destructive"}); v != nil {
		t.Fatalf("benign shell step vetoed: %+v", v)
	}
}
