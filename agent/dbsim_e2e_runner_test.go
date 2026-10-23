//go:build dbsim_e2e

package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"audspect/agent/protocol"
)

// TestDBSimE2EStepRunner is the agent half of the dbsim end-to-end harness
// (orchestrator/internal/dbsim/dbrun/e2e_test.go). The production agent can
// only receive work over its enrolled WebSocket from a running orchestrator and
// has no one-shot mode, so the harness compiles THIS test binary
// (go test -c -tags dbsim_e2e) and runs it as a subprocess:
//
//   - the signed CommandEnvelope is verified by the real
//     (*Agent).verifyCommandEnvelope against a pinned signing certificate;
//   - each step then goes through the real gateStep and execStep, which reach
//     executeDBProbe, the real adapters and the real drivers;
//   - the resulting protocol.ExecResult values are written as JSON.
//
// Not exercised: the WebSocket transport, enrollment, run events and result
// upload (runScenario). It is skipped unless DBSIM_E2E_ENVELOPE is set.
//
// Inputs (env): DBSIM_E2E_ENVELOPE (envelope JSON file), DBSIM_E2E_SIGNER_CERT
// (PEM certificate of the signing key), DBSIM_E2E_AGENT_ID, DBSIM_E2E_RESULT_OUT
// (output file). Credentials and policy come from the usual BAS_DBCRED_* and
// BAS_DBPROBE_* environment variables of this process.
func TestDBSimE2EStepRunner(t *testing.T) {
	envPath := os.Getenv("DBSIM_E2E_ENVELOPE")
	if envPath == "" {
		t.Skip("DBSIM_E2E_ENVELOPE not set: this test only runs as the dbsim E2E agent subprocess")
	}
	certPath, agentID, outPath := os.Getenv("DBSIM_E2E_SIGNER_CERT"), os.Getenv("DBSIM_E2E_AGENT_ID"), os.Getenv("DBSIM_E2E_RESULT_OUT")
	if certPath == "" || agentID == "" || outPath == "" {
		t.Fatal("DBSIM_E2E_ENVELOPE is set but DBSIM_E2E_SIGNER_CERT, DBSIM_E2E_AGENT_ID or DBSIM_E2E_RESULT_OUT is missing")
	}
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read signer cert: %v", err)
	}
	t.Setenv("BAS_CERT_DIR", t.TempDir())
	if err := saveCommandSigningCert(certPEM); err != nil {
		t.Fatalf("pin signing cert: %v", err)
	}
	a := newAgent(Config{ServerURL: "http://orchestrator.invalid"}, Identity{AgentID: agentID})

	env, err := a.verifyCommandEnvelope(raw, "command_scenario")
	if err != nil {
		t.Fatalf("envelope rejected by the agent verifier: %v", err)
	}
	var cmd protocol.ScenarioCommand
	if err := json.Unmarshal(env.Payload, &cmd); err != nil {
		t.Fatalf("decode scenario command: %v", err)
	}
	results := make([]protocol.ExecResult, 0, len(cmd.Steps))
	for _, w := range cmd.Steps {
		step := decodeStep(w)
		if v := gateStep(step); v != nil {
			results = append(results, v.result)
			continue
		}
		results = append(results, execStep(context.Background(), step, nil))
	}
	out, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	if err := os.WriteFile(outPath, out, 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}
}
