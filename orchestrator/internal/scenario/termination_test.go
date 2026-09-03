package scenario

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// The evidence sentence must state measurements and stop. An agent that did not
// report (nil) must produce nothing at all — rendering "no output" there would
// assert silence the platform never measured.
func TestTerminationEvidence(t *testing.T) {
	cases := []struct {
		name string
		in   *models.StepTermination
		want string
	}{
		{"not reported", nil, ""},
		{"silent", &models.StepTermination{OutputBytes: 0, SilenceMs: 120000},
			" It produced no output at any point before it was terminated."},
		{"busy", &models.StepTermination{OutputBytes: 4404019, SilenceMs: 300},
			" It produced 4.2 MB of output, most recently 300ms before it was terminated."},
		{"stalled", &models.StepTermination{OutputBytes: 2048, SilenceMs: 90000},
			" It produced 2.0 KB of output, most recently 1m30s before it was terminated."},
	}
	for _, tc := range cases {
		if got := terminationEvidence(tc.in); got != tc.want {
			t.Errorf("%s:\n got  %q\n want %q", tc.name, got, tc.want)
		}
	}
}

// The evidence must reach the client-facing detail line, because that is the
// only place an analyst sees it — Interpret writes its own detail for a
// timed-out step and never falls through to the agent's stderr note.
func TestInterpret_TimeoutDetailCarriesEvidence(t *testing.T) {
	step := Step{TechniqueID: "T1552.001", Name: "Credentials In Files", Framework: "art"}
	res := ExecResult{
		TaskID:     "t1",
		ExitCode:   -1,
		Stderr:     "grep: /proc/1/mem: Permission denied",
		DurationMs: 120000,
		TimedOut:   true,
		Termination: &models.StepTermination{
			Reason: models.TermExecutionTimeout, ElapsedMs: 120000,
			OutputBytes: 4404019, SilenceMs: 300,
		},
	}

	got := Interpret(step, res)

	if got.Result != models.ResultError {
		t.Fatalf("Result = %v, want ERROR — evidence must not change the verdict", got.Result)
	}
	if !strings.Contains(got.Details, "4.2 MB") || !strings.Contains(got.Details, "300ms") {
		t.Errorf("details lost the termination evidence:\n%s", got.Details)
	}
	// The structured record must survive onto the result, not only the prose:
	// SimulationResult is stored whole in raw_result JSONB, and per-technique
	// timeout budgets are meant to be derived by querying these numbers rather
	// than by parsing the sentence above.
	if got.Termination == nil {
		t.Fatal("Termination did not reach the SimulationResult — it would not be persisted")
	}
	if got.Termination.Reason != models.TermExecutionTimeout || got.Termination.OutputBytes != 4404019 {
		t.Errorf("Termination = %+v, want reason=%s output=4404019",
			got.Termination, models.TermExecutionTimeout)
	}
}

// A result from an agent that predates the field must render exactly as it did
// before — the whole change is behaviour-preserving for existing endpoints.
func TestInterpret_TimeoutWithoutEvidenceIsUnchanged(t *testing.T) {
	step := Step{TechniqueID: "T1552.001", Name: "Credentials In Files", Framework: "art"}
	res := ExecResult{TaskID: "t1", ExitCode: -1, DurationMs: 120000, TimedOut: true}

	got := Interpret(step, res)

	if got.Result != models.ResultError {
		t.Fatalf("Result = %v, want ERROR", got.Result)
	}
	if strings.Contains(got.Details, "It produced") {
		t.Errorf("asserted output evidence for an agent that reported none:\n%s", got.Details)
	}
	if !strings.Contains(got.Details, "killed after 2m0s without completing") {
		t.Errorf("legacy detail text changed:\n%s", got.Details)
	}
}

// classifyExecution is reachable directly (ART path); it must carry the same
// evidence and the same ERROR verdict.
func TestClassifyExecution_TimeoutCarriesEvidence(t *testing.T) {
	outcome, reason, detail := classifyExecution(ExecResult{
		TimedOut:    true,
		DurationMs:  120000,
		Termination: &models.StepTermination{Reason: models.TermExecutionTimeout, OutputBytes: 0, SilenceMs: 120000},
	}, "Permission denied")

	if outcome != OutcomeError || reason != ErrTimeout {
		t.Fatalf("outcome=%v reason=%v, want ERROR/timeout", outcome, reason)
	}
	if !strings.Contains(detail, "no output at any point") {
		t.Errorf("detail lost the evidence: %s", detail)
	}
}

// The agent and the orchestrator are separate Go modules, so nothing but this
// test enforces that the two struct definitions still agree on the wire.
// The literal below is the agent's own JSON shape (agent/protocol/messages.go).
func TestStepTermination_DecodesAgentWireShape(t *testing.T) {
	const wire = `{
		"taskId": "t1",
		"exitCode": -1,
		"stdout": "",
		"stderr": "step exceeded execute timeout of 120s; output=4.2 MB; last output=300ms ago",
		"durationMs": 120000,
		"executedAt": "2026-09-03T10:00:00Z",
		"timedOut": true,
		"termination": {
			"reason": "execution_timeout",
			"elapsedMs": 120000,
			"outputBytes": 4404019,
			"silenceMs": 300
		}
	}`

	var got ExecResult
	if err := json.Unmarshal([]byte(wire), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Termination == nil {
		t.Fatal("termination did not decode — the field names have drifted from the agent's")
	}
	if got.Termination.Reason != models.TermExecutionTimeout {
		t.Errorf("Reason = %q, want %q", got.Termination.Reason, models.TermExecutionTimeout)
	}
	if got.Termination.ElapsedMs != 120000 || got.Termination.OutputBytes != 4404019 || got.Termination.SilenceMs != 300 {
		t.Errorf("decoded %+v, want elapsed=120000 output=4404019 silence=300", got.Termination)
	}
}
