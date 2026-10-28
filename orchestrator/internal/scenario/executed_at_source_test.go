package scenario

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func TestInterpret_ExecutedAtSourceIsAgentWhenAgentSuppliedTimestamp(t *testing.T) {
	agentTime := time.Date(2026, 10, 28, 9, 15, 0, 0, time.UTC)
	sim := Interpret(Step{TechniqueID: "T1003.006", Name: "dcsync probe"}, ExecResult{
		TaskID: "t", ExitCode: 0, Stdout: "EXEC T1003.006: refused", ExecutedAt: agentTime,
	})
	if sim.ExecutedAt != agentTime {
		t.Fatalf("ExecutedAt = %s, want the agent-supplied %s", sim.ExecutedAt, agentTime)
	}
	if sim.ExecutedAtSource != models.ExecutedAtSourceAgent {
		t.Fatalf("ExecutedAtSource = %q, want %q", sim.ExecutedAtSource, models.ExecutedAtSourceAgent)
	}
}

func TestInterpret_ExecutedAtSourceIsOrchestratorFallbackWhenAgentOmittedTimestamp(t *testing.T) {
	before := time.Now().Add(-time.Second)
	sim := Interpret(Step{TechniqueID: "T1003.006", Name: "dcsync probe"}, ExecResult{
		TaskID: "t", ExitCode: 0, Stdout: "EXEC T1003.006: refused",
	})
	after := time.Now().Add(time.Second)

	if sim.ExecutedAtSource != models.ExecutedAtSourceOrchestratorFallback {
		t.Fatalf("ExecutedAtSource = %q, want %q -- a substituted submission time must never be labelled as agent-observed",
			sim.ExecutedAtSource, models.ExecutedAtSourceOrchestratorFallback)
	}
	// Compatibility: the fallback timestamp itself is preserved as before.
	if sim.ExecutedAt.Before(before) || sim.ExecutedAt.After(after) {
		t.Fatalf("fallback ExecutedAt = %s, want approximately now", sim.ExecutedAt)
	}
}

func TestExecutedAtSourceConstantsAreTheClosedSet(t *testing.T) {
	if models.ExecutedAtSourceAgent != "agent" {
		t.Fatalf("agent source = %q, want \"agent\"", models.ExecutedAtSourceAgent)
	}
	if models.ExecutedAtSourceOrchestratorFallback != "orchestrator_fallback" {
		t.Fatalf("fallback source = %q, want \"orchestrator_fallback\"", models.ExecutedAtSourceOrchestratorFallback)
	}
}
