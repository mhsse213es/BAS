package reporting

import (
	"bytes"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// TestGenerateHTML_TechniqueMatrixGroupsStepsUnderOneTechnique checks the
// Detection Validation matrix renders one technique block with a rowspan
// equal to its step count, and one <tr> per step, instead of repeating the
// technique cell for every step.
func TestGenerateHTML_TechniqueMatrixGroupsStepsUnderOneTechnique(t *testing.T) {
	r := &FullReport{
		Agent: models.Agent{AgentID: "WIN-01", Hostname: "WIN-01"},
		TechniqueMatrix: []TechniqueRow{
			{TechniqueID: "T1059.001", TechniqueName: "PowerShell", Tactic: "execution", Severity: "high", StepName: "primary step", ExecVerdict: "fail"},
			{TechniqueID: "T1059.001", TechniqueName: "PowerShell", Tactic: "execution", Severity: "high", StepName: "counterpart step", ExecVerdict: "pass"},
		},
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, r, nil); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `rowspan="2"`) {
		t.Error(`expected the technique cells to span two step rows (rowspan="2")`)
	}
	if strings.Count(out, "T1059.001</code>") != 1 {
		t.Errorf("technique ID rendered %d times, want exactly 1", strings.Count(out, "T1059.001</code>"))
	}
	for _, step := range []string{"primary step", "counterpart step"} {
		if !strings.Contains(out, step) {
			t.Errorf("step %q missing from the matrix", step)
		}
	}
}
