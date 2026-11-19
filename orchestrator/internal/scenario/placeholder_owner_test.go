package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// An unresolved bas-placeholder argument reaching execution is OUR
// arg-resolution defect, not an environment gap. It matches a "cannot find
// path" string, so without an explicit guard it would be classified
// missing-prerequisite → owner=environment → excluded from factory-validation
// FAIL, letting broken content reach Validated. It must be content-owned
// (owner=audspect) so it FAILs and stays visible.
func TestInterpret_UnresolvedPlaceholderIsContentOwnedNotEnvironment(t *testing.T) {
	r := Interpret(
		Step{TechniqueID: "T1046", Name: "Port Scan", Framework: "art"},
		ExecResult{ExitCode: 1, Stdout: `Cannot find path 'C:\Temp\bas-placeholder-ip_address' because it does not exist`},
	)
	if r.Result != models.ResultError {
		t.Fatalf("result = %q, want error", r.Result)
	}
	if r.ExecutionFailure == nil {
		t.Fatal("no ExecutionFailure attached to the error")
	}
	if r.ExecutionFailure.Owner != "audspect" {
		t.Errorf("owner = %q, want \"audspect\" (unresolved placeholder is our defect, not the environment's)", r.ExecutionFailure.Owner)
	}
}
