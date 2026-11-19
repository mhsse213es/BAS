package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

func interpretFailing(out string, exit int, timedOut bool) models.SimulationResult {
	return Interpret(Step{TechniqueID: "T1046", Name: "T1046 - Test 3", Framework: "art"},
		ExecResult{Stdout: out, ExitCode: exit, TimedOut: timedOut})
}

func TestExecutionFailure_ClassifiesTheObservedErrors(t *testing.T) {
	cases := []struct {
		name, out, category, status, owner string
		exit                               int
		timedOut                           bool
	}{
		{"missing tool", "nmap : The term 'nmap' is not recognized as the name of a cmdlet", "missing_dependency", "not_executed", "environment", 1, false},
		{"missing prerequisite", "The system cannot find the file specified", "missing_prerequisite", "not_executed", "environment", 1, false},
		{"malformed", "Error: Invalid syntax.", "content_defect", "execution_error", "audspect", 1, false},
		{"timeout", "", "timeout", "timed_out", "environment", 0, true},
		{"resource exists", "A subdirectory or file already exists", "environment_conflict", "not_executed", "environment", 1, false},
	}
	for _, c := range cases {
		r := interpretFailing(c.out, c.exit, c.timedOut)
		if r.Result != models.ResultError {
			t.Errorf("%s: result = %s, want error", c.name, r.Result)
			continue
		}
		f := r.ExecutionFailure
		if f == nil {
			t.Errorf("%s: no execution failure", c.name)
			continue
		}
		if f.Category != c.category || f.ExecutionStatus != c.status || f.Owner != c.owner {
			t.Errorf("%s: got %s/%s/%s want %s/%s/%s", c.name, f.Category, f.ExecutionStatus, f.Owner, c.category, c.status, c.owner)
		}
		if f.SecurityVerdict != "not_assessed" || f.EvidenceConfidence != "none" || f.Reason == "" || f.Remediation == "" {
			t.Errorf("%s: incomplete assessment %+v", c.name, f)
		}
		if f.RawError == "" && c.out != "" {
			t.Errorf("%s: the raw error was dropped", c.name)
		}
	}
}

func TestExecutionFailure_NilForEveryNonErrorResult(t *testing.T) {
	if r := interpretFailing("Ability executed", 0, false); r.ExecutionFailure != nil {
		t.Errorf("a normal result carried an execution failure: %+v", r.ExecutionFailure)
	}
}
