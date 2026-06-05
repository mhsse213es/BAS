package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// An ART step must carry framework "art" so results route through interpretART
// (block-aware), and a known technique ID must resolve its tactic — otherwise
// the result loses its metadata and falls back to the generic "custom" path.
func TestBuildStepTagsARTFramework(t *testing.T) {
	s := Step{TechniqueID: "T1003", Name: "OS Credential Dumping", Framework: "art"}
	built, err := buildStep(s, "", "", nil)
	if err != nil {
		t.Fatalf("buildStep: %v", err)
	}
	if built.Framework != "art" {
		t.Errorf("Framework = %q, want art", built.Framework)
	}

	meta := BuildStepMeta([]ScenarioStep{built})
	m, ok := meta[built.TaskID]
	if !ok {
		t.Fatalf("BuildStepMeta missing TaskID %s", built.TaskID)
	}
	if m.Framework != "art" || m.TechniqueID != "T1003" {
		t.Errorf("StepMeta = %+v, want framework=art technique=T1003", m)
	}
}

// Reconstructing the Step from persisted StepMeta must yield a result with the
// correct framework routing and a resolved tactic (not the empty "()" fallback).
func TestInterpretFromStepMetaResolvesTactic(t *testing.T) {
	m := StepMeta{TechniqueID: "T1003", Name: "OS Credential Dumping", Framework: "art"}
	step := Step{TechniqueID: m.TechniqueID, Name: m.Name, Framework: m.Framework}
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: "lsass dumped"})

	if res.Framework != "art" {
		t.Errorf("Framework = %q, want art", res.Framework)
	}
	if res.Technique.Tactic != "credential-access" {
		t.Errorf("Tactic = %q, want credential-access", res.Technique.Tactic)
	}
	if res.Result != "fail" { // exit 0, not blocked → technique executed
		t.Errorf("Result = %q, want fail", res.Result)
	}
}

func TestInterpretARTBlockDetection(t *testing.T) {
	cases := []struct {
		name   string
		r      ExecResult
		stdout string
		want   models.CheckResult
	}{
		{"plain access denied", ExecResult{ExitCode: 1}, "Access is denied.", models.ResultPass},
		{"defender quarantine", ExecResult{ExitCode: 0}, "Operation did not complete successfully because the file contains a virus", models.ResultPass},
		{"group policy block", ExecResult{ExitCode: 1}, "This program is blocked by group policy", models.ResultPass},
		{"silent access-denied exit (win32 5)", ExecResult{ExitCode: 5}, "", models.ResultPass},
		{"silent NTSTATUS access-denied (signed)", ExecResult{ExitCode: -1073741790}, "", models.ResultPass},
		{"technique ran, exit 0", ExecResult{ExitCode: 0}, "whoami\\nDESKTOP\\\\admin", models.ResultFail},
		{"technique errored, benign nonzero", ExecResult{ExitCode: 1}, "the term is not recognized", models.ResultFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := interpretART(c.r, c.stdout)
			if got != c.want {
				t.Errorf("interpretART(%q, exit=%d) = %q, want %q", c.stdout, c.r.ExitCode, got, c.want)
			}
		})
	}
}
