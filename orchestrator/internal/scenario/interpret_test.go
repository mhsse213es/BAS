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

// A BAS execution problem (malformed content, timeout, scheduler contention,
// missing prerequisite, DNS, interactive prompt, …) is NOT a security finding —
// it must classify as ERROR, never FAIL, so it is excluded from the score.
// Strings are taken verbatim from the Atomic Red Team selective-techniques report.
func TestInterpretARTExecutionErrors(t *testing.T) {
	cases := []struct {
		name   string
		r      ExecResult
		stdout string
	}{
		{"invalid syntax (T1112)", ExecResult{ExitCode: 1}, "ERROR: Invalid syntax."},
		{"invalid key name (T1112)", ExecResult{ExitCode: 1}, "ERROR: Invalid key name."},
		{"scheduler contention (T1082)", ExecResult{ExitCode: -1}, "schedule timeout: resource locks unavailable within 30s"},
		{"step timeout (T1059.003)", ExecResult{ExitCode: -1}, "step exceeded execute timeout of 120s"},
		{"dns failure (T1105)", ExecResult{ExitCode: 1}, "ssh: Could not resolve hostname adversary-host: No such host is known."},
		{"binary cannot execute (T1003.001)", ExecResult{ExitCode: 1}, "The system cannot execute the specified program."},
		{"prereq not found (T1105 OneDrive)", ExecResult{ExitCode: 1}, "OneDriveStandaloneUpdater.exe not found at C:\\...\\OneDrive. Test cannot continue."},
		{"interactive prompt (T1003.002 sam)", ExecResult{ExitCode: -1}, "File C:\\Windows\\TEMP\\sam already exists. Overwrite (Yes/No)?"},
		{"arch mismatch (T1082)", ExecResult{ExitCode: 1}, "Could not load file or assembly ... An attempt was made to load a program with an incorrect format."},
		{"msi invalid cmdline (T1569.002)", ExecResult{ExitCode: 1639}, "DESCRIPTION:"},
		{"curl cannot open (T1105)", ExecResult{ExitCode: 26}, "curl: cannot open 'c:\\temp\\atomictestfile.txt'"},
		{"generic nonzero, no signal", ExecResult{ExitCode: 1}, "Directory: C:\\temp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, detail := interpretART(c.r, c.stdout)
			if got != models.ResultError {
				t.Errorf("interpretART(%q, exit=%d) = %q, want error (detail=%q)", c.stdout, c.r.ExitCode, got, detail)
			}
		})
	}
}

// A non-zero exit that still shows the technique executed (e.g. a trailing
// cleanup line failed) is a genuine FAIL, not an execution error.
func TestInterpretARTRanToCompletionIsFail(t *testing.T) {
	for _, out := range []string{"The operation completed successfully.", "technique ran to completion"} {
		got, _ := interpretART(ExecResult{ExitCode: 1}, out)
		if got != models.ResultFail {
			t.Errorf("interpretART(%q, exit=1) = %q, want fail", out, got)
		}
	}
}
