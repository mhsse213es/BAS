package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

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
