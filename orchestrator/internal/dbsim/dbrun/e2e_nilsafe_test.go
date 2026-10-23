//go:build dbsim_e2e

package dbrun

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
)

// Live run 1: the agent vetoed DB-06 (DBProbe nil) and checkStep panicked on
// ex.DBProbe.Notes. A veto must be reported as an ordinary failure.
func TestCheckStepIsNilSafeWhenTheAgentVetoed(t *testing.T) {
	ex := AgentExec{ExitCode: -1, Vetoed: true, VetoedBlockSource: "catalog", VetoedExecutionClass: "destructive", VetoedActionKey: "dbprobe_mutation"}
	in := input("dbsim-db06-account-revocation", dbsim.ProbeAuthAfterRevoke, ex)
	ev, err := Evaluate(context.Background(), nil, in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev.Report.Reason, "destructive") {
		t.Fatalf("the veto reason must name the signed class: %q", ev.Report.Reason)
	}
	rec := &recorder{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("checkStep panicked: %v", r)
			}
		}()
		checkStep(rec, e2eConfig{engine: "postgresql"}, "dbsim-db06-account-revocation", in.Spec, ev, ex)
	}()
	if len(rec.errs) == 0 || !strings.Contains(rec.errs[0], "destructive") || !strings.Contains(rec.errs[0], "catalog") {
		t.Fatalf("the veto must be reported as a normal error naming source and class: %v", rec.errs)
	}
}

type recorder struct{ errs []string }

func (r *recorder) Helper()                   {}
func (r *recorder) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
