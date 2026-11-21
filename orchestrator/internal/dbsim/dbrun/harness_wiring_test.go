package dbrun

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

// The lab harness supplies HarnessEvidence on the step input. It must reach the
// outcome and the record, and nothing the agent reports may set it.
func TestHarnessEvidenceFromStepInputReachesOutcomeAndRecord(t *testing.T) {
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("al1", pT0.Add(14*time.Second), realStmt(pMarker)))}
	in := input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10, "shape=wide_select", "rows_read=10"))
	in.HarnessEvidence = dbsim.HarnessEvidence{AuditCoverage: "covered"}
	ev := mustEval(t, c, in)
	if ev.Outcome.HarnessEvidence.AuditCoverage != "covered" {
		t.Fatalf("outcome harness evidence = %+v", ev.Outcome.HarnessEvidence)
	}
	if !strings.Contains(ev.Record.Limitations, "Harness audit-plugin evidence") {
		t.Fatalf("record lacks the harness line: %q", ev.Record.Limitations)
	}
}

func TestAgentNotesCannotSetHarnessEvidenceInPipeline(t *testing.T) {
	c := &fakeConn{reply: alertsReply(elasticLikeAlert("al1", pT0.Add(14*time.Second), realStmt(pMarker)))}
	in := input("dbsim-db05-suspicious-read", "suspicious_read", okExec(10, "shape=wide_select", "rows_read=10", "harness_audit_coverage=covered"))
	ev := mustEval(t, c, in)
	if ev.Outcome.HarnessEvidence.AuditCoverage != "" {
		t.Fatalf("agent note produced harness evidence: %+v", ev.Outcome.HarnessEvidence)
	}
}
