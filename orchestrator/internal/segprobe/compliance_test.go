package segprobe

import (
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/segprobe/runstore"
)

func TestComplianceResults_DenyProbesMapToControlOutcomes(t *testing.T) {
	cases := []struct {
		verdict string
		want    models.CheckResult
	}{
		{"PASS", models.ResultBlocked},    // blocked with firewall evidence: the control worked
		{"FAIL", models.ResultFail},       // prohibited flow reached the target: segmentation failed
		{"UNKNOWN", models.ResultSkipped}, // no attributable evidence: not scored either way
		{"ERROR", models.ResultError},     // the probe could not run: a BAS problem, not a control result
	}
	for _, c := range cases {
		rows := []runstore.ProbeRow{{RunIndex: 1, Seq: 1, ProbeID: "p", Expect: "deny", Verdict: c.verdict, Reason: "r"}}
		got := ComplianceResults("run-1", rows)
		if len(got) != 1 {
			t.Fatalf("verdict %s: got %d results, want 1", c.verdict, len(got))
		}
		if got[0].Result != c.want {
			t.Errorf("verdict %s: result %s, want %s", c.verdict, got[0].Result, c.want)
		}
	}
}

func TestComplianceResults_AllowProbesAreNotSecurityEvidence(t *testing.T) {
	rows := []runstore.ProbeRow{{RunIndex: 1, Seq: 1, ProbeID: "p", Expect: "allow", Verdict: "PASS"}}
	if got := ComplianceResults("run-1", rows); len(got) != 0 {
		t.Fatalf("an allowed-flow probe is connectivity, not control evidence; got %d results", len(got))
	}
}

func TestComplianceResults_TechniqueAndIDAreSet(t *testing.T) {
	rows := []runstore.ProbeRow{{RunIndex: 2, Seq: 7, ProbeID: "swift-to-corp", Expect: "deny", Verdict: "PASS"}}
	got := ComplianceResults("run-9", rows)
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	r := got[0]
	if r.Technique.ID != "T1046" {
		t.Errorf("technique %s, want T1046", r.Technique.ID)
	}
	if r.ID == "" || r.ID == "run-9" {
		t.Errorf("result id %q must identify the run, run index and probe", r.ID)
	}
	if r.Framework != "segprobe" {
		t.Errorf("framework %q, want segprobe", r.Framework)
	}
}
