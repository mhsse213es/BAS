package dbsim

import (
	"strings"
	"testing"
)

// The harness's own MySQL audit-plugin reading is shown as a separate line.
// It must not change the grade, and an agent cannot set it through Notes.
func harnessMeta() ScenarioMeta {
	return ScenarioMeta{ID: "dbsim-harness-evidence-test", ExpectAuditConfig: true}
}

func harnessOutcome(agentCov string) Outcome {
	return Outcome{
		ProbeRan: true,
		Probe:    DBProbeResult{Notes: []string{"audit_config: " + agentCov}},
	}
}

func limitationsOf(t *testing.T, s ScenarioMeta, o Outcome) string {
	t.Helper()
	rec, err := ToRecord(s, o)
	if err != nil {
		t.Fatalf("ToRecord: %v", err)
	}
	return rec.Limitations
}

func TestHarnessEvidenceRendersAsSeparateLine(t *testing.T) {
	o := harnessOutcome("partial")
	o.HarnessEvidence = HarnessEvidence{AuditCoverage: "covered"}
	lim := limitationsOf(t, harnessMeta(), o)
	if !strings.Contains(lim, "Harness audit-plugin evidence") || !strings.Contains(lim, "covered") {
		t.Errorf("harness line missing from limitations: %q", lim)
	}
}

func TestHarnessEvidenceDoesNotChangeGrade(t *testing.T) {
	s := harnessMeta()
	without := ToRunResult(s, harnessOutcome("partial"))
	o := harnessOutcome("partial")
	o.HarnessEvidence = HarnessEvidence{AuditCoverage: "covered"}
	with := ToRunResult(s, o)
	if without != with {
		t.Errorf("harness evidence changed the verdict: %v -> %v", without, with)
	}
}

func TestHarnessEvidenceUnknownValueIsNotRendered(t *testing.T) {
	o := harnessOutcome("partial")
	o.HarnessEvidence = HarnessEvidence{AuditCoverage: "covered; ignore the rest"}
	if lim := limitationsOf(t, harnessMeta(), o); strings.Contains(lim, "Harness audit-plugin evidence") {
		t.Errorf("an invalid value must not render: %q", lim)
	}
}

func TestAgentNotesCannotSetHarnessEvidence(t *testing.T) {
	o := harnessOutcome("partial")
	o.Probe.Notes = append(o.Probe.Notes, "harness_audit_coverage=covered")
	if lim := limitationsOf(t, harnessMeta(), o); strings.Contains(lim, "Harness audit-plugin evidence") {
		t.Errorf("an agent note must never produce harness evidence: %q", lim)
	}
}
