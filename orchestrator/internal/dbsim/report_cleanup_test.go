package dbsim

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCleanupIncidentGradesErrorNeverPassOrSkipped(t *testing.T) {
	withIncident := func(o Outcome) Outcome { o.SafetyIncident = true; return o }
	withStatus := func(s string) func(Outcome) Outcome {
		return func(o Outcome) Outcome { o.CleanupStatus = s; return o }
	}
	probeIncident := func(o Outcome) Outcome { o.Probe.SafetyIncident = true; return o }
	probeStatus := func(s string) func(Outcome) Outcome {
		return func(o Outcome) Outcome { o.Probe.CleanupStatus = s; return o }
	}
	skippedOutcome := func(o Outcome) Outcome { o.ProbeRan = false; o.Skipped = "no audit source"; return o }
	gateOutcome := func(o Outcome) Outcome { o.ProbeRan = false; o.GateRefusal = "out of scope"; return o }

	cases := []struct {
		name string
		base Outcome
		mut  func(Outcome) Outcome
	}{
		{"pass_otherwise_with_incident", denied(), withIncident},
		{"pass_otherwise_status_residual", denied(), withStatus("residual")},
		{"pass_otherwise_status_failed", denied(), withStatus("failed")},
		{"pass_otherwise_probe_incident", denied(), probeIncident},
		{"pass_otherwise_probe_status_residual", denied(), probeStatus("residual")},
		{"pass_otherwise_probe_status_failed", denied(), probeStatus("failed")},
		{"fail_otherwise_with_incident", succeeded(), withIncident},
		{"skipped_otherwise_with_incident", denied(), func(o Outcome) Outcome { return withIncident(skippedOutcome(o)) }},
		{"gate_refusal_with_incident", denied(), func(o Outcome) Outcome { return withIncident(gateOutcome(o)) }},
		{"unrecognised_status_fails_closed", denied(), withStatus("weird")},
	}
	for _, c := range cases {
		o := c.mut(c.base)
		if got := ToRunResult(meta(), o); got != ResultError {
			t.Errorf("%s: got %s want ERROR", c.name, got)
		}
		rep, err := BuildReport(meta(), o)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if rep.Result != ResultError {
			t.Errorf("%s: stored result %s", c.name, rep.Result)
		}
		if !strings.Contains(rep.Record.Limitations, "cleanup") {
			t.Errorf("%s: limitations lack the cleanup incident line: %q", c.name, rep.Record.Limitations)
		}
		if !strings.Contains(rep.Reason, "cleanup") {
			t.Errorf("%s: reason %q", c.name, rep.Reason)
		}
	}
}

func TestCleanupOKAndNotApplicableLeaveGradingUnchanged(t *testing.T) {
	for _, st := range []string{"", "ok", "not_applicable"} {
		o := denied()
		o.CleanupStatus = st
		if got := ToRunResult(meta(), o); got != ResultPass {
			t.Errorf("outcome status %q: got %s want PASS", st, got)
		}
		o = denied()
		o.Probe.CleanupStatus = st
		if got := ToRunResult(meta(), o); got != ResultPass {
			t.Errorf("probe status %q: got %s want PASS", st, got)
		}
		f := succeeded()
		f.CleanupStatus = st
		if got := ToRunResult(meta(), f); got != ResultFail {
			t.Errorf("fail-otherwise with status %q: got %s want FAIL", st, got)
		}
		rep, err := BuildReport(meta(), o)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(rep.Record.Limitations, "safety incident") {
			t.Errorf("status %q must not add an incident limitation: %q", st, rep.Record.Limitations)
		}
	}
}

func TestStoredReportRecordsCleanupFieldsRedacted(t *testing.T) {
	o := denied()
	o.SafetyIncident = true
	o.CleanupStatus = "residual password=hunter2"
	rep, err := BuildReport(meta(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Evidence.SafetyIncident || !strings.HasPrefix(rep.Evidence.CleanupStatus, "residual") {
		t.Fatalf("evidence must record both fields: %+v", rep.Evidence)
	}
	b, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("secret leaked into the stored report")
	}
	if !strings.Contains(string(b), `"safetyIncident":true`) || !strings.Contains(string(b), `"cleanupStatus"`) {
		t.Fatalf("stored report lacks cleanup fields: %s", b)
	}
}

func TestCleanupEvidenceFieldsOmittedWhenEmptyAndHashStable(t *testing.T) {
	rep, err := BuildReport(meta(), denied())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rep.Evidence)
	if strings.Contains(string(b), "cleanupStatus") || strings.Contains(string(b), "safetyIncident") {
		t.Fatalf("empty cleanup fields must be omitted from evidence: %s", b)
	}
	// A recorded incident must change the integrity hash.
	o := denied()
	o.SafetyIncident = true
	rep2, _ := BuildReport(meta(), o)
	if rep.Record.Provenance.IntegrityHash == rep2.Record.Provenance.IntegrityHash {
		t.Fatal("integrity hash must cover the cleanup fields")
	}
}

func TestMirrorCleanupFieldsOmitEmptyAndOlderResultsDecode(t *testing.T) {
	b, _ := json.Marshal(DBProbeResult{})
	if strings.Contains(string(b), "cleanupStatus") || strings.Contains(string(b), "safetyIncident") {
		t.Fatalf("empty cleanup fields must be omitted: %s", b)
	}
	var back DBProbeResult
	if err := json.Unmarshal([]byte(`{"denied":false,"rowsRead":1}`), &back); err != nil || back.SafetyIncident || back.CleanupStatus != "" {
		t.Fatalf("older result must decode: %v %+v", err, back)
	}
}

func TestCleanupStatusValuesMatchAgent(t *testing.T) {
	got := []string{CleanupNotApplicable, CleanupOK, CleanupResidual, CleanupFailed}
	want := []string{"not_applicable", "ok", "residual", "failed"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("status %d: %q want %q", i, got[i], want[i])
		}
	}
}
