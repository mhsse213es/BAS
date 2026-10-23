package dbsim

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func meta() ScenarioMeta {
	return ScenarioMeta{
		ID: "DB-01", Version: "1", ControlObjective: "restricted table unreadable",
		Preconditions: "fixture loaded", SyntheticDataManifest: "synthetic rows only",
		ActionAttempted: "SELECT from restricted table", ExpectedPrevention: "deny",
		ExpectDetection: true, Engine: "postgresql", TargetID: "t1", Mode: ModeLab,
	}
}

func okCorr() Correlation {
	return Correlation{Evaluated: true, Telemetry: dlpreport.TelemetryPresent,
		Response: dlpreport.ResponseAlerted, Match: MatchExactMarker, Alerts: 1}
}

func denied() Outcome {
	return Outcome{ProbeRan: true, Probe: DBProbeResult{Denied: true, ErrorClass: "permission_denied"},
		Corr: okCorr(), CollectedAt: t0, Principal: "app_ro", Marker: "m1", RunID: "r1"}
}

func succeeded() Outcome {
	o := denied()
	o.Probe = DBProbeResult{RowsRead: 3}
	return o
}

func TestDeniedProbeMapsToEnforcementBlocked(t *testing.T) {
	r, err := ToRecord(meta(), denied())
	if err != nil || r.Enforcement != dlpreport.EnforcementBlocked {
		t.Fatalf("got %v %v", r.Enforcement, err)
	}
}

func TestSucceededProbeMapsToEnforcementAllowed(t *testing.T) {
	r, err := ToRecord(meta(), succeeded())
	if err != nil || r.Enforcement != dlpreport.EnforcementAllowed {
		t.Fatalf("got %v %v", r.Enforcement, err)
	}
}

func TestSucceededButAlertedKeepsDimensionsSeparate(t *testing.T) {
	m, o := meta(), succeeded()
	r, err := ToRecord(m, o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Enforcement != dlpreport.EnforcementAllowed || r.Telemetry != dlpreport.TelemetryPresent || r.Response != dlpreport.ResponseAlerted {
		t.Fatalf("record %+v", r)
	}
	rep, err := BuildReport(m, o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result != ResultFail || rep.Dimensions.Prevention != DimFail || rep.Dimensions.Detection != DimPass {
		t.Fatalf("%+v", rep)
	}
	b, _ := rep.JSON()
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	d := back["dimensions"].(map[string]any)
	if d["prevention"] != "fail" || d["detection"] != "pass" {
		t.Fatalf("stored dims %v", d)
	}
}

func TestUnsupportedAuditMapsToSkippedNotPass(t *testing.T) {
	o := Outcome{Skipped: "audit plugin missing", CollectedAt: t0, Marker: "m"}
	if got := ToRunResult(meta(), o); got != ResultSkipped {
		t.Fatalf("got %s", got)
	}
}

func TestUncertainDimensionWithoutLimitationsFailsValidate(t *testing.T) {
	r := dlpreport.Record{Enforcement: dlpreport.EnforcementAllowed, Classification: dlpreport.ClassificationCorrect,
		Telemetry: dlpreport.TelemetryUnverifiable, Response: dlpreport.ResponseAlerted}
	if r.Validate() == nil {
		t.Fatal("want Validate error")
	}
	// ToRecord must surface it when the caller supplies an uncertain
	// dimension without a limitation.
	o := succeeded()
	o.Corr = Correlation{Evaluated: true, Telemetry: dlpreport.TelemetryUnverifiable, Response: dlpreport.ResponseAlerted}
	o.Classification = dlpreport.ClassificationCorrect
	if _, err := ToRecord(meta(), o); err == nil {
		t.Fatal("ToRecord should return Validate error")
	}
	o.Corr.Limitations = "SIEM connector cannot match markers"
	if _, err := ToRecord(meta(), o); err != nil {
		t.Fatal(err)
	}
}

func TestNoSecretInRecordFields(t *testing.T) {
	o := succeeded()
	o.Probe.Notes = []string{"connect failed dsn postgres://app:S3cretPw@db:5432/x password=hunter2"}
	o.ExecutionError = "token=abc123 boom"
	m := meta()
	m.ActionAttempted = "login with pwd: topsecret"
	rep, err := BuildReport(m, o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := rep.JSON()
	for _, s := range []string{"S3cretPw", "hunter2", "abc123", "topsecret"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("secret %q leaked: %s", s, b)
		}
	}
	if !strings.Contains(string(b), "[REDACTED]") {
		t.Fatal("expected redaction marker")
	}
}

func TestGradeTable(t *testing.T) {
	absent := okCorr()
	absent.Telemetry = dlpreport.TelemetryAbsent
	delayed := okCorr()
	delayed.Telemetry = dlpreport.TelemetryDelayed
	unver := okCorr()
	unver.Telemetry = dlpreport.TelemetryUnverifiable
	ambig := okCorr()
	ambig.Match = MatchAmbiguous
	timeout := denied()
	timeout.Probe = DBProbeResult{ErrorClass: "timeout"}
	execErr := denied()
	execErr.ExecutionError = "dispatch failed"
	gate := denied()
	gate.GateRefusal = "target not in scope"
	gate.ProbeRan = false
	noRan := Outcome{CollectedAt: t0}
	nocorr := denied()
	nocorr.Corr = Correlation{}
	noExpect := meta()
	noExpect.ExpectedPrevention, noExpect.ExpectDetection = "", false

	cases := []struct {
		name string
		m    ScenarioMeta
		o    Outcome
		want RunResult
	}{
		{"all_positive_pass", meta(), denied(), ResultPass},
		{"execution_error_is_error", meta(), execErr, ResultError},
		{"timeout_is_error", meta(), timeout, ResultError},
		{"expected_unverifiable_detection_is_error", meta(), func() Outcome { o := denied(); o.Corr = unver; return o }(), ResultError},
		{"ambiguous_match_is_error", meta(), func() Outcome { o := denied(); o.Corr = ambig; return o }(), ResultError},
		{"no_correlation_expected_detection_is_error", meta(), nocorr, ResultError},
		{"absent_detection_is_fail", meta(), func() Outcome { o := denied(); o.Corr = absent; return o }(), ResultFail},
		{"delayed_detection_is_fail", meta(), func() Outcome { o := denied(); o.Corr = delayed; return o }(), ResultFail},
		{"allowed_when_deny_expected_is_fail", meta(), succeeded(), ResultFail},
		{"gate_refusal_is_skipped", meta(), gate, ResultSkipped},
		{"probe_not_run_no_reason_is_error", meta(), noRan, ResultError},
		{"nothing_expected_is_error_not_vacuous_pass", noExpect, denied(), ResultError},
		{"unverifiable_beats_fail", meta(), func() Outcome { o := succeeded(); o.Corr = unver; return o }(), ResultError},
	}
	for _, c := range cases {
		if got := ToRunResult(c.m, c.o); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestNoCorrelationIsUnverifiableNotTestedWithLimitations(t *testing.T) {
	o := denied()
	o.Corr = Correlation{}
	r, err := ToRecord(meta(), o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Telemetry != dlpreport.TelemetryUnverifiable || r.Response != dlpreport.ResponseNotTested || r.Limitations == "" {
		t.Fatalf("%+v", r)
	}
}

func TestIntegrityHashDeterministicAndEvidenceSensitive(t *testing.T) {
	a, _ := ToRecord(meta(), denied())
	b, _ := ToRecord(meta(), denied())
	if a.Provenance.IntegrityHash == "" || a.Provenance.IntegrityHash != b.Provenance.IntegrityHash {
		t.Fatal("hash not deterministic")
	}
	o := denied()
	o.Probe.RowsRead = 9
	c, _ := ToRecord(meta(), o)
	if c.Provenance.IntegrityHash == a.Provenance.IntegrityHash {
		t.Fatal("hash did not change with evidence")
	}
	if a.Provenance.SourceSystem != "dbsim-agent" || a.Provenance.CorrelationID != "m1" || a.Confidence != "exact_marker" {
		t.Fatalf("%+v", a)
	}
}

func TestStoredReportJSONRoundTripsAndIsValid(t *testing.T) {
	rep, err := BuildReport(meta(), denied())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := rep.JSON()
	if err := ValidateStoredRun("DB-01", "1", "t1", "postgresql", "r1", string(rep.Result), b); err != nil {
		t.Fatal(err)
	}
}
