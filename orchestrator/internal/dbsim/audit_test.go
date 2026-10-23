package dbsim

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

func auditMeta() ScenarioMeta {
	return ScenarioMeta{ID: "DB-04", Version: "1", ControlObjective: "audit trail records probe activity",
		Preconditions: "audit source provisioned", SyntheticDataManifest: "none",
		ActionAttempted: "tagged read_roles then audit readback", ExpectedPrevention: "allow",
		ExpectAudit: true, Engine: "postgresql", TargetID: "t1", Mode: ModeLab}
}

func auditOutcome(status string, events ...DBProbeAuditEvent) Outcome {
	return Outcome{ProbeRan: true, Probe: DBProbeResult{RowsRead: 3, AuditStatus: status, AuditEvents: events},
		CollectedAt: t0, Principal: "dbsim_test", Marker: "bas-dbsim:abc123", RunID: "r1"}
}

func markerEvent() DBProbeAuditEvent {
	return DBProbeAuditEvent{Time: t0, Principal: "dbsim_test", Statement: "/* dbsim:bas-dbsim:abc123 */ SELECT rolname FROM pg_roles"}
}

func mustValid(t *testing.T, s ScenarioMeta, o Outcome) (dlpreport.Record, StoredReport) {
	t.Helper()
	rep, err := BuildReport(s, o)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if err := rep.Record.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return rep.Record, rep
}

func TestAuditUnsupportedIsSkippedNeverPass(t *testing.T) {
	rec, rep := mustValid(t, auditMeta(), auditOutcome(AuditUnsupported))
	if rep.Result != ResultSkipped {
		t.Fatalf("result %s, want SKIPPED", rep.Result)
	}
	if rep.Dimensions.Audit != DimSkipped {
		t.Fatalf("audit dim %q", rep.Dimensions.Audit)
	}
	if rec.Telemetry == dlpreport.TelemetryPresent || !strings.Contains(rec.Limitations, "no queryable audit source") {
		t.Fatalf("telemetry %s limitations %q", rec.Telemetry, rec.Limitations)
	}
}

func TestAuditFoundWithMarkerEventPasses(t *testing.T) {
	rec, rep := mustValid(t, auditMeta(), auditOutcome(AuditFound, markerEvent()))
	if rep.Result != ResultPass || rep.Dimensions.Audit != DimPass {
		t.Fatalf("result %s audit %s", rep.Result, rep.Dimensions.Audit)
	}
	if rec.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("telemetry %s", rec.Telemetry)
	}
}

// The agent's output is untrusted data: "found" is only believed when the
// events actually carry this run's marker.
func TestAuditFoundWithoutMarkerEvidenceIsNotAPass(t *testing.T) {
	foreign := DBProbeAuditEvent{Time: t0, Statement: "/* dbsim:bas-dbsim:OTHER */ SELECT 1"}
	for name, o := range map[string]Outcome{
		"no events":      auditOutcome(AuditFound),
		"foreign marker": auditOutcome(AuditFound, foreign),
		"prefix marker":  auditOutcome(AuditFound, DBProbeAuditEvent{Statement: "/* dbsim:bas-dbsim:abc1234 */ SELECT 1"}),
	} {
		_, rep := mustValid(t, auditMeta(), o)
		if rep.Result != ResultError || rep.Dimensions.Audit != DimUnverifiable {
			t.Errorf("%s: result %s audit %s, want ERROR/unverifiable", name, rep.Result, rep.Dimensions.Audit)
		}
	}
}

func TestAuditStatusGrading(t *testing.T) {
	cases := []struct {
		status string
		want   RunResult
		dim    DimensionGrade
	}{
		{AuditAbsent, ResultFail, DimFail},
		{AuditIncomplete, ResultError, DimUnverifiable},
		{AuditError, ResultError, DimUnverifiable},
		{"", ResultError, DimUnverifiable},
		{"banana", ResultError, DimUnverifiable},
	}
	for _, c := range cases {
		rec, rep := mustValid(t, auditMeta(), auditOutcome(c.status))
		if rep.Result != c.want || rep.Dimensions.Audit != c.dim {
			t.Errorf("%q: result %s audit %s, want %s/%s", c.status, rep.Result, rep.Dimensions.Audit, c.want, c.dim)
		}
		if rec.Telemetry == dlpreport.TelemetryPresent {
			t.Errorf("%q: telemetry Present without audit evidence", c.status)
		}
	}
}

func TestAuditTelemetryMapping(t *testing.T) {
	for status, want := range map[string]dlpreport.TelemetryOutcome{
		AuditAbsent: dlpreport.TelemetryAbsent, AuditIncomplete: dlpreport.TelemetryIncomplete,
		AuditError: dlpreport.TelemetryUnverifiable, AuditUnsupported: dlpreport.TelemetryUnverifiable,
	} {
		rec, _ := mustValid(t, auditMeta(), auditOutcome(status))
		if rec.Telemetry != want {
			t.Errorf("%s: telemetry %s want %s", status, rec.Telemetry, want)
		}
	}
}

// An alert exists but the audit slice cannot back it (spec section 7):
// Telemetry is Incomplete, not Present.
func TestPresentAlertWithMissingAuditSliceIsIncomplete(t *testing.T) {
	s := auditMeta()
	s.ExpectDetection = true
	o := auditOutcome(AuditAbsent)
	o.Corr = okCorr()
	rec, rep := mustValid(t, s, o)
	if rec.Telemetry != dlpreport.TelemetryIncomplete {
		t.Fatalf("telemetry %s", rec.Telemetry)
	}
	if rep.Result == ResultPass {
		t.Fatal("must not pass")
	}
}

func TestAuditConfigGrading(t *testing.T) {
	s := ScenarioMeta{ID: "DB-04", Version: "1", ControlObjective: "o", Preconditions: "p", SyntheticDataManifest: "none",
		ActionAttempted: "read_audit_config", ExpectedPrevention: "allow", ExpectAuditConfig: true, Engine: "postgresql", TargetID: "t1", Mode: ModeLab}
	cases := map[string]struct {
		notes []string
		want  RunResult
	}{
		"covered":  {[]string{"log_statement=all", "audit_config: covered"}, ResultPass},
		"none":     {[]string{"log_statement=none", "audit_config: none"}, ResultFail},
		"partial":  {[]string{"audit_config: partial"}, ResultError},
		"missing":  {[]string{"log_statement=all"}, ResultError},
		"nonsense": {[]string{"audit_config: yes"}, ResultError},
	}
	for name, c := range cases {
		o := Outcome{ProbeRan: true, Probe: DBProbeResult{RowsRead: 5, Notes: c.notes}, CollectedAt: t0, Principal: "p", Marker: "m", RunID: "r"}
		rec, rep := mustValid(t, s, o)
		if rep.Result != c.want {
			t.Errorf("%s: result %s want %s (%s)", name, rep.Result, c.want, rep.Reason)
		}
		if name == "none" && rec.Telemetry != dlpreport.TelemetryAbsent {
			t.Errorf("none: telemetry %s", rec.Telemetry)
		}
	}
}

func TestSafetyIncidentBeatsAuditPass(t *testing.T) {
	o := auditOutcome(AuditFound, markerEvent())
	o.Probe.SafetyIncident = true
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Result != ResultError {
		t.Fatalf("result %s", rep.Result)
	}
}

func db02Meta() ScenarioMeta {
	return ScenarioMeta{ID: "DB-02", Version: "1", ControlObjective: "grants conform to policy", Preconditions: "role provisioned",
		SyntheticDataManifest: "none", ActionAttempted: "read_grants", ExpectedPrevention: "allow", RequireObservation: true, RequirePolicyDiff: true,
		Engine: "postgresql", TargetID: "t1", Mode: ModeLab}
}

func TestZeroGrantsObservedIsNeverAPass(t *testing.T) {
	o := Outcome{ProbeRan: true, Probe: DBProbeResult{RowsRead: 0}, CollectedAt: t0, Principal: "dbsim_lab", Marker: "m", RunID: "r"}
	rec, rep := mustValid(t, db02Meta(), o)
	if rep.Result != ResultError {
		t.Fatalf("result %s, want ERROR", rep.Result)
	}
	if rep.Dimensions.Prevention == DimPass {
		t.Fatal("prevention dimension passed on an empty observation")
	}
	if !strings.Contains(rec.Limitations, "no grants observed: account may lack catalog visibility") {
		t.Fatalf("limitations %q", rec.Limitations)
	}
}

func TestObservedCountOverridesRowsRead(t *testing.T) {
	zero := 0
	o := Outcome{ProbeRan: true, Probe: DBProbeResult{RowsRead: 4}, Observed: &zero, CollectedAt: t0, Principal: "p", Marker: "m", RunID: "r"}
	if _, rep := mustValid(t, db02Meta(), o); rep.Result != ResultError {
		t.Fatalf("explicit GrantsChecked=0 must be ERROR, got %s", rep.Result)
	}
	three := 3
	o.Observed = &three
	o.Probe.RowsRead = 0
	// R-AJ: a count alone is observation, not a policy comparison.
	if _, rep := mustValid(t, db02Meta(), o); rep.Result != ResultError {
		t.Fatalf("explicit GrantsChecked=3 without a diff must be ERROR, got %s", rep.Result)
	}
}

// Ruling R-AJ (deliberate contract change): grants being listable (rows > 0) is
// NOT "grants conform to policy". Until a policy diff is actually performed, a
// DB-02 outcome is never PASS and never FAIL-by-omission.
func TestGrantsObservedWithoutPolicyDiffIsUnverifiableNeverPass(t *testing.T) {
	o := Outcome{ProbeRan: true, Probe: DBProbeResult{RowsRead: 2}, CollectedAt: t0, Principal: "p", Marker: "m", RunID: "r"}
	rec, rep := mustValid(t, db02Meta(), o)
	if rep.Result != ResultError || rep.Dimensions.Policy != DimUnverifiable {
		t.Fatalf("result %s policy %s", rep.Result, rep.Dimensions.Policy)
	}
	if !strings.Contains(rec.Limitations, "policy diff not performed; grants were observable (2) but not compared to a stated policy") {
		t.Fatalf("limitations %q", rec.Limitations)
	}
}

func TestSuppliedPolicyDiffDecidesDB02(t *testing.T) {
	o := Outcome{ProbeRan: true, Probe: DBProbeResult{RowsRead: 2}, CollectedAt: t0, Principal: "p", Marker: "m", RunID: "r"}
	o.Diff = &DiffReport{PolicySource: "lab", GrantsChecked: 2, Deviations: []Deviation{}}
	if _, rep := mustValid(t, db02Meta(), o); rep.Result != ResultPass || rep.Dimensions.Policy != DimPass {
		t.Fatalf("clean diff: %s / %s", rep.Result, rep.Dimensions.Policy)
	}
	o.Diff = &DiffReport{PolicySource: "lab", GrantsChecked: 2, Deviations: []Deviation{{Kind: DeviationExcessive, Role: "r", Object: "o", Privilege: "SELECT", PolicySource: "lab"}}}
	if _, rep := mustValid(t, db02Meta(), o); rep.Result != ResultFail || rep.Dimensions.Policy != DimFail {
		t.Fatalf("deviating diff: %s / %s", rep.Result, rep.Dimensions.Policy)
	}
	o.Diff = &DiffReport{PolicySource: "lab", GrantsChecked: 0}
	if _, rep := mustValid(t, db02Meta(), o); rep.Result != ResultError {
		t.Fatalf("empty diff must be ERROR, got %s", rep.Result)
	}
}

func TestDenialIsNotUnobservable(t *testing.T) {
	s := db02Meta()
	s.RequirePolicyDiff = false
	s.ExpectedPrevention = "deny"
	d := Outcome{ProbeRan: true, Probe: DBProbeResult{Denied: true, ErrorClass: "permission_denied"}, CollectedAt: t0, Principal: "p", Marker: "m", RunID: "r"}
	if _, rep := mustValid(t, s, d); rep.Result != ResultPass {
		t.Fatalf("a real denial is an observation: %s (%s)", rep.Result, rep.Reason)
	}
}

func TestAuditEventsAreSanitisedBeforeStorage(t *testing.T) {
	var evs []DBProbeAuditEvent
	for i := 0; i < 80; i++ {
		evs = append(evs, DBProbeAuditEvent{Time: t0, Principal: strings.Repeat("p", 400),
			Statement: "/* dbsim:bas-dbsim:abc123 */ SELECT 1 -- password=hunter2 " + strings.Repeat("x", 3000), Source: strings.Repeat("s", 300)})
	}
	_, rep := mustValid(t, auditMeta(), auditOutcome(AuditFound, evs...))
	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("secret survived into the stored report")
	}
	if n := len(rep.Evidence.AuditEvents); n == 0 || n > MaxStoredAuditEvents {
		t.Fatalf("stored %d audit events, cap %d", n, MaxStoredAuditEvents)
	}
	for _, e := range rep.Evidence.AuditEvents {
		if len(e.Statement) > MaxAuditStatementBytes+16 || len(e.Principal) > 128 || len(e.Source) > 64 {
			t.Fatalf("unbounded event %d/%d/%d", len(e.Statement), len(e.Principal), len(e.Source))
		}
	}
	if rep.Evidence.AuditEventsDropped != 80-len(rep.Evidence.AuditEvents) {
		t.Fatalf("dropped %d", rep.Evidence.AuditEventsDropped)
	}
	_ = time.Now
}
