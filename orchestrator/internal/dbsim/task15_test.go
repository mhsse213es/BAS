package dbsim

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

const (
	tamperDenied  = "audit_tamper_steps=create=ok,baseline=ok,attempt=denied"
	tamperAllowed = "audit_tamper_steps=create=ok,baseline=ok,attempt=allowed"
	writeDenied   = "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged"
	exportClear   = "export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=12"
)

func TestTask15ProbesAreRegistered(t *testing.T) {
	for _, c := range []struct {
		id, fixture string
		class       ProbeClass
		labOnly     bool
	}{
		{ProbeTryDisableAudit, "empty", ClassBoundedSynthetic, false},
		{ProbeTryWriteFixture, "accounts", ClassBoundedSynthetic, false},
		{ProbeCheckExportPrivileges, "", ClassReadOnly, true},
	} {
		e, ok := LookupProbeEntry(c.id)
		if !ok || e.Class != c.class || e.RequiredFixture != c.fixture || e.LabOnly != c.labOnly ||
			len(e.ParamSchema) != 0 || e.FixtureParam != "" || e.FixedTable != "" || len(e.Engines) != 2 {
			t.Fatalf("%s: %+v ok=%v", c.id, e, ok)
		}
		if e.Class == ClassMutation {
			t.Errorf("%s must never be class mutation (option A: B5 vetoes destructive)", c.id)
		}
	}
}

// R-AS: all three are refused for client targets at the orchestrator gate, and in
// lab mode need a confirmed lab target AND the scenario's mutation approval (the
// read_only DB-11 included).
func TestMutationProbesRefusedInClientMode(t *testing.T) {
	for _, id := range []string{ProbeTryDisableAudit, ProbeTryWriteFixture, ProbeCheckExportPrivileges} {
		e, _ := LookupProbeEntry(id)
		fixture := e.RequiredFixture != ""
		mk := func(client, approved bool) AuthInput { i := in(client, approved); i.Fixture = fixture; return i }
		if err := Authorize(goodTarget(ModeClient), e, mk(true, true)); err == nil {
			t.Errorf("%s: client target accepted", id)
		}
		if err := Authorize(goodTarget(ModeLab), e, mk(false, false)); err == nil {
			t.Errorf("%s: no mutation approval accepted", id)
		}
		unconfirmed := goodTarget(ModeLab)
		unconfirmed.LabConfirmed = false
		if err := Authorize(unconfirmed, e, mk(false, true)); err == nil {
			t.Errorf("%s: unconfirmed lab target accepted", id)
		}
		if err := Authorize(goodTarget(ModeLab), e, mk(false, true)); err != nil {
			t.Errorf("%s: confirmed + approved refused: %v", id, err)
		}
	}
}

func TestAuditTamperNoteParsing(t *testing.T) {
	r, ok := ParseNotes([]string{tamperDenied}).AuditTamper()
	if !ok || r != (AuditTamperSteps{Create: "ok", Baseline: "ok", Attempt: "denied"}) {
		t.Fatalf("%+v %v", r, ok)
	}
	for _, bad := range []string{
		"", "audit_tamper_steps=", "audit_tamper_steps=create=ok,baseline=ok",
		"audit_tamper_steps=create=ok,baseline=ok,attempt=denied,extra=1",
		"audit_tamper_steps=create=ok,baseline=ok,attempt=maybe",
		"audit_tamper_steps=create=yes,baseline=ok,attempt=denied",
		"audit_tamper_steps=create=ok,create=ok,attempt=denied",
		"audit_tamper_steps=create=ok,baseline=ok,attempt=denied,",
	} {
		var notes []string
		if bad != "" {
			notes = []string{bad}
		}
		if _, ok := ParseNotes(notes).AuditTamper(); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if r, ok := ParseNotes([]string{"audit_tamper_steps=create=ok,baseline=failed,attempt=skipped", tamperDenied}).AuditTamper(); !ok || r.Baseline != "failed" {
		t.Fatalf("a later note must not override: %+v", r)
	}
}

func TestWriteAttemptNoteParsing(t *testing.T) {
	r, ok := ParseNotes([]string{writeDenied}).WriteAttempts()
	if !ok || r != (WriteAttemptSteps{Insert: "denied", Update: "denied", Delete: "denied", Fingerprint: "unchanged"}) {
		t.Fatalf("%+v %v", r, ok)
	}
	for _, bad := range []string{
		"write_attempt_steps=insert=denied,update=denied,delete=denied",
		"write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=same",
		"write_attempt_steps=insert=blocked,update=denied,delete=denied,fingerprint=unchanged",
		"write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged,x=1",
		"write_attempt_steps=insert=denied,insert=denied,delete=denied,fingerprint=unchanged",
		"write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=changed,",
	} {
		if _, ok := ParseNotes([]string{bad}).WriteAttempts(); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if v, ok := ParseNotes([]string{"fixture_changed=true"}).Bool("fixture_changed"); !ok || !v {
		t.Error("fixture_changed note")
	}
}

func TestExportChecksNoteParsing(t *testing.T) {
	r, ok := ParseNotes([]string{exportClear}).ExportChecks()
	if !ok || r.FileWrite != "no" || r.ProgramExec != "no" || r.FileRead != "no" || r.BulkSelect != "no" || r.DumpPrivs != "12" || !r.DumpKnown {
		t.Fatalf("%+v %v", r, ok)
	}
	r, ok = ParseNotes([]string{"export_checks=file_write=yes,program_exec=na,file_read=unknown,bulk_select=no,dump_privs=unknown"}).ExportChecks()
	if !ok || r.DumpKnown || r.ProgramExec != "na" || r.FileRead != "unknown" {
		t.Fatalf("%+v %v", r, ok)
	}
	for _, bad := range []string{
		"export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no",
		"export_checks=file_write=maybe,program_exec=no,file_read=no,bulk_select=no,dump_privs=1",
		"export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=-1",
		"export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=abc",
		"export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=1,extra=1",
		"export_checks=file_write=no,file_write=no,file_read=no,bulk_select=no,dump_privs=1",
		"export_checks=file_write=na,program_exec=no,file_read=no,bulk_select=no,dump_privs=1", // na only for program_exec
	} {
		if _, ok := ParseNotes([]string{bad}).ExportChecks(); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// ---- grading ---------------------------------------------------------------

func task15Meta(probe string) ScenarioMeta {
	return ScenarioMeta{ID: "dbsim-" + probe, Version: "1", ControlObjective: "obj", Preconditions: "lab",
		SyntheticDataManifest: "throwaway account", ActionAttempted: probe, ExpectedPrevention: "deny",
		Engine: "postgresql", TargetID: "lab-db", Mode: ModeLab}
}

func t15Outcome(probe string, denied bool, class string, notes ...string) Outcome {
	return Outcome{ProbeID: probe, ProbeRan: true, Marker: "m", RunID: "r", Principal: "dbsim_lab",
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Probe:       DBProbeResult{Denied: denied, ErrorClass: class, Notes: notes, CleanupStatus: CleanupOK}}
}

func detected() Correlation {
	return Correlation{Evaluated: true, Telemetry: dlpreport.TelemetryPresent, Response: dlpreport.ResponseAlerted, Match: MatchExactMarker, Alerts: 1}
}

func TestAuditTamperGrading(t *testing.T) {
	m := task15Meta(ProbeTryDisableAudit)
	m.ExpectDetection, m.ExpectResponse = true, true
	pass := t15Outcome(ProbeTryDisableAudit, true, "permission_denied", tamperDenied)
	pass.Corr = detected()
	if got := ToRunResult(m, pass); got != ResultPass {
		t.Fatalf("denial + baseline + cleanup + marker alert must pass, got %s", got)
	}
	rec, err := ToRecord(m, pass)
	if err != nil || rec.Enforcement != dlpreport.EnforcementBlocked || rec.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("%+v %v", rec, err)
	}
	if !strings.Contains(rec.Limitations, "session-scoped") {
		t.Errorf("the session-only limitation is missing: %q", rec.Limitations)
	}
	for _, c := range []struct {
		name string
		o    Outcome
		want RunResult
	}{
		{"no step note", t15Outcome(ProbeTryDisableAudit, true, "permission_denied"), ResultError},
		{"baseline failed", t15Outcome(ProbeTryDisableAudit, false, "baseline_failed", "audit_tamper_steps=create=ok,baseline=failed,attempt=skipped"), ResultError},
		{"baseline failed but denial claimed", t15Outcome(ProbeTryDisableAudit, true, "permission_denied", "audit_tamper_steps=create=ok,baseline=failed,attempt=denied"), ResultError},
		{"create failed", t15Outcome(ProbeTryDisableAudit, false, "account_create_failed", "audit_tamper_steps=create=failed,baseline=skipped,attempt=skipped"), ResultError},
		{"attempt error", t15Outcome(ProbeTryDisableAudit, false, "attempt_error", "audit_tamper_steps=create=ok,baseline=ok,attempt=error"), ResultError},
		{"denial flagged, note says allowed", t15Outcome(ProbeTryDisableAudit, true, "permission_denied", tamperAllowed), ResultError},
		{"allowed flagged, note says denied", t15Outcome(ProbeTryDisableAudit, false, "", tamperDenied), ResultError},
	} {
		c.o.Corr = detected()
		if got := ToRunResult(m, c.o); got != c.want {
			t.Errorf("%s: %s want %s", c.name, got, c.want)
		}
	}
	// A succeeding tamper statement is a real finding: FAIL, even with no alert
	// evidence (R-U: a definite failure is not hidden behind an evidence gap).
	allowed := t15Outcome(ProbeTryDisableAudit, false, "", tamperAllowed)
	if got := ToRunResult(m, allowed); got != ResultFail {
		t.Fatalf("a permitted session-level audit change must FAIL, got %s", got)
	}
	if rec, _ := ToRecord(m, allowed); rec.Enforcement != dlpreport.EnforcementAllowed {
		t.Fatalf("enforcement %s", rec.Enforcement)
	}
	// Cleanup (verified) is part of the PASS.
	for _, st := range []string{"", CleanupNotApplicable, CleanupResidual, CleanupFailed} {
		o := pass
		o.Probe.CleanupStatus = st
		if st == CleanupResidual || st == CleanupFailed {
			o.Probe.SafetyIncident = true
		}
		if got := ToRunResult(m, o); got != ResultError {
			t.Errorf("cleanup %q: %s, want ERROR", st, got)
		}
	}
	// Without the alert the detection expectation is unverifiable: ERROR.
	noAlert := t15Outcome(ProbeTryDisableAudit, true, "permission_denied", tamperDenied)
	if got := ToRunResult(m, noAlert); got != ResultError {
		t.Fatalf("no correlation must be ERROR, got %s", got)
	}
}

func TestWriteGrading(t *testing.T) {
	m := task15Meta(ProbeTryWriteFixture)
	m.ExpectDetection, m.ExpectResponse = true, true
	pass := t15Outcome(ProbeTryWriteFixture, true, "permission_denied", writeDenied)
	pass.Corr = detected()
	if got := ToRunResult(m, pass); got != ResultPass {
		t.Fatalf("three denials + unchanged fixture + cleanup + alert must pass, got %s", got)
	}
	for _, c := range []struct {
		name string
		o    Outcome
		want RunResult
	}{
		{"no step note", t15Outcome(ProbeTryWriteFixture, true, "permission_denied"), ResultError},
		{"fingerprint changed with all denied", t15Outcome(ProbeTryWriteFixture, false, "fixture_state_inconsistent", "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=changed"), ResultError},
		{"fingerprint changed, denial flagged anyway", t15Outcome(ProbeTryWriteFixture, true, "permission_denied", "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=changed"), ResultError},
		{"fingerprint error", t15Outcome(ProbeTryWriteFixture, false, "fingerprint_failed", "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=error"), ResultError},
		{"fingerprint skipped", t15Outcome(ProbeTryWriteFixture, true, "permission_denied", "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=skipped"), ResultError},
		{"one attempt errored", t15Outcome(ProbeTryWriteFixture, false, "attempt_error", "write_attempt_steps=insert=denied,update=error,delete=denied,fingerprint=unchanged"), ResultError},
		{"attempts skipped", t15Outcome(ProbeTryWriteFixture, false, "baseline_failed", "write_attempt_steps=insert=skipped,update=skipped,delete=skipped,fingerprint=skipped"), ResultError},
		{"all denied claimed but note says one allowed", t15Outcome(ProbeTryWriteFixture, true, "permission_denied", "write_attempt_steps=insert=denied,update=allowed,delete=denied,fingerprint=unchanged"), ResultError},
	} {
		c.o.Corr = detected()
		if got := ToRunResult(m, c.o); got != c.want {
			t.Errorf("%s: %s want %s", c.name, got, c.want)
		}
	}
}

func TestWriteSucceedingIsAFailAndReportsChangedFixture(t *testing.T) {
	m := task15Meta(ProbeTryWriteFixture)
	m.ExpectDetection, m.ExpectResponse = true, true
	for _, steps := range []string{
		"write_attempt_steps=insert=allowed,update=denied,delete=denied,fingerprint=changed",
		"write_attempt_steps=insert=denied,update=denied,delete=allowed,fingerprint=changed",
		"write_attempt_steps=insert=allowed,update=error,delete=denied,fingerprint=error", // definite finding beats evidence gaps
	} {
		o := t15Outcome(ProbeTryWriteFixture, false, "", steps, "fixture_changed=true")
		if got := ToRunResult(m, o); got != ResultFail {
			t.Errorf("%s: %s, want FAIL", steps, got)
		}
		rec, err := ToRecord(m, o)
		if err != nil || rec.Enforcement != dlpreport.EnforcementAllowed {
			t.Fatalf("%+v %v", rec, err)
		}
		if !strings.Contains(rec.Limitations, "fixture_changed") && !strings.Contains(rec.Limitations, "fixture was changed") {
			t.Errorf("the dirty fixture must be reported in the record: %q", rec.Limitations)
		}
	}
	// The allowed run is still graded ERROR when the cleanup of the dirty fixture
	// is not verified.
	o := t15Outcome(ProbeTryWriteFixture, false, "", "write_attempt_steps=insert=allowed,update=denied,delete=denied,fingerprint=changed", "fixture_changed=true")
	o.Probe.CleanupStatus, o.Probe.SafetyIncident = CleanupResidual, true
	if got := ToRunResult(m, o); got != ResultError {
		t.Fatalf("an unverified cleanup beats everything: %s", got)
	}
	// A denied-looking result that claims fixture_changed is inconsistent.
	o = t15Outcome(ProbeTryWriteFixture, true, "permission_denied", writeDenied, "fixture_changed=true")
	if got := ToRunResult(m, o); got != ResultError {
		t.Fatalf("fixture_changed with all denied must not pass: %s", got)
	}
}

func TestExportGrading(t *testing.T) {
	m := task15Meta(ProbeCheckExportPrivileges)
	if got := ToRunResult(m, t15Outcome(ProbeCheckExportPrivileges, true, "", exportClear)); got != ResultPass {
		t.Fatalf("none held and all observed must pass, got %s", got)
	}
	rec, _ := ToRecord(m, t15Outcome(ProbeCheckExportPrivileges, true, "", exportClear))
	if rec.Enforcement != dlpreport.EnforcementBlocked || !strings.Contains(rec.Limitations, "controlled operation") {
		t.Fatalf("%s %q", rec.Enforcement, rec.Limitations)
	}
	for _, c := range []struct {
		name string
		o    Outcome
		want RunResult
	}{
		{"file write held", t15Outcome(ProbeCheckExportPrivileges, false, "", "export_checks=file_write=yes,program_exec=no,file_read=no,bulk_select=no,dump_privs=3"), ResultFail},
		{"program exec held", t15Outcome(ProbeCheckExportPrivileges, false, "", "export_checks=file_write=no,program_exec=yes,file_read=no,bulk_select=no,dump_privs=3"), ResultFail},
		{"file read held", t15Outcome(ProbeCheckExportPrivileges, false, "", "export_checks=file_write=no,program_exec=no,file_read=yes,bulk_select=no,dump_privs=3"), ResultFail},
		{"held beats unobservable", t15Outcome(ProbeCheckExportPrivileges, false, "", "export_checks=file_write=yes,program_exec=no,file_read=no,bulk_select=unknown,dump_privs=unknown"), ResultFail},
		{"one check unobservable", t15Outcome(ProbeCheckExportPrivileges, false, "export_check_incomplete", "export_checks=file_write=no,program_exec=no,file_read=unknown,bulk_select=no,dump_privs=3"), ResultError},
		{"dump count unobservable", t15Outcome(ProbeCheckExportPrivileges, false, "export_check_incomplete", "export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=unknown"), ResultError},
		{"unknown but flagged clear", t15Outcome(ProbeCheckExportPrivileges, true, "", "export_checks=file_write=no,program_exec=no,file_read=unknown,bulk_select=no,dump_privs=3"), ResultError},
		{"held but flagged clear", t15Outcome(ProbeCheckExportPrivileges, true, "", "export_checks=file_write=yes,program_exec=no,file_read=no,bulk_select=no,dump_privs=3"), ResultError},
		{"clear but flagged held", t15Outcome(ProbeCheckExportPrivileges, false, "", exportClear), ResultError},
		{"no note", t15Outcome(ProbeCheckExportPrivileges, true, ""), ResultError},
		{"malformed note", t15Outcome(ProbeCheckExportPrivileges, true, "", "export_checks=file_write=no"), ResultError},
	} {
		if got := ToRunResult(m, c.o); got != c.want {
			t.Errorf("%s: %s want %s", c.name, got, c.want)
		}
	}
}

// DB-11 reads the catalog: it never needs and never claims telemetry.
func TestExportNeverClaimsTelemetry(t *testing.T) {
	m := task15Meta(ProbeCheckExportPrivileges)
	o := t15Outcome(ProbeCheckExportPrivileges, true, "", exportClear)
	rec, err := ToRecord(m, o)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Telemetry == dlpreport.TelemetryPresent || rec.Response != dlpreport.ResponseNotTested {
		t.Fatalf("telemetry %s response %s", rec.Telemetry, rec.Response)
	}
}
