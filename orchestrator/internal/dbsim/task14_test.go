package dbsim

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

func TestTask14ProbesAreRegistered(t *testing.T) {
	ar, ok := LookupProbeEntry(ProbeAuthAfterRevoke)
	if !ok || ar.Class != ClassMutation || ar.RequiredFixture != "empty" || len(ar.ParamSchema) != 0 || ar.FixtureParam != "" {
		t.Fatalf("auth_after_revoke: %+v ok=%v", ar, ok)
	}
	rc, ok := LookupProbeEntry(ProbeReadClassifiedFixture)
	if !ok || rc.Class != ClassBoundedSynthetic || rc.RequiredFixture != "classified-pii" || rc.FixedTable != "customers_pii" ||
		len(rc.ParamSchema) != 0 || rc.FixtureParam != "" {
		t.Fatalf("read_classified_fixture: %+v ok=%v", rc, ok)
	}
}

func TestTask14ProbesAuthorize(t *testing.T) {
	for _, id := range []string{ProbeAuthAfterRevoke, ProbeReadClassifiedFixture} {
		e, _ := LookupProbeEntry(id)
		fx := func(client, approved bool) AuthInput { i := in(client, approved); i.Fixture = true; return i }
		if err := Authorize(goodTarget(ModeClient), e, fx(true, true)); err == nil {
			t.Errorf("%s: client target accepted", id)
		}
		if err := Authorize(goodTarget(ModeLab), e, fx(false, false)); err == nil {
			t.Errorf("%s: no mutation approval accepted", id)
		}
		unconfirmed := goodTarget(ModeLab)
		unconfirmed.LabConfirmed = false
		if err := Authorize(unconfirmed, e, fx(false, true)); err == nil {
			t.Errorf("%s: unconfirmed lab target accepted", id)
		}
		if err := Authorize(goodTarget(ModeLab), e, fx(false, true)); err != nil {
			t.Errorf("%s: confirmed + approved refused: %v", id, err)
		}
	}
}

func TestRevocationNoteParsing(t *testing.T) {
	good := ParseNotes([]string{"revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied"})
	r, ok := good.Revocation()
	if !ok || r != (RevocationSteps{Create: "ok", Baseline: "ok", Revoke: "ok", Reconnect: "denied"}) {
		t.Fatalf("%+v %v", r, ok)
	}
	if !r.PreconditionsOK() {
		t.Fatal("ok/ok/ok is a satisfied precondition")
	}
	for _, bad := range []string{
		"", "revoke_steps=", "revoke_steps=create=ok,baseline=ok,revoke=ok", // missing step
		"revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied,extra=1",
		"revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=maybe",
		"revoke_steps=create=yes,baseline=ok,revoke=ok,reconnect=denied",
		"revoke_steps=create=ok,create=ok,revoke=ok,reconnect=denied",
		"revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied,",
	} {
		var notes []string
		if bad != "" {
			notes = []string{bad}
		}
		if _, ok := ParseNotes(notes).Revocation(); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	// Order independent but strict about the set; the first note wins.
	if _, ok := ParseNotes([]string{"revoke_steps=baseline=ok,create=ok,reconnect=denied,revoke=ok"}).Revocation(); !ok {
		t.Error("a reordered but complete note must parse")
	}
	first := ParseNotes([]string{"revoke_steps=create=ok,baseline=failed,revoke=skipped,reconnect=skipped", "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied"})
	if r, ok := first.Revocation(); !ok || r.Baseline != "failed" || r.PreconditionsOK() {
		t.Fatalf("a later note must not override: %+v", r)
	}
}

func revokeMeta() ScenarioMeta {
	return ScenarioMeta{ID: "dbsim-db06-account-revocation", Version: "1", ControlObjective: "revoked account cannot authenticate",
		Preconditions: "lab", SyntheticDataManifest: "throwaway account", ActionAttempted: "auth_after_revoke",
		ExpectedPrevention: "deny", Engine: "postgresql", TargetID: "lab-db", Mode: ModeLab}
}

func revokeOutcome(denied bool, class string, notes ...string) Outcome {
	return Outcome{ProbeID: ProbeAuthAfterRevoke, ProbeRan: true, Marker: "m", RunID: "r", Principal: "dbsim_lab",
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Probe:       DBProbeResult{Denied: denied, ErrorClass: class, Notes: notes, CleanupStatus: CleanupOK}}
}

const stepsDenied = "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied"

func TestRevocationGradingPassNeedsBaselineAndDenialAndCleanup(t *testing.T) {
	if got := ToRunResult(revokeMeta(), revokeOutcome(true, "auth_failed", stepsDenied)); got != ResultPass {
		t.Fatalf("baseline ok + denial + cleanup ok must pass, got %s", got)
	}
	for _, c := range []struct {
		name string
		o    Outcome
		want RunResult
	}{
		{"no step note", revokeOutcome(true, "auth_failed"), ResultError},
		{"baseline failed note with a denial", revokeOutcome(true, "auth_failed", "revoke_steps=create=ok,baseline=failed,revoke=skipped,reconnect=denied"), ResultError},
		{"baseline failed", revokeOutcome(false, "baseline_failed", "revoke_steps=create=ok,baseline=failed,revoke=skipped,reconnect=skipped"), ResultError},
		{"revoke failed", revokeOutcome(false, "revoke_failed", "revoke_steps=create=ok,baseline=ok,revoke=failed,reconnect=skipped"), ResultError},
		{"create failed", revokeOutcome(false, "account_create_failed", "revoke_steps=create=failed,baseline=skipped,revoke=skipped,reconnect=skipped"), ResultError},
		{"reconnect other error", revokeOutcome(false, "reconnect_error", "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=error"), ResultError},
		{"still connects", revokeOutcome(false, "", "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=connected"), ResultFail},
		{"denial claimed but note says connected", revokeOutcome(true, "auth_failed", "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=connected"), ResultError},
		{"connected claimed but denial flagged", revokeOutcome(false, "", stepsDenied), ResultError},
	} {
		if got := ToRunResult(revokeMeta(), c.o); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	// Cleanup incident beats a clean-looking denial.
	o := revokeOutcome(true, "auth_failed", stepsDenied)
	o.Probe.CleanupStatus, o.Probe.SafetyIncident = CleanupResidual, true
	if got := ToRunResult(revokeMeta(), o); got != ResultError {
		t.Fatalf("leftover account must be ERROR, got %s", got)
	}
}

func TestRevocationEnforcementOnlyFromACompleteDenial(t *testing.T) {
	rec, err := ToRecord(revokeMeta(), revokeOutcome(true, "auth_failed", stepsDenied))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Enforcement != dlpreport.EnforcementBlocked {
		t.Fatalf("enforcement %s", rec.Enforcement)
	}
	rec, _ = ToRecord(revokeMeta(), revokeOutcome(true, "auth_failed")) // no step note
	if rec.Enforcement == dlpreport.EnforcementBlocked {
		t.Fatal("a denial without the baseline/step evidence must not be Blocked")
	}
	rec, _ = ToRecord(revokeMeta(), revokeOutcome(false, "", "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=connected"))
	if rec.Enforcement != dlpreport.EnforcementAllowed {
		t.Fatalf("a login that still works is Allowed, got %s", rec.Enforcement)
	}
}

// Telemetry honesty: the denial itself carries no marker, so nothing here may
// claim Present/Alerted, even if a caller hands in a (baseline-statement)
// correlation.
func TestRevocationNeverClaimsTelemetryOrResponse(t *testing.T) {
	o := revokeOutcome(true, "auth_failed", stepsDenied)
	o.Corr = Correlation{Evaluated: true, Telemetry: dlpreport.TelemetryPresent, Response: dlpreport.ResponseAlerted, Match: MatchExactMarker, Alerts: 1}
	rec, err := ToRecord(revokeMeta(), o)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Telemetry == dlpreport.TelemetryPresent || rec.Response != dlpreport.ResponseNotTested {
		t.Fatalf("telemetry %s response %s", rec.Telemetry, rec.Response)
	}
	if !strings.Contains(rec.Limitations, "failed login") || !strings.Contains(rec.Limitations, "baseline statement") {
		t.Fatalf("limitation sentence missing: %q", rec.Limitations)
	}
	// ... and even a scenario that (wrongly) expects detection cannot pass on it.
	m := revokeMeta()
	m.ExpectDetection, m.ExpectResponse = true, true
	if got := ToRunResult(m, o); got == ResultPass {
		t.Fatal("a denial must not pass a detection expectation")
	}
}
