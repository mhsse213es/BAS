//go:build dbsim_integration

package postgres

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

// WRITTEN, NOT EXECUTED on the build host (no database). Live checks of Task 15
// against a throwaway PostgreSQL lab database. UNVERIFIED until run on staging:
// SQLSTATE 42501 for SET log_statement as an unprivileged role; 42501 for
// INSERT/UPDATE/DELETE as a SELECT-only role; that pgx reports them as
// *pgconn.PgError; the md5 fingerprint; and which export checks the lab account
// actually holds.

func pgLiveFixtureProbe(t *testing.T, probe, kind string) dbprobe.ProbeResult {
	t.Helper()
	a := liveAdapter(t, dbprobe.ModeLab)
	spec0, _ := fixtures.Lookup(kind)
	var got dbprobe.ProbeResult
	res, err := fixtures.WithFixture(context.Background(), a, spec0, func(fx dbprobe.Fixture) error {
		if err := a.BindFixture(fx); err != nil {
			return err
		}
		defer a.UnbindFixture()
		s := spec(probe, dbprobe.ModeLab, nil)
		s.FixtureID = kind
		s.Limits.TimeoutSec = 30
		pr, perr := a.RunProbe(context.Background(), def(probe), s)
		got = pr
		return perr
	})
	if err != nil || len(res.Residual) != 0 {
		t.Fatalf("lifecycle: res=%+v err=%v", res, err)
	}
	for _, n := range got.Notes {
		if strings.Contains(strings.ToLower(n), "password") {
			t.Errorf("note mentions a password: %q", n)
		}
	}
	return got
}

// DB-08: an unprivileged account must be refused the session-scoped audit change
// (SQLSTATE 42501). A success would be a real finding (reported Allowed), not a
// failure of the harness, so this test asserts the lifecycle and that the outcome
// is one of the two typed results.
func TestPGTryDisableAuditLive(t *testing.T) {
	got := pgLiveFixtureProbe(t, dbprobe.ProbeTryDisableAudit, dbprobe.AuditTamperFixtureKind)
	denied := hasNote(got.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=denied")
	allowed := hasNote(got.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=allowed")
	if !denied && !allowed {
		t.Fatalf("expected a recognised denial (or an allowed finding), got %+v", got)
	}
	if denied && (!got.Denied || got.ErrorClass != "permission_denied") {
		t.Fatalf("%+v", got)
	}
	t.Logf("DB-08 live outcome: denied=%v allowed=%v notes=%v", denied, allowed, got.Notes)
}

// DB-10: a SELECT-only account must be refused INSERT, UPDATE and DELETE on the
// fixture table (SQLSTATE 42501), leaving it unchanged.
func TestPGTryWriteFixtureLive(t *testing.T) {
	got := pgLiveFixtureProbe(t, dbprobe.ProbeTryWriteFixture, dbprobe.WriteFixtureKind)
	if !got.Denied || got.ErrorClass != "permission_denied" ||
		!hasNote(got.Notes, "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged") {
		t.Fatalf("expected three recognised denials and an unchanged fixture: %+v", got)
	}
}

// DB-11: fixed catalog reads for the configured lab account. The expected result
// depends on the lab account's grants (the lab account is usually privileged, so
// ALLOWED is a legitimate answer); the test asserts the typed note is complete.
func TestPGCheckExportPrivilegesLive(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	s := spec(dbprobe.ProbeCheckExportPrivileges, dbprobe.ModeLab, nil)
	s.Limits.TimeoutSec = 30
	got, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), s)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range got.Notes {
		if strings.HasPrefix(n, "export_checks=") {
			found = true
			t.Logf("DB-11 live: %s denied=%v errorClass=%q notes=%v", n, got.Denied, got.ErrorClass, got.Notes)
		}
	}
	if !found {
		t.Fatalf("no export_checks note: %+v", got)
	}
}
