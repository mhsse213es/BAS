//go:build dbsim_integration

package mysql

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

// WRITTEN, NOT EXECUTED on the build host (no database). Live checks of Task 15
// against a throwaway MySQL lab server. UNVERIFIED until run on staging: error
// 1227 for SET SESSION sql_log_off as an unprivileged account; 1142/1143/1044 for
// writes by the SELECT-only account; the CRC32 fingerprint; USER_PRIVILEGES
// grantee matching; CURRENT_ROLE; and which export checks the lab account
// actually holds.

func myLiveFixtureProbe(t *testing.T, probe, kind string) dbprobe.ProbeResult {
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
// (error 1227). A success would be a real finding (reported Allowed), not a
// failure of the harness, so this test asserts the lifecycle and that the outcome
// is one of the two typed results.
func TestMySQLTryDisableAuditLive(t *testing.T) {
	got := myLiveFixtureProbe(t, dbprobe.ProbeTryDisableAudit, dbprobe.AuditTamperFixtureKind)
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
// fixture table (error 1142), leaving it unchanged.
func TestMySQLTryWriteFixtureLive(t *testing.T) {
	got := myLiveFixtureProbe(t, dbprobe.ProbeTryWriteFixture, dbprobe.WriteFixtureKind)
	if !got.Denied || got.ErrorClass != "permission_denied" ||
		!hasNote(got.Notes, "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged") {
		t.Fatalf("expected three recognised denials and an unchanged fixture: %+v", got)
	}
}

// DB-11: fixed catalog reads for the configured lab account. The expected result
// depends on the lab account's grants (the lab account is usually privileged, so
// ALLOWED is a legitimate answer); the test asserts the typed note is complete.
func TestMySQLCheckExportPrivilegesLive(t *testing.T) {
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
