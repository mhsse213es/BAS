//go:build dbsim_integration

package postgres

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

// WRITTEN, NOT EXECUTED on the build host (no database). Live check of DB-06
// against a throwaway PostgreSQL lab database where the lab user may CREATE ROLE:
// a throwaway LOGIN role is created, a NEW connection as it succeeds (baseline),
// ALTER ROLE ... NOLOGIN is issued, and a NEW connection is then refused with
// SQLSTATE 28000 (reported Denied). The fixture teardown must drop the role and
// verify it gone. UNVERIFIED until run on staging: the exact refusal SQLSTATE and
// whether pg_hba.conf/TLS settings let the throwaway role connect at all (a
// baseline failure is reported baseline_failed, never a pass).
func TestPGAuthAfterRevokeLive(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	spec0, _ := fixtures.Lookup(dbprobe.RevokeFixtureKind)
	var got dbprobe.ProbeResult
	res, err := fixtures.WithFixture(context.Background(), a, spec0, func(fx dbprobe.Fixture) error {
		if err := a.BindFixture(fx); err != nil {
			return err
		}
		defer a.UnbindFixture()
		s := spec(dbprobe.ProbeAuthAfterRevoke, dbprobe.ModeLab, nil)
		s.FixtureID = dbprobe.RevokeFixtureKind
		s.Limits.TimeoutSec = 30
		pr, perr := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), s)
		got = pr
		return perr
	})
	if err != nil || len(res.Residual) != 0 {
		t.Fatalf("lifecycle: res=%+v err=%v", res, err)
	}
	if got.ErrorClass != "auth_failed" || !got.Denied || !hasNote(got.Notes, "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied") {
		t.Fatalf("expected a denial after the revoke: %+v", got)
	}
	for _, n := range got.Notes {
		if strings.Contains(strings.ToLower(n), "password") {
			t.Errorf("note mentions a password: %q", n)
		}
	}
}

func TestPGReadClassifiedFixtureLive(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	spec0, _ := fixtures.Lookup(dbprobe.ClassifiedFixtureKind)
	want := 0
	for _, tb := range spec0.Tables {
		if tb.Name == dbprobe.ClassifiedFixtureTable {
			want = len(tb.Rows)
		}
	}
	res, err := fixtures.WithFixture(context.Background(), a, spec0, func(fx dbprobe.Fixture) error {
		if err := a.BindFixture(fx); err != nil {
			return err
		}
		defer a.UnbindFixture()
		s := spec(dbprobe.ProbeReadClassifiedFixture, dbprobe.ModeLab, nil)
		s.FixtureID = dbprobe.ClassifiedFixtureKind
		s.Limits.MaxRows = 100
		pr, perr := a.RunProbe(context.Background(), def(dbprobe.ProbeReadClassifiedFixture), s)
		if perr != nil {
			return perr
		}
		if pr.RowsRead != want || pr.ErrorClass != "" || pr.Denied {
			t.Errorf("RowsRead=%d want %d: %+v", pr.RowsRead, want, pr)
		}
		return nil
	})
	if err != nil || len(res.Residual) != 0 {
		t.Fatalf("lifecycle: res=%+v err=%v", res, err)
	}
}
