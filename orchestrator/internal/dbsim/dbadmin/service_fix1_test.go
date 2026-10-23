package dbadmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

// I1: a mutation and its audit row are one unit. When the audit write fails the
// request fails and the state is unchanged.
func TestFailedAuditWriteFailsEveryMutationWithNoStateChange(t *testing.T) {
	ctx := context.Background()

	t.Run("client mode", func(t *testing.T) {
		s, st, _, au := newSvc()
		au.fail = true
		if err := s.SetClientMode(ctx, admin, true); err == nil {
			t.Fatal("client mode switched although the audit write failed")
		}
		if st.writes != 0 || s.ClientModeEnabled() {
			t.Fatal("state changed")
		}
	})
	t.Run("register", func(t *testing.T) {
		s, _, tg, au := newSvc()
		au.fail = true
		if _, err := s.RegisterTarget(ctx, admin, pgReg()); err == nil || len(tg.recs) != 0 {
			t.Fatalf("target registered although the audit write failed: %v", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		s, tg, au := registered(t, nil)
		au.fail = true
		if err := s.DeleteTarget(ctx, admin, "prod-pg-1"); err == nil || len(tg.recs) != 1 {
			t.Fatalf("target deleted although the audit write failed: %v", err)
		}
	})
	t.Run("identity check", func(t *testing.T) {
		run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
		s, tg, au := registered(t, run)
		au.fail = true
		_, _, err := s.RunIdentityCheck(ctx, admin, "prod-pg-1")
		if err == nil {
			t.Fatal("check recorded although the audit write failed")
		}
		if tg.recs["prod-pg-1"].IdentityCheck.Checked || tg.saveCalls != 0 {
			t.Fatal("a check result was recorded without its audit row")
		}
	})
	// The refusal itself still works when the audit store is down.
	s, _, _, au := newSvc()
	au.fail = true
	if err := s.SetClientMode(ctx, analyst, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forbidden must stay forbidden: %v", err)
	}
}

func TestAuditEntryCarriesActorAndAddress(t *testing.T) {
	s, _, _, au := newSvc()
	a := admin
	a.IP = "10.1.2.3"
	if err := s.SetClientMode(context.Background(), a, true); err != nil {
		t.Fatal(err)
	}
	e := au.find("dbsim.client_mode_enabled", "ok")
	if e == nil || e.ActorID != "u-admin" || e.IP != "10.1.2.3" {
		t.Fatalf("%+v", au.entries)
	}
}

// I4: a pass is bound to the record version the probe ran against.
func TestIdentityCheckNotAppliedToARecreatedTarget(t *testing.T) {
	run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
	s, tg, _ := registered(t, run)
	// While the probe runs, the target is deleted and re-registered (same id, same
	// values, later creation time): the pass must not be inherited.
	run.onRun = func() {
		old := tg.recs["prod-pg-1"]
		delete(tg.recs, "prod-pg-1")
		old.CreatedAt = old.CreatedAt.Add(time.Second)
		tg.recs["prod-pg-1"] = old
	}
	_, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1")
	if !errors.Is(err, dbsim.ErrTargetChanged) {
		t.Fatalf("want ErrTargetChanged, got %v", err)
	}
	if tg.recs["prod-pg-1"].IdentityCheck.Checked {
		t.Fatal("the pass was applied to a different registration")
	}
	// Same for a changed credential reference or identity.
	for _, mut := range []func(r *dbsim.TargetRecord){
		func(r *dbsim.TargetRecord) { r.CredentialRef = "dbcred:other" },
		func(r *dbsim.TargetRecord) { r.ExpectedIdentity = "999" },
		func(r *dbsim.TargetRecord) { r.Host = "other.example.com" },
		func(r *dbsim.TargetRecord) { r.Port = 5433 },
		func(r *dbsim.TargetRecord) { r.Database = "x" },
	} {
		run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
		s, tg, _ := registered(t, run)
		m := mut
		run.onRun = func() { r := tg.recs["prod-pg-1"]; m(&r); tg.recs["prod-pg-1"] = r }
		if _, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); !errors.Is(err, dbsim.ErrTargetChanged) {
			t.Fatalf("changed config accepted: %v", err)
		}
	}
}

// Fix round 2 I-1: a slower earlier check cannot overwrite a newer result.
func TestSlowerEarlierCheckDoesNotOverwriteANewerResult(t *testing.T) {
	run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
	s, tg, au := registered(t, run)
	newer := dbsim.IdentityCheckState{Checked: true, Passed: false, At: t0.Add(time.Minute), By: "u-other", Reasons: []string{"identity can write data"}}
	r := tg.recs["prod-pg-1"]
	r.IdentityCheck = newer
	tg.recs["prod-pg-1"] = r
	before := len(au.entries)
	_, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1") // clock t0 < newer.At
	if !errors.Is(err, dbsim.ErrIdentityCheckSuperseded) {
		t.Fatalf("want ErrIdentityCheckSuperseded, got %v", err)
	}
	if got := tg.recs["prod-pg-1"].IdentityCheck; got.Passed || !got.At.Equal(newer.At) || got.By != "u-other" {
		t.Fatalf("the newer failure was overwritten: %+v", got)
	}
	for _, e := range au.entries[before:] {
		if e.Outcome == "ok" && e.Action == "dbsim.target_identity_checked" {
			t.Fatalf("an ok audit row was kept for a superseded check: %+v", e)
		}
	}
}

// Fix round 2: the service clock decides whether a stored pass is still fresh.
func TestServiceClockDecidesEligibility(t *testing.T) {
	run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
	s, tg, _ := registered(t, run)
	if _, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); err != nil {
		t.Fatal(err)
	}
	rec := tg.recs["prod-pg-1"]
	s.Now = func() time.Time { return t0.Add(dbsim.DefaultIdentityCheckMaxAge - time.Second) }
	if !s.Eligible(rec) {
		t.Fatal("a pass just inside the max age must be eligible on the service clock")
	}
	s.Now = func() time.Time { return t0.Add(dbsim.DefaultIdentityCheckMaxAge) }
	if s.Eligible(rec) {
		t.Fatal("a pass at the max age must not be eligible")
	}
}

// The identity-check authorisation target is built with the service clock too:
// a record whose pass is stale on that clock is not treated as verified.
func TestRunIdentityCheckUsesTheServiceClockForTheTarget(t *testing.T) {
	run := &fakeRunner{res: dbsim.DBProbeResult{Notes: []string{clearNote}}}
	s, _, _ := registered(t, run)
	if _, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return t0.Add(48 * time.Hour) }
	if _, _, err := s.RunIdentityCheck(context.Background(), admin, "prod-pg-1"); err != nil {
		t.Fatal(err)
	}
	if run.got.ReadOnlyIdentityVerified {
		t.Fatal("the target handed to the runner was verified by a 48h-old pass")
	}
}
