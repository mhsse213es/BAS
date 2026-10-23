package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

func dbsimAudit(action string) dbadmin.AuditEntry {
	return dbadmin.AuditEntry{ActorID: "u1", Action: "dbsim.test_" + action, Resource: "dbsim-target:t1", Outcome: "ok"}
}

// failingAudit cannot be marshalled, so its audit insert fails inside the transaction.
func failingAudit() dbadmin.AuditEntry {
	e := dbsimAudit("fail")
	e.Detail = map[string]any{"bad": make(chan int)}
	return e
}

func dbsimTargetRec(t *testing.T, id string, mode dbsim.ExecMode) dbsim.TargetRecord {
	t.Helper()
	reg, err := dbsim.TargetRegistration{ID: id, Engine: "postgresql", Host: "db1.example.com", Port: 5432,
		CredentialRef: "dbcred:prod-pg-ro", ExpectedIdentity: "7312345678901234567", Mode: mode}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return dbsim.TargetRecord{TargetRegistration: reg, CreatedBy: "u1", CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
}

// Needs the Docker-backed test database (TestMain of this package): written and
// compiled, run on a Docker-capable host.
func TestDBSimTargetRegistryStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ { // idempotent
			if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
				t.Fatal(err)
			}
		}
		st := db.DBSimTargetStore{Pool: pool}
		rec := dbsimTargetRec(t, "t1", dbsim.ModeClient)
		if err := st.Create(ctx, rec, dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		if err := st.Create(ctx, rec, dbsimAudit("create")); !errors.Is(err, dbsim.ErrTargetExists) {
			t.Fatalf("duplicate: %v", err)
		}
		got, err := st.Get(ctx, "t1")
		if err != nil || got.ExpectedIdentity != "7312345678901234567" || got.CredentialRef != "dbcred:prod-pg-ro" ||
			got.IdentityCheck.Checked || got.ToTarget().ReadOnlyIdentityVerified {
			t.Fatalf("get %+v %v", got, err)
		}
		got0 := got
		missingRec := got
		missingRec.ID = "missing"
		// A recorded pass verifies; a later failure withdraws it.
		at := time.Now().UTC().Truncate(time.Microsecond)
		if err := st.SaveIdentityCheck(ctx, got0, dbsim.IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}, dbsimAudit("check")); err != nil {
			t.Fatal(err)
		}
		got, _ = st.Get(ctx, "t1")
		if !got.ToTarget().ReadOnlyIdentityVerified || got.IdentityCheck.By != "u1" {
			t.Fatalf("pass not stored: %+v", got.IdentityCheck)
		}
		if err := st.SaveIdentityCheck(ctx, got0, dbsim.IdentityCheckState{Checked: true, At: at, By: "u2", Reasons: []string{"identity can write data"}}, dbsimAudit("check")); err != nil {
			t.Fatal(err)
		}
		got, _ = st.Get(ctx, "t1")
		if got.ToTarget().ReadOnlyIdentityVerified || len(got.IdentityCheck.Reasons) != 1 {
			t.Fatalf("failure not stored: %+v", got.IdentityCheck)
		}
		if err := st.SaveIdentityCheck(ctx, missingRec, dbsim.IdentityCheckState{Checked: true, At: at}, dbsimAudit("check")); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("save missing: %v", err)
		}
		// A client target cannot be stored lab-confirmed (CHECK constraint, not just validation).
		bad := dbsimTargetRec(t, "t2", dbsim.ModeClient)
		bad.LabConfirmed = true
		if err := st.Create(ctx, bad, dbsimAudit("create")); err == nil {
			t.Fatal("client + lab_confirmed stored")
		}
		l, err := st.List(ctx)
		if err != nil || len(l) != 1 {
			t.Fatalf("list %v %v", l, err)
		}
		res := db.DBSimTargetResolver{Store: st}
		if tg, err := res.Resolve(ctx, "t1"); err != nil || tg.ID != "t1" {
			t.Fatalf("resolve %+v %v", tg, err)
		}
		if _, err := res.Resolve(ctx, "nope"); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("resolve missing: %v", err)
		}
		if err := st.Delete(ctx, "t1", dbsimAudit("delete")); err != nil {
			t.Fatal(err)
		}
		if err := st.Delete(ctx, "t1", dbsimAudit("delete")); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("delete missing: %v", err)
		}
	})
}

func TestDBSimClientModeSettingStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		st := db.DBSimSettingsStore{Pool: pool}
		if v, found, err := st.GetClientMode(ctx); err != nil || found || dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("default must be unset/OFF: %q %v %v", v, found, err)
		}
		if err := st.SetClientMode(ctx, true, "u1", dbsimAudit("mode")); err != nil {
			t.Fatal(err)
		}
		if v, found, err := st.GetClientMode(ctx); !dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("enabled not read back: %q %v %v", v, found, err)
		}
		if err := st.SetClientMode(ctx, false, "u1", dbsimAudit("mode")); err != nil {
			t.Fatal(err)
		}
		if v, found, err := st.GetClientMode(ctx); dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("disabled still on: %q %v %v", v, found, err)
		}
	})
}

// Needs the Docker-backed test database: written and compiled, run on a
// Docker-capable host. Covers fix-round findings I1 (atomic audit) and I4
// (binding to the record version).
func TestDBSimStoreMutationsAreAtomicWithAuditAndBoundToTheRecord(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		st := db.DBSimTargetStore{Pool: pool}
		ss := db.DBSimSettingsStore{Pool: pool}
		rec := dbsimTargetRec(t, "t1", dbsim.ModeClient)

		// I1: a failing audit insert rolls the change back.
		if err := st.Create(ctx, rec, failingAudit()); err == nil {
			t.Fatal("create succeeded although its audit row failed")
		}
		if _, err := st.Get(ctx, "t1"); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("a target exists without its audit row: %v", err)
		}
		if err := st.Create(ctx, rec, dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		if err := ss.SetClientMode(ctx, true, "u1", failingAudit()); err == nil {
			t.Fatal("setting changed although its audit row failed")
		}
		if v, found, err := ss.GetClientMode(ctx); dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatal("client mode is on without its audit row")
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		pass := dbsim.IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}
		cur, _ := st.Get(ctx, "t1")
		if err := st.SaveIdentityCheck(ctx, cur, pass, failingAudit()); err == nil {
			t.Fatal("check recorded although its audit row failed")
		}
		if got, _ := st.Get(ctx, "t1"); got.IdentityCheck.Checked {
			t.Fatal("a check result exists without its audit row")
		}
		if err := st.Delete(ctx, "t1", failingAudit()); err == nil {
			t.Fatal("delete succeeded although its audit row failed")
		}
		if _, err := st.Get(ctx, "t1"); err != nil {
			t.Fatalf("target vanished: %v", err)
		}

		// I4: delete + re-register the same id; the old version's pass is refused.
		if err := st.Delete(ctx, "t1", dbsimAudit("delete")); err != nil {
			t.Fatal(err)
		}
		again := rec
		again.CreatedAt = rec.CreatedAt.Add(time.Second)
		if err := st.Create(ctx, again, dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveIdentityCheck(ctx, cur, pass, dbsimAudit("check")); !errors.Is(err, dbsim.ErrTargetChanged) {
			t.Fatalf("a pass for the old version was recorded: %v", err)
		}
		if got, _ := st.Get(ctx, "t1"); got.IdentityCheck.Checked {
			t.Fatal("the re-registered target inherited a pass")
		}
		// A stale pass does not verify through the resolver.
		fresh, _ := st.Get(ctx, "t1")
		if err := st.SaveIdentityCheck(ctx, fresh, dbsim.IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}, dbsimAudit("check")); err != nil {
			t.Fatal(err)
		}
		res := db.DBSimTargetResolver{Store: st, Now: func() time.Time { return at.Add(23 * time.Hour) }}
		if tg, _ := res.Resolve(ctx, "t1"); !tg.ReadOnlyIdentityVerified {
			t.Fatal("a 23h-old pass must verify")
		}
		res.Now = func() time.Time { return at.Add(24 * time.Hour) }
		if tg, _ := res.Resolve(ctx, "t1"); tg.ReadOnlyIdentityVerified {
			t.Fatal("a pass exactly at the max age must not verify")
		}
	})
}
